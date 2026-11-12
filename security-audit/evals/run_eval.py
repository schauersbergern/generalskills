#!/usr/bin/env python3
"""Eval-Lauf des Skills security-audit: legt ein Temp-Repo mit der Test-App an, kopiert den Skill hinein, startet
`claude -p` mit eng gefassten Rechten und wertet das Ergebnis über `auswertung.auswerten` aus (TF1-D1 bis TF1-D7).

    python3 security-audit/evals/run_eval.py --fixture fixture-web [--ohne LISTE] [--ohne-lockfile]
        [--timeout 5400] [--behalten] [--prompt-art slash|text]

Ein Lauf kostet echte Modell-Token. Exit: 0 alles erfüllt, 1 DoD verfehlt (auch Timeout oder Exit ≠ 0 von claude),
2 Aufruf ungültig, 5 Docker nicht leer oder nicht lesbar, 6 Smoke-Test von `claude -p` gescheitert, 7 ein anderer
Eval-Lauf ist aktiv (Sperrdatei `<temp>/security-audit-eval.lock`; zwei Läufe würden gegenseitig Docker-Reste
abräumen).
Fortschritt und Meldungen auf stderr, das Ergebnis als JSON auf stdout und in `<temp>/ergebnis.json`.
Nur Standardbibliothek.
"""
from __future__ import annotations

import argparse
import fcntl
import fnmatch
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HIER = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HIER)
sys.path.insert(0, HIER)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))
import auswertung  # noqa: E402
import gitkopie  # noqa: E402

PRAEFIX = "security-audit-"
TEMP_PRAEFIX = "eval-security-audit-"
SKILL_NAME = "security-audit-eval"
TOOLS = "Read,Glob,Grep,Write,Edit,Agent,Skill,Bash,TodoWrite,ToolSearch"
SMOKE_PROMPT = "Antworte nur mit ok."
# Der Eval-Skill liegt in `.claude/skills/` des Temp-Repos (Claude-Konfiguration „nur im Arbeitsbaum“): `bericht.py kontext` bricht
# ohne den Schalter ab. Die Konfiguration ist hier die eigene Skill-Kopie in einem Wegwerf-Repo, also gilt der Schalter in beiden Prompts.
SCHALTER = "repo-konfig-geprueft"
PROMPTS = {"slash": f"/{SKILL_NAME} {SCHALTER}", "text": f"Nutze den Skill {SKILL_NAME} auf diesem Repo mit dem Schalter {SCHALTER}."}
SMOKE_TIMEOUT = 300
DOCKER_TIMEOUT = 60
KILL_WARTEN = 10
FORTSCHRITT_SEKUNDEN = 30
ABBRUCH_TAKT = 0.2                                         # Wartetakt, in dem das Abbruch-Flag geprüft wird
KOPIE_AUSSCHLUSS = ("__pycache__", ".pytest_cache", ".DS_Store")


def _log(text: str) -> None:
    print(f"[eval] {text}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------------------------ Rechte, Umgebung, Agent

def erlaubte_regeln(skill_ordner: str, ausgabe: str, home: str, tmp: str | None = None) -> list[str]:
    """`--allowedTools`-Regeln (jeweils die engste Form, die der Skill-Text vorschreibt):
    - Read nur auf den Skill-Ordner (`SKILL.md`, `references/`; `skill_ordner` = realpath der Skill-Kopie), den
      Ausgabeordner und die Arbeitskopien von `poc.py vorbereiten` (`<tmp>/security-audit-*`, `tmp` = realpath des
      Temp-Ordners), nicht auf das ganze Temp-Repo; `Glob`/`Grep` ohne Pfadregel (die CLI hat dafür keine
      dokumentierte Pfadsyntax; Offener Punkt im Bericht).
    - Write/Edit nur im Ausgabeordner (`//` = absoluter Pfad ab Wurzel).
    - Bash: `poc.py` (kopierter Skill), `bericht.py kontext`, `bericht.py rendern <ausgabe>/*`, `agent-stats.py add
      <ausgabe>/*` (mit `~` und mit absolutem `home`) und `ls`. Die `*`-Muster treffen auch `..`-Pfade (Restrisiko)."""
    absolut = lambda pfad: "/" + pfad                    # "//<absoluter Pfad ohne führenden />"
    if tmp is None:
        tmp = os.path.realpath(tempfile.gettempdir())
    stats = "~/.claude/skills/auto-feature/scripts/agent-stats.py"
    stats_abs = f"{home.rstrip('/')}/.claude/skills/auto-feature/scripts/agent-stats.py"
    bericht = f"python3 -I {skill_ordner}/scripts/bericht.py"
    return [
        f"Read({absolut(skill_ordner.rstrip('/'))}/**)",
        f"Read({absolut(ausgabe)}/**)",
        f"Read({absolut(tmp.rstrip('/'))}/{PRAEFIX}*/**)",
        "Glob", "Grep", "Agent", "Skill", "TodoWrite", "ToolSearch",
        f"Write({absolut(ausgabe)}/**)",
        f"Edit({absolut(ausgabe)}/**)",
        f"Bash(python3 -I {skill_ordner}/scripts/poc.py *)",
        f"Bash({bericht} kontext)",
        f"Bash({bericht} kontext *)",
        f"Bash({bericht} rendern {ausgabe}/*)",
        f"Bash(python3 {stats} add {ausgabe}/*)",
        f"Bash(python3 {stats_abs} add {ausgabe}/*)",
        "Bash(ls)",
        "Bash(ls *)",
    ]


def kind_umgebung(basis: dict, ausgabe: str, ohne: list[str], cwd: str | None = None) -> dict:
    """Umgebung des Kindprozesses: Kopie von `basis` ohne `CLAUDECODE`, `CLAUDE_EFFORT` und alle `CLAUDE_CODE_*`;
    gesetzt werden `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0`, `SECURITY_AUDIT_AUSGABE`, `SECURITY_AUDIT_OHNE`. Mit
    `cwd`: `PWD=<cwd>` und kein `OLDPWD` (sonst zeigt `PWD` auf das Verzeichnis des Aufrufers)."""
    env = {k: v for k, v in basis.items()
           if k not in ("CLAUDECODE", "CLAUDE_EFFORT") and not k.startswith("CLAUDE_CODE_")}
    env["CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"] = "0"
    env["SECURITY_AUDIT_AUSGABE"] = ausgabe
    env["SECURITY_AUDIT_OHNE"] = ",".join(ohne)
    if cwd is not None:
        env["PWD"] = cwd
        env.pop("OLDPWD", None)
    return env


def _blockskalar(art: str, zeilen: list[str]) -> str:
    """Inhalt eines YAML-Blockskalars (`>` gefaltet, `|` wörtlich; Zusätze wie `-`/`+` ignoriert) aus den eingerückten
    Folgezeilen: Einrückung entfernt, gefaltet werden einfache Zeilenumbrüche zu Leerzeichen, Leerzeilen bleiben
    Absatzwechsel."""
    einzug = min((len(z) - len(z.lstrip(" \t")) for z in zeilen if z.strip()), default=0)
    inhalt = [z[einzug:].rstrip() for z in zeilen]
    while inhalt and not inhalt[-1]:
        inhalt.pop()
    if art.startswith("|"):
        return "\n".join(inhalt)
    text = ""
    for i, z in enumerate(inhalt):
        if i == 0:
            text = z
        elif not z:
            text += "\n"
        elif text.endswith("\n") or not text:
            text += z
        else:
            text += " " + z
    return text.replace("\n\n", "\n")


def _frontmatter(text: str) -> tuple[dict[str, str], str, str]:
    """(Schlüssel → Wert der `key: value`-Zeilen samt Blockskalaren, Frontmatter-Rohtext, Rest). ValueError ohne
    Frontmatter."""
    m = re.match(r"\A---[ \t]*\n(.*?)\n---[ \t]*(?:\n|\Z)(.*)\Z", text, re.S)
    if not m:
        raise ValueError("kein Frontmatter")
    felder = {}
    zeilen = m.group(1).split("\n")
    i = 0
    while i < len(zeilen):
        k, sep, v = zeilen[i].partition(":")
        i += 1
        if not (sep and re.fullmatch(r"[A-Za-z][\w-]*", k)):
            continue
        v = v.strip()
        if re.fullmatch(r"[>|][+-]?\d*", v):
            folge = []
            while i < len(zeilen) and (not zeilen[i].strip() or zeilen[i][0] in " \t"):
                folge.append(zeilen[i])
                i += 1
            v = _blockskalar(v, folge)
        elif len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        felder[k] = v
    return felder, m.group(1), m.group(2)


def agents_json(opus_md: str) -> str:
    """`--agents`-Wert: `{"opus-xhigh": {description, prompt, model, effort}}` aus dem Text von `agents/opus-xhigh.md`
    (Frontmatter und Rumpf). ValueError ohne Frontmatter oder `description`."""
    felder, _, rumpf = _frontmatter(opus_md)
    if not felder.get("description"):
        raise ValueError("description fehlt im Frontmatter")
    agent = {"description": felder["description"], "prompt": rumpf.strip(),
             "model": felder.get("model", "opus"), "effort": felder.get("effort", "xhigh")}
    return json.dumps({"opus-xhigh": agent}, ensure_ascii=False)


def _opus_md_lesen() -> str:
    kandidaten = [os.path.join(os.path.dirname(SKILL_DIR), "agents", "opus-xhigh.md"),
                  os.path.join(os.path.expanduser("~"), ".claude", "agents", "opus-xhigh.md")]
    for i, pfad in enumerate(kandidaten):
        try:
            with open(pfad, encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        _log(f"Agent-Definition: {pfad}" + (" (Ersatz aus dem Home-Ordner, nicht aus dem Repo)" if i else ""))
        return text
    raise FileNotFoundError("agents/opus-xhigh.md nicht gefunden (" + ", ".join(kandidaten) + ")")


# ------------------------------------------------------------------------------------ Temp-Repo

def _skill_kopieren(quelle: str, ziel: str) -> None:
    def ignorieren(ordner: str, namen: list[str]) -> list[str]:
        weg = [n for n in namen if n in KOPIE_AUSSCHLUSS or fnmatch.fnmatch(n, "test_*.py")]
        if os.path.realpath(ordner) == os.path.realpath(quelle):
            weg += [n for n in namen if n == "evals"]
        return weg

    shutil.copytree(quelle, ziel, ignore=ignorieren, symlinks=True)
    pfad = os.path.join(ziel, "SKILL.md")
    with open(pfad, encoding="utf-8") as f:
        text = f.read()
    _, kopf, _ = _frontmatter(text)
    neu, n = re.subn(r"^name:.*$", f"name: {SKILL_NAME}", kopf, count=1, flags=re.M)
    if n != 1:
        raise ValueError("SKILL.md: Frontmatter ohne name")
    with open(pfad, "w", encoding="utf-8") as f:
        f.write(text.replace(kopf, neu, 1))


def temp_repo_anlegen(fixture: str, skill_quelle: str, ohne_lockfile: bool) -> tuple[str, str]:
    """Legt `<temp>/<name>/` an (Temp-Wurzel und Repo heißen gleich, `eval-security-audit-…`, beide realpath):
    Test-App aus `<skill_quelle>/evals/<fixture>/` (`package-lock.json.tmpl` → `package-lock.json`, mit
    `ohne_lockfile` ohne Lockfile), git-Repo mit einem Commit, Skill ohne `evals/`, `test_*.py`, Caches nach
    `.claude/skills/security-audit-eval/` (Frontmatter `name: security-audit-eval`), `.claude/` in
    `.git/info/exclude`. Gibt (Temp-Wurzel, Repo-Pfad) zurück."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fixture):
        raise ValueError(f"Fixture-Name ungültig: {fixture!r}")
    quelle = os.path.join(skill_quelle, "evals", fixture)
    if not os.path.isdir(quelle):
        raise FileNotFoundError(f"Fixture {fixture!r} nicht gefunden: {quelle}")
    wurzel = os.path.realpath(tempfile.mkdtemp(prefix=TEMP_PRAEFIX))
    repo = os.path.join(wurzel, os.path.basename(wurzel))
    try:
        shutil.copytree(quelle, repo, symlinks=True)
        tmpl = os.path.join(repo, "package-lock.json.tmpl")
        if os.path.exists(tmpl):
            if ohne_lockfile:
                os.remove(tmpl)
            else:
                os.rename(tmpl, os.path.join(repo, "package-lock.json"))
        _skill_kopieren(skill_quelle, os.path.join(repo, ".claude", "skills", SKILL_NAME))
        git = gitkopie.git
        git(repo, "-c", "init.defaultBranch=main", "init", "-q")
        with open(os.path.join(repo, ".git", "info", "exclude"), "a", encoding="utf-8") as f:
            f.write("\n.claude/\n")
        git(repo, "-c", "core.excludesFile=/dev/null", "add", "-A")      # kein globales Exclude (z. B. .env*)
        git(repo, "-c", "user.name=eval", "-c", "user.email=eval@localhost", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", f"Test-App {fixture}")
    except BaseException:
        shutil.rmtree(wurzel, ignore_errors=True)
        raise
    return wurzel, repo


# ------------------------------------------------------------------------------------ Docker

def _docker(args: list[str]) -> tuple[int, str]:
    """(Exit-Code, stdout); Exit -1, wenn docker nicht startbar ist oder die Zeit überschritten wird."""
    try:
        r = subprocess.run(["docker", *args], capture_output=True, timeout=DOCKER_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    return r.returncode, r.stdout.decode("utf-8", "replace")


def _eigene(zeilen: list[str], laeufe: set[str] | None = None) -> list[str]:
    """Namen mit Präfix `security-audit-` (ohne führenden `/`), ohne Dubletten, in Reihenfolge. Mit `laeufe` nur die
    Namen dieser Läufe (`security-audit-<lauf>` oder `security-audit-<lauf>-…`): ein parallel laufendes echtes Audit
    mit anderer Lauf-ID bleibt unberührt (R1-3)."""
    namen: list[str] = []
    for z in zeilen:
        n = z.strip().lstrip("/")
        if not n.startswith(PRAEFIX) or n in namen:
            continue
        if laeufe is not None and not any(n == f"{PRAEFIX}{lauf}" or n.startswith(f"{PRAEFIX}{lauf}-") for lauf in laeufe):
            continue
        namen.append(n)
    return namen


def _images(laeufe: set[str] | None = None) -> list[tuple[str, str]] | None:
    """(Repository, Tag) der Images `security-audit-*` (mit `laeufe` nur dieser Läufe); None, wenn nicht lesbar."""
    rc, out = _docker(["images", "--filter", f"reference={PRAEFIX}*", "--format", "{{.Repository}}|{{.Tag}}"])
    if rc != 0:
        return None
    paare = []
    for z in out.splitlines():
        repo, _, tag = z.strip().partition("|")
        if _eigene([repo], laeufe) and (repo, tag) not in paare:
            paare.append((repo, tag))
    return paare


def docker_listen(laeufe: set[str] | None = None) -> dict[str, list[str]]:
    """`{"container": […], "netze": […], "images": […]}` nur mit Namen `security-audit-*` (mit `laeufe` nur die dieser
    Läufe). Eine nicht lesbare Liste fehlt im Ergebnis (die Auswertung wertet das fail-closed als D7 nicht erfüllt)."""
    listen: dict[str, list[str]] = {}
    rc, out = _docker(["ps", "-a", "--format", "{{.Names}}"])
    if rc == 0:
        listen["container"] = _eigene(out.splitlines(), laeufe)
    rc, out = _docker(["network", "ls", "--format", "{{.Name}}"])
    if rc == 0:
        listen["netze"] = _eigene(out.splitlines(), laeufe)
    images = _images(laeufe)
    if images is not None:
        listen["images"] = _eigene([r for r, _ in images], laeufe)
    return listen


def _eigene_laeufe(stream_pfad: str) -> set[str]:
    """Lauf-IDs aus den `poc.py neu`-Ausgaben im Stream dieses Evals (leer, wenn der Stream fehlt: dann hat der Lauf nichts gestartet)."""
    try:
        ereignisse, _, _, _ = auswertung.lade_stream_info(stream_pfad)
    except OSError:
        return set()
    return auswertung.lauf_ids(ereignisse)


def docker_aufraeumen(laeufe: set[str]) -> bool:
    """Entfernt Container, Netze und Images der Läufe `laeufe` (Namen `security-audit-<lauf>…`, nur diese; die Lauf-IDs
    stammen aus den Ausgaben von `poc.py neu` im Stream des Evals, so bleibt ein parallel laufendes echtes Audit unberührt).
    True, wenn nichts übrig blieb; False bei Fehlern beim Entfernen und wenn eine Liste nicht lesbar war (dann ist
    unbekannt, ob etwas übrig ist). Ohne Lauf-IDs gibt es nichts zu entfernen."""
    ok = True
    if not laeufe:
        return ok

    def containerliste() -> list[str] | None:
        rc, out = _docker(["ps", "-a", "--format", "{{.Names}}"])
        return _eigene(out.splitlines(), laeufe) if rc == 0 else None

    def netzliste() -> list[str] | None:
        rc, out = _docker(["network", "ls", "--format", "{{.Name}}"])
        return _eigene(out.splitlines(), laeufe) if rc == 0 else None

    def imageliste() -> list[str] | None:
        images = _images(laeufe)
        return None if images is None else [f"{r}:{t}" for r, t in images if t and t != "<none>"]

    schritte = (("Container", containerliste, lambda n: ["rm", "-f", "-v", *n]),
                ("Netze", netzliste, lambda n: ["network", "rm", *n]),
                ("Images", imageliste, lambda n: ["rmi", "-f", *n]))
    for art, lesen, loeschen in schritte:
        namen = lesen()
        if namen is None:
            _log(f"Aufräumen: {art} nicht lesbar (läuft Docker?), Reste unbekannt")
            ok = False
            continue
        if not namen:
            continue
        rc, _ = _docker(loeschen(namen))
        if rc != 0:
            _log(f"Aufräumen: {art} nicht vollständig entfernt: {', '.join(namen)}")
            ok = False
    return ok


# ------------------------------------------------------------------------------------ Prozess

def _gruppe_beenden(p: subprocess.Popen, warten: float = KILL_WARTEN) -> None:
    """Prozessgruppe des Kindes beenden: SIGTERM, nach `warten` Sekunden SIGKILL (immer auch für Reste der Gruppe)."""
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        p.wait(timeout=warten)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        p.wait(timeout=warten)
    except subprocess.TimeoutExpired:
        pass


def _kind_starten(cmd: list[str], cwd: str, env: dict, stdout, stderr) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                            start_new_session=True)


def _smoke_test(basis: list[str], cwd: str, env: dict) -> tuple[bool, str]:
    """`claude -p "Antworte nur mit ok." --output-format json` mit den Optionen des Laufs, ohne Werkzeuge."""
    cmd = ["claude", "-p", SMOKE_PROMPT, "--output-format", "json", *basis, "--tools", ""]
    p = None                                               # Start im try: ein Abbruch nach der Zuweisung beendet die Gruppe
    try:
        _abbruch_pruefen()                                 # kein Kind starten, wenn schon ein Signal anliegt
        p = _kind_starten(cmd, cwd, env, subprocess.PIPE, subprocess.PIPE)
        ende = time.monotonic() + SMOKE_TIMEOUT
        while True:
            _abbruch_pruefen()                             # direkt nach dem Start: `p` ist zugewiesen
            rest = ende - time.monotonic()
            if rest <= 0:
                raise subprocess.TimeoutExpired(cmd, SMOKE_TIMEOUT)
            try:
                out, err = p.communicate(timeout=min(ABBRUCH_TAKT, rest))
                break
            except subprocess.TimeoutExpired:              # kurzer Takt, nicht das Gesamtbudget: weiter warten
                continue
    except OSError as e:
        return False, f"claude nicht startbar: {e}"
    except subprocess.TimeoutExpired:
        _gruppe_beenden(p, 5)
        return False, f"Zeitüberschreitung nach {SMOKE_TIMEOUT} s"
    except BaseException:
        if p is not None:
            _gruppe_beenden(p, 5)
        raise
    finally:
        if p is not None:
            try:
                os.killpg(p.pid, signal.SIGKILL)           # Reste der Gruppe
            except (ProcessLookupError, PermissionError):
                pass
    text, fehler = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    if p.returncode != 0:
        return False, f"Exit {p.returncode}: {(fehler or text).strip()[-500:]}"
    return _smoke_antwort(text)


def _smoke_antwort(text: str) -> tuple[bool, str]:
    """Wertet die Ausgabe von `claude -p --output-format json` aus. Je nach CLI-Version ist das ein einzelnes
    Ergebnisobjekt oder eine Liste aller Nachrichten; maßgeblich ist das letzte Objekt mit `type: result`."""
    try:
        antwort = json.loads(text)
    except ValueError:
        return False, f"Ausgabe ist kein JSON: {text.strip()[-300:]}"
    if isinstance(antwort, list):
        ergebnisse = [x for x in antwort if isinstance(x, dict) and x.get("type") == "result"]
        antwort = ergebnisse[-1] if ergebnisse else None
    if not isinstance(antwort, dict) or antwort.get("is_error"):
        return False, f"Fehlerantwort: {text.strip()[-300:]}"
    return True, ""


def _lauf(cmd: list[str], cwd: str, env: dict, stream_pfad: str, stderr_pfad: str, timeout: float) -> dict:
    """Startet `claude` in eigener Sitzung, schreibt stdout nach `stream_pfad`, wartet bis `timeout` Sekunden
    (Fortschritt auf stderr) und beendet bei Zeitüberschreitung oder Abbruch die ganze Prozessgruppe."""
    start = time.monotonic()
    zeitueberschreitung = False
    p = None                                               # Start im try: ein Signal nach der Zuweisung beendet die Gruppe
    with open(stream_pfad, "wb") as aus, open(stderr_pfad, "wb") as fehler:
        try:
            _abbruch_pruefen()                             # kein Kind starten, wenn schon ein Signal anliegt
            p = _kind_starten(cmd, cwd, env, aus, fehler)
            letzte_meldung = time.monotonic()
            while True:
                _abbruch_pruefen()                         # direkt nach dem Start (`p` ist zugewiesen) und in jedem Takt
                rest = timeout - (time.monotonic() - start)
                if rest <= 0:
                    zeitueberschreitung = True
                    _log(f"Zeitüberschreitung nach {timeout:g} s: beende Prozessgruppe")
                    _gruppe_beenden(p)
                    break
                try:
                    p.wait(timeout=min(ABBRUCH_TAKT, rest))
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() - letzte_meldung >= FORTSCHRITT_SEKUNDEN:
                        letzte_meldung = time.monotonic()
                        _log(f"läuft seit {time.monotonic() - start:.0f} s, Stream {os.path.getsize(stream_pfad)} Bytes")
        except BaseException:
            if p is not None:
                _gruppe_beenden(p, 5)
            raise
        finally:
            if p is not None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)       # Reste der Gruppe (Kindprozesse des Kindes)
                except (ProcessLookupError, PermissionError):
                    pass
    return {"rc": p.returncode, "timeout": zeitueberschreitung, "dauer_s": round(time.monotonic() - start, 1)}


# ------------------------------------------------------------------------------------ Zustand vorher/nachher

def _eintraege(wurzel: str, praefix: str | None = None) -> set[str]:
    """Relative Pfade aller Dateien und Ordner unter `wurzel` (rekursiv, Symlinks nicht verfolgt); mit `praefix` nur
    unterhalb von Einträgen, deren oberster Name so beginnt."""
    gefunden: set[str] = set()
    for ordner, ordner_namen, dateien in os.walk(wurzel):
        for n in ordner_namen + dateien:
            rel = os.path.relpath(os.path.join(ordner, n), wurzel)
            if praefix is None or rel.split(os.sep)[0].startswith(praefix):
                gefunden.add(rel)
    return gefunden


def _home_zustand() -> tuple[set[str], set[str]]:
    home = os.path.expanduser("~")
    return (_eintraege(os.path.join(home, ".claude", "security-reviews")),
            _eintraege(os.path.join(home, ".claude", "agent-stats"), "eval-security-audit-"))


def _bericht_lesen(ordner: str) -> tuple[dict | None, str | None]:
    """Neueste `.json` im Ausgabeordner des Repos, die ein Bericht ist (JSON-Objekt mit `befunde`-Liste); andere `.json`
    (Request-Bodys der Prüfer) zählen nicht. Ohne Bericht: (None, Pfad der neuesten `.json` oder None)."""
    try:
        namen = [n for n in os.listdir(ordner) if n.endswith(".json") and os.path.isfile(os.path.join(ordner, n))]
    except OSError:
        return None, None
    if not namen:
        return None, None
    pfade = sorted((os.path.join(ordner, n) for n in namen), key=os.path.getmtime, reverse=True)
    for pfad in pfade:
        try:
            with open(pfad, encoding="utf-8") as f:
                bericht = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(bericht, dict) and isinstance(bericht.get("befunde"), list):
            return bericht, pfad
    return None, pfade[0]


# ------------------------------------------------------------------------------------ main

def _argumente(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="run_eval.py", description="Eval-Lauf des Skills security-audit (kostet Token).")
    p.add_argument("--fixture", required=True, help="Name der Test-App unter evals/, z. B. fixture-web")
    p.add_argument("--ohne", default="", help="Kommagetrennte Liste, geht als SECURITY_AUDIT_OHNE an den Skill")
    p.add_argument("--ohne-lockfile", action="store_true", help="Test-App ohne package-lock.json anlegen")
    p.add_argument("--timeout", type=float, default=5400, help="Zeitlimit des Laufs in Sekunden (Standard 5400)")
    p.add_argument("--behalten", action="store_true", help="Temp-Verzeichnis auch nach Exit 0 behalten")
    p.add_argument("--prompt-art", choices=sorted(PROMPTS), default="slash", help="slash: /security-audit-eval, text: Satz")
    return p.parse_args(argv)


class Abbruch(KeyboardInterrupt):
    """Von SIGTERM/SIGHUP/SIGINT ausgelöst; `signum` bestimmt den Exit-Code (128 + signum)."""

    def __init__(self, signum: int):
        super().__init__(signum)
        self.signum = signum


_abbruch_signal: int | None = None


def _signal_handler(signum, _frame):
    """Setzt nur das Flag. Der Handler wirft nie mitten in eine Anweisung (etwa zwischen `Popen` und der Zuweisung des
    Objekts) und sperrt keine Signale, die ein Kind erben könnte. `_lauf` und `_smoke_test` prüfen das Flag direkt nach
    dem Start und in ihrer Warteschleife, `_lauf_main` an den Phasengrenzen."""
    global _abbruch_signal
    _abbruch_signal = signum


def _abbruch_pruefen() -> None:
    if _abbruch_signal is not None:
        raise Abbruch(_abbruch_signal)


def main(argv: list[str]) -> int:
    """Wie `_main`, aber SIGTERM, SIGHUP und SIGINT (Strg-C) setzen ein Flag; die Wartestellen lösen daraufhin `Abbruch`
    aus: die Prozessgruppe von claude wird beendet und Docker aufgeräumt (finally in `_lauf_main`), der Exit-Code ist
    128 + Signal (SIGINT: 130). Das Aufräumen selbst läuft nach einem Signal zu Ende."""
    global _abbruch_signal
    _abbruch_signal = None
    alt = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            alt[sig] = signal.signal(sig, _signal_handler)
    except ValueError:                                   # nicht im Hauptthread (z. B. Testläufer): ohne Handler
        pass
    try:
        return _main(argv)
    except Abbruch as e:
        _log(f"Signal {e.signum}: abgebrochen, Prozessgruppe beendet, Docker aufgeräumt")
        return 128 + e.signum
    except KeyboardInterrupt:
        _log("Abbruch durch KeyboardInterrupt: Prozessgruppe beendet, Docker aufgeräumt")
        return 130
    finally:
        for sig, h in alt.items():
            signal.signal(sig, h)
        _abbruch_signal = None                           # kein Rest für spätere Aufrufe im selben Prozess


def _eval_sperre() -> int | None:
    """Maschinenweite Sperre (flock auf `<temp>/security-audit-eval.lock`); None, wenn schon ein Eval-Lauf sie hält."""
    pfad = os.path.join(os.path.realpath(tempfile.gettempdir()), "security-audit-eval.lock")
    fd = os.open(pfad, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def _main(argv: list[str]) -> int:
    try:
        a = _argumente(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    fd = _eval_sperre()
    if fd is None:
        print("Ein anderer Eval-Lauf ist aktiv (Sperre security-audit-eval.lock im Temp-Ordner): zwei Läufe würden "
              "gegenseitig Docker-Ressourcen mit Präfix security-audit- entfernen. Warten oder den anderen Lauf beenden.",
              file=sys.stderr)
        return 7
    try:
        return _lauf_main(a)
    finally:
        os.close(fd)


def _lauf_main(a: argparse.Namespace) -> int:
    erwartung_pfad = os.path.join(HIER, "expected", f"{a.fixture}.json")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", a.fixture) or not os.path.isfile(erwartung_pfad) \
            or not os.path.isdir(os.path.join(HIER, a.fixture)):
        print(f"Fixture {a.fixture!r} unbekannt (erwartet evals/{a.fixture}/ und evals/expected/{a.fixture}.json)",
              file=sys.stderr)
        return 2
    try:
        with open(erwartung_pfad, encoding="utf-8") as f:
            erwartung = json.load(f)
        agenten = agents_json(_opus_md_lesen())
    except (OSError, ValueError) as e:
        print(f"Eingaben nicht lesbar: {e}", file=sys.stderr)
        return 2
    ohne = [x.strip() for x in a.ohne.split(",") if x.strip()]

    # 1. Vorprüfung: Docker darf keine Reste von security-audit-* haben
    _abbruch_pruefen()
    _log("Vorprüfung Docker")
    vorher = docker_listen()
    if set(vorher) != {"container", "netze", "images"}:
        print("Docker nicht lesbar: Vorprüfung nicht möglich (läuft der Daemon?)", file=sys.stderr)
        return 5
    reste = [f"{art}: {n}" for art, namen in (("Container", vorher["container"]), ("Netz", vorher["netze"]),
                                              ("Image", vorher["images"])) for n in namen]
    if reste:
        print("Docker nicht leer (Präfix security-audit-), vorher aufräumen:\n  " + "\n  ".join(reste), file=sys.stderr)
        return 5

    # 2. Temp-Repo
    _abbruch_pruefen()
    wurzel, repo = temp_repo_anlegen(a.fixture, SKILL_DIR, a.ohne_lockfile)
    skill = os.path.realpath(os.path.join(repo, ".claude", "skills", SKILL_NAME))
    ausgabe = os.path.join(wurzel, "ausgabe")
    os.makedirs(ausgabe)
    ausgabe = os.path.realpath(ausgabe)
    stream_pfad, stderr_pfad = os.path.join(wurzel, "stream.jsonl"), os.path.join(wurzel, "claude-stderr.log")
    _log(f"Temp-Repo {repo}")

    # 3. und 5. Optionen, Umgebung
    home = os.path.expanduser("~")
    repo = os.path.realpath(repo)
    env = kind_umgebung(os.environ, ausgabe, ohne, cwd=repo)
    gemeinsam = ["--permission-mode", "acceptEdits", "--setting-sources", "project,local", "--strict-mcp-config",
                 "--agents", agenten, "--add-dir", ausgabe, "--disallowedTools", "WebFetch,WebSearch"]
    cmd = ["claude", "-p", PROMPTS[a.prompt_art], "--output-format", "stream-json", "--verbose", *gemeinsam,
           "--tools", TOOLS, "--allowedTools", *erlaubte_regeln(skill, ausgabe, home, os.path.realpath(tempfile.gettempdir()))]

    reviews_vorher, stats_vorher = _home_zustand()
    lauf: dict = {"rc": None, "timeout": False, "dauer_s": 0.0}
    listen: dict[str, list[str]] = {}
    try:
        # 4. Smoke-Test
        _abbruch_pruefen()
        _log("Smoke-Test claude -p")
        ok, grund = _smoke_test(gemeinsam, repo, env)
        if not ok:
            print(f"Smoke-Test von claude -p gescheitert: {grund}\nTemp-Verzeichnis: {wurzel}", file=sys.stderr)
            return 6
        # 5. Lauf
        _abbruch_pruefen()
        _log(f"Lauf startet (Timeout {a.timeout:g} s, Prompt {PROMPTS[a.prompt_art]!r})")
        lauf = _lauf(cmd, repo, env, stream_pfad, stderr_pfad, a.timeout)
        _log(f"Lauf beendet: rc={lauf['rc']}, Timeout={lauf['timeout']}, {lauf['dauer_s']} s")
        # 6. Nachher: Docker-Listen erfassen
        listen = docker_listen(_eigene_laeufe(stream_pfad))
        _abbruch_pruefen()
    finally:
        eigene = _eigene_laeufe(stream_pfad)
        _log(f"Docker aufräumen (Läufe dieses Evals: {', '.join(sorted(eigene)) or 'keine'})")
        if not docker_aufraeumen(eigene):
            _log("Warnung: Docker-Reste dieses Evals (security-audit-<lauf>-…) können bleiben")

    # 6. und 7. Zustand nachher, Auswertung
    try:
        porcelain = gitkopie.git(repo, "status", "--porcelain").stdout.decode("utf-8", "replace")
    except gitkopie.GitFehler as e:
        porcelain = f"?? git status nicht lesbar: {e}"             # fail-closed: D4 rot
    ausgabe_ordner = os.path.join(ausgabe, os.path.basename(repo))
    try:
        dateien = sorted(n for n in os.listdir(ausgabe_ordner) if os.path.isfile(os.path.join(ausgabe_ordner, n)))
    except OSError:
        dateien = []
    bericht, bericht_pfad = _bericht_lesen(ausgabe_ordner)
    reviews_nachher, stats_nachher = _home_zustand()
    try:
        ereignisse, uebersprungen, nur_letzte, letzte = auswertung.lade_stream_info(stream_pfad)
    except OSError:
        ereignisse, uebersprungen, nur_letzte, letzte = [], 0, False, ""
    ergebnis = auswertung.auswerten(
        bericht, erwartung, ereignisse, porcelain, dateien,
        sorted(reviews_nachher - reviews_vorher), sorted(stats_nachher - stats_vorher), listen,
        stream_uebersprungen=uebersprungen, stream_nur_letzte=nur_letzte, stream_letzte_zeile=letzte)
    lauf_ok = lauf["rc"] == 0 and not lauf["timeout"]
    ergebnis["lauf"] = {"fixture": a.fixture, "temp": wurzel, "repo": repo, "ausgabe": ausgabe_ordner,
                        "bericht": bericht_pfad, "prompt": PROMPTS[a.prompt_art], "ohne": ohne,
                        "subagenten": auswertung.zaehle_subagenten(ereignisse),
                        "stream_zeilen_uebersprungen": uebersprungen, "ok": lauf_ok, **lauf}
    ergebnis["ok"] = bool(ergebnis["ok"] and lauf_ok)
    text = json.dumps(ergebnis, ensure_ascii=False, indent=2)
    try:
        with open(os.path.join(wurzel, "ergebnis.json"), "w", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError as e:
        _log(f"ergebnis.json nicht schreibbar: {e}")
    print(text)
    for kriterium, d in ergebnis["dod"].items():
        _log(f"{kriterium}: {'ok' if d['ok'] else 'FEHLT'}" + "".join(f"\n    {x}" for x in d["details"][:5]))
    if not lauf_ok:
        _log(f"claude: rc={lauf['rc']}, Timeout={lauf['timeout']} (stderr: {stderr_pfad})")
    if ergebnis["ok"] and not a.behalten:
        shutil.rmtree(wurzel, ignore_errors=True)
        _log("Alle Kriterien erfüllt, Temp-Verzeichnis entfernt")
        return 0
    _log(f"Temp-Verzeichnis bleibt: {wurzel}")
    return 0 if ergebnis["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
