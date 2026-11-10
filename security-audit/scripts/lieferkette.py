#!/usr/bin/env python3
"""Lieferkette, Abhängigkeiten und Secrets für den Skill security-audit (nur Standardbibliothek).

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I lieferkette.py secrets --lauf <id> --repo <wurzel> --quelle <arbeitskopie> --sha <commit>

`secrets` (Budget 300 s, davon `gitleaks dir` samt Schwärzung zuerst höchstens 120 s) schwärzt zuerst jede Secret-Fundstelle der
Arbeitskopie (gleiche Länge, Zeichen `*`, `\\n` und `\\r` bleiben), setzt dann den Marker `<zustand>/lieferkette/geschwaerzt` und
prüft danach die Historie in einem Spiegelklon des Repos. Ausgabe (JSON auf stdout): `befunde_roh` je (Regel, Datei) mit `regel`,
`datei`, `zeile`, `commits` (volle SHAs, höchstens 20, jüngster zuerst) und `in_head`, dazu `hinweise` und `geschwaerzt`. Die
gitleaks-Felder `Secret`, `Match`, `Author`, `Email`, `Message` und `Fingerprint` werden nie ausgegeben, kein Secret-Wert
verlässt den Prozess.

Exit-Codes: 0 ok (auch wenn gitleaks fehlt: `{"werkzeug": "gitleaks", "fehlt": true, ...}`, dann ohne Marker), 2 ungültige
Argumente (auch `--quelle` ≠ Arbeitskopie des Laufs), 4 Schwärzung gescheitert (`kategorie: schwaerzung-fehlgeschlagen`, kein
Marker), 1 sonstiger Fehler (z. B. Aufräumen unvollständig).

Sicherheitsgrenze: Werkzeuge laufen nie im Kundenrepo (cwd ist ein leerer Ordner im Zustandsordner, Umgebung aus
`gitkopie.werkzeug_umgebung()`, eigene Config, eigener leerer Ignore-Ordner, `--ignore-gitleaks-allow`), jedes als eigene
Prozessgruppe (`start_new_session=True`), die bei Zeitüberschreitung als einzige beendet wird. Gelöscht wird nur unter
`<zustand>/lieferkette/` und jede `.gitleaksignore` innerhalb der Arbeitskopie.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402
import poc  # noqa: E402
from gitkopie import GitFehler, ZeitbudgetFehler, _t  # noqa: E402
from poc import PocFehler  # noqa: E402

SECRETS_BUDGET = 300           # Sekunden für `secrets` insgesamt; Skill-Bash-Limit: 600 s
SECRETS_DIR_BUDGET = 120       # davon `gitleaks dir` samt Schwärzung (zuerst)
KONFIG_SUCHE_BUDGET = 30       # Suche nach Repo-Konfiguration und `gitleaks:allow` in der Arbeitskopie
ALLOW_DATEI_MAX = 16 * 1024 * 1024
REPORT_MAX = 256 * 1024 * 1024
MAX_COMMITS = 20
MAX_NENNUNGEN = 10             # Dateien je Hinweis zur Repo-Konfiguration
GITLEAKS_TOML = "[extend]\nuseDefault = true\n"
KONFIG_NAMEN = (".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml")
ARBEIT = ("leer", "leer-ignore", "gitleaks.toml", "gl-dir.json", "gl-git.json", "spiegel.git")   # unter <zustand>/lieferkette/
VOLLER_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ALLOW_MARKE = b"gitleaks:allow"


fehlt = poc.werkzeug_fehlt     # einziger Parser von SECURITY_AUDIT_OHNE (PATH + Umgebungsvariable), für alle Unterbefehle


class SchwaerzFehler(Exception):
    """Die Arbeitskopie konnte nicht (vollständig) geschwärzt werden."""


class ReportFehler(Exception):
    """Der Bericht von gitleaks fehlt oder ist unlesbar."""


# ------------------------------------------------------------------------------------ Hilfen

def _sekunden(name: str, standard: float) -> float:
    """Budget in Sekunden; die Umgebungsvariable überschreibt den Standard (Tests)."""
    try:
        wert = float(os.environ.get(name, ""))
    except ValueError:
        return standard
    return wert if wert > 0 else standard


def _lieferkette_ordner(zustand: str) -> str:
    """`<zustand>/lieferkette` (0700); ein Symlink oder Nicht-Ordner dort bricht ab, damit nichts außerhalb gelöscht wird."""
    pfad = os.path.join(zustand, "lieferkette")
    try:
        os.mkdir(pfad, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(pfad)
    if not stat.S_ISDIR(st.st_mode):
        raise PocFehler(f"{pfad} ist kein Ordner (Symlink?); abgebrochen", code=1)
    return pfad


def _aufraeumen(lk: str) -> None:
    """Arbeitsdateien unter `<zustand>/lieferkette/` löschen (Spiegel, Reports, Config, leere Ordner); der Marker bleibt."""
    for name in ARBEIT:
        poc._entferne(os.path.join(lk, name), lk)


def _ausgabe(daten: dict) -> None:
    print(json.dumps(daten, ensure_ascii=False))
    sys.stdout.flush()


def _werkzeug_optionen(bericht: str, config: str, ignore_ordner: str) -> list[str]:
    return ["--redact", "--no-banner", "--no-color", "--exit-code", "0", "--report-format", "json", "--report-path", bericht,
            "--config", config, "--gitleaks-ignore-path", ignore_ordner, "--ignore-gitleaks-allow"]


def _lese_report(pfad: str) -> list[dict]:
    try:
        st = os.lstat(pfad)
        if not stat.S_ISREG(st.st_mode) or st.st_size > REPORT_MAX:
            raise ReportFehler("Bericht ist keine normale Datei oder zu groß")
        with open(pfad, "rb") as f:
            daten = json.loads(f.read())
    except OSError as e:
        raise ReportFehler(f"Bericht nicht lesbar ({e.strerror})") from e
    except ValueError as e:
        raise ReportFehler("Bericht ist kein gültiges JSON") from e
    if not isinstance(daten, list) or not all(isinstance(t, dict) for t in daten):
        raise ReportFehler("Bericht hat nicht das erwartete Format (Liste von Objekten)")
    return daten


# ------------------------------------------------------------------------------------ Repo-Konfiguration

def _enthaelt_marke(pfad: str, ende: float) -> bool | None:
    """True, wenn die Datei `gitleaks:allow` enthält; None, wenn die Frist ablief."""
    try:
        with open(pfad, "rb") as f:
            rest = b""
            gelesen = 0
            while gelesen < ALLOW_DATEI_MAX:
                if time.monotonic() > ende:
                    return None
                stueck = f.read(1 << 20)
                if not stueck:
                    return False
                gelesen += len(stueck)
                if ALLOW_MARKE in rest + stueck:
                    return True
                rest = stueck[-(len(ALLOW_MARKE) - 1):]
    except OSError:
        return False
    return False


def _nennung(dateien: list[str]) -> str:
    gezeigt = ", ".join(_t(d) for d in dateien[:MAX_NENNUNGEN])
    return gezeigt + (f" (+{len(dateien) - MAX_NENNUNGEN} weitere)" if len(dateien) > MAX_NENNUNGEN else "")


def _repo_konfiguration(quelle: str) -> tuple[list[str], list[str]]:
    """Repo-eigene Werkzeug-Konfiguration in der Arbeitskopie erkennen (bevor `.gitleaksignore` gelöscht wird). Rückgabe:
    (Hinweise, absolute Pfade aller `.gitleaksignore`-Dateien)."""
    ende = time.monotonic() + KONFIG_SUCHE_BUDGET
    gefunden: dict[str, list[str]] = {name: [] for name in KONFIG_NAMEN}
    erlaubt: list[str] = []
    ignore: list[str] = []
    abgebrochen = False
    for ordner, unter, dateien in os.walk(quelle):
        unter.sort()
        for name in sorted(dateien):
            pfad = os.path.join(ordner, name)
            rel = os.path.relpath(pfad, quelle)
            if name in gefunden:
                gefunden[name].append(rel)
                if name == ".gitleaksignore":
                    ignore.append(pfad)
            if abgebrochen:
                continue
            try:
                regulaer = stat.S_ISREG(os.lstat(pfad).st_mode)
            except OSError:
                continue
            if regulaer:
                treffer = _enthaelt_marke(pfad, ende)
                if treffer is None:
                    abgebrochen = True
                elif treffer:
                    erlaubt.append(rel)
    hinweise = []
    for name in KONFIG_NAMEN:
        if gefunden[name]:
            zusatz = " und aus der Arbeitskopie entfernt" if name == ".gitleaksignore" else ""
            hinweise.append(f"{name} im Repo vorhanden, beim Audit ignoriert{zusatz}: {_nennung(gefunden[name])}")
    if erlaubt:
        hinweise.append(f"gitleaks:allow-Kommentare im Repo vorhanden, beim Audit ignoriert: {_nennung(erlaubt)}")
    if abgebrochen:
        hinweise.append("Suche nach gitleaks:allow abgebrochen (Zeitbudget)")
    return hinweise, ignore


def _ignore_entfernen(pfade: list[str], quelle: str) -> None:
    """`.gitleaksignore`-Dateien aus der Arbeitskopie entfernen (gitleaks liest sie auch dann, wenn `--gitleaks-ignore-path`
    woanders hinzeigt). Nur Einträge, deren Ordner per realpath innerhalb der Arbeitskopie liegt; ein Symlink wird als Link
    entfernt, nie sein Ziel."""
    for pfad in pfade:
        if os.path.commonpath([os.path.realpath(os.path.dirname(pfad)), quelle]) != quelle:
            raise SchwaerzFehler(f".gitleaksignore außerhalb der Arbeitskopie: {_t(pfad)}")
        try:
            os.unlink(pfad)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise SchwaerzFehler(f".gitleaksignore nicht entfernbar: {_t(os.path.relpath(pfad, quelle))} ({e.strerror})") from e


# ------------------------------------------------------------------------------------ Schwärzung

def _ganzzahl(wert: object) -> int:
    if isinstance(wert, bool) or not isinstance(wert, int):
        raise SchwaerzFehler("Fundstelle ohne gültige Koordinaten")
    return wert


def _bytes_von(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def _schwaerze_treffer(orig: bytes, neu: bytearray, starts: list[int], t: dict, anzeige: str) -> list[str]:
    """Eine Fundstelle in `neu` schwärzen (Koordinaten gegen das unveränderte `orig`). gitleaks 8.30 meldet Byte-Spalten,
    1-basiert, Ende inklusiv; ab Zeile 2 sind Start- und Endspalte um 1 zu groß; `EndColumn` kann hinter dem Zeilenende liegen."""
    sl, el = _ganzzahl(t.get("StartLine")), _ganzzahl(t.get("EndLine"))
    sc, ec = _ganzzahl(t.get("StartColumn")), _ganzzahl(t.get("EndColumn"))
    if not 1 <= sl <= el <= len(starts):
        raise SchwaerzFehler(f"Fundstelle in {anzeige} liegt außerhalb der Datei (Zeile {sl}-{el} von {len(starts)})")

    def zeilen_ende(zeile: int) -> int:           # Offset des Zeilenendes ohne `\n`
        return starts[zeile + 1] - 1 if zeile + 1 < len(starts) else len(orig)

    sc0 = max(sc - 1 if sl > 1 else sc, 1)
    ec0 = ec - 1 if el > 1 else ec
    beginn = starts[sl - 1] + sc0 - 1
    ende = starts[el - 1] + min(ec0, zeilen_ende(el - 1) - starts[el - 1])
    scharf = 0 <= beginn <= zeilen_ende(sl - 1) and beginn < ende
    von = bis = 0
    if scharf:
        tags = t.get("Tags")
        match = t.get("Match")
        if isinstance(tags, list) and any(isinstance(x, str) and x.startswith("decoded:") for x in tags):
            praefix = suffix = b""                 # Treffer im dekodierten Text: ganzes Segment der Datei
        elif isinstance(match, str) and match.count("REDACTED") == 1:
            vorne, _, hinten = match.partition("REDACTED")
            praefix, suffix = _bytes_von(vorne), _bytes_von(hinten)
        else:
            scharf = False
        region = orig[beginn:ende]
        if scharf and region.startswith(praefix) and region.endswith(suffix) and len(region) > len(praefix) + len(suffix):
            von, bis = beginn + len(praefix), ende - len(suffix)
        else:
            scharf = False
    hinweise = []
    if not scharf:                                # unscharf: ganze Spanne (bei unbrauchbaren Koordinaten ganze Zeilen)
        if 0 <= beginn <= zeilen_ende(sl - 1) and beginn < ende:
            von, bis = beginn, ende
        else:
            von, bis = starts[sl - 1], zeilen_ende(el - 1)
        hinweise.append(f"Schwärzung unscharf: {anzeige}:{sl}")
    neu[von:bis] = re.sub(rb"[^\r\n]", b"*", bytes(orig[von:bis]))
    return hinweise


def schwaerzen(datei: str, treffer: list[dict], wurzel: str | None = None) -> list[str]:
    """Fundstellen (Einträge aus dem gitleaks-Bericht) in `datei` überschreiben: nur der Secret-Anteil, byteweise `*`, gleiche
    Länge, `\\n` und `\\r` bleiben. Die Datei wird an Ort und Stelle beschrieben (Rechte und Inode bleiben), nie über einen
    Symlink. Rückgabe: Hinweise („Schwärzung unscharf: <datei>:<zeile>“, wenn Präfix/Suffix nicht an der berechneten Stelle
    stehen; dann wird die ganze Spanne ohne Zeilenumbrüche geschwärzt). Wirft SchwaerzFehler, wenn die Datei nicht lesbar oder
    beschreibbar ist oder eine Fundstelle nicht in der Datei liegt (dann bleibt die Datei unverändert)."""
    anzeige = _t(os.path.relpath(datei, wurzel) if wurzel else datei)
    try:
        fd = os.open(datei, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise SchwaerzFehler(f"{anzeige} nicht beschreibbar ({e.strerror})") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SchwaerzFehler(f"{anzeige} ist keine normale Datei")
        stuecke = []
        while True:
            stueck = os.read(fd, 1 << 20)
            if not stueck:
                break
            stuecke.append(stueck)
        orig = b"".join(stuecke)
        starts = [0] + [m.end() for m in re.finditer(rb"\n", orig)]
        neu = bytearray(orig)
        hinweise: list[str] = []
        for t in treffer:
            hinweise += _schwaerze_treffer(orig, neu, starts, t, anzeige)
        if bytes(neu) != orig:
            os.lseek(fd, 0, os.SEEK_SET)
            geschrieben = 0
            while geschrieben < len(neu):
                geschrieben += os.write(fd, bytes(neu[geschrieben:]))
            os.fsync(fd)
        return hinweise
    except OSError as e:
        raise SchwaerzFehler(f"{anzeige} nicht schreibbar ({e.strerror})") from e
    finally:
        os.close(fd)


def _schwaerze_arbeitskopie(quelle: str, bericht: list[dict]) -> tuple[int, list[str]]:
    """Alle Fundstellen des `dir`-Berichts in der Arbeitskopie schwärzen. `File` wird aufgelöst (realpath) und muss innerhalb
    der Arbeitskopie liegen, sonst wird nichts geschrieben. Rückgabe: (Anzahl geschwärzter Fundstellen, Hinweise)."""
    je_datei: dict[str, list[dict]] = {}
    draussen = 0
    for t in bericht:
        pfad = t.get("File")
        if not isinstance(pfad, str) or not pfad or "\0" in pfad:
            raise SchwaerzFehler("Fundstelle ohne gültigen Dateipfad")
        voll = pfad if os.path.isabs(pfad) else os.path.join(quelle, pfad)
        real = os.path.realpath(voll)
        if os.path.commonpath([real, quelle]) != quelle:
            draussen += 1
            continue
        je_datei.setdefault(real, []).append(t)
    hinweise: list[str] = []
    anzahl = 0
    for real in sorted(je_datei):
        hinweise += schwaerzen(real, je_datei[real], quelle)
        anzahl += len(je_datei[real])
    if draussen:
        hinweise.append(f"{draussen} Fundstellen außerhalb der Arbeitskopie ignoriert (nichts geschrieben)")
    if anzahl:
        hinweise.insert(0, f"{anzahl} Secret-Fundstellen in der Arbeitskopie geschwärzt")
    return anzahl, hinweise


def _gitleaks_dir(quelle: str, lk: str, ende: float) -> list[dict]:
    """`gitleaks dir` auf der Arbeitskopie; SchwaerzFehler bei Fehlstart, Exit ≠ 0, Zeitablauf oder unlesbarem Bericht."""
    rest = ende - time.monotonic()
    if rest <= 0:
        raise SchwaerzFehler("Zeitbudget für die Schwärzung erschöpft")
    bericht = os.path.join(lk, "gl-dir.json")
    try:
        r = gitkopie.werkzeug_ausfuehren(
            ["gitleaks", "dir", quelle, *_werkzeug_optionen(bericht, os.path.join(lk, "gitleaks.toml"),
                                                           os.path.join(lk, "leer-ignore"))],
            rest, os.path.join(lk, "leer"))
    except GitFehler as e:
        raise SchwaerzFehler(f"gitleaks nicht startbar ({_t(e, 200)})") from e
    if r.rc is None:
        raise SchwaerzFehler("Zeitbudget für die Schwärzung erschöpft (gitleaks dir abgebrochen)")
    if r.rc != 0:
        raise SchwaerzFehler(f"gitleaks dir endete mit Exit {r.rc}")
    try:
        return _lese_report(bericht)
    except ReportFehler as e:
        raise SchwaerzFehler(f"gitleaks dir: {e}") from e


# ------------------------------------------------------------------------------------ Historie

def _zeitpunkt(text: object) -> float:
    try:
        wert = datetime.fromisoformat(str(text))
    except ValueError:
        return 0.0
    if wert.tzinfo is None:
        wert = wert.replace(tzinfo=timezone.utc)
    return wert.timestamp()


def _gruppieren(bericht: list[dict]) -> list[dict]:
    """Je (Regel, Datei) ein Befund: `commits` (voll, jüngster zuerst, höchstens 20), `zeile` aus dem jüngsten Commit.
    Einträge ohne gültige Regel, Datei oder Commit-SHA werden verworfen; Wertfelder werden nie gelesen."""
    gruppen: dict[tuple[str, str], list[tuple[float, int, str, int]]] = {}
    for i, t in enumerate(bericht):
        regel, datei, commit = t.get("RuleID"), t.get("File"), t.get("Commit")
        if not (isinstance(regel, str) and regel and isinstance(datei, str) and datei and "\0" not in datei
                and isinstance(commit, str) and VOLLER_SHA.fullmatch(commit)):
            continue
        zeile = t.get("StartLine")
        zeile = zeile if isinstance(zeile, int) and not isinstance(zeile, bool) and zeile >= 1 else 1
        gruppen.setdefault((regel, datei), []).append((_zeitpunkt(t.get("Date")), i, commit, zeile))
    befunde = []
    for (regel, datei), eintraege in gruppen.items():
        eintraege.sort(key=lambda e: (-e[0], e[1]))
        commits: list[str] = []
        for _, _, commit, _ in eintraege:
            if commit not in commits:
                commits.append(commit)
        befunde.append({"regel": regel, "datei": datei, "zeile": eintraege[0][3], "commits": commits[:MAX_COMMITS]})
    befunde.sort(key=lambda b: (b["datei"], b["regel"]))
    return befunde


def _in_head(spiegel: str, sha: str, datei: str) -> bool:
    try:
        gitkopie.git(spiegel, "cat-file", "-e", f"{sha}:{datei}")
    except ZeitbudgetFehler:
        raise
    except GitFehler as e:
        if e.returncode is None:
            raise
        return False
    return True


def _historie(repo: str, lk: str, sha: str, ende: float, hinweise: list[str]) -> list[dict]:
    """Spiegelklon, `gitleaks git`, Gruppierung und `in_head`. Wirft ZeitbudgetFehler, GitFehler oder ReportFehler."""
    spiegel = os.path.join(lk, "spiegel.git")
    hinweise += gitkopie.spiegel(repo, spiegel, ende - time.monotonic())
    rest = ende - time.monotonic()
    if rest <= 0:
        raise ZeitbudgetFehler("gitleaks git: Zeitbudget erschöpft, nicht gestartet")
    bericht = os.path.join(lk, "gl-git.json")
    r = gitkopie.werkzeug_ausfuehren(
        ["gitleaks", "git", spiegel, *_werkzeug_optionen(bericht, os.path.join(lk, "gitleaks.toml"),
                                                        os.path.join(lk, "leer-ignore"))],
        rest, os.path.join(lk, "leer"))
    if r.rc is None:
        raise ZeitbudgetFehler("gitleaks git: Zeitbudget erschöpft")
    if r.rc != 0:
        raise GitFehler(f"gitleaks git endete mit Exit {r.rc}")
    befunde = _gruppieren(_lese_report(bericht))
    sha_da = True
    try:
        gitkopie.git(spiegel, "cat-file", "-e", f"{sha}^{{commit}}")
    except ZeitbudgetFehler:
        raise
    except GitFehler as e:
        if e.returncode is None:
            raise
        sha_da = False
        hinweise.append(f"Commit {sha[:12]} fehlt im Spiegel (auf keinem Ref erreichbar): in_head nicht ermittelbar")
    for b in befunde:
        b["in_head"] = _in_head(spiegel, sha, b["datei"]) if sha_da else None
        b["regel"] = _t(b["regel"], 100)
    return befunde


# ------------------------------------------------------------------------------------ secrets

def _marker_setzen(marker: str, anzahl: int, sha: str) -> None:
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"geschwaerzt": anzahl, "sha": sha}, f)


def _schwaerzung_gescheitert(grund: str) -> int:
    print("kategorie: schwaerzung-fehlgeschlagen")
    print(f"lieferkette.py: Schwärzung fehlgeschlagen: {_t(grund, 300)}. Arbeitskopie nicht geschwärzt — "
          f"Karte und Reviewer erst nach Prüfung durch dich.", file=sys.stderr)
    return 4


def cmd_secrets(a: argparse.Namespace) -> int:
    zustand = poc._ordner(a.lauf)
    repo = os.path.realpath(a.repo)
    if not os.path.isdir(repo):
        raise PocFehler(f"--repo ist kein Ordner: {a.repo}")
    quelle = os.path.realpath(a.quelle)
    if not os.path.isdir(zustand) or quelle != os.path.realpath(os.path.join(zustand, "quelle")) or not os.path.isdir(quelle):
        raise PocFehler("--quelle muss die Arbeitskopie dieses Laufs sein (`poc.py vorbereiten`): "
                        f"erwartet {os.path.join(zustand, 'quelle')}")
    if not os.path.isfile(os.path.join(zustand, "quelle.fertig")):
        raise PocFehler("Arbeitskopie unvollständig (kein Fertig-Marker): erneut `poc.py vorbereiten --lauf … --repo …`")
    if fehlt("gitleaks"):
        hinweis = "gitleaks fehlt, Secret-Prüfung nicht durchgeführt"
        _ausgabe({"werkzeug": "gitleaks", "fehlt": True, "hinweis": hinweis, "befunde_roh": [], "hinweise": [hinweis],
                  "geschwaerzt": 0})
        return 0
    lk = _lieferkette_ordner(zustand)
    marker = poc.schwaerz_marker(a.lauf)
    start = time.monotonic()
    ende = start + _sekunden("SECURITY_AUDIT_SECRETS_BUDGET", SECRETS_BUDGET)
    ende_dir = min(ende, start + _sekunden("SECURITY_AUDIT_SECRETS_DIR_BUDGET", SECRETS_DIR_BUDGET))
    gitkopie.frist_setzen(ende)
    try:
        poc._entferne(marker, lk)                 # kein Marker ohne diese Schwärzung, auch nicht von einem früheren Lauf
        _aufraeumen(lk)
        return _secrets(a, repo, quelle, lk, marker, ende, ende_dir)
    finally:
        gitkopie.frist_setzen(None)
        _aufraeumen(lk)


def _secrets(a: argparse.Namespace, repo: str, quelle: str, lk: str, marker: str, ende: float, ende_dir: float) -> int:
    for ordner in ("leer", "leer-ignore"):
        os.mkdir(os.path.join(lk, ordner), 0o700)
    with open(os.path.join(lk, "gitleaks.toml"), "w", encoding="utf-8") as f:
        f.write(GITLEAKS_TOML)
    hinweise: list[str] = []
    try:
        konfig_hinweise, ignore = _repo_konfiguration(quelle)
        hinweise += konfig_hinweise
        _ignore_entfernen(ignore, quelle)
        anzahl, schwaerz_hinweise = _schwaerze_arbeitskopie(quelle, _gitleaks_dir(quelle, lk, ende_dir))
    except SchwaerzFehler as e:
        return _schwaerzung_gescheitert(str(e))
    hinweise += schwaerz_hinweise
    try:
        _marker_setzen(marker, anzahl, a.sha)
    except OSError as e:
        return _schwaerzung_gescheitert(f"Marker nicht setzbar ({e.strerror})")
    befunde: list[dict] = []
    try:
        befunde = _historie(repo, lk, a.sha, ende, hinweise)
    except ZeitbudgetFehler:
        hinweise.append("Secret-Prüfung abgebrochen (Zeitbudget)")
    except (GitFehler, ReportFehler) as e:
        hinweise.append(f"Secret-Prüfung der Historie fehlgeschlagen ({_t(e, 200)})")
    _aufraeumen(lk)                               # vor der Ausgabe: scheitert das Löschen, endet der Befehl mit Exit 1
    _ausgabe({"befunde_roh": [{"regel": b["regel"], "datei": _t(b["datei"], 500), "zeile": b["zeile"],
                               "commits": b["commits"], "in_head": b["in_head"]} for b in befunde],
              "hinweise": hinweise, "geschwaerzt": anzahl})
    return 0


# ------------------------------------------------------------------------------------ Argumente

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lieferkette.py", allow_abbrev=False, description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="unterbefehl", required=True)
    s = sub.add_parser("secrets", allow_abbrev=False, help="Secrets schwärzen und in der Historie suchen")
    s.set_defaults(fn=cmd_secrets)
    s.add_argument("--lauf", required=True, type=poc._typ_lauf)
    s.add_argument("--repo", required=True, help="Repo-Wurzel (für den Spiegelklon)")
    s.add_argument("--quelle", required=True, help="Arbeitskopie des Laufs (`<zustand>/quelle`)")
    s.add_argument("--sha", required=True, type=poc._typ_sha, help="geprüfter Commit (voller Hash)")
    return p


def main(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    try:
        return a.fn(a)
    except PocFehler as e:
        print(f"lieferkette.py: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
