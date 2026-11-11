"""Kontext und Bericht des Skills security-audit.

  bericht.py kontext [--teilpfad P] [--repo R]   JSON mit Repo-Kontext auf stdout (Exit 3: kein Repo/HEAD,
                                                  ungültiger Teilpfad; das Argument nach `--teilpfad` ist immer der
                                                  Wert, auch `-x`, oder `--teilpfad=-x`)
  bericht.py repo [--repo R]                      Repo-Name (genau `kontext`-Feld `repo`) auf stdout, ohne Seiteneffekte
                                                  (Exit 3: kein Repo)
  bericht.py rendern <json>                       Schema prüfen, <basisname>.md neben das JSON schreiben
                                                  (Exit 2 mit Fehlerliste auf stderr)

Die Befundliste im ersten Codeblock des Markdown nimmt /fix-findings an (Format wie pr-review-loop).
Nur Standardbibliothek; git-Aufrufe über gitkopie.git.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402
import netzregel  # noqa: E402
from gitkopie import GitFehler, ZeitbudgetFehler, _t, git  # noqa: E402

STUFEN = ("P1", "P2", "P3")
STATUS = ("bestätigt", "unbestätigt", "verworfen", "verdacht")
IN_LISTE = ("bestätigt", "unbestätigt")
EINZEILIG = ("titel", "szenario", "erwartet", "klasse")
WERKZEUGE = ("osv-scanner", "gitleaks", "lieferkette")
LIEFERKETTE_KLASSEN = ("lockfile-fehlt", "installation-ohne-lockfile-treue", "install-skripte-offen")
MAX_COMMITS = 20
MAX_PAKETE = 300          # Pakete je Befund (so viele gibt `lieferkette.py abhaengigkeiten` insgesamt aus)
MAX_ADVISORIES = 20       # Advisories je Paket (so viele gibt `lieferkette.py abhaengigkeiten` je Paket aus)
MARKDOWN_COMMITS = 5      # Commits je Befund im Detailabschnitt, der Rest als „+n“
MAX_JSON_BYTES = 16 * 1024 * 1024
KONTEXT_BUDGET = 300      # Sekunden für `kontext` insgesamt (SECURITY_AUDIT_KONTEXT_TIMEOUT überschreibt es); Bash-Limit des Skills: 600 s
_ID = re.compile(r"S-[1-9][0-9]{0,8}")
_KATEGORIE = re.compile(r"A(0[1-9]|10)")
_ZEILE_IM_PFAD = re.compile(r"(:[0-9]+(:[0-9]+)?|#L[0-9]+(C[0-9]+)?(-L?[0-9]+(C[0-9]+)?)?)\Z")
_OWASP_KI = re.compile(r"(ASI|LLM)(0[1-9]|10)")
_KLASSE_MODELL_MOCK = re.compile(r"K[124] ")     # `klasse` von K1, K2 und K4: die Wirkung hängt an einer Modellentscheidung (Modell-Mock, TF3)
MAX_OWASP_KI = 3
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_CODE_PFAD = re.compile(r"(.+):([1-9][0-9]*)", re.DOTALL)


class KontextFehler(Exception):
    """Kontext nicht ermittelbar (kein Repo, kein HEAD, ungültiger Teilpfad, Ausgabeordner)."""


# ------------------------------------------------------------------------------------ kontext

def _bereinigen(name: str) -> str | None:
    """Repo-Name auf [A-Za-z0-9._-] beschränken; leer oder nur Punkte → None."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")[:100]
    return None if not name or re.fullmatch(r"\.+", name) else name


def _repo_name(wurzel: str) -> str:
    try:
        url = git(wurzel, "config", "--get", "remote.origin.url").stdout.decode(errors="replace").strip()
    except GitFehler:
        url = ""
    if url:
        basis = re.split(r"[/:\\]", url.rstrip("/\\"))[-1]
        if basis.endswith(".git"):
            basis = basis[:-4]
        name = _bereinigen(basis)
        if name:
            return name
    ordner = wurzel
    try:
        gemeinsam = os.fsdecode(git(wurzel, "rev-parse", "--path-format=absolute", "--git-common-dir")
                                .stdout).rstrip("\n")
        if os.path.basename(gemeinsam) == ".git":
            ordner = os.path.dirname(gemeinsam)
    except GitFehler:
        pass
    return _bereinigen(os.path.basename(ordner)) or "repo"


def _teilpfad(wurzel: str, teilpfad: str, sha: str = "HEAD") -> str:
    """Teilpfad normalisieren und gegen die im Commit `sha` versionierten Pfade prüfen (Schreibweise des Repos)."""
    if not teilpfad or teilpfad.startswith("/") or _t(teilpfad, 10**6) != teilpfad:
        raise KontextFehler(f"Ungültiger Teilpfad (leer, absolut oder mit Steuerzeichen): {_t(teilpfad)}")
    p = teilpfad
    while p.startswith("./"):
        p = p[2:]
    p = p.rstrip("/")
    komps = p.split("/")
    if any(k in ("", ".", "..") for k in komps):
        raise KontextFehler(f"Ungültiger Teilpfad (nur normalisierte relative Pfade ohne '..'): {_t(teilpfad)}")
    ziel = [unicodedata.normalize("NFC", k) for k in komps]
    try:
        baum = git(wurzel, "ls-tree", "-r", "-z", "--name-only", "--full-tree", sha, timeout=120).stdout
    except ZeitbudgetFehler as e:
        raise KontextFehler(_zeitbudget_meldung(e)) from e
    except GitFehler as e:
        raise KontextFehler(f"Dateiliste des Commits nicht lesbar: {_t(e)}") from e
    for roh in baum.split(b"\0"):
        if not roh:
            continue
        echt = os.fsdecode(roh).split("/")
        if [unicodedata.normalize("NFC", k) for k in echt[:len(ziel)]] == ziel:
            return "/".join(echt[:len(ziel)])
    raise KontextFehler(f"Teilpfad nicht im Repo (HEAD): {_t(teilpfad)}")


def _zeitbudget_meldung(e: Exception) -> str:
    return (f"Zeitbudget von bericht.py kontext erschöpft ({_t(e)}). Größere Repos: SECURITY_AUDIT_KONTEXT_TIMEOUT "
            f"(Sekunden, Standard {KONTEXT_BUDGET}) erhöhen; Bash-Limit des Skills sind 600 s.")


def repo_name_von(repo: str) -> str:
    """Name des Repos unter dem Pfad `repo` wie im `kontext`-Feld `repo`, ohne HEAD-Prüfung und ohne Dateien anzulegen;
    wirft KontextFehler (CLI: Exit 3), wenn dort kein git-Repository liegt."""
    try:
        wurzel = os.fsdecode(git(repo, "rev-parse", "--show-toplevel").stdout).rstrip("\n")
    except ZeitbudgetFehler as e:
        raise KontextFehler(_zeitbudget_meldung(e)) from e
    except GitFehler as e:
        raise KontextFehler(f"Kein git-Repository unter {_t(repo)}: {_t(e)}") from e
    return _repo_name(wurzel)


def _slug(teilpfad: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", teilpfad.lower()).strip("-") or "teil"


def kontext(repo: str, teilpfad: str | None, jetzt: datetime | None = None) -> dict:
    """Kontext des Repos unter dem Pfad `repo`; wirft KontextFehler (CLI: Exit 3)."""
    jetzt = jetzt or datetime.now()
    try:
        wurzel = os.fsdecode(git(repo, "rev-parse", "--show-toplevel").stdout).rstrip("\n")
        sha = git(wurzel, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    except ZeitbudgetFehler as e:
        raise KontextFehler(_zeitbudget_meldung(e)) from e
    except GitFehler as e:
        raise KontextFehler(f"Kein git-Repository mit HEAD unter {_t(repo)}: {_t(e)}") from e
    name = _repo_name(wurzel)
    datum = jetzt.strftime("%Y-%m-%d")
    echt = _teilpfad(wurzel, teilpfad, sha) if teilpfad is not None else None
    slug = _slug(echt) if echt is not None else None
    # git-Teil vor der Reservierung: scheitert er (auch am Zeitbudget), bleibt keine `.reserviert`-Datei zurück
    try:
        konfig = [_t(p) for p in gitkopie.repo_konfiguration(wurzel, sha)]
    except ZeitbudgetFehler as e:
        raise KontextFehler(_zeitbudget_meldung(e)) from e
    except GitFehler as e:
        raise KontextFehler(f"Konfiguration in HEAD nicht lesbar: {_t(e)}") from e
    hinweise = gitkopie.repo_hinweise(wurzel, sha)      # git-Fehler werden dort zu Hinweisen; Zeitbudget unten geprüft
    if gitkopie.frist_erschoepft():
        raise KontextFehler(_zeitbudget_meldung(ZeitbudgetFehler("Prüfung des Repos nicht beendet")))

    basis = os.environ.get("SECURITY_AUDIT_AUSGABE")
    ordner = os.path.join(basis, name) if basis else os.path.join(os.path.expanduser("~"), ".claude", "security-reviews", name)
    try:
        ziel_real = os.path.realpath(ordner)
        if os.path.commonpath([ziel_real, os.path.realpath(wurzel)]) == os.path.realpath(wurzel):
            raise KontextFehler(f"Ausgabeordner liegt im geprüften Repo ({_t(ziel_real)}): der Skill schreibt nie ins Repo. "
                                "Setze SECURITY_AUDIT_AUSGABE auf einen Ordner außerhalb.")
        os.makedirs(ordner, exist_ok=True)
        ordner = os.path.realpath(ordner)
    except OSError as e:
        raise KontextFehler(f"Ausgabeordner nicht anlegbar: {_t(e)}") from e

    stamm = f"{datum}-{sha[:7]}" + (f"-{slug}" if slug else "")
    basisname, n = stamm, 1
    while True:
        # Der Name ist erst vergeben, wenn die Reservierung (O_EXCL) angelegt ist: zwei Audits desselben Repos am selben Tag
        # schreiben sonst beide `<basisname>.json` und überschreiben sich.
        if not any(os.path.lexists(os.path.join(ordner, basisname + ext)) for ext in (".md", ".json")):
            try:
                fd = os.open(os.path.join(ordner, basisname + ".reserviert"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:        # was `kontext` ermittelt hat; `rendern` gleicht ab
                    json.dump({"sha": sha, "repo": name, "teilpfad": echt}, fh)
                break
            except FileExistsError:
                pass
            except OSError as e:
                raise KontextFehler(f"Namen im Ausgabeordner nicht reservierbar: {_t(e)}") from e
        n += 1
        basisname = f"{stamm}-{n}"

    if basis:
        stats = os.path.join(ordner, basisname + "-agent-stats.md")
    else:
        stats = os.path.join(os.path.expanduser("~"), ".claude", "agent-stats", name, f"{datum}-security-audit.md")

    return {
        "repo": name, "wurzel": wurzel, "sha": sha, "sha7": sha[:7], "datum": datum,
        "teilpfad": echt, "teilpfad_slug": slug, "ausgabe_ordner": ordner, "basisname": basisname,
        "hinweise": hinweise, "repo_konfiguration": konfig,
        "agent_stats_datei": stats,
    }


# ------------------------------------------------------------------------------------ Schema

_UNSICHTBAR_MELDUNG = "enthält Steuer-, Format- oder unsichtbare Zeichen"


def _text_fehler(wert: object, einzeilig: bool) -> str | None:
    """Fehlertext, wenn `wert` kein nichtleerer Text ist; unsichtbare Zeichen (`gitkopie.unsichtbar`: Steuer-, Format-,
    Bidi-, Zero-Width-Zeichen, Tag-Zeichen, Variation Selectors, nicht zugewiesene Codepoints) sind in jedem Feld verboten
    (versteckter Text aus dem Repo), in mehrzeiligen Feldern außer `\n`, `\r`, `\t`. Einzeilig: zusätzlich keine
    Dreifach-Backticks (würden den Befundlisten-Block verlassen)."""
    if not isinstance(wert, str) or not wert.strip():
        return "muss ein nichtleerer Text sein"
    for ch in wert:
        if gitkopie.unsichtbar(ch) and (einzeilig or ch not in "\n\r\t"):
            return _UNSICHTBAR_MELDUNG + (" (einzeiliges Feld)" if einzeilig else "")
    if einzeilig and "```" in wert:
        return "enthält ``` (einzeiliges Feld)"
    return None


def _hat_unsichtbares(text: str) -> bool:
    return any(gitkopie.unsichtbar(ch) for ch in text)


def _pfad_fehler(pfad: object) -> str | None:
    fehler = _text_fehler(pfad, True)
    if fehler:
        return fehler
    if pfad.startswith("/") or any(k in ("", ".", "..") for k in pfad.split("/")):
        return "muss ein normalisierter relativer Pfad sein (ohne ./, .., //, führenden oder End-/)"
    return None


def _unter_teilpfad(datei: str, teilpfad: str) -> bool:
    """`datei` ist der Teilpfad selbst oder liegt darunter (NFC-normalisiert, `/` am Ende des Teilpfads egal)."""
    t = unicodedata.normalize("NFC", teilpfad).rstrip("/")
    d = unicodedata.normalize("NFC", datei)
    return d == t or d.startswith(t + "/")


def _pakete_fehler(pakete: object) -> list[str]:
    """Fehlertexte (ohne Label) für `pakete`: Liste von höchstens `MAX_PAKETE` Objekten mit `name`, `version` (einzeilige Texte),
    `advisories` (Liste von höchstens `MAX_ADVISORIES` einzeiligen Texten), optional `behoben_in` (Text) und `kev`
    (true/false/null)."""
    if not isinstance(pakete, list) or not pakete:
        return ["muss eine nichtleere Liste von Objekten {name, version, advisories} sein"]
    f: list[str] = []
    if len(pakete) > MAX_PAKETE:
        f.append(f"darf höchstens {MAX_PAKETE} Einträge haben, hat {len(pakete)}")
        pakete = pakete[:MAX_PAKETE]
    for i, p in enumerate(pakete):
        if not isinstance(p, dict):
            f.append(f"[{i}] muss ein Objekt {{name, version, advisories}} sein")
            continue
        for feld in ("name", "version"):
            if feld not in p:
                f.append(f"[{i}].{feld} fehlt")
            elif msg := _text_fehler(p[feld], True):
                f.append(f"[{i}].{feld} {msg}")
        adv = p.get("advisories")
        if "advisories" not in p:
            f.append(f"[{i}].advisories fehlt")
        elif not isinstance(adv, list):
            f.append(f"[{i}].advisories muss eine Liste von Texten sein")
        else:
            if len(adv) > MAX_ADVISORIES:
                f.append(f"[{i}].advisories darf höchstens {MAX_ADVISORIES} Einträge haben, hat {len(adv)}")
            f.extend(f"[{i}].advisories[{j}] {msg}" for j, a in enumerate(adv[:MAX_ADVISORIES]) if (msg := _text_fehler(a, True)))
        if "behoben_in" in p and (msg := _text_fehler(p["behoben_in"], True)):
            f.append(f"[{i}].behoben_in {msg}")
        if "kev" in p and p["kev"] is not None and type(p["kev"]) is not bool:
            f.append(f"[{i}].kev muss true, false oder null sein")
    return f


def _werkzeug_fehler(b: dict) -> tuple[list[str], bool]:
    """(Fehlertexte, gekoppelt) zu `werkzeug`, `commits`, `pakete` eines Befunds. `gekoppelt` heißt: `werkzeug` ist gültig
    und seine Bedingungen sind erfüllt; nur dann genügt ein Code-Pfad mit einem Eintrag. Fehlertexte beginnen mit dem Feldnamen."""
    f: list[str] = []
    werkzeug = b.get("werkzeug") if "werkzeug" in b else None
    gueltig = "werkzeug" in b and isinstance(werkzeug, str) and werkzeug in WERKZEUGE
    if "werkzeug" in b and not gueltig:
        f.append(f"werkzeug muss osv-scanner, gitleaks oder lieferkette sein, ist {_t(werkzeug)!r}")
    if "commits" in b:
        c = b["commits"]
        if werkzeug != "gitleaks":
            f.append("commits nur mit werkzeug gitleaks erlaubt")
        elif not (isinstance(c, list) and 1 <= len(c) <= MAX_COMMITS
                  and all(isinstance(x, str) and _COMMIT.fullmatch(x) for x in c)):
            f.append(f"commits muss eine Liste von 1 bis {MAX_COMMITS} Hex-Hashes (7 bis 64 Zeichen, klein) sein")
    if "pakete" in b:
        if werkzeug != "osv-scanner":
            f.append("pakete nur mit werkzeug osv-scanner erlaubt")
        else:
            f.extend("pakete" + (m if m.startswith("[") else " " + m) for m in _pakete_fehler(b["pakete"]))
    if gueltig:
        kategorie = {"osv-scanner": "A03", "gitleaks": "A07", "lieferkette": "A03"}[werkzeug]
        if b.get("kategorie") != kategorie and "kategorie" in b:
            f.append(f"kategorie muss bei werkzeug {werkzeug} {kategorie} sein, ist {_t(b['kategorie'])!r}")
        if werkzeug == "osv-scanner" and "pakete" not in b:
            f.append("pakete fehlt (werkzeug osv-scanner braucht mindestens ein Paket)")
        if werkzeug == "gitleaks" and "commits" not in b:
            f.append("commits fehlt (werkzeug gitleaks braucht mindestens einen Commit)")
        if werkzeug == "lieferkette" and b.get("klasse") not in LIEFERKETTE_KLASSEN:
            f.append(f"klasse muss bei werkzeug lieferkette {', '.join(LIEFERKETTE_KLASSEN)} sein, ist {_t(b.get('klasse'))!r}")
        if isinstance(b.get("status"), str) and unicodedata.normalize("NFC", b["status"]) == "bestätigt":
            f.append("status bestätigt ist mit werkzeug nicht erlaubt (Werkzeugbefunde sind ohne Request-Beleg höchstens unbestätigt)")
    return f, gueltig and not f


def _befund_fehler(b: dict, label: str, teilpfad: str | None = None) -> list[str]:
    f: list[str] = []

    def fehler(feld: str, text: str) -> None:
        f.append(f"{label}: {feld} {text}")

    for feld in ("stufe", "status", "datei", "zeile", "kategorie", "titel", "beschreibung", "szenario", "erwartet",
                 "klasse", "ohne_anmeldung", "mandantenuebergreifend"):
        if feld not in b:
            f.append(f"{label}: Pflichtfeld fehlt: {feld}")
    if b.get("stufe", "P1") not in STUFEN:
        fehler("stufe", f"muss P1, P2 oder P3 sein, ist {_t(b['stufe'])!r}")
    status = unicodedata.normalize("NFC", b["status"]) if isinstance(b.get("status"), str) else b.get("status")
    if "status" in b and status not in STATUS:
        fehler("status", f"muss bestätigt, unbestätigt, verworfen oder verdacht sein, ist {_t(b['status'])!r}")
    if "kategorie" in b and not (isinstance(b["kategorie"], str) and _KATEGORIE.fullmatch(b["kategorie"])):
        fehler("kategorie", f"muss A01 bis A10 sein (ohne Jahr), ist {_t(b['kategorie'])!r}")
    for feld in ("datei",):
        if feld in b and b[feld] is not None and (msg := _pfad_fehler(b[feld])):
            fehler("datei", msg)
        elif feld in b and isinstance(b[feld], str) and _ZEILE_IM_PFAD.search(b[feld]):
            fehler("datei", "enthält eine Zeilenangabe: Zeile gehört in `zeile`, `datei` ist nur der Pfad")
    if (teilpfad and isinstance(b.get("datei"), str) and not _pfad_fehler(b["datei"])
            and not _unter_teilpfad(b["datei"], teilpfad)):
        fehler("datei", f"liegt außerhalb von teilpfad {_t(teilpfad)!r} (Befunde nur unter dem Teilpfad)")
    if "zeile" in b:
        z = b["zeile"]
        if z is not None and not (type(z) is int and z >= 1):
            fehler("zeile", f"muss eine ganze Zahl ≥ 1 oder null sein, ist {_t(z)!r}")
        elif "datei" in b and b["datei"] is None and z is not None:
            fehler("zeile", "muss null sein, wenn datei null (repo-weit) ist")
    for feld in EINZEILIG:
        if feld in b and (msg := _text_fehler(b[feld], True)):
            fehler(feld, msg)
    if "beschreibung" in b and (msg := _text_fehler(b["beschreibung"], False)):
        fehler("beschreibung", msg)
    for feld in ("ohne_anmeldung", "mandantenuebergreifend"):
        if feld in b and type(b[feld]) is not bool:
            fehler(feld, "muss true oder false sein")

    if "owasp_ki" in b:
        ids = b["owasp_ki"]
        if not (isinstance(ids, list) and 1 <= len(ids) <= MAX_OWASP_KI
                and all(isinstance(x, str) and _OWASP_KI.fullmatch(x) for x in ids) and len(set(ids)) == len(ids)):
            fehler("owasp_ki", f"muss eine Liste von 1 bis {MAX_OWASP_KI} verschiedenen IDs aus ASI01 bis ASI10 "
                               f"oder LLM01 bis LLM10 sein, ist {_t(ids)!r}")
    if "annahme_modell" in b:
        if type(b["annahme_modell"]) is not bool:
            fehler("annahme_modell", "muss true oder false sein")
        elif b["annahme_modell"] and status != "bestätigt":
            fehler("annahme_modell", "true ist nur mit status bestätigt erlaubt")
        elif b["annahme_modell"] and not (isinstance(b.get("klasse"), str) and _KLASSE_MODELL_MOCK.match(b["klasse"])):
            fehler("annahme_modell", "true ist nur bei K1, K2 oder K4 erlaubt (nur dort hängt die Wirkung an einer Modellentscheidung)")
    if (status == "bestätigt" and isinstance(b.get("klasse"), str) and _KLASSE_MODELL_MOCK.match(b["klasse"])
            and b.get("annahme_modell") is not True and type(b.get("annahme_modell", False)) is bool):
        fehler("annahme_modell", "K1, K2 oder K4 mit status bestätigt beruht auf dem Modell-Mock und braucht annahme_modell true "
                                 "(sonst steht „bestätigt“ ohne die Annahme im Bericht)")

    if "poc" in b:
        if msg := _text_fehler(b["poc"], False):
            fehler("poc", msg)
        else:
            f.extend(f"{label}: poc enthält nicht erlaubten Host: {_t(h)}" for h in netzregel.verstoesse_poc(b["poc"]))
    elif status == "bestätigt":
        f.append(f"{label}: Pflichtfeld fehlt: poc (Status bestätigt)")
    werkzeug_fehler, gekoppelt = _werkzeug_fehler(b)
    f.extend(f"{label}: {m}" for m in werkzeug_fehler)
    if "code_pfad" in b:
        cp = b["code_pfad"]
        # Werkzeugbefund: nur bei erfüllter Kopplung genügt ein Eintrag (kein Request-Pfad möglich)
        if not isinstance(cp, list) or len(cp) < (1 if gekoppelt else 2):
            fehler("code_pfad", "muss eine Liste von mindestens 1 Eintrag datei:zeile sein" if gekoppelt
                   else "muss eine Liste von mindestens 2 Einträgen datei:zeile sein")
        else:
            for i, eintrag in enumerate(cp):
                m = _CODE_PFAD.fullmatch(eintrag) if isinstance(eintrag, str) else None
                if not m or _pfad_fehler(m.group(1)):
                    fehler(f"code_pfad[{i}]", f"muss datei:zeile (Zeile ≥ 1, normalisierter Pfad) sein, ist {_t(eintrag)!r}")
    elif status == "unbestätigt":
        f.append(f"{label}: Pflichtfeld fehlt: code_pfad (Status unbestätigt)")
    if "grund" in b:
        if msg := _text_fehler(b["grund"], True):
            fehler("grund", msg)
    elif status == "verworfen":
        f.append(f"{label}: Pflichtfeld fehlt: grund (Status verworfen)")
    return f


def pruefe_schema(daten: object) -> list[str]:
    """Fehlerliste (leer = gültig); wirft nie, egal welche Typen im JSON stehen."""
    if not isinstance(daten, dict):
        return ["Wurzel muss ein JSON-Objekt sein"]
    f: list[str] = []
    for feld in ("version", "repo", "sha", "datum", "teilpfad", "projekt", "karte", "hinweise", "befunde"):
        if feld not in daten:
            f.append(f"Pflichtfeld fehlt: {feld}")
    if "version" in daten and not (type(daten["version"]) is int and daten["version"] == 1):
        f.append("version muss 1 sein")
    muster = {"repo": (r"[A-Za-z0-9._-]+", "nur [A-Za-z0-9._-]"), "sha": (r"[0-9a-f]{7,64}", "Hex-Hash (7 bis 64 Zeichen)"),
              "datum": (r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "YYYY-MM-DD")}
    for feld, (regex, hilfe) in muster.items():
        if feld in daten and not (isinstance(daten[feld], str) and re.fullmatch(regex, daten[feld])):
            f.append(f"{feld} ungültig: erwartet {hilfe}, ist {_t(daten[feld])!r}")
    if isinstance(daten.get("repo"), str) and re.fullmatch(r"\.+", daten["repo"]):
        f.append("repo ungültig: nur Punkte")
    for feld in ("teilpfad", "projekt"):
        if daten.get(feld) is not None and (msg := _text_fehler(daten[feld], True)):
            f.append(f"{feld} {msg}")
    if "karte" in daten:
        k = daten["karte"]
        if not isinstance(k, list):
            f.append("karte muss eine Liste sein")
        else:
            for i, e in enumerate(k):
                if not (isinstance(e, dict) and isinstance(e.get("flaeche"), str) and isinstance(e.get("dateien"), list)
                        and all(isinstance(d, str) for d in e["dateien"])):
                    f.append(f"karte[{i}] muss {{flaeche: Text, dateien: [Text]}} sein")
                elif any(_hat_unsichtbares(t) for t in [e["flaeche"], *e["dateien"]]):
                    f.append(f"karte[{i}] {_UNSICHTBAR_MELDUNG}")
    if "hinweise" in daten:
        h = daten["hinweise"]
        if not (isinstance(h, list) and all(isinstance(x, str) for x in h)):
            f.append("hinweise muss eine Liste von Texten sein")
        else:
            f.extend(f"hinweise[{i}] {_UNSICHTBAR_MELDUNG}" for i, x in enumerate(h) if _hat_unsichtbares(x))
    if "befunde" in daten:
        if not isinstance(daten["befunde"], list):
            f.append("befunde muss eine Liste sein")
        else:
            gesehen: set[str] = set()
            for i, b in enumerate(daten["befunde"]):
                if not isinstance(b, dict):
                    f.append(f"befunde[{i}] muss ein Objekt sein")
                    continue
                bid = b.get("id")
                if isinstance(bid, str) and _ID.fullmatch(bid):
                    label = bid
                    if bid in gesehen:
                        f.append(f"{bid}: id doppelt")
                    gesehen.add(bid)
                else:
                    label = f"befunde[{i}]"
                    f.append(f"{label}: " + ("Pflichtfeld fehlt: id" if "id" not in b
                                              else f"id muss S-<Zahl> sein, ist {_t(bid)!r}"))
                f.extend(_befund_fehler(b, label, daten["teilpfad"] if isinstance(daten.get("teilpfad"), str) else None))
    return f


# ------------------------------------------------------------------------------------ Markdown

def _inline(text: object) -> str:
    """Nicht validierten Text (Karte, Hinweise) einzeilig machen, unsichtbare Zeichen als Escape-Sequenz zeigen; Backticks und Tilden escapen (kein Codezaun möglich)."""
    return _t(" ".join(str(text).split()), 10**6).replace("`", "\\`").replace("~", "\\~")


def _block(inhalt: str) -> list[str]:
    """Inhalt in einen Zaun aus mindestens vier Backticks setzen, länger als jede Backtick-Folge darin."""
    laengste = max((len(m) for m in re.findall(r"`+", inhalt)), default=0)
    zaun = "`" * max(4, laengste + 1)
    return ["", zaun, inhalt.rstrip("\n"), zaun]


def _ort(b: dict) -> str:
    if b["datei"] is None:
        return "(repo-weit)"
    return b["datei"] if b["zeile"] is None else f"{b['datei']}:{b['zeile']}"


def _sortiert(befunde: list[dict]) -> list[dict]:
    return sorted(befunde, key=lambda b: (STUFEN.index(b["stufe"]), int(b["id"][2:])))


def markdown(daten: dict) -> str:
    """Bericht als Markdown; erwartet ein mit pruefe_schema geprüftes Dokument."""
    status = lambda b: unicodedata.normalize("NFC", b["status"])  # noqa: E731
    befunde = _sortiert(daten["befunde"])
    gelistet = [b for b in befunde if status(b) in IN_LISTE]
    z = [f"# Security-Audit {daten['repo']} · {daten['datum']}", "", "```",
         f"Repo {daten['repo']} · Security-Audit · geprüft auf {daten['sha']}"]
    for b in gelistet:
        z += [f"{b['id']} [{b['stufe']}] {_ort(b)} — {b['titel']}",
              f"       Szenario: {b['szenario']}", f"       Erwartet: {b['erwartet']}",
              f"       Klasse: {b['klasse']}"]
    verdacht = [f"{b['id']} {b['titel']}" for b in befunde if status(b) == "verdacht"]
    if verdacht:
        z.append("Verdacht (nicht belegt): " + "; ".join(verdacht))
    z += [f"Verworfen: {b['titel']} — {b['grund']}" for b in befunde if status(b) == "verworfen"]
    z.append("```")

    if daten.get("projekt") or daten.get("teilpfad"):
        z += ["", "## Überblick"]
        if daten.get("projekt"):
            z.append(f"- Projekt: {daten['projekt']}")
        if daten.get("teilpfad"):
            z.append(f"- Teilpfad: {daten['teilpfad']}")
    if daten["karte"]:
        z += ["", "## Karte"]
        z += [f"- {_inline(e['flaeche'])}: {', '.join(_inline(d) for d in e['dateien'])}" for e in daten["karte"]]
    if gelistet:
        z += ["", "## Befunde im Detail"]
        for b in gelistet:
            anzeige = status(b) + (" (Modell-Mock, Annahme: Modell folgt)" if b.get("annahme_modell") is True else "")
            z += ["", f"### {b['id']} [{b['stufe']}] {b['titel']}", "",
                  f"- Status: {anzeige}", f"- Ort: {_ort(b)}", f"- Kategorie: {b['kategorie']}",
                  f"- Ohne Anmeldung: {'ja' if b['ohne_anmeldung'] else 'nein'}",
                  f"- Mandantenübergreifend: {'ja' if b['mandantenuebergreifend'] else 'nein'}"]
            if b.get("owasp_ki"):
                z.append(f"- OWASP KI: {', '.join(b['owasp_ki'])}")
            z += ["", "Beschreibung:"] + _block(b["beschreibung"])
            if b.get("poc"):
                z += ["", "PoC:"] + _block(b["poc"])
            if b.get("commits"):
                rest = len(b["commits"]) - MARKDOWN_COMMITS
                z += ["", "Commits: " + ", ".join(c[:7] for c in b["commits"][:MARKDOWN_COMMITS])
                      + (f" (+{rest})" if rest > 0 else "")]
            if b.get("pakete"):
                z += ["", "Pakete: " + "; ".join(
                    _inline(f"{p['name']}@{p['version']}") + (f" ({_inline(', '.join(p['advisories']))})" if p["advisories"] else "")
                    for p in b["pakete"])]
            if b.get("code_pfad"):
                z += ["", "Code-Pfad:"] + [f"1. {_inline(p)}" for p in b["code_pfad"]]
    if daten["hinweise"]:
        z += ["", "## Hinweise"] + [f"- {_inline(h)}" for h in daten["hinweise"]]
    return "\n".join(z) + "\n"


# ------------------------------------------------------------------------------------ CLI

def _reservierung_abweichungen(marker: str, daten: dict) -> list[str]:
    """`sha`, `repo`, `teilpfad` des JSON gegen die Reservierung von `kontext` (gleicher Basisname). Ohne Reservierung (JSON
    von Hand oder älterer Lauf): keine Prüfung. Unlesbare Reservierung: Warnung auf stderr, keine Prüfung."""
    try:
        with open(marker, encoding="utf-8") as f:
            erwartet = json.load(f)
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        erwartet = None
    if not isinstance(erwartet, dict):
        print("Hinweis: Reservierung ohne lesbare Daten, sha/repo/teilpfad nicht geprüft", file=sys.stderr)
        return []
    return [f"{feld} ist {_t(daten.get(feld))!r}, `kontext` ermittelte {_t(erwartet.get(feld))!r}"
            for feld in ("sha", "repo", "teilpfad") if daten.get(feld) != erwartet.get(feld)]


def _rendern(pfad: str) -> int:
    try:
        if os.path.getsize(pfad) > MAX_JSON_BYTES:
            raise ValueError("Datei größer als 16 MB")
        with open(pfad, "rb") as fh:
            daten = json.loads(fh.read())
    except (OSError, ValueError, RecursionError) as e:
        print(f"JSON nicht lesbar: {_t(e)}", file=sys.stderr)
        return 2
    fehler = pruefe_schema(daten)
    if fehler:
        print(f"Schemafehler ({len(fehler)}):", file=sys.stderr)
        print("\n".join(f"- {x}" for x in fehler), file=sys.stderr)
        return 2
    ziel = os.path.splitext(pfad)[0] + ".md"
    if os.path.abspath(ziel) == os.path.abspath(pfad):
        print("Ziel wäre die Eingabedatei selbst", file=sys.stderr)
        return 2
    abweichungen = _reservierung_abweichungen(os.path.splitext(pfad)[0] + ".reserviert", daten)
    if abweichungen:
        print("Abweichung von der Reservierung durch `bericht.py kontext` (der Bericht nennt nicht, was ermittelt wurde):",
              file=sys.stderr)
        print("\n".join(f"- {x}" for x in abweichungen), file=sys.stderr)
        return 2
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".bericht-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(ziel)))
        with os.fdopen(fd, "wb") as fh:
            fh.write(markdown(daten).encode("utf-8", "replace"))
        os.replace(tmp, ziel)
        tmp = None
    except OSError as e:
        print(f"Schreiben fehlgeschlagen: {_t(e)}", file=sys.stderr)
        return 2
    finally:
        if tmp is not None and os.path.lexists(tmp):       # Fehler zwischen mkstemp und replace: keine Reste im Ausgabeordner
            os.unlink(tmp)
    try:
        os.unlink(os.path.splitext(pfad)[0] + ".reserviert")       # Reservierung von `kontext` freigeben
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"Hinweis: Reservierung nicht entfernt: {_t(e)}", file=sys.stderr)
    print(ziel)
    return 0


_WERT_OPTIONEN = ("--teilpfad", "--repo")


def _argv_mit_werten(argv: list[str]) -> list[str]:
    """`--teilpfad -x` wird zu `--teilpfad=-x`: das Argument nach `--teilpfad`/`--repo` ist immer der Wert, auch wenn es mit
    `-` beginnt (argparse hielte es für eine Option und endete mit Exit 2; ein nicht vorhandener Teilpfad ist Exit 3)."""
    aus: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] in _WERT_OPTIONEN and i + 1 < len(argv):
            aus.append(f"{argv[i]}={argv[i + 1]}")
            i += 2
        else:
            aus.append(argv[i])
            i += 1
    return aus


def _kontext_budget() -> float:
    """Gesamtbudget von `kontext`: SECURITY_AUDIT_KONTEXT_TIMEOUT (Sekunden, > 0) oder 300 s; ein ungültiger Wert ist ein Fehler."""
    roh = os.environ.get("SECURITY_AUDIT_KONTEXT_TIMEOUT")
    if roh is None or roh == "":
        return KONTEXT_BUDGET
    try:
        sekunden = float(roh)
    except ValueError:
        sekunden = 0.0
    if not sekunden > 0 or sekunden != sekunden or sekunden == float("inf"):
        raise KontextFehler(f"SECURITY_AUDIT_KONTEXT_TIMEOUT={_t(roh)} ungültig (erwartet: Sekunden > 0)")
    return sekunden


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="bericht.py")
    sub = ap.add_subparsers(dest="befehl", required=True)
    k = sub.add_parser("kontext")
    k.add_argument("--teilpfad")
    k.add_argument("--repo", default=".")
    rp = sub.add_parser("repo")
    rp.add_argument("--repo", default=".")
    r = sub.add_parser("rendern")
    r.add_argument("json")
    args = ap.parse_args(_argv_mit_werten(argv))
    if args.befehl == "rendern":
        return _rendern(args.json)
    if args.befehl == "repo":
        try:
            name = repo_name_von(args.repo)
        except KontextFehler as e:
            print(str(e), file=sys.stderr)
            return 3
        print(name)
        return 0
    try:
        gitkopie.frist_setzen(time.monotonic() + _kontext_budget())
        ergebnis = kontext(args.repo, args.teilpfad)
    except KontextFehler as e:
        print(str(e), file=sys.stderr)
        return 3
    finally:
        gitkopie.frist_setzen(None)
    print(json.dumps(ergebnis, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
