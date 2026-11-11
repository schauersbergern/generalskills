"""Kontext und Bericht des Skills security-audit.

  bericht.py kontext [--teilpfad P] [--repo R]   JSON mit Repo-Kontext auf stdout (Exit 3: kein Repo/HEAD,
                                                  ungültiger Teilpfad; das Argument nach `--teilpfad` ist immer der
                                                  Wert, auch `-x`, oder `--teilpfad=-x`)
  bericht.py repo [--repo R]                      Repo-Name (genau `kontext`-Feld `repo`) auf stdout, ohne Seiteneffekte
                                                  (Exit 3: kein Repo)
  bericht.py rendern <json>                       Schema prüfen, <basisname>.md neben das JSON schreiben
                                                  (Exit 2 mit Fehlerliste auf stderr; Treffer der Kundenregeln nur als Warnung,
                                                  Exit 0)

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
KUNDENFELDER = {"zusammenfassung": (40, 600), "massnahme": (20, 400)}       # optional; Länge in Zeichen (min, max)
KUNDEN_REGELN = ("du", "a", "b", "c", "d", "e", "url", "email")         # Werte von `regel` in kunden_verstoesse


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
    ordner_name = _bereinigen(os.path.basename(wurzel))         # `ordner` unten ist der Ausgabeordner, nicht dieser Name
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
        "repo": name, "ordner": ordner_name, "wurzel": wurzel, "sha": sha, "sha7": sha[:7], "datum": datum,
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
    for feld, (mini, maxi) in KUNDENFELDER.items():        # optional; Inhaltsregeln stehen in `kunden_verstoesse`, nicht hier
        if feld not in b:
            continue
        if msg := _text_fehler(b[feld], True):
            fehler(feld, msg)
        elif len(b[feld].strip()) < mini:
            fehler(feld, f"kürzer als {mini} Zeichen")
        elif len(b[feld]) > maxi:
            fehler(feld, f"länger als {maxi} Zeichen")
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
    if daten.get("ordner") is not None:         # optional (fehlt oder null erlaubt); sonst wie `repo`
        o = daten["ordner"]
        if not (isinstance(o, str) and re.fullmatch(r"[A-Za-z0-9._-]+", o)):
            f.append(f"ordner ungültig: erwartet nur [A-Za-z0-9._-], ist {_t(o)!r}")
        elif re.fullmatch(r"\.+", o):
            f.append("ordner ungültig: nur Punkte")
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


# ------------------------------------------------------------------------------------ Kundenprüfung

# Inhaltsregeln für Kundentexte (TF4). Geprüft werden Rohwerte nach NFKC (TF4 Härtung: Vollbreiten-Zeichen und Ligaturen zählen wie die
# gewöhnlichen; der Status und die Pfade des Schemas bleiben NFC), nie das erzeugte Markdown; Regex-Regeln mit
# re.IGNORECASE, Teilstring-Abgleiche (a, e, d mit Pfad) ohne Beachtung der Großschreibung. Meldungen nennen nie den
# Treffertext, nur bei `du` das Wort und bei `a` das Token (beides stammt aus dem JSON der Hauptsession).
_DU_FORMEN = ("du", "dich", "dir", "dein", "deine", "deinen", "deinem", "deiner", "deines",
              "euch", "euer", "eure", "euren", "eurem", "eurer", "eures")
# Grenzen nach Spec B1; am Ende darf ein Satzpunkt folgen (`dir.` am Satzende), nicht aber `.<Wortzeichen>` (`dir.json`)
_DU = re.compile(r"(?<![\w./@-])(?:" + "|".join(_DU_FORMEN) + r")(?![\w/@-])(?!\.\w)", re.IGNORECASE)
# Request: HTTP-Methode vor einem Pfad (auch `POST-/api`) oder irgendein Pfad mit führendem Schrägstrich (R1-1; unabhängig vom `poc`).
# `und/oder`, `24/7`, `TCP/IP`, `Lese-/Schreibrechte` und ` / ` haben ein Wortzeichen oder `-` vor dem Strich bzw. ein Leerzeichen danach.
_REGEL_B_METHODE = r"\b(?:GET|POST|PUT|PATCH|DELETE)[\s-]+/"
_REGEL_B = re.compile(_REGEL_B_METHODE + r"|(?<![\w/:-])/(?=[\w.~%@-])", re.IGNORECASE)
_REGEL_B_KOPF = re.compile(_REGEL_B_METHODE, re.IGNORECASE)    # Kopfangaben (vom Nutzer benannt): nur der Request; ein Pfad darin ist Regel a oder frei
_REGEL_C = re.compile(r"[{}<>=`]")
_REGEL_C_TITEL = re.compile(r"[{}=`]")                  # im Titel sind `<` und `>` erlaubt (`name@1.2.3`, Vergleiche in Werkzeugtiteln)
_D_LAUF = re.compile(r"(?<![\w./-])[\w./-]+")          # `Pfad:Zahl` ohne Backtracking: Lauf suchen, dann Zeichen danach prüfen
_D_MUSTER = re.compile(r"#L\d+|\bZeile\s+\d+", re.IGNORECASE)
_URL = re.compile(r"https?://|\bwww\.", re.IGNORECASE)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b", re.IGNORECASE)
_TAUSENDER = re.compile(r"\d{1,3}(?:\.\d{3})+(?:,\d+)?")
_A_ZEICHEN = frozenset("/=?&%<>{}_@$\\[]")
_A_PUNKT = re.compile(r"\w\.\w")
_A_RAND = ".,;:()\"'"
_A_VERSION = re.compile(r"v?\d+(?:\.\d+){1,2}")                 # `4.17.1`, `v4.17`; vier Teile (`10.0.0.5`) sind eine Adresse und bleiben Token
_A_DATEINAME = re.compile(r"[A-Za-z][\w-]*\.(?:js|ts|mjs|cjs|json|md|html|css)", re.IGNORECASE)   # `Node.js`, `package.json` (ohne / = ? & %)
_MAX_TOKEN = 200000      # Token aus `poc` je Bericht; darüber ist jedes geprüfte Feld ein Verstoß gegen Regel a (fail-closed)
_MAX_POC = 10**6         # Zeichen je `poc`; ein längerer `poc` zählt wie zu viele Token (fail-closed, nie still abgeschnitten)
_MAX_SCHRITTE = 5_000_000  # Teilstring-Prüfungen der Regeln a, d und e je Bericht (~1 s); danach wie zu viele Token (fail-closed)
ZU_VIELE_TOKEN = "zu viele Token zum Prüfen"
_KUNDEN_DETAIL = {                                   # fester Text je Regel (außer `du` und `a` der Befundfelder), nie Treffertext
    "a": "Text aus einem poc", "b": "Request oder Pfad mit Schrägstrich", "c": "Sonderzeichen oder Backtick", "d": "Datei mit Zeilenangabe",
    "e": "Dateipfad aus einem Befund", "url": "Webadresse", "email": "E-Mail-Adresse",
}
_KUNDEN_FELDER = (("zusammenfassung", KUNDEN_REGELN), ("massnahme", KUNDEN_REGELN),
                  ("titel", ("a", "b", "c", "d", "e", "url", "email")))           # Titel: alle Regeln außer `du` (TF4 Review 2, I1)
_MAX_PRUEF = 5000        # Zeichen je Feld; hält die Regex-Prüfung auch bei übergroßen Texten schnell


def _pruef_text(wert: object) -> str | None:
    return unicodedata.normalize("NFKC", wert[:_MAX_PRUEF]) if isinstance(wert, str) else None


def _d_allgemein(text: str) -> bool:
    """`<Pfad mit . oder />:<Zahl>`, `#L<Zahl>` oder `Zeile <Zahl>` (nicht `14:30`)."""
    if _D_MUSTER.search(text):
        return True
    for m in _D_LAUF.finditer(text):
        nach = text[m.end():m.end() + 2]
        if len(nach) == 2 and nach[0] == ":" and re.match(r"\d", nach[1]) and ("." in m.group() or "/" in m.group()):
            return True
    return False


def _regex_treffer(text: str, titel: bool = False) -> dict[str, list[str]]:
    t: dict[str, list[str]] = {}
    if woerter := [m.group() for m in _DU.finditer(text)]:
        t["du"] = woerter
    for regel, muster in (("b", _REGEL_B), ("c", _REGEL_C_TITEL if titel else _REGEL_C)):
        if muster.search(text):
            t[regel] = [_KUNDEN_DETAIL[regel]]
    if _d_allgemein(text):
        t["d"] = [_KUNDEN_DETAIL["d"]]
    if _URL.search(text):
        t["url"] = [_KUNDEN_DETAIL["url"]]
    if "@" in text and _EMAIL.search(text):
        t["email"] = [_KUNDEN_DETAIL["email"]]
    return t


def _treffer_liste(t: dict[str, list[str]], regeln: tuple[str, ...]) -> list[tuple[str, str]]:
    aus: list[tuple[str, str]] = []
    for regel in KUNDEN_REGELN:
        if regel in regeln:
            aus.extend((regel, d) for d in dict.fromkeys(t.get(regel, [])))
    return aus


def text_verstoesse(text: str) -> list[tuple[str, str]]:
    """Treffer der textbezogenen Kundenregeln `du`, `b`, `c`, `d` (ohne Pfadteile), `url`, `email` als (regel, detail);
    `detail` ist bei `du` das gefundene Wort, sonst ein fester Text. Ohne Bezug zum JSON (für feste Bausteine). Wirft bei jedem Typ
    von `text` nicht; eine Ausnahme aus der Prüfung selbst wird nicht verschluckt (ein Fehler dort ist kein „keine Verstöße“)."""
    roh = _pruef_text(text)
    return [] if roh is None else _treffer_liste(_regex_treffer(roh), ("du", "b", "c", "d", "url", "email"))


def _poc_token(poc: str) -> list[str]:
    """Token eines `poc` nach Spec R2-B-1: Whitespace-getrennt, Rand `.,;:()"'` abgeschnitten, mindestens 6 Zeichen und
    ein Zeichen aus `/ = ? & % < > { } _ @ $ \\ [ ]` oder `\\w.\\w`; Zahlen mit Tausenderpunkten zählen nie.
    Bewusste Abweichung von R2-B-1 (Review 1, I-1; enger gefasst in Review 2, N-2): Versionsnummern mit zwei oder drei Teilen
    (`4.17.1`, `v4.17`; vier Teile wie `10.0.0.5` sind Adressen und bleiben Token), `Wort.endung` ohne `/ = ? & %` nur mit der Endung
    js, ts, mjs, cjs, json, md, html oder css (`Node.js`, `package.json`; `admin.php`, `poc.py`, `evil.com` bleiben Token) und
    `und/oder` zählen nie; sie sind im Kundentext legitim. Schneidet nie ab: `_quellen` lässt nur `poc` bis `_MAX_POC` Zeichen herein."""
    aus: dict[str, None] = {}
    for roh in unicodedata.normalize("NFKC", poc).split():
        tok = roh.strip(_A_RAND)
        if (len(tok) >= 6 and (_A_ZEICHEN.intersection(tok) or _A_PUNKT.search(tok)) and not _TAUSENDER.fullmatch(tok)
                and not _A_VERSION.fullmatch(tok) and not _A_DATEINAME.fullmatch(tok) and tok.casefold() != "und/oder"):
            aus[tok] = None
    return list(aus)


def _kuerzen60(token: str) -> str:
    kurz = _t(token, 60)
    return kurz if len(kurz) <= 60 else kurz[:59] + "…"


def _quellen(befunde: list) -> tuple[list[str], list[str], list[str], bool]:
    """(Token aus allen `poc`, Pfadangaben mit `/` bzw. volle `code_pfad`-Einträge für e, alle Pfade und Basenames für d, zu viele
    Token) über alle Befunde, unabhängig vom Status. Mehr als `_MAX_TOKEN` Token oder ein `poc` über `_MAX_POC` Zeichen: die
    Token-Liste bleibt leer, das Flag ist gesetzt (der Aufrufer meldet dann jedes geprüfte Feld als Verstoß gegen Regel a)."""
    token: dict[str, None] = {}
    e: dict[str, None] = {}
    d: dict[str, None] = {}

    def pfad(p: str, voll: bool = False) -> None:
        p = unicodedata.normalize("NFKC", p[:10**4])
        if not p:
            return
        if voll or "/" in p:
            e[p] = None
        d[p] = None
        d[p.rsplit("/", 1)[-1] or p] = None

    zu_viele = False
    for b in befunde:
        if not isinstance(b, dict):
            continue
        if isinstance(b.get("poc"), str) and not zu_viele:
            if len(b["poc"]) > _MAX_POC:
                zu_viele = True
            else:
                token.update(dict.fromkeys(_poc_token(b["poc"])))
                zu_viele = len(token) > _MAX_TOKEN
            if zu_viele:
                token.clear()
        if isinstance(b.get("datei"), str):
            pfad(b["datei"])
        cp = b.get("code_pfad")
        for eintrag in (cp if isinstance(cp, list) else []):
            if not isinstance(eintrag, str):
                continue
            e[unicodedata.normalize("NFKC", eintrag[:10**4])] = None
            if m := _CODE_PFAD.fullmatch(eintrag[:10**4]):
                pfad(m.group(1))
    e.pop("", None)
    return list(token), list(e), list(d), zu_viele


def _pfad_zeile(pfad: str) -> re.Pattern:
    return re.compile(r"(?<![\w./-])" + re.escape(pfad) + r"(?:\s*:\s*\d+|,?\s*(?:Zeile|Z\.)\s*\d+)", re.IGNORECASE)


class _ZuVieleSchritte(Exception):
    """Das Arbeitsbudget (`_MAX_SCHRITTE`) der Teilstring-Prüfungen ist verbraucht."""


class _Nadeln:
    """Teilstring-Suche vieler Nadeln (klein geschrieben) in einem Text: je Nadellänge (höchstens 6) wird nur der Anfang der Nadel
    als n-Gramm des Textes nachgeschlagen, erst dann der ganze Teilstring geprüft. Laufzeit je Text ~ Textlänge statt Nadelzahl,
    solange wenige Nadeln dasselbe n-Gramm als Anfang haben. Haben sehr viele Nadeln denselben Anfang, der auch im Text steht,
    wäre jede einzeln zu prüfen (TF4 Re-Review 1, N-3: 17 s bei 190000 Token); `arbeit` (eine Liste mit dem Rest, von mehreren
    Instanzen geteilt) begrenzt das: ist er verbraucht, wirft `finde` `_ZuVieleSchritte`."""

    def __init__(self, nadeln: list[tuple[str, object]], arbeit: list[int] | None = None):
        self._arbeit = [_MAX_SCHRITTE] if arbeit is None else arbeit
        self._nach_laenge: dict[int, dict[str, list[tuple[int, str, object]]]] = {}
        for i, (klein, nutzlast) in enumerate(nadeln):
            if klein:
                n = min(len(klein), 6)
                self._nach_laenge.setdefault(n, {}).setdefault(klein[:n], []).append((i, klein, nutzlast))

    def finde(self, klein: str) -> list[object]:
        """Nutzlasten aller Nadeln, die in `klein` vorkommen, in der Reihenfolge der Nadeln."""
        treffer: dict[int, object] = {}
        for n, tabelle in self._nach_laenge.items():
            for gramm in {klein[i:i + n] for i in range(len(klein) - n + 1)}.intersection(tabelle):
                kandidaten = tabelle[gramm]
                self._arbeit[0] -= len(kandidaten)
                if self._arbeit[0] < 0:
                    raise _ZuVieleSchritte
                treffer.update((i, nutzlast) for (i, nadel, nutzlast) in kandidaten if nadel in klein)
        return [treffer[i] for i in sorted(treffer)]


def _felder_pruefen(befunde: list, zu_viele: bool, nadeln_a: "_Nadeln | None", nadeln_e: "_Nadeln | None",
                    nadeln_d: "_Nadeln | None") -> list[tuple[str, str, str, str]]:
    """Die Feldprüfung von `kunden_verstoesse`; ohne Nadeln (`zu_viele`) gelten nur die Regex-Regeln und a als Verstoß je Feld."""
    aus: list[tuple[str, str, str, str]] = []
    for b in befunde:
        if not (isinstance(b, dict) and isinstance(b.get("id"), str) and _ID.fullmatch(b["id"])):
            continue
        status = unicodedata.normalize("NFC", b["status"]) if isinstance(b.get("status"), str) else None
        if status not in IN_LISTE:
            continue
        for feld, regeln in _KUNDEN_FELDER:
            text = _pruef_text(b.get(feld))
            if text is None:
                continue
            klein = text.lower()
            t = _regex_treffer(text, titel=feld == "titel")
            if "a" in regeln and zu_viele:
                t["a"] = [ZU_VIELE_TOKEN]
            elif "a" in regeln and nadeln_a is not None and (hits := nadeln_a.finde(klein)):
                t["a"] = [_kuerzen60(k) for k in hits]
            if "e" in regeln and nadeln_e is not None and nadeln_e.finde(klein):
                t["e"] = [_KUNDEN_DETAIL["e"]]
            if "d" not in t and nadeln_d is not None and any(_pfad_zeile(p).search(text) for p in nadeln_d.finde(klein)):
                t["d"] = [_KUNDEN_DETAIL["d"]]
            aus.extend((b["id"], feld, regel, detail) for regel, detail in _treffer_liste(t, regeln))
    return aus


def kunden_verstoesse(daten: object) -> list[tuple[str, str, str, str]]:
    """Verstöße der Kundenfelder gegen die Inhaltsregeln als (id, feld, regel, detail); wirft bei keinem Typ im JSON.

    Geprüft werden Befunde mit Status bestätigt/unbestätigt (NFC) und je Feld einzeln, was vorhanden und Text ist:
    `zusammenfassung`, `massnahme` (alle Regeln) und `titel` (alle außer `du`; bei `c` ohne `<` und `>`). Fehlende Felder meldet erst
    kundenbericht.py.
    Regeln (Werte von KUNDEN_REGELN): `du` Du-Form (detail: das Wort), `a` Token aus einem `poc` (detail: das Token, höchstens 60
    Zeichen), `b` Request (HTTP-Methode vor einem Pfad) oder Pfad mit führendem Schrägstrich, `c` `{ } < > =` oder Backtick, `d` Datei mit Zeile (auch `Dockerfile:6`), `#L<n>`,
    `Zeile <n>`, `e` Dateipfad oder `code_pfad`-Eintrag eines Befunds (ohne Ausnahme, auch die eigene `datei`), `url` Webadresse,
    `email` E-Mail-Adresse. Quellen für a, d und e sind alle Befunde unabhängig vom Status.
    `detail` ist bei b, c, d, e, url und email ein fester Text ohne Treffertext (die Exit-2-Zeile von kundenbericht.py darf ihn
    ausgeben), bei `du` das Wort, bei `a` das Token.
    Fail-closed mit festem Detail „zu viele Token zum Prüfen“ (Regel a bei jedem geprüften Feld: `zusammenfassung`, `massnahme`,
    `titel`): mehr als 200000 Token in den `poc`-Feldern, ein `poc` über 10**6 Zeichen oder mehr als 5 Mio. Teilstring-Prüfungen
    (nur bei sehr vielen Token oder Pfaden mit gleichem Anfang; gewöhnliche Berichte brauchen einen Bruchteil). Die Funktion hat
    keine Seiteneffekte (keine Ausgabe auf stderr). Eine Ausnahme aus der Prüfung selbst wird nicht verschluckt: Aufrufer
    behandeln sie als „Prüfung nicht möglich“, nie als „keine Verstöße“."""
    if not isinstance(daten, dict) or not isinstance(daten.get("befunde"), list):
        return []
    befunde = daten["befunde"]
    token, pfade_e, pfade_d, zu_viele = _quellen(befunde)
    arbeit = [_MAX_SCHRITTE]
    nadeln_a = _Nadeln([(k.lower(), k) for k in token], arbeit)            # einmal vorab klein schreiben und indizieren (Laufzeit)
    nadeln_e = _Nadeln([(p.lower(), p) for p in pfade_e], arbeit)
    nadeln_d = _Nadeln([(p.lower(), p) for p in pfade_d], arbeit)
    try:
        return _felder_pruefen(befunde, zu_viele, nadeln_a, nadeln_e, nadeln_d)
    except _ZuVieleSchritte:
        return _felder_pruefen(befunde, True, None, None, None)


def kopf_verstoesse(daten: object, felder: dict[str, object]) -> list[tuple[str, str, str]]:
    """Verstöße der Kopfangaben (Projektname, Teilpfad: `felder` Name -> Wert), die im Kundenbericht stehen, ohne durch
    `kunden_verstoesse` zu laufen, als (feld, regel, detail). Nur die Regeln `a` (Token aus einem `poc`) und `b` (nur der Request: HTTP-Methode
    vor einem Pfad): Namen und Pfade sind sonst frei (Punkte, Bindestriche, Leerzeichen, Zahlen, `&`). Nach NFKC wie die Befundfelder; ein Wert,
    der kein Text ist, bleibt außer Betracht. `detail` ist ein fester Text, nie der Wert und nie das Token. Fail-closed wie
    `kunden_verstoesse` (zu viele Token, zu langer `poc`, verbrauchtes Arbeitsbudget: Regel a mit dem Detail „zu viele Token zum
    Prüfen“); eine Ausnahme aus der Prüfung wird nicht verschluckt."""
    befunde = daten["befunde"] if isinstance(daten, dict) and isinstance(daten.get("befunde"), list) else []
    token, _e, _d, zu_viele = _quellen(befunde)
    nadeln = _Nadeln([(k.lower(), k) for k in token])
    aus: list[tuple[str, str, str]] = []
    for feld, wert in felder.items():
        text = _pruef_text(wert)
        if text is None:
            continue
        try:
            a = ZU_VIELE_TOKEN if zu_viele else (_KUNDEN_DETAIL["a"] if nadeln.finde(text.lower()) else None)
        except _ZuVieleSchritte:
            a = ZU_VIELE_TOKEN
        if a:
            aus.append((feld, "a", a))
        if _REGEL_B_KOPF.search(text):
            aus.append((feld, "b", _KUNDEN_DETAIL["b"]))
    return aus


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


def _kundenwarnung(daten: dict) -> None:
    """Treffer von `kunden_verstoesse` nur als Warnung auf stderr (ID, Feld, Regel; nie Wort, Token oder Treffertext): `rendern`
    scheitert nie an Kundenregeln, `kundenbericht.py` entscheidet. Scheitert die Prüfung selbst, steht das ebenfalls auf stderr
    (nur der Ausnahmetyp, nie ihr Text): „keine Warnung“ hieße sonst fälschlich „keine Verstöße“."""
    try:
        treffer = kunden_verstoesse(daten)
    except Exception as ex:  # noqa: BLE001 - `rendern` scheitert nie an der Kundenprüfung; sichtbar machen statt schweigen
        print(f"Kundenbericht-Prüfung nicht möglich ({type(ex).__name__}); kundenbericht.py meldet den Fehler.", file=sys.stderr)
        return
    if not treffer:
        return
    zeilen = list(dict.fromkeys(f"{i} {feld}: Regel {regel}" for (i, feld, regel, _d) in treffer))
    print("Kundenbericht wird scheitern: " + "; ".join(zeilen[:30]) + (f"; … und {len(zeilen) - 30} weitere" if len(zeilen) > 30 else ""),
          file=sys.stderr)


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
    _kundenwarnung(daten)
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
