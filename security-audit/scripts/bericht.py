"""Kontext und Bericht des Skills security-audit.

  bericht.py kontext [--teilpfad P] [--repo R]   JSON mit Repo-Kontext auf stdout (Exit 3: kein Repo/HEAD,
                                                  ungültiger Teilpfad)
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
import unicodedata
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402
import netzregel  # noqa: E402
from gitkopie import GitFehler, _t, git  # noqa: E402

STUFEN = ("P1", "P2", "P3")
STATUS = ("bestätigt", "unbestätigt", "verworfen", "verdacht")
IN_LISTE = ("bestätigt", "unbestätigt")
EINZEILIG = ("titel", "szenario", "erwartet", "klasse")
MAX_JSON_BYTES = 16 * 1024 * 1024
_ID = re.compile(r"S-[1-9][0-9]{0,8}")
_KATEGORIE = re.compile(r"A(0[1-9]|10)")
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


def _teilpfad(wurzel: str, teilpfad: str) -> str:
    """Teilpfad normalisieren und gegen die in HEAD versionierten Pfade prüfen (Schreibweise des Repos)."""
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
        baum = git(wurzel, "ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD", timeout=120).stdout
    except GitFehler as e:
        raise KontextFehler(f"Dateiliste von HEAD nicht lesbar: {_t(e)}") from e
    for roh in baum.split(b"\0"):
        if not roh:
            continue
        echt = os.fsdecode(roh).split("/")
        if [unicodedata.normalize("NFC", k) for k in echt[:len(ziel)]] == ziel:
            return "/".join(echt[:len(ziel)])
    raise KontextFehler(f"Teilpfad nicht im Repo (HEAD): {_t(teilpfad)}")


def _slug(teilpfad: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", teilpfad.lower()).strip("-") or "teil"


def kontext(repo: str, teilpfad: str | None, jetzt: datetime | None = None) -> dict:
    """Kontext des Repos unter dem Pfad `repo`; wirft KontextFehler (CLI: Exit 3)."""
    jetzt = jetzt or datetime.now()
    try:
        wurzel = os.fsdecode(git(repo, "rev-parse", "--show-toplevel").stdout).rstrip("\n")
        sha = git(wurzel, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    except GitFehler as e:
        raise KontextFehler(f"Kein git-Repository mit HEAD unter {_t(repo)}: {_t(e)}") from e
    name = _repo_name(wurzel)
    datum = jetzt.strftime("%Y-%m-%d")
    echt = _teilpfad(wurzel, teilpfad) if teilpfad is not None else None
    slug = _slug(echt) if echt is not None else None

    basis = os.environ.get("SECURITY_AUDIT_AUSGABE")
    try:
        if basis:
            ordner = os.path.join(basis, name)
            os.makedirs(ordner, exist_ok=True)
            ordner = os.path.realpath(ordner)
        else:
            ordner = os.path.join(os.path.expanduser("~"), ".claude", "security-reviews", name)
            os.makedirs(ordner, exist_ok=True)
    except OSError as e:
        raise KontextFehler(f"Ausgabeordner nicht anlegbar: {_t(e)}") from e

    stamm = f"{datum}-{sha[:7]}" + (f"-{slug}" if slug else "")
    basisname, n = stamm, 1
    while any(os.path.lexists(os.path.join(ordner, basisname + ext)) for ext in (".md", ".json")):
        n += 1
        basisname = f"{stamm}-{n}"

    if basis:
        stats = os.path.join(ordner, basisname + "-agent-stats.md")
    else:
        stats = os.path.join(os.path.expanduser("~"), ".claude", "agent-stats", name, f"{datum}-security-audit.md")

    try:
        konfig = [_t(p) for p in gitkopie.repo_konfiguration(wurzel)]
    except GitFehler as e:
        raise KontextFehler(f"Konfiguration in HEAD nicht lesbar: {_t(e)}") from e
    return {
        "repo": name, "wurzel": wurzel, "sha": sha, "sha7": sha[:7], "datum": datum,
        "teilpfad": echt, "teilpfad_slug": slug, "ausgabe_ordner": ordner, "basisname": basisname,
        "hinweise": gitkopie.repo_hinweise(wurzel), "repo_konfiguration": konfig,
        "agent_stats_datei": stats,
    }


# ------------------------------------------------------------------------------------ Schema

def _text_fehler(wert: object, einzeilig: bool) -> str | None:
    """Fehlertext, wenn `wert` kein nichtleerer Text ist; einzeilig: keine Zeilenumbrüche, Steuer-/Formatzeichen
    und keine Dreifach-Backticks (würden den Befundlisten-Block verlassen)."""
    if not isinstance(wert, str) or not wert.strip():
        return "muss ein nichtleerer Text sein"
    for ch in wert:
        kat = unicodedata.category(ch)
        if kat in ("Cs", "Co") or (einzeilig and kat in ("Cc", "Cf", "Zl", "Zp")) \
                or (not einzeilig and kat == "Cc" and ch not in "\n\r\t"):
            return "enthält Steuer-, Format- oder ungültige Zeichen" + (" (einzeiliges Feld)" if einzeilig else "")
    if einzeilig and "```" in wert:
        return "enthält ``` (einzeiliges Feld)"
    return None


def _pfad_fehler(pfad: object) -> str | None:
    fehler = _text_fehler(pfad, True)
    if fehler:
        return fehler
    if pfad.startswith("/") or any(k in ("", ".", "..") for k in pfad.split("/")):
        return "muss ein normalisierter relativer Pfad sein (ohne ./, .., //, führenden oder End-/)"
    return None


def _befund_fehler(b: dict, label: str) -> list[str]:
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

    if "poc" in b:
        if msg := _text_fehler(b["poc"], False):
            fehler("poc", msg)
        else:
            f.extend(f"{label}: poc enthält nicht erlaubten Host: {_t(h)}" for h in netzregel.verstoesse_poc(b["poc"]))
    elif status == "bestätigt":
        f.append(f"{label}: Pflichtfeld fehlt: poc (Status bestätigt)")
    if "code_pfad" in b:
        cp = b["code_pfad"]
        if not isinstance(cp, list) or len(cp) < 2:
            fehler("code_pfad", "muss eine Liste von mindestens 2 Einträgen datei:zeile sein")
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
    if "hinweise" in daten and not (isinstance(daten["hinweise"], list)
                                    and all(isinstance(h, str) for h in daten["hinweise"])):
        f.append("hinweise muss eine Liste von Texten sein")
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
                f.extend(_befund_fehler(b, label))
    return f


# ------------------------------------------------------------------------------------ Markdown

def _inline(text: object) -> str:
    """Nicht validierten Text (Karte, Hinweise) einzeilig machen; Backticks und Tilden escapen (kein Codezaun möglich)."""
    return " ".join(str(text).split()).replace("`", "\\`").replace("~", "\\~")


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
            z += ["", f"### {b['id']} [{b['stufe']}] {b['titel']}", "",
                  f"- Status: {status(b)}", f"- Ort: {_ort(b)}", f"- Kategorie: {b['kategorie']}",
                  f"- Ohne Anmeldung: {'ja' if b['ohne_anmeldung'] else 'nein'}",
                  f"- Mandantenübergreifend: {'ja' if b['mandantenuebergreifend'] else 'nein'}",
                  "", "Beschreibung:"] + _block(b["beschreibung"])
            if b.get("poc"):
                z += ["", "PoC:"] + _block(b["poc"])
            if b.get("code_pfad"):
                z += ["", "Code-Pfad:"] + [f"1. {_inline(p)}" for p in b["code_pfad"]]
    if daten["hinweise"]:
        z += ["", "## Hinweise"] + [f"- {_inline(h)}" for h in daten["hinweise"]]
    return "\n".join(z) + "\n"


# ------------------------------------------------------------------------------------ CLI

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
    try:
        fd, tmp = tempfile.mkstemp(prefix=".bericht-", suffix=".tmp", dir=os.path.dirname(os.path.abspath(ziel)))
        with os.fdopen(fd, "wb") as fh:
            fh.write(markdown(daten).encode("utf-8", "replace"))
        os.replace(tmp, ziel)
    except OSError as e:
        print(f"Schreiben fehlgeschlagen: {_t(e)}", file=sys.stderr)
        return 2
    print(ziel)
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="bericht.py")
    sub = ap.add_subparsers(dest="befehl", required=True)
    k = sub.add_parser("kontext")
    k.add_argument("--teilpfad")
    k.add_argument("--repo", default=".")
    r = sub.add_parser("rendern")
    r.add_argument("json")
    args = ap.parse_args(argv)
    if args.befehl == "rendern":
        return _rendern(args.json)
    try:
        ergebnis = kontext(args.repo, args.teilpfad)
    except KontextFehler as e:
        print(str(e), file=sys.stderr)
        return 3
    print(json.dumps(ergebnis, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
