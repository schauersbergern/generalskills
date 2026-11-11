"""Kundenbericht des Skills security-audit (TF4).

  kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json
      schreibt <basisname>-kunde.md (und danach <basisname>-kunde.pdf) neben das Bericht-JSON.

Exit-Codes (bei Exit != 0 ist die erste Zeile auf stdout `kategorie: <wert>`; Meldungen stehen auf stdout, höchstens 30 Zeilen):
  0  Markdown und PDF erstellt (stdout: `kunde-md: <pfad>`, `kunde-pdf: <pfad>`)
  1  `intern`            unerwarteter Fehler (eine Zeile ohne Traceback)
  2  `inhalt`            Kundenfelder fehlen oder verstoßen gegen die Inhaltsregeln; mit Feldkorrektur behebbar; keine Kundendateien
  3  `pdf-werkzeug-fehlt` pandoc oder weasyprint fehlt oder ist nicht startbar; nur das Markdown liegt (zweite Zeile `kunde-md:`)
  4  `pdf-fehler`        PDF-Kette gescheitert (HTML-Prüfung, stderr, leere Datei, Timeout); nur das Markdown liegt
  5  `eingabe`           Argumente, Eingabedatei, Kollision, Ziel, Schema außerhalb der Kundenfelder, Schreiben; keine Korrektur

Die Meldungen zu Exit 2 haben die Form `<id> <feld>: Regel <regel>[ (<detail>)]` und nennen nie den Treffertext; ausgenommen sind
das Du-Wort und das Token bei Regel a (siehe bericht.kunden_verstoesse). Nur Standardbibliothek.
"""
import argparse
import json
import os
import re
import stat
import sys
import tempfile
import time
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bericht  # noqa: E402
from gitkopie import _t  # noqa: E402

KUNDE_BUDGET = 90         # Sekunden für `erstellen` insgesamt (Frist ab Beginn von main); Task 3 verteilt sie auf pandoc und weasyprint
MAX_ZEILEN = 30           # Meldungszeilen auf stdout; mehr werden zu `… und <n> weitere`
_FELDER = tuple(bericht.KUNDENFELDER)                      # ("zusammenfassung", "massnahme")
_FELD_REIHENFOLGE = {"zusammenfassung": 0, "massnahme": 1, "titel": 2}
_ESCAPE = frozenset("\\`*_{}[]<>!$^~@&|#")                 # K1-Menge (R1), `<` und `>` mit Backslash (R2-K-7)
_SCHEMA_KUNDENFELD = re.compile(r"(S-[0-9]+): (zusammenfassung|massnahme) (.+)", re.DOTALL)


class Abbruch(Exception):
    """Ein erwarteter Fehlerfall mit Exit-Code, Kategorie und Meldungszeilen (ohne Werte aus Daten)."""

    def __init__(self, code: int, kategorie: str, zeilen: list[str]):
        super().__init__(kategorie)
        self.code, self.kategorie, self.zeilen = code, kategorie, zeilen


def escape(text: str) -> str:
    """Markdown-Sonderzeichen (K1-Menge) mit Backslash entschärfen: aus Daten entstehen keine Links, Bilder, HTML oder Überschriften."""
    return "".join("\\" + c if c in _ESCAPE else c for c in text)


# ------------------------------------------------------------------------------------ Eingabe und Ablage

def _lstat(pfad: str) -> os.stat_result | None:
    try:
        return os.lstat(pfad)
    except FileNotFoundError:
        return None


def _pfade_pruefen(pfad: str) -> tuple[str, str]:
    """Pfadprüfung der Eingabe (R2-K-6): Endung, reguläre Datei, kein Symlink, keine Kollision mit einem Audit mit Teilpfad `kunde`,
    Ziele kein Symlink und keine Nicht-Datei. Gibt (md, pdf) zurück. Verändert nichts."""
    if not pfad.endswith(".json") or pfad == ".json":
        raise Abbruch(5, "eingabe", ["Die Eingabedatei muss auf .json enden."])
    st = _lstat(pfad)
    if st is None:
        raise Abbruch(5, "eingabe", ["Die Eingabedatei existiert nicht."])
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Abbruch(5, "eingabe", ["Die Eingabedatei muss eine reguläre Datei sein (kein Symlink)."])
    basis = pfad[:-len(".json")]
    for endung in (".json", ".reserviert"):
        if os.path.lexists(f"{basis}-kunde{endung}"):
            raise Abbruch(5, "eingabe", [f"Es gibt {os.path.basename(basis)}-kunde{endung}: der Basisname gehört einem Audit mit Teilpfad kunde."])
    md, pdf = f"{basis}-kunde.md", f"{basis}-kunde.pdf"
    for ziel in (md, pdf):
        st = _lstat(ziel)
        if st is not None and not stat.S_ISREG(st.st_mode):         # lstat: ein Symlink ist nie regulär
            raise Abbruch(5, "eingabe", [f"{_t(os.path.basename(ziel))} ist ein Symlink oder keine reguläre Datei; nichts entfernt."])
    return md, pdf


def _alte_dateien_entfernen(md: str, pdf: str) -> None:
    """Entfernt genau diese zwei Pfade (nur reguläre Dateien; `_pfade_pruefen` hat Symlinks und Nicht-Dateien ausgeschlossen)."""
    for ziel in (md, pdf):
        st = _lstat(ziel)
        if st is not None and stat.S_ISREG(st.st_mode):
            try:
                os.unlink(ziel)
            except FileNotFoundError:
                pass
            except OSError:
                raise Abbruch(5, "eingabe", [f"{_t(os.path.basename(ziel))} konnte nicht entfernt werden."]) from None


def _lesen(pfad: str) -> object:
    """JSON lesen (höchstens `bericht.MAX_JSON_BYTES`); kein Symlink, reguläre Datei."""
    try:
        fd = os.open(pfad, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise Abbruch(5, "eingabe", ["Die Eingabedatei ist nicht lesbar."]) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Abbruch(5, "eingabe", ["Die Eingabedatei muss eine reguläre Datei sein (kein Symlink)."])
        grenze = bericht.MAX_JSON_BYTES
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            roh = fh.read(grenze + 1)
    except OSError:
        raise Abbruch(5, "eingabe", ["Die Eingabedatei ist nicht lesbar."]) from None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(roh) > grenze:
        raise Abbruch(5, "eingabe", [f"Die Eingabedatei ist größer als {grenze // (1024 * 1024)} MiB."])
    try:
        return json.loads(roh)
    except (ValueError, RecursionError):
        raise Abbruch(5, "eingabe", ["Die Eingabedatei ist kein gültiges JSON."]) from None


def _ablegen(ziel: str, text: str) -> None:
    """Atomar schreiben: Temp-Datei im Zielordner, dann `os.replace`; nach einem Fehler bleibt keine Temp-Datei."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".kunde-", suffix=".tmp", dir=os.path.dirname(ziel))
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.encode("utf-8", "replace"))
        os.replace(tmp, ziel)
        tmp = None
    except OSError:
        raise Abbruch(5, "eingabe", ["Das Markdown konnte nicht geschrieben werden."]) from None
    finally:
        if tmp is not None and os.path.lexists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ------------------------------------------------------------------------------------ Prüfung

def _ohne_kundenfelder(daten: object) -> object:
    """Flache Kopie ohne `zusammenfassung` und `massnahme` der Befunde (kein deepcopy: tief verschachteltes JSON bleibt harmlos)."""
    if not isinstance(daten, dict) or not isinstance(daten.get("befunde"), list):
        return daten
    kopie = dict(daten)
    kopie["befunde"] = [{k: v for k, v in b.items() if k not in _FELDER} if isinstance(b, dict) else b for b in daten["befunde"]]
    return kopie


def _gelistet(b: object) -> bool:
    return (isinstance(b, dict) and isinstance(b.get("status"), str)
            and unicodedata.normalize("NFC", b["status"]) in bericht.IN_LISTE)


def _kappen(zeilen: list[str]) -> list[str]:
    return zeilen if len(zeilen) <= MAX_ZEILEN else zeilen[:MAX_ZEILEN] + [f"… und {len(zeilen) - MAX_ZEILEN} weitere"]


def _pruefen(daten: object) -> None:
    """Schema außerhalb der Kundenfelder (Exit 5), dann fehlende Felder, Feldschema und Inhaltsregeln (Exit 2)."""
    fehler = bericht.pruefe_schema(_ohne_kundenfelder(daten))
    if fehler:
        raise Abbruch(5, "eingabe", _kappen([f"Schemafehler außerhalb der Kundenfelder ({len(fehler)}):"] + [f"- {x}" for x in fehler]))
    schema: dict[tuple[str, str], str] = {}
    fremd = []
    for meldung in bericht.pruefe_schema(daten):
        m = _SCHEMA_KUNDENFELD.fullmatch(meldung)
        if m:
            schema[(m.group(1), m.group(2))] = m.group(3)
        else:
            fremd.append(f"- {meldung}")
    if fremd:           # kann nach der ersten Prüfung nicht vorkommen; ohne Ausweg wäre es ein Eingabefehler
        raise Abbruch(5, "eingabe", _kappen(["Schemafehler:"] + fremd))
    treffer: list[tuple[str, str, str, str | None]] = []
    reihenfolge: dict[str, int] = {}
    for i, b in enumerate(daten["befunde"]):
        reihenfolge[b["id"]] = i
        if not _gelistet(b):
            continue
        for feld in _FELDER:
            if feld not in b:
                treffer.append((b["id"], feld, "fehlt", None))
            elif (b["id"], feld) in schema:
                treffer.append((b["id"], feld, "schema", schema[(b["id"], feld)]))
    treffer += bericht.kunden_verstoesse(daten)
    if not treffer:
        return
    treffer.sort(key=lambda t: (reihenfolge.get(t[0], len(reihenfolge)), _FELD_REIHENFOLGE.get(t[1], 9)))
    zeilen = [f"{i} {feld}: Regel {regel}" + (f" ({detail})" if detail else "") for (i, feld, regel, detail) in treffer]
    raise Abbruch(2, "inhalt", _kappen(zeilen))


# ------------------------------------------------------------------------------------ Markdown (Platzhalter, 2b baut ihn aus)

def _name(daten: dict) -> str:
    for feld in ("projekt", "ordner", "repo"):
        if isinstance(daten.get(feld), str) and daten[feld].strip():
            return daten[feld]
    return "Projekt"


def markdown_erzeugen(daten: dict) -> str:
    """Platzhalter in 2a: Kopf und Befundliste mit escapten Datenfeldern."""
    z = [f"# Manibase · Sicherheitsprüfung {escape(_name(daten))}", ""]
    for b in sorted((b for b in daten["befunde"] if _gelistet(b)), key=lambda b: int(b["id"][2:])):
        z += [f"### {b['id']} · {escape(b['titel'])}", ""]
    return "\n".join(z) + "\n"


# ------------------------------------------------------------------------------------ PDF

def pdf_erstellen(md_pfad: str, pdf_pfad: str, titel: str, ende: float) -> tuple[int, str | None, list[str]]:
    """PDF-Kette (Task 3 ersetzt den Rumpf). Rückgabe (Exit-Code, Kategorie, Meldungszeilen ohne Werte aus Daten); schreibt nie auf stdout.
    `ende` ist die Frist als `time.monotonic()`-Zeitpunkt. Der Stub meldet ein fehlendes Werkzeug."""
    return 3, "pdf-werkzeug-fehlt", []


# ------------------------------------------------------------------------------------ CLI

def _erstellen(pfad: str, ende: float) -> tuple[int, str | None, list[str]]:
    pfad = os.path.abspath(pfad)
    try:
        md, pdf = _pfade_pruefen(pfad)
        _alte_dateien_entfernen(md, pdf)
        daten = _lesen(pfad)
        _pruefen(daten)
        _ablegen(md, markdown_erzeugen(daten))
    except Abbruch as a:
        return a.code, a.kategorie, a.zeilen
    code, kategorie, meldungen = pdf_erstellen(md, pdf, f"Manibase · Sicherheitsprüfung {_name(daten)}", ende)
    zeilen = [f"kunde-md: {_t(md, 4096)}"]
    if code == 0:
        return 0, None, zeilen + [f"kunde-pdf: {_t(pdf, 4096)}"]
    return code, kategorie, zeilen + _kappen(list(meldungen))


class _Parser(argparse.ArgumentParser):
    """Argumentfehler sind Eingabefehler (Exit 5): argparse selbst endet mit 2, und das hieße „Felder korrigieren“."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: Fehler: {message}", file=sys.stderr)
        print("kategorie: eingabe")
        raise SystemExit(5)


def main(argv: list[str]) -> int:
    ende = time.monotonic() + KUNDE_BUDGET
    ap = _Parser(prog="kundenbericht.py", allow_abbrev=False)
    sub = ap.add_subparsers(dest="befehl", required=True)
    e = sub.add_parser("erstellen", allow_abbrev=False)
    e.add_argument("--json", required=True, help="Bericht-JSON <ausgabe_ordner>/<basisname>.json")
    try:
        args = ap.parse_args(argv)
    except SystemExit as ex:
        return ex.code if isinstance(ex.code, int) else 5
    try:
        code, kategorie, zeilen = _erstellen(args.json, ende)
    except Exception as ex:  # noqa: BLE001 - jede unerwartete Ausnahme wird zu Exit 1 ohne Traceback und ohne Text aus der Ausnahme
        code, kategorie, zeilen = 1, "intern", [f"Unerwarteter Fehler ({type(ex).__name__})."]
    if kategorie:
        print(f"kategorie: {kategorie}")
    for zeile in zeilen:
        print(zeile)
    return code


if __name__ == "__main__":
    for strom in (sys.stdout, sys.stderr):
        try:
            strom.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    sys.exit(main(sys.argv[1:]))
