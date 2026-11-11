"""Kundenbericht des Skills security-audit (TF4).

  kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json
      schreibt <basisname>-kunde.md (und danach <basisname>-kunde.pdf) neben das Bericht-JSON.

Exit-Codes (bei Exit != 0 ist die erste Zeile auf stdout `kategorie: <wert>`; danach `kunde-md:`, wenn das Markdown liegt, und die Meldungen):
Zeilengrenze: höchstens 30 Meldungszeilen, ohne `kategorie:`, `kunde-md:` und `kunde-pdf:`; jede weitere Meldung ersetzt die Zeile
`… und <n> weitere` (sie kommt zu den 30 hinzu und fehlt bei genau 30 Meldungen).
  0  Markdown und PDF erstellt (stdout: `kunde-md: <pfad>`, `kunde-pdf: <pfad>`); auch `--help` (mit oder ohne `erstellen`) endet mit 0, schreibt aber
     keine Dateien und nennt weder `kunde-md:` noch `kunde-pdf:`
  1  `intern`            unerwarteter Fehler (eine Zeile ohne Traceback; auch eine gescheiterte Inhaltsprüfung, nie „keine Verstöße“);
                         liegt das Markdown schon, steht `kunde-md:` davor
  2  `inhalt`            Kundenfelder fehlen oder verstoßen gegen die Inhaltsregeln; mit Feldkorrektur behebbar; keine Kundendateien
  3  `pdf-werkzeug-fehlt` pandoc oder weasyprint fehlt oder ist nicht startbar; nur das Markdown liegt (zweite Zeile `kunde-md:`)
  4  `pdf-fehler`        PDF-Kette gescheitert (HTML-Prüfung, stderr, leere oder zu große Datei, Timeout); nur das Markdown liegt
  5  `eingabe`           Argumente, Eingabedatei, Kollision, Ziel, Schema außerhalb der Kundenfelder (nur ID und Feld, nie ein Wert), Kopfangaben
                         (Projektname, Teilpfad) mit Exploit-Text (Regel a oder b, `- <feld>: Regel <regel>`), ein zweiter gleichzeitiger Lauf
                         auf dieselbe JSON (Sperre), Schreiben; keine Korrektur

Die Meldungen zu Exit 2 haben die Form `<id> <feld>: Regel <regel>[ (<detail>)]` und nennen nie den Treffertext; ausgenommen sind
das Du-Wort und das Token bei Regel a (siehe bericht.kunden_verstoesse); bei mehr als 200000 Token in den `poc`-Feldern, einem `poc`
über 10**6 Zeichen oder einem verbrauchten Arbeitsbudget der Teilstring-Prüfung (sehr viele Token oder Pfade mit gleichem Anfang) meldet
jedes geprüfte Feld Regel a mit dem festen Detail „zu viele Token zum Prüfen“ (fail-closed). Alle Meldungen stehen auf stdout, stderr
bleibt für Argumentfehler (Usage). Nur Standardbibliothek.
"""
import argparse
import contextlib
import errno
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import unicodedata
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bericht  # noqa: E402
import gitkopie  # noqa: E402
import poc  # noqa: E402
from gitkopie import _t  # noqa: E402

KUNDE_BUDGET = 90         # Sekunden für `erstellen` insgesamt (Frist ab Beginn von main), über SECURITY_AUDIT_KUNDE_BUDGET nur verkürzbar
PANDOC_MAX = 20           # Anteil von pandoc; jeder Timeout ist min(Anteil, Restbudget)
WEASYPRINT_MAX = 60       # Anteil von weasyprint
TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kundenbericht.html5")
MAX_ZEILEN = 30           # Meldungszeilen auf stdout (ohne `kategorie:`/`kunde-md:`); mehr werden zu `… und <n> weitere`
_FELDER = tuple(bericht.KUNDENFELDER)                      # ("zusammenfassung", "massnahme")
_FELD_REIHENFOLGE = {"zusammenfassung": 0, "massnahme": 1, "titel": 2}
_ESCAPE = frozenset("\\`*_{}[]<>!$^~@&|#")                 # K1-Menge (R1), `<` und `>` mit Backslash (R2-K-7)
_STELLE = re.compile(r"(?:(S-[0-9]+|befunde\[[0-9]+\]): )?(?:Pflichtfeld fehlt: )?([a-z_]+(?:\[[0-9]+\])?)")
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
    if not pfad.endswith(".json") or os.path.basename(pfad) == ".json":
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


def _lesen(pfad: str | int) -> object:
    """JSON lesen (höchstens `bericht.MAX_JSON_BYTES`); kein Symlink, reguläre Datei. Ein int ist ein schon offener (gesperrter)
    Deskriptor: er wird von vorn gelesen und bleibt offen (R1-4: nie neu über den Pfad öffnen, der inzwischen eine andere Datei sein kann)."""
    if isinstance(pfad, int):
        fd = os.dup(pfad)
    else:
        try:
            fd = os.open(pfad, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            raise Abbruch(5, "eingabe", ["Die Eingabedatei ist nicht lesbar."]) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Abbruch(5, "eingabe", ["Die Eingabedatei muss eine reguläre Datei sein (kein Symlink)."])
        grenze = bericht.MAX_JSON_BYTES
        os.lseek(fd, 0, os.SEEK_SET)
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


def _modus() -> int:
    """Rechte der Kundendateien wie beim Bericht-JSON: 0644, maskiert mit der umask (`mkstemp` legt sonst 0600 an)."""
    maske = os.umask(0)
    os.umask(maske)
    return 0o644 & ~maske


def _ablegen(ziel: str, text: str) -> None:
    """Atomar schreiben: Temp-Datei im Zielordner, dann `os.replace`; nach einem Fehler bleibt keine Temp-Datei."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".kunde-", suffix=".tmp", dir=os.path.dirname(ziel))
        os.fchmod(fd, _modus())
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


def _stelle(meldung: str) -> str:
    """Ort einer Schemameldung aus `bericht.pruefe_schema` ohne Datenwerte: `<ID> <Feld>` bzw. `<Feld>`; sonst `Schemafehler`.
    Die Meldungen beginnen immer mit einem festen Namen (ID-Label und Feldname stammen aus dem Code, nie aus den Daten)."""
    m = _STELLE.match(meldung)
    return " ".join(x for x in m.groups() if x) if m else "Schemafehler"


def _stellen(meldungen: list[str]) -> list[str]:
    return [f"- {x}" for x in dict.fromkeys(_stelle(m) for m in meldungen)]


def _kappen(zeilen: list[str]) -> list[str]:
    return zeilen if len(zeilen) <= MAX_ZEILEN else zeilen[:MAX_ZEILEN] + [f"… und {len(zeilen) - MAX_ZEILEN} weitere"]


def _kopfangaben(daten: dict) -> dict[str, object]:
    """Was der Kopf zeigt und nicht durch `kunden_verstoesse` läuft: der Name (`projekt`, sonst `ordner`, sonst `repo`, wie `_name_und_hinweis`)
    und der Teilpfad."""
    felder: dict[str, object] = {}
    for feld in ("projekt", "ordner", "repo"):
        if _text(daten.get(feld)):
            felder[feld] = daten[feld]
            break
    if _text(daten.get("teilpfad")):
        felder["teilpfad"] = daten["teilpfad"]
    return felder


def _pruefen(daten: object) -> None:
    """Schema außerhalb der Kundenfelder (Exit 5), dann fehlende Felder, Feldschema und Inhaltsregeln (Exit 2)."""
    fehler = bericht.pruefe_schema(_ohne_kundenfelder(daten))
    if fehler:
        raise Abbruch(5, "eingabe", _kappen([f"Schemafehler außerhalb der Kundenfelder ({len(fehler)}):"] + _stellen(fehler)))
    kopf = bericht.kopf_verstoesse(daten, _kopfangaben(daten))
    echt = [(feld, regel) for feld, regel, detail in kopf if detail != bericht.ZU_VIELE_TOKEN]
    if echt:            # Eingabe, keine Feldkorrektur: der Projektname kommt vom Nutzer, der Teilpfad aus dem Kontext
        raise Abbruch(5, "eingabe", _kappen([f"Kopfangaben verstoßen gegen die Kundenregeln ({len(echt)}):"] + [f"- {feld}: Regel {regel}" for feld, regel in echt]))
    schema: dict[tuple[str, str], str] = {}
    fremd = []
    for meldung in bericht.pruefe_schema(daten):
        m = _SCHEMA_KUNDENFELD.fullmatch(meldung)
        if m:
            schema[(m.group(1), m.group(2))] = m.group(3)
        else:
            fremd.append(meldung)
    if fremd:           # kann nach der ersten Prüfung nicht vorkommen; ohne Ausweg wäre es ein Eingabefehler
        raise Abbruch(5, "eingabe", _kappen(["Schemafehler:"] + _stellen(fremd)))
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
    treffer += [("Kopf", feld, regel, detail) for feld, regel, detail in kopf if detail == bericht.ZU_VIELE_TOKEN]       # nicht prüfbar: wie die Befundfelder
    if not treffer:
        return
    treffer.sort(key=lambda t: (reihenfolge.get(t[0], len(reihenfolge)), _FELD_REIHENFOLGE.get(t[1], 9)))
    zeilen = [f"{i} {feld}: Regel {regel}" + (f" ({detail})" if detail else "") for (i, feld, regel, detail) in treffer]
    raise Abbruch(2, "inhalt", _kappen(zeilen))


# ------------------------------------------------------------------------------------ Markdown

KUNDENSTUFEN = ("Kritisch", "Hoch", "Mittel", "Niedrig")
GITLEAKS_TITEL = "Zugangsschlüssel in der Versionsgeschichte"       # R2-K-9: statt `titel` im Kundenbericht
MAX_TITEL = 120               # R1-W11: länger wird auf 119 Zeichen plus „…“ gekürzt
NAME_FALLBACK = "Projekt"

_HINWEIS_NAME = {
    "ordner": "Hinweis: Es wurde kein Projektname angegeben; verwendet wird der Name des Repository-Ordners.",
    "repo": "Hinweis: Es wurde kein Projektname angegeben; verwendet wird der Name des Repositorys.",
}

# Nachweis je Herkunft (R1-W6)
_NACHWEIS_WERKZEUG = {
    "osv-scanner": "aus der Abhängigkeitsliste mit bekannten Sicherheitslücken abgeglichen",
    "gitleaks": "Zugangsschlüssel in der Versionsgeschichte gefunden (Wert nicht wiedergegeben)",
    "lieferkette": "aus der Build- und Installationskonfiguration abgeleitet",
}
_NACHWEIS_NACHGESTELLT = "im Test nachgestellt"
_NACHWEIS_ANNAHME = "im Test nachgestellt unter der Annahme, dass das KI-Modell einer eingeschleusten Anweisung folgt"
_NACHWEIS_ABGELEITET = "aus dem Quellcode abgeleitet, im Test nicht bestätigt (mögliche Schwachstelle)"

# Management-Zusammenfassung: je Stufe die Auswirkung (nur bei `bestätigt`, enthält „ausnutzbar“, Singular und Plural) und die Empfehlung
# für bestätigte und für nur unbestätigte Lagen (R1-K11, K13), je als (Singular, Plural): der Singular steht bei genau einer
# Schwachstelle der Stufe, sonst der Plural (TF4 Review 2, N5-5). „ausnutzbar“ steht nie in einem Satz zu `unbestätigt`.
# Jede Empfehlung enthält „Sie“ oder beginnt mit „Wir empfehlen“ (ein Test sichert die Sie-Form: Du-Imperative erkennt text_verstoesse nicht).
_STUFE_TEXT = {
    "Kritisch": (("die ohne Anmeldung oder über die Grenzen zwischen Kundenkonten hinweg ausnutzbar ist",
                  "die ohne Anmeldung oder über die Grenzen zwischen Kundenkonten hinweg ausnutzbar sind"),
                 ("Lassen Sie die betroffene Stelle umgehend beheben.", "Lassen Sie die betroffenen Stellen umgehend beheben."),
                 ("Lassen Sie diese Stelle umgehend prüfen und, falls sie sich bestätigt, beheben.",
                  "Lassen Sie diese Stellen umgehend prüfen und, falls sie sich bestätigen, beheben.")),
    "Hoch": (("die ausnutzbar ist und erheblichen Schaden verursachen kann", "die ausnutzbar sind und erheblichen Schaden verursachen können"),
             ("Wir empfehlen, die betroffene Stelle vor dem nächsten Release zu beheben.",
              "Wir empfehlen, die betroffenen Stellen vor dem nächsten Release zu beheben."),
             ("Wir empfehlen, die betroffene Stelle vor dem nächsten Release zu prüfen und bei Bestätigung zu beheben.",
              "Wir empfehlen, die betroffenen Stellen vor dem nächsten Release zu prüfen und bei Bestätigung zu beheben.")),
    "Mittel": (("die ausnutzbar ist, deren Auswirkung aber begrenzt bleibt", "die ausnutzbar sind, deren Auswirkungen aber begrenzt bleiben"),
               ("Wir empfehlen, die betroffene Stelle zeitnah einzuplanen und zu beheben.",
                "Wir empfehlen, die betroffenen Stellen zeitnah einzuplanen und zu beheben."),
               ("Wir empfehlen, die betroffene Stelle zeitnah zu prüfen und bei Bestätigung zu beheben.",
                "Wir empfehlen, die betroffenen Stellen zeitnah zu prüfen und bei Bestätigung zu beheben.")),
    "Niedrig": (("die ausnutzbar ist, deren Auswirkung aber gering ist", "die ausnutzbar sind, deren Auswirkungen aber gering sind"),
                ("Wir empfehlen, die betroffene Stelle bei nächster Gelegenheit zu beheben.",
                 "Wir empfehlen, die betroffenen Stellen bei nächster Gelegenheit zu beheben."),
                ("Wir empfehlen, die betroffene Stelle bei nächster Gelegenheit zu prüfen und bei Bestätigung zu beheben.",
                 "Wir empfehlen, die betroffenen Stellen bei nächster Gelegenheit zu prüfen und bei Bestätigung zu beheben.")),
}
# Einordnung der Kundenstufen (fester Text unter der Stufentabelle)
_EINORDNUNG = (
    ("Kritisch", "von außen ohne Anmeldung oder über Kundengrenzen ausnutzbar."),
    ("Hoch", "ausnutzbar mit Anmeldung."),
    ("Mittel", "begrenzte Auswirkung."),
    ("Niedrig", "geringe Auswirkung oder nur in Entwicklungsumgebungen."),
)
_ZAHLWOERTER = ("", "eine", "zwei", "drei", "vier", "fünf", "sechs", "sieben", "acht", "neun", "zehn", "elf", "zwölf")
_KEINE_SCHWACHSTELLEN = "In der geprüften Version wurden keine ausnutzbaren Schwachstellen gefunden."

# Eingeschränkte Prüfung: Tabelle aus Spec R2-W-5 (Teilstring in `hinweise`, ohne Beachtung der Schreibweise -> Kundentext). „nicht geschwärzt“
# entfällt (R2-K-12). Jeder Text erscheint höchstens einmal, in der Reihenfolge der Tabelle. Die Kundentexte ändern R2-W-5 bewusst
# (TF4 Review 2: „Nachstellung in einer Testumgebung“, „Zeitlimit“; TF4 Härtung, N5-5: jeder Eintrag ist ein Satzteil, der sagt, was
# eingeschränkt war, ohne Klammer; in einer Klammer gelesen wirkten Suche und Abgleich selbst wie die Einschränkung).
# Die gitleaks-Standardausnahmen (`gitleaks-Standardausnahmen nicht geprüft`) stehen bewusst nicht in der Tabelle: sie treten fast immer auf
# (Lockfiles) und würden fast jeden Bericht als eingeschränkt kennzeichnen.
_EINGESCHRAENKT = (
    (("gitleaks fehlt",), "die Suche nach Zugangsschlüsseln war nicht möglich"),
    (("osv-scanner fehlt", "abhaengigkeiten fehlgeschlagen"), "der Abgleich der Abhängigkeiten war nicht möglich"),
    (("lieferkette fehlgeschlagen",), "die Prüfung der Build-Konfiguration war nicht möglich"),
    (("docker-fehlt", "build-fehler", "build-timeout", "start-fehler", "lockfile-fehlt", "lockfile-fremde-quelle", "nicht-npm"),
     "die Nachstellung in einer Testumgebung war nicht möglich"),
    (("zeitbudget",), "einzelne Prüfungen konnten wegen des Zeitlimits nicht abgeschlossen werden"),
    (("ki.py erkennen fehlgeschlagen", "modell-mock nicht möglich"), "die Prüfung der KI-Funktionen war nicht möglich"),
)

_GRENZEN = (
    "Geprüft wurde der oben unter „Geprüfter Stand (Commit)“ genannte Stand.",
    "Methode: Code-Analyse durch KI-Agenten; Nachweise entstanden nur in einer isolierten Testumgebung ohne Zugriff auf Produktivsysteme.",
    "Es besteht keine Garantie auf Vollständigkeit.",
    "Der technische Bericht mit Details liegt Manibase vor.",
    "Nach Umsetzung der Maßnahmen empfehlen wir eine erneute Prüfung.",
)
_FUSS = "Manibase · vertraulich"


def _text(wert: object) -> str | None:
    return wert if isinstance(wert, str) and wert.strip() else None


def _name_und_hinweis(daten: dict) -> tuple[str, str | None]:
    """Name für Kopf und Titel in der Rangfolge `projekt`, `ordner`, `repo` (R1-W10) und der passende Hinweis."""
    if name := _text(daten.get("projekt")):
        return name, None
    for feld in ("ordner", "repo"):
        if name := _text(daten.get(feld)):
            return name, _HINWEIS_NAME[feld]
    return NAME_FALLBACK, _HINWEIS_NAME["repo"]


def _name(daten: dict) -> str:
    return _name_und_hinweis(daten)[0]


def pagetitle(daten: dict) -> str:
    """Titel des PDF-Dokuments (für pandoc `--metadata pagetitle=…`): unescaped, pandoc escapt selbst (R2-K-7 der Plan-Nachträge)."""
    return f"Manibase · Sicherheitsprüfung {_name(daten)}"


def _datum(wert: object) -> str:
    """`YYYY-MM-DD` -> `TT.MM.JJJJ`; alles andere unverändert (escaped)."""
    if isinstance(wert, str) and (m := re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})", wert)):
        return f"{m.group(3)}.{m.group(2)}.{m.group(1)}"
    return escape(str(wert))


def _kundenstufe(b: dict) -> str:
    if b.get("stufe") == "P1":
        return "Kritisch" if (b.get("ohne_anmeldung") is True or b.get("mandantenuebergreifend") is True) else "Hoch"
    return "Mittel" if b.get("stufe") == "P2" else "Niedrig"


def _status(b: dict) -> str:
    return unicodedata.normalize("NFC", b["status"])


def _titel(b: dict) -> str:
    if b.get("werkzeug") == "gitleaks":
        return GITLEAKS_TITEL
    titel = b["titel"]
    return titel if len(titel) <= MAX_TITEL else titel[:MAX_TITEL - 1] + "…"


def _nachweis(b: dict) -> str:
    if b.get("werkzeug") in _NACHWEIS_WERKZEUG:
        return _NACHWEIS_WERKZEUG[b["werkzeug"]]
    if _status(b) == "bestätigt":
        return _NACHWEIS_ANNAHME if b.get("annahme_modell") is True else _NACHWEIS_NACHGESTELLT
    return _NACHWEIS_ABGELEITET


def _eingeschraenkt(daten: dict) -> list[str]:
    """Kundentexte der zutreffenden Einträge: zuerst der Teilpfad, dann die Tabelle (jeder Text höchstens einmal)."""
    texte: list[str] = []
    if teilpfad := _text(daten.get("teilpfad")):
        texte.append(f"geprüft wurde nur der Teilbereich {escape(teilpfad)}")
    hinweise = [h.lower() for h in daten.get("hinweise", []) if isinstance(h, str)] if isinstance(daten.get("hinweise"), list) else []
    for muster, text in _EINGESCHRAENKT:
        if text not in texte and any(m in h for h in hinweise for m in muster):
            texte.append(text)
    return texte


def _eingeschraenkt_satz(texte: list[str]) -> str:
    return f"Die Prüfung war eingeschränkt: {'; '.join(texte)}. Das Ergebnis ist deshalb nicht vollständig."


def _zahl(n: int) -> str:
    return _ZAHLWOERTER[n] if n <= 12 else str(n)


def _zusammenfassung(zaehler: dict[tuple[str, str], int]) -> list[str]:
    """Tabelle der Anzahlen, die Einordnung der Stufen und je Stufe ein Absatz: ein Satz je Status mit Anzahl > 0, danach die Empfehlung
    (bei gemischtem Status die für bestätigte Lagen; Singular nur bei genau einer Schwachstelle der Stufe)."""
    z = ["| Kundenstufe | Anzahl |", "|---|---|"]
    z += [f"| {st} | {zaehler.get((st, 'bestätigt'), 0) + zaehler.get((st, 'unbestätigt'), 0)} |" for st in KUNDENSTUFEN]
    z += [""] + [f"- {st}: {text}" for st, text in _EINORDNUNG]
    for st in KUNDENSTUFEN:
        (auswirkung_sg, auswirkung_pl), empfehlung_best, empfehlung_unbest = _STUFE_TEXT[st]
        n_best, n_unbest = zaehler.get((st, "bestätigt"), 0), zaehler.get((st, "unbestätigt"), 0)
        saetze = []
        if n_best:
            saetze.append(f"Es besteht eine Schwachstelle der Stufe {st}, {auswirkung_sg}." if n_best == 1
                          else f"Es bestehen {_zahl(n_best)} Schwachstellen der Stufe {st}, {auswirkung_pl}.")
        if n_unbest:
            saetze.append(f"Es besteht eine mögliche Schwachstelle der Stufe {st}, die im Test nicht nachgestellt werden konnte." if n_unbest == 1
                          else f"Es bestehen {_zahl(n_unbest)} mögliche Schwachstellen der Stufe {st}, die im Test nicht nachgestellt werden konnten.")
        if saetze:
            empfehlung = empfehlung_best if n_best else empfehlung_unbest
            z += ["", " ".join(saetze + [empfehlung[0] if n_best + n_unbest == 1 else empfehlung[1]])]
    return z


def markdown_erzeugen(daten: dict) -> str:
    """Kundenbericht als Markdown (feste Reihenfolge: Kopf, Management-Zusammenfassung, Befunde, Umfang und Grenzen, Fuß).

    Erwartet ein geprüftes Dokument. Jeder Wert aus den Daten geht durch `escape()` und steht hinter einem festen Präfix,
    nie am Zeilenanfang. Die festen Texte bestehen `bericht.text_verstoesse` (Test)."""
    name, hinweis = _name_und_hinweis(daten)
    gelistet = sorted((b for b in daten["befunde"] if _gelistet(b)), key=lambda b: (KUNDENSTUFEN.index(_kundenstufe(b)), int(b["id"][2:])))
    zaehler: dict[tuple[str, str], int] = {}
    for b in gelistet:
        schluessel = (_kundenstufe(b), _status(b))
        zaehler[schluessel] = zaehler.get(schluessel, 0) + 1
    eingeschraenkt = _eingeschraenkt(daten)

    z = [f"# Manibase · Sicherheitsprüfung {escape(name)}", "", f"**Datum:** {_datum(daten.get('datum'))}", "",
         f"**Geprüfter Stand (Commit):** {escape(str(daten.get('sha'))[:7])}"]
    if teilpfad := _text(daten.get("teilpfad")):
        z += ["", f"**Geprüfter Bereich:** nur der Teilbereich {escape(teilpfad)}"]
    if hinweis:
        z += ["", hinweis]

    z += ["", "## Management-Zusammenfassung", ""] + _zusammenfassung(zaehler)
    if eingeschraenkt:          # am Ende der Zusammenfassung, nicht nur unter „Umfang und Grenzen“; ersetzt die Entwarnung
        z += ["", _eingeschraenkt_satz(eingeschraenkt)]
    elif not gelistet:
        z += ["", _KEINE_SCHWACHSTELLEN]

    z += ["", "## Befunde"]
    if not gelistet:
        z += ["", "In diesem Bericht sind keine Befunde aufgeführt."]
    else:
        z += ["", "Die Befunde sind nach Dringlichkeit sortiert."]
    for b in gelistet:
        datei = _text(b.get("datei"))
        z += ["", f"### {b['id']} · {_kundenstufe(b)} · {escape(_titel(b))}",
              "", f"**Risiko:** {escape(str(b.get('zusammenfassung', '')))}",
              "", f"**Maßnahme:** {escape(str(b.get('massnahme', '')))}",
              "", f"**Betroffene Datei:** {escape(datei) if datei else 'gesamtes Projekt'}",
              "", f"**Nachweis:** {_nachweis(b)}"]

    z += ["", "## Umfang und Grenzen", ""] + [f"- {satz}" for satz in _GRENZEN]
    if eingeschraenkt:
        z += ["", _eingeschraenkt_satz(eingeschraenkt)]
    z += ["", "---", "", _FUSS]
    return "\n".join(z) + "\n"


# ------------------------------------------------------------------------------------ PDF

# pandoc liest das Markdown ohne alles, was Dateien oder Netz berühren könnte (R1-K2): kein raw_html/raw_tex/raw_attribute, keine
# Zitate oder Formeln, und keine Erweiterung, die Attribute, Spans, Divs oder Fußnoten erzeugt (native_spans/native_divs, Attribute
# an Überschriften, Links, Code, Fußnoten). Eine Ergänzung zu R1-K2: `<span style=…>` wird so zu Text statt zu einem Element mit
# Attribut. Dazu `--sandbox`; die zweite Schicht ist die HTML-Prüfung (Erlaubtliste für Tags und Attribute), die dritte weasyprint
# ohne Protokolle. Die HTML-Prüfung ist die Schicht, die Attribute stoppt; die Liste hier hält sie gar nicht erst entstehen.
PANDOC_FORMAT = ("markdown-smart-auto_identifiers-yaml_metadata_block-pandoc_title_block-citations-tex_math_dollars-implicit_figures"
                 "-raw_html-raw_attribute-raw_tex-header_attributes-bracketed_spans-fenced_divs-link_attributes"
                 "-native_spans-native_divs-fenced_code_attributes-inline_code_attributes-footnotes-inline_notes")
_HTML_TAGS = frozenset("html head meta title style body header main section footer h1 h2 h3 p ul li table thead tbody tr th td strong em code br hr div span".split())
_HTML_ATTRIBUTE = {"": frozenset({"class", "id"}), "meta": frozenset({"class", "id", "charset", "name", "content"}), "html": frozenset({"class", "id", "lang"})}
_FEHLER_IN_STDERR = ("disallowed protocol", "failed to load", "error")      # ohne Beachtung der Schreibweise (R2-K-3)
_HTML_MAX = 16 * 1024 * 1024
_PDF_MAX = 256 * 1024 * 1024         # größer als das, was weasyprint für einen Bericht je schreibt; ein größeres PDF ist ein Fehler, nie gekürzt


def _template_style() -> str:
    """Sollwert für das einzige `<style>`: der Text zwischen `<style>` und `</style>` der Template-Datei."""
    with open(TEMPLATE, encoding="utf-8") as fh:
        m = re.search(r"<style>(.*?)</style>", fh.read(), re.DOTALL)
    if m is None:
        raise OSError("Template ohne style")
    return m.group(1)


class _HtmlPruefer(HTMLParser):
    """Sammelt Verstöße gegen die Erlaubtliste (R1-W2, R2-W-1, R1-K4). Meldungen nennen nur Tag- und Attributnamen, nie Werte."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.verstoesse: list[str] = []
        self.styles = 0
        self.in_style = False
        self.style_text: list[str] = []

    def _melden(self, text: str) -> None:
        if text not in self.verstoesse:
            self.verstoesse.append(text)

    def handle_starttag(self, tag, attrs):
        if tag not in _HTML_TAGS:
            self._melden(f"Tag nicht erlaubt: {_t(tag, 40)}")
            return
        erlaubt = _HTML_ATTRIBUTE.get(tag, _HTML_ATTRIBUTE[""])
        for name, wert in attrs:
            if name not in erlaubt:
                self._melden(f"Attribut nicht erlaubt: {_t(name, 40)} an {tag}")
            elif tag == "html" and name == "lang" and wert != "de":
                self._melden("Attribut lang an html nur mit dem Wert de erlaubt")
        if tag == "style":
            self.styles += 1
            self.in_style = True

    def handle_endtag(self, tag):
        if tag not in _HTML_TAGS:
            self._melden(f"Tag nicht erlaubt: {_t(tag, 40)}")
        elif tag == "style":
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            self.style_text.append(data)

    def handle_comment(self, data):
        self._melden("Kommentar nicht erlaubt")

    def handle_pi(self, data):
        self._melden("Processing Instruction nicht erlaubt")

    def handle_decl(self, decl):
        if decl.strip().casefold() != "doctype html":
            self._melden("Deklaration nicht erlaubt")

    def unknown_decl(self, data):
        self._melden("Deklaration nicht erlaubt")


def html_pruefen(html: str, soll_style: str | None = None) -> list[str]:
    """Prüft das von pandoc erzeugte HTML gegen die Erlaubtliste. Leere Liste = in Ordnung.
    Erlaubt: Tags aus `_HTML_TAGS`; Attribute nur `class`, `id`, bei `meta` zusätzlich `charset`, `name`, `content`, bei `html`
    `lang="de"`; genau ein `<style>` mit dem Inhalt des Templates; als Deklaration nur `DOCTYPE html`; keine Kommentare, keine
    Processing Instructions. Escapter Text ist kein Tag und deshalb erlaubt. Die Meldungen enthalten nie Werte aus dem HTML."""
    soll = _template_style() if soll_style is None else soll_style
    pruefer = _HtmlPruefer()
    try:
        pruefer.feed(html)
        pruefer.close()
    except Exception:  # noqa: BLE001 - ein Parserfehler heißt: nicht prüfbar, also nicht rendern
        return ["HTML nicht prüfbar"]
    verstoesse = list(pruefer.verstoesse)
    if pruefer.styles != 1:
        verstoesse.append("style: genau ein Element erlaubt")
    elif "".join(pruefer.style_text) != soll:
        verstoesse.append("style: Inhalt weicht vom Template ab")
    return verstoesse


def _werkzeug_env(tmp: str) -> dict[str, str]:
    """Whitelist-Umgebung für pandoc und weasyprint (R1-K3): PATH, LANG, LC_ALL aus dem Prozess, HOME und TMPDIR im eigenen Temp-Ordner.
    Kein *_PROXY, kein PYTHONPATH oder PYTHONSTARTUP, keine geerbten Zugangsdaten."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ}
    env["HOME"] = tmp
    env["TMPDIR"] = tmp
    return env


def _werkzeug_lauf(name: str, args: list[str], anteil: int, ende: float, tmp: str) -> gitkopie.Lauf:
    """Startet ein Werkzeug über `gitkopie.werkzeug_ausfuehren` (eigene Gruppe, Timeout `min(Anteil, Rest)`). Ist der Rest ≤ 0, startet nichts."""
    rest = ende - time.monotonic()
    if rest <= 0:
        raise Abbruch(4, "pdf-fehler", [f"Zeitbudget erschöpft, {name} nicht gestartet."])
    try:
        lauf = gitkopie.werkzeug_ausfuehren(args, min(anteil, rest), tmp, _werkzeug_env(tmp))
    except gitkopie.GitFehler:
        raise Abbruch(3, "pdf-werkzeug-fehlt", [f"Werkzeug nicht startbar: {name}"]) from None
    except ValueError:      # `Popen` wirft bei einem NUL in einem Argument (etwa im Titel) ValueError statt OSError
        raise Abbruch(4, "pdf-fehler", [f"Werkzeug nicht aufrufbar: {name}"]) from None
    if lauf.rc is None:
        raise Abbruch(4, "pdf-fehler", [f"Zeitüberschreitung bei {name}."])
    return lauf


def _datei_lesen(pfad: str, grenze: int) -> bytes | None:
    """Inhalt einer regulären Datei (kein Symlink, höchstens `grenze` + 1 Bytes) oder None, wenn sie fehlt.
    Ein Lesefehler (Rechte, Datenträger) ist ein erwarteter Fehlerfall der PDF-Kette: Exit 4 `pdf-fehler`."""
    try:
        st = _lstat(pfad)
        if st is None or not stat.S_ISREG(st.st_mode):
            return None
        with open(pfad, "rb") as fh:
            return fh.read(grenze + 1)
    except OSError:
        raise Abbruch(4, "pdf-fehler", [f"{os.path.basename(pfad)} nicht lesbar."]) from None


def _pdf_ablegen(roh: bytes, ziel: str) -> None:
    """Atomar: Temp-Datei im Zielordner, dann `os.replace`; nach einem Fehler bleibt keine Temp-Datei."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".kunde-", suffix=".tmp", dir=os.path.dirname(ziel))
        os.fchmod(fd, _modus())
        with os.fdopen(fd, "wb") as fh:
            fh.write(roh)
        os.replace(tmp, ziel)
        tmp = None
    except OSError:
        raise Abbruch(5, "eingabe", ["Das PDF konnte nicht geschrieben werden."]) from None
    finally:
        if tmp is not None and os.path.lexists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _pdf_kette(md_pfad: str, pdf_pfad: str, titel: str, ende: float, pandoc: str, weasyprint: str, tmp: str) -> None:
    html_pfad, tmp_pdf = os.path.join(tmp, "kunde.html"), os.path.join(tmp, "kunde.pdf")
    erg = _werkzeug_lauf("pandoc", [pandoc, "--sandbox", "--from", PANDOC_FORMAT, "--to", "html5", "--template", TEMPLATE,
                                     "--metadata", f"pagetitle={titel}", "--columns=1000", "-o", html_pfad, os.path.abspath(md_pfad)],
                         PANDOC_MAX, ende, tmp)
    if erg.rc != 0:
        raise Abbruch(4, "pdf-fehler", [f"pandoc endete mit Exit {erg.rc}."])
    roh = _datei_lesen(html_pfad, _HTML_MAX)
    if not roh or len(roh) > _HTML_MAX:
        raise Abbruch(4, "pdf-fehler", ["pandoc hat kein HTML geschrieben."])
    try:
        verstoesse = html_pruefen(roh.decode("utf-8"))
    except (UnicodeDecodeError, OSError):
        raise Abbruch(4, "pdf-fehler", ["HTML nicht prüfbar."]) from None
    if verstoesse:
        raise Abbruch(4, "pdf-fehler", verstoesse[:10])
    erg = _werkzeug_lauf("weasyprint", [weasyprint, "--allowed-protocols", "", html_pfad, tmp_pdf], WEASYPRINT_MAX, ende, tmp)
    if erg.rc != 0:
        raise Abbruch(4, "pdf-fehler", [f"weasyprint endete mit Exit {erg.rc}."])
    fehler = erg.err.decode("utf-8", "replace").casefold()
    if any(muster in fehler for muster in _FEHLER_IN_STDERR):
        raise Abbruch(4, "pdf-fehler", ["weasyprint meldete einen Fehler (Ladefehler oder gesperrtes Protokoll)."])
    pdf = _datei_lesen(tmp_pdf, _PDF_MAX)
    if not pdf or not pdf.startswith(b"%PDF"):
        raise Abbruch(4, "pdf-fehler", ["weasyprint hat kein PDF geschrieben."])
    if len(pdf) > _PDF_MAX:             # `_datei_lesen` liest die Grenze plus ein Byte: das ist der Beleg für „zu groß“
        raise Abbruch(4, "pdf-fehler", ["weasyprint hat ein zu großes PDF geschrieben."])
    _pdf_ablegen(pdf, pdf_pfad)


def pdf_erstellen(md_pfad: str, pdf_pfad: str, titel: str, ende: float) -> tuple[int, str | None, list[str]]:
    """PDF-Kette: pandoc `--sandbox` (Markdown -> HTML), HTML-Prüfung, weasyprint `--allowed-protocols ''` (HTML -> PDF).
    Rückgabe (Exit-Code, Kategorie, Meldungszeilen ohne Werte aus Daten); schreibt nie auf stdout. `ende` ist die Frist als
    `time.monotonic()`-Zeitpunkt. Beide Werkzeuge werden geprüft, bevor ein Kindprozess startet; sie laufen im eigenen
    `mkdtemp` mit Whitelist-Umgebung. Aufgeräumt wird nur dieser Ordner."""
    fehlend = [n for n in ("pandoc", "weasyprint") if poc.werkzeug_fehlt(n)]
    if fehlend:
        return 3, "pdf-werkzeug-fehlt", [f"Werkzeug fehlt: {', '.join(fehlend)}"]
    pandoc, weasyprint = shutil.which("pandoc"), shutil.which("weasyprint")
    if pandoc is None or weasyprint is None:
        return 3, "pdf-werkzeug-fehlt", ["Werkzeug fehlt: pandoc, weasyprint"]
    try:
        tmp = tempfile.mkdtemp(prefix="kunde-pdf-")
    except OSError:
        return 4, "pdf-fehler", ["Temporärer Ordner nicht anlegbar."]
    try:
        _pdf_kette(md_pfad, pdf_pfad, titel, ende, pandoc, weasyprint, tmp)
    except Abbruch as a:
        return a.code, a.kategorie, a.zeilen
    finally:
        shutil.rmtree(tmp, ignore_errors=True)         # nur der eigene, von mkdtemp zurückgegebene Pfad
    return 0, None, []


# ------------------------------------------------------------------------------------ CLI

@contextlib.contextmanager
def _sperre(pfad: str):
    """Sperre (flock, nicht blockierend) auf die Eingabe-JSON für die Dauer eines Laufs: zwei `erstellen` auf dieselbe Datei würden sich die
    Kundendateien gegenseitig entfernen (das Entfernen kommt vor dem Lesen) und ihr PDF aus dem Markdown des anderen bauen. Der zweite Lauf
    endet mit Exit 5. Die Sperre hängt am offenen Dateideskriptor: sie endet mit dem Lauf, auch nach einem Absturz oder SIGKILL (nie eine
    Sperrdatei, die liegen bleibt). Nur zwischen Läufen von `erstellen`; `rendern` und das Schreiben der JSON sperrt sie nicht. Die Sperre hängt an der Inode: nach dem Sperren
    und vor dem Schreiben muss der Pfad noch auf sie zeigen (sonst Exit 5), und die JSON wird über den gesperrten Deskriptor gelesen (R1-4)."""
    try:
        fd = os.open(pfad, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise Abbruch(5, "eingabe", ["Die Eingabedatei ist nicht lesbar."]) from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as ex:
            if ex.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise Abbruch(5, "eingabe", ["Ein anderer Lauf von erstellen bearbeitet diese Datei gerade."]) from None
            raise Abbruch(5, "eingabe", ["Die Eingabedatei lässt sich nicht sperren."]) from None
        _ist_noch_diese_datei(fd, pfad)
        yield fd
    finally:
        os.close(fd)


def _ist_noch_diese_datei(fd: int, pfad: str) -> None:
    """Die Sperre hängt an der Inode, nicht am Pfad: wurde die JSON atomar ersetzt (Schreiben per rename), sperrt ein anderer Lauf die neue
    Inode ohne Konflikt und entfernt unsere Kundendateien (R1-4). Darum muss der Pfad noch auf die gesperrte Inode zeigen, sonst Exit 5."""
    try:
        gesperrt, jetzt = os.fstat(fd), os.lstat(pfad)
    except OSError:
        raise Abbruch(5, "eingabe", ["Die Eingabedatei wurde während des Laufs ersetzt oder entfernt."]) from None
    if (gesperrt.st_dev, gesperrt.st_ino) != (jetzt.st_dev, jetzt.st_ino):
        raise Abbruch(5, "eingabe", ["Die Eingabedatei wurde während des Laufs ersetzt oder entfernt."])


def _erstellen(pfad: str, ende: float) -> tuple[int, str | None, list[str]]:
    pfad = os.path.abspath(pfad)
    try:
        md, pdf = _pfade_pruefen(pfad)
        with _sperre(pfad) as fd:
            return _erstellen_gesperrt(pfad, md, pdf, ende, fd)
    except Abbruch as a:
        return a.code, a.kategorie, a.zeilen


def _erstellen_gesperrt(pfad: str, md: str, pdf: str, ende: float, fd: int) -> tuple[int, str | None, list[str]]:
    _alte_dateien_entfernen(md, pdf)
    daten = _lesen(fd)
    _pruefen(daten)
    _ist_noch_diese_datei(fd, pfad)
    _ablegen(md, markdown_erzeugen(daten))
    zeilen = [f"kunde-md: {_t(md, 4096)}"]
    try:
        code, kategorie, meldungen = pdf_erstellen(md, pdf, pagetitle(daten), ende)
    except Exception as ex:  # noqa: BLE001 - das Markdown liegt schon: Exit 1, aber `kunde-md:` nennen und nichts aus der Ausnahme ausgeben
        return 1, "intern", zeilen + [f"Unerwarteter Fehler ({type(ex).__name__})."]
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
    ende = time.monotonic() + poc._nur_verkuerzt("SECURITY_AUDIT_KUNDE_BUDGET", KUNDE_BUDGET)
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
