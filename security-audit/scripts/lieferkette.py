#!/usr/bin/env python3
"""Lieferkette, Abhängigkeiten und Secrets für den Skill security-audit (nur Standardbibliothek).

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I lieferkette.py secrets --lauf <id> --repo <wurzel> --quelle <arbeitskopie> --sha <commit>
  python3 -I lieferkette.py abhaengigkeiten --lauf <id> --quelle <arbeitskopie>

`secrets` (Budget 300 s, davon `gitleaks dir` samt Schwärzung zuerst höchstens 120 s) schwärzt zuerst jede Secret-Fundstelle der
Arbeitskopie (gleiche Länge, Zeichen `*`, `\\n` und `\\r` bleiben), setzt dann den Marker `<zustand>/lieferkette/geschwaerzt` und
prüft danach die Historie in einem Spiegelklon des Repos. Ausgabe (JSON auf stdout): `befunde_roh` je (Regel, Datei) mit `regel`,
`datei`, `zeile`, `commits` (volle SHAs, höchstens 20, jüngster zuerst) und `in_head`, dazu `hinweise` und `geschwaerzt`. Die
gitleaks-Felder `Secret`, `Match`, `Author`, `Email`, `Message` und `Fingerprint` werden nie ausgegeben, kein Secret-Wert
verlässt den Prozess. Grenze: gitleaks überspringt mit `useDefault = true` bestimmte Pfade (`STANDARD_AUSNAHMEN`, z. B.
`node_modules/`, Lockfiles, `*.svg`); Textdateien dieser Klassen in der Arbeitskopie werden weder geprüft noch geschwärzt und
stehen deshalb im Hinweis „gitleaks-Standardausnahmen nicht geprüft: …“.

`abhaengigkeiten` (Budget 300 s) kopiert jedes Lockfile (npm `package-lock.json`/`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`;
ohne `node_modules/`) mit seinem Dateinamen in einen eigenen leeren Ordner unter `<zustand>/lieferkette/abh/` und ruft darauf
`osv-scanner scan source --lockfile <kopie> --format json --no-resolve` auf (cwd leer, Umgebung aus `werkzeug_umgebung()`, nie im
Kundenrepo, keine `osv-scanner.toml` des Repos). Ausgabe (JSON auf stdout): `pakete` je Paket (nicht je Advisory) mit `paket`,
`version`, `lockfile`, `zeile`, `advisories` (`id`, `aliase`, `zusammenfassung` ≤ 200, `details` ≤ 500 Zeichen, einzeilig),
`behoben_in` (je Advisory die kleinste Fix-Version oberhalb der installierten im passenden Versionsbereich, davon das Maximum),
`dev` (true nur bei `dev: true` im npm-Lockfile, sonst false; yarn und pnpm tragen keine Dev-Angabe) und `kev` (true/false, null
wenn der Katalog nicht geladen werden konnte), dazu `hinweise`. Der KEV-Katalog der CISA wird höchstens einmal je Lauf geladen
(Cache `<zustand>/lieferkette/kev.json`); `SECURITY_AUDIT_KEV_DATEI` ersetzt den Download durch eine lokale Datei. Aus Kundendateien
erscheinen nur Paketnamen, Versionen und Pfade.

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
import functools
import json
import os
import re
import stat
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402
import poc  # noqa: E402
from gitkopie import GitFehler, ZeitbudgetFehler, _t  # noqa: E402
from poc import PocFehler  # noqa: E402

SECRETS_BUDGET = 300           # Sekunden für `secrets` insgesamt; Skill-Bash-Limit: 600 s
SECRETS_DIR_BUDGET = 120       # davon `gitleaks dir` samt Schwärzung (zuerst)
KONFIG_SUCHE_BUDGET = 30       # Suche nach Repo-Konfiguration und `gitleaks:allow` in der Arbeitskopie
AUSNAHMEN_SUCHE_BUDGET = 30    # Suche nach Dateien der gitleaks-Standardausnahmen in der Arbeitskopie
TEXT_PROBE = 8192              # so viele Bytes entscheiden, ob eine Datei Text ist (kein NUL, nicht leer)
MAX_NAMEN_JE_KLASSE = 3        # Dateien je Klasse im Hinweis zu den Standardausnahmen
ALLOW_DATEI_MAX = 16 * 1024 * 1024
REPORT_MAX = 256 * 1024 * 1024
MAX_COMMITS = 20
MAX_NENNUNGEN = 10             # Dateien je Hinweis zur Repo-Konfiguration
GITLEAKS_TOML = "[extend]\nuseDefault = true\n"
KONFIG_NAMEN = (".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml")
ARBEIT = ("leer", "leer-ignore", "gitleaks.toml", "gl-dir.json", "gl-git.json", "spiegel.git", "abh")   # unter <zustand>/lieferkette/
VOLLER_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
ALLOW_MARKE = b"gitleaks:allow"

ABH_BUDGET = 300               # Sekunden für `abhaengigkeiten` insgesamt (osv-scanner je Lockfile, danach KEV); Skill-Limit 600 s
KEV_TIMEOUT = 30               # Sekunden für den KEV-Download
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_USER_AGENT = "security-audit/1 (+https://github.com/schauersbergern/generalskills)"
KEV_MAX = 32 * 1024 * 1024     # Bytes, die vom KEV-Katalog gelesen werden (echte Größe etwa 1,5 MB)
LOCKFILE_NAMEN = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
LOCKFILE_MAX = 64 * 1024 * 1024
MAX_LOCKFILES = 50
MAX_PAKETE = 300               # Pakete in der Ausgabe
MAX_ADVISORIES = 20            # Advisories je Paket in der Ausgabe (`behoben_in` zählt alle)
MAX_ALIASE = 10
ZUSAMMENFASSUNG_MAX = 200
DETAILS_MAX = 500
OSV_BEREICHE = ("SEMVER", "ECOSYSTEM")


class Ausnahme(NamedTuple):
    """Pfadklasse, die gitleaks mit `useDefault = true` überspringt: Secrets darin werden weder gemeldet noch geschwärzt."""
    name: str
    muster: re.Pattern          # gegen den Pfad relativ zur Arbeitskopie (Trenner `/`)
    beispiele: tuple            # Pfade, die gitleaks 8.30 nachweislich überspringt (`test_standard_ausnahmen_echt`)


def _klasse(name: str, muster: str, *beispiele: str, gross_klein: bool = False) -> Ausnahme:
    return Ausnahme(name, re.compile(muster, re.IGNORECASE if gross_klein else 0), beispiele)


# Mit gitleaks 8.30.1 gemessen (Standard-Allowlist und Archiv-Erkennung); Groß-/Kleinschreibung wie gemessen: nur `gitleaks.toml`
# unterscheidet sie, alle anderen Klassen nicht. Die Binärformate zählen nur, wenn die Datei Text enthält.
STANDARD_AUSNAHMEN = (
    _klasse("node_modules, bower_components", r"(?:^|/)(?:node_modules|bower_components)/",
            "node_modules/x/a.js", "web/node_modules/p/b.js", "bower_components/a/b.js", gross_klein=True),
    _klasse("Paketsperrdateien", r"(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Pipfile\.lock"
            r"|poetry\.lock|gradle\.lockfile|deno\.lock)$",
            "package-lock.json", "web/package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "Pipfile.lock",
            "poetry.lock", "gradle.lockfile", "deno.lock", "sub/Deno.lock", gross_klein=True),
    _klasse("Ruby-vendor", r"(?:^|/)vendor/(?:bundle|ruby)/", "vendor/bundle/a.rb", "vendor/ruby/3.3/a.rb", "a/vendor/bundle/b.rb",
            "Vendor/Bundle/c.rb", gross_klein=True),
    _klasse("Go-Moduldateien", r"go\.(?:mod|sum|work(?:\.sum)?)$", "go.mod", "a/b/go.sum", "go.work", "go.work.sum", "xgo.sum",
            gross_klein=True),
    _klasse("Go-vendor", r"(?:^|/)vendor/(?:modules\.txt$|(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io"
            r"|k8s\.io|sigs\.k8s\.io)(?:/|$))",
            "vendor/modules.txt", "vendor/github.com/a/b.go", "vendor/golang.org/x/a.go", "vendor/google.golang.org/a.go",
            "vendor/gopkg.in/a.go", "vendor/istio.io/a.go", "vendor/k8s.io/a.go", "vendor/sigs.k8s.io/a.go",
            "sub/vendor/github.com/a.go", gross_klein=True),
    _klasse("Gradle-/Maven-Wrapper", r"(?:^|/)(?:gradlew(?:\.bat)?|mvnw(?:\.cmd)?|\.mvn/wrapper/MavenWrapperDownloader\.java)$",
            "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", "sub/gradlew", ".mvn/wrapper/MavenWrapperDownloader.java",
            gross_klein=True),
    _klasse("gitleaks.toml", r"gitleaks\.toml", "gitleaks.toml", ".gitleaks.toml", "sub/gitleaks.toml", "old-gitleaks.toml",
            "gitleaks.toml.example"),
    _klasse(".git-Ordner", r"(?:^|/)\.git/", "sub/.git/a.js", "x/.git/config", gross_klein=True),
    _klasse("Bilder (bmp, gif, jpg, png, svg, tif)", r"\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
            "x.svg", "x.png", "x.jpg", "x.jpeg", "x.gif", "x.bmp", "x.tif", "x.tiff", "x.SVG", gross_klein=True),
    _klasse("Schriften (eot, otf, ttf, woff)", r"\.(?:eot|otf|ttf|woff2?)$",
            "x.eot", "x.otf", "x.ttf", "x.woff", "x.woff2", "x.TTF", gross_klein=True),
    _klasse("Office- und Binärformate (doc, xls, pdf, exe, gltf u. ä.)",
            r"\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|pdb|exe|gltf)$",
            "x.doc", "x.docx", "x.xls", "x.xlsx", "x.pdf", "x.bin", "x.socket", "x.vsidx", "x.v2", "x.suo", "x.wsuo", "x.pdb",
            "x.exe", "x.gltf", "x.PDF", gross_klein=True),
    _klasse("Archive (zip, tar, gz, bz2, xz, zst, lz4, 7z, rar)", r"\.(?:zip|tar|gz|bz2|xz|zst|lz4|7z|rar)",
            "x.zip", "x.tar", "x.gz", "x.bz2", "x.xz", "x.zst", "x.lz4", "x.7z", "x.rar", "x.tar.gz", "x.GZ", gross_klein=True),
)


fehlt = poc.werkzeug_fehlt     # einziger Parser von SECURITY_AUDIT_OHNE (PATH + Umgebungsvariable), für alle Unterbefehle


class SchwaerzFehler(Exception):
    """Die Arbeitskopie konnte nicht (vollständig) geschwärzt werden."""


class ReportFehler(Exception):
    """Der Bericht von gitleaks fehlt oder ist unlesbar."""


# ------------------------------------------------------------------------------------ Hilfen

def _sekunden(name: str, standard: float) -> float:
    """Budget in Sekunden; die Umgebungsvariable darf den Standard nur verkürzen (Tests), nie verlängern: ungültig, nicht endlich
    oder ≤ 0 ergibt den Standard, größere Werte werden auf den Standard gedeckelt (Skill-Limit 600 s)."""
    try:
        wert = float(os.environ.get(name, ""))
    except ValueError:
        return standard
    return min(wert, standard) if wert > 0 else standard


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


def _standard_ausnahme(rel: str) -> str | None:
    """Name der Klasse der gitleaks-Standardausnahmen, in die der Pfad (relativ zur Arbeitskopie, `/`) fällt, sonst None."""
    for klasse in STANDARD_AUSNAHMEN:
        if klasse.muster.search(rel):
            return klasse.name
    return None


def _hat_textinhalt(pfad: str) -> bool:
    """Nicht leer und ohne NUL in den ersten Bytes (wie die Textheuristik von git); nur dann gibt es etwas zu prüfen."""
    try:
        if not stat.S_ISREG(os.lstat(pfad).st_mode):
            return False
        with open(pfad, "rb") as f:
            kopf = f.read(TEXT_PROBE)
    except OSError:
        return False
    return bool(kopf) and b"\0" not in kopf


def _standard_ausnahmen_hinweise(quelle: str) -> list[str]:
    """Hinweis, wenn die Arbeitskopie Textdateien enthält, die gitleaks mit `useDefault = true` überspringt (dort wird nichts
    gemeldet und nichts geschwärzt). Nennt je Klasse die Anzahl und bis zu drei Dateien, nie Inhalte."""
    ende = time.monotonic() + AUSNAHMEN_SUCHE_BUDGET
    je_klasse: dict[str, list[str]] = {}
    abgebrochen = False
    for ordner, unter, dateien in os.walk(quelle):
        unter.sort()
        for name in sorted(dateien):
            if time.monotonic() > ende:
                abgebrochen = True
                break
            pfad = os.path.join(ordner, name)
            rel = os.path.relpath(pfad, quelle).replace(os.sep, "/")
            klasse = _standard_ausnahme(rel)
            if klasse is not None and _hat_textinhalt(pfad):
                je_klasse.setdefault(klasse, []).append(rel)
        if abgebrochen:
            break
    hinweise = []
    if je_klasse:
        teile = []
        for klasse in (k.name for k in STANDARD_AUSNAHMEN if k.name in je_klasse):
            dateien = je_klasse[klasse]
            gezeigt = ", ".join(_t(d) for d in dateien[:MAX_NAMEN_JE_KLASSE])
            rest = f" (+{len(dateien) - MAX_NAMEN_JE_KLASSE} weitere)" if len(dateien) > MAX_NAMEN_JE_KLASSE else ""
            teile.append(f"{klasse} ({len(dateien)}: {gezeigt}{rest})")
        hinweise.append("gitleaks-Standardausnahmen nicht geprüft: " + "; ".join(teile)
                        + " — dort wird nichts gemeldet und nichts geschwärzt")
    if abgebrochen:
        hinweise.append("Suche nach gitleaks-Standardausnahmen abgebrochen (Zeitbudget)")
    return hinweise


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
    roh = str(text)
    if roh.endswith("Z"):                         # Python < 3.11 kennt das abschließende `Z` in fromisoformat nicht
        roh = roh[:-1] + "+00:00"
    try:
        wert = datetime.fromisoformat(roh)
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


def _arbeitskopie(lauf: str, quelle_arg: str) -> tuple[str, str]:
    """(Zustandsordner, realpath der Arbeitskopie); PocFehler (Exit 2), wenn `--quelle` nicht die Arbeitskopie dieses Laufs ist
    oder der Fertig-Marker fehlt."""
    zustand = poc._ordner(lauf)
    quelle = os.path.realpath(quelle_arg)
    if not os.path.isdir(zustand) or quelle != os.path.realpath(os.path.join(zustand, "quelle")) or not os.path.isdir(quelle):
        raise PocFehler("--quelle muss die Arbeitskopie dieses Laufs sein (`poc.py vorbereiten`): "
                        f"erwartet {os.path.join(zustand, 'quelle')}")
    if not os.path.isfile(os.path.join(zustand, "quelle.fertig")):
        raise PocFehler("Arbeitskopie unvollständig (kein Fertig-Marker): erneut `poc.py vorbereiten --lauf … --repo …`")
    return zustand, quelle


def cmd_secrets(a: argparse.Namespace) -> int:
    repo = os.path.realpath(a.repo)
    if not os.path.isdir(repo):
        raise PocFehler(f"--repo ist kein Ordner: {a.repo}")
    zustand, quelle = _arbeitskopie(a.lauf, a.quelle)
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
        hinweise += _standard_ausnahmen_hinweise(quelle)
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


# ------------------------------------------------------------------------------------ abhaengigkeiten: Versionen

_SEMVER = re.compile(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", re.ASCII)


def _zahl(ziffern: str) -> tuple[int, str]:
    """Sortierschlüssel eines Ziffernblocks ohne `int()` (das bei Python >= 3.11 ab 4300 Stellen wirft): ohne führende Nullen
    ist die längere Zahl die größere, bei gleicher Länge entscheidet der Text."""
    z = ziffern.lstrip("0")
    return len(z), z


def _zerlegt(version: str) -> tuple[tuple[tuple[int, str], ...], list[str] | None] | None:
    m = _SEMVER.fullmatch(version.strip())
    if not m:
        return None
    kern = tuple(_zahl(m.group(i) or "0") for i in (1, 2, 3))
    return kern, (m.group(4).split(".") if m.group(4) else None)


def _natuerlich(version: str) -> list[tuple[int, tuple[int, str] | str]]:
    """Notbehelf für Versionen ohne Semver-Form: Zahlen- und Buchstabenblöcke, Zahlen vor Text."""
    return [(0, _zahl(t)) if t.isdigit() else (1, t.casefold()) for t in re.findall(r"\d+|[A-Za-z]+", version, re.ASCII)]


def semver_vergleich(a: str, b: str) -> int:
    """-1, 0 oder 1, je nachdem ob Version `a` kleiner, gleich oder größer als `b` ist (Semver 2.0: Vorabversionen vor der
    Release, Build-Metadaten zählen nicht; `v`-Präfix und fehlende Teile (`1.2`) werden toleriert). Versionen ohne Semver-Form
    werden nach Zahlen- und Buchstabenblöcken verglichen; die Funktion wirft nie."""
    za, zb = _zerlegt(a), _zerlegt(b)
    if za is None or zb is None:
        na, nb = _natuerlich(a), _natuerlich(b)
        return (na > nb) - (na < nb)
    (ka, pa), (kb, pb) = za, zb
    if ka != kb:
        return -1 if ka < kb else 1
    if pa is None or pb is None:
        return 0 if pa is None and pb is None else (1 if pa is None else -1)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            if _zahl(x) == _zahl(y):                 # führende Nullen (ungültiges Semver): gleich, nicht beide Richtungen 1
                continue
            return -1 if _zahl(x) < _zahl(y) else 1
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1          # Zahlen vor Text
        return -1 if x < y else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


_version_key = functools.cmp_to_key(semver_vergleich)


def _bereiche(ereignisse: object) -> list[tuple[str, str | None, str | None]]:
    """OSV-Ereignisse eines Bereichs (`introduced`, `fixed`, `last_affected`) als Intervalle (von, fixed, last_affected)."""
    if not isinstance(ereignisse, list):
        return []
    einzeln = [(k, v) for e in ereignisse if isinstance(e, dict) for k, v in e.items()
               if k in ("introduced", "fixed", "last_affected") and isinstance(v, str)]
    einzeln.sort(key=lambda kv: _version_key(kv[1]))
    ergebnis: list[tuple[str, str | None, str | None]] = []
    offen: str | None = None
    for art, wert in einzeln:
        if art == "introduced":
            offen = wert if offen is None else offen
        elif offen is not None:
            ergebnis.append((offen, wert if art == "fixed" else None, wert if art == "last_affected" else None))
            offen = None
    if offen is not None:
        ergebnis.append((offen, None, None))
    return ergebnis


def _fix_je_advisory(vuln: dict, paket: str, version: str) -> str | None:
    """Kleinste Fix-Version oberhalb der installierten Version im Bereich, der die installierte Version enthält; passt kein
    Bereich, die kleinste Fix-Version oberhalb der installierten über alle Bereiche. Nur `affected`-Einträge mit genau diesem
    Paketnamen im Ökosystem npm."""
    treffer: list[str] = []
    alle: list[str] = []
    affected = vuln.get("affected")
    for eintrag in affected if isinstance(affected, list) else []:
        pkg = eintrag.get("package") if isinstance(eintrag, dict) else None
        if not isinstance(pkg, dict) or pkg.get("name") != paket or str(pkg.get("ecosystem", "")).casefold() != "npm":
            continue
        bereiche = eintrag.get("ranges")
        for bereich in bereiche if isinstance(bereiche, list) else []:
            if not isinstance(bereich, dict) or bereich.get("type") not in OSV_BEREICHE:
                continue
            for von, fix, bis in _bereiche(bereich.get("events")):
                if fix is not None and semver_vergleich(fix, version) > 0:
                    alle.append(fix)
                drin = semver_vergleich(version, von) >= 0 and (
                    fix is not None and semver_vergleich(version, fix) < 0
                    or bis is not None and semver_vergleich(version, bis) <= 0
                    or fix is None and bis is None)
                if drin and fix is not None:
                    treffer.append(fix)
    kandidaten = treffer or alle
    return min(kandidaten, key=_version_key) if kandidaten else None


def behoben_in(advisories: list[dict], paket: str, version: str) -> str | None:
    """Kleinste Version, die alle Advisories des Pakets behebt: je Advisory die kleinste Fix-Version oberhalb der installierten
    im passenden Versionsbereich (Versionslinien!), davon das Maximum. None, wenn kein Advisory eine Fix-Version nennt.
    `advisories` sind die OSV-Einträge (`vulnerabilities`) aus der Ausgabe von osv-scanner."""
    fixes = [f for f in (_fix_je_advisory(v, paket, version) for v in advisories if isinstance(v, dict)) if f is not None]
    return max(fixes, key=_version_key) if fixes else None


# ------------------------------------------------------------------------------------ abhaengigkeiten: Lockfiles

def _einzeilig(text: object, grenze: int) -> str:
    """Fremden Text (OSV-Datenbank) für den LLM-Kontext: Whitespace (auch Zeilentrenner) zu einem Leerzeichen, unsichtbare
    Zeichen als Escape, höchstens `grenze` Zeichen (das Kürzungszeichen eingeschlossen)."""
    if not isinstance(text, str):
        return ""
    return _t(" ".join(text.split()), grenze - 1)


def _lockfiles_finden(quelle: str, hinweise: list[str]) -> list[str]:
    """Relative Pfade (`/`) aller Lockfiles in der Arbeitskopie, sortiert; `node_modules` und `.git` werden nicht betreten,
    Symlinks nicht angenommen (Hinweis)."""
    gefunden: list[str] = []
    for ordner, unter, dateien in os.walk(quelle):
        unter[:] = sorted(u for u in unter if u not in ("node_modules", ".git"))
        for name in dateien:
            if name not in LOCKFILE_NAMEN:
                continue
            pfad = os.path.join(ordner, name)
            rel = os.path.relpath(pfad, quelle).replace(os.sep, "/")
            try:
                st = os.lstat(pfad)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                hinweise.append(f"Lockfile ist ein Symlink, übersprungen: {_t(rel)}")
            elif not stat.S_ISREG(st.st_mode):
                continue
            elif st.st_size > LOCKFILE_MAX:
                hinweise.append(f"Lockfile zu groß (> {LOCKFILE_MAX // (1024 * 1024)} MiB), übersprungen: {_t(rel)}")
            else:
                gefunden.append(rel)
    gefunden.sort()
    if len(gefunden) > MAX_LOCKFILES:
        hinweise.append(f"{len(gefunden)} Lockfiles gefunden, nur die ersten {MAX_LOCKFILES} geprüft")
        gefunden = gefunden[:MAX_LOCKFILES]
    return gefunden


def _lese_datei(pfad: str) -> bytes:
    fd = os.open(pfad, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as f:
        return f.read(LOCKFILE_MAX + 1)


class _NpmIndex(NamedTuple):
    dev: dict          # (name, version) -> True, wenn jedes Vorkommen `dev: true` trägt
    schluessel: dict   # (name, version) -> Schlüssel `node_modules/…` (Lockfile ab Version 2)


def _npm_index(text: str) -> _NpmIndex:
    """Dev-Angabe und Schlüssel je (Name, Version) aus einem npm-Lockfile; unlesbar oder fremdes Format ergibt leere Indizes."""
    dev: dict[tuple[str, str], bool] = {}
    schluessel: dict[tuple[str, str], str] = {}

    def vermerken(name: object, version: object, eintrag: dict) -> None:
        if isinstance(name, str) and isinstance(version, str):
            dev[(name, version)] = dev.get((name, version), True) and eintrag.get("dev") is True

    def altformat(wurzel: object) -> None:               # lockfileVersion 1: verschachtelt unter `dependencies`; iterativ (Tiefe!)
        offen = [wurzel]
        while offen:
            deps = offen.pop()
            for name, eintrag in deps.items() if isinstance(deps, dict) else []:
                if isinstance(eintrag, dict):
                    vermerken(name, eintrag.get("version"), eintrag)
                    offen.append(eintrag.get("dependencies"))

    try:
        daten = json.loads(text)
    except (ValueError, RecursionError):                 # kaputt oder so tief verschachtelt, dass der Parser aufgibt
        return _NpmIndex({}, {})
    if not isinstance(daten, dict):
        return _NpmIndex({}, {})
    pakete = daten.get("packages")
    for schl, eintrag in pakete.items() if isinstance(pakete, dict) else []:
        if not isinstance(eintrag, dict) or "node_modules/" not in schl:
            continue
        name = schl.rsplit("node_modules/", 1)[-1]
        vermerken(name, eintrag.get("version"), eintrag)
        if isinstance(eintrag.get("name"), str) and eintrag["name"] != name:      # Alias: auch unter dem echten Namen
            vermerken(eintrag["name"], eintrag.get("version"), eintrag)
        if isinstance(eintrag.get("version"), str):
            schluessel.setdefault((name, eintrag["version"]), schl)
    altformat(daten.get("dependencies"))
    return _NpmIndex(dev, schluessel)


def _erster_mit_version(zeilen: list[str], koepfe: list[int], version: re.Pattern[str]) -> int:
    """Von mehreren Eintragsköpfen desselben Pakets der erste, dessen Eintrag (bis zur nächsten Leerzeile, höchstens sechs
    Zeilen) die installierte Version nennt; sonst der erste Kopf."""
    for i in koepfe:
        for z in zeilen[i + 1:i + 7]:
            if not z.strip():
                break
            if version.search(z):
                return i
    return koepfe[0]


def _kopf_yarn(zeilen: list[str], name: str, version: str) -> int | None:
    """yarn.lock: Zeile des Eintragskopfs (Spalte 0, endet auf `:`), dessen durch `, ` getrennte Spezifikationen (auch in
    Anführungszeichen) mit `<name>@` beginnen."""
    koepfe = [i for i, z in enumerate(zeilen)
              if z and not z[0].isspace() and z[0] != "#" and z.rstrip().endswith(":")
              and any(s.strip().strip("\"'").startswith(name + "@") for s in z.rstrip()[:-1].split(", "))]
    if not koepfe:
        return None
    ver = re.escape(version)
    return _erster_mit_version(zeilen, koepfe, re.compile(r"^\s+version:?\s+[\"']?" + ver + r"[\"']?\s*$"))


def _kopf_pnpm(zeilen: list[str], name: str, version: str) -> int | None:
    """pnpm-lock.yaml: Zeile des Kopfs `/name@ver:`, `name@ver:`, `'/name@ver':` (auch `name@ver(peer)` und `/name/ver`) im
    Abschnitt `packages:`; fehlt die Version, der erste Kopf des Namens."""
    start, ende = 0, len(zeilen)
    for i, z in enumerate(zeilen):
        if z.rstrip() == "packages:":
            start = i + 1
            ende = next((k for k in range(start, len(zeilen)) if zeilen[k] and not zeilen[k][0].isspace() and zeilen[k][0] != "#"),
                        len(zeilen))
            break
    n, v = re.escape(name), re.escape(version)
    for muster in (re.compile(r"^\s+[\"']?/?" + n + r"[@/]" + v + r"(?:[(_\"':\s]|$)"),
                   re.compile(r"^\s+[\"']?/?" + n + r"[@/]\S")):
        for i in range(start, ende):
            if muster.search(zeilen[i]) and zeilen[i].rstrip().endswith((":", "':", '":')):
                return i
    return None


def _kopf_npm_v1(zeilen: list[str], name: str, version: str) -> int | None:
    """npm lockfileVersion 1: Zeile des Schlüssels `"<name>": {` unter `dependencies` (nicht `"<name>": "^1.0"` unter
    `requires`)."""
    muster = re.compile(r"^\s*" + re.escape(json.dumps(name, ensure_ascii=False)) + r"\s*:\s*\{")
    koepfe = [i for i, z in enumerate(zeilen) if muster.match(z)]
    if not koepfe:
        return None
    return _erster_mit_version(zeilen, koepfe, re.compile(r'"version"\s*:\s*"' + re.escape(version) + '"'))


def _zeile(zeilen: list[str], name: str, version: str, index: _NpmIndex, lockfile: str = "") -> int:
    """Zeile des Pakets im Lockfile: npm Zeile des Schlüssels `"node_modules/<name>"` der installierten Version (ab Version 2),
    sonst der Eintragskopf je Format (yarn, pnpm, npm v1), sonst die erste Zeile mit dem Paketnamen (Namensgrenze schließt `.`
    ein), Fallback 1."""
    schl = index.schluessel.get((name, version))
    if schl is not None:
        ziel = json.dumps(schl) + ":"
        for i, z in enumerate(zeilen, 1):
            if z.lstrip().startswith(ziel):
                return i
    kopf = None
    if lockfile == "yarn.lock":
        kopf = _kopf_yarn(zeilen, name, version)
    elif lockfile == "pnpm-lock.yaml":
        kopf = _kopf_pnpm(zeilen, name, version)
    elif lockfile in NPM_LOCKFILES:
        kopf = _kopf_npm_v1(zeilen, name, version)
    if kopf is not None:
        return kopf + 1
    muster = re.compile(r"(?<![\w@./-])" + re.escape(name) + r"(?![\w.-])")
    for i, z in enumerate(zeilen, 1):
        if muster.search(z):
            return i
    return 1


# ------------------------------------------------------------------------------------ abhaengigkeiten: KEV

class KevFehler(Exception):
    """Der KEV-Katalog konnte nicht geladen oder gelesen werden."""


def _kev_ids(roh: bytes) -> frozenset[str]:
    try:
        daten = json.loads(roh)
    except (ValueError, RecursionError) as e:
        raise KevFehler("kein gültiges JSON") from e
    eintraege = daten.get("vulnerabilities") if isinstance(daten, dict) else None
    if not isinstance(eintraege, list):
        raise KevFehler("unerwartetes Format")
    return frozenset(e["cveID"].strip().upper() for e in eintraege if isinstance(e, dict) and isinstance(e.get("cveID"), str))


def _kev_herunterladen(timeout: float) -> bytes:
    """Katalog laden (https, `timeout` Sekunden insgesamt, höchstens KEV_MAX Bytes)."""
    ende = time.monotonic() + timeout
    anfrage = urllib.request.Request(KEV_URL, headers={"User-Agent": KEV_USER_AGENT})
    try:
        with urllib.request.urlopen(anfrage, timeout=timeout) as antwort:
            if not str(antwort.geturl()).lower().startswith("https://"):
                raise KevFehler("Weiterleitung auf eine Adresse ohne https")
            teile: list[bytes] = []
            gelesen = 0
            while True:
                if time.monotonic() > ende:
                    raise KevFehler("Zeitüberschreitung")
                stueck = antwort.read(1 << 20)
                if not stueck:
                    return b"".join(teile)
                gelesen += len(stueck)
                if gelesen > KEV_MAX:
                    raise KevFehler("Antwort zu groß")
                teile.append(stueck)
    except KevFehler:
        raise
    except Exception as e:                       # Netz, TLS, HTTP-Status, Zeitüberschreitung: nur Hinweis
        raise KevFehler(f"Download fehlgeschlagen: {type(e).__name__}") from e


def _lese_begrenzt(pfad: str, grenze: int) -> bytes:
    with open(pfad, "rb") as f:
        roh = f.read(grenze + 1)
    if len(roh) > grenze:
        raise KevFehler("Datei zu groß")
    return roh


def _kev_cache_schreiben(cache: str, roh: bytes) -> None:
    """Cache atomar anlegen; ein Fehler dabei ist unkritisch (dann wird beim nächsten Aufruf neu geladen)."""
    temp = f"{cache}.{os.getpid()}.neu"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(roh)
        os.replace(temp, cache)
    except OSError:
        try:
            os.unlink(temp)
        except OSError:
            pass


def _kev_laden(lk: str, ende: float, hinweise: list[str]) -> frozenset[str] | None:
    """Menge der CVE-IDs im KEV-Katalog oder None (mit Hinweis). `SECURITY_AUDIT_KEV_DATEI` ersetzt den Download durch eine
    lokale Datei; sonst einmal je Lauf laden und in `<zustand>/lieferkette/kev.json` zwischenspeichern."""
    lokal = os.environ.get("SECURITY_AUDIT_KEV_DATEI")
    cache = os.path.join(lk, "kev.json")
    try:
        if lokal:
            try:
                return _kev_ids(_lese_begrenzt(lokal, KEV_MAX))
            except OSError as e:
                raise KevFehler(f"lokale Datei nicht lesbar ({e.strerror})") from e
        try:
            if stat.S_ISREG(os.lstat(cache).st_mode):
                return _kev_ids(_lese_begrenzt(cache, KEV_MAX))
        except (OSError, KevFehler):
            pass                                  # kein oder defekter Cache: neu laden
        rest = ende - time.monotonic()
        if rest <= 0:
            raise KevFehler("Zeitbudget erschöpft")
        roh = _kev_herunterladen(min(KEV_TIMEOUT, rest))
        ids = _kev_ids(roh)
        _kev_cache_schreiben(cache, roh)
        return ids
    except KevFehler as e:
        hinweise.append(f"KEV-Katalog nicht geladen ({_t(e, 120)}): kev bleibt unbestimmt")
        return None


# ------------------------------------------------------------------------------------ abhaengigkeiten

def _osv_pakete(daten: object) -> list[tuple[str, str, list[dict]]]:
    """(Name, Version, Advisories) je Paket aus der JSON-Ausgabe von osv-scanner; gleiche (Name, Version) zusammengeführt."""
    je_paket: dict[tuple[str, str], list[dict]] = {}
    ergebnisse = daten.get("results") if isinstance(daten, dict) else None
    for ergebnis in ergebnisse if isinstance(ergebnisse, list) else []:
        pakete = ergebnis.get("packages") if isinstance(ergebnis, dict) else None
        for eintrag in pakete if isinstance(pakete, list) else []:
            pkg = eintrag.get("package") if isinstance(eintrag, dict) else None
            vulns = eintrag.get("vulnerabilities") if isinstance(eintrag, dict) else None
            if not (isinstance(pkg, dict) and isinstance(pkg.get("name"), str) and isinstance(pkg.get("version"), str)
                    and isinstance(vulns, list)):
                continue
            ziel = je_paket.setdefault((pkg["name"], pkg["version"]), [])
            for v in vulns:
                if isinstance(v, dict) and isinstance(v.get("id"), str) and all(v["id"] != x["id"] for x in ziel):
                    ziel.append(v)
    return [(n, v, vs) for (n, v), vs in je_paket.items() if vs]


def _advisory(v: dict) -> dict:
    aliase = v.get("aliases")
    return {"id": _t(v["id"], 100),
            "aliase": [_einzeilig(x, 100) for x in (aliase if isinstance(aliase, list) else [])[:MAX_ALIASE]
                       if isinstance(x, str) and x != v["id"]],
            "zusammenfassung": _einzeilig(v.get("summary"), ZUSAMMENFASSUNG_MAX),
            "details": _einzeilig(v.get("details"), DETAILS_MAX)}


def _kev_treffer(vulns: list[dict], kev: frozenset[str]) -> bool:
    for v in vulns:
        aliase = v.get("aliases")
        namen = [v["id"]] + [x for x in (aliase if isinstance(aliase, list) else []) if isinstance(x, str)]
        if any(n.strip().upper() in kev for n in namen):
            return True
    return False


def _scan(rel: str, kopie: str, leer: str, rest: float) -> tuple[str, object]:
    """osv-scanner auf einer Lockfile-Kopie. Rückgabe: ("ok", Daten), ("zeit", None), ("start", Meldung) oder
    ("hinweis", Text) für Exit 127/128/andere und unlesbare Ausgabe."""
    try:
        r = gitkopie.werkzeug_ausfuehren(["osv-scanner", "scan", "source", "--lockfile", kopie, "--format", "json", "--no-resolve"],
                                         rest, leer)
    except GitFehler as e:
        return "start", f"osv-scanner nicht startbar ({_t(e, 200)}), Abhängigkeitsprüfung nicht durchgeführt"
    if r.rc is None:
        return "zeit", None
    if r.rc == 0:
        return "ok", {}
    if r.rc == 128:
        return "hinweis", f"osv-scanner fand keine Pakete (Exit 128): {_t(rel)}"
    if r.rc != 1:
        return "hinweis", f"osv-scanner Exit {r.rc}, Lockfile nicht geprüft: {_t(rel)}"
    try:
        return "ok", json.loads(r.out)
    except (ValueError, RecursionError):
        return "hinweis", f"osv-scanner-Ausgabe unlesbar, Lockfile nicht geprüft: {_t(rel)}"


def _lockfile_eintraege(rel: str, name: str, text: bytes, osv_daten: object) -> list[dict]:
    """Pakete mit Advisories eines Lockfiles (Name, Version, Zeile, Dev, rohe Advisories); erst vollständig, dann übernommen."""
    pakete = _osv_pakete(osv_daten)
    if not pakete:
        return []
    inhalt = text.decode("utf-8", "replace")
    zeilen = inhalt.splitlines()
    index = _npm_index(inhalt) if name in NPM_LOCKFILES else _NpmIndex({}, {})
    return [{"paket": _t(pname, 214), "version": _t(version, 100), "lockfile": _t(rel, 500),
             "zeile": _zeile(zeilen, pname, version, index, name),
             "vulns": vulns, "behoben_in": behoben_in(vulns, pname, version),
             "dev": index.dev.get((pname, version), False)}
            for pname, version, vulns in sorted(pakete, key=lambda p: (p[0], _version_key(p[1])))]


def _abhaengigkeiten(quelle: str, lk: str, abh: str, ende: float) -> dict:
    hinweise: list[str] = []
    eintraege: list[dict] = []                    # Pakete mit den rohen Advisories (für KEV und die Ausgabe)
    lockfiles = _lockfiles_finden(quelle, hinweise)
    if not lockfiles:
        hinweise.append("Keine Lockfiles (npm, yarn, pnpm) in der Arbeitskopie gefunden: Abhängigkeitsprüfung ohne Ergebnis")
    leer = os.path.join(abh, "leer")
    for nr, rel in enumerate(lockfiles, 1):
        rest = ende - time.monotonic()
        offen = f"{len(lockfiles) - nr + 1} von {len(lockfiles)} Lockfiles nicht geprüft"
        if rest <= 0:
            hinweise.append(f"Abhängigkeitsprüfung abgebrochen (Zeitbudget): {offen}")
            break
        name = rel.rsplit("/", 1)[-1]
        ordner = os.path.join(abh, f"lockfile-{nr}")
        os.mkdir(ordner, 0o700)
        kopie = os.path.join(ordner, name)
        try:
            text = _lese_datei(os.path.join(quelle, rel))
            with open(kopie, "xb") as f:
                f.write(text)
        except OSError as e:
            hinweise.append(f"Lockfile nicht lesbar, übersprungen: {_t(rel)} ({e.strerror})")
            continue
        try:                                      # ein feindliches Lockfile darf die übrigen nie mitreißen
            art, wert = _scan(rel, kopie, leer, rest)
            if art == "zeit":
                hinweise.append(f"Abhängigkeitsprüfung abgebrochen (Zeitbudget): {offen} (zuerst: {_t(rel)})")
                break
            if art == "start":
                hinweise.append(str(wert))
                break
            if art == "hinweis":
                hinweise.append(str(wert))
                continue
            eintraege.extend(_lockfile_eintraege(rel, name, text, wert))
        except PocFehler:
            raise
        except Exception as e:                    # nur der Typ, nie Inhalte oder Meldung aus der Kundendatei
            hinweise.append(f"{_t(rel)}: nicht auswertbar ({type(e).__name__})")
    kev = _kev_laden(lk, ende, hinweise) if eintraege else None
    pakete_aus = []
    for e in eintraege[:MAX_PAKETE]:
        vulns = sorted(e["vulns"], key=lambda v: v["id"])
        if len(vulns) > MAX_ADVISORIES:
            hinweise.append(f"{e['paket']} {e['version']}: {len(vulns)} Advisories, {MAX_ADVISORIES} ausgegeben "
                            f"(behoben_in berücksichtigt alle)")
        e["advisories"] = [_advisory(v) for v in vulns[:MAX_ADVISORIES]]
        e["kev"] = None if kev is None else _kev_treffer(vulns, kev)
        pakete_aus.append({k: e[k] for k in ("paket", "version", "lockfile", "zeile", "advisories", "behoben_in", "dev", "kev")})
    if len(eintraege) > MAX_PAKETE:
        hinweise.append(f"{len(eintraege)} Pakete mit Advisories, nur {MAX_PAKETE} ausgegeben")
    return {"pakete": pakete_aus, "hinweise": hinweise}


def cmd_abhaengigkeiten(a: argparse.Namespace) -> int:
    zustand, quelle = _arbeitskopie(a.lauf, a.quelle)
    if fehlt("osv-scanner"):
        hinweis = "osv-scanner fehlt, Abhängigkeitsprüfung nicht durchgeführt"
        _ausgabe({"werkzeug": "osv-scanner", "fehlt": True, "hinweis": hinweis, "pakete": [], "hinweise": [hinweis]})
        return 0
    lk = _lieferkette_ordner(zustand)
    abh = os.path.join(lk, "abh")
    ende = time.monotonic() + _sekunden("SECURITY_AUDIT_ABH_BUDGET", ABH_BUDGET)
    try:
        poc._entferne(abh, lk)                    # Reste eines früheren Aufrufs
        os.mkdir(abh, 0o700)
        os.mkdir(os.path.join(abh, "leer"), 0o700)
        ergebnis = _abhaengigkeiten(quelle, lk, abh, ende)
    finally:
        poc._entferne(abh, lk)                    # auch bei Fehler und Budgetablauf; scheitert das, endet der Befehl mit Exit 1
    _ausgabe(ergebnis)
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
    s = sub.add_parser("abhaengigkeiten", allow_abbrev=False, help="Lockfiles mit osv-scanner prüfen (Advisories, KEV)")
    s.set_defaults(fn=cmd_abhaengigkeiten)
    s.add_argument("--lauf", required=True, type=poc._typ_lauf)
    s.add_argument("--quelle", required=True, help="Arbeitskopie des Laufs (`<zustand>/quelle`)")
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
