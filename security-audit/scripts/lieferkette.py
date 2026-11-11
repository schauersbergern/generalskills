#!/usr/bin/env python3
"""Lieferkette, Abhängigkeiten und Secrets für den Skill security-audit (nur Standardbibliothek).

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I lieferkette.py secrets --lauf <id> --repo <wurzel> --quelle <arbeitskopie> --sha <commit>
  python3 -I lieferkette.py abhaengigkeiten --lauf <id> --quelle <arbeitskopie>
  python3 -I lieferkette.py lieferkette --lauf <id> --quelle <arbeitskopie>

`secrets` (Budget 300 s; `gitleaks dir` zuerst höchstens 120 s ab Start, nach den Vorsuchen mindestens 60 s, die Schwärzung danach
bis zum Gesamtbudget, ein Ablauf ist Exit 4) schwärzt zuerst jede von gitleaks erkannte Secret-Fundstelle der Arbeitskopie (gleiche
Länge, Zeichen `*`, `\\n` und `\\r` bleiben) und prüft das mit einem zweiten `gitleaks dir`-Lauf nach (die Spalten von gitleaks stimmen bei
sehr langen Zeilen nicht: Restfunde werden zeilenweise ganz geschwärzt, bleibt danach einer, ist es Exit 4), setzt dann den Marker `<zustand>/lieferkette/geschwaerzt` (mit der Kennung der Arbeitskopie
aus `quelle.fertig`; wird die Kopie währenddessen neu erstellt, Exit 4 ohne Marker) und prüft danach die Historie in einem
Spiegelklon des Repos. `secrets` und `abhaengigkeiten` teilen sich je Lauf eine Sperre (flock auf `<zustand>/lieferkette`): wer sie
nicht bekommt, endet mit Exit 1, ohne etwas zu löschen. Ausgabe (JSON auf stdout): `befunde_roh` je (Regel, Datei) mit `regel`,
`datei`, `zeile`, `commits` (volle SHAs, höchstens 20, jüngster zuerst) und `in_head`, dazu `hinweise` und `geschwaerzt`; höchstens 200 Einträge
(`MAX_BEFUNDE_ROH`, in HEAD vorhandene zuerst), `in_head` ist `null`, wenn es nicht ermittelt werden konnte. Die
gitleaks-Felder `Secret`, `Match`, `Author`, `Email`, `Message` und `Fingerprint` werden nie ausgegeben, kein Secret-Wert
verlässt den Prozess. Grenze: gitleaks überspringt mit `useDefault = true` bestimmte Pfade (`STANDARD_AUSNAHMEN`, z. B.
`node_modules/`, Lockfiles, `*.svg`); Textdateien dieser Klassen in der Arbeitskopie werden weder geprüft noch geschwärzt und
stehen deshalb im Hinweis „gitleaks-Standardausnahmen nicht geprüft: …“. Secrets ohne bekanntes Muster erkennt gitleaks nirgends: „geschwärzt“ heißt „soweit gitleaks sie erkennt“.

`abhaengigkeiten` (Budget 300 s) kopiert jedes Lockfile (npm `package-lock.json`/`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`;
ohne `node_modules/`) mit seinem Dateinamen in einen eigenen leeren Ordner unter `<zustand>/lieferkette/abh/` und ruft darauf
`osv-scanner scan source --lockfile <kopie> --format json --no-resolve` auf (cwd leer, Umgebung aus `werkzeug_umgebung()`, nie im
Kundenrepo, keine `osv-scanner.toml` des Repos). Ausgabe (JSON auf stdout): `pakete` je Paket (nicht je Advisory) mit `paket`,
`version`, `lockfile`, `zeile`, `advisories` (`id`, `aliase`, `zusammenfassung` ≤ 200, `details` ≤ 500 Zeichen, einzeilig),
`behoben_in` (je Advisory die kleinste Fix-Version oberhalb der installierten im passenden Versionsbereich, davon das Maximum),
`dev` (true nur bei `dev: true` im npm-Lockfile oder im pnpm-Lockfile bis Format 6.0, sonst false; yarn und pnpm ab Format 9 tragen keine Dev-Angabe) und `kev` (true/false, null
wenn der Katalog nicht geladen werden konnte), dazu `hinweise`. Der KEV-Katalog der CISA wird je Lauf einmal geladen und zwischengespeichert
(Cache `<zustand>/lieferkette/kev.json`; scheitert das Zwischenspeichern, lädt der nächste Aufruf erneut; Weiterleitungen nur auf https); `SECURITY_AUDIT_KEV_DATEI` ersetzt den Download durch eine lokale Datei. Aus Kundendateien
erscheinen nur Paketnamen, Versionen und Pfade.

`lieferkette` (Budget 60 s, `SECURITY_AUDIT_LK_BUDGET` darf nur verkürzen) prüft die Arbeitskopie rein statisch (kein Kindprozess, kein
Netz, keine Schreibzugriffe; `os.walk` ohne Symlinks, `node_modules` und `.git` übersprungen, nur reguläre Dateien, Textdateien
höchstens 1 MiB). Ausgabe (JSON auf stdout): `entwuerfe` und `hinweise`. Ein Entwurf ist ein vollständiger Befund ohne `id`
(die vergibt die Hauptsession) mit `werkzeug: lieferkette`, `kategorie: A03`, `status: unbestätigt` und `code_pfad` mit einem
Eintrag; Klassen: `lockfile-fehlt` (P2), `installation-ohne-lockfile-treue` (P2), `install-skripte-offen` (P3). Befehlszeilen
aus dem Repo stehen nie in der Ausgabe (nur der erkannte Befehl), Paketnamen nur, wenn sie dem npm-Namensmuster entsprechen.
Läuft das Budget ab, bleiben die bis dahin gefundenen Entwürfe erhalten (Hinweis „Lieferketten-Prüfung abgebrochen (Zeitbudget)“).

Exit-Codes: 0 ok (auch wenn gitleaks fehlt: `{"werkzeug": "gitleaks", "fehlt": true, ...}`, dann ohne Marker), 2 ungültige
Argumente (auch `--quelle` ≠ Arbeitskopie des Laufs, `quelle.fertig` ohne Kennung), 4 Schwärzung gescheitert (`kategorie: schwaerzung-fehlgeschlagen`, kein
Marker), 1 sonstiger Fehler (z. B. Aufräumen unvollständig, Sperre des Laufs belegt).

Sicherheitsgrenze: Werkzeuge laufen nie im Kundenrepo (cwd ist ein leerer Ordner im Zustandsordner, Umgebung aus
`gitkopie.werkzeug_umgebung()`, eigene Config, eigener leerer Ignore-Ordner, `--ignore-gitleaks-allow`), jedes als eigene
Prozessgruppe (`start_new_session=True`), die bei Zeitüberschreitung als einzige beendet wird. Gelöscht wird nur unter
`<zustand>/lieferkette/` und jede `.gitleaksignore` innerhalb der Arbeitskopie.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import functools
import json
import os
import re
import shlex
import stat
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bericht  # noqa: E402
import gitkopie  # noqa: E402
import poc  # noqa: E402
from gitkopie import GitFehler, ZeitbudgetFehler, _t  # noqa: E402
from poc import PocFehler  # noqa: E402

SECRETS_BUDGET = 300           # Sekunden für `secrets` insgesamt; Skill-Bash-Limit: 600 s
SECRETS_DIR_BUDGET = 120       # davon `gitleaks dir` (zuerst, ab Start gerechnet)
SECRETS_DIR_MINDEST = 60       # so viel bekommt `gitleaks dir` nach den Vorsuchen mindestens (höchstens das Gesamtbudget)
KONFIG_SUCHE_BUDGET = 30       # Suche nach Repo-Konfiguration und `gitleaks:allow` in der Arbeitskopie
AUSNAHMEN_SUCHE_BUDGET = 30    # Suche nach Dateien der gitleaks-Standardausnahmen in der Arbeitskopie
TEXT_PROBE = 8192              # so viele Bytes entscheiden, ob eine Datei Text ist (kein NUL, nicht leer)
MAX_NAMEN_JE_KLASSE = 3        # Dateien je Klasse im Hinweis zu den Standardausnahmen
ALLOW_DATEI_MAX = 16 * 1024 * 1024
REPORT_MAX = 256 * 1024 * 1024
MAX_COMMITS = 20
MAX_BEFUNDE_ROH = 200          # Einträge in `befunde_roh` (Rest als Hinweis; die in HEAD vorhandenen zuerst)
MAX_NENNUNGEN = 10             # Dateien je Hinweis zur Repo-Konfiguration
GITLEAKS_TOML = "[extend]\nuseDefault = true\n"
KONFIG_NAMEN = (".gitleaks.toml", ".gitleaksignore")     # `osv-scanner.toml` meldet `abhaengigkeiten` selbst
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
MAX_PAKETE = bericht.MAX_PAKETE            # Pakete in der Ausgabe (das Befund-Schema begrenzt `pakete` ebenso)
MAX_ADVISORIES = bericht.MAX_ADVISORIES    # Advisories je Paket in der Ausgabe (`behoben_in` zählt alle)
MAX_ALIASE = 10
ZUSAMMENFASSUNG_MAX = 200
DETAILS_MAX = 500
OSV_BEREICHE = ("SEMVER", "ECOSYSTEM")
OSV_AUSGABE_MAX = 32 * 1024 * 1024   # Bytes der stdout von osv-scanner, die ausgewertet werden (Rest: Hinweis, Lockfile nicht ausgewertet)


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
    _klasse(".git (Ordner oder Datei)", r"(?:^|/)\.git(?:/|$)", "sub/.git/a.js", "x/.git/config", ".git", "sub/.git", gross_klein=True),
    _klasse("Python-Umgebungen (venv, site-packages, dist-info)",
            r"(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$"
            r"|(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$"
            r"|(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$",
            "venv/lib/python3.11/site-packages/a.py", "env/lib/python3.9/site-packages/a.py", "lib/python3.11/site-packages/a.py",
            "python/3.11/lib/site-packages/a.py", "foo-1.0.dist-info/METADATA", "x/virtualenv/lib64/a.py", "venv/lib",
            ".venv/lib/python3.12/a.py", "ENV/LIB/a.py", "a/lib64/python3.11/b.py", gross_klein=True),
    _klasse("JavaScript-Bibliotheken (angular, bootstrap, jquery, plotly, swagger-ui) und javascript.json",
            r"(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$"
            r"|(?:^|/)javascript\.json$",
            "static/jquery-3.6.0.min.js", "bootstrap.js", "web/angular.min.js.map", "plotly-latest.min.js", "swagger-ui-bundle.js",
            "jquery-ui.js", "static/javascript.json", gross_klein=True),
    _klasse("Sonstiges (Ruby-Gem, Gradle-Prüfsummen, Datenbank-Refaktorlog)",
            r"\.gem$|verification-metadata\.xml|Database.refactorlog",
            "a.gem", "gradle/verification-metadata.xml", "db/Database.refactorlog", "sub/verification-metadata.xml.bak"),
    _klasse("Bilder (bmp, gif, jpg, png, svg, tif)", r"\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
            "x.svg", "x.png", "x.jpg", "x.jpeg", "x.gif", "x.bmp", "x.tif", "x.tiff", "x.SVG", gross_klein=True),
    _klasse("Schriften (eot, otf, ttf, woff)", r"\.(?:eot|otf|ttf|woff2?)$",
            "x.eot", "x.otf", "x.ttf", "x.woff", "x.woff2", "x.TTF", gross_klein=True),
    _klasse("Office- und Binärformate (doc, xls, pdf, exe, gltf u. ä.)",
            r"\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",      # `.dll` mit Punkt als Platzhalter, wie bei gitleaks
            "x.doc", "x.docx", "x.xls", "x.xlsx", "x.pdf", "x.bin", "x.socket", "x.vsidx", "x.v2", "x.suo", "x.wsuo", "x.pdb",
            "x.exe", "x.gltf", "x.PDF", "x.adll", gross_klein=True),
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


@contextlib.contextmanager
def _sperre(lk: str):
    """Exklusive Sperre (flock, nicht blockierend) auf dem Ordner `<zustand>/lieferkette`: `secrets` und `abhaengigkeiten` auf
    demselben Lauf laufen nie gleichzeitig (sie räumen sonst gegenseitig ihre Arbeitsdateien und den Marker ab). Verschiedene
    Läufe haben verschiedene Ordner und blockieren sich nicht. Die Sperre endet mit dem Prozess, es bleibt nie ein Rest zurück;
    wer sie nicht bekommt, wirft PocFehler (Exit 1), ohne etwas zu löschen."""
    fd = os.open(lk, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise PocFehler("für diesen Lauf läuft bereits ein lieferkette.py-Befehl (secrets oder abhaengigkeiten): "
                            "nacheinander ausführen, nicht parallel", code=1) from e
        yield
    finally:
        os.close(fd)


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


def _schwaerze_treffer(orig: bytes, neu: bytearray, starts: list[int], t: dict, anzeige: str,
                       ganze_zeilen: bool = False) -> list[str]:
    """Eine Fundstelle in `neu` schwärzen (Koordinaten gegen das unveränderte `orig`). gitleaks 8.30 meldet Byte-Spalten,
    1-basiert, Ende inklusiv; ab Zeile 2 sind Start- und Endspalte um 1 zu groß; `EndColumn` kann hinter dem Zeilenende liegen.
    Die Spalten stimmen nicht immer (bei Zeilen ab etwa 120 KB zählt gitleaks ab einer internen Stückgrenze): `ganze_zeilen`
    ignoriert sie und schwärzt die Zeilen `StartLine` bis `EndLine` ganz (nur die Zeilennummern müssen stimmen)."""
    sl, el = _ganzzahl(t.get("StartLine")), _ganzzahl(t.get("EndLine"))
    sc, ec = _ganzzahl(t.get("StartColumn")), _ganzzahl(t.get("EndColumn"))
    if not 1 <= sl <= el <= len(starts):
        raise SchwaerzFehler(f"Fundstelle in {anzeige} liegt außerhalb der Datei (Zeile {sl}-{el} von {len(starts)})")

    def zeilen_ende(zeile: int) -> int:           # Offset des Zeilenendes ohne `\n`
        return starts[zeile + 1] - 1 if zeile + 1 < len(starts) else len(orig)

    if ganze_zeilen:
        von, bis = starts[sl - 1], zeilen_ende(el - 1)
        neu[von:bis] = re.sub(rb"[^\r\n]", b"*", bytes(orig[von:bis]))
        return [f"Schwärzung unscharf: {anzeige}:{sl} (ganze Zeile)"]
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


def schwaerzen(datei: str, treffer: list[dict], wurzel: str | None = None, ganze_zeilen: bool = False) -> list[str]:
    """Fundstellen (Einträge aus dem gitleaks-Bericht) in `datei` überschreiben: nur der Secret-Anteil, byteweise `*`, gleiche
    Länge, `\\n` und `\\r` bleiben. Die Datei wird an Ort und Stelle beschrieben (Rechte und Inode bleiben), nie über einen
    Symlink. Rückgabe: Hinweise („Schwärzung unscharf: <datei>:<zeile>“, wenn Präfix/Suffix nicht an der berechneten Stelle
    stehen; dann wird die ganze Spanne ohne Zeilenumbrüche geschwärzt). Ob die berechnete Stelle wirklich das Secret trifft,
    weiß diese Funktion nicht (gitleaks meldet bei langen Zeilen falsche Spalten, `Match` ist mit `--redact` leer): das prüft
    `_nachpruefen` mit einem zweiten gitleaks-Lauf; `ganze_zeilen` schwärzt die Zeilen ganz. Wirft SchwaerzFehler, wenn die Datei nicht lesbar oder
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
            hinweise += _schwaerze_treffer(orig, neu, starts, t, anzeige, ganze_zeilen)
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


def _schwaerze_arbeitskopie(quelle: str, bericht: list[dict], ende: float | None = None,
                             ganze_zeilen: bool = False) -> tuple[int, list[str]]:
    """Alle Fundstellen des `dir`-Berichts in der Arbeitskopie schwärzen. `File` wird aufgelöst (realpath) und muss innerhalb
    der Arbeitskopie liegen, sonst wird nichts geschrieben. Je Datei wird vorher die Frist `ende` (Wert von `time.monotonic()`)
    geprüft: ein Ablauf ist ein SchwaerzFehler (Teile der Arbeitskopie sind dann schon geschwärzt, es gibt keinen Marker).
    Rückgabe: (Anzahl geschwärzter Fundstellen, Hinweise)."""
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
    for nr, real in enumerate(sorted(je_datei)):
        if ende is not None and time.monotonic() >= ende:
            raise SchwaerzFehler(f"Zeitbudget für die Schwärzung erschöpft ({nr} von {len(je_datei)} Dateien geschwärzt)")
        hinweise += schwaerzen(real, je_datei[real], quelle, ganze_zeilen)
        anzahl += len(je_datei[real])
    if draussen:
        hinweise.append(f"{draussen} Fundstellen außerhalb der Arbeitskopie ignoriert (nichts geschrieben)")
    if anzahl:
        hinweise.insert(0, f"{anzahl} Secret-Fundstellen in der Arbeitskopie geschwärzt")
    return anzahl, hinweise


def _innerhalb(quelle: str, bericht: list[dict]) -> list[dict]:
    """Die Fundstellen des Berichts, deren Datei (realpath) in der Arbeitskopie liegt; SchwaerzFehler bei ungültigem Pfad."""
    innen = []
    for t in bericht:
        pfad = t.get("File")
        if not isinstance(pfad, str) or not pfad or "\0" in pfad:
            raise SchwaerzFehler("Fundstelle ohne gültigen Dateipfad")
        real = os.path.realpath(pfad if os.path.isabs(pfad) else os.path.join(quelle, pfad))
        if os.path.commonpath([real, quelle]) == quelle:
            innen.append(t)
    return innen


def _nachpruefen(quelle: str, lk: str, ende: float) -> list[str]:
    """Fail-closed nach der Schwärzung: ein zweiter `gitleaks dir`-Lauf auf der Arbeitskopie darf nichts mehr finden. Die
    Spalten von gitleaks sind nicht verlässlich (lange Zeilen), die Schwärzung kann daneben liegen. Restfunde werden deshalb
    zeilenweise ganz geschwärzt und noch einmal geprüft; bleibt dann ein Fund (oder läuft die Frist ab), ist das ein
    SchwaerzFehler (Exit 4, kein Marker). Rückgabe: Hinweise."""
    rest = _innerhalb(quelle, _gitleaks_dir(quelle, lk, ende))
    if not rest:
        return []
    _, hinweise = _schwaerze_arbeitskopie(quelle, rest, ende, ganze_zeilen=True)
    uebrig = _innerhalb(quelle, _gitleaks_dir(quelle, lk, ende))
    if uebrig:
        raise SchwaerzFehler(f"nach der Schwärzung bleiben {len(uebrig)} Secret-Fundstellen in der Arbeitskopie")
    return hinweise


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


def _gruppieren(bericht: list[dict], hinweise: list[str] | None = None) -> list[dict]:
    """Je (Regel, Datei) ein Befund: `commits` (voll, jüngster zuerst, höchstens 20), `zeile` aus dem jüngsten Commit.
    Einträge ohne gültige Regel, Datei oder Commit-SHA werden verworfen (die Anzahl steht als Hinweis in `hinweise`, wenn
    übergeben); Wertfelder werden nie gelesen."""
    gruppen: dict[tuple[str, str], list[tuple[float, int, str, int]]] = {}
    verworfen = 0
    for i, t in enumerate(bericht):
        regel, datei, commit = t.get("RuleID"), t.get("File"), t.get("Commit")
        if not (isinstance(regel, str) and regel and isinstance(datei, str) and datei and "\0" not in datei
                and isinstance(commit, str) and VOLLER_SHA.fullmatch(commit)):
            verworfen += 1
            continue
        zeile = t.get("StartLine")
        zeile = zeile if isinstance(zeile, int) and not isinstance(zeile, bool) and zeile >= 1 else 1
        gruppen.setdefault((regel, datei), []).append((_zeitpunkt(t.get("Date")), i, commit, zeile))
    if verworfen and hinweise is not None:
        hinweise.append(f"{verworfen} Fundstellen der Historie mit ungültiger Regel, Datei oder Commit-SHA verworfen")
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
    befunde = _gruppieren(_lese_report(bericht), hinweise)
    sha_da = True
    abgelaufen = False                            # ab hier gilt: die gefundenen Befunde bleiben, `in_head` wird `null`
    try:
        gitkopie.git(spiegel, "cat-file", "-e", f"{sha}^{{commit}}")
    except GitFehler as e:
        if e.returncode is None:
            abgelaufen = True
        else:
            sha_da = False
            hinweise.append(f"Commit {sha[:12]} fehlt im Spiegel (auf keinem Ref erreichbar): in_head nicht ermittelbar")
    unbekannt = 0
    for b in befunde:
        b["in_head"] = None
        b["regel"] = _t(b["regel"], 100)
        if not sha_da:
            continue
        if not abgelaufen:
            try:
                b["in_head"] = _in_head(spiegel, sha, b["datei"])
                continue
            except GitFehler as e:                    # Zeitbudget oder Timeout (`returncode` None): nichts verlieren
                if e.returncode is not None:
                    raise
                abgelaufen = True
        unbekannt += 1
    if unbekannt:
        hinweise.append(f"in_head für {unbekannt} von {len(befunde)} Fundstellen nicht ermittelt (Zeitlimit)")
    return _kappen(befunde, hinweise)


def _kappen(befunde: list[dict], hinweise: list[str]) -> list[dict]:
    """Höchstens `MAX_BEFUNDE_ROH` Befunde: die in HEAD vorhandenen zuerst (dann unbekannt, dann nicht mehr vorhanden), je
    Gruppe nach Datei und Regel; die Ausgabe bleibt nach Datei und Regel sortiert. Bei Kappung steht die Gesamtzahl im Hinweis."""
    if len(befunde) <= MAX_BEFUNDE_ROH:
        return befunde
    rang = {True: 0, None: 1, False: 2}
    behalten = sorted(befunde, key=lambda b: (rang[b["in_head"]], b["datei"], b["regel"]))[:MAX_BEFUNDE_ROH]
    behalten.sort(key=lambda b: (b["datei"], b["regel"]))
    hinweise.append(f"{len(befunde)} Fundstellen in der Historie, nur {MAX_BEFUNDE_ROH} ausgegeben (in HEAD vorhandene zuerst)")
    return behalten


# ------------------------------------------------------------------------------------ secrets

def _marker_setzen(marker: str, anzahl: int, sha: str, kopie: str) -> None:
    """Marker anlegen (nur, wenn er nicht existiert), mit der Kennung der Arbeitskopie, auf der geschwärzt wurde."""
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"geschwaerzt": anzahl, "sha": sha, "kopie": kopie}, f)


def _kopie_unveraendert(lauf: str, kopie: str) -> None:
    """SchwaerzFehler, wenn die Arbeitskopie seit dem Start von `secrets` neu erstellt wurde (`poc.py vorbereiten` läuft auch
    parallel): der Bericht von `gitleaks dir` und die Schwärzung gälten dann einer anderen Kopie."""
    if poc.kopie_kennung(lauf) != kopie:
        raise SchwaerzFehler("Arbeitskopie wurde während der Schwärzung neu erstellt (poc.py vorbereiten): secrets erneut ausführen")


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


def _dir_frist(start: float, teilbudget: float, jetzt: float, ende: float) -> float:
    """Frist für `gitleaks dir`: `teilbudget` Sekunden ab Start, nach langen Vorsuchen aber mindestens `SECRETS_DIR_MINDEST`
    Sekunden (höchstens `teilbudget`) ab jetzt, nie über das Gesamtbudget `ende`."""
    return min(ende, max(start + teilbudget, jetzt + min(SECRETS_DIR_MINDEST, teilbudget)))


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
    kopie = poc.kopie_kennung(a.lauf)
    if kopie is None:
        raise PocFehler("Arbeitskopie ohne Kennung im Fertig-Marker (anderer Stand von `poc.py vorbereiten`): erneut "
                        "`poc.py vorbereiten --lauf … --repo …`")
    lk = _lieferkette_ordner(zustand)
    with _sperre(lk):
        return _secrets_mit_sperre(a, repo, quelle, lk, kopie)


def _secrets_mit_sperre(a: argparse.Namespace, repo: str, quelle: str, lk: str, kopie: str) -> int:
    marker = poc.schwaerz_marker(a.lauf)
    start = time.monotonic()
    ende = start + _sekunden("SECURITY_AUDIT_SECRETS_BUDGET", SECRETS_BUDGET)
    teil = _sekunden("SECURITY_AUDIT_SECRETS_DIR_BUDGET", SECRETS_DIR_BUDGET)
    gitkopie.frist_setzen(ende)
    try:
        poc._entferne(marker, lk)                 # kein Marker ohne diese Schwärzung, auch nicht von einem früheren Lauf
        _aufraeumen(lk)
        return _secrets(a, repo, quelle, lk, marker, kopie, start, teil, ende)
    finally:
        gitkopie.frist_setzen(None)
        try:
            _aufraeumen(lk)
        except PocFehler as e:
            if not os.path.lexists(marker):       # ohne Marker bleibt es Exit 1 (Rest könnte in eine neue Kopie hineinragen)
                raise
            print(f"lieferkette.py: Aufräumen unvollständig, Marker gültig: {_t(e, 200)}", file=sys.stderr)


def _secrets(a: argparse.Namespace, repo: str, quelle: str, lk: str, marker: str, kopie: str, start: float, teil: float,
             ende: float) -> int:
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
        ende_dir = _dir_frist(start, teil, time.monotonic(), ende)
        bericht = _gitleaks_dir(quelle, lk, ende_dir)
        _kopie_unveraendert(a.lauf, kopie)                # vor dem ersten Schreiben: der Bericht gilt dieser Kopie
        anzahl, schwaerz_hinweise = _schwaerze_arbeitskopie(quelle, bericht, ende)
        if anzahl:
            schwaerz_hinweise += _nachpruefen(quelle, lk, ende)
        _kopie_unveraendert(a.lauf, kopie)
    except SchwaerzFehler as e:
        return _schwaerzung_gescheitert(str(e))
    hinweise += schwaerz_hinweise
    try:
        _marker_setzen(marker, anzahl, a.sha, kopie)
    except OSError as e:
        return _schwaerzung_gescheitert(f"Marker nicht setzbar ({e.strerror})")
    befunde: list[dict] = []
    try:
        befunde = _historie(repo, lk, a.sha, ende, hinweise)
    except ZeitbudgetFehler:
        hinweise.append("Secret-Prüfung abgebrochen (Zeitbudget)")
    except (GitFehler, ReportFehler) as e:
        hinweise.append(f"Secret-Prüfung der Historie fehlgeschlagen ({_t(e, 200)})")
    steuer, lang = _pfad_hinweis_zaehler([b["datei"] for b in befunde])
    if steuer:
        hinweise.append(f"{steuer} Secret-Fundstellen der Historie mit unbrauchbarem Dateipfad (Zeilenangabe, Steuer- oder "
                        f"unsichtbare Zeichen) nicht ausgegeben: Historie von Hand prüfen")
    if lang:
        hinweise.append(f"{lang} Secret-Fundstellen der Historie mit überlangem Dateipfad (über {PFAD_MAX} Zeichen) nicht "
                        f"ausgegeben: Historie von Hand prüfen")
    befunde = [b for b in befunde if _pfad_problem(b["datei"]) is None]
    try:
        _aufraeumen(lk)                           # vor der Ausgabe; der Marker ist gesetzt, die Kopie geschwärzt
    except PocFehler as e:                        # kein Abbruch: SKILL.md liest jedes Exit ≠ 0 als „nicht geschwärzt“
        hinweise.append(f"Aufräumen der Arbeitsdateien unvollständig ({_t(e, 200)}): {_t(lk)} von Hand löschen")
    _ausgabe({"befunde_roh": [{"regel": b["regel"], "datei": b["datei"], "zeile": b["zeile"],
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
    im passenden Versionsbereich (Versionslinien!), davon das Maximum. Liegt die installierte Version in keinem Bereich eines
    Advisories (Lücke zwischen zwei Versionslinien), gilt für dieses Advisory die kleinste Fix-Version oberhalb über alle Bereiche,
    möglicherweise die einer anderen Versionslinie: eine nicht betroffene Zielversion, nicht unbedingt der kleinste Sprung.
    None, wenn kein Advisory eine Fix-Version nennt. `advisories` sind die OSV-Einträge (`vulnerabilities`) aus der Ausgabe von
    osv-scanner."""
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
    Symlinks nicht angenommen (Hinweis). Eine Repo-eigene `osv-scanner.toml` wirkt nicht und steht als Hinweis in `hinweise`."""
    gefunden: list[str] = []
    osv_toml: list[str] = []
    unbrauchbar = {"steuer": 0, "lang": 0}
    for ordner, unter, dateien in os.walk(quelle):
        unter[:] = sorted(u for u in unter if u not in ("node_modules", ".git"))
        for name in sorted(dateien):
            if name == "osv-scanner.toml":
                osv_toml.append(os.path.relpath(os.path.join(ordner, name), quelle).replace(os.sep, "/"))
            if name not in LOCKFILE_NAMEN:
                continue
            pfad = os.path.join(ordner, name)
            rel = os.path.relpath(pfad, quelle).replace(os.sep, "/")
            problem = _pfad_problem(rel)
            if problem:                           # kein gültiger `lockfile`-Pfad im Schema: nicht prüfen, nur zählen
                unbrauchbar[problem] += 1
                continue
            try:
                st = os.lstat(pfad)
            except OSError as e:
                hinweise.append(f"Lockfile nicht lesbar, übersprungen: {_t(rel)} ({e.strerror})")
                continue
            if stat.S_ISLNK(st.st_mode):
                hinweise.append(f"Lockfile ist ein Symlink, übersprungen: {_t(rel)}")
            elif not stat.S_ISREG(st.st_mode):
                hinweise.append(f"Lockfile keine reguläre Datei, übersprungen: {_t(rel)}")
            elif st.st_size > LOCKFILE_MAX:
                hinweise.append(f"Lockfile zu groß (> {LOCKFILE_MAX // (1024 * 1024)} MiB), übersprungen: {_t(rel)}")
            else:
                gefunden.append(rel)
    if osv_toml:                                  # osv-scanner läuft auf einer Kopie ohne die Konfiguration des Repos
        hinweise.append(f"osv-scanner.toml im Repo vorhanden, beim Audit ignoriert: {_nennung(osv_toml)}")
    if unbrauchbar["steuer"]:
        hinweise.append(f"{unbrauchbar['steuer']} Lockfiles mit Steuerzeichen oder ungültigen Zeichen im Pfad übersprungen")
    if unbrauchbar["lang"]:
        hinweise.append(f"{unbrauchbar['lang']} Lockfiles mit überlangem Pfad (über {PFAD_MAX} Zeichen) übersprungen")
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


_NAMENSZEICHEN = re.compile(r"[\w@./-]+")                      # Zeichen, aus denen Namensgrenzen der Rückfallsuche bestehen
_YARN_VERSION = re.compile(r"^\s+version:?\s+[\"']?(.*?)[\"']?\s*$")
_NPM_V1_KOPF = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:\s*\{')
_NPM_V1_VERSION = re.compile(r'"version"\s*:\s*"((?:[^"\\]|\\.)*)"')
_NPM_SCHLUESSEL = re.compile(r'"(?:[^"\\]|\\.)*":')
_PNPM_KOPF_ANFANG = re.compile(r"^\s+[\"']?/?")
_PNPM_VERSION_ENDE = re.compile(r"[(_\"':\s]")
EINTRAG_ZEILEN = 6                      # so viele Zeilen hinter einem Kopf gehören zum Eintrag (bis zur nächsten Leerzeile)


class _ZeilenIndex:
    """Zeile eines Pakets in einem Lockfile, ohne je Paket alle Zeilen zu lesen: jede Struktur entsteht beim ersten Gebrauch in
    einem Durchlauf und enthält nur die gefragten (Name, Version)-Paare `paare` (Speicher und Zeit linear in der Dateigröße).
    Reihenfolge der Strategien: npm-Schlüssel `"node_modules/<name>"` der installierten Version (ab Version 2), sonst der
    Eintragskopf je Format (yarn, pnpm, npm v1; bevorzugt der Kopf, dessen Eintrag die installierte Version nennt, sonst der
    erste Kopf des Namens), sonst die erste Zeile mit dem Namen (Namensgrenze schließt `.` ein), Fallback 1."""

    def __init__(self, zeilen: list[str], index: "_NpmIndex", lockfile: str, paare: Iterable[tuple[str, str]]):
        self.zeilen, self.npm, self.lockfile = zeilen, index, lockfile
        self.paare = set(paare)
        self.namen = {n for n, _ in self.paare}
        self._schluessel: dict[str, int] | None = None
        self._koepfe: tuple[dict[str, int], dict[tuple[str, str], int]] | None = None
        self._woerter: dict[str, int] | None = None

    # ---- npm ab lockfileVersion 2
    def _npm_schluessel(self) -> dict[str, int]:
        gefragt = {json.dumps(self.npm.schluessel[p]) + ":" for p in self.paare if p in self.npm.schluessel}
        erg: dict[str, int] = {}
        if gefragt:
            for i, z in enumerate(self.zeilen, 1):
                z = z.lstrip()
                if z.startswith('"'):
                    m = _NPM_SCHLUESSEL.match(z)
                    if m and m.group(0) in gefragt:
                        erg.setdefault(m.group(0), i)
        return erg

    # ---- Eintragsköpfe (yarn, pnpm, npm v1): (erster Kopf je Name, erster Kopf je (Name, installierter Version))
    def _kopf_yarn(self) -> tuple[dict[str, int], dict[tuple[str, str], int]]:
        """yarn.lock: Kopf in Spalte 0 (endet auf `:`), dessen durch `, ` getrennte Spezifikationen (auch in Anführungszeichen)
        mit `<name>@` beginnen; die Version steht in `version "x"` bzw. `version: x` im Eintrag."""
        erster: dict[str, int] = {}
        mit_version: dict[tuple[str, str], int] = {}
        zeilen = self.zeilen
        for i, z in enumerate(zeilen):
            if not z or z[0].isspace() or z[0] == "#" or not z.rstrip().endswith(":"):
                continue
            namen = set()
            for spez in z.rstrip()[:-1].split(", "):
                spez = spez.strip().strip("\"'")
                p = spez.find("@", 1)
                if p > 0 and spez[:p] in self.namen:
                    namen.add(spez[:p])
            if not namen:
                continue
            versionen = set()
            for e in zeilen[i + 1:i + 1 + EINTRAG_ZEILEN]:
                if not e.strip():
                    break
                m = _YARN_VERSION.match(e)
                if m:
                    versionen.add(m.group(1))
            for n in namen:
                erster.setdefault(n, i)
                for v in versionen:
                    mit_version.setdefault((n, v), i)
        return erster, mit_version

    def _kopf_pnpm(self) -> tuple[dict[str, int], dict[tuple[str, str], int]]:
        """pnpm-lock.yaml: Kopf `/name@ver:`, `name@ver:`, `'/name@ver':` (auch `name@ver(peer)` und `/name/ver`) im Abschnitt
        `packages:` (fehlt er, die ganze Datei); die Version endet bei `(`, `_`, Anführungszeichen, `:` oder Leerraum."""
        zeilen = self.zeilen
        start, ende = 0, len(zeilen)
        for i, z in enumerate(zeilen):
            if z.rstrip() == "packages:":
                start = i + 1
                ende = next((k for k in range(start, len(zeilen)) if zeilen[k] and not zeilen[k][0].isspace() and zeilen[k][0] != "#"),
                            len(zeilen))
                break
        erster: dict[str, int] = {}
        mit_version: dict[tuple[str, str], int] = {}
        for i in range(start, ende):
            z = zeilen[i]
            m = _PNPM_KOPF_ANFANG.match(z)
            if not m or not z.rstrip().endswith((":", "':", '":')):
                continue
            rest = z[m.end():]
            for p in range(1, min(len(rest), PAKETNAME_MAX + 2)):
                if rest[p] not in "@/" or rest[:p] not in self.namen or p + 1 >= len(rest):
                    continue
                name, danach = rest[:p], rest[p + 1:]
                if not danach[0].isspace():
                    erster.setdefault(name, i)
                e = _PNPM_VERSION_ENDE.search(danach)
                mit_version.setdefault((name, danach[:e.start()] if e else danach), i)
        return erster, mit_version

    def _kopf_npm_v1(self) -> tuple[dict[str, int], dict[tuple[str, str], int]]:
        """npm lockfileVersion 1: Zeile des Schlüssels `"<name>": {` unter `dependencies` (nicht `"<name>": "^1.0"` unter
        `requires`); die Version steht in `"version": "x"` im Eintrag."""
        erster: dict[str, int] = {}
        mit_version: dict[tuple[str, str], int] = {}
        gefragt = {json.dumps(n, ensure_ascii=False)[1:-1]: n for n in self.namen}
        zeilen = self.zeilen
        for i, z in enumerate(zeilen):
            m = _NPM_V1_KOPF.match(z)
            if not m or m.group(1) not in gefragt:
                continue
            name = gefragt[m.group(1)]
            erster.setdefault(name, i)
            for e in zeilen[i + 1:i + 1 + EINTRAG_ZEILEN]:
                if not e.strip():
                    break
                v = _NPM_V1_VERSION.search(e)
                if v:
                    mit_version.setdefault((name, v.group(1)), i)
        return erster, mit_version

    def _kopf(self, name: str, version: str) -> int | None:
        if self._koepfe is None:
            self._koepfe = (self._kopf_yarn() if self.lockfile == "yarn.lock" else
                            self._kopf_pnpm() if self.lockfile == "pnpm-lock.yaml" else
                            self._kopf_npm_v1() if self.lockfile in NPM_LOCKFILES else ({}, {}))
        erster, mit_version = self._koepfe
        gefunden = mit_version.get((name, version))           # erst der Kopf mit der installierten Version, sonst der erste
        return gefunden if gefunden is not None else erster.get(name)

    # ---- erste Zeile mit dem Namen
    def _erste_nennung(self, name: str) -> int | None:
        if len(name) > PAKETNAME_MAX or not re.fullmatch(r"[\w@./-]+", name):       # ungewöhnlicher Name: Einzelsuche
            muster = re.compile(r"(?<![\w@./-])" + re.escape(name) + r"(?![\w.-])")
            return next((i for i, z in enumerate(self.zeilen, 1) if muster.search(z)), None)
        if self._woerter is None:
            erg: dict[str, int] = {}
            for i, z in enumerate(self.zeilen, 1):
                for t in _NAMENSZEICHEN.finditer(z):
                    wort = t.group(0)[:PAKETNAME_MAX + 2]
                    laenge = len(t.group(0))
                    for p in range(1, len(wort) + 1):
                        if (p == laenge or (p < len(wort) and wort[p] in "@/")) and wort[:p] in self.namen:
                            erg.setdefault(wort[:p], i)
            self._woerter = erg
        return self._woerter.get(name)

    def zeile(self, name: str, version: str) -> int:
        schl = self.npm.schluessel.get((name, version))
        if schl is not None:
            if self._schluessel is None:
                self._schluessel = self._npm_schluessel()
            z = self._schluessel.get(json.dumps(schl) + ":")
            if z is not None:
                return z
        kopf = self._kopf(name, version)
        if kopf is not None:
            return kopf + 1
        return self._erste_nennung(name) or 1


def _zeile(zeilen: list[str], name: str, version: str, index: _NpmIndex, lockfile: str = "") -> int:
    """Zeile des Pakets im Lockfile (Einzelabfrage; für viele Pakete `_ZeilenIndex` einmal je Lockfile bilden)."""
    return _ZeilenIndex(zeilen, index, lockfile, [(name, version)]).zeile(name, version)


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


class _NurHttpsUmleitung(urllib.request.HTTPRedirectHandler):
    """Folgt Weiterleitungen nur auf https: jeder Schritt wird geprüft, nicht erst die Endadresse (eine http-Zwischenstation
    würde sonst angefragt)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise KevFehler("Weiterleitung auf eine Adresse ohne https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _kev_herunterladen(timeout: float) -> bytes:
    """Katalog laden (https, `timeout` Sekunden insgesamt, höchstens KEV_MAX Bytes). Die Frist gilt für das Ganze, auch bei
    einem Server, der nur tröpfelt: gelesen wird mit `read1` (ein Socket-Lesen je Aufruf, selbst begrenzt durch `timeout`),
    die Frist wird nach jedem Stück geprüft; Weiterleitungen nur auf https."""
    ende = time.monotonic() + timeout
    anfrage = urllib.request.Request(KEV_URL, headers={"User-Agent": KEV_USER_AGENT})
    urllib.request.install_opener(urllib.request.build_opener(_NurHttpsUmleitung()))
    try:
        with urllib.request.urlopen(anfrage, timeout=timeout) as antwort:
            if not str(antwort.geturl()).lower().startswith("https://"):
                raise KevFehler("Weiterleitung auf eine Adresse ohne https")
            teile: list[bytes] = []
            gelesen = 0
            while True:
                if time.monotonic() > ende:
                    raise KevFehler("Zeitüberschreitung")
                stueck = antwort.read1(1 << 16)
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
    """osv-scanner auf einer Lockfile-Kopie. Rückgabe: ("ok", {}) bei Exit 0 (keine Lücken), ("treffer", Daten) bei Exit 1,
    ("zeit", None), ("start", Meldung) oder ("hinweis", Text) für Exit 127/128/andere, zu große und unlesbare Ausgabe."""
    try:
        r = gitkopie.werkzeug_ausfuehren(["osv-scanner", "scan", "source", "--lockfile", kopie, "--format", "json", "--no-resolve"],
                                         rest, leer, ausgabe_max=OSV_AUSGABE_MAX)
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
    if r.abgeschnitten:
        return "hinweis", f"osv-scanner-Ausgabe zu groß, Lockfile nicht ausgewertet: {_t(rel)}"
    try:
        return "treffer", json.loads(r.out)
    except (ValueError, RecursionError):
        return "hinweis", f"osv-scanner-Ausgabe unlesbar, Lockfile nicht geprüft: {_t(rel)}"


def _lockfile_eintraege(rel: str, name: str, text: bytes, osv_daten: object, ende: float | None = None,
                        hinweise: list[str] | None = None) -> list[dict]:
    """Pakete mit Advisories eines Lockfiles (Name, Version, Zeile, Dev, rohe Advisories); erst vollständig, dann übernommen.
    Die Zeilen kommen aus einem Index je Lockfile; ist die Frist `ende` abgelaufen, bekommen die übrigen Pakete `zeile` 1
    und ein Hinweis in `hinweise` nennt die Anzahl."""
    pakete = _osv_pakete(osv_daten)
    if not pakete:
        return []
    inhalt = text.decode("utf-8", "replace")
    zeilen = inhalt.splitlines()
    index = (_npm_index(inhalt) if name in NPM_LOCKFILES else _NpmIndex(_pnpm_dev(inhalt), {}) if name == "pnpm-lock.yaml"
             else _NpmIndex({}, {}))
    sortiert = sorted(pakete, key=lambda p: (p[0], _version_key(p[1])))
    zeilen_index = _ZeilenIndex(zeilen, index, name, [(n, v) for n, v, _ in sortiert])
    erg = []
    ohne_zeile = 0
    for pname, version, vulns in sortiert:
        if ende is not None and time.monotonic() >= ende:
            zeile = 1
            ohne_zeile += 1
        else:
            zeile = zeilen_index.zeile(pname, version)
        erg.append({"paket": _t(pname, 214), "version": _t(version, 100), "lockfile": rel, "zeile": zeile,
                    "vulns": vulns, "behoben_in": behoben_in(vulns, pname, version),
                    "dev": index.dev.get((pname, version), False)})
    if ohne_zeile and hinweise is not None:
        hinweise.append(f"Zeilenermittlung abgebrochen (Zeitbudget): {ohne_zeile} Pakete in {_t(rel)} ohne Zeile")
    return erg


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
            neu = _lockfile_eintraege(rel, name, text, wert, ende, hinweise) if art == "treffer" else []
            if art == "treffer" and not neu:        # Exit 1 heißt Treffer: keine auswertbaren Pakete ist kein „sauber“
                hinweise.append("osv-scanner meldete Treffer (Exit 1), die Ausgabe enthält aber keine auswertbaren Pakete: "
                                f"Lockfile nicht ausgewertet: {_t(rel)}")
            eintraege.extend(neu)
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
    with _sperre(lk):
        ende = time.monotonic() + _sekunden("SECURITY_AUDIT_ABH_BUDGET", ABH_BUDGET)
        try:
            poc._entferne(abh, lk)                # Reste eines früheren Aufrufs
            os.mkdir(abh, 0o700)
            os.mkdir(os.path.join(abh, "leer"), 0o700)
            ergebnis = _abhaengigkeiten(quelle, lk, abh, ende)
        finally:
            poc._entferne(abh, lk)                # auch bei Fehler und Budgetablauf; scheitert das, endet der Befehl mit Exit 1
    _ausgabe(ergebnis)
    return 0


# ------------------------------------------------------------------------------------ lieferkette: statische Prüfung

LK_BUDGET = 60                 # Sekunden für `lieferkette` insgesamt (rein statisch, kein Kindprozess)
TEXT_MAX = 1024 * 1024         # Bytes je Textdatei (Dockerfile, Workflow, Makefile, package.json, Konfiguration)
MAX_TEXTDATEIEN = 500          # so viele Textdateien werden höchstens ausgewertet (Rest als Hinweis)
MAX_EINTRAEGE = 200_000        # Verzeichniseinträge, die die Suche in der Arbeitskopie höchstens besucht
MAX_ENTWUERFE = 200            # Entwürfe in der Ausgabe
MAX_HINWEISE = 50              # Hinweise in der Ausgabe (feindliche Arbeitskopien erzeugen sonst beliebig viele)
MAX_PAKETNAMEN = 20            # Paketnamen in der Beschreibung von `install-skripte-offen`
PAKETNAME_MAX = 214
ZEIT_HINWEIS = "Lieferketten-Prüfung abgebrochen (Zeitbudget)"
LIEFERKETTE_LOCKFILES = LOCKFILE_NAMEN + ("bun.lock", "bun.lockb")
ABHAENGIGKEIT_FELDER = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
BEFUND_GRUND = "Werkzeugbefund, kein Request-Beleg möglich"
YARN_V1_MARKE = b"# yarn lockfile v1"
YARN_V1_KOPF = 2048
NPM_PAKETNAME = re.compile(r"(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*", re.ASCII)
DOCKER_ANDERE = frozenset(("from", "copy", "add", "env", "arg", "cmd", "entrypoint", "workdir", "label", "expose", "user",
                           "volume", "healthcheck", "shell", "stopsignal", "maintainer"))
YAML_PRAEFIX = re.compile(r"(?:-\s+|(?:run|script|before_script|after_script|command|commands)\s*:\s*)")
ENV_ZUWEISUNG = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
BEFEHLSTRENNER = re.compile(r"&&|\|\||;|\|")
KURZ_GLOBAL = re.compile(r"-[A-Za-z]*g[A-Za-z]*")
# npm-Aliasse von `install` (npm `lib/utils/cmd-list.js`, `install-test` mit `it`); `ci` und seine Aliasse sind lockfile-treu
NPM_INSTALL_ALIASSE = ("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add",
                       "install-test", "it")
PNPM_REKURSIV = ("recursive", "multi", "m")
NPX_WERT_OPTIONEN = frozenset(("-p", "--package", "-c", "--call"))
WERT_OPTIONEN = frozenset(("--prefix", "-C", "--cwd", "--workspace", "-w", "--registry", "--cache", "--loglevel",
                           "--userconfig", "--filter", "-F", "--dir", "--modules-folder"))
VORSATZ_BEFEHLE = ("sudo", "env", "exec", "time", "nohup", "timeout")
VORSATZ_WERT_OPTIONEN = {"sudo": frozenset(("-u", "-g", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user", "--group")),
                         "env": frozenset(("-u", "-C", "-S")), "timeout": frozenset(("-s", "-k", "--signal", "--kill-after"))}
KONTROLLWOERTER = frozenset(("if", "then", "else", "elif", "do", "while", "until", "!", "{"))   # Befehlsanfang in Shell-Konstrukten
TRENNER_ZEICHEN = frozenset("();|&")        # Token nur aus diesen Zeichen: Shell-Operator (`;`, `&&`, `||`, `|`, `&`, `(`, `)`)
SHELLS = frozenset(("sh", "bash", "dash", "zsh", "ash"))
SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
SHELL_TIEFE = 3                             # so oft werden `sh -c`-Skripte höchstens entpackt
ZEILE_MAX = 64 * 1024                       # längere logische Zeilen werden nicht tokenisiert (Laufzeit, feindliche Dateien)
PFAD_MAX = 300                              # längere relative Pfade werden übersprungen
ZEILE_AM_ENDE = re.compile(r":[0-9]+(?::[0-9]+)?\Z|#L[0-9]+(?:C[0-9]+)?(?:-L?[0-9]+(?:C[0-9]+)?)?\Z")   # wie bericht._ZEILE_IM_PFAD
PNPM_LISTE = re.compile(r"\s*(?:only|never)BuiltDependencies\s*:")
KONFIG_NAMEN_LK = (".npmrc", "pnpm-workspace.yaml")     # `.yarnrc.yml` wird nicht gelesen, siehe `geschuetzt` in `_statisch`
KLASSEN_REIHENFOLGE = {"lockfile-fehlt": 0, "installation-ohne-lockfile-treue": 1, "install-skripte-offen": 2}


class _Zeit(Exception):
    """Das Zeitbudget von `lieferkette` ist aufgebraucht."""


class _Sammler:
    """Sammelt Entwürfe und Hinweise (beide begrenzt). Entwürfe bleiben auch erhalten, wenn das Budget abläuft. Entwürfe, die
    das Befund-Schema ablehnt (feindliche Pfade), werden verworfen und gezählt. Bei mehr als `MAX_ENTWUERFE` Entwürfen bleiben
    die mit der höchsten Schwere (P2 vor P3), bei gleicher Stufe die zuerst gefundenen."""

    def __init__(self) -> None:
        self.entwuerfe: list[dict] = []
        self.hinweise: list[str] = []
        self.zu_viele_hinweise = 0
        self.gefunden = 0                      # gültige Entwürfe insgesamt
        self.ungueltig = 0                     # Entwürfe, die das Schema ablehnt
        self.ueberlang = 0                     # logische Zeilen über ZEILE_MAX
        self._nummer: list[int] = []           # Fundnummer je Entwurf in `entwuerfe`
        self._je_stufe: Counter = Counter()
        self._gesehen: set[str] = set()
        self._schema_ok: dict[str, bool] = {}

    def hinweis(self, text: str) -> None:
        if text in self._gesehen:
            return
        self._gesehen.add(text)
        if len(self.hinweise) < MAX_HINWEISE:
            self.hinweise.append(text)
        else:
            self.zu_viele_hinweise += 1

    def entwurf(self, e: dict) -> None:
        # Gültigkeit hängt nicht an `zeile`/`code_pfad` (Zeile ist eine positive Zahl); Prüfung je Rest einmal (sonst
        # Sekunden je großer Kundendatei).
        schluessel = json.dumps({k: v for k, v in e.items() if k not in ("zeile", "code_pfad")}, sort_keys=True)
        if schluessel not in self._schema_ok:
            self._schema_ok[schluessel] = not bericht._befund_fehler({**e, "id": "S-1"}, "entwurf")
        if not self._schema_ok[schluessel]:
            self.ungueltig += 1
            return
        self.gefunden += 1
        if len(self.entwuerfe) < MAX_ENTWUERFE:
            self.entwuerfe.append(e)
            self._nummer.append(self.gefunden)
            self._je_stufe[e["stufe"]] += 1
            return
        schlechteste = max(k for k, v in self._je_stufe.items() if v)
        if e["stufe"] < schlechteste:           # nur eine bessere Stufe verdrängt (der zuletzt gefundene der schlechtesten)
            i = max((i for i, x in enumerate(self.entwuerfe) if x["stufe"] == schlechteste), key=lambda i: self._nummer[i])
            self._je_stufe[schlechteste] -= 1
            self._je_stufe[e["stufe"]] += 1
            self.entwuerfe[i] = e
            self._nummer[i] = self.gefunden

    def abschluss(self) -> list[str]:
        self.entwuerfe.sort(key=lambda e: (KLASSEN_REIHENFOLGE[e["klasse"]], e["datei"], e["zeile"]))
        h = list(self.hinweise)
        if self.gefunden > len(self.entwuerfe):
            h.append(f"{self.gefunden} Entwürfe gefunden, nur {MAX_ENTWUERFE} ausgegeben (P2 vor P3, dann "
                     "Fundreihenfolge)")
        if self.ungueltig:
            h.append(f"{self.ungueltig} Entwürfe mit ungültigem Pfad ausgelassen")
        if self.ueberlang:
            h.append(f"{self.ueberlang} überlange Zeilen nicht ausgewertet")
        if self.zu_viele_hinweise:
            h.append(f"{self.zu_viele_hinweise} weitere Hinweise ausgelassen")
        return h


def _zeitcheck(ende: float) -> None:
    if time.monotonic() >= ende:
        raise _Zeit()


def _sauber(name: str, datei: bool = False) -> bool:
    """Name ohne Steuer-, Format- oder unsichtbare Zeichen (und ohne ungültiges UTF-8) und ohne Backtick. Dateinamen dürfen
    außerdem nicht auf eine Zeilenangabe enden (`:12`, `#L5`): das Befund-Schema trennt Pfad und Zeile."""
    if "`" in name or (datei and ZEILE_AM_ENDE.search(name)):
        return False
    return (name.isascii() and name.isprintable()) or _t(name, 10**9) == name


def _pfad_problem(rel: str) -> str | None:
    """None, wenn `rel` (relativer Pfad, `/`) als `datei` oder `lockfile` ins Befund-Schema passt; sonst "lang" (über
    `PFAD_MAX`) oder "steuer" (Steuer-, Format- oder unsichtbare Zeichen, Backtick, Zeilenangabe am Ende, nicht normalisiert).
    Solche Pfade werden nie gekappt (der Pfad passte dann nicht mehr zum Repo), sondern ausgelassen und gemeldet."""
    if len(rel) > PFAD_MAX:
        return "lang"
    if not _sauber(rel, True) or bericht._pfad_fehler(rel):
        return "steuer"
    return None


def _pfad_hinweis_zaehler(rels: list[str]) -> tuple[int, int]:
    """(Anzahl mit Pfadproblem "steuer", Anzahl mit "lang") unter `rels`."""
    probleme = [_pfad_problem(r) for r in rels]
    return probleme.count("steuer"), probleme.count("lang")


def _eltern(ordner: str) -> list[str]:
    """`a/b` -> [`a/b`, `a`, ``]: der Ordner und alle Elternordner bis zur Wurzel der Arbeitskopie (leerer String)."""
    teile = ordner.split("/") if ordner else []
    return ["/".join(teile[:n]) for n in range(len(teile), -1, -1)]


def _ordner_von(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


class _Baum:
    """Ergebnis der Suche: reguläre Dateien der Arbeitskopie nach Art (relativer Pfad `/`, Größe)."""

    def __init__(self) -> None:
        self.lockfiles: list[tuple[str, int]] = []       # alle erkannten Lockfiles (auch bun)
        self.pakete: list[tuple[str, int]] = []          # package.json
        self.texte: list[tuple[str, str, int]] = []      # (rel, art, größe) mit art docker | ci | make
        self.konfig: dict[tuple[str, str], tuple[str, int]] = {}    # (Ordner, Name) -> (rel, größe)


def _art(name: str, ordner: str) -> str | None:
    klein = name.lower()
    if klein.startswith("dockerfile") or klein.endswith(".dockerfile"):
        return "docker"
    if name in ("Makefile", "makefile", "GNUmakefile"):
        return "make"
    if name == ".gitlab-ci.yml":
        return "ci"
    if klein.endswith((".yml", ".yaml")) and (ordner == ".github/workflows" or ordner.endswith("/.github/workflows")):
        return "ci"
    if name == "package.json":
        return "pkg"
    if name in LIEFERKETTE_LOCKFILES:
        return "lock"
    if name in KONFIG_NAMEN_LK:
        return "konfig"
    return None


def _baum_suchen(quelle: str, ende: float, s: _Sammler) -> _Baum:
    """`os.walk` ohne Symlinks; `node_modules` und `.git` werden nicht betreten, nur reguläre Dateien. Pfade mit Steuerzeichen,
    Backtick, Zeilenangabe am Dateinamen oder über `PFAD_MAX` Zeichen werden übersprungen und gezählt; ein Fehler des
    Verzeichnislaufs (`RecursionError`, `OSError`) beendet die Suche mit einem Hinweis, bisherige Funde bleiben."""
    baum = _Baum()
    besucht = 0
    steuer = 0
    lang = 0
    try:
        for ordner, unter, dateien in os.walk(quelle):
            _zeitcheck(ende)
            rel_ordner = "" if ordner == quelle else os.path.relpath(ordner, quelle).replace(os.sep, "/")
            behalten = []
            for u in sorted(unter):
                if u in ("node_modules", ".git"):
                    continue
                if not _sauber(u):
                    steuer += 1
                elif len(rel_ordner) + len(u) + 2 > PFAD_MAX:
                    lang += 1
                else:
                    behalten.append(u)
            unter[:] = behalten
            for name in sorted(dateien):
                besucht += 1
                if besucht > MAX_EINTRAEGE:
                    s.hinweis(f"Suche nach {MAX_EINTRAEGE} Einträgen abgebrochen: weitere Dateien nicht geprüft")
                    return _pfad_hinweise(baum, steuer, lang, s)
                art = _art(name, rel_ordner)
                if art is None:
                    continue
                if not _sauber(name, True):
                    steuer += 1
                    continue
                rel = f"{rel_ordner}/{name}" if rel_ordner else name
                if len(rel) > PFAD_MAX:
                    lang += 1
                    continue
                try:
                    st = os.lstat(os.path.join(ordner, name))
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):               # Symlinks, FIFOs, Geräte: nie lesen
                    continue
                if art == "lock":
                    baum.lockfiles.append((rel, st.st_size))
                elif art == "pkg":
                    baum.pakete.append((rel, st.st_size))
                elif art == "konfig":
                    baum.konfig[(rel_ordner, name)] = (rel, st.st_size)
                else:
                    baum.texte.append((rel, art, st.st_size))
    except (RecursionError, OSError) as e:
        s.hinweis(f"Verzeichnissuche abgebrochen ({type(e).__name__}): weitere Dateien nicht geprüft")
    return _pfad_hinweise(baum, steuer, lang, s)


def _pfad_hinweise(baum: _Baum, steuer: int, lang: int, s: _Sammler) -> _Baum:
    if steuer:
        s.hinweis(f"{steuer} Pfade mit Steuerzeichen oder ungültigen Zeichen übersprungen")
    if lang:
        s.hinweis(f"{lang} überlange Pfade übersprungen")
    return baum


def _lese_text(quelle: str, rel: str, groesse: int, s: _Sammler, grenze: int = TEXT_MAX) -> str | None:
    """Textdatei (UTF-8 mit Ersatzzeichen) oder None: zu groß (Hinweis) oder nicht lesbar (Ausnahme nach oben)."""
    if groesse > grenze:
        s.hinweis(f"{rel}: zu groß (> {grenze // (1024 * 1024)} MiB), übersprungen")
        return None
    return _lese_datei(os.path.join(quelle, rel))[:grenze].decode("utf-8", "replace")


def _kopf_lesen(pfad: str, n: int) -> bytes:
    fd = os.open(pfad, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as f:
        return f.read(n)


def _je_datei(s: _Sammler, rel: str, fn):
    """Ruft `fn()`; jede Ausnahme außer dem Zeitbudget wird zum Hinweis (nur der Typ, nie Inhalte oder Meldung)."""
    try:
        return fn()
    except _Zeit:
        raise
    except Exception as e:
        s.hinweis(f"{_t(rel)}: nicht auswertbar ({type(e).__name__})")
        return None


# ------------------------------------------------------------------------------------ lieferkette: Befehle erkennen

class _Aufruf(NamedTuple):
    zeile: int
    pm: str                      # npm | pnpm | yarn
    label: str | None            # erkannter Befehl für die Meldung; None: lockfile-treu oder kein Install-Befehl
    skripte_aus: bool | None     # nur npm-Installationen (install/i/ci, nicht global): trägt `--ignore-scripts`?


def _logische_zeilen(text: str) -> list[tuple[int, str]]:
    """[(erste physische Zeile, Text)]; `\\` am Zeilenende verbindet mit der nächsten Zeile."""
    erg: list[tuple[int, str]] = []
    puffer: str | None = None
    start = 0
    for nr, z in enumerate(text.split("\n"), 1):
        z = z.rstrip("\r")
        if puffer is None:
            start, puffer = nr, ""
        rest = z.rstrip()
        if rest.endswith("\\") and not (puffer == "" and rest.lstrip().startswith("#")):
            puffer += rest[:-1] + " "
            continue
        erg.append((start, puffer + z))
        puffer = None
    if puffer is not None:
        erg.append((start, puffer))
    return erg


def _tokenisieren(teil: str) -> list[str] | None:
    """Shell-Tokens mit Operatoren als eigenen Tokens (`;`, `&&`, `||`, `|`, `(`, `)` in Anführungszeichen bleiben Teil des
    Worts); None bei ungültigem Quoting."""
    try:
        lex = shlex.shlex(teil, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _segmente(tokens: list[str]) -> list[list[str]]:
    """Token-Liste an den Shell-Operator-Tokens in Befehle zerlegen (erst nach der Tokenisierung)."""
    erg: list[list[str]] = []
    seg: list[str] = []
    for t in tokens:
        if t and set(t) <= TRENNER_ZEICHEN:
            erg.append(seg)
            seg = []
        else:
            seg.append(t)
    erg.append(seg)
    return erg


def _ohne_vorsatz(tokens: list[str]) -> list[str]:
    """Führende Make-Präfixe (`@`, `-`, `+`), Kontrollwörter (`then`, `do`, `else` …), Umgebungszuweisungen und
    `sudo`/`env`/`exec`/`time`/`nohup`/`timeout` samt ihren Optionen übergehen."""
    tokens = list(tokens)
    if tokens:
        tokens[0] = tokens[0].lstrip("@-+")
    while tokens and not tokens[0]:
        tokens.pop(0)
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if ENV_ZUWEISUNG.match(t) or t in KONTROLLWOERTER:
            i += 1
        elif t in VORSATZ_BEFEHLE:
            i += 1
            mit_wert = VORSATZ_WERT_OPTIONEN.get(t, frozenset())
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 2 if tokens[i] in mit_wert else 1
            if t == "timeout":
                i += 1                                       # die Dauer
        else:
            break
    return tokens[i:]


def _shell_skript(tok: list[str]) -> str | None:
    """Das Skript hinter `sh -c`, `bash -lc`, `/bin/sh -ec` …; sonst None."""
    if not tok or tok[0].rsplit("/", 1)[-1] not in SHELLS:
        return None
    i = 1
    while i < len(tok) and tok[i].startswith(("-", "+")):
        if SHELL_C.fullmatch(tok[i]):
            return tok[i + 1] if i + 1 < len(tok) else None
        i += 2 if tok[i] in ("-o", "+o") else 1
    return None


def _befehle(zeile: str, art: str, tiefe: int = 0) -> list[list[str]]:
    """Befehlssegmente (Token-Listen) einer logischen Zeile; Präfixe wie Docker-`RUN`, YAML-`- `/`run:`/`script:` entfernt.
    `sh -c <skript>` wird (bis `SHELL_TIEFE`) rekursiv ausgewertet, auch in der Exec-Form."""
    if art == "shell" and "\n" in zeile:                     # Zeilenumbruch im Skript trennt Befehle
        return [t for z in zeile.splitlines() for t in _befehle(z, art, tiefe)]
    s = zeile.strip()
    if not s or s.startswith("#"):
        return []
    if art == "ci":
        for _ in range(4):
            m = YAML_PRAEFIX.match(s)
            if not m:
                break
            s = s[m.end():].lstrip()
        if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
            s = s[1:-1]
    segmente = None
    if art == "docker":
        teile = s.split(None, 1)
        wort, rest = teile[0], (teile[1] if len(teile) > 1 else "")
        if wort.lower() == "onbuild":
            teile = rest.split(None, 1)
            wort, rest = (teile[0], teile[1] if len(teile) > 1 else "") if teile else ("", "")
        if wort.lower() in DOCKER_ANDERE:
            return []
        if wort.lower() == "run":
            s = re.sub(r"^(?:--\S+\s+)+", "", rest.lstrip())
            if s.startswith("["):
                try:
                    liste = json.loads(s)
                except (ValueError, RecursionError):
                    liste = None
                if isinstance(liste, list) and liste and all(isinstance(x, str) for x in liste):
                    segmente = [list(liste)]
    if segmente is None:
        tokens = _tokenisieren(s)
        segmente = [t.split() for t in BEFEHLSTRENNER.split(s)] if tokens is None else _segmente(tokens)
    erg = []
    for seg in segmente:
        tok = _ohne_vorsatz(seg)
        skript = _shell_skript(tok) if tiefe < SHELL_TIEFE else None
        if skript is not None:
            erg.extend(_befehle(skript, "shell", tiefe + 1))
        elif tok:
            erg.append(tok)
    return erg


def _flag_an(args: list[str], name: str) -> bool:
    """Ist die Option `name` gesetzt? `--name`, `--name=true` ja; `--name=false`/`=0`/`=no`/`=off` und `--no-name` nein; die
    letzte Angabe gilt."""
    an = False
    for a in args:
        if a == name:
            an = True
        elif a.startswith(name + "="):
            an = a.split("=", 1)[1].strip().lower() not in ("", "false", "0", "no", "off")
        elif a == "--no-" + name[2:]:
            an = False
    return an


def _naechstes_wort(args: list[str], ab: int) -> tuple[str | None, int]:
    """Erstes Wort ohne führendes `-` ab Index `ab` (Optionen mit Wert, `WERT_OPTIONEN`, überspringen ihr Argument) und sein
    Index; (None, len(args)) ohne ein solches Wort."""
    i = ab
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if (a in WERT_OPTIONEN and "=" not in a) else 1
            continue
        return a, i
    return None, len(args)


def _bewerte_npx(args: list[str]) -> tuple[str, str | None, bool | None] | None:
    """`npx [Optionen] <npm|pnpm|yarn>[@Version] …`: wie der Paketmanager ohne `npx` bewerten; sonst None."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in NPX_WERT_OPTIONEN else 1
    if i >= len(args):
        return None
    name = args[i].split("@", 1)[0]
    return _bewerte([name, *args[i + 1:]]) if name in ("npm", "pnpm", "yarn") else None


def _bewerte(tok: list[str]) -> tuple[str, str | None, bool | None] | None:
    """(Paketmanager, Label, skripte_aus) für npm-, pnpm- und yarn-Befehle, die installieren; sonst None. Label None: der Aufruf
    ist lockfile-treu (`npm ci`, `--frozen-lockfile`, `--immutable`, jeweils nicht `=false`) oder ein Sonderfall (global,
    nur Lockfile). `skripte_aus` nur für npm- und pnpm-Installationen: trägt der Aufruf `--ignore-scripts`?"""
    pm = tok[0]
    if pm == "npx":                                          # `npx -y pnpm install` führt den Paketmanager aus
        return _bewerte_npx(tok[1:])
    if pm not in ("npm", "pnpm", "yarn"):
        return None
    args = tok[1:]
    flags = {a.split("=", 1)[0] for a in args if a.startswith("-")}
    sub, i = _naechstes_wort(args, 0)
    if pm == "pnpm" and sub in PNPM_REKURSIV:                # `pnpm recursive install`: das Wort danach ist der Unterbefehl
        sub, i = _naechstes_wort(args, i + 1)
        if sub is None:
            return None
    ist_global = bool({"--global", "--package-lock-only", "--lockfile-only"} & flags) or "--location=global" in args or \
        any(KURZ_GLOBAL.fullmatch(a) for a in args if not a.startswith("--"))
    if pm == "npm":
        if sub not in NPM_INSTALL_ALIASSE + ("ci", "clean-install") or ist_global:
            return None
        return pm, (f"npm {sub}" if sub in NPM_INSTALL_ALIASSE else None), _flag_an(args, "--ignore-scripts")
    if sub is None and flags & {"--version", "-v", "--help", "-h"}:
        return None
    if pm == "pnpm":
        if sub not in (None, "install", "i") or ist_global:
            return None
        treu = _flag_an(args, "--frozen-lockfile")
        return pm, None if treu else ("nacktes `pnpm`" if sub is None else f"pnpm {sub}"), _flag_an(args, "--ignore-scripts")
    if sub not in (None, "install") or ist_global:
        return None
    treu = _flag_an(args, "--frozen-lockfile") or _flag_an(args, "--immutable")
    return pm, None if treu else ("nacktes `yarn`" if sub is None else "yarn install"), None


def _aufrufe_von(zeile: int, befehle: list[list[str]]) -> list[_Aufruf]:
    erg = []
    for tok in befehle:
        b = _bewerte(tok)
        if b is not None:
            pm, label, aus = b
            erg.append(_Aufruf(zeile, pm, label if label is None or label.startswith("nacktes") else f"`{label}`", aus))
    return erg


def _zeile_auswerten(logisch: str, art: str, s: _Sammler | None, ende: float | None) -> list[list[str]]:
    """Befehle einer logischen Zeile; Zeitbudget je Zeile, Zeilen über `ZEILE_MAX` nicht tokenisieren (nur zählen)."""
    if ende is not None:
        _zeitcheck(ende)
    if len(logisch) > ZEILE_MAX:
        if s is not None:
            s.ueberlang += 1
        return []
    return _befehle(logisch, art)


def _installationen_in(rel: str, text: str, art: str, s: _Sammler | None = None, ende: float | None = None):
    """Install-Aufrufe in Dockerfile, CI-Datei oder Makefile (`art` docker | ci | make), je Befehlssegment; ein Generator,
    damit bei Budgetablauf mitten in der Datei die bisherigen Funde erhalten bleiben."""
    for zeile, logisch in _logische_zeilen(text):
        yield from _aufrufe_von(zeile, _zeile_auswerten(logisch, art, s, ende))


def _skript_zeilen(text: str) -> dict[str, int]:
    """Erste Zeile je Schlüsselname im package.json-Text (Schlüssel nach `"scripts"` bevorzugt, sonst die erste überhaupt)."""
    muster = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*:')
    nach: dict[str, int] = {}
    alle: dict[str, int] = {}
    ab = None
    for nr, z in enumerate(text.splitlines(), 1):
        m = muster.match(z)
        if not m:
            continue
        try:
            name = json.loads(f'"{m.group(1)}"')
        except ValueError:
            continue
        if name == "scripts" and ab is None:
            ab = nr
        alle.setdefault(name, nr)
        if ab is not None and nr > ab:
            nach.setdefault(name, nr)
    return {**alle, **nach}


def _skript_aufrufe(text: str, daten: dict, s: _Sammler | None = None, ende: float | None = None):
    scripts = daten.get("scripts")
    if not isinstance(scripts, dict):
        return
    zeilen = _skript_zeilen(text)
    for name, wert in scripts.items():
        if not isinstance(wert, str):
            continue
        zeile = zeilen.get(name, 1) if isinstance(name, str) else 1
        for teil in wert.splitlines():
            yield from _aufrufe_von(zeile, _zeile_auswerten(teil, "skript", s, ende))


# ------------------------------------------------------------------------------------ lieferkette: Lockfiles

def _npm_skript_pakete(text: str) -> list[tuple[str, str]]:
    """(Name, Version) der Pakete mit `"hasInstallScript": true` in einem npm-Lockfile (ab Version 2), Dateireihenfolge."""
    daten = json.loads(text)
    if not isinstance(daten, dict):
        raise TypeError(type(daten).__name__)
    pakete = daten.get("packages")
    erg = []
    for schl, eintrag in pakete.items() if isinstance(pakete, dict) else []:
        if isinstance(schl, str) and "node_modules/" in schl and isinstance(eintrag, dict) and eintrag.get("hasInstallScript") is True:
            version = eintrag.get("version")
            erg.append((schl.rsplit("node_modules/", 1)[-1], version if isinstance(version, str) else ""))
    return erg


def _pnpm_name(kopf: str) -> str:
    """Paketname aus einem Kopf von `pnpm-lock.yaml` (`/name@1.0.0`, `name@1.0.0(peer)`, `/@scope/name/1.0.0`,
    `/name/1.0.0_peer@x`): der Name endet beim ersten `@` oder `/` nach dem Scope."""
    h = kopf.strip().rstrip(":").strip().strip("\"'").lstrip("/")
    start = 0
    if h.startswith("@"):
        schraeg = h.find("/")
        if schraeg < 0:
            return h
        start = schraeg + 1
    m = re.search(r"[@/]", h[start:])
    return h if m is None else h[:start + m.start()]


def _pnpm_version(kopf: str, name: str) -> str | None:
    """Version aus dem Kopf eines `packages:`-Eintrags (`/name@1.0.0`, `name@1.0.0(peer@2)`, `/name/1.0.0_peer@x`)."""
    h = kopf.strip().rstrip(":").strip().strip("\"'").lstrip("/")
    if not h.startswith(name) or len(h) <= len(name) or h[len(name)] not in "@/":
        return None
    version = re.split(r"[(_]", h[len(name) + 1:], maxsplit=1)[0]
    return version or None


def _pnpm_dev(text: str) -> dict[tuple[str, str], bool]:
    """(Name, Version) -> True, wenn jeder `packages:`-Eintrag dazu `dev: true` trägt (Lockfile-Format 5.x und 6.0; ab Format 9
    gibt es die Angabe nicht mehr: dann leer, `dev` bleibt false)."""
    m = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.MULTILINE)
    if m is None or int(m.group(1)) >= 9:
        return {}
    eintraege: list[tuple[tuple[str, str], bool]] = []          # (Schlüssel, trägt `dev: true`) je Eintrag der Datei
    in_paketen = False
    for z in text.splitlines():
        if z and not z[0].isspace() and z[0] != "#":
            in_paketen = z.rstrip() == "packages:"
            continue
        if not in_paketen:
            continue
        k = re.match(r"  (\S.*):\s*$", z)
        if k and not z.startswith("   "):
            name = _pnpm_name(k.group(1))
            version = _pnpm_version(k.group(1), name)
            if version:
                eintraege.append(((name, version), False))
            else:
                eintraege.append((("", ""), False))              # nicht lesbarer Kopf: Zeilen darunter gehören keinem Paket
        elif eintraege and re.fullmatch(r"    dev:\s*true\s*", z):
            eintraege[-1] = (eintraege[-1][0], True)
    dev: dict[tuple[str, str], bool] = {}
    for schluessel, ist_dev in eintraege:
        if schluessel != ("", ""):
            dev[schluessel] = dev.get(schluessel, True) and ist_dev
    return dev


def _pnpm_skript_pakete(text: str) -> list[tuple[str, int]]:
    """(Name, Zeile des Kopfs) der Pakete mit `requiresBuild: true` im Abschnitt `packages:` (Lockfile v5/v6)."""
    erg: list[tuple[str, int]] = []
    in_paketen = False
    kopf: tuple[str, int] | None = None
    for nr, z in enumerate(text.splitlines(), 1):
        if z and not z[0].isspace() and z[0] != "#":
            in_paketen = z.rstrip() == "packages:"
            kopf = None
            continue
        if not in_paketen:
            continue
        m = re.match(r"  (\S.*):\s*$", z)
        if m and not z.startswith("   "):
            kopf = (_pnpm_name(m.group(1)), nr)
        elif kopf is not None and re.fullmatch(r"    requiresBuild:\s*true\s*", z):
            erg.append(kopf)
            kopf = None
    return erg


def _paketnamen_text(namen: list[str]) -> str:
    gueltig: list[str] = []
    ungueltig = 0
    for n in dict.fromkeys(namen):                              # Reihenfolge der Datei, ohne Dubletten
        if len(n) <= PAKETNAME_MAX and NPM_PAKETNAME.fullmatch(n):
            gueltig.append(n)
        else:
            ungueltig += 1
    text = ", ".join(gueltig[:MAX_PAKETNAMEN]) if gueltig else "keine gültigen Paketnamen"
    if len(gueltig) > MAX_PAKETNAMEN:
        text += f", +{len(gueltig) - MAX_PAKETNAMEN} weitere"
    if ungueltig:
        text += f"; {ungueltig} ungültige Paketnamen ausgelassen"
    return text


def _npmrc_ignore_scripts(text: str) -> bool:
    wert = False
    for z in text.splitlines():
        z = z.strip()
        if not z or z[0] in "#;" or "=" not in z:
            continue
        k, v = z.split("=", 1)
        if k.strip() == "ignore-scripts":
            wert = v.strip().strip("\"'").lower() == "true"
    return wert


# ------------------------------------------------------------------------------------ lieferkette: Entwürfe

def _entwurf(klasse: str, stufe: str, datei: str, zeile: int, titel: str, beschreibung: str, szenario: str, erwartet: str) -> dict:
    return {"stufe": stufe, "status": "unbestätigt", "datei": datei, "zeile": zeile, "kategorie": "A03", "titel": titel,
            "beschreibung": f"{BEFUND_GRUND}. {beschreibung}", "szenario": szenario, "erwartet": erwartet, "klasse": klasse,
            "ohne_anmeldung": False, "mandantenuebergreifend": False, "werkzeug": "lieferkette",
            "code_pfad": [f"{datei}:{zeile}"]}


def _erwartet_installation(pm: str) -> str:
    """Abhilfe je Paketmanager (`npm` | `pnpm` | `yarn`), nicht aus dem Label abgeleitet (`npm` steckt in `pnpm`)."""
    if pm == "npm":
        return "`npm ci` statt `npm install` verwenden (installiert exakt die Versionen aus dem Lockfile)"
    if pm == "pnpm":
        return "`pnpm install --frozen-lockfile` verwenden (bricht ab, wenn das Lockfile nicht passt)"
    return "`yarn install --immutable` (yarn berry) bzw. `yarn install --frozen-lockfile` (yarn 1) verwenden"


def _hat_abhaengigkeiten(daten: object) -> bool:
    """Nicht parsebar oder fremde Form zählt als „hat Abhängigkeiten“."""
    if not isinstance(daten, dict):
        return True
    return any(daten.get(k) for k in ABHAENGIGKEIT_FELDER)


def _statisch(quelle: str, ende: float, s: _Sammler) -> None:
    baum = _baum_suchen(quelle, ende, s)
    lock_ordner = {_ordner_von(rel) for rel, _ in baum.lockfiles}
    yarn_v1 = False
    for rel, _ in baum.lockfiles:
        if rel.rsplit("/", 1)[-1] == "yarn.lock":
            _zeitcheck(ende)
            kopf = _je_datei(s, rel, lambda r=rel: _kopf_lesen(os.path.join(quelle, r), YARN_V1_KOPF))
            yarn_v1 = yarn_v1 or (kopf is not None and YARN_V1_MARKE in kopf)

    pm_zeilen: dict[str, list[bool]] = {"npm": [], "pnpm": []}   # `--ignore-scripts` je Installationszeile (nicht global)
    pkg_daten: dict[str, object] = {}                 # Ordner -> geparstes package.json (None: nicht auswertbar)
    gesehen: set[tuple[str, int]] = set()

    def installation(rel: str, art: str, aufruf: _Aufruf) -> None:
        if aufruf.skripte_aus is not None:
            pm_zeilen[aufruf.pm].append(aufruf.skripte_aus)
        if aufruf.label is None or (rel, aufruf.zeile) in gesehen:
            return
        if art == "ci" and (aufruf.pm == "pnpm" or (aufruf.pm == "yarn" and not yarn_v1)):
            return                                    # W8: pnpm und yarn berry in CI nie, yarn nur mit v1-Lockfile
        gesehen.add((rel, aufruf.zeile))
        befehl = aufruf.label
        s.entwurf(_entwurf(
            "installation-ohne-lockfile-treue", "P2", rel, aufruf.zeile, f"Installation ohne Lockfile-Treue in {rel}",
            f"In {rel}:{aufruf.zeile} installiert {befehl} die Abhängigkeiten, ohne an das Lockfile gebunden zu sein.",
            "Builds und Deployments ziehen beim Installieren neue, ungeprüfte Versionen; ein kompromittiertes oder "
            "manipuliertes Paket gelangt so unbemerkt in Build und Betrieb, und Builds sind nicht reproduzierbar.",
            _erwartet_installation(aufruf.pm)))

    # package.json: Abhängigkeiten (lockfile-fehlt) und scripts
    pakete = baum.pakete
    texte = baum.texte
    if len(pakete) + len(texte) > MAX_TEXTDATEIEN:
        s.hinweis(f"{len(pakete) + len(texte)} Dateien (package.json, Dockerfile, CI, Makefile) gefunden, nur die ersten "
                  f"{MAX_TEXTDATEIEN} geprüft")
        pakete = pakete[:MAX_TEXTDATEIEN]
        texte = texte[:max(0, MAX_TEXTDATEIEN - len(pakete))]
    for rel, groesse in pakete:
        _zeitcheck(ende)
        ordner = _ordner_von(rel)

        def pruefen(rel=rel, groesse=groesse, ordner=ordner) -> None:
            text = _lese_text(quelle, rel, groesse, s)
            daten = None
            if text is not None:
                daten = json.loads(text)
                if not isinstance(daten, dict):
                    raise TypeError(type(daten).__name__)
            pkg_daten[ordner] = daten
            if text is not None:
                for a in _skript_aufrufe(text, daten, s, ende):
                    installation(rel, "skript", a)

        _je_datei(s, rel, pruefen)
        daten = pkg_daten.get(ordner)
        if not any(o in lock_ordner for o in _eltern(ordner)) and _hat_abhaengigkeiten(daten):
            s.entwurf(_entwurf(
                "lockfile-fehlt", "P2", rel, 1, f"Lockfile fehlt für {rel}",
                f"Zu {rel} gibt es weder im selben Ordner noch in einem Elternordner ein Lockfile "
                "(`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`).",
                "Ohne Lockfile löst jede Installation die Abhängigkeiten neu auf; eine kompromittierte oder manipulierte "
                "neue Version gelangt unbemerkt in Build und Betrieb, und Builds sind nicht reproduzierbar.",
                "Lockfile erzeugen und einchecken (z. B. `npm install --package-lock-only`), danach mit `npm ci` installieren"))

    # Dockerfile, CI, Makefile
    for rel, art, groesse in texte:
        _zeitcheck(ende)

        def pruefen_text(rel=rel, art=art, groesse=groesse) -> None:
            text = _lese_text(quelle, rel, groesse, s)
            if text is not None:
                for a in _installationen_in(rel, text, art, s, ende):
                    installation(rel, art, a)

        _je_datei(s, rel, pruefen_text)

    # Lockfiles mit Install-Skripten
    lockfiles = [(rel, g) for rel, g in baum.lockfiles if rel.rsplit("/", 1)[-1] in NPM_LOCKFILES + ("pnpm-lock.yaml",)]
    if len(lockfiles) > MAX_LOCKFILES:
        s.hinweis(f"{len(lockfiles)} Lockfiles gefunden, nur die ersten {MAX_LOCKFILES} geprüft")
        lockfiles = lockfiles[:MAX_LOCKFILES]
    if not lockfiles:
        return
    # Schutzmaßnahmen gelten je Lockfile-Typ, jeder Paketmanager liest nur seine eigene Konfiguration:
    #   npm-Lockfile:  `.npmrc` mit `ignore-scripts=true` oder `--ignore-scripts` in allen npm-Installationszeilen
    #   pnpm-Lockfile: `.npmrc` mit `ignore-scripts=true`, `--ignore-scripts` in allen pnpm-Installationszeilen,
    #                  `onlyBuiltDependencies`/`neverBuiltDependencies` oder `packageManager: pnpm@>=10`
    # yarn-Lockfiles tragen kein Install-Skript-Merkmal und werden nicht geprüft; `enableScripts: false` (`.yarnrc.yml`) hat
    # daher keine Wirkung auf npm- oder pnpm-Lockfiles und wird nicht gelesen.
    zeilen_schutz = {pm: bool(z) and all(z) for pm, z in pm_zeilen.items()}
    cache: dict[tuple[str, str], str | None] = {}

    def konfig_text(ordner: str, name: str) -> str | None:
        if (ordner, name) not in cache:
            eintrag = baum.konfig.get((ordner, name))
            cache[(ordner, name)] = (_je_datei(s, eintrag[0], lambda e=eintrag: _lese_text(quelle, e[0], e[1], s))
                                     if eintrag else None)
        return cache[(ordner, name)]

    def geschuetzt(ordner: str, pm: str) -> bool:
        if zeilen_schutz[pm]:
            return True
        for o in _eltern(ordner):
            npmrc = konfig_text(o, ".npmrc")
            if npmrc is not None and _npmrc_ignore_scripts(npmrc):
                return True
            if pm != "pnpm":
                continue
            workspace = konfig_text(o, "pnpm-workspace.yaml")
            if workspace is not None and any(PNPM_LISTE.match(z) for z in workspace.splitlines()):
                return True
            daten = pkg_daten.get(o)
            if isinstance(daten, dict):
                manager = daten.get("packageManager")
                m = re.match(r"pnpm@(\d+)", manager) if isinstance(manager, str) else None
                if m and len(m.group(1)) < 4 and int(m.group(1)) >= 10:
                    return True
                pnpm = daten.get("pnpm")
                if isinstance(pnpm, dict) and ("onlyBuiltDependencies" in pnpm or "neverBuiltDependencies" in pnpm):
                    return True
        return False

    for rel, groesse in lockfiles:
        _zeitcheck(ende)
        name = rel.rsplit("/", 1)[-1]

        def pruefen_lock(rel=rel, groesse=groesse, name=name) -> None:
            if groesse > LOCKFILE_MAX:
                s.hinweis(f"Lockfile zu groß (> {LOCKFILE_MAX // (1024 * 1024)} MiB), übersprungen: {rel}")
                return
            text = _lese_datei(os.path.join(quelle, rel)).decode("utf-8", "replace")
            if name == "pnpm-lock.yaml":
                betroffen = _pnpm_skript_pakete(text)
                namen = [n for n, _ in betroffen]
                zeile = betroffen[0][1] if betroffen else 1
            else:
                betroffen = _npm_skript_pakete(text)
                namen = [n for n, _ in betroffen]
                zeile = _zeile(text.splitlines(), betroffen[0][0], betroffen[0][1], _npm_index(text), name) if betroffen else 1
            pm = "pnpm" if name == "pnpm-lock.yaml" else "npm"
            if not betroffen or geschuetzt(_ordner_von(rel), pm):
                return
            massnahmen = ("`ignore-scripts=true` in `.npmrc`, `--ignore-scripts` in allen pnpm-Installationen, pnpm-Freigabeliste, "
                          "`packageManager: pnpm@10` oder neuer" if pm == "pnpm" else
                          "`ignore-scripts=true` in `.npmrc`, `--ignore-scripts` in allen npm-Installationen")
            s.entwurf(_entwurf(
                "install-skripte-offen", "P3", rel, zeile, f"Install-Skripte in {rel} nicht abgeschaltet",
                f"Das Lockfile {rel} enthält {len(betroffen)} Paket(e) mit Install-Skripten ({_paketnamen_text(namen)}), und keine "
                f"Schutzmaßnahme für {pm} greift ({massnahmen}).",
                "Beim Installieren laufen die Install-Skripte der Pakete (preinstall, install, postinstall) mit den Rechten des "
                "Installierenden; ein kompromittiertes Paket führt so Code auf Entwickler- und Build-Rechnern aus.",
                "Install-Skripte abschalten (`ignore-scripts=true` in `.npmrc`) oder gezielt freigeben "
                "(pnpm: `onlyBuiltDependencies`)"))

        _je_datei(s, rel, pruefen_lock)


def cmd_lieferkette(a: argparse.Namespace) -> int:
    _, quelle = _arbeitskopie(a.lauf, a.quelle)
    ende = time.monotonic() + _sekunden("SECURITY_AUDIT_LK_BUDGET", LK_BUDGET)
    s = _Sammler()
    try:
        _statisch(quelle, ende, s)
    except _Zeit:
        s.hinweis(ZEIT_HINWEIS)
    _ausgabe({"entwuerfe": s.entwuerfe, "hinweise": s.abschluss()})
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
    s = sub.add_parser("lieferkette", allow_abbrev=False, help="Lockfile, Installation und Install-Skripte statisch prüfen")
    s.set_defaults(fn=cmd_lieferkette)
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
