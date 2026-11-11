#!/usr/bin/env python3
"""Docker-PoC für den Skill security-audit (nur Standardbibliothek).

Sicherheitsgrenze: Kundencode läuft ausschließlich in Docker-Containern ohne Zugang nach außen
(`--internal`-Netz je Rolle) und nie auf dem Host. Der Bau holt nur die Pakete der Lockfile per `npm ci
--ignore-scripts` aus der npm-Registry (keine Install-Skripte, Quelle per Lockfile-Prüfung auf die Registry beschränkt);
der Build-Befehl des Kunden läuft ohne Netz. PoC-Requests gehen nur an `http://app:<port>` aus einem
Wegwerf-Container im Netz der Rolle. Es gibt keine Host-Mounts und keine veröffentlichten Ports. Gelöscht wird
nur, was `security-audit-<lauf>` heißt (Container, Netze, Images) und der eigene Zustandsordner.

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I poc.py neu | pruefen | vorbereiten | bauen | starten | ausfuehren | neustart | anfrage | modell | aufraeumen | auflisten

Exit-Codes: 0 ok, 2 ungültige Argumente, 3 Docker fehlt oder Daemon nicht erreichbar, 4 Bau/Start scheitert
(erste stdout-Zeile `kategorie: <wert>`, danach höchstens die letzten 40 Zeilen der Docker-Ausgabe),
1 sonstiger Fehler (Request fehlgeschlagen, Befehl im Container mit Exit ≠ 0, Aufräumen unvollständig).

`starten --modell-mock openai,anthropic` startet vor der App den Modell-Mock `<netz>-llm` (Alias `llm`, Port 4010, nur im internen Netz)
und setzt in der App die Variablen der gewählten APIs (Dummy-Schlüssel). `--env`: jeder Wert läuft durch die Netzregel (Exit 2 bei
fremdem Host, die Meldung nennt nie den Wert); mit `--modell-mock` sind die Namen in `MOCK_RESERVIERT` für `--env`, `--start-befehl` und `--seed` reserviert.

`modell --lauf <id> --rolle <r> (--antworten-datei <datei> | --protokoll [--suche <marker>])` steuert den Modell-Mock der Rolle
(ein `docker exec` auf `<netz>-llm`, unter der geteilten Rollensperre, Budget 60 s, nur verkürzbar). `--antworten-datei` prüft die
Antwortliste (höchstens 20 Einträge: `text` oder `werkzeug`, optional `wenn_enthaelt` nach `POCMARKER-…`, Netzregel über Rohtext und
geparstes JSON) und setzt sie. `--protokoll` gibt das Protokoll aus; die Werte der `--env` der Rolle (ab 6 Zeichen) und die Mock-Schlüssel
gehen per stdin an den Mock, der sie vor der Ausgabe durch `<ENV:NAME>` ersetzt. Ohne Modell-Mock in der Rolle Exit 1.

`SECURITY_AUDIT_OHNE` (kommagetrennt): `docker` lässt `pruefen`, `bauen`, `starten` und `neustart` mit Exit 3 `docker-fehlt` enden.
`bauen` verlangt den Schwärzungs-Marker (`schwaerz_marker`, gesetzt von `lieferkette.py secrets`; `vorbereiten` löscht ihn),
solange gitleaks im PATH liegt und nicht in `SECURITY_AUDIT_OHNE` steht: sonst Exit 4 `kategorie: nicht-geschwaerzt`. Der Marker
gilt nur für die Arbeitskopie, auf der `secrets` lief: er trägt deren Kennung (`id` aus `quelle.fertig`, bei jedem `vorbereiten`
neu), eine andere oder fehlende Kennung zählt wie ein fehlender Marker. Er sagt nicht, dass die Kopie seither unverändert blieb.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402
import netzregel  # noqa: E402

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
DOCKER_DIR = os.path.join(SKILL_DIR, "docker")
DOCKERFILE = os.path.join(DOCKER_DIR, "Dockerfile.poc")

REGISTRY = "https://registry.npmjs.org/"
KANDIDATEN = (24, 22, 20)
STANDARD_NODE = "22"
BAU_TIMEOUT = 540
KURZ_TIMEOUT = 60          # einzelne docker-Aufrufe (create, rm, ps, …)
VERSION_TIMEOUT = 20
ANFRAGE_TIMEOUT = 45
WARTEN_SEKUNDEN = 60
WARTEN_TIMEOUT = 90
SEED_TIMEOUT = 180
PULL_TIMEOUT = 300
EXEC_TIMEOUT = 120
DB_WARTEN = 60
MOCK_BEREIT = 30                 # höchstens so lange wartet starten/neustart auf die Bereitschaft des Modell-Mocks (nur verkürzbar)
MODELL_BUDGET = 60               # Gesamtzeit von `modell` (ein docker exec; nur verkürzbar)
START_BUDGET = 440               # Gesamtzeit der Arbeitsphase von starten/neustart (Skill-Bash-Limit: 600 s, Aufräumen folgt)
AUFRAEUMEN_BUDGET = 440          # Gesamtzeit der Docker-Aufrufe von aufraeumen
VORBEREITEN_BUDGET = 480         # Gesamtzeit von vorbereiten: Entfernen der alten Kopie, git-Aufrufe, Kopieren (Skill-Bash-Limit: 600 s)
LOCKFILE_MAX = 64 * 1024 * 1024  # größere package-lock.json gelten als unlesbar
TAIL_ZEILEN = 40
ZEILE_MAX = 300
DATEN_MAX = 1024 * 1024
MAX_ENGINES = 1024               # längere engines.node-Ranges gelten als unlesbar
MAX_VERGLEICHE = 64
PACKAGE_JSON_MAX = 1024 * 1024
LESE_MAX = 4 * 1024 * 1024      # je Strom beim Lesen von docker
AUSGABE_MAX = 64 * 1024         # was anfrage/ausfuehren höchstens auf stdout ausgeben
APP_PORT_DB = 5432
POSTGRES_IMAGE = "postgres:16-alpine"
DB_URL = "postgres://poc:poc@db:5432/poc"
ANTWORTEN_MAX = 20               # Einträge einer Antwortliste für den Modell-Mock
ANTWORTEN_DATEI_MAX = 64 * 1024  # `--antworten-datei`: Größe der Datei (grobe Schranke; maßgeblich ist `STDIN_MAX_MOCK` für die Serialisierung)
ANTWORT_TEXT_MAX = 16384         # UTF-16-Einheiten je `text` (Zählweise und Grenze des Mocks)
MASKIER_WERTE_MAX = 200          # Grenze des Mocks für die Zahl der Werte (`modell --protokoll`); mehr: Exit 2
MASKIER_WERT_MIN = 6             # kürzere --env-Werte werden nicht maskiert
MASKIER_WERT_MAX = 4096          # Grenze des Mocks je Wert (Zeichen)
MASKIER_NAME_MAX = 64            # Grenze des Mocks für den Namen
STDIN_MAX_MOCK = 64 * 1024       # Grenze des Mocks für stdin (Bytes)
MARKER_RE = re.compile(r"POCMARKER-[a-z0-9-]{1,40}")
WERKZEUG_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MOCK_PORT = 4010                 # API des Modell-Mocks im Netz der Rolle (Alias `llm`)
MOCK_STEUER_PORT = 4011          # Steuerung: lauscht im Container nur auf 127.0.0.1
MOCK_URL = f"http://llm:{MOCK_PORT}"
# Modell-Mock je API: (Name, Wert) der Variablen, die `starten --modell-mock` im App-Container setzt (Dummy-Schlüssel, keine echten).
MOCK_ENV = {
    "openai": (("OPENAI_BASE_URL", f"{MOCK_URL}/v1"), ("OPENAI_API_KEY", "poc-dummy-openai")),
    "anthropic": (("ANTHROPIC_BASE_URL", MOCK_URL), ("ANTHROPIC_API_KEY", "poc-dummy-anthropic")),
}
# Mit --modell-mock kein --env und keine Zuweisung oder Aufhebung im Start-Befehl und im Seed mit diesen Namen (Groß-/Kleinschreibung egal):
# die Variablen des Mocks und weitere, mit denen ein SDK sonst am Mock vorbei zu einem anderen Endpunkt, Schlüssel oder Konto liefe.
MOCK_RESERVIERT = frozenset({name for paare in MOCK_ENV.values() for name, _ in paare}
                            | {"OPENAI_API_BASE", "OPENAI_API_HOST", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "ANTHROPIC_AUTH_TOKEN",
                               "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY"})
_RESERVIERT_NAMEN = "|".join(sorted(MOCK_RESERVIERT))
# `NAME=` und `NAME+=` (Anhängen), mit Wortgrenze davor (`NEXT_PUBLIC_OPENAI_BASE_URL=` ist ein anderer Name).
MOCK_RESERVIERT_RE = re.compile(r"(?<![A-Za-z0-9_])(" + _RESERVIERT_NAMEN + r")\+?=", re.IGNORECASE)
# Alles andere, was einen Namen aufhebt, überschreibt oder die Umgebung leert, erkennt `_segment_umgehung` an den Wörtern eines einfachen Befehls
# (ein Durchgang, linear; die Prüfung läuft vor jedem Zeitbudget): `unset … NAME`, `env -u NAME` (auch gruppiert), `--unset NAME`, `read NAME`,
# `for NAME in`, `printf -v NAME`, `export -n NAME`, `typeset +x NAME`, `declare -n x=NAME` und `env -i`.
_NAME_ANFANG_RE = re.compile("(" + _RESERVIERT_NAMEN + r")(?![A-Za-z0-9_])", re.IGNORECASE)
_SEGMENT_TRENNER_RE = re.compile(r"[;&|\n]")
_DEKLARATION_FLAG_RE = re.compile(r"-[A-Za-z]*n[A-Za-z]*|\+[A-Za-z]*x[A-Za-z]*")     # export -n, typeset +x, declare -n (Namensreferenz)
_OPTION_BUCHSTABEN_RE = re.compile(r"-([A-Za-z]*)")
_ENV_WORT_RE = re.compile(r"(?:.*/)?env")
_ENV_KURZ_MIT_ARGUMENT = frozenset("uCPL")                                           # `env -u NAME`, `-C DIR`, `-P PATH`, `-L`
_ENV_LANG_MIT_ARGUMENT = frozenset({"--unset", "--chdir", "--split-string", "--argv0", "--default-signal", "--ignore-signal",
                                    "--block-signal"})
_WORT_ANFANG = "$`({!"                                                               # `$(env -i …)`, `(read X)`, `! unset X`
_FLAG_LAENGE_MAX = 16                                                                # längere Wörter sind keine Optionsbündel (Laufzeit)


def _name_am_anfang(wort: str, pos: int = 0) -> str | None:
    m = _NAME_ANFANG_RE.match(wort, pos)
    return m.group(1) if m else None


def _segment_umgehung(tokens: list[str]) -> str | None:
    """Ein einfacher Befehl (Wörter ohne `;`, `&`, `|`, Zeilenende), ein Durchgang über die Wörter. Rückgabe: der gesperrte Name,
    `""` für `env -i` (leert die Umgebung) oder None."""
    nach_unset = nach_read = nach_printf = False
    deklaration: bool | None = None          # None: kein export/typeset/declare/local; False: gesehen; True: danach `-n` oder `+x`
    erwarte_name = False                     # das nächste Wort ist ein Name: `-u`, `--unset`, `printf -v`, `for`
    for roh in tokens:
        w = roh.lstrip(_WORT_ANFANG)
        treffer = None
        if erwarte_name or nach_unset or nach_read:
            treffer = _name_am_anfang(w)
        erwarte_name = False
        if treffer is None and deklaration:
            treffer = _name_am_anfang(w, w.find("=") + 1)
        if treffer:
            return treffer
        if w == "unset":
            nach_unset = True
        elif w == "read":
            nach_read = True
        elif w == "printf":
            nach_printf = True
        elif w == "for":
            erwarte_name = True
        elif w in ("export", "typeset", "declare", "local"):
            deklaration = False
        elif deklaration is False and len(w) <= _FLAG_LAENGE_MAX and _DEKLARATION_FLAG_RE.fullmatch(w):
            deklaration = True
        if nach_printf and w.startswith("-v"):
            if len(w) == 2:
                erwarte_name = True
            elif (treffer := _name_am_anfang(w, 2)):
                return treffer
        if w == "--unset":
            erwarte_name = True
        elif w.startswith("--unset="):
            treffer = _name_am_anfang(w, len("--unset="))
            if treffer:
                return treffer
        elif len(w) > 1 and w[0] == "-" and w[1] != "-":                       # Optionsbündel: `-u NAME`, `-uNAME`, `-vu NAME`
            for j, b in enumerate(_OPTION_BUCHSTABEN_RE.match(w).group(1)):
                if b != "u":
                    continue
                if 2 + j == len(w):
                    erwarte_name = True
                elif (treffer := _name_am_anfang(w, 2 + j)):
                    return treffer
    return _env_leert_umgebung(tokens)


def _env_leert_umgebung(tokens: list[str]) -> str | None:
    """`""` bei `env -i`, `env -` oder `env --ignore-environment` an beliebiger Stelle der env-Optionen: Optionen mit Argument (`-u X`, `-C dir`,
    `--unset X`) werden übersprungen, der Rest eines `-S…`-Bündels wird weitergelesen. Die Optionen enden am ersten Wort ohne `-` (Befehl
    oder `NAME=wert`); das Wort `env` unter den bereits gelesenen Optionen ist ein Argument und startet keine zweite Suche."""
    k = 0
    while k < len(tokens):
        if not _ENV_WORT_RE.fullmatch(tokens[k].lstrip(_WORT_ANFANG)):
            k += 1
            continue
        k += 1
        zurueck: list[str] = []                                                # Rest eines `-S…`-Bündels, noch zu lesen
        while zurueck or k < len(tokens):
            if zurueck:
                w = zurueck.pop()
            else:
                w = tokens[k]
                k += 1
            if w == "-" or w == "--ignore-environment":
                return ""
            if w.startswith("--"):
                if w in _ENV_LANG_MIT_ARGUMENT:
                    k += 1
                continue
            if not w.startswith("-"):
                break
            kurz = w[1:]
            for j, b in enumerate(kurz[:_FLAG_LAENGE_MAX]):
                if b == "i":
                    return ""
                if b == "S":
                    if len(kurz) > j + 1:
                        zurueck.append(kurz[j + 1:])
                    break
                if b in _ENV_KURZ_MIT_ARGUMENT:
                    if j + 1 == len(kurz):
                        k += 1
                    break
                if not b.isalnum():
                    break
    return None


_QUOTES_RE = re.compile(r"\\\r?\n|[\"'\\]")     # Zeilenfortsetzung, Anführungszeichen und Rückstrich: die Shell entfernt sie vor dem Lesen des Namens

# Hinweis-Kategorien, die `bauen` ausgeben kann (`hinweis: <kategorie>`); SKILL.md und bericht-format.md nennen jede.
HINWEIS_KATEGORIEN = ("native-module", "prisma-engines", "lockfile-ohne-paketliste", "node-range-zu-lang",
                      "node-engines-ignoriert")

LAUF_RE = re.compile(r"[0-9a-f]{8}")
ROLLE_RE = re.compile(r"p[12]")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
DAEMON_EXIT = (1, 125)
DAEMON_WEG = ("cannot connect to the docker daemon", "error during connect", "is the docker daemon running",
              "docker.sock: connect", "failed to connect to the docker api")

HAERTUNG_APP = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "1g", "--pids-limit", "256"]
# Kein --cap-drop: der Postgres-Entrypoint braucht chown und den Benutzerwechsel.
HAERTUNG_DB = ["--security-opt", "no-new-privileges", "--memory", "512m", "--pids-limit", "256"]
# Modell-Mock: eigener Satz (kleiner als HAERTUNG_APP, kein doppeltes --memory), Dateisystem nur lesbar, /tmp ohne exec.
HAERTUNG_MOCK = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--pids-limit", "64",
                 "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"]


class PocFehler(Exception):
    """Abbruch mit Exit-Code und Meldung auf stderr."""

    def __init__(self, nachricht: str, code: int = 2):
        super().__init__(nachricht)
        self.code = code


class DockerFehlt(Exception):
    """docker nicht startbar oder Daemon nicht erreichbar (Exit 3)."""


# ------------------------------------------------------------------------------------ Namen und Zustand

def zustand_ordner(lauf: str) -> str:
    """`<realpath(tmp)>/security-audit-<lauf>`; wirft ValueError bei ungültiger Lauf-ID."""
    if not isinstance(lauf, str) or not LAUF_RE.fullmatch(lauf):
        raise ValueError(f"ungültige Lauf-ID: {lauf!r}")
    basis = os.path.realpath(tempfile.gettempdir())
    pfad = os.path.join(basis, f"security-audit-{lauf}")
    if os.path.commonpath([basis, pfad]) != basis or os.path.dirname(pfad) != basis:
        raise ValueError("Zustandsordner liegt nicht unter dem Temp-Ordner")
    return pfad


def schwaerz_marker(lauf: str) -> str:
    """Marker `<zustand>/lieferkette/geschwaerzt`: `lieferkette.py secrets` setzt ihn, sobald die Arbeitskopie geschwärzt ist
    (auch ohne Treffer), mit der Kennung der Kopie (`kopie_kennung`); `vorbereiten` löscht ihn, `bauen` verlangt ihn samt
    passender Kennung, solange gitleaks verfügbar ist."""
    return os.path.join(zustand_ordner(lauf), "lieferkette", "geschwaerzt")


def _regulaere_datei_lesen(pfad: str) -> object | None:
    """JSON einer kleinen regulären Datei (kein Symlink, kein Ordner); None bei jedem Fehler."""
    try:
        if not stat.S_ISREG(os.lstat(pfad).st_mode):
            return None
        with open(pfad, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def kopie_kennung(lauf: str) -> str | None:
    """Kennung der aktuellen Arbeitskopie: das Feld `id` des Fertig-Markers `quelle.fertig`, den `vorbereiten` mit jeder Kopie
    atomar neu schreibt. None, wenn der Marker fehlt, kein Symlink-freies JSON-Objekt oder ohne nichtleeren Text `id` ist."""
    daten = _regulaere_datei_lesen(os.path.join(zustand_ordner(lauf), "quelle.fertig"))
    kennung = daten.get("id") if isinstance(daten, dict) else None
    return kennung if isinstance(kennung, str) and kennung else None


def _ohne_werkzeuge() -> set[str]:
    """Namen aus `SECURITY_AUDIT_OHNE` (kommagetrennt, getrimmt, klein geschrieben): Werkzeuge, die der Aufrufer ausschließt."""
    return {n.strip().casefold() for n in os.environ.get("SECURITY_AUDIT_OHNE", "").split(",") if n.strip()}


def werkzeug_fehlt(name: str) -> bool:
    """True, wenn `name` nicht im PATH liegt oder in `SECURITY_AUDIT_OHNE` steht. Der einzige Parser dieser Variable."""
    return name.strip().casefold() in _ohne_werkzeuge() or shutil.which(name) is None


def _ordner(lauf: str, anlegen: bool = False) -> str:
    """Zustandsordner; mit `anlegen` wird er (0700) erstellt und auf Symlink/fremden Besitzer geprüft."""
    pfad = zustand_ordner(lauf)
    if anlegen:
        os.makedirs(pfad, mode=0o700, exist_ok=True)
    try:
        st = os.lstat(pfad)
    except FileNotFoundError:
        return pfad
    if not stat.S_ISDIR(st.st_mode):
        raise PocFehler(f"Zustandsordner {pfad} ist kein Ordner (Symlink?); abgebrochen")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PocFehler(f"Zustandsordner {pfad} gehört einem anderen Benutzer; abgebrochen")
    return pfad


def _netz(lauf: str, rolle: str) -> str:
    return f"security-audit-{lauf}-{rolle}"


def _image(lauf: str) -> str:
    return f"security-audit-{lauf}-app"


def _entferne(pfad: str, wurzel: str) -> None:
    """Direkten Eintrag `pfad` von `wurzel` löschen (Datei, Ordner oder Symlink: nur der Link). Schreibgeschützte Ordner werden
    vorher freigegeben. Bleibt nach dem zweiten Versuch etwas übrig, wirft die Funktion PocFehler (Exit 1): ein stilles
    Weitermachen ließe alte Dateien in einer neuen Arbeitskopie stehen oder meldete „aufgeräumt“ trotz Rest."""
    if os.path.realpath(os.path.dirname(pfad)) != os.path.realpath(wurzel):
        raise PocFehler(f"Löschen außerhalb des Zustandsordners verweigert: {pfad}")
    if os.path.islink(pfad) or os.path.isfile(pfad):
        os.unlink(pfad)
        return
    if not os.path.lexists(pfad):
        return
    shutil.rmtree(pfad, ignore_errors=True)
    if os.path.lexists(pfad):
        for ordner, unter, _dateien in os.walk(pfad):  # os.walk folgt keinen Symlinks
            for p in [ordner] + [os.path.join(ordner, u) for u in unter if not os.path.islink(os.path.join(ordner, u))]:
                try:
                    os.chmod(p, 0o700)
                except OSError:
                    pass                   # unveränderlich o. ä.: der Rest wird unten als nicht entfernt gemeldet
        shutil.rmtree(pfad, ignore_errors=True)
    if os.path.lexists(pfad):
        raise PocFehler(f"{pfad} nicht vollständig entfernt (Rechte oder gesperrte Dateien)", code=1)


def _schreibe_atomar(pfad: str, daten: dict) -> None:
    ordner = os.path.dirname(pfad)
    fd, tmp = tempfile.mkstemp(dir=ordner, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(daten, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, pfad)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def _rolle_datei(lauf: str, rolle: str) -> str:
    return os.path.join(_ordner(lauf), f"rolle-{rolle}.json")


def _lade_rolle(lauf: str, rolle: str) -> dict:
    pfad = _rolle_datei(lauf, rolle)
    try:
        with open(pfad, encoding="utf-8") as f:
            z = json.load(f)
        port, befehl = z["port"], z["start_befehl"]
        env, dienst, seed = z.get("env", []), z.get("dienst"), z.get("seed")
        mock = z.get("modell_mock", [])       # fehlt bei Dateien ohne Modell-Mock: Rolle ohne Mock
        if not (isinstance(port, int) and 0 < port < 65536 and isinstance(befehl, str) and befehl
                and isinstance(env, list) and all(isinstance(e, str) and "=" in e for e in env)
                and dienst in (None, "postgres") and (seed is None or isinstance(seed, str))
                and isinstance(mock, list) and all(isinstance(m, str) and m in MOCK_ENV for m in mock)
                and len(set(mock)) == len(mock)):
            raise ValueError("Zustandsdatei ungültig")
    except (OSError, ValueError, KeyError, TypeError):
        raise PocFehler(f"Rolle {rolle} nicht gestartet (oder Zustand unlesbar): erst `poc.py starten`") from None
    return {"start_befehl": befehl, "port": port, "env": env, "dienst": dienst, "seed": seed, "modell_mock": mock}


# ------------------------------------------------------------------------------------ docker-Aufruf

class Ergebnis(NamedTuple):
    rc: int | None  # None = Timeout
    out: bytes
    err: bytes
    gekuerzt: bool = False

    @property
    def text(self) -> str:
        return (self.out + self.err).decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return self.rc == 0


_ENDE: float | None = None          # monotone Frist des laufenden Befehls (starten, neustart, aufraeumen)
_BUDGET_SEKUNDEN = 0


def _nur_verkuerzt(umgebungsvariable: str, standard: int) -> int:
    """`standard`, über die Umgebungsvariable nur verkürzbar (nie verlängerbar; ungültig, 0 und negativ gelten nicht)."""
    try:
        sekunden = int(os.environ.get(umgebungsvariable, ""))
    except ValueError:
        return standard
    return sekunden if 0 < sekunden < standard else standard


def _frist_setzen(umgebungsvariable: str, standard: int, verkuerzbar: bool = False) -> None:
    """Gesamtbudget des Befehls: Docker-Aufrufe mit `budget=True` werden auf die Restzeit gekürzt, danach nicht mehr gestartet.
    Die Umgebungsvariable überschreibt den Standard (Tests); mit `verkuerzbar` nur nach unten."""
    global _ENDE, _BUDGET_SEKUNDEN
    if verkuerzbar:
        _BUDGET_SEKUNDEN = _nur_verkuerzt(umgebungsvariable, standard)
    else:
        try:
            sekunden = int(os.environ.get(umgebungsvariable, ""))
        except ValueError:
            sekunden = standard
        _BUDGET_SEKUNDEN = sekunden if sekunden > 0 else standard
    _ENDE = time.monotonic() + _BUDGET_SEKUNDEN


def _mock_bereit_sekunden() -> int:
    """Wartezeit auf den Modell-Mock: `MOCK_BEREIT`, über SECURITY_AUDIT_MOCK_BEREIT nur verkürzbar (nie verlängerbar)."""
    return _nur_verkuerzt("SECURITY_AUDIT_MOCK_BEREIT", MOCK_BEREIT)


def _ohne_frist() -> None:
    global _ENDE
    _ENDE = None


def _budget_erschoepft() -> bool:
    return _ENDE is not None and time.monotonic() >= _ENDE


def _timeout(sekunden: int) -> int:
    try:
        grenze = int(os.environ.get("SECURITY_AUDIT_DOCKER_TIMEOUT", ""))
    except ValueError:
        return sekunden
    return min(sekunden, grenze) if grenze > 0 else sekunden


class _Puffer:
    """Liest einen Strom mit Obergrenze (`ende`: die letzten, sonst die ersten `grenze` Bytes); der Rest wird
    verworfen, aber weiter gelesen, damit docker nie an einer vollen Pipe hängt."""

    def __init__(self, strom, grenze: int, ende: bool):
        self.daten = bytearray()
        self.gekuerzt = False
        self.lesefehler = False          # Lesefehler am Strom: die Ausgabe ist unvollständig
        self._grenze = grenze
        self._ende = ende
        self.thread = threading.Thread(target=self._lesen, args=(strom,), daemon=True)
        self.thread.start()

    def _lesen(self, strom) -> None:
        fd = strom.fileno()
        while True:
            try:
                teil = os.read(fd, 65536)
            except OSError:
                self.lesefehler = True
                return
            if not teil:
                return
            if self._ende:
                self.daten += teil
                if len(self.daten) > 2 * self._grenze:
                    del self.daten[:len(self.daten) - self._grenze]
                    self.gekuerzt = True
            else:
                frei = self._grenze - len(self.daten)
                if frei > 0:
                    self.daten += teil[:frei]
                if len(teil) > frei:
                    self.gekuerzt = True

    def ergebnis(self, frist: float) -> tuple[bytes, bool]:
        self.thread.join(timeout=max(0.0, frist - time.monotonic()))  # Enkelprozess mit offener Pipe blockiert nicht
        daten, gekuerzt = bytes(self.daten), self.gekuerzt
        if self._ende and len(daten) > self._grenze:
            daten, gekuerzt = daten[-self._grenze:], True
        return daten, gekuerzt


def _schreiben(strom, daten: bytes) -> None:
    try:
        strom.write(daten)
    except OSError:
        pass
    finally:
        try:
            strom.close()
        except OSError:
            pass


def _beenden(p: subprocess.Popen) -> None:
    p.terminate()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def _docker(args: list[str], timeout: int, eingabe: bytes | None = None, env: dict | None = None,
            begrenzen: bool = True, anfang: bool = False, budget: bool = True) -> Ergebnis:
    """docker ohne Shell mit Timeout (erst SIGTERM, dann SIGKILL) und Lesegrenze (LESE_MAX je Strom; behalten
    wird das Ende, mit `anfang` der Anfang). Wirft DockerFehlt, wenn docker fehlt oder der Daemon nicht erreichbar
    ist: bei Exit 1/125 und Treffer in stderr nur, wenn `docker version` danach ebenfalls scheitert (die Ausgabe von
    Build und Container stammt vom Kunden und beweist nichts)."""
    if budget and _ENDE is not None and args[0] != "version":
        rest = _ENDE - time.monotonic()
        if rest <= 0:                                       # Gesamtbudget aufgebraucht: nichts mehr starten
            return Ergebnis(None, b"", b"", False)
        timeout = min(timeout, rest)
    umgebung = dict(os.environ)
    umgebung.update(env or {})
    try:
        p = subprocess.Popen(["docker", *args], stdin=subprocess.PIPE if eingabe is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=umgebung)
    except OSError as e:
        raise DockerFehlt(f"docker nicht startbar: {e}") from e
    out, err = _Puffer(p.stdout, LESE_MAX, not anfang), _Puffer(p.stderr, LESE_MAX, not anfang)
    if eingabe is not None:
        threading.Thread(target=_schreiben, args=(p.stdin, eingabe), daemon=True).start()
    try:
        rc: int | None = p.wait(timeout=_timeout(timeout) if begrenzen else timeout)
    except subprocess.TimeoutExpired:
        _beenden(p)
        rc = None
    frist = time.monotonic() + 5
    (o, ko), (e, ke) = out.ergebnis(frist), err.ergebnis(frist)
    r = Ergebnis(rc, o, e, ko or ke)
    if r.gekuerzt:
        print(f"docker {args[0]}: Ausgabe auf {LESE_MAX // 1024 // 1024} MiB gekürzt", file=sys.stderr)
    if out.lesefehler or err.lesefehler:
        print(f"docker {args[0]}: Ausgabe unvollständig (Lesefehler am Strom)", file=sys.stderr)
    if (rc in DAEMON_EXIT and args[0] != "version"
            and any(m in e.decode("utf-8", "replace").lower() for m in DAEMON_WEG)):
        v = _docker(["version", "--format", "{{.Server.Version}}"], VERSION_TIMEOUT, budget=False)
        if not v.ok:
            raise DockerFehlt(_tail(e.decode("utf-8", "replace"), 3))
    return r


def _daemon_pruefen() -> str:
    if "docker" in _ohne_werkzeuge():         # zentral für pruefen, bauen, starten, neustart: kein docker-Aufruf
        raise DockerFehlt("docker per SECURITY_AUDIT_OHNE ausgeschlossen")
    r = _docker(["version", "--format", "{{.Server.Version}}"], VERSION_TIMEOUT, budget=False)
    if not r.ok:
        grund = "Timeout" if r.rc is None else _tail(r.text, 3)
        raise DockerFehlt(f"Docker-Server nicht erreichbar: {grund}")
    return r.out.decode("utf-8", "replace").strip()


_unsichtbar = gitkopie.unsichtbar      # eine Definition für alle Ausgaben (gitkopie._t nutzt dieselbe)


def _entschaerfen(text: str) -> str:
    """Kundenstämmigen Text für die Ausgabe entschärfen (fließt in den LLM-Kontext): Steuer- und Formatzeichen
    (ESC, ANSI, NUL, CR, Bidi, Zero-Width, Zeilentrenner) als Escape-Sequenz; `\\n` und `\\t` bleiben."""
    aus = []
    for ch in text:
        if ch in "\n\t":
            aus.append(ch)
        elif ch == "\r":
            aus.append("\\r")
        elif _unsichtbar(ch):
            aus.append(gitkopie.escape_zeichen(ch))
        else:
            aus.append(ch)
    return "".join(aus)


def _tail(text: str, n: int = TAIL_ZEILEN) -> str:
    zeilen = [_entschaerfen(z.rstrip())[:ZEILE_MAX] for z in text.splitlines() if z.strip()]
    return "\n".join(zeilen[-n:])


def _gib_aus(r: Ergebnis) -> None:
    """stdout/stderr eines Kunden-Containers entschärft ausgeben; AUSGABE_MAX Zeichen je Strom gelten nach dem
    Escaping als harte Grenze."""
    for strom, ziel in ((r.out, sys.stdout), (r.err, sys.stderr)):
        text = _entschaerfen(strom[:AUSGABE_MAX].decode("utf-8", "replace"))
        gekuerzt = len(strom) > AUSGABE_MAX or len(text) > AUSGABE_MAX
        ziel.write(text[:AUSGABE_MAX])
        if gekuerzt:
            print(f"\n[Ausgabe auf {AUSGABE_MAX // 1024} KiB gekürzt]", file=sys.stderr)


def _ausgabe(text: str) -> None:
    if text:
        print(text, flush=True)


def _fehler_ende(kategorie: str, text: str = "", hinweise: list[str] | None = None) -> int:
    print(f"kategorie: {kategorie}")
    for h in hinweise or []:
        print(f"hinweis: {h}")
    _ausgabe(_tail(text))
    sys.stdout.flush()
    return 4


@contextlib.contextmanager
def _rollen_sperre(lauf: str, rolle: str, exklusiv: bool):
    """Sperre je Rolle (`rolle-<r>.lock` im Zustandsordner, flock): starten/neustart exklusiv, anfrage/ausfuehren geteilt.
    Ist die Rolle gerade belegt, endet der Aufruf mit Exit 1 und Meldung, statt Container eines anderen Aufrufs zu löschen
    oder eine Anfrage mitten in einem Neustart zu verlieren. Ohne Zustandsordner gibt es nichts zu schützen."""
    ordner = _ordner(lauf)
    if not os.path.isdir(ordner):
        yield
        return
    fd = os.open(os.path.join(ordner, f"rolle-{rolle}.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exklusiv else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PocFehler(f"Rolle {rolle} wird gerade von einem anderen poc.py-Aufruf neu gestartet oder benutzt: "
                            f"warten und erneut aufrufen", code=1) from None
        yield
    finally:
        os.close(fd)


# ------------------------------------------------------------------------------------ Lockfile / Node

def _json_datei(pfad: str) -> object:
    with open(pfad, encoding="utf-8") as f:
        return json.load(f)


def _lock_laden(quelle: str) -> dict | None:
    pfad = os.path.join(quelle, "package-lock.json")
    try:
        if os.path.getsize(pfad) > LOCKFILE_MAX:
            print(f"poc.py: package-lock.json zu groß (über {LOCKFILE_MAX // 1024 // 1024} MiB), nicht gelesen", file=sys.stderr)
            return None
        daten = _json_datei(pfad)
    except (OSError, ValueError, RecursionError) as e:
        print(f"poc.py: package-lock.json nicht lesbar ({_tail(f'{type(e).__name__}: {e}', 1)})", file=sys.stderr)
        return None
    if not isinstance(daten, dict):
        print("poc.py: package-lock.json nicht lesbar (kein JSON-Objekt)", file=sys.stderr)
        return None
    return daten


FREMDE_PRAEFIXE = ("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:", "file:", "link:", "ssh://")


def _fremde_quelle(daten: object) -> bool:
    """Irgendein Eintrag zeigt nicht auf die npm-Registry (iterativ, damit tiefe Verschachtelung nichts sprengt)."""
    stapel: list[tuple[str | None, object]] = [(None, daten)]
    while stapel:
        schluessel, wert = stapel.pop()
        if isinstance(wert, dict):
            for k, v in wert.items():
                if k == "resolved" and not (isinstance(v, str) and v.startswith(REGISTRY)):
                    return True
                if k == "link" and v is True:
                    return True
                stapel.append((k, v))
        elif isinstance(wert, list):
            stapel.extend((schluessel, v) for v in wert)
        elif isinstance(wert, str):
            klein = wert.strip().lower()
            if klein.startswith(FREMDE_PRAEFIXE):
                return True
            if schluessel == "version" and klein.startswith(("http://", "https://")):
                return True
    return False


def lockfile_pruefen(quelle: str) -> str | None:
    """Kategorie, wenn die Quelle nicht gebaut werden darf, sonst None."""
    lock = os.path.join(quelle, "package-lock.json")
    if not os.path.isfile(lock):
        if any(os.path.isfile(os.path.join(quelle, n)) for n in ("pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")):
            return "nicht-npm"
        return "lockfile-fehlt"
    daten = _lock_laden(quelle)
    if daten is None:
        return "lockfile-fehlt"
    if _fremde_quelle(daten):
        return "lockfile-fremde-quelle"
    return None


def lockfile_hinweise(quelle: str) -> list[str]:
    """Hinweis-Kategorien (brechen den Bau nicht ab): native-module, prisma-engines, lockfile-ohne-paketliste."""
    daten = _lock_laden(quelle)
    if daten is None:
        return []
    pakete = daten.get("packages")
    if not isinstance(pakete, dict):
        return ["lockfile-ohne-paketliste"]          # lockfileVersion 1: native Module und Prisma nicht erkennbar
    hinweise: list[str] = []
    native = prisma = False
    for pfad, eintrag in pakete.items():
        if not pfad:
            continue  # Wurzelpaket: seine Skripte laufen nie (npm ci --ignore-scripts)
        if isinstance(eintrag, dict) and eintrag.get("hasInstallScript") is True:
            native = True
        if pfad.endswith(("node_modules/@prisma/client", "node_modules/prisma")):
            prisma = True
    if native:
        hinweise.append("native-module")
    if prisma:
        hinweise.append("prisma-engines")
    return hinweise


_VERGLEICH = re.compile(r"(\^|~|>=|<=|>|<|=)?v?([0-9]+|[xX*])(?:\.([0-9]+|[xX*]))?(?:\.([0-9]+|[xX*]))?(?:[-+][0-9A-Za-z.+-]*)?")
Vergleich = tuple  # (op, major|None, minor|None, patch|None); None = Platzhalter


def _teil(s: str | None) -> int | None:
    return None if s is None or s in ("x", "X", "*") else int(s)  # ValueError bei über 4300 Ziffern: s. _vergleich_lesen


def _vergleich_lesen(token: str) -> Vergleich | None:
    """Ein Vergleich wie `^20.11`, `>=18`, `x`; None, wenn der Token nicht lesbar ist."""
    m = _VERGLEICH.fullmatch(token)
    if not m:
        return None
    try:
        a, b, c = (_teil(m.group(i)) for i in (2, 3, 4))
    except ValueError:
        return None
    if a is None:
        return (m.group(1) or "^", None, None, None)
    return (m.group(1) or "^", a, b, None if b is None else c)


def _bereich_lesen(bereich: str) -> list[list[Vergleich]] | None:
    """Range einmal in Alternativen mit Vergleichen zerlegen (unlesbare Alternativen entfallen). None, wenn die
    Range zu lang ist (MAX_ENGINES Zeichen, MAX_VERGLEICHE Vergleiche)."""
    if len(bereich) > MAX_ENGINES:
        return None
    alternativen: list[list[Vergleich]] = []
    anzahl = 0
    for alternative in bereich.split("||"):
        bis = re.fullmatch(r"\s*(\S+)\s+-\s+(\S+)\s*", alternative)  # Bindestrich-Bereich `a - b`
        if bis:
            alternative = f">={bis.group(1)} <={bis.group(2)}"
        tokens = re.sub(r"(\^|~|>=|<=|>|<|=)\s+", r"\1", alternative.strip()).split()
        anzahl += len(tokens)
        if anzahl > MAX_VERGLEICHE:
            return None
        vergleiche = [_vergleich_lesen(tok) for tok in tokens]
        if None not in vergleiche:  # leere Alternative = alles
            alternativen.append(vergleiche)  # type: ignore[arg-type]
    return alternativen


def _vergleich_passt(v: tuple[int, int, int], vergleich: Vergleich) -> bool:
    op, a, b, c = vergleich
    if a is None:
        return True
    unten = (a, b or 0, c or 0)
    if op == "=":
        return v[0] == a and (b is None or v[1] == b) and (c is None or v[2] == c)
    if op == "^":
        if a > 0:
            oben = (a + 1, 0, 0)
        elif b is None:
            oben = (1, 0, 0)
        elif b > 0 or c is None:
            oben = (0, b + 1, 0)
        else:
            oben = (0, 0, c + 1)
        return unten <= v < oben
    if op == "~":
        return unten <= v < ((a + 1, 0, 0) if b is None else (a, b + 1, 0))
    if op == ">=":
        return v >= unten
    if op == "<":
        return v < unten
    if op == ">":
        return v > (a, b, c) if c is not None else v >= ((a, b + 1, 0) if b is not None else (a + 1, 0, 0))
    return v <= (a, b, c) if c is not None else v < ((a, b + 1, 0) if b is not None else (a + 1, 0, 0))  # <=


def _range_erfuellt(v: tuple[int, int, int], alternativen: list[list[Vergleich]]) -> bool:
    """Minimale semver-Auswertung: `||`, Leerzeichen = UND, ^ ~ >= > <= < = x * und nackte Version (= ^)."""
    return any(all(_vergleich_passt(v, x) for x in alt) for alt in alternativen)


def _proben(major: int, alternativen: list[list[Vergleich]]) -> set[tuple[int, int, int]]:
    """Versionen eines Majors, an denen sich die Erfüllung einer Range ändern kann: Grenzen 0/99 und jeder in
    der Range genannte Minor/Patch mit seinen Nachbarn (höchstens ~9 je Vergleich)."""
    proben = {(major, m, p) for m in (0, 99) for p in (0, 99)}
    for alt in alternativen:
        for _op, a, b, c in alt:
            if a != major or b is None:
                continue
            for m in (b - 1, b, b + 1):
                if m < 0:
                    continue
                for p in ((0, 99) if c is None else (c - 1, c, c + 1)):
                    if p >= 0:
                        proben.add((major, m, p))
    return proben


def _engines(quelle: str) -> str | None:
    """`engines.node` aus package.json; None bei fehlend, unlesbar oder größer als PACKAGE_JSON_MAX."""
    try:
        with open(os.path.join(quelle, "package.json"), "rb") as f:
            if os.fstat(f.fileno()).st_size > PACKAGE_JSON_MAX:
                return None
            paket = json.loads(f.read())
        engines = paket["engines"]["node"]
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None
    return engines if isinstance(engines, str) and engines.strip() else None


def _node_wahl(quelle: str, vorgabe: str | None) -> tuple[str, str]:
    """(Node-Major, Quelle der Wahl): `vorgabe`, `engines`, `nvmrc` oder `standard`."""
    if vorgabe:
        return str(vorgabe), "vorgabe"
    engines = _engines(quelle)
    alternativen = _bereich_lesen(engines) if engines else None
    if alternativen is not None:
        for major in KANDIDATEN:
            if _range_erfuellt((major, 99, 99), alternativen):
                return str(major), "engines"
        # Bereiche, die nur einzelne Minor-/Patch-Versionen treffen (~20.11, =20.11.5, <=20.11.0).
        for major in KANDIDATEN:
            if any(_range_erfuellt(v, alternativen) for v in sorted(_proben(major, alternativen))):
                return str(major), "engines"
    try:
        with open(os.path.join(quelle, ".nvmrc"), encoding="utf-8", errors="replace") as f:
            nvmrc = f.readline(100).strip()
    except OSError:
        nvmrc = ""
    m = re.fullmatch(r"v?(\d+)(?:\.\d+){0,2}", nvmrc)
    if m and len(m.group(1)) <= 3 and int(m.group(1)) in KANDIDATEN:
        return m.group(1), "nvmrc"
    return STANDARD_NODE, "standard"


def node_hinweise(quelle: str, vorgabe: str | None) -> list[str]:
    """Hinweis-Kategorien zur Node-Auswahl: `node-range-zu-lang` (engines.node wird ignoriert) und `node-engines-ignoriert`
    (engines.node ist unlesbar oder von keinem Kandidaten 24/22/20 erfüllbar; es gilt `.nvmrc` oder der Standard)."""
    if vorgabe:
        return []
    engines = _engines(quelle)
    if engines is None:
        return []
    if _bereich_lesen(engines) is None:
        return ["node-range-zu-lang"]
    return [] if _node_wahl(quelle, None)[1] == "engines" else ["node-engines-ignoriert"]


def node_version(quelle: str, vorgabe: str | None) -> str:
    """Node-Major: Vorgabe, sonst höchster Kandidat (24/22/20) zu `engines.node`, sonst `.nvmrc`, sonst 22."""
    return _node_wahl(quelle, vorgabe)[0]


# ------------------------------------------------------------------------------------ Befehle

def cmd_neu(_a: argparse.Namespace) -> int:
    """Neue Lauf-ID; der Zustandsordner wird dabei exklusiv angelegt (0700): zwei parallele Audits bekommen nie dieselbe ID,
    und ein Lauf, der gleich danach abbricht, bleibt über `poc.py auflisten` auffindbar."""
    for _ in range(50):
        lauf = secrets.token_hex(4)
        try:
            os.mkdir(zustand_ordner(lauf), 0o700)
        except FileExistsError:
            continue
        print(lauf)
        return 0
    raise PocFehler("keine freie Lauf-ID gefunden (Temp-Ordner voller security-audit-*-Ordner?)", code=1)


def cmd_pruefen(_a: argparse.Namespace) -> int:
    version = _daemon_pruefen()
    print(f"docker: ok (Server {version})")
    return 0


def cmd_vorbereiten(a: argparse.Namespace) -> int:
    repo = os.path.realpath(a.repo)
    if not os.path.isdir(repo):
        raise PocFehler(f"--repo ist kein Ordner: {a.repo}")
    ordner = _ordner(a.lauf, anlegen=True)
    quelle = os.path.join(ordner, "quelle")
    marker = os.path.join(ordner, "quelle.fertig")
    _frist_setzen("SECURITY_AUDIT_VORBEREITEN_BUDGET", VORBEREITEN_BUDGET)
    gitkopie.frist_setzen(_ENDE)       # die Frist gilt für alle git-Aufrufe und das Kopieren; sie läuft ab dem Entfernen
    try:
        return _vorbereiten(a, repo, ordner, quelle, marker)
    finally:
        gitkopie.frist_setzen(None)
        _ohne_frist()


def _vorbereiten(a: argparse.Namespace, repo: str, ordner: str, quelle: str, marker: str) -> int:
    _entferne(schwaerz_marker(a.lauf), os.path.join(ordner, "lieferkette"))    # neue Kopie ist ungeschwärzt: `secrets` erneut
    _entferne(marker, ordner)          # erst der Marker, dann die Kopie: ein Absturz dazwischen hinterlässt keine „fertige“ Kopie
    _entferne(quelle, ordner)          # lokale Dateioperation: wird nicht unterbrochen, zählt aber gegen das Budget
    sha = a.sha or "HEAD"
    try:
        meldungen = gitkopie.arbeitskopie(repo, quelle, sha)
    except gitkopie.GitFehler as e:
        print("kategorie: git-fehler")
        print(f"git-Fehler: {e}", file=sys.stderr)
        return 4
    except OSError as e:
        print("kategorie: arbeitskopie-unvollstaendig")
        print(f"Arbeitskopie unvollständig: {e}", file=sys.stderr)
        return 4
    for m in meldungen:
        print(m, file=sys.stderr)
    if any("Arbeitskopie unvollständig" in m for m in meldungen):
        print("kategorie: arbeitskopie-unvollstaendig")
        return 4
    try:
        kopiert = gitkopie.git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}").stdout.decode().strip()
    except gitkopie.ZeitbudgetFehler as e:         # keine „fertige“ Kopie ohne geklärten Commit nach Ablauf des Budgets
        print("kategorie: git-fehler")
        print(f"git-Fehler: {e}", file=sys.stderr)
        return 4
    except gitkopie.GitFehler:
        kopiert = sha
    _schreibe_atomar(marker, {"fertig": True, "sha": kopiert, "id": secrets.token_hex(16)})
    print(quelle)
    return 0


def _marker_gueltig(lauf: str) -> bool:
    """Schwärzungs-Marker ist eine reguläre Datei (kein Symlink, kein Ordner, kein Gerät) und trägt die Kennung der aktuellen
    Arbeitskopie (Feld `kopie`); ohne Kennung der Kopie gilt er nie."""
    daten = _regulaere_datei_lesen(schwaerz_marker(lauf))
    kennung = kopie_kennung(lauf)
    return kennung is not None and isinstance(daten, dict) and daten.get("kopie") == kennung


def cmd_bauen(a: argparse.Namespace) -> int:
    _daemon_pruefen()
    ordner = _ordner(a.lauf)
    quelle = os.path.join(ordner, "quelle")
    if not os.path.isdir(quelle):
        raise PocFehler("Arbeitskopie fehlt: erst `poc.py vorbereiten --lauf … --repo …`")
    if not os.path.isfile(os.path.join(ordner, "quelle.fertig")):
        raise PocFehler("Arbeitskopie unvollständig (kein Fertig-Marker, Abbruch beim Kopieren?): "
                        "erneut `poc.py vorbereiten --lauf … --repo …`")
    if not werkzeug_fehlt("gitleaks") and not _marker_gueltig(a.lauf):
        return _fehler_ende("nicht-geschwaerzt", "Arbeitskopie nicht auf Secrets geprüft und geschwärzt: erst "
                            "`lieferkette.py secrets --lauf … --repo … --quelle … --sha …` (Marker fehlt), dann erneut bauen.")
    kategorie = lockfile_pruefen(quelle)
    if kategorie:
        return _fehler_ende(kategorie)
    hinweise = lockfile_hinweise(quelle) + node_hinweise(quelle, a.node)
    version = node_version(quelle, a.node)
    befehl = ["build", "--progress=plain", "--build-arg", f"NODE={version}"]
    if a.build_befehl:
        befehl += ["--build-arg", f"BUILD_BEFEHL={a.build_befehl}"]
    befehl += ["-f", DOCKERFILE, "--build-context", f"poc={DOCKER_DIR}", "-t", _image(a.lauf), quelle]
    try:
        grenze = int(os.environ.get("SECURITY_AUDIT_BAU_TIMEOUT", ""))
    except ValueError:
        grenze = BAU_TIMEOUT
    r = _docker(befehl, grenze if grenze > 0 else BAU_TIMEOUT, env={"DOCKER_BUILDKIT": "1"}, begrenzen=False)
    if r.rc is None:
        return _fehler_ende("build-timeout", r.text, hinweise)
    if r.rc != 0:
        _daemon_pruefen()  # Daemon-Störung ohne Marker im Text: docker-fehlt statt build-fehler
        return _fehler_ende("build-fehler", r.text, hinweise)
    for h in hinweise:
        print(f"hinweis: {h}")
    print(f"node: {version}")
    print(f"image: {_image(a.lauf)}")
    return 0


def _rolle_entfernen(lauf: str, rolle: str) -> None:
    netz = _netz(lauf, rolle)
    # `-v`: auch das anonyme Volume des Postgres-Images; sonst bliebe je neustart ein Volume liegen
    _docker(["rm", "-f", "-v", f"{netz}-app", f"{netz}-db", f"{netz}-llm"], KURZ_TIMEOUT, budget=False)  # fehlende Container sind kein Fehler


def _anfrage_container(lauf: str, rolle: str, argumente: list[str], daten: bytes, timeout: int) -> Ergebnis:
    """Request-Container im internen Netz der Rolle; Daten per stdin, bei Timeout wird der Container entfernt."""
    name = f"security-audit-{lauf}-{rolle}-anfrage-{secrets.token_hex(3)}"
    befehl = ["run", "-i", "--rm", "--pull", "never", "--name", name, "--network", _netz(lauf, rolle), *HAERTUNG_APP,
              _image(lauf), "node", "/poc/anfrage.mjs", *argumente]
    r = _docker(befehl, timeout, eingabe=daten, anfang=True)
    if r.rc is None:
        _docker(["rm", "-f", name], KURZ_TIMEOUT)
    return r


def _start_fehler(lauf: str, rolle: str, text: str, container: str = "app") -> int:
    """`container`: dessen Logs den Fehlertext ergänzen (`app`, bei einem Fehler des Modell-Mocks `llm`)."""
    try:
        _daemon_pruefen()  # Daemon-Störung ohne Marker im Text: docker-fehlt statt start-fehler
    except DockerFehlt:
        try:
            _rolle_entfernen(lauf, rolle)  # best effort: bereits angelegte Container der Rolle nicht liegen lassen
        except DockerFehlt:
            pass                           # Daemon wirklich weg: `poc.py aufraeumen` holt es später nach
        raise
    logs = _docker(["logs", "--tail", str(TAIL_ZEILEN), f"{_netz(lauf, rolle)}-{container}"], KURZ_TIMEOUT, budget=False)
    _rolle_entfernen(lauf, rolle)
    if _budget_erschoepft():
        text = f"Zeitbudget von {_BUDGET_SEKUNDEN} s erschöpft (Bash-Limit des Skills: 600 s). {text}"
    return _fehler_ende("start-fehler", "\n".join(t for t in (_tail(text), _tail(logs.text) if logs.ok else "") if t))


def _mock_starten(lauf: str, rolle: str) -> str | None:
    """Modell-Mock `<netz>-llm` im internen Netz der Rolle starten und auf seine Bereitschaft warten (`exec --bereit`: Exit 0
    heißt bereit, Exit 1 nicht; bei festen Ports schreibt der Server nichts auf stdout). Gibt die Fehlerbeschreibung zurück,
    None bei Erfolg. Jede Abfrage bekommt höchstens die Restzeit der Bereitschaftsfrist als Timeout."""
    netz = _netz(lauf, rolle)
    llm = f"{netz}-llm"
    r = _docker(["run", "-d", "--pull", "never", "--name", llm, "--network", netz, "--network-alias", "llm", *HAERTUNG_MOCK,
                 _image(lauf), "node", "/poc/llm-mock.mjs", "--server", "--port", str(MOCK_PORT),
                 "--steuer-port", str(MOCK_STEUER_PORT)], 120)
    if not r.ok:
        return f"nicht gestartet: {'Zeitüberschreitung' if r.rc is None else r.text}"
    frist = _mock_bereit_sekunden()
    ende = time.monotonic() + frist
    while True:
        rest = ende - time.monotonic()
        if rest <= 0 or _budget_erschoepft():
            return f"nicht bereit nach {frist} s"
        r = _docker(["exec", "-i", llm, "node", "/poc/llm-mock.mjs", "--bereit"], min(KURZ_TIMEOUT, max(1, int(rest))))
        if r.ok:
            return None
        time.sleep(min(1, max(0, ende - time.monotonic())))


def _starte(lauf: str, rolle: str, p: dict) -> int:
    netz = _netz(lauf, rolle)
    app, db = f"{netz}-app", f"{netz}-db"
    _rolle_entfernen(lauf, rolle)
    r = _docker(["network", "create", "--internal", netz], KURZ_TIMEOUT)
    if not r.ok and "already exists" not in r.text:
        return _start_fehler(lauf, rolle, f"Netz {netz} nicht erstellt: {r.text}")
    if p["modell_mock"]:
        fehler = _mock_starten(lauf, rolle)
        if fehler is not None:
            return _start_fehler(lauf, rolle, f"Modell-Mock: {fehler}", "llm")
    if p["dienst"] == "postgres":
        if not _docker(["image", "inspect", POSTGRES_IMAGE], KURZ_TIMEOUT).ok:
            r = _docker(["pull", POSTGRES_IMAGE], PULL_TIMEOUT)
            if not r.ok:
                return _start_fehler(lauf, rolle, f"{POSTGRES_IMAGE} nicht ladbar: {r.text}")
        r = _docker(["run", "-d", "--pull", "never", "--name", db, "--network", netz, "--network-alias", "db", *HAERTUNG_DB,
                     "-e", "POSTGRES_USER=poc", "-e", "POSTGRES_PASSWORD=poc", "-e", "POSTGRES_DB=poc",
                     POSTGRES_IMAGE], 120)
        if not r.ok:
            return _start_fehler(lauf, rolle, f"Datenbank nicht gestartet: {r.text}")
        ende = time.monotonic() + DB_WARTEN
        while True:
            # TCP statt Unix-Socket: der temporäre Init-Server von initdb lauscht nur auf dem Socket.
            r = _docker(["exec", db, "pg_isready", "-h", "127.0.0.1", "-U", "poc", "-d", "poc"], KURZ_TIMEOUT)
            if r.ok:
                break
            if time.monotonic() >= ende:
                return _start_fehler(lauf, rolle, f"Datenbank nicht bereit nach {DB_WARTEN} s: {r.text}")
            time.sleep(1)
    umgebung = ["-e", "HOST=0.0.0.0", "-e", f"PORT={p['port']}"]
    for e in p["env"]:
        umgebung += ["-e", e]
    for api in p["modell_mock"]:
        for name, wert in MOCK_ENV[api]:
            umgebung += ["-e", f"{name}={wert}"]
    r = _docker(["run", "-d", "--pull", "never", "--name", app, "--network", netz, "--network-alias", "app", *HAERTUNG_APP, *umgebung,
                 _image(lauf), "sh", "-c", p["start_befehl"]], 120)
    if not r.ok:
        return _start_fehler(lauf, rolle, f"App nicht gestartet: {r.text}")
    if p["seed"]:
        r = _docker(["exec", app, "sh", "-c", p["seed"]], SEED_TIMEOUT)
        if not r.ok:
            return _start_fehler(lauf, rolle, f"Seed fehlgeschlagen: {r.text}")
    r = _anfrage_container(lauf, rolle, ["--url", f"http://app:{p['port']}/", "--warten", str(WARTEN_SEKUNDEN)],
                           b"", WARTEN_TIMEOUT)
    if not r.ok:
        return _start_fehler(lauf, rolle, f"App antwortet nicht: {r.text}")
    print(f"app: http://app:{p['port']} (Rolle {rolle}, Netz {netz})")
    if p["dienst"] == "postgres":
        print(f"db: {DB_URL}")
    if p["modell_mock"]:
        print(f"modell-mock: {MOCK_URL} ({', '.join(p['modell_mock'])})")
    return 0


def _fremde_hosts_env(wert: str) -> list[str]:
    """Nicht erlaubte Hosts in einem `--env`-Wert. Die Netzregel liest die Authority bis `/`, `?`, `#` oder Leerzeichen; in einer Liste
    `https://app:3000,http://localhost:5173` wäre das `app:3000,http:`. Enthält ein gefundener „Host“ `,` oder `;` (das kommt in
    keinem Host vor), wird jedes Listenelement für sich geprüft; die Bash-Prüfung (`netzregel.ist_poc_aufruf`) bleibt unberührt."""
    fremd = netzregel.verstoesse_poc(wert)
    if any("," in h or ";" in h for h in fremd):
        fremd = [h for h in fremd if "," not in h and ";" not in h]
        for teil in re.split(r"[,;]", wert):
            fremd += [h for h in netzregel.verstoesse_poc(teil) if h not in fremd]
    return fremd


def _env_pruefen(env: list[str], modell_mock: list[str]) -> None:
    """Regeln für `--env` (Exit 2, Meldungen nennen nur Namen und Host, nie den Wert): jeder Wert läuft durch die Netzregel
    (`netzregel.verstoesse_poc`: nur app, db, llm, localhost und Loopback); mit `--modell-mock` sind die Namen in `MOCK_RESERVIERT`
    (auch die der nicht gewählten API) gesperrt, weil `starten` sie selbst setzt."""
    for e in env:
        name, _, wert = e.partition("=")
        if modell_mock and name.upper() in MOCK_RESERVIERT:
            raise PocFehler(f"--env {name}: reservierter Name bei --modell-mock")
        fremd = _fremde_hosts_env(wert)
        if fremd:
            raise PocFehler(f"--env {name}: nicht erlaubter Host {_entschaerfen(fremd[0])[:100]}")


def _start_befehl_pruefen(befehl: str, modell_mock: list[str], option: str = "--start-befehl") -> None:
    """Regeln für `--start-befehl` und `--seed` (`option`; Exit 2, die Meldung nennt nur Namen oder Host, nie den Befehl): mit `--modell-mock`
    darf der Befehl keinen Namen aus `MOCK_RESERVIERT` zuweisen oder aufheben (`NAME=`, `NAME+=`, auch nach `env` und `export`, `unset NAME`,
    `env -u NAME` auch gruppiert, `read NAME`, `for NAME in`, `printf -v NAME`, `export -n NAME`, `typeset +x NAME`, `declare -n x=NAME`; Anführungszeichen,
    Rückstriche und Zeilenfortsetzungen im Namen zählen nicht: `OPENAI_BASE_UR""L=` wird erkannt) und kein `env -i`, `env -` oder `env --ignore-environment` (leeren die Umgebung);
    unabhängig davon läuft er durch die Netzregel (nur URL-Hosts). Nicht erkennbar ist, was die Shell erst beim Ausführen zusammensetzt
    (`eval`, Variablennamen aus Variablen, `process.env[…]` in einem Skript) und weitere Builtins, die Variablen setzen (`mapfile`, `getopts`,
    `let`, `${NAME:=…}`): die Sperre ist das interne Netz, nicht diese Prüfung."""
    if modell_mock:
        for text in (befehl, _QUOTES_RE.sub("", befehl)):
            m = MOCK_RESERVIERT_RE.search(text)
            if m:
                raise PocFehler(f"{option}: reservierter Name {m.group(1)} bei --modell-mock")
            for segment in _SEGMENT_TRENNER_RE.split(text):
                r = _segment_umgehung(segment.split())
                if r:
                    raise PocFehler(f"{option}: reservierter Name {r} bei --modell-mock")
                if r is not None:
                    raise PocFehler(f"{option}: env -i leert die Umgebung samt der Mock-Variablen bei --modell-mock")
    fremd = netzregel.url_verstoesse(befehl)
    if fremd:
        raise PocFehler(f"{option}: nicht erlaubter Host {_entschaerfen(fremd[0])[:100]}")


def cmd_starten(a: argparse.Namespace) -> int:
    modell_mock = a.modell_mock or []
    _env_pruefen(a.env or [], modell_mock)
    _start_befehl_pruefen(a.start_befehl, modell_mock)
    if a.seed:
        _start_befehl_pruefen(a.seed, modell_mock, "--seed")      # läuft per `docker exec app sh -c`, also wie der Start-Befehl
    _daemon_pruefen()
    _frist_setzen("SECURITY_AUDIT_START_BUDGET", START_BUDGET)
    ordner = _ordner(a.lauf, anlegen=True)
    p = {"start_befehl": a.start_befehl, "port": a.port, "env": a.env or [], "dienst": a.dienst, "seed": a.seed,
         "modell_mock": modell_mock}
    with _rollen_sperre(a.lauf, a.rolle, exklusiv=True):
        _schreibe_atomar(os.path.join(ordner, f"rolle-{a.rolle}.json"), {"lauf": a.lauf, "rolle": a.rolle, **p})
        return _starte(a.lauf, a.rolle, p)


def cmd_neustart(a: argparse.Namespace) -> int:
    _daemon_pruefen()
    _frist_setzen("SECURITY_AUDIT_START_BUDGET", START_BUDGET)
    with _rollen_sperre(a.lauf, a.rolle, exklusiv=True):
        return _starte(a.lauf, a.rolle, _lade_rolle(a.lauf, a.rolle))


def cmd_ausfuehren(a: argparse.Namespace) -> int:
    with _rollen_sperre(a.lauf, a.rolle, exklusiv=False):
        r = _docker(["exec", f"{_netz(a.lauf, a.rolle)}-app", *a.kommando], EXEC_TIMEOUT, anfang=True)
    _gib_aus(r)
    if r.rc is None:
        print("ausfuehren: Zeitüberschreitung. Der Befehl kann im Container weiterlaufen (docker exec beendet ihn nicht); "
              f"`poc.py neustart --lauf {a.lauf} --rolle {a.rolle}` setzt die Rolle zurück", file=sys.stderr)
        return 1
    if r.rc != 0:
        print(f"ausfuehren: Befehl endete mit Exit {r.rc}", file=sys.stderr)
        return 1
    return 0


def cmd_anfrage(a: argparse.Namespace) -> int:
    z = _lade_rolle(a.lauf, a.rolle)
    daten = b""
    if a.daten is not None:
        daten = os.fsencode(a.daten)  # argv kann ungültiges UTF-8 (surrogateescape) enthalten
    elif a.daten_datei:
        try:
            with open(a.daten_datei, "rb") as f:
                daten = f.read(DATEN_MAX + 1)
        except OSError as e:
            raise PocFehler(f"--daten-datei nicht lesbar: {e}") from e
        if len(daten) > DATEN_MAX:
            raise PocFehler(f"--daten-datei größer als {DATEN_MAX} Bytes")
    argumente = ["--url", f"http://app:{z['port']}{a.pfad}", "--methode", a.methode]
    for h in a.header or []:
        argumente += ["--header", h]
    with _rollen_sperre(a.lauf, a.rolle, exklusiv=False):
        r = _anfrage_container(a.lauf, a.rolle, argumente, daten, ANFRAGE_TIMEOUT)
    _gib_aus(r)
    if r.rc is None:
        print("anfrage: Zeitüberschreitung", file=sys.stderr)
        return 1
    return 0 if r.rc == 0 else 1


# ------------------------------------------------------------------------------------ modell (Steuerung des Modell-Mocks)

def _antworten_serialisieren(daten: object) -> str:
    """Was der Mock auf stdin bekommt: kompaktes JSON (Trennzeichen ohne Leerzeichen), kein NaN und kein Infinity."""
    return json.dumps(daten, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _antworten_lesen(pfad: str) -> list:
    """Antwortliste aus `--antworten-datei`: höchstens 64 KiB (+ 1 Byte gelesen), sonst Exit 2. Prüft Form und Netzregel
    (Rohtext und geparstes JSON) und gibt die geprüfte Liste zurück; jede Abweichung endet mit Exit 2 ohne Docker-Aufruf."""
    try:
        with open(pfad, "rb") as f:
            roh = f.read(ANTWORTEN_DATEI_MAX + 1)
    except OSError as e:
        raise PocFehler(f"--antworten-datei nicht lesbar: {e}") from e
    if len(roh) > ANTWORTEN_DATEI_MAX:
        raise PocFehler(f"--antworten-datei größer als {ANTWORTEN_DATEI_MAX // 1024} KiB")
    try:
        text = roh.decode("utf-8")
        daten = json.loads(text)
    except (ValueError, RecursionError):
        raise PocFehler("--antworten-datei: kein gültiges JSON (UTF-8)") from None
    try:
        neu = _antworten_serialisieren(daten)                  # NaN und Infinity (auch aus `1e999`) kennt JSON nicht
        eingabe = neu.encode("utf-8")                          # ein einzelnes Surrogat (\ud800) ist kein UTF-8
    except (ValueError, RecursionError):
        raise PocFehler("--antworten-datei: kein gültiges JSON (UTF-8)") from None
    if len(eingabe) > STDIN_MAX_MOCK:                          # so viele Bytes bekäme der Mock auf stdin (`1e2` wird zu `100.0`)
        raise PocFehler(f"--antworten-datei: nach dem Serialisieren größer als {STDIN_MAX_MOCK // 1024} KiB")
    for fremd in (netzregel.verstoesse_poc(text), netzregel.verstoesse_poc(neu)):        # Rohtext und geparster Inhalt
        if fremd:
            raise PocFehler(f"--antworten-datei: nicht erlaubter Host {_entschaerfen(fremd[0])[:100]}")
    _antworten_pruefen(daten)
    return daten


def _antworten_pruefen(daten: object) -> None:
    """Form der Antwortliste (Exit 2 bei Abweichung): Liste mit höchstens 20 Einträgen; je Eintrag genau `text` (String, höchstens 16 384 UTF-16-Einheiten) oder
    `werkzeug` (`name` nach `[A-Za-z0-9_.-]{1,64}`, `argumente` ein Objekt, optional), optional `wenn_enthaelt` nach `POCMARKER-…`."""
    def falsch(grund: str) -> PocFehler:
        return PocFehler(f"--antworten-datei: {grund}")

    if not isinstance(daten, list):
        raise falsch("JSON-Liste erwartet")
    if len(daten) > ANTWORTEN_MAX:
        raise falsch(f"höchstens {ANTWORTEN_MAX} Einträge")
    for i, e in enumerate(daten, 1):
        if not isinstance(e, dict) or not set(e) <= {"text", "werkzeug", "wenn_enthaelt"}:
            raise falsch(f"Eintrag {i}: Objekt mit text oder werkzeug (und wenn_enthaelt) erwartet")
        if ("text" in e) == ("werkzeug" in e):
            raise falsch(f"Eintrag {i}: genau eines von text und werkzeug")
        if "text" in e and not (isinstance(e["text"], str) and _utf16_laenge(e["text"]) <= ANTWORT_TEXT_MAX):
            raise falsch(f"Eintrag {i}: text muss ein String mit höchstens {ANTWORT_TEXT_MAX} Zeichen sein")
        if "werkzeug" in e:
            w = e["werkzeug"]
            if not (isinstance(w, dict) and set(w) <= {"name", "argumente"}):
                raise falsch(f"Eintrag {i}: werkzeug braucht name (und argumente)")
            if not (isinstance(w.get("name"), str) and WERKZEUG_NAME_RE.fullmatch(w["name"])):
                raise falsch(f"Eintrag {i}: werkzeug.name muss [A-Za-z0-9_.-]{{1,64}} sein")
            if "argumente" in w and not isinstance(w["argumente"], dict):
                raise falsch(f"Eintrag {i}: werkzeug.argumente muss ein Objekt sein")
        if "wenn_enthaelt" in e and not (isinstance(e["wenn_enthaelt"], str) and MARKER_RE.fullmatch(e["wenn_enthaelt"])):
            raise falsch(f"Eintrag {i}: wenn_enthaelt muss POCMARKER-[a-z0-9-]{{1,40}} sein")


def _utf16_laenge(wert: str) -> int:
    """Länge in UTF-16-Einheiten wie `String.length` im Mock (ein Emoji zählt 2); argv-Surrogate zählen je 1."""
    return len(wert.encode("utf-16-le", "surrogatepass")) // 2


def _maskier_paare(z: dict) -> list[tuple[str, str]]:
    """(Name, Wert) aller Werte der Rolle, die nicht ins Protokoll gehören: die `--env`-Werte und die Schlüssel des Mocks (`*_API_KEY`
    der gewählten APIs). Quelle für die Maskierung im Mock (`_maskier_werte`) und für den Fehlerauszug (`_ohne_werte`)."""
    paare: list[tuple[str, str]] = []
    for e in z["env"]:
        name, _, wert = e.partition("=")
        paare.append((name, wert))
    for api in z["modell_mock"]:
        paare += [(name, wert) for name, wert in MOCK_ENV[api] if name.endswith("_API_KEY")]
    return paare


def _maskier_werte(z: dict) -> bytes:
    """stdin für `llm-mock.mjs --protokoll`: `{"werte":[{name,wert}]}` mit den Werten aus `_maskier_paare` ab 6 Zeichen, längste zuerst.
    Mehr als 200 Werte (Grenze des Mocks), ein Wert über 4096 UTF-16-Einheiten (Zählweise des Mocks), eine Liste über 64 KiB oder ein Wert
    mit ungültigem UTF-8 lassen sich nicht maskieren: Exit 2 statt Werte wegzulassen."""
    gesehen: set[tuple[str, str]] = set()
    werte = []
    for name, wert in _maskier_paare(z):
        if len(wert) >= MASKIER_WERT_MIN and (name, wert) not in gesehen:
            try:
                wert.encode("utf-8")
            except UnicodeEncodeError:                             # `starten` lässt das nicht zu (`_typ_env`); alte Rollendatei o. ä.
                raise PocFehler(f"--env {name}: Wert ist kein gültiges UTF-8, lässt sich nicht maskieren") from None
            gesehen.add((name, wert))
            werte.append((name[:MASKIER_NAME_MAX], wert))
    werte.sort(key=lambda p: -len(p[1]))                   # stabil: bei gleicher Länge die Reihenfolge von `--env`
    for name, wert in werte:
        if _utf16_laenge(wert) > MASKIER_WERT_MAX:
            raise PocFehler(f"--env {name}: Wert länger als {MASKIER_WERT_MAX} Zeichen, lässt sich nicht maskieren")
    if len(werte) > MASKIER_WERTE_MAX:
        raise PocFehler(f"{len(werte)} Werte der Rolle zu maskieren, höchstens {MASKIER_WERTE_MAX} möglich: weniger --env-Werte übergeben")
    nutzlast = json.dumps({"werte": [{"name": n, "wert": w} for n, w in werte]}, ensure_ascii=False).encode("utf-8", "replace")
    if len(nutzlast) > STDIN_MAX_MOCK:
        raise PocFehler(f"Maskierwerte der Rolle zusammen größer als {STDIN_MAX_MOCK // 1024} KiB, lassen sich nicht maskieren")
    return nutzlast


def _ohne_werte(text: str, z: dict) -> str:
    """Fehlertext ohne die Werte, die maskiert werden sollen (Mock und Docker geben sie nie aus; das hier ist die zweite Sicherung)."""
    for name, wert in sorted(_maskier_paare(z), key=lambda p: -len(p[1])):
        if len(wert) >= MASKIER_WERT_MIN:
            text = text.replace(wert, f"<ENV:{name}>")
    return text


def cmd_modell(a: argparse.Namespace) -> int:
    antworten = _antworten_lesen(a.antworten_datei) if a.antworten_datei else None
    _frist_setzen("SECURITY_AUDIT_MODELL_BUDGET", MODELL_BUDGET, verkuerzbar=True)
    with _rollen_sperre(a.lauf, a.rolle, exklusiv=False):
        z = _lade_rolle(a.lauf, a.rolle)
        if not z["modell_mock"]:
            raise PocFehler(f"Rolle {a.rolle} läuft ohne Modell-Mock (`starten --modell-mock`)", code=1)
        if antworten is not None:
            modus, eingabe = ["--setzen"], _antworten_serialisieren(antworten).encode("utf-8")
        else:
            modus = ["--protokoll"] + (["--suche", a.suche] if a.suche else [])
            eingabe = _maskier_werte(z)
        r = _docker(["exec", "-i", f"{_netz(a.lauf, a.rolle)}-llm", "node", "/poc/llm-mock.mjs", *modus,
                     "--steuer-port", str(MOCK_STEUER_PORT)], MODELL_BUDGET, eingabe=eingabe, anfang=True)
    if r.rc is None:
        print("modell: Zeitüberschreitung (Modell-Mock antwortet nicht)", file=sys.stderr)
        return 1
    if r.rc != 0:
        auszug = _tail(_ohne_werte(r.err.decode("utf-8", "replace"), z), 5)
        print(f"modell: Modell-Mock endete mit Exit {r.rc}" + (f": {auszug}" if auszug else ""), file=sys.stderr)
        return 1
    if antworten is not None:
        print(f"modell: {len(antworten)} Antworten gesetzt (Rolle {a.rolle})")
    else:
        sys.stdout.write(_entschaerfen(r.out.decode("utf-8", "replace")))      # unverändert, nicht gekürzt; Kundenstämmiges läuft durch _entschaerfen
    return 0


def _eigene_namen(lauf: str, text: str) -> list[str]:
    muster = re.compile(r"/?security-audit-" + re.escape(lauf) + r"(?:-[^\n]*)?")
    namen: list[str] = []
    for zeile in text.splitlines():
        name = zeile.strip()
        if name and muster.fullmatch(name):
            name = name.lstrip("/")
            if name not in namen:
                namen.append(name)
    return namen


def cmd_aufraeumen(a: argparse.Namespace) -> int:
    lauf = a.lauf
    _frist_setzen("SECURITY_AUDIT_AUFRAEUMEN_BUDGET", AUFRAEUMEN_BUDGET)
    ordner = zustand_ordner(lauf)  # bewusst ohne Besitzerprüfung: ein Symlink wird als Link entfernt
    unvollstaendig = False
    entfernt = {"container": 0, "netze": 0, "images": 0}
    try:
        schritte = (
            ("container", ["ps", "-a", "--format", "{{.Names}}"], lambda n: ["rm", "-f", "-v", *n]),
            ("netze", ["network", "ls", "--format", "{{.Name}}"], lambda n: ["network", "rm", *n]),
            ("images", ["images", "--format", "{{.Repository}}"], lambda n: ["rmi", *n]),
        )
        for art, liste, loeschen in schritte:
            r = _docker(liste, KURZ_TIMEOUT)
            if not r.ok:
                print(f"aufraeumen: {art} nicht lesbar: {_tail(r.text, 3) or 'Timeout'}", file=sys.stderr)
                unvollstaendig = True
                continue
            namen = _eigene_namen(lauf, r.out.decode("utf-8", "replace"))
            if not namen:
                continue
            r = _docker(loeschen(namen), 120)
            if r.ok:
                entfernt[art] = len(namen)
            else:
                print(f"aufraeumen: {art} nicht vollständig entfernt: {_tail(r.text, 5) or 'Timeout'}", file=sys.stderr)
                unvollstaendig = True
    except DockerFehlt as e:
        unvollstaendig = True          # Docker nicht geprüft: nicht „sauber“ melden (Exit 1)
        print(f"aufraeumen: Docker nicht erreichbar ({e}); Docker-Ressourcen mit Präfix security-audit-{lauf} "
              f"nicht geprüft, später erneut `poc.py aufraeumen --lauf {lauf}` ausführen", file=sys.stderr)
    if os.path.lexists(ordner):
        try:
            _entferne(ordner, os.path.dirname(ordner))
        except PocFehler as e:
            unvollstaendig = True
            print(f"aufraeumen: {e}", file=sys.stderr)
    print(f"aufgeräumt: {entfernt['container']} Container, {entfernt['netze']} Netze, {entfernt['images']} Images")
    return 1 if unvollstaendig else 0


_LAUF_NAME = re.compile(r"/?security-audit-([0-9a-f]{8})(?:-[^\n]*)?")


def cmd_auflisten(_a: argparse.Namespace) -> int:
    """Lesen, nie löschen: alle Läufe, deren Zustandsordner im Temp-Ordner oder deren Docker-Ressourcen `security-audit-<lauf>*`
    noch existieren (ein Abbruch ohne Aufräumen, verlorene Lauf-ID). Pro Lauf eine Zeile; aufgeräumt wird je Lauf mit
    `poc.py aufraeumen --lauf <id>`."""
    laeufe: dict[str, dict[str, object]] = {}

    def eintrag(lauf: str) -> dict[str, object]:
        return laeufe.setdefault(lauf, {"ordner": "nein", "container": 0, "netze": 0, "images": 0})

    basis = os.path.realpath(tempfile.gettempdir())
    for name in sorted(os.listdir(basis)):
        m = re.fullmatch(r"security-audit-([0-9a-f]{8})", name)
        if m and os.path.isdir(os.path.join(basis, name)) and not os.path.islink(os.path.join(basis, name)):
            eintrag(m.group(1))["ordner"] = "ja"
    unvollstaendig = False
    try:
        for art, liste in (("container", ["ps", "-a", "--format", "{{.Names}}"]),
                           ("netze", ["network", "ls", "--format", "{{.Name}}"]),
                           ("images", ["images", "--format", "{{.Repository}}"])):
            r = _docker(liste, KURZ_TIMEOUT)
            if not r.ok:
                print(f"auflisten: {art} nicht lesbar: {_tail(r.text, 3) or 'Timeout'}", file=sys.stderr)
                unvollstaendig = True
                continue
            gesehen: set[str] = set()
            for zeile in r.out.decode("utf-8", "replace").splitlines():
                m = _LAUF_NAME.fullmatch(zeile.strip())
                if m and zeile.strip().lstrip("/") not in gesehen:
                    gesehen.add(zeile.strip().lstrip("/"))
                    eintrag(m.group(1))[art] = int(eintrag(m.group(1))[art]) + 1
    except DockerFehlt as e:
        unvollstaendig = True
        print(f"auflisten: Docker nicht erreichbar ({e}); nur Zustandsordner aufgelistet", file=sys.stderr)
    for lauf in sorted(laeufe):
        e = laeufe[lauf]
        print(f"{lauf} ordner={e['ordner']} container={e['container']} netze={e['netze']} images={e['images']}")
    if laeufe:
        print("auflisten: je Lauf aufräumen mit `poc.py aufraeumen --lauf <id>` (nur eigene, beendete Läufe!)", file=sys.stderr)
    return 1 if unvollstaendig else 0


# ------------------------------------------------------------------------------------ Argumente

def _typ_lauf(s: str) -> str:
    if not LAUF_RE.fullmatch(s):
        raise argparse.ArgumentTypeError("--lauf: 8 Hex-Zeichen erwartet (0-9a-f)")
    return s


def _typ_sha(s: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", s):
        raise argparse.ArgumentTypeError("--sha: voller Commit-Hash (40 oder 64 Hex-Zeichen, klein) erwartet")
    return s


def _typ_rolle(s: str) -> str:
    if not ROLLE_RE.fullmatch(s):
        raise argparse.ArgumentTypeError("--rolle: p1 oder p2 erwartet")
    return s


def _typ_port(s: str) -> int:
    if not re.fullmatch(r"[0-9]{1,5}", s) or not 0 < int(s) < 65536:
        raise argparse.ArgumentTypeError("--port: 1 bis 65535 erwartet")
    return int(s)


def _utf8_pruefen(s: str, option: str) -> None:
    """Ein argv-Surrogat (ungültiges UTF-8) lässt sich weder in der Rollendatei speichern noch dem Mock zum Maskieren übergeben: Exit 2
    mit der Option, nie mit dem Wert (statt eines Tracebacks beim Schreiben oder eines still unmaskierten Werts)."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise argparse.ArgumentTypeError(f"{option}: kein gültiges UTF-8") from None


def _typ_env(s: str) -> str:
    name, gleich, _wert = s.partition("=")
    if not gleich or not ENV_NAME_RE.fullmatch(name) or "\x00" in s:
        raise argparse.ArgumentTypeError("--env: K=V erwartet (K: Buchstaben, Ziffern, _)")
    _utf8_pruefen(s, "--env")
    return s


def _typ_modell_mock(s: str) -> list[str]:
    apis = s.split(",")
    if not all(api in MOCK_ENV for api in apis) or len(set(apis)) != len(apis):
        raise argparse.ArgumentTypeError("--modell-mock: Liste aus openai und anthropic ohne Duplikate erwartet (openai,anthropic)")
    return apis


def _typ_marker(s: str) -> str:
    if not MARKER_RE.fullmatch(s):
        raise argparse.ArgumentTypeError("--suche: POCMARKER-[a-z0-9-]{1,40} erwartet")
    return s


def _typ_text(s: str) -> str:
    if not s.strip() or "\x00" in s:
        raise argparse.ArgumentTypeError("leerer Wert oder NUL-Zeichen")
    _utf8_pruefen(s, "Wert")
    return s


def _typ_pfad(s: str) -> str:
    vor_query = re.split(r"[?#]", s, maxsplit=1)[0]
    if not s.startswith("/") or s.startswith("//") or "://" in vor_query or re.search(r"[\x00-\x20\x7f\\]", s):
        raise argparse.ArgumentTypeError(
            "--pfad muss mit genau einem / beginnen, ohne Schema/Host davor, ohne Leer-, Steuer- und Rückstrich-Zeichen")
    return s


def _typ_header(s: str) -> str:
    name, doppelpunkt, wert = s.partition(":")
    if not doppelpunkt or not HEADER_NAME_RE.fullmatch(name) or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", wert):
        raise argparse.ArgumentTypeError("--header: 'Name: Wert' ohne Zeilenumbruch erwartet")
    return s


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="poc.py", allow_abbrev=False, description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="unterbefehl", required=True)

    def neu(name: str, fn, *, lauf: bool = True, rolle: bool = False) -> argparse.ArgumentParser:
        s = sub.add_parser(name, allow_abbrev=False)
        s.set_defaults(fn=fn)
        if lauf:
            s.add_argument("--lauf", required=True, type=_typ_lauf)
        if rolle:
            s.add_argument("--rolle", required=True, type=_typ_rolle)
        return s

    neu("neu", cmd_neu, lauf=False)
    neu("pruefen", cmd_pruefen, lauf=False)
    s = neu("vorbereiten", cmd_vorbereiten)
    s.add_argument("--repo", required=True)
    s.add_argument("--sha", type=_typ_sha, help="Commit, der kopiert wird (der `sha` aus bericht.py kontext); ohne: HEAD")
    s = neu("bauen", cmd_bauen)
    s.add_argument("--build-befehl", type=_typ_text)
    s.add_argument("--node", choices=["20", "22", "24"])
    s = neu("starten", cmd_starten, rolle=True)
    s.add_argument("--start-befehl", required=True, type=_typ_text)
    s.add_argument("--port", required=True, type=_typ_port)
    s.add_argument("--env", action="append", type=_typ_env)
    s.add_argument("--dienst", choices=["postgres"])
    s.add_argument("--seed", type=_typ_text)
    s.add_argument("--modell-mock", type=_typ_modell_mock,
                   help="Modell-Mock `llm` im Netz der Rolle starten: openai, anthropic oder openai,anthropic")
    neu("neustart", cmd_neustart, rolle=True)
    neu("ausfuehren", cmd_ausfuehren, rolle=True)
    s = neu("anfrage", cmd_anfrage, rolle=True)
    s.add_argument("--methode", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    s.add_argument("--pfad", required=True, type=_typ_pfad)
    s.add_argument("--header", action="append", type=_typ_header)
    s.add_argument("--daten")
    s.add_argument("--daten-datei")
    s = neu("modell", cmd_modell, rolle=True)
    betriebsart = s.add_mutually_exclusive_group(required=True)
    betriebsart.add_argument("--antworten-datei", help="Antwortliste (JSON) für den Modell-Mock setzen")
    betriebsart.add_argument("--protokoll", action="store_true", help="Protokoll der Requests an den Modell-Mock ausgeben")
    s.add_argument("--suche", type=_typ_marker, help="mit --protokoll: nur Requests, deren Body den Marker POCMARKER-… enthält")
    neu("aufraeumen", cmd_aufraeumen)
    neu("auflisten", cmd_auflisten, lauf=False)
    return p


def main(argv: list[str]) -> int:
    parser = _parser()
    befehl: list[str] = []
    if argv and argv[0] == "ausfuehren" and "--" in argv:
        i = argv.index("--")
        argv, befehl = argv[:i], argv[i + 1:]
    a = parser.parse_args(argv)
    if a.unterbefehl == "ausfuehren":
        if not befehl:
            parser.error("ausfuehren: Befehl nach `--` fehlt")
        a.kommando = befehl
    if a.unterbefehl == "anfrage" and a.daten is not None and a.daten_datei:
        parser.error("anfrage: --daten und --daten-datei schließen sich aus")
    if a.unterbefehl == "modell" and a.suche is not None and not a.protokoll:
        parser.error("modell: --suche gehört zu --protokoll")
    try:
        return a.fn(a)
    except DockerFehlt as e:
        print("kategorie: docker-fehlt")
        print(f"Docker nicht verfügbar: {e}", file=sys.stderr)
        return 3
    except PocFehler as e:
        print(f"poc.py: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
