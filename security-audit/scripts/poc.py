#!/usr/bin/env python3
"""Docker-PoC für den Skill security-audit (nur Standardbibliothek).

Sicherheitsgrenze: Kundencode läuft ausschließlich in Docker-Containern ohne Zugang nach außen
(`--internal`-Netz je Rolle) und nie auf dem Host. Der Bau holt nur die Pakete der Lockfile per `npm ci
--ignore-scripts` aus der npm-Registry (keine Install-Skripte, Quelle per Lockfile-Prüfung auf die Registry beschränkt);
der Build-Befehl des Kunden läuft ohne Netz. PoC-Requests gehen nur an `http://app:<port>` aus einem
Wegwerf-Container im Netz der Rolle. Es gibt keine Host-Mounts und keine veröffentlichten Ports. Gelöscht wird
nur, was `security-audit-<lauf>` heißt (Container, Netze, Images) und der eigene Zustandsordner.

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I poc.py neu | pruefen | vorbereiten | bauen | starten | ausfuehren | neustart | anfrage | aufraeumen | auflisten

Exit-Codes: 0 ok, 2 ungültige Argumente, 3 Docker fehlt oder Daemon nicht erreichbar, 4 Bau/Start scheitert
(erste stdout-Zeile `kategorie: <wert>`, danach höchstens die letzten 40 Zeilen der Docker-Ausgabe),
1 sonstiger Fehler (Request fehlgeschlagen, Befehl im Container mit Exit ≠ 0, Aufräumen unvollständig).
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
        if not (isinstance(port, int) and 0 < port < 65536 and isinstance(befehl, str) and befehl
                and isinstance(env, list) and all(isinstance(e, str) and "=" in e for e in env)
                and dienst in (None, "postgres") and (seed is None or isinstance(seed, str))):
            raise ValueError("Zustandsdatei ungültig")
    except (OSError, ValueError, KeyError, TypeError):
        raise PocFehler(f"Rolle {rolle} nicht gestartet (oder Zustand unlesbar): erst `poc.py starten`") from None
    return {"start_befehl": befehl, "port": port, "env": env, "dienst": dienst, "seed": seed}


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


def _frist_setzen(umgebungsvariable: str, standard: int) -> None:
    """Gesamtbudget des Befehls: Docker-Aufrufe mit `budget=True` werden auf die Restzeit gekürzt, danach nicht mehr gestartet.
    Die Umgebungsvariable überschreibt den Standard (Tests)."""
    global _ENDE, _BUDGET_SEKUNDEN
    try:
        sekunden = int(os.environ.get(umgebungsvariable, ""))
    except ValueError:
        sekunden = standard
    _BUDGET_SEKUNDEN = sekunden if sekunden > 0 else standard
    _ENDE = time.monotonic() + _BUDGET_SEKUNDEN


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
SPEC_FELDER = frozenset({"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "requires", "overrides"})
# Registry-Spec: Semver-Range oder dist-Tag (kein `:`, `/` oder `@`), optional `$name` (overrides) oder `npm:<name>[@<range>]`.
_REGISTRY_RANGE = re.compile(r"[A-Za-z0-9._+*^~<>=|, -]*")
_REGISTRY_ALIAS = re.compile(r"npm:(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*(?:@[A-Za-z0-9._+*^~<>=|, -]*)?")
_REGISTRY_REF = re.compile(r"\$[A-Za-z0-9._~@/-]+")


def _registry_spec(spec: object) -> bool:
    """Spec-String zeigt nur auf die npm-Registry (Range, Tag, `npm:`-Alias, overrides-Verweis `$name`)."""
    if not isinstance(spec, str):
        return False
    s = spec.strip()
    return bool(_REGISTRY_RANGE.fullmatch(s) or _REGISTRY_ALIAS.fullmatch(s) or _REGISTRY_REF.fullmatch(s))


def _specs_fremd(feld: dict) -> bool:
    """Eine Spec-Map (name → Spec, bei overrides verschachtelt) enthält etwas außerhalb der Registry. Karten alter
    Lockfiles (`dependencies` name → Objekt) werden vom Aufrufer weiter durchsucht, hier nur Strings geprüft."""
    stapel: list[object] = [feld]
    while stapel:
        wert = stapel.pop()
        if isinstance(wert, dict):
            stapel.extend(wert.values())
        elif isinstance(wert, list):
            return True
        elif isinstance(wert, str) and not _registry_spec(wert):
            return True
    return False


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
                if k in SPEC_FELDER and isinstance(v, dict):
                    for name, spec in v.items():
                        if isinstance(spec, dict):
                            if k == "overrides":
                                if _specs_fremd(spec):
                                    return True
                            else:
                                stapel.append((name, spec))     # v1-Lockfile: dependencies name → Eintrag
                        elif not _registry_spec(spec):
                            return True
                    continue
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


_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


def _ohne_resolved(daten: dict) -> bool:
    """Ein Paket unter `node_modules/` hat kein `resolved` und keine reine Semver-`version` (gebündelte Pakete
    ausgenommen): npm ginge dann nach einer Spec statt nach Registry-Name und -Version los. Einträge ohne `resolved`
    mit reiner Version kommen in echten Lockfiles vor (dedupe) und holen `name@version` aus der Registry."""
    pakete = daten.get("packages")
    if not isinstance(pakete, dict):
        return False
    return any(isinstance(e, dict) and "node_modules/" in pfad and "resolved" not in e and e.get("inBundle") is not True
               and not (isinstance(e.get("version"), str) and _SEMVER.fullmatch(e["version"]))
               for pfad, e in pakete.items())


def _package_json_fremd(quelle: str) -> bool:
    pfad = os.path.join(quelle, "package.json")
    if not os.path.isfile(pfad):
        return False
    try:
        daten = _json_datei(pfad)
    except (OSError, ValueError, RecursionError):
        return True       # nicht lesbar: nicht bauen (kein stilles Durchwinken)
    if not isinstance(daten, dict):
        return True
    return _fremde_quelle({k: v for k, v in daten.items() if k in SPEC_FELDER})


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
    if _fremde_quelle(daten) or _ohne_resolved(daten) or _package_json_fremd(quelle):
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
    _entferne(marker, ordner)          # erst der Marker, dann die Kopie: ein Absturz dazwischen hinterlässt keine „fertige“ Kopie
    _entferne(quelle, ordner)          # lokale Dateioperation: wird nicht unterbrochen, zählt aber gegen das Budget
    try:
        # Der Commit wird einmal aufgelöst und genau dieser Hash kopiert und im Marker festgehalten: weder ein stiller
        # Ersatzwert „HEAD“ noch ein Wandern von HEAD zwischen Kopie und rev-parse.
        kopiert = gitkopie.git(repo, "rev-parse", "--verify", f"{a.sha or 'HEAD'}^{{commit}}").stdout.decode().strip()
        meldungen = gitkopie.arbeitskopie(repo, quelle, kopiert)
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
    _schreibe_atomar(marker, {"fertig": True, "sha": kopiert, "repo": os.path.basename(repo)})
    print(quelle)
    return 0


def cmd_bauen(a: argparse.Namespace) -> int:
    _daemon_pruefen()
    ordner = _ordner(a.lauf)
    quelle = os.path.join(ordner, "quelle")
    if not os.path.isdir(quelle):
        raise PocFehler("Arbeitskopie fehlt: erst `poc.py vorbereiten --lauf … --repo …`")
    if not os.path.isfile(os.path.join(ordner, "quelle.fertig")):
        raise PocFehler("Arbeitskopie unvollständig (kein Fertig-Marker, Abbruch beim Kopieren?): "
                        "erneut `poc.py vorbereiten --lauf … --repo …`")
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
    _docker(["rm", "-f", "-v", f"{netz}-app", f"{netz}-db"], KURZ_TIMEOUT, budget=False)  # fehlende Container sind kein Fehler


def _anfrage_container(lauf: str, rolle: str, argumente: list[str], daten: bytes, timeout: int) -> Ergebnis:
    """Request-Container im internen Netz der Rolle; Daten per stdin, bei Timeout wird der Container entfernt."""
    name = f"security-audit-{lauf}-{rolle}-anfrage-{secrets.token_hex(3)}"
    befehl = ["run", "-i", "--rm", "--pull", "never", "--name", name, "--network", _netz(lauf, rolle), *HAERTUNG_APP,
              _image(lauf), "node", "/poc/anfrage.mjs", *argumente]
    r = _docker(befehl, timeout, eingabe=daten, anfang=True)
    if r.rc is None:
        _docker(["rm", "-f", name], KURZ_TIMEOUT)
    return r


def _start_fehler(lauf: str, rolle: str, text: str) -> int:
    try:
        _daemon_pruefen()  # Daemon-Störung ohne Marker im Text: docker-fehlt statt start-fehler
    except DockerFehlt:
        try:
            _rolle_entfernen(lauf, rolle)  # best effort: bereits angelegte Container der Rolle nicht liegen lassen
        except DockerFehlt:
            pass                           # Daemon wirklich weg: `poc.py aufraeumen` holt es später nach
        raise
    logs = _docker(["logs", "--tail", str(TAIL_ZEILEN), f"{_netz(lauf, rolle)}-app"], KURZ_TIMEOUT, budget=False)
    _rolle_entfernen(lauf, rolle)
    if _budget_erschoepft():
        text = f"Zeitbudget von {_BUDGET_SEKUNDEN} s erschöpft (Bash-Limit des Skills: 600 s). {text}"
    return _fehler_ende("start-fehler", "\n".join(t for t in (_tail(text), _tail(logs.text) if logs.ok else "") if t))


def _starte(lauf: str, rolle: str, p: dict) -> int:
    netz = _netz(lauf, rolle)
    app, db = f"{netz}-app", f"{netz}-db"
    _rolle_entfernen(lauf, rolle)
    r = _docker(["network", "create", "--internal", netz], KURZ_TIMEOUT)
    if not r.ok and "already exists" not in r.text:
        return _start_fehler(lauf, rolle, f"Netz {netz} nicht erstellt: {r.text}")
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
    return 0


def cmd_starten(a: argparse.Namespace) -> int:
    _daemon_pruefen()
    _frist_setzen("SECURITY_AUDIT_START_BUDGET", START_BUDGET)
    ordner = _ordner(a.lauf, anlegen=True)
    p = {"start_befehl": a.start_befehl, "port": a.port, "env": a.env or [], "dienst": a.dienst, "seed": a.seed}
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
    laufend = _laufende_laeufe()
    for lauf in sorted(laeufe):
        e = laeufe[lauf]
        print(f"{lauf} ordner={e['ordner']} container={e['container']} netze={e['netze']} images={e['images']} "
              f"{_lauf_angaben(lauf, laufend)}")
    if laeufe:
        print("auflisten: je Lauf aufräumen mit `poc.py aufraeumen --lauf <id>` (nur eigene Läufe mit laeuft=nein; ein "
              "paralleles Audit sieht gleich aus: im Zweifel den User fragen)", file=sys.stderr)
    return 1 if unvollstaendig else 0


def _laufende_laeufe() -> set[str] | None:
    """Lauf-IDs mit mindestens einem laufenden Container; None, wenn Docker nicht lesbar ist."""
    try:
        r = _docker(["ps", "--format", "{{.Names}}"], KURZ_TIMEOUT)
    except DockerFehlt:
        return None
    if not r.ok:
        return None
    treffer = (_LAUF_NAME.fullmatch(z.strip()) for z in r.out.decode("utf-8", "replace").splitlines())
    return {m.group(1) for m in treffer if m}


def _lauf_angaben(lauf: str, laufend: set[str] | None) -> str:
    """`repo=<name> alter_min=<n> laeuft=ja|nein|?` aus Fertig-Marker (Repo), Zustandsordner (letzte Änderung) und `docker ps`.
    Fehlende Angaben heißen `?`, nie geraten."""
    ordner = zustand_ordner(lauf)
    repo = alter = "?"
    try:
        alter = str(max(0, int((time.time() - os.lstat(ordner).st_mtime) // 60)))
    except OSError:
        pass
    try:
        with open(os.path.join(ordner, "quelle.fertig"), encoding="utf-8") as f:
            marker = json.load(f)
        if isinstance(marker, dict) and isinstance(marker.get("repo"), str):
            repo = re.sub(r"\s", "_", _entschaerfen(marker["repo"]))[:60] or "?"   # Ordnername des Kunden: eine Zeile, entschärft
    except (OSError, ValueError):
        pass
    laeuft = "?" if laufend is None else ("ja" if lauf in laufend else "nein")
    return f"repo={repo} alter_min={alter} laeuft={laeuft}"


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


def _typ_env(s: str) -> str:
    name, gleich, _wert = s.partition("=")
    if not gleich or not ENV_NAME_RE.fullmatch(name) or "\x00" in s:
        raise argparse.ArgumentTypeError("--env: K=V erwartet (K: Buchstaben, Ziffern, _)")
    return s


def _typ_text(s: str) -> str:
    if not s.strip() or "\x00" in s:
        raise argparse.ArgumentTypeError("leerer Wert oder NUL-Zeichen")
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
    neu("neustart", cmd_neustart, rolle=True)
    neu("ausfuehren", cmd_ausfuehren, rolle=True)
    s = neu("anfrage", cmd_anfrage, rolle=True)
    s.add_argument("--methode", default="GET", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    s.add_argument("--pfad", required=True, type=_typ_pfad)
    s.add_argument("--header", action="append", type=_typ_header)
    s.add_argument("--daten")
    s.add_argument("--daten-datei")
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
