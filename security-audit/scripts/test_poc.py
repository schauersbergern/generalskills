"""Tests für poc.py (Docker-PoC) mit Fake-`docker` im Shim-PATH; kein echtes Docker nötig.

Aufruf: python3 -m pytest security-audit/scripts/test_poc.py -q
Der Fake protokolliert jeden Aufruf (Argumente, stdin) als JSON-Zeile und liefert Ausgaben aus einer
Konfigurationsdatei (Schlüssel: die ersten zwei Argumente, sonst das erste). Alles liegt in tmp_path.
"""
import http.client
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import gitkopie  # noqa: E402
import poc  # noqa: E402

POC = os.path.join(HIER, "poc.py")
SKILL = os.path.dirname(HIER)
LAUF = "0a1b2c3d"
ANDERER_LAUF = "ffeeddcc"

FAKE_DOCKER = '''#!{python}
import json, os, sys, time
args = sys.argv[1:]
roh = sys.stdin.buffer.read() if "-i" in args[:3] else None
eingabe = roh.decode("utf-8", "replace") if roh is not None else None
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps({{"args": args, "stdin": eingabe, "stdin_hex": roh.hex() if roh is not None else None}}) + "\\n")
try:
    with open(os.environ["FAKE_DOCKER_CONFIG"]) as f:
        cfg = json.load(f)
except OSError:
    cfg = {{}}
antwort = cfg.get(" ".join(args[:2])) or cfg.get(args[0] if args else "") or {{}}
if antwort.get("folge"):
    zaehler = os.environ["FAKE_DOCKER_CONFIG"] + ".n." + "".join(c for c in "_".join(args[:2]) if c.isalnum())
    try:
        n = int(open(zaehler).read())
    except OSError:
        n = 0
    open(zaehler, "w").write(str(n + 1))
    antwort = antwort["folge"][min(n, len(antwort["folge"]) - 1)]
if antwort.get("sleep"):
    time.sleep(antwort["sleep"])
for _ in range(antwort.get("flood", 0)):
    sys.stdout.write(("y" * 1023 + "\\n") * 1024)
sys.stdout.write(antwort.get("stdout", ""))
sys.stdout.flush()
sys.stderr.write(antwort.get("stderr", ""))
sys.exit(antwort.get("rc", 0))
'''


class Umgebung:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.log_datei = tmp_path / "docker.log"
        self.config_datei = tmp_path / "docker.json"
        fake = self.bin / "docker"
        fake.write_text(FAKE_DOCKER.format(python=sys.executable))
        fake.chmod(0o755)
        self.konfig({})

    def konfig(self, cfg):
        self.config_datei.write_text(json.dumps(cfg))

    def env(self, **extra):
        # SECURITY_AUDIT_OHNE=gitleaks: `bauen` verlangt sonst den Schwärzungs-Marker, sobald gitleaks auf dem Host liegt
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "HOME": str(self.home),
               "TMPDIR": str(self.tmp), "FAKE_DOCKER_LOG": str(self.log_datei),
               "FAKE_DOCKER_CONFIG": str(self.config_datei), "GIT_CONFIG_NOSYSTEM": "1",
               "SECURITY_AUDIT_OHNE": "gitleaks"}
        env.update(extra)
        return env

    def poc(self, *args, env=None, timeout=60):
        return subprocess.run([sys.executable, "-I", POC, *args], env=env or self.env(),
                              capture_output=True, text=True, timeout=timeout)

    def aufrufe(self):
        if not self.log_datei.exists():
            return []
        return [json.loads(z) for z in self.log_datei.read_text().splitlines() if z]

    def zustand(self, lauf=LAUF):
        return os.path.join(os.path.realpath(self.tmp), f"security-audit-{lauf}")

    def fake_gitleaks(self):
        """Fake-`gitleaks` im Shim-PATH (nur zum Auffinden; wird von `poc.py` nie aufgerufen)."""
        fake = self.bin / "gitleaks"
        fake.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n")
        fake.chmod(0o755)
        return fake

    def marker(self, lauf=LAUF):
        return os.path.join(self.zustand(lauf), "lieferkette", "geschwaerzt")

    def marker_setzen(self, lauf=LAUF, kopie="aus-fertig-marker"):
        """Schwärzungs-Marker wie `lieferkette.py secrets` ihn setzt: mit der Kennung der Arbeitskopie (`id` aus `quelle.fertig`,
        sonst ein Platzhalter für Läufe ohne Arbeitskopie)."""
        pfad = self.marker(lauf)
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        if kopie == "aus-fertig-marker":
            try:
                with open(os.path.join(self.zustand(lauf), "quelle.fertig"), encoding="utf-8") as f:
                    kopie = json.load(f).get("id", "ohne-id")
            except OSError:
                kopie = "ohne-arbeitskopie"
        with open(pfad, "w") as f:
            json.dump({"geschwaerzt": 0, "sha": "0" * 40, "kopie": kopie}, f)
        return pfad


@pytest.fixture
def umg(tmp_path):
    return Umgebung(tmp_path)


@pytest.fixture
def temp_ordner(tmp_path, monkeypatch):
    """In-Process-Tests: Zustandsordner unter tmp_path."""
    ordner = tmp_path / "inproc-tmp"
    ordner.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(ordner))
    return ordner


# ------------------------------------------------------------------------------------ Hilfen

def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                        "-c", "commit.gpgsign=false", *args], capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"})
    assert r.returncode == 0, r.stderr
    return r.stdout


def lockdatei(extra=None, root=None):
    pakete = {"": {"name": "mini", "version": "1.0.0"}}
    pakete.update(extra or {})
    return json.dumps({"name": "mini", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                       "packages": pakete, **(root or {})})


def paket(url="https://registry.npmjs.org/a/-/a-1.0.0.tgz", **eigen):
    return {"version": "1.0.0", "resolved": url, "integrity": "sha512-xx", **eigen}


def projekt(ordner, dateien):
    ordner.mkdir(parents=True, exist_ok=True)
    for name, inhalt in dateien.items():
        pfad = ordner / name
        pfad.parent.mkdir(parents=True, exist_ok=True)
        pfad.write_text(inhalt)
    return str(ordner)


def repo_mit(tmp_path, dateien, name="kunde"):
    repo = projekt(tmp_path / name, dateien)
    subprocess.run(["git", "init", "-q", repo], check=True)
    git(repo, "add", "-A", "-f")
    git(repo, "commit", "-q", "-m", "c")
    return repo


MINI = {"package.json": json.dumps({"name": "mini", "version": "1.0.0"}), "package-lock.json": lockdatei(),
        "server.js": "// mini\n"}


def vorbereitet(umg, tmp_path, dateien=None, lauf=LAUF):
    repo = repo_mit(tmp_path, dateien or MINI, name=f"kunde-{lauf}")
    r = umg.poc("vorbereiten", "--lauf", lauf, "--repo", repo)
    assert r.returncode == 0, r.stderr
    return r


def gestartet(umg, rolle="p1", lauf=LAUF, port="3000"):
    r = umg.poc("starten", "--lauf", lauf, "--rolle", rolle, "--start-befehl", "node server.js",
                "--port", port)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


# ------------------------------------------------------------------------------------ lockfile_pruefen

def lock_in(tmp_path, inhalt=None, dateien=None):
    ordner = tmp_path / "quelle"
    projekt(ordner, dateien or ({"package-lock.json": inhalt} if inhalt is not None else {}))
    return str(ordner)


def test_lockfile_fehlt(tmp_path):
    assert poc.lockfile_pruefen(lock_in(tmp_path)) == "lockfile-fehlt"


def test_lockfile_nicht_lesbar(tmp_path):
    assert poc.lockfile_pruefen(lock_in(tmp_path, "{kaputt")) == "lockfile-fehlt"


def test_lockfile_nur_pnpm_oder_yarn(tmp_path):
    assert poc.lockfile_pruefen(lock_in(tmp_path, dateien={"pnpm-lock.yaml": "lockfileVersion: 9\n"})) == "nicht-npm"
    assert poc.lockfile_pruefen(lock_in(tmp_path / "y", dateien={"yarn.lock": "# yarn\n"})) == "nicht-npm"


def test_lockfile_npm_neben_pnpm_ist_npm(tmp_path):
    q = lock_in(tmp_path, dateien={"pnpm-lock.yaml": "x", "package-lock.json": lockdatei({"node_modules/a": paket()})})
    assert poc.lockfile_pruefen(q) is None


def test_lockfile_sauber(tmp_path):
    assert poc.lockfile_pruefen(lock_in(tmp_path, lockdatei({"node_modules/a": paket()}))) is None


@pytest.mark.parametrize("url", [
    "https://evil.test/x.tgz",
    "http://registry.npmjs.org/a/-/a-1.0.0.tgz",
    "https://registry.npmjs.org.evil.test/a.tgz",
    "git+https://github.com/a/b.git#abc",
    "git+ssh://git@github.com/a/b.git",
    "github:a/b",
    "file:../x",
    "link:../x",
    "../x",
    "",
    None,
])
def test_lockfile_fremde_quelle(tmp_path, url):
    inhalt = lockdatei({"node_modules/a": paket(url)})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) == "lockfile-fremde-quelle"


def test_lockfile_link_eintrag(tmp_path):
    inhalt = lockdatei({"node_modules/a": {"resolved": "packages/a", "link": True}})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) == "lockfile-fremde-quelle"


def test_lockfile_alte_version_mit_dependencies(tmp_path):
    inhalt = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "github:a/b#abc", "from": "github:a/b"},
        "b": {"version": "1.0.0", "resolved": "https://evil.test/b.tgz"}}})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) == "lockfile-fremde-quelle"


def test_lockfile_abhaengigkeits_spezifikation_mit_git(tmp_path):
    inhalt = lockdatei({"node_modules/a": paket(dependencies={"b": "github:x/y"})})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) == "lockfile-fremde-quelle"


def test_lockfile_funding_urls_sind_kein_verstoss(tmp_path):
    inhalt = lockdatei({"node_modules/a": paket(funding=[{"type": "github", "url": "https://github.com/sponsors/a"}])})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) is None


def test_lockfile_hinweise(tmp_path):
    assert poc.lockfile_hinweise(lock_in(tmp_path, lockdatei({"node_modules/a": paket()}))) == []
    q = lock_in(tmp_path / "n", lockdatei({"node_modules/sharp": paket(hasInstallScript=True)}))
    assert poc.lockfile_hinweise(q) == ["native-module"]
    q = lock_in(tmp_path / "p", lockdatei({"node_modules/@prisma/client": paket()}))
    assert poc.lockfile_hinweise(q) == ["prisma-engines"]
    q = lock_in(tmp_path / "p2", lockdatei({"node_modules/prisma": paket()}))
    assert poc.lockfile_hinweise(q) == ["prisma-engines"]
    q = lock_in(tmp_path / "b", lockdatei({"node_modules/prisma": paket(), "node_modules/x": paket(hasInstallScript=True)}))
    assert poc.lockfile_hinweise(q) == ["native-module", "prisma-engines"]
    # Hinweise brechen die Prüfung nicht ab.
    assert poc.lockfile_pruefen(q) is None


def test_lockfile_hinweise_ohne_lockfile(tmp_path):
    assert poc.lockfile_hinweise(lock_in(tmp_path)) == []
    assert poc.lockfile_hinweise(lock_in(tmp_path / "k", "{kaputt")) == []


# ------------------------------------------------------------------------------------ node_version

def node_in(tmp_path, engines=None, nvmrc=None):
    dateien = {"package.json": json.dumps({"name": "x", **({"engines": {"node": engines}} if engines else {})})}
    if nvmrc is not None:
        dateien[".nvmrc"] = nvmrc
    return projekt(tmp_path / "n", dateien)


@pytest.mark.parametrize("engines,erwartet", [
    (">=22", "24"), ("^20.11", "20"), (">=18 <21", "20"), ("20.x || 22.x", "22"), ("*", "24"),
    (">= 18", "24"), ("<22", "20"), ("22", "22"), ("=22", "22"), ("^22.3.0", "22"), ("~20", "20"),
    (">20", "24"), ("<=22", "22"), ("20 || >=24", "24"), ("^0.8", "22"), (">=26", "22"), ("???", "22"),
    # T3-M2: Bereiche, die nur einzelne Minor-Versionen eines Majors treffen
    ("~20.11", "20"), ("=20.11.0", "20"), ("<=20.11.0", "20"), (">=20.11.0 <20.12.0", "20"), ("18 - 20", "20"),
    ("20.11.x", "20"), (">=20.11.1 <=20.11.5", "20"), ("=20.11.5", "20"), (">=20.11.1 <20.12.0", "20"),
    (">20.11.98 <20.12.0", "20"), ("=20.11.99", "20"), ("20.11.1 - 20.11.5", "20"), ("<20.11.5 >=20.11.4", "20"),
    (">=20.11.6 <=20.11.5", "22"), ("~22.3 || ~20.11", "22"), ("18 - 22", "22"), ("16 - 18", "22"), ("20.11.0 - 20.11.9", "20"),
])
def test_node_version_engines(tmp_path, engines, erwartet):
    assert poc.node_version(node_in(tmp_path, engines=engines), None) == erwartet


@pytest.mark.parametrize("nvmrc,erwartet", [
    ("v22.3.0\n", "22"), ("22", "22"), ("v20", "20"), ("24.1", "24"), ("lts/*", "22"), ("node", "22"),
    ("lts/iron", "22"), ("v18.0.0", "22"), ("quatsch", "22"), ("", "22"),
])
def test_node_version_nvmrc(tmp_path, nvmrc, erwartet):
    assert poc.node_version(node_in(tmp_path, nvmrc=nvmrc), None) == erwartet


def test_node_version_riesige_zahlen(tmp_path):
    """T3-M3: Zahlen über dem int-Stringlimit lösen kein ValueError aus, es gilt der Fallback."""
    gross = "9" * 5000
    assert poc.node_version(node_in(tmp_path, engines=f"^{gross}"), None) == "22"
    assert poc.node_version(node_in(tmp_path / "a", engines=f">={gross}.1.2 || ^20"), None) == "22"  # zu lang
    assert poc._vergleich_lesen(f"^{gross}") is None and poc._vergleich_lesen(f"=20.{gross}") is None
    assert poc.node_version(node_in(tmp_path / "b", nvmrc=gross), None) == "22"


def test_node_version_dos_grenzen(tmp_path):
    """T3-R2: lange Ranges und große package.json kosten keine Rechenzeit."""
    lang = ">=20.11.1 <=20.11.5 || " * 6200  # ~140 KB
    assert len(lang) > 140_000
    q = node_in(tmp_path, engines=lang, nvmrc="v20")
    t0 = time.monotonic()
    assert poc.node_version(q, None) == "20"  # nur wegen .nvmrc; die Range gilt als unlesbar
    assert time.monotonic() - t0 < 1
    q = node_in(tmp_path / "v", engines=">=22", nvmrc="v20")
    assert poc.node_version(q, None) == "24"
    gross = projekt(tmp_path / "g", {"package.json": json.dumps({"engines": {"node": ">=22"}, "x": "y" * (2 * 1024 * 1024)}),
                                     ".nvmrc": "v20"})
    t0 = time.monotonic()
    assert poc.node_version(gross, None) == "20"  # package.json über 1 MiB wird nicht gelesen
    assert time.monotonic() - t0 < 1
    # Viele Vergleiche in 1024 Zeichen: begrenzt und schnell.
    viele = projekt(tmp_path / "m", {"package.json": json.dumps({"engines": {"node": " || ".join(f"=20.{i}.{i}" for i in range(80))}})})
    t0 = time.monotonic()
    poc.node_version(viele, None)
    assert time.monotonic() - t0 < 1


def test_node_hinweis_range_zu_lang(tmp_path):
    q = node_in(tmp_path, engines=">=20 " * 300)
    assert poc.node_hinweise(q, None) == ["node-range-zu-lang"]
    assert poc.node_hinweise(q, "22") == []
    assert poc.node_hinweise(node_in(tmp_path / "k", engines=">=22"), None) == []
    assert poc.node_hinweise(str(tmp_path / "gibt-es-nicht"), None) == []


def test_node_version_standard_und_vorgabe(tmp_path):
    assert poc.node_version(node_in(tmp_path), None) == "22"
    assert poc.node_version(str(tmp_path / "gibt-es-nicht"), None) == "22"
    assert poc.node_version(node_in(tmp_path / "v", engines=">=22"), "20") == "20"
    assert poc.node_version(node_in(tmp_path / "w", nvmrc="v22.3.0"), "24") == "24"


def test_node_version_engines_vor_nvmrc(tmp_path):
    assert poc.node_version(node_in(tmp_path, engines="^20.11", nvmrc="22"), None) == "20"


def test_node_version_kaputte_package_json(tmp_path):
    q = projekt(tmp_path / "k", {"package.json": "{kaputt", ".nvmrc": "20"})
    assert poc.node_version(q, None) == "20"


# ------------------------------------------------------------------------------------ zustand_ordner

def test_zustand_ordner(temp_ordner):
    erwartet = os.path.join(os.path.realpath(temp_ordner), f"security-audit-{LAUF}")
    assert poc.zustand_ordner(LAUF) == erwartet


@pytest.mark.parametrize("lauf", ["../..", "", "ABCDEF12", "0a1b2c3", "0a1b2c3d\n", "0a1b2c3d/..", "0a1b2c3g"])
def test_zustand_ordner_ungueltig(temp_ordner, lauf):
    with pytest.raises(ValueError):
        poc.zustand_ordner(lauf)


# ------------------------------------------------------------------------------------ Argumente

def test_neu(umg):
    r = umg.poc("neu")
    assert r.returncode == 0
    assert re.fullmatch(r"[0-9a-f]{8}\n", r.stdout)
    assert umg.aufrufe() == []


@pytest.mark.parametrize("args", [
    ["pruefen", "--lauf", "../.."],
    ["aufraeumen", "--lauf", "../.."],
    ["aufraeumen", "--lauf", "0A1B2C3D"],
    ["aufraeumen", "--lauf", LAUF + "\n"],
    ["bauen", "--lauf", "x"],
    ["starten", "--lauf", LAUF, "--rolle", "../x", "--start-befehl", "x", "--port", "3000"],
    ["starten", "--lauf", LAUF, "--rolle", "p3", "--start-befehl", "x", "--port", "3000"],
    ["anfrage", "--lauf", LAUF, "--rolle", "p1\n", "--pfad", "/"],
    ["anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/", "--methode", "TRACE"],
    ["neustart", "--lauf", LAUF, "--rolle", "../x"],
    ["bauen", "--lauf", LAUF, "--node", "18"],
    ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "0"],
    ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "70000"],
    ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "3000", "--env", "OHNE_GLEICH"],
    ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "3000", "--env", "a b=1"],
    ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "3000", "--dienst", "mysql"],
    ["ausfuehren", "--lauf", LAUF, "--rolle", "p1"],
    ["gibtesnicht"],
    [],
])
def test_lauf_ungueltig(umg, args):
    r = umg.poc(*args)
    assert r.returncode == 2, r.stdout + r.stderr
    assert umg.aufrufe() == []


def test_ungueltiger_lauf_legt_nichts_an(umg):
    umg.poc("aufraeumen", "--lauf", "../..")
    assert os.listdir(umg.tmp) == []


# ------------------------------------------------------------------------------------ pruefen / ohne Docker

def test_pruefen(umg):
    umg.konfig({"version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon at unix:///x.sock"}})
    r = umg.poc("pruefen")
    assert r.returncode == 3
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"
    umg.konfig({"version": {"rc": 0, "stdout": "29.1.3\n"}})
    r = umg.poc("pruefen")
    assert r.returncode == 0, r.stderr
    assert umg.aufrufe()[-1]["args"][0] == "version"


def test_pruefen_timeout(umg):
    umg.konfig({"version": {"sleep": 30}})
    r = umg.poc("pruefen", env=umg.env(SECURITY_AUDIT_DOCKER_TIMEOUT="1"), timeout=40)
    assert r.returncode == 3


def test_ohne_docker_binary(umg, tmp_path):
    leer = tmp_path / "leer"
    leer.mkdir()
    env = umg.env(PATH=str(leer))
    assert umg.poc("pruefen", env=env).returncode == 3
    assert umg.poc("bauen", "--lauf", LAUF, env=env).returncode == 3
    assert umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1",
                   env=env).returncode == 3
    r = umg.poc("aufraeumen", "--lauf", LAUF, env=env)
    assert r.returncode == 1                      # Härtung B2: nicht geprüft heißt unvollständig
    assert "Docker" in r.stderr


@pytest.mark.parametrize("befehl,ohne", [
    (["pruefen"], "docker"),
    (["bauen", "--lauf", LAUF], "gitleaks,docker"),
    (["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1"], "docker")])
def test_daemon_pruefen_ohne_docker_exit3(umg, befehl, ohne):
    """`SECURITY_AUDIT_OHNE=docker` wirkt zentral in `_daemon_pruefen`, obwohl ein (Fake-)docker im PATH liegt."""
    umg.konfig({"version": {"rc": 0, "stdout": "29.1.3\n"}})
    r = umg.poc(*befehl, env=umg.env(SECURITY_AUDIT_OHNE=ohne))
    assert r.returncode == 3, r.stdout + r.stderr
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"
    assert umg.aufrufe() == []                    # kein einziger docker-Aufruf


def test_ohne_docker_trimmt_gross_klein_und_liste(umg):
    umg.konfig({"version": {"rc": 0, "stdout": "29.1.3\n"}})
    r = umg.poc("pruefen", env=umg.env(SECURITY_AUDIT_OHNE=" Gitleaks , DOCKER ,osv-scanner"))
    assert r.returncode == 3 and r.stdout.splitlines()[0] == "kategorie: docker-fehlt"
    r = umg.poc("pruefen", env=umg.env(SECURITY_AUDIT_OHNE="dockerx,gitleaks"))
    assert r.returncode == 0, r.stderr


def test_werkzeug_fehlt(umg, tmp_path, monkeypatch):
    leer = tmp_path / "leer-bin"
    leer.mkdir()
    fake = umg.bin / "gitleaks"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{umg.bin}{os.pathsep}{leer}")
    monkeypatch.delenv("SECURITY_AUDIT_OHNE", raising=False)
    assert poc.werkzeug_fehlt("gitleaks") is False
    assert poc.werkzeug_fehlt("osv-scanner") is True                  # nicht im PATH
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "osv-scanner")
    assert poc.werkzeug_fehlt("gitleaks") is False
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", " OSV-Scanner , Gitleaks ")
    assert poc.werkzeug_fehlt("gitleaks") is True and poc.werkzeug_fehlt("GitLeaks") is True
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "gitleaks-x,,")
    assert poc.werkzeug_fehlt("gitleaks") is False
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    assert poc.werkzeug_fehlt("gitleaks") is False


def test_schwaerz_marker_pfad(temp_ordner):
    assert poc.schwaerz_marker(LAUF) == os.path.join(poc.zustand_ordner(LAUF), "lieferkette", "geschwaerzt")
    with pytest.raises(ValueError):
        poc.schwaerz_marker("../x")


def test_ohne_docker_binary_stdout_kategorie(umg, tmp_path):
    leer = tmp_path / "leer"
    leer.mkdir()
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(PATH=str(leer)))
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"


# ------------------------------------------------------------------------------------ vorbereiten

def test_vorbereiten_ohne_env(umg, tmp_path):
    dateien = dict(MINI, **{".env.production": "SECRET=geheim\n", ".env": "X=1\n", ".env.example": "X=\n",
                            "src/app.js": "x\n"})
    repo = repo_mit(tmp_path, dateien)
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 0, r.stderr
    quelle = r.stdout.strip()
    assert quelle == os.path.join(umg.zustand(), "quelle")
    assert not os.path.exists(os.path.join(quelle, ".env.production"))
    assert not os.path.exists(os.path.join(quelle, ".env"))
    assert os.path.exists(os.path.join(quelle, ".env.example"))
    assert os.path.exists(os.path.join(quelle, "src", "app.js"))
    assert ".env.production" in r.stderr
    assert umg.aufrufe() == []  # vorbereiten braucht kein Docker


def test_vorbereiten_zweimal_ersetzt_kopie(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI)
    quelle = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).stdout.strip()
    with open(os.path.join(quelle, "fremd.txt"), "w") as f:
        f.write("alt")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 0
    assert not os.path.exists(os.path.join(quelle, "fremd.txt"))


def test_vorbereiten_loescht_marker(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI)
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    marker = umg.marker_setzen()
    daneben = os.path.join(os.path.dirname(marker), "andere-datei")
    with open(daneben, "w") as f:
        f.write("bleibt")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 0, r.stderr
    assert not os.path.lexists(marker)                         # nach dem Neuaufbau muss `secrets` erneut laufen
    assert open(daneben).read() == "bleibt"                    # nur der Marker, nichts sonst unter lieferkette/


def test_vorbereiten_ohne_marker_und_ohne_lieferkette_ordner(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI)
    assert not os.path.exists(os.path.join(umg.zustand(), "lieferkette"))
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    assert not os.path.exists(os.path.join(umg.zustand(), "lieferkette"))       # legt nichts an


def test_vorbereiten_marker_symlink_wird_nur_als_link_entfernt(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI)
    ziel = tmp_path / "ziel-datei"
    ziel.write_text("fremd")
    os.makedirs(os.path.join(umg.zustand(), "lieferkette"))
    os.symlink(ziel, umg.marker())
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    assert not os.path.lexists(umg.marker()) and ziel.read_text() == "fremd"


def test_vorbereiten_repo_fehlt(umg, tmp_path):
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", str(tmp_path / "gibt-es-nicht"))
    assert r.returncode == 2


def test_vorbereiten_kein_git_repo(umg, tmp_path):
    kein = tmp_path / "kein-repo"
    kein.mkdir()
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", str(kein))
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: git-fehler"
    assert "Traceback" not in r.stderr


def test_vorbereiten_unvollstaendig(temp_ordner, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", lambda repo, ziel, rev="HEAD": [
        "Namenskollision: a", "Arbeitskopie unvollständig: git cat-file abgebrochen bei x (boom)"])
    repo = tmp_path / "r"
    repo.mkdir()
    assert poc.main(["vorbereiten", "--lauf", LAUF, "--repo", str(repo)]) == 4
    aus = capsys.readouterr()
    assert aus.out.splitlines()[0] == "kategorie: arbeitskopie-unvollstaendig"
    assert "Arbeitskopie unvollständig" in aus.err


def test_vorbereiten_git_fehler(temp_ordner, tmp_path, monkeypatch, capsys):
    def kaputt(repo, ziel, rev="HEAD"):
        raise gitkopie.GitFehler("git ls-tree fehlgeschlagen (Exit 128): kein HEAD")
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", kaputt)
    repo = tmp_path / "r"
    repo.mkdir()
    assert poc.main(["vorbereiten", "--lauf", LAUF, "--repo", str(repo)]) == 4
    aus = capsys.readouterr()
    assert aus.out.splitlines()[0] == "kategorie: git-fehler"
    assert "kein HEAD" in aus.err


def test_vorbereiten_meldungen_nur_auf_stderr(temp_ordner, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", lambda repo, ziel, rev="HEAD": ["Symlink übersprungen: x"])
    repo = tmp_path / "r"
    repo.mkdir()
    assert poc.main(["vorbereiten", "--lauf", LAUF, "--repo", str(repo)]) == 0
    aus = capsys.readouterr()
    assert aus.out.strip() == os.path.join(poc.zustand_ordner(LAUF), "quelle")
    assert "Symlink übersprungen" in aus.err


# ------------------------------------------------------------------------------------ bauen

def build_aufruf(umg):
    aufrufe = [a["args"] for a in umg.aufrufe() if a["args"][0] == "build"]
    assert len(aufrufe) == 1, aufrufe
    return aufrufe[0]


def test_bauen_argumente(umg, tmp_path):
    vorbereitet(umg, tmp_path, dict(MINI, **{"package.json": json.dumps(
        {"name": "x", "version": "1.0.0", "engines": {"node": "^20.11"}})}))
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 0, r.stdout + r.stderr
    args = build_aufruf(umg)
    assert args[args.index("--build-arg") + 1] == "NODE=20"
    assert args[args.index("-f") + 1] == os.path.join(SKILL, "docker", "Dockerfile.poc")
    assert args[args.index("-t") + 1] == f"security-audit-{LAUF}-app"
    assert args[args.index("--build-context") + 1] == f"poc={os.path.join(SKILL, 'docker')}"
    assert args[-1] == os.path.join(umg.zustand(), "quelle")
    assert "BUILD_BEFEHL" not in " ".join(args)
    assert f"image: security-audit-{LAUF}-app" in r.stdout


def test_bauen_optionen(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    r = umg.poc("bauen", "--lauf", LAUF, "--node", "24", "--build-befehl", "npm run x && echo $HOME")
    assert r.returncode == 0, r.stderr
    args = build_aufruf(umg)
    assert "NODE=24" in args
    assert "BUILD_BEFEHL=npm run x && echo $HOME" in args  # ein Argument, nie durch eine Shell


def test_bauen_setzt_buildkit(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    fake = umg.bin / "docker"
    text = fake.read_text().replace(
        'antwort = cfg.get', 'if args[:1] == ["build"]:\n    sys.stderr.write("BK=" + os.environ.get("DOCKER_BUILDKIT", "-") + "\\n")\n'
        '    sys.exit(7)\nantwort = cfg.get', 1)
    fake.write_text(text)
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4
    assert "BK=1" in r.stdout


# ---- Schwärzungs-Marker (TF2)

def test_bauen_ohne_marker_mit_gitleaks_verweigert(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4, r.stdout + r.stderr
    assert r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


def test_bauen_mit_marker_baut(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    umg.marker_setzen()
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 0, r.stdout + r.stderr
    build_aufruf(umg)


def test_bauen_ohne_gitleaks_im_path_baut(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    # PATH nur mit dem Fake-docker: kein gitleaks, also keine Marker-Pflicht
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(PATH=str(umg.bin), SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 0, r.stdout + r.stderr
    build_aufruf(umg)


def test_bauen_ohne_marker_bei_ohne_gitleaks_baut(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE="osv-scanner, GITLEAKS"))
    assert r.returncode == 0, r.stdout + r.stderr
    build_aufruf(umg)


def test_bauen_marker_pruefung_nach_daemon_pruefung(umg, tmp_path):
    """Docker nicht erreichbar und Marker fehlt: zuerst docker-fehlt (Exit 3), nicht nicht-geschwaerzt."""
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    umg.konfig({"version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon at unix:///x.sock"}})
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 3
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"


def test_bauen_marker_ist_pro_lauf(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    umg.marker_setzen(ANDERER_LAUF)                    # Marker eines anderen Laufs zählt nicht
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"


def test_bauen_ohne_arbeitskopie_meldet_arbeitskopie(umg):
    """Kein Marker und keine Arbeitskopie: Exit 2 „Arbeitskopie fehlt“, nicht nicht-geschwaerzt."""
    umg.fake_gitleaks()
    os.makedirs(umg.zustand())
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "Arbeitskopie fehlt" in r.stderr and "nicht-geschwaerzt" not in r.stdout
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


def test_bauen_marker_symlink_zaehlt_nicht(umg, tmp_path):
    """Ein Symlink (auch auf eine existierende Datei) ist kein Marker: nur eine reguläre Datei zählt."""
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    ziel = tmp_path / "irgendeine-datei"
    ziel.write_text("x")
    pfad = umg.marker()
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    os.symlink(ziel, pfad)
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


def test_bauen_ohne_quelle(umg):
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 2
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


@pytest.mark.parametrize("dateien,kategorie", [
    ({"package.json": "{}"}, "lockfile-fehlt"),
    ({"package.json": "{}", "pnpm-lock.yaml": "x"}, "nicht-npm"),
    ({"package.json": "{}", "package-lock.json": lockdatei({"node_modules/a": paket("https://evil.test/a.tgz")})},
     "lockfile-fremde-quelle"),
])
def test_bauen_lockfile_abbruch(umg, tmp_path, dateien, kategorie):
    vorbereitet(umg, tmp_path, dateien)
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == f"kategorie: {kategorie}"
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


def test_bauen_hinweise_brechen_nicht_ab(umg, tmp_path):
    lock = lockdatei({"node_modules/sharp": paket(hasInstallScript=True), "node_modules/prisma": paket()})
    vorbereitet(umg, tmp_path, dict(MINI, **{"package-lock.json": lock}))
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 0
    zeilen = r.stdout.splitlines()
    assert "hinweis: native-module" in zeilen and "hinweis: prisma-engines" in zeilen
    assert len(build_aufruf(umg)) > 0


def test_bauen_fehler_kategorie_und_tail(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"build": {"rc": 1, "stderr": "\n".join(f"zeile {i}" for i in range(100))}})
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4
    zeilen = r.stdout.splitlines()
    assert zeilen[0] == "kategorie: build-fehler"
    assert zeilen[-1] == "zeile 99"
    assert "zeile 59" not in r.stdout and "zeile 60" in r.stdout
    assert len(zeilen) <= 41


def test_bauen_timeout(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"build": {"sleep": 30}})
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_BAU_TIMEOUT="1"), timeout=40)
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: build-timeout"


# ------------------------------------------------------------------------------------ starten

def laeufe(umg):
    return [a["args"] for a in umg.aufrufe() if a["args"][0] == "run"]


def wert(args, flag):
    return [args[i + 1] for i, a in enumerate(args) if a == flag]


def test_rollen_getrennte_namen(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg, "p1")
    gestartet(umg, "p2", port="3001")
    erstellt = [a["args"] for a in umg.aufrufe() if a["args"][:2] == ["network", "create"]]
    assert [a[-1] for a in erstellt] == [f"security-audit-{LAUF}-p1", f"security-audit-{LAUF}-p2"]
    assert all("--internal" in a for a in erstellt)
    apps = [a for a in laeufe(umg) if "-d" in a]
    assert [wert(a, "--name")[0] for a in apps] == [f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p2-app"]
    for a, rolle in zip(apps, ("p1", "p2")):
        assert wert(a, "--network") == [f"security-audit-{LAUF}-{rolle}"]
        assert wert(a, "--network-alias") == ["app"]
        assert wert(a, "--cap-drop") == ["ALL"]
        assert wert(a, "--security-opt") == ["no-new-privileges"]
        assert wert(a, "--memory") == ["1g"]
        assert wert(a, "--pids-limit") == ["256"]
        assert "-p" not in a and "--publish" not in a and "-P" not in a and "-v" not in a and "--volume" not in a
        assert a[a.index(f"security-audit-{LAUF}-app"):] == [f"security-audit-{LAUF}-app", "sh", "-c", "node server.js"]
    env = wert(apps[1], "-e")
    assert "PORT=3001" in env and "HOST=0.0.0.0" in env


def test_starten_env_dienst_seed(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node server.js", "--port", "3000",
                "--env", "DATABASE_URL=postgres://poc:poc@db:5432/poc?a=b", "--env", "X=", "--dienst", "postgres",
                "--seed", "node seed.js")
    assert r.returncode == 0, r.stdout + r.stderr
    db = [a for a in laeufe(umg) if wert(a, "--name") == [f"security-audit-{LAUF}-p1-db"]][0]
    assert db[-1] == "postgres:16-alpine"
    assert wert(db, "--network-alias") == ["db"]
    assert wert(db, "--security-opt") == ["no-new-privileges"]
    assert wert(db, "--memory") == ["512m"] and wert(db, "--pids-limit") == ["256"]
    assert "--cap-drop" not in db
    app = [a for a in laeufe(umg) if wert(a, "--name") == [f"security-audit-{LAUF}-p1-app"]][0]
    assert "DATABASE_URL=postgres://poc:poc@db:5432/poc?a=b" in wert(app, "-e") and "X=" in wert(app, "-e")
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert ["exec", f"security-audit-{LAUF}-p1-app", "sh", "-c", "node seed.js"] in aufrufe
    assert any(a[:2] == ["exec", f"security-audit-{LAUF}-p1-db"] and "pg_isready" in a for a in aufrufe)
    assert "postgres://poc:poc@db:5432/poc" in r.stdout


def test_starten_wartet_per_anfrage_container(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg, "p1", port="4000")
    wartend = [a for a in laeufe(umg) if "/poc/anfrage.mjs" in a]
    assert len(wartend) == 1
    a = wartend[0]
    assert wert(a, "--url") == ["http://app:4000/"] and wert(a, "--warten") == ["60"]
    assert wert(a, "--network") == [f"security-audit-{LAUF}-p1"]
    assert re.fullmatch(rf"security-audit-{LAUF}-p1-anfrage-[0-9a-f]{{6}}", wert(a, "--name")[0])


def test_starten_zustandsdatei(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.poc("starten", "--lauf", LAUF, "--rolle", "p2", "--start-befehl", "node s.js", "--port", "3005",
            "--env", "A=1")
    with open(os.path.join(umg.zustand(), "rolle-p2.json")) as f:
        z = json.load(f)
    assert z["port"] == 3005 and z["start_befehl"] == "node s.js" and z["env"] == ["A=1"]
    assert [n for n in os.listdir(umg.zustand()) if n.startswith(".")] == []  # keine Temp-Reste


def test_starten_fehler(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"logs": {"stdout": "Error: Cannot find module 'x'\n"},
                "run": {"rc": 125, "stderr": "docker: Error response from daemon: boom\n"}})
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node x.js", "--port", "3000")
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "boom" in r.stdout
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db", f"security-audit-{LAUF}-p1-llm"] in aufrufe  # eigene Reste


def test_starten_app_nicht_erreichbar(umg, tmp_path):
    vorbereitet(umg, tmp_path)

    # Fake: Wegwerf-Container mit --warten scheitert; App-Logs liefern die Ursache.
    fake = umg.bin / "docker"
    fake.write_text(fake.read_text().replace(
        'antwort = cfg.get', 'if "--warten" in args:\n    sys.stderr.write("fehler: app nicht erreichbar\\n")\n    sys.exit(1)\n'
        'antwort = cfg.get', 1))
    umg.konfig({"logs": {"stdout": "Error: EADDRINUSE\\n"}})
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node x.js", "--port", "3000")
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "EADDRINUSE" in r.stdout


def test_starten_vorhandene_container_werden_ersetzt(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    aufrufe = [a["args"] for a in umg.aufrufe()]
    erster_run = next(i for i, a in enumerate(aufrufe) if a[0] == "run")
    assert ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db", f"security-audit-{LAUF}-p1-llm"] in aufrufe[:erster_run]


def test_starten_netz_existiert_schon(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"network create": {"rc": 1, "stderr": "Error response from daemon: network with name x already exists"}})
    assert umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1").returncode == 0


# ------------------------------------------------------------------------------------ TF3: Modell-Mock und Env-Regeln

MOCK_NAMEN = ("OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY")
LLM = f"security-audit-{LAUF}-p1-llm"
APP = f"security-audit-{LAUF}-p1-app"


def starten(umg, *extra, rolle="p1", env=None):
    return umg.poc("starten", "--lauf", LAUF, "--rolle", rolle, "--start-befehl", "node server.js", "--port", "3000",
                   *extra, env=env)


def run_mit_name(umg, name):
    return [a for a in laeufe(umg) if wert(a, "--name") == [name]]


@pytest.mark.parametrize("name", MOCK_NAMEN)
def test_env_regeln_reservierte_namen_nur_mit_mock(umg, tmp_path, name):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai,anthropic", "--env", f"{name}=http://llm:4010")
    assert r.returncode == 2, r.stdout + r.stderr
    assert name in r.stderr
    assert not any(a["args"][0] in ("run", "network") for a in umg.aufrufe())       # vor jedem Docker-Aufruf abgelehnt
    umg.log_datei.unlink(missing_ok=True)
    r = starten(umg, "--env", f"{name}=http://llm:4010")                              # ohne Mock bleibt der Name frei
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"{name}=http://llm:4010" in wert(run_mit_name(umg, APP)[0], "-e")


@pytest.mark.parametrize("gewaehlt", ["openai", "anthropic"])
@pytest.mark.parametrize("name", MOCK_NAMEN)
def test_env_regeln_reserviert_auch_fuer_nicht_gewaehlte_api(umg, tmp_path, gewaehlt, name):
    """K3: Mit --modell-mock sind alle vier Namen reserviert, auch die der nicht gewählten API."""
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", gewaehlt, "--env", f"{name}=x")
    assert r.returncode == 2, r.stdout + r.stderr
    assert not any(a["args"][0] == "run" for a in umg.aufrufe())


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai"]])
@pytest.mark.parametrize("wert_", ["http://poc-fremd.invalid/x", "https://192.0.2.1:9/", "HTTP://POC-FREMD.INVALID/",
                                   "redis://:pw@cache.invalid:6379"])
def test_env_regeln_fremder_host_exit2(umg, tmp_path, mock, wert_):
    vorbereitet(umg, tmp_path)
    r = starten(umg, *mock, "--env", f"EXTERN_URL={wert_}")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "--env EXTERN_URL: nicht erlaubter Host" in r.stderr
    assert not any(a["args"][0] in ("run", "network") for a in umg.aufrufe())
    assert umg.aufrufe() == []                                                          # M4a: auch kein `version` (Prüfung vor dem Daemon)


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai,anthropic"]])
def test_env_regeln_db_und_localhost_erlaubt(umg, tmp_path, mock):
    vorbereitet(umg, tmp_path)
    r = starten(umg, *mock, "--env", "DATABASE_URL=postgres://poc:poc@db:5432/poc", "--env", "SELBST=http://localhost:3000",
                "--env", "MOCK=http://llm:4010/v1", "--env", "OHNE_URL=abc")
    assert r.returncode == 0, r.stdout + r.stderr
    env = wert(run_mit_name(umg, APP)[0], "-e")
    assert "DATABASE_URL=postgres://poc:poc@db:5432/poc" in env and "SELBST=http://localhost:3000" in env


def test_env_regeln_meldung_ohne_wert(umg, tmp_path):
    """W2-neu: Die Meldung nennt Namen und Host, nie den Wert (auch nicht Pfad, Query oder Zugangsdaten)."""
    vorbereitet(umg, tmp_path)
    geheim = "poc-dummy-geheim-4711"
    r = starten(umg, "--env", f"EXTERN_URL=https://nutzer:{geheim}@poc-fremd.invalid/pfad-{geheim}?k={geheim}")
    assert r.returncode == 2
    assert r.stderr.strip().endswith("--env EXTERN_URL: nicht erlaubter Host poc-fremd.invalid"), r.stderr
    assert geheim not in r.stdout + r.stderr
    r = starten(umg, "--modell-mock", "openai", "--env", f"OPENAI_API_KEY={geheim}")
    assert r.returncode == 2 and geheim not in r.stdout + r.stderr


def starten_mit_befehl(umg, befehl, *extra):
    return umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", befehl, "--port", "3000", *extra)


@pytest.mark.parametrize("befehl,name", [
    ("OPENAI_BASE_URL=http://llm:4010/v1 node server.js", "OPENAI_BASE_URL"),
    ("env ANTHROPIC_API_KEY=x node server.js", "ANTHROPIC_API_KEY"),
    ("export OPENAI_API_KEY=x && node server.js", "OPENAI_API_KEY"),
    ("export ANTHROPIC_BASE_URL=http://llm:4010; node server.js", "ANTHROPIC_BASE_URL"),
    ("PORT=1 openai_base_url=http://llm:4010 node server.js", "openai_base_url"),
    ("OPENAI_API_BASE=http://llm:4010 node server.js", "OPENAI_API_BASE"),
    ("env -i AZURE_OPENAI_ENDPOINT=http://llm:4010 node server.js", "AZURE_OPENAI_ENDPOINT"),
])
def test_start_befehl_reservierte_namen_mit_mock_exit2(umg, tmp_path, befehl, name):
    """M-2: Mit --modell-mock darf der Start-Befehl keinen reservierten Namen setzen (sonst biegt er die Mock-Variablen um).
    Die Meldung nennt nur den Namen, nie den Befehl; ohne Mock bleibt der Befehl erlaubt."""
    vorbereitet(umg, tmp_path)
    r = starten_mit_befehl(umg, befehl, "--modell-mock", "openai")
    assert r.returncode == 2, r.stdout + r.stderr
    assert name in r.stderr and "node server.js" not in r.stderr and "llm:4010" not in r.stderr, r.stderr
    assert umg.aufrufe() == []                                                          # vor jedem Docker-Aufruf abgelehnt
    r = starten_mit_befehl(umg, befehl)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai"]])
def test_start_befehl_fremder_host_exit2(umg, tmp_path, mock):
    """M-2: Der Start-Befehl läuft durch die Netzregel; die Meldung nennt nur den Host, nie den Befehl."""
    vorbereitet(umg, tmp_path)
    r = starten_mit_befehl(umg, "EXTERN=https://poc-fremd.invalid/v1 node geheim-server.js", *mock)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "--start-befehl: nicht erlaubter Host poc-fremd.invalid" in r.stderr
    assert "geheim-server" not in r.stdout + r.stderr and "/v1" not in r.stderr
    assert umg.aufrufe() == []


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai"]])
@pytest.mark.parametrize("befehl", ["node src/server.js", "npm start", "PORT=3000 node server.js",
                                    "node server.js --db postgres://poc:poc@db:5432/poc --llm http://llm:4010/v1",
                                    # Re-Review 4: Wortgrenze vor dem reservierten Namen, Shell-Optionen sind keine Hosts
                                    "NEXT_PUBLIC_OPENAI_BASE_URL=http://llm:4010 npm start", "sh -x ./start.sh",
                                    "bash -x start.sh", "node s.js --label host: foo"])
def test_start_befehl_legitim_erlaubt(umg, tmp_path, mock, befehl):
    vorbereitet(umg, tmp_path)
    r = starten_mit_befehl(umg, befehl, *mock)
    assert r.returncode == 0, r.stdout + r.stderr
    assert befehl in run_mit_name(umg, APP)[0]


# Härtung Mi-3: Syntaxformen, mit denen ein reservierter Name sonst am Regex vorbeikäme (Anhängen, Quote-Zerlegung, Zeilenfortsetzung,
# Aufheben statt Setzen) und die weiteren Namen, mit denen ein SDK am Mock vorbei zu einem anderen Endpunkt oder Konto liefe.
@pytest.mark.parametrize("befehl,name", [
    ("OPENAI_BASE_URL+=@poc-fremd.invalid node server.js", "OPENAI_BASE_URL"),
    ("export ANTHROPIC_BASE_URL+=x; node server.js", "ANTHROPIC_BASE_URL"),
    ('env OPENAI_BASE_UR""L=x node server.js', "OPENAI_BASE_URL"),
    ("env OPENAI_BASE_UR''L=x node server.js", "OPENAI_BASE_URL"),
    ("env 'OPENAI_API_KEY'=x node server.js", "OPENAI_API_KEY"),
    ("export OPENAI_BASE_URL\\=x && node server.js", "OPENAI_BASE_URL"),
    ("env OPENAI_BASE_\\\nURL=x node server.js", "OPENAI_BASE_URL"),
    ("unset OPENAI_BASE_URL && node server.js", "OPENAI_BASE_URL"),
    ("unset FOO OPENAI_API_KEY; node server.js", "OPENAI_API_KEY"),
    ('unset "ANTHROPIC_API_KEY"; node server.js', "ANTHROPIC_API_KEY"),
    ("env -u OPENAI_BASE_URL node server.js", "OPENAI_BASE_URL"),
    ("env -uOPENAI_BASE_URL node server.js", "OPENAI_BASE_URL"),
    ("env --unset=ANTHROPIC_BASE_URL node server.js", "ANTHROPIC_BASE_URL"),
    ("env --unset ANTHROPIC_API_KEY node server.js", "ANTHROPIC_API_KEY"),
    ("OPENAI_API_HOST=http://llm:4010 node server.js", "OPENAI_API_HOST"),
    ("ANTHROPIC_AUTH_TOKEN=x node server.js", "ANTHROPIC_AUTH_TOKEN"),
    ("OPENAI_PROJECT_ID=proj-x node server.js", "OPENAI_PROJECT_ID"),
])
def test_start_befehl_syntaxformen_reservierter_namen_exit2(umg, tmp_path, befehl, name):
    vorbereitet(umg, tmp_path)
    r = starten_mit_befehl(umg, befehl, "--modell-mock", "openai")
    assert r.returncode == 2, (befehl, r.stdout + r.stderr)
    assert f"--start-befehl: reservierter Name {name} bei --modell-mock" in r.stderr, r.stderr
    assert "node server.js" not in r.stderr and "poc-fremd" not in r.stderr
    assert umg.aufrufe() == []


@pytest.mark.parametrize("befehl", ["unset NODE_OPTIONS && node server.js", "node server.js -u poc", "env -u NODE_OPTIONS node server.js",
                                    "NEXT_PUBLIC_OPENAI_BASE_URL+=x npm start", "echo OPENAI_BASE_URL gesetzt; node server.js",
                                    "unset FOO; node server.js --modell OPENAI_API_KEY", "node server.js --unsetzen OPENAI_API_KEY"])
def test_start_befehl_syntaxformen_legitim_erlaubt(umg, tmp_path, befehl):
    """Gegenprobe zu den Syntaxformen: Wortgrenzen, Befehlsgrenzen (`;`, `&&`) und `-u` ohne reservierten Namen bleiben erlaubt."""
    vorbereitet(umg, tmp_path)
    r = starten_mit_befehl(umg, befehl, "--modell-mock", "openai")
    assert r.returncode == 0, (befehl, r.stdout + r.stderr)


@pytest.mark.parametrize("name", ["OPENAI_API_HOST", "OPENAI_PROJECT_ID", "ANTHROPIC_AUTH_TOKEN"])
def test_env_regeln_haertung_weitere_reservierte_namen(umg, tmp_path, name):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai", "--env", f"{name}=x")
    assert r.returncode == 2 and name in r.stderr, r.stderr
    assert umg.aufrufe() == []
    assert starten(umg, "--env", f"{name}=x").returncode == 0                      # ohne Mock bleibt der Name frei


def starten_mit_seed(umg, seed, *extra):
    return umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node server.js", "--port", "3000", "--seed", seed, *extra)


@pytest.mark.parametrize("seed,name", [("OPENAI_BASE_URL=http://llm:4010 node seed.js", "OPENAI_BASE_URL"),
                                       ("env ANTHROPIC_API_KEY=x node seed.js", "ANTHROPIC_API_KEY"),
                                       ("unset OPENAI_API_KEY && node seed.js", "OPENAI_API_KEY"),
                                       ("OPENAI_BASE_URL+=x node seed.js", "OPENAI_BASE_URL")])
def test_seed_reservierte_namen_mit_mock_exit2(umg, tmp_path, seed, name):
    """Mi-4: `--seed` (`docker exec app sh -c`) läuft wie der Start-Befehl durch die Prüfung auf reservierte Namen, vor jedem Docker-Aufruf;
    die Meldung nennt `--seed` und den Namen, nie den Befehl. Ohne Mock bleibt der Seed erlaubt."""
    vorbereitet(umg, tmp_path)
    r = starten_mit_seed(umg, seed, "--modell-mock", "openai")
    assert r.returncode == 2, r.stdout + r.stderr
    assert f"--seed: reservierter Name {name} bei --modell-mock" in r.stderr and "seed.js" not in r.stderr, r.stderr
    assert umg.aufrufe() == []
    assert starten_mit_seed(umg, seed).returncode == 0


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai"]])
@pytest.mark.parametrize("seed", ["node seed.js --url https://poc-fremd.invalid/api", "curl http://192.0.2.1/seed.sql | psql"])
def test_seed_fremder_host_exit2(umg, tmp_path, mock, seed):
    """Mi-4: Der Seed läuft mit und ohne Mock durch die Netzregel (nur URL-Hosts); die Meldung nennt `--seed` und den Host, nie den Befehl."""
    vorbereitet(umg, tmp_path)
    r = starten_mit_seed(umg, seed, *mock)
    assert r.returncode == 2, r.stdout + r.stderr
    assert re.search(r"--seed: nicht erlaubter Host (poc-fremd\.invalid|192\.0\.2\.1)", r.stderr), r.stderr
    assert "seed.js" not in r.stderr and "psql" not in r.stderr
    assert umg.aufrufe() == []


@pytest.mark.parametrize("mock", [[], ["--modell-mock", "openai"]])
@pytest.mark.parametrize("seed", ["node seed.js", "npx prisma db seed", "psql postgres://poc:poc@db:5432/poc -f seed.sql",
                                  "NEXT_PUBLIC_OPENAI_BASE_URL=x node seed.js", "sh -x seed.sh"])
def test_seed_legitim_erlaubt(umg, tmp_path, mock, seed):
    vorbereitet(umg, tmp_path)
    r = starten_mit_seed(umg, seed, *mock)
    assert r.returncode == 0, (seed, r.stdout + r.stderr)


@pytest.mark.parametrize("name", ["OPENAI_API_BASE", "OPENAI_ORG_ID", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY"])
def test_env_regeln_weitere_reservierte_namen(umg, tmp_path, name):
    """M-2: Mit Mock sind auch die weiteren Namen gesperrt, ohne Rücksicht auf Groß-/Kleinschreibung; ohne Mock bleiben sie frei."""
    vorbereitet(umg, tmp_path)
    for schreibweise in (name, name.lower(), name.title()):
        r = starten(umg, "--modell-mock", "openai", "--env", f"{schreibweise}=x")
        assert r.returncode == 2 and schreibweise in r.stderr, (schreibweise, r.stderr)
    assert umg.aufrufe() == []
    r = starten(umg, "--env", f"{name}=x")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("name", MOCK_NAMEN)
def test_env_regeln_reservierte_namen_gross_kleinschreibung_egal(umg, tmp_path, name):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai", "--env", f"{name.lower()}=x")
    assert r.returncode == 2, r.stdout + r.stderr
    assert umg.aufrufe() == []


@pytest.mark.parametrize("wert_", ["", "gemini", "openai,gemini", "openai,openai", "openai,", ",openai", "OpenAI", "openai anthropic"])
def test_modell_mock_argument_ungueltig_exit2(umg, tmp_path, wert_):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", wert_)
    assert r.returncode == 2, r.stdout + r.stderr
    assert not any(a["args"][0] in ("run", "network") for a in umg.aufrufe())


def test_modell_mock_env_gesetzt(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai,anthropic", "--env", "A=1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "modell-mock: http://llm:4010 (openai, anthropic)" in r.stdout.splitlines()
    app = run_mit_name(umg, APP)[0]
    env = wert(app, "-e")
    assert "OPENAI_BASE_URL=http://llm:4010/v1" in env and "OPENAI_API_KEY=poc-dummy-openai" in env
    assert "ANTHROPIC_BASE_URL=http://llm:4010" in env and "ANTHROPIC_API_KEY=poc-dummy-anthropic" in env
    assert "A=1" in env and "PORT=3000" in env
    mock = run_mit_name(umg, LLM)[0]
    assert wert(mock, "--network") == [f"security-audit-{LAUF}-p1"] and wert(mock, "--network-alias") == ["llm"]
    assert mock[mock.index(f"security-audit-{LAUF}-app"):] == [f"security-audit-{LAUF}-app", "node", "/poc/llm-mock.mjs",
                                                                "--server", "--port", "4010", "--steuer-port", "4011"]
    aufrufe = [a["args"] for a in umg.aufrufe()]
    bereit = ["exec", "-i", LLM, "node", "/poc/llm-mock.mjs", "--bereit"]
    assert bereit in aufrufe
    i_mock = aufrufe.index(mock)
    assert i_mock < aufrufe.index(bereit) < aufrufe.index(app)                        # Mock, Bereitschaft, dann die App
    with open(os.path.join(umg.zustand(), "rolle-p1.json")) as f:
        z = json.load(f)
    assert z["modell_mock"] == ["openai", "anthropic"]
    assert z["env"] == ["A=1"]                                                         # Mock-Variablen gehören nicht in `env`


def test_modell_mock_env_nur_gewaehlte_api(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "anthropic")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "modell-mock: http://llm:4010 (anthropic)" in r.stdout.splitlines()
    env = wert(run_mit_name(umg, APP)[0], "-e")
    assert "ANTHROPIC_BASE_URL=http://llm:4010" in env and "ANTHROPIC_API_KEY=poc-dummy-anthropic" in env
    assert not any(e.startswith("OPENAI_") for e in env)


def test_modell_mock_mit_db_reihenfolge_mock_db_app(umg, tmp_path):
    """D6: Reihenfolge der `run`-Aufrufe mit Mock und Datenbank: Mock, DB, App (die Bereitschaft des Mocks liegt vor der DB)."""
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai", "--dienst", "postgres")
    assert r.returncode == 0, r.stdout + r.stderr
    assert [wert(a, "--name")[0] for a in laeufe(umg)[:3]] == [LLM, f"security-audit-{LAUF}-p1-db", APP]
    aufrufe = [a["args"] for a in umg.aufrufe()]
    bereit = ["exec", "-i", LLM, "node", "/poc/llm-mock.mjs", "--bereit"]
    db = next(i for i, a in enumerate(aufrufe) if a[0] == "run" and wert(a, "--name") == [f"security-audit-{LAUF}-p1-db"])
    assert aufrufe.index(bereit) < db


def test_ohne_modell_mock_kein_mock_container(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    assert run_mit_name(umg, LLM) == []
    assert not any("--bereit" in a["args"] for a in umg.aufrufe())
    z = json.load(open(os.path.join(umg.zustand(), "rolle-p1.json")))
    assert z["modell_mock"] == []


def test_modell_mock_bereit_timeout(umg, tmp_path):
    """K2: Die Bereitschaft dauert höchstens SECURITY_AUDIT_MOCK_BEREIT s (nur verkürzend); jeder `exec --bereit` bekommt
    höchstens die Restzeit als Timeout. Scheitert sie, endet starten als start-fehler mit `Modell-Mock`; die App startet nicht."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"exec -i": {"rc": 1}, "logs": {"stdout": "Modell-Mock-Log-Zeile\n"}})
    t0 = time.monotonic()
    r = starten(umg, "--modell-mock", "openai", env=umg.env(SECURITY_AUDIT_MOCK_BEREIT="2"))
    assert 1.5 < time.monotonic() - t0 < 8
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "Modell-Mock" in r.stdout and "nicht bereit" in r.stdout
    assert run_mit_name(umg, APP) == []
    assert sum(1 for a in umg.aufrufe() if "--bereit" in a["args"]) >= 2             # es wurde wiederholt abgefragt


def test_modell_mock_bereit_exec_hoechstens_restzeit(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"exec -i": {"rc": 1, "sleep": 20}})
    t0 = time.monotonic()
    r = starten(umg, "--modell-mock", "openai", env=umg.env(SECURITY_AUDIT_MOCK_BEREIT="2"))
    assert time.monotonic() - t0 < 10, "ein hängender exec darf die Bereitschaftsfrist nicht überschreiten"
    assert r.returncode == 4 and "Modell-Mock" in r.stdout


def test_modell_mock_bereit_frist_nur_verkuerzend(monkeypatch):
    for gesetzt, erwartet in (("", 30), ("5", 5), ("29", 29), ("30", 30), ("100", 30), ("0", 30), ("-3", 30), ("x", 30)):
        monkeypatch.setenv("SECURITY_AUDIT_MOCK_BEREIT", gesetzt)
        assert poc._mock_bereit_sekunden() == erwartet, gesetzt
    monkeypatch.delenv("SECURITY_AUDIT_MOCK_BEREIT")
    assert poc.MOCK_BEREIT == 30 and poc._mock_bereit_sekunden() == 30


def test_modell_mock_start_zeitueberschreitung_nennt_den_grund_haertung(umg, tmp_path):
    """Härtung (Frage 5): Hängt `docker run` des Mocks bis zum Timeout, steht im Fehlertext „Zeitüberschreitung“ statt eines leeren
    „nicht gestartet: “. Die App startet nicht, die Container der Rolle werden entfernt."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"run": {"sleep": 30}})
    r = starten(umg, "--modell-mock", "openai", env=umg.env(SECURITY_AUDIT_DOCKER_TIMEOUT="1"))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: start-fehler", r.stdout + r.stderr
    assert "Modell-Mock: nicht gestartet: Zeitüberschreitung" in r.stdout, r.stdout
    assert run_mit_name(umg, APP) == []
    assert ["rm", "-f", "-v", APP, f"security-audit-{LAUF}-p1-db", LLM] == [a["args"] for a in umg.aufrufe()][-1]


def test_modell_mock_start_fehler_ohne_bereitschaft_bei_run_fehler(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"run": {"rc": 125, "stderr": "docker: Error response from daemon: mock-boom\n"}})
    r = starten(umg, "--modell-mock", "openai")
    assert r.returncode == 4 and "Modell-Mock" in r.stdout and "mock-boom" in r.stdout
    assert not any("--bereit" in a["args"] for a in umg.aufrufe())


def test_mock_container_haertung(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    assert starten(umg, "--modell-mock", "openai").returncode == 0
    a = run_mit_name(umg, LLM)[0]
    assert a[:3] == ["run", "-d", "--pull"] and wert(a, "--pull") == ["never"]
    assert wert(a, "--cap-drop") == ["ALL"]
    assert wert(a, "--security-opt") == ["no-new-privileges"]
    assert wert(a, "--memory") == ["256m"]                                             # kein doppeltes --memory
    assert wert(a, "--pids-limit") == ["64"]
    assert "--read-only" in a
    assert wert(a, "--tmpfs") == ["/tmp:rw,noexec,nosuid,size=16m"]
    for verboten in ("-p", "--publish", "-P", "-v", "--volume", "--mount", "--privileged", "--dns", "-e", "--env"):
        assert verboten not in a, verboten
    assert wert(a, "--network") == [f"security-audit-{LAUF}-p1"]
    assert poc.HAERTUNG_MOCK == ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m",
                                 "--pids-limit", "64", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"]


def test_neustart_mit_mock(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    assert starten(umg, "--modell-mock", "openai,anthropic", "--env", "A=1").returncode == 0
    vorher = open(os.path.join(umg.zustand(), "rolle-p1.json")).read()
    umg.log_datei.unlink()
    r = umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "modell-mock: http://llm:4010 (openai, anthropic)" in r.stdout.splitlines()
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert aufrufe[1] == ["rm", "-f", "-v", APP, f"security-audit-{LAUF}-p1-db", LLM]         # alter Mock mit entfernt
    mock = run_mit_name(umg, LLM)
    assert len(mock) == 1 and ["exec", "-i", LLM, "node", "/poc/llm-mock.mjs", "--bereit"] in aufrufe
    assert aufrufe.index(mock[0]) < aufrufe.index(run_mit_name(umg, APP)[0])
    env = wert(run_mit_name(umg, APP)[0], "-e")
    assert "OPENAI_API_KEY=poc-dummy-openai" in env and "ANTHROPIC_BASE_URL=http://llm:4010" in env and "A=1" in env
    assert open(os.path.join(umg.zustand(), "rolle-p1.json")).read() == vorher


def test_neustart_ohne_mock_startet_keinen(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.log_datei.unlink()
    assert umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1").returncode == 0
    assert run_mit_name(umg, LLM) == []


def test_rolle_entfernen_nennt_llm(temp_ordner, monkeypatch):
    aufrufe = []
    monkeypatch.setattr(poc, "_docker", lambda args, timeout, **kw: aufrufe.append(args) or poc.Ergebnis(0, b"", b""))
    poc._rolle_entfernen(LAUF, "p2")
    n = f"security-audit-{LAUF}-p2"
    assert aufrufe == [["rm", "-f", "-v", f"{n}-app", f"{n}-db", f"{n}-llm"]]


def test_aufraeumen_erfasst_llm_ueber_praefix(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"ps": {"stdout": f"{LLM}\nsecurity-audit-{ANDERER_LAUF}-p1-llm\n"}})
    assert umg.poc("aufraeumen", "--lauf", LAUF).returncode == 0
    rm = [a["args"] for a in umg.aufrufe() if a["args"][:3] == ["rm", "-f", "-v"]]
    assert rm == [["rm", "-f", "-v", LLM]]                                             # nur der eigene Mock


def test_lade_rolle_ohne_modell_mock_kompatibel(umg, tmp_path, temp_ordner):
    """K1: Rollendateien ohne `modell_mock` (älterer Stand) gelten als ohne Mock; ein ungültiges Feld macht die Datei ungültig."""
    ordner = poc._ordner(LAUF, anlegen=True)
    basis = {"lauf": LAUF, "rolle": "p1", "start_befehl": "node s.js", "port": 3000, "env": ["A=1"], "dienst": None, "seed": None}
    with open(os.path.join(ordner, "rolle-p1.json"), "w") as f:
        json.dump(basis, f)
    z = poc._lade_rolle(LAUF, "p1")
    assert z["modell_mock"] == [] and z["port"] == 3000 and z["env"] == ["A=1"]
    for gut in (["openai"], ["anthropic"], ["anthropic", "openai"], []):
        _schreibe = {**basis, "modell_mock": gut}
        with open(os.path.join(ordner, "rolle-p1.json"), "w") as f:
            json.dump(_schreibe, f)
        assert poc._lade_rolle(LAUF, "p1")["modell_mock"] == gut
    for schlecht in ("openai", None, ["gemini"], ["openai", "openai"], [1], {"openai": 1}, True):
        with open(os.path.join(ordner, "rolle-p1.json"), "w") as f:
            json.dump({**basis, "modell_mock": schlecht}, f)
        with pytest.raises(poc.PocFehler) as e:
            poc._lade_rolle(LAUF, "p1")
        assert e.value.code == 2


def test_neustart_alte_rollendatei_ohne_modell_mock(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    pfad = os.path.join(umg.zustand(), "rolle-p1.json")
    z = json.load(open(pfad))
    del z["modell_mock"]
    json.dump(z, open(pfad, "w"))
    umg.log_datei.unlink()
    assert umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1").returncode == 0
    assert run_mit_name(umg, LLM) == []


def test_start_fehler_mock_liest_llm_logs(umg, tmp_path):
    """Scheitert der Mock-Start, stehen die Logs von `-llm` (nicht von `-app`) im Fehlertext."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"exec -i": {"rc": 1}, "logs": {"stdout": "mock-log: EADDRINUSE 4010\n"}})
    r = starten(umg, "--modell-mock", "openai", env=umg.env(SECURITY_AUDIT_MOCK_BEREIT="1"))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "mock-log: EADDRINUSE 4010" in r.stdout
    logs = [a["args"] for a in umg.aufrufe() if a["args"][0] == "logs"]
    assert logs == [["logs", "--tail", "40", LLM]]
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert ["rm", "-f", "-v", APP, f"security-audit-{LAUF}-p1-db", LLM] == aufrufe[-1]          # auch der Mock wird entfernt


# ------------------------------------------------------------------------------------ neustart / ausfuehren

def test_neustart(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node s.js", "--port", "3007",
            "--env", "A=1", "--seed", "node seed.js")
    vorher = open(os.path.join(umg.zustand(), "rolle-p1.json")).read()
    umg.log_datei.unlink()
    r = umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1")
    assert r.returncode == 0, r.stdout + r.stderr
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert aufrufe[0][0] == "version"
    assert aufrufe[1] == ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db", f"security-audit-{LAUF}-p1-llm"]
    app = [a for a in laeufe(umg) if wert(a, "--name") == [f"security-audit-{LAUF}-p1-app"]][0]
    assert "PORT=3007" in wert(app, "-e") and "A=1" in wert(app, "-e")
    assert ["exec", f"security-audit-{LAUF}-p1-app", "sh", "-c", "node seed.js"] in aufrufe
    assert open(os.path.join(umg.zustand(), "rolle-p1.json")).read() == vorher


def test_neustart_ohne_start(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    assert umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1").returncode == 2


def test_ausfuehren(umg):
    umg.konfig({"exec": {"stdout": "inhalt\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p2", "--", "cat", "/app/.netz", "-x")
    assert r.returncode == 0 and r.stdout == "inhalt\n"
    assert umg.aufrufe()[-1]["args"] == ["exec", f"security-audit-{LAUF}-p2-app", "cat", "/app/.netz", "-x"]


def test_ausfuehren_fehlercode(umg):
    umg.konfig({"exec": {"rc": 3, "stderr": "nope\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "false")
    assert r.returncode == 1 and "nope" in r.stderr


# ------------------------------------------------------------------------------------ anfrage

def anfrage_aufrufe(umg):
    return [a for a in umg.aufrufe() if a["args"][0] == "run" and "--url" in a["args"] and "--warten" not in a["args"]]


def test_anfrage_nur_app(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg, "p1", port="3000")
    for pfad in ["http://evil.test/", "https://evil.test/x", "evil.test/x", "//evil.test/", "/http://evil.test/",
                 "/a://b", "x", "", "/a b", "/a\r\nHost: x", "/a\\b", "\\\\evil.test\\x"]:
        r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", pfad)
        assert r.returncode == 2, pfad
    assert anfrage_aufrufe(umg) == []
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/x?url=http://127.0.0.1/")
    assert r.returncode == 0, r.stderr
    a = anfrage_aufrufe(umg)[0]["args"]
    assert wert(a, "--url") == ["http://app:3000/x?url=http://127.0.0.1/"]
    assert wert(a, "--network") == [f"security-audit-{LAUF}-p1"]
    assert a[a.index("node"):a.index("node") + 2] == ["node", "/poc/anfrage.mjs"]
    assert a[a.index(f"security-audit-{LAUF}-app") + 1:a.index("node")] == []
    assert "-i" in a and "--rm" in a
    assert wert(a, "--cap-drop") == ["ALL"] and wert(a, "--security-opt") == ["no-new-privileges"]
    assert wert(a, "--memory") == ["1g"] and wert(a, "--pids-limit") == ["256"]
    assert not {"-v", "--volume", "--mount", "-p", "--publish"} & set(a)
    assert wert(a, "--methode") == ["GET"]


def test_anfrage_ohne_gestartete_rolle(umg):
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/")
    assert r.returncode == 2
    assert anfrage_aufrufe(umg) == []


def test_anfrage_header_und_daten(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--methode", "POST", "--pfad", "/api",
                "--header", "Content-Type: application/json", "--header", "X-A:1", "--daten", '{"a":1}')
    assert r.returncode == 0, r.stderr
    aufruf = anfrage_aufrufe(umg)[0]
    assert wert(aufruf["args"], "--methode") == ["POST"]
    assert wert(aufruf["args"], "--header") == ["Content-Type: application/json", "X-A:1"]
    assert aufruf["stdin"] == '{"a":1}'


def test_anfrage_daten_datei(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    datei = tmp_path / "body.txt"
    datei.write_text("a=1&url=http://127.0.0.1/ ä\n")
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--methode", "POST", "--pfad", "/", "--daten-datei", str(datei))
    assert r.returncode == 0, r.stderr
    assert anfrage_aufrufe(umg)[0]["stdin"] == "a=1&url=http://127.0.0.1/ ä\n"
    # Kein Bind-Mount der Datei in den Container.
    assert str(datei) not in " ".join(anfrage_aufrufe(umg)[0]["args"])


def test_anfrage_daten_ungueltig(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    datei = tmp_path / "b"
    datei.write_text("x")
    basis = ["anfrage", "--lauf", LAUF, "--rolle", "p1", "--methode", "POST", "--pfad", "/"]
    assert umg.poc(*basis, "--daten", "a", "--daten-datei", str(datei)).returncode == 2
    assert umg.poc(*basis, "--daten-datei", str(tmp_path / "fehlt")).returncode == 2
    assert umg.poc(*basis, "--header", "Kaputt").returncode == 2
    assert umg.poc(*basis, "--header", "A b: c").returncode == 2
    assert umg.poc(*basis, "--header", "A: c\r\nHost: evil").returncode == 2
    assert anfrage_aufrufe(umg) == []


def test_anfrage_ausgabe_und_fehler(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.konfig({"run": {"stdout": "status: 200\nbody:\nhallo\n"}})
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/")
    assert r.returncode == 0 and r.stdout == "status: 200\nbody:\nhallo\n"
    umg.konfig({"run": {"rc": 1, "stderr": "fehler: Anfrage fehlgeschlagen: ECONNREFUSED\n"}})
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/")
    assert r.returncode == 1 and "ECONNREFUSED" in r.stderr


def test_anfrage_timeout_entfernt_container(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.konfig({"run": {"sleep": 30}})
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/",
                env=umg.env(SECURITY_AUDIT_DOCKER_TIMEOUT="1"), timeout=40)
    assert r.returncode == 1
    name = wert(anfrage_aufrufe(umg)[0]["args"], "--name")[0]
    assert ["rm", "-f", name] in [a["args"] for a in umg.aufrufe()]


def test_parallele_anfragen(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg, "p1")
    gestartet(umg, "p2", port="3001")
    p2 = os.path.join(umg.zustand(), "rolle-p2.json")
    vorher = open(p2).read()
    umg.log_datei.unlink()
    codes = []

    def anfrage():
        codes.append(umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/").returncode)

    def neustart():
        codes.append(umg.poc("neustart", "--lauf", LAUF, "--rolle", "p2").returncode)

    threads = [threading.Thread(target=anfrage) for _ in range(3)] + [threading.Thread(target=neustart)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes == [0, 0, 0, 0]
    namen = [wert(a["args"], "--name")[0] for a in umg.aufrufe() if a["args"][0] == "run"]
    assert len(namen) == len(set(namen)) == 5  # 3 Anfragen + neue App + Wartecontainer von neustart
    assert json.load(open(p2)) == json.loads(vorher)
    assert open(p2).read() == vorher


# ------------------------------------------------------------------------------------ aufraeumen

def test_aufraeumen_idempotent(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    assert os.path.isdir(umg.zustand())
    eigene = [f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db", f"security-audit-{LAUF}-p2-app"]
    fremde = [f"x-security-audit-{LAUF}-app", f"security-audit-{ANDERER_LAUF}-p1-app", f"security-audit-{LAUF}x",
              "postgres", f"security-audit-{LAUF[:-1]}"]
    umg.konfig({
        "ps": {"stdout": "\n".join(["/" + eigene[0], *eigene[1:], *fremde]) + "\n"},
        "network ls": {"stdout": "\n".join(["bridge", f"security-audit-{LAUF}-p1", f"security-audit-{LAUF}-p2",
                                              f"security-audit-{ANDERER_LAUF}-p1", f"security-audit-{LAUF}x"]) + "\n"},
        "images": {"stdout": "\n".join([f"security-audit-{LAUF}-app", f"security-audit-{LAUF}-app",
                                          f"security-audit-{ANDERER_LAUF}-app", f"x-security-audit-{LAUF}-app",
                                          "<none>", "postgres"]) + "\n"},
    })
    for _ in range(2):
        r = umg.poc("aufraeumen", "--lauf", LAUF)
        assert r.returncode == 0, r.stderr
    assert not os.path.exists(umg.zustand())
    aufrufe = [a["args"] for a in umg.aufrufe()]
    entfernt_c = [n for a in aufrufe if a[:3] == ["rm", "-f", "-v"] for n in a[3:]]    # -v: anonyme Volumes (Postgres) mit
    entfernt_n = [n for a in aufrufe if a[:2] == ["network", "rm"] for n in a[2:]]
    entfernt_i = [n for a in aufrufe if a[0] == "rmi" for n in a[1:] if not n.startswith("-")]
    assert sorted(set(entfernt_c)) == sorted(eigene)
    assert sorted(set(entfernt_n)) == [f"security-audit-{LAUF}-p1", f"security-audit-{LAUF}-p2"]
    assert sorted(set(entfernt_i)) == [f"security-audit-{LAUF}-app"]
    # Listen mit Format, kein Shell-Aufruf.
    assert ["ps", "-a", "--format", "{{.Names}}"] in aufrufe
    assert ["network", "ls", "--format", "{{.Name}}"] in aufrufe
    assert ["images", "--format", "{{.Repository}}"] in aufrufe


def test_aufraeumen_ohne_treffer(umg):
    umg.konfig({"ps": {"stdout": "postgres\n"}})
    r = umg.poc("aufraeumen", "--lauf", LAUF)
    assert r.returncode == 0
    assert [a["args"][0] for a in umg.aufrufe() if a["args"][0] in ("rm", "rmi")] == []
    assert [a["args"][:2] for a in umg.aufrufe() if a["args"][:2] == ["network", "rm"]] == []


def test_aufraeumen_ohne_daemon(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon"},
                "ps": {"rc": 1, "stderr": "Cannot connect to the Docker daemon at unix:///x.sock. Is the docker daemon running?"},
                "network": {"rc": 1, "stderr": "Cannot connect to the Docker daemon"},
                "images": {"rc": 1, "stderr": "Cannot connect to the Docker daemon"}})
    r = umg.poc("aufraeumen", "--lauf", LAUF)
    assert r.returncode == 1                  # Härtung B2: Docker nicht geprüft heißt unvollständig, nicht „sauber“
    assert "Docker" in r.stderr and "Cannot connect" not in r.stdout
    assert "aufraeumen --lauf" in r.stderr
    assert not os.path.exists(umg.zustand())  # Zustandsordner trotzdem entfernt


def test_aufraeumen_entfernt_nur_eigenen_zustand(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    vorbereitet(umg, tmp_path, lauf=ANDERER_LAUF)
    umg.poc("aufraeumen", "--lauf", LAUF)
    assert not os.path.exists(umg.zustand())
    assert os.path.isdir(umg.zustand(ANDERER_LAUF))


def test_aufraeumen_symlink_als_zustandsordner(umg, tmp_path):
    ziel = tmp_path / "wichtig"
    ziel.mkdir()
    (ziel / "datei").write_text("bleibt")
    os.symlink(ziel, umg.zustand())
    r = umg.poc("aufraeumen", "--lauf", LAUF)
    assert r.returncode == 0
    assert (ziel / "datei").read_text() == "bleibt"  # Ziel unangetastet
    assert not os.path.lexists(umg.zustand())


def test_aufraeumen_schreibgeschuetzte_kopie(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    sperre = os.path.join(umg.zustand(), "quelle", "sperre")
    os.makedirs(sperre)
    with open(os.path.join(sperre, "x"), "w") as f:
        f.write("x")
    os.chmod(sperre, 0o500)
    try:
        assert umg.poc("aufraeumen", "--lauf", LAUF).returncode == 0
        assert not os.path.exists(umg.zustand())
    finally:
        if os.path.exists(sperre):
            os.chmod(sperre, 0o700)


def test_zustandsordner_fremder_symlink_abgewiesen(umg, tmp_path):
    ziel = tmp_path / "fremd"
    ziel.mkdir()
    os.symlink(ziel, umg.zustand())
    repo = repo_mit(tmp_path, MINI)
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 2
    assert os.listdir(ziel) == []


def test_kein_shell_und_kein_host_bezug():
    """Produktionscode ruft docker nie über eine Shell auf und nutzt keine Host-Mounts."""
    quelle = open(POC, encoding="utf-8").read()
    assert "shell=True" not in quelle and "os.system" not in quelle
    ohne_rm = quelle.replace('"rm", "-f", "-v"', "")    # einzige Ausnahme: `docker rm -f -v` löscht anonyme Volumes
    assert '"-v"' not in ohne_rm and "--volume" not in ohne_rm and "--mount" not in ohne_rm
    assert "--privileged" not in quelle and '"-p"' not in quelle and "--publish" not in quelle
    assert "--network\", \"host\"" not in quelle and "--net=host" not in quelle


def test_dockerfile_und_ignore():
    docker = os.path.join(SKILL, "docker")
    text = open(os.path.join(docker, "Dockerfile.poc"), encoding="utf-8").read()
    zeilen = [z.strip() for z in text.splitlines() if z.strip() and not z.strip().startswith("#")]
    assert not any(z.startswith("# syntax") for z in text.splitlines())
    deps = zeilen.index("FROM node:${NODE}-slim AS deps")
    assert zeilen.index("USER node") > deps
    assert zeilen.index("USER node") < next(i for i, z in enumerate(zeilen) if z.startswith("RUN npm ci"))
    assert zeilen.index("RUN chown node:node /app") < zeilen.index("USER node")
    assert any("npm ci --ignore-scripts --registry=https://registry.npmjs.org/" in z for z in zeilen)
    assert 'RUN --network=none sh -c "$BUILD_BEFEHL"' in zeilen
    assert "COPY --from=poc --chown=root:root anfrage.mjs /poc/anfrage.mjs" in zeilen
    mock = "COPY --from=poc --chown=root:root llm-mock.mjs /poc/llm-mock.mjs"
    assert mock in zeilen                                  # K4: wie anfrage.mjs root-eigen, nach dem Kunden-Build
    assert zeilen.index(mock) > zeilen.index('RUN --network=none sh -c "$BUILD_BEFEHL"')
    assert not any("chown -R" in z for z in zeilen)
    assert zeilen[-1] != "USER root" and "USER root" not in zeilen
    ignore = open(os.path.join(docker, "Dockerfile.poc.dockerignore"), encoding="utf-8").read().split()
    assert any(z.endswith("node_modules") for z in ignore) and any(z.endswith(".git") for z in ignore)


# ------------------------------------------------------------------------------------ Fix-Runde 1 (Review T3)

def test_daemon_erkennung_nicht_in_container_ausgabe(umg):
    """T3-M1: Ein Treffer in der Ausgabe des Befehls ist kein Daemon-Ausfall, solange `docker version` antwortet."""
    umg.konfig({"exec": {"rc": 1, "stderr": "error during connect: Cannot connect to the Docker daemon (gespielt)\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "false")
    assert r.returncode == 1
    assert "kategorie: docker-fehlt" not in r.stdout


def test_daemon_erkennung_prueft_version_erneut(umg):
    umg.konfig({"exec": {"rc": 1, "stderr": "Cannot connect to the Docker daemon\n"},
                "version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "true")
    assert r.returncode == 3
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"


def test_daemon_erkennung_nur_bei_exit_1_und_125(umg):
    umg.konfig({"exec": {"rc": 2, "stderr": "Cannot connect to the Docker daemon\n"},
                "version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "true")
    assert r.returncode == 1
    assert [a for a in umg.aufrufe() if a["args"][0] == "version"] == []


def test_build_ausgabe_mit_daemon_text_ist_build_fehler(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"build": {"rc": 1, "stderr": "npm error: error during connect: Cannot connect to the Docker daemon\n"}})
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: build-fehler"


def test_daten_mit_ungueltigem_utf8(temp_ordner, umg, tmp_path, monkeypatch, capsys):
    """T3-M4: argv mit surrogateescape (ungültiges UTF-8) wird byte-genau durchgereicht, kein Traceback."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    for k, v in umg.env().items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    roh = b"a\xffb"
    arg = os.fsdecode(roh)
    assert poc.main(["anfrage", "--lauf", LAUF, "--rolle", "p1", "--methode", "POST", "--pfad", "/",
                     "--daten", arg]) == 0
    assert anfrage_aufrufe(umg)[-1]["stdin_hex"] == roh.hex()


def test_ausgabe_wird_gekappt(umg, tmp_path):
    """T3-M5: 20 MiB Ausgabe sprengen weder Speicher noch Ausgabe; der Hinweis steht auf stderr."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.konfig({"exec": {"flood": 20, "stdout": "ENDE\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "cat", "gross")
    assert r.returncode == 0
    assert len(r.stdout) <= 70 * 1024
    assert "gekürzt" in r.stderr
    umg.konfig({"build": {"rc": 1, "flood": 20, "stdout": "ENDE-BUILD\n"}})
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4
    zeilen = r.stdout.splitlines()
    assert zeilen[0] == "kategorie: build-fehler" and zeilen[-1] == "ENDE-BUILD" and len(zeilen) <= 41
    assert "gekürzt" in r.stderr


def test_lesen_nach_kill_haengt_nicht(umg, tmp_path):
    """T3-M5: Ein Enkelprozess, der die Pipe offen hält, blockiert nach dem Timeout nicht."""
    fake = umg.bin / "docker"
    fake.write_text(fake.read_text().replace("antwort = cfg.get", "if args[0] == 'exec':\n    import subprocess\n"
                    "    subprocess.Popen(['sleep', '60'])\n    time.sleep(30)\nantwort = cfg.get", 1))
    inicio = time.monotonic()
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "x",
                env=umg.env(SECURITY_AUDIT_DOCKER_TIMEOUT="1"), timeout=40)
    assert r.returncode == 1
    assert time.monotonic() - inicio < 15


def test_pull_never(umg, tmp_path):
    """T3-M6: Kein Container-Start zieht Images nach; das DB-Image wird vorher gezielt geholt."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"image inspect": {"rc": 1, "stderr": "Error: No such image"}})
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node s.js", "--port", "3000",
                "--dienst", "postgres")
    assert r.returncode == 0, r.stdout + r.stderr
    runs = laeufe(umg)
    assert len(runs) == 3  # DB, App, Wartecontainer
    for a in runs:
        assert wert(a, "--pull") == ["never"], a
    aufrufe = [a["args"] for a in umg.aufrufe()]
    pull = aufrufe.index(["pull", "postgres:16-alpine"])
    assert pull < next(i for i, a in enumerate(aufrufe) if a[0] == "run" and "postgres:16-alpine" in a)


def test_pull_nur_wenn_image_fehlt(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node s.js", "--port", "3000",
                "--dienst", "postgres")
    assert r.returncode == 0
    assert [a for a in umg.aufrufe() if a["args"][0] == "pull"] == []


def test_anfrage_container_ohne_pull(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    assert umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/").returncode == 0
    assert wert(anfrage_aufrufe(umg)[0]["args"], "--pull") == ["never"]


def test_antwort_wird_entschaerft(umg, tmp_path):
    """T3-M8: Steuerzeichen, ANSI und unsichtbare Zeichen der Kunden-App erreichen stdout nicht roh."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    boese = "status: 200\nbody:\n\x1b[31mrot\x1b[0m\x1b]0;titel\x07 a\rb\tc \u202eX\u200b \x00 \x7f\nzweite Zeile ä\n"
    umg.konfig({"run": {"stdout": boese}})
    r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/")
    assert r.returncode == 0
    for z in ("\x1b", "\x07", "\r", "\x00", "\x7f", "\u202e", "\u200b"):
        assert z not in r.stdout
    assert "\\x1b[31mrot" in r.stdout and "\\r" in r.stdout and "\\u202e" in r.stdout
    assert "\tc" in r.stdout and "\nzweite Zeile ä\n" in r.stdout  # Tab und Zeilenumbrüche bleiben
    umg.konfig({"exec": {"stdout": "\x1b[2Jweg\n", "stderr": "\x1b[1mfehler\n"}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "x")
    assert "\x1b" not in r.stdout and "\x1b" not in r.stderr


def test_daten_datei_zu_gross(umg, tmp_path):
    """T3-M9: DATEN_MAX = 1 MiB; ein Byte mehr ist Exit 2, genau 1 MiB geht durch."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    gross = tmp_path / "gross"
    gross.write_bytes(b"x" * (1024 * 1024 + 1))
    basis = ["anfrage", "--lauf", LAUF, "--rolle", "p1", "--methode", "POST", "--pfad", "/"]
    assert umg.poc(*basis, "--daten-datei", str(gross)).returncode == 2
    assert anfrage_aufrufe(umg) == []
    gross.write_bytes(b"x" * (1024 * 1024))
    assert umg.poc(*basis, "--daten-datei", str(gross)).returncode == 0
    assert len(anfrage_aufrufe(umg)[0]["stdin"]) == 1024 * 1024


def test_lockfile_v1_version_url(tmp_path):
    inhalt = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "https://evil.test/x.tgz"}}})
    assert poc.lockfile_pruefen(lock_in(tmp_path, inhalt)) == "lockfile-fremde-quelle"


def test_timeouts_werden_uebergeben(temp_ordner, monkeypatch):
    """T3-M9: ANFRAGE_TIMEOUT und EXEC_TIMEOUT gehen an _docker."""
    poc._schreibe_atomar(os.path.join(poc._ordner(LAUF, anlegen=True), "rolle-p1.json"),
                         {"start_befehl": "x", "port": 3000, "env": [], "dienst": None, "seed": None})
    aufrufe = []

    def fake(args, timeout, **kw):
        aufrufe.append((args[0], timeout))
        return poc.Ergebnis(0, b"", b"")

    monkeypatch.setattr(poc, "_docker", fake)
    assert poc.main(["anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/"]) == 0
    assert poc.main(["ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "true"]) == 0
    assert ("run", poc.ANFRAGE_TIMEOUT) in aufrufe and ("exec", poc.EXEC_TIMEOUT) in aufrufe
    assert poc.ANFRAGE_TIMEOUT == 45 and poc.EXEC_TIMEOUT == 120


# ------------------------------------------------------------------------------------ Fix-Runde 2 (Review T3-R2)

def test_bauen_node_range_hinweis(umg, tmp_path):
    vorbereitet(umg, tmp_path, dict(MINI, **{"package.json": json.dumps(
        {"name": "x", "version": "1.0.0", "engines": {"node": ">=20 " * 300}})}))
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "hinweis: node-range-zu-lang" in r.stdout.splitlines()
    assert "NODE=22" in build_aufruf(umg)


def test_bauen_fehler_mit_daemon_stoerung_ohne_marker(umg, tmp_path):
    """T3-R2-Minor-1: Build scheitert ohne Daemon-Text, aber `docker version` fällt jetzt aus: Exit 3."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"build": {"rc": 1, "stderr": "failed to solve: rpc error: code = Unavailable\n"},
                "version": {"folge": [{"rc": 0}, {"rc": 1, "stderr": "Cannot connect to the Docker daemon"}]}})
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 3
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"


def test_bauen_fehler_bei_laufendem_daemon_bleibt_build_fehler(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"build": {"rc": 1, "stderr": "boom\n"}})
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: build-fehler"
    assert [a["args"][0] for a in umg.aufrufe()].count("version") == 2  # davor und danach


def test_starten_fehler_mit_daemon_stoerung(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"run": {"rc": 125, "stderr": "docker: Error response from daemon: x\n"},
                "version": {"folge": [{"rc": 0}, {"rc": 1, "stderr": "Cannot connect to the Docker daemon"}]}})
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1")
    assert r.returncode == 3
    assert r.stdout.splitlines()[0] == "kategorie: docker-fehlt"

def test_starten_fehler_mit_daemon_stoerung_entfernt_rollen_container_haertung_a4(umg, tmp_path):
    """Fällt der Daemon nach dem Anlegen der Container aus, werden die Container der Rolle (best effort) trotzdem
    entfernt, bevor Exit 3 kommt."""
    vorbereitet(umg, tmp_path)
    umg.konfig({"run": {"rc": 125, "stderr": "docker: Error response from daemon: x\n"},
                "version": {"folge": [{"rc": 0}, {"rc": 1, "stderr": "Cannot connect to the Docker daemon"}]}})
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1")
    assert r.returncode == 3
    aufrufe = [a["args"] for a in umg.aufrufe()]
    rm = ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db", f"security-audit-{LAUF}-p1-llm"]
    letzter_run = max(i for i, a in enumerate(aufrufe) if a[0] == "run")
    assert any(a == rm for a in aufrufe[letzter_run + 1:]), aufrufe


def test_start_fehler_docker_fehlt_versucht_aufraeumen_und_wirft_weiter_haertung_a4(monkeypatch):
    aufrufe = []

    def fake(args, timeout, **kw):
        aufrufe.append(args[0])
        raise poc.DockerFehlt("weg")

    monkeypatch.setattr(poc, "_docker", fake)
    with pytest.raises(poc.DockerFehlt):
        poc._start_fehler(LAUF, "p1", "x")
    assert "rm" in aufrufe, aufrufe                       # Aufräumversuch trotz kaputtem Daemon, ohne eigenen Absturz



@pytest.mark.parametrize("zeichen", [
    "\ufe00", "\ufe0f", "\U000e0100", "\U000e01ef",      # Variation Selectors
    "\u034f", "\u180b", "\u180d", "\u180f", "\u17b4", "\u17b5",   # Combining Grapheme Joiner, Mongolisch, Khmer
    "\u3164", "\uffa0", "\u115f", "\u1160", "\u2800",  # Hangul-/Braille-Füller
    "\u2028", "\u2029",                                    # Zeilen-/Absatztrenner
    "\u0378", "\U0010ffff",                                # nicht zugewiesen (Cn)
])
def test_entschaerfen_weitere_unsichtbare_zeichen(zeichen):
    aus = poc._entschaerfen(f"a{zeichen}b")
    assert zeichen not in aus and aus.startswith("a\\") and aus.endswith("b"), ascii(aus)


def test_entschaerfen_laesst_normalen_text(tmp_path):
    assert poc._entschaerfen("Grüße, 世界 é\u0301 😀 a\tb\nc") == "Grüße, 世界 é\u0301 😀 a\tb\nc"


def test_ausgabegrenze_gilt_nach_dem_escaping(umg, tmp_path):
    """T3-R2-Minor-4: 65536 Steuerzeichen werden zu 4 Zeichen je Stück; ausgegeben werden höchstens 64 KiB."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.konfig({"exec": {"stdout": "\x01" * 65536, "stderr": "\x02" * 65536}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "x")
    assert len(r.stdout) <= 64 * 1024
    assert "gekürzt" in r.stderr
    assert r.stderr.count("\\x02") * 4 <= 64 * 1024 + 4
    assert len(r.stderr) <= 64 * 1024 + 200  # Escapes + Hinweis


# ------------------------------------------------------------------------------------ Härtung TF1-B1 (lange Operationen)

def test_gesamtbudgets_liegen_unter_dem_bash_limit_haertung_b1():
    """Der Bash-Timeout des Skills ist 600 s; die Arbeitsphase von starten/aufraeumen endet davor, samt Aufräumen."""
    assert poc.START_BUDGET + poc.KURZ_TIMEOUT * 2 + poc.VERSION_TIMEOUT < 600
    assert poc.AUFRAEUMEN_BUDGET + poc.KURZ_TIMEOUT < 600
    assert poc.BAU_TIMEOUT + 2 * poc.VERSION_TIMEOUT < 600
    assert poc.VORBEREITEN_BUDGET < 540                  # Härtung I3: vorbereiten, inkl. Entfernen der alten Kopie


def test_erschoepftes_budget_startet_keinen_docker_prozess_haertung_b1(umg, monkeypatch):
    """Bei Budget 0 (Frist verstrichen) wird kein docker-Prozess gestartet; ohne die Prüfung liefe ein Start mit
    negativem Timeout, der sofort beendet würde und nur als Prozessstart beobachtbar wäre."""
    for k, v in umg.env().items():
        monkeypatch.setenv(k, v)
    echtes_popen = poc.subprocess.Popen

    def kein_start(*a, **kw):
        raise AssertionError(f"docker gestartet trotz erschöpftem Budget: {a[0]}")

    monkeypatch.setattr(poc, "_ENDE", time.monotonic() - 1)
    monkeypatch.setattr(poc.subprocess, "Popen", kein_start)
    r = poc._docker(["ps"], 10)
    assert r.rc is None and not r.ok and r.out == b"" and r.err == b""
    monkeypatch.setattr(poc.subprocess, "Popen", echtes_popen)
    assert umg.aufrufe() == []
    monkeypatch.setattr(poc, "_ENDE", time.monotonic() + 60)                      # Gegenprobe: mit Restzeit läuft docker
    r = poc._docker(["ps"], 10)
    assert r.rc == 0 and [a["args"] for a in umg.aufrufe()] == [["ps"]]


def test_starten_zeitbudget_erschoepft_ist_start_fehler_mit_aufraeumen_haertung_b1(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"network create": {"sleep": 6}})
    t0 = time.monotonic()
    r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1",
                env=umg.env(SECURITY_AUDIT_START_BUDGET="2"))
    assert time.monotonic() - t0 < 5.5, "Aufruf muss am Budget enden, nicht am Einzel-Timeout"
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "Zeitbudget" in r.stdout
    aufrufe = [a["args"] for a in umg.aufrufe()]
    assert not any(a[0] == "run" for a in aufrufe), "nach erschöpftem Budget startet nichts mehr"
    rm = [a for a in aufrufe if a[0] == "rm" and f"security-audit-{LAUF}-p1-app" in a]
    assert len(rm) >= 2                                 # am Anfang und im Fehlerpfad (Aufräumen ist vom Budget ausgenommen)


def test_aufraeumen_zeitbudget_erschoepft_ist_unvollstaendig_haertung_b1(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"ps": {"sleep": 6}})
    t0 = time.monotonic()
    r = umg.poc("aufraeumen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_AUFRAEUMEN_BUDGET="2"))
    assert time.monotonic() - t0 < 5.5
    assert r.returncode == 1 and "Timeout" in r.stderr
    assert not os.path.exists(umg.zustand())            # lokaler Teil läuft immer


def test_ausfuehren_zeitueberschreitung_meldet_weiterlaufenden_prozess_haertung_b1(umg):
    umg.konfig({"exec": {"sleep": 5}})
    r = umg.poc("ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "sleep", "99",
                env=umg.env(SECURITY_AUDIT_DOCKER_TIMEOUT="1"))
    assert r.returncode == 1 and "Zeitüberschreitung" in r.stderr
    assert "weiter" in r.stderr and "neustart" in r.stderr, r.stderr


def test_lockfile_zu_gross_ist_lockfile_fehlt_mit_grund_haertung_b1(tmp_path, monkeypatch, capsys):
    ordner = lock_in(tmp_path, lockdatei())
    monkeypatch.setattr(poc, "LOCKFILE_MAX", 50)
    assert poc.lockfile_pruefen(ordner) == "lockfile-fehlt"
    assert "zu groß" in capsys.readouterr().err
    monkeypatch.setattr(poc, "LOCKFILE_MAX", 10 * 1024 * 1024)
    assert poc.lockfile_pruefen(ordner) is None


# ------------------------------------------------------------------------------------ Härtung TF1-B2 (Teilzustände, Übergänge)

def test_container_entfernen_loescht_anonyme_volumes_haertung_b2(umg, tmp_path):
    """Das Postgres-Image legt ein anonymes Volume an; `docker rm -f` ohne `-v` ließe es je neustart liegen."""
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    rm = [a["args"] for a in umg.aufrufe() if a["args"][0] == "rm" and f"security-audit-{LAUF}-p1-db" in a["args"]]
    assert rm and all(a[:3] == ["rm", "-f", "-v"] for a in rm), rm
    umg.konfig({"ps": {"stdout": f"security-audit-{LAUF}-p1-db\n"}})
    umg.poc("aufraeumen", "--lauf", LAUF)
    rm = [a["args"] for a in umg.aufrufe() if a["args"][0] == "rm" and a["args"][-1] == f"security-audit-{LAUF}-p1-db"]
    assert rm[-1][:3] == ["rm", "-f", "-v"]


def test_neu_reserviert_den_zustandsordner_haertung_b2(umg):
    r = umg.poc("neu")
    lauf = r.stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{8}", lauf)
    assert os.path.isdir(umg.zustand(lauf)) and (os.stat(umg.zustand(lauf)).st_mode & 0o777) == 0o700


def test_neu_ueberspringt_belegte_ids_haertung_b2(temp_ordner, monkeypatch, capsys):
    os.mkdir(os.path.join(os.path.realpath(temp_ordner), "security-audit-aaaaaaaa"))
    ids = iter(["aaaaaaaa", "aaaaaaaa", "bbbbbbbb"])
    monkeypatch.setattr(poc.secrets, "token_hex", lambda n: next(ids))
    assert poc.cmd_neu(None) == 0
    assert capsys.readouterr().out.strip() == "bbbbbbbb"
    assert os.path.isdir(os.path.join(os.path.realpath(temp_ordner), "security-audit-bbbbbbbb"))


def test_neu_ohne_freie_id_ist_fehler_haertung_b2(temp_ordner, monkeypatch):
    os.mkdir(os.path.join(os.path.realpath(temp_ordner), "security-audit-aaaaaaaa"))
    monkeypatch.setattr(poc.secrets, "token_hex", lambda n: "aaaaaaaa")
    with pytest.raises(poc.PocFehler):
        poc.cmd_neu(None)


def test_vorbereiten_schreibt_fertig_marker_und_bauen_verlangt_ihn_haertung_b2(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    assert os.path.isfile(os.path.join(umg.zustand(), "quelle.fertig"))
    os.unlink(os.path.join(umg.zustand(), "quelle.fertig"))        # Absturz mitten im Kopieren: Ordner da, Marker fehlt
    r = umg.poc("bauen", "--lauf", LAUF)
    assert r.returncode == 2 and "unvollständig" in r.stderr and "vorbereiten" in r.stderr
    assert not any(a["args"][0] == "build" for a in umg.aufrufe())


def test_vorbereiten_unvollstaendig_hinterlaesst_keinen_marker_haertung_b2(umg, tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, MINI, name="kunde-x")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 0
    shim = tmp_path / "gitshim"
    shim.mkdir()
    echtes = subprocess.run(["which", "git"], capture_output=True, text=True).stdout.strip()
    skript = shim / "git"
    skript.write_text('#!/bin/sh\ncase " $* " in *" cat-file "*) read x; echo garbage; cat >/dev/null; exit 0;; esac\n'
                      f'exec {echtes} "$@"\n')
    skript.chmod(0o755)
    env = umg.env()
    env["PATH"] = f"{shim}{os.pathsep}{env['PATH']}"
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, env=env)
    assert r.returncode == 4
    assert not os.path.exists(os.path.join(umg.zustand(), "quelle.fertig"))     # vom ersten Lauf entfernt, nicht neu gesetzt


def test_entferne_meldet_unvollstaendiges_loeschen_haertung_b2(tmp_path, monkeypatch):
    wurzel = tmp_path / "w"
    ziel = wurzel / "x"
    ziel.mkdir(parents=True)
    (ziel / "datei").write_text("x")
    monkeypatch.setattr(poc.shutil, "rmtree", lambda *a, **k: None)           # Löschen scheitert still
    with pytest.raises(poc.PocFehler, match="nicht vollständig entfernt"):
        poc._entferne(str(ziel), str(wurzel))


def test_aufraeumen_meldet_nicht_loeschbaren_zustandsordner_haertung_b2(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    sperre = os.path.join(umg.zustand(), "quelle", "sperre")
    os.makedirs(sperre)
    with open(os.path.join(sperre, "x"), "w") as f:
        f.write("x")
    os.chflags(sperre, stat.UF_IMMUTABLE) if hasattr(os, "chflags") and sys.platform == "darwin" else None
    try:
        r = umg.poc("aufraeumen", "--lauf", LAUF)
        if os.path.exists(umg.zustand()):
            assert r.returncode == 1 and "nicht vollständig entfernt" in r.stderr
        else:
            pytest.skip("Plattform ließ das Löschen trotz Sperre zu")
    finally:
        if hasattr(os, "chflags") and sys.platform == "darwin":
            os.chflags(sperre, 0)


def test_auflisten_zeigt_laeufe_aus_ordnern_und_docker_haertung_b2(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    anderer = umg.poc("neu").stdout.strip()
    nur_docker = "12345678"
    umg.konfig({
        "ps": {"stdout": f"security-audit-{LAUF}-p1-app\nsecurity-audit-{nur_docker}-p2-db\nfremd\n"},
        "network ls": {"stdout": f"bridge\nsecurity-audit-{nur_docker}-p2\n"},
        "images": {"stdout": f"security-audit-{LAUF}-app\npostgres\n"},
    })
    r = umg.poc("auflisten")
    assert r.returncode == 0, r.stderr
    zeilen = {z.split()[0]: z for z in r.stdout.splitlines() if z.strip()}
    assert set(zeilen) == {LAUF, anderer, nur_docker}, r.stdout
    assert "ordner=ja" in zeilen[LAUF] and "container=1" in zeilen[LAUF] and "images=1" in zeilen[LAUF]
    assert "ordner=ja" in zeilen[anderer] and "container=0" in zeilen[anderer]
    assert "ordner=nein" in zeilen[nur_docker] and "container=1" in zeilen[nur_docker] and "netze=1" in zeilen[nur_docker]
    assert not any(a["args"][0] in ("rm", "rmi") or a["args"][:2] == ["network", "rm"] for a in umg.aufrufe())   # nur lesen


def test_auflisten_ohne_docker_meldet_und_endet_mit_1_haertung_b2(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"version": {"rc": 1, "stderr": "Cannot connect to the Docker daemon"},
                "ps": {"rc": 1, "stderr": "Cannot connect to the Docker daemon. Is the docker daemon running?"}})
    r = umg.poc("auflisten")
    assert r.returncode == 1 and LAUF in r.stdout and "ordner=ja" in r.stdout
    assert "Docker" in r.stderr


def test_auflisten_ignoriert_fremde_ordner_haertung_b2(umg):
    os.makedirs(os.path.join(umg.tmp, "security-audit-xyz"))
    os.makedirs(os.path.join(umg.tmp, "security-audit-0a1b2c3d-extra"))
    os.makedirs(os.path.join(umg.tmp, "anderes"))
    assert umg.poc("auflisten").stdout.strip() == ""


def _sperre(umg, rolle, art):
    import fcntl
    os.makedirs(umg.zustand(), exist_ok=True)
    fd = os.open(os.path.join(umg.zustand(), f"rolle-{rolle}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, art)
    return fd


def test_rollen_sperre_exklusiv_blockiert_alle_anderen_aufrufe_haertung_b2(umg, tmp_path):
    import fcntl
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    fd = _sperre(umg, "p1", fcntl.LOCK_EX)
    try:
        for args in (["neustart", "--lauf", LAUF, "--rolle", "p1"],
                     ["starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1"],
                     ["anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/"],
                     ["ausfuehren", "--lauf", LAUF, "--rolle", "p1", "--", "true"]):
            umg.log_datei.unlink(missing_ok=True)
            r = umg.poc(*args)
            assert r.returncode == 1 and "Rolle p1" in r.stderr and "gerade" in r.stderr, (args, r.stderr)
            assert not any(a["args"][0] in ("run", "rm", "exec") for a in umg.aufrufe()), args
        r = umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p2", "--pfad", "/")       # andere Rolle bleibt frei
        assert "gerade" not in r.stderr
    finally:
        os.close(fd)


def test_rollen_sperre_geteilt_erlaubt_anfragen_aber_kein_neustart_haertung_b2(umg, tmp_path):
    import fcntl
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    fd = _sperre(umg, "p1", fcntl.LOCK_SH)                   # eine laufende anfrage
    try:
        assert umg.poc("anfrage", "--lauf", LAUF, "--rolle", "p1", "--pfad", "/").returncode == 0
        r = umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1")
        assert r.returncode == 1 and "gerade" in r.stderr
    finally:
        os.close(fd)
    assert umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1").returncode == 0     # Sperre frei: geht


def test_rollen_sperre_starten_ist_exklusiv_gegenueber_geteilter_sperre(umg, tmp_path):
    """L4: `starten` nimmt die Rollensperre exklusiv: schon eine geteilte Sperre (laufende anfrage oder modell) blockiert es,
    ohne dass ein Docker-Aufruf stattfindet."""
    import fcntl
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    fd = _sperre(umg, "p1", fcntl.LOCK_SH)
    try:
        umg.log_datei.unlink(missing_ok=True)
        r = umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node server.js", "--port", "3000")
        assert r.returncode == 1 and "Rolle p1" in r.stderr and "gerade" in r.stderr, r.stderr
        assert not any(a["args"][0] in ("run", "rm", "network") for a in umg.aufrufe())
    finally:
        os.close(fd)
    assert umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "node server.js", "--port", "3000").returncode == 0


# ------------------------------------------------------------------------------------ Härtung TF1-B3 (gepinnter Commit)

def test_vorbereiten_kopiert_den_uebergebenen_sha_haertung_b3(umg, tmp_path):
    repo = repo_mit(tmp_path, {**MINI, "stand.txt": "eins\n"}, name="kunde-pin")
    sha1 = git(repo, "rev-parse", "HEAD").strip()
    (tmp_path / "kunde-pin" / "stand.txt").write_text("zwei\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "zwei")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, "--sha", sha1)
    assert r.returncode == 0, r.stderr
    quelle = r.stdout.strip()
    assert open(os.path.join(quelle, "stand.txt")).read() == "eins\n"
    with open(os.path.join(umg.zustand(), "quelle.fertig")) as f:
        assert json.load(f)["sha"] == sha1                                  # der Marker hält fest, was kopiert wurde
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)               # ohne --sha: HEAD (Rückwärtskompatibilität)
    assert open(os.path.join(r.stdout.strip(), "stand.txt")).read() == "zwei\n"


@pytest.mark.parametrize("sha", ["HEAD", "abc", "--output=x", "A" * 40, "0" * 39, "g" * 40])
def test_vorbereiten_sha_ungueltig_ist_aufruffehler_haertung_b3(umg, tmp_path, sha):
    repo = repo_mit(tmp_path, MINI, name="kunde-x")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, "--sha", sha)
    assert r.returncode == 2


def test_vorbereiten_unbekannter_sha_ist_git_fehler_haertung_b3(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI, name="kunde-x")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, "--sha", "0" * 40)
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: git-fehler"
    assert not os.path.exists(os.path.join(umg.zustand(), "quelle.fertig"))


# ------------------------------------------------------------------------------------ Härtung TF1-B5 (keine stillen Fallbacks)

def test_lockfile_unlesbar_nennt_den_grund_haertung_b5(tmp_path, capsys):
    ordner = lock_in(tmp_path, "{kaputt")
    assert poc.lockfile_pruefen(ordner) == "lockfile-fehlt"
    assert "package-lock.json nicht lesbar" in capsys.readouterr().err
    leer = lock_in(tmp_path / "x", None, dateien={})
    assert poc.lockfile_pruefen(leer) == "lockfile-fehlt"
    assert "nicht lesbar" not in capsys.readouterr().err        # fehlende Datei: eigene, bekannte Kategorie


def test_lockfile_ohne_paketliste_ist_hinweis_haertung_b5(tmp_path):
    v1 = json.dumps({"name": "m", "lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0"}}})
    assert "lockfile-ohne-paketliste" in poc.lockfile_hinweise(lock_in(tmp_path, v1))
    assert "lockfile-ohne-paketliste" not in poc.lockfile_hinweise(lock_in(tmp_path / "v3", lockdatei()))


@pytest.mark.parametrize("engines, erwartet", [
    (">=99", True), ("lts/*", True), (">=18 <19", True), ("garbage ??", True),     # nicht auswählbar: Standard 22 gilt
    (">=20", False), ("^22", False), ("20 || 22", False),
])
def test_node_engines_ignoriert_ist_hinweis_haertung_b5(tmp_path, engines, erwartet):
    ordner = projekt(tmp_path / "q", {"package.json": json.dumps({"name": "m", "engines": {"node": engines}})})
    hinweise = poc.node_hinweise(ordner, None)
    assert ("node-engines-ignoriert" in hinweise) is erwartet, (engines, hinweise)
    assert poc.node_hinweise(ordner, "22") == []                     # explizite Vorgabe: nichts zu melden


def test_node_ohne_engines_kein_hinweis_haertung_b5(tmp_path):
    assert poc.node_hinweise(projekt(tmp_path / "q", {"package.json": "{}"}), None) == []


def test_node_range_zu_lang_bleibt_eigener_hinweis_haertung_b5(tmp_path):
    ordner = projekt(tmp_path / "q", {"package.json": json.dumps({"engines": {"node": ">=1 " * 2000}})})
    assert poc.node_hinweise(ordner, None) == ["node-range-zu-lang"]


def test_puffer_lesefehler_wird_markiert_haertung_b5():
    import types
    fd = os.open(os.devnull, os.O_RDONLY)
    os.close(fd)                                                      # ungültiger Deskriptor: os.read wirft OSError
    puffer = poc._Puffer(types.SimpleNamespace(fileno=lambda: fd), 100, False)
    puffer.ergebnis(time.monotonic() + 5)
    assert puffer.lesefehler is True


def test_puffer_ohne_fehler_ohne_marke_haertung_b5():
    r, w = os.pipe()
    os.write(w, b"abc")
    os.close(w)
    with os.fdopen(r, "rb") as strom:
        puffer = poc._Puffer(strom, 100, False)
        assert puffer.ergebnis(time.monotonic() + 5) == (b"abc", False) and puffer.lesefehler is False


# ------------------------------------------------------------------------------------ Härtung TF1-I3 (Budget vorbereiten)

def _langsames_git(umg, pause):
    """`git` vor dem echten im PATH der Umgebung: wartet `pause` Sekunden je Aufruf."""
    import shutil
    echt = shutil.which("git")
    shim = umg.bin / "git"
    shim.write_text(f'#!/bin/sh\nsleep {pause}\nexec {echt} "$@"\n')
    shim.chmod(0o755)


def test_vorbereiten_gesamtbudget_ueberschritten_ist_exit_4_ohne_fertig_marker_haertung_i3(umg, tmp_path):
    """Jeder git-Aufruf (0,7 s) liegt weit unter seiner Einzelgrenze; die Summe sprengt das Budget von 2 s."""
    repo = repo_mit(tmp_path, MINI, name="kunde-i3")
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    marker = os.path.join(umg.zustand(), "quelle.fertig")
    assert os.path.isfile(marker)
    _langsames_git(umg, 0.7)
    t0 = time.monotonic()
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, env=umg.env(SECURITY_AUDIT_VORBEREITEN_BUDGET="2"))
    assert time.monotonic() - t0 < 20
    assert r.returncode == 4 and "Zeitbudget" in r.stderr and "Traceback" not in r.stderr, (r.stdout, r.stderr)
    assert r.stdout.splitlines()[0] in ("kategorie: git-fehler", "kategorie: arbeitskopie-unvollstaendig")
    assert not os.path.exists(marker), "nach Abbruch gilt keine Kopie als fertig"
    assert umg.poc("bauen", "--lauf", LAUF).returncode != 0              # bauen verlangt den Marker


def test_vorbereiten_einzelner_haengender_git_aufruf_endet_mit_dem_budget_haertung_i3(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI, name="kunde-i3b")
    _langsames_git(umg, 30)
    t0 = time.monotonic()
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, env=umg.env(SECURITY_AUDIT_VORBEREITEN_BUDGET="1"))
    assert time.monotonic() - t0 < 15
    assert r.returncode == 4 and "Zeitbudget" in r.stderr


def test_vorbereiten_mit_ausreichendem_budget_laeuft_normal_haertung_i3(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI, name="kunde-i3c")
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, env=umg.env(SECURITY_AUDIT_VORBEREITEN_BUDGET="120"))
    assert r.returncode == 0, r.stderr
    assert os.path.isfile(os.path.join(umg.zustand(), "quelle.fertig"))


# ---- Härtung TF2: der Marker gehört zu genau einer Arbeitskopie

def fertig_id(umg, lauf=LAUF):
    with open(os.path.join(umg.zustand(lauf), "quelle.fertig"), encoding="utf-8") as f:
        return json.load(f)["id"]


def test_vorbereiten_vergibt_je_kopie_eine_neue_kennung(umg, tmp_path):
    repo = repo_mit(tmp_path, MINI, name="kunde-kennung")
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    erste = fertig_id(umg)
    assert re.fullmatch(r"[0-9a-f]{32}", erste)
    assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo).returncode == 0
    assert fertig_id(umg) != erste


def test_kopie_kennung_liest_die_id_aus_dem_fertig_marker(temp_ordner, tmp_path):
    zustand = poc.zustand_ordner(LAUF)
    assert poc.kopie_kennung(LAUF) is None                               # kein Zustandsordner
    os.makedirs(zustand)
    assert poc.kopie_kennung(LAUF) is None                               # kein Marker
    for inhalt in ("", "kein json", "[]", '{"id": 5}', '{"id": ""}', '{"fertig": true}'):
        with open(os.path.join(zustand, "quelle.fertig"), "w") as f:
            f.write(inhalt)
        assert poc.kopie_kennung(LAUF) is None, inhalt
    with open(os.path.join(zustand, "quelle.fertig"), "w") as f:
        f.write('{"fertig": true, "id": "abc123"}')
    assert poc.kopie_kennung(LAUF) == "abc123"
    os.unlink(os.path.join(zustand, "quelle.fertig"))
    ziel = tmp_path / "anderswo.json"
    ziel.write_text('{"id": "fremd"}')
    os.symlink(ziel, os.path.join(zustand, "quelle.fertig"))
    assert poc.kopie_kennung(LAUF) is None                               # ein Symlink ist kein Marker


def test_bauen_marker_einer_anderen_kopie_verweigert(umg, tmp_path):
    """Marker aus einer früheren Kopie (z. B. `secrets` lief über ein `vorbereiten` hinweg): kein Bau auf der neuen,
    ungeschwärzten Kopie."""
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    umg.marker_setzen(kopie="0" * 32)
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


@pytest.mark.parametrize("inhalt", ["", "kein json", "[]", '{"geschwaerzt": 0}', '{"kopie": 5}', '{"kopie": null}'])
def test_bauen_marker_ohne_kennung_der_kopie_verweigert(umg, tmp_path, inhalt):
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    pfad = umg.marker()
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    with open(pfad, "w") as f:
        f.write(inhalt)
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"
    assert [a for a in umg.aufrufe() if a["args"][0] == "build"] == []


def test_poc_verweist_nur_auf_vorhandene_unterbefehle_von_lieferkette():
    """Task 4 (Vorwärtsreferenz): Der Docstring von `poc.py` nennt `lieferkette.py secrets`; das Skript und der Unterbefehl
    müssen existieren (die Referenz war bis Task 1 voraus)."""
    quelle = open(os.path.join(SKILL, "scripts", "poc.py"), encoding="utf-8").read()
    assert "`lieferkette.py secrets`" in quelle
    lieferkette = open(os.path.join(SKILL, "scripts", "lieferkette.py"), encoding="utf-8").read()
    assert 'sub.add_parser("secrets"' in lieferkette


def test_bauen_marker_und_fertig_marker_ohne_kennung_gelten_nicht_als_gleich(umg, tmp_path):
    """`None == None` darf nie als „gleiche Kopie“ zählen: ohne Kennung im Fertig-Marker gilt auch ein Marker mit `kopie: null` nicht."""
    vorbereitet(umg, tmp_path)
    umg.fake_gitleaks()
    with open(os.path.join(umg.zustand(), "quelle.fertig"), "w") as f:
        f.write('{"fertig": true}')
    umg.marker_setzen(kopie=None)
    r = umg.poc("bauen", "--lauf", LAUF, env=umg.env(SECURITY_AUDIT_OHNE=""))
    assert r.returncode == 4 and r.stdout.splitlines()[0] == "kategorie: nicht-geschwaerzt"


# ------------------------------------------------------------------------------------ TF3: poc.py modell

def mit_mock(umg, tmp_path, *extra, rolle="p1", apis="openai"):
    """Lauf vorbereiten, Rolle mit Modell-Mock starten, Docker-Protokoll leeren."""
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", apis, *extra, rolle=rolle)
    assert r.returncode == 0, r.stdout + r.stderr
    umg.log_datei.unlink(missing_ok=True)


def modell(umg, *args, rolle="p1", env=None):
    return umg.poc("modell", "--lauf", LAUF, "--rolle", rolle, *args, env=env)


def antworten_datei(tmp_path, inhalt, name="antworten.json"):
    pfad = tmp_path / name
    pfad.write_text(inhalt if isinstance(inhalt, str) else json.dumps(inhalt))
    return str(pfad)


def exec_aufrufe(umg):
    return [a for a in umg.aufrufe() if a["args"][0] == "exec"]


MOCK_CLI = ["node", "/poc/llm-mock.mjs"]
GUELTIGE_ANTWORTEN = [
    [],
    [{"text": "hallo"}],
    [{"text": "ä ö ü 😀"}],
    [{"werkzeug": {"name": "datei.lesen-1", "argumente": {"pfad": "/x", "n": 1}}}],
    [{"werkzeug": {"name": "ohne_argumente"}}],
    [{"text": "a", "wenn_enthaelt": "POCMARKER-abc-1"}, {"werkzeug": {"name": "w", "argumente": {}}, "wenn_enthaelt": "POCMARKER-x"}],
    [{"text": str(i)} for i in range(20)],
    [{"text": "x" * 16384}],
]


@pytest.mark.parametrize("liste", GUELTIGE_ANTWORTEN, ids=range(len(GUELTIGE_ANTWORTEN)))
def test_modell_antworten_gueltig(umg, tmp_path, liste):
    mit_mock(umg, tmp_path)
    r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, liste))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout == f"modell: {len(liste)} Antworten gesetzt (Rolle p1)\n"
    aufrufe = exec_aufrufe(umg)
    assert len(aufrufe) == 1
    assert aufrufe[0]["args"] == ["exec", "-i", LLM, *MOCK_CLI, "--setzen", "--steuer-port", "4011"]
    assert json.loads(aufrufe[0]["stdin"]) == liste                        # geprüfte Liste auf stdin, nicht in argv
    assert str(tmp_path) not in " ".join(aufrufe[0]["args"])


UNGUELTIGE_ANTWORTEN = {
    "objekt": {}, "string": "x", "null": None, "21 Eintraege": [{"text": "a"}] * 21,
    "eintrag kein objekt": ["a"], "eintrag null": [None],
    "text und werkzeug": [{"text": "a", "werkzeug": {"name": "w"}}], "weder noch": [{}], "nur marker": [{"wenn_enthaelt": "POCMARKER-a"}],
    "fremdes feld": [{"text": "a", "x": 1}], "text kein string": [{"text": 1}], "text null": [{"text": None}],
    "text zu lang": [{"text": "x" * 16385}],
    "werkzeug kein objekt": [{"werkzeug": "w"}], "werkzeug liste": [{"werkzeug": []}], "werkzeug ohne name": [{"werkzeug": {"argumente": {}}}],
    "name leer": [{"werkzeug": {"name": ""}}], "name leerzeichen": [{"werkzeug": {"name": "a b"}}],
    "name schraegstrich": [{"werkzeug": {"name": "a/b"}}], "name zu lang": [{"werkzeug": {"name": "a" * 65}}],
    "name umlaut": [{"werkzeug": {"name": "füge"}}], "name zahl": [{"werkzeug": {"name": 1}}],
    "name zeilenumbruch": [{"werkzeug": {"name": "a\n"}}],
    "argumente liste": [{"werkzeug": {"name": "w", "argumente": []}}], "argumente string": [{"werkzeug": {"name": "w", "argumente": "x"}}],
    "werkzeug fremdes feld": [{"werkzeug": {"name": "w", "x": 1}}],
    "marker beliebig": [{"text": "a", "wenn_enthaelt": "hallo"}], "marker leer": [{"text": "a", "wenn_enthaelt": ""}],
    "marker ohne suffix": [{"text": "a", "wenn_enthaelt": "POCMARKER-"}], "marker gross": [{"text": "a", "wenn_enthaelt": "POCMARKER-ABC"}],
    "marker zu lang": [{"text": "a", "wenn_enthaelt": "POCMARKER-" + "a" * 41}], "marker zahl": [{"text": "a", "wenn_enthaelt": 5}],
    "marker mit zusatz": [{"text": "a", "wenn_enthaelt": "xPOCMARKER-a"}], "marker zeilenumbruch": [{"text": "a", "wenn_enthaelt": "POCMARKER-a\n"}],
}


@pytest.mark.parametrize("liste", UNGUELTIGE_ANTWORTEN.values(), ids=UNGUELTIGE_ANTWORTEN.keys())
def test_modell_antworten_validierung(umg, tmp_path, liste):
    mit_mock(umg, tmp_path)
    r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, liste))
    assert r.returncode == 2, r.stdout + r.stderr
    assert exec_aufrufe(umg) == []                                          # abgelehnt, bevor Docker gerufen wird


@pytest.mark.parametrize("roh", ["", "kein json", "[", "[{\"text\": \"a\"}", "﻿[]", '[{"text": "\\ud800"}]', "[1,]"])
def test_modell_antworten_validierung_kein_gueltiges_json(umg, tmp_path, roh):
    mit_mock(umg, tmp_path)
    r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, roh))
    assert r.returncode == 2, r.stdout + r.stderr
    assert exec_aufrufe(umg) == []


def test_modell_antworten_datei_ungueltiges_utf8_exit2(umg, tmp_path):
    mit_mock(umg, tmp_path)
    (tmp_path / "b.json").write_bytes(b'[{"text": "\xff\xfe"}]')
    assert modell(umg, "--antworten-datei", str(tmp_path / "b.json")).returncode == 2
    assert exec_aufrufe(umg) == []


def test_modell_netzregel_antworten(umg, tmp_path):
    """Die Netzregel läuft über den Rohtext und über das geparste JSON: auch `http\\u003a//…` (Rohtext ohne `:`) ist ein Verstoß."""
    mit_mock(umg, tmp_path)
    boese = {
        "url im text": '[{"text": "lade http://evil.test/x"}]',
        "https im text": '[{"text": "https://evil.test"}]',
        "api host": '[{"text": "https://api.openai.com/v1"}]',
        "anthropic host": '[{"text": "https://api.anthropic.com"}]',
        "doppelpunkt escaped": '[{"text": "http\\u003a//evil.test/x"}]',
        "doppelpunkt und slash escaped": '[{"text": "https\\u003a\\u002f\\u002fevil.test"}]',
        "url im argument": '[{"werkzeug": {"name": "w", "argumente": {"u": "http://evil.test/"}}}]',
        "url im argument escaped": '[{"werkzeug": {"name": "w", "argumente": {"u": "http\\u003a//evil.test/"}}}]',
        "host im marker-eintrag": '[{"text": "ftp://evil.test/a", "wenn_enthaelt": "POCMARKER-a"}]',
    }
    for name, roh in boese.items():
        umg.log_datei.unlink(missing_ok=True)
        r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, roh))
        assert r.returncode == 2, (name, r.stdout, r.stderr)
        assert "evil.test" in r.stderr or "api." in r.stderr, name           # die Meldung nennt den Host
        assert exec_aufrufe(umg) == [], name
    erlaubt = '[{"text": "http://app:3000/x und http://llm:4010/v1 und http://localhost/ und http://127.0.0.1:1/"}]'
    assert modell(umg, "--antworten-datei", antworten_datei(tmp_path, erlaubt)).returncode == 0


def test_modell_ohne_mock_exit1(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    gestartet(umg)
    umg.log_datei.unlink(missing_ok=True)
    r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, [{"text": "a"}]))
    assert r.returncode == 1 and "Modell-Mock" in r.stderr, r.stderr
    r = modell(umg, "--protokoll")
    assert r.returncode == 1 and "Modell-Mock" in r.stderr, r.stderr
    assert exec_aufrufe(umg) == []


def test_modell_rolle_nicht_gestartet_exit2(umg, tmp_path):
    antworten = antworten_datei(tmp_path, [{"text": "a"}])
    assert modell(umg, "--antworten-datei", antworten).returncode == 2         # ganz ohne Zustand
    assert modell(umg, "--protokoll").returncode == 2
    mit_mock(umg, tmp_path, rolle="p1")
    for args in (["--antworten-datei", antworten], ["--protokoll"]):
        r = modell(umg, *args, rolle="p2")                                       # p1 läuft, p2 nie gestartet
        assert r.returncode == 2 and "Rolle p2 nicht gestartet" in r.stderr, r.stderr
    assert not any(a["args"][0] in ("exec", "run") for a in umg.aufrufe())


def test_modell_antworten_datei_zu_gross_exit2(umg, tmp_path):
    """K10: höchstens 64 KiB (+ 1 Byte gelesen); nicht lesbar (fehlt, Ordner) endet mit Exit 2."""
    mit_mock(umg, tmp_path)
    grenze = 64 * 1024
    ok = antworten_datei(tmp_path, "[]" + " " * (grenze - 2), "ok.json")
    assert os.path.getsize(ok) == grenze
    assert modell(umg, "--antworten-datei", ok).returncode == 0
    umg.log_datei.unlink(missing_ok=True)
    zu_gross = antworten_datei(tmp_path, "[]" + " " * (grenze - 1), "gross.json")
    assert os.path.getsize(zu_gross) == grenze + 1
    r = modell(umg, "--antworten-datei", zu_gross)
    assert r.returncode == 2 and "64 KiB" in r.stderr, r.stderr
    for pfad in (str(tmp_path / "fehlt.json"), str(tmp_path)):
        assert modell(umg, "--antworten-datei", pfad).returncode == 2
    assert exec_aufrufe(umg) == []


def test_modell_suche_nur_marker(umg, tmp_path):
    mit_mock(umg, tmp_path)
    for suche in ("hallo", "POCMARKER-", "POCMARKER-A", "POCMARKER-x y", "POCMARKER-" + "a" * 41, "", "--x", "pocmarker-a",
                  "POCMARKER-a\n", "xPOCMARKER-a", "POCMARKER-ä"):
        r = modell(umg, "--protokoll", "--suche", suche)
        assert r.returncode == 2, (suche, r.stdout, r.stderr)
    r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, []), "--suche", "POCMARKER-a")     # --suche gehört zu --protokoll
    assert r.returncode == 2
    assert exec_aufrufe(umg) == []
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    r = modell(umg, "--protokoll", "--suche", "POCMARKER-" + "a" * 40)
    assert r.returncode == 0, r.stderr
    assert exec_aufrufe(umg)[0]["args"] == ["exec", "-i", LLM, *MOCK_CLI, "--protokoll", "--suche", "POCMARKER-" + "a" * 40,
                                           "--steuer-port", "4011"]


def test_modell_genau_eine_betriebsart(umg, tmp_path):
    mit_mock(umg, tmp_path)
    assert modell(umg).returncode == 2
    assert modell(umg, "--protokoll", "--antworten-datei", antworten_datei(tmp_path, [])).returncode == 2
    assert exec_aufrufe(umg) == []


def test_modell_ein_docker_aufruf(umg, tmp_path):
    """Realismus: je `modell` genau ein Docker-Aufruf (`exec -i`), kein `inspect`, kein `version`, kein `ps`."""
    mit_mock(umg, tmp_path)
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    for args in (["--antworten-datei", antworten_datei(tmp_path, [{"text": "a"}])], ["--protokoll"],
                 ["--protokoll", "--suche", "POCMARKER-a"]):
        umg.log_datei.unlink(missing_ok=True)
        r = modell(umg, *args)
        assert r.returncode == 0, r.stderr
        aufrufe = umg.aufrufe()
        assert len(aufrufe) == 1 and aufrufe[0]["args"][:3] == ["exec", "-i", LLM], [a["args"] for a in aufrufe]


def test_modell_unter_rollensperre(umg, tmp_path):
    """Nicht exklusiv: eine geteilte Sperre (laufende anfrage) blockiert `modell` nicht, eine exklusive (starten, neustart) schon."""
    import fcntl
    mit_mock(umg, tmp_path)
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    antworten = antworten_datei(tmp_path, [{"text": "a"}])
    fd = _sperre(umg, "p1", fcntl.LOCK_EX)
    try:
        for args in (["--antworten-datei", antworten], ["--protokoll"]):
            umg.log_datei.unlink(missing_ok=True)
            r = modell(umg, *args)
            assert r.returncode == 1 and "Rolle p1" in r.stderr and "gerade" in r.stderr, (args, r.stderr)
            assert umg.aufrufe() == [], args
        r = modell(umg, "--protokoll", rolle="p2")                                # andere Rolle: die Sperre betrifft sie nicht
        assert "gerade" not in r.stderr
    finally:
        os.close(fd)
    fd = _sperre(umg, "p1", fcntl.LOCK_SH)
    try:
        assert modell(umg, "--antworten-datei", antworten).returncode == 0
        assert modell(umg, "--protokoll").returncode == 0
        assert umg.poc("neustart", "--lauf", LAUF, "--rolle", "p1").returncode == 1      # starten/neustart bleiben exklusiv
    finally:
        os.close(fd)


def test_modell_budget(umg, tmp_path):
    """K2: Budget 60 s, über SECURITY_AUDIT_MODELL_BUDGET nur verkürzbar; ein hängender exec endet nach dem Budget mit Exit 1."""
    mit_mock(umg, tmp_path)
    umg.konfig({"exec -i": {"sleep": 30}})
    t0 = time.monotonic()
    r = modell(umg, "--protokoll", env=umg.env(SECURITY_AUDIT_MODELL_BUDGET="2"))
    assert 1.5 < time.monotonic() - t0 < 12
    assert r.returncode == 1 and "Zeitüberschreitung" in r.stderr, r.stderr
    assert r.stdout == ""
    assert poc.MODELL_BUDGET == 60


def test_modell_budget_nur_verkuerzend(monkeypatch):
    try:
        for gesetzt, erwartet in (("", 60), ("5", 5), ("59", 59), ("60", 60), ("1000", 60), ("0", 60), ("-3", 60), ("x", 60)):
            monkeypatch.setenv("SECURITY_AUDIT_MODELL_BUDGET", gesetzt)
            assert poc._nur_verkuerzt("SECURITY_AUDIT_MODELL_BUDGET", poc.MODELL_BUDGET) == erwartet, gesetzt
            poc._frist_setzen("SECURITY_AUDIT_MODELL_BUDGET", poc.MODELL_BUDGET, verkuerzbar=True)
            assert poc._BUDGET_SEKUNDEN == erwartet, gesetzt
        monkeypatch.setenv("SECURITY_AUDIT_START_BUDGET", "1000")                    # Bestand: starten bleibt verlängerbar
        poc._frist_setzen("SECURITY_AUDIT_START_BUDGET", poc.START_BUDGET)
        assert poc._BUDGET_SEKUNDEN == 1000
    finally:
        poc._ohne_frist()


def test_modell_antworten_ausgabe_und_fehler(umg, tmp_path):
    mit_mock(umg, tmp_path)
    antworten = antworten_datei(tmp_path, [{"text": "a"}, {"text": "b"}])
    r = modell(umg, "--antworten-datei", antworten)
    assert r.returncode == 0 and r.stdout == "modell: 2 Antworten gesetzt (Rolle p1)\n" and r.stderr == ""
    for rc in (1, 2, 125):
        umg.konfig({"exec -i": {"rc": rc, "stderr": "fehler: Steuerung nicht erreichbar\n"}})
        r = modell(umg, "--antworten-datei", antworten)
        assert r.returncode == 1, (rc, r.stderr)                                    # Exit ≠ 0 des Mocks: Exit 1
        assert "Steuerung nicht erreichbar" in r.stderr and "gesetzt" not in r.stdout


def test_modell_protokoll_ausgabe_unveraendert_und_entschaerft(umg, tmp_path):
    mit_mock(umg, tmp_path)
    gross = '{"eintraege":[{"nr":1,"methode":"POST","pfad":"/v1/x","body":"' + "a" * 65000 + '"}],"gekuerzt":0}\n'
    umg.konfig({"exec -i": {"stdout": gross}})
    r = modell(umg, "--protokoll")
    assert r.returncode == 0 and r.stdout == gross and r.stderr == ""                # nicht gekürzt, unverändert
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[{"body":"a\x1b[31mb‮c\x00"}],"gekuerzt":0}\n'}})
    r = modell(umg, "--protokoll")
    assert r.returncode == 0
    assert "\x1b" not in r.stdout and "‮" not in r.stdout and "\x00" not in r.stdout    # _entschaerfen, nicht _gib_aus
    assert r.stdout.endswith("\n") and "a" in r.stdout and "b" in r.stdout and "[31m" in r.stdout


def test_modell_protokoll_fehler_exit1_entschaerft_ohne_werte(umg, tmp_path):
    geheim = "poc-dummy-geheimwert"
    mit_mock(umg, tmp_path, "--env", f"X_TOKEN={geheim}")
    umg.konfig({"exec -i": {"rc": 1, "stdout": "teil\n", "stderr": f"fehler\x1b[31m: Steuerung nicht erreichbar {geheim}\n"}})
    r = modell(umg, "--protokoll")
    assert r.returncode == 1, r.stderr
    assert "Steuerung nicht erreichbar" in r.stderr and "\x1b" not in r.stderr
    assert geheim not in r.stderr and geheim not in r.stdout                          # auch ein Wert im Fehlertext erscheint nicht
    assert "teil" not in r.stdout


def test_modell_protokoll_fehler_maskiert_auch_mock_keys(umg, tmp_path):
    """M-3: Der Fehlerauszug maskiert wie der Mock auch die Schlüssel des Mocks, nicht nur die `--env`-Werte."""
    mit_mock(umg, tmp_path, "--env", "X_TOKEN=poc-dummy-abcdef")
    umg.konfig({"exec -i": {"rc": 1, "stderr": "boom poc-dummy-openai und poc-dummy-abcdef\n"}})
    r = modell(umg, "--protokoll")
    assert r.returncode == 1, r.stderr
    assert "poc-dummy-openai" not in r.stderr and "poc-dummy-abcdef" not in r.stderr, r.stderr
    assert "boom <ENV:OPENAI_API_KEY> und <ENV:X_TOKEN>" in r.stderr, r.stderr


def test_modell_protokoll_wertlaenge_in_utf16_einheiten(umg, tmp_path):
    """M-5: Wie im Mock zählt die Länge in UTF-16-Einheiten (ein Emoji sind 2): 2049 Emojis sind 4098 Einheiten und passen nicht."""
    mit_mock(umg, tmp_path, "--env", "EMOJI=" + "\U0001F600" * 2049)
    r = modell(umg, "--protokoll")
    assert r.returncode == 2 and "EMOJI" in r.stderr and "4096" in r.stderr, r.stderr
    assert exec_aufrufe(umg) == []
    # genau 4096 Einheiten: erlaubt
    assert starten(umg, "--modell-mock", "openai", "--env", "EMOJI=" + "\U0001F600" * 2048).returncode == 0
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    assert modell(umg, "--protokoll").returncode == 0
    assert any(w["name"] == "EMOJI" for w in json.loads(exec_aufrufe(umg)[-1]["stdin"])["werte"])
    assert poc._utf16_laenge("a\U0001F600") == 3 and poc._utf16_laenge("\udcff") == 1


def test_modell_protokoll_maskierwerte_ohne_dubletten(umg, tmp_path):
    """M6g: Dieselbe Variable mit demselben Wert geht nur einmal an den Mock; derselbe Wert unter anderem Namen bleibt eigener Eintrag."""
    mit_mock(umg, tmp_path, "--env", "DUP=poc-dummy-dupwert", "--env", "DUP=poc-dummy-dupwert", "--env", "ZWEI=poc-dummy-dupwert")
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    assert modell(umg, "--protokoll").returncode == 0
    werte = json.loads(exec_aufrufe(umg)[0]["stdin"])["werte"]
    assert sorted((w["name"], w["wert"]) for w in werte) == [("DUP", "poc-dummy-dupwert"), ("OPENAI_API_KEY", "poc-dummy-openai"),
                                                             ("ZWEI", "poc-dummy-dupwert")]


def test_modell_protokoll_maskierwerte_per_stdin(umg, tmp_path):
    """Die Werte gehen per stdin, nie per argv: alle `--env`-Werte der Rolle ab 6 Zeichen plus die Mock-Keys, längste zuerst."""
    geheim = "poc-dummy-abcdef"
    mit_mock(umg, tmp_path, "--env", f"X_TOKEN={geheim}", "--env", "KURZ=abc12", "--env", "GRENZ=sechs6",
             "--env", "DATABASE_URL=postgres://poc:poc@db:5432/poc")
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    r = modell(umg, "--protokoll", "--suche", "POCMARKER-a")
    assert r.returncode == 0, r.stderr
    a = exec_aufrufe(umg)[0]
    assert a["args"] == ["exec", "-i", LLM, *MOCK_CLI, "--protokoll", "--suche", "POCMARKER-a", "--steuer-port", "4011"]
    daten = json.loads(a["stdin"])
    assert list(daten) == ["werte"]
    werte = daten["werte"]
    assert all(sorted(w) == ["name", "wert"] for w in werte)
    assert {w["name"]: w["wert"] for w in werte} == {"DATABASE_URL": "postgres://poc:poc@db:5432/poc", "X_TOKEN": geheim,
                                                       "GRENZ": "sechs6", "OPENAI_API_KEY": "poc-dummy-openai"}
    laengen = [len(w["wert"]) for w in werte]
    assert laengen == sorted(laengen, reverse=True)
    allargs = " ".join(a["args"])
    for w in werte:
        assert w["wert"] not in allargs                                               # nie per argv
    assert "abc12" not in a["stdin"]                                                  # unter 6 Zeichen: nicht maskiert
    assert r.stderr == ""


def test_modell_protokoll_maskierwerte_nur_gewaehlte_api_keys(umg, tmp_path):
    mit_mock(umg, tmp_path, apis="anthropic")
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    assert modell(umg, "--protokoll").returncode == 0
    werte = json.loads(exec_aufrufe(umg)[0]["stdin"])["werte"]
    assert werte == [{"name": "ANTHROPIC_API_KEY", "wert": "poc-dummy-anthropic"}]


def test_modell_protokoll_hoechstens_50_werte(umg, tmp_path):
    """Mi-4: mehr als 50 Werte: die 50 längsten gehen an den Mock, der Hinweis steht auf stderr (ohne Werte)."""
    envs = [a for i in range(55) for a in ("--env", f"V{i:02d}=" + "x" * (6 + i))]
    mit_mock(umg, tmp_path, *envs)
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    r = modell(umg, "--protokoll")
    assert r.returncode == 0, r.stderr
    werte = json.loads(exec_aufrufe(umg)[0]["stdin"])["werte"]
    assert len(werte) == 50
    assert {w["name"] for w in werte} >= {f"V{i:02d}" for i in range(6, 55)} | {"OPENAI_API_KEY"}
    assert not {w["name"] for w in werte} & {f"V{i:02d}" for i in range(0, 6)}      # die kürzesten (6 bis 11 Zeichen) entfallen
    assert "50" in r.stderr and "56" in r.stderr and "xxxxxx" not in r.stderr


def test_modell_protokoll_wert_zu_lang_exit2(umg, tmp_path):
    """Ein Wert über 4096 Zeichen (Grenze des Mocks) lässt sich nicht maskieren: Exit 2 mit dem Namen, ohne Docker-Aufruf."""
    mit_mock(umg, tmp_path, "--env", "GROSS=" + "x" * 4097)
    r = modell(umg, "--protokoll")
    assert r.returncode == 2 and "GROSS" in r.stderr and "xxxx" not in r.stderr, r.stderr
    assert exec_aufrufe(umg) == []
    assert starten(umg, "--modell-mock", "openai", "--env", "GRENZE=" + "x" * 4096).returncode == 0
    umg.konfig({"exec -i": {"stdout": '{"eintraege":[],"gekuerzt":0}\n'}})
    assert modell(umg, "--protokoll").returncode == 0


def test_modell_protokoll_ungueltiges_utf8_im_env_wert_exit2_haertung(umg, tmp_path):
    """Härtung (Frage 5, stiller Fallback): Ein `--env`-Wert mit ungültigem UTF-8 (argv-Surrogat) lässt sich dem Mock nicht übergeben; bisher
    wurde das Zeichen still durch `?` ersetzt und der Wert so nie maskiert. Jetzt Exit 2 mit dem Namen, ohne Docker-Aufruf und ohne den Wert.
    Werte mit gültigem UTF-8 (auch Emojis) und Werte unter 6 Zeichen bleiben unberührt."""
    z = {"env": ["POC_TOKEN=poc-dummy-\udc80xyz", "KURZ=\udc80", "GUT=poc-dummy-ä😀"], "modell_mock": ["openai"]}
    with pytest.raises(poc.PocFehler) as e:
        poc._maskier_werte(z)
    assert e.value.code == 2 and "POC_TOKEN" in str(e.value) and "xyz" not in str(e.value) and "KURZ" not in str(e.value)
    ok = poc._maskier_werte({"env": ["KURZ=\udc80", "GUT=poc-dummy-ä😀"], "modell_mock": []})
    assert json.loads(ok)["werte"] == [{"name": "GUT", "wert": "poc-dummy-ä😀"}]


@pytest.mark.parametrize("args", [("--env", "POC_TOKEN=poc-dummy-\udc80xyz"), ("--seed", "node seed.js \udc80xyz")])
def test_starten_ungueltiges_utf8_im_argument_exit2_ohne_traceback_haertung(umg, tmp_path, args):
    """Härtung (Frage 5): Ein Argument mit ungültigem UTF-8 (argv-Surrogat) endete bisher mit einem Traceback (Exit 1) beim Schreiben der
    Rollendatei, mitten in `starten`. Jetzt weist `argparse` es mit Exit 2 ab, ohne Docker-Aufruf und ohne das Argument zu nennen."""
    vorbereitet(umg, tmp_path)
    r = starten(umg, "--modell-mock", "openai", *args)
    assert r.returncode == 2 and "Traceback" not in r.stderr and "UTF-8" in r.stderr, r.stderr
    assert "xyz" not in r.stderr and umg.aufrufe() == []


def test_modell_protokoll_werte_gesamt_zu_gross_exit2(umg, tmp_path):
    """Der Mock liest höchstens 64 KiB stdin: passt die Werteliste nicht hinein, bricht `modell` ab, statt Werte wegzulassen."""
    envs = [a for i in range(20) for a in ("--env", f"G{i:02d}=" + chr(97 + i) * 4000)]
    mit_mock(umg, tmp_path, *envs)
    r = modell(umg, "--protokoll")
    assert r.returncode == 2 and "64 KiB" in r.stderr and "xxxx" not in r.stderr, r.stderr
    assert exec_aufrufe(umg) == []


def test_modell_argumente(umg, tmp_path):
    for args in (["--lauf", "xyz", "--rolle", "p1", "--protokoll"], ["--lauf", LAUF, "--rolle", "p3", "--protokoll"],
                 ["--lauf", LAUF, "--protokoll"], ["--rolle", "p1", "--protokoll"]):
        assert umg.poc("modell", *args).returncode == 2, args
    assert umg.aufrufe() == []


def test_poc_docstring_nennt_modell():
    zeile = next(z for z in poc.__doc__.splitlines() if z.lstrip().startswith("python3 -I poc.py"))
    assert " modell " in zeile, zeile


# --- Ende zu Ende: poc.py modell gegen den echten Mock (lokal mit Node) --------------------------------------------

ATTRAPPE = """#!{python}
import os, sys
args = sys.argv[1:]
# erwartet: exec -i <name> node /poc/llm-mock.mjs <modus …> --steuer-port 4011; ersetzt sich durch den lokalen Mock-Client
if args[:2] != ["exec", "-i"] or args[3:5] != ["node", "/poc/llm-mock.mjs"] or args[-2:] != ["--steuer-port", "4011"]:
    sys.stderr.write("attrappe: unerwarteter Aufruf\\n")
    sys.exit(99)
os.execvp("node", ["node", {mock!r}, *args[5:-1], os.environ["ATTRAPPE_STEUER_PORT"]])
"""


class LokalerMock:
    """Der echte Mock (`docker/llm-mock.mjs --server`) auf 127.0.0.1, Ports frei (0), als eigene Prozessgruppe.
    Beendet wird nur der eigene Popen, und nur solange er läuft."""

    def __init__(self):
        self.p = subprocess.Popen(["node", os.path.join(SKILL, "docker", "llm-mock.mjs"), "--server", "--host", "127.0.0.1",
                                   "--port", "0", "--steuer-port", "0"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            bereit, _, _ = select.select([self.p.stdout], [], [], 10)
            assert bereit, "Mock meldet sich nicht"
            m = re.fullmatch(r"bereit api=(\d+) steuer=(\d+)", self.p.stdout.readline().decode().strip())
            assert m, "bereit-Zeile fehlt"
            self.api, self.steuer = int(m.group(1)), int(m.group(2))
        except BaseException:
            self.beenden()
            raise

    def beenden(self):
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGTERM)
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if self.p.poll() is None:
                os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait(timeout=10)
        self.p.stdout.close()

    def post(self, pfad, objekt):
        c = http.client.HTTPConnection("127.0.0.1", self.api, timeout=10)
        try:
            c.request("POST", pfad, json.dumps(objekt), {"content-type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()


@pytest.mark.skipif(shutil.which("node") is None, reason="node fehlt")
def test_modell_protokoll_maskierung_ende_zu_ende(umg, tmp_path):
    """B1/K7: `poc.py modell` gegen den echten Mock. Die Docker-Attrappe ersetzt sich per `os.execvp` durch `node llm-mock.mjs` und
    reicht stdin durch. Der `--env`-Wert erscheint im Protokoll weder roh noch JSON-escaped noch doppelt escaped."""
    geheim = 'poc-dummy-a"b\\c'                                       # Anführungszeichen und Rückstrich: die escapten Formen weichen ab
    json_form = json.dumps(geheim)[1:-1]
    doppelt = json.dumps(json_form)[1:-1]
    assert len({geheim, json_form, doppelt}) == 3
    mit_mock(umg, tmp_path, "--env", f"X_TOKEN={geheim}")
    mock = LokalerMock()
    try:
        attrappe = umg.bin / "docker"
        attrappe.write_text(ATTRAPPE.format(python=sys.executable, mock=os.path.join(SKILL, "docker", "llm-mock.mjs")))
        attrappe.chmod(0o755)
        env = umg.env(ATTRAPPE_STEUER_PORT=str(mock.steuer))
        r = modell(umg, "--antworten-datei", antworten_datei(tmp_path, [{"text": "mock-antwort-e2e", "wenn_enthaelt": "POCMARKER-e2e-1"}]),
                   env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout == "modell: 1 Antworten gesetzt (Rolle p1)\n"
        inhalt = f"POCMARKER-e2e-1 token={geheim} key=poc-dummy-openai werkzeug={json.dumps({'k': geheim})}"
        status, antwort = mock.post("/v1/chat/completions", {"model": "m", "messages": [{"role": "user", "content": inhalt}]})
        assert status == 200 and antwort["choices"][0]["message"]["content"] == "mock-antwort-e2e", antwort
        for suche in ([], ["--suche", "POCMARKER-e2e-1"]):
            r = modell(umg, "--protokoll", *suche, env=env)
            assert r.returncode == 0, r.stdout + r.stderr
            for form in (geheim, json_form, doppelt, "poc-dummy-openai"):
                assert form not in r.stdout, form
            daten = json.loads(r.stdout)
            assert daten["gekuerzt"] == 0 and len(daten["eintraege"]) == 1
            body = daten["eintraege"][0]["body"]
            assert "<ENV:X_TOKEN>" in body and "<ENV:OPENAI_API_KEY>" in body and "POCMARKER-e2e-1" in body
            assert body.count("<ENV:X_TOKEN>") == 2                               # Rohform des Tokens und die im Werkzeug-JSON
            erwartet = {"model": "m", "messages": [{"role": "user", "content": 'POCMARKER-e2e-1 token=<ENV:X_TOKEN> key=<ENV:OPENAI_API_KEY> '
                                                                              'werkzeug={"k": "<ENV:X_TOKEN>"}'}]}
            assert body == json.dumps(erwartet), body                                 # E4: kein Rest des Werts, auch kein einzelnes Zeichen
            for i in range(len(geheim) - 3):                                          # und kein Teilstück ab 4 Zeichen im Protokoll
                assert geheim[i:i + 4] not in r.stdout and json_form[i:i + 4] not in r.stdout, geheim[i:i + 4]
            for form in (geheim, json_form, doppelt):
                assert form not in body, form
            if suche:
                assert "<ENV:X_TOKEN>" in daten["eintraege"][0]["fundstelle"]
        r = modell(umg, "--protokoll", "--suche", "POCMARKER-nicht-da", env=env)
        assert r.returncode == 0 and json.loads(r.stdout)["eintraege"] == []
    finally:
        mock.beenden()
