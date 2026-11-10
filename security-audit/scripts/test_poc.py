"""Tests für poc.py (Docker-PoC) mit Fake-`docker` im Shim-PATH; kein echtes Docker nötig.

Aufruf: python3 -m pytest security-audit/scripts/test_poc.py -q
Der Fake protokolliert jeden Aufruf (Argumente, stdin) als JSON-Zeile und liefert Ausgaben aus einer
Konfigurationsdatei (Schlüssel: die ersten zwei Argumente, sonst das erste). Alles liegt in tmp_path.
"""
import json
import os
import re
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
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "HOME": str(self.home),
               "TMPDIR": str(self.tmp), "FAKE_DOCKER_LOG": str(self.log_datei),
               "FAKE_DOCKER_CONFIG": str(self.config_datei), "GIT_CONFIG_NOSYSTEM": "1"}
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
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", lambda repo, ziel: [
        "Namenskollision: a", "Arbeitskopie unvollständig: git cat-file abgebrochen bei x (boom)"])
    repo = tmp_path / "r"
    repo.mkdir()
    assert poc.main(["vorbereiten", "--lauf", LAUF, "--repo", str(repo)]) == 4
    aus = capsys.readouterr()
    assert aus.out.splitlines()[0] == "kategorie: arbeitskopie-unvollstaendig"
    assert "Arbeitskopie unvollständig" in aus.err


def test_vorbereiten_git_fehler(temp_ordner, tmp_path, monkeypatch, capsys):
    def kaputt(repo, ziel):
        raise gitkopie.GitFehler("git ls-tree fehlgeschlagen (Exit 128): kein HEAD")
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", kaputt)
    repo = tmp_path / "r"
    repo.mkdir()
    assert poc.main(["vorbereiten", "--lauf", LAUF, "--repo", str(repo)]) == 4
    aus = capsys.readouterr()
    assert aus.out.splitlines()[0] == "kategorie: git-fehler"
    assert "kein HEAD" in aus.err


def test_vorbereiten_meldungen_nur_auf_stderr(temp_ordner, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(poc.gitkopie, "arbeitskopie", lambda repo, ziel: ["Symlink übersprungen: x"])
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
    assert ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db"] in aufrufe  # eigene Reste


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
    assert ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db"] in aufrufe[:erster_run]


def test_starten_netz_existiert_schon(umg, tmp_path):
    vorbereitet(umg, tmp_path)
    umg.konfig({"network create": {"rc": 1, "stderr": "Error response from daemon: network with name x already exists"}})
    assert umg.poc("starten", "--lauf", LAUF, "--rolle", "p1", "--start-befehl", "x", "--port", "1").returncode == 0


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
    assert aufrufe[1] == ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db"]
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
    rm = ["rm", "-f", "-v", f"security-audit-{LAUF}-p1-app", f"security-audit-{LAUF}-p1-db"]
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
