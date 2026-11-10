"""Docker-Integrationstests für poc.py (echtes Docker).

Aufruf: SECURITY_AUDIT_DOCKER=1 python3 -m pytest security-audit/scripts/test_poc_docker.py -q
Ohne die Umgebungsvariable werden alle Tests übersprungen. Der Zustandsordner liegt unter tmp_path (TMPDIR);
HOME bleibt unverändert, weil die docker-CLI ihre Konfiguration und Plugins (buildx) dort sucht.
Alle Docker-Ressourcen tragen den Präfix security-audit-<lauf>; die Fixture räumt per `aufraeumen` auf.
"""
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("SECURITY_AUDIT_DOCKER") != "1",
                                reason="echtes Docker: SECURITY_AUDIT_DOCKER=1 setzen")

HIER = os.path.dirname(os.path.abspath(__file__))
POC = os.path.join(HIER, "poc.py")

SERVER_JS = """\
const http = require('http');
http.createServer((q, r) => {
  const teile = [];
  q.on('data', (t) => teile.push(t));
  q.on('end', () => {
    r.setHeader('content-type', 'text/plain');
    r.end(`hallo ${q.method} ${q.url} ${Buffer.concat(teile).toString()}`);
  });
}).listen(Number(process.env.PORT), process.env.HOST);
"""


def docker(*args, timeout=120):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def praefix_reste(lauf):
    muster = re.compile(r"/?security-audit-" + lauf + r"(-.*)?")
    reste = []
    for art, args in (("container", ["ps", "-a", "--format", "{{.Names}}"]),
                      ("netz", ["network", "ls", "--format", "{{.Name}}"]),
                      ("image", ["images", "--format", "{{.Repository}}"])):
        for name in docker(*args).stdout.split():
            if muster.fullmatch(name):
                reste.append((art, name))
    return reste


class Stack:
    def __init__(self, lauf, tmp, repo):
        self.lauf = lauf
        self.tmp = tmp
        self.repo = repo
        # SECURITY_AUDIT_OHNE=gitleaks: `bauen` verlangt sonst den Schwärzungs-Marker (setzt `lieferkette.py secrets`)
        self.env = dict(os.environ, TMPDIR=str(tmp), SECURITY_AUDIT_OHNE="gitleaks")
        self.netz = f"security-audit-{lauf}-p1"
        self.image = f"security-audit-{lauf}-app"

    def poc(self, *args, timeout=900):
        return subprocess.run([sys.executable, "-I", POC, *args], env=self.env, capture_output=True, text=True,
                              timeout=timeout)

    def lauf_args(self, *args):
        return [args[0], "--lauf", self.lauf, *args[1:]]

    def probe(self, netz, js, *args):
        """Node-Probe im Container des App-Images direkt per docker run (kein Testmodus in poc.py)."""
        r = docker("run", "--rm", "--network", netz, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   self.image, "node", "-e", js, *args, timeout=90)
        return r.stdout.strip()


TCP_PROBE = """
const net = require('net');
const [host, port] = process.argv.slice(1);
const s = net.connect({host, port: Number(port)});
s.setTimeout(4000);
s.on('connect', () => { console.log('ok'); process.exit(0); });
s.on('timeout', () => { console.log('fail'); process.exit(0); });
s.on('error', () => { console.log('fail'); process.exit(0); });
"""

DNS_PROBE = """
require('dns').lookup('example.com', (e) => { console.log(e ? 'fail' : 'ok'); process.exit(0); });
setTimeout(() => { console.log('fail'); process.exit(0); }, 8000);
"""


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("zustand")
    repo = tmp_path_factory.mktemp("kunde") / "mini"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({"name": "mini", "version": "1.0.0",
                                                    "scripts": {"start": "node server.js"}}))
    (repo / "package-lock.json").write_text(json.dumps({"name": "mini", "version": "1.0.0", "lockfileVersion": 3,
                                                         "requires": True, "packages": {"": {"name": "mini", "version": "1.0.0"}}}))
    (repo / "server.js").write_text(SERVER_JS)
    git_env = {"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    for args in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@t",
                                                  "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, env=git_env, capture_output=True)
    s = Stack(secrets.token_hex(4), tmp, str(repo))
    try:
        yield s
    finally:
        s.poc("aufraeumen", "--lauf", s.lauf, timeout=300)


@pytest.fixture(scope="module")
def host_listener():
    """TCP-Listener auf dem Host (127.0.0.1), den kein Container erreichen darf (außer der Positivkontrolle)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def annehmen():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                pass

    t = threading.Thread(target=annehmen, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    t.join()
    srv.close()


def test_01_vorbereiten_bauen_starten_anfrage(stack):
    r = stack.poc("vorbereiten", "--lauf", stack.lauf, "--repo", stack.repo)
    assert r.returncode == 0, r.stderr
    r = stack.poc("bauen", "--lauf", stack.lauf, "--node", "22", "--build-befehl", "cat /proc/net/dev > /app/.netz")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"image: {stack.image}" in r.stdout
    r = stack.poc("starten", "--lauf", stack.lauf, "--rolle", "p1", "--start-befehl", "node server.js", "--port", "3000")
    assert r.returncode == 0, r.stdout + r.stderr
    r = stack.poc("anfrage", "--lauf", stack.lauf, "--rolle", "p1", "--pfad", "/x?url=http://127.0.0.1/")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.startswith("status: 200\n")
    assert "hallo GET /x?url=http://127.0.0.1/" in r.stdout


def test_02_anfrage_methode_header_daten(stack, tmp_path):
    datei = tmp_path / "body.txt"
    datei.write_text("a=1&url=http://127.0.0.1/ ä")
    r = stack.poc("anfrage", "--lauf", stack.lauf, "--rolle", "p1", "--methode", "POST", "--pfad", "/p",
                  "--header", "Content-Type: text/plain", "--daten-datei", str(datei))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "status: 200" in r.stdout and "hallo POST /p a=1&url=http://127.0.0.1/ ä" in r.stdout
    r = stack.poc("anfrage", "--lauf", stack.lauf, "--rolle", "p1", "--methode", "POST", "--pfad", "/q", "--daten", "direkt")
    assert "hallo POST /q direkt" in r.stdout


def test_03_anfrage_ungueltiger_pfad(stack):
    r = stack.poc("anfrage", "--lauf", stack.lauf, "--rolle", "p1", "--pfad", "http://example.com/")
    assert r.returncode == 2


def test_04_container_haertung(stack):
    app = f"security-audit-{stack.lauf}-p1-app"
    info = json.loads(docker("inspect", app).stdout)[0]
    host = info["HostConfig"]
    assert host["CapDrop"] == ["ALL"] and "no-new-privileges" in " ".join(host["SecurityOpt"])
    assert host["Memory"] == 1024 ** 3 and host["PidsLimit"] == 256
    assert not host.get("Binds") and not host.get("PortBindings")
    assert list(info["NetworkSettings"]["Networks"]) == [stack.netz]
    assert docker("network", "inspect", stack.netz, "--format", "{{.Internal}}").stdout.strip() == "true"
    assert info["Config"]["User"] == "node"


def test_05_host_und_internet_nicht_erreichbar(stack, host_listener):
    port = str(host_listener)
    # Positivkontrollen: die Probe funktioniert, wo eine Verbindung möglich ist.
    assert stack.probe("bridge", TCP_PROBE, "host.docker.internal", port) == "ok", \
        "Positivkontrolle: Host-Listener muss aus dem Default-Bridge-Netz per host.docker.internal erreichbar sein"
    assert stack.probe(stack.netz, TCP_PROBE, "app", "3000") == "ok"
    # Im internen Netz der Rolle: nichts davon.
    assert stack.probe(stack.netz, TCP_PROBE, "host.docker.internal", port) == "fail"
    assert stack.probe(stack.netz, TCP_PROBE, "1.1.1.1", "443") == "fail"
    assert stack.probe(stack.netz, DNS_PROBE) == "fail"


def test_06_build_ohne_netz(stack):
    r = stack.poc("ausfuehren", "--lauf", stack.lauf, "--rolle", "p1", "--", "cat", "/app/.netz")
    assert r.returncode == 0, r.stdout + r.stderr
    echte = ("eth", "en", "wl", "veth", "br", "docker", "tun0", "wg")

    def schnittstellen(text):
        return {z.split(":")[0].strip() for z in text.splitlines() if ":" in z and "|" not in z}

    # Der Build-Schritt sah nur Loopback (der Kernel listet daneben unkonfigurierte Tunnel-Fallbackgeräte
    # wie tunl0/gre0, die ohne Konfiguration nichts erreichen).
    nur = schnittstellen(r.stdout)
    assert "lo" in nur and not [n for n in nur if n.startswith(echte)], r.stdout
    # Positivkontrolle: im Laufzeit-Netz hat derselbe Befehl eine echte Schnittstelle.
    laufzeit = docker("run", "--rm", "--network", "bridge", stack.image, "cat", "/proc/net/dev")
    assert [n for n in schnittstellen(laufzeit.stdout) if n.startswith("eth")], laufzeit.stdout


def test_07_anfrage_programm_gehoert_root(stack):
    r = stack.poc("ausfuehren", "--lauf", stack.lauf, "--rolle", "p1", "--", "stat", "-c", "%U %a", "/poc/anfrage.mjs")
    assert r.stdout.strip() == "root 644", r.stdout + r.stderr


def test_08_zweite_rolle_mit_postgres_und_neustart(stack):
    r = stack.poc("starten", "--lauf", stack.lauf, "--rolle", "p2", "--start-befehl", "node server.js", "--port", "3000",
                  "--dienst", "postgres", "--seed", "echo seed > /tmp/seed.txt",
                  "--env", "DATABASE_URL=postgres://poc:poc@db:5432/poc")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "postgres://poc:poc@db:5432/poc" in r.stdout
    p2 = f"security-audit-{stack.lauf}-p2"
    assert docker("network", "inspect", p2, "--format", "{{.Internal}}").stdout.strip() == "true"
    r = stack.poc("ausfuehren", "--lauf", stack.lauf, "--rolle", "p2", "--", "cat", "/tmp/seed.txt")
    assert r.stdout.strip() == "seed"
    assert stack.probe(p2, TCP_PROBE, "db", "5432") == "ok"
    assert stack.probe(stack.netz, TCP_PROBE, "db", "5432") == "fail"      # p1 sieht die DB von p2 nicht
    assert stack.probe(stack.netz, TCP_PROBE, f"{p2}-app", "3000") == "fail"
    # Datenbank-Container: nur no-new-privileges, Speicher- und Prozessgrenze.
    db = json.loads(docker("inspect", f"{p2}-db").stdout)[0]["HostConfig"]
    assert db["Memory"] == 512 * 1024 ** 2 and db["PidsLimit"] == 256 and not db["CapDrop"]
    # neustart: neue Container, Anfrage geht wieder.
    vorher = docker("inspect", "-f", "{{.Id}}", f"{p2}-app").stdout.strip()
    r = stack.poc("neustart", "--lauf", stack.lauf, "--rolle", "p2")
    assert r.returncode == 0, r.stdout + r.stderr
    assert docker("inspect", "-f", "{{.Id}}", f"{p2}-app").stdout.strip() != vorher
    r = stack.poc("anfrage", "--lauf", stack.lauf, "--rolle", "p2", "--pfad", "/")
    assert "status: 200" in r.stdout


def test_09_start_fehler_kategorie(stack):
    r = stack.poc("starten", "--lauf", stack.lauf, "--rolle", "p1", "--start-befehl", "node gibt-es-nicht.js",
                  "--port", "3000", timeout=300)
    assert r.returncode == 4
    assert r.stdout.splitlines()[0] == "kategorie: start-fehler"
    assert "gibt-es-nicht" in r.stdout
    # Netz der Rolle bleibt, Container sind entfernt.
    assert docker("ps", "-a", "--filter", f"name=security-audit-{stack.lauf}-p1-app", "--format", "{{.Names}}").stdout.strip() == ""


def test_10_aufraeumen(stack):
    assert praefix_reste(stack.lauf) != []
    for _ in range(2):
        r = stack.poc("aufraeumen", "--lauf", stack.lauf, timeout=300)
        assert r.returncode == 0, r.stdout + r.stderr
    assert praefix_reste(stack.lauf) == []
    assert not os.path.exists(os.path.join(os.path.realpath(stack.tmp), f"security-audit-{stack.lauf}"))


MS_LOCK = {"name": "dep", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "dep", "version": "1.0.0", "dependencies": {"ms": "2.1.3"}},
    "node_modules/ms": {"version": "2.1.3", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
                        "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="}}}


def test_11_kunden_dockerignore_und_node_modules(tmp_path_factory):
    """T3-I1: Eine Kunden-`.dockerignore` (`*`) darf Dockerfile/Lockfile nicht aussperren, getrackte
    `node_modules` kommen nicht ins Image, die Abhängigkeiten stammen aus `npm ci`."""
    tmp = tmp_path_factory.mktemp("zustand-ignore")
    repo = tmp_path_factory.mktemp("kunde-ignore") / "dep"
    (repo / "src").mkdir(parents=True)
    (repo / "node_modules" / "marker").mkdir(parents=True)
    (repo / "node_modules" / "marker" / "index.js").write_text("// getrackt, darf nicht im Image landen\n")
    (repo / ".dockerignore").write_text("*\n!src\n")
    (repo / "src" / "server.js").write_text(SERVER_JS)
    (repo / "package.json").write_text(json.dumps({"name": "dep", "version": "1.0.0", "dependencies": {"ms": "2.1.3"}}))
    (repo / "package-lock.json").write_text(json.dumps(MS_LOCK))
    git_env = {"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    for args in (["init", "-q"], ["add", "-A", "-f"], ["-c", "user.name=t", "-c", "user.email=t@t",
                                                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, env=git_env, capture_output=True)
    s = Stack(secrets.token_hex(4), tmp, str(repo))
    try:
        assert s.poc("vorbereiten", "--lauf", s.lauf, "--repo", s.repo).returncode == 0
        quelle = os.path.join(os.path.realpath(tmp), f"security-audit-{s.lauf}", "quelle")
        assert os.path.isdir(os.path.join(quelle, "node_modules", "marker"))  # Kopie hat sie, der Kontext nicht
        r = s.poc("bauen", "--lauf", s.lauf, "--node", "22")
        assert r.returncode == 0, r.stdout + r.stderr
        r = s.poc("starten", "--lauf", s.lauf, "--rolle", "p1", "--start-befehl", "node src/server.js", "--port", "3000")
        assert r.returncode == 0, r.stdout + r.stderr
        r = s.poc("ausfuehren", "--lauf", s.lauf, "--rolle", "p1", "--", "ls", "node_modules")
        assert r.returncode == 0, r.stdout + r.stderr
        assert r.stdout.split() == ["ms"], r.stdout
        r = s.poc("ausfuehren", "--lauf", s.lauf, "--rolle", "p1", "--", "ls", "-a", ".")
        # Die Kunden-`.dockerignore` (`*`) war nicht wirksam: sonst fehlten package.json und Lockfile im Kontext.
        assert "src" in r.stdout.split() and "package-lock.json" in r.stdout.split()
    finally:
        s.poc("aufraeumen", "--lauf", s.lauf, timeout=300)
    assert praefix_reste(s.lauf) == []
