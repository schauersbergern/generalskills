"""Tests für `lieferkette.py abhaengigkeiten` (TF2, Task 2).

Aufruf: python3 -m pytest security-audit/scripts/test_lieferkette_abh.py -q

Ein Fake-`osv-scanner` im Shim-PATH protokolliert jeden Aufruf (Argumente, cwd, Ordnerinhalt neben dem Lockfile, Umgebung) und
liefert Antworten im JSON-Format von osv-scanner 2.6 aus einer Konfigurationsdatei. Es gibt kein Netz in diesen Tests: die
autouse-Fixture setzt `SECURITY_AUDIT_KEV_DATEI` auf eine lokale Fake-Datei und sperrt `urllib.request.urlopen` im Testprozess.
Lockfiles und alle Testdaten entstehen zur Laufzeit in tmp_path (keine Lockfiles mit verwundbaren Versionen im Repo). Der Test
mit dem echten osv-scanner läuft nur mit `SECURITY_AUDIT_NETZ=1`. Signale gehen nur an Prozessgruppen, die der getestete Code
selbst gestartet hat; die Tests enthalten keine Kill-Logik.
"""
import http.server
import io
import json
import re
import os
import threading
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import lieferkette  # noqa: E402

LIEFERKETTE = os.path.join(HIER, "lieferkette.py")
LAUF = "0a1b2c3d"
NETZ = os.environ.get("SECURITY_AUDIT_NETZ") == "1"      # vor der autouse-Fixture lesen
ECHTES_URLOPEN = urllib.request.urlopen                  # die autouse-Fixture sperrt `urlopen`; nur Loopback-Tests nutzen das Original
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_UA = "security-audit/1 (+https://github.com/schauersbergern/generalskills)"

FAKE_OSV = '''#!{python}
import hashlib, json, os, sys, time
args = sys.argv[1:]
cfg = json.load(open(os.environ["FAKE_OSV_CONFIG"]))
log = os.environ["FAKE_OSV_LOG"]
n = len(open(log).read().splitlines()) if os.path.exists(log) else 0
antworten = cfg.get("antworten", [])
antwort = antworten[n] if n < len(antworten) else cfg.get("standard", {{"rc": 0}})
lockfile = args[args.index("--lockfile") + 1] if "--lockfile" in args else None
ordner = os.path.dirname(lockfile) if lockfile else None
eintrag = {{
    "args": args, "cwd": os.getcwd(), "cwd_leer": not os.listdir(os.getcwd()), "lockfile": lockfile,
    "name": os.path.basename(lockfile) if lockfile else None, "ordner": ordner,
    "ordner_inhalt": sorted(os.listdir(ordner)) if ordner and os.path.isdir(ordner) else None,
    "toml_im_cwd": os.path.exists(os.path.join(os.getcwd(), "osv-scanner.toml")),
    "toml_beim_lockfile": bool(ordner) and os.path.exists(os.path.join(ordner, "osv-scanner.toml")),
    "env": {{k: v for k, v in os.environ.items() if k.startswith(("GITLEAKS_", "GIT_", "OSV_"))}},
    "sha": hashlib.sha256(open(lockfile, "rb").read()).hexdigest() if lockfile and os.path.isfile(lockfile) else None,
}}
with open(log, "a") as f:
    f.write(json.dumps(eintrag) + "\\n")
if antwort.get("sleep"):
    time.sleep(antwort["sleep"])
sys.stderr.write(antwort.get("stderr", ""))
if "roh" in antwort:
    sys.stdout.write(antwort["roh"])
elif "stdout" in antwort:
    sys.stdout.write(json.dumps(antwort["stdout"]))
sys.exit(antwort.get("rc", 0))
'''


# ------------------------------------------------------------------------------------ Bausteine

def vuln(name, id_="GHSA-test-0001", aliase=(), zusammenfassung="Zusammenfassung", details="Details", bereiche=(("0", "9.9.9"),),
         **extra):
    """OSV-Eintrag wie osv-scanner 2.6 ihn ausgibt; `bereiche`: (introduced, fixed|None) je Versionslinie."""
    ranges = [{"type": "SEMVER", "events": [{"introduced": von}] + ([{"fixed": fix}] if fix else [])} for von, fix in bereiche]
    d = {"id": id_, "aliases": list(aliase), "summary": zusammenfassung, "details": details, "modified": "2026-01-01T00:00:00Z",
         "affected": [{"package": {"ecosystem": "npm", "name": name, "purl": f"pkg:npm/{name}"}, "ranges": ranges}]}
    d.update(extra)
    return d


def osv_ausgabe(*pakete):
    """pakete: (name, version, [vuln, ...]) -> JSON-Struktur wie `osv-scanner scan source --format json`."""
    return {"results": [{"source": {"path": "/x/package-lock.json", "type": "lockfile"},
                         "packages": [{"package": {"name": n, "version": v, "ecosystem": "npm"}, "vulnerabilities": vs,
                                       "groups": [{"ids": [x["id"] for x in vs]}]} for n, v, vs in pakete]}],
            "experimental_config": {}}


def npm_lock(*pakete, v1=False):
    """pakete: (schluessel, version, dev) -> package-lock.json-Text (lockfileVersion 3); mit v1 das alte `dependencies`-Format."""
    if v1:
        deps = {k.rsplit("node_modules/", 1)[-1]: dict(version=v, **({"dev": True} if dev else {})) for k, v, dev in pakete}
        return json.dumps({"name": "x", "lockfileVersion": 1, "dependencies": deps}, indent=2) + "\n"
    pk = {"": {"name": "x", "version": "1.0.0"}}
    for k, v, dev in pakete:
        pk[k] = dict(version=v, **({"dev": True} if dev else {}))
    return json.dumps({"name": "x", "lockfileVersion": 3, "packages": pk}, indent=2) + "\n"


KEV_KATALOG = {"title": "Fake KEV", "vulnerabilities": [{"cveID": "CVE-2099-0001"}, {"cveID": "CVE-2099-0002"}]}


class Umgebung:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.log = tmp_path / "osv.log"
        self.config = tmp_path / "osv.json"
        self.config.write_text("{}")
        self.kev = tmp_path / "kev.json"
        self.kev.write_text(json.dumps(KEV_KATALOG))
        os.makedirs(self.zustand(), mode=0o700)
        os.makedirs(self.quelle())
        open(os.path.join(self.zustand(), "quelle.fertig"), "w").close()

    def env(self, **extra):
        env = {"PATH": str(self.bin), "HOME": str(self.home), "TMPDIR": str(self.tmp),
               "FAKE_OSV_LOG": str(self.log), "FAKE_OSV_CONFIG": str(self.config), "SECURITY_AUDIT_KEV_DATEI": str(self.kev),
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        env.update(extra)
        return env

    def zustand(self):
        return os.path.join(os.path.realpath(self.tmp), f"security-audit-{LAUF}")

    def quelle(self):
        return os.path.join(self.zustand(), "quelle")

    def lk(self):
        return os.path.join(self.zustand(), "lieferkette")

    def fake_osv(self, *antworten, standard=None):
        fake = self.bin / "osv-scanner"
        fake.write_text(FAKE_OSV.format(python=sys.executable))
        fake.chmod(0o755)
        cfg = {"antworten": list(antworten)}
        if standard is not None:
            cfg["standard"] = standard
        self.config.write_text(json.dumps(cfg))
        if self.log.exists():
            self.log.unlink()                    # neue Antworten, neues Protokoll (die Antwort richtet sich nach der Aufrufnummer)

    def schreibe(self, rel, inhalt):
        ziel = os.path.join(self.quelle(), rel)
        os.makedirs(os.path.dirname(ziel), exist_ok=True)
        with open(ziel, "wb") as f:
            f.write(inhalt if isinstance(inhalt, bytes) else inhalt.encode())

    def aufrufe(self):
        if not self.log.exists():
            return []
        return [json.loads(z) for z in self.log.read_text().splitlines() if z]

    def abh(self, *extra, env=None, quelle=None, timeout=120):
        return subprocess.run([sys.executable, "-I", LIEFERKETTE, "abhaengigkeiten", "--lauf", LAUF, "--quelle",
                               quelle or self.quelle(), *extra], env=env or self.env(), capture_output=True, text=True,
                              timeout=timeout)

    def lk_inhalt(self):
        return sorted(os.listdir(self.lk())) if os.path.isdir(self.lk()) else []


@pytest.fixture
def umg(tmp_path):
    return Umgebung(tmp_path)


@pytest.fixture(autouse=True)
def hermetisch(tmp_path, monkeypatch):
    """Kein Netz, keine geerbten Variablen: lokale KEV-Datei, `urlopen` gesperrt, eigenes HOME."""
    home = tmp_path / "home-inproc"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in list(os.environ):
        if name.startswith(("GIT_", "GITLEAKS_", "OSV_", "SECURITY_AUDIT_")):
            monkeypatch.delenv(name)
    kev = tmp_path / "kev-inproc.json"
    kev.write_text(json.dumps(KEV_KATALOG))
    monkeypatch.setenv("SECURITY_AUDIT_KEV_DATEI", str(kev))

    def gesperrt(*a, **k):
        raise AssertionError("Netzzugriff im Unit-Test")
    monkeypatch.setattr(urllib.request, "urlopen", gesperrt)


def ausgabe(r):
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)


def je_paket(out):
    return {(p["paket"], p["version"], p["lockfile"]): p for p in out["pakete"]}


# ------------------------------------------------------------------------------------ semver und behoben_in

@pytest.mark.parametrize("a,b,erwartet", [
    ("1.2.3", "1.2.3", 0), ("1.2.3", "1.2.4", -1), ("1.10.0", "1.9.9", 1), ("2.0.0", "10.0.0", -1),
    ("0", "0.0.1", -1), ("1.2", "1.2.0", 0), ("v1.2.3", "1.2.3", 0),
    ("1.0.0-alpha", "1.0.0", -1), ("1.0.0", "1.0.0-rc.1", 1), ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1), ("1.0.0-beta.2", "1.0.0-beta.11", -1), ("1.0.0-rc.1", "1.0.0-beta.11", 1),
    ("1.0.0+build1", "1.0.0+build2", 0),
])
def test_semver_vergleich(a, b, erwartet):
    assert lieferkette.semver_vergleich(a, b) == erwartet
    assert lieferkette.semver_vergleich(b, a) == -erwartet


def test_semver_vergleich_unparsebare_versionen_werfen_nicht():
    assert lieferkette.semver_vergleich("abc", "abc") == 0
    assert lieferkette.semver_vergleich("1.0.0.1", "1.0.0.2") == -1
    assert lieferkette.semver_vergleich("2023-01-05", "2022-12-31") == 1


def test_semver_vergleich_riesige_ziffern():
    """Ziffernblöcke jenseits des int-Limits (Python >= 3.11: 4300 Stellen) aus feindlichen Dateien: nie eine Ausnahme."""
    gross, klein = "1" * 5000, "1"
    assert lieferkette.semver_vergleich(gross + ".0.0", "1.0.0") == 1
    assert lieferkette.semver_vergleich("1.0.0", gross + ".0.0") == -1
    assert lieferkette.semver_vergleich(gross + ".0.0", gross + ".0.0") == 0
    assert lieferkette.semver_vergleich("9" * 5000 + ".0.0", "1" * 5001 + ".0.0") == -1       # kürzere Zahl ist kleiner
    assert lieferkette.semver_vergleich("1." + gross + ".0", "1." + gross + "0.0") == -1
    assert lieferkette.semver_vergleich("0" * 5000 + "7.0.0", "7.0.0") == 0                     # führende Nullen zählen nicht
    assert lieferkette.semver_vergleich("1.0.0-" + gross, "1.0.0-" + klein) == 1                # Vorabversion, Zahlenblock
    assert lieferkette.semver_vergleich("1.0.0-" + gross, "1.0.0-" + gross + "1") == -1
    assert lieferkette.semver_vergleich("1.0.0-" + gross, "1.0.0") == -1
    assert lieferkette.semver_vergleich("v" + gross + "x", "v" + klein + "x") == 1              # Notbehelf ohne Semver-Form
    assert lieferkette.semver_vergleich("a" + gross, "a" + gross) == 0
    assert lieferkette.semver_vergleich("1.0.0.1." + gross, "1.0.0.1.2") == 1
    for a, b in (("1" * 5000 + ".0.0", "1.0.0"), ("1.0.0-" + gross, "1.0.0-2"), ("a" + gross, "a2")):
        assert lieferkette.semver_vergleich(a, b) == -lieferkette.semver_vergleich(b, a)


def test_behoben_in_versionslinien():
    """Mehrere Versionslinien: die kleinste Fix-Version oberhalb der installierten Version im passenden Bereich, über mehrere
    Advisories das Maximum."""
    linien = vuln("lib", "A", bereiche=(("1.0.0", "1.5.3"), ("2.0.0", "2.4.1"), ("3.0.0", "3.0.9")))
    assert lieferkette.behoben_in([linien], "lib", "1.2.0") == "1.5.3"
    assert lieferkette.behoben_in([linien], "lib", "2.0.0") == "2.4.1"
    assert lieferkette.behoben_in([linien], "lib", "2.3.9") == "2.4.1"
    assert lieferkette.behoben_in([linien], "lib", "3.0.8") == "3.0.9"
    assert lieferkette.behoben_in([linien], "lib", "1.5.3") != "1.5.3"        # genau die Fix-Version ist nicht betroffen
    zweites = vuln("lib", "B", bereiche=(("0", "2.9.0"),))
    assert lieferkette.behoben_in([linien, zweites], "lib", "2.3.9") == "2.9.0"   # Maximum über die Advisories
    assert lieferkette.behoben_in([zweites, linien], "lib", "1.2.0") == "2.9.0"
    assert lieferkette.behoben_in([linien, zweites], "lib", "1.2.0") == "2.9.0"


def test_behoben_in_randfaelle():
    assert lieferkette.behoben_in([], "lib", "1.0.0") is None
    offen = vuln("lib", "A", bereiche=(("0", None),))                             # kein Fix bekannt
    assert lieferkette.behoben_in([offen], "lib", "1.0.0") is None
    assert lieferkette.behoben_in([offen, vuln("lib", "B", bereiche=(("0", "1.1.0"),))], "lib", "1.0.0") == "1.1.0"
    fremd = vuln("anderes", "C", bereiche=(("0", "5.0.0"),))                      # anderer Paketname: ignoriert
    assert lieferkette.behoben_in([fremd], "lib", "1.0.0") is None
    pypi = vuln("lib", "D")
    pypi["affected"][0]["package"]["ecosystem"] = "PyPI"                         # anderes Ökosystem: ignoriert
    assert lieferkette.behoben_in([pypi], "lib", "1.0.0") is None
    gemischt = vuln("lib", "E", bereiche=(("0", "1.2.0"),))
    gemischt["affected"].append({"package": {"ecosystem": "npm", "name": "anderes"},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "7.0.0"}]}]})
    assert lieferkette.behoben_in([gemischt], "lib", "1.0.0") == "1.2.0"          # nur der Eintrag mit genau diesem Namen
    git_bereich = vuln("lib", "F")
    git_bereich["affected"][0]["ranges"] = [{"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}]
    assert lieferkette.behoben_in([git_bereich], "lib", "1.0.0") is None
    kaputt = {"id": "G", "affected": "kein-array"}
    assert lieferkette.behoben_in([kaputt], "lib", "1.0.0") is None


def test_behoben_in_unsortierte_ereignisse_und_last_affected():
    unsortiert = vuln("lib", "A")
    unsortiert["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"fixed": "2.0.1"}, {"introduced": "2.0.0"},
                                                                         {"fixed": "1.0.5"}, {"introduced": "0"}]}]
    assert lieferkette.behoben_in([unsortiert], "lib", "0.9.0") == "1.0.5"
    assert lieferkette.behoben_in([unsortiert], "lib", "2.0.0") == "2.0.1"
    bis = vuln("lib", "B")
    bis["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.9.9"}]}]
    assert lieferkette.behoben_in([bis], "lib", "1.5.0") is None                  # nur last_affected: kein Fix bekannt


# ------------------------------------------------------------------------------------ Lockfiles und Advisories

def test_abhaengigkeiten_mehrere_lockfiles_und_advisories(umg):
    """Mehrere Lockfiles (npm, yarn, pnpm; node_modules wird ignoriert), mehrere Advisories je Paket: ein Eintrag je Paket."""
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False), ("node_modules/minimist", "1.2.5", False)))
    umg.schreibe("web/yarn.lock", '# yarn lockfile v1\n\nlodash@^4.17.15:\n  version "4.17.15"\n')
    umg.schreibe("api/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.10:\n    resolution: {integrity: x}\n")
    umg.schreibe("node_modules/x/package-lock.json", npm_lock(("node_modules/zzz", "1.0.0", False)))
    umg.schreibe("a/node_modules/y/yarn.lock", "zzz@1:\n  version \"1\"\n")
    lodash_a = vuln("lodash", "GHSA-aaaa", aliase=["CVE-2021-0001"], bereiche=(("0", "4.17.21"),))
    lodash_b = vuln("lodash", "GHSA-bbbb", aliase=["CVE-2020-0002"], bereiche=(("0", "4.17.19"),))
    mini = vuln("minimist", "GHSA-cccc", aliase=["CVE-2021-0003"], bereiche=(("1.0.0", "1.2.6"),))
    umg.fake_osv(
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.10", [lodash_a, lodash_b]))},          # api/pnpm-lock.yaml
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [lodash_a]), ("minimist", "1.2.5", [mini]))},   # package-lock.json
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.15", [lodash_a, lodash_b]))})          # web/yarn.lock
    out = ausgabe(umg.abh())
    assert len(umg.aufrufe()) == 3                                                  # genau die drei Lockfiles, nie node_modules
    pakete = je_paket(out)
    assert set(pakete) == {("lodash", "4.17.10", "api/pnpm-lock.yaml"), ("lodash", "4.17.20", "package-lock.json"),
                           ("minimist", "1.2.5", "package-lock.json"), ("lodash", "4.17.15", "web/yarn.lock")}
    p = pakete[("lodash", "4.17.10", "api/pnpm-lock.yaml")]
    assert [a["id"] for a in p["advisories"]] == ["GHSA-aaaa", "GHSA-bbbb"]         # ein Eintrag je Paket, nicht je Advisory
    assert p["advisories"][0]["aliase"] == ["CVE-2021-0001"]
    assert p["advisories"][0]["zusammenfassung"] == "Zusammenfassung" and p["advisories"][0]["details"] == "Details"
    assert p["behoben_in"] == "4.17.21"                                              # Maximum über beide Advisories
    assert pakete[("minimist", "1.2.5", "package-lock.json")]["behoben_in"] == "1.2.6"
    assert set(out) == {"pakete", "hinweise"}
    for p in out["pakete"]:
        assert set(p) == {"paket", "version", "lockfile", "zeile", "advisories", "behoben_in", "dev", "kev"}
        assert all(set(a) == {"id", "aliase", "zusammenfassung", "details"} for a in p["advisories"])


def test_abhaengigkeiten_gleiches_paket_mehrfach_wird_zusammengefuehrt(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    a, b = vuln("lodash", "A"), vuln("lodash", "B")
    ausgabe_osv = osv_ausgabe(("lodash", "4.17.20", [a]), ("lodash", "4.17.20", [a, b]))
    umg.fake_osv({"rc": 1, "stdout": ausgabe_osv})
    out = ausgabe(umg.abh())
    assert len(out["pakete"]) == 1 and [x["id"] for x in out["pakete"][0]["advisories"]] == ["A", "B"]


def test_abhaengigkeiten_lockfile_kopie_und_aufruf(umg):
    """Kopie in eigenem leerem Ordner unter `<zustand>/lieferkette/`, Dateiname wie das Original (K7), `--no-resolve`, cwd leer,
    bereinigte Umgebung, Original unverändert."""
    inhalt = npm_lock(("node_modules/lodash", "4.17.20", False))
    umg.schreibe("package-lock.json", inhalt)
    umg.schreibe("web/yarn.lock", "lodash@1:\n")
    umg.schreibe("web/npm-shrinkwrap.json", inhalt)
    umg.fake_osv({"rc": 0}, {"rc": 0}, {"rc": 0})
    env = umg.env(GITLEAKS_CONFIG="/x", OSV_SCANNER_CONFIG="/y", GIT_DIR="/z")
    out = ausgabe(umg.abh(env=env))
    aufrufe = umg.aufrufe()
    assert sorted(a["name"] for a in aufrufe) == ["npm-shrinkwrap.json", "package-lock.json", "yarn.lock"]
    for a in aufrufe:
        assert a["args"][:3] == ["scan", "source", "--lockfile"] and a["args"][3] == a["lockfile"]
        assert "--format" in a["args"] and a["args"][a["args"].index("--format") + 1] == "json"
        assert "--no-resolve" in a["args"]
        assert a["ordner_inhalt"] == [a["name"]]                                    # eigener Ordner, nur diese Datei
        assert os.path.realpath(a["ordner"]).startswith(os.path.realpath(umg.lk()) + os.sep)
        assert a["cwd_leer"] and os.path.realpath(a["cwd"]).startswith(os.path.realpath(umg.lk()) + os.sep)
        assert os.path.realpath(a["cwd"]) != os.path.realpath(a["ordner"])
        assert a["env"].get("GIT_CONFIG_NOSYSTEM") == "1" and "GITLEAKS_CONFIG" not in a["env"]
        assert "OSV_SCANNER_CONFIG" not in a["env"] and "GIT_DIR" not in a["env"]
    assert len({a["ordner"] for a in aufrufe}) == 3
    assert len({a["sha"] for a in aufrufe if a["name"] != "yarn.lock"}) == 1       # Kopie hat denselben Inhalt
    with open(os.path.join(umg.quelle(), "package-lock.json")) as f:
        assert f.read() == inhalt
    assert out["pakete"] == []


def test_abhaengigkeiten_arbeitsdateien_geloescht(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    ausgabe(umg.abh())
    assert umg.lk_inhalt() == []                                                     # mit lokaler KEV-Datei entsteht kein Cache


def test_abhaengigkeiten_ausgabe_ohne_kundendateiinhalte(umg):
    """Aus Kundendateien erscheinen nur Paketnamen, Versionen und Pfade; stderr des Werkzeugs wird nie ausgegeben."""
    inhalt = json.loads(npm_lock(("node_modules/lodash", "4.17.20", False)))
    inhalt["packages"]["node_modules/lodash"]["resolved"] = "https://SENTINEL-HOST.invalid/SENTINEL-TOKEN/lodash.tgz"
    inhalt["description"] = "SENTINEL-KUNDENTEXT"
    umg.schreibe("package-lock.json", json.dumps(inhalt, indent=2) + "\n")
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")])), "stderr": "SENTINEL-STDERR\n"})
    r = umg.abh()
    assert r.returncode == 0
    assert "SENTINEL" not in r.stdout and "SENTINEL" not in r.stderr


# ------------------------------------------------------------------------------------ osv-scanner fehlt

def test_abhaengigkeiten_osv_fehlt(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    r = umg.abh(env=umg.env(SECURITY_AUDIT_OHNE="osv-scanner"))                     # per Variable ausgeschlossen
    out = ausgabe(r)
    assert out["werkzeug"] == "osv-scanner" and out["fehlt"] is True
    assert out["hinweis"].startswith("osv-scanner fehlt") and out["hinweise"] == [out["hinweis"]]
    assert out["pakete"] == [] and umg.aufrufe() == []
    leer = umg.tmp_path / "leer-bin"
    leer.mkdir()
    out = ausgabe(umg.abh(env=umg.env(PATH=str(leer))))                              # nicht im PATH
    assert out["fehlt"] is True and out["hinweis"].startswith("osv-scanner fehlt")
    out = ausgabe(umg.abh(env=umg.env(SECURITY_AUDIT_OHNE=" Gitleaks , OSV-Scanner ")))   # Parser: getrimmt, case-insensitiv
    assert out["fehlt"] is True


def test_abhaengigkeiten_ohne_lockfile_ist_hinweis(umg):
    umg.fake_osv()
    out = ausgabe(umg.abh())
    assert out["pakete"] == [] and any("Lockfile" in h for h in out["hinweise"]) and umg.aufrufe() == []


# ------------------------------------------------------------------------------------ Exit-Codes von osv-scanner

def test_abhaengigkeiten_exit_codes(umg):
    """0 keine Treffer, 1 Treffer, 127/128/andere: Hinweis je Lockfile, kein Abbruch der übrigen."""
    for name in ("a", "b", "c", "d", "e"):
        umg.schreibe(f"{name}/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 0}, {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))},
                 {"rc": 127, "stderr": "SENTINEL-STDERR"}, {"rc": 128}, {"rc": 3, "stdout": osv_ausgabe(("x", "1", [vuln("x")]))})
    out = ausgabe(umg.abh())
    assert len(umg.aufrufe()) == 5
    assert [(p["paket"], p["lockfile"]) for p in out["pakete"]] == [("lodash", "b/package-lock.json")]
    hinweise = "\n".join(out["hinweise"])
    assert "c/package-lock.json" in hinweise and "127" in hinweise
    assert "d/package-lock.json" in hinweise and "128" in hinweise
    assert "e/package-lock.json" in hinweise and "Exit 3" in hinweise
    assert "a/package-lock.json" not in hinweise and "b/package-lock.json" not in hinweise
    assert "SENTINEL" not in hinweise


def test_abhaengigkeiten_unlesbare_ausgabe_ist_hinweis(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "roh": "das ist kein json"})
    out = ausgabe(umg.abh())
    assert out["pakete"] == [] and any("package-lock.json" in h and "unlesbar" in h for h in out["hinweise"])
    umg.fake_osv({"rc": 1, "roh": ""})
    assert any("unlesbar" in h for h in ausgabe(umg.abh())["hinweise"])
    umg.fake_osv({"rc": 1, "stdout": {"results": "kein array"}})
    assert ausgabe(umg.abh())["pakete"] == []


# ------------------------------------------------------------------------------------ Repo-Konfiguration

def test_repo_konfig_wirkt_nicht_osv(umg):
    """Eine `osv-scanner.toml` im Repo (Wurzel, neben dem Lockfile, im Unterordner) landet weder im cwd noch neben der Kopie."""
    umg.schreibe("osv-scanner.toml", '[[IgnoredVulns]]\nid = "GHSA-test-0001"\nreason = "x"\n')
    umg.schreibe("web/osv-scanner.toml", '[[IgnoredVulns]]\nid = "GHSA-test-0001"\nreason = "x"\n')
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.schreibe("web/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv(standard={"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    out = ausgabe(umg.abh())
    aufrufe = umg.aufrufe()
    assert len(aufrufe) == 2 and len(out["pakete"]) == 2                            # Treffer nicht unterdrückt
    for a in aufrufe:
        assert not a["toml_im_cwd"] and not a["toml_beim_lockfile"]
        assert "osv-scanner.toml" not in a["ordner_inhalt"]
        assert a["cwd_leer"]
        assert not os.path.realpath(a["cwd"]).startswith(os.path.realpath(umg.quelle()))     # nie im Kundenrepo
        assert not os.path.realpath(a["lockfile"]).startswith(os.path.realpath(umg.quelle()))
    assert "--config" not in aufrufe[0]["args"]


# ------------------------------------------------------------------------------------ Zeile im Lockfile

def test_abhaengigkeiten_zeile_im_lockfile(umg):
    """npm: Zeile des Schlüssels `node_modules/<name>` der passenden Version; sonst erste Zeile mit dem Namen; Fallback 1."""
    npm = npm_lock(("node_modules/lodash", "4.17.21", False), ("node_modules/a", "1.0.0", False),
                   ("node_modules/a/node_modules/lodash", "4.17.20", False), ("node_modules/@scope/pkg", "2.0.0", False))
    umg.schreibe("package-lock.json", npm)
    zeilen = npm.splitlines()
    genest = next(i for i, z in enumerate(zeilen, 1) if z.strip().startswith('"node_modules/a/node_modules/lodash"'))
    scope = next(i for i, z in enumerate(zeilen, 1) if z.strip().startswith('"node_modules/@scope/pkg"'))
    umg.schreibe("web/yarn.lock", '# yarn lockfile v1\n\n"@babel/core@^7.0.0":\n  version "7.0.0"\n\nlodash@^4.17.15:\n  version "4.17.15"\n')
    umg.schreibe("api/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  other@1.0.0:\n    x: y\n  lodash@4.17.10:\n    x: y\n")
    umg.schreibe("alt/package-lock.json", npm_lock(("node_modules/lodash", "4.17.5", False), v1=True))
    umg.schreibe("leer/package-lock.json", npm_lock(("node_modules/etwas", "1.0.0", False)))
    umg.fake_osv(
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.5", [vuln("lodash")]))},          # alt/package-lock.json (v1)
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.10", [vuln("lodash")]))},         # api/pnpm-lock.yaml
        {"rc": 1, "stdout": osv_ausgabe(("unbekannt", "1.0.0", [vuln("unbekannt")]))},     # leer/package-lock.json: Name fehlt
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]), ("@scope/pkg", "2.0.0", [vuln("@scope/pkg")]))},
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.15", [vuln("lodash")]))})         # web/yarn.lock
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("lodash", "4.17.20", "package-lock.json")]["zeile"] == genest      # nicht der Schlüssel der anderen Version
    assert pakete[("@scope/pkg", "2.0.0", "package-lock.json")]["zeile"] == scope
    assert pakete[("lodash", "4.17.15", "web/yarn.lock")]["zeile"] == 6               # erste Zeile mit dem Namen (nicht @babel)
    assert pakete[("lodash", "4.17.10", "api/pnpm-lock.yaml")]["zeile"] == 5
    v1 = umg.quelle() + "/alt/package-lock.json"
    erwartet_v1 = next(i for i, z in enumerate(open(v1).read().splitlines(), 1) if '"lodash"' in z)
    assert pakete[("lodash", "4.17.5", "alt/package-lock.json")]["zeile"] == erwartet_v1
    assert pakete[("unbekannt", "1.0.0", "leer/package-lock.json")]["zeile"] == 1     # Fallback


def test_abhaengigkeiten_zeile_erste_zeile_mit_dem_namen_in_npm_ohne_schluessel(umg):
    """Fehlt der Schlüssel `node_modules/<name>` (z. B. Alias), gilt die erste Zeile mit dem Paketnamen."""
    text = '{\n  "name": "x",\n  "lockfileVersion": 3,\n  "packages": {\n    "node_modules/anders": {\n      "name": "lodash",\n' \
           '      "version": "4.17.20"\n    }\n  }\n}\n'
    umg.schreibe("package-lock.json", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    assert ausgabe(umg.abh())["pakete"][0]["zeile"] == 6


def _zeile_von(text, praefix):
    """1-basierte Nummer der ersten Zeile, die mit `praefix` beginnt (Einrückung zählt mit)."""
    return next(i for i, z in enumerate(text.splitlines(), 1) if z.startswith(praefix))


def test_abhaengigkeiten_zeile_yarn_kopf_des_eintrags(umg):
    """yarn: Zeile des Eintragskopfs (Spalte 0, auch mehrere Spezifikationen und Anführungszeichen), nicht ein Verweis unter
    `dependencies:`; `lodash` trifft nicht `lodash.merge`."""
    text = ('# yarn lockfile v1\n\n'
            '"@babel/helper@^7.0.0":\n  version "7.0.0"\n  dependencies:\n    lodash "^4.17.20"\n    lodash.merge "^4.6.0"\n\n'
            'lodash.merge@^4.6.0:\n  version "4.6.0"\n\n'
            'foo@^1.0.0, lodash@^4.17.20, "lodash@>=4.17.0":\n  version "4.17.20"\n\n'
            '"@scope/lodash@^2.0.0":\n  version "2.0.0"\n')
    umg.schreibe("yarn.lock", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]), ("lodash.merge", "4.6.0", [vuln("lodash.merge")]),
                                                 ("@scope/lodash", "2.0.0", [vuln("@scope/lodash")]))})
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("lodash", "4.17.20", "yarn.lock")]["zeile"] == _zeile_von(text, "foo@^1.0.0, lodash@") == 12
    assert pakete[("lodash.merge", "4.6.0", "yarn.lock")]["zeile"] == _zeile_von(text, "lodash.merge@^4.6.0:") == 9
    assert pakete[("@scope/lodash", "2.0.0", "yarn.lock")]["zeile"] == _zeile_von(text, '"@scope/lodash@')


def test_abhaengigkeiten_zeile_yarn_bevorzugt_den_kopf_der_installierten_version(umg):
    text = 'lodash@^3.0.0:\n  version "3.10.1"\n\n"lodash@^4.17.15":\n  version "4.17.15"\n'
    umg.schreibe("yarn.lock", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.15", [vuln("lodash")]))})
    assert ausgabe(umg.abh())["pakete"][0]["zeile"] == 4


def test_abhaengigkeiten_zeile_pnpm_kopf_unter_packages(umg):
    """pnpm: Kopf `/name@ver:`, `name@ver:`, `'/name@ver':` unter `packages:`, nicht `importers:` oder `snapshots:`;
    `lodash` trifft nicht `lodash.merge`."""
    text = ("lockfileVersion: '6.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.10\n"
            "        version: 4.17.10\n      lodash.merge:\n        specifier: ^4.6.0\n        version: 4.6.0\n\npackages:\n\n"
            "  /lodash.merge@4.6.0:\n    resolution: {integrity: x}\n    dev: false\n\n"
            "  /lodash@4.17.10:\n    resolution: {integrity: x}\n    dev: false\n\n"
            "  'lodash@4.17.5(peer@1.0.0)':\n    resolution: {integrity: x}\n\n"
            "  '/@scope/pkg@2.0.0':\n    resolution: {integrity: x}\n\n"
            "  minimist@1.2.5:\n    resolution: {integrity: x}\n\n"
            "snapshots:\n\n  lodash@4.17.10:\n    dependencies: {}\n")
    umg.schreibe("pnpm-lock.yaml", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(
        ("lodash", "4.17.10", [vuln("lodash")]), ("lodash.merge", "4.6.0", [vuln("lodash.merge")]),
        ("lodash", "4.17.5", [vuln("lodash")]), ("@scope/pkg", "2.0.0", [vuln("@scope/pkg")]),
        ("minimist", "1.2.5", [vuln("minimist")]))})
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("lodash", "4.17.10", "pnpm-lock.yaml")]["zeile"] == _zeile_von(text, "  /lodash@4.17.10:") == 19
    assert pakete[("lodash.merge", "4.6.0", "pnpm-lock.yaml")]["zeile"] == _zeile_von(text, "  /lodash.merge@4.6.0:")
    assert pakete[("lodash", "4.17.5", "pnpm-lock.yaml")]["zeile"] == _zeile_von(text, "  'lodash@4.17.5(")
    assert pakete[("@scope/pkg", "2.0.0", "pnpm-lock.yaml")]["zeile"] == _zeile_von(text, "  '/@scope/pkg@2.0.0'")
    assert pakete[("minimist", "1.2.5", "pnpm-lock.yaml")]["zeile"] == _zeile_von(text, "  minimist@1.2.5:")


def test_abhaengigkeiten_zeile_npm_v1_schluessel_unter_dependencies(umg):
    """npm v1: Zeile des Schlüssels `"name": {` unter `dependencies`, nicht eine `requires`-Angabe eines anderen Pakets;
    `lodash` trifft nicht `lodash.merge`."""
    text = ('{\n  "name": "x",\n  "lockfileVersion": 1,\n  "dependencies": {\n'
            '    "a": {\n      "version": "1.0.0",\n      "requires": {\n        "lodash": "^4.17.5",\n        "lodash.merge": "^4.6.0"\n      }\n    },\n'
            '    "lodash": {\n      "version": "4.17.5"\n    },\n'
            '    "lodash.merge": {\n      "version": "4.6.0"\n    }\n  }\n}\n')
    umg.schreibe("package-lock.json", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.5", [vuln("lodash")]), ("lodash.merge", "4.6.0", [vuln("lodash.merge")]))})
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("lodash", "4.17.5", "package-lock.json")]["zeile"] == _zeile_von(text, '    "lodash": {') == 12
    assert pakete[("lodash.merge", "4.6.0", "package-lock.json")]["zeile"] == _zeile_von(text, '    "lodash.merge": {')


def test_abhaengigkeiten_zeile_fallback_schliesst_punkt_in_der_namensgrenze_ein(umg):
    """Ohne Kopfzeile (Fallback): `lodash` trifft nicht `lodash.merge`, aber die erste echte Nennung; sonst Zeile 1."""
    umg.schreibe("yarn.lock", 'x@1:\n  dependencies:\n    lodash.merge "1"\n    lodash "^4"\n')
    umg.schreibe("a/yarn.lock", 'x@1:\n  dependencies:\n    lodash.merge "1"\n')
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.0.0", [vuln("lodash")]))},
                 {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.0.0", [vuln("lodash")]))})
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("lodash", "4.0.0", "yarn.lock")]["zeile"] == 4
    assert pakete[("lodash", "4.0.0", "a/yarn.lock")]["zeile"] == 1


# ------------------------------------------------------------------------------------ dev

def test_abhaengigkeiten_dev(umg):
    """`dev` ist true nur, wenn der npm-Lockfile `dev: true` trägt (alle Vorkommen der Version); sonst false (auch yarn, pnpm)."""
    umg.schreibe("package-lock.json", npm_lock(("node_modules/nur-dev", "1.0.0", True), ("node_modules/prod", "1.0.0", False),
                                              ("node_modules/beides", "1.0.0", True), ("node_modules/x/node_modules/beides", "1.0.0", False)))
    umg.schreibe("yarn.lock", "yarn@1:\n  version \"1\"\n")
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("nur-dev", "1.0.0", [vuln("nur-dev")]), ("prod", "1.0.0", [vuln("prod")]),
                                                 ("beides", "1.0.0", [vuln("beides")]))},
                 {"rc": 1, "stdout": osv_ausgabe(("yarn", "1", [vuln("yarn")]))})
    pakete = je_paket(ausgabe(umg.abh()))
    assert pakete[("nur-dev", "1.0.0", "package-lock.json")]["dev"] is True
    assert pakete[("prod", "1.0.0", "package-lock.json")]["dev"] is False
    assert pakete[("beides", "1.0.0", "package-lock.json")]["dev"] is False          # ein Vorkommen ohne dev: Produktivpfad
    assert pakete[("yarn", "1", "yarn.lock")]["dev"] is False


def test_abhaengigkeiten_dev_kaputter_lockfile(umg):
    umg.schreibe("package-lock.json", "{ das ist kein json")
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    p = ausgabe(umg.abh())["pakete"][0]
    assert p["dev"] is False and p["zeile"] == 1


# ------------------------------------------------------------------------------------ feindliche Kundendateien

def _tiefes_v1_lockfile(tiefe):
    """package-lock.json (lockfileVersion 1) mit `tiefe` Ebenen `dependencies`; entsteht zur Laufzeit, ohne Rekursion."""
    kopf = '{"version": "1.0.0", "dependencies": {"p": '
    tief = kopf * tiefe + '{"version": "1.0.0"}' + "}}" * tiefe
    return ('{"name": "x", "lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.5", "dependencies": {"p": '
            + tief + "}}}}")


@pytest.mark.parametrize("tiefe", [3000, 200000], ids=["rekursion-in-altformat", "rekursion-im-json-parser"])
def test_abhaengigkeiten_tiefes_v1_lockfile(umg, tiefe):
    """Tief verschachteltes Lockfile (RecursionError im eigenen Durchlauf bzw. im JSON-Parser): kein Absturz, Prüfung läuft
    weiter, der Rest der Auswertung (behoben_in, Pakete) bleibt erhalten."""
    text = _tiefes_v1_lockfile(tiefe)
    umg.schreibe("package-lock.json", text)
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.5", [vuln("lodash", bereiche=(("0", "4.17.21"),))]))})
    r = umg.abh()
    out = ausgabe(r)
    assert "Traceback" not in r.stderr
    p = out["pakete"][0]
    assert (p["paket"], p["version"], p["behoben_in"]) == ("lodash", "4.17.5", "4.17.21")
    assert p["dev"] is False and isinstance(p["zeile"], int) and p["zeile"] >= 1
    assert "abh" not in umg.lk_inhalt()                                              # nichts von abh/ bleibt liegen


def test_abhaengigkeiten_riesige_version_in_osv_ausgabe(umg):
    """Eine Version mit 5000 Ziffern (aus dem Lockfile des Kunden) bringt weder behoben_in noch die Sortierung zu Fall."""
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "1" * 5000 + ".0.0", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "1" * 5000 + ".0.0", [vuln("lodash", bereiche=(("0", "1" * 5001 + ".0.0"),))]),
                                                 ("lodash", "4.17.20", [vuln("lodash", bereiche=(("0", "4.17.21"),))]))})
    r = umg.abh()
    out = ausgabe(r)
    assert "Traceback" not in r.stderr
    assert len(out["pakete"]) == 2
    assert out["pakete"][0]["version"] == "4.17.20"                                  # sortiert: klein vor riesig
    assert out["pakete"][0]["behoben_in"] == "4.17.21" and out["pakete"][1]["behoben_in"] == "1" * 5001 + ".0.0"


def test_abhaengigkeiten_ein_kaputtes_lockfile_verliert_die_anderen_nicht(umg, monkeypatch, capsys):
    """Scheitert die Auswertung eines Lockfiles mit irgendeiner Ausnahme: Hinweis ohne Inhalte, die übrigen Lockfiles bleiben,
    Arbeitsdateien werden gelöscht."""
    _in_process_umgebung(umg, monkeypatch)
    monkeypatch.setenv("SECURITY_AUDIT_KEV_DATEI", str(umg.kev))
    original = lieferkette._npm_index

    def index(text):
        if "GEHEIM-SENTINEL" in text:
            raise RuntimeError("GEHEIM-SENTINEL im Fehlertext")
        return original(text)
    monkeypatch.setattr(lieferkette, "_npm_index", index)
    umg.schreibe("a/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)).replace("\"x\"", "\"GEHEIM-SENTINEL\""))
    umg.schreibe("b/yarn.lock", 'lodash@^4.17.15:\n  version "4.17.15"\n')
    umg.schreibe("c/package-lock.json", npm_lock(("node_modules/minimist", "1.2.5", False)))
    umg.fake_osv(
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))},          # a/package-lock.json: scheitert
        {"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.15", [vuln("lodash")]))},          # b/yarn.lock
        {"rc": 1, "stdout": osv_ausgabe(("minimist", "1.2.5", [vuln("minimist")]))})        # c/package-lock.json
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    roh = capsys.readouterr().out
    out = json.loads(roh)
    assert sorted((p["paket"], p["lockfile"]) for p in out["pakete"]) == [("lodash", "b/yarn.lock"), ("minimist", "c/package-lock.json")]
    assert out["hinweise"] == ["a/package-lock.json: nicht auswertbar (RuntimeError)"]
    assert "GEHEIM-SENTINEL" not in roh
    assert len(umg.aufrufe()) == 3
    assert not os.path.exists(os.path.join(umg.lk(), "abh"))


# ------------------------------------------------------------------------------------ Texte

def test_texte_gekuerzt_einzeilig(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    lang = "Zeile eins\nZeile zwei\r\nZeile drei\x1b[31m‮ " + "x" * 3000
    v = vuln("lodash", "GHSA-x", zusammenfassung="Titel\nmit Umbruch " + "y" * 500, details=lang,
             aliase=["CVE-1\nZ", "A" * 400] + [f"ALIAS-{i}" for i in range(30)])
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [v]))})
    a = ausgabe(umg.abh())["pakete"][0]["advisories"][0]
    for feld, grenze in (("zusammenfassung", 200), ("details", 500)):
        text = a[feld]
        assert len(text) <= grenze, feld
        assert not any(c in text for c in "\n\r  \x1b‮\t"), feld
    assert a["zusammenfassung"].startswith("Titel mit Umbruch y")
    assert a["details"].startswith("Zeile eins Zeile zwei Zeile")
    assert len(a["aliase"]) <= 10 and all(len(x) <= 100 and "\n" not in x for x in a["aliase"])


def test_texte_fehlende_felder(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    v = vuln("lodash", "GHSA-x")
    del v["summary"], v["details"], v["aliases"]
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [v]))})
    a = ausgabe(umg.abh())["pakete"][0]["advisories"][0]
    assert a == {"id": "GHSA-x", "aliase": [], "zusammenfassung": "", "details": ""}


def test_ausgabe_kappt_viele_advisories_und_pakete(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    viele = [vuln("lodash", f"GHSA-{i:03d}", bereiche=(("0", f"4.18.{i}"),)) for i in range(40)]
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", viele))})
    out = ausgabe(umg.abh())
    p = out["pakete"][0]
    assert len(p["advisories"]) == lieferkette.MAX_ADVISORIES == 20
    assert p["behoben_in"] == "4.18.39"                                              # aus allen Advisories, nicht nur den gezeigten
    assert any("lodash" in h and "40" in h for h in out["hinweise"])


def test_ausgabe_kappt_pakete(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/x", "1.0.0", False)))
    viele = [(f"paket-{i:04d}", "1.0.0", [vuln(f"paket-{i:04d}")]) for i in range(lieferkette.MAX_PAKETE + 10)]
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(*viele)})
    out = ausgabe(umg.abh())
    assert len(out["pakete"]) == lieferkette.MAX_PAKETE == 300
    assert any("310" in h and "300" in h for h in out["hinweise"])


# ------------------------------------------------------------------------------------ KEV

def test_kev_markierung(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/a", "1.0.0", False), ("node_modules/b", "1.0.0", False),
                                              ("node_modules/c", "1.0.0", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(
        ("a", "1.0.0", [vuln("a", "GHSA-1", aliase=["CVE-2099-0001"])]),                  # Alias im Katalog
        ("b", "1.0.0", [vuln("b", "GHSA-2", aliase=["CVE-2000-0000"]), vuln("b", "CVE-2099-0002")]),   # ID selbst im Katalog
        ("c", "1.0.0", [vuln("c", "GHSA-3", aliase=["CVE-2000-0001"])]))})
    out = ausgabe(umg.abh())
    assert {p["paket"]: p["kev"] for p in out["pakete"]} == {"a": True, "b": True, "c": False}
    assert not any("KEV" in h for h in out["hinweise"])


@pytest.mark.parametrize("variante", ["fehlt", "kein_json", "falsche_struktur"])
def test_kev_fehler_ist_null_mit_hinweis(umg, variante):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash", aliase=["CVE-2099-0001"])]))})
    if variante == "fehlt":
        umg.kev.unlink()
    elif variante == "kein_json":
        umg.kev.write_text("<html>")
    else:
        umg.kev.write_text(json.dumps({"vulnerabilities": "nein"}))
    out = ausgabe(umg.abh())
    assert [p["kev"] for p in out["pakete"]] == [None]
    assert any(h.startswith("KEV-Katalog nicht geladen") for h in out["hinweise"])
    assert out["pakete"][0]["advisories"]                                            # der Rest bleibt erhalten


class _Antwort(io.BytesIO):
    status = 200

    def __init__(self, daten, url=KEV_URL):
        super().__init__(daten)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _in_process_umgebung(umg, monkeypatch):
    monkeypatch.setenv("PATH", str(umg.bin))
    monkeypatch.setenv("TMPDIR", str(umg.tmp))
    monkeypatch.setenv("FAKE_OSV_LOG", str(umg.log))
    monkeypatch.setenv("FAKE_OSV_CONFIG", str(umg.config))
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.delenv("SECURITY_AUDIT_KEV_DATEI")


def test_kev_einmal_je_lauf(umg, monkeypatch, capsys):
    """Ein Download je Lauf, auch bei mehreren Lockfiles und einem zweiten Aufruf (Cache unter `<zustand>/lieferkette/`);
    URL, User-Agent und Timeout wie in Plan und Spec."""
    _in_process_umgebung(umg, monkeypatch)
    anfragen = []

    def urlopen(req, timeout=None, **kw):
        anfragen.append((req.full_url, dict(req.header_items()), timeout))
        return _Antwort(json.dumps(KEV_KATALOG).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    umg.schreibe("a/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.schreibe("b/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv(standard={"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash", aliase=["CVE-2099-0001"])]))})
    for _ in range(2):
        assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
        out = json.loads(capsys.readouterr().out)
        assert [p["kev"] for p in out["pakete"]] == [True, True]
    assert len(anfragen) == 1
    url, kopfzeilen, timeout = anfragen[0]
    assert url == KEV_URL == lieferkette.KEV_URL
    assert {k.lower(): v for k, v in kopfzeilen.items()}["user-agent"] == KEV_UA == lieferkette.KEV_USER_AGENT
    assert timeout is not None and 0 < timeout <= 30
    assert umg.lk_inhalt() == ["kev.json"]                                           # nur der Cache; Arbeitsdateien sind weg


def test_kev_kein_download_ohne_pakete(umg, monkeypatch, capsys):
    _in_process_umgebung(umg, monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: pytest.fail("Download ohne Treffer"))
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 0})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    assert json.loads(capsys.readouterr().out)["pakete"] == []


def test_kev_download_fehler_ist_null_mit_hinweis(umg, monkeypatch, capsys):
    _in_process_umgebung(umg, monkeypatch)

    def urlopen(*a, **k):
        raise OSError("Netz weg")
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [p["kev"] for p in out["pakete"]] == [None]
    assert any(h.startswith("KEV-Katalog nicht geladen") for h in out["hinweise"])
    assert not os.path.exists(os.path.join(umg.lk(), "kev.json"))                    # kein Cache bei Fehler


@pytest.mark.parametrize("antwort", [b"<html>nope</html>", b'{"vulnerabilities": 5}', b"x" * (33 * 1024 * 1024)],
                         ids=["html", "struktur", "zu-gross"])
def test_kev_download_ungueltige_antwort(umg, monkeypatch, capsys, antwort):
    _in_process_umgebung(umg, monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Antwort(antwort))
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [p["kev"] for p in out["pakete"]] == [None]
    assert not os.path.exists(os.path.join(umg.lk(), "kev.json"))


def test_kev_download_gueltiges_json_ueber_dem_limit_wird_verworfen(umg, monkeypatch, capsys):
    """Das Größenlimit greift auch bei gültigem JSON (nicht nur bei Müll); genau am Limit wird noch angenommen."""
    _in_process_umgebung(umg, monkeypatch)
    katalog = json.dumps({"vulnerabilities": [{"cveID": f"CVE-2099-{n:04d}"} for n in range(1, 200)]}).encode()
    assert json.loads(katalog)["vulnerabilities"]                                    # gültig und strukturell richtig
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash", aliase=["CVE-2099-0007"])]))})
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Antwort(katalog))

    monkeypatch.setattr(lieferkette, "KEV_MAX", len(katalog) - 1)
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [p["kev"] for p in out["pakete"]] == [None]
    assert any(h.startswith("KEV-Katalog nicht geladen") and "Antwort zu groß" in h for h in out["hinweise"])
    assert not os.path.exists(os.path.join(umg.lk(), "kev.json"))

    monkeypatch.setattr(lieferkette, "KEV_MAX", len(katalog))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash", aliase=["CVE-2099-0007"])]))})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    assert [p["kev"] for p in json.loads(capsys.readouterr().out)["pakete"]] == [True]


def test_kev_download_weiterleitung_auf_http_wird_verworfen(umg, monkeypatch, capsys):
    _in_process_umgebung(umg, monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: _Antwort(json.dumps(KEV_KATALOG).encode(), url="http://evil.invalid/kev.json"))
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    assert [p["kev"] for p in json.loads(capsys.readouterr().out)["pakete"]] == [None]


def test_kev_cache_defekt_wird_neu_geladen(umg, monkeypatch, capsys):
    _in_process_umgebung(umg, monkeypatch)
    zaehler = []
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: zaehler.append(1) or _Antwort(json.dumps(KEV_KATALOG).encode()))
    os.makedirs(umg.lk(), mode=0o700)
    with open(os.path.join(umg.lk(), "kev.json"), "w") as f:
        f.write("kaputt")
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash", aliase=["CVE-2099-0002"])]))})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    assert [p["kev"] for p in json.loads(capsys.readouterr().out)["pakete"]] == [True] and len(zaehler) == 1


# ------------------------------------------------------------------------------------ Budget

def test_abhaengigkeiten_budget(umg):
    """Budget abgelaufen: Hinweis, bereits ermittelte Pakete bleiben, der hängende Prozess wird beendet, nichts bleibt liegen."""
    umg.schreibe("a/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.schreibe("b/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.schreibe("c/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": osv_ausgabe(("lodash", "4.17.20", [vuln("lodash")]))}, {"rc": 0, "sleep": 60},
                 {"rc": 0, "sleep": 60})
    start = time.monotonic()
    out = ausgabe(umg.abh(env=umg.env(SECURITY_AUDIT_ABH_BUDGET="3")))
    assert time.monotonic() - start < 40
    assert [p["lockfile"] for p in out["pakete"]] == ["a/package-lock.json"]
    assert any("Abhängigkeitsprüfung abgebrochen (Zeitbudget)" in h for h in out["hinweise"])
    assert len(umg.aufrufe()) == 2                                                    # das dritte Lockfile wurde nicht mehr gestartet
    assert not os.path.exists(os.path.join(umg.lk(), "abh"))


def test_abhaengigkeiten_budget_variable_kann_das_limit_nicht_erhoehen(umg):
    assert lieferkette.ABH_BUDGET == 300
    assert lieferkette._sekunden("SECURITY_AUDIT_ABH_BUDGET", lieferkette.ABH_BUDGET) == 300
    os.environ["SECURITY_AUDIT_ABH_BUDGET"] = "100000"
    try:
        assert lieferkette._sekunden("SECURITY_AUDIT_ABH_BUDGET", lieferkette.ABH_BUDGET) == 300
        os.environ["SECURITY_AUDIT_ABH_BUDGET"] = "5"
        assert lieferkette._sekunden("SECURITY_AUDIT_ABH_BUDGET", lieferkette.ABH_BUDGET) == 5
    finally:
        del os.environ["SECURITY_AUDIT_ABH_BUDGET"]


# ------------------------------------------------------------------------------------ Argumente und Quelle

def test_abhaengigkeiten_quelle_ausserhalb_verweigert(umg, tmp_path):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 0})
    fremd = tmp_path / "fremd"
    (fremd).mkdir()
    (fremd / "package-lock.json").write_text(npm_lock(("node_modules/lodash", "4.17.20", False)))
    open(fremd / "quelle.fertig", "w").close()
    r = umg.abh(quelle=str(fremd))
    assert r.returncode == 2 and "quelle" in r.stderr.lower() and umg.aufrufe() == []
    for falsch in (umg.zustand(), os.path.join(umg.quelle(), "..", "quelle", "x")):
        assert umg.abh(quelle=falsch).returncode == 2
    assert umg.abh(quelle=os.path.join(umg.quelle(), "package-lock.json")).returncode == 2


def test_abhaengigkeiten_quelle_ohne_fertig_marker_verweigert(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 0})
    os.unlink(os.path.join(umg.zustand(), "quelle.fertig"))
    assert umg.abh().returncode == 2 and umg.aufrufe() == []


def test_abhaengigkeiten_symlink_auf_echte_quelle_ist_erlaubt(umg, tmp_path):
    umg.fake_osv({"rc": 0})
    link = tmp_path / "quelle-link"
    link.symlink_to(umg.quelle())
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    assert umg.abh(quelle=str(link)).returncode == 0


def test_abhaengigkeiten_ungueltige_argumente(umg):
    r = subprocess.run([sys.executable, "-I", LIEFERKETTE, "abhaengigkeiten", "--lauf", "xyz", "--quelle", umg.quelle()],
                       env=umg.env(), capture_output=True, text=True)
    assert r.returncode == 2
    r = subprocess.run([sys.executable, "-I", LIEFERKETTE, "abhaengigkeiten", "--lauf", LAUF], env=umg.env(),
                       capture_output=True, text=True)
    assert r.returncode == 2


def test_abhaengigkeiten_symlink_lockfile_wird_uebersprungen(umg, tmp_path):
    """Ein Symlink namens package-lock.json wird weder gelesen noch kopiert (Hinweis)."""
    ziel = tmp_path / "ausserhalb.json"
    ziel.write_text(npm_lock(("node_modules/lodash", "4.17.20", False)))
    os.symlink(ziel, os.path.join(umg.quelle(), "package-lock.json"))
    umg.fake_osv({"rc": 0})
    out = ausgabe(umg.abh())
    assert umg.aufrufe() == [] and any("Symlink" in h for h in out["hinweise"])


def test_abhaengigkeiten_werkzeug_nicht_startbar(umg):
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    kaputt = umg.bin / "osv-scanner"
    kaputt.write_text("#!/nicht/vorhanden/interpreter\n")
    kaputt.chmod(0o755)                                                              # PATH enthält nur den Shim-Ordner
    out = ausgabe(umg.abh())
    assert out["pakete"] == [] and any("nicht startbar" in h for h in out["hinweise"])


# ------------------------------------------------------------------------------------ echter osv-scanner (opt-in)

@pytest.mark.skipif(not NETZ or shutil.which("osv-scanner") is None,
                    reason="nur mit SECURITY_AUDIT_NETZ=1 und installiertem osv-scanner (Netzzugriff auf die OSV-API)")
def test_abhaengigkeiten_echt(tmp_path):
    """Echter osv-scanner auf einem zur Laufzeit erzeugten Lockfile (bekannt verwundbare Version, nur in tmp_path)."""
    umg = Umgebung(tmp_path)
    umg.schreibe("package-lock.json", npm_lock(("node_modules/minimist", "1.2.5", False), ("node_modules/ohne-treffer-xyz", "1.0.0", True)))
    env = {"PATH": os.environ["PATH"], "HOME": str(umg.home), "TMPDIR": str(umg.tmp), "SECURITY_AUDIT_KEV_DATEI": str(umg.kev)}
    out = ausgabe(umg.abh(env=env, timeout=300))
    pakete = [p for p in out["pakete"] if p["paket"] == "minimist"]
    assert len(pakete) == 1 and pakete[0]["version"] == "1.2.5" and pakete[0]["lockfile"] == "package-lock.json"
    assert pakete[0]["advisories"] and pakete[0]["dev"] is False and pakete[0]["kev"] is False
    assert lieferkette.semver_vergleich(pakete[0]["behoben_in"], "1.2.5") > 0
    assert isinstance(pakete[0]["zeile"], int) and pakete[0]["zeile"] > 1
    assert not os.path.exists(os.path.join(umg.lk(), "abh"))


# ------------------------------------------------------------------------------------ Re-Review Task 2 (N-2, N-3)

@pytest.mark.parametrize("a, b", [("1.0.0-01", "1.0.0-1"), ("1.0.0-0", "1.0.0-00")])
def test_semver_vergleich_vorabversion_fuehrende_nullen_antisymmetrisch(a, b):
    assert lieferkette.semver_vergleich(a, b) == -lieferkette.semver_vergleich(b, a)


def test_kev_ids_tiefe_verschachtelung_ist_kevfehler():
    with pytest.raises(lieferkette.KevFehler):
        lieferkette._kev_ids(b"[" * 200000)


# ------------------------------------------------------------------------------------ Härtung TF2: parallele Befehle

def test_zweites_abhaengigkeiten_auf_demselben_lauf_verweigert_ohne_etwas_zu_loeschen(umg):
    """`abhaengigkeiten` (und `secrets`) teilen sich je Lauf eine Sperre auf `<zustand>/lieferkette`: wer sie nicht bekommt,
    endet mit Exit 1, ohne die Arbeitsdateien des laufenden Befehls zu löschen."""
    import fcntl
    umg.schreibe("package-lock.json", npm_lock(("node_modules/a", "1.0.0", False)))
    umg.fake_osv(standard={"rc": 0})
    ausgabe(umg.abh())
    laufender = os.path.join(umg.lk(), "abh")
    os.makedirs(laufender)                                                       # Arbeitsordner des (gedachten) laufenden Befehls
    fd = os.open(umg.lk(), os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        r = umg.abh()
        assert r.returncode == 1 and "läuft bereits" in r.stderr, r.stdout + r.stderr
        assert os.path.isdir(laufender)
        assert len(umg.aufrufe()) == 1
    finally:
        os.close(fd)


# ------------------------------------------------------------------------------------ Härtung TF2: Zeilenermittlung (N-1)

def _gross_yarn(n):
    kopf = "# yarn lockfile v1\n\n"
    return kopf + "".join(f'pkg{i}@^1.0.0:\n  version "1.0.{i}"\n  resolved "https://x/{i}"\n\n' for i in range(n))


def _gross_npm(n):
    pk = {"": {"name": "x"}}
    pk.update({f"node_modules/pkg{i}": {"version": f"1.0.{i}"} for i in range(n)})
    return json.dumps({"lockfileVersion": 3, "packages": pk}, indent=2) + "\n"


def _gross_pnpm(n):
    return "lockfileVersion: '9.0'\n\npackages:\n\n" + "".join(
        f"  pkg{i}@1.0.{i}:\n    resolution: {{integrity: x}}\n\n" for i in range(n)) + "snapshots:\n"


@pytest.mark.parametrize("name, bauen", [("yarn.lock", _gross_yarn), ("package-lock.json", _gross_npm),
                                         ("pnpm-lock.yaml", _gross_pnpm)])
def test_zeilenermittlung_ist_nicht_quadratisch(name, bauen):
    """6000 verwundbare Pakete in einem Lockfile: die Zeilenermittlung nutzt einen Index je Lockfile (vorher O(Pakete x Zeilen):
    etwa 14 s und mehr)."""
    n = 6000
    text = bauen(n)
    daten = osv_ausgabe(*((f"pkg{i}", f"1.0.{i}", [vuln(f"pkg{i}", bereiche=(("0", "9.0.0"),))]) for i in range(n)))
    start = time.monotonic()
    eintraege = lieferkette._lockfile_eintraege("x/" + name, name, text.encode(), daten)
    assert time.monotonic() - start < 4
    zeilen = text.splitlines()
    assert len(eintraege) == n
    for e in (eintraege[0], eintraege[n // 2], eintraege[-1]):
        assert e["paket"] in zeilen[e["zeile"] - 1]


def test_zeilenermittlung_budget_in_der_schleife():
    """Ist die Frist abgelaufen, bekommen die übrigen Pakete `zeile` 1 und ein Hinweis nennt die Anzahl."""
    text = _gross_yarn(50)
    daten = osv_ausgabe(*((f"pkg{i}", f"1.0.{i}", [vuln(f"pkg{i}")]) for i in range(50)))
    hinweise = []
    eintraege = lieferkette._lockfile_eintraege("yarn.lock", "yarn.lock", text.encode(), daten, time.monotonic() - 1, hinweise)
    assert len(eintraege) == 50 and all(e["zeile"] == 1 for e in eintraege)
    assert hinweise == ["Zeilenermittlung abgebrochen (Zeitbudget): 50 Pakete in yarn.lock ohne Zeile"]


# Bezugsstand: die Einzelsuche vor der Einführung des Index (Stand 8c9c621), unverändert übernommen. Der Index muss dieselbe
# Zeile liefern.
def _alt_erster_mit_version(zeilen: list[str], koepfe: list[int], version: re.Pattern[str]) -> int:
    """Von mehreren Eintragsköpfen desselben Pakets der erste, dessen Eintrag (bis zur nächsten Leerzeile, höchstens sechs
    Zeilen) die installierte Version nennt; sonst der erste Kopf."""
    for i in koepfe:
        for z in zeilen[i + 1:i + 7]:
            if not z.strip():
                break
            if version.search(z):
                return i
    return koepfe[0]


def _alt_kopf_yarn(zeilen: list[str], name: str, version: str) -> int | None:
    """yarn.lock: Zeile des Eintragskopfs (Spalte 0, endet auf `:`), dessen durch `, ` getrennte Spezifikationen (auch in
    Anführungszeichen) mit `<name>@` beginnen."""
    koepfe = [i for i, z in enumerate(zeilen)
              if z and not z[0].isspace() and z[0] != "#" and z.rstrip().endswith(":")
              and any(s.strip().strip("\"'").startswith(name + "@") for s in z.rstrip()[:-1].split(", "))]
    if not koepfe:
        return None
    ver = re.escape(version)
    return _alt_erster_mit_version(zeilen, koepfe, re.compile(r"^\s+version:?\s+[\"']?" + ver + r"[\"']?\s*$"))


def _alt_kopf_pnpm(zeilen: list[str], name: str, version: str) -> int | None:
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


def _alt_kopf_npm_v1(zeilen: list[str], name: str, version: str) -> int | None:
    """npm lockfileVersion 1: Zeile des Schlüssels `"<name>": {` unter `dependencies` (nicht `"<name>": "^1.0"` unter
    `requires`)."""
    muster = re.compile(r"^\s*" + re.escape(json.dumps(name, ensure_ascii=False)) + r"\s*:\s*\{")
    koepfe = [i for i, z in enumerate(zeilen) if muster.match(z)]
    if not koepfe:
        return None
    return _alt_erster_mit_version(zeilen, koepfe, re.compile(r'"version"\s*:\s*"' + re.escape(version) + '"'))


def _alt_zeile(zeilen: list[str], name: str, version: str, index: lieferkette._NpmIndex, lockfile: str = "") -> int:
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
        kopf = _alt_kopf_yarn(zeilen, name, version)
    elif lockfile == "pnpm-lock.yaml":
        kopf = _alt_kopf_pnpm(zeilen, name, version)
    elif lockfile in lieferkette.NPM_LOCKFILES:
        kopf = _alt_kopf_npm_v1(zeilen, name, version)
    if kopf is not None:
        return kopf + 1
    muster = re.compile(r"(?<![\w@./-])" + re.escape(name) + r"(?![\w.-])")
    for i, z in enumerate(zeilen, 1):
        if muster.search(z):
            return i
    return 1


BEISPIELE = [
    ("yarn.lock", '# yarn lockfile v1\n\n"@a/b@^1.0.0", "@a/b@~1.1.0":\n  version "1.1.2"\n\nfoo@^1:\n  version "1.0.0"\n', "@a/b", "1.1.2"),
    ("yarn.lock", '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.20, lodash@npm:^4.17.21":\n  version: 4.17.21\n', "lodash", "4.17.21"),
    ("yarn.lock", 'lodash@^3:\n  version "3.0.0"\n\nlodash@^4:\n  version "4.0.1"\n\nlodash@^4.1:\n  version "4.0.1"\n', "lodash", "4.0.1"),
    ("yarn.lock", 'lodash@^3:\n  version "3.0.0"\n\nlodash@^4:\n  version "4.0.1"\n', "lodash", "9.9.9"),
    ("pnpm-lock.yaml", "lockfileVersion: 5.4\n\nimporters:\n  .:\n    lodash: 4.17.10\n\npackages:\n\n  /lodash/4.17.10:\n    dev: false\n", "lodash", "4.17.10"),
    ("pnpm-lock.yaml", "packages:\n  'lodash@4.17.5(x@1)':\n    resolution: {}\n  lodash@4.17.6:\n    resolution: {}\n", "lodash", "4.17.6"),
    ("pnpm-lock.yaml", "packages:\n  'lodash@4.17.5(x@1)':\n    resolution: {}\n  lodash@4.17.6:\n    resolution: {}\n", "lodash", "4.17.5"),
    ("pnpm-lock.yaml", "packages:\n  /@a/b@1.0.0_c@2:\n    resolution: {}\n  /@a/b/2.0.0:\n    x: 1\n", "@a/b", "2.0.0"),
    ("pnpm-lock.yaml", "packages:\n  /@a/b@1.0.0_c@2:\n    resolution: {}\n", "@a/b", "7.0.0"),
    ("pnpm-lock.yaml", "packages:\n  lodash.merge@4.6.0:\n    x: 1\n  lodash@4.0.0-beta:\n    x: 1\n", "lodash", "4.0.0"),
    ("package-lock.json", '{\n  "lockfileVersion": 1,\n  "requires": true,\n  "dependencies": {\n    "lodash": {\n      "version": "4.17.5"\n    }\n  }\n}\n', "lodash", "4.17.5"),
    ("package-lock.json", '{\n "dependencies": {\n  "lodash": {\n   "version": "3.0.0",\n   "dependencies": {\n    "lodash": {\n     "version": "4.0.0"\n    }\n   }\n  }\n }\n}\n', "lodash", "4.0.0"),
    ("package-lock.json", '{\n "lockfileVersion": 3,\n "packages": {\n  "node_modules/a/node_modules/lodash": {"version": "4.17.20"},\n  "node_modules/lodash": {"version": "4.17.21"}\n }\n}\n', "lodash", "4.17.20"),
    ("yarn.lock", "irgendwas mit lodash@4 in der Mitte\n", "lodash", "4.0.0"),
    ("yarn.lock", "x.lodash und lodash.merge und -lodash und lodash\n", "lodash", "4.0.0"),
    ("yarn.lock", "foo @scope/pkg@1 bar\n@scope/pkg/x\n", "@scope/pkg", "1.0.0"),
    ("yarn.lock", "x\nfoo lodash/4.0.0 bar\n", "lodash", "4.0.0"),
    ("yarn.lock", "a~b und a~b2\n", "a~b", "1.0.0"),
    ("yarn.lock", "leer\n", "lodash", "4.0.0"),
]


@pytest.mark.parametrize("name, text, paket, version", BEISPIELE)
def test_zeilenermittlung_index_gleich_einzelsuche(name, text, paket, version):
    index = lieferkette._npm_index(text) if name in lieferkette.NPM_LOCKFILES else lieferkette._NpmIndex({}, {})
    zeilen = text.splitlines()
    erwartet = _alt_zeile(zeilen, paket, version, index, name)
    daten = osv_ausgabe((paket, version, [vuln(paket)]))
    [e] = lieferkette._lockfile_eintraege(name, name, text.encode(), daten)
    assert e["zeile"] == erwartet == lieferkette._zeile(zeilen, paket, version, index, name)


def test_zeilenermittlung_index_gleich_einzelsuche_zufallsdateien():
    """Zufällig zusammengesetzte Lockfile-Zeilen aus Bausteinen der drei Formate (Köpfe, Versionen, Rauschen) und mehrere
    gefragte Pakete: der Index liefert je Paket dieselbe Zeile wie die Einzelsuche."""
    import random
    rng = random.Random(20261110)
    namen = ["lodash", "lodash.merge", "@a/b", "a", "minimist", "x-y"]
    versionen = ["1.0.0", "2.0.0-beta", "4.17.21"]
    bausteine = [
        "{n}@^{v}:", '"{n}@^{v}", "{n}@~{v}":', '  version "{v}"', "  version: {v}", "  /{n}@{v}:", "  '/{n}@{v}':", "  {n}@{v}(p@1):",
        "  /{n}/{v}_q@2:", '    "{n}": {{', '      "version": "{v}"', '  "node_modules/{n}": {{', "text {n} text", "{n}.merge {n}-x", "", "",
        "packages:", "importers:", "  .:", "# {n}@{v}:", "{n}@{v}", "foo/{n}@1", "x{n}@1:", '    "{n}": "^{v}"',
    ]
    for runde in range(200):
        zeilen = [rng.choice(bausteine).format(n=rng.choice(namen), v=rng.choice(versionen)) for _ in range(rng.randint(1, 40))]
        text = "\n".join(zeilen) + "\n"
        for name in ("yarn.lock", "pnpm-lock.yaml", "package-lock.json"):
            index = lieferkette._npm_index(text) if name in lieferkette.NPM_LOCKFILES else lieferkette._NpmIndex({}, {})
            paare = [(rng.choice(namen), rng.choice(versionen)) for _ in range(4)]
            zi = lieferkette._ZeilenIndex(text.splitlines(), index, name, paare)
            for n, v in paare:
                assert zi.zeile(n, v) == _alt_zeile(text.splitlines(), n, v, index, name), (runde, name, n, v, text)


# ------------------------------------------------------------------------------------ Härtung TF2: behoben_in (M-4)

def test_behoben_in_ausserhalb_aller_bereiche_nennt_die_kleinste_fix_version_darueber_m_4():
    """Liegt die installierte Version in keinem Bereich (Lücke zwischen zwei Versionslinien), ist `behoben_in` die kleinste
    Fix-Version oberhalb der installierten über alle Bereiche, also möglicherweise die einer anderen Versionslinie; das ist
    dokumentiert (Docstring, `references/pruefpunkte-web.md`)."""
    luecke = vuln("lib", "A", bereiche=(("0", "3.10.1"), ("4.0.0", "4.17.21")))
    assert lieferkette.behoben_in([luecke], "lib", "3.11.0") == "4.17.21"
    assert "Versionslinie" in lieferkette.behoben_in.__doc__ and "keinem Bereich" in lieferkette.behoben_in.__doc__


# ------------------------------------------------------------------------------------ Härtung TF2: KEV (M-5, Tropfen)

class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


def _umleitungs_server(anfragen):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            anfragen.append(self.path)
            if self.path == "/kev":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/zwei")
                self.end_headers()
            else:
                daten = json.dumps(KEV_KATALOG).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(daten)))
                self.end_headers()
                self.wfile.write(daten)

        def log_message(self, *a):
            pass
    server = _Server(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_kev_download_folgt_keiner_weiterleitung_auf_http_m_5(monkeypatch):
    """Jeder Weiterleitungsschritt muss https sein, nicht erst die Endadresse: die zweite Adresse wird nie angefragt."""
    anfragen = []
    server = _umleitungs_server(anfragen)
    try:
        monkeypatch.setattr(urllib.request, "urlopen", ECHTES_URLOPEN)
        monkeypatch.setenv("no_proxy", "*")
        monkeypatch.setattr(lieferkette, "KEV_URL", f"http://127.0.0.1:{server.server_port}/kev")
        with pytest.raises(lieferkette.KevFehler, match="Weiterleitung"):
            lieferkette._kev_herunterladen(5)
    finally:
        server.shutdown()
        server.server_close()
        urllib.request.install_opener(None)
    assert anfragen == ["/kev"]


def test_kev_umleitungs_handler_laesst_https_zu_und_lehnt_http_ab():
    h = lieferkette._NurHttpsUmleitung()
    req = urllib.request.Request("https://www.cisa.gov/a")
    neu = h.redirect_request(req, io.BytesIO(), 302, "Found", {}, "https://www.cisa.gov/b")
    assert neu is not None and neu.full_url == "https://www.cisa.gov/b"
    for ziel in ("http://www.cisa.gov/b", "ftp://x/b", "file:///etc/passwd"):
        with pytest.raises(lieferkette.KevFehler):
            h.redirect_request(req, io.BytesIO(), 302, "Found", {}, ziel)


class _Tropfen:
    """Antwort, die nur tröpfelt: `read(n)` blockiert wie ein Socket-Lesen von n Bytes (bis zu 3 s), `read1` liefert je Aufruf
    nach 0,2 s ein Byte. Ein Gesamtlimit lässt sich nur mit `read1` durchsetzen."""
    status = 200

    def geturl(self):
        return KEV_URL

    def read(self, n=-1):
        time.sleep(3)
        return b"x" * 10

    def read1(self, n=-1):
        time.sleep(0.2)
        return b"x"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_kev_download_gesamtfrist_haelt_auch_bei_tropfender_antwort(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Tropfen())
    start = time.monotonic()
    with pytest.raises(lieferkette.KevFehler, match="Zeit"):
        lieferkette._kev_herunterladen(0.6)
    assert time.monotonic() - start < 1.8


# ------------------------------------------------------------------------------------ Härtung TF2: osv-scanner-Ausgabe

def test_osv_exit_1_ohne_auswertbare_pakete_ist_ein_hinweis(umg):
    """Exit 1 heißt „Treffer“. Liefert die Ausgabe keine auswertbaren Pakete (anderes Format, andere Version), darf das nicht als
    „keine Lücken“ durchgehen."""
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.schreibe("b/package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "stdout": {"neues": "format"}}, {"rc": 1, "stdout": {"results": []}})
    out = ausgabe(umg.abh())
    assert out["pakete"] == []
    assert "osv-scanner meldete Treffer (Exit 1), die Ausgabe enthält aber keine auswertbaren Pakete: Lockfile nicht ausgewertet: b/package-lock.json" in out["hinweise"]
    assert "osv-scanner meldete Treffer (Exit 1), die Ausgabe enthält aber keine auswertbaren Pakete: Lockfile nicht ausgewertet: package-lock.json" in out["hinweise"]


def test_osv_ausgabe_ueber_dem_limit_wird_nicht_ausgewertet(umg, monkeypatch, capsys):
    _in_process_umgebung(umg, monkeypatch)
    monkeypatch.setattr(lieferkette, "OSV_AUSGABE_MAX", 1000)
    umg.schreibe("package-lock.json", npm_lock(("node_modules/lodash", "4.17.20", False)))
    umg.fake_osv({"rc": 1, "roh": "x" * 5000})
    assert lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pakete"] == []
    assert any("Ausgabe zu groß" in h and "package-lock.json" in h for h in out["hinweise"])


def test_lockfile_das_keine_regulaere_datei_ist_ein_hinweis(umg):
    """Ein Lockfile-Name, hinter dem keine reguläre Datei steht (FIFO, Gerät), wird nicht gelesen, verschwindet aber nicht still."""
    umg.schreibe("package-lock.json", npm_lock(("node_modules/a", "1.0.0", False)))
    os.makedirs(os.path.join(umg.quelle(), "sub"))
    os.mkfifo(os.path.join(umg.quelle(), "sub", "yarn.lock"))
    umg.fake_osv(standard={"rc": 0})
    out = ausgabe(umg.abh())
    assert "Lockfile keine reguläre Datei, übersprungen: sub/yarn.lock" in out["hinweise"]
    assert len(umg.aufrufe()) == 1


def test_kev_treffer_ignoriert_gross_klein_und_leerraum():
    kev = frozenset({"CVE-2099-0001"})
    assert lieferkette._kev_treffer([{"id": "GHSA-x", "aliases": [" cve-2099-0001 "]}], kev) is True
    assert lieferkette._kev_treffer([{"id": "cve-2099-0001"}], kev) is True
    assert lieferkette._kev_treffer([{"id": "GHSA-x", "aliases": ["CVE-2099-0002"]}], kev) is False


def test_advisory_listet_die_eigene_id_nicht_als_alias():
    a = lieferkette._advisory({"id": "GHSA-a", "aliases": ["GHSA-a", "CVE-1"], "summary": "s", "details": "d"})
    assert a["aliase"] == ["CVE-1"]


def _sekunden_aufzeichnen(monkeypatch):
    """`_sekunden` im Testprozess durch einen Aufzeichner ersetzen: Liste der (Name, Standard) der Aufrufstellen."""
    aufrufe = []
    echt = lieferkette._sekunden

    def aufzeichner(name, standard):
        aufrufe.append((name, standard))
        return echt(name, standard)
    monkeypatch.setattr(lieferkette, "_sekunden", aufzeichner)
    return aufrufe


def test_abhaengigkeiten_budget_laeuft_ueber_den_deckel_r1_4(umg, monkeypatch, capsys):
    """Die Aufrufstelle in `cmd_abhaengigkeiten` nimmt `_sekunden` mit dem Standard 300 s (kein Rohwert der Variable)."""
    umg.fake_osv()
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    monkeypatch.setenv("PATH", f"{umg.bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_OSV_LOG", str(umg.log))
    monkeypatch.setenv("FAKE_OSV_CONFIG", str(umg.config))
    monkeypatch.setenv("SECURITY_AUDIT_ABH_BUDGET", "1e9")
    aufrufe = _sekunden_aufzeichnen(monkeypatch)
    rc = lieferkette.main(["abhaengigkeiten", "--lauf", LAUF, "--quelle", umg.quelle()])
    capsys.readouterr()
    assert rc == 0 and aufrufe == [("SECURITY_AUDIT_ABH_BUDGET", 300)]


def test_unbrauchbare_lockfile_pfade_werden_nicht_geprueft_und_gemeldet_r1_6(umg):
    """Pfade mit Steuerzeichen oder über 300 Zeichen kämen nie als `lockfile` ins Befund-Schema: übersprungen mit Hinweis,
    nicht gekappt."""
    lang = "/".join(["verzeichnis-mit-langem-namen"] * 12)
    umg.schreibe("a\x01b/package-lock.json", "{}")
    umg.schreibe(f"{lang}/package-lock.json", "{}")
    umg.schreibe("ok/package-lock.json", "{}")
    umg.fake_osv({"rc": 0, "stdout": {"results": []}})
    out = ausgabe(umg.abh())
    hinweise = "\n".join(out["hinweise"])
    assert "1 Lockfiles mit Steuerzeichen oder ungültigen Zeichen im Pfad übersprungen" in hinweise
    assert "1 Lockfiles mit überlangem Pfad (über 300 Zeichen) übersprungen" in hinweise
    assert "\x01" not in hinweise and lang not in hinweise
    assert len(umg.aufrufe()) == 1                                                                  # nur ok/package-lock.json
