"""Tests für `lieferkette.py abhaengigkeiten` (TF2, Task 2).

Aufruf: python3 -m pytest security-audit/scripts/test_lieferkette_abh.py -q

Ein Fake-`osv-scanner` im Shim-PATH protokolliert jeden Aufruf (Argumente, cwd, Ordnerinhalt neben dem Lockfile, Umgebung) und
liefert Antworten im JSON-Format von osv-scanner 2.6 aus einer Konfigurationsdatei. Es gibt kein Netz in diesen Tests: die
autouse-Fixture setzt `SECURITY_AUDIT_KEV_DATEI` auf eine lokale Fake-Datei und sperrt `urllib.request.urlopen` im Testprozess.
Lockfiles und alle Testdaten entstehen zur Laufzeit in tmp_path (keine Lockfiles mit verwundbaren Versionen im Repo). Der Test
mit dem echten osv-scanner läuft nur mit `SECURITY_AUDIT_NETZ=1`. Signale gehen nur an Prozessgruppen, die der getestete Code
selbst gestartet hat; die Tests enthalten keine Kill-Logik.
"""
import io
import json
import os
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
