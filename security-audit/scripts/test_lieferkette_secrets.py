"""Tests für `lieferkette.py secrets` und `gitkopie.spiegel` / `gitkopie.werkzeug_ausfuehren` (TF2, Task 1).

Aufruf: python3 -m pytest security-audit/scripts/test_lieferkette_secrets.py -q

Fake-`gitleaks` im Shim-PATH protokolliert jeden Aufruf (Argumente, cwd, Umgebung, Marker-Zustand) und liefert Berichte aus einer
Konfigurationsdatei. Echte gitleaks-Tests (`test_schwaerzung_echt_*`, `test_repo_konfig_wirkt_nicht_*`, `test_spiegel_*_echt`)
laufen nur, wenn das Binary installiert ist. Alle Repos, Zustandsordner und Testwerte liegen in tmp_path; Testwerte werden zur
Laufzeit erzeugt (keine echt aussehenden Secrets im öffentlichen Repo). Signale gehen nur an Prozessgruppen, die der getestete
Code selbst gestartet hat.
"""
import base64
import errno
import json
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import NamedTuple

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import gitkopie  # noqa: E402
import lieferkette  # noqa: E402

LIEFERKETTE = os.path.join(HIER, "lieferkette.py")
POC = os.path.join(HIER, "poc.py")
LAUF = "0a1b2c3d"
GITLEAKS = shutil.which("gitleaks")
echt = pytest.mark.skipif(GITLEAKS is None, reason="gitleaks nicht installiert")
SENTINELS = ("SENTINEL-SECRET", "SENTINEL-AUTHOR", "sentinel@example.invalid", "SENTINEL-MESSAGE", "SENTINEL-FINGERPRINT")

FAKE_GITLEAKS = '''#!{python}
import json, os, sys, time
args = sys.argv[1:]
modus = args[0] if args else ""
ziel = args[1] if len(args) > 1 else ""
cfg = json.load(open(os.environ["FAKE_GL_CONFIG"]))
verhalten = cfg.get(modus, {{}})
frueher = 0
if os.path.exists(os.environ["FAKE_GL_LOG"]):
    frueher = sum(1 for z in open(os.environ["FAKE_GL_LOG"]) if z.strip() and json.loads(z)["modus"] == modus)
if modus == "dir" and frueher > 0:                     # Prüfläufe nach der Schwärzung: `nach` je Lauf, danach findet er nichts mehr
    nach = verhalten.get("nach", [])
    verhalten = nach[frueher - 1] if frueher - 1 < len(nach) else {{}}


def opt(name):
    return args[args.index(name) + 1] if name in args else None


config = opt("--config")
ignore = opt("--gitleaks-ignore-path")
eintrag = {{
    "modus": modus, "args": args, "cwd": os.getcwd(), "cwd_leer": not os.listdir(os.getcwd()),
    "env": {{k: v for k, v in os.environ.items() if k.startswith(("GITLEAKS_", "GIT_", "OSV_"))}},
    "marker": os.path.exists(cfg["marker"]) if cfg.get("marker") else None,
    "config_text": open(config).read() if config and os.path.isfile(config) else None,
    "ignore_leer": bool(ignore and os.path.isdir(ignore) and not os.listdir(ignore)),
    "ignore_in_quelle": os.path.exists(os.path.join(ziel, ".gitleaksignore")) if modus == "dir" else None,
    "ziel_vorhanden": os.path.isdir(ziel),
    "report_pfad": opt("--report-path"),
}}
with open(os.environ["FAKE_GL_LOG"], "a") as f:
    f.write(json.dumps(eintrag) + "\\n")
if verhalten.get("sleep"):
    time.sleep(verhalten["sleep"])
pfad = opt("--report-path")
if "roh" in verhalten:
    open(pfad, "w").write(verhalten["roh"])
elif not verhalten.get("kein_report"):
    text = json.dumps(verhalten.get("report", [])).replace("{{ziel}}", ziel.replace("\\\\", "\\\\\\\\"))
    open(pfad, "w").write(text)
sys.stderr.write(verhalten.get("stderr", ""))
sys.exit(verhalten.get("rc", 0))
'''

SPIEGEL_SLEEP_GIT = '''#!/bin/sh
case "$*" in
  *clone*) sleep 30 ;;
esac
exec "{git}" "$@"
'''


def geheimnis(seed, laenge=32):
    """Zur Laufzeit erzeugter, zufällig aussehender Testwert (alphanumerisch, hohe Entropie)."""
    return "".join(random.Random(seed).choices(string.ascii_letters + string.digits, k=laenge))


WERT = geheimnis(20261110)
JS_ZEILE = f'const apiKey = "{WERT}";\n'


class Umgebung:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.log_datei = tmp_path / "gitleaks.log"
        self.config_datei = tmp_path / "gitleaks.json"
        self.config_datei.write_text("{}")

    def env(self, **extra):
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "HOME": str(self.home), "TMPDIR": str(self.tmp),
               "FAKE_GL_LOG": str(self.log_datei), "FAKE_GL_CONFIG": str(self.config_datei),
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        env.update(extra)
        return env

    def zustand(self, lauf=LAUF):
        return os.path.join(os.path.realpath(self.tmp), f"security-audit-{lauf}")

    def lieferkette_ordner(self, lauf=LAUF):
        return os.path.join(self.zustand(lauf), "lieferkette")

    def marker(self, lauf=LAUF):
        return os.path.join(self.lieferkette_ordner(lauf), "geschwaerzt")

    def fake_gitleaks(self, **verhalten):
        """Fake-`gitleaks` im Shim-PATH; `verhalten` je Modus: {"dir": {...}, "git": {...}}."""
        fake = self.bin / "gitleaks"
        fake.write_text(FAKE_GITLEAKS.format(python=sys.executable))
        fake.chmod(0o755)
        self.konfig(**verhalten)

    def konfig(self, **verhalten):
        cfg = dict(verhalten)
        cfg["marker"] = self.marker()
        self.config_datei.write_text(json.dumps(cfg))

    def aufrufe(self):
        if not self.log_datei.exists():
            return []
        return [json.loads(z) for z in self.log_datei.read_text().splitlines() if z]

    def lk(self, *args, env=None, timeout=120):
        return subprocess.run([sys.executable, "-I", LIEFERKETTE, *args], env=env or self.env(),
                              capture_output=True, text=True, timeout=timeout)

    def poc(self, *args, env=None):
        return subprocess.run([sys.executable, "-I", POC, *args], env=env or self.env(), capture_output=True, text=True,
                              timeout=120)

    def git(self, repo, *args):
        r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                            *args], env=self.env(), capture_output=True, timeout=60)
        assert r.returncode == 0, r.stderr.decode(errors="replace")
        return r.stdout.decode().strip()


class Vorbereitet(NamedTuple):
    repo: str
    quelle: str
    shas: list
    sha: str


@pytest.fixture
def umg(tmp_path):
    return Umgebung(tmp_path)


@pytest.fixture(autouse=True)
def sauberes_home(tmp_path, monkeypatch):
    """In-Process-Aufrufe (gitkopie, lieferkette) laufen hermetisch: eigenes HOME, keine geerbten GIT_*/SECURITY_AUDIT_*-Variablen."""
    home = tmp_path / "home-inproc"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in list(os.environ):
        if (name.startswith("GIT_") and name not in ("GIT_CONFIG_NOSYSTEM", "GIT_EXEC_PATH")) or name.startswith(
                ("GITLEAKS_", "OSV_", "SECURITY_AUDIT_")):
            monkeypatch.delenv(name)
    gitkopie.frist_setzen(None)
    yield
    gitkopie.frist_setzen(None)


def schreibe(wurzel, pfad, inhalt):
    ziel = os.path.join(wurzel, pfad)
    os.makedirs(os.path.dirname(ziel), exist_ok=True)
    with open(ziel, "wb") as f:
        f.write(inhalt if isinstance(inhalt, bytes) else inhalt.encode())


def repo_bauen(umg, commits, name="kunde"):
    """commits: Liste von Dicts Pfad -> Bytes/str (Inhalt) oder None (löschen); eine Funktion `f(bisherige_shas) -> dict` ist
    ebenfalls erlaubt. Rückgabe: (Pfad, SHAs alt → neu)."""
    repo = umg.tmp_path / name
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=umg.env())
    shas = []
    for i, aenderung in enumerate(commits):
        aenderung = aenderung(list(shas)) if callable(aenderung) else aenderung
        for pfad, inhalt in aenderung.items():
            if inhalt is None:
                umg.git(repo, "rm", "-q", "--", pfad)
            else:
                schreibe(str(repo), pfad, inhalt)
        umg.git(repo, "add", "-A", "-f")
        umg.git(repo, "commit", "-q", "--allow-empty", "-m", f"c{i}")
        shas.append(umg.git(repo, "rev-parse", "HEAD"))
    return str(repo), shas


def vorbereiten(umg, commits, sha=None, name="kunde"):
    repo, shas = repo_bauen(umg, commits, name)
    args = ["vorbereiten", "--lauf", LAUF, "--repo", repo]
    if sha:
        args += ["--sha", sha]
    r = umg.poc(*args)
    assert r.returncode == 0, r.stderr
    return Vorbereitet(repo, os.path.join(umg.zustand(), "quelle"), shas, sha or shas[-1])


def secrets(umg, v, *extra, env=None, quelle=None, sha=None):
    return umg.lk("secrets", "--lauf", LAUF, "--repo", v.repo, "--quelle", quelle or v.quelle, "--sha", sha or v.sha,
                  *extra, env=env)


def ausgabe(r):
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)


def treffer(regel="generic-api-key", datei="src/a.js", zeile=1, von=7, bis=49, match='apiKey = "REDACTED"', commit="",
            datum="2026-01-01T00:00:00Z", **extra):
    d = {"RuleID": regel, "Description": "Detected a Generic API Key", "StartLine": zeile, "EndLine": zeile,
         "StartColumn": von, "EndColumn": bis, "Match": match, "Secret": "SENTINEL-SECRET", "File": datei,
         "SymlinkFile": "", "Commit": commit, "Entropy": 4.5, "Author": "SENTINEL-AUTHOR",
         "Email": "sentinel@example.invalid", "Date": datum, "Message": "SENTINEL-MESSAGE", "Tags": [],
         "Fingerprint": "SENTINEL-FINGERPRINT"}
    d.update(extra)
    return d


def dir_treffer(inhalt, datei="src/a.js", regel="generic-api-key", wert=WERT, **extra):
    """dir-Fundstelle für `apiKey = "<wert>"` in `inhalt` (Bytes) mit den Koordinaten von gitleaks 8.30 (Byte-Spalten, ab
    Zeile 2 um 1 verschoben)."""
    voll = b'apiKey = "' + wert.encode() + b'"'
    i = inhalt.index(voll)
    zeile = inhalt.count(b"\n", 0, i) + 1
    sc = i - (inhalt.rfind(b"\n", 0, i) + 1) + 1
    ec = sc + len(voll) - 1
    if zeile > 1:
        sc, ec = sc + 1, ec + 1
    return treffer(regel=regel, datei="{ziel}/" + datei, zeile=zeile, von=sc, bis=ec, **extra)


def lieferkette_inhalt(umg):
    pfad = umg.lieferkette_ordner()
    return sorted(os.listdir(pfad)) if os.path.isdir(pfad) else []


def lesen(pfad):
    with open(pfad, "rb") as f:
        return f.read()


MINI = {"src/a.js": JS_ZEILE, "package.json": "{}"}


# ------------------------------------------------------------------------------------ werkzeug_ausfuehren

def test_werkzeug_ausfuehren_liefert_rc_und_ausgabe(tmp_path):
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", "import sys; print('a'); sys.stderr.write('b'); sys.exit(3)"],
                                     10, str(tmp_path))
    assert r.rc == 3 and r.out.strip() == b"a" and r.err == b"b"


def test_werkzeug_ausfuehren_cwd_und_umgebung(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/x")
    monkeypatch.setenv("GITLEAKS_CONFIG", "/y")
    r = gitkopie.werkzeug_ausfuehren(
        [sys.executable, "-c", "import os, json; print(json.dumps([os.getcwd(), sorted(k for k in os.environ if k.startswith(('GIT_', 'GITLEAKS_')))]))"],
        10, str(tmp_path))
    cwd, namen = json.loads(r.out)
    assert os.path.realpath(cwd) == os.path.realpath(tmp_path)
    assert "GIT_DIR" not in namen and "GITLEAKS_CONFIG" not in namen and "GIT_CONFIG_NOSYSTEM" in namen


def test_werkzeug_ausfuehren_timeout_beendet_eigene_gruppe(tmp_path):
    start = time.monotonic()
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", "import time; time.sleep(60)"], 1, str(tmp_path))
    assert r.rc is None
    assert time.monotonic() - start < 20


def test_werkzeug_ausfuehren_nicht_startbar(tmp_path):
    with pytest.raises(gitkopie.GitFehler):
        gitkopie.werkzeug_ausfuehren([str(tmp_path / "gibt-es-nicht")], 5, str(tmp_path))


# ------------------------------------------------------------------------------------ Spiegel

def marker_skript(tmp_path, name):
    skript = tmp_path / name
    skript.write_text(f"#!/bin/sh\ntouch '{tmp_path}/MARKER-{name}'\ncat\n")
    skript.chmod(0o755)
    return skript


def test_spiegel_klont_alle_refs(umg, tmp_path):
    repo, shas = repo_bauen(umg, [{"a.txt": "1"}, {"a.txt": "2"}])
    umg.git(repo, "branch", "nebenzweig", shas[0])
    umg.git(repo, "tag", "v1", shas[0])
    ziel = str(tmp_path / "spiegel.git")
    hinweise = gitkopie.spiegel(repo, ziel, 60)
    assert hinweise == []
    def refs(pfad):
        return gitkopie.git(pfad, "for-each-ref", "--format=%(refname) %(objectname)").stdout.decode().splitlines()
    assert refs(ziel) == refs(repo)
    assert gitkopie.git(ziel, "rev-parse", "--is-bare-repository").stdout.strip() == b"true"
    assert gitkopie.git(ziel, "cat-file", "-e", f"{shas[0]}:a.txt").returncode == 0


def test_spiegel_keine_treiber_ausgefuehrt(umg, tmp_path):
    """Filter, Textconv, Fsmonitor und Hooks aus der Konfiguration des Kundenrepos laufen weder beim Klonen noch danach."""
    repo, shas = repo_bauen(umg, [{"a.txt": "1", ".gitattributes": "* filter=x diff=x\n"}, {"a.txt": "2"}])
    skripte = {n: marker_skript(tmp_path, n) for n in ("clean.sh", "smudge.sh", "textconv.sh", "fsm.sh", "pack.sh")}
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for h in ("post-checkout", "post-merge", "reference-transaction", "pre-auto-gc", "post-update"):
        (hooks / h).write_text(f"#!/bin/sh\ntouch '{tmp_path}/MARKER-{h}'\n")
        (hooks / h).chmod(0o755)
    for schluessel, wert in {"filter.x.clean": skripte["clean.sh"], "filter.x.smudge": skripte["smudge.sh"],
                             "filter.x.process": skripte["smudge.sh"], "diff.x.textconv": skripte["textconv.sh"],
                             "core.fsmonitor": skripte["fsm.sh"], "core.hooksPath": hooks,
                             "uploadpack.packObjectsHook": skripte["pack.sh"]}.items():
        umg.git(repo, "config", schluessel, str(wert))
    ziel = str(tmp_path / "spiegel.git")
    gitkopie.spiegel(repo, ziel, 60)
    gitkopie.git(ziel, "log", "-p", "--all")                          # was gitleaks danach tut
    assert sorted(p.name for p in tmp_path.glob("MARKER-*")) == []
    config = (tmp_path / "spiegel.git" / "config").read_text()
    assert "textconv" not in config and "filter" not in config and "fsmonitor" not in config


def test_spiegel_versteckte_refs_hinweis(umg, tmp_path):
    repo, shas = repo_bauen(umg, [{"a.txt": "1"}])
    umg.git(repo, "branch", "geheim-intern", shas[0])
    umg.git(repo, "config", "transfer.hideRefs", "refs/heads/geheim-intern")
    ziel = str(tmp_path / "spiegel.git")
    hinweise = gitkopie.spiegel(repo, ziel, 60)
    assert len(hinweise) == 1 and "Refs fehlen im Spiegel" in hinweise[0] and "refs/heads/geheim-intern" in hinweise[0]


def test_spiegel_flache_quelle_hinweis(umg, tmp_path):
    repo, _ = repo_bauen(umg, [{"a.txt": "1"}, {"a.txt": "2"}, {"a.txt": "3"}])
    flach = str(tmp_path / "flach")
    r = subprocess.run(["git", "clone", "-q", "--depth", "1", "--no-local", repo, flach], env=umg.env(), capture_output=True)
    assert r.returncode == 0, r.stderr
    hinweise = gitkopie.spiegel(flach, str(tmp_path / "spiegel.git"), 60)
    assert any("flach" in h and "shallow" in h for h in hinweise)


def test_spiegel_budget_wirft_zeitbudgetfehler(umg, tmp_path, monkeypatch):
    """Ein hängender Klon wird nach der Frist beendet (nur die eigene Gruppe) und als ZeitbudgetFehler gemeldet."""
    repo, _ = repo_bauen(umg, [{"a.txt": "1"}])
    git_echt = shutil.which("git")
    (umg.bin / "git").write_text(SPIEGEL_SLEEP_GIT.format(git=git_echt))
    (umg.bin / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{umg.bin}{os.pathsep}{os.environ['PATH']}")
    start = time.monotonic()
    with pytest.raises(gitkopie.ZeitbudgetFehler):
        gitkopie.spiegel(repo, str(tmp_path / "spiegel.git"), 1)
    assert time.monotonic() - start < 20


def test_spiegel_fehler_bei_ungueltiger_quelle(tmp_path):
    with pytest.raises(gitkopie.GitFehler):
        gitkopie.spiegel(str(tmp_path / "kein-repo"), str(tmp_path / "spiegel.git"), 20)


# ------------------------------------------------------------------------------------ schwaerzen (Einheit)

def datei_mit(tmp_path, inhalt, name="a.js"):
    pfad = tmp_path / name
    pfad.write_bytes(inhalt)
    return str(pfad)


def test_schwaerzen_zeile_1_behaelt_praefix_und_suffix(tmp_path):
    inhalt = JS_ZEILE.encode()
    pfad = datei_mit(tmp_path, inhalt)
    hinweise = lieferkette.schwaerzen(pfad, [dir_treffer(inhalt, datei="a.js") | {"File": pfad}])
    assert hinweise == []
    assert lesen(pfad) == f'const apiKey = "{"*" * len(WERT)}";\n'.encode()


def test_schwaerzen_zeile_ueber_1_korrigiert_verschiebung(tmp_path):
    inhalt = ("// kopf\nfoo();\n" + JS_ZEILE + "bar();\n").encode()
    pfad = datei_mit(tmp_path, inhalt)
    t = dir_treffer(inhalt, datei="a.js") | {"File": pfad}
    assert t["StartLine"] == 3 and t["StartColumn"] == 8                      # so meldet gitleaks 8.30 (1-basiert + 1)
    assert lieferkette.schwaerzen(pfad, [t]) == []
    assert lesen(pfad) == inhalt.replace(WERT.encode(), b"*" * len(WERT))


def test_schwaerzen_utf8_vor_dem_treffer_zaehlt_bytes(tmp_path):
    inhalt = ("// ä😀\nvar s = 'ä😀' + " + f'apiKey = "{WERT}"' + ";\n").encode()
    pfad = datei_mit(tmp_path, inhalt)
    assert lieferkette.schwaerzen(pfad, [dir_treffer(inhalt, datei="a.js") | {"File": pfad}]) == []
    assert lesen(pfad) == inhalt.replace(WERT.encode(), b"*" * len(WERT))
    assert "ä😀".encode() in lesen(pfad)


def test_schwaerzen_endspalte_hinter_zeilenende_wird_geklemmt(tmp_path):
    inhalt = f'x\nconst apiKey = "{WERT}"'.encode()                           # kein Zeilenende, Suffix `"` am Ende
    pfad = datei_mit(tmp_path, inhalt)
    t = dir_treffer(inhalt, datei="a.js") | {"File": pfad}
    t["EndColumn"] += 5                                                      # gitleaks meldet gelegentlich zu weit
    t["Match"] = 'apiKey = "REDACTED"'
    assert lieferkette.schwaerzen(pfad, [t]) == []                           # auf das Zeilenende geklemmt: Suffix `"` passt
    assert lesen(pfad) == inhalt.replace(WERT.encode(), b"*" * len(WERT))


def test_schwaerzen_ohne_end_newline_und_crlf(tmp_path):
    inhalt = f'a\r\nb\r\nconst apiKey = "{WERT}";\r\nrest\r\n'.encode()
    pfad = datei_mit(tmp_path, inhalt)
    assert lieferkette.schwaerzen(pfad, [dir_treffer(inhalt, datei="a.js") | {"File": pfad}]) == []
    neu = lesen(pfad)
    assert neu == inhalt.replace(WERT.encode(), b"*" * len(WERT))
    assert neu.count(b"\r\n") == 4


def test_schwaerzen_decoded_schwaerzt_ganzes_segment(tmp_path):
    b64 = base64.b64encode(f'password = "{WERT}"'.encode()).decode()
    inhalt = f"x\ndata = {b64}\ny\n".encode()
    pfad = datei_mit(tmp_path, inhalt, "h.txt")
    sc = len("data = ") + 1 + 1                                              # 1-basiert, Zeile 2: +1
    t = treffer(regel="generic-api-key", datei=pfad, zeile=2, von=sc, bis=sc + len(b64) - 1, match='password = "REDACTED"',
                Tags=["decoded:base64", "decode-depth:1"])
    assert lieferkette.schwaerzen(pfad, [t]) == []
    assert lesen(pfad) == f"x\ndata = {'*' * len(b64)}\ny\n".encode()


def test_schwaerzen_mehrzeilig_behaelt_umbrueche(tmp_path):
    pem = "-----BEGIN RSA PRIVATE KEY-----\r\nAAAAAAAAAAAA\r\nBBBBBBBBBBBB\r\n-----END RSA PRIVATE KEY-----"
    inhalt = f"kopf\r\n{pem}\r\nende\r\n".encode()
    pfad = datei_mit(tmp_path, inhalt, "k.pem")
    t = treffer(regel="private-key", datei=pfad, zeile=2, von=2, bis=len("-----END RSA PRIVATE KEY-----") + 1,
                match="REDACTED")
    t["EndLine"] = 5
    assert lieferkette.schwaerzen(pfad, [t]) == []
    neu = lesen(pfad)
    assert len(neu) == len(inhalt) and neu.count(b"\n") == inhalt.count(b"\n") and neu.count(b"\r") == inhalt.count(b"\r")
    assert neu.startswith(b"kopf\r\n") and neu.endswith(b"\r\nende\r\n")
    assert b"AAAA" not in neu and b"BEGIN" not in neu and b"END RSA" not in neu


def test_schwaerzen_unscharf_schwaerzt_ganze_spanne_ohne_umbrueche(tmp_path):
    inhalt = f'ab\nconst apiKey = "{WERT}";\nzz\n'.encode()
    pfad = datei_mit(tmp_path, inhalt)
    t = dir_treffer(inhalt, datei="a.js") | {"File": pfad, "Match": 'passwort = "REDACTED"'}   # Präfix passt nicht
    hinweise = lieferkette.schwaerzen(pfad, [t], wurzel=str(tmp_path))
    assert hinweise == ["Schwärzung unscharf: a.js:2"]
    voll = f'apiKey = "{WERT}"'.encode()
    assert lesen(pfad) == b"ab\nconst " + b"*" * len(voll) + b";\nzz\n"      # ganze Spanne, Umbrüche bleiben


def test_schwaerzen_ueberlappende_treffer_gleicher_wert(tmp_path):
    inhalt = JS_ZEILE.encode()
    pfad = datei_mit(tmp_path, inhalt)
    t1 = dir_treffer(inhalt, datei="a.js") | {"File": pfad}
    t2 = dir_treffer(inhalt, datei="a.js", regel="andere-regel") | {"File": pfad}
    assert lieferkette.schwaerzen(pfad, [t1, t2]) == []                      # beide gegen das Original geprüft
    assert lesen(pfad) == f'const apiKey = "{"*" * len(WERT)}";\n'.encode()


def test_schwaerzen_zeile_ausserhalb_der_datei_wirft(tmp_path):
    inhalt = JS_ZEILE.encode()
    pfad = datei_mit(tmp_path, inhalt)
    t = dir_treffer(inhalt, datei="a.js") | {"File": pfad, "StartLine": 9, "EndLine": 9}
    with pytest.raises(lieferkette.SchwaerzFehler):
        lieferkette.schwaerzen(pfad, [t])
    assert lesen(pfad) == inhalt


def test_schwaerzen_schreibt_keinen_symlink(tmp_path):
    ziel = tmp_path / "ziel.js"
    ziel.write_bytes(JS_ZEILE.encode())
    link = tmp_path / "link.js"
    os.symlink(ziel, link)
    with pytest.raises(lieferkette.SchwaerzFehler):
        lieferkette.schwaerzen(str(link), [dir_treffer(JS_ZEILE.encode(), datei="x") | {"File": str(link)}])
    assert ziel.read_bytes() == JS_ZEILE.encode()


def test_schwaerzen_behaelt_dateirechte(tmp_path):
    pfad = datei_mit(tmp_path, JS_ZEILE.encode())
    os.chmod(pfad, 0o755)
    lieferkette.schwaerzen(pfad, [dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": pfad}])
    assert stat.S_IMODE(os.stat(pfad).st_mode) == 0o755


# ------------------------------------------------------------------------------------ secrets (Fake-gitleaks)

def historie(v, *eintraege, regel="generic-api-key", datei="src/a.js"):
    return [treffer(regel=regel, datei=datei, commit=sha, **kw) for sha, kw in eintraege]


def test_secrets_ausgabe_ohne_wertfelder(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]},
                      git={"report": [treffer(commit=v.shas[0])]})
    r = secrets(umg, v)
    out = ausgabe(r)
    for sentinel in SENTINELS:
        assert sentinel not in r.stdout and sentinel not in r.stderr
    gesamt = r.stdout + r.stderr
    for feld in ("Secret", "Match", "Author", "Email", "Message", "Fingerprint"):
        assert f'"{feld}"' not in gesamt
    assert set(out) == {"befunde_roh", "hinweise", "geschwaerzt"}
    assert out["befunde_roh"] == [{"regel": "generic-api-key", "datei": "src/a.js", "zeile": 1, "commits": [v.shas[0]],
                                   "in_head": True}]
    assert out["geschwaerzt"] == 1
    assert "1 Secret-Fundstellen in der Arbeitskopie geschwärzt" in out["hinweise"]


def test_secrets_reihenfolge_dir_vor_git_und_optionen(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    r = secrets(umg, v, env=umg.env(GITLEAKS_CONFIG="/geerbt.toml", GITLEAKS_BASELINE_PATH="/b", OSV_SCANNER_CONFIG="/o",
                                    GIT_DIR="/g", GIT_WORK_TREE="/w"))
    ausgabe(r)
    aufrufe = umg.aufrufe()
    assert [a["modus"] for a in aufrufe] == ["dir", "git"]
    lk = os.path.realpath(umg.lieferkette_ordner())
    for a in aufrufe:
        args = a["args"]
        assert args[1] == (v.quelle if a["modus"] == "dir" else os.path.join(lk, "spiegel.git"))
        for opt in ("--redact", "--no-banner", "--ignore-gitleaks-allow"):
            assert opt in args
        assert args[args.index("--exit-code") + 1] == "0" and args[args.index("--report-format") + 1] == "json"
        assert a["config_text"].strip().splitlines() == ["[extend]", "useDefault = true"]
        assert not os.path.realpath(args[args.index("--config") + 1]).startswith((v.quelle, v.repo))
        assert a["ignore_leer"] is True                                          # leerer Ordner, keine Repo-.gitleaksignore
        assert os.path.realpath(a["cwd"]).startswith(lk + os.sep) and a["cwd_leer"] is True
        assert not [k for k in a["env"] if k.startswith(("GITLEAKS_", "OSV_"))]
        assert set(a["env"]) == {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT",
                                 "GIT_OPTIONAL_LOCKS"}
        assert a["env"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert not args[args.index("--report-path") + 1].startswith((v.quelle, v.repo))


def test_secrets_aufraeumen(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]}, git={"report": [treffer(commit=v.shas[0])]})
    ausgabe(secrets(umg, v))
    assert lieferkette_inhalt(umg) == ["geschwaerzt"]                           # Reports, Spiegel, Config, leere Ordner weg
    assert not os.path.lexists(os.path.join(umg.lieferkette_ordner(), "spiegel.git"))


def test_secrets_gitleaks_fehlt_ohne_env_und_im_path(umg):
    v = vorbereiten(umg, [MINI])
    r = secrets(umg, v, env=umg.env(PATH=str(umg.bin)))                         # kein gitleaks im PATH
    out = ausgabe(r)
    assert out["werkzeug"] == "gitleaks" and out["fehlt"] is True
    assert "gitleaks fehlt" in out["hinweis"] and any("gitleaks fehlt" in h for h in out["hinweise"])
    assert out["befunde_roh"] == [] and not os.path.lexists(umg.marker())
    assert lesen(os.path.join(v.quelle, "src/a.js")) == JS_ZEILE.encode()    # nichts angefasst


@pytest.mark.parametrize("ohne", ["gitleaks", " Gitleaks , osv-scanner", "docker,GITLEAKS"])
def test_secrets_gitleaks_fehlt_per_ohne(umg, ohne):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]})
    out = ausgabe(secrets(umg, v, env=umg.env(SECURITY_AUDIT_OHNE=ohne)))
    assert out["werkzeug"] == "gitleaks" and out["fehlt"] is True and out["befunde_roh"] == []
    assert umg.aufrufe() == [] and not os.path.lexists(umg.marker())
    assert lesen(os.path.join(v.quelle, "src/a.js")) == JS_ZEILE.encode()


def test_secrets_gitleaksignore_wird_aus_arbeitskopie_entfernt(umg):
    v = vorbereiten(umg, [dict(MINI, **{".gitleaksignore": "x:y:1\n", "sub/dir/.gitleaksignore": "x:y:2\n",
                                         "sub/.gitleaksignore.bak": "bleibt\n"})])
    assert os.path.exists(os.path.join(v.quelle, ".gitleaksignore"))
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))
    assert umg.aufrufe()[0]["ignore_in_quelle"] is False                       # schon beim dir-Aufruf weg
    assert not os.path.lexists(os.path.join(v.quelle, ".gitleaksignore"))
    assert not os.path.lexists(os.path.join(v.quelle, "sub/dir/.gitleaksignore"))
    assert os.path.exists(os.path.join(v.quelle, "sub/.gitleaksignore.bak"))   # nur exakt `.gitleaksignore`
    assert os.path.exists(os.path.join(v.quelle, "src/a.js")) and os.path.isdir(v.repo)


def test_repo_konfig_hinweise(umg):
    v = vorbereiten(umg, [dict(MINI, **{".gitleaks.toml": "[allowlist]\n", ".gitleaksignore": "x\n",
                                         "web/osv-scanner.toml": "[[IgnoredVulns]]\n",
                                         "src/b.js": 'const k = "x"; // gitleaks:allow\n'})])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    out = ausgabe(secrets(umg, v))
    text = "\n".join(out["hinweise"])
    assert ".gitleaks.toml" in text and ".gitleaksignore" in text and "web/osv-scanner.toml" in text
    assert "gitleaks:allow" in text and "src/b.js" in text
    assert all("ignoriert" in h for h in out["hinweise"] if ("Standardausnahmen" not in h) and (".toml" in h or "allow" in h))
    for name in (".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml"):
        assert any(h.startswith(f"{name} im Repo vorhanden, beim Audit ignoriert") for h in out["hinweise"]), name
    assert any(h.startswith("gitleaks:allow-Kommentare im Repo vorhanden, beim Audit ignoriert") for h in out["hinweise"])
    assert any(h.startswith("gitleaks-Standardausnahmen nicht geprüft:") and ".gitleaks.toml" in h for h in out["hinweise"])
    assert os.path.exists(os.path.join(v.quelle, ".gitleaks.toml")) and os.path.exists(os.path.join(v.quelle, "web/osv-scanner.toml"))
    assert not os.path.exists(os.path.join(v.quelle, ".gitleaksignore"))        # erkannt, bevor sie gelöscht wurde


def test_repo_konfig_hinweise_ohne_konfig_keine_meldung(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    assert ausgabe(secrets(umg, v))["hinweise"] == []


def test_marker_gesetzt_und_vor_historie(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]}, git={"report": []})
    ausgabe(secrets(umg, v))
    dir_aufruf, pruef_aufruf, git_aufruf = umg.aufrufe()                         # dir, Prüflauf nach der Schwärzung, git
    assert [a["modus"] for a in (dir_aufruf, pruef_aufruf, git_aufruf)] == ["dir", "dir", "git"]
    assert dir_aufruf["marker"] is False and pruef_aufruf["marker"] is False and git_aufruf["marker"] is True  # test_marker_vor_historie
    assert os.path.isfile(umg.marker()) and not os.path.islink(umg.marker())


def test_marker_ohne_treffer(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    out = ausgabe(secrets(umg, v))
    assert out["geschwaerzt"] == 0 and out["befunde_roh"] == [] and os.path.isfile(umg.marker())


def test_marker_alt_wird_vor_dem_lauf_entfernt(umg):
    v = vorbereiten(umg, [MINI])
    os.makedirs(umg.lieferkette_ordner(), exist_ok=True)
    open(umg.marker(), "w").close()
    umg.fake_gitleaks(dir={"rc": 2})
    assert secrets(umg, v).returncode == 4
    assert not os.path.lexists(umg.marker())


@pytest.mark.parametrize("dir_verhalten", [
    {"rc": 2},
    {"rc": 1, "report": []},
    {"roh": "das ist kein json"},
    {"roh": '{"kein": "array"}'},
    {"kein_report": True},
    {"report": [{"RuleID": "x", "File": "{ziel}/src/a.js", "StartLine": "eins", "EndLine": 1, "StartColumn": 1, "EndColumn": 2}]},
])
def test_schwaerzung_scheitert_exit4_ohne_marker(umg, dir_verhalten):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir=dir_verhalten, git={"report": [treffer(commit=v.shas[0])]})
    r = secrets(umg, v)
    assert r.returncode == 4, r.stdout + r.stderr
    assert "nicht geschwärzt" in r.stdout + r.stderr
    assert "kategorie: schwaerzung-fehlgeschlagen" in r.stdout.splitlines()
    assert not os.path.lexists(umg.marker())
    assert [a["modus"] for a in umg.aufrufe()] == ["dir"]                         # keine Historie nach gescheiterter Schwärzung
    assert lieferkette_inhalt(umg) == []
    for sentinel in SENTINELS:
        assert sentinel not in r.stdout and sentinel not in r.stderr


def test_marker_setzen_in_unbeschreibbarem_ordner_wirft_oserror(tmp_path):
    ordner = tmp_path / "ro"
    ordner.mkdir()
    ordner.chmod(0o500)
    try:
        if os.access(ordner, os.W_OK):
            pytest.skip("Ordner trotz 0500 beschreibbar (root?)")
        with pytest.raises(OSError):
            lieferkette._marker_setzen(str(ordner / "geschwaerzt"), 0, "a" * 40, "k" * 32)
    finally:
        ordner.chmod(0o700)
    assert not os.path.lexists(ordner / "geschwaerzt")


def test_marker_nicht_setzbar_ist_exit4_ohne_marker(umg, monkeypatch, capsys):
    """Fehlerpfad von `_marker_setzen` im ganzen Befehl (in-process): Exit 4, `kategorie: schwaerzung-fehlgeschlagen`, kein
    Marker, keine Historie, Aufräumen."""
    v = vorbereiten(umg, [MINI])
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    monkeypatch.setattr(lieferkette, "fehlt", lambda name: False)
    monkeypatch.setattr(lieferkette, "_gitleaks_dir", lambda quelle, lk, ende: [])

    def marker_scheitert(marker, anzahl, sha, kopie):
        raise OSError(errno.EACCES, "Permission denied")

    def historie_darf_nicht_laufen(*args, **kwargs):
        raise AssertionError("Historie nach gescheiterter Schwärzung")

    monkeypatch.setattr(lieferkette, "_marker_setzen", marker_scheitert)
    monkeypatch.setattr(lieferkette, "_historie", historie_darf_nicht_laufen)
    rc = lieferkette.main(["secrets", "--lauf", LAUF, "--repo", v.repo, "--quelle", v.quelle, "--sha", v.sha])
    aus = capsys.readouterr()
    assert rc == 4
    assert "kategorie: schwaerzung-fehlgeschlagen" in aus.out.splitlines()
    assert "Marker nicht setzbar" in aus.err and "Permission denied" in aus.err
    assert not os.path.lexists(umg.marker())
    assert lieferkette_inhalt(umg) == []


def test_schwaerzung_scheitert_bei_zeitablauf_des_teilbudgets(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"sleep": 60, "report": []})
    start = time.monotonic()
    r = secrets(umg, v, env=umg.env(SECURITY_AUDIT_SECRETS_DIR_BUDGET="1"))
    assert r.returncode == 4 and "Zeit" in r.stdout + r.stderr
    assert time.monotonic() - start < 30
    assert not os.path.lexists(umg.marker()) and lieferkette_inhalt(umg) == []


def test_schwaerzung_unscharf_hinweis(umg):
    v = vorbereiten(umg, [dict(MINI, **{"src/a.js": "x\n" + JS_ZEILE})])
    inhalt = lesen(os.path.join(v.quelle, "src/a.js"))
    t = dir_treffer(inhalt) | {"Match": 'passwort = "REDACTED"'}
    umg.fake_gitleaks(dir={"report": [t]}, git={"report": []})
    out = ausgabe(secrets(umg, v))
    assert "Schwärzung unscharf: src/a.js:2" in out["hinweise"]
    neu = lesen(os.path.join(v.quelle, "src/a.js"))
    assert WERT.encode() not in neu and len(neu) == len(inhalt) and neu.count(b"\n") == 2
    assert os.path.isfile(umg.marker())


def test_schwaerzung_pfad_ausserhalb_nicht_geschrieben(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    ziele = {"absolut": aussen / "a.js", "punktpunkt": os.path.join(umg.zustand(), "aussen-b.js"),
             "relativ": os.path.join(os.path.realpath(umg.tmp), "c.js"), "symlink": str(tmp_path / "d.js")}
    ziele = {k: type(aussen)(z) for k, z in ziele.items()}
    for ziel in ziele.values():
        ziel.write_bytes(JS_ZEILE.encode())
    os.symlink(ziele["symlink"], os.path.join(v.quelle, "link.js"))               # Symlink in der Kopie zeigt nach außen
    treffer_liste = [
        dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": str(ziele["absolut"])},
        dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": os.path.join(v.quelle, "..", "aussen-b.js")},
        dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": "../../c.js"},
        dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": os.path.join(v.quelle, "link.js")},
    ]
    umg.fake_gitleaks(dir={"report": treffer_liste}, git={"report": []})
    vorher = {k: z.read_bytes() for k, z in ziele.items()}
    out = ausgabe(secrets(umg, v))
    assert {k: z.read_bytes() for k, z in ziele.items()} == vorher
    assert out["geschwaerzt"] == 0 and any("außerhalb" in h for h in out["hinweise"])
    assert os.path.isfile(umg.marker())


def test_secrets_mehrere_commits(umg):
    v = vorbereiten(umg, [MINI, {"x": "1"}, {"x": "2"}])
    a, b, c = v.shas
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(commit=a, zeile=3, datum="2026-01-01T10:00:00Z"),
        treffer(commit=c, zeile=7, datum="2026-03-01T10:00:00Z"),
        treffer(commit=b, zeile=5, datum="2026-02-01T10:00:00+01:00")]})
    out = ausgabe(secrets(umg, v))
    assert out["befunde_roh"] == [{"regel": "generic-api-key", "datei": "src/a.js", "zeile": 7, "commits": [c, b, a],
                                   "in_head": True}]                          # jüngster Commit zuerst, Zeile aus dem jüngsten
    assert all(len(x) == 40 for x in out["befunde_roh"][0]["commits"])


def test_secrets_dedup_je_regel_und_datei(umg):
    v = vorbereiten(umg, [MINI, {"src/b.js": "1"}])
    a, b = v.shas
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(regel="r1", datei="src/a.js", commit=a, zeile=1),
        treffer(regel="r2", datei="src/a.js", commit=a, zeile=1),            # ≥ 2 Regeln je Datei
        treffer(regel="r1", datei="src/b.js", commit=b, zeile=4),            # ≥ 2 Dateien je Regel
        treffer(regel="r1", datei="src/a.js", commit=b, zeile=2, datum="2027-01-01T00:00:00Z")]})
    out = ausgabe(secrets(umg, v))
    kurz = [(x["regel"], x["datei"], x["zeile"], x["commits"]) for x in out["befunde_roh"]]
    assert kurz == [("r1", "src/a.js", 2, [b, a]), ("r2", "src/a.js", 1, [a]), ("r1", "src/b.js", 4, [b])]


def test_secrets_commits_gekappt_auf_20(umg):
    v = vorbereiten(umg, [MINI])
    shas = [f"{i:040x}" for i in range(1, 26)]
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(commit=s, datum=f"2026-01-{i + 1:02d}T00:00:00Z") for i, s in enumerate(shas)]})
    out = ausgabe(secrets(umg, v))
    commits = out["befunde_roh"][0]["commits"]
    assert len(commits) == 20 and commits[0] == shas[-1] and commits[-1] == shas[5]


def test_secrets_verwirft_ungueltige_commits_und_dateinamen(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(commit="nicht-hex"), treffer(commit=v.shas[0], datei="src/‮gpj.js"), treffer(commit=v.shas[0], datei="")]})
    out = ausgabe(secrets(umg, v))
    assert [x["datei"] for x in out["befunde_roh"]] == ["src/\\u202egpj.js"]     # Bidi-Zeichen escaped, Ungültiges verworfen


def test_secrets_in_head_env_datei(umg):
    """`.env*` fehlt in der Arbeitskopie, liegt aber in HEAD; eine gelöschte Datei liegt nicht mehr in HEAD."""
    v = vorbereiten(umg, [{".env.local": f'KEY="{WERT}"\n', "alt.js": JS_ZEILE, "package.json": "{}"}, {"alt.js": None}])
    assert not os.path.exists(os.path.join(v.quelle, ".env.local"))
    a, b = v.shas
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(datei=".env.local", commit=a), treffer(datei="alt.js", commit=a)]})
    out = ausgabe(secrets(umg, v))
    in_head = {x["datei"]: x["in_head"] for x in out["befunde_roh"]}
    assert in_head == {".env.local": True, "alt.js": False}


def test_secrets_in_head_nutzt_den_uebergebenen_sha(umg):
    repo, shas = repo_bauen(umg, [{"alt.js": JS_ZEILE}, {"alt.js": None, "neu.txt": "1"}])
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo, "--sha", shas[0])
    assert r.returncode == 0, r.stderr
    v = Vorbereitet(repo, os.path.join(umg.zustand(), "quelle"), shas, shas[0])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [treffer(datei="alt.js", commit=shas[0])]})
    out = ausgabe(secrets(umg, v))
    assert out["befunde_roh"][0]["in_head"] is True                               # im übergebenen Commit, nicht in HEAD


def test_secrets_quelle_ausserhalb_verweigert(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    fremd = tmp_path / "fremd"
    schreibe(str(fremd), "src/a.js", JS_ZEILE)
    schreibe(str(fremd), ".gitleaksignore", "x\n")
    open(fremd / "quelle.fertig", "w").close()
    vorher = {p: lesen(os.path.join(fremd, p)) for p in ("src/a.js", ".gitleaksignore")}
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]})
    r = secrets(umg, v, quelle=str(fremd))
    assert r.returncode == 2 and "quelle" in r.stderr.lower()
    assert {p: lesen(os.path.join(fremd, p)) for p in vorher} == vorher
    assert umg.aufrufe() == [] and not os.path.lexists(umg.marker())
    # auch der Elternordner der echten Quelle und ein `..`-Pfad zählen nicht
    for falsch in (umg.zustand(), os.path.join(v.quelle, "..", "quelle", "src")):
        assert secrets(umg, v, quelle=falsch).returncode == 2


def test_secrets_quelle_ohne_fertig_marker_verweigert(umg):
    v = vorbereiten(umg, [MINI])
    os.unlink(os.path.join(umg.zustand(), "quelle.fertig"))
    umg.fake_gitleaks(dir={"report": []})
    r = secrets(umg, v)
    assert r.returncode == 2 and umg.aufrufe() == []


def test_secrets_symlink_auf_echte_quelle_ist_erlaubt(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    link = tmp_path / "quelle-link"
    link.symlink_to(v.quelle)
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    assert secrets(umg, v, quelle=str(link)).returncode == 0


def test_secrets_ungueltige_argumente(umg):
    v = vorbereiten(umg, [MINI])
    assert umg.lk("secrets", "--lauf", "xyz", "--repo", v.repo, "--quelle", v.quelle, "--sha", v.sha).returncode == 2
    assert umg.lk("secrets", "--lauf", LAUF, "--repo", v.repo, "--quelle", v.quelle, "--sha", "HEAD").returncode == 2
    assert umg.lk("secrets", "--lauf", LAUF, "--repo", str(umg.tmp_path / "nix"), "--quelle", v.quelle,
                  "--sha", v.sha).returncode == 2
    assert umg.lk("unbekannt").returncode == 2


def test_secrets_budget_beendet_historie_und_raeumt_auf(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]}, git={"sleep": 60, "report": []})
    start = time.monotonic()
    r = secrets(umg, v, env=umg.env(SECURITY_AUDIT_SECRETS_BUDGET="3"))
    out = ausgabe(r)
    assert time.monotonic() - start < 40
    assert "Secret-Prüfung abgebrochen (Zeitbudget)" in out["hinweise"]
    assert os.path.isfile(umg.marker())                                          # Schwärzung war fertig
    assert lieferkette_inhalt(umg) == ["geschwaerzt"]                              # Spiegel und Reports trotzdem gelöscht
    assert out["befunde_roh"] == [] and out["geschwaerzt"] == 1


def test_secrets_budget_im_spiegelklon(umg, monkeypatch):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    git_echt = shutil.which("git")
    (umg.bin / "git").write_text(SPIEGEL_SLEEP_GIT.format(git=git_echt))
    (umg.bin / "git").chmod(0o755)
    start = time.monotonic()
    out = ausgabe(secrets(umg, v, env=umg.env(SECURITY_AUDIT_SECRETS_BUDGET="3")))
    assert time.monotonic() - start < 40
    assert "Secret-Prüfung abgebrochen (Zeitbudget)" in out["hinweise"]
    assert [a["modus"] for a in umg.aufrufe()] == ["dir"]
    assert lieferkette_inhalt(umg) == ["geschwaerzt"]


def test_secrets_git_fehler_ist_hinweis_und_kein_exit4(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"rc": 1})
    out = ausgabe(secrets(umg, v))
    assert any("Historie" in h and "fehlgeschlagen" in h for h in out["hinweise"])
    assert os.path.isfile(umg.marker()) and out["befunde_roh"] == []


def test_secrets_stderr_von_gitleaks_wird_nicht_ausgegeben(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [], "stderr": "SENTINEL-SECRET im Log\n"}, git={"rc": 1, "stderr": "SENTINEL-MESSAGE\n"})
    r = secrets(umg, v)
    assert "SENTINEL" not in r.stdout + r.stderr


def test_secrets_ordner_der_quelle_nur_anlegen_wo_erlaubt(umg):
    """`lieferkette` im Zustandsordner darf kein Symlink sein."""
    v = vorbereiten(umg, [MINI])
    ziel = umg.tmp_path / "umgeleitet"
    ziel.mkdir()
    (ziel / "wichtig.txt").write_text("bleibt")
    os.symlink(ziel, umg.lieferkette_ordner())
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    r = secrets(umg, v)
    assert r.returncode != 0 and (ziel / "wichtig.txt").read_text() == "bleibt" and sorted(os.listdir(ziel)) == ["wichtig.txt"]


# ------------------------------------------------------------------------------------ Standardausnahmen, Budget, Zeitstempel

def test_secrets_hinweis_standard_ausnahmen(umg):
    """Dateien, die gitleaks standardmäßig überspringt (Text, nicht leer, ohne NUL), werden als Klasse mit Anzahl genannt; Inhalte
    und Binärdateien nicht."""
    dateien = dict(MINI, **{"package-lock.json": JS_ZEILE, "web/yarn.lock": JS_ZEILE, "node_modules/x/a.js": JS_ZEILE,
                            "assets/logo.svg": JS_ZEILE, "assets/bild.png": b"\x89PNG\x00\x00" + JS_ZEILE.encode(),
                            "leer.svg": ""})
    v = vorbereiten(umg, [dateien])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    out = ausgabe(secrets(umg, v))
    hinweise = [h for h in out["hinweise"] if h.startswith("gitleaks-Standardausnahmen nicht geprüft:")]
    assert len(hinweise) == 1, out["hinweise"]
    hinweis = hinweise[0]
    assert "Paketsperrdateien (2" in hinweis and "node_modules" in hinweis and "(1" in hinweis
    assert "package-lock.json" in hinweis and "web/yarn.lock" in hinweis and "assets/logo.svg" in hinweis
    assert "bild.png" not in hinweis and "leer.svg" not in hinweis                  # binär bzw. leer: nichts zu prüfen
    assert WERT not in json.dumps(out) and "apiKey" not in json.dumps(out)
    assert os.path.isfile(umg.marker())                                             # nur Hinweis, kein Abbruch


def test_secrets_hinweis_standard_ausnahmen_fehlt_ohne_solche_dateien(umg):
    v = vorbereiten(umg, [dict(MINI, **{"vendor/a.js": JS_ZEILE, "x.min.js": JS_ZEILE, "x.lock": JS_ZEILE})])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    assert not [h for h in ausgabe(secrets(umg, v))["hinweise"] if "Standardausnahmen" in h]


def test_secrets_hinweis_standard_ausnahmen_nennt_hoechstens_drei_namen(umg):
    dateien = dict(MINI, **{f"node_modules/p{i}/index.js": JS_ZEILE for i in range(6)})
    v = vorbereiten(umg, [dateien])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    hinweis = [h for h in ausgabe(secrets(umg, v))["hinweise"] if "Standardausnahmen" in h][0]
    assert "(6" in hinweis and hinweis.count("index.js") == 3 and "(+3 weitere)" in hinweis


def test_standard_ausnahme_pfadklassen_unit():
    f = lieferkette._standard_ausnahme
    assert f("package-lock.json") and f("a/b/yarn.lock") and f("node_modules/x/y.js") and f("a/node_modules/x.js")
    assert f("logo.SVG") and f("sub/gitleaks.toml") and f("old-gitleaks.toml") and f("vendor/github.com/a/b.go")
    assert f("package-lock.json") != f("logo.svg")
    for pfad in ("src/a.js", "vendor/a.js", "x.min.js", "x.lock", "pnpm-lock.yml", "xnode_modules/a.js", "Gitleaks.toml",
                 "x.ico", "gradlew.sh", "my-package-lock.json"):
        assert f(pfad) is None, pfad


NICHT_AUSGENOMMEN = ("x.js", "src/a.js", "vendor/a.js", "vendor/other/a.go", "x.min.js", "x.lock", "Cargo.lock", "pnpm-lock.yml",
                     "xnode_modules/a.js", "node_modules.js", "Gitleaks.toml", "x.ico", "x.dll", "x.webp", "gradlew.sh",
                     "my-package-lock.json", "Pipfile.lock.bak", "x.docm", "x.tgz", "x.png.js", "x.exe.txt",
                     "vendor/cache/a.rb", "vendor/assets/a.js", "vendor/plugins/a.rb", "vendor/composer/a.php", "xdeno.lock")


@echt
def test_standard_ausnahmen_echt(umg, tmp_path):
    """Die Liste bleibt wahr: jedes Beispiel jeder Klasse in `STANDARD_AUSNAHMEN` wird von gitleaks tatsächlich übersprungen
    (`useDefault = true`), jedes Gegenbeispiel gefunden; die Klassenmuster stimmen mit beidem überein."""
    wurzel = tmp_path / "ausn"
    (tmp_path / "leer").mkdir()
    beispiele = [(k, b) for k in lieferkette.STANDARD_AUSNAHMEN for b in k.beispiele]
    assert len(lieferkette.STANDARD_AUSNAHMEN) >= 8 and all(k.beispiele for k in lieferkette.STANDARD_AUSNAHMEN)
    pfade = [b for _, b in beispiele] + list(NICHT_AUSGENOMMEN)
    assert len(set(pfade)) == len(pfade)
    for i, pfad in enumerate(pfade):                                              # je Pfad ein Ordner: keine Namenskollisionen
        schreibe(str(wurzel / f"d{i}"), pfad, JS_ZEILE)
    config = tmp_path / "cfg.toml"
    config.write_text(lieferkette.GITLEAKS_TOML)
    bericht = tmp_path / "bericht.json"
    r = subprocess.run([GITLEAKS, "dir", str(wurzel), "--config", str(config), "--report-format", "json", "--report-path",
                        str(bericht), "--exit-code", "0", "--no-banner", "--no-color", "--redact"],
                       cwd=tmp_path / "leer", env=umg.env(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    gefunden = {os.path.relpath(t["File"], wurzel).split(os.sep, 1)[1] for t in json.loads(bericht.read_text())}
    for klasse, pfad in beispiele:
        assert pfad not in gefunden, f"{klasse.name}: gitleaks prüft {pfad} doch"
        assert lieferkette._standard_ausnahme(pfad) == klasse.name, pfad
    for pfad in NICHT_AUSGENOMMEN:
        assert pfad in gefunden, f"gitleaks überspringt {pfad}"
        assert lieferkette._standard_ausnahme(pfad) is None, pfad


def test_sekunden_ist_nach_oben_gedeckelt(monkeypatch):
    f = lieferkette._sekunden
    for wert in ("1e9", "inf", "301", "999999"):
        monkeypatch.setenv("SECURITY_AUDIT_SECRETS_BUDGET", wert)
        assert f("SECURITY_AUDIT_SECRETS_BUDGET", 300) == 300, wert
    for wert in ("0", "-5", "nan", "-inf", "abc", ""):
        monkeypatch.setenv("SECURITY_AUDIT_SECRETS_BUDGET", wert)
        assert f("SECURITY_AUDIT_SECRETS_BUDGET", 300) == 300, wert
    monkeypatch.setenv("SECURITY_AUDIT_SECRETS_BUDGET", "2.5")
    assert f("SECURITY_AUDIT_SECRETS_BUDGET", 300) == 2.5
    monkeypatch.delenv("SECURITY_AUDIT_SECRETS_BUDGET")
    assert f("SECURITY_AUDIT_SECRETS_BUDGET", 300) == 300


def test_secrets_budget_variable_kann_das_limit_nicht_erhoehen(umg):
    """Auch mit riesigen Werten gilt höchstens 300 s / 120 s; der Standard wird in `_sekunden` verwendet."""
    assert lieferkette.SECRETS_BUDGET == 300 and lieferkette.SECRETS_DIR_BUDGET == 120
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    env = umg.env(SECURITY_AUDIT_SECRETS_BUDGET="1e9", SECURITY_AUDIT_SECRETS_DIR_BUDGET="inf")
    assert ausgabe(secrets(umg, v, env=env))["befunde_roh"] == []


class _AltesDatetime(datetime):
    """Wie `datetime` vor Python 3.11: `fromisoformat` kennt das abschließende `Z` nicht."""

    @classmethod
    def fromisoformat(cls, text):
        if str(text).endswith("Z"):
            raise ValueError(f"Invalid isoformat string: {text!r}")
        return super().fromisoformat(text)


def test_zeitpunkt_versteht_z_auch_ohne_python_311(monkeypatch):
    monkeypatch.setattr(lieferkette, "datetime", _AltesDatetime)
    erwartet = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc).timestamp()
    assert lieferkette._zeitpunkt("2026-01-01T12:30:00Z") == erwartet
    assert lieferkette._zeitpunkt("2026-01-01T12:30:00+00:00") == erwartet
    assert lieferkette._zeitpunkt("2026-01-01T14:30:00+02:00") == erwartet
    assert lieferkette._zeitpunkt("kein datum") == 0.0


def test_gruppieren_sortiert_jungen_commit_zuerst_auch_mit_z_datum(monkeypatch):
    monkeypatch.setattr(lieferkette, "datetime", _AltesDatetime)
    alt, jung = "a" * 40, "b" * 40
    bericht = [treffer(commit=alt, zeile=3, datum="2025-01-01T00:00:00Z"), treffer(commit=jung, zeile=9, datum="2026-06-01T00:00:00Z")]
    [befund] = lieferkette._gruppieren(bericht)
    assert befund["commits"] == [jung, alt] and befund["zeile"] == 9


# ------------------------------------------------------------------------------------ echtes gitleaks

def echt_lauf(umg, dateien, *, historie=None, env=None, nachher=None):
    """Repo mit `dateien` (+ optional weiteren Commits), poc vorbereiten, echtes `secrets`. Gibt (ausgabe, Vorbereitet) zurück."""
    commits = (historie or []) + [dateien]
    v = vorbereiten(umg, commits)
    r = secrets(umg, v, env=env)
    return ausgabe(r), v


def erwartet_geschwaerzt(inhalt: bytes, wert: bytes) -> bytes:
    return inhalt.replace(wert, b"*" * len(wert))


@echt
def test_schwaerzung_echt_zeile_1_und_api_key_praefix(umg):
    inhalt = JS_ZEILE.encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    neu = lesen(os.path.join(v.quelle, "src/a.js"))
    assert neu == erwartet_geschwaerzt(inhalt, WERT.encode())                     # Präfix `apiKey = "` und `";` bleiben
    assert neu.startswith(b'const apiKey = "*') and neu.endswith(b'*";\n')
    assert out["geschwaerzt"] >= 1 and os.path.isfile(umg.marker())
    assert [(b["regel"], b["datei"], b["in_head"]) for b in out["befunde_roh"]] == [("generic-api-key", "src/a.js", True)]
    assert len(out["befunde_roh"][0]["commits"]) == 1 and len(out["befunde_roh"][0]["commits"][0]) == 40
    assert WERT not in json.dumps(out)


@echt
def test_schwaerzung_echt_zeile_ueber_1(umg):
    inhalt = ("// kopf\nfoo();\nbar();\n" + JS_ZEILE + "baz();\n").encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    assert lesen(os.path.join(v.quelle, "src/a.js")) == erwartet_geschwaerzt(inhalt, WERT.encode())
    assert not [h for h in out["hinweise"] if "unscharf" in h]


@echt
def test_schwaerzung_echt_utf8_davor(umg):
    inhalt = ("// ä😀 öü\nvar s = 'ä😀ß' + " + f'apiKey = "{WERT}"' + ";\n").encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    neu = lesen(os.path.join(v.quelle, "src/a.js"))
    assert neu == erwartet_geschwaerzt(inhalt, WERT.encode())
    assert not [h for h in out["hinweise"] if "unscharf" in h]


@echt
def test_schwaerzung_echt_ohne_end_newline(umg):
    inhalt = ("x\n" + f'const apiKey = "{WERT}";').encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    assert lesen(os.path.join(v.quelle, "src/a.js")) == erwartet_geschwaerzt(inhalt, WERT.encode())


@echt
def test_schwaerzung_echt_crlf(umg):
    inhalt = f'a\r\nb\r\nconst apiKey = "{WERT}";\r\nrest\r\n'.encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    neu = lesen(os.path.join(v.quelle, "src/a.js"))
    assert neu == erwartet_geschwaerzt(inhalt, WERT.encode()) and neu.count(b"\r\n") == 4


@echt
def test_schwaerzung_echt_pem(umg):
    zeilen = [base64.b64encode(random.Random(i).randbytes(48)).decode() for i in range(12)]
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(zeilen) + "\n-----END RSA PRIVATE KEY-----\n"
    inhalt = ("hdr\n" + pem + "tail\n").encode()
    out, v = echt_lauf(umg, {"keys/k.pem": inhalt})
    neu = lesen(os.path.join(v.quelle, "keys/k.pem"))
    assert len(neu) == len(inhalt) and neu.count(b"\n") == inhalt.count(b"\n")
    assert neu.startswith(b"hdr\n") and neu.endswith(b"\ntail\n")
    for zeile in zeilen:
        assert zeile.encode() not in neu
    assert b"BEGIN RSA" not in neu
    assert [b["regel"] for b in out["befunde_roh"]] == ["private-key"]


@echt
def test_schwaerzung_echt_base64(umg):
    b64 = base64.b64encode(f'password = "{WERT}"'.encode()).decode()
    inhalt = f"x\ndata = {b64}\ny\n".encode()
    out, v = echt_lauf(umg, {"conf/data.txt": inhalt})
    neu = lesen(os.path.join(v.quelle, "conf/data.txt"))
    assert neu == f"x\ndata = {'*' * len(b64)}\ny\n".encode()
    assert WERT.encode() not in neu and b64.encode() not in neu


@echt
def test_secrets_echt_historie_geloeschte_datei(umg):
    out, v = echt_lauf(umg, {"src/a.js": None, "package.json": "{}"}, historie=[{"src/a.js": JS_ZEILE, "package.json": "{}"}])
    assert [(b["datei"], b["in_head"], b["commits"]) for b in out["befunde_roh"]] == [("src/a.js", False, [v.shas[0]])]
    assert out["geschwaerzt"] == 0 and os.path.isfile(umg.marker())              # in HEAD nichts mehr, Marker trotzdem gesetzt
    assert lieferkette_inhalt(umg) == ["geschwaerzt"]


KONFIG_ALLOW = "[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = ['''.*''']\n"


@echt
def test_repo_konfig_wirkt_nicht_gitleaks_toml_und_env(umg, tmp_path):
    fremd = tmp_path / "eigene.toml"
    fremd.write_text(KONFIG_ALLOW)
    out, v = echt_lauf(umg, {"src/a.js": JS_ZEILE, ".gitleaks.toml": KONFIG_ALLOW},
                       env=umg.env(GITLEAKS_CONFIG=str(fremd), GITLEAKS_CONFIG_TOML=KONFIG_ALLOW))
    assert [b["datei"] for b in out["befunde_roh"]] == ["src/a.js"] and out["geschwaerzt"] >= 1
    assert WERT.encode() not in lesen(os.path.join(v.quelle, "src/a.js"))
    assert any(".gitleaks.toml" in h and "ignoriert" in h for h in out["hinweise"])


@echt
def test_repo_konfig_wirkt_nicht_gitleaksignore(umg):
    """Fingerabdrücke im Format von gitleaks: dir `<abs>:<regel>:<zeile>`, git `<commit>:<datei>:<regel>:<zeile>`; die Datei liegt
    im Repo (HEAD) und damit in der Arbeitskopie."""
    quelle = os.path.join(umg.zustand(), "quelle")
    ignore = lambda shas: {".gitleaksignore": f"{quelle}/src/a.js:generic-api-key:1\n{shas[0]}:src/a.js:generic-api-key:1\n"}
    out, v = echt_lauf(umg, ignore, historie=[{"src/a.js": JS_ZEILE}])
    assert [(b["datei"], b["commits"]) for b in out["befunde_roh"]] == [("src/a.js", [v.shas[0]])]
    assert out["geschwaerzt"] >= 1 and WERT.encode() not in lesen(os.path.join(v.quelle, "src/a.js"))
    assert not os.path.exists(os.path.join(v.quelle, ".gitleaksignore"))
    assert any(".gitleaksignore" in h and "ignoriert" in h for h in out["hinweise"])


@echt
def test_repo_konfig_wirkt_nicht_gitleaks_allow(umg):
    inhalt = f'const apiKey = "{WERT}"; // gitleaks:allow\n'.encode()
    out, v = echt_lauf(umg, {"src/a.js": inhalt})
    assert [b["datei"] for b in out["befunde_roh"]] == ["src/a.js"] and out["geschwaerzt"] >= 1
    assert WERT.encode() not in lesen(os.path.join(v.quelle, "src/a.js"))
    assert any("gitleaks:allow" in h for h in out["hinweise"])


@echt
def test_spiegel_keine_treiber_ausgefuehrt_echt(umg, tmp_path):
    """Komplettlauf mit echtem gitleaks: Treiber aus der Konfiguration des Kundenrepos bleiben ungenutzt."""
    repo, shas = repo_bauen(umg, [{"src/a.js": JS_ZEILE, ".gitattributes": "* diff=x filter=x\n"}])
    skript = marker_skript(tmp_path, "textconv.sh")
    for schluessel in ("diff.x.textconv", "filter.x.clean", "filter.x.smudge", "core.fsmonitor"):
        umg.git(repo, "config", schluessel, str(skript))
    r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", repo)
    assert r.returncode == 0
    v = Vorbereitet(repo, os.path.join(umg.zustand(), "quelle"), shas, shas[-1])
    out = ausgabe(secrets(umg, v))
    assert out["befunde_roh"] and not list(tmp_path.glob("MARKER-*"))


# ------------------------------------------------------------------------------------ Härtung TF2: Budgets (M-b, M-c, Schwärzungsschleife)

def inproc_secrets(umg, v, monkeypatch, capsys, **env):
    """`lieferkette.py secrets` im Testprozess (damit Monkeypatches wirken): Fake-gitleaks im PATH, Temp-Ordner der Umgebung."""
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    monkeypatch.setenv("PATH", f"{umg.bin}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_GL_LOG", str(umg.log_datei))
    monkeypatch.setenv("FAKE_GL_CONFIG", str(umg.config_datei))
    for name, wert in env.items():
        monkeypatch.setenv(name, wert)
    rc = lieferkette.main(["secrets", "--lauf", LAUF, "--repo", v.repo, "--quelle", v.quelle, "--sha", v.sha])
    aus = capsys.readouterr()
    return rc, aus


def test_standard_ausnahmen_suche_bricht_nach_dem_budget_ab_m_b(tmp_path, monkeypatch):
    schreibe(str(tmp_path), "a/package-lock.json", JS_ZEILE)
    schreibe(str(tmp_path), "b/yarn.lock", JS_ZEILE)
    monkeypatch.setattr(lieferkette, "AUSNAHMEN_SUCHE_BUDGET", -1)
    assert lieferkette._standard_ausnahmen_hinweise(str(tmp_path)) == ["Suche nach gitleaks-Standardausnahmen abgebrochen (Zeitbudget)"]


def test_konfig_suche_bricht_ab_findet_aber_jede_gitleaksignore_m_b(tmp_path, monkeypatch):
    """Nach Ablauf der Frist wird nicht mehr nach `gitleaks:allow` gelesen, die Namen der Konfigurationsdateien (und jede
    `.gitleaksignore`, die danach entfernt werden muss) werden weiter gesammelt."""
    schreibe(str(tmp_path), "a/.gitleaksignore", "x\n")
    schreibe(str(tmp_path), "z/tief/.gitleaksignore", "y\n")
    schreibe(str(tmp_path), "b/osv-scanner.toml", "")
    schreibe(str(tmp_path), "c/code.js", "// gitleaks:allow\n")
    monkeypatch.setattr(lieferkette, "KONFIG_SUCHE_BUDGET", -1)
    hinweise, ignore = lieferkette._repo_konfiguration(str(tmp_path))
    assert "Suche nach gitleaks:allow abgebrochen (Zeitbudget)" in hinweise
    assert sorted(os.path.relpath(p, tmp_path) for p in ignore) == ["a/.gitleaksignore", "z/tief/.gitleaksignore"]
    assert any(h.startswith("osv-scanner.toml im Repo vorhanden") for h in hinweise)
    assert not any(h.startswith("gitleaks:allow-Kommentare") for h in hinweise)


def test_schwaerzung_ueber_viele_dateien_haelt_das_gesamtbudget(umg, monkeypatch, capsys):
    """Die Schwärzungsschleife prüft die Frist je Datei: ein Ablauf ist Exit 4 (kein Marker), keine stille Überschreitung."""
    n = 6
    v = vorbereiten(umg, [dict(MINI, **{f"src/f{i}.js": JS_ZEILE for i in range(n)})])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode(), datei=f"src/f{i}.js") for i in range(n)]}, git={"report": []})
    echt_schwaerzen = lieferkette.schwaerzen
    aufrufe = []

    def langsam(*args, **kwargs):
        aufrufe.append(args[0])
        time.sleep(0.5)
        return echt_schwaerzen(*args, **kwargs)

    monkeypatch.setattr(lieferkette, "schwaerzen", langsam)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys, SECURITY_AUDIT_SECRETS_BUDGET="2")
    assert rc == 4, aus.out + aus.err
    assert "kategorie: schwaerzung-fehlgeschlagen" in aus.out.splitlines() and "Zeitbudget" in aus.err
    assert 0 < len(aufrufe) < n
    assert not os.path.lexists(umg.marker()) and lieferkette_inhalt(umg) == []


def test_gitleaks_dir_behaelt_nach_langen_vorsuchen_sein_teilbudget_m_c(umg, monkeypatch, capsys):
    """Fressen die Vorsuchen (Konfiguration, Standardausnahmen) das Teilbudget ab Start auf, bekommt `gitleaks dir` trotzdem
    seine Mindestzeit (hier: das ganze 1-s-Teilbudget ab dem Ende der Vorsuchen)."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"sleep": 0.3, "report": []}, git={"report": []})
    echt = lieferkette._repo_konfiguration

    def langsame_suche(quelle):
        time.sleep(1.3)
        return echt(quelle)

    monkeypatch.setattr(lieferkette, "_repo_konfiguration", langsame_suche)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys, SECURITY_AUDIT_SECRETS_DIR_BUDGET="1")
    assert rc == 0, aus.out + aus.err
    assert os.path.isfile(umg.marker())


# ------------------------------------------------------------------------------------ Härtung TF2: Historie (verworfene Funde, Budget in der Schleife, Kappung)

def test_secrets_verworfene_fundstellen_sind_ein_hinweis(umg):
    """Ein Eintrag mit unbrauchbarer Regel, Datei oder Commit-SHA verschwindet nicht still: Anzahl im Hinweis."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(commit=v.shas[0]), treffer(commit="nicht-hex"), treffer(commit=v.shas[0], datei=""),
        treffer(commit=v.shas[0], regel="")]})
    out = ausgabe(secrets(umg, v))
    assert [x["datei"] for x in out["befunde_roh"]] == ["src/a.js"]
    assert "3 Fundstellen der Historie mit ungültiger Regel, Datei oder Commit-SHA verworfen" in out["hinweise"]


def test_secrets_ohne_verworfene_fundstellen_kein_hinweis(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [treffer(commit=v.shas[0])]})
    assert not [h for h in ausgabe(secrets(umg, v))["hinweise"] if "verworfen" in h]


def test_secrets_budget_waehrend_in_head_behaelt_die_befunde(umg, monkeypatch, capsys):
    """Läuft das Budget während der `in_head`-Schleife ab, gehen die schon gefundenen Befunde nicht verloren: `in_head` ist
    dann `null` (unbekannt) und ein Hinweis nennt die Anzahl."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(datei=f"src/f{i}.js", commit=v.shas[0]) for i in range(5)]})
    aufrufe = []

    def knapp(spiegel, sha, datei):
        aufrufe.append(datei)
        if len(aufrufe) > 2:
            raise gitkopie.ZeitbudgetFehler("git cat-file: Zeitbudget erschöpft")
        return False

    monkeypatch.setattr(lieferkette, "_in_head", knapp)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys)
    assert rc == 0, aus.out + aus.err
    out = json.loads(aus.out)
    assert [b["datei"] for b in out["befunde_roh"]] == [f"src/f{i}.js" for i in range(5)]
    assert [b["in_head"] for b in out["befunde_roh"]] == [False, False, None, None, None]
    assert "in_head für 3 von 5 Fundstellen nicht ermittelt (Zeitlimit)" in out["hinweise"]
    assert len(aufrufe) == 3                                                         # nach dem Ablauf kein weiterer git-Aufruf
    assert os.path.isfile(umg.marker()) and lieferkette_inhalt(umg) == ["geschwaerzt"]


def test_secrets_befunde_roh_sind_gekappt_und_bevorzugen_head(umg):
    """Eine Historie mit sehr vielen Fundstellen sprengt weder Ausgabe noch Bericht: höchstens `MAX_BEFUNDE_ROH` Einträge, die
    noch in HEAD liegenden zuerst, dazu ein Hinweis mit der Gesamtzahl."""
    assert lieferkette.MAX_BEFUNDE_ROH == 200
    v = vorbereiten(umg, [{**{f"in-head/h{i}.js": JS_ZEILE for i in range(3)}, "package.json": "{}"}])
    gesamt = 230
    dateien = [f"alt/a{i:03d}.js" for i in range(gesamt - 3)] + [f"in-head/h{i}.js" for i in range(3)]
    umg.fake_gitleaks(dir={"report": []}, git={"report": [treffer(datei=d, commit=v.shas[0]) for d in dateien]})
    out = ausgabe(secrets(umg, v))
    assert len(out["befunde_roh"]) == 200
    assert [b["datei"] for b in out["befunde_roh"]] == sorted(b["datei"] for b in out["befunde_roh"])     # wieder nach Datei sortiert
    assert {b["datei"] for b in out["befunde_roh"] if b["in_head"]} == {f"in-head/h{i}.js" for i in range(3)}
    assert f"{gesamt} Fundstellen in der Historie, nur 200 ausgegeben (in HEAD vorhandene zuerst)" in out["hinweise"]


def test_secrets_budget_beim_commit_check_behaelt_die_befunde(umg, monkeypatch, capsys):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [treffer(commit=v.shas[0])]})
    echt = gitkopie.git

    def git_mit_ablauf(repo, *args, **kwargs):
        if args[:2] == ("cat-file", "-e") and args[2].endswith("^{commit}"):
            raise gitkopie.ZeitbudgetFehler("git cat-file: Zeitbudget erschöpft")
        return echt(repo, *args, **kwargs)

    monkeypatch.setattr(gitkopie, "git", git_mit_ablauf)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys)
    assert rc == 0, aus.out + aus.err
    out = json.loads(aus.out)
    assert [(b["datei"], b["in_head"]) for b in out["befunde_roh"]] == [("src/a.js", None)]
    assert "in_head für 1 von 1 Fundstellen nicht ermittelt (Zeitlimit)" in out["hinweise"]


# ------------------------------------------------------------------------------------ Härtung TF2: Marker und Arbeitskopie, parallele Befehle

def marker_inhalt(umg):
    with open(umg.marker(), encoding="utf-8") as f:
        return json.load(f)


def fertig_id(umg):
    with open(os.path.join(umg.zustand(), "quelle.fertig"), encoding="utf-8") as f:
        return json.load(f)["id"]


def test_marker_traegt_die_kennung_der_arbeitskopie(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))
    assert marker_inhalt(umg) == {"geschwaerzt": 0, "sha": v.sha, "kopie": fertig_id(umg)}


def test_secrets_ohne_kennung_im_fertig_marker_ist_aufruffehler(umg):
    v = vorbereiten(umg, [MINI])
    with open(os.path.join(umg.zustand(), "quelle.fertig"), "w") as f:
        f.write('{"fertig": true}')                                       # Stand vor der Kennung: neu vorbereiten
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    r = secrets(umg, v)
    assert r.returncode == 2 and "vorbereiten" in r.stderr
    assert not os.path.lexists(umg.marker()) and umg.aufrufe() == []


def test_vorbereiten_waehrend_der_schwaerzung_setzt_keinen_marker(umg, monkeypatch, capsys):
    """Wird die Arbeitskopie während `secrets` neu erstellt (`poc.py vorbereiten`), gilt der Bericht von `gitleaks dir` nicht
    mehr für sie: Exit 4, kein Marker (sonst stünde er auf einer ungeschwärzten Kopie)."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": [dir_treffer(JS_ZEILE.encode())]}, git={"report": []})
    echt = lieferkette._gitleaks_dir

    def dir_und_dazwischen_vorbereiten(quelle, lk, ende):
        bericht = echt(quelle, lk, ende)
        r = umg.poc("vorbereiten", "--lauf", LAUF, "--repo", v.repo)
        assert r.returncode == 0, r.stderr
        return bericht

    monkeypatch.setattr(lieferkette, "_gitleaks_dir", dir_und_dazwischen_vorbereiten)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys)
    assert rc == 4, aus.out + aus.err
    assert "kategorie: schwaerzung-fehlgeschlagen" in aus.out.splitlines() and "neu erstellt" in aus.err
    assert not os.path.lexists(umg.marker())
    assert lesen(os.path.join(v.quelle, "src/a.js")) == JS_ZEILE.encode()         # der Bericht der alten Kopie schreibt nicht in die neue


def test_vorbereiten_nach_der_schwaerzung_vor_dem_marker_setzen_wird_erkannt(umg, monkeypatch, capsys):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    echt = lieferkette._schwaerze_arbeitskopie

    def schwaerzen_und_dazwischen_vorbereiten(quelle, bericht, ende=None):
        erg = echt(quelle, bericht, ende)
        assert umg.poc("vorbereiten", "--lauf", LAUF, "--repo", v.repo).returncode == 0
        return erg

    monkeypatch.setattr(lieferkette, "_schwaerze_arbeitskopie", schwaerzen_und_dazwischen_vorbereiten)
    rc, aus = inproc_secrets(umg, v, monkeypatch, capsys)
    assert rc == 4 and "neu erstellt" in aus.err and not os.path.lexists(umg.marker())


def sperre_halten(pfad):
    """Hält die gleiche Sperre wie `lieferkette.py` (flock auf dem Ordner `<zustand>/lieferkette`)."""
    import fcntl
    fd = os.open(pfad, os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def test_zweites_secrets_auf_demselben_lauf_verweigert_ohne_etwas_zu_loeschen(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))                                                      # Marker und Ordner anlegen
    alt = lesen(umg.marker())
    fd = sperre_halten(umg.lieferkette_ordner())
    try:
        r = secrets(umg, v)
        assert r.returncode == 1 and "läuft bereits" in r.stderr, r.stdout + r.stderr
        assert lesen(umg.marker()) == alt                                         # der laufende Befehl behält seinen Marker
        assert len(umg.aufrufe()) == 2                                            # nur die beiden Aufrufe des ersten Laufs
    finally:
        os.close(fd)
    assert ausgabe(secrets(umg, v))["geschwaerzt"] == 0                           # Sperre frei: läuft wieder


def test_sperre_gehoert_zum_zustandsordner_des_laufs(umg):
    """Zwei Audits auf verschiedenen Läufen blockieren sich nicht."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))
    anderer = umg.zustand("ffeeddcc")
    os.makedirs(anderer, mode=0o700)
    fd = sperre_halten(umg.lieferkette_ordner())
    try:
        with lieferkette._sperre(lieferkette._lieferkette_ordner(anderer)):
            pass
        with pytest.raises(lieferkette.PocFehler):
            with lieferkette._sperre(umg.lieferkette_ordner()):
                pass
    finally:
        os.close(fd)
    with lieferkette._sperre(umg.lieferkette_ordner()):                         # nach dem Loslassen wieder frei
        pass


# ------------------------------------------------------------------------------------ Härtung TF2: Ausgabegrenze der Werkzeuge (M-6)

def test_werkzeug_ausfuehren_kappt_die_ausgabe_je_strom(tmp_path):
    """Die Ausgabe eines Werkzeugs landet nicht unbegrenzt im Speicher: höchstens `ausgabe_max` Bytes je Strom, `abgeschnitten`
    zeigt es an; der Exit-Code bleibt erhalten."""
    code = "import sys; sys.stdout.write('o' * 5000); sys.stderr.write('e' * 300); sys.exit(1)"
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", code], 10, str(tmp_path), ausgabe_max=1000)
    assert r.rc == 1 and r.out == b"o" * 1000 and r.err == b"e" * 300 and r.abgeschnitten is True
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", code], 10, str(tmp_path), ausgabe_max=5000)
    assert len(r.out) == 5000 and r.abgeschnitten is False
    assert gitkopie.AUSGABE_MAX >= 1 << 20


def test_werkzeug_ausfuehren_timeout_mit_ausgabegrenze(tmp_path):
    start = time.monotonic()
    code = "import sys, time; sys.stdout.write('x' * 100); sys.stdout.flush(); time.sleep(60)"
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", code], 1, str(tmp_path), ausgabe_max=50)
    assert r.rc is None and r.out == b"x" * 50 and r.abgeschnitten is True
    assert time.monotonic() - start < 20


def test_befunde_roh_genau_am_limit_ohne_kappungshinweis(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": [
        treffer(datei=f"alt/a{i:03d}.js", commit=v.shas[0]) for i in range(lieferkette.MAX_BEFUNDE_ROH)]})
    out = ausgabe(secrets(umg, v))
    assert len(out["befunde_roh"]) == lieferkette.MAX_BEFUNDE_ROH
    assert not [h for h in out["hinweise"] if "nur 200 ausgegeben" in h]


def test_gruppieren_derselbe_commit_in_mehreren_zeilen_zaehlt_einmal():
    a = "a" * 40
    [b] = lieferkette._gruppieren([treffer(commit=a, zeile=3), treffer(commit=a, zeile=9, datum="2027-01-01T00:00:00Z")])
    assert b["commits"] == [a] and b["zeile"] == 9


def test_werkzeug_ausfuehren_abgeschnitten_auch_nur_durch_stderr(tmp_path):
    r = gitkopie.werkzeug_ausfuehren([sys.executable, "-c", "import sys; sys.stderr.write('e' * 900)"], 10, str(tmp_path),
                                     ausgabe_max=100)
    assert r.out == b"" and r.err == b"e" * 100 and r.abgeschnitten is True


def test_sperre_ist_exklusiv_auch_zwischen_zwei_haltern(umg):
    """Zwei `_sperre` auf demselben Ordner (zwei Befehle desselben Laufs) schließen sich aus; die Sperre endet mit dem Block."""
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))
    lk = umg.lieferkette_ordner()
    with lieferkette._sperre(lk):
        with pytest.raises(lieferkette.PocFehler) as e:
            with lieferkette._sperre(lk):
                pass
        assert e.value.code == 1
    with lieferkette._sperre(lk):
        pass


def test_enthaelt_marke_findet_die_marke_ueber_die_stuecke_hinweg(tmp_path):
    """`gitleaks:allow` genau über der 1-MiB-Stückgrenze wird gefunden (der Rest des vorigen Stücks wird mitgeführt)."""
    for versatz in range(1, len(lieferkette.ALLOW_MARKE)):
        datei = tmp_path / f"a{versatz}.js"
        datei.write_bytes(b"x" * ((1 << 20) - versatz) + lieferkette.ALLOW_MARKE + b"y" * 10)
        assert lieferkette._enthaelt_marke(str(datei), time.monotonic() + 60) is True, versatz
    leer = tmp_path / "leer.js"
    leer.write_bytes(b"x" * ((1 << 20) + 50))
    assert lieferkette._enthaelt_marke(str(leer), time.monotonic() + 60) is False


def test_lese_report_verweigert_zu_grosse_berichte(tmp_path, monkeypatch):
    pfad = tmp_path / "bericht.json"
    pfad.write_text("[" + ",".join(["{}"] * 50) + "]")
    assert lieferkette._lese_report(str(pfad)) == [{}] * 50
    monkeypatch.setattr(lieferkette, "REPORT_MAX", 20)
    with pytest.raises(lieferkette.ReportFehler, match="zu groß"):
        lieferkette._lese_report(str(pfad))


# ------------------------------------------------------------------------------------ lange Zeilen (Review R1-1)

LANGE_ZEILE = b"var a=1;" * 20000                                                # 160 KB: gitleaks 8.30 meldet dahinter falsche Spalten


def _lang_lauf(umg, inhalt):
    v = vorbereiten(umg, [{"dist/bundle.min.js": inhalt, "package.json": "{}"}])
    return secrets(umg, v), v


@echt
@pytest.mark.parametrize("variante", ["github-pat", "base64"])
def test_schwaerzung_echt_lange_zeile_laesst_keinen_wert_stehen_r1_1(umg, variante):
    pat = "ghp_" + geheimnis(20261111, 36)
    if variante == "github-pat":
        geheim = pat.encode()
        inhalt = LANGE_ZEILE + b'var t="' + geheim + b'";\n'
    else:
        geheim = base64.b64encode(f'password = "{WERT}"'.encode())
        inhalt = LANGE_ZEILE + b"var d='" + geheim + b"';\n"
    r, v = _lang_lauf(umg, inhalt)
    neu = lesen(os.path.join(v.quelle, "dist/bundle.min.js"))
    assert geheim not in neu and WERT.encode() not in neu, "Secret-Wert steht nach der Schwärzung noch in der Arbeitskopie"
    assert len(neu) == len(inhalt) and neu.count(b"\n") == 1
    assert r.returncode in (0, 4), r.stdout + r.stderr
    assert (r.returncode == 0) == os.path.isfile(umg.marker())                      # Marker nur bei geschwärzter Kopie
    assert geheim.decode() not in r.stdout + r.stderr


def _lang_treffer(inhalt, datei="src/a.js", zeile=1):
    """Fundstelle mit unbrauchbaren Spalten (wie gitleaks bei langen Zeilen): Zeile stimmt, Spalten zeigen daneben."""
    return treffer(datei="{ziel}/" + datei, zeile=zeile, von=3, bis=9, match="REDACTED", regel="github-pat")


def test_nachpruefung_schwaerzt_restfunde_zeilenweise_und_prueft_erneut_r1_1(umg):
    langer_wert = "ghp_" + geheimnis(7, 36)
    inhalt = f'var a=1;var t="{langer_wert}";\nvar b=2;\n'
    v = vorbereiten(umg, [{"src/a.js": inhalt, "package.json": "{}"}])
    t = _lang_treffer(inhalt)
    umg.fake_gitleaks(dir={"report": [t]}, git={"report": []})
    cfg = json.loads(umg.config_datei.read_text())
    cfg["dir"]["nach"] = [{"report": [t]}, {"report": []}]                        # Prüflauf 1 findet den Rest, Prüflauf 2 nicht
    umg.config_datei.write_text(json.dumps(cfg))
    out = ausgabe(secrets(umg, v))
    neu = lesen(os.path.join(v.quelle, "src/a.js"))
    assert langer_wert.encode() not in neu and neu.endswith(b"\nvar b=2;\n")        # Zeile 1 ganz, Zeile 2 unverändert
    assert neu.split(b"\n")[0] == b"*" * len(inhalt.split("\n")[0])
    assert "Schwärzung unscharf: src/a.js:1 (ganze Zeile)" in out["hinweise"]
    assert [a["modus"] for a in umg.aufrufe()] == ["dir", "dir", "dir", "git"]
    assert os.path.isfile(umg.marker())
    assert langer_wert not in json.dumps(out)


def test_nachpruefung_mit_bleibendem_restfund_ist_exit4_ohne_marker_r1_1(umg):
    inhalt = 'var a=1;var t="geheim-geheim-geheim";\n'
    v = vorbereiten(umg, [{"src/a.js": inhalt, "package.json": "{}"}])
    t = _lang_treffer(inhalt)
    umg.fake_gitleaks(dir={"report": [t], "nach": [{"report": [t]}, {"report": [t]}]}, git={"report": [treffer(commit=v.shas[0])]})
    r = secrets(umg, v)
    assert r.returncode == 4, r.stdout + r.stderr
    assert "nicht geschwärzt" in r.stdout + r.stderr and "kategorie: schwaerzung-fehlgeschlagen" in r.stdout.splitlines()
    assert not os.path.lexists(umg.marker())
    assert [a["modus"] for a in umg.aufrufe()] == ["dir", "dir", "dir"]            # keine Historie
    assert lieferkette_inhalt(umg) == []
    for sentinel in SENTINELS:
        assert sentinel not in r.stdout and sentinel not in r.stderr


def test_nachpruefung_laeuft_nur_nach_einer_schwaerzung_r1_1(umg):
    v = vorbereiten(umg, [MINI])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    ausgabe(secrets(umg, v))
    assert [a["modus"] for a in umg.aufrufe()] == ["dir", "git"]


def test_nachpruefung_ignoriert_funde_ausserhalb_der_arbeitskopie_r1_1(umg, tmp_path):
    v = vorbereiten(umg, [MINI])
    aussen = tmp_path / "aussen.js"
    aussen.write_bytes(JS_ZEILE.encode())
    t_innen = dir_treffer(JS_ZEILE.encode())
    t_aussen = dir_treffer(JS_ZEILE.encode(), datei="a.js") | {"File": str(aussen)}
    umg.fake_gitleaks(dir={"report": [t_innen], "nach": [{"report": [t_aussen]}]}, git={"report": []})
    ausgabe(secrets(umg, v))
    assert aussen.read_bytes() == JS_ZEILE.encode()
    assert os.path.isfile(umg.marker())


# ------------------------------------------------------------------------------------ Standardausnahmen gegen die Quelle (Review R1-2)

# Die `paths` der Standard-Allowlist aus config/gitleaks.toml von gitleaks 8.30.1, wörtlich, je Regex ein Beispielpfad, den sie
# erfasst. Weicht die eingebettete Config des installierten gitleaks ab, scheitert der Test: Liste und `STANDARD_AUSNAHMEN` prüfen.
GITLEAKS_STANDARD_PFADE = (
    ("gitleaks\\.toml", "gitleaks.toml"),
    ("(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$", "x.png"),
    ("(?i)\\.(?:eot|[ot]tf|woff2?)$", "x.woff2"),
    ("(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$", "x.docx"),
    ("go\\.(?:mod|sum|work(?:\\.sum)?)$", "go.mod"),
    ("(?:^|/)vendor/modules\\.txt$", "vendor/modules.txt"),
    ("(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$",
     "vendor/github.com/a/b.go"),
    ("(?:^|/)gradlew(?:\\.bat)?$", "gradlew"),
    ("(?:^|/)gradle\\.lockfile$", "gradle.lockfile"),
    ("(?:^|/)mvnw(?:\\.cmd)?$", "mvnw"),
    ("(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$", ".mvn/wrapper/MavenWrapperDownloader.java"),
    ("(?:^|/)node_modules(?:/.*)?$", "node_modules/x/a.js"),
    ("(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$", "package-lock.json"),
    ("(?:^|/)bower_components(?:/.*)?$", "bower_components/a/b.js"),
    ("(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$",
     "static/jquery-3.6.0.min.js"),
    ("(?:^|/)javascript\\.json$", "static/javascript.json"),
    ("(?:^|/)(?:Pipfile|poetry)\\.lock$", "poetry.lock"),
    ("(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$", "venv/lib/python3.11/site-packages/a.py"),
    ("(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$",
     "lib/python3.11/site-packages/a.py"),
    ("(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$", "foo-1.0.dist-info/METADATA"),
    ("(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$", "vendor/bundle/a.rb"),
    ("\\.gem$", "a.gem"),
    ("verification-metadata\\.xml", "verification-metadata.xml"),
    ("Database.refactorlog", "Database.refactorlog"),
    ("(?:^|/)\\.git$", ".git"),
)


def _eingebettete_standard_pfade():
    """Die `paths` der Standard-Allowlist aus der Config, die im gitleaks-Binary steckt (None, wenn nicht auffindbar)."""
    with open(GITLEAKS, "rb") as f:
        daten = f.read()
    kopf = daten.find(b'description = "global allow lists"\npaths = [\n')
    if kopf < 0:
        return None
    pfade = []
    for zeile in daten[kopf:].split(b"\n")[2:]:
        zeile = zeile.strip()
        if not (zeile.startswith(b"'''") and zeile.endswith(b"''',")):
            break
        pfade.append(zeile[3:-4].decode())
    return pfade


@echt
def test_standard_ausnahmen_decken_die_eingebettete_gitleaks_allowlist_ab_r1_2(umg, tmp_path):
    """Jede Pfad-Regex der Standard-Allowlist von gitleaks hat einen Beispielpfad, den gitleaks tatsächlich überspringt und den
    `_standard_ausnahme` einer Klasse zuordnet: eine unvollständige Liste (venv, site-packages, dist-info, …) fällt auf."""
    eingebettet = _eingebettete_standard_pfade()
    assert eingebettet is not None, "Allowlist im gitleaks-Binary nicht auffindbar: Format geändert, Test anpassen"
    assert eingebettet == [r for r, _ in GITLEAKS_STANDARD_PFADE], \
        "gitleaks hat eine andere Standard-Allowlist als 8.30.1: GITLEAKS_STANDARD_PFADE und STANDARD_AUSNAHMEN prüfen"
    pfade = [p for _, p in GITLEAKS_STANDARD_PFADE]
    wurzel = tmp_path / "ausn"
    (tmp_path / "leer").mkdir()
    for i, pfad in enumerate(pfade):
        schreibe(str(wurzel / f"d{i}"), pfad, JS_ZEILE)
    config = tmp_path / "cfg.toml"
    config.write_text(lieferkette.GITLEAKS_TOML)
    bericht = tmp_path / "bericht.json"
    r = subprocess.run([GITLEAKS, "dir", str(wurzel), "--config", str(config), "--report-format", "json", "--report-path",
                        str(bericht), "--exit-code", "0", "--no-banner", "--no-color", "--redact"],
                       cwd=tmp_path / "leer", env=umg.env(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    gefunden = {os.path.relpath(t["File"], wurzel).split(os.sep, 1)[1] for t in json.loads(bericht.read_text())}
    for pfad in pfade:
        assert pfad not in gefunden, f"gitleaks prüft {pfad} doch"
        assert lieferkette._standard_ausnahme(pfad) is not None, f"{pfad}: keine Klasse in STANDARD_AUSNAHMEN"


def test_standard_ausnahmen_hinweis_nennt_python_umgebungen_r1_2(umg):
    v = vorbereiten(umg, [dict(MINI, **{"venv/lib/python3.11/site-packages/a.py": "x = 1\n",
                                        "foo-1.0.dist-info/METADATA": "Name: foo\n"})])
    umg.fake_gitleaks(dir={"report": []}, git={"report": []})
    out = ausgabe(secrets(umg, v))
    hinweis = next(h for h in out["hinweise"] if h.startswith("gitleaks-Standardausnahmen nicht geprüft"))
    assert "venv/lib/python3.11/site-packages/a.py" in hinweis and "foo-1.0.dist-info/METADATA" in hinweis
