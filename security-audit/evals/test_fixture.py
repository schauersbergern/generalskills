"""Tests für die Test-Apps evals/fixture-web und evals/fixture-deps und ihre Erwartungen unter evals/expected/.

Aufruf: python3 -m pytest security-audit/evals/test_fixture.py -q
test_server_startet und test_deps_server_startet laufen nur mit SECURITY_AUDIT_FIXTURE_START=1: Sie kopieren die App in ein
Temp-Verzeichnis, installieren dort mit `npm ci --ignore-scripts` (npm-Registry) und starten Node auf dem Host (eigener
Code, kein Kundencode). test_deps_osv_scanner_echt braucht zusätzlich SECURITY_AUDIT_FIXTURE_OSV=1 (osv-scanner, OSV-API).
Lockfiles mit verwundbaren Versionen liegen im öffentlichen Repo nur als `.tmpl`; die Tests kopieren sie unter dem echten
Namen in Temp-Ordner.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import run_eval  # noqa: E402

SKILL = os.path.dirname(HIER)
FIXTURE = os.path.join(HIER, "fixture-web")
FIXTURE_DEPS = os.path.join(HIER, "fixture-deps")
ERWARTUNG = os.path.join(HIER, "expected", "fixture-web.json")
ERWARTUNG_DEPS = os.path.join(HIER, "expected", "fixture-deps.json")
LOCKFILE = "package-lock.json.tmpl"
LOCKFILES = (LOCKFILE,)


def erwartung():
    with open(ERWARTUNG, encoding="utf-8") as f:
        return json.load(f)


def lockfile_pfad():
    pfad = os.path.join(FIXTURE, LOCKFILE)
    return pfad if os.path.isfile(pfad) else None


def dateien_unter(wurzel):
    for ordner, namen, dateien in os.walk(wurzel):
        namen[:] = [n for n in namen if n != "node_modules"]
        for datei in dateien:
            yield os.path.join(ordner, datei)


def test_fixture_dateien_vollstaendig():
    e = erwartung()
    assert e["fixture"] == "fixture-web"
    assert e["verbotene_muster"] == ["fixture.invalid"]
    assert e["start"] == {"befehl": "node src/server.js", "port": 3000}
    eintraege = e["eintraege"]
    luecken = [x for x in eintraege if x["typ"] == "luecke"]
    koeder = [x for x in eintraege if x["typ"] == "koeder"]
    assert isinstance(e["nebenbefunde"], list) and e["nebenbefunde"]
    assert all(isinstance(x, str) and x for x in e["nebenbefunde"])
    assert len(luecken) == 6
    assert sum(1 for x in luecken if x["stufe"] == "P1") == 4
    assert len(koeder) == 3
    assert [x["id"] for x in eintraege] == ["L1", "L2", "L3", "L4", "L5", "L6", "K1", "K2", "K3"]
    for x in luecken:
        assert x["kategorien"]
        assert all(re.fullmatch(r"A(0[1-9]|10)", k) for k in x["kategorien"])
    for x in eintraege:
        assert x["dateien"]
        for datei in x["dateien"]:
            assert os.path.isfile(os.path.join(FIXTURE, datei)), datei
    for pflicht in ("package.json", "README.md", ".env.example", ".env.production",
                    "src/server.js", "src/db.js", "src/auth.js", "src/middleware/orgScope.js"):
        assert os.path.isfile(os.path.join(FIXTURE, pflicht)), pflicht
    assert os.listdir(os.path.join(FIXTURE, "data", "files"))
    assert os.listdir(os.path.join(FIXTURE, "data", "avatars"))


def test_keine_verraeterischen_kommentare():
    muster = re.compile(r"vuln|köder|koeder|decoy|insecure|TODO|FIXME|unsafe|injection|ssrf|traversal", re.I)
    gefunden = []
    for pfad in dateien_unter(os.path.join(FIXTURE, "src")):
        with open(pfad, encoding="utf-8") as f:
            for nr, zeile in enumerate(f, 1):
                if muster.search(zeile):
                    gefunden.append(f"{os.path.relpath(pfad, FIXTURE)}:{nr}: {zeile.strip()}")
    assert gefunden == []


def test_readme_neutral():
    with open(os.path.join(FIXTURE, "README.md"), encoding="utf-8") as f:
        text = f.read()
    assert not re.search(r"vuln|köder|koeder|decoy|insecure|unsafe|injection|ssrf|traversal|lücke|luecke|absichtlich",
                         text, re.I)


def test_keine_fremden_urls_und_keine_echten_secrets():
    erlaubt = {"127.0.0.1", "localhost", "0.0.0.0"}
    url = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^/\s'\"`@?#]*@)?([^/\s'\"`:@?#]+)", re.I)
    secret = re.compile(r"sk_live_|sk_test_|ghp_|gho_|xox[bp]-|AKIA[0-9A-Z]{12}|-----BEGIN", re.I)
    for pfad in dateien_unter(FIXTURE):
        rel = os.path.relpath(pfad, FIXTURE)
        if rel in LOCKFILES:
            continue
        with open(pfad, encoding="utf-8", errors="replace") as f:
            text = f.read()
        assert not secret.search(text), rel
        if rel == ".env.production":
            continue  # darf fixture.invalid nennen (verbotenes Muster für den Skill)
        for host in url.findall(text):
            assert host in erlaubt, f"{rel}: {host}"
        assert "fixture.invalid" not in text, rel


def test_env_production_ohne_passwort():
    with open(os.path.join(FIXTURE, ".env.production"), encoding="utf-8") as f:
        text = f.read()
    zeilen = [z for z in text.splitlines() if z.startswith("DATABASE_URL=")]
    assert len(zeilen) == 1
    url = zeilen[0].split("=", 1)[1]
    assert url == "postgres://audit@db.fixture.invalid/app"
    assert not re.search(r"://[^/@]*:[^/@]*@", url)


def test_keine_install_skripte():
    with open(os.path.join(FIXTURE, "package.json"), encoding="utf-8") as f:
        paket = json.load(f)
    skripte = paket.get("scripts", {})
    for name in ("preinstall", "install", "postinstall", "prepare"):
        assert name not in skripte
    assert paket["dependencies"] == {"express": "4.22.3", "sql.js": "1.15.2"}
    pfad = lockfile_pfad()
    assert pfad, "package-lock.json.tmpl fehlt"
    assert not os.path.exists(os.path.join(FIXTURE, "package-lock.json")), "Lockfile nur als .tmpl ablegen"
    with open(pfad, encoding="utf-8") as f:
        lock = json.load(f)
    pakete = lock["packages"]
    assert len(pakete) > 2
    for name, daten in pakete.items():
        assert not daten.get("hasInstallScript"), name
        assert not daten.get("resolved", "https://registry.npmjs.org/").startswith(("git+", "http://")), name


# --- fixture-deps ---------------------------------------------------------------------------------------------

def erwartung_deps():
    with open(ERWARTUNG_DEPS, encoding="utf-8") as f:
        return json.load(f)


def deps_lockfile():
    with open(os.path.join(FIXTURE_DEPS, "package-lock.json.tmpl"), encoding="utf-8") as f:
        return json.load(f)


def deps_manifest():
    with open(os.path.join(FIXTURE_DEPS, "package.json.tmpl"), encoding="utf-8") as f:
        return json.load(f)


def test_app_fixtures_benennen_alle_tmpl_um(tmp_path, monkeypatch):
    """K7: `run_eval` benennt jede `*.tmpl` der Test-Apps um (nicht nur das Lockfile); im Quellordner bleiben sie `.tmpl`."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(tempfile, "tempdir", os.path.realpath(tmp_path))
    for fixture, erwartet in (("fixture-web", {"package-lock.json"}),
                              ("fixture-deps", {"package.json", "package-lock.json", "Dockerfile", "src/server.js",
                                                "src/routes/vorlage.js"})):
        quelle = [os.path.relpath(p, os.path.join(HIER, fixture)) for p in dateien_unter(os.path.join(HIER, fixture))]
        tmpl = {p for p in quelle if p.endswith(".tmpl")}
        assert tmpl, fixture
        wurzel, repo = run_eval.temp_repo_anlegen(fixture, SKILL, False)
        try:
            dort = {os.path.relpath(p, repo) for p in dateien_unter(repo)
                    if not os.path.relpath(p, repo).startswith((".git" + os.sep, ".claude" + os.sep))}
            assert not {p for p in dort if p.endswith(".tmpl")}, fixture
            assert {p[:-len(".tmpl")] for p in tmpl} <= dort and erwartet <= dort, (fixture, sorted(dort))
        finally:
            shutil.rmtree(wurzel, ignore_errors=True)
        assert tmpl == {p for p in (os.path.relpath(q, os.path.join(HIER, fixture))
                                    for q in dateien_unter(os.path.join(HIER, fixture))) if p.endswith(".tmpl")}
    for datei in ("package.json", "package-lock.json"):
        assert not os.path.exists(os.path.join(FIXTURE_DEPS, datei)), f"{datei} nur als .tmpl ablegen (öffentliches Repo)"


def test_deps_fixture_dateien_vollstaendig():
    e = erwartung_deps()
    assert e["fixture"] == "fixture-deps" and e["verbotene_muster"] == ["fixture.invalid"]
    assert e["koeder_pruefen"] is False and e["secret"] is True
    assert e["werkzeug_hinweise"] == [] and e["alle_unbestaetigt"] is False
    assert [x["id"] for x in e["eintraege"]] == ["W1", "W2", "W3", "W4"]
    assert all(x["typ"] == "werkzeug" and x["stufen"] and x["kategorien"] for x in e["eintraege"])
    assert {x["dod"] for x in e["eintraege"]} == {"TF2-D1", "TF2-D2", "TF2-D3"}
    for x in e["eintraege"]:
        for datei in x["dateien"]:
            if datei == "config/keys.js":                                  # entsteht erst im Lauf (Laufzeit-Secret)
                assert not os.path.exists(os.path.join(FIXTURE_DEPS, "config"))
            elif datei == "package-lock.json":
                assert os.path.isfile(os.path.join(FIXTURE_DEPS, "package-lock.json.tmpl"))
            else:
                assert os.path.isfile(os.path.join(FIXTURE_DEPS, datei)), datei
        for k in x["kategorien"]:
            assert re.fullmatch(r"A(0[1-9]|10)", k)
    for pflicht in ("package.json.tmpl", "package-lock.json.tmpl", "Dockerfile", "README.md", "src/server.js",
                    "src/routes/vorlage.js"):
        assert os.path.isfile(os.path.join(FIXTURE_DEPS, pflicht)), pflicht
    # festgehaltene osv-scanner-Treffer (echter Lauf vor dem Einchecken): nur Pakete, die das Lockfile enthält
    pakete = {f"{k.rsplit('node_modules/', 1)[-1]}@{d['version']}" for k, d in deps_lockfile()["packages"].items() if k}
    assert set(e["osv_ids"]) == {"lodash@4.17.20", "minimist@1.2.5"} and set(e["osv_ids"]) <= pakete
    for ids in e["osv_ids"].values():
        assert ids and all(re.fullmatch(r"GHSA(-[2-9cfghjmpqrvwx]{4}){3}", i) for i in ids)


def test_deps_manifest_und_lockfile_passen_zusammen():
    pkg, lock = deps_manifest(), deps_lockfile()
    assert pkg["dependencies"] == {"express": "4.22.3", "lodash": "4.17.20", "minimist": "1.2.5"}
    assert lock["packages"][""]["dependencies"] == pkg["dependencies"]
    assert lock["packages"]["node_modules/lodash"]["version"] == "4.17.20"
    assert lock["packages"]["node_modules/minimist"]["version"] == "1.2.5"
    assert lock["lockfileVersion"] == 3 and len(lock["packages"]) > 10


def test_deps_aufruf_nur_von_lodash():
    """lodash steht mit Aufruf in `src/routes/vorlage.js`; minimist ist nur deklariert (kein `require`, kein Aufruf)."""
    quelle = {os.path.relpath(p, FIXTURE_DEPS): open(p, encoding="utf-8").read()
              for p in dateien_unter(os.path.join(FIXTURE_DEPS, "src"))}
    assert re.search(r"_\.template\(vorlage, \{ variable: req\.query\.v \}\)", quelle["src/routes/vorlage.js"])
    assert re.search(r'require\("lodash"\)', quelle["src/routes/vorlage.js"])
    assert not [p for p, t in quelle.items() if "minimist" in t]


def test_deps_dockerfile_installiert_ohne_lockfile_treue():
    with open(os.path.join(FIXTURE_DEPS, "Dockerfile"), encoding="utf-8") as f:
        zeilen = f.read().splitlines()
    assert "RUN npm install" in zeilen
    assert not [z for z in zeilen if re.search(r"npm (ci|clean-install)|ignore-scripts", z)]


def test_deps_keine_install_skripte():
    pkg, lock = deps_manifest(), deps_lockfile()
    for name in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"):
        assert name not in pkg.get("scripts", {})
    for name, daten in lock["packages"].items():
        assert not daten.get("hasInstallScript"), name
        assert not daten.get("resolved", "https://registry.npmjs.org/").startswith(("git+", "http://", "file:")), name
    with open(os.path.join(FIXTURE_DEPS, "package-lock.json.tmpl"), encoding="utf-8") as f:
        assert "hasInstallScript" not in f.read()
    with open(os.path.join(FIXTURE_DEPS, "package.json.tmpl"), encoding="utf-8") as f:
        assert "hasInstallScript" not in f.read()
    assert not os.path.exists(os.path.join(FIXTURE_DEPS, ".npmrc"))


def test_deps_keine_echten_secrets_und_fremden_urls():
    erlaubt = {"127.0.0.1", "localhost", "0.0.0.0", "registry.npmjs.org"}
    url = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^/\s'\"`@?#]*@)?([^/\s'\"`:@?#]+)", re.I)
    secret = re.compile(r"sk_live_|sk_test_|ghp_|gho_|xox[bp]-|AKIA[0-9A-Z]{12}|-----BEGIN|apikey|api_key|secret|password|token",
                        re.I)
    for pfad in dateien_unter(FIXTURE_DEPS):
        rel = os.path.relpath(pfad, FIXTURE_DEPS)
        with open(pfad, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if rel == "package-lock.json.tmpl":                                # Lockfile: Hashes und Funding-Links; resolved nur Registry
            assert all(d.get("resolved", "https://registry.npmjs.org/").startswith("https://registry.npmjs.org/")
                       for d in json.loads(text)["packages"].values())
            continue
        assert not secret.search(text), rel
        for host in url.findall(text):
            assert host in erlaubt, f"{rel}: {host}"
        assert "fixture.invalid" not in text, rel
    assert not os.path.exists(os.path.join(FIXTURE_DEPS, "config")), "das Fake-Secret entsteht erst im Eval-Lauf"
    assert not os.path.exists(os.path.join(FIXTURE_DEPS, ".env")) and not os.path.exists(os.path.join(FIXTURE_DEPS, ".git"))


def test_deps_keine_verraeterischen_kommentare():
    muster = re.compile(r"vuln|köder|koeder|decoy|insecure|TODO|FIXME|unsafe|injection|ssrf|traversal|lodash.*(alt|veraltet)|"
                        r"cve-|ghsa-|advisory|absichtlich", re.I)
    gefunden = []
    for pfad in dateien_unter(FIXTURE_DEPS):
        rel = os.path.relpath(pfad, FIXTURE_DEPS)
        if rel == "package-lock.json.tmpl":
            continue
        with open(pfad, encoding="utf-8") as f:
            for nr, zeile in enumerate(f, 1):
                if muster.search(zeile):
                    gefunden.append(f"{rel}:{nr}: {zeile.strip()}")
    assert gefunden == []


def test_deps_lieferkette_entwurf_dockerfile(tmp_path):
    """TF2-D3 (Teil Skript): `lieferkette.py lieferkette` auf einer Arbeitskopie der Test-App liefert genau einen
    Entwurf `installation-ohne-lockfile-treue` mit `Dockerfile` (Zeile des `RUN npm install`), schema-gültig als Befund."""
    sys.path.insert(0, os.path.join(SKILL, "scripts"))
    import bericht as bericht_schema
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    zustand = os.path.join(os.path.realpath(tmp), "security-audit-0a1b2c3d")
    quelle = os.path.join(zustand, "quelle")
    os.makedirs(zustand, mode=0o700)
    shutil.copytree(FIXTURE_DEPS, quelle)
    run_eval._tmpl_umbenennen(quelle, False)
    open(os.path.join(zustand, "quelle.fertig"), "w").close()
    r = subprocess.run([sys.executable, "-I", os.path.join(SKILL, "scripts", "lieferkette.py"), "lieferkette", "--lauf",
                        "0a1b2c3d", "--quelle", quelle], capture_output=True, text=True, timeout=120,
                       env={"PATH": "/nonexistent", "HOME": str(tmp_path), "TMPDIR": str(tmp)})
    assert r.returncode == 0, r.stdout + r.stderr
    ausgabe = json.loads(r.stdout)
    assert [(e["klasse"], e["datei"], e["werkzeug"], e["stufe"], e["kategorie"]) for e in ausgabe["entwuerfe"]] \
        == [("installation-ohne-lockfile-treue", "Dockerfile", "lieferkette", "P2", "A03")], ausgabe
    e = ausgabe["entwuerfe"][0]
    with open(os.path.join(FIXTURE_DEPS, "Dockerfile"), encoding="utf-8") as f:
        assert f.read().splitlines()[e["zeile"] - 1] == "RUN npm install"
    assert bericht_schema._befund_fehler({**e, "id": "S-1"}, "entwurf") == []
    assert ausgabe["hinweise"] == []                                       # kein Lockfile-Fehlen, keine Install-Skripte


@pytest.mark.skipif(os.environ.get("SECURITY_AUDIT_FIXTURE_OSV") != "1" or shutil.which("osv-scanner") is None,
                    reason="echter osv-scanner-Lauf (OSV-API, Netz): SECURITY_AUDIT_FIXTURE_OSV=1 setzen")
def test_deps_osv_scanner_echt(tmp_path):
    """Die festgehaltenen IDs sind (weiterhin) in der OSV-Datenbank: Advisory-Drift darf nur ergänzen."""
    shutil.copy(os.path.join(FIXTURE_DEPS, "package-lock.json.tmpl"), tmp_path / "package-lock.json")
    r = subprocess.run(["osv-scanner", "scan", "source", "--lockfile", "package-lock.json", "--format", "json",
                        "--no-resolve"], cwd=tmp_path, capture_output=True, text=True, timeout=180)
    assert r.returncode in (0, 1), r.stderr
    gefunden = {f"{p['package']['name']}@{p['package']['version']}": {v["id"] for v in p.get("vulnerabilities", [])}
                for res in json.loads(r.stdout)["results"] for p in res["packages"]}
    for paket, ids in erwartung_deps()["osv_ids"].items():
        assert set(ids) <= gefunden.get(paket, set()), paket


# --- Start der App auf dem Host ---------------------------------------------------------------------------

pytest_start = pytest.mark.skipif(os.environ.get("SECURITY_AUDIT_FIXTURE_START") != "1",
                                  reason="startet Node auf dem Host: SECURITY_AUDIT_FIXTURE_START=1 setzen")


def freier_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def anfrage(port, pfad, token=None, methode="GET", daten=None, kopf=None, roh=None, mit_kopf=False):
    kopf = dict(kopf or {})
    if token:
        kopf["x-token"] = token
    koerper = None
    if daten is not None:
        koerper = json.dumps(daten).encode()
        kopf["content-type"] = "application/json"
    if roh is not None:
        koerper = roh
        kopf["content-type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{pfad}", data=koerper, headers=kopf, method=methode)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            erg = (r.status, r.read().decode("utf-8", "replace"))
            return erg + (dict(r.headers),) if mit_kopf else erg
    except urllib.error.HTTPError as e:
        erg = (e.code, e.read().decode("utf-8", "replace"))
        return erg + (dict(e.headers),) if mit_kopf else erg


def _app_starten(fixture, praefix):
    """Kopiert die Test-App in einen Temp-Ordner (alle `.tmpl` verlieren die Endung), installiert mit `npm ci
    --ignore-scripts` und startet Node in eigener Sitzung; gibt den Port zurück und beendet am Ende nur diese eigene
    Gruppe."""
    wurzel = os.path.realpath(tempfile.mkdtemp(prefix=praefix))
    kopie = os.path.join(wurzel, "app")
    prozess = None
    try:
        shutil.copytree(fixture, kopie, ignore=shutil.ignore_patterns("node_modules"))
        run_eval._tmpl_umbenennen(kopie, False)
        inst = subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=kopie,
                              capture_output=True, text=True, timeout=240)
        assert inst.returncode == 0, inst.stdout + inst.stderr
        port = freier_port()
        env = dict(os.environ, HOST="127.0.0.1", PORT=str(port), TMPDIR=wurzel)
        prozess = subprocess.Popen(["node", "src/server.js"], cwd=kopie, env=env, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ende = time.time() + 30
        while True:
            assert prozess.poll() is None, prozess.stdout.read().decode("utf-8", "replace")
            try:
                if anfrage(port, "/health")[0] == 200:
                    break
            except OSError:
                pass
            assert time.time() < ende, "Server startet nicht"
            time.sleep(0.2)
        yield port
    finally:
        if prozess is not None:
            try:
                os.killpg(prozess.pid, signal.SIGTERM)
                prozess.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(prozess.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if prozess.stdout:
                prozess.stdout.close()
        shutil.rmtree(wurzel, ignore_errors=True)


@pytest.fixture(scope="module")
def app():
    yield from _app_starten(FIXTURE, "fixture-web-test-")


@pytest.fixture(scope="module")
def app_deps():
    yield from _app_starten(FIXTURE_DEPS, "fixture-deps-test-")


def projekt_ids(port, token):
    status, body = anfrage(port, "/api/projects", token)
    assert status == 200
    return json.loads(body)


def globex_rechnung(port):
    status, body = anfrage(port, "/api/invoices", "tok-globex")
    assert status == 200
    return json.loads(body)[0]["id"]


@pytest_start
def test_server_startet(app):
    port = app
    assert anfrage(port, "/health")[0] == 200
    assert anfrage(port, "/api/projects")[0] == 401
    assert anfrage(port, "/api/projects", "tok-falsch")[0] == 401

    acme = projekt_ids(port, "tok-acme")
    globex = projekt_ids(port, "tok-globex")
    assert len(acme) == 2 and len(globex) == 2
    assert not {p["id"] for p in acme} & {p["id"] for p in globex}

    # L1: Projekt einer fremden Org per ID
    status, body = anfrage(port, f"/api/projects/{globex[0]['id']}", "tok-acme")
    assert status == 200 and globex[0]["name"] in body
    # L2: SQL über String-Bau
    status, body = anfrage(port, "/api/search?q=" + urllib.request.quote("' OR 1=1 --"), "tok-acme")
    assert status == 200 and all(p["name"] in body for p in globex)
    status, body = anfrage(port, "/api/search?q=" + urllib.request.quote(acme[0]["name"][:4]), "tok-acme")
    assert status == 200 and not any(p["name"] in body for p in globex)
    # L3: Admin ohne Token
    status, body = anfrage(port, "/admin/users")
    assert status == 200 and len(json.loads(body)) >= 2
    # L4: Webhook ohne Signatur
    rechnung = globex_rechnung(port)
    status, body = anfrage(port, f"/api/invoices/{rechnung}", "tok-globex")
    assert status == 200 and json.loads(body)["paid"] == 0
    event = {"type": "invoice.paid", "data": {"object": {"metadata": {"invoice_id": rechnung}}}}
    assert anfrage(port, "/webhooks/stripe", methode="POST", daten=event)[0] == 200
    status, body = anfrage(port, f"/api/invoices/{rechnung}", "tok-globex")
    assert status == 200 and json.loads(body)["paid"] == 1
    # L5: Preview holt beliebige URL
    ziel = urllib.request.quote(f"http://127.0.0.1:{port}/admin/users", safe="")
    status, body = anfrage(port, f"/api/preview?url={ziel}", "tok-acme")
    assert status == 200 and "role" in body and len(json.loads(body)) >= 2
    # L6: Download außerhalb des Basisordners
    status, body = anfrage(port, "/api/download?name=../../package.json", "tok-acme")
    assert status == 200 and '"name"' in body
    status, body = anfrage(port, "/api/download?name=..%2F..%2Fpackage.json", "tok-acme")
    assert status == 200 and '"name"' in body
    status, body = anfrage(port, "/api/download?name=welcome.txt", "tok-acme")
    assert status == 200
    globex_labels = {r["label"] for r in json.loads(anfrage(port, "/api/invoices", "tok-globex")[1])}
    # K1: Sortierspalte per Whitelist
    status, _ = anfrage(port, "/api/reports?sort=" + urllib.request.quote("amount;DROP TABLE x"), "tok-acme")
    assert status == 400
    status, body = anfrage(port, "/api/reports?sort=amount", "tok-acme")
    assert status == 200 and json.loads(body) and not any(r["label"] in globex_labels for r in json.loads(body))
    # K2: Rechnung einer fremden Org
    assert anfrage(port, f"/api/invoices/{rechnung}", "tok-acme")[0] == 404
    for pfad, kopf in ((f"/api/invoices/{rechnung}?org=2", None), (f"/api/invoices/{rechnung}?org_id=2", None),
                       (f"/api/invoices/{rechnung}", {"x-org-id": "2"})):
        assert anfrage(port, pfad, "tok-acme", kopf=kopf)[0] == 404, pfad
    status, body = anfrage(port, "/api/invoices?org=2", "tok-acme")
    assert status == 200 and json.loads(body)
    assert not {r["label"] for r in json.loads(body)} & globex_labels
    # K3: Avatar außerhalb des Basisordners
    for name in ("../package.json", "../../package.json", "..%2F..%2Fpackage.json", "%2e%2e%2f%2e%2e%2fpackage.json"):
        status, body = anfrage(port, f"/api/avatar?name={name}", "tok-acme")
        assert status in (400, 404), name
        assert '"name"' not in body, name
    # Fehlerbehandlung: kein Stacktrace, kein Framework-Header
    status, body, kopf = anfrage(port, "/webhooks/stripe", methode="POST", roh=b"{bad", mit_kopf=True)
    assert status == 400 and json.loads(body) == {"fehler": "ungültige Anfrage"}
    assert "at " not in body and "/" not in body
    assert "x-powered-by" not in {k.lower() for k in kopf}
    assert anfrage(port, "/api/avatar?name=acme.png", "tok-acme")[0] == 200


@pytest_start
def test_deps_server_startet(app_deps):
    port = app_deps
    assert anfrage(port, "/health") == (200, '{"status":"ok"}')
    status, body = anfrage(port, "/api/vorlage?v=daten&name=Anna")
    assert status == 200 and body == "Hallo Anna, willkommen beim Vorlagen-Dienst."
    assert anfrage(port, "/api/vorlage?name=Anna")[0] == 400                      # ohne v: die Vorlage findet `daten` nicht


@pytest_start
def test_deps_vorlage_variable_ausnutzbar_harmlos(app_deps):
    """lodash 4.17.20 setzt `variable` ungeprüft in den Funktionsrumpf: Ein Wert, der die Parameterliste schließt, ändert die
    Antwort. Die Nutzlast hier rechnet nur (6 * 7), kein Dateisystem, kein Prozess, kein Netz."""
    port = app_deps
    nutzlast = "x){return 6*7};function f(y"
    status, body = anfrage(port, "/api/vorlage?v=" + urllib.request.quote(nutzlast, safe=""))
    assert status == 200 and body == "42", (status, body)
    # Gegenprobe: ein harmloser Name rendert die Vorlage normal
    assert anfrage(port, "/api/vorlage?v=daten&name=Bob")[1].startswith("Hallo Bob")
