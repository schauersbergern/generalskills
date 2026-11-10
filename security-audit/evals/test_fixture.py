"""Tests für die Test-App evals/fixture-web und ihre Erwartung evals/expected/fixture-web.json.

Aufruf: python3 -m pytest security-audit/evals/test_fixture.py -q
test_server_startet läuft nur mit SECURITY_AUDIT_FIXTURE_START=1: Es kopiert die App in ein Temp-Verzeichnis,
installiert dort mit `npm ci --ignore-scripts` und startet Node auf dem Host (eigener Code, kein Kundencode).
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HIER, "fixture-web")
ERWARTUNG = os.path.join(HIER, "expected", "fixture-web.json")
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


@pytest.fixture(scope="module")
def app():
    wurzel = os.path.realpath(tempfile.mkdtemp(prefix="fixture-web-test-"))
    kopie = os.path.join(wurzel, "app")
    prozess = None
    try:
        shutil.copytree(FIXTURE, kopie, ignore=shutil.ignore_patterns("node_modules"))
        tmpl = os.path.join(kopie, "package-lock.json.tmpl")
        if os.path.isfile(tmpl):
            os.replace(tmpl, os.path.join(kopie, "package-lock.json"))
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
