"""Tests für die Test-Apps evals/fixture-web, evals/fixture-deps und evals/fixture-ki und ihre Erwartungen unter evals/expected/.

Aufruf: python3 -m pytest security-audit/evals/test_fixture.py -q
test_server_startet und test_deps_server_startet laufen nur mit SECURITY_AUDIT_FIXTURE_START=1: Sie kopieren die App in ein
Temp-Verzeichnis, installieren dort mit `npm ci --ignore-scripts` (npm-Registry) und starten Node auf dem Host (eigener
Code, kein Kundencode). test_deps_osv_scanner_echt braucht zusätzlich SECURITY_AUDIT_FIXTURE_OSV=1 (osv-scanner, OSV-API).
Lockfiles mit verwundbaren Versionen liegen im öffentlichen Repo nur als `.tmpl`; die Tests kopieren sie unter dem echten
Namen in Temp-Ordner.
test_ki_*_start laufen ebenfalls nur mit SECURITY_AUDIT_FIXTURE_START=1: Die App fixture-ki spricht ausschließlich mit dem
lokalen Modell-Mock (docker/llm-mock.mjs auf 127.0.0.1, eigene Prozessgruppe), ihre Umgebung ist eine Whitelist (nie eine echte
Modell-API). Node >= 22 verlangt das SDK; ein anderes node wählt SECURITY_AUDIT_SDK_NODE=<pfad>.
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
import threading
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
FIXTURE_KI = os.path.join(HIER, "fixture-ki")
ERWARTUNG = os.path.join(HIER, "expected", "fixture-web.json")
ERWARTUNG_DEPS = os.path.join(HIER, "expected", "fixture-deps.json")
ERWARTUNG_KI = os.path.join(HIER, "expected", "fixture-ki.json")
MOCK = os.path.join(SKILL, "docker", "llm-mock.mjs")
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
                                                "src/routes/vorlage.js"}),
                              ("fixture-ki", {"package.json", "package-lock.json", "src/server.js", "src/llm.js"})):
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
    for ordner in (FIXTURE_DEPS, FIXTURE_KI):
        for datei in ("package.json", "package-lock.json"):
            assert not os.path.exists(os.path.join(ordner, datei)), f"{datei} nur als .tmpl ablegen (öffentliches Repo)"


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


# --- fixture-ki ----------------------------------------------------------------------------------------------

API_HOSTS = ("api.openai.com", "api.anthropic.com")
KI_ROUTEN = {"L1": "src/agent/tickets.js", "L2": "src/agent/assistent.js", "L3": "src/routes/antwort.js",
             "L4": "src/agent/prompt.js", "K1": "src/routes/antwort-sicher.js"}


def erwartung_ki():
    with open(ERWARTUNG_KI, encoding="utf-8") as f:
        return json.load(f)


def ki_text(rel):
    with open(os.path.join(FIXTURE_KI, rel), encoding="utf-8") as f:
        return f.read()


def ki_quellen():
    """Alle JS-Dateien unter `src/` (relativer Pfad -> Text)."""
    return {os.path.relpath(p, FIXTURE_KI): ki_text(os.path.relpath(p, FIXTURE_KI))
            for p in dateien_unter(os.path.join(FIXTURE_KI, "src"))}


def ki_lockfile():
    with open(os.path.join(FIXTURE_KI, "package-lock.json.tmpl"), encoding="utf-8") as f:
        return json.load(f)


def ki_manifest():
    with open(os.path.join(FIXTURE_KI, "package.json.tmpl"), encoding="utf-8") as f:
        return json.load(f)


def test_ki_fixture_erwartung_schema():
    e = erwartung_ki()
    assert e["fixture"] == "fixture-ki"
    assert e["verbotene_muster"] == ["fixture.invalid", "api.openai.com", "api.anthropic.com"]
    assert e["ki_hinweis"] == "angewendet"
    assert e["start"] == {"befehl": "node src/server.js", "port": 3000, "modell_mock": ["openai"]}
    assert isinstance(e["nebenbefunde"], list) and e["nebenbefunde"]
    assert all(isinstance(x, str) and x for x in e["nebenbefunde"])
    assert [x["id"] for x in e["eintraege"]] == ["L1", "L2", "L3", "L4", "K1"]
    for x in e["eintraege"]:
        assert x["dateien"] and all(os.path.isfile(os.path.join(FIXTURE_KI, d)) for d in x["dateien"]), x["id"]
        assert KI_ROUTEN[x["id"]] in x["dateien"], x["id"]
        if x["typ"] == "luecke":
            assert x["dod"] == "TF3-D1" and x["stufen"] and set(x["stufen"]) <= {"P1", "P2", "P3"}
            assert x["kategorien"] and all(re.fullmatch(r"A(0[1-9]|10)", k) for k in x["kategorien"])
        else:
            assert x["typ"] == "koeder" and x["dod"] == "TF3-D2" and x["id"] == "K1"


def test_ki_fixture_dateien_vollstaendig():
    for pflicht in ("package.json.tmpl", "package-lock.json.tmpl", "README.md", ".env.example", "src/server.js", "src/auth.js",
                    "src/llm.js", "src/agent/tickets.js", "src/agent/assistent.js", "src/agent/prompt.js",
                    "src/routes/antwort.js", "src/routes/antwort-sicher.js"):
        assert os.path.isfile(os.path.join(FIXTURE_KI, pflicht)), pflicht
    assert ki_text(".env.example") == "CRM_API_KEY=poc-dummy-crm\n"
    server = ki_text("src/server.js")
    assert 'app.get("/health"' in server and 'app.get("/"' in server
    assert re.search(r"tok-mitarbeiter-a", ki_text("src/auth.js")) and re.search(r"tok-mitarbeiter-b", ki_text("src/auth.js"))


def test_ki_fixture_trennung_der_dateien():
    """W5: Jede Lücke hat ihre eigene Datei mit eigener Schleife und eigenen Tools; keine Lücken-Datei enthält die Senke einer
    anderen. Gemeinsam ist nur `src/llm.js`."""
    q = ki_quellen()
    assert set(q) == {"src/server.js", "src/auth.js", "src/llm.js", "src/agent/tickets.js", "src/agent/assistent.js",
                      "src/agent/prompt.js", "src/routes/antwort.js", "src/routes/antwort-sicher.js"}

    def nur_in(muster, erlaubt):
        treffer = {p for p, t in q.items() if re.search(muster, t)}
        assert treffer == set(erlaubt), (muster, sorted(treffer))

    nur_in(r"\bexec(Sync|File|FileSync)?\b|child_process|\bspawn", {"src/agent/assistent.js"})
    nur_in(r"datei_suchen", {"src/agent/assistent.js"})
    nur_in(r"send_email", {"src/agent/tickets.js"})
    nur_in(r"ausgang\.jsonl|appendFile|writeFile", {"src/agent/tickets.js"})
    nur_in(r"CRM_API_KEY", {"src/agent/prompt.js"})
    nur_in(r"<html|text/html|<body", {"src/routes/antwort.js", "src/routes/antwort-sicher.js"})
    nur_in(r"escapeHtml", {"src/routes/antwort-sicher.js"})
    nur_in(r"require\(\"openai\"\)|from \"openai\"|import\(\"openai\"\)", {"src/llm.js"})
    # unescaptes HTML: die Antwort-Route ruft nichts auf, was escaped
    assert not re.search(r"escape|replace\(", q["src/routes/antwort.js"], re.I)
    # Importe: je Lücken-Datei nur Client und Anmeldung, der Prompt nur von der Schleife in assistent.js
    erlaubt = {"src/agent/tickets.js": {"../llm", "../auth"}, "src/agent/assistent.js": {"../llm", "../auth", "./prompt"},
               "src/agent/prompt.js": set(), "src/routes/antwort.js": {"../llm"}, "src/routes/antwort-sicher.js": {"../llm"},
               "src/llm.js": set(), "src/auth.js": set()}
    for datei, ok in erlaubt.items():
        relativ = set(re.findall(r"require\(\"(\.[^\"]*)\"\)", q[datei]))
        assert relativ == ok, (datei, relativ)
    nur_in(r"require\(\"\./agent/prompt\"\)|require\(\"\.\./agent/prompt\"\)", set())
    assert len(re.findall(r"chat\(", q["src/agent/tickets.js"])) >= 1 and len(re.findall(r"\bfor \(", q["src/agent/tickets.js"])) >= 1
    assert len(re.findall(r"\bfor \(", q["src/agent/assistent.js"])) >= 1


def test_ki_fixture_client_lazy_ohne_basis_url_im_code():
    """Der Client entsteht erst beim ersten Aufruf; die Basis-URL kommt aus der Umgebung des SDKs (`OPENAI_BASE_URL`), nicht
    aus dem Code."""
    q = ki_quellen()
    llm = q["src/llm.js"]
    assert not re.search(r"^(const|let|var)\s+\w+\s*=\s*(await\s+)?(new\s+\w+\(|require\(\"openai\"\))", llm, re.M)
    assert re.search(r"^\s+.*new OpenAI\(", llm, re.M)                                     # nur eingerückt, also in einer Funktion
    for rel, text in q.items():
        assert not re.search(r"base_?url|https?://", text, re.I), rel
        assert not re.search(r"\bapiKey\b|OPENAI_API_KEY", text), rel


def test_ki_fixture_keine_verraeterischen_kommentare():
    muster = re.compile(r"vuln|köder|koeder|decoy|insecure|TODO|FIXME|unsafe|injection|ssrf|traversal|xss|poc|absichtlich|"
                        r"lücke|luecke", re.I)
    gefunden = []
    for rel, text in ki_quellen().items():
        for nr, zeile in enumerate(text.splitlines(), 1):
            if muster.search(zeile):
                gefunden.append(f"{rel}:{nr}: {zeile.strip()}")
    assert gefunden == []
    readme = ki_text("README.md")
    assert not re.search(r"vuln|köder|koeder|decoy|insecure|unsafe|injection|ssrf|traversal|xss|lücke|luecke|absichtlich|"
                         r"escape|shell|exec", readme, re.I)


def test_ki_fixture_keine_schluessel_und_fremden_urls():
    erlaubt = {"127.0.0.1", "localhost", "0.0.0.0"}
    url = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^/\s'\"`@?#]*@)?([^/\s'\"`:@?#]+)", re.I)
    secret = re.compile(r"sk_live_|sk_test_|sk-[A-Za-z0-9_-]{16,}|ghp_|gho_|xox[bp]-|AKIA[0-9A-Z]{12}|-----BEGIN", re.I)
    for pfad in dateien_unter(FIXTURE_KI):
        rel = os.path.relpath(pfad, FIXTURE_KI)
        with open(pfad, encoding="utf-8", errors="replace") as f:
            text = f.read()
        assert not secret.search(text), rel
        if rel == "package-lock.json.tmpl":                                # Lockfile: nur die Registry
            continue
        for host in url.findall(text):
            assert host in erlaubt, f"{rel}: {host}"
    assert not os.path.exists(os.path.join(FIXTURE_KI, ".env")) and not os.path.exists(os.path.join(FIXTURE_KI, ".git"))
    assert not os.path.exists(os.path.join(FIXTURE_KI, ".npmrc"))


def test_ki_fixture_ohne_api_hosts():
    """W9: Weder die API-Hosts noch `fixture.invalid` stehen irgendwo in der Test-App (Code, Kommentare, README, Lockfile).
    Sonst landen sie über Protokollauszüge im `poc` und machen TF1-D5 rot."""
    verboten = ["fixture.invalid", *API_HOSTS]
    assert verboten == erwartung_ki()["verbotene_muster"]
    for pfad in dateien_unter(FIXTURE_KI):
        with open(pfad, encoding="utf-8", errors="replace") as f:
            text = f.read().casefold()
        for muster in verboten:
            assert muster not in text, f"{muster} in {os.path.relpath(pfad, FIXTURE_KI)}"


def test_ki_fixture_manifest_und_lockfile_gepinnt():
    pkg, lock = ki_manifest(), ki_lockfile()
    assert pkg["dependencies"] == {"express": "4.22.3", "openai": "7.49.0"}
    assert lock["packages"][""]["dependencies"] == pkg["dependencies"]
    assert lock["packages"]["node_modules/openai"]["version"] == "7.49.0"
    assert lock["packages"]["node_modules/express"]["version"] == "4.22.3"
    assert lock["lockfileVersion"] == 3 and len(lock["packages"]) > 10


def test_ki_fixture_keine_install_skripte():
    pkg, lock = ki_manifest(), ki_lockfile()
    for name in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"):
        assert name not in pkg.get("scripts", {})
    for name, daten in lock["packages"].items():
        assert not daten.get("hasInstallScript"), name
        if name:
            assert daten["resolved"].startswith("https://registry.npmjs.org/"), name
    for datei in ("package.json.tmpl", "package-lock.json.tmpl"):
        assert "hasInstallScript" not in ki_text(datei)


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


def _node():
    """Das node für die App: `SECURITY_AUDIT_SDK_NODE` (echte Binärdatei, kein Versions-Manager-Shim) oder das aus dem PATH."""
    return os.environ.get("SECURITY_AUDIT_SDK_NODE") or shutil.which("node")


def _node_major(pfad):
    r = subprocess.run([pfad, "--version"], capture_output=True, timeout=20)
    m = re.match(rb"v(\d+)\.", r.stdout)
    return int(m.group(1)) if m else 0


def _start_umgebung(wurzel, port, umgebung=None):
    """Umgebung des App-Prozesses. Ohne `umgebung` wie bisher `dict(os.environ, HOST, PORT, TMPDIR)`. Mit `umgebung` (dict) wird
    die Umgebung vollständig ERSETZT: Whitelist `PATH`, `HOME` (Temp), `TMPDIR`, `LANG`, dazu `HOST`, `PORT` und genau die Einträge
    von `umgebung`. Nichts wird aus der Umgebung des Testlaufs geerbt (kein `OPENAI_*`, keine Proxys, kein `NODE_OPTIONS`)."""
    if umgebung is None:
        return dict(os.environ, HOST="127.0.0.1", PORT=str(port), TMPDIR=wurzel)
    pfad = os.environ.get("PATH") or "/usr/bin:/bin"
    node = os.environ.get("SECURITY_AUDIT_SDK_NODE")
    if node:
        pfad = os.path.dirname(node) + os.pathsep + pfad
    home = os.path.join(wurzel, "home")
    os.makedirs(home, exist_ok=True)
    return {"PATH": pfad, "HOME": home, "TMPDIR": wurzel, "LANG": os.environ.get("LANG") or "C.UTF-8",
            "HOST": "127.0.0.1", "PORT": str(port), **umgebung}


def _app_starten(fixture, praefix, bereit_pfad="/health", umgebung=None, info=None):
    """Kopiert die Test-App in einen Temp-Ordner (alle `.tmpl` verlieren die Endung), installiert mit `npm ci
    --ignore-scripts` und startet Node in eigener Sitzung; gibt den Port zurück und beendet am Ende nur diese eigene
    Gruppe. `bereit_pfad` ist der Pfad, der mit 200 antworten muss, bevor der Port zurückgegeben wird. `umgebung` ersetzt
    die Umgebung des Node-Prozesses (siehe `_start_umgebung`); `npm ci` erbt wie bisher. `info` (dict) bekommt `wurzel`."""
    wurzel = os.path.realpath(tempfile.mkdtemp(prefix=praefix))
    if info is not None:
        info["wurzel"] = wurzel
    kopie = os.path.join(wurzel, "app")
    prozess = None
    try:
        shutil.copytree(fixture, kopie, ignore=shutil.ignore_patterns("node_modules"))
        run_eval._tmpl_umbenennen(kopie, False)
        inst = subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=kopie,
                              capture_output=True, text=True, timeout=240)
        assert inst.returncode == 0, inst.stdout + inst.stderr
        port = freier_port()
        env = _start_umgebung(wurzel, port, umgebung)
        node = _node() if umgebung is not None else "node"
        prozess = subprocess.Popen([node, "src/server.js"], cwd=kopie, env=env, start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ende = time.time() + 30
        while True:
            assert prozess.poll() is None, prozess.stdout.read().decode("utf-8", "replace")
            try:
                if anfrage(port, bereit_pfad)[0] == 200:
                    break
            except OSError:
                pass
            assert time.time() < ende, "Server startet nicht"
            time.sleep(0.2)
        yield port
    finally:
        _gruppe_beenden(prozess)
        shutil.rmtree(wurzel, ignore_errors=True)


def _gruppe_beenden(prozess):
    """Beendet nur die eigene Prozessgruppe (`Popen(start_new_session=True)`), und nur solange der Prozess noch läuft."""
    if prozess is None:
        return
    if prozess.poll() is None:
        try:
            os.killpg(prozess.pid, signal.SIGTERM)
            prozess.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if prozess.poll() is None:
                try:
                    os.killpg(prozess.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    for strom in (prozess.stdout, prozess.stderr):
        if strom:
            strom.close()


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


# --- fixture-ki: Start der App gegen den lokalen Modell-Mock --------------------------------------------------

TOKEN_A = "tok-mitarbeiter-a"
TOKEN_B = "tok-mitarbeiter-b"
KI_DUMMY = {"OPENAI_API_KEY": "poc-dummy-openai", "CRM_API_KEY": "poc-dummy-crm"}
BEREIT_ZEILE = re.compile(r"^bereit api=(\d+) steuer=(\d+)$")


class ModellMock:
    """`docker/llm-mock.mjs` lokal auf 127.0.0.1 (Port 0), als eigene Prozessgruppe. Beendet wird nur diese Gruppe."""

    def __init__(self, node, home):
        env = {"PATH": os.path.dirname(node) + os.pathsep + (os.environ.get("PATH") or "/usr/bin:/bin"), "HOME": home,
               "TMPDIR": home, "LANG": os.environ.get("LANG") or "C.UTF-8"}
        self.node = node
        self.p = subprocess.Popen([node, MOCK, "--server", "--host", "127.0.0.1", "--port", "0", "--steuer-port", "0"],
                                  env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        try:
            gelesen = []
            t = threading.Thread(target=lambda: gelesen.append(self.p.stdout.readline()), daemon=True)
            t.start()
            t.join(10)
            assert gelesen and gelesen[0], "keine bereit-Zeile des Mocks innerhalb von 10 s"
            m = BEREIT_ZEILE.match(gelesen[0].decode("utf-8").rstrip("\n"))
            assert m, gelesen[0]
            self.api, self.steuer = int(m.group(1)), int(m.group(2))
        except BaseException:
            self.beenden()
            raise

    def beenden(self):
        _gruppe_beenden(self.p)

    def _cli(self, modus, eingabe, extra=()):
        r = subprocess.run([self.node, MOCK, modus, "--steuer-port", str(self.steuer), *extra], input=eingabe.encode("utf-8"),
                           capture_output=True, timeout=30,
                           env={"PATH": os.environ.get("PATH") or "/usr/bin:/bin", "LANG": "C.UTF-8"})
        assert r.returncode == 0, r.stderr
        return r.stdout.decode("utf-8")

    def setzen(self, antworten):
        assert self._cli("--setzen", json.dumps(antworten)) == ""

    def protokoll(self, suche, werte=()):
        text = self._cli("--protokoll", json.dumps({"werte": [{"name": n, "wert": w} for n, w in werte]}), ["--suche", suche])
        return text


class KiApp:
    def __init__(self, port, mock, wurzel):
        self.port, self.mock, self.wurzel = port, mock, wurzel

    def ausgang(self):
        pfad = os.path.join(self.wurzel, "ausgang.jsonl")
        if not os.path.exists(pfad):
            return []
        with open(pfad, encoding="utf-8") as f:
            return [json.loads(z) for z in f.read().splitlines() if z]


@pytest.fixture(scope="module")
def app_ki():
    node = _node()
    if node is None or _node_major(node) < 22:
        pytest.skip("Node >= 22 nötig (SECURITY_AUDIT_SDK_NODE=<pfad>)")
    home = os.path.realpath(tempfile.mkdtemp(prefix="fixture-ki-mock-"))
    mock = ModellMock(node, home)
    info = {}
    try:
        umgebung = {"OPENAI_BASE_URL": f"http://127.0.0.1:{mock.api}/v1", **KI_DUMMY}
        for port in _app_starten(FIXTURE_KI, "fixture-ki-test-", umgebung=umgebung, info=info):
            yield KiApp(port, mock, info["wurzel"])
    finally:
        mock.beenden()
        shutil.rmtree(home, ignore_errors=True)


def test_ki_start_umgebung_ohne_fremde_variablen(monkeypatch, tmp_path):
    """W3-neu: `umgebung` ersetzt die Prozessumgebung vollständig. Fremde Variablen des Testlaufs kommen im Kind nicht an."""
    fremd = {"OPENAI_ORG_ID": "org-fremd", "HTTPS_PROXY": "http://poc-fremd.invalid:3128", "NODE_OPTIONS": "--require /fremd.js",
             "OPENAI_BASE_URL": "http://poc-fremd.invalid/v1", "ANTHROPIC_API_KEY": "fremd", "ALL_PROXY": "http://poc-fremd.invalid:3128",
             "CRM_API_KEY": "echt-wirkender-schluessel"}
    for k, v in fremd.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("OPENAI_API_KEY", "echt-wirkender-schluessel")
    wurzel = str(tmp_path)
    zusatz = {"OPENAI_BASE_URL": "http://127.0.0.1:4242/v1", **KI_DUMMY}
    env = _start_umgebung(wurzel, 3999, zusatz)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "HOST", "PORT", "OPENAI_BASE_URL", "OPENAI_API_KEY", "CRM_API_KEY"}
    assert env["HOST"] == "127.0.0.1" and env["PORT"] == "3999" and env["TMPDIR"] == wurzel
    assert env["HOME"] != wurzel and env["HOME"].startswith(wurzel) and os.path.isdir(env["HOME"])
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:4242/v1"
    assert env["OPENAI_API_KEY"] == "poc-dummy-openai" and env["CRM_API_KEY"] == "poc-dummy-crm"
    # im Kind (echter Prozess mit genau dieser Umgebung): nichts Fremdes
    r = subprocess.run([sys.executable, "-I", "-c", "import json, os; print(json.dumps(dict(os.environ)))"], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    kind = json.loads(r.stdout)
    kind.pop("__CF_USER_TEXT_ENCODING", None)                                  # setzt macOS selbst (reine Kodierung)
    assert not [k for k in kind if k not in env], kind
    for k in ("OPENAI_ORG_ID", "HTTPS_PROXY", "NODE_OPTIONS", "ALL_PROXY", "ANTHROPIC_API_KEY"):
        assert k not in kind, k
    assert "poc-fremd" not in r.stdout and "echt-wirkender-schluessel" not in r.stdout


def test_start_umgebung_ohne_zusatz_erbt_wie_bisher(monkeypatch, tmp_path):
    """fixture-web und fixture-deps starten ohne `umgebung` wie vorher: `dict(os.environ, HOST, PORT, TMPDIR)`."""
    monkeypatch.setenv("POC_PROBE_VARIABLE", "da")
    env = _start_umgebung(str(tmp_path), 3998)
    assert env["POC_PROBE_VARIABLE"] == "da" and env["HOST"] == "127.0.0.1" and env["PORT"] == "3998"
    assert env["TMPDIR"] == str(tmp_path) and env["PATH"] == os.environ["PATH"]


def test_ki_start_mock_und_app_nur_loopback():
    """Die Start-Fixture gibt dem Kind nur den lokalen Mock als Modell-Ziel; die Dummy-Werte sind die der Spezifikation."""
    quelle = open(os.path.abspath(__file__), encoding="utf-8").read()
    assert 'f"http://127.0.0.1:{mock.api}/v1"' in quelle
    assert KI_DUMMY == {"OPENAI_API_KEY": "poc-dummy-openai", "CRM_API_KEY": "poc-dummy-crm"}
    assert ki_text(".env.example").strip() == "CRM_API_KEY=" + KI_DUMMY["CRM_API_KEY"]


@pytest_start
def test_ki_server_startet(app_ki):
    port = app_ki.port
    assert anfrage(port, "/")[0] == 200
    assert anfrage(port, "/health")[0] == 200
    assert anfrage(port, "/assistent", methode="POST", daten={"frage": "x"})[0] == 401
    assert anfrage(port, "/assistent", "tok-falsch", "POST", {"frage": "x"})[0] == 401
    assert anfrage(port, "/ausgang")[0] == 404                                     # keine Route zum Lesen der Mails


@pytest_start
def test_ki_l1_ticket_ohne_anmeldung_loest_mail_aus(app_ki):
    """L1: Ein Fremder legt ohne Anmeldung ein Ticket mit Dokument an, ein Mitarbeiter lässt es bearbeiten, das Modell ruft
    `send_email` auf, und die Mail geht ohne Bestätigung raus (hier: nur in `<TMPDIR>/ausgang.jsonl`, an eine `.invalid`-Adresse)."""
    marker = "POCMARKER-ki-l1"
    port = app_ki.port
    status, body = anfrage(port, "/tickets", methode="POST", daten={"text": "Bitte um Rückruf", "dokument": f"Anlage {marker}"})
    assert status in (200, 201), body
    ticket = json.loads(body)["id"]
    assert anfrage(port, f"/agent/tickets/{ticket}/bearbeiten", methode="POST", daten={})[0] == 401
    assert app_ki.ausgang() == []
    app_ki.mock.setzen([{"wenn_enthaelt": marker, "werkzeug": {"name": "send_email", "argumente": {
        "an": "x@example.invalid", "betreff": "poc", "text": "poc-l1"}}}])
    status, body = anfrage(port, f"/agent/tickets/{ticket}/bearbeiten", TOKEN_A, "POST", {})
    assert status == 200, body
    mails = app_ki.ausgang()
    assert len(mails) == 1 and mails[0]["an"] == "x@example.invalid" and mails[0]["text"] == "poc-l1", mails
    assert anfrage(port, "/agent/tickets/999/bearbeiten", TOKEN_B, "POST", {})[0] == 404


@pytest_start
def test_ki_l2_tool_argument_erreicht_die_shell(app_ki):
    """L2: `datei_suchen` hängt das Argument des Modells an `ls ` und führt es in der Shell aus; `; echo poc-l2` erzeugt eine
    eigene Ausgabezeile. Harmlos: nur Textausgabe."""
    marker = "POCMARKER-ki-l2"
    port = app_ki.port
    app_ki.mock.setzen([{"wenn_enthaelt": marker, "werkzeug": {"name": "datei_suchen", "argumente": {"pfad": ".; echo poc-l2"}}}])
    status, body = anfrage(port, "/assistent", TOKEN_B, "POST", {"frage": f"Wo liegt die Datei? {marker}"})
    assert status == 200, body
    ausgaben = [w["ausgabe"] for w in json.loads(body)["werkzeuge"]]
    assert len(ausgaben) == 1 and "poc-l2" in ausgaben[0].splitlines(), ausgaben


@pytest_start
def test_ki_l3_antwort_roh_und_koeder_escaped(app_ki):
    """L3: Die Modellausgabe kommt unverändert als HTML zurück; der Köder escaped sie."""
    marker = "POCMARKER-ki-l3"
    port = app_ki.port
    app_ki.mock.setzen([{"wenn_enthaelt": marker, "text": "<b>poc</b>"}])
    status, body, kopf = anfrage(port, f"/antwort?frage={marker}", mit_kopf=True)
    assert status == 200 and "<b>poc</b>" in body and kopf["Content-Type"].startswith("text/html"), (status, body)
    app_ki.mock.setzen([{"wenn_enthaelt": marker, "text": "<b>poc</b>"}])
    status, body = anfrage(port, f"/antwort-sicher?frage={marker}")
    assert status == 200 and "&lt;b&gt;poc&lt;/b&gt;" in body and "<b>poc</b>" not in body, (status, body)


@pytest_start
def test_ki_l4_systemprompt_enthaelt_den_schluessel_maskiert(app_ki):
    """L4: Der Systemprompt trägt `CRM_API_KEY`. Das Mock-Protokoll zeigt es nur maskiert (`<ENV:CRM_API_KEY>`); ohne Maskierung
    stünde der Dummy-Wert im Request, also kommt er wirklich beim Modell an."""
    marker = "POCMARKER-ki-l4"
    port = app_ki.port
    app_ki.mock.setzen([])
    status, body = anfrage(port, "/assistent", TOKEN_A, "POST", {"frage": f"Hallo {marker}"})
    assert status == 200, body
    roh = app_ki.mock.protokoll(marker)
    assert KI_DUMMY["CRM_API_KEY"] in roh and "<ENV:" not in roh
    maskiert = app_ki.mock.protokoll(marker, [("CRM_API_KEY", KI_DUMMY["CRM_API_KEY"])])
    assert "<ENV:CRM_API_KEY>" in maskiert and KI_DUMMY["CRM_API_KEY"] not in maskiert
    assert json.loads(maskiert)["eintraege"]


def test_ki_fixture_auth_ohne_prototyp_umgehung():
    """6a/6b-Review M2: Tokens wie `constructor` oder `__proto__` dürfen die Anmeldung der Test-App nicht bestehen
    (sonst eine unbeabsichtigte Auth-Lücke neben L1–L4)."""
    with open(os.path.join(FIXTURE_KI, "src", "auth.js"), encoding="utf-8") as f:
        quelle = f.read()
    assert "Object.hasOwn(" in quelle
