"""Tests für bericht.py (Kontext, Schema, Markdown-Befundliste).

Aufruf: python3 -m pytest security-audit/scripts/test_bericht.py -q
Alle Repos und Ausgaben liegen in tmp_path; HOME und SECURITY_AUDIT_AUSGABE zeigen dorthin.
"""
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

import pytest

SKRIPTE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SKRIPTE)
import bericht  # noqa: E402

BERICHT = os.path.join(SKRIPTE, "bericht.py")
JETZT = datetime(2026, 11, 9, 12, 0, 0)
KOPF = "Repo kunde-portal · Security-Audit · geprüft auf " + "a" * 40


@pytest.fixture(autouse=True)
def sauberes_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ausgabe = tmp_path / "ausgabe"
    ausgabe.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SECURITY_AUDIT_AUSGABE", str(ausgabe))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in list(os.environ):
        if name.startswith("GIT_") and name not in ("GIT_CONFIG_NOSYSTEM", "GIT_EXEC_PATH"):
            monkeypatch.delenv(name)
    return tmp_path


def roh(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@example.com",
                        "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def neues_repo(pfad, dateien=None, origin=None, commit=True):
    pfad.mkdir(parents=True)
    roh(pfad, "init", "-q", "-b", "main")
    for name, inhalt in (dateien or {"src/a.js": "x"}).items():
        voll = pfad / name
        voll.parent.mkdir(parents=True, exist_ok=True)
        voll.write_text(inhalt)
    if origin:
        roh(pfad, "remote", "add", "origin", origin)
    if commit:
        roh(pfad, "add", "-A")
        roh(pfad, "commit", "-q", "-m", "init")
    return pfad


def lauf(*argumente, cwd=None):
    return subprocess.run([sys.executable, "-I", BERICHT, *argumente], capture_output=True, text=True, cwd=cwd)


# ------------------------------------------------------------------------------------ kontext

def test_repo_aus_origin(tmp_path):
    r = neues_repo(tmp_path / "ordner", origin="https://github.com/a/kunde-portal.git")
    k = bericht.kontext(str(r), None, JETZT)
    assert k["repo"] == "kunde-portal"
    assert k["wurzel"] == os.path.realpath(r)
    assert k["datum"] == "2026-11-09"
    assert re.fullmatch(r"[0-9a-f]{40}", k["sha"]) and k["sha7"] == k["sha"][:7]
    assert k["teilpfad"] is None and k["teilpfad_slug"] is None
    assert k["hinweise"] == [] and k["repo_konfiguration"] == []


def test_repo_aus_scp_url(tmp_path):
    r = neues_repo(tmp_path / "ordner", origin="git@github.com:a/mein.portal.git")
    assert bericht.kontext(str(r), None, JETZT)["repo"] == "mein.portal"


@pytest.mark.parametrize("origin", ["https://x/...git", "https://x/a b.git", "https://x/a%0Ab;rm.git"])
def test_repo_name_nur_sichere_zeichen(tmp_path, origin):
    r = neues_repo(tmp_path / "kunde.portal v2", origin=origin)
    name = bericht.kontext(str(r), None, JETZT)["repo"]
    assert re.fullmatch(r"[A-Za-z0-9._-]+", name) and name not in (".", "..")
    if origin == "https://x/...git":
        assert name == "kunde.portal-v2"          # Fallback: bereinigter Ordnername
    if origin == "https://x/a b.git":
        assert name == "a-b"


def test_repo_ohne_origin_ist_ordnername(tmp_path):
    r = neues_repo(tmp_path / "mein-ordner")
    assert bericht.kontext(str(r), None, JETZT)["repo"] == "mein-ordner"


def test_repo_im_worktree_ist_ordnername_des_haupt_repos(tmp_path):
    r = neues_repo(tmp_path / "haupt-repo")
    wt = tmp_path / "anderer-name"
    roh(r, "worktree", "add", "-q", str(wt), "-b", "feature")
    k = bericht.kontext(str(wt), None, JETZT)
    assert k["repo"] == "haupt-repo"
    assert k["wurzel"] == os.path.realpath(wt)


def test_basisname_und_kollision(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    k1 = bericht.kontext(str(r), None, JETZT)
    assert k1["basisname"] == f"2026-11-09-{k1['sha7']}"
    ordner = k1["ausgabe_ordner"]
    open(os.path.join(ordner, k1["basisname"] + ".md"), "w").close()
    k2 = bericht.kontext(str(r), None, JETZT)
    assert k2["basisname"] == k1["basisname"] + "-2"
    open(os.path.join(ordner, k2["basisname"] + ".json"), "w").close()
    assert bericht.kontext(str(r), None, JETZT)["basisname"] == k1["basisname"] + "-3"


def test_teilpfad_slug_und_normalisierung(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", {"Src/API v2/x.js": "x", "lib/b.js": "y"},
                   origin="https://github.com/a/kunde-portal.git")
    k = bericht.kontext(str(r), "Src/API v2/", JETZT)
    assert k["teilpfad"] == "Src/API v2"
    assert k["teilpfad_slug"] == "src-api-v2"
    assert k["basisname"] == f"2026-11-09-{k['sha7']}-src-api-v2"
    assert bericht.kontext(str(r), "./lib", JETZT)["teilpfad"] == "lib"
    assert bericht.kontext(str(r), "lib/b.js", JETZT)["teilpfad_slug"] == "lib-b-js"


@pytest.mark.parametrize("teilpfad", ["../x", "src/../../x", "/etc", "gibt-es-nicht", "src/a.js/x", "", "a//b",
                                      "src\nx"])
def test_teilpfad_ungueltig_exit_3(tmp_path, teilpfad):
    r = neues_repo(tmp_path / "r")
    with pytest.raises(bericht.KontextFehler):
        bericht.kontext(str(r), teilpfad, JETZT)
    p = lauf("kontext", "--repo", str(r), "--teilpfad", teilpfad)
    assert p.returncode == 3 and "Traceback" not in p.stderr and p.stderr.strip()


@pytest.mark.parametrize("teilpfad", ["-x", "--help", "-h", "-", "--", "-x/y"])
@pytest.mark.parametrize("form", ["getrennt", "gleich"])
def test_teilpfad_mit_fuehrendem_minus_exit_3_statt_argparse_haertung_a8(tmp_path, teilpfad, form):
    """`--teilpfad -x` ist ein (nicht vorhandener) Teilpfad: Exit 3 mit Meldung, nie Exit 2 von argparse oder Hilfe."""
    r = neues_repo(tmp_path / "r")
    args = ["--teilpfad", teilpfad] if form == "getrennt" else [f"--teilpfad={teilpfad}"]
    p = lauf("kontext", "--repo", str(r), *args)
    assert p.returncode == 3 and "Traceback" not in p.stderr and "usage" not in p.stderr, (p.returncode, p.stderr)
    assert "Teilpfad nicht im Repo" in p.stderr, p.stderr


def test_teilpfad_und_repo_mit_fuehrendem_minus_existierend_haertung_a8(tmp_path):
    r = neues_repo(tmp_path / "-repo", {"-x/a.js": "x", "ok.js": "y"})
    p = lauf("kontext", "--repo", str(r), "--teilpfad", "-x")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["teilpfad"] == "-x"
    p = lauf("kontext", "--repo", "-repo", cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["repo"] == "repo"            # führender `-` wird aus dem Namen bereinigt


def test_fehlender_wert_nach_teilpfad_bleibt_aufruffehler_haertung_a8(tmp_path):
    r = neues_repo(tmp_path / "r")
    p = lauf("kontext", "--repo", str(r), "--teilpfad")
    assert p.returncode == 2 and "Traceback" not in p.stderr


def _neuer_commit(repo, dateien):
    for name, inhalt in dateien.items():
        voll = repo / name
        voll.parent.mkdir(parents=True, exist_ok=True)
        voll.write_text(inhalt)
    roh(repo, "add", "-A")
    roh(repo, "commit", "-q", "-m", "weiter")


def test_kontext_bleibt_beim_ermittelten_sha_wenn_head_wandert_haertung_b3(tmp_path, monkeypatch):
    """HEAD wandert zwischen der SHA-Ermittlung und den restlichen Abfragen (Commit eines anderen Prozesses): Hinweise,
    Konfiguration und Teilpfad beziehen sich weiter auf den gemeldeten SHA."""
    r = neues_repo(tmp_path / "r", {"a/x.js": "x"})
    sha1 = roh(r, "rev-parse", "HEAD")
    echt = bericht._repo_name

    def wanderer(wurzel):
        _neuer_commit(r, {".mcp.json": "{}", "neu/y.js": "y"})
        os.symlink("a/x.js", r / "l")
        roh(r, "add", "-A")
        roh(r, "commit", "-q", "-m", "symlink")
        return echt(wurzel)

    monkeypatch.setattr(bericht, "_repo_name", wanderer)
    k = bericht.kontext(str(r), "a", JETZT)
    assert k["sha"] == sha1 and k["repo_konfiguration"] == []
    assert not any("Symlink" in h for h in k["hinweise"]), k["hinweise"]
    assert roh(r, "rev-parse", "HEAD") != sha1


def test_kontext_teilpfad_wird_gegen_den_ermittelten_sha_geprueft_haertung_b3(tmp_path, monkeypatch):
    r = neues_repo(tmp_path / "r", {"a/x.js": "x"})
    echt = bericht._repo_name

    def wanderer(wurzel):
        _neuer_commit(r, {"neu/y.js": "y"})
        return echt(wurzel)

    monkeypatch.setattr(bericht, "_repo_name", wanderer)
    with pytest.raises(bericht.KontextFehler, match="Teilpfad nicht im Repo"):   # `neu/` gibt es erst nach dem Wandern
        bericht.kontext(str(r), "neu", JETZT)


def test_kontext_pfad_mit_leerzeichen(tmp_path):
    r = neues_repo(tmp_path / "mein repo mit leerzeichen", {"a b/c d.js": "x"})
    p = lauf("kontext", "--repo", str(r), "--teilpfad", "a b")
    assert p.returncode == 0, p.stderr
    k = json.loads(p.stdout)
    assert k["wurzel"] == os.path.realpath(r) and k["teilpfad"] == "a b"
    assert k["repo"] == "mein-repo-mit-leerzeichen"


def test_ausgabe_ordner_aus_umgebung(tmp_path, monkeypatch):
    ziel = tmp_path / "echt"
    ziel.mkdir()
    link = tmp_path / "link"
    link.symlink_to(ziel)
    monkeypatch.setenv("SECURITY_AUDIT_AUSGABE", str(link))
    r = neues_repo(tmp_path / "kunde-portal")
    k = bericht.kontext(str(r), None, JETZT)
    assert k["ausgabe_ordner"] == os.path.realpath(ziel / "kunde-portal")
    assert os.path.isdir(k["ausgabe_ordner"])
    assert k["agent_stats_datei"] == os.path.join(k["ausgabe_ordner"], k["basisname"] + "-agent-stats.md")


def test_ausgabe_ordner_standard_unter_home(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_AUDIT_AUSGABE")
    r = neues_repo(tmp_path / "kunde-portal")
    k = bericht.kontext(str(r), None, JETZT)
    home = str(tmp_path / "home")
    assert k["ausgabe_ordner"] == os.path.join(home, ".claude", "security-reviews", "kunde-portal")
    assert os.path.isdir(k["ausgabe_ordner"])
    assert k["agent_stats_datei"] == os.path.join(home, ".claude", "agent-stats", "kunde-portal",
                                                  "2026-11-09-security-audit.md")


def test_repo_konfiguration_escaped_durchgereicht(tmp_path):
    r = neues_repo(tmp_path / "r", {".mcp.json": "{}", "sub/.claude/commands/x\ny.md": "x", "src/a.js": "x"})
    k = bericht.kontext(str(r), None, JETZT)
    assert ".mcp.json" in k["repo_konfiguration"]
    assert "sub/.claude/commands/x\\ny.md" in k["repo_konfiguration"]
    assert all("\n" not in p for p in k["repo_konfiguration"])


def test_hinweise_aus_repo_hinweise(tmp_path):
    r = neues_repo(tmp_path / "r")
    (r / "src" / "a.js").write_text("geaendert")
    k = bericht.kontext(str(r), None, JETZT)
    assert any("src/a.js" in h for h in k["hinweise"])


def test_kontext_kein_repo_oder_kein_head_exit_3(tmp_path):
    leer = tmp_path / "leer"
    leer.mkdir()
    p = lauf("kontext", "--repo", str(leer))
    assert p.returncode == 3 and "Traceback" not in p.stderr and p.stderr.strip()
    ohne_head = neues_repo(tmp_path / "ohne-head", commit=False)
    p = lauf("kontext", "--repo", str(ohne_head))
    assert p.returncode == 3 and "Traceback" not in p.stderr and p.stderr.strip()
    p = lauf("kontext", "--repo", str(tmp_path / "gibt-es-nicht"))
    assert p.returncode == 3 and "Traceback" not in p.stderr


def test_kontext_cli_json(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    p = lauf("kontext", "--repo", str(r))
    assert p.returncode == 0, p.stderr
    k = json.loads(p.stdout)
    for feld in ("repo", "wurzel", "sha", "sha7", "datum", "teilpfad", "teilpfad_slug", "ausgabe_ordner",
                 "basisname", "hinweise", "repo_konfiguration", "agent_stats_datei"):
        assert feld in k
    assert k["repo"] == "kunde-portal"


# ------------------------------------------------------------------------------------ repo (TF5)

def test_repo_befehl_aus_origin(tmp_path):
    r = neues_repo(tmp_path / "ordner", origin="https://x/a/kunde-portal.git")
    p = lauf("repo", "--repo", str(r))
    assert p.returncode == 0, p.stderr
    assert p.stdout == "kunde-portal\n"


def test_repo_befehl_ohne_origin_worktree(tmp_path):
    r = neues_repo(tmp_path / "haupt-repo")
    wt = tmp_path / "anderer-name"
    roh(r, "worktree", "add", "-q", str(wt), "-b", "feature")
    p = lauf("repo", cwd=str(wt))                                       # Default: cwd
    assert p.returncode == 0, p.stderr
    assert p.stdout == "haupt-repo\n"


def test_repo_befehl_ohne_git(tmp_path):
    leer = tmp_path / "leer"
    leer.mkdir()
    for argumente in (("--repo", str(leer)), ("--repo", str(tmp_path / "gibt-es-nicht"))):
        p = lauf("repo", *argumente)
        assert p.returncode == 3, p.stderr
        assert p.stdout == "" and p.stderr.strip() and "Traceback" not in p.stderr


def _inhalt(wurzel):
    return sorted(os.path.join(d, n) for d, ds, fs in os.walk(wurzel) for n in ds + fs)


def test_repo_befehl_ohne_seiteneffekte(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", origin="https://x/a/kunde-portal.git")
    vorher = (_inhalt(tmp_path / "home"), _inhalt(tmp_path / "ausgabe"), _inhalt(r))
    p = lauf("repo", "--repo", str(r))
    assert p.returncode == 0, p.stderr
    nachher = (_inhalt(tmp_path / "home"), _inhalt(tmp_path / "ausgabe"), _inhalt(r))
    assert nachher == vorher, "repo darf nichts anlegen (kein Ausgabeordner, keine .reserviert-Datei)"


@pytest.mark.parametrize("fall", ["https", "scp", "ohne-origin", "worktree"])
def test_repo_befehl_gleich_kontext(tmp_path, fall):
    if fall == "https":
        r = neues_repo(tmp_path / "ordner", origin="https://github.com/a/kunde-portal.git")
    elif fall == "scp":
        r = neues_repo(tmp_path / "ordner", origin="git@github.com:o/n.git")
    elif fall == "ohne-origin":
        r = neues_repo(tmp_path / "mein-ordner")
    else:
        haupt = neues_repo(tmp_path / "haupt-repo")
        r = tmp_path / "anderer-name"
        roh(haupt, "worktree", "add", "-q", str(r), "-b", "feature")
    p = lauf("repo", "--repo", str(r))
    assert p.returncode == 0, p.stderr
    assert p.stdout == bericht.kontext(str(r), None, JETZT)["repo"] + "\n"


# ------------------------------------------------------------------------------------ Schema

def befund(**kw):
    b = {"id": "S-1", "stufe": "P1", "status": "bestätigt", "datei": "src/routes/projects.js", "zeile": 12,
         "kategorie": "A01", "titel": "IDOR auf Projekte", "beschreibung": "Erste Zeile\nZweite Zeile",
         "szenario": "Nutzer A liest Projekt von B", "erwartet": "Mandanten-Scope prüfen",
         "klasse": "keine weiteren", "ohne_anmeldung": False, "mandantenuebergreifend": True,
         "poc": "GET http://app:3000/api/projects/2\nx-token: tok-acme"}
    b.update(kw)
    return b


def beispiel():
    return {
        "version": 1, "repo": "kunde-portal", "sha": "a" * 40, "datum": "2026-11-09", "teilpfad": None,
        "projekt": "Portal", "karte": [{"flaeche": "API", "dateien": ["src/routes/projects.js"]}],
        "hinweise": ["Submodul: vendor/x (nicht in der Arbeitskopie)"],
        "befunde": [
            befund(),
            befund(id="S-2", stufe="P2", status="unbestätigt", datei="src/db.js", zeile=30, titel="Raw SQL",
                   code_pfad=["src/routes/search.js:8", "src/db.js:30"]),
            befund(id="S-3", stufe="P3", status="verworfen", titel="Debug-Route", grund="nur im Testmodus aktiv"),
            befund(id="S-4", stufe="P2", status="verdacht", datei=None, zeile=None, titel="Rate-Limit fehlt"),
        ],
    }


def test_schema_gueltig_alle_status():
    assert bericht.pruefe_schema(beispiel()) == []


def test_schema_teilpfad_und_projekt_gesetzt():
    d = beispiel()
    d["teilpfad"] = "src"
    d["projekt"] = None
    assert bericht.pruefe_schema(d) == []


PFLICHT_JE_STATUS = [("bestätigt", "poc"), ("unbestätigt", "code_pfad"), ("verworfen", "grund")]


@pytest.mark.parametrize("status,feld", PFLICHT_JE_STATUS)
def test_schema_pflichtfeld_je_status(status, feld):
    d = beispiel()
    d["befunde"] = [befund(id="S-9", status=status, code_pfad=["a.js:1", "b.js:2"], grund="g")]
    assert bericht.pruefe_schema(d) == []
    del d["befunde"][0][feld]
    fehler = bericht.pruefe_schema(d)
    assert fehler and all("S-9" in f for f in fehler) and any(feld in f for f in fehler)


@pytest.mark.parametrize("feld", ["id", "stufe", "status", "datei", "zeile", "kategorie", "titel", "beschreibung",
                                  "szenario", "erwartet", "klasse", "ohne_anmeldung", "mandantenuebergreifend"])
def test_schema_pflichtfeld_allgemein(feld):
    d = beispiel()
    del d["befunde"][0][feld]
    fehler = bericht.pruefe_schema(d)
    assert fehler and any(feld in f for f in fehler)
    if feld != "id":
        assert any("S-1" in f for f in fehler)


@pytest.mark.parametrize("feld", ["version", "repo", "sha", "datum", "teilpfad", "projekt", "karte", "hinweise",
                                  "befunde"])
def test_schema_pflichtfeld_oben(feld):
    d = beispiel()
    del d[feld]
    fehler = bericht.pruefe_schema(d)
    assert fehler and any(feld in f for f in fehler)


@pytest.mark.parametrize("kategorie", ["A01:2025", "A11", "A00", "a01", "A1", "", None, 1])
def test_schema_kategorie_ungueltig(kategorie):
    d = beispiel()
    d["befunde"][0]["kategorie"] = kategorie
    assert any("kategorie" in f for f in bericht.pruefe_schema(d))


@pytest.mark.parametrize("kategorie", ["A01", "A09", "A10"])
def test_schema_kategorie_gueltig(kategorie):
    d = beispiel()
    d["befunde"][0]["kategorie"] = kategorie
    assert bericht.pruefe_schema(d) == []


@pytest.mark.parametrize("datei", ["./src/a.js", "../a.js", "/a.js", "src/../a.js", "src//a.js", "src/a.js/",
                                   "src/./a.js", "", "src/a```b.js"])
def test_schema_datei_ungueltig(datei):
    d = beispiel()
    d["befunde"][0]["datei"] = datei
    assert any("datei" in f for f in bericht.pruefe_schema(d))


@pytest.mark.parametrize("datei", ["src/a.js:42", "src/a.js:42:7", "src/a.js#L42", "src/a.js#L42-L50", "src/a.js#L42C3"])
def test_schema_datei_mit_zeilenangabe_ist_fehler(datei):
    d = beispiel()
    d["befunde"][0]["datei"] = datei
    fehler = [f for f in bericht.pruefe_schema(d) if "datei" in f]
    assert fehler and "gehört in `zeile`" in fehler[0]


def test_schema_datei_mit_doppelpunkt_im_namen_erlaubt():
    d = beispiel()
    d["befunde"][0]["datei"] = "src/a:b.js"
    assert bericht.pruefe_schema(d) == []


def test_schema_datei_null_mit_zeile_ist_fehler():
    d = beispiel()
    d["befunde"][0].update(datei=None, zeile=3)
    assert any("zeile" in f for f in bericht.pruefe_schema(d))
    d["befunde"][0].update(datei=None, zeile=None)
    assert bericht.pruefe_schema(d) == []


def test_schema_zeile_null_mit_datei_erlaubt():
    d = beispiel()
    d["befunde"][0]["zeile"] = None
    assert bericht.pruefe_schema(d) == []


@pytest.mark.parametrize("code_pfad", [["a.js:1"], [], "a.js:1,b.js:2", ["a.js:1", "b.js"], ["a.js:1", "b.js:0"],
                                       ["a.js:1", "../b.js:2"], ["a.js:1", 3]])
def test_schema_code_pfad_ungueltig(code_pfad):
    d = beispiel()
    d["befunde"][1]["code_pfad"] = code_pfad
    assert any("code_pfad" in f for f in bericht.pruefe_schema(d))


# ------------------------------------------------------------------------------------ Werkzeugbefunde (TF2)

def osv_befund(**kw):
    b = befund(id="S-5", stufe="P2", status="unbestätigt", datei="package-lock.json", zeile=40, kategorie="A03",
               titel="lodash 4.17.20 verwundbar", poc=None, code_pfad=["package-lock.json:40"],
               werkzeug="osv-scanner",
               pakete=[{"name": "lodash", "version": "4.17.20", "advisories": ["GHSA-35jh-r3h4-6jhm"]}])
    del b["poc"]
    b.update(kw)
    return b


def gitleaks_befund(**kw):
    b = befund(id="S-6", stufe="P1", status="unbestätigt", datei="config/keys.js", zeile=1, kategorie="A07",
               titel="Secret in der Historie", werkzeug="gitleaks", commits=["a" * 40, "b1b2c3d"],
               code_pfad=["config/keys.js:1"])
    del b["poc"]
    b.update(kw)
    return b


def lieferkette_befund(**kw):
    b = befund(id="S-7", stufe="P2", status="unbestätigt", datei="Dockerfile", zeile=3, kategorie="A03",
               titel="npm install ohne Lockfile-Treue", werkzeug="lieferkette",
               klasse="installation-ohne-lockfile-treue", code_pfad=["Dockerfile:3"])
    del b["poc"]
    b.update(kw)
    return b


def mit(*befunde):
    d = beispiel()
    d["befunde"] = list(befunde)
    return d


def test_schema_werkzeug_kopplung():
    # gekoppelt: code_pfad mit einem Eintrag genügt
    for b in (osv_befund(), gitleaks_befund(), lieferkette_befund()):
        assert bericht.pruefe_schema(mit(b)) == [], b["werkzeug"]
    # ohne werkzeug bleibt es bei mindestens 2 Einträgen
    assert any("code_pfad" in f for f in bericht.pruefe_schema(mit(
        befund(status="unbestätigt", code_pfad=["a.js:1"]))))
    # osv-scanner ohne pakete
    b = osv_befund()
    del b["pakete"]
    assert any("pakete" in f for f in bericht.pruefe_schema(mit(b)))
    assert any("pakete" in f for f in bericht.pruefe_schema(mit(osv_befund(pakete=[]))))
    # gitleaks ohne commits
    b = gitleaks_befund()
    del b["commits"]
    assert any("commits" in f for f in bericht.pruefe_schema(mit(b)))
    assert any("commits" in f for f in bericht.pruefe_schema(mit(gitleaks_befund(commits=[]))))
    # lieferkette mit fremder klasse
    assert any("klasse" in f for f in bericht.pruefe_schema(mit(lieferkette_befund(klasse="keine weiteren"))))
    for klasse in ("lockfile-fehlt", "installation-ohne-lockfile-treue", "install-skripte-offen"):
        assert bericht.pruefe_schema(mit(lieferkette_befund(klasse=klasse))) == [], klasse
    # werkzeug + bestätigt
    f = bericht.pruefe_schema(mit(osv_befund(status="bestätigt", poc="GET http://app:3000/x")))
    assert any("bestätigt" in x and "werkzeug" in x for x in f)
    # falsche Kategorie je Werkzeug
    assert any("kategorie" in f for f in bericht.pruefe_schema(mit(osv_befund(kategorie="A07"))))
    assert any("kategorie" in f for f in bericht.pruefe_schema(mit(gitleaks_befund(kategorie="A03"))))
    assert any("kategorie" in f for f in bericht.pruefe_schema(mit(lieferkette_befund(kategorie="A05"))))


def test_schema_werkzeug_ungekoppelt_braucht_zwei_code_pfade():
    # Kopplung verletzt (fremde Klasse) heißt: kein Sonderrecht, code_pfad bleibt ≥ 2
    f = bericht.pruefe_schema(mit(lieferkette_befund(klasse="keine weiteren")))
    assert any("code_pfad" in x for x in f) and any("klasse" in x for x in f)
    assert bericht.pruefe_schema(mit(lieferkette_befund(klasse="keine weiteren",
                                                         code_pfad=["Dockerfile:3", "Dockerfile:4"]))) != []


def test_schema_werkzeug_unbekannt():
    f = bericht.pruefe_schema(mit(osv_befund(werkzeug="semgrep")))
    assert any("werkzeug" in x for x in f)
    assert any("code_pfad" in x for x in f)         # kein Sonderrecht für unbekanntes Werkzeug
    assert any("werkzeug" in x for x in bericht.pruefe_schema(mit(osv_befund(werkzeug=["osv-scanner"]))))
    assert any("werkzeug" in x for x in bericht.pruefe_schema(mit(osv_befund(werkzeug=None))))


@pytest.mark.parametrize("commits", ["a" * 40, [123], ["xyz1234"], ["abc123"], ["A" * 40], ["a" * 65],
                                     ["abcdef1"] * 21, [None]])
def test_schema_commits_ungueltig(commits):
    assert any("commits" in f for f in bericht.pruefe_schema(mit(gitleaks_befund(commits=commits))))


def test_schema_commits_grenzen():
    for commits in (["abcdef1"], ["a" * 64], ["abcdef1"] * 20):
        assert bericht.pruefe_schema(mit(gitleaks_befund(commits=commits))) == [], commits


@pytest.mark.parametrize("pakete", [
    {"name": "x"}, ["lodash"], [{"version": "1", "advisories": []}], [{"name": "x", "advisories": []}],
    [{"name": "x", "version": "1"}], [{"name": "x", "version": "1", "advisories": "GHSA-1"}],
    [{"name": "x", "version": "1", "advisories": [1]}], [{"name": "x", "version": "1", "advisories": ["a\nb"]}],
    [{"name": "", "version": "1", "advisories": []}], [{"name": "x", "version": 1, "advisories": []}],
    [{"name": "x", "version": "1", "advisories": [], "kev": "ja"}],
    [{"name": "x", "version": "1", "advisories": [], "behoben_in": 5}]])
def test_schema_pakete_ungueltig(pakete):
    assert any("pakete" in f for f in bericht.pruefe_schema(mit(osv_befund(pakete=pakete))))


def test_schema_pakete_optionale_felder():
    pakete = [{"name": "lodash", "version": "4.17.20", "advisories": ["GHSA-1", "CVE-2021-23337"],
               "behoben_in": "4.17.21", "kev": True},
              {"name": "minimist", "version": "1.2.5", "advisories": ["GHSA-2"], "kev": None}]
    assert bericht.pruefe_schema(mit(osv_befund(pakete=pakete))) == []


def test_schema_pakete_und_advisories_sind_gekappt():
    """Auch die Befund-Liste ist begrenzt: höchstens 300 Pakete je Befund, höchstens 20 Advisories je Paket (wie die Ausgabe von
    `lieferkette.py abhaengigkeiten`); sonst wuchse das Markdown nur durch das 16-MiB-Limit begrenzt."""
    assert bericht.MAX_PAKETE == 300 and bericht.MAX_ADVISORIES == 20
    paket = {"name": "x", "version": "1", "advisories": ["GHSA-1"]}
    assert bericht.pruefe_schema(mit(osv_befund(pakete=[paket] * 300))) == []
    zu_viele = bericht.pruefe_schema(mit(osv_befund(pakete=[paket] * 301)))
    assert any("pakete darf höchstens 300 Einträge haben, hat 301" in f for f in zu_viele), zu_viele
    viele = {"name": "x", "version": "1", "advisories": [f"GHSA-{i}" for i in range(20)]}
    assert bericht.pruefe_schema(mit(osv_befund(pakete=[viele]))) == []
    viele["advisories"].append("GHSA-21")
    f = bericht.pruefe_schema(mit(osv_befund(pakete=[viele])))
    assert any("pakete[0].advisories darf höchstens 20 Einträge haben, hat 21" in x for x in f), f


@pytest.mark.parametrize("fehlerhaft", [
    lambda: befund(commits=["abcdef1"]),
    lambda: befund(pakete=[{"name": "x", "version": "1", "advisories": []}]),
    lambda: osv_befund(commits=["abcdef1"]),
    lambda: gitleaks_befund(pakete=[{"name": "x", "version": "1", "advisories": []}]),
    lambda: lieferkette_befund(commits=["abcdef1"]),
    lambda: lieferkette_befund(pakete=[{"name": "x", "version": "1", "advisories": []}])])
def test_schema_commits_pakete_ohne_passendes_werkzeug(fehlerhaft):
    f = bericht.pruefe_schema(mit(fehlerhaft()))
    assert any(("commits" in x or "pakete" in x) and "werkzeug" in x for x in f), f


def test_schema_werkzeug_befund_verdacht_und_verworfen_ok():
    # Status verdacht/verworfen brauchen kein code_pfad
    b = osv_befund(status="verdacht")
    del b["code_pfad"]
    assert bericht.pruefe_schema(mit(b)) == []
    b = osv_befund(status="verworfen", grund="g")
    del b["code_pfad"]
    assert bericht.pruefe_schema(mit(b)) == []


def test_schema_werkzeug_code_pfad_format_bleibt_geprueft():
    assert any("code_pfad" in f for f in bericht.pruefe_schema(mit(osv_befund(code_pfad=["../x:1"]))))
    assert any("code_pfad" in f for f in bericht.pruefe_schema(mit(osv_befund(code_pfad=[]))))


def test_markdown_werkzeugbefunde_commits_und_pakete_im_detail():
    d = mit(osv_befund(pakete=[
        {"name": "lodash", "version": "4.17.20", "advisories": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"]},
        {"name": "minimist", "version": "1.2.5", "advisories": ["GHSA-xvch-5gv4-984h"]}]),
        gitleaks_befund(commits=["1234567" + "a" * 33, "2345678" + "b" * 33]))
    md = bericht.markdown(d)
    assert "Commits: 1234567, 2345678" in md
    assert "Pakete: lodash@4.17.20 (GHSA-35jh-r3h4-6jhm, CVE-2021-23337); minimist@1.2.5 (GHSA-xvch-5gv4-984h)" in md
    # Befundliste (Codeblock) unverändert: weder Commits noch Pakete
    block = "\n".join(codeblock(md))
    assert "Commits" not in block and "Pakete" not in block and "lodash@" not in block
    assert "S-5 [P2] package-lock.json:40 — lodash 4.17.20 verwundbar" in block


def test_markdown_commits_gekappt_auf_fuenf():
    commits = [f"{i}abcdef" for i in range(1, 9)]
    md = bericht.markdown(mit(gitleaks_befund(commits=commits)))
    assert "Commits: 1abcdef, 2abcdef, 3abcdef, 4abcdef, 5abcdef (+3)" in md
    assert "6abcdef" not in md
    md5 = bericht.markdown(mit(gitleaks_befund(commits=commits[:5])))
    assert "Commits: 1abcdef, 2abcdef, 3abcdef, 4abcdef, 5abcdef" in md5 and "(+" not in md5


def test_markdown_ohne_werkzeug_keine_commits_pakete_zeilen():
    md = bericht.markdown(beispiel())
    assert "Commits:" not in md and "Pakete:" not in md


def test_markdown_pakete_escaped_backticks_und_leere_advisories():
    d = mit(osv_befund(pakete=[{"name": "a`b", "version": "1", "advisories": []}]))
    md = bericht.markdown(d)
    assert "Pakete: a\\`b@1" in md and "()" not in md


# ------------------------------------------------------------------------------------ KI-Felder (TF3)

def ki_befund(**kw):
    return befund(owasp_ki=["ASI01", "LLM02"], annahme_modell=True, **kw)


def test_schema_owasp_ki_gueltig():
    for ids in (["ASI01"], ["ASI10", "LLM01", "LLM10"], ["LLM05"], ["ASI01", "ASI02", "ASI03"]):
        assert bericht.pruefe_schema(mit(befund(owasp_ki=ids))) == [], ids
    assert bericht.pruefe_schema(mit(ki_befund())) == []


@pytest.mark.parametrize("ids", [
    ["ASI00"], ["ASI11"], ["LLM00"], ["LLM11"], ["asi01"], ["ASI1"], ["ASI01 "], ["OWASP01"], ["A01"],      # falsche ID
    [],                                                                                                   # leer
    ["ASI01", "ASI02", "ASI03", "ASI04"],                                                                 # 4 IDs
    ["ASI01", "ASI01"], ["ASI01", "LLM01", "ASI01"],                                                      # Duplikat
    [1], [None], [["ASI01"]], [True], ["ASI01", 2],                                                       # Nicht-String
    "ASI01", None, {"ASI01": 1}, 1])                                                                      # keine Liste
def test_schema_owasp_ki_ungueltig(ids):
    f = bericht.pruefe_schema(mit(befund(owasp_ki=ids)))
    assert any("S-1" in x and "owasp_ki" in x for x in f), f


@pytest.mark.parametrize("wert", ["true", 1, 0, None, "ja", [True]])
def test_schema_annahme_modell_kein_bool(wert):
    f = bericht.pruefe_schema(mit(befund(annahme_modell=wert)))
    assert any("S-1" in x and "annahme_modell" in x for x in f), f


def test_schema_annahme_modell_false_immer_ok():
    for status in ("bestätigt", "unbestätigt", "verworfen", "verdacht"):
        b = befund(status=status, annahme_modell=False)
        if status == "unbestätigt":
            b["code_pfad"] = ["src/a.js:1", "src/b.js:2"]
        if status == "verworfen":
            b["grund"] = "g"
        assert bericht.pruefe_schema(mit(b)) == [], status


@pytest.mark.parametrize("status", ["unbestätigt", "verworfen", "verdacht"])
def test_schema_annahme_modell_true_nur_mit_bestaetigt(status):
    b = befund(status=status, annahme_modell=True, code_pfad=["src/a.js:1", "src/b.js:2"], grund="g")
    f = bericht.pruefe_schema(mit(b))
    assert any("S-1" in x and "annahme_modell" in x and "bestätigt" in x for x in f), f


def test_schema_annahme_modell_true_status_nfd_ist_bestaetigt():
    import unicodedata
    b = befund(status=unicodedata.normalize("NFD", "bestätigt"), annahme_modell=True)
    assert not any("annahme_modell" in x for x in bericht.pruefe_schema(mit(b)))


@pytest.mark.parametrize("klasse", ["K1 Tool mit Wirkung nach fremd befülltem Kontext", "K2 Tool-Argumente in Senke", "K4 Modellausgabe in Senke",
                                    "K1 x", "K4 "])
def test_schema_k1_k2_k4_bestaetigt_braucht_annahme_modell_haertung(klasse):
    """Härtung (Frage 7): Ein bestätigter K1-, K2- oder K4-Befund beruht auf dem Modell-Mock. Ohne `annahme_modell: true` (vergessen von der
    Hauptsession) liefe er als schlichtes „bestätigt“ ohne die Annahme durch; `rendern` lehnt das ab. Mit `annahme_modell: true` ist er gültig."""
    f = bericht.pruefe_schema(mit(befund(klasse=klasse)))
    assert any("S-1" in x and "annahme_modell" in x and "K1, K2 oder K4" in x for x in f), f
    assert bericht.pruefe_schema(mit(befund(klasse=klasse, annahme_modell=False))) != []
    assert bericht.pruefe_schema(mit(befund(klasse=klasse, annahme_modell=True))) == []
    assert "Modell-Mock, Annahme" in bericht.markdown(mit(befund(klasse=klasse, annahme_modell=True)))


@pytest.mark.parametrize("klasse", ["K3 Tool-Rechte", "K5 Geheimnis im Prompt", "K6 Speicher", "K7 MCP", "K10 x", "K1", "K1x", "k1 x", " K1 x",
                                    "Injection K1 x", "keine weiteren", "x K2 y"])
def test_schema_bestaetigt_ohne_k1_k2_k4_praefix_braucht_keine_annahme_haertung(klasse):
    """Die Kopplung gilt nur bei dem Präfix `K1 `, `K2 ` oder `K4 ` am Anfang von `klasse` (so erkennt Schritt 6 den Fall)."""
    assert bericht.pruefe_schema(mit(befund(klasse=klasse))) == [], klasse


@pytest.mark.parametrize("wert", ["true", 1, None])
def test_schema_k1_annahme_modell_kein_bool_meldet_nur_den_typfehler_haertung(wert):
    """Ein `annahme_modell`, das kein Wahrheitswert ist, ergibt bei K1 nur den Typfehler, nicht zusätzlich den Fehler „braucht annahme_modell true“."""
    f = [x for x in bericht.pruefe_schema(mit(befund(klasse="K1 x", annahme_modell=wert))) if "annahme_modell" in x]
    assert len(f) == 1 and "muss true oder false sein" in f[0], f


@pytest.mark.parametrize("status", ["unbestätigt", "verworfen", "verdacht"])
def test_schema_k1_ohne_bestaetigt_braucht_keine_annahme_haertung(status):
    b = befund(status=status, klasse="K1 Tool mit Wirkung nach fremd befülltem Kontext", code_pfad=["src/a.js:1", "src/b.js:2"], grund="g")
    assert not any("annahme_modell" in x for x in bericht.pruefe_schema(mit(b)))


def test_schema_ki_felder_optional():
    b = befund()
    assert "owasp_ki" not in b and "annahme_modell" not in b
    assert bericht.pruefe_schema(mit(b)) == []


def test_markdown_owasp_ki_detailzeile():
    md = bericht.markdown(mit(befund(owasp_ki=["ASI01", "ASI02"])))
    assert "- OWASP KI: ASI01, ASI02" in md.splitlines()
    assert bericht.markdown(beispiel()).count("OWASP KI") == 0


def test_markdown_annahme_modell_statusanzeige():
    md = bericht.markdown(mit(ki_befund()))
    assert "- Status: bestätigt (Modell-Mock, Annahme: Modell folgt)" in md.splitlines()
    ohne = bericht.markdown(mit(befund(annahme_modell=False)))
    assert "- Status: bestätigt" in ohne.splitlines() and "Modell-Mock" not in ohne
    nur_ids = bericht.markdown(mit(befund(owasp_ki=["ASI01"])))
    assert "Modell-Mock" not in nur_ids


def test_markdown_ki_felder_lassen_befundliste_unveraendert():
    basis = codeblock(bericht.markdown(mit(befund())))
    mit_ki = codeblock(bericht.markdown(mit(ki_befund())))
    assert mit_ki == basis
    block = "\n".join(mit_ki)
    assert "OWASP" not in block and "Modell-Mock" not in block and "ASI01" not in block


def test_schema_unbekannte_felder_erlaubt():
    d = beispiel()
    d["extra"] = {"x": 1}
    d["befunde"][0]["zusatz"] = [1, 2]
    assert bericht.pruefe_schema(d) == []


def test_schema_poc_mit_fremdem_host():
    d = beispiel()
    d["befunde"][0]["poc"] = "GET http://evil.test/x"
    fehler = bericht.pruefe_schema(d)
    assert any("S-1" in f and "poc" in f and "evil.test" in f for f in fehler)
    d["befunde"][0]["poc"] = "GET http://app:3000/p?u=http%3A%2F%2Fevil.test"
    assert any("poc" in f for f in bericht.pruefe_schema(d))


def test_schema_falsche_typen(tmp_path):
    d = beispiel()
    d["befunde"][0]["zeile"] = "12"
    assert any("zeile" in f for f in bericht.pruefe_schema(d))
    d["befunde"][0]["zeile"] = True
    assert any("zeile" in f for f in bericht.pruefe_schema(d))
    d["befunde"][0]["zeile"] = 0
    assert any("zeile" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    d["befunde"][0]["stufe"] = "p1"
    assert any("stufe" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    del d["befunde"]
    assert any("befunde" in f for f in bericht.pruefe_schema(d))
    for schlecht in (None, [], "x", 3, [1], {"a": 1}):
        fehler = bericht.pruefe_schema(schlecht)           # darf nie werfen
        assert isinstance(fehler, list) and fehler
    d = beispiel()
    d.update(version=True, karte="x", hinweise=[1], befunde=[1, None])
    assert len(bericht.pruefe_schema(d)) >= 4
    d = beispiel()
    d["befunde"][0].update(ohne_anmeldung="nein", mandantenuebergreifend=0, titel=5)
    assert len(bericht.pruefe_schema(d)) >= 3
    # CLI: falsche Typen enden mit Exit 2 ohne Traceback
    pfad = tmp_path / "b.json"
    d = beispiel()
    d.update(befunde=[{"id": 1, "zeile": "x"}], karte=[3])
    pfad.write_text(json.dumps(d))
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "Traceback" not in p.stderr and p.stderr.strip()


def test_schema_doppelte_id():
    d = beispiel()
    d["befunde"][1]["id"] = "S-1"
    assert any("S-1" in f and "doppelt" in f for f in bericht.pruefe_schema(d))


@pytest.mark.parametrize("id_", ["S-", "S1", "s-1", "S-1a", "S- 1", "S-1\n"])
def test_schema_id_format(id_):
    d = beispiel()
    d["befunde"][0]["id"] = id_
    assert any("id" in f for f in bericht.pruefe_schema(d))


@pytest.mark.parametrize("feld", ["titel", "szenario", "erwartet", "klasse", "grund"])
@pytest.mark.parametrize("wert", ["a\nb", "a\rb", "a ``` b", "a\x1b[31mb", "a‮b"])
def test_schema_einzeilige_felder(feld, wert):
    d = beispiel()
    d["befunde"][2][feld] = wert                       # S-3 ist verworfen und hat alle Felder inkl. grund
    fehler = bericht.pruefe_schema(d)
    assert any("S-3" in f and feld in f for f in fehler)


def test_schema_mehrzeilig_nur_beschreibung_und_poc():
    d = beispiel()
    d["befunde"][0]["beschreibung"] = "a\n```\nb"
    d["befunde"][0]["poc"] = "GET http://app:3000/x\n```\n"
    assert bericht.pruefe_schema(d) == []


def test_schema_kopfzeilen_felder_sicher():
    d = beispiel()
    d["repo"] = "a\nb"
    assert any("repo" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    d["sha"] = "xyz```"
    assert any("sha" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    d["datum"] = "heute"
    assert any("datum" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    d["teilpfad"] = "a\nb"
    assert any("teilpfad" in f for f in bericht.pruefe_schema(d))


def test_rendern_ungueltiges_json_exit_2(tmp_path):
    pfad = tmp_path / "kaputt.json"
    pfad.write_text("{")
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "Traceback" not in p.stderr and p.stderr.strip()
    pfad.write_bytes(b"\xff\xfe\x00")
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "Traceback" not in p.stderr
    p = lauf("rendern", str(tmp_path / "gibt-es-nicht.json"))
    assert p.returncode == 2 and "Traceback" not in p.stderr
    pfad.write_text("[" * 100000)
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "Traceback" not in p.stderr
    assert not (tmp_path / "kaputt.md").exists()


def test_rendern_schreibt_md_neben_json(tmp_path):
    pfad = tmp_path / "2026-11-09-abc1234.json"
    pfad.write_text(json.dumps(beispiel()))
    p = lauf("rendern", str(pfad))
    assert p.returncode == 0, p.stderr
    md = tmp_path / "2026-11-09-abc1234.md"
    assert md.read_text(encoding="utf-8") == bericht.markdown(beispiel())
    assert str(md) in p.stdout


def test_rendern_schemafehler_schreibt_nichts(tmp_path):
    d = beispiel()
    d["befunde"][0]["kategorie"] = "A11"
    pfad = tmp_path / "x.json"
    pfad.write_text(json.dumps(d))
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "S-1" in p.stderr and "kategorie" in p.stderr
    assert not (tmp_path / "x.md").exists()


# ------------------------------------------------------------------------------------ Markdown

def codeblock(md):
    zeilen = md.splitlines()
    start = zeilen.index("```")
    ende = zeilen.index("```", start + 1)
    return zeilen[start + 1:ende]


def test_markdown_kopfzeile_erste_zeile_im_ersten_codeblock():
    md = bericht.markdown(beispiel())
    assert md.startswith("# Security-Audit kunde-portal · 2026-11-09\n")
    assert codeblock(md)[0] == KOPF


def test_markdown_p1_vor_p2_unabhaengig_von_json_reihenfolge():
    d = beispiel()
    d["befunde"] = [befund(id="S-2", stufe="P2", titel="zweiter"), befund(id="S-10", stufe="P1", titel="e"),
                    befund(id="S-3", stufe="P1", titel="dritter"), befund(id="S-9", stufe="P3", titel="letzter")]
    ids = [z.split()[0] for z in codeblock(bericht.markdown(d)) if re.match(r"S-\d+ \[", z)]
    assert ids == ["S-3", "S-10", "S-2", "S-9"]


def test_markdown_befundzeile_und_einrueckung():
    block = codeblock(bericht.markdown(beispiel()))
    i = block.index("S-1 [P1] src/routes/projects.js:12 — IDOR auf Projekte")
    assert block[i + 1] == "       Szenario: Nutzer A liest Projekt von B"
    assert block[i + 2] == "       Erwartet: Mandanten-Scope prüfen"
    assert block[i + 3] == "       Klasse: keine weiteren"
    assert "S-2 [P2] src/db.js:30 — Raw SQL" in block


def test_markdown_repo_weit_und_ohne_zeile():
    d = beispiel()
    d["befunde"] = [befund(id="S-4", stufe="P2", datei=None, zeile=None, titel="Rate-Limit fehlt"),
                    befund(id="S-5", stufe="P2", zeile=None, titel="Ganze Datei")]
    block = codeblock(bericht.markdown(d))
    assert "S-4 [P2] (repo-weit) — Rate-Limit fehlt" in block
    assert "S-5 [P2] src/routes/projects.js — Ganze Datei" in block


def test_markdown_verworfen_und_verdacht_nur_in_eigenen_zeilen():
    md = bericht.markdown(beispiel())
    block = codeblock(md)
    assert "Verworfen: Debug-Route — nur im Testmodus aktiv" in block
    assert "Verdacht (nicht belegt): S-4 Rate-Limit fehlt" in block
    assert md.count("Debug-Route") == 1 and md.count("Rate-Limit fehlt") == 1
    assert not any(re.match(r"S-[34] \[", z) for z in block)


def test_markdown_mehrere_verdachte_in_einer_zeile():
    d = beispiel()
    d["befunde"] += [befund(id="S-7", stufe="P2", status="verdacht", titel="zweiter Verdacht")]
    zeilen = [z for z in codeblock(bericht.markdown(d)) if z.startswith("Verdacht")]
    assert zeilen == ["Verdacht (nicht belegt): S-4 Rate-Limit fehlt; S-7 zweiter Verdacht"]


def test_markdown_ohne_verworfen_und_verdacht_keine_zeilen():
    d = beispiel()
    d["befunde"] = d["befunde"][:2]
    block = codeblock(bericht.markdown(d))
    assert not any(z.startswith(("Verworfen", "Verdacht")) for z in block)


def test_markdown_beschreibung_und_poc_nicht_in_der_befundliste():
    d = beispiel()
    d["befunde"][0].update(beschreibung="Einzigartig\nzwei", poc="GET http://app:3000/einzigartig")
    md = bericht.markdown(d)
    block = "\n".join(codeblock(md))
    assert "Einzigartig" not in block and "einzigartig" not in block
    assert md.count("Einzigartig") == 1 and md.count("einzigartig") == 1


def test_markdown_vier_backticks_und_laengerer_zaun_bei_inhalt():
    d = beispiel()
    d["befunde"][0]["beschreibung"] = "a\n````\nb\n``````\nc"
    d["befunde"][0]["poc"] = "GET http://app:3000/x\n```\n"
    md = bericht.markdown(d)
    zeilen = md.splitlines()
    # jeder Zaun außerhalb der Befundliste ist länger als jede Backtick-Folge im umschlossenen Inhalt
    i = zeilen.index("a")
    zaun = zeilen[i - 1]
    assert set(zaun) == {"`"} and len(zaun) >= 7
    assert zeilen[zeilen.index("c") + 1] == zaun
    j = zeilen.index("GET http://app:3000/x")
    assert zeilen[j - 1] == "````" and zeilen[j + 2] == "````"


def test_markdown_abschnitte():
    md = bericht.markdown(beispiel())
    assert "## Karte" in md and "API" in md and "src/routes/projects.js" in md
    assert "## Befunde im Detail" in md and "### S-1 [P1]" in md
    assert "src/routes/search.js:8" in md and "src/db.js:30" in md             # Code-Pfad von S-2
    assert "## Hinweise" in md and "Submodul: vendor/x" in md
    assert "A01" in md and "bestätigt" in md and "unbestätigt" in md


def test_markdown_hinweise_und_karte_einzeilig():
    d = beispiel()
    d["hinweise"] = ["zwei\nZeilen # Überschrift"]
    d["karte"] = [{"flaeche": "A\n# B", "dateien": ["x\ny"]}]
    md = bericht.markdown(d)
    assert "\n# B" not in md and "\n# Überschrift" not in md
    assert "Überschrift" in md


def test_markdown_ohne_befunde():
    d = beispiel()
    d["befunde"] = []
    d["hinweise"] = []
    d["karte"] = []
    md = bericht.markdown(d)
    assert codeblock(md) == [KOPF]


def test_markdown_veraendert_eingabe_nicht():
    d = beispiel()
    vorher = copy.deepcopy(d)
    bericht.markdown(d)
    assert d == vorher


# ------------------------------------------------------------------------------------ Fix-Runde 1

def test_schema_lange_id_kein_traceback_t2_i3(tmp_path):
    d = beispiel()
    d["befunde"][0]["id"] = "S-" + "1" * 5000
    assert any("id" in f for f in bericht.pruefe_schema(d))
    pfad = tmp_path / "lang.json"
    pfad.write_text(json.dumps(d))
    p = lauf("rendern", str(pfad))
    assert p.returncode == 2 and "Traceback" not in p.stderr and p.stderr.strip()
    assert not (tmp_path / "lang.md").exists()


@pytest.mark.parametrize("id_", ["S-01", "S-0", "S-1234567890", "S-" + "9" * 400])
def test_schema_id_ohne_fuehrende_nullen_max_9_ziffern_t2_i3(id_):
    d = beispiel()
    d["befunde"][0]["id"] = id_
    assert any("id" in f for f in bericht.pruefe_schema(d))


def test_schema_id_9_ziffern_gueltig_und_sortierbar_t2_i3():
    d = beispiel()
    d["befunde"][0]["id"] = "S-999999999"
    assert bericht.pruefe_schema(d) == []
    assert "S-999999999 [P1]" in "\n".join(codeblock(bericht.markdown(d)))


@pytest.mark.parametrize("feld", ["titel", "grund", "datei"])
@pytest.mark.parametrize("zeichen", [" ", " ", "\u0085", "\x0b", "\x0c"])
def test_schema_einzeilig_unicode_zeilentrenner_t2_i5(feld, zeichen):
    d = beispiel()
    d["befunde"][2][feld] = f"src/a{zeichen}b.js" if feld == "datei" else f"a{zeichen}b"
    fehler = bericht.pruefe_schema(d)
    assert any("S-3" in f and feld in f for f in fehler)


@pytest.mark.parametrize("repo", ["x ``` y", "a · Security-Audit · geprüft auf b", "a/b", "a b", "a\nb", ".."])
def test_schema_repo_kopfzeile_nicht_manipulierbar_t2_i6(repo):
    d = beispiel()
    d["repo"] = repo
    assert any("repo" in f for f in bericht.pruefe_schema(d))


def nfd(text):
    import unicodedata
    return unicodedata.normalize("NFD", text)


def test_status_nfd_wird_wie_nfc_akzeptiert_t2_i7():
    d = beispiel()
    d["befunde"][0]["status"] = nfd("bestätigt")
    d["befunde"][1]["status"] = nfd("unbestätigt")
    assert nfd("bestätigt") != "bestätigt"
    assert bericht.pruefe_schema(d) == []
    block = codeblock(bericht.markdown(d))
    assert any(z.startswith("S-1 [P1]") for z in block) and any(z.startswith("S-2 [P2]") for z in block)
    md = bericht.markdown(d)
    assert "- Status: bestätigt" in md and "- Status: unbestätigt" in md


def test_status_nfd_pflichtfelder_gelten_t2_i7():
    d = beispiel()
    d["befunde"] = [befund(status=nfd("bestätigt"))]
    del d["befunde"][0]["poc"]
    assert any("poc" in f for f in bericht.pruefe_schema(d))
    d["befunde"] = [befund(status=nfd("unbestätigt"))]
    assert any("code_pfad" in f for f in bericht.pruefe_schema(d))


def test_hinweis_mit_backticks_oeffnet_keinen_zaun_t2_m6():
    d = beispiel()
    d["hinweise"] = ["``` x", "```\nfoo"]
    d["karte"] = [{"flaeche": "``` F", "dateien": ["```"]}]
    zeilen = bericht.markdown(d).splitlines()
    assert zeilen[:3] == ["# Security-Audit kunde-portal · 2026-11-09", "", "```"]
    ende = zeilen.index("```", 3)
    rest = zeilen[ende + 1:]
    # kein ungeescapter Dreifach-Backtick außerhalb der Detail-Zäune (vier Backticks)
    assert all("```" not in z.replace("\\`", "") for z in rest if z.startswith(("- ", "1. ")))
    assert "- ``` x" not in rest and "- \\`\\`\\` x" in rest
    assert all(z != "```" for z in rest)
    for kopf in ("## Karte", "## Befunde im Detail", "## Hinweise"):
        assert kopf in rest


# ------------------------------------------------------------------------------------ Fix-Runde 2

def test_hinweis_mit_tilden_oeffnet_keinen_zaun_t2_n3():
    d = beispiel()
    d["hinweise"] = ["~~~ x", "a ~~~"]
    d["karte"] = [{"flaeche": "~~~ F", "dateien": ["~~~"]}]
    zeilen = bericht.markdown(d).splitlines()
    ende = zeilen.index("```", 3)
    rest = zeilen[ende + 1:]
    assert not any(z.lstrip("- 1.").startswith("~~~") for z in rest)
    assert "- \\~\\~\\~ x" in rest
    for kopf in ("## Karte", "## Befunde im Detail", "## Hinweise"):
        assert kopf in rest


# ------------------------------------------------------------------------------------ Härtung TF1-B5 (unsichtbare Zeichen, Reste)

UNSICHTBAR_B5 = ["\ufe0f", "\u034f", "\u0378", "\U000e0041", "\u200b", "\u202e", "\u115f", "\u2800", "\u180e", "\U000e0100"]


@pytest.mark.parametrize("zeichen", UNSICHTBAR_B5)
@pytest.mark.parametrize("feld", ["titel", "szenario", "erwartet", "klasse", "beschreibung", "poc"])
def test_schema_lehnt_unsichtbare_zeichen_in_freitext_ab_haertung_b5(feld, zeichen):
    """Versteckter Text (Tag-Zeichen, Variation Selectors, Bidi, Zero-Width) darf nicht in den Bericht, auch nicht in die
    mehrzeiligen Felder; `\n`, `\r`, `\t` bleiben dort erlaubt."""
    d = beispiel()
    d["befunde"][0][feld] = f"vorher{zeichen}nachher"
    fehler = bericht.pruefe_schema(d)
    assert any("S-1" in f and feld in f for f in fehler), (feld, ascii(zeichen), fehler)


@pytest.mark.parametrize("zeichen", UNSICHTBAR_B5)
def test_schema_lehnt_unsichtbare_zeichen_in_grund_projekt_teilpfad_karte_hinweisen_ab_haertung_b5(zeichen):
    d = beispiel()
    d["befunde"][2]["grund"] = f"a{zeichen}b"
    assert any("S-3" in f and "grund" in f for f in bericht.pruefe_schema(d))
    for feld in ("projekt", "teilpfad"):
        d = beispiel()
        d[feld] = f"a{zeichen}b"
        assert any(feld in f for f in bericht.pruefe_schema(d)), feld
    d = beispiel()
    d["karte"] = [{"flaeche": f"a{zeichen}b", "dateien": ["x"]}]
    assert any("karte[0]" in f for f in bericht.pruefe_schema(d))
    d["karte"] = [{"flaeche": "a", "dateien": [f"x{zeichen}y"]}]
    assert any("karte[0]" in f for f in bericht.pruefe_schema(d))
    d = beispiel()
    d["hinweise"] = [f"a{zeichen}b"]
    assert any("hinweise[0]" in f for f in bericht.pruefe_schema(d))


def test_schema_erlaubt_normale_zeichen_und_zeilenumbrueche_in_beschreibung_haertung_b5():
    d = beispiel()
    d["befunde"][0]["beschreibung"] = "Zeile 1\r\n\tZeile 2: Grüße 世界 😀 é\u0301 — „ok“"
    d["befunde"][0]["titel"] = "Größe 世界 😀"
    d["karte"] = [{"flaeche": "Fläche 世界", "dateien": ["src/ä.js"]}]
    d["hinweise"] = ["Symlink: a -> b (Ziel gesperrt)"]
    assert bericht.pruefe_schema(d) == []


def test_markdown_escaped_unsichtbare_zeichen_in_karte_und_hinweisen_haertung_b5():
    d = beispiel()
    d["hinweise"] = ["a\u202eb\ufe0f"]
    d["karte"] = [{"flaeche": "F\u200b", "dateien": ["x\U000e0041"]}]
    md = bericht.markdown(d)
    for z in ("\u202e", "\ufe0f", "\u200b", "\U000e0041"):
        assert z not in md
    assert "\\u202e" in md and "\\ufe0f" in md


def test_rendern_hinterlaesst_bei_internem_fehler_keine_tmp_datei_haertung_b5(tmp_path, monkeypatch):
    d = beispiel()
    (tmp_path / "w").mkdir()
    pfad = tmp_path / "w" / "bericht.json"
    pfad.write_text(json.dumps(d), encoding="utf-8")

    def kaputt(_daten):
        raise RuntimeError("interner Fehler")

    monkeypatch.setattr(bericht, "markdown", kaputt)
    with pytest.raises(RuntimeError):
        bericht._rendern(str(pfad))
    assert sorted(os.listdir(tmp_path / "w")) == ["bericht.json"]


# ------------------------------------------------------------------------------------ Härtung TF1-B6 (zwei Worker)

def test_kontext_reserviert_den_basisnamen_haertung_b6(tmp_path):
    """Zwei Audits desselben Repos am selben Tag und Commit bekommen verschiedene Dateinamen, auch bevor eines schreibt."""
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    k1 = bericht.kontext(str(r), None, JETZT)
    k2 = bericht.kontext(str(r), None, JETZT)
    assert k2["basisname"] == k1["basisname"] + "-2"
    for k in (k1, k2):
        assert os.path.isfile(os.path.join(k["ausgabe_ordner"], k["basisname"] + ".reserviert"))


def test_kontext_parallel_vergibt_eindeutige_basisnamen_haertung_b6(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    with ThreadPoolExecutor(8) as pool:
        namen = list(pool.map(lambda _: bericht.kontext(str(r), None, JETZT)["basisname"], range(16)))
    assert len(set(namen)) == 16, namen


def test_rendern_gibt_die_reservierung_frei_haertung_b6(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    k = bericht.kontext(str(r), None, JETZT)
    d = beispiel()
    d.update(sha=k["sha"], repo=k["repo"])
    pfad = os.path.join(k["ausgabe_ordner"], k["basisname"] + ".json")
    with open(pfad, "w", encoding="utf-8") as f:
        json.dump(d, f)
    marker = os.path.join(k["ausgabe_ordner"], k["basisname"] + ".reserviert")
    assert os.path.exists(marker)
    assert lauf("rendern", pfad).returncode == 0
    assert not os.path.exists(marker) and os.path.exists(os.path.join(k["ausgabe_ordner"], k["basisname"] + ".md"))
    assert lauf("rendern", pfad).returncode == 0              # erneutes Rendern ohne Marker: kein Fehler


def test_rendern_ohne_reservierung_bleibt_moeglich_haertung_b6(tmp_path):
    (tmp_path / "w").mkdir()
    pfad = tmp_path / "w" / "frei.json"
    pfad.write_text(json.dumps(beispiel()), encoding="utf-8")
    assert lauf("rendern", str(pfad)).returncode == 0


# ------------------------------------------------------------------------------------ Härtung TF1-B7 (Zusagen)

def test_kontext_verweigert_ausgabeordner_im_geprueften_repo_haertung_b7(tmp_path, monkeypatch):
    """„Der Skill ändert nie das geprüfte Repo“: der Ausgabeordner darf nicht darin liegen (auch nicht über HOME)."""
    r = neues_repo(tmp_path / "kunde-portal")
    monkeypatch.setenv("SECURITY_AUDIT_AUSGABE", str(r / "out"))
    with pytest.raises(bericht.KontextFehler, match="im geprüften Repo"):
        bericht.kontext(str(r), None, JETZT)
    assert not (r / "out").exists(), "der Ordner darf nicht einmal angelegt werden"
    p = lauf("kontext", "--repo", str(r))
    assert p.returncode == 3 and "im geprüften Repo" in p.stderr
    monkeypatch.delenv("SECURITY_AUDIT_AUSGABE")
    monkeypatch.setenv("HOME", str(r))                                  # Dotfile-Repo: ~/.claude/… läge im Repo
    with pytest.raises(bericht.KontextFehler, match="im geprüften Repo"):
        bericht.kontext(str(r), None, JETZT)
    assert not (r / ".claude").exists()


def test_kontext_ausgabeordner_ueber_symlink_ins_repo_wird_erkannt_haertung_b7(tmp_path, monkeypatch):
    r = neues_repo(tmp_path / "kunde-portal")
    (tmp_path / "aussen").mkdir()
    os.symlink(r, tmp_path / "aussen" / "kunde-portal")                 # <ausgabe>/<name> ist ein Link ins Repo
    monkeypatch.setenv("SECURITY_AUDIT_AUSGABE", str(tmp_path / "aussen"))
    with pytest.raises(bericht.KontextFehler, match="im geprüften Repo"):
        bericht.kontext(str(r), None, JETZT)


def test_kontext_ausgabeordner_neben_dem_repo_ist_ok_haertung_b7(tmp_path, monkeypatch):
    r = neues_repo(tmp_path / "kunde-portal")
    monkeypatch.setenv("SECURITY_AUDIT_AUSGABE", str(tmp_path / "kunde-portal-ausgabe"))   # gleicher Präfix, anderer Ordner
    assert bericht.kontext(str(r), None, JETZT)["ausgabe_ordner"].startswith(os.path.realpath(tmp_path / "kunde-portal-ausgabe"))


def teil(datei, teilpfad="src/api"):
    d = beispiel()
    d["teilpfad"] = teilpfad
    for b in d["befunde"]:
        b["datei"], b["zeile"] = teilpfad + "/x.js", 3
        if b["status"] == "unbestätigt":
            b["code_pfad"] = ["a.js:1", "b.js:2"]            # der Weg darf außerhalb liegen
    d["befunde"][0]["datei"] = datei
    return d


@pytest.mark.parametrize("datei", ["src/api/orders.ts", "src/api/a/b/c.ts", "src/api"])
def test_schema_befund_unter_teilpfad_ok_haertung_b7(datei):
    assert bericht.pruefe_schema(teil(datei)) == []


@pytest.mark.parametrize("datei", ["src/lib/x.ts", "src/apix/orders.ts", "src/api2", "src", "README.md", "SRC/api/x.ts"])
def test_schema_befund_ausserhalb_des_teilpfads_ist_fehler_haertung_b7(datei):
    fehler = bericht.pruefe_schema(teil(datei))
    assert any("S-1" in f and "teilpfad" in f for f in fehler), (datei, fehler)


def test_schema_teilpfad_repo_weit_und_ohne_teilpfad_haertung_b7():
    d = teil("src/api/x.ts")
    d["befunde"][0].update(datei=None, zeile=None)               # repo-weiter Befund bleibt erlaubt
    assert bericht.pruefe_schema(d) == []
    d = beispiel()                                                # ohne teilpfad: jeder Pfad
    assert d["teilpfad"] is None and bericht.pruefe_schema(d) == []


def test_schema_teilpfad_mit_nfd_und_schraegstrich_am_ende_haertung_b7():
    import unicodedata
    d = teil("src/Äpfel/x.ts", teilpfad="src/Äpfel")
    d["teilpfad"] = unicodedata.normalize("NFD", "src/Äpfel") + "/"
    assert unicodedata.normalize("NFD", d["teilpfad"]) != "src/Äpfel/"
    assert bericht.pruefe_schema(d) == []


def _json_zu_kontext(k, **ueberschreibe):
    d = beispiel()
    d.update(sha=k["sha"], repo=k["repo"], teilpfad=k["teilpfad"], befunde=[])
    d.update(ueberschreibe)
    pfad = os.path.join(k["ausgabe_ordner"], k["basisname"] + ".json")
    with open(pfad, "w", encoding="utf-8") as f:
        json.dump(d, f)
    return pfad


def test_rendern_prueft_sha_repo_und_teilpfad_gegen_die_reservierung_haertung_b4(tmp_path):
    """Die Zusage „geprüft auf <sha>“ ist an das gebunden, was `kontext` ermittelt hat: ein anderer SHA im JSON scheitert."""
    r = neues_repo(tmp_path / "kunde-portal", {"src/a.js": "x"}, origin="https://github.com/a/kunde-portal.git")
    k = bericht.kontext(str(r), "src", JETZT)
    for feld, falsch in (("sha", "b" * 40), ("repo", "anderes-repo"), ("teilpfad", None), ("teilpfad", "lib")):
        p = lauf("rendern", _json_zu_kontext(k, **{feld: falsch}))
        assert p.returncode == 2 and "Reservierung" in p.stderr and feld in p.stderr, (feld, p.stderr)
        assert not os.path.exists(os.path.join(k["ausgabe_ordner"], k["basisname"] + ".md"))
    p = lauf("rendern", _json_zu_kontext(k))
    assert p.returncode == 0, p.stderr


def test_rendern_mit_unlesbarer_reservierung_warnt_statt_zu_pruefen_haertung_b4(tmp_path):
    r = neues_repo(tmp_path / "kunde-portal", origin="https://github.com/a/kunde-portal.git")
    k = bericht.kontext(str(r), None, JETZT)
    with open(os.path.join(k["ausgabe_ordner"], k["basisname"] + ".reserviert"), "w") as f:
        f.write("kein json")
    p = lauf("rendern", _json_zu_kontext(k, sha="c" * 40))
    assert p.returncode == 0 and "Reservierung" in p.stderr and "nicht geprüft" in p.stderr


# ------------------------------------------------------------------------------------ Härtung TF1-I3 (Gesamtbudget kontext)

def _langsames_git(tmp_path, monkeypatch, pause):
    """`git` im PATH, das vor jedem Aufruf `pause` Sekunden wartet und dann das echte git ausführt."""
    echt = shutil.which("git")
    ordner = tmp_path / "langsames-git"
    ordner.mkdir()
    shim = ordner / "git"
    shim.write_text(f'#!/bin/sh\nsleep {pause}\nexec {echt} "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{ordner}{os.pathsep}{os.environ['PATH']}")


def test_kontext_standardbudget_ist_300_sekunden_haertung_i3(monkeypatch):
    monkeypatch.delenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", raising=False)
    assert bericht.KONTEXT_BUDGET == 300 and bericht._kontext_budget() == 300
    monkeypatch.setenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", "12.5")
    assert bericht._kontext_budget() == 12.5


@pytest.mark.parametrize("wert", ["abc", "0", "-5", "nan", "inf"])
def test_kontext_ungueltiges_budget_ist_exit_3_ohne_stillen_standard_haertung_i3(tmp_path, monkeypatch, wert):
    r = neues_repo(tmp_path / "kunde-portal")
    monkeypatch.setenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", wert)
    p = lauf("kontext", "--repo", str(r))
    assert p.returncode == 3 and "SECURITY_AUDIT_KONTEXT_TIMEOUT" in p.stderr and p.stdout == ""


def test_kontext_gesamtbudget_ueberschritten_ist_exit_3_mit_meldung_haertung_i3(tmp_path, monkeypatch):
    """Jeder einzelne git-Aufruf (0,7 s) bliebe unter seinem Timeout; die Summe sprengt das Gesamtbudget von 2 s."""
    r = neues_repo(tmp_path / "kunde-portal")
    _langsames_git(tmp_path, monkeypatch, 0.7)
    monkeypatch.setenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", "2")
    t0 = time.monotonic()
    p = lauf("kontext", "--repo", str(r))
    assert time.monotonic() - t0 < 20
    assert p.returncode == 3 and "Zeitbudget" in p.stderr and "Traceback" not in p.stderr and p.stdout == ""
    ziel = os.path.join(os.environ["SECURITY_AUDIT_AUSGABE"], "kunde-portal")
    assert not os.path.isdir(ziel) or not os.listdir(ziel), "abgebrochenes kontext darf keinen Namen reserviert lassen"


def test_kontext_budget_kuerzt_den_einzelaufruf_haertung_i3(tmp_path, monkeypatch):
    """Ein einziger hängender git-Aufruf (30 s, Einzelgrenze 60 s) endet mit dem Gesamtbudget, nicht erst mit seiner Grenze."""
    r = neues_repo(tmp_path / "kunde-portal")
    _langsames_git(tmp_path, monkeypatch, 30)
    monkeypatch.setenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", "1")
    t0 = time.monotonic()
    p = lauf("kontext", "--repo", str(r))
    assert time.monotonic() - t0 < 15
    assert p.returncode == 3 and "Zeitbudget" in p.stderr


def test_kontext_mit_ausreichendem_budget_laeuft_normal_haertung_i3(tmp_path, monkeypatch):
    r = neues_repo(tmp_path / "kunde-portal")
    monkeypatch.setenv("SECURITY_AUDIT_KONTEXT_TIMEOUT", "120")
    p = lauf("kontext", "--repo", str(r))
    assert p.returncode == 0, p.stderr
