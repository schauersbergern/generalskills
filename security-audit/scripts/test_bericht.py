"""Tests für bericht.py (Kontext, Schema, Markdown-Befundliste).

Aufruf: python3 -m pytest security-audit/scripts/test_bericht.py -q
Alle Repos und Ausgaben liegen in tmp_path; HOME und SECURITY_AUDIT_AUSGABE zeigen dorthin.
"""
import copy
import json
import os
import re
import subprocess
import sys
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
    d["teilpfad"] = "src/api"
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
