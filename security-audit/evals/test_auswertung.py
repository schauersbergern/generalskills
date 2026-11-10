"""Tests für evals/auswertung.py (TF1-D8): reine Funktionen auf präparierten Berichten und Streams.

Aufruf: python3 -m pytest security-audit/evals/test_auswertung.py -q
Testdaten liegen in evals/testdaten/ (handgeschrieben, nur evil.test und fixture.invalid als fremde Hosts).
"""
import copy
import json
import os
import sys
import unicodedata

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import auswertung  # noqa: E402

TESTDATEN = os.path.join(HIER, "testdaten")
POC = "python3 /skill/scripts/poc.py"
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
