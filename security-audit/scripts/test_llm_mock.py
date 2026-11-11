"""Tests für docker/llm-mock.mjs (Modell-Mock, Kern: Chat Completions, Embeddings, Models, Steuerung).

Aufruf: python3 -m pytest security-audit/scripts/test_llm_mock.py -q
Der Mock läuft lokal mit Node auf 127.0.0.1 (Port 0, Ports aus der bereit-Zeile) als eigene Prozessgruppe
(`start_new_session=True`). Beendet wird nur diese Gruppe, und nur solange der eigene Popen noch läuft.
Requests gehen per `http.client` ausschließlich an 127.0.0.1.
"""
import base64
import http.client
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import threading

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HIER)
MOCK = os.path.join(SKILL, "docker", "llm-mock.mjs")
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node fehlt")

BEREIT = re.compile(r"^bereit api=(\d+) steuer=(\d+)$")
BODY_GRENZE = 8192


class Mock:
    """Ein lokal gestarteter Mock. Beendet wird nur die eigene Prozessgruppe."""

    def __init__(self, extra=()):
        self.p = subprocess.Popen(
            [NODE, MOCK, "--server", "--host", "127.0.0.1", "--port", "0", "--steuer-port", "0", *extra],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.api = self.steuer = None
        self.erste_zeile = None
        try:
            self._bereit_lesen()
        except BaseException:
            self.beenden()
            raise

    def _bereit_lesen(self, frist=10):
        gelesen = []
        t = threading.Thread(target=lambda: gelesen.append(self.p.stdout.readline()), daemon=True)
        t.start()
        t.join(frist)
        if not gelesen or not gelesen[0]:
            pytest.fail(f"keine bereit-Zeile innerhalb von {frist} s")
        self.erste_zeile = gelesen[0].decode("utf-8").rstrip("\n")
        m = BEREIT.match(self.erste_zeile)
        assert m, f"bereit-Zeile ungültig: {self.erste_zeile!r}"
        self.api, self.steuer = int(m.group(1)), int(m.group(2))

    def beenden(self):
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGTERM)
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if self.p.poll() is None:
                    os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait(timeout=5)

    def rest(self):
        """Alles, was der Server nach der bereit-Zeile auf stdout/stderr geschrieben hat (erst nach beenden)."""
        assert self.p.poll() is not None
        return self.p.stdout.read(), self.p.stderr.read()


@pytest.fixture
def mock():
    m = Mock()
    try:
        yield m
    finally:
        m.beenden()


def anfrage(port, methode, pfad, body=None, header=None):
    """Gibt (status, Header-Dict mit kleingeschriebenen Namen, Bytes) zurück."""
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        c.request(methode, pfad, body=body, headers=header or {})
        r = c.getresponse()
        daten = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, daten
    finally:
        c.close()


def cli(modus, steuer, eingabe="", extra=(), timeout=20):
    """Ruft das Mock-CLI als kurzlebigen Kindprozess auf. `eingabe` ist str oder bytes."""
    daten = eingabe.encode("utf-8") if isinstance(eingabe, str) else eingabe
    return subprocess.run(
        [NODE, MOCK, modus, "--steuer-port", str(steuer), *extra],
        input=daten, capture_output=True, timeout=timeout,
    )


def setzen(m, liste):
    r = cli("--setzen", m.steuer, json.dumps(liste))
    assert r.returncode == 0, r.stderr
    assert r.stdout == b""


def protokoll(m, werte=(), suche=None):
    extra = ["--suche", suche] if suche is not None else []
    r = cli("--protokoll", m.steuer, json.dumps({"werte": list(werte)}), extra)
    assert r.returncode == 0, r.stderr
    assert r.stdout.isascii()
    assert len(r.stdout) <= 65536 + 1  # plus Zeilenumbruch
    return json.loads(r.stdout)


def chat(m, inhalt="hallo", pfad="/v1/chat/completions", **extra):
    body = {"model": "x", "messages": [{"role": "user", "content": inhalt}], **extra}
    status, header, roh = anfrage(m.api, "POST", pfad, body)
    return status, header, roh


def chat_json(m, inhalt="hallo", **extra):
    status, _, roh = chat(m, inhalt, **extra)
    assert status == 200, roh
    return json.loads(roh)


def sse_daten(roh):
    ereignisse = []
    for block in roh.decode("utf-8").split("\n\n"):
        if not block.strip():
            continue
        assert block.startswith("data: "), block
        ereignisse.append(block[len("data: "):])
    return ereignisse


def chat_stream(m, inhalt="hallo", **extra):
    status, header, roh = chat(m, inhalt, stream=True, **extra)
    assert status == 200, roh
    assert header["content-type"].startswith("text/event-stream")
    daten = sse_daten(roh)
    assert daten[-1] == "[DONE]"
    return [json.loads(d) for d in daten[:-1]]


def freier_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------- Start und Statik


def test_mock_bereit_zeile_und_bereit_befehl(mock):
    assert BEREIT.match(mock.erste_zeile)
    assert mock.api != mock.steuer
    r = cli("--bereit", mock.steuer)
    assert (r.returncode, r.stdout, r.stderr) == (0, b"", b"")


def test_mock_nur_node_builtins():
    quelle = open(MOCK, encoding="utf-8").read()
    importe = re.findall(r"^import\b.*?from\s+\"([^\"]+)\"", quelle, re.M)
    assert importe and all(i.startswith("node:") for i in importe), importe
    assert "require(" not in quelle and "import(" not in quelle
    assert "experimental" not in quelle.split("\n", 1)[0].lower()


def test_mock_nach_bereit_nichts_mehr_auf_stdout_und_kein_echo(mock):
    geheim = "GEHEIM-ECHO-4711"
    antworten = []
    setzen(mock, [{"text": "antwort"}])
    antworten.append(chat(mock, geheim)[2])
    antworten.append(chat(mock, geheim, stream=True)[2])
    antworten.append(chat(mock, geheim, stream=True, stream_options={"include_usage": True})[2])
    antworten.append(anfrage(mock.api, "POST", f"/v1/{geheim}?x={geheim}", f"{geheim}", {"x-geheim": geheim})[2])
    antworten.append(anfrage(mock.api, "POST", "/v1/chat/completions", "{" + geheim)[2])
    antworten.append(anfrage(mock.api, "POST", "/v1/embeddings", {"input": geheim, "model": geheim})[2])
    antworten.append(anfrage(mock.api, "POST", "/v1/embeddings", {"input": [], "model": geheim})[2])
    antworten.append(anfrage(mock.api, "GET", f"/v1/models?{geheim}")[2])
    for a in antworten:
        assert geheim.encode() not in a
        assert geheim.lower().encode() not in a.lower()
    mock.beenden()
    out, err = mock.rest()
    assert out == b"" and err == b""


# --------------------------------------------------------------- Chat Completions


def test_mock_chat_nicht_streamend_text(mock):
    setzen(mock, [{"text": "Guten Tag"}])
    d = chat_json(mock, "frage", model="irgendein-modell-xyz")
    assert d["object"] == "chat.completion"
    assert d["id"].startswith("chatcmpl-") and isinstance(d["created"], int)
    assert d["model"] == "poc-mock"  # kein Echo des Request-Modells
    (wahl,) = d["choices"]
    assert wahl["index"] == 0 and wahl["finish_reason"] == "stop"
    assert wahl["message"]["role"] == "assistant" and wahl["message"]["content"] == "Guten Tag"
    assert "tool_calls" not in wahl["message"]
    u = d["usage"]
    assert u["total_tokens"] == u["prompt_tokens"] + u["completion_tokens"] and u["completion_tokens"] >= 1


def test_mock_chat_nicht_streamend_tool(mock):
    setzen(mock, [{"werkzeug": {"name": "tool_a", "argumente": {"pfad": "x y", "n": 3}}}])
    d = chat_json(mock)
    (wahl,) = d["choices"]
    assert wahl["finish_reason"] == "tool_calls"
    assert wahl["message"]["content"] is None
    (tc,) = wahl["message"]["tool_calls"]
    assert tc["type"] == "function" and tc["id"]
    assert tc["function"]["name"] == "tool_a"
    assert json.loads(tc["function"]["arguments"]) == {"pfad": "x y", "n": 3}


def test_mock_chat_streamend_text(mock):
    text = "Dies ist eine längere Antwort mit mehreren Stücken."
    setzen(mock, [{"text": text}])
    chunks = chat_stream(mock)
    assert len(chunks) >= 4
    assert all(c["object"] == "chat.completion.chunk" and c["model"] == "poc-mock" for c in chunks)
    assert len({c["id"] for c in chunks}) == 1
    assert chunks[0]["choices"][0]["delta"]["role"] == "assistant"
    inhalt = "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks)
    assert inhalt == text
    assert [c["choices"][0]["finish_reason"] for c in chunks[:-1]] == [None] * (len(chunks) - 1)
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert all("usage" not in c for c in chunks)  # ohne include_usage keine usage


def test_mock_chat_streamend_tool(mock):
    argumente = {"pfad": "/etc; echo poc", "tiefe": 2, "liste": ["a", "b"]}
    setzen(mock, [{"werkzeug": {"name": "tool_b", "argumente": argumente}}])
    chunks = chat_stream(mock)
    aufrufe = {}
    for c in chunks:
        for tc in c["choices"][0]["delta"].get("tool_calls") or []:
            a = aufrufe.setdefault(tc["index"], {"id": None, "name": "", "args": ""})
            a["id"] = tc.get("id") or a["id"]
            a["name"] += (tc.get("function") or {}).get("name") or ""
            a["args"] += (tc.get("function") or {}).get("arguments") or ""
    assert list(aufrufe) == [0]
    assert aufrufe[0]["id"] and aufrufe[0]["name"] == "tool_b"
    assert json.loads(aufrufe[0]["args"]) == argumente
    assert chunks[-1]["choices"][0]["finish_reason"] == "tool_calls"
    assert sum(1 for c in chunks if c["choices"][0]["delta"].get("tool_calls")) >= 3  # Kopf plus mehrere Argument-Stücke


def test_mock_chat_streamend_usage_bei_include_usage(mock):
    setzen(mock, [{"text": "abc"}])
    chunks = chat_stream(mock, stream_options={"include_usage": True})
    *vorher, letzter = chunks
    assert letzter["choices"] == [] and letzter["usage"]["total_tokens"] == letzter["usage"]["prompt_tokens"] + letzter["usage"]["completion_tokens"]
    assert all(c["usage"] is None for c in vorher)
    assert vorher[-1]["choices"][0]["finish_reason"] == "stop"


def test_mock_tool_ids_eindeutig(mock):
    setzen(mock, [{"werkzeug": {"name": "t", "argumente": {}}} for _ in range(4)])
    ids = []
    for _ in range(2):
        ids.append(chat_json(mock)["choices"][0]["message"]["tool_calls"][0]["id"])
    for _ in range(2):
        for c in chat_stream(mock):
            for tc in c["choices"][0]["delta"].get("tool_calls") or []:
                if tc.get("id"):
                    ids.append(tc["id"])
    assert len(ids) == 4 and len(set(ids)) == 4
    # auch über einen weiteren Durchgang eindeutig
    setzen(mock, [{"werkzeug": {"name": "t", "argumente": {}}}])
    ids.append(chat_json(mock)["choices"][0]["message"]["tool_calls"][0]["id"])
    assert len(set(ids)) == 5


def test_mock_werkzeug_ohne_argumente_ergibt_leeres_objekt(mock):
    setzen(mock, [{"werkzeug": {"name": "ohne"}}])
    tc = chat_json(mock)["choices"][0]["message"]["tool_calls"][0]
    assert json.loads(tc["function"]["arguments"]) == {}


# --------------------------------------------------------------- Warteschlange und Marker


def test_mock_wenn_enthaelt_mehrere(mock):
    setzen(mock, [
        {"text": "A", "wenn_enthaelt": "POCMARKER-p1-aaaa"},
        {"text": "B", "wenn_enthaelt": "POCMARKER-p1-bbbb"},
        {"text": "C"},
        {"werkzeug": {"name": "w", "argumente": {}}, "wenn_enthaelt": "POCMARKER-p1-cccc"},
    ])

    def text(d):
        return d["choices"][0]["message"]["content"]

    # Der Request mit dem zweiten Marker bekommt B, auch wenn A davor in der Schlange steht.
    assert text(chat_json(mock, "x POCMARKER-p1-bbbb y")) == "B"
    # Ein Request ohne Marker bekommt den ersten Eintrag ohne Marker (C), nicht A.
    assert text(chat_json(mock, "ohne")) == "C"
    # Verbraucht: derselbe Marker bekommt B nicht noch einmal.
    assert text(chat_json(mock, "POCMARKER-p1-bbbb")) == "ok"
    # A wartet weiter auf seinen Marker.
    assert text(chat_json(mock, "POCMARKER-p1-aaaa")) == "A"
    # Das Werkzeug geht nur an den Request mit seinem Marker.
    d = chat_json(mock, "POCMARKER-p1-cccc")
    assert d["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "w"
    assert text(chat_json(mock, "POCMARKER-p1-cccc")) == "ok"


def test_mock_wenn_enthaelt_gilt_auch_streamend(mock):
    setzen(mock, [{"text": "nur-mit-marker", "wenn_enthaelt": "POCMARKER-p2-1234"}])
    chunks = chat_stream(mock, "ohne marker")
    assert "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks) == "ok"
    chunks = chat_stream(mock, "mit POCMARKER-p2-1234")
    assert "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks) == "nur-mit-marker"


def test_mock_ohne_passenden_eintrag_ok(mock):
    # leere Warteschlange
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"
    # nur Einträge mit fremdem Marker: Antwort „ok“, der Eintrag bleibt erhalten
    setzen(mock, [{"text": "geheim", "wenn_enthaelt": "POCMARKER-p1-zzzz"}])
    assert chat_json(mock, "kein marker")["choices"][0]["message"]["content"] == "ok"
    assert chat_json(mock, "POCMARKER-p1-zzzz")["choices"][0]["message"]["content"] == "geheim"
    chunks = chat_stream(mock)
    assert "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks) == "ok"


def test_mock_setzen_ersetzt_die_warteschlange(mock):
    setzen(mock, [{"text": "alt1"}, {"text": "alt2"}])
    setzen(mock, [{"text": "neu"}])
    assert chat_json(mock)["choices"][0]["message"]["content"] == "neu"
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"
    setzen(mock, [])
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"


# --------------------------------------------------------------- Embeddings und Models


def test_mock_embeddings_verbrauchen_nichts(mock):
    setzen(mock, [{"text": "bleibt"}, {"werkzeug": {"name": "t", "argumente": {}}}])
    status, _, roh = anfrage(mock.api, "POST", "/v1/embeddings", {"input": "hallo", "model": "m"})
    assert status == 200
    status, _, roh2 = anfrage(mock.api, "POST", "/v1/embeddings", {"input": ["a", "b"], "model": "m", "dimensions": 8})
    assert status == 200
    d = json.loads(roh)
    assert d["object"] == "list" and d["model"] == "poc-mock"
    assert len(json.loads(roh2)["data"]) == 2
    # die Warteschlange ist unberührt: beide Einträge kommen noch, in Reihenfolge
    assert chat_json(mock)["choices"][0]["message"]["content"] == "bleibt"
    assert chat_json(mock)["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "t"
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"


def test_mock_embeddings_dimension_und_determinismus(mock):
    def holen(**kw):
        status, _, roh = anfrage(mock.api, "POST", "/v1/embeddings", {"model": "m", **kw})
        assert status == 200, roh
        return json.loads(roh)

    standard = holen(input="text")
    assert len(standard["data"][0]["embedding"]) == 1536
    assert standard["data"][0]["object"] == "embedding" and standard["data"][0]["index"] == 0
    klein = holen(input="text", dimensions=8)
    assert len(klein["data"][0]["embedding"]) == 8
    assert holen(input="text", dimensions=8) == klein  # deterministisch
    assert holen(input="anderer text", dimensions=8)["data"][0]["embedding"] != klein["data"][0]["embedding"]
    zwei = holen(input=["a", "b", "c"], dimensions=4)
    assert [x["index"] for x in zwei["data"]] == [0, 1, 2]
    token = holen(input=[1, 2, 3], dimensions=4)  # ein Token-Array ist eine Eingabe
    assert len(token["data"]) == 1
    u = standard["usage"]
    assert u["total_tokens"] == u["prompt_tokens"]


def test_mock_embeddings_base64(mock):
    # Das openai-SDK fordert standardmäßig base64 an.
    status, _, roh = anfrage(mock.api, "POST", "/v1/embeddings", {"input": "t", "model": "m", "dimensions": 5, "encoding_format": "base64"})
    assert status == 200
    b64 = json.loads(roh)["data"][0]["embedding"]
    zahlen = struct.unpack("<5f", base64.b64decode(b64))
    status, _, roh2 = anfrage(mock.api, "POST", "/v1/embeddings", {"input": "t", "model": "m", "dimensions": 5})
    liste = json.loads(roh2)["data"][0]["embedding"]
    assert [round(z, 5) for z in zahlen] == pytest.approx([round(x, 5) for x in liste], abs=1e-5)


@pytest.mark.parametrize("body", [
    {"model": "m"},
    {"input": [], "model": "m"},
    {"input": "x", "dimensions": 0},
    {"input": "x", "dimensions": 100000},
    {"input": "x", "dimensions": "8"},
    {"input": 5},
])
def test_mock_embeddings_ungueltig_400(mock, body):
    status, _, roh = anfrage(mock.api, "POST", "/v1/embeddings", body)
    assert status == 400
    assert "error" in json.loads(roh)


def test_mock_models(mock):
    status, header, roh = anfrage(mock.api, "GET", "/v1/models")
    assert status == 200 and header["content-type"].startswith("application/json")
    d = json.loads(roh)
    assert d["object"] == "list" and [m["id"] for m in d["data"]] == ["poc-mock"]
    assert d["data"][0]["object"] == "model"


# --------------------------------------------------------------- Pfade und Fehler


def test_mock_v1_ist_optional(mock):
    for pfad in ("/chat/completions", "/v1/chat/completions", "/v1/chat/completions/", "/chat/completions?api-version=1"):
        status, _, roh = anfrage(mock.api, "POST", pfad, {"messages": []})
        assert status == 200, pfad
        assert json.loads(roh)["object"] == "chat.completion"
    for pfad in ("/models", "/v1/models", "/models/"):
        status, _, roh = anfrage(mock.api, "GET", pfad)
        assert status == 200 and json.loads(roh)["data"][0]["id"] == "poc-mock", pfad
    for pfad in ("/embeddings", "/v1/embeddings"):
        status, _, _ = anfrage(mock.api, "POST", pfad, {"input": "x", "dimensions": 2})
        assert status == 200, pfad


def test_mock_v1_normalisierung_verbraucht_gleich(mock):
    setzen(mock, [{"text": "eins"}, {"text": "zwei"}])
    status, _, roh = anfrage(mock.api, "POST", "/chat/completions", {"messages": []})
    assert json.loads(roh)["choices"][0]["message"]["content"] == "eins"
    status, _, roh = anfrage(mock.api, "POST", "/v1/chat/completions", {"messages": []})
    assert json.loads(roh)["choices"][0]["message"]["content"] == "zwei"


def test_mock_unbekannter_pfad_404_mit_protokolleintrag(mock):
    status, header, roh = anfrage(mock.api, "GET", "/v1/gibt-es-nicht?a=1")
    assert status == 404 and header["content-type"].startswith("application/json")
    assert "error" in json.loads(roh)
    status, _, _ = anfrage(mock.api, "POST", "/v2/chat/completions", {"messages": []})
    assert status == 404
    p = protokoll(mock)
    assert [(e["methode"], e["pfad"]) for e in p["eintraege"]] == [("GET", "/v1/gibt-es-nicht?a=1"), ("POST", "/v2/chat/completions")]
    assert [e["nr"] for e in p["eintraege"]] == [1, 2]
    assert p["gekuerzt"] == 0
    assert json.loads(p["eintraege"][1]["body"]) == {"messages": []}


def test_mock_falsche_methode_405_und_protokoll(mock):
    status, _, _ = anfrage(mock.api, "GET", "/v1/chat/completions")
    assert status == 405
    status, _, _ = anfrage(mock.api, "POST", "/v1/models", {})
    assert status == 405
    assert len(protokoll(mock)["eintraege"]) == 2


def test_mock_keine_steuerung_auf_api_port(mock):
    setzen(mock, [{"text": "bleibt"}])
    for methode, pfad, body in [
        ("POST", "/setzen", [{"text": "fremd"}]),
        ("POST", "/v1/setzen", [{"text": "fremd"}]),
        ("POST", "/protokoll", {"werte": []}),
        ("POST", "/v1/protokoll", {"werte": []}),
        ("GET", "/bereit", None),
        ("GET", "/v1/bereit", None),
        ("GET", "/protokoll", None),
        ("GET", "/", None),
    ]:
        status, _, roh = anfrage(mock.api, methode, pfad, body)
        assert status == 404, (methode, pfad)
        assert b"eintraege" not in roh and b"bereit" not in roh.replace(b"error", b"")
    # Die Warteschlange ist unverändert, und die Steuerung hat die Requests auf dem API-Port protokolliert.
    assert chat_json(mock)["choices"][0]["message"]["content"] == "bleibt"
    assert len(protokoll(mock)["eintraege"]) == 9
    # Umgekehrt bedient die Steuerung keine API-Pfade.
    status, _, _ = anfrage(mock.steuer, "POST", "/v1/chat/completions", {"messages": []})
    assert status == 404
    status, _, _ = anfrage(mock.steuer, "GET", "/v1/models")
    assert status == 404
    status, _, _ = anfrage(mock.steuer, "GET", "/bereit")
    assert status == 200


def test_mock_ungueltiger_json_400(mock):
    setzen(mock, [{"text": "bleibt"}])
    for pfad in ("/v1/chat/completions", "/v1/embeddings"):
        for body in ("{kaputt", "", "[1,2]", "null", '"text"', "42"):
            status, header, roh = anfrage(mock.api, "POST", pfad, body)
            assert status == 400, (pfad, body)
            assert header["content-type"].startswith("application/json")
            assert "error" in json.loads(roh)
    # nichts verbraucht, alle Versuche protokolliert
    assert chat_json(mock)["choices"][0]["message"]["content"] == "bleibt"
    assert len(protokoll(mock)["eintraege"]) == 13


def test_mock_zu_grosser_body_413(mock):
    status, _, roh = anfrage(mock.api, "POST", "/v1/chat/completions", b"x" * (1024 * 1024 + 10))
    assert status == 413 and "error" in json.loads(roh)
    p = protokoll(mock)
    assert [e["body"] for e in p["eintraege"]] == [""]  # nie ein halber Body, den die Maskierung nicht kennt
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"  # der Mock lebt weiter


# --------------------------------------------------------------- Protokoll: Ring, Suche, Maskierung, Größe


def test_mock_ring_mit_50_eintraegen(mock):
    for _ in range(60):
        assert anfrage(mock.api, "GET", "/v1/models")[0] == 200
    p = protokoll(mock)
    assert [e["nr"] for e in p["eintraege"]] == list(range(11, 61))
    assert p["gekuerzt"] == 0
    # Die Nummern laufen weiter, auch nach dem Abruf (der Abruf selbst wird nicht protokolliert).
    anfrage(mock.api, "GET", "/v1/models")
    assert protokoll(mock)["eintraege"][-1]["nr"] == 61


def test_mock_protokoll_suche(mock):
    chat_json(mock, "erste POCMARKER-p1-aaaa zeile")
    chat_json(mock, "zweite POCMARKER-p1-bbbb zeile")
    chat_json(mock, "dritte POCMARKER-p1-aaaa zeile")
    p = protokoll(mock, suche="POCMARKER-p1-aaaa")
    assert [e["nr"] for e in p["eintraege"]] == [1, 3]
    assert protokoll(mock, suche="POCMARKER-p1-bbbb")["eintraege"][0]["nr"] == 2
    assert protokoll(mock, suche="POCMARKER-p1-nix")["eintraege"] == []
    assert len(protokoll(mock)["eintraege"]) == 3


def test_mock_suche_arbeitet_auf_dem_maskierten_body(mock):
    wert = "zq7Xk9-geheimer-wert-4711"
    chat_json(mock, f"POCMARKER-p1-m1 {wert}")
    werte = [{"name": "CRM_TOKEN", "wert": wert}]
    assert [e["nr"] for e in protokoll(mock, werte, suche="<ENV:CRM_TOKEN>")["eintraege"]] == [1]
    assert protokoll(mock, werte, suche=wert)["eintraege"] == []  # der Rohwert ist im maskierten Body nicht mehr da
    assert [e["nr"] for e in protokoll(mock, werte, suche="POCMARKER-p1-m1")["eintraege"]] == [1]
    assert [e["nr"] for e in protokoll(mock, [], suche=wert)["eintraege"]] == [1]  # ohne Maskierungswerte steht er da


def test_mock_maskierung_roh_json_und_pfad(mock):
    wert = 'zq7Xk"9\\geheim-4711'  # Anführungszeichen und Backslash: Rohform und JSON-Form unterscheiden sich
    json_form = json.dumps(wert)[1:-1]
    assert json_form != wert
    anfrage(mock.api, "POST", "/v1/nix", f"roh {wert} ende")
    anfrage(mock.api, "POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": wert}]})
    anfrage(mock.api, "GET", "/v1/models?schluessel=zq7Xk")
    e = protokoll(mock, [{"name": "TOKEN", "wert": wert}, {"name": "KURZ", "wert": "zq7Xk"}])["eintraege"]
    ausgabe = json.dumps(e)
    assert wert not in e[0]["body"] and "<ENV:TOKEN>" in e[0]["body"]
    assert json_form not in e[1]["body"] and "<ENV:TOKEN>" in e[1]["body"]
    assert e[2]["pfad"] == "/v1/models?schluessel=<ENV:KURZ>"
    assert "geheim-4711" not in ausgabe


def test_mock_maskierung_nicht_ascii_wert(mock):
    wert = "pä€ss-wört-9"
    # Python-Clients senden JSON standardmäßig mit \uXXXX, andere roh.
    anfrage(mock.api, "POST", "/v1/chat/completions", json.dumps({"messages": [{"content": wert}]}, ensure_ascii=True))
    anfrage(mock.api, "POST", "/v1/chat/completions", json.dumps({"messages": [{"content": wert}]}, ensure_ascii=False))
    ausgabe = protokoll(mock, [{"name": "PW", "wert": wert}])
    for e in ausgabe["eintraege"]:
        assert "<ENV:PW>" in e["body"]
        assert "w\\u00f6rt" not in e["body"].lower() and "wört" not in e["body"] and "wrt" not in e["body"]


def test_mock_maskierung_laengste_zuerst_und_erster_name(mock):
    kurz, lang = "abc123XYZ", "abc123XYZ-lang-0815"
    chat_json(mock, f"a {lang} b {kurz} c")
    werte = [{"name": "KURZ", "wert": kurz}, {"name": "LANG", "wert": lang}, {"name": "ZWEITER", "wert": kurz}, {"name": "LEER", "wert": ""}]
    (e,) = protokoll(mock, werte)["eintraege"]
    assert e["body"].count("<ENV:LANG>") == 1 and e["body"].count("<ENV:KURZ>") == 1
    assert "-lang-0815" not in e["body"] and "abc123" not in e["body"] and "ZWEITER" not in e["body"]


def test_mock_maskierung_ersatztext_wird_nicht_erneut_maskiert(mock):
    chat_json(mock, "x geheim-wert-77 y")
    (e,) = protokoll(mock, [{"name": "A", "wert": "geheim-wert-77"}, {"name": "B", "wert": "ENV:A"}])["eintraege"]
    assert "<ENV:A>" in e["body"] and "<ENV:<ENV" not in e["body"]


@pytest.mark.parametrize("art", ["roh", "json"])
@pytest.mark.parametrize("ueberhang", ["endet_genau", "ragt_hinaus", "beginnt_an_grenze"])
def test_mock_maskierung_vor_kuerzung(mock, art, ueberhang):
    """Ein Wert an der 8-KiB-Grenze darf nie als Bruchstück im Protokoll stehen: erst maskieren, dann kürzen."""
    wert = 'zq7Xk"9\\-geheim-token-4711'
    form = wert if art == "roh" else json.dumps(wert)[1:-1]
    # Position des Werts im Body (ASCII, also Bytes gleich Zeichen)
    kopf = "" if art == "roh" else '{"messages":[{"role":"user","content":"'
    ueber = {"endet_genau": 0, "ragt_hinaus": 5, "beginnt_an_grenze": len(form)}[ueberhang]
    start = BODY_GRENZE - len(form) + ueber
    body = kopf + "a" * (start - len(kopf)) + form + ("bbbb" * 40 if art == "roh" else 'bbbb"}]}')
    assert len(body) > BODY_GRENZE and body.index(form) == start
    pfad = "/v1/nix" if art == "roh" else "/v1/chat/completions"
    anfrage(mock.api, "POST", pfad, body)
    (e,) = protokoll(mock, [{"name": "TOKEN", "wert": wert}])["eintraege"]
    assert len(e["body"].encode("utf-8")) <= BODY_GRENZE
    # kein Bruchstück: weder der Wert noch ein Anfang noch ein Ende davon
    for stueck in ("zq7Xk", "geheim", "token-4711", "4711"):
        assert stueck not in e["body"], stueck
    if ueberhang != "beginnt_an_grenze":
        assert "<ENV:TOKEN>" in e["body"]
    # der Body ist tatsächlich gekürzt (nicht nur maskiert)
    assert e["body"].startswith(kopf + "aaaa") and len(e["body"]) >= BODY_GRENZE - 30


def test_mock_protokoll_hoechstens_64kib(mock):
    # 8 KiB je Body, durch die ASCII-Ausgabe (\uXXXX) wird jeder Eintrag deutlich größer.
    inhalt = "é" * 4000  # 8000 Bytes in UTF-8, 6 Zeichen je Zeichen als é
    for i in range(8):
        anfrage(mock.api, "POST", "/v1/chat/completions", json.dumps({"messages": [{"content": f"{i:02d}" + inhalt}]}, ensure_ascii=False))
    r = cli("--protokoll", mock.steuer, json.dumps({"werte": []}))
    assert r.returncode == 0 and r.stderr == b""
    assert r.stdout.isascii()
    assert len(r.stdout.rstrip(b"\n")) <= 65536
    p = json.loads(r.stdout)
    assert p["gekuerzt"] > 0 and p["gekuerzt"] + len(p["eintraege"]) == 8
    # die ältesten werden weggelassen: die verbleibenden sind die neuesten, lückenlos
    nrs = [e["nr"] for e in p["eintraege"]]
    assert nrs == list(range(8 - len(nrs) + 1, 9))
    assert p["eintraege"][-1]["body"].count("é") > 0 and "\\u00e9" not in p["eintraege"][-1]["body"]  # der Body ist Text, nur die Ausgabe ASCII


def test_mock_protokoll_ist_ascii_und_gueltiges_json(mock):
    anfrage(mock.api, "POST", "/v1/chat/completions", json.dumps({"messages": [{"content": "ä ö ü € 😀 \u007f"}]}, ensure_ascii=False))
    r = cli("--protokoll", mock.steuer, json.dumps({"werte": []}))
    assert r.stdout.isascii() and b"\\u00e4" in r.stdout
    assert json.loads(r.stdout)["eintraege"][0]["body"].count("😀") == 1


# --------------------------------------------------------------- CLI: Exit-Codes, kein Echo von Werten


@pytest.mark.parametrize("args", [
    [],
    ["--server", "--bereit"],
    ["--setzen", "--protokoll"],
    ["--unbekannt"],
    ["--server", "--port", "abc"],
    ["--server", "--port", "70000"],
    ["--server", "--steuer-port", "-1"],
    ["--bereit", "--port", "1"],
    ["--bereit", "--steuer-port", "0"],
    ["--setzen", "--suche", "m"],
    ["--protokoll", "--suche", ""],
    ["--bereit", "--host", "127.0.0.1"],
    ["--bereit", "extra"],
])
def test_mock_cli_ungueltige_argumente_exit2(args):
    r = subprocess.run([NODE, MOCK, *args], input=b"", capture_output=True, timeout=20)
    assert r.returncode == 2, (args, r.stderr)
    assert r.stdout == b""


@pytest.mark.parametrize("modus,eingabe", [
    ("--setzen", "kein json"),
    ("--setzen", "{}"),
    ("--setzen", '[{"text": 1}]'),
    ("--setzen", '[{"text": "a", "werkzeug": {"name": "x"}}]'),
    ("--setzen", '[{}]'),
    ("--setzen", '[{"werkzeug": {"name": "mit leerzeichen"}}]'),
    ("--setzen", '[{"werkzeug": {"name": "x", "argumente": [1]}}]'),
    ("--setzen", '[{"text": "a", "wenn_enthaelt": ""}]'),
    ("--setzen", '[{"text": "a", "unbekannt": 1}]'),
    ("--setzen", "[" + ",".join(['{"text":"a"}'] * 101) + "]"),
    ("--protokoll", "kein json"),
    ("--protokoll", "[]"),
    ("--protokoll", '{"werte": "x"}'),
    ("--protokoll", '{"werte": [{"name": "a b", "wert": "geheim-wert-123"}]}'),
    ("--protokoll", '{"werte": [{"name": "A", "wert": 5}]}'),
    ("--protokoll", '{"werte": [{"name": "A", "wert": "geheim-wert-123", "x": 1}]}'),
])
def test_mock_cli_ungueltiger_stdin_exit2_ohne_echo(mock, modus, eingabe):
    r = cli(modus, mock.steuer, eingabe)
    assert r.returncode == 2, r.stderr
    assert r.stdout == b""
    assert b"geheim-wert-123" not in r.stderr and eingabe.encode()[:12] not in r.stderr.replace(b"stdin", b"")


def test_mock_cli_stdin_zu_gross_exit2(mock):
    r = cli("--setzen", mock.steuer, b"[" + b" " * 70000 + b"]")
    assert r.returncode == 2


def test_mock_cli_ohne_server_exit1():
    port = freier_port()
    r = cli("--bereit", port)
    assert (r.returncode, r.stdout, r.stderr) == (1, b"", b"")
    r = cli("--setzen", port, "[]")
    assert r.returncode == 1 and r.stdout == b""
    r = cli("--protokoll", port, '{"werte": []}')
    assert r.returncode == 1 and r.stdout == b""


def test_mock_cli_port_belegt_exit1(mock):
    r = subprocess.run([NODE, MOCK, "--server", "--host", "127.0.0.1", "--port", str(mock.api), "--steuer-port", "0"], input=b"", capture_output=True, timeout=20)
    assert r.returncode == 1 and r.stdout == b""


def test_mock_cli_werte_erscheinen_nie_auf_stderr_oder_stdout(mock):
    wert = "zq7Xk9-geheimer-wert-4711"
    chat_json(mock, wert)
    r = cli("--protokoll", mock.steuer, json.dumps({"werte": [{"name": "T", "wert": wert}]}))
    assert r.returncode == 0 and wert.encode() not in r.stdout + r.stderr and b"<ENV:T>" in r.stdout
    mock.beenden()
    out, err = mock.rest()
    assert wert.encode() not in out + err
