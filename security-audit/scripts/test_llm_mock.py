"""Tests für docker/llm-mock.mjs (Modell-Mock: Chat Completions, Responses, Messages, Embeddings, Models, Steuerung).

Aufruf: python3 -m pytest security-audit/scripts/test_llm_mock.py -q
Der Mock läuft lokal mit Node auf 127.0.0.1 (Port 0, Ports aus der bereit-Zeile) als eigene Prozessgruppe
(`start_new_session=True`). Beendet wird nur diese Gruppe, und nur solange der eigene Popen noch läuft.
Requests gehen per `http.client` ausschließlich an 127.0.0.1.
Ab "SDK-Vertragstest" laufen die echten SDKs (Node >= 22, Opt-in `SECURITY_AUDIT_SDK_VERTRAG=1`) gegen den Mock, mit Wächter
und Umgebungs-Whitelist; `npm ci` ist dort die einzige Netzaktion (nur die npm-Registry).
"""
import base64
import http.client
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HIER)
MOCK = os.path.join(SKILL, "docker", "llm-mock.mjs")
NODE = shutil.which("node")

# Ohne node entfallen alle Tests außer diesen (reine Dateiprüfungen des SDK-Vertragstests, siehe unten).
OHNE_NODE = {"test_vertrag_umgebung_ohne_fremde_variablen", "test_sdk_vertrag_lockfile_nur_registry",
             "test_sdk_vertrag_dateien_ohne_modell_api_hosts"}


@pytest.fixture(autouse=True)
def _node_noetig(request):
    if NODE is None and request.node.originalname not in OHNE_NODE:
        pytest.skip("node fehlt")

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
    assert len(r.stdout) <= 65536  # einschließlich des abschließenden Zeilenumbruchs
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


ERLAUBTE_IMPORTE = {"node:http", "node:crypto", "node:util"}


def funktionsrumpf(quelle, name):
    """Quelltext der Funktion `name` (von `function name(` bis zur schließenden Klammer in Spalte 0)."""
    m = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", quelle, re.M | re.S)
    assert m, name
    return m.group(0)


def test_mock_nur_node_builtins():
    quelle = open(MOCK, encoding="utf-8").read()
    importe = re.findall(r"^import\b.*?from\s+\"([^\"]+)\"", quelle, re.M)
    assert set(importe) == ERLAUBTE_IMPORTE and len(importe) == len(ERLAUBTE_IMPORTE), importe
    assert "require(" not in quelle and "import(" not in quelle
    assert "experimental" not in quelle.split("\n", 1)[0].lower()


def test_mock_keine_ausgehenden_requests_ausser_steuerclient():
    quelle = open(MOCK, encoding="utf-8").read()
    steuer = funktionsrumpf(quelle, "steuerAnfrage")
    rest = quelle.replace(steuer, "")
    # Der Quelltext ohne Kommentarzeilen: ausgehender Verkehr gibt es nur im Steuerclient, und der geht an 127.0.0.1.
    code = "\n".join(z for z in rest.split("\n") if not z.lstrip().startswith("//"))
    for muster in (r"\bfetch\s*\(", r"\bhttp\.request\b", r"\bhttp\.get\b", r"\bhttps\b", r"\bnet\.connect\b",
                   r"\bnew\s+WebSocket\b", r"\bXMLHttpRequest\b", r"\bchild_process\b"):
        assert not re.search(muster, code), muster
    assert "http.request(" in steuer and 'host: "127.0.0.1"' in steuer
    assert "fetch(" not in steuer and "http.get" not in steuer
    assert re.findall(r"\b(?:host|hostname)\s*:\s*([^,}]+)", steuer) == ['"127.0.0.1"']


def test_mock_bereit_zeile_nur_bei_port_0_nicht_bei_festen_ports():
    """Mit festen Ports (ungleich 0) erscheint nie eine bereit-Zeile auf stdout (die Prüfung läuft per --bereit)."""
    letzter_fehler = None
    for _ in range(4):  # freie Ports aus einem Bind sind racy: bei Kollision neu versuchen
        api, steuer = freier_port(), freier_port()
        if api == steuer:
            continue
        p = subprocess.Popen([NODE, MOCK, "--server", "--host", "127.0.0.1", "--port", str(api), "--steuer-port", str(steuer)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            bereit = False
            for _ in range(100):
                if p.poll() is not None:
                    break
                if cli("--bereit", steuer).returncode == 0:
                    bereit = True
                    break
                time.sleep(0.1)
            if not bereit:
                letzter_fehler = p.stderr.read() if p.poll() is not None else b"nicht bereit"
                continue
            time.sleep(0.3)  # eine verspätete bereit-Zeile hätte jetzt Zeit zu erscheinen
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)  # nur die eigene Gruppe
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=5)
        assert p.stdout.read() == b"" and p.stderr.read() == b""
        return
    pytest.fail(f"Mock mit festen Ports nicht gestartet: {letzter_fehler!r}")


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


def strom_senden(port, pfad, grenze=64 * 1024 * 1024, frist=10):
    """Sendet einen chunked-Body ohne Ende (bis `grenze` Bytes oder `frist` Sekunden) und liest nebenbei die Antwort.
    Gibt (gesendet, Antwort-Bytes, Verbindung_vom_Server_beendet) zurück."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(f"POST {pfad} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".encode())
    stueck = b"10000\r\n" + b"x" * 65536 + b"\r\n"
    gesendet, antwort, beendet = 0, b"", False
    ende = time.monotonic() + frist
    s.settimeout(0.2)
    try:
        while time.monotonic() < ende and gesendet < grenze and not beendet:
            try:
                s.sendall(stueck)
                gesendet += 65536
            except (BrokenPipeError, ConnectionResetError):
                beendet = True
            except socket.timeout:
                pass
            if select.select([s], [], [], 0)[0]:
                try:
                    teil = s.recv(65536)
                except ConnectionResetError:
                    beendet = True
                    break
                if not teil:
                    beendet = True
                else:
                    antwort += teil
            if b"\r\n\r\n" in antwort and not beendet:
                # Antwort da: noch kurz warten, ob der Server die Verbindung beendet
                s.settimeout(1)
                try:
                    while True:
                        teil = s.recv(65536)
                        if not teil:
                            beendet = True
                            break
                        antwort += teil
                except (socket.timeout, ConnectionResetError, OSError) as e:
                    beendet = beendet or isinstance(e, ConnectionResetError)
                break
    finally:
        s.close()
    return gesendet, antwort, beendet


def test_mock_zu_grosser_body_413_sofort_und_verbindung_wird_beendet(mock):
    """Der Mock liest einen zu großen Body nicht bis zum Ende, sondern antwortet sofort und schließt (Review Mi-5)."""
    gesendet, antwort, beendet = strom_senden(mock.api, "/v1/chat/completions")
    kopf = antwort.split(b"\r\n\r\n", 1)[0].lower()
    assert antwort.startswith(b"HTTP/1.1 413"), (gesendet, antwort[:200])
    assert b"connection: close" in kopf
    assert gesendet < 8 * 1024 * 1024, gesendet  # nach gut 1 MiB ist Schluss, nicht erst nach dem Strom
    assert beendet
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"  # der Mock lebt weiter


def test_mock_begrenzt_verbindungen_und_hat_kurze_zeitgrenzen(mock):
    """`maxConnections` auf beiden Listenern: Verbindungen über der Grenze werden sofort geschlossen (Review Mi-5)."""
    quelle = open(MOCK, encoding="utf-8").read()
    # Zeitgrenzen (ein Verhaltenstest bräuchte 30 s Wartezeit): beide Listener setzen sie auf einen Wert von höchstens 30 s.
    assert re.search(r"server\.requestTimeout\s*=\s*ZEITGRENZE_MS\b", quelle) and re.search(r"server\.headersTimeout\s*=\s*ZEITGRENZE_MS\b", quelle)
    (zeit,) = re.findall(r"^const ZEITGRENZE_MS\s*=\s*([\d_]+);", quelle, re.M)
    assert 0 < int(zeit.replace("_", "")) <= 30_000
    for port in (mock.api, mock.steuer):
        offen = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(90)]
        try:
            time.sleep(0.3)  # der Server hat alle Verbindungen angenommen und die überzähligen geschlossen
            lesbar = select.select(offen, [], [], 0.5)[0]  # lesbar: geschlossen (EOF) oder Fehler, nie Daten
            geschlossen = 0
            for s in lesbar:
                try:
                    geschlossen += s.recv(1) == b""
                except OSError:
                    geschlossen += 1
            assert 90 - 64 - 2 <= geschlossen <= 90 - 64 + 2, geschlossen
        finally:
            for s in offen:
                s.close()
        time.sleep(0.3)
    assert chat_json(mock)["choices"][0]["message"]["content"] == "ok"


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


def test_mock_maskierung_doppelt_escapte_form(mock):
    """Tool-Ergebnisse stehen als JSON-String in einem JSON-String: der Wert ist doppelt escapt (Review Mi-1)."""
    wert = 'ab"cd\\ef\nXYZ-geheim-77'
    innen = json.dumps({"k": wert})  # Tool-Ergebnis als JSON-Text
    body = json.dumps({"messages": [{"role": "tool", "content": innen}]})
    assert json.dumps(json.dumps(wert)[1:-1])[1:-1] in body  # der Body enthält die doppelt escapte Form
    anfrage(mock.api, "POST", "/v1/chat/completions", body)
    (e,) = protokoll(mock, [{"name": "SECRET", "wert": wert}])["eintraege"]
    assert "<ENV:SECRET>" in e["body"]
    for stueck in ("XYZ-geheim-77", "geheim", "ab\\\"cd", "XYZ"):
        assert stueck not in e["body"], stueck
    # auch mit der Suche arbeitet der Mock auf dem maskierten Body
    (f,) = protokoll(mock, [{"name": "SECRET", "wert": wert}], suche="tool")["eintraege"]
    assert "geheim" not in f["fundstelle"] and "<ENV:SECRET>" in f["fundstelle"]


def test_mock_maskierung_doppelt_escapt_nicht_ascii_und_pem(mock):
    wert = "-----BEGIN KEY-----\nMIIä€x9\n-----END KEY-----"
    innen = json.dumps({"k": wert}, ensure_ascii=False)
    for ascii_ in (True, False):
        anfrage(mock.api, "POST", "/v1/chat/completions", json.dumps({"messages": [{"role": "tool", "content": innen}]}, ensure_ascii=ascii_))
    for e in protokoll(mock, [{"name": "KEY", "wert": wert}])["eintraege"]:
        assert "<ENV:KEY>" in e["body"] and "MII" not in e["body"] and "BEGIN KEY" not in e["body"]


def test_mock_pfad_wird_erst_maskiert_dann_gekuerzt(mock):
    """Ein langer Wert im Pfad, der über die frühere Vorab-Kürzung (2048) hinausragt, steht nie als Bruchstück da (Review Mi-2)."""
    wert = "".join(chr(97 + (i * 7 + i // 3) % 26) for i in range(1700))
    pfad = "/v1/nix?" + "a" * 392 + wert + "b" * 200  # der Wert beginnt bei 400 und endet hinter 2048
    assert pfad.index(wert) == 400 and len(pfad) > 2048 + 100
    anfrage(mock.api, "GET", pfad)
    (e,) = protokoll(mock, [{"name": "TOKEN", "wert": wert}])["eintraege"]
    assert len(e["pfad"]) <= 512
    assert e["pfad"].startswith("/v1/nix?aaaa") and "<ENV:TOKEN>" in e["pfad"]
    assert wert[:20] not in e["pfad"] and wert[:20] not in json.dumps(e)


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
    assert len(r.stdout) <= 65536
    p = json.loads(r.stdout)
    assert p["gekuerzt"] > 0 and p["gekuerzt"] + len(p["eintraege"]) == 8
    # die ältesten werden weggelassen: die verbleibenden sind die neuesten, lückenlos
    nrs = [e["nr"] for e in p["eintraege"]]
    assert nrs == list(range(8 - len(nrs) + 1, 9))
    assert p["eintraege"][-1]["body"].count("é") > 0 and "\\u00e9" not in p["eintraege"][-1]["body"]  # der Body ist Text, nur die Ausgabe ASCII


def test_mock_protokoll_genau_an_der_grenze_einschliesslich_zeilenumbruch():
    """Die Ausgabe (mit Zeilenumbruch) ist höchstens 65 536 Bytes, auch wenn das JSON allein genau 65 536 Bytes hätte (Review Mi-6)."""
    def fuellen(m, letzter):
        for _ in range(7):
            anfrage(m.api, "POST", "/v1/nix", "a" * BODY_GRENZE)
        anfrage(m.api, "POST", "/v1/nix", "a" * letzter)

    m = Mock()
    try:
        fuellen(m, 0)
        laenge = len(cli("--protokoll", m.steuer, json.dumps({"werte": []})).stdout.rstrip(b"\n"))
    finally:
        m.beenden()
    letzter = 65536 - laenge
    assert 0 < letzter <= BODY_GRENZE
    m = Mock()
    try:
        fuellen(m, letzter)
        r = cli("--protokoll", m.steuer, json.dumps({"werte": []}))
    finally:
        m.beenden()
    assert r.returncode == 0 and r.stdout.endswith(b"\n")
    assert len(r.stdout) <= 65536, len(r.stdout)
    p = json.loads(r.stdout)
    assert p["gekuerzt"] + len(p["eintraege"]) == 8


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


# --------------------------------------------------------------- Responses und Messages (3b)

STREAM = pytest.mark.parametrize("stream", [False, True], ids=["nicht_streamend", "streamend"])


def sse_ereignisse(roh):
    """Parst einen SSE-Strom mit `event:`- und `data:`-Zeilen. Gibt [(event, daten-dict)] zurück.

    Das Format ist streng: je Block genau eine event-Zeile und eine data-Zeile, getrennt durch eine Leerzeile.
    Der Event-Name muss dem `type` im JSON entsprechen (beide SDKs lesen je eines davon).
    """
    text = roh.decode("utf-8")
    assert text.endswith("\n\n"), "Strom endet nicht mit einer Leerzeile"
    ereignisse = []
    for block in text[:-2].split("\n\n"):
        zeilen = block.split("\n")
        assert len(zeilen) == 2, block
        assert zeilen[0].startswith("event: ") and zeilen[1].startswith("data: "), block
        name, daten = zeilen[0][len("event: "):], json.loads(zeilen[1][len("data: "):])
        assert daten["type"] == name, (name, daten["type"])
        ereignisse.append((name, daten))
    return ereignisse


def responses_aufruf(m, inhalt="hallo", stream=False, pfad="/v1/responses", **extra):
    """Gibt (Antwortobjekt, Ereignisliste oder None) zurück. Im Stream ist das Objekt das aus `response.completed`."""
    body = {"model": "x", "input": inhalt, "stream": stream, **extra}
    status, header, roh = anfrage(m.api, "POST", pfad, body)
    assert status == 200, roh
    if not stream:
        assert header["content-type"].startswith("application/json")
        return json.loads(roh), None
    assert header["content-type"].startswith("text/event-stream")
    ereignisse = sse_ereignisse(roh)
    assert ereignisse[-1][0] == "response.completed"
    return ereignisse[-1][1]["response"], ereignisse


def messages_aufruf(m, inhalt="hallo", stream=False, pfad="/v1/messages", **extra):
    body = {"model": "x", "max_tokens": 64, "messages": [{"role": "user", "content": inhalt}], "stream": stream, **extra}
    status, header, roh = anfrage(m.api, "POST", pfad, body, {"x-api-key": "k", "anthropic-version": "2023-06-01"})
    assert status == 200, roh
    if not stream:
        assert header["content-type"].startswith("application/json")
        return json.loads(roh), None
    assert header["content-type"].startswith("text/event-stream")
    return None, sse_ereignisse(roh)


def daten_logprobs(ereignisse):
    """Die API sendet `logprobs: []` an Text-Delta und -Done; das AI SDK liest das Feld."""
    return all(d.get("logprobs") == [] for n, d in ereignisse if n in ("response.output_text.delta", "response.output_text.done"))


def usage_responses_pruefen(u):
    assert u["input_tokens"] >= 1 and u["output_tokens"] >= 1
    assert u["total_tokens"] == u["input_tokens"] + u["output_tokens"]
    assert u["input_tokens_details"]["cached_tokens"] == 0
    assert u["output_tokens_details"]["reasoning_tokens"] == 0


def response_rahmen_pruefen(r, status):
    assert r["object"] == "response" and r["id"].startswith("resp_") and isinstance(r["created_at"], int)
    assert r["status"] == status and r["model"] == "poc-mock"  # kein Echo des Request-Modells
    assert r["error"] is None and r["incomplete_details"] is None
    assert isinstance(r["output"], list)


@STREAM
def test_mock_responses_text_und_tool(mock, stream):
    text = "Dies ist eine längere Antwort mit mehreren Stücken."
    argumente = {"pfad": "/etc; echo poc", "tiefe": 2, "liste": ["a", "b"]}
    setzen(mock, [{"text": text}, {"werkzeug": {"name": "tool_r", "argumente": argumente}}])

    # --- Text
    r, ereignisse = responses_aufruf(mock, "frage", stream, model="irgendein-modell-xyz")
    response_rahmen_pruefen(r, "completed")
    usage_responses_pruefen(r["usage"])
    (item,) = r["output"]
    assert item["type"] == "message" and item["id"].startswith("msg_") and item["status"] == "completed"
    assert item["role"] == "assistant"
    assert item["content"] == [{"type": "output_text", "text": text, "annotations": []}]
    if stream:
        namen = [n for n, _ in ereignisse]
        assert namen[:3] == ["response.created", "response.output_item.added", "response.content_part.added"]
        assert namen[-4:] == ["response.output_text.done", "response.content_part.done", "response.output_item.done", "response.completed"]
        deltas = [d for n, d in ereignisse if n == "response.output_text.delta"]
        assert len(deltas) >= 3 and set(namen[3:-4]) == {"response.output_text.delta"}
        assert "".join(d["delta"] for d in deltas) == text
        assert all(d["logprobs"] == [] for d in deltas) and daten_logprobs(ereignisse)
        daten = dict(ereignisse)
        angelegt = daten["response.created"]["response"]
        response_rahmen_pruefen(angelegt, "in_progress")
        assert angelegt["output"] == [] and angelegt["id"] == r["id"]
        hinzu = daten["response.output_item.added"]
        assert hinzu["output_index"] == 0 and hinzu["item"]["id"] == item["id"] and hinzu["item"]["status"] == "in_progress"
        assert hinzu["item"]["type"] == "message" and hinzu["item"]["content"] == []
        teil = daten["response.content_part.added"]
        assert teil["part"] == {"type": "output_text", "text": "", "annotations": []}
        for n, d in ereignisse:
            if n.startswith("response.output_text.") or n.startswith("response.content_part."):
                assert (d["item_id"], d["output_index"], d["content_index"]) == (item["id"], 0, 0), n
        assert daten["response.output_text.done"]["text"] == text
        assert daten["response.content_part.done"]["part"] == item["content"][0]
        assert daten["response.output_item.done"]["item"] == item and daten["response.output_item.done"]["output_index"] == 0

    # --- Tool
    r, ereignisse = responses_aufruf(mock, "frage", stream)
    response_rahmen_pruefen(r, "completed")
    usage_responses_pruefen(r["usage"])
    (item,) = r["output"]
    assert item["type"] == "function_call" and item["id"].startswith("fc_") and item["status"] == "completed"
    assert item["call_id"].startswith("call_") and item["name"] == "tool_r"
    assert isinstance(item["arguments"], str) and json.loads(item["arguments"]) == argumente
    if stream:
        namen = [n for n, _ in ereignisse]
        assert namen[:2] == ["response.created", "response.output_item.added"]
        assert namen[-3:] == ["response.function_call_arguments.done", "response.output_item.done", "response.completed"]
        deltas = [d for n, d in ereignisse if n == "response.function_call_arguments.delta"]
        assert len(deltas) >= 3 and set(namen[2:-3]) == {"response.function_call_arguments.delta"}
        assert "".join(d["delta"] for d in deltas) == item["arguments"]
        daten = dict(ereignisse)
        hinzu = daten["response.output_item.added"]
        assert hinzu["output_index"] == 0 and hinzu["item"]["type"] == "function_call" and hinzu["item"]["status"] == "in_progress"
        assert (hinzu["item"]["id"], hinzu["item"]["call_id"], hinzu["item"]["name"], hinzu["item"]["arguments"]) == (item["id"], item["call_id"], "tool_r", "")
        for n, d in ereignisse:
            if n.startswith("response.function_call_arguments."):
                assert (d["item_id"], d["output_index"]) == (item["id"], 0), n
        assert daten["response.function_call_arguments.done"]["arguments"] == item["arguments"]
        assert daten["response.output_item.done"]["item"] == item
        assert "response.content_part.added" not in namen

    if stream:
        # sequence_number an jedem Event, streng monoton und lückenlos ab 0 (auch im zweiten Strom)
        assert [d["sequence_number"] for _, d in ereignisse] == list(range(len(ereignisse)))


@STREAM
def test_mock_responses_ohne_v1_und_ohne_passenden_eintrag(mock, stream):
    r, _ = responses_aufruf(mock, "x", stream, pfad="/responses")
    assert r["output"][0]["content"][0]["text"] == "ok"
    r, _ = responses_aufruf(mock, "x", stream, pfad="/v1/responses/")
    assert r["output"][0]["content"][0]["text"] == "ok"


@STREAM
def test_mock_messages_text_und_tool(mock, stream):
    text = "Dies ist eine längere Antwort mit mehreren Stücken."
    argumente = {"pfad": "/etc; echo poc", "tiefe": 2, "liste": ["a", "b"]}
    setzen(mock, [{"text": text}, {"werkzeug": {"name": "tool_m", "argumente": argumente}}])

    def zusammenbauen(ereignisse):
        """Setzt aus dem Strom die Nachricht zusammen, so wie es das Anthropic-SDK tut."""
        namen = [n for n, _ in ereignisse]
        assert namen[0] == "message_start" and namen[-2:] == ["message_delta", "message_stop"]
        start = ereignisse[0][1]["message"]
        assert start["content"] == [] and start["role"] == "assistant" and start["type"] == "message"
        assert start["stop_reason"] is None and start["stop_sequence"] is None and start["model"] == "poc-mock"
        assert start["usage"]["input_tokens"] >= 1 and "output_tokens" in start["usage"]
        bloecke = {}
        offen = None
        for n, d in ereignisse[1:-2]:
            if n == "content_block_start":
                assert offen is None and d["index"] == len(bloecke)
                offen = d["index"]
                bloecke[offen] = {"start": d["content_block"], "teile": []}
            elif n == "content_block_delta":
                assert offen == d["index"]
                bloecke[offen]["teile"].append(d["delta"])
            else:
                assert n == "content_block_stop" and offen == d["index"]
                offen = None
        assert offen is None
        ende = ereignisse[-2][1]
        return start, bloecke, ende

    # --- Text
    d, ereignisse = messages_aufruf(mock, "frage", stream, model="irgendein-modell-xyz")
    if stream:
        start, bloecke, ende = zusammenbauen(ereignisse)
        assert [n for n, _ in ereignisse][1] == "content_block_start" and len(bloecke) == 1
        assert bloecke[0]["start"] == {"type": "text", "text": ""}
        assert len(bloecke[0]["teile"]) >= 3 and all(t["type"] == "text_delta" for t in bloecke[0]["teile"])
        assert "".join(t["text"] for t in bloecke[0]["teile"]) == text
        assert ende["delta"] == {"stop_reason": "end_turn", "stop_sequence": None} and ende["usage"]["output_tokens"] >= 1
        assert [n for n, _ in ereignisse][-3] == "content_block_stop"
        assert start["id"].startswith("msg_")
    else:
        assert d["type"] == "message" and d["role"] == "assistant" and d["id"].startswith("msg_")
        assert d["model"] == "poc-mock"
        assert d["content"] == [{"type": "text", "text": text}]
        assert d["stop_reason"] == "end_turn" and d["stop_sequence"] is None
        assert d["usage"]["input_tokens"] >= 1 and d["usage"]["output_tokens"] >= 1

    # --- Tool
    d, ereignisse = messages_aufruf(mock, "frage", stream)
    if stream:
        start, bloecke, ende = zusammenbauen(ereignisse)
        assert len(bloecke) == 1
        kopf = bloecke[0]["start"]
        assert kopf["type"] == "tool_use" and kopf["id"].startswith("toolu_") and kopf["name"] == "tool_m" and kopf["input"] == {}
        assert len(bloecke[0]["teile"]) >= 3 and all(t["type"] == "input_json_delta" for t in bloecke[0]["teile"])
        assert json.loads("".join(t["partial_json"] for t in bloecke[0]["teile"])) == argumente
        assert ende["delta"] == {"stop_reason": "tool_use", "stop_sequence": None} and ende["usage"]["output_tokens"] >= 1
    else:
        assert d["type"] == "message" and d["role"] == "assistant" and d["model"] == "poc-mock"
        (block,) = d["content"]
        assert block["type"] == "tool_use" and block["id"].startswith("toolu_") and block["name"] == "tool_m"
        assert block["input"] == argumente  # Objekt, kein String
        assert d["stop_reason"] == "tool_use" and d["stop_sequence"] is None
        assert d["usage"]["output_tokens"] >= 1


@STREAM
def test_mock_messages_ohne_v1(mock, stream):
    setzen(mock, [{"text": "eins"}, {"text": "zwei"}, {"text": "drei"}])

    def text(d, ereignisse):
        if not stream:
            return d["content"][0]["text"]
        return "".join(x["delta"]["text"] for n, x in ereignisse if n == "content_block_delta")

    assert text(*messages_aufruf(mock, "x", stream, pfad="/messages")) == "eins"
    assert text(*messages_aufruf(mock, "x", stream, pfad="/v1/messages")) == "zwei"
    assert text(*messages_aufruf(mock, "x", stream, pfad="/messages/")) == "drei"  # ein abschließendes „/“ ist egal
    assert [e["pfad"] for e in protokoll(mock)["eintraege"]] == ["/messages", "/v1/messages", "/messages/"]


def test_mock_responses_messages_falsche_methode_und_ungueltiger_body(mock):
    for pfad in ("/v1/responses", "/v1/messages", "/messages"):
        assert anfrage(mock.api, "GET", pfad)[0] == 405
        assert anfrage(mock.api, "POST", pfad, "{kaputt")[0] == 400
        assert anfrage(mock.api, "POST", pfad, "[1]")[0] == 400
    assert len(protokoll(mock)["eintraege"]) == 9


def test_mock_wenn_enthaelt_gilt_fuer_responses_und_messages_streamend(mock):
    setzen(mock, [
        {"text": "nur-responses", "wenn_enthaelt": "POCMARKER-p3-resp"},
        {"werkzeug": {"name": "nur_messages", "argumente": {"a": 1}}, "wenn_enthaelt": "POCMARKER-p3-msgs"},
        {"text": "ohne-marker"},
    ])
    # ohne Marker bekommt der Request den ersten Eintrag ohne Marker, danach „ok“
    r, _ = responses_aufruf(mock, "ohne", True)
    assert r["output"][0]["content"][0]["text"] == "ohne-marker"
    r, _ = responses_aufruf(mock, "ohne", True)
    assert r["output"][0]["content"][0]["text"] == "ok"
    # der Marker im Body (hier in der Eingabe) findet seinen Eintrag, auch streamend; ein fremder Marker nicht
    _, ereignisse = messages_aufruf(mock, "POCMARKER-p3-fremd", True)
    assert "".join(x["delta"]["text"] for n, x in ereignisse if n == "content_block_delta") == "ok"
    r, ereignisse = responses_aufruf(mock, "POCMARKER-p3-resp", True)
    assert r["output"][0]["content"][0]["text"] == "nur-responses"
    assert [n for n, _ in ereignisse].count("response.output_text.delta") >= 1
    r, _ = responses_aufruf(mock, "POCMARKER-p3-resp", False)
    assert r["output"][0]["content"][0]["text"] == "ok"  # verbraucht
    _, ereignisse = messages_aufruf(mock, "mit POCMARKER-p3-msgs", True)
    kopf = ereignisse[1][1]["content_block"]
    assert kopf["type"] == "tool_use" and kopf["name"] == "nur_messages"
    d, _ = messages_aufruf(mock, "POCMARKER-p3-msgs", False)
    assert d["content"] == [{"type": "text", "text": "ok"}]  # verbraucht

    # nicht streamend: derselbe Mechanismus über die Formate hinweg
    setzen(mock, [{"text": "m", "wenn_enthaelt": "POCMARKER-p3-nstr"}])
    d, _ = messages_aufruf(mock, "ohne", False)
    assert d["content"][0]["text"] == "ok"
    d, _ = messages_aufruf(mock, "POCMARKER-p3-nstr", False)
    assert d["content"][0]["text"] == "m"


def test_mock_tool_ids_eindeutig_ueber_alle_formate(mock):
    setzen(mock, [{"werkzeug": {"name": "t", "argumente": {}}} for _ in range(14)])
    ids = []
    for stream in (False, False, True, True):
        r, _ = responses_aufruf(mock, "x", stream)
        (item,) = r["output"]
        ids += [item["id"], item["call_id"]]
        d, ereignisse = messages_aufruf(mock, "x", stream)
        ids.append(d["content"][0]["id"] if not stream else ereignisse[1][1]["content_block"]["id"])
    for _ in range(2):
        ids.append(chat_json(mock)["choices"][0]["message"]["tool_calls"][0]["id"])
    assert len(ids) == 14 and len(set(ids)) == 14
    # Antwort-IDs (resp_, msg_) sind ebenfalls je Aufruf eindeutig
    setzen(mock, [])
    antworten = [responses_aufruf(mock, "x", False)[0]["id"] for _ in range(3)]
    antworten += [messages_aufruf(mock, "x", False)[0]["id"] for _ in range(3)]
    assert len(set(antworten)) == 6


def test_mock_responses_messages_kein_echo_und_protokoll(mock):
    geheim = "GEHEIM-ECHO-4712"
    for stream in (False, True):
        for pfad, bau in (("/v1/responses", {"model": geheim, "input": geheim}), ("/v1/messages", {"model": geheim, "max_tokens": 5, "messages": [{"role": "user", "content": geheim}]})):
            status, _, roh = anfrage(mock.api, "POST", pfad, {**bau, "stream": stream, "instructions": geheim})
            assert status == 200 and geheim.encode() not in roh
    p = protokoll(mock, suche=geheim)
    assert [e["pfad"] for e in p["eintraege"]] == ["/v1/responses", "/v1/messages"] * 2
    mock.beenden()
    out, err = mock.rest()
    assert out == b"" and err == b""


# --------------------------------------------------------------- Fundstelle bei --suche


def test_mock_suche_fundstelle_hinter_kuerzung(mock):
    marker = "POCMARKER-p1-fund"
    body = "a" * (BODY_GRENZE + 1000) + f" davor {marker} danach " + "b" * 500
    anfrage(mock.api, "POST", "/v1/nix", body)
    (e,) = protokoll(mock, suche=marker)["eintraege"]
    assert marker not in e["body"] and len(e["body"].encode()) <= BODY_GRENZE  # der Marker liegt hinter der Kürzung
    f = e["fundstelle"]
    assert marker in f and " davor " in f and " danach " in f
    assert len(f) <= 300 and "\n" not in f and "\r" not in f
    # der Ausschnitt stammt wirklich aus dem Body: zusammenhängend und um den Marker
    assert body.index(f) < body.index(marker) < body.index(f) + len(f)


def test_mock_suche_fundstelle_einzeilig_und_maskiert(mock):
    marker = "POCMARKER-p1-zeile"
    wert = "zq7Xk9-geheimer-wert-4711"
    anfrage(mock.api, "POST", "/v1/nix", f"kopf\nzeile eins\r\nzeile zwei {marker} {wert}\n ende\n")
    (e,) = protokoll(mock, [{"name": "CRM_TOKEN", "wert": wert}], suche=marker)["eintraege"]
    f = e["fundstelle"]
    assert re.search(r"[\r\n  ]", f) is None
    assert f.startswith("kopf zeile eins") and f"{marker} <ENV:CRM_TOKEN>" in f  # Zeilenumbrüche werden zu Leerzeichen, Wert maskiert
    assert wert not in f


def test_mock_suche_fundstelle_ist_hoechstens_300_zeichen_und_enthaelt_langen_marker(mock):
    marker = "POCMARKER-" + "x" * 190  # 200 Zeichen, die Obergrenze für --suche
    assert len(marker) == 200
    anfrage(mock.api, "POST", "/v1/nix", "v" * 1000 + marker + "n" * 1000)
    anfrage(mock.api, "POST", "/v1/nix", marker + "n" * 1000)  # Marker ganz am Anfang
    anfrage(mock.api, "POST", "/v1/nix", "v" * 1000 + marker)  # Marker ganz am Ende
    e1, e2, e3 = protokoll(mock, suche=marker)["eintraege"]
    for e in (e1, e2, e3):
        assert marker in e["fundstelle"] and 200 < len(e["fundstelle"]) <= 300
    assert e2["fundstelle"].startswith(marker) and e3["fundstelle"].endswith(marker)


def test_mock_suche_fundstelle_nimmt_das_erste_vorkommen_und_bleibt_ascii(mock):
    marker = "POCMARKER-p1-erst"
    anfrage(mock.api, "POST", "/v1/nix", f"é{marker}é erstes " + "x" * 400 + f" {marker} zweites")
    r = cli("--protokoll", mock.steuer, json.dumps({"werte": []}), ["--suche", marker])
    assert r.returncode == 0 and r.stdout.isascii() and b"\\u00e9" in r.stdout
    (e,) = json.loads(r.stdout)["eintraege"]
    assert "erstes" in e["fundstelle"] and "zweites" not in e["fundstelle"]
    assert e["fundstelle"].startswith("é" + marker + "é")


def test_mock_protokoll_ohne_suche_hat_keine_fundstelle(mock):
    chat_json(mock, "POCMARKER-p1-keine")
    (e,) = protokoll(mock)["eintraege"]
    assert "fundstelle" not in e
    (e,) = protokoll(mock, suche="POCMARKER-p1-keine")["eintraege"]
    assert "POCMARKER-p1-keine" in e["fundstelle"]


def test_mock_protokoll_mit_fundstellen_bleibt_unter_64kib(mock):
    marker = "POCMARKER-p1-gross"
    for i in range(8):
        anfrage(mock.api, "POST", "/v1/nix", "é" * 4000 + marker + "é" * 400 + f"{i}")
    r = cli("--protokoll", mock.steuer, json.dumps({"werte": []}), ["--suche", marker])
    assert r.returncode == 0 and r.stdout.isascii() and len(r.stdout) <= 65536
    p = json.loads(r.stdout)
    assert p["gekuerzt"] > 0 and p["gekuerzt"] + len(p["eintraege"]) == 8
    assert all(marker in e["fundstelle"] for e in p["eintraege"])


# --- SDK-Vertragstest (TF3 Task 3c) ---------------------------------------------------------------------------
# Die echten SDKs laufen auf dem Host gegen den lokalen Mock (nur 127.0.0.1). Davor installiert `waechter.mjs` einen
# Wächter, der jede Verbindung zu einem anderen Ziel abweist. Die Umgebung der Node-Prozesse kommt aus einer Whitelist.
# Netz nur für `npm ci` (nur die npm-Registry) im Opt-in-Test. Fremde Ziele der Tests: nur poc-fremd.invalid und 192.0.2.1.

VERTRAG = os.path.join(SKILL, "evals", "sdk-vertrag")
REGISTRY = "https://registry.npmjs.org/"
VERTRAG_PAKETE = ("@ai-sdk/anthropic", "@ai-sdk/openai", "@anthropic-ai/sdk", "ai", "openai")
VERTRAG_OPTIN = os.environ.get("SECURITY_AUDIT_SDK_VERTRAG") == "1"
FREMDE_ZIELE = ("poc-fremd.invalid", "192.0.2.1")

FAELLE = [
    (paket, weg, stream, art)
    for paket, weg in (
        ("openai", "chat"), ("openai", "responses"), ("@anthropic-ai/sdk", "messages"),
        ("ai+@ai-sdk/openai", "responses"), ("ai+@ai-sdk/openai", "chat"), ("ai+@ai-sdk/anthropic", "messages"),
    )
    for stream in (False, True)
    for art in ("text", "tool")
] + [("openai", "embeddings", False, "embedding")]


# Erlaubte Schlüssel der Umgebung eines Vertrags-Prozesses (Whitelist von vertrag_umgebung). Dazu kommt auf macOS
# __CF_USER_TEXT_ENCODING, den das System selbst setzt (reine Kodierung).
UMGEBUNG_ERLAUBT = {"PATH", "HOME", "TMPDIR", "LANG", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_API_KEY",
                    "ANTHROPIC_API_KEY", "__CF_USER_TEXT_ENCODING"}


TRICK_HOSTS = ("127.0.0.1.poc-fremd.invalid", "127.0.0.1@poc-fremd.invalid", "poc-fremd.invalid#127.0.0.1")


def fall_id(f):
    paket, weg, stream, art = f
    return f"{paket}-{weg}-{'stream' if stream else 'ohne'}-{art}"


def vertrag_umgebung(home, port):
    """Umgebung für Node-Prozesse des Vertragstests: Whitelist, nichts wird aus der Umgebung des Testlaufs geerbt."""
    return {
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "OPENAI_BASE_URL": f"http://127.0.0.1:{port}/v1",
        "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
        "OPENAI_API_KEY": "poc-dummy-openai",
        "ANTHROPIC_API_KEY": "poc-dummy-anthropic",
    }


def test_vertrag_umgebung_ohne_fremde_variablen(monkeypatch, tmp_path):
    fremd = {
        "OPENAI_ORG_ID": "org-fremd", "OPENAI_PROJECT_ID": "proj-fremd", "OPENAI_API_BASE": "http://poc-fremd.invalid/v1",
        "OPENAI_BASE_URL": "http://poc-fremd.invalid/v1", "ANTHROPIC_BASE_URL": "http://poc-fremd.invalid",
        "ANTHROPIC_AUTH_TOKEN": "poc-fremd-token", "ANTHROPIC_API_KEY": "echt-wirkender-schluessel",
        "AZURE_OPENAI_ENDPOINT": "http://poc-fremd.invalid", "AZURE_OPENAI_API_KEY": "azure-fremd",
        "HTTPS_PROXY": "http://poc-fremd.invalid:3128", "HTTP_PROXY": "http://poc-fremd.invalid:3128",
        "https_proxy": "http://poc-fremd.invalid:3128", "ALL_PROXY": "http://poc-fremd.invalid:3128",
        "NO_PROXY": "", "NODE_OPTIONS": "--require /fremd.js", "NODE_EXTRA_CA_CERTS": "/fremd.pem",
        "NPM_CONFIG_REGISTRY": "http://poc-fremd.invalid/", "GOOGLE_API_KEY": "g-fremd", "AWS_ACCESS_KEY_ID": "aws-fremd",
    }
    for k, v in fremd.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("OPENAI_API_KEY", "echt-wirkender-schluessel")
    env = vertrag_umgebung(tmp_path, 4242)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL",
                        "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
    assert env["HOME"] == env["TMPDIR"] == str(tmp_path)
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:4242/v1"
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4242"
    assert env["OPENAI_API_KEY"] == "poc-dummy-openai" and env["ANTHROPIC_API_KEY"] == "poc-dummy-anthropic"
    werte = "\n".join(env.values())
    for v in fremd.values():
        if v:
            assert v not in werte
    assert "echt-wirkender-schluessel" not in werte


def test_sdk_vertrag_lockfile_nur_registry():
    with open(os.path.join(VERTRAG, "package.json.tmpl"), encoding="utf-8") as f:
        paket = json.load(f)
    with open(os.path.join(VERTRAG, "package-lock.json.tmpl"), encoding="utf-8") as f:
        roh = f.read()
    lock = json.loads(roh)
    assert not os.path.exists(os.path.join(VERTRAG, "package.json")), "Manifest nur als .tmpl ablegen"
    assert not os.path.exists(os.path.join(VERTRAG, "package-lock.json")), "Lockfile nur als .tmpl ablegen"
    assert not os.path.exists(os.path.join(VERTRAG, "node_modules"))
    for name in ("preinstall", "install", "postinstall", "prepare"):
        assert name not in paket.get("scripts", {})
    # gepinnt: genau diese Pakete, jeweils eine feste Version ohne Bereich
    assert sorted(paket["dependencies"]) == sorted(VERTRAG_PAKETE)
    for name, version in paket["dependencies"].items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), (name, version)
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["dependencies"] == paket["dependencies"]
    for name in VERTRAG_PAKETE:
        assert lock["packages"][f"node_modules/{name}"]["version"] == paket["dependencies"][name]
    pakete = {k: v for k, v in lock["packages"].items() if k}
    assert len(pakete) > len(VERTRAG_PAKETE)
    for name, daten in pakete.items():
        assert not daten.get("hasInstallScript"), name
        assert not daten.get("link"), name
        assert daten.get("resolved", "").startswith(REGISTRY), name
        assert daten.get("integrity", "").startswith("sha512-"), name
    # keine andere URL als die Registry; `funding` ist reine Metadaten-Angabe (Spendenlink) und wird nie abgerufen
    for daten in pakete.values():
        daten.pop("funding", None)
    rest = json.dumps(pakete)
    hosts = set(re.findall(r"[a-z][a-z0-9+.-]*://([^/\s\"']+)", rest))
    assert hosts == {"registry.npmjs.org"}, hosts
    assert not re.search(r"git\+|github:|file:|\"http://", rest)


def test_sdk_vertrag_dateien_ohne_modell_api_hosts():
    """Kein Vertragsskript und kein Test nennt einen echten Modell-API-Host als Ziel (hier nur zusammengesetzt)."""
    muster = re.compile("api" + r"\.(?:" + "openai" + "|" + "anthropic" + r")\.com")
    dateien = [os.path.join(VERTRAG, n) for n in sorted(os.listdir(VERTRAG))] + [os.path.join(HIER, "test_llm_mock.py")]
    assert any(d.endswith("vertrag.mjs") for d in dateien) and any(d.endswith("waechter.mjs") for d in dateien)
    for d in dateien:
        with open(d, encoding="utf-8") as f:
            assert not muster.search(f.read()), d


WAECHTER_PROBE = r"""
import "./waechter.mjs";
import { treffer } from "./waechter.mjs";
import http, { request as httpRequestBenannt } from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

const FREMD = ["poc-fremd.invalid", "192.0.2.1"];
const TRICKS = ["127.0.0.1.poc-fremd.invalid", "127.0.0.1@poc-fremd.invalid", "poc-fremd.invalid#127.0.0.1"];
const ergebnisse = {};

async function versuch(name, f) {
  try {
    const r = await f();
    if (r && typeof r.destroy === "function") r.destroy();
    ergebnisse[name] = "erlaubt";
  } catch (e) {
    ergebnisse[name] = /waechter/i.test(String(e && e.message)) ? "blockiert" : "anderer fehler: " + String(e && e.message);
  }
}

// Lokaler Listener (127.0.0.1, Port 0): hier muss alles durchgehen.
const server = http.createServer((req, res) => res.end("ok"));
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const port = server.address().port;
const lokal = (fn) => () => new Promise((ok, fehler) => fn(ok, fehler));

await versuch("lokal.fetch", async () => { const r = await fetch(`http://127.0.0.1:${port}/`); await r.text(); });
await versuch("lokal.http.get", lokal((ok, fehler) => {
  http.get({ host: "127.0.0.1", port, path: "/" }, (res) => { res.resume(); res.on("end", ok); }).on("error", fehler);
}));
await versuch("lokal.http.request", lokal((ok, fehler) => {
  const r = http.request(`http://127.0.0.1:${port}/`, (res) => { res.resume(); res.on("end", ok); });
  r.on("error", fehler); r.end();
}));
await versuch("lokal.net.connect", lokal((ok, fehler) => {
  const s = net.connect({ host: "127.0.0.1", port }, () => { s.destroy(); ok(); }); s.on("error", fehler);
}));
await versuch("lokal.net.createConnection", lokal((ok, fehler) => {
  const s = net.createConnection(port, "127.0.0.1", () => { s.destroy(); ok(); }); s.on("error", fehler);
}));
server.close();

// Der benannte Import muss nach syncBuiltinESMExports() dieselbe Sperre sehen wie http.request selbst (nicht erst die Socket-Schicht).
{
  const n = treffer.length;
  await versuch("benannt.http.request", () => httpRequestBenannt({ hostname: "poc-fremd.invalid" }));
  ergebnisse["benannt.art"] = treffer.length === n + 1 ? treffer[n].art : "kein Treffer";
}

for (const ziel of FREMD) {
  const url = ziel === "192.0.2.1" ? "http://192.0.2.1:9/" : "http://poc-fremd.invalid/";
  const surl = url.replace("http:", "https:");
  await versuch(`${ziel}.fetch`, () => fetch(url, { signal: AbortSignal.timeout(2000) }));
  await versuch(`${ziel}.fetch.request`, () => fetch(new Request(url), { signal: AbortSignal.timeout(2000) }));
  await versuch(`${ziel}.http.request`, () => http.request({ host: ziel, port: 9, path: "/" }));
  await versuch(`${ziel}.http.request.url`, () => http.request(url));
  await versuch(`${ziel}.http.get`, () => http.get(url));
  await versuch(`${ziel}.http.benannt`, () => httpRequestBenannt({ hostname: ziel }));
  await versuch(`${ziel}.https.request`, () => https.request(surl));
  await versuch(`${ziel}.https.get`, () => https.get({ hostname: ziel, port: 9 }));
  await versuch(`${ziel}.net.connect`, () => net.connect({ host: ziel, port: 9 }));
  await versuch(`${ziel}.net.connect.args`, () => net.connect(9, ziel));
  await versuch(`${ziel}.net.createConnection`, () => net.createConnection({ host: ziel, port: 9 }));
  await versuch(`${ziel}.tls.connect`, () => tls.connect({ host: ziel, port: 9 }));
  await versuch(`${ziel}.socket.connect`, () => new net.Socket().connect(9, ziel));
}
// Ohne Host gilt localhost, nicht 127.0.0.1: ebenfalls abgewiesen. Tricks mit dem Hostnamen ebenso.
await versuch("ohne_host.http.request", () => http.request({ port: 9 }));
// Trickhosts (Präfix, Userinfo, Fragment) über ALLE Wege: der Wächter vergleicht den Host exakt mit 127.0.0.1.
for (const h of TRICKS) {
  const url = `http://${h}/`;
  const surl = `https://${h}/`;
  await versuch(`trick.${h}.fetch`, () => fetch(url, { signal: AbortSignal.timeout(2000) }));
  await versuch(`trick.${h}.http.request`, () => http.request({ host: h, port: 9, path: "/" }));
  await versuch(`trick.${h}.http.request.url`, () => http.request(url));
  await versuch(`trick.${h}.http.get`, () => http.get({ hostname: h, port: 9 }));
  await versuch(`trick.${h}.https.request`, () => https.request(surl));
  await versuch(`trick.${h}.https.get`, () => https.get({ host: h, port: 9 }));
  await versuch(`trick.${h}.net.connect`, () => net.connect({ host: h, port: 9 }));
  await versuch(`trick.${h}.net.createConnection`, () => net.createConnection(9, h));
  await versuch(`trick.${h}.tls.connect`, () => tls.connect({ host: h, port: 9 }));
  await versuch(`trick.${h}.socket.connect`, () => new net.Socket().connect(9, h));
}
// Nicht lesbare Ziele werden abgewiesen (fail-closed), nie durchgelassen.
await versuch("unlesbar.fetch.objekt", () => fetch({}));
await versuch("unlesbar.fetch.undefined", () => fetch(undefined));
await versuch("unlesbar.fetch.text", () => fetch("::keine url::"));
await versuch("unlesbar.http.request.text", () => http.request("::keine url::"));
{
  const n = treffer.length;
  await versuch("trick.ipc", () => net.connect({ path: "/tmp/poc-nicht-vorhanden.sock" }));
  ergebnisse["ipc.ziel"] = treffer.length === n + 1 ? treffer[n].ziel : "kein Treffer";
}

// Ein SDK, das den Fehler fängt, ändert nichts an der Liste.
const vorher = treffer.length;
try { await fetch("http://poc-fremd.invalid/", { signal: AbortSignal.timeout(2000) }); } catch {}
ergebnisse["liste.waechst_trotz_fang"] = treffer.length === vorher + 1 ? "ja" : "nein";

process.stdout.write(JSON.stringify({ ergebnisse, treffer, umgebung: Object.keys(process.env).sort(), execArgv: process.execArgv }) + "\n");
"""


def vertrag_dateien_kopieren(ziel, namen=("vertrag.mjs", "waechter.mjs")):
    for n in namen:
        shutil.copy(os.path.join(VERTRAG, n), os.path.join(str(ziel), n))


# Die Wächter- und Exit-Tests laufen mit demselben node wie der Opt-in-Lauf (SECURITY_AUDIT_SDK_NODE), falls gesetzt.
VERTRAG_NODE = os.environ.get("SECURITY_AUDIT_SDK_NODE") or NODE


def node_lauf(skript, cwd, env, args=(), timeout=60, node_args=()):
    return subprocess.run([VERTRAG_NODE, *node_args, skript, *args], cwd=str(cwd), env=env, capture_output=True, timeout=timeout)


def test_vertrag_waechter_blockiert_fremden_host(tmp_path):
    vertrag_dateien_kopieren(tmp_path, ("waechter.mjs",))
    (tmp_path / "probe.mjs").write_text(WAECHTER_PROBE, encoding="utf-8")
    r = node_lauf("probe.mjs", tmp_path, vertrag_umgebung(tmp_path, 1))
    assert r.returncode == 0, (r.stdout, r.stderr)
    daten = json.loads(r.stdout)
    erg = daten["ergebnisse"]
    for name, wert in erg.items():
        if name.startswith("lokal."):
            assert wert == "erlaubt", (name, wert)
        elif name == "liste.waechst_trotz_fang":
            assert wert == "ja"
        elif name == "benannt.art":
            assert wert == "http.request", wert
        elif name == "ipc.ziel":
            assert wert.startswith("ipc:"), wert
        else:
            assert wert == "blockiert", (name, wert)
    assert len([n for n in erg if n.startswith("lokal.")]) == 5
    assert len([n for n in erg if n.startswith("trick.") and n != "trick.ipc"]) == 3 * 10  # drei Trickhosts über zehn Wege
    for h in TRICK_HOSTS:
        assert sum(1 for n in erg if n.startswith(f"trick.{h}.")) == 10, h
    assert len([n for n in erg if n.startswith("unlesbar.")]) == 4
    # Die Probe lief mit der Umgebung aus vertrag_umgebung und ohne Node-Optionen (belegt, dass der Test sie verwendet).
    assert set(daten["umgebung"]) <= UMGEBUNG_ERLAUBT, daten["umgebung"]
    assert daten["execArgv"] == []
    for ziel in FREMDE_ZIELE:
        assert sum(1 for n in erg if n.startswith(ziel + ".")) == 13, ziel
    # jeder Treffer steht in der Liste, mit Art und Ziel (nur Host, ohne Pfad und Query)
    arten = {t["art"] for t in daten["treffer"]}
    assert arten >= {"fetch", "http.request", "http.get", "https.request", "https.get", "net.connect",
                     "net.createConnection", "tls.connect", "socket.connect"}, arten
    for t in daten["treffer"]:
        assert set(t) == {"art", "ziel"}, t
        # Socket-Pfade (ipc:) sind keine Hosts; die Trickhosts stehen als host-Option roh (so, wie der Aufrufer sie übergab)
        if not t["ziel"].startswith("ipc:") and t["ziel"] not in TRICK_HOSTS:
            assert "/" not in t["ziel"] and "?" not in t["ziel"] and "@" not in t["ziel"], t
    ziele = {t["ziel"] for t in daten["treffer"]}
    assert set(FREMDE_ZIELE) <= ziele
    assert not any(t["ziel"] == "127.0.0.1" for t in daten["treffer"])


def test_vertrag_faelle_stimmen_mit_dem_skript(tmp_path):
    vertrag_dateien_kopieren(tmp_path)
    r = node_lauf("vertrag.mjs", tmp_path, vertrag_umgebung(tmp_path, 1), ["--faelle"])
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert r.stdout.isascii()
    ist = [(z["paket"], z["weg"], z["stream"], z["art"]) for z in json.loads(r.stdout)]
    assert ist == FAELLE  # auch die Reihenfolge: die Fallnummer (Index) steckt im Marker


def test_vertrag_antworten_je_fall_mit_eigenem_marker(tmp_path, mock):
    vertrag_dateien_kopieren(tmp_path)
    r = node_lauf("vertrag.mjs", tmp_path, vertrag_umgebung(tmp_path, mock.api), ["--antworten"])
    assert r.returncode == 0, (r.stdout, r.stderr)
    liste = json.loads(r.stdout)
    assert len(liste) == sum(1 for f in FAELLE if f[3] in ("text", "tool"))  # Embeddings brauchen keine Antwort
    marker = [e["wenn_enthaelt"] for e in liste]
    assert len(set(marker)) == len(marker)
    assert all(re.fullmatch(r"POCMARKER-vertrag-\d\d", m) for m in marker)
    assert any("text" in e for e in liste) and any("werkzeug" in e for e in liste)
    setzen(mock, liste)  # der Mock nimmt die Liste an


ATTRAPPEN = {
    # lässt beides scheinbar durch
    "beides_offen": (
        'globalThis.fetch = async () => new Response("x");\n'
        'http.request = () => ({ on() { return this; }, end() {}, destroy() {} });\n'),
    # weist nur fetch ab, http.request bleibt offen (ein Selbsttest nur für fetch würde das übersehen)
    "nur_fetch_zu": (
        'globalThis.fetch = async () => { const e = new Error("waechter"); e.code = "EWAECHTER"; throw e; };\n'
        'http.request = () => ({ on() { return this; }, end() {}, destroy() {} });\n'),
    # weist nur http.request ab, fetch bleibt offen (ein Selbsttest nur für http.request würde das übersehen)
    "nur_http_zu": (
        'globalThis.fetch = async () => new Response("x");\n'
        'http.request = () => { const e = new Error("waechter"); e.code = "EWAECHTER"; throw e; };\n'),
}


@pytest.mark.parametrize("attrappe", sorted(ATTRAPPEN))
def test_vertrag_ohne_wirksamen_waechter_exit3_und_kein_sdk(tmp_path, attrappe):
    # Attrappe statt Wächter, ohne dass ein Request das Netz erreicht. Jede Attrappe lässt mindestens einen der beiden
    # Wege (fetch, http.request) offen: Der Selbsttest muss beide prüfen und mit Exit 3 enden.
    (tmp_path / "waechter.mjs").write_text(
        'import http from "node:http";\n'
        'import module from "node:module";\n'
        'export const treffer = [];\n' + ATTRAPPEN[attrappe] + 'module.syncBuiltinESMExports();\n', encoding="utf-8")
    vertrag_dateien_kopieren(tmp_path, ("vertrag.mjs",))
    r = node_lauf("vertrag.mjs", tmp_path, vertrag_umgebung(tmp_path, 1))
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == b""  # keine Ergebniszeile: kein SDK wurde importiert (es gibt hier auch kein node_modules)
    assert b"Selbsttest" in r.stderr


@pytest.mark.parametrize("fehlt", ["OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"])
def test_vertrag_ohne_basis_url_in_der_umgebung_exit4(tmp_path, fehlt):
    vertrag_dateien_kopieren(tmp_path)
    env = vertrag_umgebung(tmp_path, 1)
    del env[fehlt]
    r = node_lauf("vertrag.mjs", tmp_path, env)
    assert r.returncode == 4, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == b""


@pytest.mark.parametrize("name", ["OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"])
@pytest.mark.parametrize("url", [
    "http://poc-fremd.invalid/v1", "http://192.0.2.1:9/v1", "http://localhost:1/v1",
    "http://127.0.0.1/v1",                  # ohne Port: der Mock-Port muss in der Umgebung stehen
    "http://u:p@127.0.0.1:1/v1",            # Userinfo
    "http://127.0.0.1:1@poc-fremd.invalid/v1", "https://127.0.0.1:1/v1",
])
def test_vertrag_basis_url_ungueltig_exit4(tmp_path, name, url):
    vertrag_dateien_kopieren(tmp_path)
    env = vertrag_umgebung(tmp_path, 1)
    env[name] = url
    r = node_lauf("vertrag.mjs", tmp_path, env)
    assert r.returncode == 4, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == b""


@pytest.mark.parametrize("name", ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"])
@pytest.mark.parametrize("wert", ["", "sk-echt-wirkend", "dummy-poc-", "xpoc-dummy-1"])
def test_vertrag_schluessel_ohne_poc_dummy_praefix_exit4(tmp_path, name, wert):
    vertrag_dateien_kopieren(tmp_path)
    env = vertrag_umgebung(tmp_path, 1)
    env[name] = wert
    r = node_lauf("vertrag.mjs", tmp_path, env)
    assert r.returncode == 4, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == b""


FREMDE_SCHLUESSEL = [
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "OPENAI_API_BASE", "ANTHROPIC_AUTH_TOKEN",
    "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "NPM_CONFIG_REGISTRY", "AWS_ACCESS_KEY_ID", "POC_IRGENDWAS",
]


@pytest.mark.parametrize("schluessel", FREMDE_SCHLUESSEL)
@pytest.mark.parametrize("modus", ["--faelle", "--antworten", None])
def test_vertrag_fremde_umgebungsvariable_exit4(tmp_path, schluessel, modus):
    """Der Prozess prüft seine eigene Umgebung: nur die Whitelist ist erlaubt, alles andere endet mit Exit 4 (ohne SDK)."""
    vertrag_dateien_kopieren(tmp_path)
    env = vertrag_umgebung(tmp_path, 1)
    wert = "--no-warnings" if schluessel == "NODE_OPTIONS" else "poc-wert-fremd"
    env[schluessel] = wert
    r = node_lauf("vertrag.mjs", tmp_path, env, [modus] if modus else [])
    assert r.returncode == 4, (r.returncode, r.stdout, r.stderr)
    assert r.stdout == b""
    assert schluessel.encode() in r.stderr  # der Name wird genannt, nie der Wert
    if schluessel not in ("NODE_OPTIONS", "NODE_EXTRA_CA_CERTS"):  # diese Werte meldet Node selbst, noch vor dem Skript
        assert wert.encode() not in r.stderr


def test_vertrag_node_optionen_exit4(tmp_path):
    vertrag_dateien_kopieren(tmp_path)
    (tmp_path / "leer.cjs").write_text("")             # CommonJS: --require geht auf jeder Node-Version (Re-Review 3c M-3)
    for optionen in (["--no-warnings"], ["--require", "./leer.cjs"], ["--max-old-space-size=512"]):
        r = node_lauf("vertrag.mjs", tmp_path, vertrag_umgebung(tmp_path, 1), ["--faelle"], node_args=optionen)
        assert r.returncode == 4, (optionen, r.returncode, r.stdout, r.stderr)
        assert r.stdout == b""


def test_vertrag_umgebung_der_whitelist_laeuft(tmp_path):
    """Gegenprobe: genau die Whitelist (wie vom Test gebaut) wird akzeptiert."""
    vertrag_dateien_kopieren(tmp_path)
    r = node_lauf("vertrag.mjs", tmp_path, vertrag_umgebung(tmp_path, 1), ["--faelle"])
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)


# Opt-in: SECURITY_AUDIT_SDK_VERTRAG=1 (braucht npm, Node >= 22 und Netz zur npm-Registry). Node >= 22 verlangen die
# aktuellen SDKs; ein anderes node wählt SECURITY_AUDIT_SDK_NODE=<pfad>.

def _node_major(pfad):
    r = subprocess.run([pfad, "--version"], capture_output=True, timeout=20)
    m = re.match(rb"v(\d+)\.", r.stdout)
    return int(m.group(1)) if m else 0


# Endpunkt je Fall: das Mock-Protokoll belegt den Weg, den der Client wirklich genommen hat (genau ein Request je Fall).
# Das AI SDK für Anthropic hängt /messages an die Basis-URL (ohne /v1) an, der Anthropic-Client /v1/messages.
ERWARTETER_PFAD = {
    ("openai", "chat"): "/v1/chat/completions",
    ("openai", "responses"): "/v1/responses",
    ("openai", "embeddings"): "/v1/embeddings",
    ("@anthropic-ai/sdk", "messages"): "/v1/messages",
    ("ai+@ai-sdk/openai", "responses"): "/v1/responses",
    ("ai+@ai-sdk/openai", "chat"): "/v1/chat/completions",
    ("ai+@ai-sdk/anthropic", "messages"): "/messages",
}


def vertrag_npm_umgebung(home):
    """Umgebung für `npm ci`: Whitelist, kein ~/.npmrc, keine npm_config_*-Variablen, kein Proxy aus dem Testlauf."""
    return {"PATH": os.environ.get("PATH") or "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home)}


@pytest.fixture(scope="module")
def vertrag_zeilen(tmp_path_factory):
    if not VERTRAG_OPTIN:
        pytest.skip("Opt-in: SECURITY_AUDIT_SDK_VERTRAG=1")
    npm = shutil.which("npm")
    node = os.environ.get("SECURITY_AUDIT_SDK_NODE") or NODE
    if npm is None or node is None:
        pytest.skip("npm oder node fehlt")
    if _node_major(node) < 22:
        pytest.skip("Node >= 22 nötig (SECURITY_AUDIT_SDK_NODE=<pfad>)")
    arbeit = tmp_path_factory.mktemp("sdk-vertrag")
    npm_home = tmp_path_factory.mktemp("sdk-vertrag-npm")
    leer, leer_global = npm_home / "leer.npmrc", npm_home / "leer-global.npmrc"  # npm lädt dieselbe Datei nicht doppelt
    leer.write_text("", encoding="utf-8")
    leer_global.write_text("", encoding="utf-8")
    try:
        shutil.copy(os.path.join(VERTRAG, "package.json.tmpl"), arbeit / "package.json")
        shutil.copy(os.path.join(VERTRAG, "package-lock.json.tmpl"), arbeit / "package-lock.json")
        vorher = (arbeit / "package-lock.json").read_bytes()
        # einzige Netzaktion: npm ci gegen die npm-Registry, mit Whitelist-Umgebung, leerer npm-Konfiguration, eigenem Cache,
        # ausdrücklicher Registry und ohne Skripte
        i = subprocess.run([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", REGISTRY,
                            "--userconfig", str(leer), "--globalconfig", str(leer_global), "--cache", str(npm_home / "cache")],
                           cwd=str(arbeit), env=vertrag_npm_umgebung(npm_home), capture_output=True, timeout=300)
        assert i.returncode == 0, i.stderr.decode("utf-8", "replace")[-2000:]
        assert (arbeit / "package-lock.json").read_bytes() == vorher
        vertrag_dateien_kopieren(arbeit)
        m = Mock()
        try:
            home = tmp_path_factory.mktemp("sdk-vertrag-home")
            env = vertrag_umgebung(home, m.api)
            env["PATH"] = os.path.dirname(node) + os.pathsep + env["PATH"]
            a = subprocess.run([node, "vertrag.mjs", "--antworten"], cwd=str(arbeit), env=env, capture_output=True, timeout=60)
            assert a.returncode == 0, a.stderr
            setzen(m, json.loads(a.stdout))
            # 25 Fälle mit je höchstens 20 s Frist plus 10 s Reserve
            r = subprocess.run([node, "vertrag.mjs"], cwd=str(arbeit), env=env, capture_output=True, timeout=900)
            pfade = {}
            for nr in range(len(FAELLE)):
                p = cli("--protokoll", m.steuer, json.dumps({"werte": []}), ["--suche", f"POCMARKER-vertrag-{nr:02d}"])
                pfade[nr] = sorted(e["pfad"] for e in json.loads(p.stdout)["eintraege"]) if p.returncode == 0 else None
        finally:
            m.beenden()
        assert r.returncode == 0, (r.returncode, r.stdout.decode("utf-8", "replace")[-2000:], r.stderr.decode("utf-8", "replace")[-2000:])
        ausgabe = os.environ.get("SECURITY_AUDIT_SDK_VERTRAG_AUSGABE")
        if ausgabe:
            with open(ausgabe, "wb") as f:
                f.write(r.stdout)
        zeilen = {}
        for z in r.stdout.decode("utf-8").splitlines():
            d = json.loads(z)
            assert set(d) == {"paket", "weg", "stream", "art", "ergebnis", "waechter"}, d
            zeilen[(d["paket"], d["weg"], d["stream"], d["art"])] = d
        for nr, f in enumerate(FAELLE):  # die Reihenfolge der Zeilen ist die der Fälle (--faelle, Nummer = Index)
            if f in zeilen:
                zeilen[f]["pfade"] = pfade[nr]
        return zeilen
    finally:
        shutil.rmtree(arbeit, ignore_errors=True)  # node_modules (rund 95 MB) nicht liegen lassen
        shutil.rmtree(npm_home, ignore_errors=True)


def test_vertrag_sdk_vollstaendig(vertrag_zeilen):
    assert sorted(vertrag_zeilen) == sorted(FAELLE)


@pytest.mark.parametrize("fall", FAELLE, ids=fall_id)
def test_vertrag_sdk(vertrag_zeilen, fall):
    z = vertrag_zeilen[fall]
    assert z["ergebnis"] == "gruen", z  # sonst "rot: <Grund>" oder "liest Env nicht" (Wächter hat ausgelöst)
    assert z["waechter"] == [], z
    # der Weg ist belegt, nicht nur benannt: genau ein Request, auf dem erwarteten Endpunkt
    assert z["pfade"] == [ERWARTETER_PFAD[(fall[0], fall[1])]], (fall, z["pfade"])
