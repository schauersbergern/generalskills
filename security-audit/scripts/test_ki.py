"""Tests für `ki.py erkennen` (TF3, Task 2): Erkennung von LLM- und Agenten-SDKs in den package.json einer Arbeitskopie.

Aufruf: python3 -m pytest security-audit/scripts/test_ki.py -q

Alle Testdaten entstehen zur Laufzeit in tmp_path. Der Befehl startet keinen Kindprozess, geht nicht ins Netz und schreibt
nichts; die Tests enthalten keine Signal- oder Kill-Logik.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import ki  # noqa: E402
import lieferkette  # noqa: E402

KI = os.path.join(HIER, "ki.py")
LAUF = "0a1b2c3d"
NICHT_ANWENDBAR = "KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)"

# Unabhängige Kopie der Liste aus Spec §1 (Name -> Beispielname; `/*` heißt jeder Name im Scope).
SDK_NAMEN = [
    "openai", "@openai/agents", "@azure/openai",
    "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk",
    "ai", "@ai-sdk/openai", "@ai-sdk/anthropic",
    "langchain", "@langchain/core", "@langchain/openai",
    "llamaindex", "@llamaindex/openai",
    "@modelcontextprotocol/sdk", "@modelcontextprotocol/server-filesystem", "fastmcp",
    "@google/generative-ai", "@google/genai", "@google-cloud/vertexai",
    "@mistralai/mistralai", "cohere-ai", "groq-sdk", "ollama", "@openrouter/ai-sdk-provider", "@huggingface/inference",
    "replicate", "@aws-sdk/client-bedrock-runtime",
    "@mastra/core", "genkit", "@genkit-ai/googleai",
]
KEINE_SDKS = ["openai-utils", "my-ai", "aiohttp", "ai-sdk", "@openai-foo/x", "@anthropic/sdk", "langchain-community",
              "@aws-sdk/client-s3", "@google/maps", "express", "react", "ollama-js", "fast-mcp", "@modelcontextprotocols/x"]


class Umgebung:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        os.makedirs(self.zustand(), mode=0o700)
        os.makedirs(self.quelle())
        open(os.path.join(self.zustand(), "quelle.fertig"), "w").close()

    def env(self, **extra):
        env = {"PATH": "/nonexistent", "HOME": str(self.home), "TMPDIR": str(self.tmp)}
        env.update(extra)
        return env

    def zustand(self):
        return os.path.join(os.path.realpath(self.tmp), f"security-audit-{LAUF}")

    def quelle(self):
        return os.path.join(self.zustand(), "quelle")

    def schreibe(self, rel, inhalt):
        ziel = os.path.join(self.quelle(), rel)
        os.makedirs(os.path.dirname(ziel), exist_ok=True)
        with open(ziel, "wb") as f:
            f.write(inhalt if isinstance(inhalt, bytes) else inhalt.encode())

    def pkg(self, rel="package.json", **felder):
        """package.json mit `dependencies` (Standard) oder anderen Feldern; Werte sind Listen von Paketnamen."""
        daten = {"name": "x"}
        for feld, namen in felder.items():
            daten[feld] = {n: "1.0.0" for n in namen}
        self.schreibe(rel, json.dumps(daten))

    def lauf(self, *extra, env=None, quelle=None, timeout=120):
        return subprocess.run([sys.executable, "-I", KI, "erkennen", "--lauf", LAUF, "--quelle",
                               quelle or self.quelle(), *extra], env=env or self.env(), capture_output=True, text=True,
                              timeout=timeout)

    def ergebnis(self, **kw):
        r = self.lauf(**kw)
        assert r.returncode == 0, r.stdout + r.stderr
        return json.loads(r.stdout)

    def inproc(self, monkeypatch, capsys):
        """`ki.main` im Testprozess (für Attrappen); Rückgabe (Exit, stdout-JSON oder None, stderr)."""
        monkeypatch.setattr(tempfile, "tempdir", str(self.tmp))
        rc = ki.main(["erkennen", "--lauf", LAUF, "--quelle", self.quelle()])
        aus = capsys.readouterr()
        return rc, (json.loads(aus.out) if aus.out.strip() else None), aus.err


@pytest.fixture
def umg(tmp_path):
    return Umgebung(tmp_path)


@pytest.fixture(autouse=True)
def hermetisch(tmp_path, monkeypatch):
    home = tmp_path / "home-inproc"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in list(os.environ):
        if name.startswith(("GIT_", "GITLEAKS_", "OSV_", "SECURITY_AUDIT_")):
            monkeypatch.delenv(name)


# ------------------------------------------------------------------------------------ Hinweise

def test_ki_hinweis_nicht_anwendbar_woertlich(umg):
    umg.pkg(dependencies=["express"])
    out = umg.ergebnis()
    assert set(out) == {"anwendbar", "sdks", "hinweise"}
    assert out["anwendbar"] is False and out["sdks"] == []
    assert out["hinweise"][0] == "KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)"
    assert out["hinweise"] == [NICHT_ANWENDBAR]


def test_ki_hinweis_nicht_anwendbar_ohne_package_json(umg):
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["hinweise"] == [NICHT_ANWENDBAR]


def test_ki_hinweis_angewendet_woertlich(umg):
    umg.pkg(dependencies=["openai", "express"])
    out = umg.ergebnis()
    assert out["anwendbar"] is True
    assert out["sdks"] == [{"paket": "openai", "datei": "package.json"}]
    assert out["hinweise"][0] == "KI-Prüfpunkte: angewendet (openai)"


def test_ki_hinweis_angewendet_hoechstens_fuenf_sortiert_eindeutig(umg):
    umg.pkg(dependencies=["ollama", "openai", "@anthropic-ai/sdk"], devDependencies=["ai", "openai"])
    umg.pkg("b/package.json", dependencies=["groq-sdk", "cohere-ai", "openai"])
    out = umg.ergebnis()
    # sieben verschiedene Namen: die ersten fünf in Sortierung (Codepunkte), `openai` nur einmal
    assert out["hinweise"][0] == "KI-Prüfpunkte: angewendet (@anthropic-ai/sdk, ai, cohere-ai, groq-sdk, ollama)"
    assert len(out["sdks"]) == 7      # openai steht je Datei einmal (auch bei zwei Feldern in einer Datei)


def test_ki_hinweis_steht_vor_weiteren_hinweisen(umg):
    umg.pkg(dependencies=["openai"])
    umg.schreibe("b/package.json", "{kaputt")
    out = umg.ergebnis()
    assert out["hinweise"][0].startswith("KI-Prüfpunkte: angewendet (")
    assert len(out["hinweise"]) >= 2


# ------------------------------------------------------------------------------------ Erkennung

@pytest.mark.parametrize("name", SDK_NAMEN)
def test_ki_jeder_listeneintrag_wird_erkannt(umg, name):
    umg.pkg(dependencies=[name])
    out = umg.ergebnis()
    assert out["anwendbar"] is True
    assert out["sdks"] == [{"paket": name, "datei": "package.json"}]
    assert out["hinweise"][0] == f"KI-Prüfpunkte: angewendet ({name})"


@pytest.mark.parametrize("name", KEINE_SDKS)
def test_ki_aehnliche_namen_werden_nicht_erkannt(umg, name):
    umg.pkg(dependencies=[name])
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["sdks"] == []


@pytest.mark.parametrize("feld", ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"])
def test_ki_alle_abhaengigkeitsfelder(umg, feld):
    umg.pkg(**{feld: ["openai"]})
    assert umg.ergebnis()["anwendbar"] is True


def test_ki_andere_felder_zaehlen_nicht(umg):
    umg.schreibe("package.json", json.dumps({"name": "openai", "keywords": ["openai"], "scripts": {"x": "openai"},
                                             "bundledDependencies": ["openai"], "resolutions": {"openai": "1"}}))
    assert umg.ergebnis()["anwendbar"] is False


def test_ki_fremde_form_der_felder_wird_ignoriert(umg):
    umg.schreibe("package.json", json.dumps({"dependencies": ["openai"], "devDependencies": "openai",
                                             "peerDependencies": None, "optionalDependencies": 3}))
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["hinweise"] == [NICHT_ANWENDBAR]


def test_ki_workspaces(umg):
    umg.pkg("package.json", devDependencies=["typescript"])
    umg.pkg("packages/a/package.json", dependencies=["openai"])
    umg.pkg("packages/b/package.json", dependencies=["@anthropic-ai/sdk", "ai"])
    umg.pkg("packages/c/package.json", dependencies=["express"])
    out = umg.ergebnis()
    assert out["anwendbar"] is True
    assert sorted((s["paket"], s["datei"]) for s in out["sdks"]) == [
        ("@anthropic-ai/sdk", "packages/b/package.json"), ("ai", "packages/b/package.json"),
        ("openai", "packages/a/package.json")]
    assert out["hinweise"][0] == "KI-Prüfpunkte: angewendet (@anthropic-ai/sdk, ai, openai)"


def test_ki_scope_wildcard(umg):
    umg.pkg(dependencies=["@openai/irgendwas", "@ai-sdk/neu-erfunden", "@langchain/x", "@llamaindex/y", "@modelcontextprotocol/z",
                          "@openrouter/q", "@mastra/m", "@genkit-ai/g", "@anthropic-ai/h"])
    out = umg.ergebnis()
    assert {s["paket"] for s in out["sdks"]} == {"@openai/irgendwas", "@ai-sdk/neu-erfunden", "@langchain/x", "@llamaindex/y",
                                                  "@modelcontextprotocol/z", "@openrouter/q", "@mastra/m", "@genkit-ai/g",
                                                  "@anthropic-ai/h"}


def test_ki_scope_ohne_namen_ist_keiner(umg):
    umg.pkg(dependencies=["@openai/", "@openai", "@ai-sdk/"])
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["sdks"] == []


def test_ki_sdks_hoechstens_50(umg):
    for i in range(60):
        umg.pkg(f"p{i:02d}/package.json", dependencies=["openai"])
    out = umg.ergebnis()
    assert len(out["sdks"]) == 50 and out["anwendbar"] is True
    assert out["hinweise"][0] == "KI-Prüfpunkte: angewendet (openai)"
    assert any("60" in h and "50" in h for h in out["hinweise"][1:])


# ------------------------------------------------------------------------------------ Robustheit

def test_ki_node_modules_und_symlink_uebersprungen(umg, tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    (aussen / "package.json").write_text(json.dumps({"dependencies": {"openai": "1"}}))
    umg.pkg("node_modules/foo/package.json", dependencies=["openai"])
    umg.pkg("a/node_modules/package.json", dependencies=["openai"])
    umg.pkg(".git/package.json", dependencies=["openai"])
    os.symlink(aussen / "package.json", os.path.join(umg.quelle(), "package.json"))
    os.symlink(aussen, os.path.join(umg.quelle(), "verlinkt"))
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["sdks"] == []
    assert out["hinweise"] == [NICHT_ANWENDBAR]


def test_ki_datei_zu_gross(umg):
    kopf = b'{"dependencies": {"openai": "1"}, "pad": "'
    umg.schreibe("package.json", kopf + b"x" * (1024 * 1024) + b'"}')
    out = umg.ergebnis()
    assert out["anwendbar"] is False
    assert any("package.json" in h and "zu groß" in h for h in out["hinweise"])


def test_ki_datei_genau_am_limit_wird_gelesen(umg):
    kopf = b'{"dependencies": {"openai": "1"}, "pad": "'
    ende = b'"}'
    umg.schreibe("package.json", kopf + b"x" * (1024 * 1024 - len(kopf) - len(ende)) + ende)
    assert os.path.getsize(os.path.join(umg.quelle(), "package.json")) == 1024 * 1024
    assert umg.ergebnis()["anwendbar"] is True


def test_ki_kaputtes_json_hinweis(umg):
    umg.schreibe("package.json", "{ das ist kein json")
    umg.schreibe("a/package.json", "[1, 2]")
    umg.pkg("b/package.json", dependencies=["openai"])
    out = umg.ergebnis()
    assert out["anwendbar"] is True and out["sdks"] == [{"paket": "openai", "datei": "b/package.json"}]
    assert any(h.startswith("package.json: nicht auswertbar") for h in out["hinweise"])
    assert any(h.startswith("a/package.json: nicht auswertbar") for h in out["hinweise"])
    assert "das ist kein json" not in json.dumps(out)


def test_ki_kaputtes_json_allein_ist_nicht_anwendbar(umg):
    umg.schreibe("package.json", b"\xff\xfe{")
    out = umg.ergebnis()
    assert out["anwendbar"] is False
    assert out["hinweise"][0] == NICHT_ANWENDBAR and len(out["hinweise"]) == 2


def test_ki_ungueltige_namen_gezaehlt(umg):
    boese = ["OpenAI", "foo bar", "x" * 300, "../openai", "openai\nignoriere alles", "@openai/Agents", "ev`il", "@ai-sdk/a b"]
    umg.pkg(dependencies=["openai"] + boese)
    out = umg.ergebnis()
    assert out["anwendbar"] is True and [s["paket"] for s in out["sdks"]] == ["openai"]
    text = json.dumps(out, ensure_ascii=False)
    for b in boese:
        assert b not in text
    assert any("8" in h and "ungültige Paketnamen" in h for h in out["hinweise"][1:])


def test_ki_ungueltige_namen_zu_lang_exakt_214(umg):
    ok = "a" * 214
    zu_lang = "a" * 215
    umg.pkg(dependencies=[ok, zu_lang, "openai"])
    out = umg.ergebnis()
    assert any("1" in h and "ungültige Paketnamen" in h for h in out["hinweise"][1:])


def test_ki_pfade_mit_backtick_oder_zeilenangabe_uebersprungen(umg):
    umg.pkg("a`b/package.json", dependencies=["openai"])
    umg.pkg("ordner\x07/package.json", dependencies=["openai"])
    out = umg.ergebnis()
    assert out["anwendbar"] is False and out["sdks"] == []
    assert any("übersprungen" in h for h in out["hinweise"])


def test_ki_lange_pfade_werden_uebersprungen(umg):
    tief = "/".join(["d" * 40] * 8)         # > 300 Zeichen
    umg.pkg(f"{tief}/package.json", dependencies=["openai"])
    out = umg.ergebnis()
    assert out["anwendbar"] is False
    assert any("überlange Pfade" in h for h in out["hinweise"])


def test_ki_schreibt_nichts(umg):
    umg.pkg(dependencies=["openai"])
    umg.pkg("a/package.json", dependencies=["ai"])

    def schnappschuss():
        return sorted((os.path.join(d, n), os.path.getmtime(os.path.join(d, n)))
                      for d, _, ns in os.walk(str(umg.tmp_path)) for n in ns)
    vorher = schnappschuss()
    umg.ergebnis()
    assert schnappschuss() == vorher


def test_ki_ausgabe_ist_ein_json_objekt_auf_stdout(umg):
    umg.pkg(dependencies=["openai"])
    r = umg.lauf()
    assert r.returncode == 0 and r.stderr == ""
    assert r.stdout.count("\n") == 1 and isinstance(json.loads(r.stdout), dict)


# ------------------------------------------------------------------------------------ Aufruf, Kindprozess, Budget

def test_ki_quelle_fremd_exit2(umg, tmp_path):
    fremd = tmp_path / "fremd"
    fremd.mkdir()
    (fremd / "package.json").write_text(json.dumps({"dependencies": {"openai": "1"}}))
    r = umg.lauf(quelle=str(fremd))
    assert r.returncode == 2
    assert r.stdout == "" and "Arbeitskopie" in r.stderr


def test_ki_quelle_ohne_fertig_marker_exit2(umg):
    os.unlink(os.path.join(umg.zustand(), "quelle.fertig"))
    assert umg.lauf().returncode == 2


def test_ki_ungueltige_lauf_id_exit2(umg):
    r = subprocess.run([sys.executable, "-I", KI, "erkennen", "--lauf", "../x", "--quelle", umg.quelle()], env=umg.env(),
                       capture_output=True, text=True)
    assert r.returncode == 2


def test_ki_unterbefehl_und_argumente_pflicht(umg):
    for args in ([], ["erkennen"], ["erkennen", "--lauf", LAUF], ["anderes", "--lauf", LAUF, "--quelle", umg.quelle()]):
        r = subprocess.run([sys.executable, "-I", KI, *args], env=umg.env(), capture_output=True, text=True)
        assert r.returncode == 2


def test_ki_kein_kindprozess(umg, monkeypatch, capsys):
    umg.pkg(dependencies=["openai"])
    umg.pkg("a/package.json", dependencies=["express"])

    def attrappe(*a, **k):
        raise AssertionError("ki.py darf keinen Kindprozess starten")
    monkeypatch.setattr(subprocess, "Popen", attrappe)
    monkeypatch.setattr(os, "fork", attrappe, raising=False)
    monkeypatch.setattr(os, "system", attrappe)
    rc, out, _ = umg.inproc(monkeypatch, capsys)
    assert rc == 0 and out["anwendbar"] is True


def test_ki_kein_netz_und_keine_schreibzugriffe_im_code():
    quelltext = open(KI, encoding="utf-8").read()
    for verboten in ("subprocess", "urllib", "socket", "requests", "os.system", "os.exec", "os.spawn", "shutil.rmtree"):
        assert verboten not in quelltext, verboten


def test_ki_budget_ohne_fund_exit1(umg):
    umg.pkg(dependencies=["express"])
    r = umg.lauf(env=umg.env(SECURITY_AUDIT_KI_BUDGET="0.000000001"))
    assert r.returncode == 1
    assert r.stdout == ""
    assert "ki.py" in r.stderr and "Zeitbudget" in r.stderr


def test_ki_budget_mit_fund_anwendbar(umg, monkeypatch, capsys):
    umg.pkg(dependencies=["openai"])
    umg.pkg("a/package.json", dependencies=["express"])
    umg.pkg("b/package.json", dependencies=["express"])
    echt = ki._zeitcheck
    aufrufe = []

    def uhr(ende):
        aufrufe.append(1)
        if len(aufrufe) >= 2:                  # nach der ersten package.json ist die Zeit um
            raise lieferkette._Zeit()
        echt(ende)
    monkeypatch.setattr(ki, "_zeitcheck", uhr)
    rc, out, err = umg.inproc(monkeypatch, capsys)
    assert rc == 0, err
    assert out["anwendbar"] is True and out["sdks"] == [{"paket": "openai", "datei": "package.json"}]
    assert out["hinweise"][0] == "KI-Prüfpunkte: angewendet (openai)"
    assert "KI-Erkennung abgebrochen (Zeitbudget)" in out["hinweise"]


def test_ki_budget_ablauf_ohne_fund_in_der_auswertung_exit1(umg, monkeypatch, capsys):
    umg.pkg(dependencies=["express"])
    umg.pkg("a/package.json", dependencies=["express"])

    def uhr(ende):
        raise lieferkette._Zeit()
    monkeypatch.setattr(ki, "_zeitcheck", uhr)
    rc, out, err = umg.inproc(monkeypatch, capsys)
    assert rc == 1 and out is None and "Zeitbudget" in err


def test_ki_budget_ohne_ablauf_kein_abbruchhinweis(umg):
    umg.pkg(dependencies=["openai"])
    assert "KI-Erkennung abgebrochen (Zeitbudget)" not in umg.ergebnis()["hinweise"]


def test_ki_budget_override_nie_ueber_dem_standard(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_KI_BUDGET", "100000")
    assert lieferkette._sekunden("SECURITY_AUDIT_KI_BUDGET", ki.KI_BUDGET) == ki.KI_BUDGET == 30
    assert ki._budget() == 30
    monkeypatch.setenv("SECURITY_AUDIT_KI_BUDGET", "5")
    assert ki._budget() == 5


def test_ki_helfer_werden_aus_lieferkette_importiert():
    assert ki._arbeitskopie is lieferkette._arbeitskopie
    assert ki._sekunden is lieferkette._sekunden
    assert ki.NPM_PAKETNAME is lieferkette.NPM_PAKETNAME
    assert ki.PAKETNAME_MAX == lieferkette.PAKETNAME_MAX == 214
    assert ki.ABHAENGIGKEIT_FELDER is lieferkette.ABHAENGIGKEIT_FELDER


def test_ki_keine_fixture_namen_in_ki_und_test():
    """Die Fixture-Namen der Eval gehören nicht in `scripts/` (Plan R2 K9); die Liste wird zur Laufzeit aus Teilen gebaut,
    damit dieser Test sie nicht selbst enthält."""
    namen = ["CRM_API" + "_KEY", "datei_" + "suchen", "antwort-" + "sicher", "tickets" + ".js", "assistent" + ".js",
             "fixture-" + "ki", "ausgang" + ".jsonl", "send_" + "email"]
    for datei in ("ki.py", "test_ki.py"):
        text = open(os.path.join(HIER, datei), encoding="utf-8").read()
        for n in namen:
            assert n not in text, (datei, n)
