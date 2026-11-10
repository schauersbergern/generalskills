"""Vertragstests für die Skill-Prosa (SKILL.md, references/): Frontmatter, Aufrufformen, Unterbefehle und Optionen
der Skripte, Pflichtabschnitte, Beispiel-JSON gegen das Schema, keine Pfade der Test-App.

Geprüft wird nur der Vertrag mit den Skripten und dem Eval, nie die Formulierung der Prosa.

Aufruf: python3 -m pytest security-audit/scripts/test_skill_text.py -q
"""
import json
import os
import re
import subprocess
import sys

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HIER)
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")
REFERENCES = os.path.join(SKILL_DIR, "references")
BRIEFINGS = os.path.join(REFERENCES, "agenten-briefings.md")
BERICHT_FORMAT = os.path.join(REFERENCES, "bericht-format.md")
ERWARTUNG = os.path.join(SKILL_DIR, "evals", "expected", "fixture-web.json")

sys.path.insert(0, HIER)
import bericht  # noqa: E402

PRAEFIX_SKILL = ("python3 -I ${CLAUDE_SKILL_DIR}/scripts/", "python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py")
PRAEFIX_REFERENZ = ("python3 -I <SKILL_DIR>/scripts/",)
SKRIPTE = ("poc", "bericht")


def _lies(pfad: str) -> str:
    with open(pfad, encoding="utf-8") as f:
        return f.read()


def _referenzen() -> list[str]:
    assert os.path.isdir(REFERENCES), "references/ fehlt"
    return sorted(os.path.join(REFERENCES, n) for n in os.listdir(REFERENCES) if n.endswith(".md"))


def _bloecke(text: str) -> list[tuple[str, str]]:
    """Codeblöcke (Zaun aus ≥ 3 Backticks, auch länger) als (Info-Zeile, Inhalt)."""
    ergebnis, zeilen, i = [], text.split("\n"), 0
    while i < len(zeilen):
        m = re.match(r"^(\s*)(`{3,})(.*)$", zeilen[i])
        if not m:
            i += 1
            continue
        zaun, info, inhalt = m.group(2), m.group(3).strip(), []
        i += 1
        while i < len(zeilen) and not re.match(r"^\s*" + zaun + r"`*\s*$", zeilen[i]):
            inhalt.append(zeilen[i])
            i += 1
        i += 1
        ergebnis.append((info, "\n".join(inhalt)))
    return ergebnis


def _code_zeilen(text: str, bloecke: bool = True) -> list[str]:
    """Zeilen aus Codeblöcken (nur mit `bloecke`) plus alle Inline-Code-Spans außerhalb der Blöcke, gestrippt."""
    zeilen = [z.strip() for _info, inhalt in _bloecke(text) for z in inhalt.split("\n")] if bloecke else []
    ohne_bloecke = re.sub(r"(?ms)^\s*(`{3,}).*?^\s*\1`*\s*$", "", text)
    zeilen += [s.strip() for s in re.findall(r"`([^`\n]+)`", ohne_bloecke)]
    return [z for z in zeilen if z]


def _aufrufzeilen(text: str) -> list[str]:
    return [z for z in _code_zeilen(text) if z.startswith("python3")]


def _frontmatter_roh(text: str) -> dict[str, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "Frontmatter fehlt"
    werte = {}
    for zeile in m.group(1).split("\n"):
        schluessel, doppelpunkt, wert = zeile.partition(":")
        if doppelpunkt:
            werte[schluessel.strip()] = wert.strip()
    return werte


def _frontmatter(text: str) -> dict[str, str]:
    """Werte ohne die einfachen Anführungszeichen, mit denen YAML sie einfasst."""
    return {k: (v[1:-1].replace("''", "'") if len(v) >= 2 and v[0] == v[-1] == "'" else v)
            for k, v in _frontmatter_roh(text).items()}


def _hilfe(skript: str, *unterbefehl: str) -> str:
    r = subprocess.run([sys.executable, "-I", os.path.join(HIER, f"{skript}.py"), *unterbefehl, "--help"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


def _unterbefehle(skript: str) -> set[str]:
    m = re.search(r"\{([^}]+)\}", _hilfe(skript))
    assert m, f"{skript}.py --help nennt keine Unterbefehle"
    return set(m.group(1).split(","))


def _aufrufe(text: str) -> list[tuple[str, str, str]]:
    """(skript, unterbefehl, ganze Zeile) für jede Aufrufzeile (`python3 …` in Blöcken) und jeden Inline-Span, in dem
    `poc.py <wort>` oder `bericht.py <wort>` steht. Fließtext in Codeblöcken (Briefing-Vorlagen) zählt nicht."""
    zeilen = [z for z in _code_zeilen(text) if z.startswith("python3")] + _code_zeilen(text, bloecke=False)
    gefunden = []
    for zeile in zeilen:
        for m in re.finditer(r"\b(poc|bericht)\.py\s+([A-Za-zÄÖÜäöüß][\w-]*)", zeile):
            gefunden.append((m.group(1), m.group(2), zeile))
    return gefunden


# ------------------------------------------------------------------------------------ Frontmatter

def test_frontmatter():
    fm = _frontmatter(_lies(SKILL_MD))
    assert fm["name"] == "security-audit"
    assert fm["model"] == "opus"
    assert fm["effort"] == "xhigh"
    assert fm["disallowed-tools"] == "WebFetch, WebSearch"
    assert fm["argument-hint"] == '[teilpfad] [projekt="…"] [repo-konfig-geprueft]'
    assert fm.get("description"), "description fehlt"


def test_frontmatter_ist_gueltiges_yaml():
    """Ungequotete Werte dürfen nicht mit `[`, `{`, `"`, `'`, `*`, `&`, `!`, `|`, `>`, `%`, `@` oder `` ` `` beginnen und
    kein `: ` oder ` #` enthalten (YAML-Plain-Scalar); mit PyYAML, falls vorhanden, wird zusätzlich echt geparst."""
    text = _lies(SKILL_MD)
    for schluessel, wert in _frontmatter_roh(text).items():
        if wert[:1] == "'":
            assert wert[-1] == "'" and len(wert) >= 2, f"{schluessel}: Anführungszeichen nicht geschlossen"
            continue
        assert wert[:1] not in set("[{\"*&!|>%@`"), f"{schluessel}: Plain-Scalar beginnt mit {wert[:1]!r}"
        assert ": " not in wert and " #" not in wert, f"{schluessel}: Plain-Scalar enthält ': ' oder ' #'"
    yaml = pytest.importorskip("yaml")
    daten = yaml.safe_load(re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL).group(1))
    assert daten["argument-hint"] == '[teilpfad] [projekt="…"] [repo-konfig-geprueft]'
    assert all(isinstance(v, str) for v in daten.values())


# ------------------------------------------------------------------------------------ Aufrufformen

def test_aufrufzeilen_skill_md():
    zeilen = _aufrufzeilen(_lies(SKILL_MD))
    assert zeilen, "SKILL.md enthält keine Aufrufzeilen"
    schlecht = [z for z in zeilen if not z.startswith(PRAEFIX_SKILL)]
    assert not schlecht, schlecht


@pytest.mark.parametrize("pfad", _referenzen() if os.path.isdir(REFERENCES) else [], ids=os.path.basename)
def test_references_platzhalter_und_aufrufzeilen(pfad):
    text = _lies(pfad)
    assert "${CLAUDE_SKILL_DIR}" not in text
    schlecht = [z for z in _aufrufzeilen(text) if not z.startswith(PRAEFIX_REFERENZ)]
    assert not schlecht, schlecht


def test_briefings_haben_aufrufzeilen_mit_platzhalter():
    assert _aufrufzeilen(_lies(BRIEFINGS)), "agenten-briefings.md enthält keine Aufrufzeilen"


def test_alle_drei_references_vorhanden():
    namen = {os.path.basename(p) for p in _referenzen()}
    assert {"agenten-briefings.md", "bericht-format.md", "pruefpunkte-web.md"} <= namen


# ------------------------------------------------------------------------------------ Unterbefehle und Optionen

@pytest.mark.parametrize("pfad", [SKILL_MD, BRIEFINGS, BERICHT_FORMAT], ids=os.path.basename)
def test_unterbefehle_existieren(pfad):
    erlaubt = {s: _unterbefehle(s) for s in SKRIPTE}
    aufrufe = _aufrufe(_lies(pfad))
    schlecht = [(s, u) for s, u, _z in aufrufe if u not in erlaubt[s]]
    assert not schlecht, schlecht


@pytest.mark.parametrize("pfad", [SKILL_MD, BRIEFINGS, BERICHT_FORMAT], ids=os.path.basename)
def test_optionen_existieren(pfad):
    """Jede `--option` einer Aufrufzeile steht in der --help des Unterbefehls."""
    hilfen: dict[tuple[str, str], str] = {}
    schlecht = []
    for skript, unter, zeile in _aufrufe(_lies(pfad)):
        if unter not in _unterbefehle(skript) or not zeile.startswith("python3"):
            continue
        hilfe = hilfen.setdefault((skript, unter), _hilfe(skript, unter))
        for option in re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", zeile):
            if option != "--help" and option not in hilfe:
                schlecht.append((skript, unter, option))
    assert not schlecht, schlecht


def test_skill_md_nennt_jeden_poc_unterbefehl():
    """Der Ablauf braucht alle Unterbefehle von poc.py und bericht.py."""
    gesehen = {(s, u) for s, u, _z in _aufrufe(_lies(SKILL_MD))}
    fehlt = [(s, u) for s in SKRIPTE for u in sorted(_unterbefehle(s)) if (s, u) not in gesehen]
    assert not fehlt, fehlt


# ------------------------------------------------------------------------------------ Abschnitte

def test_briefings_abschnitte():
    ueberschriften = re.findall(r"(?m)^## (.+?)\s*$", _lies(BRIEFINGS))
    assert "Reviewer" in ueberschriften
    assert "Prüfer" in ueberschriften


# ------------------------------------------------------------------------------------ Härtung TF1-A6

BASH_TIMEOUT = "timeout: 600000"
# laufen länger als der Bash-Standard (120 s); jeder hat ein eigenes Zeitbudget unter 600 s (Härtung B1)
LANGE_UNTERBEFEHLE = ("vorbereiten", "bauen", "starten", "neustart", "ausfuehren", "aufraeumen")
NICHT_GEPRUEFT = "nicht geprüft (Budget)"


def test_timeout_liste_nennt_alle_langen_unterbefehle_haertung_a6():
    """Jede Zeile mit dem 600000-ms-Timeout nennt alle langen poc.py-Unterbefehle (keine Teilliste in SKILL.md)."""
    zeilen = [z for z in _lies(SKILL_MD).splitlines() if BASH_TIMEOUT in z]
    assert zeilen, "kein Hinweis auf Bash-timeout 600000 in SKILL.md"
    for zeile in zeilen:
        assert all(f"poc.py {u}" in zeile for u in LANGE_UNTERBEFEHLE), zeile
        assert "bericht.py kontext" in zeile, zeile
    briefing = [z for z in _lies(BRIEFINGS).splitlines() if "timeout 600000" in z]
    assert briefing and all(u in briefing[0] for u in ("neustart", "ausfuehren"))


def test_budget_vermerk_in_skill_und_format_haertung_a6():
    """Mehr als 12 P1/P2 je Prüfer: der Grund steht in `beschreibung`, mit dem festen Vermerk."""
    for pfad in (SKILL_MD, BERICHT_FORMAT):
        assert NICHT_GEPRUEFT in _lies(pfad), pfad
    zeile = next(z for z in _lies(SKILL_MD).splitlines() if NICHT_GEPRUEFT in z)
    assert "beschreibung" in zeile and "unbestätigt" in zeile


def test_kern_behauptet_keinen_widerlegungsversuch_fuer_jedes_unbestaetigt_haertung_a6():
    """P3, ungeprüfter Rest und von der Hauptsession übernommene Aufträge sind `unbestätigt` ohne Prüfer-Widerlegung:
    der Kern-Absatz sagt das (Verweis auf `beschreibung`) und nennt den Widerlegungsversuch nur für geprüfte Befunde."""
    kern = next(z for z in _lies(SKILL_MD).splitlines() if z.startswith("**Kern:**"))
    assert "beschreibung" in kern and "geprüft" in kern
    assert "P3" in kern


def test_vorbereiten_wird_mit_dem_ermittelten_sha_aufgerufen_haertung_b3():
    """Die Arbeitskopie stammt vom SHA, den der Bericht nennt: `vorbereiten` bekommt `--sha <sha>` aus dem Kontext."""
    zeilen = [z for z in _aufrufzeilen(_lies(SKILL_MD)) if "poc.py vorbereiten" in z]
    assert zeilen and all("--sha <sha>" in z for z in zeilen), zeilen


def test_alle_hinweis_kategorien_von_poc_sind_dokumentiert_haertung_b5():
    """Jede Kategorie, die `poc.py bauen` als `hinweis:` ausgeben kann, steht in SKILL.md und im Berichtsformat."""
    import poc
    assert set(poc.HINWEIS_KATEGORIEN) >= {"native-module", "prisma-engines", "node-range-zu-lang",
                                           "node-engines-ignoriert", "lockfile-ohne-paketliste"}
    quelle = _lies(os.path.join(HIER, "poc.py"))
    verwendet = set(re.findall(r'"((?:native-module|prisma-engines|node-[a-z-]+|lockfile-ohne-[a-z-]+))"', quelle))
    assert verwendet <= set(poc.HINWEIS_KATEGORIEN), verwendet - set(poc.HINWEIS_KATEGORIEN)
    for pfad in (SKILL_MD, BERICHT_FORMAT):
        text = _lies(pfad)
        fehlt = [k for k in poc.HINWEIS_KATEGORIEN if k not in text]
        assert not fehlt, (pfad, fehlt)


def test_request_dateien_der_pruefer_kollidieren_nicht_haertung_b6():
    """Beide Prüfer laufen gleichzeitig und teilen `<DATEIORDNER>`: jeder `--daten-datei`-Name trägt die Rolle."""
    beispiele = re.findall(r"--daten-datei (\S+)", _lies(BRIEFINGS))
    assert beispiele, "kein --daten-datei-Beispiel im Prüfer-Briefing"
    assert all("<ROLLE>" in b for b in beispiele), beispiele
    assert "<ROLLE>" in next(z for z in _lies(BRIEFINGS).splitlines() if "Request-Body kommt nie per --daten" in z)


# ------------------------------------------------------------------------------------ Beispiel-JSON

def test_beispiel_json_ist_gueltig():
    """Das JSON-Beispiel in bericht-format.md besteht das Schema von bericht.py und zeigt jeden Status."""
    kandidaten = []
    for info, inhalt in _bloecke(_lies(BERICHT_FORMAT)):
        if info.startswith("json"):
            try:
                daten = json.loads(inhalt)
            except ValueError:
                continue
            if isinstance(daten, dict) and "befunde" in daten:
                kandidaten.append(daten)
    assert kandidaten, "kein vollständiges JSON-Beispiel mit `befunde` in bericht-format.md"
    daten = kandidaten[0]
    assert bericht.pruefe_schema(daten) == []
    assert {b["status"] for b in daten["befunde"]} == set(bericht.STATUS)


# ------------------------------------------------------------------------------------ Test-App nicht verraten

def _verbotene_texte() -> list[str]:
    erwartung = json.loads(_lies(ERWARTUNG))
    texte = list(erwartung.get("verbotene_muster", []))
    for eintrag in erwartung["eintraege"]:
        texte += eintrag["dateien"]
    assert texte
    return texte


@pytest.mark.parametrize("pfad", [SKILL_MD] + (_referenzen() if os.path.isdir(REFERENCES) else []), ids=os.path.basename)
def test_keine_pfade_der_test_app(pfad):
    """Beispielpfade sind neutral: weder Dateien aus evals/expected/fixture-web.json noch fixture.invalid."""
    text = _lies(pfad)
    treffer = [t for t in _verbotene_texte() if t in text]
    assert not treffer, treffer
    assert "fixture.invalid" not in text
