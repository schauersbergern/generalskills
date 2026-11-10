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


def _frontmatter(text: str) -> dict[str, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "Frontmatter fehlt"
    werte = {}
    for zeile in m.group(1).split("\n"):
        schluessel, doppelpunkt, wert = zeile.partition(":")
        if doppelpunkt:
            werte[schluessel.strip()] = wert.strip()
    return werte


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
