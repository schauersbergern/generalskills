#!/usr/bin/env python3
"""KI-Erkennung für den Skill security-audit (nur Standardbibliothek).

Aufruf (immer als einzelner einfacher Befehl, siehe Netzregel):
  python3 -I ki.py erkennen --lauf <id> --quelle <arbeitskopie>

`erkennen` (Budget 30 s, `SECURITY_AUDIT_KI_BUDGET` darf nur verkürzen) liest alle `package.json` der Arbeitskopie (rekursiv, ohne
`node_modules`, `.git` und Symlinks, nur reguläre Dateien bis 1 MiB; Suche, Pfadregeln und Lesen wie bei `lieferkette.py
lieferkette`) und prüft die Namen in `dependencies`, `devDependencies`, `optionalDependencies` und `peerDependencies` gegen die
feste SDK-Liste unten (`@scope/` heißt: jeder Name in diesem Scope). Der Befehl startet keinen Kindprozess, geht nicht ins Netz
und schreibt nichts. Übernommen wird nur, was der npm-Namensregel entspricht; alles andere wird gezählt (Hinweis) und nie
ausgegeben.

Ausgabe (JSON auf stdout): `anwendbar` (bool), `sdks` (Liste aus `paket` und `datei`, höchstens 50, sortiert) und `hinweise`. Der
Erkennungshinweis steht immer an erster Stelle und wird von der Hauptsession wörtlich übernommen:
  „KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)“
  „KI-Prüfpunkte: angewendet (<bis zu 5 Paketnamen, sortiert, eindeutig, mit `, ` getrennt>)“

Exit-Codes: 0 ok, 2 ungültige Argumente (auch `--quelle` ≠ Arbeitskopie des Laufs, `quelle.fertig` fehlt), 1 das Zeitbudget ist
abgelaufen, bevor ein SDK gefunden wurde (Meldung auf stderr; die Hauptsession schreibt „ki.py erkennen fehlgeschlagen (Exit 1)“).
Ist beim Ablauf schon ein SDK gefunden, endet der Befehl mit Exit 0, `anwendbar: true` und dem Zusatzhinweis „KI-Erkennung
abgebrochen (Zeitbudget)“.

Die Helfer (Arbeitskopie prüfen, Budget, Verzeichnissuche, Lesen, Namensregel) stammen aus `lieferkette.py` und werden nur
importiert.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc  # noqa: E402
from lieferkette import (  # noqa: E402
    ABHAENGIGKEIT_FELDER, NPM_PAKETNAME, PAKETNAME_MAX, _arbeitskopie, _ausgabe, _baum_suchen, _je_datei, _lese_text, _Sammler,
    _sekunden, _Zeit, _zeitcheck)
from poc import PocFehler  # noqa: E402

KI_BUDGET = 30                  # Sekunden für `erkennen` insgesamt (rein statisch, kein Kindprozess)
MAX_SDKS = 50                   # Einträge in `sdks`
MAX_NAMEN_IM_HINWEIS = 5        # Paketnamen im Erkennungshinweis
ZEIT_HINWEIS = "KI-Erkennung abgebrochen (Zeitbudget)"
HINWEIS_NICHT_ANWENDBAR = "KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)"

# Feste SDK-Liste (Spec §1): exakte Namen und Scopes (`@scope/` = jeder Name in diesem Scope).
SDK_EXAKT = frozenset((
    "openai", "@azure/openai",                                                              # OpenAI
    "ai",                                                                                   # Vercel AI SDK
    "langchain",                                                                            # LangChain
    "llamaindex",                                                                           # LlamaIndex
    "fastmcp",                                                                              # MCP
    "@google/generative-ai", "@google/genai", "@google-cloud/vertexai",                    # Google
    "@mistralai/mistralai", "cohere-ai", "groq-sdk", "ollama", "@huggingface/inference",   # weitere Anbieter
    "replicate", "@aws-sdk/client-bedrock-runtime",
    "genkit",                                                                               # Frameworks
))
SDK_SCOPES = ("@openai/", "@anthropic-ai/", "@ai-sdk/", "@langchain/", "@llamaindex/", "@modelcontextprotocol/",
              "@openrouter/", "@mastra/", "@genkit-ai/")


def _budget() -> float:
    return _sekunden("SECURITY_AUDIT_KI_BUDGET", KI_BUDGET)


def _gueltiger_name(name: object) -> bool:
    return isinstance(name, str) and len(name) <= PAKETNAME_MAX and NPM_PAKETNAME.fullmatch(name) is not None


def _ist_sdk(name: str) -> bool:
    return name in SDK_EXAKT or any(name.startswith(scope) and len(name) > len(scope) for scope in SDK_SCOPES)


class _Funde:
    def __init__(self) -> None:
        self.paare: set[tuple[str, str]] = set()      # (Paket, Datei)
        self.ungueltig = 0                            # Namen, die die npm-Namensregel ablehnt

    def datei(self, rel: str, daten: dict) -> None:
        for feld in ABHAENGIGKEIT_FELDER:
            deps = daten.get(feld)
            if not isinstance(deps, dict):
                continue
            for name in deps:
                if not _gueltiger_name(name):
                    self.ungueltig += 1
                elif _ist_sdk(name):
                    self.paare.add((name, rel))


def _auswerten(quelle: str, ende: float, s: _Sammler, f: _Funde) -> None:
    baum = _baum_suchen(quelle, ende, s)
    for rel, groesse in baum.pakete:
        _zeitcheck(ende)

        def lesen(rel=rel, groesse=groesse) -> None:
            text = _lese_text(quelle, rel, groesse, s)
            if text is None:
                return
            daten = json.loads(text.lstrip("\ufeff"))   # UTF-8-BOM (Task-2-Review Minor 1)
            if not isinstance(daten, dict):
                raise TypeError(type(daten).__name__)
            f.datei(rel, daten)

        _je_datei(s, rel, lesen)


def cmd_erkennen(a: argparse.Namespace) -> int:
    _, quelle = _arbeitskopie(a.lauf, a.quelle)
    ende = time.monotonic() + _budget()
    s = _Sammler()
    f = _Funde()
    abgebrochen = False
    try:
        _auswerten(quelle, ende, s, f)
    except _Zeit:
        abgebrochen = True
    if abgebrochen and not f.paare:
        raise PocFehler("KI-Erkennung abgebrochen (Zeitbudget), bevor ein SDK gefunden wurde; kein Ergebnis", code=1)
    # Task-2-Review Minor 2: unvollständige Suche (Kappung, Fehler im Verzeichnislauf) ohne Fund ist kein „nicht anwendbar“
    if not f.paare and any(h.endswith("weitere Dateien nicht geprüft") for h in s.hinweise):
        raise PocFehler("KI-Erkennung unvollständig (Verzeichnissuche abgebrochen), bevor ein SDK gefunden wurde; kein Ergebnis",
                        code=1)
    sdks = sorted(f.paare)
    if sdks:
        namen = sorted({p for p, _ in sdks})[:MAX_NAMEN_IM_HINWEIS]
        erkennung = f"KI-Prüfpunkte: angewendet ({', '.join(namen)})"
    else:
        erkennung = HINWEIS_NICHT_ANWENDBAR
    hinweise = [erkennung]
    if abgebrochen:
        hinweise.append(ZEIT_HINWEIS)
    hinweise.extend(s.abschluss())
    if f.ungueltig:
        hinweise.append(f"{f.ungueltig} ungültige Paketnamen übersprungen")
    if len(sdks) > MAX_SDKS:
        hinweise.append(f"{len(sdks)} SDK-Funde, nur {MAX_SDKS} aufgelistet")
    _ausgabe({"anwendbar": bool(sdks), "sdks": [{"paket": p, "datei": d} for p, d in sdks[:MAX_SDKS]], "hinweise": hinweise})
    return 0


# ------------------------------------------------------------------------------------ Argumente

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ki.py", allow_abbrev=False, description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="unterbefehl", required=True)
    s = sub.add_parser("erkennen", allow_abbrev=False, help="LLM- und Agenten-SDKs in package.json erkennen")
    s.set_defaults(fn=cmd_erkennen)
    s.add_argument("--lauf", required=True, type=poc._typ_lauf)
    s.add_argument("--quelle", required=True, help="Arbeitskopie des Laufs (`<zustand>/quelle`)")
    return p


def main(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    try:
        return a.fn(a)
    except PocFehler as e:
        print(f"ki.py: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
