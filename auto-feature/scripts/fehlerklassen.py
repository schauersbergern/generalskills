#!/usr/bin/env python3
"""Kandidatendatei für neue Fehlerklassen (Retro in auto-feature, pr-review-loop, fix-findings).

  liste  <datei> [--status offen]     eine Zeile je Kandidat: ID · Status · Klasse · Belege: n
  neu    <datei>   < block(s)         Kandidaten mit Kopf „## K-? · <Klasse>“ anhängen, IDs vergeben, IDs ausgeben
  beleg  <datei> K-<n> < zeile        weiteren Beleg („- Beleg: …“) an einen Kandidaten hängen
  status <datei> K-<n> <status> [vermerk]   offen | übernommen | verworfen (übernommen/verworfen mit Vermerk)

Schreibende Befehle halten eine Sperre auf <datei>.lock, damit parallele Review-Threads keine ID doppelt vergeben.
Nur Python-Standardbibliothek.
"""
import argparse
import fcntl
import os
import re
import sys
import tempfile

KOPF_RE = re.compile(r"^## (K-(\d+|\?)) · (.+)$")
FELDER = ("Beleg", "Durchgerutscht", "Prüfpunkt", "Deterministisch", "Status")
BELEG_RE = re.compile(r"^- Beleg: .*`[^`]+(?::\d+(?:[-–]\d+)?| §[^`]+)`.*\b\d{4}-\d{2}-\d{2}\b")
PRUEF_RE = re.compile(r"^- Prüfpunkt \(.+?\): .*„.+“")
ZEILE_RE = re.compile(r"^- (?:(Beleg|Durchgerutscht|Deterministisch|Status): |(Prüfpunkt) \(.+\): )\S")
FORTSETZUNG_RE = re.compile(r"^  \S")
STATUS = ("offen", "übernommen", "verworfen")


def fehler(text):
    print(f"fehlerklassen.py: {text}", file=sys.stderr)
    sys.exit(1)


def lies(pfad):
    if not os.path.isfile(pfad):
        fehler(f"Datei fehlt: {pfad}")
    with open(pfad, encoding="utf-8") as f:
        return f.read().splitlines()


def schreibe(pfad, zeilen):
    ordner = os.path.dirname(os.path.abspath(pfad))
    fd, tmp = tempfile.mkstemp(dir=ordner, prefix=".kandidaten-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(zeilen).rstrip("\n") + "\n")
    os.replace(tmp, pfad)


class Sperre:
    def __init__(self, pfad):
        self.pfad = pfad + ".lock"

    def __enter__(self):
        self.f = open(self.pfad, "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def kandidaten(zeilen):
    """Liste von (id, klasse, start, ende) mit ende exklusiv. Codeblöcke (Vorlage im Kopf) zählen nicht."""
    koepfe, im_code = [], False
    for i, z in enumerate(zeilen):
        if z.startswith("```"):
            im_code = not im_code
        elif not im_code and (m := KOPF_RE.match(z)):
            koepfe.append((i, m))
        elif not im_code and z.startswith("## K-"):
            fehler(f"Zeile {i + 1} sieht nach einem Kandidatenkopf aus, passt aber nicht zu „## K-<n> · <Klasse>“: {z}")
    out = []
    for n, (i, m) in enumerate(koepfe):
        ende = koepfe[n + 1][0] if n + 1 < len(koepfe) else len(zeilen)
        while ende > i + 1 and not zeilen[ende - 1].strip():
            ende -= 1
        out.append((m.group(1), m.group(3), i, ende))
    return out


def finde(zeilen, kid):
    for k in kandidaten(zeilen):
        if k[0] == kid:
            return k
    fehler(f"Kandidat {kid} nicht gefunden")


def pruefe_beleg(zeile):
    if not BELEG_RE.match(zeile):
        fehler("Beleg braucht die Form „- Beleg: <PR/Lauf> <ID> [P…], `datei:zeile`, YYYY-MM-DD — <Befund>“: "
               + zeile)


def pruefe_block(block):
    kopf = KOPF_RE.match(block[0])
    if not kopf or kopf.group(2) != "?":
        fehler(f"Block muss mit „## K-? · <Klasse>“ beginnen: {block[0]}")
    gesehen = {}
    for z in block[1:]:
        if z.lstrip().startswith("```"):
            fehler(f"{kopf.group(3)}: Zaunzeile (```) im Block, die Vorlage ohne Zaun einfügen: {z}")
        m = ZEILE_RE.match(z)
        if not m:
            if FORTSETZUNG_RE.match(z):
                continue
            fehler(f"{kopf.group(3)}: Zeile ist weder „- <Feld>: <Wert>“ mit nicht leerem Wert noch eine "
                   f"eingerückte Fortsetzung: {z}")
        feld = m.group(1) or m.group(2)
        gesehen[feld] = gesehen.get(feld, 0) + 1
        if feld == "Beleg":
            pruefe_beleg(z)
        if feld == "Prüfpunkt" and not PRUEF_RE.match(z):
            fehler(f"Prüfpunkt braucht Ort und Wortlaut: „- Prüfpunkt (<Ort>): „<Wortlaut>““: {z}")
        if feld == "Status" and z.strip() != "- Status: offen":
            fehler("Neue Kandidaten haben „- Status: offen“")
    for feld in FELDER:
        if feld not in gesehen:
            fehler(f"{kopf.group(3)}: Feld „{feld}“ fehlt")
        if feld != "Beleg" and gesehen[feld] > 1:
            fehler(f"{kopf.group(3)}: Feld „{feld}“ steht mehrfach")


def bloecke(text):
    zeilen = text.splitlines()
    start = [i for i, z in enumerate(zeilen) if z.startswith("## ")]
    if not start:
        fehler("Keine Kandidaten in der Eingabe (Kopf „## K-? · <Klasse>“)")
    davor = [z for z in zeilen[:start[0]] if z.strip()]
    if davor:
        fehler(f"Text vor dem ersten Kopf „## K-? · <Klasse>“ (Zaun der Vorlage mitkopiert?): {davor[0]}")
    out = []
    for n, i in enumerate(start):
        ende = start[n + 1] if n + 1 < len(start) else len(zeilen)
        out.append([z for z in zeilen[i:ende] if z.strip()])
    return out


def cmd_neu(a):
    neue = bloecke(sys.stdin.read())
    for b in neue:
        pruefe_block(b)
    lies(a.datei)
    with Sperre(a.datei):
        zeilen = lies(a.datei)
        hoechste = max([int(k[0][2:]) for k in kandidaten(zeilen) if k[0][2:].isdigit()], default=0)
        ids = []
        for b in neue:
            hoechste += 1
            kid = f"K-{hoechste}"
            ids.append(kid)
            zeilen += [""] + [b[0].replace("K-?", kid, 1)] + b[1:]
        schreibe(a.datei, zeilen)
    print("\n".join(ids))


def cmd_beleg(a):
    neu = [z for z in sys.stdin.read().splitlines() if z.strip()]
    if not neu:
        fehler("Kein Beleg auf stdin")
    for z in neu:
        pruefe_beleg(z)
    lies(a.datei)
    with Sperre(a.datei):
        zeilen = lies(a.datei)
        _, _, start, ende = finde(zeilen, a.id)
        belege = [i for i in range(start, ende) if zeilen[i].startswith("- Beleg")]
        pos = (belege[-1] + 1) if belege else start + 1
        zeilen[pos:pos] = neu
        schreibe(a.datei, zeilen)


def cmd_status(a):
    if a.status not in STATUS:
        fehler(f"Status muss einer von {', '.join(STATUS)} sein")
    if a.status != "offen" and not a.vermerk:
        fehler(f"„{a.status}“ braucht einen Vermerk (PR bzw. Grund)")
    if a.vermerk is not None and a.vermerk.splitlines() != [a.vermerk]:
        fehler("Der Vermerk muss eine einzelne Zeile sein, ohne Zeilenumbruch")
    lies(a.datei)
    with Sperre(a.datei):
        zeilen = lies(a.datei)
        _, _, start, ende = finde(zeilen, a.id)
        neu = f"- Status: {a.status}" + (f" ({a.vermerk})" if a.vermerk else "")
        for i in range(start, ende):
            if zeilen[i].startswith("- Status"):
                zeilen[i] = neu
                break
        else:
            zeilen.insert(ende, neu)
        schreibe(a.datei, zeilen)


def cmd_liste(a):
    zeilen = lies(a.datei)
    for kid, klasse, start, ende in kandidaten(zeilen):
        block = zeilen[start:ende]
        status = next((z[len("- Status: "):].split(" (")[0] for z in block if z.startswith("- Status: ")), "?")
        if a.status and status != a.status:
            continue
        belege = sum(1 for z in block if z.startswith("- Beleg"))
        print(f"{kid} · {status} · {klasse} · Belege: {belege}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("liste")
    s.add_argument("datei")
    s.add_argument("--status", choices=STATUS)
    s.set_defaults(f=cmd_liste)
    s = sub.add_parser("neu")
    s.add_argument("datei")
    s.set_defaults(f=cmd_neu)
    s = sub.add_parser("beleg")
    s.add_argument("datei")
    s.add_argument("id")
    s.set_defaults(f=cmd_beleg)
    s = sub.add_parser("status")
    s.add_argument("datei")
    s.add_argument("id")
    s.add_argument("status")
    s.add_argument("vermerk", nargs="?")
    s.set_defaults(f=cmd_status)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
