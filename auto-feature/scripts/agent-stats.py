#!/usr/bin/env python3
"""Agent-Statistik: Zeilen eintragen, auswerten, Thread-Tokens aus Transkripten holen.

Format und Spalten: Skill auto-feature, Abschnitt „Agent-Statistik“. Nur Standardbibliothek.

  agent-stats.py add <datei> --rolle "Review R1 Korrektheit" --typ opus-xhigh --tokens 254691 \
      --dauer 500731 --tool-uses 57 [--tf 171] [--bwk 0/1/3] [--angenommen 2] \
      [--betrieb "1: Stichwort"] [--fix-runden 1] [--status fertig] [--fortsetzung-von 3] \
      [--kopf "Repo: …" --kopf "PR: …"]
  agent-stats.py summarize <datei> [--write]
  agent-stats.py summarize-all [--root ~/.claude/agent-stats] [--seit 2026-10-22]
  agent-stats.py threads <local_…|cli-uuid|self> … [--subagents] [--md]
"""
import argparse
import datetime as dt
import glob
import json
import os
import re
import statistics
import sys

SPALTEN = ["#", "Zeitpunkt", "TF", "Rolle", "Agent-Typ", "Modell", "Effort", "tokens",
           "Δ tokens", "duration_ms", "tool_uses", "B/W/K", "angenommen", "betriebsrelevant",
           "Fix-Runden", "Status"]
TYPEN = {"opus-xhigh": ("opus", "xhigh"), "sonnet-xhigh": ("sonnet", "xhigh"),
         "sonnet-high": ("sonnet", "high")}
# Preisverhältnisse relativ zu frischem Input (Anthropic-Listenpreise, für Opus und Sonnet gleich).
FAKTOR = {"input_tokens": 1.0, "cache_creation_input_tokens": 1.25,
          "cache_read_input_tokens": 0.1, "output_tokens": 5.0}
APP_SESSIONS = os.path.expanduser("~/Library/Application Support/Claude/claude-code-sessions")
PROJECTS = os.path.expanduser("~/.claude/projects")


def zellen(zeile):
    return [z.strip() for z in zeile.strip().strip("|").split("|")]


def ist_datenzeile(zeile):
    if not zeile.lstrip().startswith("|"):
        return False
    z = zellen(zeile)
    return len(z) >= len(SPALTEN) and z[0].isdigit()


def zahl(text):
    t = text.replace("(kum.)", "").replace(".", "").replace(",", "").replace(" ", "").strip()
    return int(t) if t.isdigit() else None


def zeile_md(werte):
    return "| " + " | ".join(str(w) for w in werte) + " |"


# ---------- add ----------

def cmd_add(a):
    pfad = os.path.expanduser(a.datei)
    zeilen = open(pfad, encoding="utf-8").read().splitlines() if os.path.exists(pfad) else []
    daten = [(i, zellen(z)) for i, z in enumerate(zeilen) if ist_datenzeile(z)]

    modell, effort = TYPEN.get(a.typ, (a.modell, a.effort))
    modell, effort = a.modell or modell, a.effort or effort
    if not modell:
        sys.exit(f"Agent-Typ {a.typ!r} unbekannt: --modell angeben (und --effort, sonst „n/a“).")

    if not a.tokens.isdigit():
        tokens = delta = "n/a"  # fehlende <usage>-Angabe: nicht schätzen
    else:
        a.tokens = int(a.tokens)
        tokens, delta = str(a.tokens), a.tokens
    if a.fortsetzung_von is not None and delta != "n/a":
        vor = [z for _, z in daten if z[0] == str(a.fortsetzung_von)]
        if not vor:
            sys.exit(f"Zeile #{a.fortsetzung_von} nicht gefunden.")
        vorwert = zahl(vor[-1][7])
        # Vorwert = zuletzt gemeldeter Wert desselben Agenten (auch aus späteren Fortsetzungen).
        for _, z in daten:
            if f"Forts. #{a.fortsetzung_von}" in z[3] and zahl(z[7]) is not None:
                vorwert = zahl(z[7])
        if vorwert is not None and a.tokens >= vorwert:
            tokens, delta = f"{a.tokens} (kum.)", a.tokens - vorwert

    nr = max([int(z[0]) for _, z in daten], default=0) + 1
    rolle = a.rolle + (f" (Forts. #{a.fortsetzung_von})" if a.fortsetzung_von is not None else "")
    neu = zeile_md([nr, a.zeit or dt.datetime.now().strftime("%Y-%m-%d %H:%M"), a.tf, rolle, a.typ,
                    modell, effort or "n/a", tokens, delta,
                    a.dauer if a.dauer is not None else "n/a",
                    a.tool_uses if a.tool_uses is not None else "n/a",
                    a.bwk, a.angenommen, a.betrieb, a.fix_runden, a.status])

    if daten:
        zeilen.insert(daten[-1][0] + 1, neu)
    else:
        if not zeilen:
            zeilen = [f"# Agent-Statistik · {os.path.splitext(os.path.basename(pfad))[0]}", ""]
            zeilen += [f"- {k}" for k in a.kopf] + ([""] if a.kopf else [])
        zeilen += ["## Agenten", "", zeile_md(SPALTEN), zeile_md(["---"] * len(SPALTEN)), neu]
    os.makedirs(os.path.dirname(pfad) or ".", exist_ok=True)
    with open(pfad, "w", encoding="utf-8") as f:
        f.write("\n".join(zeilen) + "\n")
    print(f"#{nr} eingetragen: {rolle} · {a.typ} · Δ {delta}")


# ---------- summarize ----------

def gruppe(rolle):
    r = re.sub(r"\s*\(.*?\)", "", rolle).strip()
    if r.startswith("Review R1"):
        # Fokus mitführen (erstes Wort), damit sich die Fokusse vergleichen lassen.
        fokus = r[len("Review R1"):].split()
        return "Review R1 " + fokus[0].split("/")[0] if fokus else "Review R1"
    return r.split()[0] if r else "?"


def lies_zeilen(pfad):
    out = []
    for z in open(pfad, encoding="utf-8"):
        if ist_datenzeile(z):
            c = zellen(z)
            delta = zahl(c[8])
            if delta is None:
                continue
            bwk = re.search(r"(\d+)/(\d+)/(\d+)", c[11])
            betr = re.match(r"\s*(\d+)", c[13])  # „–“ = nicht erhoben
            out.append({"gruppe": gruppe(c[3]), "typ": c[4], "delta": delta,
                        "ms": zahl(c[9]), "bwk": tuple(map(int, bwk.groups())) if bwk else None,
                        "betr": int(betr.group(1)) if betr else None})
    return out


def auswertung(rows):
    gruppen = {}
    for r in rows:
        gruppen.setdefault((r["gruppe"], r["typ"]), []).append(r)
    kopf = ["Rolle", "Agent-Typ", "Läufe", "Σ Δ tokens", "Median Δ tokens", "Dauer-Median",
            "B/W/K", "B+W je 100k", "betriebsrelevant je 100k"]
    out = [zeile_md(kopf), zeile_md(["---"] * len(kopf))]
    for (g, t), v in sorted(gruppen.items(), key=lambda kv: -sum(r["delta"] for r in kv[1])):
        s = sum(r["delta"] for r in v)
        ms = [r["ms"] for r in v if r["ms"]]
        bwk = [r["bwk"] for r in v if r["bwk"]]
        b, w, k = (sum(x[i] for x in bwk) for i in range(3)) if bwk else (None, None, None)
        betr = [r["betr"] for r in v if r["betr"] is not None]
        je = lambda n: f"{100000 * n / s:.2f}".replace(".", ",") if s and n is not None else "–"
        out.append(zeile_md([g, t, len(v), f"{s:,}".replace(",", "."),
                             f"{int(statistics.median(r['delta'] for r in v)):,}".replace(",", "."),
                             f"{int(statistics.median(ms) / 1000)} s" if ms else "n/a",
                             f"{b}/{w}/{k}" if bwk else "–",
                             je(b + w) if bwk else "–", je(sum(betr)) if betr else "–"]))
    return out


def cmd_summarize(a):
    pfad = os.path.expanduser(a.datei)
    rows = lies_zeilen(pfad)
    if not rows:
        sys.exit("Keine auswertbaren Zeilen (Spalten wie im Format, Δ tokens als Zahl).")
    tabelle = auswertung(rows)
    if not a.write:
        print("\n".join(tabelle))
        return
    text = open(pfad, encoding="utf-8").read().splitlines()
    abschnitt = ["## Auswertung je Rolle", "", *tabelle, ""]
    start = next((i for i, z in enumerate(text) if z.startswith("## Auswertung")), None)
    if start is None:
        text += [""] + abschnitt
    else:
        ende = next((i for i in range(start + 1, len(text)) if text[i].startswith("## ")), len(text))
        text[start:ende] = abschnitt
    with open(pfad, "w", encoding="utf-8") as f:
        f.write("\n".join(text).rstrip() + "\n")
    print(f"Auswertung geschrieben: {pfad}")


def cmd_summarize_all(a):
    root = os.path.expanduser(a.root)
    rows, je_repo, dateien = [], {}, 0
    for pfad in sorted(glob.glob(os.path.join(root, "**", "*.md"), recursive=True)):
        name = os.path.basename(pfad)
        if a.seit and name[:10] < a.seit:
            continue
        r = lies_zeilen(pfad)
        if r:
            dateien += 1
            repo = os.path.relpath(pfad, root).split(os.sep)[0]
            je_repo[repo] = je_repo.get(repo, 0) + sum(x["delta"] for x in r)
            rows += r
    if not rows:
        sys.exit("Keine auswertbaren Zeilen gefunden.")
    gesamt = f"{sum(r['delta'] for r in rows):,}".replace(",", ".")
    print(f"{dateien} Dateien, {len(rows)} Läufe, Σ Δ tokens {gesamt}")
    print("Nicht im Standardformat geführte Tabellen fehlen hier.\n")
    print("\n".join(auswertung(rows)))
    print("\n| Repo | Σ Δ tokens |\n| --- | --- |")
    for repo, s in sorted(je_repo.items(), key=lambda kv: -kv[1]):
        print(f"| {repo} | {s:,} |".replace(",", "."))


# ---------- threads ----------

def cli_id(ref):
    if ref == "self":
        ref = os.environ.get("CLAUDE_CODE_HOST_SESSION_ID") or os.environ.get("CLAUDE_CODE_SESSION_ID")
        if not ref:
            sys.exit("self: weder CLAUDE_CODE_HOST_SESSION_ID noch CLAUDE_CODE_SESSION_ID gesetzt.")
    if ref.startswith("local_"):
        treffer = glob.glob(os.path.join(APP_SESSIONS, "*", "*", f"{ref}.json"))
        if not treffer:
            return None, f"{ref}: keine Sitzungsdatei der Desktop-App (gelöscht oder andere Maschine)"
        d = json.load(open(treffer[0], encoding="utf-8"))
        return d.get("cliSessionId"), d.get("title") or ref
    return ref, ref


def summe(pfad):
    je_msg = {}
    for zeile in open(pfad, encoding="utf-8"):
        try:
            e = json.loads(zeile)
        except ValueError:
            continue
        m = e.get("message") if isinstance(e, dict) else None
        if not isinstance(m, dict) or not isinstance(m.get("usage"), dict):
            continue
        # Gestreamte Antworten stehen mehrfach im Transkript: je Message-ID nur einmal zählen.
        je_msg[m.get("id") or e.get("uuid")] = (m.get("model", "?"), m["usage"])
    s = {k: 0 for k in FAKTOR}
    modelle = set()
    for modell, u in je_msg.values():
        modelle.add(modell)
        for k in FAKTOR:
            s[k] += u.get(k) or 0
    s["aufrufe"] = len(je_msg)
    s["modell"] = ",".join(sorted(m.replace("claude-", "") for m in modelle if m != "<synthetic>"))
    s["äquivalent"] = int(sum(s[k] * f for k, f in FAKTOR.items()))
    return s


def cmd_threads(a):
    kopf = ["Thread", "Modell", "API-Aufrufe", "input", "cache_write", "cache_read", "output",
            "Input-Äquivalent"]
    zeilen, gesamt = [], 0
    for ref in a.ids:
        sid, titel = cli_id(ref)
        if not sid:
            print(titel, file=sys.stderr)
            continue
        dateien = glob.glob(os.path.join(PROJECTS, "*", f"{sid}.jsonl"))
        if not dateien:
            print(f"{ref}: Transkript {sid}.jsonl nicht gefunden", file=sys.stderr)
            continue
        teile = [(f"{titel} ({ref})", dateien[0])]
        if a.subagents:
            for p in sorted(glob.glob(os.path.join(os.path.splitext(dateien[0])[0], "subagents", "agent-*.jsonl"))):
                meta = os.path.splitext(p)[0] + ".meta.json"
                m = json.load(open(meta, encoding="utf-8")) if os.path.exists(meta) else {}
                teile.append((f"  ↳ {m.get('agentType', '?')}: {m.get('description', os.path.basename(p))}", p))
        for name, p in teile:
            s = summe(p)
            gesamt += s["äquivalent"]
            zeilen.append([name, s["modell"], s["aufrufe"], s["input_tokens"],
                           s["cache_creation_input_tokens"], s["cache_read_input_tokens"],
                           s["output_tokens"], s["äquivalent"]])
    if not zeilen:
        sys.exit(1)
    if a.md:
        print(zeile_md(kopf))
        print(zeile_md(["---"] * len(kopf)))
        for z in zeilen:
            print(zeile_md([z[0], z[1]] + [f"{x:,}".replace(",", ".") for x in z[2:]]))
    else:
        for z in zeilen:
            print("\t".join(str(x) for x in z))
    gesamt = f"{gesamt:,}".replace(",", ".")
    print(f"\nΣ Input-Äquivalent {gesamt} (cache_write ×1,25, cache_read ×0,1, output ×5)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("add", help="eine Zeile eintragen (legt die Datei bei Bedarf an)")
    s.add_argument("datei")
    s.add_argument("--rolle", required=True)
    s.add_argument("--typ", required=True, help="Agent-Typ, z. B. opus-xhigh, sonnet-high")
    s.add_argument("--tokens", required=True, help="subagent_tokens aus <usage>, sonst n/a")
    s.add_argument("--dauer", type=int, help="duration_ms")
    s.add_argument("--tool-uses", type=int)
    s.add_argument("--tf", default="–")
    s.add_argument("--zeit")
    s.add_argument("--modell")
    s.add_argument("--effort")
    s.add_argument("--bwk", default="–")
    s.add_argument("--angenommen", default="–")
    s.add_argument("--betrieb", default="–", help="betriebsrelevant, Format „n: Stichwort; …“")
    s.add_argument("--fix-runden", default="–")
    s.add_argument("--status", default="fertig")
    s.add_argument("--fortsetzung-von", type=int, help="# der Erstzeile bei SendMessage-Fortsetzung")
    s.add_argument("--kopf", action="append", default=[], help="Kopfzeile bei neuer Datei (mehrfach)")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("summarize", help="Auswertung je Rolle einer Datei")
    s.add_argument("datei")
    s.add_argument("--write", action="store_true", help="Abschnitt „Auswertung je Rolle“ ersetzen")
    s.set_defaults(fn=cmd_summarize)

    s = sub.add_parser("summarize-all", help="Auswertung über alle Dateien")
    s.add_argument("--root", default="~/.claude/agent-stats")
    s.add_argument("--seit", help="nur Dateien ab diesem Datum (Dateiname YYYY-MM-DD-…)")
    s.set_defaults(fn=cmd_summarize_all)

    s = sub.add_parser("threads", help="Tokens von Threads aus ihren Transkripten")
    s.add_argument("ids", nargs="+", help="local_…-ID der Desktop-App, CLI-Session-UUID oder self")
    s.add_argument("--subagents", action="store_true", help="Subagenten je Thread einzeln aufführen")
    s.add_argument("--md", action="store_true", help="als Markdown-Tabelle")
    s.set_defaults(fn=cmd_threads)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
