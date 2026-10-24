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
import stat
import statistics
import sys
import tempfile

SPALTEN = ["#", "Zeitpunkt", "TF", "Rolle", "Agent-Typ", "Modell", "Effort", "tokens",
           "Δ tokens", "duration_ms", "tool_uses", "B/W/K", "angenommen", "betriebsrelevant",
           "Fix-Runden", "Status"]
TYPEN = {"opus-xhigh": ("opus", "xhigh"), "sonnet-xhigh": ("sonnet", "xhigh"),
         "sonnet-high": ("sonnet", "high")}
# Preisverhältnisse relativ zu frischem Input desselben Modells (Anthropic-Listenpreise, für Opus und
# Sonnet gleich). Cache-Writes: 5-min-Cache ×1,25, 1-h-Cache ×2. Modelle nicht untereinander verrechnen.
FAKTOR = {"input": 1.0, "cache_write_5m": 1.25, "cache_write_1h": 2.0, "cache_read": 0.1, "output": 5.0}
MARKE, MARKE_ENDE = "<!-- agent-stats:auswertung -->", "<!-- /agent-stats:auswertung -->"
APP_SESSIONS =os.path.expanduser("~/Library/Application Support/Claude/claude-code-sessions")
PROJECTS = os.path.expanduser("~/.claude/projects")


FORTS = re.compile(r"\(Forts\. #(\d+)\)")


def zellen(zeile):
    # „\|“ ist ein Strich im Zelltext, kein Spaltentrenner.
    return [z.strip().replace("\\|", "|") for z in re.split(r"(?<!\\)\|", zeile.strip().strip("|"))]


def forts_von(rolle):
    m = FORTS.search(rolle)
    return int(m.group(1)) if m else None


def ist_datenzeile(zeile):
    if not zeile.lstrip().startswith("|"):
        return False
    z = zellen(zeile)
    return len(z) >= len(SPALTEN) and z[0].isdigit()


def zahl(text):
    t = text.replace("(kum.)", "").replace(".", "").replace(",", "").replace(" ", "").strip()
    return int(t) if t.isdigit() else None


def schreibe(pfad, zeilen):
    # Über eine Temp-Datei, damit ein Abbruch keine gekürzte Datei hinterlässt.
    ordner = os.path.dirname(pfad) or "."
    os.makedirs(ordner, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=ordner, prefix=".agent-stats-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(zeilen).rstrip() + "\n")
        if os.path.exists(pfad):
            os.chmod(tmp, stat.S_IMODE(os.stat(pfad).st_mode))
        os.replace(tmp, pfad)
    except BaseException:
        os.unlink(tmp)
        raise


def agenten_ende(zeilen):
    """Index hinter der Agenten-Tabelle: Kopf im Standardformat, sonst Block der ersten Datenzeile."""
    start = next((i for i, z in enumerate(zeilen)
                  if z.lstrip().startswith("|") and zellen(z)[:len(SPALTEN)] == SPALTEN), None)
    if start is None:
        start = next((i for i, z in enumerate(zeilen) if ist_datenzeile(z)), None)
    if start is None:
        return None
    while start + 1 < len(zeilen) and zeilen[start + 1].lstrip().startswith("|"):
        start += 1
    return start + 1


def zeile_md(werte):
    return "| " + " | ".join(str(w).replace("|", "\\|") for w in werte) + " |"


# ---------- add ----------

def cmd_add(a):
    pfad = os.path.expanduser(a.datei)
    zeilen = open(pfad, encoding="utf-8").read().splitlines() if os.path.exists(pfad) else []
    daten = [(i, zellen(z)) for i, z in enumerate(zeilen) if ist_datenzeile(z)]

    modell, effort = TYPEN.get(a.typ, (a.modell, a.effort))
    modell, effort = a.modell or modell, a.effort or effort
    if not modell:
        sys.exit(f"Agent-Typ {a.typ!r} unbekannt: --modell angeben (und --effort, sonst „n/a“).")

    if a.tokens == "n/a":
        tokens = delta = "n/a"  # fehlende <usage>-Angabe: nicht schätzen
    else:
        a.tokens = zahl(a.tokens)
        if a.tokens is None:
            sys.exit("--tokens: keine Zahl. Fehlt die <usage>-Angabe, „n/a“ angeben.")
        tokens, delta = str(a.tokens), a.tokens
    erst = a.fortsetzung_von
    if erst is not None:
        vor = [z for _, z in daten if z[0] == str(erst)]
        if not vor:
            sys.exit(f"Zeile #{erst} nicht gefunden.")
        # Fortsetzung einer Fortsetzung: auf die Erstzeile des Agenten normalisieren.
        erst = forts_von(vor[-1][3]) or erst
    if erst is not None and delta != "n/a":
        # Vorwert = zuletzt gemeldeter Wert desselben Agenten (Erstzeile oder eine ihrer Fortsetzungen).
        werte = [zahl(z[7]) for _, z in daten if z[0] == str(erst) or forts_von(z[3]) == erst]
        werte = [w for w in werte if w is not None]
        if werte and a.tokens >= werte[-1]:
            tokens, delta = f"{a.tokens} (kum.)", a.tokens - werte[-1]

    nr = max([int(z[0]) for _, z in daten], default=0) + 1
    rolle = a.rolle + (f" (Forts. #{erst})" if erst is not None else "")
    neu = zeile_md([nr, a.zeit or dt.datetime.now().strftime("%Y-%m-%d %H:%M"), a.tf, rolle, a.typ,
                    modell, effort or "n/a", tokens, delta,
                    a.dauer if a.dauer is not None else "n/a",
                    a.tool_uses if a.tool_uses is not None else "n/a",
                    a.bwk, a.angenommen, a.betrieb, a.fix_runden, a.status])

    ende = agenten_ende(zeilen)
    if ende is not None:
        zeilen.insert(ende, neu)
    else:
        if not zeilen:
            zeilen = [f"# Agent-Statistik · {os.path.splitext(os.path.basename(pfad))[0]}", ""]
            zeilen += [f"- {k}" for k in a.kopf] + ([""] if a.kopf else [])
        else:
            zeilen.append("")
        zeilen += ["## Agenten", "", zeile_md(SPALTEN), zeile_md(["---"] * len(SPALTEN)), neu]
    schreibe(pfad, zeilen)
    print(f"#{nr} eingetragen: {rolle} · {a.typ} · Δ {delta}")


# ---------- summarize ----------

def gruppe(rolle):
    r = re.sub(r"\s*\(.*?\)", "", rolle).strip()
    if r.startswith("Review R1"):
        # Fokus mitführen (erstes Wort), damit sich die Fokusse vergleichen lassen.
        fokus = r[len("Review R1"):].split()
        return "Review R1 " + fokus[0].split("/")[0] if fokus else "Review R1"
    return r.split()[0] if r else "?"


def lies_zeilen(pfad, uebersprungen=None):
    """Datenzeilen mit Δ als Zahl; die übrigen landen als „#n“ in uebersprungen."""
    out = []
    for z in open(pfad, encoding="utf-8"):
        if ist_datenzeile(z):
            c = zellen(z)
            delta = zahl(c[8])
            if delta is None:
                if uebersprungen is not None:
                    uebersprungen.append(f"#{c[0]} (Δ {c[8]})")
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
    # Raten je 100k nur über Läufe mit erhobenem Wert („–“ = nicht erhoben, nicht 0); dahinter
    # steht, wie viele Läufe der Gruppe erhoben sind.
    kopf = ["Rolle", "Agent-Typ", "Läufe", "Σ Δ tokens", "Median Δ tokens", "Dauer-Median",
            "B/W/K", "B+W je 100k (erhoben)", "betriebsrelevant je 100k (erhoben)"]
    out = [zeile_md(kopf), zeile_md(["---"] * len(kopf))]
    for (g, t), v in sorted(gruppen.items(), key=lambda kv: -sum(r["delta"] for r in kv[1])):
        s = sum(r["delta"] for r in v)
        ms = [r["ms"] for r in v if r["ms"]]
        mit_bwk = [r for r in v if r["bwk"]]
        b, w, k = (sum(r["bwk"][i] for r in mit_bwk) for i in range(3))
        mit_betr = [r for r in v if r["betr"] is not None]

        def je(n, erhoben):
            nenner = sum(r["delta"] for r in erhoben)
            if not nenner:
                return "–"
            return f"{100000 * n / nenner:.2f}".replace(".", ",") + f" ({len(erhoben)} von {len(v)})"

        out.append(zeile_md([g, t, len(v), f"{s:,}".replace(",", "."),
                             f"{int(statistics.median(r['delta'] for r in v)):,}".replace(",", "."),
                             f"{int(statistics.median(ms) / 1000)} s" if ms else "n/a",
                             f"{b}/{w}/{k}" if mit_bwk else "–",
                             je(b + w, mit_bwk), je(sum(r["betr"] for r in mit_betr), mit_betr)]))
    return out


def cmd_summarize(a):
    pfad = os.path.expanduser(a.datei)
    weg = []
    rows = lies_zeilen(pfad, weg)
    if weg:
        print(f"Nicht ausgewertet: {', '.join(weg)}", file=sys.stderr)
    if not rows:
        sys.exit("Keine auswertbaren Zeilen (Spalten wie im Format, Δ tokens als Zahl).")
    tabelle = auswertung(rows)
    if not a.write:
        print("\n".join(tabelle))
        return
    text = open(pfad, encoding="utf-8").read().splitlines()
    # Nur den eigenen, markierten Block ersetzen; fremder Text und Datenzeilen bleiben stehen.
    block = [MARKE, *tabelle, MARKE_ENDE]
    start = next((i for i, z in enumerate(text) if z.strip() == MARKE), None)
    ende = next((i for i in range(start + 1, len(text)) if text[i].strip() == MARKE_ENDE), None) \
        if start is not None else None
    if ende is None:
        text += ["", "## Auswertung je Rolle", "", *block]
    else:
        text[start:ende + 1] = block
    schreibe(pfad, text)
    print(f"Auswertung geschrieben: {pfad}")


def cmd_summarize_all(a):
    root = os.path.expanduser(a.root)
    rows, je_repo, dateien, ohne, weg = [], {}, 0, [], 0
    for pfad in sorted(glob.glob(os.path.join(root, "**", "*.md"), recursive=True)):
        name = os.path.basename(pfad)
        if a.seit and name[:10] < a.seit:
            continue
        uebersprungen = []
        r = lies_zeilen(pfad, uebersprungen)
        weg += len(uebersprungen)
        if r:
            dateien += 1
            repo = os.path.relpath(pfad, root).split(os.sep)[0]
            je_repo[repo] = je_repo.get(repo, 0) + sum(x["delta"] for x in r)
            rows += r
        else:
            ohne.append(os.path.relpath(pfad, root))
    if ohne:
        print(f"Ohne auswertbare Zeilen (nicht im Standardformat?), {len(ohne)} Dateien: {', '.join(ohne)}",
              file=sys.stderr)
    if weg:
        print(f"{weg} Datenzeilen ohne Δ als Zahl nicht ausgewertet.", file=sys.stderr)
    if not rows:
        sys.exit("Keine auswertbaren Zeilen gefunden.")
    gesamt = f"{sum(r['delta'] for r in rows):,}".replace(",", ".")
    print(f"{dateien} Dateien, {len(rows)} Läufe, Σ Δ tokens {gesamt}\n")
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
        if m.get("model") == "<synthetic>":  # lokal erzeugt, kein API-Aufruf
            continue
        # Gestreamte Antworten stehen mehrfach im Transkript: je Message-ID nur einmal zählen.
        je_msg[m.get("id") or e.get("uuid")] = (m.get("model", "?"), m["usage"], m.get("stop_reason"))
    s = {k: 0 for k in FAKTOR}
    s["je_modell"], s["ohne_stop"] = {}, 0
    for modell, u, stop in je_msg.values():
        cc = u.get("cache_creation") if isinstance(u.get("cache_creation"), dict) else {}
        if "ephemeral_1h_input_tokens" in cc or "ephemeral_5m_input_tokens" in cc:
            w5m, w1h = cc.get("ephemeral_5m_input_tokens") or 0, cc.get("ephemeral_1h_input_tokens") or 0
        else:  # ältere Transkripte ohne Aufteilung: als 5-min-Cache werten
            w5m, w1h = u.get("cache_creation_input_tokens") or 0, 0
        werte = {"input": u.get("input_tokens") or 0, "cache_write_5m": w5m, "cache_write_1h": w1h,
                 "cache_read": u.get("cache_read_input_tokens") or 0, "output": u.get("output_tokens") or 0}
        for k in FAKTOR:
            s[k] += werte[k]
        name = modell.replace("claude-", "")
        s["je_modell"][name] = s["je_modell"].get(name, 0) + sum(werte[k] * f for k, f in FAKTOR.items())
        if stop is None:
            s["ohne_stop"] += 1
    s["aufrufe"] = len(je_msg)
    s["modell"] = ",".join(sorted(s["je_modell"]))
    s["äquivalent"] = int(sum(s["je_modell"].values()))
    return s


def cmd_threads(a):
    kopf = ["Thread", "Modell", "API-Aufrufe", "input", "cache_write_5m", "cache_write_1h", "cache_read",
            "output", "Input-Äquivalent"]
    zeilen, je_modell, fehlt = [], {}, []
    for ref in a.ids:
        sid, titel = cli_id(ref)
        dateien = glob.glob(os.path.join(PROJECTS, "*", f"{sid}.jsonl")) if sid else []
        if not dateien:
            grund = titel if not sid else f"Transkript {sid}.jsonl nicht gefunden"
            print(grund, file=sys.stderr)
            fehlt.append(ref)
            zeilen.append([f"{ref}: fehlt ({grund})"] + ["–"] * (len(kopf) - 1))
            continue
        # Nach einem Worktree-Wechsel liegt das Transkript in mehreren Projektordnern; die älteren
        # Kopien sind Präfixe der aktuellen, also die längste nehmen.
        transkript = max(dateien, key=os.path.getsize)
        teile = [(f"{titel} ({ref})", transkript)]
        if a.subagents:
            for p in sorted(glob.glob(os.path.join(os.path.splitext(transkript)[0], "subagents", "agent-*.jsonl"))):
                meta = os.path.splitext(p)[0] + ".meta.json"
                m = json.load(open(meta, encoding="utf-8")) if os.path.exists(meta) else {}
                teile.append((f"  ↳ {m.get('agentType', '?')}: {m.get('description', os.path.basename(p))}", p))
        for name, p in teile:
            s = summe(p)
            for modell, x in s["je_modell"].items():
                je_modell[modell] = je_modell.get(modell, 0) + x
            if s["ohne_stop"]:
                print(f"{name.strip()}: {s['ohne_stop']} von {s['aufrufe']} Aufrufen ohne stop_reason "
                      "(nur Stream-Anfang im Transkript), output dort unterschätzt", file=sys.stderr)
            zeilen.append([name, s["modell"], s["aufrufe"], *(s[k] for k in FAKTOR), s["äquivalent"]])
    tausend = lambda x: f"{int(x):,}".replace(",", ".") if isinstance(x, (int, float)) else x
    if a.md:
        print(zeile_md(kopf))
        print(zeile_md(["---"] * len(kopf)))
        for z in zeilen:
            print(zeile_md([z[0], z[1]] + [tausend(x) for x in z[2:]]))
    else:
        for z in zeilen:
            print("\t".join(str(x) for x in z))
    print()
    for modell, x in sorted(je_modell.items()):
        print(f"Σ Input-Äquivalent {modell}: {tausend(x)}")
    print("(relativ zum Input-Preis des jeweiligen Modells: cache_write_5m ×1,25, cache_write_1h ×2, "
          "cache_read ×0,1, output ×5; Modelle nicht addieren)")
    if fehlt:
        sys.exit(f"Fehlend: {', '.join(fehlt)}")


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
