---
name: feature-file
description: Use when a customer wish, call notes, feedback or a rough feature idea has to become a Feature-File for `auto-feature` ("Feature-File schreiben", "Vertrag", "Akzeptanzkriterien", "mach daraus ein Feature-File", "Backlog für den autonomen Lauf").
argument-hint: <Quelle: Pfad, Mail-Text oder Stichworte>
model: opus
effort: xhigh
---

# Feature-File erstellen

Eingang: `$ARGUMENTS`

**Kern:** Das Feature-File ist das Approval für einen Lauf ohne Rückfragen. Alles, was nur der User oder der Kunde entscheiden kann, wird **hier** geklärt. Was Code, Recherche oder Spec klären können, wird nicht gefragt, sondern als `Default` vorgeschlagen.

**Pflicht vor dem ersten Satz des Files:** Vorlage und Regeln in `~/.claude/skills/auto-feature/references/feature-file.md` vollständig lesen. Das File folgt ihnen ohne Ausnahme.

## Ablauf

1. **Eingang und Repo lesen:** Quelle (Mail, Call-Notiz, Kundendoc), Repo-`CLAUDE.md`, vorhandene Feature-Files des Repos (Ablage und Ton übernehmen).
2. **Ist-Stand erheben, bevor gefragt wird.** Je Wunsch im Code suchen, was es schon gibt: Datei mit Zeile, Spalte, Config-Wert, Abhängigkeit. Ergebnis je Fund: übernehmen, erweitern oder ersetzen. Wer erst fragt und dann liest, fragt nach Dingen, die schon gebaut sind.
3. **Zuschneiden:** Teilfeatures mit je einem Nutzen, ein TF ergibt einen PR. Reihenfolge nach Nutzen und Abhängigkeit vorschlagen.
4. **Interview:** Jede Entscheidung, die beim Zuschnitt und Ist-Stand anfällt, wird einer von zwei Klassen zugeordnet:
   - **Frage an den User:** alles, was Kunden oder Nutzer sehen oder bemerken. Dazu zählen: wer etwas einstellen oder sehen darf, Oberfläche oder Skript, Umfang je Helfer oder Kunde, Texte und Begriffe für Kunden, Daten und Aufbewahrung, Kosten und Anbieter, Grenzen des Laufs. Hat der Agent eine Empfehlung, bleibt es trotzdem eine Frage.
   - **`Default` des Workflows:** alles, was nur Code und Betrieb betrifft (Bibliothek, Speicherort, Erzeugung bei Abruf oder im Job).
   - Ebenfalls Fragen an den User: eine Antwort, die zwei Lesarten zulässt („pro Org“ als ein Schalter oder als einer je Helfer?), und Fakten, die nicht im Repo stehen (welche Kunden oder Bestandsdaten betroffen sind).
   - Je Frage ein Vorschlag mit einem Satz Begründung. Fragen gebündelt stellen (`AskUserQuestion`, bis zu vier je Aufruf), nicht einzeln nacheinander.
   - Antworten des Users oder Kunden werden `Entschieden` mit Herkunft.
   - Bleibt eine Frage unbeantwortet: `Default` mit `offen: <Frage>`.
5. **Recherche je TF** (Web, aktuell, mit Datum): typische Fehlerpfade, Grenzfälle, Sicherheits- und Rechtsanforderungen für genau dieses Problem. Rechtsrahmen nach `~/.claude/CLAUDE.md`.
   - Ein recherchierter Punkt kommt nur ins File, wenn er in **dieser** App ein konkretes Fehlerszenario hat und sich prüfen lässt. Er steht als `Default` mit `(Recherche: <Quelle>)`, nie als `Entschieden`.
   - Was die Recherche nicht trägt, bleibt draußen. Kein Kriterienkatalog „der Vollständigkeit halber“.
6. **Schreiben** nach der Vorlage. Ablage nach Repo-Konvention, sonst `docs/features/<YYYY-MM-DD>-<thema>.md`. `Freigabe` bleibt leer.
7. **Builder-Check:** ein frischer `Agent(subagent_type: "opus-xhigh", model: "opus")` (siehe unten). Die Hauptsession urteilt über jeden Befund (`superpowers:receiving-code-review`):
   - Faktenfehler gegen den Code: korrigieren.
   - Lücken, die nur User oder Kunde schließen können: als eine gebündelte Rückfrage an den User.
   - Alle übrigen Lücken: selbst als `Default` mit Begründung entscheiden.
   - Ergebnis in die Kopfzeile `Builder-Check`. Ein zweiter Check nur, wenn der erste Faktenfehler im Ist-Stand fand.
8. **Freigabe:** Dem User zeigen: TFs mit Reihenfolge, alle `Entschieden`, alle `Default` mit `offen:`, „Nicht in diesem File“, Ergebnis des Builder-Checks. `Freigabe: <Datum>, <Name>` erst nach ausdrücklichem OK eintragen. Commit oder PR nur auf Ansage.
   - Letzte Zeile: „Start: `/auto-feature <pfad>`“.

## Builder-Check: Briefing

- Pfad des Feature-Files, Repo-`CLAUDE.md`, Vorlage `~/.claude/skills/auto-feature/references/feature-file.md`, Hinweis auf `~/.claude/skills/auto-feature/SKILL.md` (wie der Lauf arbeitet).
- Auftrag: „Du sollst dieses File ohne jede Rückfrage bis zum PR umsetzen. Prüfe, ob das geht.“ Gesucht sind:
  - Faktenfehler im Ist-Stand gegen den echten Code, mit Datei und Zeile
  - Stellen, an denen der Lauf raten müsste, jeweils mit der Frage, die er stellen würde
  - Widersprüche zwischen TFs, zu `CLAUDE.md` oder zum Rahmen
  - DoD-Punkte ohne beobachtbares Verhalten oder ohne Nachweis
  - Verstöße gegen die Regeln der Vorlage
- Ausgabe: Liste mit Fundstelle, je Befund „Faktenfehler“, „Frage“, „Widerspruch“, „DoD“ oder „Vorlage“, dazu die Einschätzung, ob er im Betrieb sichtbar würde.
- Ändert nichts, keine git-Befehle außer lesenden, keine Subagenten.
- Agent-Statistik nach `~/.claude/CLAUDE.md`: Rolle `Builder-Check`, Ablage `~/.claude/agent-stats/<repo>/<YYYY-MM-DD>-<thema>-feature-file.md`, per `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py add …`.

## Fehler, die vorkommen

| Fehler | Stattdessen |
|---|---|
| Fragen stellen, die ein Blick in den Code beantwortet | Ist-Stand zuerst (Schritt 2) |
| Recherche-Ergebnisse als `Entschieden` | Recherche ist immer `Default` mit Quelle |
| DoD „funktioniert zuverlässig“, „ist sicher“ | beobachtbares Verhalten mit ID und `[Test]`/`[Durchklick]`/`[Ops]` |
| Offene Frage im File stehen lassen | `Default` mit `offen: …`, der Lauf berichtet sie |
| Andockpunkte, Härtungsschwerpunkte, Review Focus, Effort, Tasks im File | genau die Abschnitte der Vorlage, der Rest entsteht in Spec und Plan des Laufs |
| Sichtbare Produktentscheidung selbst getroffen („per Skript statt Oberfläche“) | Frage an den User mit Vorschlag |
| Bugfix mit zwanzig Kriterien | Größe passend zum Problem |
| Freigabe-Zeile vorab ausfüllen | erst nach ausdrücklichem OK |
