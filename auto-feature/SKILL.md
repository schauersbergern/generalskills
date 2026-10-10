---
name: auto-feature
description: Use when Nikolaus hands over a feature file (Feature-File, Master-Spec, Backlog with several Teilfeatures) to be implemented autonomously ("autonom umsetzen", "voll autonom", "ich bin bis morgen weg"), from spec through pull requests without further user input.
argument-hint: <Pfad zum Feature-File>
model: opus
effort: xhigh
---

# Autonomer Feature-Workflow

Feature-File: `$ARGUMENTS`

**Kern:** Das Feature-File ersetzt den Dialog und ist das Approval.
- **Pro Teilfeature:** Spec → Spec-Review → Plan → Plan-Review → Umsetzung durch Sonnet-Subagenten → Härtungsdurchgang → Verifikation → PR.
- **Ohne Zwischenhalt:** Der Lauf geht vom Feature-File bis zu 1…n PRs durch.
- **Dann harter Stopp (HITL):** Nikolaus prüft den Reasoning-Weg und stößt selbst `/pr-review-loop` an. Merge und Deploy gehören ihm.

**Modelle und Effort:** Spec und Plan schreibt die Hauptsession mit **Opus 5.5** (Skill-Frontmatter `model: opus`). Reviews machen frische Opus-Subagenten, die Umsetzung macht **Sonnet 5.5**, subagent-driven. **Alles mit Effort `xhigh`**: die Hauptsession über das Skill-Frontmatter, die Subagenten über die Agent-Typen `opus-xhigh` und `sonnet-xhigh` (aus `~/.claude/agents/`). Fehlt ein Typ in der Liste der verfügbaren Agents: `general-purpose` mit demselben `model` und „Effort nicht garantiert“ im Abschlussbericht.

**Projektspezifisches** liefert das Repo-`CLAUDE.md`: Befehle, Konventionen, Pfade, Teststrategie. Dieser Skill liefert den Ablauf. Weicht ein anderes Workflow-Dokument im Repo davon ab (nicht `CLAUDE.md`), gilt dieser Skill. Die Abweichung kommt in den Abschlussbericht.

## Start

1. Das Feature-File und `CLAUDE.md` vollständig lesen. In Teilfeatures (TF) zerlegen. Reihenfolge und Abhängigkeiten aus dem File übernehmen. Ein TF ergibt einen PR.
2. Voraussetzungen prüfen:
   - `gh auth status` und ein Remote vorhanden.
   - Prüfbefehle bekannt: aus `CLAUDE.md`, ergänzt um Typecheck/Build, falls `package.json`/`Makefile`/`pyproject.toml`/CI-Konfiguration sie haben.
   - Abhängigkeiten zwischen TFs: Nennt das File keine, aus dem Inhalt ableiten und begründen.
3. **Kein Stopp vor den PRs**, auch wenn Nikolaus online ist. Widersprüche oder Lücken, die sich nicht aus File und Code lösen lassen, werden nicht erfragt. Eine Frage würde den Turn beenden und den Lauf anhalten.
   - Stattdessen den vorsichtigsten umkehrbaren Default wählen und als Annahme dokumentieren.
   - Die offene Frage kommt in den Abschlussbericht.
   - **Fehlen Zugangsdaten oder Anbieterwahl nur für den Betrieb:** hinter einer Schnittstelle mit Stub-Adapter bauen und testen. Live-Schaltung und Anbieterwahl kommen als offene Entscheidung in den Abschlussbericht, besonders bei Kosten oder personenbezogenen Daten (AV-Vertrag).
   - **Lässt sich ein TF auch so nicht bauen oder testen** (kein Remote, keine Zugriffsrechte): dieses TF und seine Abhängigen überspringen, die anderen umsetzen und das Übersprungene melden.
   - Alles Übrige entscheidest du selbst mit begründetem Default und hältst es in der Spec unter „Entscheidungen/Annahmen“ fest.
4. Ein Todo pro TF anlegen. Unabhängige TFs dürfen in eigenen Worktrees parallel laufen (`superpowers:using-git-worktrees`), abhängige laufen in Reihenfolge.

## Phasen je Teilfeature

| Phase | Wer | Regel |
|---|---|---|
| A Spec | Hauptsession (**Opus 5.5**) · `superpowers:brainstorming` im Autonom-Modus | Repo-Konvention, sonst `docs/superpowers/specs/<YYYY-MM-DD>-<tf>-design.md` (Ordner ggf. anlegen); Ziel, Andockpunkte mit Pfaden, Abnahmekriterien aus der DoD; Commit auf dem TF-Branch |
| B Spec-Review | frischer `opus-xhigh`-Subagent je Runde | **max. 2 Runden** |
| C Plan | Hauptsession (**Opus 5.5**) · `superpowers:writing-plans` | Repo-Konvention, sonst `docs/superpowers/plans/<YYYY-MM-DD>-<tf>.md`; TDD-Tasks mit exakten Pfaden; Commit auf dem TF-Branch |
| D Plan-Review | frischer `opus-xhigh`-Subagent je Runde | **max. 2 Runden** |
| E Umsetzung | nur `sonnet-xhigh`-Subagenten (**Sonnet 5.5**) · `superpowers:subagent-driven-development`, TDD | ein Implementierer je Plan-Task; Task-Reviews ebenfalls `sonnet-xhigh` |
| E2 Härtung | Hauptsession | immer durchgehen; ausführlich bei Storage, Zuständen, Jobs, Nebenläufigkeit |
| Verifikation | Hauptsession | Prüfbefehle aus `CLAUDE.md`, Output zeigen (`superpowers:verification-before-completion`) |
| F PR | Hauptsession | pushen ohne Rückfrage, `gh pr create`, **nie Draft** |

**Spec und Plan schreibt die Hauptsession** selbst und arbeitet auch die Review-Befunde ein. Die Unabhängigkeit kommt aus den frischen Opus-Reviewern.

**Autonom-Modus:** Wo ein Skill den Nutzer fragt oder auf Approval wartet, antwortest du dir aus dem Feature-File und machst weiter:
- `brainstorming`: Die User-Review-Schritte entfallen, das Review machen die Opus-Subagenten in Phase B.
- `writing-plans`: Die Frage nach der Ausführungsart lautet immer subagent-driven.
- `finishing-a-development-branch`: Die Antwort ist immer „PR öffnen“.

## Reviews (B und D)

- Pro Runde ein **neuer** `Agent(subagent_type: "opus-xhigh", model: "opus")`, ohne Wissen aus der Vorrunde. **`model: "opus"` explizit setzen.**
- **Briefing:**
  - Pfad der Spec bzw. des Plans, Feature-File, Hinweis auf `CLAUDE.md`
  - Auftrag „als Design prüfen“: fehlende Anforderungen, Widersprüche, falsche Datei-/Typ-Annahmen gegen den echten Code, Sicherheits- und Betriebsrisiken, Testbarkeit; beim Plan zusätzlich: deckt er die Spec vollständig ab?
  - Ausgabe Blocker / Wichtig / Klein mit Datei-/Zeilenbeleg
  - **ändert nichts**, kein `git checkout`/`switch`/`stash`/`reset`, keine Subagenten
  - Pläne **nicht probeweise umsetzen**; was nicht durch Lesen belegbar ist, als Verdacht kennzeichnen
- **Die Hauptsession urteilt** über jeden Befund (`superpowers:receiving-code-review`), statt ihn abzunicken, und arbeitet ihn ein. Begründete Ablehnungen kommen ins Dokument.
- **Runde 2 nur**, wenn Runde 1 Blocker oder Wichtiges ergab. Danach geht es immer weiter, auch mit offenen Befunden. Diese stehen als Abschnitt **„Offene Review-Punkte“** in Spec bzw. Plan und später im PR-Body. Eine dritte Runde gibt es nicht.

## Umsetzung (E)

Die Hauptsession schreibt **weder Produktiv- noch Testcode**, auch keine 4-Zeilen-Config. Jeder Plan-Task geht an `Agent(subagent_type: "sonnet-xhigh", model: "sonnet")`, kleine Tasks hängst du an einen benachbarten Task an. Die Konventionen aus `CLAUDE.md` gelten strikt.

Die Task-Reviews von `subagent-driven-development` (Spec-Treue und Codequalität je Task) bleiben, sie sind kein PR-Review-Loop.
- **Grenze:** Je Task gibt es nach der Erstumsetzung höchstens 2 Korrekturdurchläufe.
- **Danach offene Qualitätsbefunde** kommen unter „Offene Review-Punkte“ in den PR-Body.
- **Sind danach Tests rot oder ist der Build kaputt:** kein PR für dieses TF. Branch pushen, Stand und Ursache im Abschlussbericht melden, mit den unabhängigen TFs weitermachen.

## Härtungsdurchgang (E2)

Vor dem PR den gebauten Code systematisch durchgehen und diese sechs Fragen **schriftlich mit vollständiger Aufzählung** beantworten. Trifft keine zu, genügt ein Satz.

1. **Lange Operationen:** Timeouts, Leases, Stuck-Erkennung, alle, auch in Schleifen.
2. **Teilzustandsfenster** (DB + Storage, zwei Dateien): Was bleibt beim Absturz dazwischen liegen, und ist es auffindbar?
3. **Zustandsübergänge:** Wer löst aus, ist es atomar, was passiert bei doppelter oder verspäteter Auslösung?
4. **Zeitpunkt-Zusagen** (eingefrorene Dokumente/Protokolle): Halten sie, wenn Daten danach gelöscht werden?
5. **Stille Fallbacks:** jedes `catch`, `?? default`, jedes Überspringen. Wäre ein sichtbarer Fehler besser?
6. **Zwei Worker/Geräte gleichzeitig:** Was passiert, wenn einer enteignet wird, während er noch schreibt?

- **Klasse statt Instanz:** Braucht eine Stelle Behandlung, behandelst du im selben Durchgang alle Stellen derselben Klasse.
- **Lücken schließen:** Jede Lücke wird zu failing test → Fix → grün. Test und Fix schreibt ein Sonnet-Subagent.
- **Zweiter Fund = Design-Pass**, kein weiterer Flicken. Das gilt, wenn dieselbe Eigenschaft im selben Modul ein zweites Mal auffällt, egal ob in Spec-/Plan-Review, Task-Review oder Härtung:
  - Die Hauptsession überarbeitet den betroffenen Abschnitt in Spec und Plan, ohne neue Review-Runde.
  - Sonnet setzt die Änderung um.
  - Der PR-Body vermerkt den Design-Pass.
- **Ergebnis:** Abschnitt „Härtungsdurchgang“ im PR-Body.

**Binär-Check** (Ausgabe muss leer sein; nach `git fetch`, Basis = PR-Basis). Ein Steuerzeichen macht eine Datei für git binär, ihr Diff ist dann im Review unsichtbar:
`git diff --numstat origin/<basis>...HEAD | awk -F'\t' '$1=="-" {print "BINÄR: "$3}'`

## PR (F) und Stapel

- **Body:**
  - was gebaut wurde
  - Links zu Spec und Plan
  - DoD als Haken
  - Härtungsdurchgang
  - Offene Review-Punkte
  - Verifikations-Output
  - lauf-spezifische Zusätze aus dem Feature-File
  - Merge-Hinweise: Überschneidungen, Basis, Reihenfolge
  - „Reasoning-Weg“: der TF-Teil des Abschlussberichts (siehe unten), damit er auch nach dem Chat erhalten bleibt
- **Abhängiges TF:** gestapelt branchen, PR-Basis = Vorgänger-Branch. Binär-Check und Reviews laufen gegen diesen Branch. Ins PR-Body gehört der Hinweis „nach Merge von #<vorgänger> auf `main` retargeten“.
- **Unabhängiges TF:** gegen `main`.
- **Branch-Namen ohne die Zeichenfolge „-f“.** Ein lokaler git-Wrapper hält das sonst für einen Force-Push.
- Danach sofort das nächste TF. **Nie zwischen TFs fragen**, ob erst gemergt oder reviewt werden soll. Ein offener Vorgänger-PR ist kein Grund anzuhalten.

## Ende des Laufs: harter Stopp (HITL)

Sobald alle PRs stehen bzw. alle TFs abgeschlossen oder übersprungen sind, **stoppt der Lauf**.
- **Phase G entfällt:** kein PR-Review-Loop, kein `/code-review`, kein `/pr-review-loop`. Den PR-Review stößt Nikolaus selbst an, nachdem er den Lauf geprüft hat.
- **Nicht mergen, nicht deployen, keine Server-Aktionen.**

Der **Abschlussbericht** ist die Grundlage für Nikolaus' Prüfung. Er macht den Reasoning-Weg nachvollziehbar, je TF:
- **PR:** Link, Basis, Merge-Reihenfolge, Status (offen, übersprungen, kein PR wegen roter Tests)
- **Entscheidungen und Annahmen:** jede mit Begründung, besonders jeder Default anstelle einer offenen Frage
- **Review-Verlauf B/D:** je Runde die Befunde und das Urteil (angenommen, abgelehnt mit Grund, offen)
- **Umsetzung:** Abweichungen vom Plan, Task-Korrekturen, Design-Passes und warum
- **Härtungsdurchgang:** Ergebnis in Kurzform, gefundene Lücken
- **Verifikation:** Befehle und Ergebnis
- **Offene Fragen und Entscheidungen** für Nikolaus, inklusive Abweichungen von repo-eigenen Workflow-Dokumenten und „Effort nicht garantiert“, falls zutreffend
- **Nötige Ops-Schritte:** Migrationen, Env, Resync

Letzte Zeile: „Stopp. Bitte prüfen; danach `/pr-review-loop <PR>` je PR.“

## Ausreden und was stimmt

| Ausrede | Realität |
|---|---|
| „Runde 2 hat noch Wichtiges, eine dritte schadet nicht“ | Genau so entstehen Endlosschleifen. Offenes kommt in „Offene Review-Punkte“, dann weiter. |
| „Vier Zeilen schreibe ich schneller selbst“ | Die Hauptsession orchestriert und prüft. Implementiert wird nur von Sonnet. |
| „Tests grün, also PR“ | Grüne Tests finden keine Absturzfenster. Erst kommt die Härtung. |
| „Ich frag kurz, ob TF1 erst gemergt werden soll“ | Kein Stopp vor den PRs, auch wenn Nikolaus online ist. Stapeln ist der Default. |
| „Zum Schluss noch ein Review-Loop über alle PRs“ | Phase G entfällt. Den Review stößt Nikolaus an. |
| „Brainstorming fragt mich etwas, ich warte“ | Das Feature-File ist die Antwort. Annahme dokumentieren, weiter. |
| „Nikolaus ist doch online, ich frag kurz“ | Kein Stopp vor den PRs. Default wählen, im Bericht als offene Frage führen. |
| „PRs stehen, ich starte gleich `/pr-review-loop`“ | Erst prüft Nikolaus den Lauf (HITL). Den Review stößt er an. |
