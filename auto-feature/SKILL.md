---
name: auto-feature
description: Use when Nikolaus hands over a feature file (Feature-File, Master-Spec, Backlog with several Teilfeatures) to be implemented autonomously ("autonom umsetzen", "voll autonom", "ich bin bis morgen weg"), from spec through pull requests without further user input.
argument-hint: <Pfad zum Feature-File>
---

# Autonomer Feature-Workflow

Feature-File: `$ARGUMENTS`

**Kern:** Das Feature-File ersetzt den Dialog und ist das Approval. Pro Teilfeature: Spec → Spec-Review → Plan → Plan-Review → Umsetzung durch Sonnet-Subagenten → Härtungsdurchgang → Verifikation → PR. Am Ende stehen 1…n PRs. Der PR-Review, der Merge und der Deploy gehören Nikolaus.

**Projektspezifisches** liefert das Repo-`CLAUDE.md`: Befehle, Konventionen, Pfade, Teststrategie. Dieser Skill liefert den Ablauf. Widerspricht ein repo-eigenes Workflow-Dokument dem Ablauf, wird das **vor dem Start** in einer Frage geklärt, nicht mittendrin.

## Start

1. Das Feature-File und `CLAUDE.md` vollständig lesen. In Teilfeatures (TF) zerlegen. Reihenfolge und Abhängigkeiten aus dem File übernehmen. Ein TF ergibt einen PR.
2. Voraussetzungen prüfen: `gh auth status`, Remote vorhanden, Prüfbefehle bekannt (aus `CLAUDE.md`, sonst `package.json`/`Makefile`/`pyproject.toml`/CI-Konfiguration).
3. Blockierende Widersprüche oder Lücken, die sich nicht aus File und Code lösen lassen, **jetzt gebündelt** in einer Nachricht stellen. Danach gibt es keine Rückfragen mehr.
   - **Nikolaus hat angekündigt, weg zu sein** (oder ist es erkennbar): Eine Frage würde den Turn beenden und den Lauf bis zu seiner Rückkehr anhalten. Deshalb die Fragen als Text ausgeben und **im selben Turn** weiterarbeiten, mit dem vorsichtigsten umkehrbaren Default, dokumentiert als Annahme.
   - **Ist er da:** einmal fragen und auf die Antwort warten.
   - **Fehlen Zugangsdaten oder Anbieterwahl nur für den Betrieb:** hinter einer Schnittstelle mit Stub-Adapter bauen und testen. Live-Schaltung und Anbieterwahl kommen als offene Entscheidung in den Abschlussbericht, besonders bei Kosten oder personenbezogenen Daten (AV-Vertrag).
   - **Lässt sich ein TF auch so nicht bauen oder testen** (kein Remote, keine Zugriffsrechte): dieses TF und seine Abhängigen überspringen, die anderen umsetzen und das Übersprungene melden.
   - Alles Übrige entscheidest du selbst mit begründetem Default und hältst es in der Spec unter „Entscheidungen/Annahmen“ fest.
4. Ein Todo pro TF anlegen. Unabhängige TFs dürfen in eigenen Worktrees parallel laufen (`superpowers:using-git-worktrees`), abhängige laufen in Reihenfolge.

## Phasen je Teilfeature

| Phase | Wer | Regel |
|---|---|---|
| A Spec | **Fable** · `superpowers:brainstorming` im Autonom-Modus | `docs/superpowers/specs/<YYYY-MM-DD>-<tf>-design.md` (oder Repo-Konvention); Ziel, Andockpunkte mit Pfaden, Abnahmekriterien aus der DoD; Commit |
| B Spec-Review | frischer **Opus**-Subagent je Runde | **max. 2 Runden** |
| C Plan | **Fable** · `superpowers:writing-plans` | `docs/superpowers/plans/<YYYY-MM-DD>-<tf>.md`; TDD-Tasks mit exakten Pfaden; Commit |
| D Plan-Review | frischer **Opus**-Subagent je Runde | **max. 2 Runden** |
| E Umsetzung | nur **Sonnet**-Subagenten · `superpowers:subagent-driven-development`, TDD | ein Implementierer je Plan-Task |
| E2 Härtung | Hauptsession | immer durchgehen; ausführlich bei Storage, Zuständen, Jobs, Nebenläufigkeit |
| Verifikation | Hauptsession | Prüfbefehle aus `CLAUDE.md`, Output zeigen (`superpowers:verification-before-completion`) |
| F PR | Hauptsession | pushen ohne Rückfrage, `gh pr create`, **nie Draft** |

**Fable schreibt Spec und Plan.** Läuft die Hauptsession auf Fable, schreibt sie selbst. Sonst übernimmt `Agent(model: "fable", run_in_background: false)`. Ist Fable nicht verfügbar, schreibt die Hauptsession selbst und vermerkt das im Abschlussbericht.

Der Fable-Subagent kennt diesen Skill nicht. Sein Briefing enthält deshalb:
- Pfad des Feature-Files, das TF, den Zielpfad und `CLAUDE.md`
- „Autonom-Modus: keine Fragen an den Nutzer, das Feature-File ist die Antwort. Entscheidungen begründen und unter ‚Entscheidungen/Annahmen‘ festhalten.“
- „Schreib **nur** die Spec bzw. **nur** den Plan, committe ihn und hör dann auf. Kein Wechsel zu `writing-plans`, keine Wahl der Ausführungsart, keine Umsetzung. Die User-Review-Schritte der Skills entfallen, das Review machen frische Opus-Subagenten.“

Beim Einarbeiten von Review-Befunden bekommt Fable die Befunde zusammen mit dem Urteil der Hauptsession (annehmen / ablehnen mit Grund / offen) und schreibt alles ins Dokument. Läuft die Hauptsession selbst auf Fable, urteilt sie und arbeitet ein. Die Unabhängigkeit kommt aus den frischen Opus-Reviewern.

**Autonom-Modus:** Wo ein Skill den Nutzer fragt oder auf Approval wartet (`brainstorming`, `finishing-a-development-branch`), antwortest du dir aus dem Feature-File und machst weiter. Bei `finishing-a-development-branch` ist die Antwort immer „PR öffnen“.

## Reviews (B und D)

- Pro Runde ein **neuer** `Agent(subagent_type: "general-purpose", model: "opus")`, ohne Wissen aus der Vorrunde. **`model: "opus"` explizit setzen.**
- **Briefing:**
  - Pfad der Spec bzw. des Plans, Feature-File, Hinweis auf `CLAUDE.md`
  - Auftrag „als Design prüfen“: fehlende Anforderungen, Widersprüche, falsche Datei-/Typ-Annahmen gegen den echten Code, Sicherheits- und Betriebsrisiken, Testbarkeit; beim Plan zusätzlich: deckt er die Spec vollständig ab?
  - Ausgabe Blocker / Wichtig / Klein mit Datei-/Zeilenbeleg
  - **ändert nichts**, kein `git checkout`/`switch`/`stash`/`reset`, keine Subagenten
  - Pläne **nicht probeweise umsetzen**; was nicht durch Lesen belegbar ist, als Verdacht kennzeichnen
- **Die Hauptsession urteilt** über jeden Befund (`superpowers:receiving-code-review`), statt ihn abzunicken. Eingearbeitet wird vom Autor (Fable). Begründete Ablehnungen kommen ins Dokument.
- **Nach Runde 2 geht es immer weiter**, auch mit offenen Befunden. Diese stehen als Abschnitt **„Offene Review-Punkte“** in Spec bzw. Plan und später im PR-Body. Eine dritte Runde gibt es nicht.

## Umsetzung (E)

Die Hauptsession schreibt **weder Produktiv- noch Testcode**, auch keine 4-Zeilen-Config. Jeder Plan-Task geht an `Agent(model: "sonnet")`, kleine Tasks hängst du an einen benachbarten Task an. Die Konventionen aus `CLAUDE.md` gelten strikt.

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
  - Fable überarbeitet den betroffenen Abschnitt in Spec und Plan, ohne neue Review-Runde.
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
- **Abhängiges TF:** gestapelt branchen, PR-Basis = Vorgänger-Branch. Binär-Check und Reviews laufen gegen diesen Branch. Ins PR-Body gehört der Hinweis „nach Merge von #<vorgänger> auf `main` retargeten“.
- **Unabhängiges TF:** gegen `main`.
- **Branch-Namen ohne die Zeichenfolge „-f“.** Ein lokaler git-Wrapper hält das sonst für einen Force-Push.
- Danach sofort das nächste TF. **Nie zwischen TFs fragen**, ob erst gemergt oder reviewt werden soll. Ein offener Vorgänger-PR ist kein Grund anzuhalten.

## Ende des Laufs

- **Phase G entfällt:** kein PR-Review-Loop, kein `/code-review`. Den PR-Review stößt Nikolaus selbst an (z. B. mit `/pr-review-loop`).
- **Nicht mergen, nicht deployen, keine Server-Aktionen.**
- **Abschlussbericht:**
  - PR-Links mit Basis und Merge-Reihenfolge
  - offene Review-Punkte je PR
  - nötige Ops-Schritte (Migrationen, Env, Resync)
  - Entscheidungen, die Nikolaus treffen muss

## Ausreden und was stimmt

| Ausrede | Realität |
|---|---|
| „Runde 2 hat noch Wichtiges, eine dritte schadet nicht“ | Genau so entstehen Endlosschleifen. Offenes kommt in „Offene Review-Punkte“, dann weiter. |
| „Vier Zeilen schreibe ich schneller selbst“ | Die Hauptsession orchestriert und prüft. Implementiert wird nur von Sonnet. |
| „Tests grün, also PR“ | Grüne Tests finden keine Absturzfenster. Erst kommt die Härtung. |
| „Ich frag kurz, ob TF1 erst gemergt werden soll“ | Nikolaus ist weg. Stapeln ist der Default. |
| „Zum Schluss noch ein Review-Loop über alle PRs“ | Phase G entfällt. Den Review stößt Nikolaus an. |
| „Brainstorming fragt mich etwas, ich warte“ | Das Feature-File ist die Antwort. Annahme dokumentieren, weiter. |
