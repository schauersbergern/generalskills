---
name: auto-feature
description: Use when the user hands over a feature file (Feature-File, Master-Spec, Backlog with several Teilfeatures) to be implemented autonomously ("autonom umsetzen", "voll autonom", "ich bin bis morgen weg"), from spec through pull requests without further user input.
argument-hint: <Pfad zum Feature-File>
model: opus
effort: xhigh
---

# Autonomer Feature-Workflow

Feature-File: `$ARGUMENTS`

**Kern:** Das Feature-File ersetzt den Dialog und ist das Approval.
- **Pro Teilfeature:** Spec → Spec-Review → Plan → Plan-Review → Umsetzung durch Sonnet-Subagenten → Härtungsdurchgang → Verifikation → PR.
- **Ohne Zwischenhalt:** Der Lauf geht vom Feature-File bis zu 1…n PRs durch.
- **Dann harter Stopp (HITL):** Der User prüft den Reasoning-Weg und stößt selbst `/pr-review-loop` an. Merge und Deploy entscheidet der User.

**Modelle und Effort:** Spec und Plan schreibt die Hauptsession mit **Opus 5.5** (Skill-Frontmatter `model: opus`). Reviews machen frische Opus-Subagenten, die Umsetzung macht **Sonnet 5.5**, subagent-driven. **Effort `xhigh` als Standard**: die Hauptsession über das Skill-Frontmatter, die Subagenten über die Agent-Typen `opus-xhigh` und `sonnet-xhigh` (aus `~/.claude/agents/`). **Einzige Ausnahme:** In Phase E gehen Re-Reviews (auch bei DB oder Sperren), lesende Reviews reiner Refactor-/UI-Tasks und mechanische Implementierungen an `sonnet-high` (Regel unter „Effort-Regel“). Fehlt ein Typ in der Liste der verfügbaren Agents: `general-purpose` mit demselben `model` und „Effort nicht garantiert“ im Abschlussbericht.

**Projektspezifisches** liefert das Repo-`CLAUDE.md`: Befehle, Konventionen, Pfade, Teststrategie. Dieser Skill liefert den Ablauf. Weicht ein anderes Workflow-Dokument im Repo davon ab (nicht `CLAUDE.md`), gilt dieser Skill. Die Abweichung kommt in den Abschlussbericht.

## Start

1. Das Feature-File und `CLAUDE.md` vollständig lesen. In Teilfeatures (TF) zerlegen. Reihenfolge und Abhängigkeiten aus dem File übernehmen. Ein TF ergibt einen PR.
2. Voraussetzungen prüfen:
   - `gh auth status` und ein Remote vorhanden.
   - Prüfbefehle bekannt: aus `CLAUDE.md`, ergänzt um Typecheck/Build, falls `package.json`/`Makefile`/`pyproject.toml`/CI-Konfiguration sie haben.
   - Abhängigkeiten zwischen TFs: Nennt das File keine, aus dem Inhalt ableiten und begründen.
3. **Kein Stopp vor den PRs**, auch wenn der User online ist. Widersprüche oder Lücken, die sich nicht aus File und Code lösen lassen, werden nicht erfragt. Eine Frage würde den Turn beenden und den Lauf anhalten.
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
| C Plan | Hauptsession (**Opus 5.5**) · `superpowers:writing-plans` | Repo-Konvention, sonst `docs/superpowers/plans/<YYYY-MM-DD>-<tf>.md`; TDD-Tasks mit exakten Pfaden; Abschnitt „Review Focus“ mit fester Checkliste (siehe „Plan (C)“); Commit auf dem TF-Branch |
| D Plan-Review | frischer `opus-xhigh`-Subagent je Runde | **max. 2 Runden** |
| E Umsetzung | nur Sonnet-Subagenten (**Sonnet 5.5**) · `superpowers:subagent-driven-development`, TDD | ein Implementierer je Plan-Task; Task-Reviews ebenfalls Sonnet; `sonnet-xhigh` oder `sonnet-high` nach der Effort-Regel |
| E2 Härtung | Hauptsession verantwortet und prüft; Durchsicht samt Test und Fix an `sonnet-xhigh`-Subagenten | immer durchgehen; ausführlich bei Storage, Zuständen, Jobs, Nebenläufigkeit |
| Verifikation | Hauptsession | Prüfbefehle aus `CLAUDE.md`, Output zeigen (`superpowers:verification-before-completion`) |
| F PR | Hauptsession | pushen ohne Rückfrage, `gh pr create`, **nie Draft** |

**Spec und Plan schreibt die Hauptsession** selbst und arbeitet auch die Review-Befunde ein. Die Unabhängigkeit kommt aus den frischen Opus-Reviewern.

**Autonom-Modus:** Wo ein Skill den Nutzer fragt oder auf Approval wartet, antwortest du dir aus dem Feature-File und machst weiter:
- `brainstorming`: Die User-Review-Schritte entfallen, das Review machen die Opus-Subagenten in Phase B.
- `writing-plans`: Die Frage nach der Ausführungsart lautet immer subagent-driven.
- `finishing-a-development-branch`: Die Antwort ist immer „PR öffnen“.

## Plan (C): Review Focus

Jeder Plan hat einen Abschnitt **„Review Focus“**. Er beginnt mit der folgenden festen Checkliste wiederkehrender Fehlerklassen, danach folgen TF-spezifische Punkte. Je Punkt steht im Plan entweder „trifft zu → Task <n>, Test <Name>“ oder „trifft nicht zu“ mit einem Satz Begründung. Ein zutreffender Punkt ohne Task und Test ist ein Plan-Fehler.

1. **Sperren mit deterministischem Wartenachweis:** Jede neue Sperre (Advisory Lock, `SELECT … FOR UPDATE`, Lease-Spalte, Mutex) bekommt einen Test, der nachweist, dass der zweite Aufrufer tatsächlich wartet bzw. abgewiesen wird: über Barriere oder Latch im ersten Halter oder Abfrage des Sperrzustands (`pg_locks`), nicht über `sleep` oder Timing.
2. **Werte, die die App-Validierung bestehen, aber an Prisma/PostgreSQL scheitern oder still verfälscht werden:** je Eingabefeld, das in die DB geht, Grenzwerte gegen die echte DB prüfen:
   - Datumsbereiche: `Invalid Date` (lehnt schon der Prisma-Client ab), Jahr 0 (gibt es in PostgreSQL nicht, z. B. scheitert `0000-…` als `::date`), Jahre außerhalb des PostgreSQL-Bereichs
   - Steuerzeichen: `\u0000` in `text`/`jsonb`
   - Surrogate: ungepaarte UTF-16-Surrogate (`\uD800`) scheitern je nach Pfad in der Prisma-Engine oder werden still zu U+FFFD
3. **Transaktions-Timeouts explizit:** Jede interaktive Transaktion setzt `timeout` (und `maxWait`) ausdrücklich. Der Prisma-Default von 5 s führt bei Sperrwartezeit oder Last zu P2028.
4. **Org-/Owner-Scope in neuen Modulen:** Jede Abfrage eines neuen Moduls ist org-scoped bzw. läuft über den Besitzer-Filter des Repos (siehe `CLAUDE.md`). Test mit fremder Org bzw. fremdem Besitzer.
5. **Testaufbau mit genug Quellen:** Zusammenführungs- und Abgleichstests mit **≥ 2 Quellen** (Orgs, Projekte, Geräte), Nebenläufigkeitstests mit **≥ 3 parallelen Aufrufern** (Festlegung, nicht aus dem Referenzlauf abgeleitet). Mit nur einer Quelle führt ein Zusammenführungstest nichts zusammen. Tests mit Gegenreihenfolge führen jedes mögliche Deadlock-Opfer gezielt herbei (z. B. simulierter P2034) und lassen im natürlichen Deadlock-Fall jeden Ausgang zu, statt ein bestimmtes Opfer zu erwarten.
6. **Uhrsprung und Uhrwahl bei Sperren:** Lease- und Sperrablauf an genau einer Uhr messen, nie Geräte- und Serveruhr mischen. Persistierte Leases und Sperren laufen über DB-Zeit (`clock_timestamp()`, oder bewusst `now()` = Start der Transaktion). Prozesslokale Sperren laufen über eine monotone Uhr (`performance.now()`/`process.hrtime`), die nur innerhalb des Prozesses und nicht über einen Neustart gilt. Das Verhalten bei Uhrsprung (Neustart, NTP) steht im Plan, ebenso Sortierung und Paginierung nach Gerätezeit: Eine Geräteuhr auf 1970 ist ein gültiger DB-Wert, aber ein Logik-Grenzfall.

**Herkunft:** Diese Klassen tauchten im Lauf Meckelein (2026-10-17) erst in Task-/Re-Reviews oder in der Härtung auf (u. a. P2028 nach 5 s, `busySince` nach Neustart, „Mehr laden“ bei Geräteuhr 1970, Sperre ohne monotone Uhr, ungetestete Sperren). Im Plan kosten sie einen Satz, in der Umsetzung eine Fix-Runde.

## Reviews (B und D)

**Bleiben bei `opus-xhigh`, ohne Abschlag.** Im Referenzlauf kamen alle 28 Blocker aus Opus-Spec-/Plan-Reviews (3,4–4,2 Blocker+Wichtig je 100k Tokens, Task-Reviews 0,43), und auch Runde 2 fand noch Blocker. Ein Abschlag hier verschiebt Fehler in die teurere Umsetzung.

- Pro Runde ein **neuer** `Agent(subagent_type: "opus-xhigh", model: "opus")`, ohne Wissen aus der Vorrunde. **`model: "opus"` explizit setzen.**
- **Briefing:**
  - Pfad der Spec bzw. des Plans, Feature-File, Hinweis auf `CLAUDE.md`
  - Auftrag „als Design prüfen“: fehlende Anforderungen, Widersprüche, falsche Datei-/Typ-Annahmen gegen den echten Code, Sicherheits- und Betriebsrisiken, Testbarkeit; beim Plan zusätzlich: deckt er die Spec vollständig ab, und ist jeder Punkt der „Review Focus“-Checkliste gegen den echten Code richtig als zutreffend/nicht zutreffend eingestuft und mit Task und Test hinterlegt?
  - Ausgabe Blocker / Wichtig / Klein mit Datei-/Zeilenbeleg
  - **ändert nichts**, kein `git checkout`/`switch`/`stash`/`reset`, keine Subagenten
  - Pläne **nicht probeweise umsetzen**; was nicht durch Lesen belegbar ist, als Verdacht kennzeichnen
- **Die Hauptsession urteilt** über jeden Befund (`superpowers:receiving-code-review`), statt ihn abzunicken, und arbeitet ihn ein. Begründete Ablehnungen kommen ins Dokument.
- **Runde 2 nur**, wenn Runde 1 Blocker oder Wichtiges ergab. Danach geht es immer weiter, auch mit offenen Befunden. Diese stehen als Abschnitt **„Offene Review-Punkte“** in Spec bzw. Plan und später im PR-Body. Eine dritte Runde gibt es nicht.

## Umsetzung (E)

Die Hauptsession schreibt **weder Produktiv- noch Testcode**, auch keine 4-Zeilen-Config. Jeder Plan-Task geht an `Agent(subagent_type: "sonnet-xhigh" | "sonnet-high", model: "sonnet")` nach der Effort-Regel, kleine Tasks hängst du an einen benachbarten Task an. Die Konventionen aus `CLAUDE.md` gelten strikt.

### Effort-Regel

Die Hauptsession legt den Agent-Typ je Implementierung und je Review beim Dispatch fest und nennt ihn im Abschlussbericht unter „Umsetzung“.

| Typ | Wofür |
|---|---|
| `sonnet-xhigh` | Implementierung **und** Task-Review (nicht Re-Review) jedes Tasks, der **DB** (Schema, Migration, Abfragen), **Sperren**, **Jobs/Inngest**, **Zustandsautomaten** oder **Raw SQL** berührt. Außerdem alle Härtungs-Subagenten (E2). |
| `sonnet-high` | **Re-Reviews** von Fix-Diffs, auch bei DB, Sperren, Jobs, Zustandsautomaten oder Raw SQL (einzige Ausnahme unter „Fix-Runden“); **lesende Task-Reviews** reiner Refactor-/UI-Tasks; **mechanische Implementierungen** (Verschieben, Umbenennen, Re-Exporte, Texte, Styles ohne neue Logik). |

- **Im Zweifel und bei Misch-Tasks** gilt für Implementierung und Task-Review `sonnet-xhigh`. Re-Reviews bleiben bei `sonnet-high`. Ein Task ist erst dann mechanisch, wenn er keine neue Verzweigung, Invariante oder Abfrage einführt.
- **Fix-Runden** laufen als Fortsetzung desselben Implementierers (`SendMessage`), also mit dessen Typ. Das spart die Einarbeitung. Ausnahme: Bringt ein Fix neue Logik (Verzweigung, Invariante, Abfrage) oder einen der `sonnet-xhigh`-Bereiche in einen `sonnet-high`-Task, schreibt ihn ein frischer `sonnet-xhigh`-Implementierer. Statt des Re-Reviews folgt dann ein volles `sonnet-xhigh`-Task-Review mit Mutationsproben.
- **Unverändert bleiben** die Opus-Reviews (B/D) und die Härtungs-Subagenten (E2, `sonnet-xhigh`). Begründung: Alle 28 Blocker des Referenzlaufs kamen aus Opus-Reviews, und die Härtung fand in jedem TF echte Lücken.
- **Begründung des Abschlags:** Re-Reviews brachten 0,14 Blocker+Wichtig je 100k Tokens (Median 91k), und beide echten Funde lagen im eng umrissenen Fix-Diff. Lesende Reviews von Refactor-/UI-Tasks kosteten 100–136k und fanden 0–1 Wichtig. Ein kleineres Modell als Sonnet ist nicht vorgesehen, weil auch Re-Review-Funde Transaktions- und Deadlock-Semantik verlangten.

### Testumfang

Die ganze Suite läuft **einmal je TF**, in der Verifikation. Implementierer, Fix-Runden, Reviews und Härtungs-Subagenten lassen nur laufen:
- Typecheck und die Testdateien des Tasks bzw. Fixes
- die Tests, die von den geänderten Dateien abhängen: der Befehl aus `CLAUDE.md`, sonst das Runner-Äquivalent (z. B. `vitest related --run <dateien>`, Jest `--findRelatedTests`)

Das steht ausdrücklich im Briefing, denn die Templates von `subagent-driven-development` lassen sonst die ganze Suite laufen. **Ausnahme:** Ändert ein Task Test-Infrastruktur, Schema oder Migrationen, Abhängigkeiten oder Build-Konfiguration, läuft dort einmal die ganze Suite, weil der Import-Graph die Betroffenen nicht findet.

### Mutationsproben im Task-Review

**Task-Reviews mit Logik führen Mutationsproben durch.** Logik heißt: neue Verzweigung, Invariante, Validierung, Abfrage oder ein neuer Zustandsübergang. Rein lesend geprüft werden nur reine Refactor-/UI-Tasks ohne neue Logik. Im Referenzlauf fanden Reviews mit Mutationsproben echte Laufzeitfehler (Cursor-Tag → 500, „Mehr laden“ hängt bei Geräteuhr 1970, Reconcile ohne Verfügbarkeitsprüfung, ungetestete Sperren).

Ins Review-Briefing gehört:
- **Vorrang vor dem Template:** Die Reviewer-Templates von `subagent-driven-development` (`task-reviewer-prompt.md`, `re-review-prompt.md`) verlangen ein rein lesendes Review, Tests nur bei konkretem Zweifel und keine git-Befehle. Das Briefing sagt ausdrücklich, dass alle drei Vorgaben für dieses Review aufgehoben sind und stattdessen gilt: Arbeitsbaum nur temporär ändern, Endstand = Ausgangsstand, nur die betroffenen Testdateien laufen lassen, `git status`/`git diff` nur zur Kontrolle des Endstands, sonst keine git-Befehle. Das gilt auch für Re-Reviews, die mutieren.
- Je neuer Verzweigung bzw. Invariante eine Mutation (Zweig entfernen, Bedingung umdrehen, Sperre oder Scope-Filter weglassen) und nur die betroffenen Testdateien laufen lassen, nicht die ganze Suite.
- Die Mutation danach von Hand zurücknehmen. Am Ende muss `git status` den Stand vor dem Review zeigen. Kein `git checkout`/`stash`/`reset`, keine Commits.
- Ergebnis je Probe im Review: „Mutation → Test <Name> rot“ oder „kein Test rot → Befund Wichtig: Test fehlt“.
- Re-Reviews mutieren nur, wenn der Fix-Diff selbst Logik ändert, und dann nur dort.
- Reviews mit Mutationsprobe (auch Re-Reviews) erst dispatchen, wenn kein anderer Subagent im selben Worktree arbeitet, und bis zu ihrem Ende keinen weiteren dort starten. Warten statt auslassen.

### Task-Reviews und Korrekturdurchläufe

Die Task-Reviews von `subagent-driven-development` (Spec-Treue und Codequalität je Task) bleiben, sie sind kein PR-Review-Loop.
- **Grenze:** Je Task gibt es nach der Erstumsetzung höchstens 2 Korrekturdurchläufe.
- **Danach offene Qualitätsbefunde** kommen unter „Offene Review-Punkte“ in den PR-Body.
- **Sind danach Tests rot oder ist der Build kaputt:** kein PR für dieses TF. Branch pushen, Stand und Ursache im Abschlussbericht melden, mit den unabhängigen TFs weitermachen.

## Härtungsdurchgang (E2)

Die Hauptsession verantwortet den Durchgang. Die Durchsicht samt Test und Fix gibt sie an einen oder mehrere `sonnet-xhigh`-Subagenten (bei großen TFs getrennt, z. B. Server und Client). Mehrere laufen nacheinander oder in getrennten Worktrees, weil sie mutieren und fixen. Die Hauptsession prüft deren Antworten und gefundene Lücken selbst und fordert Fehlendes nach.

Vor dem PR den gebauten Code systematisch durchgehen und diese acht Fragen **schriftlich mit vollständiger Aufzählung** beantworten. Trifft keine zu, genügt ein Satz.

1. **Lange Operationen:** Timeouts, Leases, Stuck-Erkennung, alle, auch in Schleifen.
2. **Teilzustandsfenster** (DB + Storage, zwei Dateien): Was bleibt beim Absturz dazwischen liegen, und ist es auffindbar?
3. **Zustandsübergänge:** Wer löst aus, ist es atomar, was passiert bei doppelter oder verspäteter Auslösung?
4. **Zeitpunkt-Zusagen** (eingefrorene Dokumente/Protokolle): Halten sie, wenn Daten danach gelöscht werden?
5. **Stille Fallbacks:** jedes `catch`, `?? default`, jedes Überspringen. Wäre ein sichtbarer Fehler besser?
6. **Zwei Worker/Geräte gleichzeitig:** Was passiert, wenn einer enteignet wird, während er noch schreibt?
7. **Endgültigkeitszusagen:** jede Stelle, die etwas als dauerhaft, nicht wiederholbar, endgültig oder „immer/nie“ markiert, in Code (Statuswerte, Sperren, Retry-Verbote) und in Texten (Meldungen, Kommentare). Gilt die Zusage für **jeden** Weg, der dort ankommt, oder auch für Fälle, in denen ein neuer Versuch gelingen kann?
8. **Wirksamkeit der Tests:** für jede neue Verzweigung bzw. Invariante eine Mutationsprobe (Zweig entfernen oder Bedingung umdrehen) gegen die betroffenen Testdateien, nicht die ganze Suite. Wird ein Test rot? Wenn nicht, fehlt der Test.

- **Klasse statt Instanz:** Braucht eine Stelle Behandlung, behandelst du im selben Durchgang alle Stellen derselben Klasse.
- **Lücken schließen:** Jede Lücke wird zu failing test → Fix → grün. Test und Fix schreibt ein `sonnet-xhigh`-Subagent.
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
- **Branch-Namen ohne die Zeichenfolge „-f“.** Manche lokalen git-Wrapper halten das sonst für einen Force-Push.
- Danach sofort das nächste TF. **Nie zwischen TFs fragen**, ob erst gemergt oder reviewt werden soll. Ein offener Vorgänger-PR ist kein Grund anzuhalten.

## Ende des Laufs: harter Stopp (HITL)

Sobald alle PRs stehen bzw. alle TFs abgeschlossen oder übersprungen sind, **stoppt der Lauf**.
- **Phase G entfällt:** kein PR-Review-Loop, kein `/code-review`, kein `/pr-review-loop`. Den PR-Review stößt der User selbst an, nachdem der Lauf geprüft ist.
- **Nicht mergen, nicht deployen, keine Server-Aktionen.**

Der **Abschlussbericht** ist die Grundlage für die Prüfung durch den User. Er macht den Reasoning-Weg nachvollziehbar, je TF:
- **PR:** Link, Basis, Merge-Reihenfolge, Status (offen, übersprungen, kein PR wegen roter Tests)
- **Entscheidungen und Annahmen:** jede mit Begründung, besonders jeder Default anstelle einer offenen Frage
- **Review-Verlauf B/D:** je Runde die Befunde und das Urteil (angenommen, abgelehnt mit Grund, offen)
- **Umsetzung:** Abweichungen vom Plan, Task-Korrekturen, Design-Passes und warum
- **Härtungsdurchgang:** Ergebnis in Kurzform, gefundene Lücken
- **Verifikation:** Befehle und Ergebnis
- **Offene Fragen und Entscheidungen** für den User, inklusive Abweichungen von repo-eigenen Workflow-Dokumenten und „Effort nicht garantiert“, falls zutreffend
- **Nötige Ops-Schritte:** Migrationen, Env, Resync
- **Agent-Statistik:** Pfad und die Auswertung je Rolle

Letzte Zeile: „Stopp. Bitte prüfen; danach `/pr-review-loop <PR>` je PR.“

## Agent-Statistik

**Jeder Lauf führt eine Agent-Statistik**, als Grundlage für spätere Token-Optimierung. Dieses Format gilt auch für `pr-review-loop`, `fix-findings` und jede andere Session, die Subagenten startet. Ablage nach Repo-Konvention, sonst `docs/superpowers/runs/<YYYY-MM-DD>-<lauf>-agent-stats.md`. Außerhalb von `auto-feature` liegt sie unter `~/.claude/agent-stats/<repo>/`.

- **Kopf:** Repo, Lauf, Session-ID der Hauptsession. Deren eigene Tokens stehen in keiner `<usage>`-Angabe und lassen sich später aus dem Transkript holen.
- **Fortschreiben** nach jeder Task-Notification, nicht erst am Ende. Nach einer Kompaktierung fehlen sonst die Werte.

- **Quelle:** die `<usage>`-Angaben der Task-Notifications (`subagent_tokens`, `duration_ms`, `tool_uses`). Fehlt eine Angabe, steht dort „n/a“, nicht geschätzt.
- **Spalten:** # | Zeitpunkt | TF | Rolle | Agent-Typ | Modell | Effort | tokens | Δ tokens | duration_ms | tool_uses | B/W/K | angenommen | betriebsrelevant | Fix-Runden | Status
- **Fortsetzungen per `SendMessage`** (Fix-Runden, Nachträge):
  - `tokens` = gemeldeter Wert, gekennzeichnet mit „(kum.)“. Annahme, nicht belegt: Der Wert enthält die Vorläufe desselben Agenten.
  - `Δ tokens` = gemeldeter Wert minus Vorwert, also minus dem zuletzt gemeldeten Wert desselben Agenten.
  - Ist der gemeldete Wert kleiner als der Vorwert, trägt die Annahme für diesen Agenten nicht, etwa weil der Wert nach einer Kompaktierung nur noch die Kontextgröße zeigt. Dann gilt `Δ tokens` = `tokens`, ohne „(kum.)“, und die Auswertung hält das fest.
  - Erstläufe: `Δ tokens` = `tokens`.
  - **Summen, Mediane und Ausbeuten rechnen mit `Δ tokens`.**
- **betriebsrelevant:** Anzahl der angenommenen Befunde, die im Betrieb sichtbar geworden wären (Fehler oder Absturz, Datenverlust, Hänger, falsche Anzeige, Sicherheits- oder Scope-Lücke), Format `n: Stichwort; Stichwort`. Reine Stil-, Test-, Doku- und Benennungsbefunde zählen nicht. Gilt für Reviews und Härtungsläufe (gefundene Lücken je Härtungs-Subagent), sonst „–“.
- **Auswertung je Rolle:** Läufe, Summe und Median `Δ tokens`, Dauer-Median, B/W/K, Blocker+Wichtig je 100k, betriebsrelevant je 100k. `sonnet-high` und `sonnet-xhigh` getrennt ausweisen, damit sich die Effort-Regel überprüfen lässt.

## Ausreden und was stimmt

| Ausrede | Realität |
|---|---|
| „Runde 2 hat noch Wichtiges, eine dritte schadet nicht“ | Genau so entstehen Endlosschleifen. Offenes kommt in „Offene Review-Punkte“, dann weiter. |
| „Vier Zeilen schreibe ich schneller selbst“ | Die Hauptsession orchestriert und prüft. Implementiert wird nur von Sonnet. |
| „Zur Sicherheit nach jedem Task die ganze Suite“ | Die läuft einmal je TF in der Verifikation und dann in der CI. Je Task Typecheck und die abhängigen Tests. |
| „Die Statistik schreibe ich am Ende zusammen“ | Nach einer Kompaktierung sind die `<usage>`-Werte weg. Nach jeder Notification fortschreiben. |
| „Tests grün, also PR“ | Grüne Tests finden keine Absturzfenster. Erst kommt die Härtung. |
| „Die Tests decken den neuen Zweig ab, steht ja im Namen“ | Erst eine Mutation zeigt, ob ein Test rot wird. Ohne Probe bleibt die Lücke bis zum Review. |
| „Der Task ist klein, Review lesend reicht“ | Hat er Logik, wird mutiert. Lesend nur reine Refactor-/UI-Tasks. |
| „Spart Tokens: Plan-Review mit Sonnet oder Effort high“ | Alle Blocker des Referenzlaufs kamen aus Opus-xhigh-Reviews. Der Abschlag gilt nur in Phase E nach der Effort-Regel. |
| „Der Task fasst nur kurz die DB an, `sonnet-high` reicht“ | DB, Sperren, Jobs, Zustandsautomaten oder Raw SQL bedeuten immer `sonnet-xhigh`, für Implementierung und Task-Review. Nur das Re-Review des Fix-Diffs geht an `sonnet-high`, außer erst der Fix bringt einen dieser Bereiche in einen `sonnet-high`-Task: Dann folgt ein volles `sonnet-xhigh`-Task-Review. |
| „Ich frag kurz, ob TF1 erst gemergt werden soll“ | Kein Stopp vor den PRs, auch wenn der User online ist. Stapeln ist der Default. |
| „Zum Schluss noch ein Review-Loop über alle PRs“ | Phase G entfällt. Den Review stößt der User an. |
| „Brainstorming fragt mich etwas, ich warte“ | Das Feature-File ist die Antwort. Annahme dokumentieren, weiter. |
| „Der User ist doch online, ich frag kurz“ | Kein Stopp vor den PRs. Default wählen, im Bericht als offene Frage führen. |
| „PRs stehen, ich starte gleich `/pr-review-loop`“ | Erst prüft der User den Lauf (HITL) und stößt dann den Review an. |
