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

**Modelle und Effort:** Spec und Plan schreibt die Hauptsession mit **Opus 5.5** (Skill-Frontmatter `model: opus`). Reviews machen frische Opus-Subagenten, die Umsetzung macht **Sonnet 5.5**, subagent-driven. **Effort `xhigh` als Standard**: die Hauptsession über das Skill-Frontmatter, die Subagenten über die Agent-Typen `opus-xhigh` und `sonnet-xhigh` (aus `~/.claude/agents/`). **Einzige Ausnahme:** In Phase E gehen Re-Reviews (auch bei DB oder Sperren), lesende Reviews reiner Refactor-/UI-Tasks, mechanische Implementierungen und, solange die Messphase läuft, Task-Reviews gerader Tasknummer an `sonnet-high` (Regel unter „Effort-Regel“). Fehlt ein Typ in der Liste der verfügbaren Agents: `general-purpose` mit demselben `model` und „Effort nicht garantiert“ im Abschlussbericht.

**Projektspezifisches** liefert das Repo-`CLAUDE.md`: Befehle, Konventionen, Pfade, Teststrategie. Dieser Skill liefert den Ablauf. Weicht ein anderes Workflow-Dokument im Repo davon ab (nicht `CLAUDE.md`), gilt dieser Skill. Die Abweichung kommt in den Abschlussbericht.

## Start

0. **Fortsetzung?** Liegt zum Feature-File schon eine Stand-Datei (siehe „Kontext der Hauptsession“), setzt du den Lauf fort: Stand-Datei, Feature-File, `CLAUDE.md` und Spec/Plan des offenen TF lesen, dann beim dort genannten nächsten Schritt weitermachen. Die übrigen Start-Schritte entfallen. Vorher für jede dort geführte frühere Session-ID die noch nicht eingetragenen Agenten nachtragen: `agent-stats.py import <datei> <alte-ID> --tf TF<n>` je betroffenem TF (`import … self` liest nur die Subagenten der laufenden Session, die der alten fehlen sonst dauerhaft).
1. Das Feature-File und `CLAUDE.md` vollständig lesen. Format und Regeln des Feature-Files: `~/.claude/skills/auto-feature/references/feature-file.md`. In Teilfeatures (TF) zerlegen. Reihenfolge und Abhängigkeiten aus dem File übernehmen. Ein TF ergibt einen PR.
   - **DoD-IDs und Nachweis-Art:** Hat das File keine `TF<n>-D<m>`-IDs oder keine Nachweis-Art (ältere Files), vergibt die Spec beides: IDs in der Reihenfolge des Files, Nachweis-Art je Punkt nach „Was einen Test bekommt“, im Zweifel `[Code]`. Das steht im Abschlussbericht.
   - **Vorrang `[Test]` gegen „Test überflüssig“:** Lässt sich für einen `[Test]`-Punkt (etwa aus einem älteren File, das pauschal `[Test]` vergibt) kein Laufzeitfehler benennen, stuft die Spec ihn mit Begründung unter „Entscheidungen/Annahmen“ auf `[Code]` um; die Umstufung steht im Abschlussbericht. Ein Test, der einen verbleibenden `[Test]`-Punkt belegt, ist nie „überflüssig“.
   - **Schreibgeschützt:** Das Feature-File bleibt im Lauf unverändert, auch ein vorhandener Abschnitt „Offene Review-Punkte“ (parallele TF-Branches würden sonst kollidieren). Abweichungen und offene Punkte stehen in Spec, Plan, PR-Body und Abschlussbericht.
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
| A Spec | Hauptsession (**Opus 5.5**) · `superpowers:brainstorming` im Autonom-Modus | Repo-Konvention, sonst `docs/superpowers/specs/<YYYY-MM-DD>-<tf>-design.md` (Ordner ggf. anlegen); Ziel, Andockpunkte mit Pfaden, Abnahmekriterien = DoD-Punkte mit ihren IDs; „Entschieden“ ist bindend, von „Default“ nur mit Begründung unter „Entscheidungen/Annahmen“ abweichen; Commit auf dem TF-Branch |
| B Spec-Review | frischer `opus-xhigh`-Subagent je Runde | **max. 2 Runden** |
| C Plan | Hauptsession (**Opus 5.5**) · `superpowers:writing-plans` | Repo-Konvention, sonst `docs/superpowers/plans/<YYYY-MM-DD>-<tf>.md`; Tasks mit exakten Pfaden und je einer Zeile `Tests:`; Abschnitt „Review Focus“ mit fester Checkliste (siehe „Plan (C)“); Commit auf dem TF-Branch |
| D Plan-Review | frischer `opus-xhigh`-Subagent je Runde | **max. 2 Runden** |
| E Umsetzung | nur Sonnet-Subagenten (**Sonnet 5.5**) · `superpowers:subagent-driven-development`, TDD für die Tests der Zeile `Tests:` | ein Implementierer je Plan-Task; Task-Reviews ebenfalls Sonnet; `sonnet-xhigh` oder `sonnet-high` nach der Effort-Regel |
| E2 Härtung | Hauptsession verantwortet und prüft; Durchsicht samt Test und Fix an `sonnet-xhigh`-Subagenten | immer durchgehen; ausführlich bei Storage, Zuständen, Jobs, Nebenläufigkeit |
| Verifikation | Hauptsession | Prüfbefehle aus `CLAUDE.md`, Output zeigen (`superpowers:verification-before-completion`) |
| F PR | Hauptsession | pushen ohne Rückfrage, `gh pr create`, **nie Draft** |

**Spec und Plan schreibt die Hauptsession** selbst und arbeitet auch die Review-Befunde ein. Die Unabhängigkeit kommt aus den frischen Opus-Reviewern.

**Autonom-Modus:** Wo ein Skill den Nutzer fragt oder auf Approval wartet, antwortest du dir aus dem Feature-File und machst weiter:
- `brainstorming`: Die User-Review-Schritte entfallen, das Review machen die Opus-Subagenten in Phase B.
- `writing-plans`: Die Frage nach der Ausführungsart lautet immer subagent-driven. Die Testschritte der Vorlage (je Task „Write the failing test“, ein Test je Review-Focus-Zeile, „the spec's exact values“) gelten nur für Tests aus der Zeile `Tests:` des Tasks. Ein Task mit `Tests: keine` bekommt keinen Testschritt, Werte aus der Spec werden nur bei Zusagen nach außen wörtlich geprüft.
- `finishing-a-development-branch`: Die Antwort ist immer „PR öffnen“.

## Kontext der Hauptsession

Jeder API-Aufruf der Hauptsession liest ihren ganzen Kontext neu. Im Lauf security-audit (2026-11-09 bis 11-11) war sie mit 761 Aufrufen bei einem Kontext von im Median 490k der größte Einzelposten, gut ein Fünftel der Gesamtkosten. Ihr Kontext bleibt klein, wenn:

- **Stand-Datei:** `<YYYY-MM-DD>-<lauf>-stand.md` neben der Agent-Statistik. Fortschreiben nach jedem Plan-Task (eine Zeile) und an jeder TF-Grenze: je TF Status, Branch, Worktree, PR, nächster Schritt und offene Punkte, nach Abschluss des TF dessen Teil des Abschlussberichts; dazu die Session-IDs des Laufs. Nach einer Kompaktierung liest die Hauptsession zuerst Stand-Datei, Feature-File und Spec/Plan des laufenden TF. Retro und Abschlussbericht entstehen aus der Stand-Datei, nicht aus dem Gedächtnis.
- **Früh kompaktieren:** Der Lauf ist darauf ausgelegt, dass die Hauptsession bei etwa 300k kompaktiert (User-Einstellung `/autocompact 300k` für Opus oder `CLAUDE_CODE_AUTO_COMPACT_WINDOW=300k`). Mit der Stand-Datei geht dabei nichts verloren. Eine frische Session je TF startet der Lauf nicht selbst: Die App verweigert Session-Starts in Zügen, die eine Task-Notification ausgelöst hat. Unterbricht der User den Lauf, setzt ein neues `/auto-feature <Feature-File>` über Start-Schritt 0 fort.
- **Kurze Berichte:** Jedes Briefing endet mit einer Grenze für den Bericht. Implementierer, Fix-Runden und Härtung: höchstens etwa 300 Wörter (Commit, Testergebnis als Zahl, Abweichungen vom Plan, gefundene Lücken je eine Zeile, offene Punkte), keine Testausgaben, Diff-Auszüge oder Nacherzählung. Reviewer: nur Befunde, Blocker und Wichtige mit Beleg, Kleinigkeiten je eine Zeile, keine Liste des Geprüften. Im Referenzlauf brachten 132 Berichte im Schnitt 7,5k Zeichen in den Kontext.
- **Edit statt Neuschreiben:** Review-Befunde arbeitet die Hauptsession per Edit in Spec und Plan ein, nicht durch Neuschreiben des ganzen Dokuments.
- **Statistik nur je TF** (Abschnitt „Agent-Statistik“), nicht nach jeder Notification.

## Was einen Test bekommt

Tests sichern das Minimum ab, das für die Qualität nötig ist, nie eine Abdeckung. Für jeden neuen Test im Lauf (Spec, Plan, Implementierer, Reviews, Härtung) gilt die Frage:

> **Welchen Laufzeitfehler fängt dieser Test, den weder der Compiler noch ein Blick in den Code zeigt?**

Die Antwort ist ein Satz. Ohne Antwort gibt es keinen Test. Was die Antwort trägt:
- **Standardumfang je Einheit mit Logik:** Happy Case, Unter- und Obergrenzen, der Beweis, dass die Fehlerbehandlung greift. Ungültige Eingaben dort, wo sie von außen ankommen (Route, Formular, Job-Payload, LLM-Antwort, Datei), nicht an internen, typisierten Funktionen.
- **Darüber hinaus, was man an keiner einzelnen Codestelle sieht:** Nebenläufigkeit und Sperren, fremde Org oder fremder Besitzer, DB-Constraints und Migrationen, Außenränder (LLM, Browser-Speicher, fremde Systeme). Je Risiko ein Test, keine Matrix aller Kombinationen. Jedes mögliche Deadlock-Opfer (Review Focus 5) ist ein eigenes Risiko.
- **Wörtliche Werte** (Zahl, Text, Feldliste) nur, wenn sie eine Zusage nach außen sind: eine Frist aus dem Löschkonzept, ein Vertrag mit einem anderen System oder einer anderen, getrennt gepflegten Stelle. „Steht so in der Spec“ ist keine Zusage nach außen.
- **Engere Regeln** aus der Teststrategie in `CLAUDE.md` gehen vor.

Ein Test ohne Antwort ist ein Befund vom selben Rang wie ein fehlender Test mit Antwort, in Plan-Review, Task-Review, Härtung und PR-Review. Grund: In einem Repo mit zwei Monaten `auto-feature` stammten gut 80 % aller Testdateien aus diesen Läufen, zuletzt kamen 2,7 Zeilen Test auf jede Zeile Code. Ein Review fand nur 0,3 % sinnlose Tests; die Masse war Übertestung sinnvoller Dinge, erzeugt von der früheren Mechanik (Nachweis im Zweifel `[Test]`, Tests in jedem Task, „Test fehlt“ nach jeder grünen Mutation).

## Plan (C): Review Focus

**DoD-Abdeckung:** Jeder DoD-Punkt mit Nachweis `[Test]` steht im Plan mit Task und Test (`TF1-D2 → Task 3, Test <Name>`), jeder `[Code]`-Punkt mit seinem Task (`TF1-D3 → Task 2, Code`); den belegt der Task-Review am Diff. `[Durchklick]`- und `[Ops]`-Punkte kommen in die PR-Checkliste. Ein `[Test]`-Punkt ohne Task und Test ist ein Plan-Fehler; war er nicht benennbar, ist er nach Start-Schritt 1 schon auf `[Code]` umgestuft.

**Tests je Task:** Jeder Task hat eine Zeile `Tests:`. Sie nennt je Test den Namen und den Laufzeitfehler, den er fängt (`Tests: „lehnt fremde Org ab“ – fehlender Scope-Filter gibt fremde Einträge heraus`), oder lautet `Tests: keine – <ein Satz Grund>`. Ein Task ohne diese Zeile oder ein Test ohne benannten Laufzeitfehler (außer einem, der einen `[Test]`-Punkt belegt) ist ein Plan-Fehler. Der Plan-Review prüft beide Richtungen: fehlt ein Test für ein benanntes Risiko, und fängt jeder geplante Test wirklich etwas?

**Task-Größe:** Ein Task berührt höchstens einen Risikobereich (Sperre, Job, Zustandsautomat, Migration, Raw SQL) und bringt höchstens etwa 300 Zeilen Produktivcode. Größere Tasks teilt der Plan, kleine hängt er weiterhin an einen benachbarten Task an. Der Plan-Review prüft das mit. Grund: Im Cockpit-Lauf (2026-11-13, Sonnet zusammen 560 M Input-Äquivalent) trugen die Implementierer 56 % der Kosten. Der Median lag bei 4 M je Task, die sechs größten Tasks kosteten 11–22 M, und der größte (ein Broker mit Sperren, Protokoll und Aufräumlauf) brauchte 341 API-Aufrufe.

Jeder Plan hat einen Abschnitt **„Review Focus“**. Er beginnt mit der folgenden festen Checkliste wiederkehrender Fehlerklassen, danach folgen TF-spezifische Punkte. Je Punkt steht im Plan entweder „trifft zu → Task <n>“ oder „trifft nicht zu“ mit einem Satz Begründung. Punkte 1, 2 und 4 nennen beim Zutreffen zusätzlich den Test (`Test <Name>`); Punkte 3, 5 und 6 belegt der Code, der Task-Review liest sie. Ein zutreffender Punkt ohne Task, bei 1, 2 und 4 ohne Test, ist ein Plan-Fehler.

1. **Sperren mit deterministischem Wartenachweis:** Jede neue Sperre (Advisory Lock, `SELECT … FOR UPDATE`, Lease-Spalte, Mutex) bekommt einen Test, der nachweist, dass der zweite Aufrufer tatsächlich wartet bzw. abgewiesen wird: über Barriere oder Latch im ersten Halter oder Abfrage des Sperrzustands (`pg_locks`), nicht über `sleep` oder Timing.
2. **Werte, die die App-Validierung bestehen, aber an Prisma/PostgreSQL scheitern oder still verfälscht werden:** je Feldart, die von außen kommt und in die DB geht (Datum, Freitext), ein Grenzwert-Test gegen die echte DB, nicht je Feld:
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
  - Auftrag „als Design prüfen“: fehlende Anforderungen, Widersprüche, falsche Datei-/Typ-Annahmen gegen den echten Code, Sicherheits- und Betriebsrisiken, Testbarkeit; beim Plan zusätzlich: deckt er die Spec und jeden DoD-Punkt per ID vollständig ab, hält jeder Task die Task-Größe ein (höchstens ein Risikobereich, etwa 300 Zeilen Produktivcode), ist jeder Punkt der „Review Focus“-Checkliste gegen den echten Code richtig als zutreffend/nicht zutreffend eingestuft und mit Task (und wo verlangt Test) hinterlegt, und besteht jede Zeile `Tests:` die Frage aus „Was einen Test bekommt“, in beide Richtungen?
  - Ausgabe Blocker / Wichtig / Klein mit Datei-/Zeilenbeleg
  - **ändert nichts** im Repo, kein `git checkout`/`switch`/`stash`/`reset`, keine Subagenten (im eigenen Wegwerf-Repo, nächster Punkt, sind Edits und git-Befehle erlaubt)
  - Wegwerf-Repos und Messskripte nur in einem frischen Temp-Verzeichnis: `d=$(mktemp -d) && cd "$d" || exit 1`, alle weiteren Befehle in derselben `&&`-Kette oder mit absoluten Pfaden unter `$d`. `$d` gilt nur im selben Bash-Aufruf, in Folgeaufrufen den ausgegebenen Pfad wörtlich einsetzen (`git -C /…/tmp.XXXX …`), nie `$d` (`cd ""` gelingt und bleibt im Repo). Nie `rm` als ersten Schritt einer Kette, nie ein Skript ohne geprüftes `cd`.
  - Pläne **nicht probeweise umsetzen**; was nicht durch Lesen belegbar ist, als Verdacht kennzeichnen
- **Die Hauptsession urteilt** über jeden Befund (`superpowers:receiving-code-review`), statt ihn abzunicken, und arbeitet ihn ein. Begründete Ablehnungen kommen ins Dokument.
- **Runde 2 nur**, wenn Runde 1 Blocker oder Wichtiges ergab. Danach geht es immer weiter, auch mit offenen Befunden. Diese stehen als Abschnitt **„Offene Review-Punkte“** in Spec bzw. Plan und später im PR-Body. Eine dritte Runde gibt es nicht.

## Umsetzung (E)

Die Hauptsession schreibt **weder Produktiv- noch Testcode**, auch keine 4-Zeilen-Config. Jeder Plan-Task geht an `Agent(subagent_type: "sonnet-xhigh" | "sonnet-high", model: "sonnet")` nach der Effort-Regel, kleine Tasks hängst du an einen benachbarten Task an. Die Konventionen aus `CLAUDE.md` gelten strikt.

**Tests im Implementierer-Briefing:** Das Briefing enthält die Zeile `Tests:` des Tasks und die Frage aus „Was einen Test bekommt“. Der Implementierer schreibt genau diese Tests, testgetrieben. Hält er einen weiteren Test für nötig, schreibt er ihn nur mit benanntem Laufzeitfehler und nennt ihn im Bericht; das gilt auch bei `Tests: keine`. Ohne Zeile `Tests:` und ohne solchen Fund schreibt er keinen Test. Die Testschritte je Task stammen sonst aus der Plan-Vorlage (siehe Autonom-Modus), nicht aus dem `subagent-driven-development`-Template.

### Effort-Regel

Die Hauptsession legt den Agent-Typ je Implementierung und je Review beim Dispatch fest und nennt ihn im Abschlussbericht unter „Umsetzung“.

| Typ | Wofür |
|---|---|
| `sonnet-xhigh` | Implementierung **und** Task-Review (nicht Re-Review) jedes Tasks, der **DB** (Schema, Migration, Abfragen), **Sperren**, **Jobs/Inngest**, **Zustandsautomaten** oder **Raw SQL** berührt (Task-Review: Ausnahme Messphase, siehe unten). Außerdem alle Härtungs-Subagenten (E2). |
| `sonnet-high` | **Re-Reviews** von Fix-Diffs, auch bei DB, Sperren, Jobs, Zustandsautomaten oder Raw SQL (einzige Ausnahme unter „Fix-Runden“); **lesende Task-Reviews** reiner Refactor-/UI-Tasks; **mechanische Implementierungen** (Verschieben, Umbenennen, Re-Exporte, Texte, Styles ohne neue Logik); in der **Messphase** Task-Reviews gerader Tasknummer (siehe unten). |

- **Im Zweifel und bei Misch-Tasks** gilt für Implementierung und Task-Review `sonnet-xhigh`. Re-Reviews bleiben bei `sonnet-high`. Ein Task ist erst dann mechanisch, wenn er keine neue Verzweigung, Invariante oder Abfrage einführt.
- **Messphase Task-Review (ab Stand nach generalskills PR #20):** Task-Reviews, die nach dieser Regel an `sonnet-xhigh` gingen, gehen bei **gerader Tasknummer** an `sonnet-high`, mit unveränderten Mutationsproben, auch bei DB, Jobs, Zustandsautomaten oder Raw SQL. Ausgenommen sind Tasks mit Sperren oder Migrationen; die bleiben bei `sonnet-xhigh`.
  - **Tasknummer:** die erste Ziffernfolge der Task-Nummer im Plan (`T2a` und `T2b` zählen als 2, `T1+T2` als 1, `Task 9a` als 9).
  - **Rolle `Task-Review-M T<n>`** nur für diese Reviews. Alle übrigen heißen weiter `Task-Review T<n>`, auch die lesenden Reviews reiner Refactor-/UI-Tasks mit `sonnet-high`. So bildet die Messphase eine eigene Gruppe in der Auswertung und verschmilzt nicht mit ihnen. Jede `Task-Review-M`-Zeile bekommt ihr Urteil per `bewerte`, sonst ist die Messung wertlos.
  - **Vergleichsgruppe** ist `Task-Review` mit `sonnet-xhigh`. Sie enthält auch die ausgenommenen Sperr- und Migrations-Tasks, die schwerer sind; das gehört in jede Auswertung als Einschränkung.
  - **Ende der Messphase:** je 20 bewertete Zeilen `Task-Review-M` (`sonnet-high`) und `Task-Review` (`sonnet-xhigh`), gezählt über alle Läufe und Skill-Stände, also ohne `--nach-version`. Gezählt wird das n aus „(n von m)“ in der Spalte „B+W je 100k (erhoben)“ der Zeile der Rolle; die Spalte „Läufe“ enthält auch unbewertete Zeilen und zählt zu viel. Dann entscheidet der User über die Regel.
  - **Wer zählt:** Die Hauptsession nennt im Abschlussbericht jedes Laufs die Zahl der bewerteten `Task-Review-M`-Zeilen und der `Task-Review`-Zeilen mit `sonnet-xhigh` des eigenen Repos, aus `summarize-all --root <Ordner mit den Statistik-Dateien des Repos>` (`auto-feature` legt sie unter `docs/superpowers/runs/` ab, sonst nach Repo-Konvention, nicht unter dem Standard `~/.claude/agent-stats`; `--root` durchsucht den Ordner rekursiv). Die Summe über mehrere Repos führt der User.
  - **Bruch ab Stand nach generalskills PR #21** (Tests nach Bedarf): Eine grüne Mutation ist nur mit benanntem Schaden ein Befund, und überflüssige Tests zählen als Befund. Das trifft `Task-Review-M` und `Task-Review` gleich, der Vergleich zwischen beiden bleibt also gültig. Absolute Ausbeuten vor und nach dem Bruch nicht vergleichen; dafür `summarize-all --root <Ordner mit den Statistik-Dateien des Repos> --nach-version` (ohne `--root` liest es nur `~/.claude/agent-stats`).
  - **Grund:** Im Lauf zentraler MCP (2026-11-12) brachten Task-Reviews mit `sonnet-xhigh` 2,1 Blocker+Wichtig je Million Input-Äquivalent und solche mit `sonnet-high` 2,2, bei einem Viertel der Kosten je Review. Das waren aber nur 6 Reviews mit `sonnet-high`.
- **Fix-Runden** laufen als Fortsetzung desselben Implementierers (`SendMessage`), also mit dessen Typ, solange dessen Kontext klein ist: Die Task-Notification meldet `subagent_tokens` (Endkontext), und bis etwa **250k** spart die Fortsetzung die Einarbeitung. **Darüber** schreibt ein frischer Fixer (`TF<n> Fix T<k>`, Typ nach dieser Regel) die Korrektur. Sein Briefing: Plan-Task, Commit-Bereich des Tasks, betroffene Dateien, die Befundliste wörtlich, Testumfang und Berichtsgrenze wie bei Implementierern. Grund: Jeder Aufruf einer Fortsetzung liest den ganzen Kontext des Implementierers erneut. Im Cockpit-Lauf hatten 50 von 56 Implementierern mindestens eine Fix-Runde; ein Implementierer samt Fix-Runden kostete im Schnitt 5,4 M Input-Äquivalent (Median 4,1 M), ein frischer Fixer unter 1 M. Ausnahme: Bringt ein Fix neue Logik (Verzweigung, Invariante, Abfrage) oder einen der `sonnet-xhigh`-Bereiche in einen `sonnet-high`-Task, schreibt ihn ein frischer `sonnet-xhigh`-Implementierer. Statt des Re-Reviews folgt dann ein volles `sonnet-xhigh`-Task-Review mit Mutationsproben, unabhängig von der Tasknummer (die Messphase gilt hier nicht, Rolle `Task-Review T<n>`).
- **Unverändert bleiben** die Opus-Reviews (B/D) und die Härtungs-Subagenten (E2, `sonnet-xhigh`). Begründung: Alle 28 Blocker des Referenzlaufs kamen aus Opus-Reviews, und die Härtung fand in jedem TF echte Lücken.
- **Begründung des Abschlags:** Re-Reviews brachten 0,14 Blocker+Wichtig je 100k Tokens (Median 91k), und beide echten Funde lagen im eng umrissenen Fix-Diff. Lesende Reviews von Refactor-/UI-Tasks kosteten 100–136k und fanden 0–1 Wichtig. Ein kleineres Modell als Sonnet ist nicht vorgesehen, weil auch Re-Review-Funde Transaktions- und Deadlock-Semantik verlangten.

### Testumfang

Die ganze Suite läuft **einmal je TF**, in der Verifikation. Implementierer, Fix-Runden, Reviews und Härtungs-Subagenten lassen nur laufen:
- Typecheck und die Testdateien des Tasks bzw. Fixes
- die Tests, die von den geänderten Dateien abhängen: der Befehl aus `CLAUDE.md`, sonst das Runner-Äquivalent (z. B. `vitest related --run <dateien>`, Jest `--findRelatedTests`)

Das steht ausdrücklich im Briefing, denn die Templates von `subagent-driven-development` lassen sonst die ganze Suite laufen. **Ausnahme:** Ändert ein Task Test-Infrastruktur, Schema oder Migrationen, Abhängigkeiten oder Build-Konfiguration, läuft dort einmal die ganze Suite, weil der Import-Graph die Betroffenen nicht findet.

### Mutationsproben im Task-Review

**Task-Reviews mit Logik führen Mutationsproben durch.** Logik heißt: neue Verzweigung, Invariante, Validierung, Abfrage oder ein neuer Zustandsübergang. Rein lesend geprüft werden nur reine Refactor-/UI-Tasks ohne neue Logik. Im Referenzlauf fanden Reviews mit Mutationsproben echte Laufzeitfehler (Cursor-Tag → 500, „Mehr laden“ hängt bei Geräteuhr 1970, Reconcile ohne Verfügbarkeitsprüfung, ungetestete Sperren).

Ins Review-Briefing **jedes** Task-Reviews gehört, auch des rein lesenden:
- **Plan-Zuordnung:** die `[Code]`-DoD-Punkte des Tasks mit ihrer Zuordnung aus dem Plan (`TF1-D3 → Task 2, Code`) und die ihm zugeordneten Review-Focus-Punkte 3, 5 und 6; der Review belegt sie am Diff.
- **Gegenrichtung:** Je neuem Test des Tasks die Frage aus „Was einen Test bekommt“. Tests ohne Antwort sind zusammen ein Befund Wichtig „Test überflüssig“ mit der Liste der Testnamen und je einem Satz. Das gilt auch für Refactor-/UI-Tasks (Render- und Snapshot-Tests).

Zusätzlich in das Briefing eines Reviews mit Mutationsproben:
- **Vorrang vor dem Template:** Die Reviewer-Templates von `subagent-driven-development` (`task-reviewer-prompt.md`, `re-review-prompt.md`) verlangen ein rein lesendes Review, Tests nur bei konkretem Zweifel und keine git-Befehle. Das Briefing sagt ausdrücklich, dass alle drei Vorgaben für dieses Review aufgehoben sind und stattdessen gilt: Arbeitsbaum nur temporär ändern, Endstand = Ausgangsstand, nur die betroffenen Testdateien laufen lassen, `git status`/`git diff` nur zur Kontrolle des Endstands, sonst keine git-Befehle im Repo (im eigenen Wegwerf-Repo, siehe unten, sind sie erlaubt). Das gilt auch für Re-Reviews, die mutieren.
- Je neuer Verzweigung bzw. Invariante eine Mutation (Zweig entfernen, Bedingung umdrehen, Sperre oder Scope-Filter weglassen) und nur die betroffenen Testdateien laufen lassen, nicht die ganze Suite.
- Die Mutation danach von Hand zurücknehmen. Am Ende muss `git status` den Stand vor dem Review zeigen. Kein `git checkout`/`stash`/`reset`, keine Commits im Repo.
- Wegwerf-Repos und Messskripte nur in einem frischen Temp-Verzeichnis: `d=$(mktemp -d) && cd "$d" || exit 1`, alle weiteren Befehle in derselben `&&`-Kette oder mit absoluten Pfaden unter `$d`. `$d` gilt nur im selben Bash-Aufruf, in Folgeaufrufen den ausgegebenen Pfad wörtlich einsetzen (`git -C /…/tmp.XXXX …`), nie `$d` (`cd ""` gelingt und bleibt im Repo). Nie `rm` als ersten Schritt einer Kette, nie ein Skript ohne geprüftes `cd`.
- Ergebnis je Probe im Review: „Mutation → Test <Name> rot“, oder bei „kein Test rot“ der Schaden im Betrieb, den die Mutation anrichten würde (Datenverlust oder -leck, falsche Anzeige, Absturz, Hänger). Ein Befund Wichtig „Test fehlt“ entsteht nur, wenn dieser Schaden benannt ist und beim Lesen des Codes nicht auffiele (Maßstab: „Was einen Test bekommt“). Sonst steht eine Zeile „kein Test rot, kein eigener Test nötig: <ein Satz>“ ohne Befund.
- Re-Reviews mutieren nur, wenn der Fix-Diff selbst Logik ändert, und dann nur dort.
- Reviews mit Mutationsprobe (auch Re-Reviews) erst dispatchen, wenn kein anderer Subagent im selben Worktree arbeitet, und bis zu ihrem Ende keinen weiteren dort starten. Warten statt auslassen.

### Task-Reviews und Korrekturdurchläufe

Die Task-Reviews von `subagent-driven-development` (Spec-Treue und Codequalität je Task) bleiben, sie sind kein PR-Review-Loop.
- **Grenze:** Je Task gibt es nach der Erstumsetzung höchstens 2 Korrekturdurchläufe.
- **Kein Re-Review für reine Kleinigkeiten:** Behebt eine Fix-Runde nur Befunde der Stufe Klein und/oder streicht sie nur Tests („Test überflüssig“) und ändert keine Logik (keine neue Verzweigung, Invariante oder Abfrage), entfällt der Re-Review. Der Fixer meldet Commit und Testzahl, die Hauptsession prüft nur `git diff --stat` gegen die Befundliste. Grund: `sonnet-high`-Re-Reviews fanden im Cockpit-Lauf 0/1/13 (14 von 56 bewertet) und in den Läufen zentraler MCP und Beitrags-Ansicht zusammen 0/1/13 in 9.
- **Danach offene Qualitätsbefunde** kommen unter „Offene Review-Punkte“ in den PR-Body.
- **Sind danach Tests rot oder ist der Build kaputt:** kein PR für dieses TF. Branch pushen, Stand und Ursache im Abschlussbericht melden, mit den unabhängigen TFs weitermachen.

## Härtungsdurchgang (E2)

Die Hauptsession verantwortet den Durchgang. Die Durchsicht samt Test und Fix gibt sie an einen oder mehrere `sonnet-xhigh`-Subagenten (bei großen TFs getrennt, z. B. Server und Client). Mehrere laufen nacheinander oder in getrennten Worktrees, weil sie mutieren und fixen. Ins Briefing gehört die Temp-Verzeichnis-Regel für Wegwerf-Repos und Messskripte aus „Mutationsproben im Task-Review“. Die Hauptsession prüft deren Antworten und gefundene Lücken selbst und fordert Fehlendes nach.

**Durchsicht und Fix trennen, sobald der Kontext wächst:** Das Briefing sagt dem Härtungs-Subagenten, dass er die acht Fragen erst vollständig beantwortet und dann die Lücken schließt. Liegt sein Kontext dabei über etwa 250k (er sieht das am Umfang des Gelesenen, im Zweifel nach etwa 60 Werkzeugaufrufen), schließt er die laufende Lücke ab und meldet die übrigen als Liste: Frage, Stelle, failing test, falls schon geschrieben; dazu die Tests, die nach Frage 8 zu streichen sind. Diese Lücken schließt und diese Tests streicht ein frischer `sonnet-xhigh`-Fixer (`TF<n> Fix Härtung`); für ihn gilt die Regel „Klasse statt Instanz“ unverändert. Grund: Härtungs-Subagenten kosteten im Cockpit-Lauf 2,3–16,4 M Input-Äquivalent je Agent (Ø 7,9 M) und brauchten im Lauf zentraler MCP bis zu 102 Aufrufe, weil Durchsicht und alle Fixes in einem Kontext liefen. Die Aufteilung nach Bereichen bleibt, weil sie in allen drei Läufen betriebsrelevante Lücken fand (0,76–1,42 je 100k). Die Kosten des Fixers `TF<n> Fix Härtung` landen in der Auswertung in der Gruppe `Fix`, nicht in `Härtung`.

Vor dem PR den gebauten Code systematisch durchgehen und diese acht Fragen **schriftlich mit vollständiger Aufzählung** beantworten. Trifft keine zu, genügt ein Satz.

1. **Lange Operationen:** Timeouts, Leases, Stuck-Erkennung, alle, auch in Schleifen.
2. **Teilzustandsfenster** (DB + Storage, zwei Dateien): Was bleibt beim Absturz dazwischen liegen, und ist es auffindbar?
3. **Zustandsübergänge:** Wer löst aus, ist es atomar, was passiert bei doppelter oder verspäteter Auslösung?
4. **Zeitpunkt-Zusagen** (eingefrorene Dokumente/Protokolle): Halten sie, wenn Daten danach gelöscht werden?
5. **Stille Fallbacks:** jedes `catch`, `?? default`, jedes Überspringen. Wäre ein sichtbarer Fehler besser?
6. **Zwei Worker/Geräte gleichzeitig:** Was passiert, wenn einer enteignet wird, während er noch schreibt?
7. **Endgültigkeitszusagen:** jede Stelle, die etwas als dauerhaft, nicht wiederholbar, endgültig oder „immer/nie“ markiert, in Code (Statuswerte, Sperren, Retry-Verbote) und in Texten (Meldungen, Kommentare). Gilt die Zusage für **jeden** Weg, der dort ankommt, oder auch für Fälle, in denen ein neuer Versuch gelingen kann?
8. **Wirksamkeit der Tests, in beide Richtungen:** für jede neue Verzweigung bzw. Invariante eine Mutationsprobe (Zweig entfernen oder Bedingung umdrehen) gegen die betroffenen Testdateien, nicht die ganze Suite. Wird kein Test rot, nennt die Antwort den Schaden im Betrieb; ein Test fehlt nur, wenn dieser Schaden beim Lesen des Codes nicht auffiele. Umgekehrt: Welche neuen Tests des TF fangen keinen Laufzeitfehler (Frage aus „Was einen Test bekommt“)? Die werden gestrichen.

- **Klasse statt Instanz:** Braucht eine Stelle Behandlung, behandelst du im selben Durchgang alle Stellen derselben Klasse.
- **Lücken schließen:** Test, Fix und Streichung schreibt ein `sonnet-xhigh`-Subagent (bei geteilter Härtung der Fixer, siehe oben).
  - **Echtes Fehlverhalten (Fragen 1–7):** failing test → Fix → grün; dieser Regressionstest besteht die Frage aus „Was einen Test bekommt“ schon durch den Fund. Betrifft ein Fund aus Frage 7 nur Text (Meldung, Kommentar), ist er Prosa: Text ändern, kein Test.
  - **Fehlender Test (Frage 8):** nur mit dem Schaden aus Frage 8 (benannt, beim Lesen nicht aufgefallen). Es gibt nichts zu fixen: Der Subagent schreibt den Test, der die Mutation rot macht.
  - **Überflüssige Tests (Frage 8):** werden gestrichen, ohne Ersatz.
- **Zweiter Fund = Design-Pass**, kein weiterer Flicken. Das gilt, wenn dieselbe Eigenschaft im selben Modul ein zweites Mal auffällt, egal ob in Spec-/Plan-Review, Task-Review oder Härtung:
  - Die Hauptsession überarbeitet den betroffenen Abschnitt in Spec und Plan, ohne neue Review-Runde.
  - Sonnet setzt die Änderung um.
  - Der PR-Body vermerkt den Design-Pass.
- **Ergebnis:** Abschnitt „Härtungsdurchgang“ im PR-Body.

**Binär-Check** (Ausgabe muss leer sein; nach `git fetch`, Basis = PR-Basis). Ein Steuerzeichen macht eine Datei für git binär, ihr Diff ist dann im Review unsichtbar:
`git diff --numstat origin/<basis>...HEAD | awk -F'\t' '$1=="-" {print "BINÄR: "$3}'`

## PR (F) und Stapel

- **Body:**
  - erste Zeile `Herkunft: auto-feature` (daran legt `pr-review-loop` die Prüftiefe fest: Task-Reviews mit Mutationsproben und Härtung sind schon gelaufen)
  - was gebaut wurde
  - Links zu Spec und Plan
  - DoD als Haken mit IDs, `[Durchklick]`-Punkte als Checkliste für den User
  - Härtungsdurchgang
  - Offene Review-Punkte
  - Verifikations-Output
  - **Tests im Diff:** die Ausgabe des Befehls unten, ohne Grenzwert. Liegt das Verhältnis über etwa 1,5, steht ein Satz dazu, welche Risiken den Umfang tragen.
  - lauf-spezifische Zusätze aus dem Feature-File
  - Merge-Hinweise: Überschneidungen, Basis, Reihenfolge
  - „Reasoning-Weg“: der TF-Teil des Abschlussberichts (siehe unten), damit er auch nach dem Chat erhalten bleibt
- **Befehl für „Tests im Diff“** (nach `git fetch`, Basis = PR-Basis; zählt hinzugefügte Zeilen von Code-Dateien. Testhilfen und Test-Setup gelten als Test. Doku, Config (`*.config.*`), Daten, Lockfiles und Binärdateien zählen nicht; Umbenennungen zählen als neue Datei. Bei Code +0 steht „Verhältnis –“):
  `git -c core.quotePath=false diff --numstat --no-renames origin/<basis>...HEAD | awk -F'\t' '$1=="-"{next} $3 ~ /\.config\.[^\/]+$/ {next} $3 !~ /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs|py|go|rb|java|kt|rs|cs|php|swift)$/ {next} $3 ~ /(^|\/)(tests?|__tests__|testing|__mocks__|__fixtures__|fixtures)\// || $3 ~ /test-(helpers|fixtures|utils)|(^|\/)conftest\.py$|[._-](test|spec|testdaten|setup)\.[^\/]+$|_test\.(go|py)$|(^|\/)test_[^\/]*\.py$/ {t+=$1; next} {c+=$1} END {printf "Test +%d · Code +%d · Verhältnis %s\n", t, c, (c ? sprintf("%.1f", t/c) : "–")}'`
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
- **Tests im Diff:** Verhältnis wie im PR-Body, über etwa 1,5 mit dem Satz dazu
- **Offene Fragen und Entscheidungen** für den User, inklusive Abweichungen von repo-eigenen Workflow-Dokumenten und „Effort nicht garantiert“, falls zutreffend
- **Nötige Ops-Schritte:** Migrationen, Env, Resync
- **Agent-Statistik:** Pfad und die Auswertung je Rolle

Letzte Zeile: „Stopp. Bitte prüfen; danach `/pr-review-loop <PR>` je PR.“

## Agent-Statistik

**Jeder Lauf führt eine Agent-Statistik**, als Grundlage für spätere Token-Optimierung. Dieses Format gilt auch für `pr-review-loop`, `fix-findings` und jede andere Session, die Subagenten startet. Ablage nach Repo-Konvention, sonst `docs/superpowers/runs/<YYYY-MM-DD>-<lauf>-agent-stats.md`. Außerhalb von `auto-feature` liegt sie unter `~/.claude/agent-stats/<repo>/`.

- **Kopf:** Repo, Lauf, Session-ID der Hauptsession. Die Zeile „Skills:“ schreibt das Skript selbst (siehe „Skill-Stand“).
- **Eintragen einmal je TF**, nicht nach jeder Task-Notification: nach dem PR des TF (endet ein TF ohne PR, an der TF-Grenze), spätestens vor `summarize`, ein einziger Bash-Aufruf mit `import … --tf TF<n>` und `bewerte` (unten). `--tf` ist Pflicht, sobald die Session mehr als eine Statistik-Datei führt oder fremde Agenten enthält (z. B. `feature-file` davor, mehrere PRs im Reviewer-Thread): ohne Filter trägt `import … self` alle Agenten der Session in jede Datei ein, und `summarize-all` zählt doppelt. Die Messwerte liest das Skript aus den Subagent-Transkripten der Session, sie überstehen also jede Kompaktierung. Grund: Im Lauf security-audit waren rund 200 der 761 Aufrufe der Hauptsession Statistik-Einträge, etwa ein Viertel ihrer Kosten. **Ausnahme:** `security-audit` und `feature-file` tragen weiter per `add` ein (ihre Abläufe und Evals sind darauf ausgelegt, die Beschreibung ihrer Agenten hat kein TF-Präfix).
- **Agent-Beschreibung = `<TF> <Rolle>`:** Die `description` jedes Agent-Aufrufs beginnt mit dem TF und nennt dann die Rolle in der Schreibweise unten, z. B. `TF2 Spec-Review R1`, `TF2 Impl T3`. `import` übernimmt TF und Rolle daraus. Eine Fix-Runde per `SendMessage` bleibt in der Zeile ihres Implementierers: Die Spalte Fix-Runden zählt sie, tokens, Dauer und Werkzeuge schreibt der nächste `import` fort (die Urteilsspalten bleiben). Ein frischer Fix-Implementierer heißt `TF2 Fix T3`. **Bruch gegenüber älteren Dateien:** Dort stand jede Fortsetzung als eigene Zeile `Fix T<n> (Forts. #m)`; ab dem Stand mit `import` enthält die Zeile `Impl` die Fix-Runden, und `Fix T<n>` gibt es nur noch für frische Fix-Implementierer. `summarize` und `summarize-all --nach-version` zeigen an dieser Stelle einen künstlichen Sprung (Impl höher, Gruppe Fix kleiner). **Zweiter Bruch:** `Fix Härtung` (frischer Fixer nach der Härtung) zählt zur Gruppe `Fix`, die Kosten der Härtung wandern also ab diesem Stand teilweise von `Härtung` nach `Fix`.
- **Werkzeug:** `~/.claude/skills/auto-feature/scripts/agent-stats.py` (nur Python-Standardbibliothek), in jedem Aufruf mit vollem Pfad, denn eine Shell-Variable überlebt den Bash-Aufruf nicht. Es hält das Format ein, damit sich die Dateien über Läufe hinweg auswerten lassen:
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py import <datei> self [--tf TF<n>] [--kopf "Repo: …"]`: trägt die noch nicht eingetragenen Subagenten der Session ein, je Agent eine Zeile; mit `--tf TF2` (mehrfach möglich, `12` und `PR12` gelten gleich) nur die eines TF; das Präfix der Beschreibung darf `TF2 `, `TF2: ` oder `tf2 ` lauten, ohne erkanntes Präfix übersprungene Agenten meldet das Skript auf stderr. Bereits eingetragene erkennt es an Agent-ID und Transkriptgröße (Kommentarzeile `agent-stats:importiert` in der Datei): Wächst das Transkript, etwa durch eine Fix-Runde per `SendMessage`, aktualisiert der nächste Aufruf die Zeile. Noch laufende Agenten (Transkript in den letzten 30 min geändert) kommen beim nächsten Aufruf; ein Agent ohne `finished`, der seit 30 min still steht, kommt mit Status `abgebrochen` herein (endete er regulär mit `end_turn` oder mit einer reinen Text-Antwort ohne Werkzeugaufruf: `fertig`). Verschachtelte Subagenten (laufen unter einem Subagenten) überspringt es mit Hinweis. Legt die Datei bei Bedarf an und stempelt den Skill-Stand wie `add`.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py bewerte <datei> <<'EOF'` mit einer JSON-Zeile je bewerteter Zeile, z. B. `{"tf": "TF2", "rolle": "Spec-Review R1", "bwk": "1/4/6", "angenommen": "9", "betrieb": "2: Leck im Bericht; Absturz bei leerem Repo"}` oder mit `"nr": 12` statt TF und Rolle (die `nr` steht in der Ausgabe von `import`; gibt es TF und Rolle mehrfach, bewertet ein zweiter Aufruf mit `nr`). Felder: `bwk`, `angenommen`, `betrieb`, `status`; die Spalte Fix-Runden führt `import` aus den Fortsetzungen im Transkript. `tf` gilt in jeder Schreibweise (`PR12` wie `12`). Passt eine Angabe nicht auf genau eine Zeile, oder widersprechen `nr` und `tf`/`rolle` einander, schreibt es nichts. Die Werte stehen ohnehin im Review-Verlauf von Spec und Plan.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py add <datei> --rolle "<Rolle>" --typ <agent-typ> --tokens <subagent_tokens> --dauer <duration_ms> --tool-uses <n> [--tf …] [--bwk 0/1/3] [--angenommen …] [--betrieb "n: …"] [--fix-runden …] [--status …]`, bei einer `SendMessage`-Fortsetzung zusätzlich `--fortsetzung-von <#>` mit der Nummer der Erstzeile des Agenten (eine angegebene Fortsetzungszeile lenkt es auf deren Erstzeile um), dann rechnet es `(kum.)` und `Δ tokens` selbst. Eine neue Datei legt es an, Kopfzeilen per `--kopf "Repo: …"`, und stempelt dabei den Skill-Stand. Nur für Läufe ohne Subagent-Transkript in dieser Session, etwa Evals per `claude -p`.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py summarize <datei> --write`: am Ende des Laufs. Es warnt auf stderr vor Prüfläufen (Reviews, Härtung, Builder-Check) ohne `bewerte` und vor einem fehlenden Abschnitt „## Threads“ (Zusätze wie „## Threads (Stand …)“ sind erlaubt; ein zweiter Abschnitt wird nicht angehängt). Prüfläufe mit Status `abgebrochen` meldet es nicht, sie haben kein Urteil. Beide Warnungen werden vor dem Abschlussbericht behoben, nicht hingenommen: Im Cockpit-Lauf waren 102 Prüfzeilen unbewertet und die Threads fehlten, sodass sich weder Ausbeute noch Kosten je Rolle aus der Datei ablesen ließen. Schreibt die Auswertung als markierten Block, beim ersten Mal unter eine neue Überschrift „Auswertung je Rolle“ am Dateiende, danach ersetzt es nur diesen Block. Ein älterer, unmarkierter Abschnitt gleichen Namens bleibt stehen und wird von Hand entfernt.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py threads self <weitere local_…-IDs> --subagents --md`: Tokens der Hauptsession, gestarteter Threads und ihrer Subagenten aus den Transkripten, inklusive Cache-Reads und Input-Äquivalent je Modell (Cache-Write 5 min ×1,25, 1 h ×2). Fehlt eine ID, steht sie als Zeile „fehlt“ in der Tabelle, und das Skript endet mit Exit 1. Am Ende des Laufs in den Abschnitt „Threads“, **bevor** Threads archiviert oder gelöscht werden.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py summarize-all [--seit YYYY-MM-DD] [--nach-version]`: Auswertung über alle Dateien unter `~/.claude/agent-stats/` (Grundlage für Regeländerungen wie diese). Mit `--nach-version` steht je Skill-Stand eine eigene Tabelle da, so lässt sich eine Regeländerung vorher und nachher vergleichen.
  - `python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py stamp <datei>`: schreibt den Skill-Stand in eine Datei, die nicht über `add` entstanden ist (z. B. nur Kopf und Threads-Tabelle). Mit `--stand "…" --hinweis "…"` für Nachträge, `--ersetzen` überschreibt vorhandene Stand-Zeilen.
  - Tests nach Änderungen am Skript: `python3 ~/.claude/skills/auto-feature/scripts/test_agent_stats.py`.
- **Rollen-Namen** einheitlich, denn die Auswertung gruppiert nach dem ersten Wort (bei `Review R1` nach dem Fokus): `Spec-Review R<r>`, `Plan-Review R<r>`, `Impl T<n>`, `Task-Review T<n>`, `Task-Review-M T<n>` (nur Messphase, eigene Gruppe), `Re-Review T<n> R<k>` (`k` = Korrekturdurchlauf, bis zu 2 je Task), `Fix T<n>`, `Fix Härtung` (frischer Fixer nach der Härtung, Gruppe `Fix`), `Härtung`, `Design-Pass`, `Builder-Check`; in `pr-review-loop` `Review R1 <Korrektheit|Verträge|Korrektheit+Verträge|Tests|sachlich>` und `Delta-Review R<r>`.
- **Skill-Stand:** Die Skills sind per Symlink an den Checkout von generalskills gebunden, also gilt, was dort ausgecheckt ist. `add` stempelt diesen Stand beim Anlegen der Datei als `- Skills: generalskills@<sha> (<commit-zeit>, <branch>)`, mit `-dirty` bei uncommitteten Änderungen an versionierten Dateien (unversionierte zählen nicht). Wechselt der Stand während eines Laufs, schreibt `add` `- Skills ab #<n>: …` dazu. Lässt er sich nicht ermitteln (kein git-Checkout, git fehlt oder hängt), ist er ganz unbekannt: kein Teilstand, und nach bekanntem Stand steht `- Skills ab #<n>: unbekannt`. Zwei Stände aus derselben Minute sortiert `--nach-version` nach SHA, also zufällig; ein alter, nur datierter Stempel steht vor jedem Stempel mit Uhrzeit desselben Tages. Der Timeout je git-Aufruf (Standard 10 s) steht in `AGENT_STATS_GIT_TIMEOUT`. Grenze: Eine Session folgt dem Skill-Text, den sie beim Aufruf geladen hat. Wird mitten im Lauf gemergt, zeigt die Ab-Zeile den Wechsel des Checkouts, nicht den des geladenen Texts.
- **`<usage>` misst keinen Verbrauch:** `subagent_tokens` ist die Kontextgröße des letzten API-Aufrufs (Input, Cache-Write und Cache-Read) plus dessen Output, keine Summe über die Aufrufe. `Δ tokens` ist bei Fortsetzungen also Kontextwachstum und taugt nur für grobe Vergleiche zwischen Rollen. Kostenaussagen nur mit dem Input-Äquivalent je Modell aus `threads`.

- **Quelle:** bei `import` das Subagent-Transkript: `tokens` nach dem Muster von `<usage>` (Kontext des letzten Aufrufs plus Output, bei Fortsetzungen also der Endkontext; kann um wenige Tokens darunter liegen, wenn der letzte Transkript-Eintrag nur den Stand vom Stream-Anfang trägt), `tool_uses` gezählt, `duration_ms` als Summe der Arbeitssegmente: Pausen über 10 min (Hintergrundarbeit) und die Wartezeit zwischen Abschluss und Fix-Runde zählen nicht, Zeitpunkt = letzter Aufruf, `Δ tokens` = `tokens`. Bei `add` die `<usage>`-Angaben der Task-Notification. Fehlt eine Angabe, steht dort „n/a“, nicht geschätzt.
- **Spalten:** # | Zeitpunkt | TF | Rolle | Agent-Typ | Modell | Effort | tokens | Δ tokens | duration_ms | tool_uses | B/W/K | angenommen | betriebsrelevant | Fix-Runden | Status
- **Fortsetzungen per `add --fortsetzung-von`** (nur ältere Dateien und Handeinträge):
  - `tokens` = gemeldeter Wert, gekennzeichnet mit „(kum.)“: Der Endkontext einer Fortsetzung enthält den Kontext der Vorläufe desselben Agenten.
  - `Δ tokens` = gemeldeter Wert minus Vorwert, also minus dem zuletzt gemeldeten Wert desselben Agenten.
  - Ist der gemeldete Wert kleiner als der Vorwert, ist der Kontext geschrumpft, etwa durch eine Kompaktierung. Dann gilt `Δ tokens` = `tokens`, ohne „(kum.)“, und die Auswertung hält das fest.
  - Erstläufe: `Δ tokens` = `tokens`.
  - **Summen, Mediane und Ausbeuten rechnen mit `Δ tokens`.**
- **betriebsrelevant:** Anzahl der angenommenen Befunde, die im Betrieb sichtbar geworden wären (Fehler oder Absturz, Datenverlust, Hänger, falsche Anzeige, Sicherheits- oder Scope-Lücke), Format `n: Stichwort; Stichwort`. Reine Stil-, Test-, Doku- und Benennungsbefunde zählen nicht. Gilt für Reviews und Härtungsläufe (gefundene Lücken je Härtungs-Subagent), sonst „–“.
- **Auswertung je Rolle:** Läufe, Summe und Median `Δ tokens`, Dauer-Median, B/W/K, Blocker+Wichtig je 100k, betriebsrelevant je 100k. `sonnet-high` und `sonnet-xhigh` getrennt ausweisen, damit sich die Effort-Regel überprüfen lässt (`summarize` trennt nach Agent-Typ).
- **Stand 24.10.2026** (`summarize-all --seit 2026-10-22`, 120 Läufe im Standardformat, Raten nur über Läufe mit erhobenem Wert): Unter den Rollen mit mehreren Läufen brachte die Härtung mit 1,06 betriebsrelevanten Befunden je 100k die höchste Ausbeute, vor Task-Reviews (0,81) und PR-Reviews Runde 1 (0,29–0,80 je Fokus). Frei werdende Tokens gehören eher in E2 als in zusätzliche Review-Runden.

## Ausreden und was stimmt

| Ausrede | Realität |
|---|---|
| „Runde 2 hat noch Wichtiges, eine dritte schadet nicht“ | Genau so entstehen Endlosschleifen. Offenes kommt in „Offene Review-Punkte“, dann weiter. |
| „Vier Zeilen schreibe ich schneller selbst“ | Die Hauptsession orchestriert und prüft. Implementiert wird nur von Sonnet. |
| „Zur Sicherheit nach jedem Task die ganze Suite“ | Die läuft einmal je TF in der Verifikation und dann in der CI. Je Task Typecheck und die abhängigen Tests. |
| „Ich trage jeden Agenten gleich nach seiner Notification ein“ | Jeder Eintrag ist ein eigener Aufruf auf dem vollen Kontext der Hauptsession, im Lauf security-audit ein Viertel ihrer Kosten. Die Werte stehen im Transkript: einmal je TF `import` und `bewerte`. |
| „Der Bericht des Implementierers darf ruhig ausführlich sein“ | Er bleibt bis zur Kompaktierung im Kontext und wird bei jedem weiteren Aufruf mitgelesen. Höchstens etwa 300 Wörter, Details stehen im Commit. |
| „Die Tabelle tippe ich schneller von Hand“ | Handtabellen drifteten (eigene Spalten, fehlendes Δ, fehlende Uhrzeiten) und fielen aus der Auswertung über alle Läufe. |
| „Tests grün, also PR“ | Grüne Tests finden keine Absturzfenster. Erst kommt die Härtung. |
| „Die Tests decken den neuen Zweig ab, steht ja im Namen“ | Erst eine Mutation zeigt, ob ein Test rot wird. Ohne Probe bleibt die Lücke bis zum Review. |
| „Mutation blieb grün, also fehlt ein Test“ | Erst den Schaden im Betrieb benennen. Fällt er beim Lesen auf oder gibt es keinen, ist es kein Befund. |
| „Im Zweifel lieber ein Test mehr, schadet ja nicht“ | Jeder Test kostet Laufzeit, Pflege und Review. Im Zweifel `[Code]` bzw. `Tests: keine`; ein Test ohne benannten Laufzeitfehler ist ein Befund. |
| „Die Spec nennt den Wert, also pinne ich ihn im Test“ | Wörtliche Werte nur bei einer Zusage nach außen. Was in Spec und Code gleich steht, prüft der Review am Diff. |
| „Der Task ist klein, Review lesend reicht“ | Hat er Logik, wird mutiert. Lesend nur reine Refactor-/UI-Tasks. |
| „Spart Tokens: Plan-Review mit Sonnet oder Effort high“ | Alle Blocker des Referenzlaufs kamen aus Opus-xhigh-Reviews. Der Abschlag gilt nur in Phase E nach der Effort-Regel. |
| „Der Task fasst nur kurz die DB an, `sonnet-high` reicht“ | DB, Sperren, Jobs, Zustandsautomaten oder Raw SQL bedeuten `sonnet-xhigh` für die Implementierung und, bis auf die Messphase (gerade Tasknummer, ohne Sperren und Migrationen), für den Task-Review. Das Re-Review des Fix-Diffs geht an `sonnet-high`, außer erst der Fix bringt einen dieser Bereiche in einen `sonnet-high`-Task: Dann folgt ein volles `sonnet-xhigh`-Task-Review. |
| „Ich frag kurz, ob TF1 erst gemergt werden soll“ | Kein Stopp vor den PRs, auch wenn der User online ist. Stapeln ist der Default. |
| „Zum Schluss noch ein Review-Loop über alle PRs“ | Phase G entfällt. Den Review stößt der User an. |
| „Brainstorming fragt mich etwas, ich warte“ | Das Feature-File ist die Antwort. Annahme dokumentieren, weiter. |
| „Der User ist doch online, ich frag kurz“ | Kein Stopp vor den PRs. Default wählen, im Bericht als offene Frage führen. |
| „PRs stehen, ich starte gleich `/pr-review-loop`“ | Erst prüft der User den Lauf (HITL) und stößt dann den Review an. |
