# Spec TF5: `fix-findings` nimmt Audit-Befundlisten ohne PR an

**Feature-File:** `docs/features/2026-11-09-security-audit.md`, TF5 · **Branch:** `skills/audit-ohne-pr` (gestapelt auf `skills/security-audit`) · **Datum:** 2026-11-10

## Ziel

`/fix-findings` nimmt die Befundliste eines `security-audit`-Berichts an, ohne nach einer PR-Nummer zu fragen: Es brancht vom geprüften SHA, fixt wie gewohnt, pusht den Branch und gibt den Link zum Erstellen eines PRs aus. Einen PR öffnet es nicht (Entschieden, User). Der Pfad mit PR bleibt unverändert.

## Andockpunkte (Ist)

| Pfad | Heute | Änderung |
|---|---|---|
| `fix-findings/SKILL.md:3` | Description „on the current PR branch“ | nennt beide Eingänge |
| `fix-findings/SKILL.md:30` (Merge und Deploy) | setzt PR voraus | Audit-Eingang: Befehlswörter werden mit Hinweis ignoriert |
| `fix-findings/SKILL.md:37` (Ablauf 1) | PR aus Kopfzeile oder Branch, sonst Frage | neuer Zweig „Audit-Liste“ vor der PR-Suche |
| `fix-findings/SKILL.md:48` (Zweiter Fund) | `--grep 'Review R'` | Audit-Liste: eine Runde, Regel entfällt |
| `fix-findings/SKILL.md:67` (Ganze Suite) | „keine CI“ per `gh pr checks` | Audit-Liste: kein `.github/workflows/` → ganze Suite einmal vor dem Push |
| `fix-findings/SKILL.md:75-77` (Statistik) | `…-pr<n>-fix.md`, Kopf `PR #<n>` | Audit: `<datum>-audit-<sha7>-fix.md`, Kopf `Security-Audit <sha7>` |
| `fix-findings/SKILL.md:82` (Abschlusstabelle) | `PR #<n> · Head` | Audit: `Security-Audit <sha7> · Branch <name> · Head <sha>` |
| `security-audit/scripts/bericht.py` (`markdown`, `kontext`) | erzeugt Kopfzeile `Repo <repo> · Security-Audit · geprüft auf <sha>`, `<repo>`-Regel | Vertrag, unverändert |
| `README.md` (Tabelle, Zeile `fix-findings`) | PR-Eingang | nennt Audit-Eingang |

## Verhalten (neuer Abschnitt in `fix-findings/SKILL.md`, Ablauf 1)

1. **Erkennung:** Erste nichtleere Zeile der Liste hat die Form `Repo <repo> · Security-Audit · geprüft auf <sha>` (Mittelpunkt U+00B7, `<sha>` 7–64 Hex). Dann gilt der Audit-Eingang; sonst der bisherige PR-Weg.
2. **Repo-Abgleich:** `<repo>` wird wie in `security-audit` gebildet: Basename der `origin`-URL ohne `.git`; ohne `origin` der Ordnername des Haupt-Worktrees (Elternordner von `git rev-parse --path-format=absolute --git-common-dir`); nur `[A-Za-z0-9._-]`. Weicht er ab → Abbruch mit genau dieser Meldung: „Die Befundliste stammt aus Repo `<repo>`, dieses Repo ist `<eigenes>`. Nichts geändert.“
3. **SHA-Prüfung:** `git cat-file -e <sha>^{commit}`; fehlt er (auch nach `git fetch`) → Abbruch „Geprüfter Stand `<sha>` ist hier nicht vorhanden. Nichts geändert.“
4. **Branch:** `security-audit-<YYYY-MM-DD>` vom geprüften SHA (`git switch -c <name> <sha>` bzw. eigener Worktree, falls ein anderer Thread im Verzeichnis arbeitet). Existiert der Name lokal oder auf `origin`, Suffix `-2`, `-3` … Der SHA steht nicht im Namen (`-f…` löst den Force-Push-Wächter aus, `auto-feature/SKILL.md:178`).
5. **Befundprüfung, Fixes, Tests:** wie bisher (Ablauf 2–5). Commit-Bezug `(Audit S-<n>)`. Die Regel „Zweiter Fund“ entfällt (eine Runde).
6. **Ganze Suite:** Gibt es kein `.github/workflows/`, gilt das Repo als „ohne CI“ → ganze Suite genau einmal vor dem Push.
7. **Push:** `git push -u origin <branch>` ohne Nachfrage. Danach Link zum Erstellen des PRs ausgeben: `https://github.com/<owner>/<name>/compare/<default-branch>...<branch>?expand=1` (aus `gh repo view --json nameWithOwner,defaultBranchRef`; ohne `gh` die Remote-URL umrechnen; geht beides nicht, den Befehl `gh pr create --head <branch>` nennen). **Kein `gh pr create`.**
8. **Befehlswörter** „mergen“/„deployen“ mit Audit-Liste: nicht ausführen, unter der Tabelle „Kein PR vorhanden: Merge und Deploy entscheidest du nach dem PR.“
9. **Statistik/Tabelle:** Datei `~/.claude/agent-stats/<repo>/<YYYY-MM-DD>-audit-<sha7>-fix.md`, Kopf `# Agent-Statistik · Security-Audit <sha7> Fix`, Spalte TF = `audit`; Abschlusstabelle beginnt mit `Security-Audit <sha7> · Branch <name> · Head <neuer-sha>`; der PR-Link steht unter der Tabelle.
10. **Antwort an:** Kommt die Liste per Nachricht (selten beim Audit), gilt die bestehende Regel.

## Abnahmekriterien

| ID | Nachweis | Wo |
|---|---|---|
| TF5-D1 | [Durchklick] | PR-Checkliste: Audit-Liste per Copy-Paste → keine PR-Frage, Branch, Commits mit `(Audit S-n)`, Push, PR-Link, kein PR |
| TF5-D2 | [Durchklick] | PR-Checkliste: Liste mit `PR #<n> · …` läuft wie bisher |
| TF5-D3 | [Durchklick] | PR-Checkliste: Audit-Liste aus anderem Repo → Abbruch ohne Branch/Commit |
| TF5-D4 | [Durchklick] | PR-Checkliste: Audit-Liste mit „mergen“ → Push und Hinweis, kein Merge |
| TF5-D5 | [Durchklick] | PR-Checkliste: README-Zeile `fix-findings` nennt den Audit-Eingang |

Zusätzlich (Workflow): Vertragstest in `security-audit/scripts/test_skill_text.py`: Die Kopfzeile, die `bericht.markdown` erzeugt, passt auf das in `fix-findings/SKILL.md` beschriebene Erkennungsmuster (Regex wird aus einem markierten Codeblock in fix-findings/SKILL.md gelesen); die `<repo>`-Regel in fix-findings/SKILL.md nennt dieselben Schritte wie `bericht.kontext` (Stichproben `origin`, `git-common-dir`, `[A-Za-z0-9._-]`).

## Entscheidungen/Annahmen

1. **PR-Link statt PR** (Entschieden, User).
2. **Erkennung über die erste nichtleere Zeile**, weil die Kopfzeile laut TF1 erste Zeile im Codeblock ist; der User kopiert den Codeblock.
3. **Branch vom geprüften SHA** statt vom aktuellen Default-Branch: Zeilenangaben der Befunde gelten für diesen Stand; spätere Commits auf `main` merged der User über den PR.
4. **Ohne Mutationsproben**: reine Prosa plus Vertragstest; Durchklick-DoD laut Feature-File.
5. **Sicherheitsregel aus dem Vorfall 2026-11-10** gilt auch hier: keine Signale an fremde Prozesse, keine Mutationen an Kill-/Lösch-Logik (betrifft TF5 praktisch nicht).
