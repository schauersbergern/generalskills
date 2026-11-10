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

1. **Erkennung:** Irgendeine Zeile der Eingabe, die nach Trimmen von Leerraum voll dem Muster `^Repo [A-Za-z0-9._-]+ · Security-Audit · geprüft auf [0-9a-f]{7,64}$` entspricht (Mittelpunkt U+00B7), schaltet den Audit-Eingang ein. Begleittext, Befehlswörter und Codezaun-Zeilen (```` ``` ````) davor oder danach sind erlaubt. Eine `PR #<n> · …`-Kopfzeile passt nie auf das Muster; findet sich keine Audit-Zeile, gilt der bisherige PR-Weg unverändert.
2. **Befunde:** Nur Zeilen `S-<n> [P1|P2|P3] …` (mit ihren eingerückten Folgezeilen) sind Befunde. `Verdacht (nicht belegt): …` und `Verworfen: … — …` werden nicht gefixt; Verdachtsfälle stehen höchstens als Hinweis unter der Tabelle. Befunde mit `(repo-weit)` statt `datei:zeile` sind zulässig; die Stelle sucht der Fixer selbst.
3. **Repo-Abgleich:** `<repo>` liefert `python3 -I <security-audit>/scripts/bericht.py repo` (neuer Unterbefehl ohne Seiteneffekte, gleiche Funktion `_repo_name` wie `kontext`; `<security-audit>` = `~/.claude/skills/security-audit`, fehlt der Skill, Abbruch mit Hinweis). Weicht er ab → Abbruch mit genau dieser Meldung: „Die Befundliste stammt aus Repo `<repo>`, dieses Repo ist `<eigenes>`. Nichts geändert.“
4. **SHA-Prüfung:** `git fetch origin` (nur lesend), dann `git cat-file -e <sha>^{commit}`; fehlt er → Abbruch „Geprüfter Stand `<sha>` ist hier nicht vorhanden. Nichts geändert.“
5. **Basis:** Ist `<sha>` Vorfahre von `origin/<default>` (`git merge-base --is-ancestor`), ist der Default-Branch die PR-Basis; sonst der erste Remote-Branch, der `<sha>` enthält (`git branch -r --contains <sha>`, `origin/HEAD` ausgenommen). Enthält kein Remote-Branch den SHA (ungepushte Commits) → Abbruch „Geprüfter Stand `<sha>` liegt auf keinem Remote-Branch; ein Push würde ungepushte Commits veröffentlichen. Nichts geändert.“ Default-Branch: `git symbolic-ref --short refs/remotes/origin/HEAD`, sonst `gh repo view <owner/name> --json defaultBranchRef` mit dem aus `origin` abgeleiteten Repo, sonst Abbruch.
6. **Worktree und Branch:** Immer eigener Worktree (`git worktree add -b <name> <pfad> <sha>`, Pfad unter `$TMPDIR` oder `.claude/worktrees/` falls vorhanden); das Arbeitsverzeichnis des Users wechselt nie den Branch. Name `security-audit-<YYYY-MM-DD>` (Datum des Fix-Laufs); existiert er lokal oder auf `origin` (`git ls-remote --exit-code --heads origin refs/heads/<name>`), Suffix `-2`, `-3` … Kein SHA im Namen (`-f…`, `auto-feature/SKILL.md:178`).
7. **Abgleich mit dem aktuellen Stand:** `git log --oneline <sha>..origin/<basis> -- <Dateien der Befunde>` zeigen. Gibt es Treffer, jeden betroffenen Befund zusätzlich am Basis-Head prüfen; Urteil „erledigt (Commit …)“ ist zulässig. Die Tabelle nennt, wie viele Commits der Branch hinter der Basis liegt.
8. **Befundprüfung, Fixes, Tests:** wie bisher (Ablauf 2–5) im eigenen Worktree. Commit-Bezug `(Audit S-<n>)`. Die Regel „Zweiter Fund“ entfällt (eine Runde).
9. **Ganze Suite:** Fehlt `.github/workflows/` im Fix-Worktree, gilt das Repo als „ohne CI“ → ganze Suite genau einmal vor dem Push (andere CI-Systeme lösen das konservativ ebenfalls aus). Hinweis in der Verifikationszeile: Workflows mit nur `on: pull_request` laufen erst nach dem PR.
10. **Sichtbarkeit vor dem Push:** `gh repo view <owner/name> --json visibility` (Repo aus `origin`). Bei `PUBLIC` oder unbekannt (kein `gh`, Fehler) wird nicht gepusht: Die Tabelle nennt Branch und Worktree-Pfad und den Satz „Öffentliches oder nicht prüfbares Repo: nicht gepusht, damit die Lücken nicht vor dem Deploy sichtbar werden. Pushen und PR entscheidest du.“ Bei `PRIVATE`/`INTERNAL`: `git push -u origin <branch>` ohne Nachfrage.
11. **PR-Link (kein PR):** Der von GitHub beim Push ausgegebene Link (`remote: … /pull/new/<branch>`) wird übernommen; fehlt er, bei GitHub-`origin` `https://github.com/<owner>/<name>/compare/<basis>...<branch>?expand=1`; bei anderem Host nur „Branch gepusht: `<branch>`“. **Kein `gh pr create`.**
12. **Befehlswörter** „mergen“/„deployen“ mit Audit-Liste: nicht ausführen, unter der Tabelle „Kein PR vorhanden: Merge und Deploy entscheidest du nach dem PR.“
13. **Statistik/Tabelle:** Datei `~/.claude/agent-stats/<repo>/<YYYY-MM-DD>-audit-<sha7>-fix.md`, Kopf `# Agent-Statistik · Security-Audit <sha7> Fix` mit Zeilen `- Repo: <repo>` und `- Security-Audit: <sha>`, Spalte TF = `audit`; Abschlusstabelle beginnt mit `Security-Audit <sha7> · Branch <name> · Head <neuer-sha>`; Basis, Rückstand, PR-Link bzw. Nicht-gepusht-Satz stehen unter der Tabelle.
14. **Antwort an:** Kommt die Liste per Nachricht, gilt die bestehende Regel.

## Abnahmekriterien

| ID | Nachweis | Wo |
|---|---|---|
| TF5-D1 | [Durchklick] | PR-Checkliste: Audit-Liste per Copy-Paste → keine PR-Frage, Branch, Commits mit `(Audit S-n)`, Push, PR-Link, kein PR |
| TF5-D2 | [Durchklick] | PR-Checkliste: Liste mit `PR #<n> · …` läuft wie bisher |
| TF5-D3 | [Durchklick] | PR-Checkliste: Audit-Liste aus anderem Repo → Abbruch ohne Branch/Commit |
| TF5-D4 | [Durchklick] | PR-Checkliste: Audit-Liste mit „mergen“ → Push und Hinweis, kein Merge |
| TF5-D5 | [Durchklick] | PR-Checkliste: README-Zeile `fix-findings` nennt den Audit-Eingang |

Zusätzlich (Workflow, Vertrag zwischen zwei Skills — kein Prosatest, analog `test_skill_text.py`):
- `security-audit/scripts/test_skill_text.py`: Das Erkennungsmuster steht in `fix-findings/SKILL.md` in einem markierten Codeblock (`<!-- audit-kopfzeile -->`); der Test liest es und prüft: Kopfzeile aus `bericht.markdown` passt; dieselbe Zeile mit Einrückung passt nach Trimmen; `PR #12 · Code · Runde 1/3 · geprüft auf abc1234` passt nicht; Eingabe mit Begleittext und Codezaun davor enthält eine passende Zeile.
- `security-audit/scripts/test_bericht.py`: `bericht.py repo [pfad]` gibt genau `_repo_name` aus, ohne Dateien anzulegen (Ausgabeordner unverändert, keine `.reserviert`-Datei).

## Entscheidungen/Annahmen

1. **PR-Link statt PR** (Entschieden, User).
2. **Erkennung über irgendeine Zeile, die voll dem Muster entspricht**, weil Befehlswörter, Begleittext und Codezäune vor der Kopfzeile stehen dürfen (fix-findings/SKILL.md:12, bericht.py setzt den Zaun).
3. **Branch vom geprüften SHA**, Basis = Remote-Branch, der ihn enthält; Abgleich mit dem aktuellen Stand (Schritt 7) statt stillem Fixen auf veraltetem Code.
4. **Nie pushen bei öffentlichem oder nicht prüfbarem Repo** (Default, Workflow): ergänzt die User-Entscheidung „nur Branch pushen“ um den Schutz, Lücken nicht vor dem Deploy öffentlich zu machen; im Abschlussbericht als offene Bestätigung an den User.
5. **Rahmen-„Nie“-Regeln des Feature-Files** (kein Kundencode auf dem Host, ausgehende Verbindungen nur Allowlist) binden den Audit-Skill, nicht `fix-findings`: `fix-findings` ist der normale Fix-Prozess des Users im eigenen Repo (TDD auf dem Host, `git fetch`/`push`, `gh`), unverändert wie auf dem PR-Weg. Im Abschlussbericht genannt.
6. **`bericht.py repo`** als neuer Unterbefehl in TF1-Datei (gestapelter Branch), damit `fix-findings` die `<repo>`-Regel nicht nachbilden muss.
7. **Ohne Mutationsproben**: Prosa plus Vertragstests; Durchklick-DoD laut Feature-File.
8. **Sicherheitsregel aus dem Vorfall 2026-11-10** gilt auch hier: keine Signale an fremde Prozesse, keine Mutationen an Kill-/Lösch-Logik.
9. **README**: neben der Tabellenzeile auch die Merge/Deploy-Regel (README „Gemeinsame harte Regel“) um „auf dem Audit-Weg nie“ ergänzen.

## Review-Verlauf

**R1 (opus-xhigh):** 1 Blocker, 7 Wichtig, 7 Klein — alle angenommen (B1 Erkennung, W1 Basis/ungepushte Commits, W2 Abgleich, W3 Worktree, W4 öffentliches Repo als Default, W5 PR-Link, W6 Rahmen-Abgrenzung, W7 Verdacht/Verworfen/repo-weit, K1 `bericht.py repo`, K2 Negativtests, K3 ls-remote/Datum, K4 Statistik-Kopf, K5 CI-Hinweise, K6 Kleinbuchstaben-Hex, K7 README).
