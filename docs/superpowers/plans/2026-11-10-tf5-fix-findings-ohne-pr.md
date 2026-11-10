# TF5 `fix-findings` ohne PR — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** `/fix-findings` nimmt Befundlisten aus `security-audit` ohne PR an (Branch vom geprüften SHA in eigenem Worktree, Fixes, Push, PR-Link, kein PR).

**Architecture:** Ein neuer Unterbefehl `bericht.py repo` liefert die `<repo>`-Regel ohne Seiteneffekte; `fix-findings/SKILL.md` bekommt einen Audit-Eingang in Ablauf 1 und Anpassungen an Merge/Deploy, Ganze-Suite-Regel, Statistik und Abschlusstabelle. Vertragstests sichern Kopfzeile und Unterbefehl.

**Tech Stack:** Python 3.14 (Standardbibliothek), pytest 9, Markdown-Prosa.

**Spec:** `docs/superpowers/specs/2026-11-10-tf5-fix-findings-ohne-pr-design.md` (Verhalten Schritte 1–14, Entscheidungen).

## Global Constraints

- Kopfzeilen-Muster wörtlich: `^Repo [A-Za-z0-9._-]+ · Security-Audit · geprüft auf [0-9a-f]{7,64}$` (U+00B7).
- Branch `security-audit-<YYYY-MM-DD>`, Suffix `-2` …; Worktree `<hauptcheckout>/.claude/worktrees/<name>`.
- Kein `gh pr create`; immer pushen; PUBLIC → Warnsatz.
- Bestehender PR-Pfad in `fix-findings/SKILL.md` bleibt wortgleich, wo die Spec nichts ändert.
- Sicherheitsregel (Vorfall 2026-11-10): keine Signale an fremde Prozesse, keine Mutationen an Kill-/Lösch-Logik.
- Tests nur die betroffenen Dateien: `python3 -m pytest security-audit/scripts/test_bericht.py security-audit/scripts/test_skill_text.py -q`.

## Review Focus

Feste Checkliste: 1 Sperren — trifft nicht zu (keine Sperren). 2 Prisma/PG — trifft nicht zu. 3 Transaktions-Timeouts — trifft nicht zu. 4 Org-Scope — trifft nicht zu (Repo-Abgleich ist analog: Task 1 `test_repo_*`, Task 2 Vertragstest). 5 Testaufbau mit ≥ 2 Quellen — trifft zu für die Kopfzeilen-Erkennung: Audit- und PR-Kopfzeile in einem Test → Task 2 `test_audit_kopfzeile_vertrag`. 6 Uhrsprung — trifft nicht zu (Datum nur im Branch-Namen).

TF-spezifisch:
1. Kopfzeile mit Begleittext, Befehlswort und Codezaun davor → Task 2 `test_audit_kopfzeile_vertrag`.
2. `bericht.py repo` außerhalb eines Repos → Exit 3 → Task 1 `test_repo_ohne_git`.
3. `bericht.py repo` legt nichts an (kein Ausgabeordner, keine `.reserviert`) → Task 1 `test_repo_ohne_seiteneffekte`.
4. Neuer Unterbefehl ist in `security-audit/SKILL.md` genannt (bestehender Test `test_skill_md_nennt_jeden_poc_unterbefehl`) → Task 1.
5. PR-Kopfzeile aus `pr-review-loop/SKILL.md` passt nicht → Task 2.

---

### Task 1: `bericht.py repo`

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/bericht.py`, `security-audit/scripts/test_bericht.py`, `security-audit/SKILL.md` (ein Inline-Span `bericht.py repo` bei der Übergabe an `/fix-findings`).

- [ ] **Step 1: Tests** in `test_bericht.py`: `test_repo_aus_origin` (origin `https://x/a/kunde-portal.git` → stdout `kunde-portal\n`, Exit 0); `test_repo_ohne_origin_worktree` (Worktree → Name des Haupt-Repos); `test_repo_ohne_git` (Temp-Ordner ohne Repo → Exit 3, Meldung auf stderr, kein Traceback); `test_repo_ohne_seiteneffekte` (HOME/`SECURITY_AUDIT_AUSGABE` auf `tmp_path`: danach existiert dort nichts Neues); `test_repo_gleich_kontext` (`repo`-Ausgabe == `kontext`-Feld `repo` für dasselbe Repo).
- [ ] **Step 2:** rot. **Step 3:** Unterbefehl `repo [--repo P]` (Default cwd): `git rev-parse --show-toplevel` via `gitkopie.git`, sonst Exit 3; Ausgabe `_repo_name(wurzel)`. In `security-audit/SKILL.md` den Inline-Span `` `python3 -I ${CLAUDE_SKILL_DIR}/scripts/bericht.py repo` `` in einem Satz zur Übergabe an `/fix-findings` (die Befundliste nutzt ihn dort zum Repo-Abgleich). **Step 4:** grün (`test_bericht.py`, `test_skill_text.py`). **Step 5: Commit** `feat(security-audit): bericht.py repo ohne Seiteneffekte (TF5)`.

### Task 2: Audit-Eingang in `fix-findings/SKILL.md`, Vertragstest, README

**Agent:** `sonnet-xhigh` (Prosa mit Ablauflogik)

**Files:** Modify `fix-findings/SKILL.md` (Z. 3 Description, Merge/Deploy-Abschnitt, Ablauf 1 neuer Unterpunkt „Audit-Liste“ vor „PR finden“, Ablauf 3 Zweiter Fund, Ablauf 5 Ganze Suite, Agent-Statistik, Abschlusstabelle), `security-audit/scripts/test_skill_text.py`, `README.md` (Tabellenzeile `fix-findings`, Abschnitt „Gemeinsame harte Regel“).

- [ ] **Step 1: Test** `test_audit_kopfzeile_vertrag` in `test_skill_text.py`: liest die eine Regex-Zeile im Codezaun direkt nach `<!-- audit-kopfzeile -->` aus `fix-findings/SKILL.md`; erzeugt die Kopfzeile per `bericht.markdown(...)` aus dem Beispiel-JSON des Tests; prüft `re.fullmatch` auf die Kopfzeile, auf die eingerückte Kopfzeile nach `strip()`, auf keine Zeile von `PR #12 · Code · Runde 1/3 · geprüft auf abc1234`, und dass in `"mergen\nbitte fixen:\n```\n" + kopfzeile + "\n```"` genau eine Zeile passt. Zweiter Test `test_fix_findings_nennt_bericht_repo`: `fix-findings/SKILL.md` enthält `bericht.py repo`.
- [ ] **Step 2:** rot. **Step 3:** Prosa nach Spec Schritte 1–14 (Meldungen wörtlich aus der Spec; Stil wie die bestehende Datei, deutsch, knapp). README: Tabellenzeile um „oder Befundliste aus `security-audit` ohne PR (eigener Worktree vom geprüften SHA, Push des Branches, PR-Link, kein PR)“; „Gemeinsame harte Regel“ um „auf dem Audit-Weg nie“. **Step 4:** grün. **Step 5: Commit** `feat(fix-findings): Audit-Befundlisten ohne PR (TF5)`.

## DoD-Abdeckung

| DoD | Nachweis |
|---|---|
| TF5-D1–D5 | [Durchklick] PR-Checkliste; abgesichert durch Task 2 `test_audit_kopfzeile_vertrag`, `test_fix_findings_nennt_bericht_repo` und Task 1 `test_repo_*` |

## Reihenfolge

Task 1 → Task 2.

## Nachträge nach Plan-Review R1 (Vorrang vor dem Text oben)

- **B1:** Neue Tests in `test_bericht.py` heißen `test_repo_befehl_aus_origin`, `test_repo_befehl_ohne_origin_worktree`, `test_repo_befehl_ohne_git`, `test_repo_befehl_ohne_seiteneffekte`, `test_repo_befehl_gleich_kontext` (bestehendes `test_repo_aus_origin` bleibt unangetastet).
- **K1:** `test_repo_befehl_gleich_kontext` parametrisiert über https-origin, scp-origin (`git@host:o/n.git`), ohne origin und Worktree; je `repo`-Ausgabe == `kontext()["repo"]`.
- **K5:** `test_repo_befehl_ohne_git` zusätzlich mit nicht existierendem `--repo`-Pfad: Exit 3, leeres stdout, kein Traceback.
- **K3:** Modul-Docstring von `bericht.py` nennt `repo`. Span in `security-audit/SKILL.md` an der Schlussmeldung (Z. ~127): `` `python3 -I ${CLAUDE_SKILL_DIR}/scripts/bericht.py repo --repo <pfad>` `` nicht in einer Zeile mit `timeout: 600000`.
- **W1 Einfügestellen in `fix-findings/SKILL.md`** (alles Übrige wortgleich; Task-Review prüft `git diff origin/main -- fix-findings/SKILL.md`):
  - Z. 3 Description: beide Eingänge (kein `: ` im Plain-Scalar, K8).
  - Merge-und-Deploy-Abschnitt: ein Punkt „Audit-Liste“ (Spec Schritt 12).
  - Ablauf 1: neuer erster Unterpunkt **„Audit-Liste (ohne PR)“** mit Spec Schritten 1–7 (Erkennung mit `<!-- audit-kopfzeile -->`-Block, Befunde, Repo-Abgleich, SHA, Basis, Worktree/Abhängigkeiten, Basis hereinholen) und dem Satz „Danach gelten Ablauf 2–5 im Worktree; Ablauf 6 und 7 ersetzt durch die Audit-Punkte unten.“
  - Ablauf 3 „Zweiter Fund“: Satz „Auf dem Audit-Weg entfällt die Regel (eine Runde).“
  - Ablauf 4 Commit-Beispiel: zusätzlich „auf dem Audit-Weg `(Audit S-<n>)`“ (Spec 8).
  - Ablauf 5 Ganze Suite: Audit-Fall „kein `.github/workflows/`“ und `pull_request`-Hinweis (Spec 9).
  - Ablauf 6 Push: Audit-Variante (Spec 10: `git push -u origin <branch> 2>&1`, Sichtbarkeit, Warnsatz, `git worktree remove`).
  - Ablauf 7 Abschluss: Audit-Variante (Spec 11: compare-Link oder „Branch gepusht“, kein `gh pr create`).
  - Agent-Statistik und Abschlusstabelle: Audit-Varianten (Spec 13).
  - Text „Nicht gemergt, nicht deployt“ bleibt; auf dem Audit-Weg steht der Hinweis aus Spec 12 darunter.
- **K4 Marker:** Die nächste nicht leere Zeile nach `<!-- audit-kopfzeile -->` öffnet einen Codezaun mit genau einer Inhaltszeile (Regex); Einrückung erlaubt, der Test nimmt `strip()`.
- **W3:** In `test_skill_text.py` den JSON-Extraktor aus `test_beispiel_json_ist_gueltig` in einen Helfer `_beispiel_json()` verschieben; `test_audit_kopfzeile_vertrag` nutzt `bericht.markdown(_beispiel_json())`.
- **K2:** `fix-findings/SKILL.md` in die Parametrisierung von `test_unterbefehle_existieren` und `test_optionen_existieren` aufnehmen (Aufrufe dort in der Form `python3 -I ~/.claude/skills/security-audit/scripts/bericht.py repo …`; falls die Präfixregel von `test_skill_text.py` für fix-findings nicht passt, eine eigene Präfixliste je Datei).
- **K7:** README-Tabellenzeile im Stil der Tabelle transliteriert („geprueften“).
- **W2 Reviews:** Task 1: `sonnet-xhigh`-Review mit Mutationsproben (`repo` über `kontext()` statt `_repo_name` → `test_repo_befehl_ohne_seiteneffekte` rot; `show-toplevel`-Prüfung entfernt → `test_repo_befehl_ohne_git` rot). Task 2: eine Probe (Regex auf `.*` gelockert → PR-Negativtest rot). Keine Mutationen an Signal-/Kill-/Lösch-Logik.
- **K6 DoD je ID (PR-Checkliste, Setup:** `ln -sfn <worktree>/security-audit ~/.claude/skills/security-audit` und `fix-findings` vom TF5-Branch, nach dem Test zurück auf den Hauptcheckout):
  - TF5-D1: Audit-Liste aus einem `security-audit`-Bericht in einem eigenen Test-Repo (privat) an `/fix-findings` → keine PR-Frage, Worktree, Branch `security-audit-…`, Commits `(Audit S-n)`, Push, compare-Link, kein PR.
  - TF5-D2: Liste `PR #<n> · …` aus `pr-review-loop` → bisheriger Ablauf.
  - TF5-D3: Audit-Liste mit fremdem Repo-Namen → Meldung, kein Branch, kein Commit.
  - TF5-D4: Audit-Liste plus „mergen“ → Push und Hinweis, kein Merge.
  - TF5-D5: README-Zeile `fix-findings` nennt den Audit-Eingang.
- **K9 Verifikation:** Kein `.github/workflows/` → ganze Suite (`python3 -m pytest security-audit auto-feature/scripts -q`) einmal in der Verifikation.

## Nachträge nach Plan-Review R2 (Vorrang)

- **W:** Ablauf 6 und 7 werden auf dem Audit-Weg **ergänzt**, nicht ersetzt: Die Antwortregel per `SendMessage` (Ablauf 7, `from`/„Antwort an:“, neuer Head-SHA) gilt unverändert auch für Audit-Listen (Spec 14). Im Ablauf-1-Unterpunkt heißt es daher „Ablauf 6 und 7 gelten mit den Audit-Ergänzungen unten“.
- **K1:** K2 bedeutet nur: `fix-findings/SKILL.md` in die Parametrisierung von `test_unterbefehle_existieren` und `test_optionen_existieren` aufnehmen; keine Präfixprüfung für fix-findings.
- **K2:** Im Review Focus gelten die neuen Namen `test_repo_befehl_*` (nicht die bestehenden `test_repo_*`).
- **K3:** Die Kopfzeile im Vertragstest stammt aus `_bloecke(bericht.markdown(_beispiel_json()))[0][1].split("\n")[0]` — nie per Suche mit dem Muster aus fix-findings.
- **K4:** Durchklick-Setup: danach den Link `~/.claude/skills/security-audit` wieder entfernen und `fix-findings` auf den Hauptcheckout zurücksetzen; parallel laufende Sessions nutzen in der Zeit das TF5-`fix-findings`.
- **K5:** Geschwisterpfad zu `fix-findings/SKILL.md` in `test_skill_text.py` über `os.path.realpath`.
