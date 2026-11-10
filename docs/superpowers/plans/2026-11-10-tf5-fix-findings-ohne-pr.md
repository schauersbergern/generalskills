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
