# TF2 Lieferkette und Secrets — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** `security-audit` findet Abhängigkeitslücken (mit Erreichbarkeit), Lieferketten-Schwächen und Secrets in der Historie, ohne Kundencode/Repo-Konfiguration auszuführen und ohne Secret-Werte ins Modell zu lassen.

**Architecture:** Neues Skript `scripts/lieferkette.py` (Unterbefehle `secrets`, `abhaengigkeiten`, `lieferkette`); Schema-Kopplung für Werkzeugbefunde in `bericht.py`; `poc.py` beachtet `SECURITY_AUDIT_OHNE` und den Schwärzungs-Marker; SKILL.md bekommt Schritt 1b; Eval um `fixture-deps`, Laufzeit-Secret und Erwartung je Lauf erweitert.

**Tech Stack:** Python 3.14 Standardbibliothek, pytest 9, osv-scanner 2.6, gitleaks 8.30, Node 20/22 (nur Fixture).

**Spec:** `docs/superpowers/specs/2026-11-10-tf2-lieferkette-secrets-design.md` — **die „Nachträge nach Spec-Review R2“ haben Vorrang** vor dem Text darüber.

## Global Constraints

- Sicherheitsregel (Vorfall 2026-11-10): Signale nur an selbst per `Popen(start_new_session=True)` gestartete Gruppen; keine kill-Befehle in der Shell; **keine Mutationsproben an Signal-, Kill- oder Lösch-Logik**.
- Werkzeuge nie im Kundenrepo: osv-scanner auf kopierten Lockfiles in leerem Temp-Ordner (`--no-resolve`), gitleaks mit `--config <useDefault-TOML>`, `--gitleaks-ignore-path <leer>`, `--ignore-gitleaks-allow`, `--redact`, cwd leer, Umgebung ohne `GITLEAKS_*`, `OSV_*`, `GIT_*` plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_NO_LAZY_FETCH=1`.
- Secret-Werte nie in stdout/Bericht/JSON/Ausgabeordner; gitleaks-Felder `Secret`, `Match`, `Author`, `Email`, `Message`, `Fingerprint` nie ausgeben.
- Zustand: `poc.zustand_ordner(lauf)/lieferkette/`; Löschen nur dort genannte Pfade.
- Budgets: `secrets` 300 s (davon `dir`+Schwärzung 120 s zuerst), `abhaengigkeiten` 300 s, `lieferkette` 60 s; KEV-Download 30 s mit User-Agent `security-audit/1 (+https://github.com/schauersbergern/generalskills)`.
- Öffentliches Repo: keine echten Secrets, keine Lockfiles mit verwundbaren Versionen unter Standardnamen (`.tmpl`).
- Tests je Task nur die betroffenen Dateien.

## Review Focus

Feste Checkliste: 1 Sperren — nicht zutreffend. 2 Prisma/PG — nicht zutreffend. 3 Transaktions-Timeouts — analog: jeder Kindprozess mit Timeout → Task 1/2 `test_*_budget`. 4 Org-Scope — nicht zutreffend. 5 ≥ 2 Quellen — trifft zu: mehrere Lockfiles, mehrere Advisories je Paket, mehrere Commits je Secret → Task 1 `test_secrets_mehrere_commits`, Task 2 `test_abhaengigkeiten_mehrere_lockfiles_und_advisories`. 6 Uhrsprung — nicht zutreffend.

TF-spezifisch:
1. Schwärzung bei UTF-8, Zeile > 1, CRLF, PEM, base64 → Task 1 `test_schwaerzung_echt_*` (echtes gitleaks, skip ohne Binary).
2. Repo-Konfiguration unterdrückt Treffer (`.gitleaks.toml`, `.gitleaksignore`, `gitleaks:allow`, `osv-scanner.toml`, `GITLEAKS_CONFIG`) → Task 1/2 `test_repo_konfig_wirkt_nicht_*`.
3. Spiegel führt keine Treiber aus, meldet versteckte Refs und flache Quelle → Task 1 `test_spiegel_*`.
4. Werkzeug fehlt / `SECURITY_AUDIT_OHNE` → Task 1–4 `test_*_fehlt`.
5. Schema-Missbrauch (Code-Befund mit `werkzeug`) → Task 4 `test_schema_werkzeug_kopplung`.

---

### Task 1: `lieferkette.py secrets` und `gitkopie.spiegel`

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/scripts/lieferkette.py` (Grundgerüst, CLI, `secrets`), Modify `security-audit/scripts/gitkopie.py` (`spiegel`), Test `security-audit/scripts/test_lieferkette_secrets.py`.

Interfaces: `lieferkette.py secrets --lauf <id> --repo <wurzel> --quelle <arbeitskopie>` → JSON `{"befunde_roh": [{"regel","datei","zeile","commits","in_head"}], "hinweise": [...], "geschwaerzt": <anzahl>}`; Exit 0 auch bei fehlendem Werkzeug (`{"werkzeug":"gitleaks","fehlt":true,…}`), Exit 4 wenn die Schwärzung scheitert (Meldung). Funktionen `schwaerzen(datei: str, treffer: list[dict]) -> list[str]` (Hinweise), `werkzeug_umgebung() -> dict`, `fehlt(name) -> bool`. `gitkopie.spiegel(repo: str, ziel: str, frist: float) -> list[str]` (Hinweise: fehlende Refs, flach).

- [ ] Tests: Fake-gitleaks (Report mit `Secret`/`Match`=REDACTED, `Author`…) → stdout ohne diese Felder; Report-Dateien und Spiegel danach gelöscht (auch bei Budget-Ablauf); Reihenfolge `dir` vor `git` (Protokoll des Fakes); `.gitleaksignore` in der Arbeitskopie entfernt; Optionen `--config`, `--gitleaks-ignore-path`, `--ignore-gitleaks-allow`, `--redact` im Aufruf; Umgebung ohne `GITLEAKS_CONFIG`; `SECURITY_AUDIT_OHNE=gitleaks` → fehlt; Marker `geschwaerzt` gesetzt; Dedup je (Regel, Datei) mit `commits` (≥ 2 Commits). Echte gitleaks-Tests (`skipif` ohne Binary): Schwärzung Zeile 1, Zeile > 1, UTF-8 davor, Zeilenende ohne `\n`, CRLF, PEM, base64, `apiKey = "…"` (Präfix bleibt) — Wert weg, Zeilenzahl gleich, Bytes außerhalb gleich; `.gitleaks.toml` mit Allowlist und `gitleaks:allow` im Repo unterdrücken nichts. Spiegel: Textconv-/Filter-Treiber in `.git/config` erzeugen keinen Marker; `transfer.hideRefs` → Hinweis „Refs fehlen im Spiegel“; flache Quelle → Hinweis.
- [ ] Implementieren nach Spec + Nachträgen (Koordinaten-Regeln dort wörtlich). Commit `feat(security-audit): Secret-Prüfung mit Schwärzung und Spiegelklon (TF2)`.

### Task 2: `lieferkette.py abhaengigkeiten`

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/lieferkette.py`, Test `security-audit/scripts/test_lieferkette_abh.py`.

Interfaces: `abhaengigkeiten --lauf <id> --quelle <arbeitskopie>` → `{"pakete": [{"paket","version","lockfile","advisories":[{"id","aliase","zusammenfassung","details"}],"behoben_in","dev","kev"}], "hinweise": [...]}`; `semver_vergleich(a, b) -> int`; `behoben_in(advisories, paket, version) -> str | None`.

- [ ] Tests: Fake-osv-scanner (JSON wie 2.6, Exit 0/1/128/127); Lockfile wird in leeren Ordner kopiert (Fake protokolliert cwd und dass dort keine `osv-scanner.toml` liegt); `--no-resolve` im Aufruf; mehrere Lockfiles, Pakete mit mehreren Advisories; `behoben_in` nach K4 (Versionslinien); `dev` nur `dev: true`; KEV über lokale Fake-Datei (Download-Funktion per Parameter/Umgebung `SECURITY_AUDIT_KEV_DATEI` ersetzbar), Download-Fehler → `kev: null` + Hinweis; `SECURITY_AUDIT_OHNE=osv-scanner` → fehlt; Budget.
- [ ] Commit `feat(security-audit): Abhängigkeitsprüfung mit osv-scanner und KEV (TF2)`.

### Task 3: `lieferkette.py lieferkette`

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/lieferkette.py`, Test `security-audit/scripts/test_lieferkette_statisch.py`.

- [ ] Tests: `lockfile-fehlt` (Workspace mit Root-Lockfile → kein Befund); `installation-ohne-lockfile-treue` in Dockerfile (inkl. `\`-Fortsetzung), Makefile, `package.json`-scripts; `npm install -g x` kein Befund; CI-Dateien nur npm und yarn v1; `install-skripte-offen` mit/ohne `.npmrc ignore-scripts=true`, `npm ci --ignore-scripts`, `packageManager: pnpm@10.1.0`, yarn berry `enableScripts: false`; Entwürfe bestehen `bericht.pruefe_schema` (nach Task 4) — bis dahin Felder prüfen.
- [ ] Commit `feat(security-audit): statische Lieferketten-Prüfung (TF2)`.

### Task 4: Schema-Kopplung, `poc.py` OHNE und Marker

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/bericht.py`, `security-audit/scripts/poc.py`, Tests `test_bericht.py`, `test_poc.py`.

- [ ] Tests: `test_schema_werkzeug_kopplung` (osv ohne `pakete` → Fehler; gitleaks ohne `commits` → Fehler; lieferkette mit fremder `klasse` → Fehler; `werkzeug` + `bestätigt` → Fehler; gekoppelt mit `code_pfad` 1 Eintrag → ok; ohne `werkzeug` weiterhin ≥ 2); `_daemon_pruefen` mit `SECURITY_AUDIT_OHNE=docker` → Exit 3 `docker-fehlt` für `pruefen`, `bauen`, `starten`; `vorbereiten` löscht Marker; `bauen` ohne Marker (gitleaks vorhanden, nicht in OHNE) → Exit 4 `nicht-geschwaerzt`; mit Marker oder OHNE=gitleaks → normal.
- [ ] Commit `feat(security-audit): Schema für Werkzeugbefunde, OHNE und Schwärzungs-Marker (TF2)`.

### Task 5: SKILL.md, references, Eval-Regel

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/SKILL.md` (Schritt 1b, Grundregeln 3 und 8, Regel „Code-Pfad ≥ 2“ mit Werkzeug-Ausnahme, Teilpfad-Regel für Werkzeugbefunde, Abbruch bei gescheiterter Schwärzung wörtlich), `references/pruefpunkte-web.md` (A03), `references/agenten-briefings.md` (Reviewer-Auftrag Erreichbarkeit mit `details`; Werkzeug-Ausnahme), `references/bericht-format.md` (Felder `werkzeug`, `commits`, `pakete`, Beispiel), `evals/run_eval.py::erlaubte_regeln` (`Bash(python3 -I <skill>/scripts/lieferkette.py *)`), Tests `scripts/test_skill_text.py`, `evals/test_auswertung.py` (Regeltest).

- [ ] Tests: SKILL.md nennt `lieferkette.py secrets|abhaengigkeiten|lieferkette` in der Aufrufform; Beispiel-JSON in bericht-format.md besteht das Schema inkl. eines Werkzeugbefunds; Regeltest deckt neue Aufrufe.
- [ ] Commit `docs(security-audit): Schritt Werkzeuge, A03 und Werkzeugbefunde im Skill (TF2)`.

### Task 6: Eval — `fixture-deps`, Laufzeit-Secret, Erwartungen, Auswertung

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/evals/fixture-deps/` (Express minimal, `src/routes/vorlage.js` mit `_.template(vorlage, { variable: req.query.v })`, `package.json.tmpl`, `package-lock.json.tmpl` mit `lodash@4.17.20`, `minimist@1.2.5` nur deklariert, `Dockerfile` mit `RUN npm install`), `evals/expected/fixture-deps.json`, `evals/expected/fixture-web-ohne.json`; Modify `evals/run_eval.py` (`.tmpl` für alle Dateien umbenennen, `--erwartung`, Secret-Einbau bei `secret: true`, `secret_info` an `auswerten`), `evals/auswertung.py` (Eintragstyp `werkzeug`, `stufen`, Flags mit Defaults, `pruefe_status` mit Kopplung, Köder-Ausnahme nur gekoppelt, TF2-Prüfungen und DoD-Schlüssel), Tests `evals/test_auswertung.py`, `evals/test_fixture.py`.

- [ ] Vor dem Einchecken: `osv-scanner scan source --lockfile <kopie>` auf das Lockfile in einem Temp-Ordner, IDs in die Erwartung; Dateien bleiben `.tmpl`.
- [ ] Tests: Secret-Einbau erzeugt zwei Commits, Datei danach weg, Wert nur im Speicher (nicht in `ergebnis.json`); Auswertung TF2-D1…D4 mit präparierten Berichten (inkl. Stufen außerhalb `stufen` → rot, Wert im Stream → rot); TF1-D1 zählt nur `luecke`; Defaults der Flags; `fixture-deps` startet (opt-in `SECURITY_AUDIT_FIXTURE_START`) und `_.template` mit `variable` ist ausnutzbar.
- [ ] Commit `feat(security-audit): Eval für Lieferkette und Secrets (TF2)`.

### Task 7: README

**Agent:** `sonnet-high`

- [ ] README-Zeile `security-audit` nennt Abhängigkeiten (osv-scanner, KEV), Lieferkette und Secrets (gitleaks, geschwärzt); Hinweis auf benötigte Werkzeuge (`brew install osv-scanner gitleaks`). Commit `docs(README): security-audit mit Lieferkette und Secrets (TF2)`.

## DoD-Abdeckung

| DoD | Task, Test |
|---|---|
| TF2-D1 | Task 6 Eval `fixture-deps` + Auswertung; Task 2 Unit-Tests |
| TF2-D2 | Task 6 Eval + `secret_info`; Task 1 Unit- und echte gitleaks-Tests |
| TF2-D3 | Task 6 Eval; Task 3 Unit-Tests |
| TF2-D4 | Task 6 Eval ohne-Lauf; Task 1/2 `*_fehlt`; Task 4 OHNE-Tests |
| TF2-D5, D6 | Task 6 Eval-Läufe |
| TF2-D7 | Task 7, PR-Checkliste |

## Reihenfolge

Task 4 → 1 → 2 → 3 → 5 → 6 → 7 (Schema zuerst, weil die Entwürfe aus Task 3 und die Auswertung darauf bauen). Danach Härtung, Verifikation (ganze Suite; echte gitleaks-Tests; Evals nur nach CLI-Anmeldung), PR.
