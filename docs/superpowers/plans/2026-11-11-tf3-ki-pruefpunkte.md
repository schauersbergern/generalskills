# TF3 KI-Prüfpunkte — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** `security-audit` erkennt KI- und Agenten-Apps (`ki.py erkennen`), prüft sie nach eigenen Prüfpunkten (K1–K7) und belegt Befunde per Modell-Mock im internen Docker-Netz, ohne je eine echte Modell-API aufzurufen.

**Architecture:**
- Neues Skript `scripts/ki.py` (Erkennung).
- Neuer Mock `docker/llm-mock.mjs` im PoC-Image, gesteuert über `poc.py starten --modell-mock` und `poc.py modell`.
- Schemafelder `owasp_ki` und `annahme_modell`.
- Netzregel mit `llm`.
- Neue Datei `references/pruefpunkte-ki.md`, SKILL.md wird erweitert.
- Eval mit `fixture-ki`, TF3-Schlüsseln in der Auswertung und `ki_hinweis`.

**Tech Stack:** Python 3.14 Standardbibliothek, pytest 9, Node 20/22 (nur Mock, Fixture, Tests), Docker (nur opt-in).

**Spec:** `docs/superpowers/specs/2026-11-11-tf3-ki-pruefpunkte-design.md`. **Die „Nachträge nach Spec-Review R2“ haben Vorrang** vor dem Text darüber.

## Global Constraints

- **Vorfall 2026-11-10:**
  - Signale nur an selbst per `Popen(start_new_session=True)` gestartete Gruppen. Keine kill-Befehle in der Shell, nie PIDs aus `ps` oder Dateien.
  - **Keine Mutationsproben an Signal-, Kill- oder Lösch-Logik**, also an `_gruppe_beenden`, `_rolle_entfernen`, `aufraeumen`, `_entferne` und Aufräum-`finally`.
- **Nie eine echte Modell-API:** Der Mock läuft nur auf 127.0.0.1 oder im `--internal`-Netz. Netz in Tests nur opt-in, und nur zur npm-Registry: Vertragstest und Fixture-Start.
- **Öffentliches Repo:** keine Schlüssel, Dummy-Werte nur mit dem Präfix `poc-dummy-`, Lockfiles nur als `.tmpl`.
- **Testumfang:** Tests je Task nur für die betroffenen Dateien. Die ganze Suite läuft einmal in der Verifikation.
- **Fixture-Namen nicht im Skill-Text (W7):** `CRM_API_KEY`, `datei_suchen`, `antwort-sicher`, `tickets.js`, `assistent.js`, `fixture-ki`.

## Review Focus

Feste Checkliste:
1. **Sperren:** trifft zu. `poc.py modell` läuft unter der Rollensperre, nicht exklusiv; `starten`/`neustart` exklusiv. Nachweis: Task 4 `test_modell_unter_rollensperre`.
2. **Prisma/PG:** nicht zutreffend.
3. **Transaktions-Timeouts, analog Kindprozess-Timeouts:** trifft zu. Mock-Bereitschaft höchstens 30 s, `modell`-Budget 60 s, `ki.py` 30 s. Nachweis: Task 2 `test_ki_budget`, Task 4 `test_modell_mock_bereit_timeout`.
4. **Org-Scope:** nicht zutreffend.
5. **≥ 2 Quellen:** trifft zu. Mehrere `package.json` (Workspaces), mehrere Einträge in der Warteschlange, mehrere Requests mit Marker. Nachweis: Task 2 `test_ki_workspaces`, Task 3 `test_mock_wenn_enthaelt_mehrere`.
6. **Uhrsprung:** nicht zutreffend; Budgets laufen über `time.monotonic`.

TF-spezifisch:
1. **Mock-Integrität:** read-only, tmpfs, Zustand nur im Speicher, keine Steuerpfade auf 4010. Nachweis: Task 3 `test_mock_keine_steuerung_auf_api_port`, Task 4 `test_mock_container_haertung`.
2. **Umgehung des Mocks:** `--env` mit reservierten Namen oder fremden Hosts endet mit Exit 2. Nachweis: Task 4 `test_env_regeln_*`.
3. **Kein Wert im Transkript:** Maskierung vor Kürzung, roh und JSON-escaped. Nachweis: Task 3 `test_mock_maskierung_vor_kuerzung`.
4. **Marker-Kopplung:** Antwort nur auf den passenden Request, Embeddings verbrauchen nichts. Nachweis: Task 3.
5. **SDK-Kompatibilität:** Task 3, Vertragstest opt-in.
6. **Auswertung:** Schlüsselmengen für fixture-ki und fixture-web. Nachweis: Task 6 `test_auswertung_tf3_schluessel_fixture_ki`, `test_auswerten_ok`.

---

### Task 1: Schema und Netzregel

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/bericht.py`, `security-audit/scripts/netzregel.py`; Tests `test_bericht.py`, `test_netzregel.py`.

- [ ] Tests:
  - `owasp_ki`: 1 bis 3 IDs aus `ASI01`…`ASI10` oder `LLM01`…`LLM10`. Falsche ID, leere Liste, 4 IDs, Duplikat und Nicht-String sind Fehler.
  - `annahme_modell`: bool. `true` ohne `status: bestätigt` ist ein Fehler.
  - Markdown-Detailzeile `OWASP KI: …` und Statuszeile „bestätigt (Modell-Mock, Annahme: Modell folgt)“. Die Befundliste im Codeblock bleibt unverändert.
  - Netzregel: `llm` ist erlaubt (`http://llm:4010/v1`). `api.openai.com` und `api.anthropic.com` sind Verstöße, in Bash und im `poc`-Text.
- [ ] Commit: `feat(security-audit): Schema owasp_ki/annahme_modell, Netzregel mit llm (TF3)`

### Task 2: `scripts/ki.py erkennen`

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/scripts/ki.py`; Test `security-audit/scripts/test_ki.py`.

- [ ] Nach Spec §1 mit den Nachträgen; `basis_url` entfällt.
- [ ] Wiederverwenden statt duplizieren: `lieferkette._arbeitskopie`, `_sekunden`, die Prüfung „Pfad sauber“ und die npm-Namensregel. Gemeinsame Helfer dürfen dafür in ein geteiltes Modul wandern, wenn das kleiner ist.
- [ ] Tests:
  - Erkennung je Listeneintrag, `@scope/*`-Wildcards, Workspaces mit mehreren `package.json`.
  - `node_modules` wird übersprungen, Symlinks und zu große Dateien ebenfalls.
  - Kaputtes JSON führt zu einem Hinweis, ungültige Paketnamen werden gezählt.
  - Beide Hinweise erscheinen wörtlich.
  - Eine fremde `--quelle` endet mit Exit 2.
  - Budget: `test_ki_budget`.
  - Kein Kindprozess (Popen-Attrappe wirft).
- [ ] Commit: `feat(security-audit): ki.py erkennt LLM- und Agenten-SDKs (TF3)`

### Task 3: Modell-Mock `docker/llm-mock.mjs`

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/docker/llm-mock.mjs`, `security-audit/scripts/test_llm_mock.py`, `security-audit/evals/sdk-vertrag/package.json.tmpl` und `package-lock.json.tmpl` sowie ein Vertragsskript `security-audit/evals/sdk-vertrag/vertrag.mjs`.

- [ ] Umsetzung nach Spec §4 und Nachträgen R2 (W4, W6, Klein):
  - Zwei Listener: 4010 für die API, 127.0.0.1:4011 für die Steuerung.
  - CLI `--server | --setzen | --protokoll | --bereit`. Die Maskierungswerte kommen per stdin.
  - Endpunkte mit Pflichtfeldern, Streaming in drei Formaten, `/v1`-Normalisierung, Embeddings ohne Verbrauch, 404 mit Protokolleintrag, Ring mit 50 Einträgen.
  - Nur `node:`-Builtins, Node 20 und 22.
- [ ] `test_llm_mock.py`:
  - Node startet lokal mit `start_new_session=True`, Ports frei per `--port`/`--steuer-port` (Testparameter, Standard 4010/4011). Am Ende wird nur die eigene Gruppe beendet.
  - Abgedeckt: alle Endpunkte und Formate, `wenn_enthaelt` (`test_mock_wenn_enthaelt_mehrere`), Verbrauch, Ring, `--suche`, Maskierung vor Kürzung roh und JSON-escaped (`test_mock_maskierung_vor_kuerzung`).
  - Keine Steuerung auf 4010: `test_mock_keine_steuerung_auf_api_port`. Ungültiger JSON-Body ergibt 400.
- [ ] Vertragstest (opt-in `SECURITY_AUDIT_SDK_VERTRAG=1`):
  - `npm ci --ignore-scripts` aus den `.tmpl` im Temp-Ordner (nur npm-Registry).
  - Je SDK Text und Tool-Aufruf, streamend und nicht streamend, gegen den lokalen Mock. Für `@ai-sdk/openai` beide Wege, Responses und Chat.
  - Ergebnis im Bericht. Nicht grüne Zeilen markiert Task 5 in der Mock-Tabelle als „ungeprüft“.
- [ ] Commit: `feat(security-audit): Modell-Mock für OpenAI/Anthropic (TF3)`

### Task 4: `poc.py`-Integration

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/poc.py`, `security-audit/docker/Dockerfile.poc`; Tests `test_poc.py`, `test_poc_docker.py` (opt-in).

- [ ] **Bau:** `Dockerfile.poc` kopiert `llm-mock.mjs` wie `anfrage.mjs` (root-eigen, nach dem Kunden-Build).
- [ ] **`starten --modell-mock openai,anthropic`:**
  - Mock vor der App mit `HAERTUNG_MOCK`, Bereitschaft per `exec --bereit` (höchstens 30 s).
  - Env-Variablen setzen, Stdout-Zeile ausgeben, Rollendatei mit `modell_mock`; `_lade_rolle` und `neustart` beachten das.
  - Bei einem Mock-Fehler liest `_start_fehler` die Logs von `-llm`.
- [ ] **`--env`-Regeln (B1):**
  - Jeder Wert läuft durch `netzregel.verstoesse_poc`; ein Verstoß endet mit Exit 2.
  - Die reservierten Namen enden nur mit Mock mit Exit 2.
- [ ] **`poc.py modell --lauf --rolle (--antworten-datei <d> | --protokoll [--suche <m>])`:**
  - Validierung in Python: Größe, Liste, Namen, Marker-Muster, Netzregel über den Inhalt.
  - Läuft unter der Rollensperre (nicht exklusiv) mit Budget 60 s.
  - Ohne Mock: Exit 1.
  - `--protokoll` übergibt die Maskierungswerte (`--env` der Rolle ab 6 Zeichen und die Mock-Keys) per stdin, nie per argv.
- [ ] **`_rolle_entfernen` und `aufraeumen`:** Den Containernamen `-llm` **ergänzen**. Keine anderen Änderungen an dieser Logik, keine Mutationsproben dort.
- [ ] **Tests in `test_poc.py`** (Attrappen-Docker wie bisher):
  - `test_env_regeln_reservierte_namen_nur_mit_mock`, `test_env_regeln_fremder_host_exit2`, `test_env_regeln_db_und_localhost_erlaubt`.
  - `test_modell_mock_env_gesetzt`, `test_modell_mock_bereit_timeout`, `test_modell_unter_rollensperre`.
  - `test_modell_antworten_validierung`, `test_modell_netzregel_antworten`, `test_modell_ohne_mock_exit1`.
  - `test_modell_protokoll_maskierwerte_per_stdin`, `test_neustart_mit_mock`, `test_rolle_entfernen_nennt_llm`, `test_mock_container_haertung`.
- [ ] **`test_poc_docker.py`** (opt-in): `llm` ist aus dem App-Container erreichbar, der Host nicht. Ein Request an `api.openai.com` scheitert. Das DNS-Ergebnis wird nur beobachtet und festgehalten. Danach Aufräumen.
- [ ] Commit: `feat(security-audit): poc.py startet und steuert den Modell-Mock (TF3)`

### Task 5: SKILL.md, references, README, Eval-Regel

**Agent:** `sonnet-xhigh`

**Files:**
- Modify `security-audit/SKILL.md` (Description; Regeln 3 und 8; Schritte 1b, 2, 3, 4, 5b/6, 7; Typische Fehler).
- Create `references/pruefpunkte-ki.md`.
- Modify `references/pruefpunkte-web.md` (A05: XSS), `references/agenten-briefings.md` (Fläche KI/Agent, `<MODELL_MOCK>`, Prüfer-Abschnitt „Modell-Mock“ mit höchstens 20 Zeilen, Ergebnisformate mit `owasp_ki`/`marker`, Hostlisten), `references/bericht-format.md` (Felder, Beispiel, Hostliste), `README.md` (Zeile und Dateiliste, TF3-D5), `evals/run_eval.py` (`erlaubte_regeln` mit `ki.py`).
- Tests `scripts/test_skill_text.py`, `evals/test_auswertung.py` (Regeltest).

- [ ] **Inhalte nach Spec §2, §3 und §5 mit Nachträgen:**
  - Hinweise wörtlich übernehmen, Fehlerpfad von `ki.py`.
  - Mock-Entscheidung, die vier reservierten Namen.
  - Marker-Regel, Belege 1–6 im `poc`.
  - `annahme_modell` setzt die Hauptsession.
  - TF3-D3-Satz („nie in einem Befehl, auch nicht als Suchmuster“).
  - Mock-Tabelle mit „ungeprüft“ laut Ergebnis des Vertragstests aus Task 3.
- [ ] **Tests:** Satz-Tests je Regel, Beispiel-JSON mit KI-Befund besteht das Schema, W7-Verbotsliste erweitert, Regeltest für `ki.py`.
- [ ] Commit: `docs(security-audit): KI-Prüfpunkte und Modell-Mock im Skill (TF3)`

### Task 6: Eval — `fixture-ki`, Erwartungen, Auswertung

**Agent:** `sonnet-xhigh`

**Files:**
- Create `security-audit/evals/fixture-ki/` (nach Spec §6 + W5), `evals/expected/fixture-ki.json`.
- Modify `evals/expected/fixture-web.json` (`ki_hinweis`), `evals/auswertung.py` (TF3-D1 bis D4, Filterparameter, `leer` über alle Einträge), `evals/run_eval.py` (falls für `start.modell_mock` nötig).
- Tests `evals/test_auswertung.py`, `evals/test_fixture.py`.

- [ ] **Fixture:** Je Lücke eine eigene Datei mit eigener Schleife bzw. Tools, gemeinsam nur `src/llm.js` (lazy). Mail-Ausgang `/tmp/ausgang.jsonl`, `.env.example` mit `CRM_API_KEY=poc-dummy-crm`, `openai` ≥ 5, Lockfile als `.tmpl`.
- [ ] **Auswertung:**
  - `test_auswertung_tf3_d1_*`, `_d2_*`, `_d3_api_host_im_bash_rot` (auch URL-kodiert), `_d4_hinweis_*`.
  - `test_auswertung_tf3_schluessel_fixture_ki` (genau TF1-D3 bis D7 + TF3-D1 bis D4).
  - `test_auswerten_ok` (fixture-web: TF1-D1 bis D7 + TF3-D4), TF2-Erwartungen unverändert.
- [ ] **`test_fixture.py`:**
  - Erwartungsschema; Trennung der Dateien (keine Lücken-Datei enthält die Senke einer anderen); keine Schlüssel; keine Install-Skripte.
  - Opt-in-Start: App und `llm-mock.mjs` lokal als eigene Gruppen. L1 bis L3 sind mit harmlosen Payloads ausnutzbar, der Köder escaped.
- [ ] Commit: `feat(security-audit): Eval fixture-ki und TF3-Auswertung (TF3)`

## DoD-Abdeckung

| DoD | Task, Test |
|---|---|
| TF3-D1 | Task 6 Auswertung und Eval `fixture-ki` |
| TF3-D2 | Task 6 Auswertung und Eval |
| TF3-D3 | Task 1 Netzregel, Task 4 Antworten-Datei/`--env`, Task 6 `_d3_*`, Eval |
| TF3-D4 | Task 2 Hinweise, Task 5 Übernahme, Task 6 `ki_hinweis`, Eval `fixture-web` |
| TF3-D5 | Task 5 README (Durchklick) |

## Reihenfolge

Task 1 → 2 → 3 → 4 → 5 → 6. Task 3 vor 4, weil `poc.py` die CLI des Mocks nutzt. Task 5 nach dem Vertragstest aus Task 3, wegen der Kennzeichnung „ungeprüft“. Danach folgen Härtung, Verifikation (ganze Suite, Docker opt-in, Vertragstest opt-in), zwei Evals (`fixture-ki`, `fixture-web`) und der PR auf `skills/audit-lieferkette`.
