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

## Nachträge nach Plan-Review R1 (Vorrang vor den Tasks oben)

**B1** (Der Vertrag zwischen Mock-CLI (Task 3) und `poc.py` (Task 4) fehlt, und kein Test prüft beide zusammen)
**Mock-CLI-Vertrag (Task 3 legt ihn an, Task 4 nutzt ihn):** `node llm-mock.mjs --server [--host <h>] [--port <n>] [--steuer-port <n>]`; `--host` ist nur für die API (Standard `0.0.0.0`), die Steuerung lauscht immer auf `127.0.0.1`. Bei Port `0` schreibt `--server` als erste stdout-Zeile `bereit api=<port> steuer=<port>`. `--bereit [--steuer-port n]`: Exit 0 oder 1, keine Ausgabe. `--setzen [--steuer-port n]`: stdin ist die Antwortliste (JSON-Array, Schema wie in Spec §4), Exit 0, bei ungültigem Inhalt Exit 2. `--protokoll [--suche <marker>] [--steuer-port n]`: stdin ist `{"werte": [{"name": "<NAME>", "wert": "<wert>"}, …]}`. stdout ist ein JSON-Objekt `{"eintraege": [{nr, methode, pfad, body}], "gekuerzt": <anzahl weggelassener Einträge>}`, in sich gültig und höchstens 64 KiB groß; der Mock lässt dafür die ältesten Einträge weg. Werte aus stdin erscheinen nie auf stdout oder stderr, auch nicht in Fehlermeldungen. `poc.py modell` gibt die Ausgabe über `_entschaerfen` aus (Kundendaten, Grundregel 1) und kürzt nicht selbst.
**Ende-zu-Ende-Test (Task 4, `skipif` ohne `node`):** `test_modell_protokoll_maskierung_ende_zu_ende`. Der Test startet `docker/llm-mock.mjs --server --host 127.0.0.1 --port 0 --steuer-port 0` als eigene Gruppe. Eine zweite Attrappe `docker` führt `exec -i <name> node /poc/llm-mock.mjs …` lokal als `node <skill>/docker/llm-mock.mjs … --steuer-port <p>` aus und reicht stdin durch. Der Test schickt einen Request mit einem `--env`-Wert der Rolle an `/v1/chat/completions` und prüft: Die Ausgabe von `poc.py modell --protokoll` enthält `<ENV:NAME>`, aber weder den Wert roh noch JSON-escaped.
**B2** (`ki_hinweis` in `fixture-web.json` macht mindestens 8 Bestandstests rot, darunter TF2-DoD-Tests. Der Plan nennt nur einen.)
Task 6 ergänzt in `evals/testdaten/bericht_ok.json` den Hinweis „KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)“. Die Erwartungsmengen in `test_auswerten_ok`, `test_lauf_ok_und_aufruf`, `test_eval_fixture_web`, `test_flags_defaults`, `test_auswertung_regression_nur_tf1` und `test_erwartung_pfad_relativ_zu_evals_und_absolut` (dritte Prüfung) werden auf `{TF1-D1…D7, TF3-D4}` erweitert. Das ist keine Aufweichung: TF2-D6 verlangt nur, dass TF1-D1 bis D7 gelten. Docstring und Name von `test_auswertung_regression_nur_tf1` sagen das künftig („TF1 vollständig, kein TF2-Schlüssel“). `fixture-web-ohne.json` bleibt ohne `ki_hinweis`; die Tests bei `:2070` und `:2404` bleiben unverändert. Neu: `test_auswertung_tf3_d4_fehlender_hinweis_rot` mit `bericht_ok.json` ohne den Hinweis.
**B3** (Host-Tests mit echten SDKs können eine echte Modell-API erreichen)
**Host-Läufe mit SDKs (Vertragstest, Opt-in-Start fixture-ki):** Die Umgebung wird aus einer Whitelist gebaut (`PATH`, `HOME` = Temp-Ordner, `TMPDIR`, `LANG`), dazu explizit `OPENAI_BASE_URL=http://127.0.0.1:<port>/v1`, `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`, `OPENAI_API_KEY=poc-dummy-openai` und `ANTHROPIC_API_KEY=poc-dummy-anthropic`. Kein anderes `OPENAI_*`, `ANTHROPIC_*`, `AZURE_*` oder `*_PROXY` wird geerbt. `vertrag.mjs` setzt die Basis-URL **nicht** im Code, sondern prüft den Env-Weg. Vor dem ersten SDK-Import installiert es einen Wächter: `globalThis.fetch`, `http.request`/`https.request` und `net.connect`/`tls.connect` werfen bei jedem Host außer `127.0.0.1`. Ein SDK, das den Wächter auslöst, bekommt in der Ergebniszeile „liest Env nicht“ und gilt als nicht grün. Tests: `test_vertrag_umgebung_ohne_fremde_variablen` (immer), `test_vertrag_waechter_blockiert_fremden_host` (`skipif` ohne `node`, ohne Netz).
**W1** (Bestehende `rm`-Erwartungen in `test_poc.py` brechen; `aufraeumen` braucht keine Änderung)
`_rolle_entfernen` hängt `f"{netz}-llm"` **ans Ende** der `rm`-Liste an. `aufraeumen` bleibt unverändert, weil das Präfix `-llm` schon erfasst. Die Erwartungslisten in `test_poc.py:871, 894, 915, 1394` werden auf `[…-app, …-db, …-llm]` erweitert; das ist keine Mutationsprobe. Neu: `test_aufraeumen_erfasst_llm_ueber_praefix` (ps liefert `…-p1-llm` → im `rm`-Aufruf).
**W2** (Task 4 macht `test_skill_text.py` rot, Task 5 muss den Text-Test auf `ki.py` erweitern)
Task 4 nennt in SKILL.md Schritt 6 eine Aufrufzeile `poc.py modell` als Platzhalter (Task 5 schreibt den Abschnitt aus) und läuft zusätzlich `test_skill_text.py -k unterbefehl`. Task 5: `SKRIPTE` um `"ki"` erweitern, den Regex in `_aufrufe` um `ki`, und `test_skill_budget_ki_und_modell` prüft „`ki.py erkennen` … 30 s“ und „`poc.py modell` … 60 s“ gegen `ki.KI_BUDGET` und `poc.MODELL_BUDGET`, außerhalb der Zeile mit `timeout: 600000`. Grundregel 8 nennt `ki.py` bei „einzelner einfacher Befehl“ und bei „Bash sonst nur für …“.
**W3** (`test_llm_mock.py` braucht Port 0 mit Rückmeldung, einen Loopback-Host und eine Skip-Regel)
`test_llm_mock.py` startet den Mock mit `--host 127.0.0.1 --port 0 --steuer-port 0` und liest die Ports aus der Zeile `bereit api=… steuer=…` (B1). `pytestmark = skipif(shutil.which("node") is None)`. Am Ende `os.killpg(p.pid, …)` nur, wenn `p.poll() is None` (eigene Gruppe, kein PID-Recycling). Der Mock nutzt nur `node:http`, `node:crypto` und `node:url`, ohne experimentelle Flags; Zielversionen sind Node 20, 22 und 24.
**W4** (`ki.py` ohne Umbau von `lieferkette.py` bauen; Verhalten bei Budget-Ablauf festlegen)
`ki.py` importiert die Helfer aus `lieferkette` und verschiebt nichts; `lieferkette.py` bleibt in TF3 unverändert. Budget: `KI_BUDGET = 30`, `_sekunden("SECURITY_AUDIT_KI_BUDGET", KI_BUDGET)`. Läuft es ab, bevor ein SDK gefunden ist, endet der Befehl mit Exit 1 und Meldung auf stderr; die Hauptsession schreibt dann „ki.py erkennen fehlgeschlagen (Exit 1)“. Ist schon ein SDK gefunden, gibt er Exit 0 mit `anwendbar: true` und dem Zusatzhinweis „KI-Erkennung abgebrochen (Zeitbudget)“. Der Erkennungshinweis nennt die Paketnamen sortiert, eindeutig und mit `, ` getrennt. Tests: `test_ki_budget_ohne_fund_exit1`, `test_ki_budget_mit_fund_anwendbar`. Das Task-Review prüft, dass `lieferkette.py` nicht im Diff von Task 2 steht.
**W5** (Lockfiles erzeugen und den Vertragstest ausführen braucht Netz, und der Plan sagt nicht, wer das wann tut)
Lockfiles erzeugt der Implementierer im Temp-Ordner mit `npm install --package-lock-only --ignore-scripts --no-audit --no-fund` (einzige erlaubte Netzaktion, nur npm-Registry) und checkt sie als `.tmpl` ein; `resolved` zeigt nur auf `https://registry.npmjs.org/` (Test wie `test_keine_install_skripte`). Den Vertragstest führt die **Hauptsession** nach dem Task-3-Review einmal aus: `SECURITY_AUDIT_SDK_VERTRAG=1 python3 -m pytest security-audit/scripts/test_llm_mock.py -k vertrag`. Das Ergebnis (Tabelle Paket × Weg × streamend/nicht streamend × Text/Tool, grün/rot/„liest Env nicht“) schreibt sie nach `.superpowers/sdd/2026-11-11-tf3-ki/vertrag.md` und gibt es Task 5 im Briefing mit. Ohne Netz oder `npm` sind alle Zeilen außer „`openai` chat“ (deckt W5-Start ab) „ungeprüft“. `@openai/agents` steht nicht im Vertragstest und bleibt „ungeprüft“.
**W6** (Interfaces und Testnamen je DoD fehlen)
**Interfaces:** `ki.py erkennen --lauf <id> --quelle <p>` → `{"anwendbar": bool, "sdks": [{"paket","datei"}] (≤ 50), "hinweise": [<Erkennungshinweis>, …weitere]}`; der Erkennungshinweis steht immer an erster Stelle. `poc.py modell … --antworten-datei` → stdout `modell: <n> Antworten gesetzt (Rolle <r>)`, Exit 0/1/2. `poc.py modell … --protokoll [--suche m]` → JSON wie B1.
**Testnamen je DoD:**
- TF3-D1: `test_auswertung_tf3_d1_ok`, `test_auswertung_tf3_d1_l2_nur_p2_rot`, `test_auswertung_tf3_d1_luecke_fehlt_rot`.
- TF3-D2: `test_auswertung_tf3_d2_koeder_p2_rot`, `test_auswertung_tf3_d2_koeder_p3_ok`.
- TF3-D3: `test_auswertung_tf3_d3_api_host_im_bash_rot`, `…_url_kodiert_rot`, `…_subagent_rot`, `…_letzte_zeile_rot`, `test_netzregel_api_hosts_verstoss`, `test_modell_netzregel_antworten`.
- TF3-D4: `test_ki_hinweis_nicht_anwendbar_woertlich`, `test_ki_hinweis_angewendet_woertlich`, `test_skill_ki_hinweise_unveraendert`, `test_auswertung_tf3_d4_fehlender_hinweis_rot`, `test_auswertung_tf3_d4_ki_hinweis_ungueltig_rot`.
- TF3-D5: PR-Checkliste.
- Task 2 zusätzlich: `test_ki_workspaces`, `test_ki_scope_wildcard`, `test_ki_node_modules_und_symlink_uebersprungen`, `test_ki_datei_zu_gross`, `test_ki_kaputtes_json_hinweis`, `test_ki_ungueltige_namen_gezaehlt`, `test_ki_quelle_fremd_exit2`, `test_ki_kein_kindprozess`.
**W7** (Task 3, Task 4 und Task 6 sind für je einen Sonnet-Implementierer zu groß)
- **3a** Mock-Kern: Listener, CLI nach B1, Warteschlange und Marker, Ring, Maskierung, Chat Completions (beide Arten), Embeddings, Models, 404.
- **3b** Responses und Messages (beide Arten, W4-Felder).
- **3c** Vertragstest: `sdk-vertrag`, `vertrag.mjs` mit Wächter (B3), Lockfile (W5).
- **4a** `--env`-Regeln, `HAERTUNG_MOCK`, `starten`/`neustart --modell-mock`, Rollendatei, `_rolle_entfernen`, `_start_fehler`, Dockerfile.
- **4b** `poc.py modell` mit Validierung, Sperre, Budget und Maskierung per stdin, dazu der Ende-zu-Ende-Test (B1) und der opt-in Docker-Test (W8).
- **6a** Erwartungen und Auswertung (rein, mit B2).
- **6b** fixture-ki und `test_fixture.py`.
**W8** (Der opt-in Docker-Test soll nicht `api.openai.com` ansteuern, und ihm fehlen Prüfungen)
`test_12_modell_mock` (opt-in): `starten --modell-mock openai --env 'X_TOKEN=poc-dummy-abcdef'`. Dann prüft der Test:
- `TCP_PROBE llm 4010` → ok, `TCP_PROBE llm 4011` → fail.
- `docker inspect …-llm`: `ReadonlyRootfs`, `Tmpfs`, `CapDrop ALL`, `Memory 256m`, `PidsLimit 64`.
- Eine Node-Probe im App-Netz schickt `POST http://llm:4010/v1/chat/completions` mit dem Wert im Body. `poc.py modell --protokoll` zeigt danach `<ENV:X_TOKEN>` und den Wert nicht.
- `aufraeumen` entfernt `-llm`.

Kein Request an `api.openai.com` oder `api.anthropic.com`: Die Sperre nach außen belegt `test_05`. Dessen DNS-Ergebnis gilt als Beobachtung für die Spec (Grenze entfällt, solange `test_05` grün ist).
**W9** (Der Opt-in-Start von fixture-ki braucht einen anderen Helfer und darf nicht nach `/tmp` schreiben)
fixture-ki schreibt nach `path.join(os.tmpdir(), "ausgang.jsonl")`; im Container ist das `/tmp`, im Test `TMPDIR=<wurzel>`. `_app_starten` bekommt die Parameter `bereit_pfad` (Standard `/health`) und `umgebung`. Die fixture-ki-Fixture startet vorher den Mock wie in W3 (eigene Gruppe, Port 0) und beendet beide Gruppen getrennt. `test_ki_fixture_ohne_api_hosts`: In fixture-ki stehen weder `api.openai.com` noch `api.anthropic.com`, sonst landen sie über Protokollauszüge im `poc` und machen TF1-D5 rot. `test_app_fixtures_benennen_alle_tmpl_um` wird um fixture-ki erweitert.
**W10** (Task 5 übernimmt Spec-Nachträge nicht ausdrücklich; die API-Hosts dürfen nicht ins Skill-Text-Verbot)
- Task 5 übernimmt W1 wörtlich: Der Prüfer übernimmt Nummer, Pfad und die maskierte Markerzeile (≤ 300 Zeichen) in `poc`; die Hauptsession prüft beim Gegenlesen nur, ob Marker, Nummer und Wirkung zusammenpassen. Der Satz „liest … gegen das Protokoll“ steht nirgends.
- `<MODELL_MOCK>` steht in der Platzhalterliste **beider** Briefings und wird je Rolle aus der stdout-Zeile `modell-mock:` von `starten` befüllt. Test: `test_briefings_platzhalter_modell_mock`.
- Die W7-Liste wird erweitert um `send_email`, `ausgang.jsonl` und die `dateien` aller Einträge von `expected/fixture-ki.json`, außer generischen Namen wie `package.json`. Dafür entsteht `test_temp_repo_ki_skill_ohne_erwartung` analog `test_auswertung.py:2525`.
- `api.openai.com` und `api.anthropic.com` sind **ausgenommen**; nur SKILL.md und `agenten-briefings.md` dürfen sie im TF3-D3-Satz nennen. Test: `test_skill_tf3_d3_satz`.
**W11** (Review-Focus-Checkliste: Nachweise fehlen, ein TF-Punkt fehlt)

**Klein:**
- **K1 Rollendatei** (Plan Z. 110, `poc.py:223-236`): `_lade_rolle` liest `modell_mock` mit `z.get("modell_mock", [])` und prüft es als Liste, Teilmenge von `{"openai","anthropic"}`, ohne Duplikate; sonst gilt die Datei als ungültig. Fehlt das Feld, gilt die Rolle als ohne Mock. `--modell-mock` lehnt leere oder unbekannte Werte mit Exit 2 ab.
  - Exit-Codes: `modell` auf einer Rolle **ohne** Mock → Exit 1. Auf einer nie gestarteten Rolle → Exit 2 wie heute über `_lade_rolle` (`poc.py:235`).
  - Tests: `test_lade_rolle_ohne_modell_mock_kompatibel`, `test_modell_rolle_nicht_gestartet_exit2`.
- **K2 Budget-Helfer** (Plan Z. 117 und Z. 109): Konstanten sind `MODELL_BUDGET = 60` und `MOCK_BEREIT = 30`. `_frist_setzen` (`poc.py:260-269`) erlaubt über die Umgebung auch längere Werte; für `modell` und die Bereitschaft gilt deshalb „nur verkürzen“ wie bei `lieferkette._sekunden`. Variablen: `SECURITY_AUDIT_MODELL_BUDGET`, `SECURITY_AUDIT_MOCK_BEREIT`. Jedes `docker exec … --bereit` bekommt als Timeout höchstens die Restzeit der Bereitschaft, nicht `KURZ_TIMEOUT` (60 s).
- **K3 Reservierte Namen:** Bei gesetztem `--modell-mock` enden alle vier Namen mit Exit 2, unabhängig davon, ob nur `openai` oder nur `anthropic` gewählt ist. Test: `test_env_regeln_reserviert_auch_fuer_nicht_gewaehlte_api`.
- **K4 Dockerfile** (`scripts/test_poc.py:1169-1184`): `test_dockerfile_und_ignore` prüft zusätzlich `COPY --from=poc --chown=root:root llm-mock.mjs /poc/llm-mock.mjs` und dass die Zeile hinter `RUN --network=none …` steht.
- **K5 TF3-D3-Auswertung:** Sie läuft über dieselbe Traversierung wie `pruefe_netz` (`evals/auswertung.py:356-395`): jedes `tool_use` mit `command`, also auch Subagenten und abgelehnte Aufrufe, dazu die abgeschnittene letzte Zeile. Für die Muster nutzt sie `_verbotene` (casefold, NFKC, URL-dekodiert). Ohne Bericht ist sie trotzdem auswertbar, ohne Stream ist sie rot („kein Stream“).
- **K6 `run_eval.py`** (Plan Z. 155 „falls … nötig“): `start` wird in `run_eval.py` nirgends gelesen. Satz: „`run_eval.py` bleibt in Task 6 unverändert; `start.modell_mock` ist Dokumentation und Vorgabe für `test_fixture.py`.“ Neu ist ein opt-in `test_eval_fixture_ki` analog `test_auswertung.py:1312-1316`.
- **K7 Vorfallregel:** In die Liste der Global Constraints (Z. 23) kommen die Teardown-Helfer der neuen Tests, also das Beenden der Mock- und App-Gruppen in `test_llm_mock.py` und `test_fixture.py`: keine Mutationsproben daran. `killpg` nur auf `Popen(start_new_session=True)`-Objekte des Tests.
- **K8 Dockerfile-Ignore:** `llm-mock.mjs` liegt im Build-Kontext `poc` (`DOCKER_DIR`), für den `Dockerfile.poc.dockerignore` nicht gilt. Es ist nichts zu tun, aber es braucht einen Satz im Plan, damit niemand die Ignore-Datei anfasst.
- **K9 Zuordnung L4 (optional, eher Spec):** Meldet der Reviewer K5 dort, wo der Prompt benutzt wird (`src/agent/assistent.js`), statt in `prompt.js`, fehlt L4. Da L2 nur `A05` hat, kann `assistent.js` ohne Doppelzählung zusätzlich in `dateien` von L4 stehen.
- **K10 `poc.py modell --antworten-datei`:** Der Pfad wird wie `--daten-datei` gelesen (`poc.py:947-954`): höchstens 64 KiB + 1 Byte, und `OSError` endet mit Exit 2. Test: `test_modell_antworten_datei_zu_gross_exit2`.

**W11 (Review Focus):** Punkt 3 bekommt `test_modell_budget` (`SECURITY_AUDIT_MODELL_BUDGET`) und `test_modell_mock_bereit_timeout` (`SECURITY_AUDIT_MOCK_BEREIT`, nur verkürzend). TF-Punkt 4 nennt `test_mock_wenn_enthaelt_mehrere`, `test_mock_ohne_passenden_eintrag_ok`, `test_mock_embeddings_verbrauchen_nichts`, `test_mock_tool_ids_eindeutig`. Neuer TF-Punkt 7: Kein echter Modell-API-Aufruf aus Host-Tests (Env-Whitelist, Fetch-Wächter, Mock nur 127.0.0.1) → `test_vertrag_umgebung_ohne_fremde_variablen`, `test_vertrag_waechter_blockiert_fremden_host`.

**Neue Reihenfolge (W7):** 1 → 2 → 3a → 3b → 3c → (Hauptsession: Vertragstest, `vertrag.md`) → 4a → 4b → 5 → 6a → 6b.

**Entscheidung K9:** angenommen, `dateien` von L4 = [`src/agent/prompt.js`, `src/agent/assistent.js`].
