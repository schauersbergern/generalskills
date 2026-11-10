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

## Nachträge nach Plan-Review R1 (Vorrang vor den Tasks oben)

**Gemeinsame Bausteine (W2, K1) — in Task 4 anlegen, Tasks 1–3 nutzen sie:**
- `poc.werkzeug_fehlt(name: str) -> bool` (`shutil.which` + `SECURITY_AUDIT_OHNE`, kommagetrennt, getrimmt, case-insensitiv) — einziger Parser; `lieferkette.py` importiert ihn.
- `poc.schwaerz_marker(lauf: str) -> str` = `<zustand_ordner(lauf)>/lieferkette/geschwaerzt`; `vorbereiten` löscht ihn **vor** dem Neuaufbau von `quelle` über `_entferne(pfad, wurzel=<zustand>/lieferkette)`.
- `gitkopie.werkzeug_umgebung() -> dict` (Umgebung ohne `GIT_*`, `GITLEAKS_*`, `OSV_*`; plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`); `gitkopie.spiegel` nutzt sie; `lieferkette.py` ebenfalls.
- Löschregel: `lieferkette.py` löscht nur unter `<zustand>/lieferkette/` (über `poc._entferne`) und zusätzlich `.gitleaksignore`-Dateien innerhalb `<zustand>/quelle` (Pfad-Containment per `realpath`/`commonpath`).

**B1 (bestehende bauen-Tests):** `Umgebung.env()` in `test_poc.py` und die `stack`-/`test_11`-Umgebung in `test_poc_docker.py` setzen standardmäßig `SECURITY_AUDIT_OHNE=gitleaks`. Neue Marker-Tests legen ein Fake-`gitleaks` in den Shim-PATH: `test_bauen_ohne_marker_mit_gitleaks_verweigert`, `test_bauen_mit_marker_baut`, `test_bauen_ohne_gitleaks_im_path_baut` (`PATH=<shim ohne gitleaks>`), `test_bauen_ohne_marker_bei_ohne_gitleaks_baut`, `test_vorbereiten_loescht_marker`, `test_daemon_pruefen_ohne_docker_exit3` (für `pruefen`, `bauen`, `starten` parametrisiert).

**B2 (Erwartung und Auswertung):** Erwartungsschema:
```json
{"fixture": "fixture-deps", "verbotene_muster": ["fixture.invalid"],
 "koeder_pruefen": false, "secret": true, "werkzeug_hinweise": [], "alle_unbestaetigt": false,
 "eintraege": [
  {"id": "W1", "typ": "werkzeug", "dod": "TF2-D1", "dateien": ["src/routes/vorlage.js"], "paket": "lodash", "kategorien": ["A03", "A05"], "stufen": ["P1"]},
  {"id": "W2", "typ": "werkzeug", "dod": "TF2-D1", "dateien": ["package-lock.json"], "paket": "minimist", "kategorien": ["A03"], "stufen": ["P2", "P3"]},
  {"id": "W3", "typ": "werkzeug", "dod": "TF2-D2", "dateien": ["config/keys.js"], "kategorien": ["A07", "A04"], "stufen": ["P1"]},
  {"id": "W4", "typ": "werkzeug", "dod": "TF2-D3", "dateien": ["Dockerfile"], "klasse": "installation-ohne-lockfile-treue", "kategorien": ["A03"], "stufen": ["P2"]}]}
```
`fixture-web-ohne.json`: Einträge von `fixture-web` (Lücken und Köder) plus `{"id":"W1","typ":"werkzeug","dod":"TF2-D4","dateien":["package.json"],"klasse":"lockfile-fehlt","kategorien":["A03"],"stufen":["P2"]}`, `werkzeug_hinweise: ["gitleaks fehlt", "osv-scanner fehlt"]`, `alle_unbestaetigt: true`. DoD-Schlüssel je Erwartung: TF1-D3…D7 immer; TF1-D1 nur bei `luecke`-Einträgen; TF1-D2 nur bei `koeder_pruefen` und `koeder`-Einträgen; TF2-Dn für jedes `dod` der `werkzeug`-Einträge; TF2-D2 zusätzlich bei `secret`; TF2-D4 zusätzlich bei `werkzeug_hinweise`/`alle_unbestaetigt`. `ok` = alle vorhandenen Schlüssel ok. Ein `werkzeug`-Eintrag passt auf einen Befund, wenn `datei` ∈ `dateien`, `kategorie` ∈ `kategorien`, bei `paket` dessen Name in `pakete[].name`, bei `klasse` gleiche `klasse`; erfüllt, wenn Stufe ∈ `stufen` und Status `unbestätigt`. `test_auswerten_ok` bleibt für fixture-web bei genau `{TF1-D1..D7}`. **Wert-Suche:** `run_eval` liest Stream-Datei, Bericht-`.md`/`.json` und alle Dateien im Ausgabeordner als Text und übergibt `geheim_quellen: dict[str, str]` und `secret_info: {"sha256": …, "commit": …, "laenge": 32}`; `auswerten` hasht jedes 32-Zeichen-Fenster in Läufen `[A-Za-z0-9]{32,}`; ein Treffer → TF2-D2 rot. TF2-D2 erfüllt außerdem nur, wenn der Secret-Befund `secret_info.commit` in `commits` enthält. `run_eval --erwartung` prüft, dass `fixture` zur gewählten Fixture passt.

**W1:** SKILL.md Regel 8: `lieferkette.py secrets` und `abhaengigkeiten` mit `timeout: 600000`; Budget-Zusage je Befehl (300/300/60 s); `test_skill_text.py` (`LANGE_UNTERBEFEHLE`, `erwartet`-Dict, Budget-Satz) erweitern. SKILL.md: Jeder Ausgang von `secrets` außer Exit 0 mit Marker → Abbruch vor der Karte mit wörtlicher Meldung; nach jedem erneuten `vorbereiten` wieder `secrets` (K3); `nicht-geschwaerzt` in die Fehlerliste von Schritt 3.

**W3 (Task 3 Interface):** `lieferkette --lauf <id> --quelle <arbeitskopie>` → `{"entwuerfe": [...], "hinweise": [...]}`; Entwurf ohne `id` (vergibt die Hauptsession); `lockfile-fehlt`: `datei` = `package.json`, `zeile` = 1, `code_pfad` = [`package.json:1`]; `installation-ohne-lockfile-treue`: `datei`/`zeile` der logischen Zeile (erste physische Zeile); `install-skripte-offen`: `datei` = Lockfile, `zeile` = Zeile des ersten betroffenen Pakets, Paketnamen in `beschreibung`. Tests bauen einen vollständigen Bericht um die Entwürfe (IDs `S-1…`) und prüfen `bericht.pruefe_schema`.

**W4:** `in_head` per `git cat-file -e HEAD:<datei>` auf dem Spiegel (gilt für `.env*` und übersprungene Pfade). Test `test_secrets_in_head_env_datei`.

**W5 (Task 1 Negativ- und Hinweistests):** `test_schwaerzung_scheitert_exit4_ohne_marker` (Fake-gitleaks `dir` Exit 2, Timeout, unlesbarer Report; Ablauf des 120-s-Teilbudgets gilt als Scheitern); `test_schwaerzung_unscharf_hinweis` (Präfix passt nicht → ganze Spannen ohne Umbruch geschwärzt + Hinweis); `test_schwaerzung_pfad_ausserhalb_nicht_geschrieben` (`File` absolut außerhalb, mit `..`); `test_repo_konfig_hinweise` (`.gitleaks.toml`, `.gitleaksignore`, `osv-scanner.toml`, `gitleaks:allow` werden **vor** dem Löschen erkannt und gemeldet); Marker wird direkt nach erfolgreicher Schwärzung gesetzt (`test_marker_vor_historie`); Kappung `commits` ≤ 20; Dedup mit ≥ 2 Regeln je Datei und ≥ 2 Dateien je Regel.

**W6:** `test_skill_text.py` und `test_auswertung.py` verbieten zusätzlich in SKILL.md, references und kopiertem Skill: `config/keys.js`, `src/routes/vorlage.js`, `_.template`, `variable:`, `lodash`, `minimist` (generische Namen wie `package.json`, `package-lock.json`, `Dockerfile` erlaubt).

**W7:** `bericht.markdown` rendert im Detailabschnitt eines Befunds `Commits: <sha7>, …` (≤ 5, dann „+n“) und `Pakete: name@version (IDs)`; in der Befundliste (Codeblock) bleibt das Format unverändert. Test in `test_bericht.py` (Task 4).

**W8 Testnamen je DoD:** TF2-D1 → Task 6 `test_auswertung_tf2_d1_*`, Task 2 `test_abhaengigkeiten_mehrere_lockfiles_und_advisories`, `test_behoben_in_versionslinien`; TF2-D2 → Task 6 `test_auswertung_tf2_d2_wert_im_stream_rot`, `test_secret_einbau_zwei_commits`, Task 1 `test_secrets_ausgabe_ohne_wertfelder`, `test_schwaerzung_echt_*`; TF2-D3 → Task 6 `test_auswertung_tf2_d3_*`, Task 3 `test_installation_dockerfile_fortsetzung`; TF2-D4 → Task 6 `test_auswertung_tf2_d4_*`, Task 4 `test_daemon_pruefen_ohne_docker_exit3`, Task 1 `test_secrets_gitleaks_fehlt`, Task 2 `test_abhaengigkeiten_osv_fehlt`. Review-Focus 1/2/4/6: keine Sperren/keine DB/keine Org-Scopes (Werkzeugskripte ohne Persistenz); Budgets über `time.monotonic`.

**K4 Schema-Tests (Task 4):** unbekannter `werkzeug`-Wert; `commits` kein Hex oder > 20; `pakete[].advisories` kein String; `commits`/`pakete` ohne passendes `werkzeug`.
**K5:** Task 2 `test_texte_gekuerzt_einzeilig`, `test_kev_einmal_je_lauf` (Cache); Task 3 pnpm `onlyBuiltDependencies`/`neverBuiltDependencies`, nacktes `pnpm`/`yarn`, `--package-lock-only`.
**K6:** KEV-URL wörtlich `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; Unit-Tests setzen immer `SECURITY_AUDIT_KEV_DATEI` (autouse-Fixture), nie Netz.
**K7:** `test_fixture.py`: App-Fixture benennt alle `.tmpl` um; Tests „keine Install-Skripte“ und „keine echten Secrets“ für `fixture-deps`; PoC-Payload in Tests harmlos (`variable` liefert ein Rechenergebnis, kein Dateisystem/Prozess); Lockfile-Kopien heißen `package-lock.json`.
**K8:** Task-3-Satz „bis dahin Felder prüfen“ entfällt (Schema existiert nach Task 4).
**K9:** Testnamen wie oben, eindeutig gegenüber bestehenden (`test_lockfile_fehlt` u. a.).

## Nachträge nach Plan-Review R2 (Vorrang vor allem oben)

**B1 (SKILL.md, ersetzt den W1-Satz zu `secrets`):** `secrets` Exit 0 mit gesetztem Marker **oder** Exit 0 mit `{"werkzeug":"gitleaks","fehlt":true}` → weiter (fehlt: Hinweis übernehmen, keine Secret-Befunde). Alles andere (Exit ≠ 0; Exit 0 ohne Marker und ohne `fehlt`) → Abbruch vor der Karte mit wörtlicher Meldung. Test `test_skill_secrets_fehlt_laeuft_weiter` in `test_skill_text.py` (beide Sätze wörtlich vorhanden).

**W-a (DoD-Schlüssel, ergänzt B2):** Hat die Erwartung weder `luecke`- noch `werkzeug`-Einträge, sind TF1-D1 und TF1-D2 immer vorhanden und rot („Erwartung leer“). `test_erwartung_leer` bleibt unverändert grün.

**W-b (Task 1):** `secrets --lauf <id> --quelle <p> --sha <sha>`: Exit 2, wenn `realpath(--quelle) != realpath(<zustand_ordner(lauf)>/quelle)` oder `quelle.fertig` fehlt (wie `poc.py` beim Bau). Test `test_secrets_quelle_ausserhalb_verweigert` (Ordner außerhalb bleibt byte-gleich).

**W-c (Hinweise):** SKILL.md Schritt 1b: `hinweis`/`hinweise` aller drei Unterbefehle werden unverändert in `bericht.hinweise` übernommen; bei `fehlt` lautet der Hinweis wörtlich „gitleaks fehlt“ bzw. „osv-scanner fehlt“ (von den Skripten erzeugt, nicht vom Modell formuliert). `auswertung`: jeder Eintrag aus `werkzeug_hinweise` muss als Teilstring (NFC, casefold) in einem Element von `bericht["hinweise"]` stehen. Tests `test_auswertung_tf2_d4_hinweis_fehlt_rot`, `test_skill_hinweise_uebernehmen`.

**Klein:**
- K-a: Commit-Vergleich per Präfix (Befund-SHA ≥ 7 Zeichen, Präfix von `secret_info.commit`); SKILL.md schreibt volle SHAs aus der `secrets`-Ausgabe vor.
- K-b: `befunde_zuordnen`: Befunde mit `werkzeug` werden nur `werkzeug`-Einträgen zugeordnet, nie `luecke`/`koeder`. Test `test_werkzeug_befund_nicht_als_luecke`.
- K-c: `alle_unbestaetigt` = kein Befund mit Status `bestätigt` im Bericht.
- K-d: Nachtrag R1 gilt (`poc.werkzeug_fehlt`, `gitkopie.werkzeug_umgebung`); Task 4 Files zusätzlich `security-audit/scripts/gitkopie.py`, `security-audit/scripts/test_gitkopie.py`; Test `test_werkzeug_umgebung_ohne_git_variablen`.
- K-e: `abhaengigkeiten` liefert je Paket `zeile`: npm-Lockfile Zeile des Schlüssels `"node_modules/<name>"`, sonst erste Zeile mit dem Paketnamen, Fallback 1; `code_pfad` = `<lockfile>:<zeile>`. Test `test_abhaengigkeiten_zeile_im_lockfile`.
- K-f: `in_head` per `git cat-file -e <sha>:<datei>` mit dem übergebenen `--sha` (nicht `HEAD`).
- K-g: Marker wird auch gesetzt, wenn `gitleaks dir` nichts findet. Test `test_marker_ohne_treffer`.
- K-h: In `bauen` kommt die Marker-Prüfung **nach** `_daemon_pruefen`.
- K-i: TF2-D5 → `test_auswertung_fixture_web_ohne_tf1_d1`; TF2-D6 → `test_auswertung_regression_nur_tf1`.
- K-j: Kurze git-Aufrufe über `gitkopie.git()` (`subprocess.run` mit Timeout, beendet nur das eigene direkte Kind) sind erlaubt; der Spiegel-Klon und die Werkzeuge (gitleaks, osv-scanner) laufen über eigenes `Popen(start_new_session=True)` und beenden bei Timeout nur diese eigene Gruppe. Keine anderen Signale.
