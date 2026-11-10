# Spec TF2: Abhängigkeiten, Lieferkette und Secrets

**Feature-File:** `docs/features/2026-11-09-security-audit.md`, TF2 · **Branch:** `skills/audit-lieferkette` (gestapelt auf `skills/audit-ohne-pr`) · **Datum:** 2026-11-10 · **Stand:** nach Spec-Review R1

## Ziel

`/security-audit` findet zusätzlich bekannte Lücken in Abhängigkeiten (mit belegter Erreichbarkeit), Lieferketten-Schwächen (Lockfile, Installation, Install-Skripte) und Secrets in der Git-Historie. Dabei läuft weder Kundencode noch Repo-Konfiguration (Git-Treiber, Ignore-/Allowlist-Dateien der Werkzeuge) auf dem Host, und kein Secret-Wert gelangt ins Modell, ins Transkript, in Bericht, JSON oder Ausgabeordner.

## Andockpunkte (Ist)

| Pfad | Änderung |
|---|---|
| `security-audit/SKILL.md` Grundregeln 3 und 8, Ablauf 1–9 | neuer Schritt 1b „Werkzeuge“ (direkt nach `vorbereiten`, vor der Karte); Reviewer-Auftrag Erreichbarkeit; Regel 8 um `lieferkette.py` und Budgets |
| `security-audit/references/pruefpunkte-web.md`, `agenten-briefings.md` | Abschnitt A03; Reviewer-Briefing für Erreichbarkeit |
| `security-audit/references/bericht-format.md`, `scripts/bericht.py` | optionale Felder `werkzeug`, `commits`, `pakete`; Regel: mit `werkzeug` genügt `code_pfad` mit ≥ 1 Eintrag |
| `security-audit/scripts/poc.py` (`pruefen`) | beachtet `SECURITY_AUDIT_OHNE` (`docker` → Exit 3 `docker-fehlt`) |
| `security-audit/scripts/gitkopie.py` | Wiederverwendung `git()`; neue Funktion `spiegel(repo, ziel, frist)` |
| `security-audit/evals/run_eval.py`, `auswertung.py`, `expected/`, `test_*` | Fixture `fixture-deps`, Laufzeit-Secret, Erwartung je Lauf, neue Prüfungen, Regel für `lieferkette.py` |
| `security-audit/scripts/test_skill_text.py` | neuer Unterbefehl in SKILL.md erwähnt |
| osv-scanner 2.6, gitleaks 8.30 (`/opt/homebrew/bin`) | Werkzeuge |

## Verhalten

### Neues Skript `security-audit/scripts/lieferkette.py`

Nur Standardbibliothek; jeder Unterbefehl mit `--lauf <id>` (Zustand unter `poc.zustand_ordner(lauf)`, Unterordner `lieferkette/`), Gesamtbudget, JSON auf stdout, Kindprozesse nur per eigenem `Popen` mit `start_new_session=True` und Timeout (Sicherheitsregel 2026-11-10: Signale nur an eigene Gruppe). Werkzeug gilt als fehlend, wenn `shutil.which` nichts findet oder der Name in `SECURITY_AUDIT_OHNE` steht → Ausgabe `{"werkzeug": "<name>", "fehlt": true, "hinweis": "<name> fehlt, <Prüfung> nicht durchgeführt"}`, Exit 0. Werkzeugumgebung: ohne `GITLEAKS_*`, `OSV_*`, `GIT_*`; `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`; cwd = eigener leerer Temp-Ordner im Zustand.

1. **`secrets --lauf <id> --repo <wurzel> --quelle <arbeitskopie>`** (Budget 300 s) — läuft in Schritt 1b **vor** jeder Leselast:
   - `gitkopie.spiegel`: `git clone --mirror --no-local <wurzel> <zustand>/lieferkette/spiegel.git` mit derselben bereinigten Umgebung (frische Konfiguration; keine Hooks, keine Treiber aus `.git/config`; alle Refs inkl. Remote-Tracking).
   - Historie: `gitleaks git <spiegel> --redact --no-banner --exit-code 0 --report-format json --report-path <zustand>/lieferkette/gl-git.json --config <leere-config> --gitleaks-ignore-path <leerer-ordner> --ignore-gitleaks-allow`. Die leere Config ist eine TOML-Datei, die nur `[extend] useDefault = true` enthält (Standardregeln, keine Repo-Allowlist).
   - Aktueller Stand: `gitleaks dir <quelle> …` mit denselben Optionen → Report `gl-dir.json`. Jede Fundstelle (`File`, `StartLine`, `StartColumn`, `EndColumn`, `EndLine`) wird **in der Arbeitskopie** überschrieben (gleiche Länge, Zeichen `*`), damit Karte, Reviewer und Prüfer den Wert nie lesen. Gemeldet als Hinweis „N Secret-Fundstellen in der Arbeitskopie geschwärzt“.
   - Ausgabe je (Regel, Datei): `regel`, `datei` (relativ), `zeile` (aus dem jüngsten Commit), `commits` (Liste voller SHAs, max. 20), `in_head` (bool: Datei kommt in `gl-dir` mit derselben Regel vor). Nie `Secret`, `Match`, `Author`, `Email`, `Message`, `Fingerprint`.
   - `finally`: `spiegel.git`, `gl-*.json`, leere Config/Ordner löschen (nur diese Pfade unter `<zustand>/lieferkette/`), auch bei Fehler/Budget. Budget abgelaufen → Hinweis „Secret-Prüfung abgebrochen (Zeitbudget)“.
   - Repo-eigene Werkzeug-Konfiguration (`.gitleaks.toml`, `.gitleaksignore`, `osv-scanner.toml` irgendwo im Baum, `gitleaks:allow`-Kommentare) wird als Hinweis gemeldet („im Repo vorhanden, beim Audit ignoriert“).
2. **`abhaengigkeiten --lauf <id> --quelle <arbeitskopie>`** (Budget 300 s):
   - Lockfiles in der Arbeitskopie (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`; rekursiv ohne `node_modules`) je einzeln in einen leeren Temp-Ordner kopieren (keine `osv-scanner.toml` daneben) und dort `osv-scanner scan source --lockfile <kopie> --format json --no-resolve` aufrufen. Exit 0 = keine, 1 = Treffer, 128 = keine Pakete (kein Fehler), sonst Werkzeugfehler → Hinweis.
   - Ausgabe **je Paket** (nicht je Advisory): `paket`, `version`, `lockfile`, `advisories` (Liste aus `id`, `aliase` (CVE), `zusammenfassung` einzeilig ≤ 200 Zeichen, `details` einzeilig ≤ 500 Zeichen), `behoben_in` (höchste `fixed`-Version über alle Advisories, nur `affected`-Einträge mit genau diesem Paketnamen und Ökosystem npm), `dev` (nur `dev: true` im npm-Lockfile; sonst `false`, dokumentiert), `kev` (true/false/null).
   - KEV: Katalog-URL der Erlaubtliste, einmal je Lauf in `<zustand>/lieferkette/kev.json` (Timeout 30 s, User-Agent `security-audit/1 (+https://github.com/schauersbergern/generalskills)`); Fehler → `kev: null`, Hinweis „KEV-Katalog nicht geladen“.
3. **`lieferkette --lauf <id> --quelle <arbeitskopie>`** (Budget 60 s, statisch):
   - `lockfile-fehlt`: `package.json` ohne Lockfile im selben Ordner **und** in keinem Elternordner bis zur Wurzel (Workspaces) → Entwurf P2.
   - `installation-ohne-lockfile-treue`: in `Dockerfile*`, `*.dockerfile`, `.github/workflows/*.y*ml`, `.gitlab-ci.yml`, `Makefile`, `package.json`-`scripts`: logische Zeilen (Fortsetzungen mit `\` zusammengefügt) mit `npm install`/`npm i` (nicht mit `-g`/`--global`, nicht `--package-lock-only`), `pnpm install`/`pnpm i`/nacktes `pnpm` ohne `--frozen-lockfile`, `yarn install`/nacktes `yarn` ohne `--frozen-lockfile`/`--immutable` → Entwurf P2 mit `datei`/`zeile`.
   - `install-skripte-offen`: Lockfile mit `hasInstallScript: true`-Paketen und keiner der Schutzmaßnahmen (`ignore-scripts=true` in `.npmrc`; `npm ci --ignore-scripts` in jeder gefundenen Installationszeile; pnpm `onlyBuiltDependencies`/`neverBuiltDependencies` oder `packageManager: pnpm@>=10`; yarn berry `enableScripts: false`) → Entwurf P3 mit bis zu 20 Paketnamen.
   - Entwürfe enthalten alle Pflichtfelder des Schemas, `status: unbestätigt`, `werkzeug: "lieferkette"`, `kategorie: "A03"`, `code_pfad: ["<datei>:<zeile>"]`.

### Einordnung im Skill

- **Schritt 1b (neu, nach `vorbereiten`, vor der Karte):** `lieferkette.py secrets`, `abhaengigkeiten`, `lieferkette` (je ein einfacher Befehl). Ihre Hinweise und Entwürfe merkt sich die Hauptsession.
- **Docker:** `poc.py pruefen` gibt bei `docker` in `SECURITY_AUDIT_OHNE` Exit 3 `docker-fehlt`.
- **Abhängigkeitslücken:** Je Paket mit Treffern prüft ein Reviewer (bestehende Fläche oder Fläche „Lieferkette“ innerhalb von 6 Reviewern) Import und Aufruf der in `details` genannten Funktion in der Arbeitskopie. Befund je Paket: `kategorie` `A03`, `werkzeug` `osv-scanner`, `pakete: [{"name","version","advisories":[ids]}]`, `status` **`unbestätigt`**, `code_pfad` = [`<lockfile>:<zeile>`, Import `datei:zeile`, Aufruf `datei:zeile`] (ohne Import nur der Lockfile-Eintrag). Stufe **P1**, wenn Aufruf belegt oder `kev: true` (nicht bei `dev`); sonst **P2**; reine Dev-Abhängigkeiten **P3**. `datei`/`zeile` = Aufrufstelle, sonst Lockfile. `erwartet` = „auf ≥ <behoben_in> aktualisieren“. Befunde mit `werkzeug` gehen nicht an die Prüfer (kein Request-PoC möglich); Feature-File TF1: ohne Request-Beleg ist der Status `unbestätigt`.
- **Secrets:** Je (Regel, Datei) ein Befund **P1**, `kategorie` `A07`, `werkzeug` `gitleaks`, `commits`, `datei`/`zeile`, `status` `unbestätigt`, `code_pfad: ["<datei>:<zeile>"]`, `erwartet` = „Secret rotieren; erst danach aus der Historie entfernen“ (bei `in_head: false` zusätzlich „Datei existiert in HEAD nicht mehr“).
- **Lieferkette:** Entwürfe übernehmen.
- **Teilpfad:** Werkzeugbefunde mit `datei` außerhalb des Teilpfads werden nicht zu Befunden, sondern zu Hinweisen „außerhalb des Teilpfads: <titel> (<datei>)“.
- **Dedup:** Ein A03-Werkzeugbefund und ein Code-Befund an derselben Senke bleiben getrennt (andere Ursache, andere Fix-Richtung); die Regel „gleiche Senke = ein Befund“ gilt nur zwischen Code-Befunden.

### Schema (`bericht.py`, Version 1)

Optionale Felder: `werkzeug` ∈ {`osv-scanner`, `gitleaks`, `lieferkette`}, `commits` (Liste Hex 7–64, ≤ 20), `pakete` (Liste Objekte `name`, `version`, `advisories`). Mit `werkzeug` genügt bei `unbestätigt` ein `code_pfad` mit ≥ 1 Eintrag. Einzeilige Felder bleiben einzeilig.

### Eval

- **`evals/fixture-deps/`:** minimale Express-App, `package.json.tmpl` + `package-lock.json.tmpl` (beide werden von `run_eval.py` umbenannt), `lodash@4.17.20` mit `_.template(vorlage, { variable: req.query.v })` in `src/routes/vorlage.js` (CVE-2021-23337 über `variable`), `minimist@1.2.5` nur deklariert, `Dockerfile` mit `RUN npm install`, keine Install-Skripte. Vor dem Einchecken per `osv-scanner` bestätigen und die Treffer (IDs) in `expected/fixture-deps.json` festhalten.
- **Laufzeit-Secret** (in `run_eval.py`, nur bei Fixtures mit `secret: true` in der Erwartung): nach dem Initial-Commit `config/keys.js` mit `const apiKey = "<32 Zeichen [A-Za-z0-9] aus secrets.choice>";` committen, dann löschen und committen. Alphanumerisch statt `token_hex`, weil Hex-Werte in ~19 % unter der gitleaks-Entropieschwelle bleiben (Spec-Review R1 K1, gemessen). Wert nur im Speicher; geprüft gegen Stream, Bericht, JSON, alle Dateien im Ausgabeordner und die Arbeitskopie; in `ergebnis.json` nur `sha256`.
- **Erwartung je Lauf:** `expected/fixture-deps.json` (Einträge: Abhängigkeit lodash P1 `paket: "lodash"` Datei `src/routes/vorlage.js` Kategorien A03/A05; minimist P2/P3 `paket: "minimist"` Datei `package-lock.json`; Secret P1 Datei `config/keys.js` Kategorien A07/A04; Lieferkette P2 Datei `Dockerfile`; `koeder_pruefen: false`, `secret: true`), `expected/fixture-web-ohne.json` für den Lauf `--ohne-lockfile --ohne gitleaks,osv-scanner,docker` (Lücken wie fixture-web, zusätzlich `lockfile-fehlt` P2 `package.json`, `werkzeug_hinweise: ["gitleaks fehlt", "osv-scanner fehlt"]`, `alle_unbestaetigt: true`). `run_eval.py --erwartung <datei>` wählt die Erwartung (Default `expected/<fixture>.json`).
- **Auswertung:** `auswerten` liest aus der Erwartung, welche Prüfungen gelten (`koeder_pruefen`, `secret`, `werkzeug_hinweise`, `alle_unbestaetigt`). Zuordnung: Einträge mit `paket` passen nur auf Befunde, deren `pakete` den Namen enthalten. Köder-Prüfung ignoriert Befunde mit `werkzeug`. Neue DoD-Schlüssel `TF2-D1`…`TF2-D4` im Ergebnis.
- **Drei Läufe:** `fixture-deps`; `fixture-web` (Regression); `fixture-web --ohne-lockfile --ohne gitleaks,osv-scanner,docker --erwartung expected/fixture-web-ohne.json`.

## Abnahmekriterien

| ID | Nachweis | Wo |
|---|---|---|
| TF2-D1 | [Test] | Eval `fixture-deps`: lodash P1 mit Aufrufstelle `src/routes/vorlage.js`, minimist P2/P3; Unit-Tests `abhaengigkeiten` (Fake-osv) |
| TF2-D2 | [Test] | Eval `fixture-deps`: Secret P1 mit Commit; Wert nirgends; Unit-Tests `secrets` (Fake-gitleaks: keine Wertfelder, Report gelöscht, Schwärzung in der Arbeitskopie, Spiegel ohne Treiberausführung) |
| TF2-D3 | [Test] | Eval `fixture-deps`: Befund nennt `Dockerfile`; Unit-Tests `lieferkette` |
| TF2-D4 | [Test] | Eval ohne Lockfile/Werkzeuge: Hinweise, Befund „Lockfile fehlt“, jeder P1/P2 `unbestätigt`; Unit-Test `poc.py pruefen` mit `SECURITY_AUDIT_OHNE=docker` |
| TF2-D5 | [Test] | derselbe Lauf: TF1-D1 |
| TF2-D6 | [Test] | Regression `fixture-web`: TF1-D1…D7 |
| TF2-D7 | [Durchklick] | README-Zeile nennt Abhängigkeiten und Secrets |

## Entscheidungen/Annahmen

1. **Werkzeugbefunde sind `unbestätigt`** (TF1 Entschieden: ohne Request-Beleg kein `bestätigt`); sie gehen nicht an die Prüfer; Schema erlaubt dafür `code_pfad` ≥ 1.
2. **Werkzeuge laufen nie im Kundenrepo und ohne Repo-Konfiguration** (Spiegelklon, eigene leere Configs, leeres cwd, bereinigte Umgebung), sonst könnten Repo-Inhalte Treffer unterdrücken oder Treiber ausführen.
3. **Secrets werden vor der Karte in der Arbeitskopie geschwärzt**; Ausgabe nur Metadaten.
4. **Erreichbarkeit belegt das Modell** (Import + Aufruf); ohne Beleg P2.
5. **KEV-Download einmal je Lauf**, Fehler → Hinweis.
6. **Teilpfad:** Werkzeugbefunde außerhalb → Hinweise.
7. **Advisory-Drift:** Erwartungen fordern nur die festgehaltenen Pakete; zusätzliche Werkzeugbefunde stören weder Recall noch Köder-Prüfung.
8. **Sicherheitsregel 2026-11-10** gilt.
9. **Eval-Rechte:** `Bash(python3 -I <skill>/scripts/lieferkette.py *)`.
