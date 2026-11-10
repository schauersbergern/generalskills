# Spec TF2: Abhängigkeiten, Lieferkette und Secrets

**Feature-File:** `docs/features/2026-11-09-security-audit.md`, TF2 · **Branch:** `skills/audit-lieferkette` (gestapelt auf `skills/audit-ohne-pr`) · **Datum:** 2026-11-10

## Ziel

`/security-audit` findet zusätzlich bekannte Lücken in Abhängigkeiten (mit Erreichbarkeit im Code), Lieferketten-Schwächen (Lockfile, Installation, Install-Skripte) und Secrets in der Git-Historie — ohne dass Kundencode oder Repo-Konfiguration auf dem Host läuft und ohne dass ein Secret-Wert ins Modell, ins Transkript, in Bericht oder JSON gelangt.

## Andockpunkte (Ist)

| Pfad | Rolle | Änderung |
|---|---|---|
| `security-audit/SKILL.md` Ablauf 1–9 | Kern-Ablauf | neue Schritte „Werkzeuge“ (nach Docker-Vorbereitung, vor Reviewern) und Erreichbarkeitsprüfung durch Reviewer |
| `security-audit/references/pruefpunkte-web.md` | A01–A10 ohne A03 | Abschnitt A03 (Lieferkette) |
| `security-audit/references/bericht-format.md`, `scripts/bericht.py` | Schema v1 | optionale Felder `werkzeug` (`osv-scanner`/`gitleaks`/`lieferkette`), `commit` (Secrets), `pakete` (Abhängigkeit, Version, IDs) — bleiben optional, Schema-Version 1 |
| `security-audit/scripts/gitkopie.py` | Arbeitskopie, sichere git-Aufrufe | Wiederverwendung (`git()`), neue Funktion für Spiegelklon |
| `security-audit/evals/run_eval.py`, `auswertung.py`, `expected/` | Eval | neue Fixture `fixture-deps`, Laufzeit-Secret, Option `--ohne`/`--ohne-lockfile` (gibt es), Auswertung TF2-D1…D6 |
| `/opt/homebrew/bin/osv-scanner` 2.6, `/opt/homebrew/bin/gitleaks` 8.30 | Werkzeuge | lokal installiert |

## Verhalten

### Neues Skript `security-audit/scripts/lieferkette.py` (nur Standardbibliothek, alle Unterbefehle mit Gesamtbudget, Ausgabe JSON auf stdout)

Werkzeug gilt als fehlend, wenn `shutil.which` nichts findet oder sein Name in `SECURITY_AUDIT_OHNE` (kommagetrennt) steht → `{"werkzeug": "<name>", "fehlt": true}` und Exit 0 (der Rest des Audits läuft weiter); der Bericht nennt „<name> fehlt, <Prüfung> nicht durchgeführt“ als Hinweis.

1. **`abhaengigkeiten --quelle <arbeitskopie>`** (Budget 300 s):
   - Lockfiles in der Arbeitskopie (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`; rekursiv, ohne `node_modules`) einzeln mit `osv-scanner scan source --lockfile <datei> --format json` (cwd = Temp-Ordner, nie das Repo). Nach außen gehen nur Paketnamen und Versionen (OSV-API; Rahmen-Erlaubtliste).
   - Ausgabe je Treffer: `paket`, `version`, `lockfile` (relativ), `ids` (OSV/GHSA), `aliase` (CVE), `zusammenfassung` (einzeilig, gekürzt), `behoben_in`, `dev` (aus Lockfile `dev: true` bzw. `devOptional`), `kev` (bool).
   - KEV: Katalog `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (Rahmen-Erlaubtliste), einmal je Lauf in den Zustandsordner geladen (Timeout 30 s); scheitert der Download, `kev: null` und Hinweis „KEV-Katalog nicht geladen“.
   - osv-scanner-Exit 1 = Treffer, 0 = keine, sonst Werkzeugfehler → Hinweis, keine Befunde erfunden.
2. **`secrets --repo <wurzel>`** (Budget 300 s):
   - Zuerst Spiegelklon `git clone --bare --no-local <wurzel> <zustand>/spiegel.git` über `gitkopie.git` (sichere Umgebung): Der Klon hat eine frische Konfiguration, damit keine Diff-/Textconv-/Filter-Treiber aus `.git/config` des Kundenrepos laufen, wenn gitleaks `git log -p` aufruft. Kein `--mirror` von Hooks.
   - `gitleaks git <spiegel.git> --redact --no-banner --report-format json --report-path <zustand>/gitleaks.json --exit-code 0` mit bereinigter git-Umgebung (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, ohne geerbte `GIT_*`).
   - Ausgabe je Treffer nur: `regel` (RuleID), `datei`, `zeile`, `commit` (voller SHA), `datum`, `noch_vorhanden` (Datei+Zeile in HEAD enthält noch einen Treffer derselben Regel: per zweitem gitleaks-Lauf `gitleaks dir <arbeitskopie> --redact` oder Commit = HEAD-Erreichbarkeit — Default: `gitleaks dir` auf die Arbeitskopie). Felder `Secret`, `Match`, `Line` aus dem gitleaks-JSON werden nie ausgegeben. Report-Datei und Spiegel werden danach gelöscht (`aufraeumen` des Zustandsordners).
3. **`lieferkette --quelle <arbeitskopie>`** (Budget 60 s), rein statisch:
   - `lockfile-fehlt`: `package.json` ohne eines der Lockfiles im selben Ordner → Befund P2, `datei` = `package.json`.
   - `installation-ohne-lockfile-treue`: in `Dockerfile*`, `**/*.dockerfile`, `.github/workflows/*.yml|yaml`, `.gitlab-ci.yml`, `Makefile`, `package.json`-Skripten jede Zeile mit `npm install` / `npm i` (Wortgrenze) ohne `--package-lock-only`; `pnpm install` ohne `--frozen-lockfile`; `yarn install` ohne `--frozen-lockfile`/`--immutable` → Befund P2 mit `datei`/`zeile`.
   - `install-skripte-offen`: Lockfile enthält Pakete mit `hasInstallScript: true` und es gibt weder `ignore-scripts=true` in `.npmrc` noch pnpm `onlyBuiltDependencies`/`neverBuiltDependencies` → Befund P3 mit Paketliste (gekürzt auf 20).
   - Ausgabe als Befund-Entwürfe (Felder wie JSON-Schema, Status `bestätigt`, `poc` = Fundstelle als Text, `werkzeug: "lieferkette"`).

### Einordnung im Skill (SKILL.md, neuer Schritt nach Docker-Vorbereitung)

- Hauptsession ruft die drei Unterbefehle (je ein einfacher Befehl, Netzregel).
- **Abhängigkeitslücken:** Je Treffer bekommt der zuständige Reviewer (oder ein eigener „Lieferkette“-Reviewer innerhalb des Budgets von 6) den Auftrag, die Erreichbarkeit zu belegen: Import des Pakets und Aufruf der betroffenen Funktion mit `datei:zeile` in der Arbeitskopie. Stufe: **P1**, wenn erreichbar (Aufrufstelle belegt) oder `kev: true`; sonst **P2**; reine Dev-Abhängigkeiten **P3** (auch bei KEV, mit Hinweis). Befund: `datei` = Aufrufstelle (erreichbar) bzw. Lockfile, `kategorie` `A03`, `status` `bestätigt` mit `poc` = „osv-scanner: <ID>/<CVE> in <paket>@<version>; Aufruf <datei:zeile>“ (erreichbar) bzw. `unbestätigt` mit `code_pfad` = [Lockfile-Eintrag, Import] wenn nur importiert. Fix-Richtung: Version aus `behoben_in`.
- **Secrets:** Je Treffer Befund **P1** (auch wenn nicht mehr vorhanden), `kategorie` `A04`, `datei`/`zeile` aus gitleaks, `commit`, `status` `bestätigt`, `poc` = „gitleaks Regel <regel> in Commit <commit7>, Datei <datei>:<zeile> (Wert geschwärzt)“, `erwartet` = „Secret rotieren; aus der Historie entfernen nur nach Rotation“. Kein Prüfer-PoC.
- **Lieferkette:** Entwürfe aus `lieferkette` übernehmen (Prüfer nicht nötig; Stufen wie oben).
- **Werkzeug fehlt:** Hinweis im Bericht; bei `SECURITY_AUDIT_OHNE` mit `docker` keine PoCs (vorhanden in TF1-Logik über `poc.py pruefen` → hier: Skill prüft `SECURITY_AUDIT_OHNE` vor `poc.py pruefen`).
- **Datenschutz:** Kein Read der gitleaks-Report-Datei durch das Modell; die Hauptsession sieht nur die bereinigte Ausgabe von `lieferkette.py secrets`.

### Eval

- **Test-App `security-audit/evals/fixture-deps/`:** Express-App (wie fixture-web, minimal) mit `package.json.tmpl` und `package-lock.json.tmpl` (Dependabot-Schutz), darin
  - eine bekannt verwundbare Version, deren betroffene Funktion aufgerufen wird (Kandidat: `lodash@4.17.20` mit `_.template` an einer Route; CVE-2021-23337 — per osv-scanner vor dem Einchecken bestätigen, sonst anderes Paket),
  - eine zweite verwundbare Version, die nur deklariert, nie importiert wird (Kandidat: `minimist@1.2.5`),
  - `Dockerfile` mit `RUN npm install`,
  - keine Install-Skripte (Fixture bleibt im PoC lauffähig).
- **Laufzeit-Secret:** `run_eval.py` legt im Temp-Repo nach dem Initial-Commit eine Datei `config/keys.js` mit einem zufällig erzeugten Wert an, der eine generische gitleaks-Regel trifft (Form `const apiKey = "<32 Zeichen [A-Za-z0-9] aus secrets>"`; vorher per `gitleaks dir` in einem Wegwerf-Ordner prüfen, welche Form trifft), committet, löscht die Datei, committet erneut. Der Wert steht nur im Speicher von `run_eval.py` und wird für TF2-D2 gegen Stream, Bericht, JSON und Ausgabeordner geprüft (nie in `ergebnis.json` geschrieben, nur ein Hash).
- **Drei Läufe** (Budget laut Feature-File): `fixture-deps`; `fixture-web` (Regression TF1-D1…D7); `fixture-web --ohne-lockfile --ohne gitleaks,osv-scanner,docker`.
- **Erwartung `expected/fixture-deps.json`:** Einträge für die erreichbare Abhängigkeit (P1, Datei der Aufrufstelle), die nicht erreichbare (P2/P3, Lockfile), Secret (P1, `config/keys.js`), Lieferkette Dockerfile (P2, `Dockerfile`).
- **Auswertung:** neue Prüfungen `pruefe_abhaengigkeiten`, `pruefe_secret` (Wert nirgends; Treffer mit Commit), `pruefe_lieferkette`, `pruefe_werkzeug_hinweise`, `pruefe_alles_unbestaetigt`.

## Abnahmekriterien

| ID | Nachweis | Wo |
|---|---|---|
| TF2-D1 | [Test] | Eval `fixture-deps`: erreichbare Abhängigkeit P1 mit Aufrufstelle, nicht erreichbare P2/P3 |
| TF2-D2 | [Test] | Eval `fixture-deps`: Secret P1 mit Commit; Wert in keinem Stream-Ereignis, Bericht, JSON, Ausgabeordner-Datei; dazu Unit-Test `lieferkette.py secrets` gibt nie `Secret`/`Match` aus |
| TF2-D3 | [Test] | Eval `fixture-deps`: Befund „Installation ohne Lockfile-Treue“ nennt `Dockerfile`; Unit-Test `lieferkette` |
| TF2-D4 | [Test] | Eval `fixture-web` ohne Lockfile/Werkzeuge: Hinweise „gitleaks fehlt“, „osv-scanner fehlt“, Befund „Lockfile fehlt“, jeder P1/P2 `unbestätigt` |
| TF2-D5 | [Test] | wie D4: TF1-D1 gilt |
| TF2-D6 | [Test] | Regression `fixture-web`: TF1-D1…D7 |
| TF2-D7 | [Durchklick] | README-Zeile nennt Abhängigkeiten und Secrets |

Unit-Tests (immer, ohne Netz): `lieferkette.py` mit Fake-`osv-scanner`/Fake-`gitleaks` im `PATH` (JSON-Ausgaben), Spiegelklon führt keinen Textconv-Treiber aus (Marker), Report-Datei nach Lauf gelöscht, `SECURITY_AUDIT_OHNE`, KEV-Abgleich mit lokalem Katalog-Fake, Budgets.

## Entscheidungen/Annahmen

1. **Werkzeuge laufen nie im Kundenrepo**, sondern auf Arbeitskopie bzw. Spiegelklon: gitleaks ruft `git log -p` auf; Repo-Konfiguration (Textconv, externe Diffs) würde sonst Kundencode auf dem Host ausführen (TF1-Grundregel).
2. **Secret-Werte gelangen nie ins Modell:** `--redact` (Entschieden) plus Ausgabe ohne `Secret`/`Match`-Felder; die Report-Datei liegt im Zustandsordner (Temp, außerhalb Repo und Ausgabeordner) und wird gelöscht.
3. **Erreichbarkeit belegt das Modell** (Import + Aufruf mit `datei:zeile`), nicht ein Werkzeug — kein Call-Graph-Analysator für JS in der Standardbibliothek; konservativ P2 ohne Beleg.
4. **`hasInstallScript`-Prüfung als P3**: real, aber ohne konkreten Angriffsweg im Code.
5. **KEV-Download einmal je Lauf**, scheitert er → Hinweis, keine Stufenerhöhung.
6. **Schema bleibt Version 1** mit optionalen Feldern `werkzeug`, `commit`, `pakete` (unbekannte Felder sind erlaubt).
7. **Sicherheitsregel Vorfall 2026-11-10**: keine Signale an fremde Prozesse; Mutationsproben nie an Kill-/Lösch-Logik.
8. **Eval-Rechte** (`run_eval.erlaubte_regeln`): `Bash(python3 -I <skill>/scripts/lieferkette.py *)` ergänzen; osv-scanner/gitleaks laufen nur über das Skript.
