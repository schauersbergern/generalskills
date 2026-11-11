# TF4 Kundenbericht — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Aus dem Bericht-JSON entsteht über `scripts/kundenbericht.py erstellen` ein deutscher Kundenbericht als Markdown und PDF. Er enthält Kopf, Management-Zusammenfassung, Kundenstufen sowie Risiko und Maßnahme je Befund, ohne Exploit-Details und in Sie-Form. Die Inhaltsregeln greifen vor dem Schreiben. Das PDF entsteht über pandoc `--sandbox`, die HTML-Prüfung und weasyprint `--allowed-protocols ''`.

**Spec:** `docs/superpowers/specs/2026-11-11-tf4-kundenbericht-design.md`. **Die Nachträge R1 und R2 haben Vorrang, R2 vor R1, beide vor dem Haupttext.** Wo der Haupttext anderes sagt, gilt der Nachtrag. Das betrifft ausdrücklich:
- Du-Liste und Prüfumfang: R1-B1, R2-W-2 und W-3
- Exploit-Regeln: R1-W4, R2-B-1 und W-4
- Exit-Codes: R2-K-2
- Budget: R2-K-1
- Prüfort: R2-B-2 statt R1-K16

**Tech Stack:** Python 3.14 Standardbibliothek, pytest 9, pandoc 3.9, weasyprint 68.1. Die Werkzeuge laufen nur in den opt-in-Tests und im Eval.

## Global Constraints

- **Vorfall 2026-11-10:** Kindprozesse (pandoc, weasyprint) laufen nur über `gitkopie.werkzeug_ausfuehren`, also mit eigener Gruppe und Timeout. Es gibt keine weiteren Signale. **Keine Mutationsproben an Signal-, Kill- oder Lösch-Logik**: `_gruppe_beenden`, das Entfernen alter Kundendateien und Aufräum-`finally`.
- **Kein Netz:** pandoc läuft mit `--sandbox`, weasyprint mit `--allowed-protocols ''`, und die Umgebung enthält kein `*_PROXY`.
- **Öffentliches Repo:** Tests verwenden nur synthetische Berichte, keine Kundendaten.
- **Tests je Task:** nur die betroffenen Dateien. Die ganze Suite läuft einmal in der Verifikation.

## Review Focus

Feste Checkliste:
1. **Sperren:** nicht zutreffend, weil kein paralleler Zugriff stattfindet. Die Ablage schreibt atomar per `os.replace`. Nachweis: Task 2 `test_ablage_atomar`.
2. **Prisma/PG:** nicht zutreffend.
3. **Timeouts:** trifft zu. Gesamtbudget 90 s, pandoc höchstens 20 s, weasyprint höchstens 60 s, jeweils als Minimum aus Anteil und Rest. Nachweis: Task 3 `test_budget_*`.
4. **Org-Scope:** nicht zutreffend.
5. **≥ 2 Quellen:** trifft zu.
   - Die Exploit-Regeln prüfen gegen die `poc`- und `code_pfad`-Werte **aller** Befunde.
   - Die Liste „eingeschränkt“ wird aus mehreren Hinweisen gebildet.
   - Nachweis: Task 1 `test_kunden_verstoesse_fremder_befund`, Task 2 `test_eingeschraenkt_mehrere_hinweise`.
6. **Uhrsprung:** nicht zutreffend. Das Datum stammt aus dem JSON.

TF-spezifisch:
1. **Kein Datenzugriff aus Daten:** Escaping, die Erweiterungsliste von pandoc, `html.parser` mit Erlaubtliste und `--allowed-protocols` sperren das. Nachweis: Task 2 `test_escaping_*`, Task 3 `test_html_pruefung_*`, `test_weasyprint_args`.
2. **Keine Exploit-Spuren:** Regeln a bis e, W11 und der Titel. Nachweis: Task 1 `test_kunden_verstoesse_*`, dazu Falschpositiv-Tests.
3. **Sie-Form:** Du-Liste mit Grenzen. Nachweis: Task 1 `test_du_*`.
4. **Keine veralteten Dateien:** Vor jedem Lauf werden alte Kundendateien entfernt, das PDF wird atomar geschrieben. Nachweis: Task 2 `test_alte_kundendateien_entfernt`.
5. **Ehrliche Zusammenfassung:** Ist die Prüfung eingeschränkt, entfällt „keine Schwachstellen“. Nachweis: Task 2 `test_eingeschraenkt_*`.

---

### Task 1: `bericht.py` — Felder, `ordner`, `kunden_verstoesse`

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/scripts/bericht.py`; Test `security-audit/scripts/test_bericht.py`.

- [ ] Schema für `zusammenfassung` und `massnahme` (beide optional): Typ, einzeilig, keine unsichtbaren Zeichen, Länge 40 bis 600 bzw. 20 bis 400.
- [ ] `ordner` (optional): kommt aus `kontext` als Basename von `wurzel`, bereinigt wie `repo`; Schema wie `repo` (R2-K-4).
- [ ] `kunden_verstoesse(daten) -> list[dict]` mit den Schlüsseln `id`, `feld`, `regel` und `token`.
  - `token` gibt es nur bei Regel a: gekürzt auf 60 Zeichen und nur, wenn das Token aus `poc` stammt (R2-B-1).
  - Geprüft werden die Rohwerte von `zusammenfassung` und `massnahme` (Du-Liste, Regeln a bis e, W11) sowie `titel` (Regeln d, e und W11, R2-W-2), nach NFC und casefold.
  - Es werden nur Befunde mit Status `bestätigt` oder `unbestätigt` geprüft.
- [ ] `rendern` gibt die Treffer von `kunden_verstoesse` nur als Warnung auf stderr aus und endet mit Exit 0 (R2-B-2).
- [ ] Tests:
  - `test_kunden_verstoesse_*`: Du-Formen, Gegenbeispiele (`deinstallieren`, `Eureka`, `dir-glob`, `Ihr`), Regel a mit den R2-B-1-Fällen, Regeln b bis e, `Dockerfile:6`, `Zeile 42`, `#L42`.
  - Falschpositive: `Node 22`, `Port 3000`, `14:30 Uhr`, `Version 4.17.21`, `name@1.2.3`, `@scope/pkg@1.0.0`.
  - Weitere: E-Mail- und URL-Treffer, `test_kunden_verstoesse_fremder_befund`, `test_rendern_warnt_bei_kundenverstoss_exit0`, `test_kontext_gibt_ordner`, Schema für die Felder.

### Task 2: `kundenbericht.py` — Kern (Markdown, Prüfung, Ablage)

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/scripts/kundenbericht.py`, `security-audit/scripts/test_kundenbericht.py`.

- [ ] **CLI:** `erstellen --json <pfad>`.
- [ ] **Exit-Codes** laut Tabelle R2-K-2 (0/2/3/4/5, mit `kategorie:`-Zeile).
- [ ] **Eingabe:** `bericht.MAX_JSON_BYTES`, reguläre Datei, kein Symlink.
- [ ] **Kollisionen und alte Dateien:**
  - `-kunde.json` ist vorhanden → Exit 5 (R2-K-5).
  - Alte `-kunde.md` und `-kunde.pdf` direkt nach der Pfadprüfung entfernen. Ein Symlink an dieser Stelle ergibt Exit 5 ohne Entfernen (R2-K-6).
- [ ] **Schema:** zuerst eine Kopie ohne die zwei Kundenfelder prüfen (Fehler → Exit 5), danach die Felder selbst. Fehlt ein Feld oder gibt es einen Verstoß aus `kunden_verstoesse`, endet das Skript mit Exit 2 und der Meldung aus ID, Feld, Regel und Wort bzw. Token.
- [ ] **Auswahl und Stufen:** Status NFC-normalisiert. Die Stufentabelle steht in der Spec. IDs werden numerisch sortiert.
- [ ] **Kopf:**
  - Name in der Reihenfolge `projekt`, `ordner`, `repo`, jeweils mit dem Hinweis aus R1-W10.
  - Datum `TT.MM.JJJJ`, SHA 7-stellig.
  - Bei Teilpfad der Vermerk aus R2-W-5.
- [ ] **Management-Zusammenfassung:** Bausteine in Singular und Plural, „ausnutzbar“ nur bei `bestätigt`, sonst „mögliche Schwachstelle“. Kritisch heißt „umgehend“.
- [ ] **Eingeschränkte Prüfung:** Die Tabelle aus R2-W-5 entscheidet. Der Satz „keine Schwachstellen“ erscheint nur, wenn die Prüfung nicht eingeschränkt war.
- [ ] **Befunde:** Nachweistexte je Herkunft (R1-W6) inklusive `annahme_modell`. Für gitleaks steht ein fester Titel (R2-K-9). Ist `datei` null, steht „gesamtes Projekt“.
- [ ] **Escaping:** K1-Menge mit Backslash, auch `<` und `>` (R2-K-7). Daten stehen nie am Zeilenanfang.
- [ ] **Ablage:** atomar mit Temp-Datei im Zielordner und `os.replace`.
- [ ] **PDF:** Dieser Task ruft für das PDF eine Funktion aus Task 3 auf und stubbt sie hier. Bis Task 3 endet `erstellen` nach dem Markdown mit Exit 3 `pdf-werkzeug-fehlt`.
- [ ] **Tests:**
  - TF4-D1: `test_kopf_mit_projekt`, `test_kopf_ohne_projekt_ordner_hinweis`, `test_kopf_ohne_ordner_repo_hinweis`.
  - TF4-D2: `test_stufen_*`, `test_verworfen_und_verdacht_fehlen`.
  - TF4-D3: `test_poc_text_exit2_keine_datei`, `test_code_pfad_exit2_keine_datei`, `test_datei_zahl_exit2_keine_datei`.
  - TF4-D4: `test_du_exit2`, `test_datei_mit_dir_loest_nichts_aus` (R2-K-10).
  - Escaping: `test_escaping_*` für Link, Bild, HTML, `{…}`, Span und ATX-Schluss.
  - Ablage: `test_alte_kundendateien_entfernt`, `test_symlink_ziel_exit5`, `test_kunde_json_kollision_exit5`, `test_ablage_atomar`.
  - Eingeschränkt: `test_eingeschraenkt_mehrere_hinweise`, `test_eingeschraenkt_keine_befunde_kein_entwarnungssatz`.
  - Nachweise: `test_nachweis_je_herkunft`.

### Task 3: PDF-Kette

**Agent:** `sonnet-xhigh`

**Files:** Create `security-audit/scripts/kundenbericht.html5` (Template mit Inline-CSS, `lang="de"`, A4, Seitenzahlen, Systemschrift). Modify `kundenbericht.py` und `test_kundenbericht.py`.

- [ ] **Werkzeuge:** Fehlen sie, entscheidet `poc.werkzeug_fehlt("pandoc"|"weasyprint")`; dann Exit 3. Kindprozesse laufen über `gitkopie.werkzeug_ausfuehren` mit eigener Umgebung ohne `*_PROXY`. `GitFehler` ergibt Exit 3.
- [ ] **pandoc:** `--sandbox`, die Erweiterungsliste aus R1-K2, `--template`, `pagetitle`, `--columns=1000`. Ausgabe als HTML in einen eigenen Temp-Ordner.
- [ ] **HTML-Prüfung:** `html.parser` mit Erlaubtliste nach R1-W2 und R2-W-1 (`lang="de"` nur an `html`, genau ein `<style>` byte-gleich mit dem Template). Ein Verstoß ergibt Exit 4 mit Tag- bzw. Attributname.
- [ ] **weasyprint:** `--allowed-protocols ''`. stderr wird ohne Groß-/Kleinschreibung auf `disallowed protocol`, `failed to load` und `error` geprüft, ein Treffer ergibt Exit 4. Ist die Datei leer oder fehlt `%PDF`, ergibt das ebenfalls Exit 4. Das PDF wird atomar in den Zielordner geschrieben.
- [ ] **Budget:** 90 s gesamt über `SECURITY_AUDIT_KUNDE_BUDGET`, nur verkürzend. Jeder Timeout ist `min(Anteil, Rest)`.
- [ ] **Tests:**
  - TF4-D5: `test_weasyprint_fehlt_exit3_markdown_liegt` und `test_pandoc_fehlt_exit3`, mit `PATH`-Shim bzw. `SECURITY_AUDIT_OHNE`.
  - Werkzeugaufrufe: `test_pandoc_args` und `test_weasyprint_args` mit Attrappen, die die Argumente protokollieren.
  - HTML-Prüfung: `test_html_pruefung_*` für `img`, `link`, `object`, `href=http`, `style` an `h3`, zweites `<style>`; escapter Text ist erlaubt.
  - Fehlerpfade: `test_weasyprint_stderr_fehler_exit4`, `test_budget_*`.
  - Opt-in `SECURITY_AUDIT_PDF=1` mit echten Werkzeugen: `test_pdf_echt` (Ergebnis beginnt mit `%PDF`, Seitenzahl ≥ 1 per zlib nach R1-K3) und `test_pdf_echt_ohne_dateizugriff`. Dort steht im Titel ein escaptes `url(file:///etc/hosts)`; das PDF entsteht, und es tauchen keine Ladefehler auf.

### Task 4: SKILL.md, references, README

**Agent:** `sonnet-xhigh`

**Files:** Modify `security-audit/SKILL.md`, `references/bericht-format.md`, `README.md`, `scripts/test_skill_text.py`.

- [ ] **Grundregel 8:** Bash-Liste und kurzes Budget (90 s).
- [ ] **Schritt 1:** Die Notiz enthält `ordner`.
- [ ] **Schritt 7:**
  - Nach `rendern` folgt die wörtliche Aufrufzeile `kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json`.
  - Exit 2: `zusammenfassung`, `massnahme` oder `titel` korrigieren, danach `rendern` und `erstellen` neu, höchstens 2 Runden.
  - Exit 3 oder 4: Hinweis in die Schlussmeldung.
  - Exit 5 oder 1: „Kundenbericht nicht erstellt (<kategorie>)“ in die Schlussmeldung.
- [ ] **Schreibregeln:**
  - Sie-Form mit festem Satzmuster.
  - Keine Pfade mit Zeile, keine Requests, kein Code, keine Bezeichner.
  - Risiko in Geschäftsfolgen formulieren.
  - Nichts aus `advisories[].zusammenfassung` übernehmen.
- [ ] **Schlussmeldung:** Pfade der Kundendateien, „Vor Weitergabe lesen.“ und gegebenenfalls „Projektname fehlte“.
- [ ] **`bericht-format.md`:** Felder, Beispiel-JSON mit Sie-Form-Mustern (besteht Schema und `kunden_verstoesse`) und Abschnitt „Kundenbericht“ mit Stufentabelle.
- [ ] **README:** Die Zeile nennt Kundenbericht und `projekt=` (TF4-D8), dazu die Dateiliste und die Mindestversionen von pandoc und weasyprint.
- [ ] **Tests:**
  - `SKRIPTE` enthält `kundenbericht`.
  - Satz-Tests für Schritt 7, Schreibregeln, Schlussmeldung und Budget.
  - Das Beispiel besteht `kunden_verstoesse`.

### Task 5: Eval-Verdrahtung

**Agent:** `sonnet-xhigh`

**Files:** Modify `evals/run_eval.py`, `evals/auswertung.py`, `evals/expected/fixture-web.json`, `evals/testdaten/bericht_ok.json`, `evals/test_auswertung.py`.

- [ ] **`run_eval.py`:**
  - `--projekt` nach R1-K10, mit Anhang an den Prompt.
  - `erlaubte_regeln` mit der engen `kundenbericht.py`-Regel und dem I1-Negativbeispiel.
  - Übergabe von `kunde={md, pdf_anfang, projekt}` an `auswerten`.
- [ ] **`auswertung.py`:**
  - TF4-D6 bei `kundenbericht: true`: Markdown und PDF vorhanden, `%PDF`, Kopf, Projektname, `kunden_verstoesse` auf dem JSON leer.
  - `pruefe_ablage` schließt `-kunde.*` aus.
- [ ] **Erwartungen und Daten:**
  - `fixture-web.json` erhält `kundenbericht: true`.
  - `bericht_ok.json` erhält Kundenfelder.
  - Die festen Schlüsselmengen werden auf {TF1-D1…D7, TF3-D4, TF4-D6} erweitert.
  - Das Fake-claude schreibt `-kunde.md`/`.pdf`.
- [ ] **Tests:**
  - `test_auswertung_tf4_d6_*`: ok, PDF fehlt, Projekt fehlt, `code_pfad` im Feld.
  - `test_regeln_passen_zu_skill` mit `kundenbericht`.
  - `test_run_eval_projekt_im_prompt`.

## DoD-Abdeckung

| DoD | Task, Test |
|---|---|
| TF4-D1 | Task 2 `test_kopf_*` |
| TF4-D2 | Task 2 `test_stufen_*`, `test_verworfen_und_verdacht_fehlen` |
| TF4-D3 | Task 1 `test_kunden_verstoesse_*`, Task 2 `test_*_exit2_keine_datei` |
| TF4-D4 | Task 1 `test_du_*`, Task 2 `test_du_exit2`, `test_datei_mit_dir_loest_nichts_aus` |
| TF4-D5 | Task 3 `test_weasyprint_fehlt_exit3_markdown_liegt` |
| TF4-D6 | Task 5 und Eval `fixture-web --projekt Testportal --behalten` |
| TF4-D7 | Durchklick: PDF aus dem Eval |
| TF4-D8 | Task 4 README |

## Reihenfolge

Task 1 → 2 → 3 → 4 → 5. Danach folgen Härtung und Verifikation (ganze Suite, opt-in PDF, Docker), ein Eval (letzter Lauf aus dem Budget) und der PR auf `skills/audit-ki`.
