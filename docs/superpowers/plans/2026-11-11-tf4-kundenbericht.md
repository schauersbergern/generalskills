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

## Nachträge nach Plan-Review R1 (Vorrang vor den Tasks oben; alle angenommen)

Die Befunde stehen mit Begründung und fertigem Nachtrag hier; bei Widerspruch gilt der jeweilige **Nachtrag** bzw. der Klein-Vorschlag. Neue Reihenfolge (W7): 1 → 2a → 2b → 3 → 4 → 5.

#### W1 Schnittstelle `kunden_verstoesse` widerspricht der Spec und kann das Du-Wort nicht transportieren (Z. 53–56, Z. 75; Spec Z. 177, Z. 274)
- Der Plan legt `list[dict]` mit `id, feld, regel, token` fest; `token` gibt es „nur bei Regel a“. Die Spec (B-2, Vorrang) sagt `list[tuple[id, feld, regel, detail]]`. B1 verlangt in der Meldung das gefundene Du-Wort. Task 2 (Z. 75) will „Wort bzw. Token“ melden, das Dict hat dafür aber kein Feld.
- Die Werte von `regel` stehen nirgends fest (Du, a–e, URL, E-Mail, `www.`). Task 2 (Meldung), Task 4 (Schritt 7 erklärt die Meldung) und Task 5 (Tests) brauchen sie gleich.
- `auswertung.py` ruft die Funktion auf dem Eval-JSON auf, auch wenn dort das Schema verletzt ist (`auswerten` prüft D3 nur und läuft weiter, `auswertung.py:681`). Wirft die Funktion, ist der ganze Eval-Lauf ohne Auswertung, und das bei „letzter Lauf aus dem Budget“.
- **Nachtrag:**
  > `bericht.kunden_verstoesse(daten) -> list[tuple[str, str, str, str | None]]` mit (id, feld, regel, detail). `feld` ist `zusammenfassung`, `massnahme` oder `titel`. `regel` ist eines von `du`, `a`, `b`, `c`, `d`, `e`, `url`, `email`. `detail` ist bei `du` das gefundene Wort (wie im Text, ≤ 20 Zeichen), bei `a` das Token per `gitkopie._t(token, 60)`, sonst `None`. Die Funktion wirft nie, egal welche Typen im JSON stehen (wie `pruefe_schema`). Befunde ohne gültige `id` oder mit fehlenden Feldern überspringt sie. Quellen für a, d und e sind `poc`, `code_pfad` und `datei` **aller** Befunde, unabhängig vom Status. Geprüft werden nur Befunde mit Status `bestätigt`/`unbestätigt` (NFC). Test: `test_kunden_verstoesse_wirft_nie` (Wurzel als Liste, `befunde` als Text, `poc` als Zahl, `code_pfad` mit Nicht-Text).

#### W2 PDF-Stub, Task-2-Tests und echte Werkzeuge (Z. 14, Z. 86, Z. 88–95, Z. 103)
- Der Stub hat keine Signatur. Task 3 „ruft … auf und stubbt sie hier“ lässt offen, was Task 3 ersetzt.
- Task 2 testet Kopf, Stufen und Escaping über die CLI. Mit dem Stub endet jeder Lauf mit Exit 3. Sobald Task 3 den Stub ersetzt, laufen dieselben Tests mit den lokal installierten Werkzeugen (`/opt/homebrew/bin/pandoc`, `/opt/homebrew/bin/weasyprint`; das Repo hat keine CI). Die Asserts auf Exit 3 werden rot, oder der Task-3-Implementierer stellt sie auf Exit 0 um. Dann läuft die Standard-Suite echte Werkzeuge, entgegen Z. 14 („nur in den opt-in-Tests“).
- Offen ist auch, ob bei fehlendem weasyprint pandoc vorher schon läuft (TF4-D5 mit PATH-Shim: Ist dann pandoc im Shim, startet die echte oder eine Attrappe?).
- **Nachtrag:**
  > Task 2 legt `pdf_erstellen(md_pfad: str, pdf_pfad: str, titel: str, ende: float) -> tuple[int, str | None]` an (Exit-Code 0/3/4 und Kategorie). Der Stub gibt `(3, "pdf-werkzeug-fehlt")` zurück; Task 3 ersetzt nur den Rumpf. Der Test-Helfer in `test_kundenbericht.py` setzt standardmäßig `SECURITY_AUDIT_OHNE=pandoc,weasyprint`. Alle Task-2-Tests mit der CLI erwarten Exit 3 und `kunde-md:`, oder sie prüfen die reine Funktion `markdown_erzeugen(daten) -> str`. Nur Task-3-Tests überschreiben die Umgebung, und zwar mit PATH-Shim-Attrappen. Echte Werkzeuge laufen nur bei `SECURITY_AUDIT_PDF=1`. `pdf_erstellen` prüft beide Werkzeuge (`poc.werkzeug_fehlt`), bevor es einen Kindprozess startet.

#### W3 Task 4 lässt Tests in `evals/` rot, bis Task 5 läuft (Z. 119, Z. 137–139, Z. 147–149)
- `test_regeln_passen_zu_skill` (`evals/test_auswertung.py:882–898`) verlangt für **jede** `python3`-Zeile in SKILL.md und `references/` eine Bash-Regel. Die neue Aufrufzeile aus Task 4 hat erst in Task 5 eine Regel. Task 4 führt `test_auswertung.py` nicht aus und bleibt damit rot, ohne es zu merken. TF3 hat genau das gelöst, indem es `erlaubte_regeln` in den Skill-Text-Task zog (TF3-Plan Task 5, „Eval-Regel“).
- Die Temp-Repo-Tests (`test_auswertung.py:2575–2593` und `:2600–2620`) prüfen **jede** Datei des kopierten Skills auf die Namen von fixture-deps und fixture-ki. Davon betroffen sind `kundenbericht.py`, `kundenbericht.html5` und das neue Beispiel in `bericht-format.md`. Ein naheliegendes Beispiel wie „Aktualisieren Sie lodash …“ oder ein Kommentar `lodash@4.17.21` macht sie rot (`VERBOTENE_NAMEN_TF2`, `test_auswertung.py:34`). Weder Task 2 und 3 noch Task 4 führen diese Tests aus.
- **Nachtrag:**
  > Task 4 übernimmt aus Task 5 `erlaubte_regeln` (Regel nach R1-K9, I1-Negativbeispiele `… kundenbericht.py erstellen --json /etc/x.json` und `… kundenbericht.py erstellen --json {aus}x/y.json`) und erweitert `test_regeln_passen_zu_skill` (`gesehen["kundenbericht"]`, Marke `/kundenbericht.py erstellen `). Task 4 führt zusätzlich `pytest security-audit/evals/test_auswertung.py -k "regeln or temp_repo"` aus. Tasks 1 bis 4 verwenden in Nicht-Test-Dateien (Docstrings, Kommentare, Template, Beispiele) keine Namen aus `VERBOTENE_NAMEN_TF2`/`_TF3` und keine Pfade aus `expected/fixture-web.json`. Paketbeispiele heißen `beispiel-paket`.

#### W4 Task 5: welche Bestandstests brechen und wie `auswerten` die Kundendaten bekommt (Z. 150–162)
- Mit `kundenbericht: true` in `fixture-web.json` bekommt jeder `alles()`-Aufruf mit dieser Erwartung den Schlüssel TF4-D6. Das sind 104 Aufrufe (Helfer `test_auswertung.py:374`). Ohne `kunde`-Argument ist TF4-D6 rot. Damit brechen `test_auswerten_ok` (`:382`), `test_auswertung_regression_nur_tf1` (`:2179`), die Fake-Lauf-Tests an `:1162`, `:1348`, `:1966` und `:2461` sowie jeder Test, der `e["ok"] is True` erwartet. Der Plan nennt nur „feste Schlüsselmengen“. Das ist derselbe Fall wie TF3 R1-B2.
- Der Vertrag für `kunde` ist offen: Typen (`pdf_anfang` als Bytes oder Text), Verhalten bei fehlender Datei, und welche `-kunde.md` genommen wird, wenn mehrere im Ordner liegen (`-2`-Basisnamen). Ebenso offen ist, ob „vorhanden“ aus `ausgabe_dateien` oder aus `kunde` kommt.
- **Nachtrag:**
  > `auswerten(…, kunde: dict | None = None)` mit `{"md": str | None, "pdf_anfang": bytes | None, "projekt": str | None}`. `run_eval` leitet die Pfade aus `bericht_pfad` ab (`os.path.splitext(bericht_pfad)[0] + "-kunde.md"` bzw. `.pdf`), liest das Markdown (höchstens 1 MiB) und 8 Bytes des PDFs; fehlt eine Datei, ist der Wert `None`. TF4-D6 ist bei `kundenbericht: true` und `kunde is None` rot („keine Kundendaten“). `DOD_WEB` (`test_auswertung.py:32`) bekommt `TF4-D6`. `alles()` setzt standardmäßig `kunde=KUNDE_OK` (Markdown mit Kopf ohne Projekt, `b"%PDF-1.7"`, `projekt=None`) und `ausgabe_dateien` um `x-kunde.md`, `x-kunde.pdf` erweitert. Der Docstring von `test_auswertung_regression_nur_tf1` nennt TF4-D6. Das Fake-claude schreibt `x-kunde.md` (Kopfzeile) und `x-kunde.pdf` (`%PDF-1.7`). Neu: `test_pruefe_ablage_zaehlt_kunde_md_nicht` (nur `x-kunde.md` und `x.json` → „kein Bericht (.md)“).

#### W5 Titelkorrektur gegen „Entwürfe unverändert übernehmen“ (Z. 125; R2-W-2; `SKILL.md:131`)
- `lieferkette.py` erzeugt Titel mit Pfad: „Installation ohne Lockfile-Treue in {rel}“ und „Lockfile fehlt für {rel}“ (`lieferkette.py:2039–2040`, `:2073–2074`). Bei `rel` mit `/`, etwa `apps/web/package.json` oder `.github/workflows/ci.yml`, trifft Regel e den Titel, und `kundenbericht.py` endet mit Exit 2.
- SKILL.md 5b sagt aber „Die Entwürfe aus `entwuerfe` unverändert übernehmen“ (`SKILL.md:131`). Das Modell steht dann zwischen zwei Regeln. Entweder es korrigiert nicht, und nach 2 Runden gibt es keinen Kundenbericht, oder es bricht 5b.
- In fixture-web tritt der Fall nicht auf (kein Dockerfile, Paket-Root ohne `/`). In Monorepos ist er der Normalfall.
- **Nachtrag:**
  > Task 4, Schritt 7 (Exit 2): „Trifft eine Meldung `titel`, formulierst du den Titel ohne Pfad und Zeile um. Das gilt auch für Titel, die aus `lieferkette`-Entwürfen oder den festen Werkzeugtiteln aus 5b stammen. Die Korrektur geht der Regel ‚unverändert übernehmen‘ vor, `stufe`, `status`, `datei` und alle anderen Felder bleiben.“ In 5b steht ein Verweis darauf. Test: `test_skill_schritt_7_titelkorrektur_vor_5b`.

#### W6 Spec-Anforderungen ohne Task oder ohne Test (Spec R1-W11, R2-K-8, §5, Z. 18–19 Plan)
- **K-8:** „Die festen Texte sichert ein Test.“ Dieser Test ersetzt die Feature-File-Vorgabe „prüft das ganze erzeugte Markdown“. Im Plan fehlt er.
- **R1-W11:** Der Titel wird auf 120 Zeichen gekürzt und mit „…“ beendet. Das fehlt in Task 2.
- **Spec §5 / R1-W4:** „Die Meldung enthält nie den Treffertext“ (Regeln b bis e). Kein Test im Plan prüft das.
- **Global Constraint „kein `*_PROXY`“ (Z. 19):** ohne Test. Er ist Teil der Sicherheitsregeln.
- **Nachtrag:**
  > - Task 2: `test_feste_texte_ohne_du_und_spuren`. Sie rendert Berichte über alle Stufen in Singular und Plural, `bestätigt` und `unbestätigt`, jeden Eintrag der Eingeschränkt-Tabelle, Teilpfad und keine Befunde. Datenfelder werden dabei durch neutrale Platzhalter ersetzt, und das ganze Markdown wird mit der Du-Liste, Regel d und W11 geprüft: keine Treffer.
  > - Task 2: `titel` über 120 Zeichen wird auf 119 Zeichen plus „…“ gekürzt (`test_titel_gekuerzt`). Die Prüfung läuft auf dem Rohwert.
  > - Task 2: `test_meldung_ohne_treffertext`. Bei b, c, d und e enthält stdout weder den `code_pfad`-Eintrag noch `datei:zahl`, `GET /…` oder die URL, nur ID, Feld und Regel.
  > - Task 3: `test_werkzeug_umgebung_ohne_proxy`. `HTTPS_PROXY`, `http_proxy`, `ALL_PROXY` und `PYTHONPATH` werden per monkeypatch gesetzt, und die Attrappen protokollieren ihre Umgebung: Keine dieser Variablen kommt an. Die Umgebung ist eine Whitelist (siehe K3).

#### W7 Task 2 ist für einen Sonnet-Implementierer zu groß (Z. 63–95)
- Task 2 umfasst CLI, Exit-Tabelle, Eingabe- und Kollisionsprüfung, Löschlogik, das zweistufige Schema, Stufen, Kopf mit drei Namensquellen, Management-Zusammenfassung mit Singular/Plural und Statusvarianten, die Eingeschränkt-Tabelle, Nachweistexte je Herkunft, Escaping, atomare Ablage und den Stub. Dazu kommen über 20 Tests. TF3 hat vergleichbare Umfänge geteilt (TF3 R1-W7).
- **Nachtrag:**
  > Task 2 wird geteilt. **2a** (`kundenbericht.py`, `test_kundenbericht.py`): CLI und argparse-Unterbefehl `erstellen`, Exit-Tabelle, Eingabe, `-kunde.json`-Kollision, Entfernen alter Dateien, Schema-Kopie (Exit 5), Feldprüfung und `kunden_verstoesse` (Exit 2), atomare Ablage, Stub nach W2, mit einem Platzhalter-Markdown (`# Manibase · Sicherheitsprüfung …`). Tests: TF4-D3, TF4-D4, Ablage, `test_meldung_ohne_treffertext`. **2b** (dieselben Dateien): `markdown_erzeugen` mit Kopf, Zusammenfassung, Eingeschränkt-Tabelle, Befunden, Nachweisen, Umfang und Grenzen, Fuß und Escaping. Tests: TF4-D1, TF4-D2, `test_escaping_*`, `test_eingeschraenkt_*`, `test_nachweis_je_herkunft`, `test_feste_texte_ohne_du_und_spuren`, `test_titel_gekuerzt`. Neue Reihenfolge: 1 → 2a → 2b → 3 → 4 → 5.

### Klein (R1)

- **K1 casefold und Regex (Z. 55):** Nach `casefold` trifft ein Muster wie `\b(GET|POST|…)\s+/` (Regel b) nie, ebenso `\bZeile\s+\d+` (Regel d).
  > Die Regex-Regeln (b, d, url, email, `\bwww\.`) laufen mit `re.IGNORECASE` auf dem NFC-Text. `casefold` gilt nur für die Teilstring-Abgleiche (a, e, d-Pfade, Du-Liste). Test `test_kunden_verstoesse_b_grossklein` mit `get /api` und `Post /x`.
- **K2 Exit 1 und Meldungsformat (Z. 70, Spec R2-K-2):** Für Exit 1 fehlt der Wert von `kategorie`, und ein Traceback endet mit rc 1 ohne `kategorie:`-Zeile. Die Grenze von 30 Zeilen fehlt im Plan.
  > `main` fängt jede unerwartete Ausnahme ab, gibt `kategorie: intern` und eine Zeile ohne Traceback aus und endet mit Exit 1. Exit-2-Zeilen haben das Format `<id> <feld>: Regel <regel>[ (<detail>)]`, höchstens 30 Zeilen, danach `… und <n> weitere`. Tests: `test_unerwarteter_fehler_exit1_kategorie`, `test_meldung_hoechstens_30_zeilen`.
- **K3 Kindprozesse (Z. 103–104):** `werkzeug_ausfuehren` setzt stdin auf `/dev/null` (`gitkopie.py:143–144`), Markdown per stdin geht also nicht. Ohne `env` erbt es `*_PROXY` (`gitkopie.py:84–92`). weasyprint ist ein Python-Programm und wertet `PYTHONPATH` und `PYTHONSTARTUP` aus.
  > pandoc liest die geschriebene `-kunde.md` als absoluten Pfad. Die Umgebung beider Werkzeuge ist eine Whitelist: `PATH`, `LANG`, `LC_ALL`, `HOME`=Temp-Ordner, `TMPDIR`=Temp-Ordner. Per Probe läuft weasyprint auch ohne `HOME` ohne stderr. Aufgerufen wird der von `shutil.which` gelieferte absolute Pfad.
- **K4 Template und HTML-Prüfung (Z. 101, Z. 105):**
  > Das CSS im Template enthält kein `$` (pandoc-Template-Syntax). Der Sollwert für `<style>` ist der Text zwischen `<style>` und `</style>` der Template-Datei. Die Teile aus `handle_data` werden im Style-Element verkettet. Erlaubt ist nur `handle_decl` mit `DOCTYPE html`. Kommentare, Processing Instructions und `unknown_decl` ergeben Exit 4. Test `test_html_pruefung_kommentar_und_pi`.
- **K5 Budget (Z. 107, Z. 28):**
  > Konstante `KUNDE_BUDGET = 90`, Anteile `PANDOC_MAX = 20`, `WEASYPRINT_MAX = 60`, Wert über `poc._nur_verkuerzt("SECURITY_AUDIT_KUNDE_BUDGET", KUNDE_BUDGET)` (`poc.py:308`). Die Frist beginnt am Anfang von `main`. Ist die Restzeit vor einem Werkzeug ≤ 0, startet es nicht, und das Skript endet mit Exit 4. Ein Timeout (`rc is None`) ergibt Exit 4. Tests (monkeypatch auf `werkzeug_ausfuehren`, der die `timeout`-Werte protokolliert, kein Kindprozess): `test_budget_anteile`, `test_budget_rest_kuerzt_weasyprint`, `test_budget_env_nur_verkuerzend`, `test_budget_erschoepft_exit4`. Es gibt höchstens einen Timeout-Test mit echter Attrappe (`sleep`, Budget 1 s), keine Mutationsprobe daran.
- **K6 `test_skill_text.py` (Z. 137):** `SKRIPTE` allein genügt nicht.
  > Task 4 erweitert die Regex in `_aufrufe` (`test_skill_text.py:115`) um `kundenbericht`. `kundenbericht.py` nutzt argparse-Unterbefehle, damit `--help` `{erstellen}` zeigt (`_unterbefehle`, `test_skill_text.py:106`). Der Budget-Satztest vergleicht „`kundenbericht.py erstellen` … 90 s“ mit `kundenbericht.KUNDE_BUDGET`, außerhalb der Zeile mit `timeout: 600000`. `test_readme_nennt_ki_pruefpunkte_dateien_und_sdk_vertrag` (`:1315`) bleibt grün. Die Mindestversionen (pandoc ≥ 2.15, weasyprint mit `--allowed-protocols`) stehen nach R1-W1 auch in SKILL.md.
- **K7 Testnamen (Z. 39, Z. 59, Z. 88–89, Z. 109, Z. 171):** Review Focus und DoD-Tabelle nennen `test_du_*`, Task 1 nennt nur `test_kunden_verstoesse_*`. `test_stufen_*` ist offen. TF4-D5 erlaubt im Plan „PATH-Shim bzw. `SECURITY_AUDIT_OHNE`“, das DoD sagt aber „fehlt im `PATH`“.
  > Task 1: `test_du_formen_treffen`, `test_du_gegenbeispiele` (deinstallieren, Eureka, `dir-glob`, Ihr). Task 2b: `test_stufen_p1_ohne_anmeldung_kritisch`, `test_stufen_p1_mandantenuebergreifend_kritisch`, `test_stufen_p1_sonst_hoch`, `test_stufen_p2_mittel_p3_niedrig`. `test_weasyprint_fehlt_exit3_markdown_liegt` nutzt ausschließlich einen PATH-Shim (Attrappe `pandoc`, kein `weasyprint`), und die Attrappe protokolliert, dass sie nicht aufgerufen wurde.
- **K8 Kollision und Eingabe (Z. 72–74):** Ein laufendes Audit mit Teilpfad `kunde` hat nach `kontext` nur `<basis>-kunde.reserviert` (`bericht.py:174–178`), noch keine `.json`. Sein späteres `rendern` ersetzt dann per `os.replace` die `-kunde.md` des Gesamt-Audits, und der „Kundenbericht“ enthält danach PoCs.
  > K-5 prüft zusätzlich `<basisname>-kunde.reserviert` (Exit 5). Endet die Eingabe nicht auf `.json`, folgt Exit 5 ohne Entfernen. Test: `test_kunde_reserviert_kollision_exit5`.
- **K9 `ordner` ohne gültigen Namen (Z. 52):** `_bereinigen` kann `None` liefern (`bericht.py:56–59`).
  > `kontext` gibt dann `"ordner": null` aus. `pruefe_schema` akzeptiert `ordner` fehlend, `null` oder als Text nach dem `repo`-Muster. Der Kopf fällt bei `null` auf `repo` zurück. Test im Rahmen von `test_kontext_gibt_ordner`.
- **K10 Pfade in Task 4 (Z. 119):** `README.md` liegt in der Repo-Wurzel, nicht unter `security-audit/`.
  > Files: `README.md` (Repo-Wurzel), `security-audit/references/bericht-format.md`, `security-audit/scripts/test_skill_text.py`.
- **K11 Inhalt der Zusammenfassung (Z. 81–82):** Für eine Stufe mit gemischtem Status, für „Umfang und Grenzen“, den Fuß und `pagetitle` fehlt eine Festlegung.
  > Je Stufe und Status mit einer Anzahl größer 0 gibt es einen Satz: „ausnutzbar“ für `bestätigt`, „mögliche Schwachstelle“ für `unbestätigt`. Die Abschnittsfolge ist Kopf, Management-Zusammenfassung (Tabelle, Sätze), Befunde, Umfang und Grenzen (fester Text nach Spec §2.4 und der Eingeschränkt-Satz), Fuß „Manibase · vertraulich“. `pagetitle` ist „Manibase · Sicherheitsprüfung <Name>“.
- **K12 Seitenzahl im Opt-in-Test (Z. 113):** Der Pages-Knoten steht im Objekt-Stream als `/Type /Pages/Kids […]/Count 1` (Probe).
  > Alle Streams per `zlib` entpacken (Fehler überspringen), danach suchen mit `rb"/Type\s*/Pages\b.*?/Count\s+(\d+)"` (DOTALL).
- **K13 Review Focus (Z. 23–41):** Mehrere Nachweise sind nicht genannt: Löschgrenzen, Treffertext, Proxy, feste Texte.
  > TF-Punkt 4 nennt zusätzlich `test_symlink_ziel_exit5`, `test_kunde_json_kollision_exit5` und `test_kunde_reserviert_kollision_exit5`. Neuer TF-Punkt 6, „Keine Exploit-Texte in Meldungen und keine Proxys“: `test_meldung_ohne_treffertext`, `test_werkzeug_umgebung_ohne_proxy`. TF-Punkt 3 nennt `test_feste_texte_ohne_du_und_spuren`. Punkt 3 der festen Checkliste nennt die Budget-Tests aus K5 einzeln.


## Nachträge nach Plan-Review R2 (Vorrang vor allem oben; alle angenommen, Sätze wörtlich übernommen)

#### W-1 Regel e: Ob die eigene `datei` zählt, ist offen (Spec Z. 199 gegen Z. 286 und Z. 333; Plan Z. 53–56, Z. 190)
- Spec R1-W4 (e) nimmt „die eigene `datei`-Zeile“ aus. Diese Ausnahme stammt aus der Zeit, als das fertige Markdown geprüft wurde. Seit R2-W-3 werden die Rohwerte geprüft, und die Ausnahme hat keinen Gegenstand mehr.
- R2-K-10 sagt nebenbei, der eigene Pfad in `massnahme` „wäre ein Treffer der Regel e“. Plan W1 nennt die Quellen für e (`datei` aller Befunde), aber keine Ausnahme.
- Ein Task-1-Implementierer, der die Spec Z. 199 liest, baut die Ausnahme ein. Dann ist `test_datei_mit_dir_loest_nichts_aus` (K-10) inhaltlich anders gemeint als implementiert.
- Für das Eval ist das der häufigste erwartbare Treffer, etwa „Ergänzen Sie in src/routes/projects.js …“.
- **Nachtrag:** „Regel e gilt ohne Ausnahme: Auch die eigene `datei` eines Befunds ist in seinen Feldern `zusammenfassung`, `massnahme` und `titel` ein Treffer, sobald sie `/` enthält. Die Wendung ‚außer der eigenen `datei`-Zeile‘ (Spec R1-W4 e) entfällt mit R2-W-3. Test in Task 1: `test_kunden_verstoesse_e_eigene_datei` (eigene `datei` `src/x/y.ts` in `massnahme` ergibt `('S-1', 'massnahme', 'e', None)`).“

#### W-2 Schritt 7 erklärt dem Modell die Regeln nicht, und die Schreibregel ist schwächer als die Prüfung (Plan Z. 125–132, W1 Z. 187, K2 Z. 239)
- Die Exit-2-Meldung lautet `<id> <feld>: Regel <regel>[ (<detail>)]`. Bei b bis e und `url`/`email` gibt es kein Detail (Treffertext gesperrt). Das Modell muss also aus dem Buchstaben ableiten, was es ändern soll.
- Task 4 verlangt keine Legende der `regel`-Werte. W1 setzt sie nur voraus („Schritt 7 erklärt die Meldung“).
- Die Schreibregel „Keine Pfade mit Zeile“ (Z. 130) erlaubt Pfade ohne Zeile, Regel e verbietet sie. Regel c (`{ } < > =` und Backticks) fehlt in den Schreibregeln ganz. Modelle setzen Bezeichner gern in Backticks.
- Beides zusammen macht die 2-Runden-Schleife und damit TF4-D6 im letzten Eval-Lauf unnötig fragil.
- **Nachtrag:** „Task 4, Schritt 7 enthält eine Legende aller `regel`-Werte mit je einem Satz:
  - `du`: Du-Form, Detail ist das Wort
  - `a`: Text aus einem `poc`, Detail ist das Token
  - `b`: HTTP-Methode mit Pfad
  - `c`: Zeichen `{ } < > =` oder Backtick
  - `d`: Datei mit Zeile, `#L…` oder ‚Zeile n‘
  - `e`: Dateipfad oder Code-Pfad eines Befunds, auch der eigene
  - `url`: URL oder `www.`
  - `email`: E-Mail-Adresse
  - `fehlt`, `schema`: siehe Klein K-1

  Die Schreibregeln verbieten ausdrücklich Datei- und Pfadnamen (die betroffene Datei zeigt der Bericht selbst), Backticks und die Zeichen `{ } < > =`. Test: `test_skill_schritt_7_regel_legende` prüft, dass jeder Wert aus `bericht.KUNDEN_REGELN` (neue Konstante in Task 1) in Schritt 7 als `` `<wert>` `` steht.“

#### W-3 `pdf_erstellen` hat keinen Kanal für Meldungen (Plan W2 Z. 197 gegen Z. 105–106 und Spec R2-K-2)
- Laut W2 gibt `pdf_erstellen(...)` `tuple[int, str | None]` zurück, und Task 3 ersetzt „nur den Rumpf“.
- Exit 4 soll aber den Tag- bzw. Attributnamen nennen (Z. 105), dazu die stderr-Kategorie. Die erste stdout-Zeile muss `kategorie: …` sein, die zweite `kunde-md: …` (K-2).
- Druckt `pdf_erstellen` die Meldung selbst, steht sie vor der `kategorie:`-Zeile, die `main` erst nach der Rückkehr ausgibt. Gibt es sie zurück, ändert sich die Signatur.
- **Nachtrag:** „`pdf_erstellen(md_pfad: str, pdf_pfad: str, titel: str, ende: float) -> tuple[int, str | None, list[str]]` (Exit-Code, Kategorie, Meldungszeilen ohne Werte aus Daten). `pdf_erstellen` schreibt nie auf stdout. `main` gibt `kategorie: …`, `kunde-md: …` und danach die Meldungen aus, höchstens 30 Zeilen insgesamt. Der Stub in 2a gibt `(3, 'pdf-werkzeug-fehlt', [])` zurück.“

#### W-4 Welche Tests jeder Task ausführt (Plan Z. 21, W3 Z. 203)
- `test_skill_text.py::test_keine_namen_der_ki_fixture_in_scripts_und_docker` (`test_skill_text.py:1283–1290`) liest **alle** `.py` unter `scripts/`, auch `test_*.py`. Gesucht wird case-insensitiv nach der Liste in `test_skill_text.py:915–918`, etwa `send_email`, `tickets.js`, `datei_suchen`, `fixture-ki`.
- W3 beschränkt die Namensregel auf „Nicht-Test-Dateien“. Ein Regel-e- oder Regel-a-Test in `test_bericht.py` oder `test_kundenbericht.py` mit `tickets.js` oder `send_email` macht `test_skill_text.py` rot. Das merkt erst Task 4, und der darf die Testdateien von Task 1 bis 3 laut Files nicht ändern.
- Die Temp-Repo-Tests (`test_auswertung.py:1056ff.`, `:2569ff.`, `:2596ff.`) hängen genauso an `kundenbericht.py` und `kundenbericht.html5` aus Task 2a und 3.
- Task 1 ändert `bericht.pruefe_schema`, das `test_lieferkette_statisch.py:19/766/1098`, `evals/test_fixture.py:309` und `evals/test_auswertung.py` importieren. Der Monkeypatch in `test_lieferkette_statisch.py:1098` setzt die Signatur `_befund_fehler(b, w)` mit zwei Positionsargumenten voraus.
- **Nachtrag:**
  > „Die Namensregel aus W3 gilt auch für `scripts/test_*.py` (Liste `test_skill_text.py:915`).
  >
  > Je Task laufen:
  > - Task 1: `test_bericht.py`, `test_lieferkette_statisch.py`, `test_skill_text.py -k ki_fixture` sowie `evals/test_fixture.py` und `evals/test_auswertung.py -k "schema or bericht_ok"`. `_befund_fehler` behält seine Signatur.
  > - Task 2a, 2b und 3: `test_kundenbericht.py`, `test_skill_text.py -k ki_fixture` und `evals/test_auswertung.py -k temp_repo`.
  > - Task 4: wie W3.
  > - Task 5: `evals/test_auswertung.py` ganz.“

### Klein

- **K-1 Exit-2-Zeilen für fehlende Felder sowie Typ- und Längenfehler (Plan Z. 75, W1, K2):** Die `regel`-Liste in W1 deckt nur `kunden_verstoesse` ab.
  > „Für eigene Prüfungen nutzt `kundenbericht.py` dasselbe Zeilenformat mit `regel` `fehlt` (Feld fehlt) und `schema` (Typ, Einzeiligkeit, unsichtbare Zeichen, Länge; Detail ist die Schemameldung ohne den Wert, z. B. `kürzer als 40 Zeichen`). Test `test_feld_fehlt_und_zu_kurz_exit2` in 2a.“
- **K-2 `www.` und Du-Regex (W1, K1 Z. 237):** In W1 fehlt der `regel`-Wert für `\bwww\.`. K1 ordnet die Du-Liste dem casefold-Teilstringabgleich zu, W1 verlangt aber das Wort „wie im Text“. Nach casefold verschieben sich die Positionen, etwa bei `ß`.
  > „`\bwww\.` meldet `url`. Die Du-Liste läuft als Regex mit den Grenzen aus B1 und `re.IGNORECASE` auf dem NFC-Text, nicht auf casefold; Detail ist `match.group()`.“
- **K-3 Fehlende Felder in `kunden_verstoesse` (W1 Z. 190):** „überspringt sie“ lässt offen, ob der ganze Befund entfällt. Dann bliebe der Titel ungeprüft, und es bräuchte eine Korrekturrunde mehr.
  > „Fehlende oder nicht-textuelle Felder werden einzeln übersprungen, die übrigen Felder des Befunds werden geprüft.“
- **K-4 `ordner` (Task 1 Z. 52 gegen R2-K-4 und K9):**
  > „Es gilt K9: Der Wert fehlt, ist `null` oder ein Text nach `[A-Za-z0-9._-]+` und nicht nur aus Punkten. In `kontext()` heißt die bestehende Variable `ordner` (`bericht.py:160–167`) bereits der Ausgabeordner. Der neue Wert bekommt einen eigenen Namen (z. B. `ordner_name`), damit nicht der Ausgabepfad im JSON landet. `bericht-format.md` führt `ordner` als optionales Feld außerhalb der Tabelle ‚Oberste Ebene (alles Pflicht)‘ (`bericht-format.md:11`).“
- **K-5 W2 wörtlich (Z. 197):** „Alle Task-2-Tests mit der CLI erwarten Exit 3“ widerspricht TF4-D3/D4 (Exit 2) und den Ablage-Tests (Exit 5).
  > „… alle Task-2-Tests, deren Lauf bis zur PDF-Stufe kommt, erwarten Exit 3 und `kunde-md:`.“
- **K-6 Tests ohne Task (K2 Z. 239, K8 Z. 251):**
  > „`test_unerwarteter_fehler_exit1_kategorie`, `test_meldung_hoechstens_30_zeilen` und `test_kunde_reserviert_kollision_exit5` gehören zu 2a.“
- **K-7 `pagetitle` (Task 3 Z. 104):** Belegt durch die Probe oben.
  > „`pagetitle` wird nur per `--metadata pagetitle=…` übergeben (pandoc escapt), nie per `-V`/`--variable` (dort landet der Wert roh im `<title>`). `test_pandoc_args` prüft das.“
- **K-8 cwd von pandoc (Task 3 Z. 104):** Der cwd ist nur für weasyprint festgelegt (Spec Z. 92).
  > „Beide Werkzeuge laufen mit `cwd` gleich dem eigenen Temp-Ordner aus `tempfile.mkdtemp`. Aufgeräumt wird per `shutil.rmtree` nur dieser zurückgegebene Pfad.“
- **K-9 Festgelegter Satz in Grundregel 8:** `test_skill_budget_ki_und_modell` (`test_skill_text.py:1034–1036`) sucht die Zeile, die mit „- `poc.py`, `lieferkette.py` und `ki.py` immer als **einzelner einfacher Befehl**“ beginnt.
  > „Task 4 lässt diese Zeile unverändert und nennt `kundenbericht.py` unter ‚Kurze Budgets‘ und ‚Bash sonst nur für‘. Muss sie doch geändert werden, darf Task 4 den Satz in diesem Test mitziehen.“
- **K-10 Files von Task 4 und 5 nach W3:**
  > „Task 4 ändert zusätzlich `security-audit/evals/run_eval.py` (`erlaubte_regeln`, Docstring) und `security-audit/evals/test_auswertung.py` (`test_regeln_passen_zu_skill`). In Task 5 entfallen die Punkte `erlaubte_regeln` (Z. 149) und `test_regeln_passen_zu_skill` (Z. 161).“
- **K-11 Schlussmeldung nach 2 Runden (Spec Z. 104 „(Prüfung)“ gegen R2-K-2):**
  > „Nach 2 gescheiterten Runden lautet sie ‚Kundenbericht nicht erstellt (inhalt)‘, im selben Muster wie bei Exit 5 und 1.“
- **K-12 Eingeschränkt-Tabelle:** R1-W7 nennt „nicht geschwärzt“, R2-W-5 nicht.
  > „Die Tabelle aus R2-W-5 ist abschließend. ‚nicht geschwärzt‘ entfällt, weil dieser Abbruch keinen Bericht erzeugt.“
- **K-13 Mindestversion weasyprint (Task 4 Z. 135, K6):** Eine Versionsnummer steht nirgends. Ein Implementierer würde raten.
  > „README und SKILL.md nennen ‚pandoc ≥ 2.15 (für `--sandbox`), weasyprint mit Option `--allowed-protocols` (geprüft mit 68.1)‘ und keine weitere Versionsnummer.“
- **K-14 TF4-D6 im Detail (W4 Z. 209):** K10 erlaubt `_` im Projektnamen, die Escaping-Menge macht daraus `\_`. Ein Teilstringvergleich mit dem Rohnamen scheitert dann. Offen ist auch die Quelle für „vorhanden“.
  > „TF4-D6 vergleicht die erste Markdown-Zeile mit `'# Manibase · Sicherheitsprüfung ' + kundenbericht.escape(projekt)`. ‚Vorhanden‘ heißt `kunde['md'] is not None` bzw. `kunde['pdf_anfang'] is not None`. `ausgabe_dateien` zählt nur für `pruefe_ablage`. Ist `bericht_pfad` `None`, übergibt `run_eval` `kunde=None`.“
- **K-15 `run_eval` liest Kundendateien (W4):**
  > „`run_eval` öffnet `-kunde.md`/`.pdf` mit `O_NOFOLLOW` und nur als reguläre Datei, sonst `None`. Die TF4-D6-Details zitieren nie Inhalt aus dem Markdown.“
- **K-16 Regel a und Zahlen mit Punkten (R2-B-1):** Ein Token wie `10.000` (6 Zeichen, `\w\.\w`) aus einem PoC-Antworttext trifft „über 10.000 Datensätze“ in `zusammenfassung`.
  > „Tokens, die nur aus Ziffern mit Tausenderpunkten bestehen (`\d{1,3}(\.\d{3})+(,\d+)?`), zählen für Regel a nicht.“
- **K-17 `test_feste_texte_ohne_du_und_spuren` (W6) braucht eine Prüffunktion für Text:**
  > „Task 1 stellt `bericht.text_verstoesse(text: str) -> list[tuple[str, str | None]]` bereit, mit den Regeln `du`, `d` ohne die Pfadteile, `url` und `email`, ohne Bezug zum JSON. `kunden_verstoesse` nutzt sie, und der Test in 2b ruft sie auf dem ganzen Markdown auf.“
- **K-18 Beispiel in `bericht-format.md` (Task 4 Z. 134):**
  > „Jeder Befund mit Status `bestätigt` oder `unbestätigt` im Beispiel trägt beide Felder (Längen nach Schema). Der Test prüft das zusätzlich zu `kunden_verstoesse == []`.“
- **K-19 Titel im Kundenbericht:** Für `titel` gelten nur d, e und W11 (R2-W-2). Titel wie „… per GET /api/projects/:id“ oder „SSRF über /preview?url=“ bestehen die Prüfung und stehen dann im Kunden-PDF. Das ist kein Testfehler.
  > „TF4-D7 (Durchklick) prüft ausdrücklich, ob Titel Routen oder Parameternamen enthalten. Ist das der Fall, wird Regel b in TF4-Härtung für `titel` übernommen.“

### Widersprüche Task-Text, Nachtrag und Spec mit gültiger Auflösung

| Stelle | Widerspruch | Es gilt |
|---|---|---|
| Task 1 Z. 53–54 | `list[dict]`, `token` | W1: Tupel `(id, feld, regel, detail)` |
| Task 1 Z. 52 | `ordner` „wie repo“ / R2-K-4 „einzeiliger Text“ | K9 (+ K-4 hier) |
| Task 1 Z. 55 | NFC + casefold für alles | K1 (Regex mit IGNORECASE), Du nach K-2 hier |
| Spec R1-W4 (a) | Token-Nummer statt Token | R2-B-1: Token, `_t(…, 60)` |
| Spec R1-W4 (e) | „außer eigener datei-Zeile“ | offen, W-1 hier |
| Task 2 Z. 63–95 | ein Task | W7: 2a/2b |
| Task 2 Z. 86 | Stub ohne Signatur | W2, ergänzt um W-3 hier |
| Task 2 Z. 72–74 | nur `-kunde.json` | K8: dazu `-kunde.reserviert`, Endung `.json` |
| Task 3 Z. 103 | Umgebung „ohne *_PROXY“ | K3: Whitelist |
| Spec R1-W1 | `weasyprint --help`-Vorprüfung | R2-K-3: entfällt |
| Task 3 Z. 109 | PATH-Shim „bzw.“ `SECURITY_AUDIT_OHNE` | K7: nur PATH-Shim |
| Task 4 Z. 119 | Files `security-audit/README.md` | K10 + W3 + K-10 hier |
| Task 4 Z. 125 | nur Felder korrigieren | W5: auch `titel`, vor 5b |
| Task 5 Z. 149, 161 | `erlaubte_regeln`, `test_regeln_*` | W3: in Task 4 |
| Task 5 Z. 157 | „feste Schlüsselmengen“ | W4 (DOD_WEB, `alles()`, Fake-claude) |
| Spec Z. 40/101, Z. 92 | 120 s / weasyprint 90 s | R2-K-1: 90/20/60 s |
| Spec Z. 88 | Symlink-Ziel Exit 2 | R1-K5/R2-K-2: Exit 5 |
| Spec Z. 75 | `&lt;`/`&gt;` | R2-K-7: Backslash |
| Spec Z. 43 | 2 MiB | R1-K4: `bericht.MAX_JSON_BYTES` |
| Spec Z. 90 | `--metadata title`, `-H` | R1-K2: `--template`, `pagetitle` (per `--metadata`, K-7 hier) |
| Spec Z. 104 | „(Prüfung)“ | K-11 hier: „(inhalt)“ |
| Plan Z. 179 | 1 → 2 → 3 → 4 → 5 | W7: 1 → 2a → 2b → 3 → 4 → 5 |

### TDD-Grünheit je Task

- **Task 1:** Grün, wenn `_befund_fehler` seine Signatur behält. Keine Bestandstests prüfen die Schlüssel von `kontext` exakt (`test_kontext_cli_json` prüft nur, ob sie vorhanden sind) oder ein leeres stderr bei `rendern`. Die Laufliste steht in W-4.
- **Task 2a, 2b:** Grün mit `SECURITY_AUDIT_OHNE` als Standard (W2) und K-5. Das Risiko liegt allein im Namensscan (W-4).
- **Task 3:** Task-2-Tests bleiben über `SECURITY_AUDIT_OHNE` auf Exit 3, und es läuft kein echtes Werkzeug. Grün mit W-3.
- **Task 4:** `_unterbefehle("kundenbericht")` braucht argparse-Unterbefehle aus 2a. `KUNDE_BUDGET` stammt aus Task 3 (K5), die Reihenfolge passt. Grün mit K-9 und K-10.
- **Task 5:** Die Bruchstellen sind in W4 vollständig benannt. Geprüft: Kein Test listet exakt die fehlgeschlagenen Schlüssel. `:1868` und `:2502` gelten für fixture-deps ohne `kundenbericht`.

