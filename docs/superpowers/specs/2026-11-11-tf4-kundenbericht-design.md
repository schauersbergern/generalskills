# Spec TF4: Kundenbericht (Markdown und PDF)

Stand: nach Spec-Review R2. **Die Nachträge R1 und R2 am Ende haben Vorrang; R2 vor R1.** Feature-File `docs/features/2026-11-09-security-audit.md`, Abschnitt TF4 (DoD TF4-D1 bis TF4-D8). Branch `skills/audit-kundenbericht`, gestapelt auf `skills/audit-ki` (TF3, PR #13).

## Ziel

Aus dem Bericht-JSON eines Audits entsteht ein deutscher Kundenbericht als Markdown und PDF. Er enthält eine Management-Zusammenfassung, die Kundenstufe je Befund (Kritisch, Hoch, Mittel, Niedrig) und die Maßnahmen. Exploit-Details stehen nicht darin: keine Zeilen, kein `poc`, kein `code_pfad`, keine `beschreibung`. Die Anrede ist durchgehend „Sie“. Kopf: „Manibase · Sicherheitsprüfung <Projekt>“ mit Datum und Commit.

## Andockpunkte (Ist)

- `security-audit/scripts/bericht.py`:
  - Schema (`pruefe_schema`, `_befund_fehler`), Kopffelder `repo`, `sha`, `datum`, `teilpfad`, `projekt` (optional, `projekt="…"`), `hinweise`, `befunde`.
  - `rendern <json>` schreibt das technische Markdown neben das JSON (`<ausgabe_ordner>/<basisname>.md`).
- `security-audit/SKILL.md`:
  - Argument `projekt="…"` (Z. 4, 14).
  - Schritt 7 (Bericht): JSON schreiben, dann `bericht.py rendern`; Exit 2 → korrigieren.
  - Grundregel 8: Aufrufform und Budgets.
- `security-audit/references/bericht-format.md`: Felder und Beispiel-JSON.
- `security-audit/evals/run_eval.py`:
  - Prompt `/security-audit-eval` ohne Argumente (`PROMPTS`).
  - `erlaubte_regeln` für die Bash-Rechte des Eval-Laufs.
- `security-audit/evals/auswertung.py`: DoD-Schlüssel je Erwartung (`_dod_schluessel`); `fixture-web` hat TF1-D1 bis D7 und TF3-D4.
- Werkzeuge lokal: `pandoc` 3.9 (kennt `--sandbox`), `weasyprint` 68.1.

## Verhalten

### 1. Neue Befundfelder (Schema)

- `zusammenfassung`: Kundensprache.
  - Was ist das Risiko und was kann passieren, für Geschäftsführer verständlich, ohne Technikdetails.
  - Einzeilig, 40 bis 600 Zeichen.
- `massnahme`: Kundensprache, was zu tun ist. Einzeilig, 20 bis 400 Zeichen.
- Beide Felder sind im Schema **optional**, damit ältere JSONs und `fix-findings` unverändert bleiben. `kundenbericht.py` verlangt sie für jeden Befund, der im Kundenbericht erscheint (Status `bestätigt` oder `unbestätigt`). Fehlt eines, endet das Skript mit Exit 2 und nennt die Befund-ID und das Feld.
- Die Hauptsession schreibt beide Felder in Schritt 7 für jeden Befund mit Status `bestätigt` oder `unbestätigt`, auch für Werkzeugbefunde aus TF2 und KI-Befunde aus TF3.

### 2. Skript `scripts/kundenbericht.py`

`python3 -I ${CLAUDE_SKILL_DIR}/scripts/kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json`

Nur Standardbibliothek. Kindprozesse (`pandoc`, `weasyprint`) laufen über eigenes `Popen(start_new_session=True)` mit Timeout; bei Ablauf wird nur die eigene Gruppe beendet. Dafür gibt es einen gemeinsamen Helfer, z. B. `gitkopie.werkzeug_ausfuehren`. Budget: 120 s gesamt.

1. **Eingabe:**
   - JSON lesen (höchstens 2 MiB) und mit `bericht.pruefe_schema` prüfen. Bei Fehlern Exit 2 mit Fehlerliste.
   - Der Pfad muss eine reguläre Datei sein, kein Symlink.
2. **Auswahl:** Befunde mit Status `bestätigt` oder `unbestätigt`. `verworfen` und `verdacht` erscheinen nicht.
3. **Kundenstufe:**

   | Interne Stufe | Bedingung | Kundenstufe |
   |---|---|---|
   | P1 | `ohne_anmeldung` oder `mandantenuebergreifend` | Kritisch |
   | P1 | sonst | Hoch |
   | P2 | – | Mittel |
   | P3 | – | Niedrig |

4. **Inhalt** (Markdown, Reihenfolge fest):
   - **Kopf:** `# Manibase · Sicherheitsprüfung <Projekt>`. Darunter Datum (`datum` aus dem JSON, als `TT.MM.JJJJ`), geprüfter Commit (`sha` 7-stellig) und, falls gesetzt, der Teilpfad.
     - `<Projekt>` ist `projekt` aus dem JSON. Fehlt es, steht dort `repo`, und darunter der Satz: „Hinweis: Es wurde kein Projektname angegeben; verwendet wird der Name des Repository-Ordners.“
   - **Management-Zusammenfassung:** feste Textbausteine, nicht vom Modell.
     - Anzahl je Kundenstufe als Tabelle.
     - Ein Satz je Lage, z. B. „Es bestehen <n> kritische Schwachstellen, die ohne Anmeldung oder über Mandantengrenzen ausnutzbar sind. Wir empfehlen, diese vor dem nächsten Release zu beheben.“
     - Ohne Befunde: „In der geprüften Version wurden keine ausnutzbaren Schwachstellen gefunden.“ Dazu der Grenzen-Satz.
   - **Befunde,** nach Kundenstufe, dann ID sortiert. Je Befund:
     - `### <ID> · <Kundenstufe> · <titel>`
     - **Risiko:** `zusammenfassung`
     - **Maßnahme:** `massnahme`
     - **Betroffene Datei:** `datei` (ohne Zeile)
     - **Nachweis:** „im Test nachgestellt“ (`bestätigt` ohne `annahme_modell`), „im Test nachgestellt unter der Annahme, dass das KI-Modell einer eingeschleusten Anweisung folgt“ (`annahme_modell: true`) oder „aus dem Quellcode abgeleitet“ (`unbestätigt`)
   - **Umfang und Grenzen** (fester Text):
     - Geprüft wurde der genannte Commit.
     - Methode: Code-Analyse durch KI-Agenten; Nachweise nur in einer isolierten Testumgebung ohne Zugriff auf Produktivsysteme.
     - Keine Garantie auf Vollständigkeit.
     - Der technische Bericht mit Details liegt Manibase vor.
   - **Fuß:** „Manibase · vertraulich“.
5. **Escaping:** Jeder Text aus dem JSON (`titel`, `zusammenfassung`, `massnahme`, `datei`, `projekt`, `repo`, `teilpfad`) wird escaped.
   - Markdown-Sonderzeichen werden mit Backslash entschärft, `<` und `>` als `&lt;` und `&gt;`.
   - Aus Daten können so keine Links, Bilder, HTML-Tags oder Überschriften entstehen.
6. **Prüfung des fertigen Markdowns** (vor dem Schreiben, in Kundendaten-Abschnitten):
   - **Du-Anrede:** Wortgrenzen-Regex, Groß- und Kleinschreibung egal: `du`, `dein*`, `dich`, `dir`, `euch`, `euer*`, `eure*`. Nicht geprüft werden die Werte von `datei` und `teilpfad` (Pfadangaben), also die Zeilen „Betroffene Datei“ und „Teilpfad“. Damit löst `datei: src/dir/x.ts` nichts aus. „Ihr“ ist nicht in der Liste (Höflichkeitsform).
   - **Exploit-Spuren:**
     - Muster `<pfad-artig>:<zahl>` (Regex `[\w./-]+\.\w+:\d+`) außerhalb der Kopfzeile.
     - Jeder `code_pfad`-Eintrag eines beliebigen Befunds als Teilstring.
     - Jede Zeile aus `poc` (getrimmt, ab 12 Zeichen) als Teilstring.
     - Der Abgleich läuft nach NFC und casefold.
   - Ein Treffer ergibt Exit 2. Gemeldet werden nur Befund-ID, Feld und Art des Treffers, **nie** der Treffertext (der kann Exploit-Details enthalten). Es werden keine Dateien geschrieben (TF4-D3/D4).
7. **Ablage:**
   - `<basisname>-kunde.md` neben dem JSON. Atomar schreiben (Temp-Datei, `os.replace`).
   - Ein bestehendes `-kunde.md` oder `-kunde.pdf` wird ersetzt.
   - Symlink als Ziel: Exit 2.
8. **PDF**, zweistufig statt `--pdf-engine=weasyprint`:
   1. `pandoc --sandbox -f markdown-raw_html-raw_attribute-raw_tex -t html5 --standalone --metadata title=… -H <eigenes CSS als <style>>`. Das ergibt HTML im eigenen Temp-Ordner.
   2. Das HTML wird geprüft: kein `src=`, kein `href=` außer `#…`, kein `<link`, kein `@import`, kein `url(` außer im eigenen CSS.
   3. `weasyprint <html> <pdf>` mit cwd im Temp-Ordner, Umgebung ohne Proxy-Variablen und Timeout 90 s.
   - Begründung für zwei Stufen: Erst so lässt sich vor dem PDF-Schritt prüfen, dass weasyprint keine externen oder lokalen Ressourcen lädt. `--sandbox` verbietet pandoc Datei- und Netzzugriffe.
   - Fehlt `pandoc` oder `weasyprint` (`shutil.which`, auch `SECURITY_AUDIT_OHNE=pandoc|weasyprint`), entsteht nur das Markdown, Exit 3, stdout `kategorie: pdf-werkzeug-fehlt` (TF4-D5).
   - Andere PDF-Fehler (Exit ≠ 0, Timeout, leere Datei) ergeben Exit 4 `kategorie: pdf-fehler`. Das Markdown bleibt bestehen.
   - Das PDF hat A4, Seitenzahlen und eine serifenlose Systemschrift. Es wird keine Schrift nachgeladen.
9. **Ausgabe stdout:** `kunde-md: <pfad>` und `kunde-pdf: <pfad>`. Erfolg ist Exit 0.

### 3. Skill

- **Grundregel 8:** `kundenbericht.py erstellen` ist ein einfacher Einzelbefehl mit Budget 120 s.
- **Schritt 7, nach `rendern`:**
  - Ruf `kundenbericht.py erstellen --json <pfad>` auf.
  - **Exit 2:** Felder `zusammenfassung`/`massnahme` korrigieren, und zwar nur diese Felder und nur in Kundensprache. Nach jeder Korrektur `rendern` erneut. Höchstens 2 Korrekturrunden; danach wird der Hinweis „Kundenbericht nicht erstellt (Prüfung)“ ausgegeben.
  - **Exit 3 oder 4:** Hinweis „Kundenbericht nur als Markdown (<kategorie>)“.
- **Schreibregeln für die zwei Felder:**
  - Sie-Form.
  - Keine Dateipfade mit Zeile, keine Requests, Payloads, Code oder Bezeichner aus dem Code.
  - Risiko in Geschäftsfolgen ausdrücken: Datenabfluss, fremder Zugriff, Ausfall, Kosten.
  - Die Maßnahme konkret, ohne Code.
- **Schlussmeldung:** nennt die Pfade von `-kunde.md` und `-kunde.pdf`.
- `references/bericht-format.md`: neue Felder, Beispiel-JSON mit beiden Feldern, Abschnitt „Kundenbericht“ mit der Stufentabelle.

### 4. Eval

- `run_eval.py --projekt <name>` hängt `projekt="<name>"` an den Prompt an. Der Name ist auf `[A-Za-z0-9 ._-]{1,60}` begrenzt.
- `erlaubte_regeln` bekommt `Bash(python3 -I <skill>/scripts/kundenbericht.py *)`. pandoc und weasyprint ruft nur das Skript auf, das Modell nie.
- `expected/fixture-web.json` bekommt `kundenbericht: true`. Die Auswertung bekommt den Schlüssel **TF4-D6**:
  - Im Ausgabeordner liegen `*-kunde.md` und `*-kunde.pdf`.
  - Das PDF beginnt mit `%PDF`, das Markdown mit `# Manibase · Sicherheitsprüfung`.
  - Bei `--projekt` steht der Name im Kopf.
  - Kein `code_pfad`-Eintrag und kein `datei:zahl` im Markdown.
- `fixture-web` hat damit TF1-D1 bis D7, TF3-D4 und TF4-D6. `test_auswerten_ok`, `bericht_ok.json` und die B2-Mengen werden nachgezogen, wie in TF3.
- Ein Lauf: `run_eval.py --fixture fixture-web --projekt Testportal` (TF4-D6, liefert das PDF für TF4-D7). Die Ausgabe bleibt mit `--behalten` erhalten, damit Nikolaus das PDF lesen kann.

### 5. Tests

- **`test_kundenbericht.py`:**
  - **Stufen:** P1 mit oder ohne Anmeldung, mandantenübergreifend, P2, P3.
  - **Filter:** `verworfen` und `verdacht` fehlen.
  - **Kopf:** mit und ohne `projekt` (Hinweis), Datum, SHA.
  - **Exit 2:** bei `poc`-Zeile, `code_pfad`, `datei:zahl`, Du-Formen. `datei: src/dir/x.ts` ist erlaubt. Die Meldung enthält nie den Treffertext.
  - **Escaping:** Link, Bild, HTML und Überschrift im `titel` bleiben Text.
  - **Fehlende Felder:** führen zu Exit 2.
  - **Werkzeuge:** fehlen pandoc oder weasyprint, gibt es Exit 3 und das Markdown liegt vor (mit `PATH`-Shim). Ein Werkzeugfehler ergibt Exit 4.
  - **HTML-Prüfung:** greift bei `src=` und `href=` (Attrappe).
  - **Weiteres:** atomares Schreiben, Symlink-Ziel ergibt Exit 2, Budget.
  - **Opt-in** `SECURITY_AUDIT_PDF=1`: echtes pandoc und weasyprint; das PDF beginnt mit `%PDF`, und die Seitenzahl ist mindestens 1.
- **`test_bericht.py`:** Schema für `zusammenfassung` und `massnahme` (Typ, einzeilig, Länge).
- **`test_auswertung.py`:** TF4-D6 grün und rot (fehlendes PDF, Projektname fehlt, `code_pfad` im Markdown) sowie die Schlüsselmengen.
- **`test_skill_text.py`:** Satz-Tests für Schritt 7, Grundregel 8, Schreibregeln und Schlussmeldung; `SKRIPTE` enthält `kundenbericht`.

## Abnahmekriterien

| DoD | Nachweis |
|---|---|
| TF4-D1 | `test_kundenbericht.py` (Kopf mit und ohne `projekt`) |
| TF4-D2 | `test_kundenbericht.py` (Stufen, Filter) |
| TF4-D3 | `test_kundenbericht.py` (Exit 2, keine Datei geschrieben) |
| TF4-D4 | `test_kundenbericht.py` (Du-Formen, Pfadausnahme) |
| TF4-D5 | `test_kundenbericht.py` (Exit 3, Markdown liegt vor) |
| TF4-D6 | Eval `fixture-web --projekt Testportal`, Auswertung TF4-D6 |
| TF4-D7 | Durchklick: Nikolaus liest das PDF aus dem Eval |
| TF4-D8 | Durchklick: README-Zeile |

## Entscheidungen/Annahmen

1. **Zweistufiges PDF** (pandoc → HTML → Prüfung → weasyprint) statt `--pdf-engine=weasyprint` (Default im Feature-File). Grund: Nur so lässt sich vor dem Rendern sicherstellen, dass keine Ressource nachgeladen wird; das Ergebnis ist dasselbe. weasyprint selbst bietet in der CLI keine Sperre für den Abruf von Ressourcen.
2. **Management-Zusammenfassung aus Textbausteinen**, nicht vom Modell. Grund: Ein kundenseitiger Text ohne Prüfung durch Menschen soll so wenig freien Modelltext wie möglich enthalten. Die zwei freien Felder je Befund werden geprüft.
3. **Neue Felder optional im Schema**, Pflicht nur im Kundenbericht. So bleiben `fix-findings` und alte Berichte gültig.
4. **Du-Prüfung erweitert** um `dir`, `euch`, `euer*` und `eure*` (über das DoD hinaus, das `du`, `dein` und `dich` nennt). „Ihr“ bleibt erlaubt, weil es die Höflichkeitsform ist.
5. **Kein Logo, keine Fremdschrift**, Systemschrift wie entschieden.
6. **Keine echten Kundendaten in Tests**: Beispiel-JSONs werden synthetisch erzeugt.

## Sicherheitsregeln

- Vorfall 2026-11-10: Signale gehen nur an selbst gestartete Gruppen; keine Mutationsproben an Signal-, Kill- oder Lösch-Logik.
- pandoc und weasyprint laden nie Netzressourcen und keine Dateien außerhalb des eigenen Temp-Ordners (Sandbox und HTML-Prüfung).
- Öffentliches Repo: keine Kundendaten in Tests oder Beispielen.

## Nachträge nach Spec-Review R1 (Vorrang vor dem Text oben)

**B1 Du-Prüfung**
- Geprüft wird nur auf `zusammenfassung` und `massnahme`, wie im DoD. `titel`, `projekt` und `repo` bleiben ungeprüft, weil das Modell sie im Korrekturschritt nicht ändern darf.
- Die Formen stehen als feste Liste fest: `du`, `dich`, `dir`, `dein`, `deine`, `deinen`, `deinem`, `deiner`, `deines`, `euch`, `euer`, `eure`, `euren`, `eurem`, `eurer`, `eures`.
- Grenzen: `(?<![\w./@-])` vorn und `(?![\w./@-])` hinten, ohne Beachtung der Groß- und Kleinschreibung. „deinstallieren“, „Eureka“ und `dir-glob` lösen damit nichts aus.
- Die Meldung nennt Befund-ID, Feld und das gefundene Wort, kein Kontext.
- **W12:** Imperative in Du-Form („Aktualisiere …“) sind statisch nicht erkennbar. Abhilfe schafft eine Schreibregel mit festem Satzmuster („Aktualisieren Sie …“ bzw. „Wir empfehlen, …“). Das Beispiel-JSON in `bericht-format.md` zeigt das Muster.

**W1 weasyprint**
- Aufruf mit `--allowed-protocols ''`, damit keine Protokolle erlaubt sind; das eigene CSS ist inline.
- Enthält stderr `disallowed protocol`, `Failed to load` oder `Error`, gilt das als Exit 4 `pdf-fehler`, auch wenn weasyprint mit rc 0 endet.
- Mindestversionen: weasyprint mit `--allowed-protocols` (Prüfung per `weasyprint --help`; fehlt die Option, Exit 4) und pandoc ≥ 2.15 für `--sandbox`. Beide stehen in SKILL.md und README.
- Entscheidung 1 bleibt bei zwei Stufen, mit neuer Begründung: Die HTML-Prüfung ist eine zweite Schicht, `--allowed-protocols` die erste.

**W2 HTML-Prüfung**
- Statt einer Teilstring-Suche parst `html.parser` das HTML.
- Erlaubte Tags: `html head meta title style body header main section footer h1 h2 h3 p ul li table thead tbody tr th td strong em code br hr div span`.
- Attribute sind nur `class` und `id` sowie bei `meta` die Attribute `charset`, `name` und `content`.
- Alles andere ergibt Exit 4 `pdf-fehler` mit Tag- bzw. Attributnamen, ohne Wert. Escapter Text (`&lt;img …&gt;`) ist kein Tag und deshalb erlaubt.

**W3 Budget:** 90 s gesamt, verkürzbar über `SECURITY_AUDIT_KUNDE_BUDGET` (nur verkürzend). Davon höchstens 60 s für weasyprint.

**W4/W5 Exploit-Spuren** (nur in `zusammenfassung` und `massnahme`)
- Verboten sind:
  - (a) jedes Token aus `poc` (Trenner Whitespace, Länge ≥ 8, ohne Allerweltswörter wie `python3`, `poc.py`, `anfrage`, `--rolle`, `--lauf`, `--pfad`, `--methode`);
  - (b) Muster `\b(GET|POST|PUT|PATCH|DELETE)\s+/`;
  - (c) die Zeichen `{ } < > =` sowie Backticks;
  - (d) `\S+:\d+` (z. B. `Dockerfile:6`), `#L\d+` und `Zeile \d+`;
  - (e) jeder `code_pfad`-Eintrag und jeder `datei`-Pfad mit `/` als Teilstring, außer der eigenen `datei`-Zeile.
- Die Meldung nennt Befund-ID, Feld, Regel (a bis e) und bei (a) die Token-Nummer im `poc`, nie den Text.
- Falschpositiv-Tests: „Node 22“, „Port 3000“, „um 14:30 Uhr“ (erlaubt, weil `\S+:\d+` nur greift, wenn vor dem Doppelpunkt ein Punkt oder `/` steht) und „Version 4.17.21“.
- Für (d) gilt deshalb `[\w-]*[./][\w./-]*:\d+`, `#L\d+` und `\bZeile\s+\d+`.
- **W11:** Verboten sind außerdem `https?://`, `www.` und E-Mail-Muster in beiden Feldern und im Titel. Der Titel ist auf 120 Zeichen begrenzt; ist er länger, wird er gekürzt und mit „…“ beendet.

**W6 Nachweis-Texte je Herkunft**

| Herkunft | Text |
|---|---|
| `werkzeug: osv-scanner` | „aus der Abhängigkeitsliste mit bekannten Sicherheitslücken abgeglichen“ |
| `werkzeug: gitleaks` | „Zugangsschlüssel in der Versionsgeschichte gefunden (Wert nicht wiedergegeben)“ |
| `werkzeug: lieferkette` | „aus der Build- und Installationskonfiguration abgeleitet“ |
| sonst | wie oben (nachgestellt, Annahme, abgeleitet) |

**W7 Management-Zusammenfassung**
- Jede Stufe hat einen eigenen Baustein für Singular und Plural.
- „ausnutzbar“ erscheint nur bei `bestätigt`. Für `unbestätigt` heißt es „mögliche Schwachstelle“.
- Kritisch: „umgehend beheben“ (K13).
- Satz für den Fall ohne Befunde: Er erscheint nur, wenn `bericht.hinweise` keinen Hinweis auf eine eingeschränkte Prüfung trägt. Eingeschränkt heißt: `gitleaks fehlt`, `osv-scanner fehlt`, `docker-fehlt`, „Zeitbudget“, „nicht geschwärzt“ oder „ki.py erkennen fehlgeschlagen“.
- Bei eingeschränkter Prüfung steht stattdessen: „Die Prüfung war eingeschränkt (<Liste in Kundensprache>); das Ergebnis ist deshalb nicht vollständig.“

**W8 Ablage**
- Vor jedem Lauf werden ein bestehendes `-kunde.md` und `-kunde.pdf` entfernt (nur diese zwei Pfade, nur reguläre Dateien, kein Symlink).
- Das PDF entsteht in einer Temp-Datei im Zielordner und wird per `os.replace` ersetzt.
- Bei Exit 2 gibt es keine Kundendateien. Bei Exit 3/4 gibt es nur das Markdown.

**W9 Eval-Verdrahtung**
- `run_eval` übergibt `auswerten` die Inhalte von `*-kunde.md`, den Anfang des PDFs (8 Bytes) und `projekt` als `kunde={…}`.
- `pruefe_ablage` schließt `-kunde.md` und `-kunde.pdf` aus der Zählung der technischen Berichte aus.
- Das Fake-claude in `test_auswertung.py` schreibt `-kunde.md` und `-kunde.pdf` (Minimal-PDF `%PDF-1.7`), damit die bestehenden Lauf-Tests grün bleiben.
- TF4-D6 gilt nur, wenn `kundenbericht: true` in der Erwartung steht.

**W10 Name ohne `projekt`:** Neues optionales Kopffeld `ordner` mit dem Basename der Repo-Wurzel aus `bericht.py kontext`. `kontext` gibt `wurzel` bereits aus; die Hauptsession schreibt `ordner` ins JSON. Rangfolge für den Kopf: `projekt`, dann `ordner` (Hinweis „Name des Repository-Ordners“), dann `repo` (Hinweis „Name des Repositorys“). So bleibt das Entschiedene erfüllt.

**Klein**
- **K1 Escaping:** Die Menge `` \ ` * _ { } [ ] < > ! $ ^ ~ @ & | # `` wird mit Backslash escaped, gilt für alle Datenfelder und wird je Konstrukt getestet: `{…}`-Attribute, Bild, Link, Span, ATX-Schluss ` #` und HTML.
- **K2 pandoc:**
  - Eigenes `--template` (`scripts/kundenbericht.html5`) mit `lang="de"` und eigenem CSS inline.
  - `pagetitle` statt `title`.
  - Eingangsformat: `markdown-smart-auto_identifiers-yaml_metadata_block-pandoc_title_block-citations-tex_math_dollars-implicit_figures-raw_html-raw_attribute-raw_tex-header_attributes-bracketed_spans-fenced_divs-link_attributes`.
  - Deutsche Anführungszeichen setzt der Text selbst.
- **K3 Seitenzahl:** Der Opt-in-Test entpackt die Flate-Streams mit `zlib` und sucht `/Type /Pages … /Count`.
- **K4 Größe:** `bericht.MAX_JSON_BYTES` übernehmen.
- **K5 Exit-Codes:**
  - Exit 2 nur bei Inhaltsfehlern, die per Feldkorrektur behebbar sind; die erste stdout-Zeile ist dann `kategorie: inhalt`.
  - Eingabe- und Schreibfehler (Symlink, Lesen, Schema-Fehler außerhalb der zwei Felder) ergeben Exit 5 `kategorie: eingabe`; das Modell korrigiert dann nicht.
- **K6:** Ist `datei` null, steht dort „gesamtes Projekt“.
- **K7:** Status vor dem Filter NFC-normalisieren; IDs numerisch sortieren.
- **K8:** Fehlende Werkzeuge über `poc.werkzeug_fehlt`. Kindprozesse über `gitkopie.werkzeug_ausfuehren`, mit eigener Umgebung ohne `*_PROXY`. Ist ein Werkzeug nicht startbar (`GitFehler`), gilt Exit 3.
- **K9:**
  - Grundregel 8: Bash-Liste um `kundenbericht.py` ergänzen.
  - Aufrufzeile wörtlich `… kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json`.
  - Eval-Regel `Bash(python3 -I {skill}/scripts/kundenbericht.py erstellen --json {ausgabe}/*)`.
  - `gesehen` um `kundenbericht` ergänzen.
  - README-Zeile und Dateiliste (TF4-D8).
- **K10:** `--projekt` passt auf `[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}`. Bei `--prompt-art text` hängt der Wert als „ mit projekt="…"“ an.
- **K11:** Die Sicherheitsregel heißt jetzt „keine aus Daten bestimmten URLs oder Dateien“. Systemschriften und Fontconfig sind erlaubt.
- **K13:**
  - Werkzeugtitel für Secrets lauten „Zugangsschlüssel in der Versionsgeschichte“; die Schreibregel gilt für `zusammenfassung`.
  - Die Schlussmeldung nennt die Kundendateien mit dem Satz „Vor Weitergabe lesen.“ und gegebenenfalls „Projektname fehlte“.
- **K14:** Der Hinweis nach 2 gescheiterten Runden steht in der Schlussmeldung, nicht in `bericht.hinweise`.
- **K15:** Die Schreibregel verbietet, `advisories[].zusammenfassung` (OSV-Text) zu übernehmen.
- **K16:** Die Prüfungen auf Du-Formen, Exploit-Spuren, URLs und Länge laufen zusätzlich in `bericht.pruefe_schema`, sobald die Felder vorhanden sind. So reicht eine Korrekturschleife über `rendern`, und `kundenbericht.py` prüft danach erneut. Der Prüfcode wird geteilt, `kundenbericht.py` importiert ihn aus `bericht.py`.

## Nachträge nach Spec-Review R2 (Vorrang vor allem oben)


**B-1** (Regel (a) trifft gewöhnliche deutsche Wörter aus dem `poc` (Z. 196, mit Z. 82–83))
(a) Ein Token aus `poc` (Trenner Whitespace; vorn und hinten werden `.,;:()"'` abgeschnitten) zählt nur, wenn es mindestens 6 Zeichen hat **und** eines der Zeichen `/ = ? & % < > { } _ @ $ \ [ ]` enthält oder eine Folge Wortzeichen-Punkt-Wortzeichen (`\w\.\w`). Reine Wörter aus Buchstaben und Bindestrichen zählen nie; eine Liste von Allerweltswörtern entfällt. Der Abgleich ist ein Teilstring-Abgleich nach NFC und casefold. Die Meldung nennt Befund-ID, Feld, Regel `a` und das Token selbst, gekürzt auf 60 Zeichen per `gitkopie._t`. Das Token stammt aus dem JSON der Hauptsession und ist ihr bereits bekannt. Die Regel „nie den Treffertext“ gilt weiter für die Regeln b bis e und für Text außerhalb des Tokens.
- Test: Der PoC aus `bericht-format.md:134` plus die zwei Kundensätze oben ergeben Exit 0. Steht `/api/orders/9` oder `org_id` in `massnahme`, ergibt das Exit 2.


**B-2** (K16 koppelt den technischen Bericht an die Kundenprüfung, ohne Ausweg (Z. 263))
K16 neu: `bericht.pruefe_schema` prüft `zusammenfassung` und `massnahme` nur auf Typ, Einzeiligkeit, unsichtbare Zeichen und Länge (40 bis 600 bzw. 20 bis 400). Die Inhaltsregeln (Du-Formen, a bis e, URLs/E-Mail) stehen in `bericht.kunden_verstoesse(daten) -> list[tuple[id, feld, regel, detail]]` und laufen nicht in `pruefe_schema`. `rendern` ruft `kunden_verstoesse` auf und gibt Treffer nur als Warnung auf stderr aus („Kundenbericht wird scheitern: …“), mit Exit 0. `kundenbericht.py` ruft zuerst `pruefe_schema` auf einer Kopie ohne die beiden Felder auf; Fehler dort ergeben Exit 5 `kategorie: eingabe`. Danach folgen die Typ- und Längenprüfung der Felder, fehlende Felder und `kunden_verstoesse`; Treffer ergeben Exit 2 `kategorie: inhalt`. Die Grenze von 2 Korrekturrunden gilt für Exit 2 von `kundenbericht.py`. `rendern` scheitert nie an Kundenregeln.


**W-1** (Die Erlaubtliste der HTML-Prüfung verwirft das eigene Template (Z. 188–189 gegen Z. 238))
W2 ergänzt: `lang` ist nur auf `html` erlaubt, nur mit dem Wert `de`. Es gibt genau ein `<style>`, sein Inhalt ist byte-gleich mit dem CSS des Templates. Tabellen gibt es nur in der Management-Zusammenfassung (Spalten Kundenstufe und Anzahl); Befunde stehen nie in Tabellen. pandoc läuft mit `--columns=1000`.


**W-2** (`titel`: B1 und W11 widersprechen sich, Skript und Eval prüfen Verschiedenes (Z. 174, 204, 122))
Für `titel` gelten im Kundenbericht die Regeln d, e und W11 (nicht a, b, c und nicht die Du-Prüfung). Ein Treffer im Titel ergibt Exit 2. Die Korrektur darf dann `titel` umformulieren, ohne `stufe`, `status`, `datei` oder andere Felder zu ändern, danach folgt wie bei den Feldern erneut `rendern`. Das Eval prüft TF4-D6 mit derselben Funktion `bericht.kunden_verstoesse` auf dem Bericht-JSON (keine Treffer) und am Markdown nur Kopf, Datei-Endungen und `%PDF`. Eine zweite Regex-Prüfung am Markdown gibt es nicht.


**W-3** (Was geprüft wird, ist offen: Rohwerte oder fertiges Markdown, ersetzt oder zusätzlich (Z. 77–84 gegen Z. 194–203))
Die Regeln a bis e, die Du-Prüfung und W11 ersetzen Z. 77–84 vollständig. Geprüft werden die Rohwerte aus dem JSON (nach NFC und casefold), vor dem Escaping, nie das erzeugte Markdown.


**W-4** (Regel (d) verfehlt `Dockerfile:6`, das eigene Beispiel (Z. 199 gegen Z. 203))
(d) zusätzlich: Für jeden `datei`-Wert und jeden Dateiteil eines `code_pfad`-Eintrags aller Befunde, jeweils auch für den Basename, ist `<pfad>` gefolgt von `\s*:\s*\d+` oder `,?\s*(Zeile|Z\.)\s*\d+` verboten (`re.escape`, casefold). Der Satz „z. B. `Dockerfile:6`“ in Z. 199 bezieht sich auf diese Regel.


**W-5** (Die Liste „eingeschränkt“ (W7) ist unvollständig und ohne Kundentext (Z. 219–220))
W7 ergänzt: Eine feste Tabelle im Skript bildet Teilstrings in `hinweise` auf Kundentexte ab:
- `gitleaks fehlt` → „Suche nach Zugangsschlüsseln“
- `osv-scanner fehlt` oder `abhaengigkeiten fehlgeschlagen` → „Abgleich der Abhängigkeiten“
- `lieferkette fehlgeschlagen` → „Prüfung der Build-Konfiguration“
- `docker-fehlt`, `build-fehler`, `build-timeout`, `start-fehler`, `lockfile-fehlt`, `lockfile-fremde-quelle`, `nicht-npm` → „Nachweis im Test“
- `Zeitbudget` → „vollständige Laufzeit einzelner Prüfungen“
- `ki.py erkennen fehlgeschlagen` oder `Modell-Mock nicht möglich` → „Prüfung der KI-Funktionen“

Ein gesetzter `teilpfad` ergibt „nur der Teilbereich <teilpfad>“. Der Satz „Die Prüfung war eingeschränkt (…)“ steht immer unter „Umfang und Grenzen“, sobald ein Eintrag zutrifft (jeder Text nur einmal). Ohne Befunde ersetzt er zusätzlich den Satz „keine ausnutzbaren Schwachstellen“.


**W-6** (Das E-Mail-Muster ist nicht festgelegt; Werkzeugtitel enthalten `@` (Z. 204))
W11: Das E-Mail-Muster ist `[\w.+-]+@[\w-]+(\.[\w-]+)*\.[A-Za-z]{2,}\b`; `name@1.2.3` und `@scope/pkg@1.0.0` treffen es nicht (Test). `www.` gilt nur mit Wortgrenze davor: `\bwww\.`.


**Klein (R2), alle angenommen:**
- **K-1 Budget (Z. 40, 101 gegen Z. 192):**
  > Gesamt 90 s, pandoc höchstens 20 s, weasyprint höchstens 60 s, jeder Timeout ist `min(Anteil, Restbudget)`. Grundregel 8 nennt `kundenbericht.py erstellen` unter „Kurze Budgets ohne langen Bash-Timeout“ mit 90 s. Z. 40 und Z. 101 gelten nicht mehr.
  - Hintergrund: `_gruppe_beenden` kann nach einem Timeout bis zu 25 s brauchen (`gitkopie.py:105–122`). Mit 90 s bleibt das unter dem Bash-Standard von 120 s.
- **K-2 Exit-Codes in einer Tabelle:**
  > 0: Markdown und PDF erstellt. 2 `inhalt`: Feldkorrektur möglich. 3 `pdf-werkzeug-fehlt`: Werkzeug fehlt oder ist nicht startbar. 4 `pdf-fehler`: dazu gehören auch eine unbekannte Option, die HTML-Prüfung, ein Treffer in stderr und eine leere Datei. 5 `eingabe`: Lesen, Symlink, Schema außerhalb der zwei Felder, Schreiben. 1: unerwarteter Fehler. Die erste stdout-Zeile ist bei Exit ≠ 0 `kategorie: <wert>`. Bei 3 und 4 folgt `kunde-md: <pfad>`. Meldungen stehen auf stdout, höchstens 30 Zeilen. Schritt 7: Bei Exit 5 und 1 gibt es keine Korrektur, die Schlussmeldung sagt „Kundenbericht nicht erstellt (<kategorie>)“.
- **K-3 weasyprint (Z. 182–183):**
  > Der stderr-Abgleich ignoriert Groß- und Kleinschreibung (weasyprint schreibt `ERROR: Failed to load …`). Die Vorprüfung per `weasyprint --help` entfällt: Eine unbekannte `--allowed-protocols` endet mit rc ≠ 0 und damit mit Exit 4.
  - Per Probe belegt: `--allowed-protocols ''` ergibt die Menge `{''}` (`weasyprint/__main__.py:200–202`), damit ist jedes Protokoll gesperrt, auch `file:` und `data:`. Die Eingabedatei wird trotzdem gelesen, rc ist 0.
- **K-4 `ordner` (Z. 233):**
  > `bericht.py kontext` gibt `ordner` (Basename von `wurzel`, bereinigt wie `repo`) selbst aus. Die Notiz in Schritt 1 nennt `ordner`. `pruefe_schema` prüft `ordner`, falls vorhanden, als einzeiligen Text. Das Escaping nach K1 gilt auch für `ordner`.
  - Grund: So muss das Modell den Basename nicht selbst bilden, und der Text im Kopf ist geprüft. Bisher würden unbekannte Felder ignoriert (`bericht-format.md:58`).
- **K-5 Namenskollision `-kunde`:**
  > Gibt es `<basisname>-kunde.json`, endet `kundenbericht.py` mit Exit 5 und entfernt nichts.
  - Grund: Ein Audit mit `teilpfad` `kunde` erhält den Basename `<datum>-<sha7>-kunde` (`bericht.py:130–131`, `:171`). Sein technisches `.md` heißt dann wie der Kundenbericht des Gesamt-Audits vom selben Tag, und W8 würde es löschen.
- **K-6 Reihenfolge in W8 (Z. 223):**
  > Das Entfernen von `-kunde.md` und `-kunde.pdf` geschieht direkt nach der Pfadprüfung des JSON und vor dem Lesen. Ist einer der beiden Pfade ein Symlink oder keine reguläre Datei, endet das Skript mit Exit 5, ohne etwas zu entfernen.
- **K-7 Escaping (Z. 75 gegen Z. 236):**
  > `<` und `>` werden wie alle Zeichen der K1-Menge mit Backslash escaped, nicht als `&lt;`/`&gt;`, sonst entsteht ein doppeltes Escaping.
- **K-8 Abweichung vom Default festhalten:**
  > Entscheidung 7: Die Feature-File-Vorgabe „prüft danach das ganze erzeugte Markdown“ gilt eingeschränkt: Geprüft werden die Rohwerte von `zusammenfassung`, `massnahme` und (nach W-2) `titel`. Die festen Texte sichert ein Test.
- **K-9 K13 und der Secret-Titel (Z. 259 gegen `SKILL.md:130`, `test_skill_text.py:611`):**
  > Der Kundenbericht zeigt für Befunde mit `werkzeug: gitleaks` statt `titel` den festen Titel „Zugangsschlüssel in der Versionsgeschichte“. Schritt 5b und der technische Titel bleiben unverändert.
- **K-10 Testdesign zu D4 und Regel e:**
  > Der Test für TF4-D4 nutzt `datei: src/dir/x.ts` bei einem Befund und schreibt diesen Pfad nicht in `massnahme` (das wäre ein Treffer der Regel e). Zusätzlich gibt es einen Test, in dem „dir“ als eigenes Wort in `massnahme` Exit 2 ergibt.

**Entscheidung R2-B2:** K16 aus R1 entfällt; es gilt B-2 (Inhaltsregeln nur in `bericht.kunden_verstoesse`, `rendern` warnt, `kundenbericht.py` entscheidet). **Entscheidung K-8:** Geprüft werden die Rohwerte der Kundenfelder und des Titels (W-2/W-3), nicht das ganze Markdown — Abweichung vom Default „ganzes Markdown“, weil Escapes den Abgleich verfälschen und feste Bausteine keine Kundendaten enthalten.


## Nachträge nach PR-Review Runde 1 (Vorrang vor allem oben)

- **R1-1 Regel b:** Neben „HTTP-Methode vor einem Pfad“ (auch `POST-/api`) gilt jeder Pfad mit führendem Schrägstrich (`/segment…`) als Regel b, unabhängig vom `poc`. `und/oder`, `24/7`, `TCP/IP`, `Lese-/Schreibrechte` und ` / ` bleiben erlaubt. Der feste Detailtext lautet „Request oder Pfad mit Schrägstrich“. Kopfangaben prüfen weiter nur den Request. Bezeichner (camelCase, snake_case) prüft das Skript nur, wenn sie als Token im `poc` stehen (Regel a); sonst gilt allein die Schreibregel.
- **R1-2:** Die Titel der Lieferkette-Entwürfe nennen keinen Pfad („Lockfile fehlt“, „Installation ohne Lockfile-Treue“, „Install-Skripte nicht abgeschaltet“); der Pfad steht unter „Betroffene Datei“.
- **R1-3:** Kopfangaben werden vollständig geprüft (keine Kappung bei 5000 Zeichen); Befundfelder bleiben gekappt.
- **R1-4:** Nach dem Sperren muss der Pfad noch auf die gesperrte Inode zeigen (sonst Exit 5), und die JSON wird über den gesperrten Deskriptor gelesen. Ein Ersetzen der JSON während eines Laufs fängt erst die zweite Prüfung vor dem Schreiben des Markdown ab.
- **R1-6:** Eine Eingabe mit dem Dateinamen `.json` (in beliebigem Ordner) ist Exit 5.
- **R1-7:** `--help` endet mit Exit 0, schreibt keine Dateien und nennt weder `kunde-md:` noch `kunde-pdf:`.
- **R1-8 (nach R2-K-4):** `ordner` ist der Ordnername der Hauptkopie des Repos (im git-Worktree der Hauptordner), nicht der Basename von `wurzel`.

## Nachträge nach PR-Review Runde 2 (Vorrang vor allem oben)

- **R2-2 Regel b:** Lookbehind ohne `:` (also `Endpunkt:/api` und `C:/Users` zählen, `://` bleibt frei, weil nach dem ersten `/` kein Pfadzeichen folgt); `//pfad` zählt (nicht `://`); Schrägstrich auch als U+2215, U+2044, U+29F8; Pfadzeichen nach dem Strich: Wortzeichen und `. ~ % @ -`. Bekannte Fehlalarme (fail-closed): „500 €/Monat“, „01.01./31.12.“, „5 %/Jahr“, „bzw./oder“, „ca./etwa“, „Benutzer(innen)/Admin“; die Schreibregeln in SKILL.md Schritt 7 nennen sie. **Bekannte Grenzen:** `Endpunkt-/api` (ließe sich nicht ohne „Lese-/Schreibrechte“ lösen) und `file:///etc/hosts` (der Pfad folgt auf `//`) werden nicht erkannt.
- **R2-3:** Der feste Detailtext von Regel b lautet „Request oder Pfad mit führendem Schrägstrich“.
- **R2-4:** Zusätzlich zur Sperre auf die JSON sperrt jeder Lauf den Ausgabeordner (flock auf einen O_RDONLY-Deskriptor des Ordners, keine Sperrdatei). Er wartet höchstens 30 s darauf (`_ORDNER_WARTEN`), danach Exit 5. Läufe im selben Ordner (ein Ordner gehört einem Repo) laufen also nacheinander. Wird die JSON per rename ersetzt, sperrt ein anderer Lauf zwar eine neue Inode, wartet aber auf den Ordner und entfernt keine Kundendateien eines laufenden Laufs. `flock` auf einem Ordner setzt ein Dateisystem mit `flock` voraus (wie bisher auf der JSON; sonst Exit 5).
- **R2-5:** Kopfangaben sind im Schema begrenzt: `projekt` 200, `repo` und `ordner` 100 (wie `kontext`), `teilpfad` 4096 Zeichen; sonst Schemafehler (Exit 5). Dadurch bleibt die vollständige Prüfung der Kopfangaben (R1-3) begrenzt.
