# Spec TF4: Kundenbericht (Markdown und PDF)

Stand: Entwurf vor Spec-Review R1. Feature-File `docs/features/2026-11-09-security-audit.md`, Abschnitt TF4 (DoD TF4-D1 bis TF4-D8). Branch `skills/audit-kundenbericht`, gestapelt auf `skills/audit-ki` (TF3, PR #13).

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
