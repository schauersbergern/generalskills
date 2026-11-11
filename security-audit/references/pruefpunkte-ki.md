# Prüfpunkte KI und Agenten (OWASP Agentic Top 10 und LLM Top 10, TF3)

Zusätzlich zu `pruefpunkte-web.md` für Apps mit LLM- oder Agenten-SDK (`ki.py erkennen` meldet `anwendbar: true`). Sie decken die Wege ab, die es nur dort gibt: fremde Inhalte steuern einen Agenten, Tools laufen mit Wirkung oder mit Argumenten vom Modell, Modellausgabe landet in einer Senke, Geheimnisse stehen im Prompt. Die Stufen P1 bis P3, die Gegenprüfung und die Belegstufen stehen in `pruefpunkte-web.md` und gelten hier weiter.

`kategorie` im Bericht bleibt `A01` bis `A10`. Die OWASP-KI-IDs aus der Spalte `owasp_ki` stehen im Feld `owasp_ki` des Befunds (1 bis 3 IDs, `ASI01` bis `ASI10` oder `LLM01` bis `LLM10`, ohne Doppelte). Die `kategorie` ist wie bei Web-Befunden die der **Wurzel**.

## Fremd befüllbar

**Fremd befüllbar** heißt: Der Inhalt kann von jemandem stammen, der nicht der auslösende Nutzer ist. Beispiele sind ein Upload oder Formular ohne Anmeldung, die Daten eines anderen Nutzers oder Mandanten, E-Mails, abgerufene Webseiten, RAG-Dokumente und Tool-Ergebnisse.

Für K2 und K4 zählt auch die **eigene Eingabe** des Nutzers als Quelle. **Das Modell ist keine Rechtegrenze:** Wer den Prompt steuert, steuert die Tool-Argumente und die Ausgabe.

## Prüfpunkte

| Prüfpunkt | `owasp_ki` | `kategorie` | Befund, wenn … | Stufe |
|---|---|---|---|---|
| K1 Injection → Tool mit Wirkung | ASI01, ASI02 | A01 oder A05 | Fremd befüllter Inhalt gelangt in den Kontext eines Modellaufrufs, dessen Antwort ein Tool mit Wirkung auslöst. Es gibt keine Bestätigung durch den Nutzer und keine Rechteprüfung gegen den Auslöser. | P1, wenn die Wirkung nach außen geht (E-Mail, Zahlung, Webhook), auf den Host (Datei, Shell) oder auf fremde Mandanten; sonst P2 |
| K2 Tool-Argumente in Senke | ASI02, ASI05 | A05 | Tool-Argumente gehen ohne Allowlist oder Parametrisierung in Shell, SQL, Dateipfad, URL-Abruf (SSRF) oder `eval`. | P1 bei Shell, `eval` und SQL mit Schreibrecht; sonst P2 |
| K3 Tool-Rechte | ASI03 | A01 | Das Tool läuft mit mehr Rechten als der Auslöser: fremder Mandant, Admin-Token oder globaler Key. | P2 (P1 mit belegtem Fremdzugriff) |
| K4 Modellausgabe in Senke | LLM05 | A05 | Die Ausgabe geht ungefiltert in HTML (`innerHTML`, `dangerouslySetInnerHTML`, `res.send` oder Template mit HTML), SQL, Shell oder ein Template. | P1, wenn sie andere Nutzer erreicht (gespeichert oder geteilt); sonst P2 |
| K5 Geheimnis im Prompt | LLM02, LLM07 | A02 oder A04 | `process.env.*KEY*`, `*TOKEN*`, `*SECRET*` oder `*PASSWORD*`, Zugangsdaten oder Daten anderer Mandanten stehen im System- oder Nutzerprompt. Der Befund nennt nie einen Wert. | P2 |
| K6 Speicher und Kontext | ASI06 | A01 | Verlauf, Vektor-Index oder Cache wird mandantenübergreifend geteilt. | P1 mit Beleg, sonst P2 |
| K7 MCP und Tool-Herkunft | ASI04, ASI07 | A08 | MCP-Server oder Tools aus nicht vertrauenswürdiger Quelle werden ohne Pinning geladen, oder Tool-Beschreibungen sind fremd befüllt. | P2 |

- **Vorrang:** Ein Befund braucht den Weg von einer fremd befüllbaren Quelle (bei K2 und K4 auch von der eigenen Eingabe) bis zur Wirkung. Ohne Quelle höchstens P3.
- **Gegenprüfung (zusätzlich zu `pruefpunkte-web.md`):** Suche eine Bestätigung durch den Nutzer vor dem Tool-Aufruf, eine Allowlist oder Parametrisierung der Argumente, eine Rechteprüfung gegen den Auslöser (nicht gegen das Modell) und Escaping vor der Senke. Findest du eine wirksame, ist es kein Befund.
- **Wo der Befund steht:** `datei:zeile` ist die Stelle des Fehlers (die Senke, das Tool oder die Stelle, an der das Geheimnis in den Prompt gelangt). Der `code_pfad` führt von der Quelle über den Modellaufruf bis zur Wirkung und nennt bei K5 auch die Stelle, an der der Prompt benutzt wird.
- **Nicht hier:** Allgemeine Web-Lücken in denselben Dateien (fehlende Anmeldung, IDOR, SQL-Injection ohne Modell) gehören zu `pruefpunkte-web.md`. Die HTML-Senke (XSS) steht dort bei A05, unabhängig von KI.

## Belege

- **K1, K2 und K4** hängen an einer Modellentscheidung. Sie sind `bestätigt` nur mit Marker-Beleg gegen den Modell-Mock (Briefing „Modell-Mock“ und Schritt 6 in `SKILL.md`): ein Marker `POCMARKER-<rolle>-<8 hex>` in der Quelle bzw. der eigenen Eingabe, ein Antwort-Eintrag mit `wenn_enthaelt`, der Request im Protokoll (`--suche`) und die beobachtete Wirkung. Die Hauptsession setzt dann `annahme_modell: true`; das Markdown nennt die Annahme („bestätigt (Modell-Mock, Annahme: Modell folgt)“). Ohne Mock oder ohne vollständigen Beleg bleibt der Befund `unbestätigt` mit eigenem `code_pfad`.
- **K3, K5, K6 und K7** hängen nicht an einer Modellentscheidung. Es gelten die Belegstufen von `pruefpunkte-web.md`. K5 ist `bestätigt`, wenn `--protokoll --suche <marker>` im Prompt den Platzhalter `<ENV:NAME>` (NAME ist der Variablenname) zeigt; das setzt voraus, dass die Variable beim Start als `--env` mit einem Dummy-Wert ab 6 Zeichen gesetzt war, sonst ersetzt der Mock nichts. K3, K6 und K7 belegt ein Request mit zwei Zugängen oder der Code-Pfad.
- **Marker:** `POCMARKER-<rolle>-<8 hex>`, je Befund neu, nie aus Repo-Inhalt oder Testdaten übernommen.
- **Der Mock ersetzt nur die Modellentscheidung,** nicht den Weg in der App: Ob eine echte Modellantwort dieselbe Tool-Wahl träfe, belegt er nicht. Das ist die Annahme in `annahme_modell`.

## Modell-Mock

`poc.py starten --modell-mock <apis>` startet vor der App einen Mock als Container `llm` im internen Netz der Rolle (Port 4010, nur dort erreichbar) und setzt Basis-URL und Dummy-Schlüssel der gewählten APIs. Eine echte Modell-API wird nie aufgerufen. Der Mock antwortet auf Chat Completions, Responses, Messages, Embeddings und Modellliste, streamend und nicht streamend, und liefert Text oder einen Tool-Aufruf, wie es die Antworten-Datei des Prüfers vorgibt.

Die Tabelle nennt als geprüft nur, was der Vertragstest gegen die echten SDKs grün hatte (Node 22.23.1; Text und Tool-Aufruf, streamend und nicht streamend, Basis-URL allein über die Umgebung). Jede andere Zeile ist ungeprüft, ebenso andere Versionen als die genannten.

| Paket | Weg am Mock | Env | Stand |
|---|---|---|---|
| `openai` (7.49.0) | chat/completions und responses; embeddings | `OPENAI_BASE_URL` | geprüft |
| `@anthropic-ai/sdk` (1.4.0) | messages | `ANTHROPIC_BASE_URL` (ohne `/v1`) | geprüft |
| `@ai-sdk/openai` (4.0.108, mit `ai` 7.0.162) | responses (Standard) und chat | `OPENAI_BASE_URL` | geprüft |
| `@ai-sdk/anthropic` (4.0.96, mit `ai` 7.0.162) | messages | `ANTHROPIC_BASE_URL` (ohne `/v1`) | geprüft |
| `@openai/agents` | responses | `OPENAI_BASE_URL` | ungeprüft |
| `@langchain/openai`, `@langchain/anthropic` | über das jeweilige SDK | wie oben | ungeprüft |

- Ungeprüft heißt: Der Mock kann funktionieren, ein Beleg fehlt. `--modell-mock` wird auch dort gesetzt (die Zeile steht in der Tabelle). Führt die App den Mock-Weg nicht aus, zeigt `--protokoll` keinen Request, und der Befund bleibt `unbestätigt`.
- Liest die App die Basis-URL aus einer eigenen Variable, setzt `SKILL.md` Schritt 3 sie auf `llm`.

## Grenzen

- **Direkte HTTP-Aufrufe** an Modell-APIs per `fetch` erkennt `ki.py` nicht: Ohne SDK in `package.json` meldet es „nicht anwendbar“. Der Reviewer findet sie über die Karte (Modellaufrufe), der Mock deckt sie nicht ab.
- **Dienst namens `llm`:** Heißt ein Dienst in der Repo-Konfiguration `llm`, zeigt er im Container auf den Mock.
- **Anbieter:** Azure, Bedrock, Vertex und Gemini laufen nicht über den Mock.
- **Maskierung im Protokoll:** Der Mock ersetzt Werte roh sowie einfach und doppelt JSON-escaped durch `<ENV:NAME>`. Nicht erfasst sind Werte, die dreifach escaped, URL-kodiert oder Base64-kodiert sind, und Teilstücke über Feldgrenzen. Ein solcher Wert kann im Protokoll stehen; niemand nennt ihn.
- **Node:** Die geprüften SDK-Majors verlangen Node ≥ 22. Node < 22 ist für sie ungeprüft.
- **Erkennung:** `ki.py` kennt nur die feste SDK-Liste und liest nur `package.json`; andere Sprachen, Python-Pakete und Eigenbauten erkennt es nicht.
