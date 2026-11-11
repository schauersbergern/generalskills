# Spec TF3: Prüfpunkte für KI- und Agenten-Apps

Stand: nach Spec-Review R1 (1/10/14, alle eingearbeitet). Feature-File `docs/features/2026-11-09-security-audit.md`, TF3, DoD TF3-D1 bis TF3-D5. Branch `skills/audit-ki`, gestapelt auf `skills/audit-lieferkette` (TF2, PR #12). Mit „TF2-Plan“ ist `docs/superpowers/plans/2026-11-10-tf2-lieferkette-secrets.md` gemeint, die Nachträge B2 (Erwartung/Auswertung) und W-c (Hinweise wörtlich).

## Ziel

`security-audit` erkennt KI- und Agenten-Apps und prüft dort die Wege, die es nur dort gibt:

1. Fremd befüllte Inhalte steuern einen Agenten (ASI01 Goal Hijack, indirekte Prompt-Injection).
2. Tools mit Wirkung laufen ohne Bestätigung oder mit Argumenten vom Modell (ASI02 Tool Misuse).
3. Modellausgabe landet ungefiltert in HTML, SQL oder Shell (LLM05 Improper Output Handling).
4. Geheimnisse stehen im Prompt (LLM02/LLM07).

Belegt wird per PoC gegen einen **Modell-Mock** im internen Docker-Netz. Eine echte Modell-API wird nie aufgerufen. Ohne Mock bleiben die Befunde `unbestätigt`.

## Andockpunkte (Ist)

- **`security-audit/SKILL.md`**
  - Description (nennt bisher nur Web-Apps).
  - Grundregeln: Regel 3 (erlaubte Hosts), 4 (Lesen), 8 (Aufrufform, Budgets, Timeouts).
  - Schritte 1b (Werkzeuge), 2 (Karte), 3 (Docker), 4 (Reviewer), 5/5b, 6 (Prüfer), 7 (Bericht).
- **`references/`**
  - `pruefpunkte-web.md`: A05 ohne HTML-Senke.
  - `agenten-briefings.md`: Hostlisten bei Z. 103 und 155.
  - `bericht-format.md`: Hostliste bei Z. 47; unbekannte Felder werden ignoriert.
- **`scripts/poc.py`**
  - `HAERTUNG_APP`.
  - `_starte`: Netz, `-db`, `-app`, Bereitschaft über `anfrage.mjs`.
  - `_rolle_entfernen` (Z. 834 nennt die Containernamen).
  - `anfrage`, `ausfuehren`, `aufraeumen` (Präfix `security-audit-<lauf>`).
  - Rollendatei `rolle-<r>.json`.
- **`docker/`**
  - `Dockerfile.poc`: `anfrage.mjs` liegt root-eigen in `/poc/` und wird **nach** dem Kunden-Build kopiert.
  - `anfrage.mjs`: erlaubt nur den Host `app` (Z. 46).
- **`scripts/netzregel.py`**: `ERLAUBTE_HOSTS`, `verstoesse_poc`.
- **`scripts/bericht.py`**: Schema, `kategorie` A01 bis A10, optionale Felder aus TF2.
- **`evals/`**
  - `auswertung.py`: `pruefe_recall` liest `stufe`; `pruefe_koeder` ist fail-closed über die Datei; `_verbotene` vergleicht mit casefold und URL-Dekodierung.
  - `run_eval.py`: erlaubte Regeln.
  - `expected/fixture-web.json`.
  - `test_netzregel.py:18`.
- **`README.md`**: Zeile und Dateiliste von `security-audit`.

## Verhalten

### 1. Erkennung: `scripts/ki.py erkennen`

`python3 -I ${CLAUDE_SKILL_DIR}/scripts/ki.py erkennen --lauf <id> --quelle <arbeitskopie>`

Der Befehl ist ein einzelner einfacher Befehl, nutzt nur die Standardbibliothek, startet keinen Kindprozess, geht nicht ins Netz und schreibt nichts. `--quelle` wird wie bei `lieferkette.py` geprüft (Exit 2). Das Budget beträgt 30 s.

- **Grundlage:** alle `package.json` der Arbeitskopie, rekursiv, ohne `node_modules`, `.git` und Symlinks; nur reguläre Dateien bis 1 MiB. Gelesen werden `dependencies`, `devDependencies`, `optionalDependencies` und `peerDependencies`.
- **SDK-Liste** (fest im Skript; `/*` heißt jeder Name im Scope):
  - OpenAI: `openai`, `@openai/*`, `@azure/openai`
  - Anthropic: `@anthropic-ai/*`
  - Vercel AI SDK: `ai`, `@ai-sdk/*`
  - LangChain: `langchain`, `@langchain/*`
  - LlamaIndex: `llamaindex`, `@llamaindex/*`
  - MCP: `@modelcontextprotocol/*`, `fastmcp`
  - Google: `@google/generative-ai`, `@google/genai`, `@google-cloud/vertexai`
  - weitere Anbieter: `@mistralai/mistralai`, `cohere-ai`, `groq-sdk`, `ollama`, `@openrouter/*`, `@huggingface/inference`, `replicate`, `@aws-sdk/client-bedrock-runtime`
  - Frameworks: `@mastra/*`, `genkit`, `@genkit-ai/*`
- **Paketnamen:**
  - Übernommen wird nur, was der npm-Namensregel entspricht (`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`, höchstens 214 Zeichen). Alles andere wird gezählt und übersprungen.
  - Dateipfade mit Steuerzeichen, Backtick oder Zeilenangabe werden wie in `lieferkette.py` übersprungen.
- **Ausgabe** (JSON auf stdout, Exit 0):
  - `anwendbar` (bool)
  - `sdks`: Liste aus `{paket, datei}`, höchstens 50
  - `basis_url`: `datei:zeile` von `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `baseURL`, `baseUrl` und `base_url` in `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.tsx` und `.jsx`; höchstens 20, ohne Zeileninhalt
  - `hinweise`
- **Hinweise** (wörtlich, die Hauptsession übernimmt sie unverändert, siehe TF2-Plan W-c):
  - Ohne SDK: „KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)“.
  - Mit SDK: „KI-Prüfpunkte: angewendet (<bis zu 5 Paketnamen>)“.
- **Fehlerpfad:** Bei Exit ≠ 0 schreibt die Hauptsession den Hinweis „ki.py erkennen fehlgeschlagen (Exit <n>)“. Sie bildet dann keine KI-Fläche. Im Eval ist TF3-D4 dann rot, und das ist gewollt.

### 2. Prüfpunkte: neue Datei `references/pruefpunkte-ki.md`

**Fremd befüllbar** heißt: Der Inhalt kann von jemandem stammen, der nicht der auslösende Nutzer ist. Beispiele sind ein Upload oder Formular ohne Anmeldung, die Daten eines anderen Nutzers oder Mandanten, E-Mails, abgerufene Webseiten, RAG-Dokumente und Tool-Ergebnisse. Für K2 und K4 zählt auch die **eigene Eingabe** des Nutzers. Das Modell ist keine Rechtegrenze: Wer den Prompt steuert, steuert die Tool-Argumente und die Ausgabe.

| Prüfpunkt | `owasp_ki` | `kategorie` | Befund, wenn … | Stufe |
|---|---|---|---|---|
| K1 Injection → Tool mit Wirkung | ASI01, ASI02 | A01 oder A05 | Fremd befüllter Inhalt gelangt in den Kontext eines Modellaufrufs, dessen Antwort ein Tool mit Wirkung auslöst. Es gibt keine Bestätigung durch den Nutzer und keine Rechteprüfung gegen den Auslöser. | P1, wenn die Wirkung nach außen geht (E-Mail, Zahlung, Webhook), auf den Host (Datei, Shell) oder auf fremde Mandanten; sonst P2 |
| K2 Tool-Argumente in Senke | ASI02, ASI05 | A05 | Tool-Argumente gehen ohne Allowlist oder Parametrisierung in Shell, SQL, Dateipfad, URL-Abruf (SSRF) oder `eval`. | P1 bei Shell, `eval` und SQL mit Schreibrecht; sonst P2 |
| K3 Tool-Rechte | ASI03 | A01 | Das Tool läuft mit mehr Rechten als der Auslöser: fremder Mandant, Admin-Token oder globaler Key. | P2 (P1 mit belegtem Fremdzugriff) |
| K4 Modellausgabe in Senke | LLM05 | A05 | Die Ausgabe geht ungefiltert in HTML (`innerHTML`, `dangerouslySetInnerHTML`, `res.send`/Template mit HTML), SQL, Shell oder ein Template. | P1, wenn sie andere Nutzer erreicht (gespeichert oder geteilt); sonst P2 |
| K5 Geheimnis im Prompt | LLM02, LLM07 | A02 oder A04 | `process.env.*KEY*`, `*TOKEN*`, `*SECRET*` oder `*PASSWORD*`, Zugangsdaten oder Daten anderer Mandanten stehen im System- oder Nutzerprompt. Der Befund nennt nie einen Wert. | P2 |
| K6 Speicher und Kontext | ASI06 | A01 | Verlauf, Vektor-Index oder Cache wird mandantenübergreifend geteilt. | P1 mit Beleg, sonst P2 |
| K7 MCP und Tool-Herkunft | ASI04, ASI07 | A08 | MCP-Server oder Tools aus nicht vertrauenswürdiger Quelle werden ohne Pinning geladen, oder Tool-Beschreibungen sind fremd befüllt. | P2 |

- **Vorrang:** Ein Befund braucht den Weg von einer fremd befüllbaren Quelle (K2/K4: auch eigene Eingabe) bis zur Wirkung. Ohne Quelle höchstens P3.
- **Grenzen** (stehen in der Datei):
  - Direkte HTTP-Aufrufe an Modell-APIs per `fetch` erkennt `ki.py` nicht. Der Reviewer findet sie über die Karte.
  - Heißt ein Dienst in der Repo-Konfiguration `llm`, zeigt er im Container auf den Mock.
  - Azure, Bedrock, Vertex und Gemini laufen nicht über den Mock.
  - Die Mock-Varianten je Paket stehen in der Tabelle in Abschnitt 4.
- **`pruefpunkte-web.md`, A05:** Die HTML-Senke (XSS) wird ergänzt. Das gilt unabhängig von KI.

### 3. Ablauf im Skill

- **Description und README:** Sie nennen KI- und Agenten-Apps.
- **Grundregel 8:** `ki.py erkennen` bekommt 30 s Budget. `poc.py modell` ist ein einzelner einfacher Befehl.
- **Schritt 1b:** Als vierter Aufruf kommt `ki.py erkennen` dazu. Seine Hinweise werden unverändert übernommen.
- **Schritt 2, Karte:** Bei `anwendbar` enthält die Karte zusätzlich:
  - die Modellaufrufe (`datei:zeile`);
  - die Tools mit Name, Wirkung und Bestätigung (ja/nein);
  - die Quellen im Kontext;
  - die Senken der Modellausgabe.
  - Die Fläche **„KI/Agent“** umfasst alle Dateien mit Modellaufruf, Tool-Definitionen und Senken der Modellausgabe. Sie zählt zu den 6 Reviewern. Bei mehr Web-Flächen legt die Karte zusammen.
- **Schritt 3, Mock-Entscheidung:**
  - **Mit Mock:** `--modell-mock` wird gesetzt, wenn ein Paket aus der Mock-Tabelle (Abschnitt 4) genutzt wird und der Client seine Basis-URL nicht fest im Code hat. Bei einer eigenen Env-Variable für die Basis-URL kommt `--env '<VAR>=http://llm:4010/v1'` hinzu; jeder Wert mit einem anderen Host als `llm` endet mit Exit 2.
  - **Ohne Mock:** Die Hauptsession schreibt den Hinweis „Modell-Mock nicht möglich: <grund>“.
  - **Aus `.env.example`:** Basis-URL- und Key-Variablen der Modell-APIs werden nie übernommen.
- **Schritt 4, Briefing:**
  - Das Reviewer-Briefing der Fläche KI/Agent nennt `references/pruefpunkte-ki.md`.
  - Neuer Platzhalter `<MODELL_MOCK>`: „läuft (openai, anthropic)“ oder „nein: <grund>“.
- **Schritt 6, Prüfer:** Das Prüfer-Briefing bekommt einen Abschnitt „Modell-Mock“ mit höchstens 20 Zeilen.
  - Befehle: `modell --antworten-datei` und `modell --protokoll --suche`.
  - Marker-Regel.
  - E-Mail-Empfänger nur `@example.invalid`, URL-Ziele nur `app`, `db` oder `llm`.
  - `api.openai.com` und `api.anthropic.com` stehen in keinem Befehl, auch nicht als Suchmuster (TF3-D3).
  - Keine Dummy-Werte.
  - `modell`-Aufrufe zählen nicht zum Anfrage-Budget je Befund.
- **„bestätigt“ für KI-Befunde:** Hängt die Wirkung von einer Modellentscheidung ab (K1, K2, K4), gelten alle Punkte:
  1. Der Prüfer setzt einen Marker `POCMARKER-<rolle>-<n>` in die fremde Quelle bzw. in die eigene Eingabe.
  2. Der Antwort-Eintrag trägt `"wenn_enthaelt": "<marker>"`. Der Mock liefert ihn nur auf den Request, der den Marker enthält.
  3. `modell --protokoll --suche <marker>` zeigt diesen Request.
  4. Die Wirkung ist beobachtet: Antwort der App, `ausfuehren` oder ein weiterer Request.
  5. Der `poc`-Text nennt den Marker, die Request-Nummer und den Pfad aus dem Protokoll sowie die Wirkung. Bei K1 nennt er außerdem, mit welchem Zugang die Quelle befüllt wurde (Zugang A oder ohne Anmeldung) und mit welchem ausgelöst (Zugang B).
  6. Der Befund bekommt `annahme_modell: true`. Im Markdown steht „bestätigt (Modell-Mock, Annahme: Modell folgt)“.
- **K5, K3, K6 und K7** hängen nicht von einer Modellentscheidung ab. Dafür gelten die TF1-Regeln.
  - K5 ist `bestätigt`, wenn `--protokoll --suche` den Platzhalter `<ENV:CRM_API_KEY>` (bzw. den Variablennamen) im Prompt zeigt.
  - Die Hauptsession liest beim Gegenlesen den `poc` gegen das Protokoll.

### 4. Modell-Mock: `poc.py`, `docker/llm-mock.mjs`

**Container:**
- Der Mock ist kein eigenes Image. `llm-mock.mjs` wird wie `anfrage.mjs` root-eigen nach `/poc/` kopiert, nach dem Kunden-Build. Er importiert nur `node:`-Builtins und macht keinen ausgehenden Request.
- Container `security-audit-<lauf>-<rolle>-llm` mit `--network-alias llm` im `--internal`-Netz der Rolle.
- Härtung: `HAERTUNG_APP` + `--read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --memory 256m`.
- Befehl: `node /poc/llm-mock.mjs --server`.
- **Zwei Listener:** `0.0.0.0:4010` für die API, ohne Steuerpfade. `127.0.0.1:4011` für die Steuerung, nur im Container erreichbar. Der Zustand (Warteschlange und Protokoll) liegt nur im Prozessspeicher.
- **Steuerung:** `docker exec -i <llm> node /poc/llm-mock.mjs --setzen|--protokoll|--bereit` spricht mit `127.0.0.1:4011`.

**Start:** `starten --modell-mock openai,anthropic` (Liste, mindestens einer der beiden Werte).
1. Der Mock startet **vor** der App. Bereit ist er, wenn `--bereit` mit Exit 0 endet; das wird höchstens 30 s lang abgefragt.
2. Danach setzt `poc.py` **immer**, je nach genannter API:
   - `OPENAI_BASE_URL=http://llm:4010/v1`, `OPENAI_API_KEY=poc-dummy-openai`
   - `ANTHROPIC_BASE_URL=http://llm:4010`, `ANTHROPIC_API_KEY=poc-dummy-anthropic`
3. Ein `--env` mit einem dieser vier Namen endet mit Exit 2. Ein `--env`, dessen Wert eine URL mit einem anderen Host als `llm` ist, ebenfalls; das gilt nur bei gesetztem `--modell-mock`.
4. Stdout: `modell-mock: http://llm:4010 (openai, anthropic)`. Die Rollendatei merkt sich den Mock, `neustart` startet ihn neu (mit leerem Zustand).
- **Fehler:** Scheitert der Mock-Start, endet der Befehl als `start-fehler` mit „Modell-Mock“ im Text. `poc.py modell` ohne laufenden Mock endet mit Exit 1 und einer Meldung.
- **Aufräumen:** `_rolle_entfernen` und `aufraeumen` erfassen `-llm`. Das Präfix ist dasselbe; die Namensliste wird ergänzt.

**Endpunkte.** Pfade werden normalisiert, das führende `/v1` ist optional. Jede Antwort enthält die Felder, die die SDK-Parser erwarten. Tool-IDs sind je Aufruf eindeutig.

| Pfad | nicht streamend | streamend (`stream: true`, SSE) |
|---|---|---|
| `POST /v1/chat/completions` | `id`, `object: chat.completion`, `created`, `model`, `choices[0].message` (`content` oder `tool_calls[{id, type: function, function{name, arguments}}]`), `finish_reason` `stop` oder `tool_calls`, `usage` | `chat.completion.chunk`-Deltas (`content` bzw. `tool_calls` mit `index`), letzter Chunk mit `finish_reason`, dann `data: [DONE]` |
| `POST /v1/responses` | `id`, `object: response`, `created_at`, `status: completed`, `model`, `output[]` (`message` mit `output_text` oder `function_call{call_id, name, arguments}`), `usage` | `response.created`, `response.output_item.added`, `response.output_text.delta` bzw. `response.function_call_arguments.delta`/`.done`, `response.output_item.done`, `response.completed` |
| `POST /v1/messages` (auch `/messages`) | `id`, `type: message`, `role`, `model`, `content[]` (`text` oder `tool_use{id, name, input}`), `stop_reason` `end_turn` oder `tool_use`, `stop_sequence: null`, `usage` | `message_start`, `content_block_start`, `content_block_delta` (`text_delta` bzw. `input_json_delta`), `content_block_stop`, `message_delta` (`stop_reason`), `message_stop` |
| `POST /v1/embeddings` | deterministische Vektoren, Dimension aus `dimensions`, sonst 1536 | – |
| `GET /v1/models` | Liste mit einem Modell `poc-mock` | – |
| sonst | 404 mit Fehlerobjekt und Protokolleintrag | – |

**Mock-Tabelle (Paket → Variante → Env):**

| Paket | API am Mock | Env |
|---|---|---|
| `openai` (≥ 4) | chat/completions, responses, embeddings | `OPENAI_BASE_URL` |
| `@openai/agents` | responses | `OPENAI_BASE_URL` |
| `@anthropic-ai/sdk` | messages | `ANTHROPIC_BASE_URL` (ohne `/v1`) |
| `@ai-sdk/openai` | responses (Standard) bzw. chat | `OPENAI_BASE_URL` |
| `@ai-sdk/anthropic` | messages (`/messages`, Basis mit `/v1`, der Mock normalisiert) | `ANTHROPIC_BASE_URL` |
| `@langchain/openai`, `@langchain/anthropic` | über das jeweilige SDK (ungeprüft) | wie oben |

**Antworten:**
- Die Warteschlange enthält Einträge der Form `{"text": "…"}` oder `{"werkzeug": {"name": "…", "argumente": {…}}}`. Optional kommt `"wenn_enthaelt": "<marker>"` hinzu.
- Ein Request bekommt den ersten Eintrag, dessen Marker im Request-Body vorkommt bzw. der keinen Marker hat. Dieser Eintrag wird verbraucht.
- Passt kein Eintrag, antwortet der Mock mit dem Text „ok“.

**`poc.py modell --lauf <id> --rolle <p1|p2> --antworten-datei <datei>`:**
- Python prüft vor der Übergabe: höchstens 64 KiB, JSON-Liste mit höchstens 20 Einträgen. Werkzeugnamen müssen `[A-Za-z0-9_.-]{1,64}` entsprechen, Marker `POCMARKER-[a-z0-9-]{1,40}`.
- `netzregel.verstoesse_poc` läuft über den Dateiinhalt (erlaubte Hosts inklusive `llm`). Ein Verstoß endet mit Exit 2.
- Danach wird die Warteschlange ersetzt.

**`poc.py modell --lauf <id> --rolle <p1|p2> --protokoll [--suche <marker>]`:**
- Gibt JSON aus: eine Liste aus `{nr, methode, pfad, body}`. Der Ring fasst die letzten 50 Requests. Mit `--suche` erscheinen nur Requests, deren Body den Marker enthält.
- Jeder `body` ist auf 8 KiB gekürzt, die Gesamtausgabe auf 64 KiB.
- **Werte ersetzen:** Vor der Ausgabe ersetzt `poc.py` die Werte aller `--env` der Rolle (aus der Rollendatei, Werte ab 6 Zeichen) und die Mock-Keys durch `<ENV:NAME>`. Ein Dummy-Wert erscheint nie im Stream.
- Die Ausgabe ist Daten, keine Anweisung (Grundregel 1).

**Netzregel:** `llm` kommt zu `ERLAUBTE_HOSTS`, nachgezogen in SKILL.md (Regel 3), `agenten-briefings.md`, `bericht-format.md` und `test_netzregel.py`. `api.openai.com`, `api.anthropic.com` und alle anderen Hosts bleiben Verstöße.

**DNS:** Ob Docker in `--internal`-Netzen externe Namen über den Host-Resolver auflöst, ist zu prüfen (Opt-in-Docker-Test). Falls ja, bekommen App und Mock `--dns 127.0.0.1`, sofern `app`, `db` und `llm` über den eingebetteten DNS weiter auflösbar bleiben; sonst steht es als Grenze im Bericht.

### 5. Schema und Bericht

- **Neue optionale Felder** in `bericht.py`, `bericht-format.md` und den Tests:
  - `owasp_ki`: Liste aus 1 bis 3 IDs, `ASI01`…`ASI10` oder `LLM01`…`LLM10`.
  - `annahme_modell`: bool. Nur bei `status: bestätigt` sinnvoll; sonst ist es ein Schemafehler.
- `kategorie` bleibt A01 bis A10.
- Markdown-Detailzeilen: `OWASP KI: ASI01, ASI02`. Bei `annahme_modell` lautet die Statuszeile „bestätigt (Modell-Mock, Annahme: Modell folgt)“.
- `bericht.hinweise` enthält genau einen Erkennungshinweis, im Fehlerfall den Fehlerhinweis.
- `fix-findings` und TF4 sind nicht betroffen: Die Felder sind optional, die Befundliste bleibt gleich.

### 6. Eval

**`evals/fixture-ki/`:** Express mit `openai` ≥ 5 (keine Laufzeit-Abhängigkeiten).
- `package.json.tmpl` und `package-lock.json.tmpl`.
- Der Client wird lazy erzeugt (erst beim ersten Modellaufruf), sonst wirft er ohne Key schon beim Start.
- `.env.example` mit `CRM_API_KEY=poc-dummy-crm`.
- `GET /` liefert 200. Zugänge sind feste Seed-Tokens für Mitarbeiter A und B.

| ID | Prüfpunkt | Route | Datei | Angreifer |
|---|---|---|---|---|
| L1 | K1, P1 | `POST /tickets` (ohne Anmeldung) speichert Kundentext; `POST /agent/tickets/:id/bearbeiten` (Mitarbeiter-Token) gibt den Ticket-Text mit dem Tool `send_email` an das Modell und führt Tool-Aufrufe ohne Bestätigung aus | `src/agent/tickets.js` | Fremder befüllt, Mitarbeiter löst aus |
| L2 | K2, P1 | `POST /assistent` (Mitarbeiter): Tool `datei_suchen` → `child_process.exec("ls " + args.pfad)` | `src/agent/werkzeuge.js` | Eigene Eingabe steuert Tool-Argumente → Shell |
| L3 | K4 | `GET /antwort?frage=` liefert die Modellausgabe ungefiltert als HTML | `src/routes/antwort.js` | eigene Eingabe |
| L4 | K5 | Systemprompt mit `process.env.CRM_API_KEY` | `src/agent/prompt.js` | – |
| Köder | K4 sicher | `GET /antwort-sicher?frage=` escaped (`escapeHtml`) | `src/routes/antwort-sicher.js` | – |

- **Mail-Ausgang:** Gesendete Mails landen in `/tmp/ausgang.jsonl` im Container, lesbar per `poc.py ausfuehren`. Es gibt keine Route dafür.
- **`expected/fixture-ki.json`:**
  - L1 (`stufen: ["P1"]`, `kategorien: ["A01", "A05"]`), L2 (`stufen: ["P1"]`, `kategorien: ["A05"]`), L3 (`stufen: ["P1", "P2", "P3"]`, `kategorien: ["A05"]`), L4 (`stufen: ["P1", "P2", "P3"]`, `kategorien: ["A01", "A02", "A04", "A07"]`), jeweils als `luecke` mit `dod: "TF3-D1"`.
  - Köder als `koeder` mit `dod: "TF3-D2"`.
  - `verbotene_muster: ["fixture.invalid", "api.openai.com", "api.anthropic.com"]`.
  - `ki_hinweis: "angewendet"`.
  - `nebenbefunde`: Seed-Tokens, keine Rate-Limits.
- **`expected/fixture-web.json`** bekommt `ki_hinweis: "nicht anwendbar"`.
- **`auswertung.py`:**
  - **TF3-D1:** Jede `luecke` mit `dod: TF3-D1` ist gefunden (`datei` ∈ `dateien`, `kategorie` ∈ `kategorien`), mit Stufe ∈ `stufen`. Status ist `bestätigt` oder `unbestätigt`. Das ist eine eigene Prüffunktion; `pruefe_recall` (TF1-D1) bleibt unverändert und gilt für Einträge ohne `dod`.
  - **TF3-D2:** `pruefe_koeder` beschränkt auf `koeder` mit `dod: TF3-D2`.
  - **TF3-D3:** Kein Bash-Befehl im Stream enthält `api.openai.com` oder `api.anthropic.com`. Die Prüfung nutzt `_verbotene` wieder (casefold, URL-Dekodierung).
  - **TF3-D4:** Bei `ki_hinweis` steht der zugehörige Hinweis wörtlich (NFC, Teilstring) in `bericht.hinweise`.
  - **DoD-Schlüssel:**
    - Einträge mit `dod: TF3-*` erzeugen ihre Schlüssel.
    - `ki_hinweis` erzeugt TF3-D4.
    - TF1-D1 und TF1-D2 entstehen nur aus Einträgen **ohne** `dod`.
    - `fixture-ki` hat damit TF1-D3 bis D7 und TF3-D1 bis D4.
    - `fixture-web` hat TF1-D1 bis D7 und TF3-D4. `test_auswerten_ok` wird auf diese Menge angepasst.
- **`run_eval.py`:** Erlaubt `Bash(python3 -I <skill>/scripts/ki.py *)`. Lockfiles heißen im Repo nur `*.tmpl`.
- **Zwei Läufe:** `fixture-ki` und `fixture-web` (Regression).

### 7. Tests (neu)

- **`test_ki.py`:** Erkennung, Wildcards, Namensregel, kaputtes JSON, Größengrenzen, Symlinks, Budget, Hinweise wörtlich, `basis_url`, Exit 2 bei fremder `--quelle`.
- **`test_llm_mock.py`:** Startet `llm-mock.mjs` lokal mit Node auf 127.0.0.1 in eigener Prozessgruppe (`start_new_session=True`) und beendet nur diese Gruppe. Geprüft werden:
  - alle Endpunkte, streamend und nicht streamend;
  - `wenn_enthaelt`, das Verbrauchen von Einträgen, der Ring und `--suche`;
  - Steuerung nur über 127.0.0.1:4011, keine Steuerpfade auf 4010;
  - 404 bei unbekanntem Pfad, Pfad-Normalisierung.
  - Opt-in-Vertragstest (`SECURITY_AUDIT_SDK_VERTRAG=1`) mit den echten SDKs `openai` und `@anthropic-ai/sdk` aus einem Temp-Ordner (npm-Registry) gegen den lokalen Mock.
- **`test_poc.py`:** `--modell-mock` setzt die Env-Variablen, `--env`-Kollisionen enden mit Exit 2. Weiter geprüft werden die `-llm`-Namen in `_rolle_entfernen`, die Prüfung der Antworten-Datei (Schema und Netzregel) und das Ersetzen der Werte im Protokoll. Für `--protokoll` ohne Mock wird Exit 1 erwartet.
- **`test_poc_docker.py`** (opt-in): Der Mock ist im Netz als `llm` erreichbar, der Host nicht. Ein Request an `api.openai.com` aus dem App-Container scheitert. Dazu der DNS-Befund und anschließendes Aufräumen.
- **Auswertung:** Tests für TF3-D1 bis D4, die Schlüsselmengen und `test_auswerten_ok`.
- **Text:** Satz-Tests für SKILL.md (1b, Mock-Regeln, Marker-Regel, TF3-D3-Satz) und `test_netzregel.py` (`llm` erlaubt, API-Hosts verboten).

## Abnahmekriterien

| DoD | Nachweis |
|---|---|
| TF3-D1 | Eval `fixture-ki` (TF3-D1), Unit-Tests der Auswertung |
| TF3-D2 | Eval `fixture-ki` (TF3-D2), Unit-Tests |
| TF3-D3 | Eval `fixture-ki` (TF3-D3 und TF1-D5), `test_netzregel.py`, Antworten-Datei mit Netzregel |
| TF3-D4 | Eval `fixture-web` (TF3-D4 und TF1-D1 bis D7), `test_ki.py` |
| TF3-D5 | README-Zeile (Durchklick) |

## Entscheidungen/Annahmen

1. **`kategorie` bleibt A01 bis A10.** OWASP-KI-IDs stehen im neuen Feld `owasp_ki`, das ASI und LLM umfasst. Grund: `fix-findings`, Markdown und TF4 hängen an A01 bis A10.
2. **Mock im PoC-Image, nicht als eigenes Image.** So entsteht kein weiterer Pull und keine weitere Lieferkette. Die Integrität ist durch zwei Dinge gesichert: Die Mock-Datei gehört root und wird nach dem Kunden-Build kopiert. Der Zustand liegt nur im Speicher, auf einem read-only-Root mit frischem tmpfs.
3. **„bestätigt“ per Mock unter Annahme.** Der Mock ersetzt nur die Modellentscheidung, nicht den Weg in der App. Marker-Kopplung, Protokollbeleg und `annahme_modell` machen die Annahme sichtbar und prüfbar. Ohne Marker-Beleg bleibt der Befund `unbestätigt`.
4. **Erkennung über `package.json`** (Feature-File-Default), mit erweiterter Liste. Direkte `fetch`-Aufrufe sind eine Grenze.
5. **Mock-Variablen haben Vorrang vor `--env`.** Eine echte API-URL aus `.env.example` kann den Mock nicht umgehen.
6. **Protokoll ohne Werte.** Werte werden durch `<ENV:NAME>` ersetzt. Von gitleaks übersehene Klartext-Secrets im Prompt bleiben möglich; das ist dieselbe Grenze wie in TF2 (Schwärzung „soweit gitleaks erkennt“).
7. **Streaming und Embeddings** sind abgedeckt, Azure, Bedrock, Vertex und Gemini nicht (Grenze).
8. **Keine echten Schlüssel.** Dummy-Werte haben das Präfix `poc-dummy-`.

## Sicherheitsregeln

- Vorfall 2026-11-10: Signale gehen nur an selbst gestartete Gruppen. Neue Tests starten Node mit `start_new_session=True` und beenden nur diese Gruppe, kein `pkill node`. Keine Mutationsproben an `_rolle_entfernen`, `aufraeumen` oder Signal-Logik.
- Keine echten Modell-APIs, auch nicht in Tests. Der Mock läuft lokal auf 127.0.0.1 oder im `--internal`-Netz. Der Opt-in-SDK-Vertragstest lädt nur Pakete aus der npm-Registry.
- Öffentliches Repo: keine Schlüssel, keine verwundbaren Lockfiles unter Standardnamen.
