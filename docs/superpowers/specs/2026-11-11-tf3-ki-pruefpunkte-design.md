# Spec TF3: Prüfpunkte für KI- und Agenten-Apps

Stand: Entwurf vor Spec-Review R1. Feature-File: `docs/features/2026-11-09-security-audit.md`, TF3 (DoD TF3-D1 bis TF3-D5). Branch `skills/audit-ki`, gestapelt auf `skills/audit-lieferkette` (TF2, PR #12).

## Ziel

`security-audit` erkennt, ob ein Repo eine KI- oder Agenten-App ist. Ist das der Fall, prüft der Skill die Wege, die es nur dort gibt:

1. Fremd befüllbare Inhalte steuern einen Agenten (ASI01 Goal Hijack, indirekte Prompt-Injection).
2. Tools mit Wirkung laufen ohne Bestätigung oder mit Argumenten vom Modell (ASI02 Tool Misuse, Shell, E-Mail, Zahlung, Dateisystem).
3. Modellausgabe landet ungefiltert in HTML, SQL oder Shell (Improper Output Handling).
4. Schlüssel oder Geheimnisse stehen im Prompt (Sensitive Information Disclosure, System Prompt Leakage).

Belegt wird per PoC gegen einen **Modell-Mock** im internen Docker-Netz. Eine echte Modell-API wird nie aufgerufen. Ohne Mock-Möglichkeit bleiben die Befunde `unbestätigt`.

## Andockpunkte (Ist)

- `security-audit/SKILL.md`
  - Schritt 1 Kontext, 1b Werkzeuge, 2 Karte, 3 Docker, 4 Reviewer, 5/5b Dedup, 6 Prüfer, 7 Bericht.
  - Grundregeln 1 bis 9. Regel 3 erlaubt die Hosts `app`, `db`, `localhost` und Loopback.
- `security-audit/references/pruefpunkte-web.md` enthält die Web-Prüfpunkte A01 bis A10.
- `references/agenten-briefings.md` enthält das Reviewer- und das Prüfer-Briefing.
- `references/bericht-format.md` beschreibt das Schema.
- `security-audit/scripts/poc.py`
  - `starten` legt das Netz `security-audit-<lauf>-<rolle>` (`--internal`) an, dazu optional `-db` (Postgres) und `-app` mit `HAERTUNG_APP`.
  - `anfrage` läuft über einen Wegwerf-Container mit `/poc/anfrage.mjs`.
  - `ausfuehren` ist ein `docker exec` in `-app`.
  - `aufraeumen` entfernt alles mit dem Präfix `security-audit-<lauf>`.
- `security-audit/docker/Dockerfile.poc` kopiert `anfrage.mjs` aus dem zweiten Kontext `poc` nach `/poc/` (root-eigen).
- `security-audit/scripts/netzregel.py`: `ERLAUBTE_HOSTS = {"app", "db", "localhost", "127.0.0.1", "::1", "0.0.0.0"}`.
- `security-audit/scripts/bericht.py`
  - `kategorie` A01 bis A10 (OWASP Top 10 2025).
  - Optionale Felder, darunter `werkzeug`, `commits`, `pakete` und `klasse` (TF2).
- `security-audit/evals/`
  - `fixture-web` (Regression).
  - `auswertung.py` (DoD-Schlüssel je Erwartung, TF2-Muster).
  - `run_eval.py` (`--erwartung`, erlaubte Regeln).
  - `expected/*.json`.

## Verhalten

### 1. Erkennung (neues Skript `scripts/ki.py`, Unterbefehl `erkennen`)

`python3 -I ${CLAUDE_SKILL_DIR}/scripts/ki.py erkennen --lauf <id> --quelle <arbeitskopie>`

Ein einfacher Einzelbefehl, nur Standardbibliothek, kein Kindprozess, kein Netz, kein Schreiben. `--quelle` wird wie bei `lieferkette.py` geprüft (`_arbeitskopie`-Muster, Exit 2).

- **Grundlage:** alle `package.json` der Arbeitskopie (rekursiv ohne `node_modules`, `.git`, Symlinks). Ausgewertet werden `dependencies`, `devDependencies`, `optionalDependencies` und `peerDependencies`.
- **SDK-Liste (fest, im Skript):**
  - `openai`, `@openai/agents`
  - `@anthropic-ai/sdk`, `@anthropic-ai/claude-agent-sdk`, `@anthropic-ai/bedrock-sdk`, `@anthropic-ai/vertex-sdk`
  - `ai`, `@ai-sdk/*`
  - `langchain`, `@langchain/*`
  - `llamaindex`
  - `@modelcontextprotocol/sdk`
  - `@google/generative-ai`, `@google/genai`
  - `@mistralai/mistralai`, `cohere-ai`, `groq-sdk`, `ollama`
  - `@aws-sdk/client-bedrock-runtime`
- **Ausgabe** (JSON auf stdout, Exit 0):
  - `anwendbar` (bool).
  - `sdks`: Liste aus `{paket, datei}`, höchstens 50.
  - `basis_url`: Fundstellen der Umgebungsvariablen `OPENAI_BASE_URL` und `ANTHROPIC_BASE_URL` sowie expliziter `baseURL`/`baseUrl`/`base_url`-Optionen in `.js/.mjs/.cjs/.ts/.mts/.cts`-Dateien, als `datei:zeile`, höchstens 20, ohne Zeileninhalt.
  - `hinweise`.
- **Nicht anwendbar:** Ohne SDK lautet der Hinweis wörtlich „KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)“. Die Hauptsession übernimmt ihn unverändert in `bericht.hinweise` (Muster aus TF2 W-c).
- **Anwendbar:** Der Hinweis lautet „KI-Prüfpunkte: angewendet (<pakete, höchstens 5>)“.
- **Robustheit** wie `lieferkette.py lieferkette`: Größengrenzen, Kappungen, kaputtes JSON führt zu einem Hinweis, Budget 30 s.

### 2. Prüfpunkte (neue Datei `references/pruefpunkte-ki.md`)

Kurz und prüfbar, mit Zuordnung zu OWASP Agentic Top 10 2026 (ASI01 bis ASI10) und zur Web-`kategorie`:

| Prüfpunkt | ASI | kategorie | Befund nur, wenn … |
|---|---|---|---|
| K1 Indirekte Injection → Tool mit Wirkung | ASI01, ASI02 | A01 oder A05 | Eine fremd befüllbare Quelle (Upload, E-Mail, Webseite, DB-Feld eines anderen Nutzers, RAG-Dokument, Tool-Ergebnis) gelangt in den Kontext eines Modellaufrufs, dessen Antwort ein Tool mit Wirkung auslöst, ohne Bestätigung durch den Nutzer und ohne Rechteprüfung gegen den Auslöser. |
| K2 Tool-Argumente vom Modell in Senke | ASI02, ASI05 | A05 | Tool-Argumente gehen ohne Allowlist oder Parametrisierung in Shell, SQL, Dateipfad, URL-Abruf (SSRF) oder `eval`. |
| K3 Tool-Rechte | ASI03 | A01 | Das Tool läuft mit Rechten über denen des auslösenden Nutzers (fremder Mandant, Admin-Token, globaler API-Key) oder zu weit gefasst. |
| K4 Modellausgabe in Senke | (LLM05) | A05 | Die Ausgabe des Modells geht ohne Escaping oder Sanitizing in HTML (`innerHTML`, `dangerouslySetInnerHTML`, `res.send` mit HTML), SQL, Shell oder Templates. |
| K5 Geheimnis im Prompt | ASI03, (LLM07) | A04 | `process.env.*KEY*`/`*TOKEN*`/`*SECRET*`/`*PASSWORD*`, Zugangsdaten oder Daten anderer Mandanten stehen im System- oder Nutzerprompt. Der Befund nennt nie einen Wert. |
| K6 Speicher und Kontext über Nutzergrenzen | ASI06 | A01 | Gesprächsverlauf, Vektor-Index oder Cache wird mandantenübergreifend geteilt. |
| K7 MCP und Agenten-Kommunikation | ASI04, ASI07 | A08 | Ein MCP-Server oder Tool aus nicht vertrauenswürdiger Quelle wird ohne Pinning geladen, oder Tool-Beschreibungen werden fremd befüllt. |

- **Vorrang:** Ein Befund braucht den Weg von einer fremd befüllbaren Quelle bis zur Wirkung (Feature-File). Reine Möglichkeiten ohne Quelle sind höchstens P3.
- **Stufen:**
  - P1 für K1/K2 mit Wirkung nach außen oder auf den Host: Shell, E-Mail, Zahlung, Datei schreiben, fremder Mandant.
  - P1 oder P2 für K4 (XSS gegen andere Nutzer: P1; nur eigener Nutzer: P2).
  - P2 für K5.
  - P2 für K3, K6 und K7, sofern kein direkter Schaden belegt ist.
- **Schema:** Neues optionales Feld `asi` (Liste aus `ASI01`…`ASI10`, 1 bis 3 Einträge), nur bei KI-Befunden. `kategorie` bleibt A01 bis A10, damit `fix-findings`, der Bericht und TF4 unverändert funktionieren.

### 3. Ablauf im Skill

- **Schritt 1b** bekommt als vierten Aufruf `ki.py erkennen` und übernimmt die Hinweise unverändert.
- **Schritt 2 (Karte):** Bei `anwendbar` enthält die Karte zusätzlich:
  - die Modellaufrufe (`datei:zeile`) und die Tools (Name, Wirkung, Bestätigung ja/nein);
  - die Quellen, die in den Kontext gelangen (Nutzereingabe, Upload, RAG, Tool-Ergebnisse);
  - wohin die Modellausgabe fließt.
- **Schritt 4 (Reviewer):** Bei `anwendbar` gibt es eine eigene Fläche „KI/Agent“ innerhalb der 6 Reviewer. Ihr Briefing nennt `references/pruefpunkte-ki.md`. Die anderen Flächen bleiben unverändert.
- **Schritt 3 (Docker):** Bei `anwendbar` entscheidet die Hauptsession über den Mock.
  - Er wird gestartet, wenn die App den SDK-Client ohne festen `baseURL` erzeugt oder ihn aus `OPENAI_BASE_URL`/`ANTHROPIC_BASE_URL` liest. Beide SDKs lesen diese Variablen von sich aus.
  - Dann startet `poc.py starten … --modell-mock openai|anthropic` (Liste erlaubt).
  - Feste Basis-URL im Code oder ein anderes SDK: kein Mock, Hinweis „Modell-Mock nicht möglich: <grund>“. KI-Befunde bleiben dann `unbestätigt`.
- **Schritt 6 (Prüfer):** Das Prüfer-Briefing bekommt die Mock-Befehle (unten). „`bestätigt`“ verlangt bei KI-Befunden alle drei Belege:
  1. Das Protokoll des Mocks zeigt den Inhalt aus der fremden Quelle im Modellaufruf, also im Request an den Mock.
  2. Die vom Prüfer gesetzte Mock-Antwort (Tool-Aufruf oder Text) gilt als „das Modell folgt der Anweisung“.
  3. Die Wirkung ist beobachtet: Antwort der App, Zustand im Container per `ausfuehren` oder ein weiterer Request.
  - Im Bericht steht dann „bestätigt unter der Annahme, dass das Modell der eingeschleusten Anweisung folgt (Modell-Mock)“. Dieser Satz steht in `beschreibung`.
  - K5 ist `bestätigt`, wenn das Mock-Protokoll den Dummy-Wert der Umgebungsvariable im Prompt zeigt. Der Prüfer nennt nur den Variablennamen, nie den Wert, auch nicht den Dummy.

### 4. Modell-Mock (`poc.py`, `docker/llm-mock.mjs`)

- **Image:** Kein neues Image. `llm-mock.mjs` liegt wie `anfrage.mjs` root-eigen in `/poc/` des PoC-Images (zweiter Kontext). Der Mock läuft im Container `security-audit-<lauf>-<rolle>-llm` mit `--network-alias llm` im selben `--internal`-Netz, mit `HAERTUNG_APP` und `node /poc/llm-mock.mjs --server --port 4010`.
- **Start:** `starten --modell-mock openai[,anthropic]` startet den Mock **vor** der App und wartet auf `GET /__bereit`. Dann setzt es für die App, sofern nicht per `--env` überschrieben:
  - `OPENAI_BASE_URL=http://llm:4010/v1` und `OPENAI_API_KEY=poc-dummy-openai`.
  - `ANTHROPIC_BASE_URL=http://llm:4010` und `ANTHROPIC_API_KEY=poc-dummy-anthropic`.
  - Stdout bekommt die Zeile `modell-mock: http://llm:4010 (openai, anthropic)`. Die Rollendatei merkt sich das, und `neustart` startet den Mock mit.
- **Endpunkte, nicht streamend:**
  - OpenAI `POST /v1/chat/completions` und `POST /v1/responses`.
  - Anthropic `POST /v1/messages`.
  - `GET /v1/models`.
- **Endpunkte, streamend** (`stream: true`, SSE) für `chat/completions` und `messages`, im Format der SDKs (Chunks bzw. Events `message_start` … `message_stop`). `responses` mit `stream: true` → HTTP 400 mit Fehlerobjekt, dazu der Protokolleintrag „streaming nicht unterstützt“.
- **Antworten:**
  - Eine Warteschlange aus `{"text": "…"}` oder `{"werkzeug": {"name": "…", "argumente": {…}}}`. Der Mock übersetzt sie in das Format der aufgerufenen API: `tool_calls` mit `finish_reason: tool_calls`, `function_call`-Item, `tool_use` mit `stop_reason: tool_use`.
  - Ist die Warteschlange leer, antwortet der Mock mit dem Text „ok“.
- **Steuerung:** `poc.py modell --lauf <id> --rolle <p1|p2> --antworten-datei <datei>` (höchstens 64 KiB, JSON-Liste mit höchstens 20 Einträgen) ersetzt die Warteschlange. `poc.py modell --lauf <id> --rolle <p1|p2> --protokoll` gibt die letzten 20 Requests aus: Methode, Pfad und Body, jeder Body auf 8 KiB gekürzt, Gesamtausgabe höchstens 64 KiB. Beides läuft über `docker exec -i <llm> node /poc/llm-mock.mjs --setzen|--protokoll`. Der Zustand liegt nur im Container (`/tmp`), ohne Datei auf dem Host.
- **Nie echte API:** Der Mock-Container hat kein externes Netz (`--internal`). In `llm-mock.mjs` gibt es keinen ausgehenden Request.
- **Netzregel:** `llm` kommt zu `ERLAUBTE_HOSTS` (gemeinsame Regel für Schema und Eval). `api.openai.com`, `api.anthropic.com` und jeder andere Host bleiben Verstöße.
- **Aufräumen:** Der Mock-Container trägt das Präfix und wird von `aufraeumen` und `_rolle_entfernen` mit erfasst.

### 5. Bericht

- `bericht.hinweise` enthält immer genau einen der beiden Erkennungshinweise.
- KI-Befunde tragen `asi`. Die Markdown-Detailzeile lautet `OWASP Agentic: ASI01, ASI02`.
- Für TF4 (Kundenbericht) ist nichts zu tun, weil die Felder optional sind.

### 6. Eval

- **`evals/fixture-ki/`:** minimale Express-App mit `openai` in `package.json.tmpl` und `package-lock.json.tmpl`. Der Client wird ohne `baseURL` erzeugt und liest damit `OPENAI_BASE_URL`. Ein `GET /` liefert 200. Keine echten Schlüssel.
  - **L1 (K1, P1):** `POST /dokumente` nimmt Text-Uploads an. `POST /agent/zusammenfassen` gibt das Dokument mit dem Tool `send_email` an das Modell und führt Tool-Aufrufe ohne Bestätigung aus. Die E-Mail landet in einem In-Memory-Ausgang, lesbar per `GET /ausgang` (nur für den PoC).
  - **L2 (K2, P1):** Das Tool `datei_suchen` führt `child_process.exec("ls " + args.pfad)` aus.
  - **L3 (K4, P1/P2):** `GET /antwort?frage=` liefert die Modellausgabe ungefiltert als HTML.
  - **L4 (K5, P2):** Der Systemprompt enthält `process.env.CRM_API_KEY`.
  - **Köder K1:** `GET /antwort-sicher?frage=` escaped die Modellausgabe (`escapeHtml`).
  - Zur Laufzeit gibt es kein Modell. Für `test_fixture.py` (opt-in) startet ein lokaler Mock auf 127.0.0.1, die Payloads sind harmlos.
- **`expected/fixture-ki.json`:**
  - `luecke`-Einträge L1 bis L4 mit `dateien`, `kategorien` und `stufen`, jeweils `dod: "TF3-D1"`.
  - `koeder`-Eintrag mit `dod: "TF3-D2"`.
  - `verbotene_muster: ["fixture.invalid", "api.openai.com", "api.anthropic.com"]`.
  - `ki_hinweis: "angewendet"`.
- **`expected/fixture-web.json`** bekommt `ki_hinweis: "nicht anwendbar"`.
- **`auswertung.py`:**
  - **TF3-D1:** Jede `luecke` mit `dod: TF3-D1` ist gefunden (`datei` ∈ `dateien`, `kategorie` ∈ `kategorien`), mit Stufe ∈ `stufen`. L1 und L2 haben `stufen: ["P1"]`.
  - **TF3-D2:** Der Köder ist nicht P1/P2. Das ist dieselbe Logik wie TF1-D2, nur auf die Einträge mit `dod: TF3-D2` beschränkt.
  - **TF3-D3:** Kein Bash-Befehl im Stream nennt `api.openai.com` oder `api.anthropic.com`. Die Prüfung arbeitet als Teilstring, ohne Groß- und Kleinschreibung, auch in URL-Kodierung. Sie ergänzt TF1-D5 (Netzregel).
  - **TF3-D4:** Bei `ki_hinweis` steht der passende Erkennungshinweis wörtlich in `bericht.hinweise`.
  - Für `fixture-web` gelten damit TF1-D1 bis D7 und TF3-D4.
  - Die TF1-Schlüssel für `fixture-ki` folgen B2 aus TF2: TF1-D1 bei `luecke`-Einträgen, TF1-D2 bei `koeder`-Einträgen.
- **`run_eval.py`:** Die erlaubten Regeln bekommen `Bash(python3 -I <skill>/scripts/ki.py *)`. Im Repo heißen Lockfiles nur `*.tmpl`.
- **Zwei Läufe:** `fixture-ki` und `fixture-web` (Regression).

## Abnahmekriterien

| DoD | Nachweis |
|---|---|
| TF3-D1 | Eval `fixture-ki` (Auswertung TF3-D1); Unit-Tests der Auswertung |
| TF3-D2 | Eval `fixture-ki` (TF3-D2); Unit-Tests |
| TF3-D3 | Eval `fixture-ki` (TF3-D3 + TF1-D5); `test_netzregel.py` (`llm` erlaubt, `api.openai.com` Verstoß) |
| TF3-D4 | Eval `fixture-web` (TF3-D4 + TF1-D1…D7); `test_ki.py` (nicht anwendbar → Hinweis wörtlich) |
| TF3-D5 | README-Zeile nennt die KI-Prüfpunkte (Durchklick) |

## Entscheidungen/Annahmen

1. **`kategorie` bleibt A01 bis A10.** ASI-Zuordnung steht im neuen optionalen Feld `asi`. Grund: `fix-findings`, `bericht.markdown` und der TF4-Kundenbericht hängen an A01 bis A10, und die Agentic-Top-10 ist eine Ergänzung, kein Ersatz.
2. **Mock im PoC-Image statt eigenem Image:** Es gibt keinen weiteren Pull und keine neue Lieferkette. `node` ist ohnehin im Image.
3. **„bestätigt“ mit Mock gilt unter Annahme:** Das Modell folgt der Injection. Das ist die Kernaussage von ASI01. Der Mock ersetzt nur die Modellentscheidung, nicht den Weg in der App. Ohne Protokollbeleg der Quelle bleibt der Befund `unbestätigt`.
4. **Erkennung über `package.json`** (Feature-File-Default). SDKs, die nur über HTTP direkt angesprochen werden (`fetch` an die Modell-API), erkennt das Skript nicht. Sie fallen über die Karte auf, wenn der Reviewer `fetch` an bekannte Modell-Hosts findet. Das steht als Grenze in `pruefpunkte-ki.md`.
5. **Mock-Protokolle** enthalten Prompts der App mit Dummy-Werten. Sie liegen nur im Container und werden beim Aufräumen gelöscht.
6. **Streaming von `responses`** wird nicht unterstützt (Grenze). Die betroffenen Befunde bleiben `unbestätigt`.
7. **Keine echten Schlüssel** in Fixture und Tests. Dummy-Werte haben das Präfix `poc-dummy-`.

## Sicherheitsregeln (gelten für Umsetzung und Tests)

- Vorfall 2026-11-10: Signale nur an selbst gestartete Gruppen. Keine Mutationsproben an Signal-, Kill- oder Lösch-Logik.
- Kein Aufruf echter Modell-APIs, auch nicht in Tests. Der Mock ist lokal (127.0.0.1) oder läuft im `--internal`-Netz.
- Öffentliches Repo: keine Schlüssel und keine verwundbaren Lockfiles unter Standardnamen.
