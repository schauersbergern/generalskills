# Feature-File: Skill `security-audit` (Sicherheitsprüfung ganzer Codebasen)

**Datum:** 2026-11-09 · **Typ:** Feature-File für `auto-feature` · **Quelle:** Wunsch von Nikolaus im Chat vom 2026-11-09, Interview in derselben Session
· **Freigabe:** 2026-11-09, Nikolaus Schauersberger · **Builder-Check:** 2026-11-09, zwei Runden. R1 fand 1 kleinen Faktenfehler sowie 20 Fragen und Widersprüche, vor allem zur Eval-Mechanik. R2 fand keinen Faktenfehler, aber 16 Fragen, darunter 4 betriebsrelevante (Eval rot, Build mit Netz, Secrets im Modellkontext, Symlinks). 6 Punkte hat der User per Rückfrage entschieden, der Rest steht als Default im File.

Pro Teilfeature gibt es eine eigene Spec und einen eigenen PR. Dieses File ist das Approval. „Entschieden“ ist
bindend, bei „Default“ darf die Spec mit Begründung abweichen.

## 0. Rahmen (gilt für alle Teilfeatures)

- **Leitsatz:** Ein Befund zählt nur mit einem belegten Weg von einer Eingabe, die ein Angreifer kontrolliert, bis zum Schaden; ein bestätigter P1 ist mehr wert als zehn Verdachtsfälle.
- **Invarianten:**
  - README, Abschnitt „Coding-Workflow-Skills“: Kein Skill merged oder deployt von sich aus.
  - Agent-Statistik nach `~/.claude/CLAUDE.md` mit `auto-feature/scripts/agent-stats.py`.
  - Ein Review-Skill ändert keinen Code im geprüften Repo (wie `pr-review-loop/SKILL.md`, „Harte Grenzen“).
  - Das Repo hat weder `CLAUDE.md` noch CI. Die ganze Suite besteht aus den Tests unter `security-audit/` und `auto-feature/scripts/`, nicht `.claude/worktrees/`.
- **Was nicht brechen darf:**
  - `fix-findings` mit Befundlisten aus `pr-review-loop` (Kopfzeile `PR #<n> · …`, Format in `pr-review-loop/SKILL.md:203-216`).
  - `pr-review-loop`, `auto-feature` und `feature-file` bleiben unverändert.
  - Die live genutzten Skills: `~/.claude/skills/{auto-feature,fix-findings,pr-review-loop,feature-file}` und `~/.claude/agents/*.md` sind Symlinks in den Haupt-Checkout. Deshalb arbeitet der Lauf nur in Worktrees unter `.claude/worktrees/`, und der Haupt-Checkout bleibt auf `main`.
- **Teststrategie:**
  - Neue Skripte (Auswertung, Kundenbericht) bekommen pytest-Tests. Diese müssen in jedem Fall grün sein.
  - Das Verhalten des Skills prüfen Eval-Läufe. Dafür gibt es Test-Apps mit eingebauten Lücken und harmlosen Ködern. Jeder Lauf ist ein `claude -p` in einem Temp-Repo, ein Skript vergleicht das Ergebnis.
  - Die Eval-Läufe sind opt-in (`SECURITY_AUDIT_EVAL=1`). Die Hauptsession startet sie in der Verifikation nacheinander im Hintergrund. Nie in TDD-Schritten, gezielten Testläufen, Mutationsproben oder der Härtung.
  - Budget: die in den TFs genannten Läufe, insgesamt 7. Verfehlt ein Lauf ein DoD, gibt es höchstens eine Wiederholung, und dazwischen darf der Skill nachgeschärft werden. Verfehlt auch die Wiederholung das DoD, entsteht der PR trotzdem. Das DoD steht dann oben im PR-Body unter „Offene Review-Punkte“ mit beiden Ergebnissen, und die folgenden TFs laufen weiter (User).
  - Die Prosa von `SKILL.md` wird nicht per Test geprüft.
- **Nie:**
  - Requests oder PoCs gegen die geprüfte App, ihre Dienste oder Hosts aus ihrer Konfiguration, außer innerhalb des lokalen Docker-Netzes. Das gilt auch für Staging (User).
  - Andere ausgehende Verbindungen. Erlaubt bleiben nur OSV-API, CISA-KEV-Download, Docker Hub für Base-Images, die npm-Registry im Abhängigkeits-Schritt des Builds und die Modell-API von Claude Code.
  - Kundencode oder seine Abhängigkeiten außerhalb eines Docker-Containers starten oder bauen (User).
  - Literale Secrets, die echt aussehen, und Lockfiles mit bekannt verwundbaren Versionen unter Standard-Dateinamen committen. Das Repo `schauersbergern/generalskills` ist öffentlich, Push Protection und Dependabot schlagen sonst an.
  - Für Eval-Läufe `--permission-mode bypassPermissions` oder `--dangerously-skip-permissions` nutzen.
  - Im Haupt-Checkout den Branch wechseln, `~/.claude/skills/` oder `~/.claude/settings.json` ändern oder mergen.
- **Auslieferung:**
  - TF1 kommt als PR gegen `main`, die übrigen gestapelt auf ihren Vorgänger (Abschnitt 2).
  - TF1 committet dieses Feature-File unverändert als ersten Commit.
  - Den Symlink `~/.claude/skills/security-audit` setzt der User nach dem Merge (Ops im PR-Body von TF1).

## 1. Teilfeatures

### TF1: Kern-Skill: Audit eines ganzen Repos mit verifizierten Befunden

**Problem:** Nikolaus will seine Apps und die seiner Kunden als Ganzes auf ausnutzbare Lücken prüfen, nicht nur einen Diff. Angreifer mit lokalen oder unveröffentlichten Modellen finden solche Wege inzwischen automatisiert (Recherche: [Google GTIG via SecurityWeek, 09/2026](https://www.securityweek.com/google-ai-is-changing-the-pace-and-profile-of-vulnerability-discovery/)). Befunde von Modellen sind oft Fehlalarme. Ein Befund taugt deshalb erst, wenn er belegt ist und ein zweiter Agent ihn nicht widerlegen konnte.

**Ist:**
- Weder im Repo noch unter `~/.claude/skills/` gibt es einen eigenen Security-Skill. Er wird neu gebaut.
- Das eingebaute `/security-review` prüft nur offene Änderungen ([README anthropics/claude-code-security-review](https://cdn.jsdelivr.net/gh/anthropics/claude-code-security-review@main/README.md)). Es bleibt unangetastet.
- Das Befundformat P1/P2/P3 aus `pr-review-loop/SKILL.md:203-216` wird übernommen. Reviewer und Prüfer laufen als `agents/opus-xhigh.md`.
- Lokal vorhanden: Node 20.19 (kein `node:sqlite`), Docker 29, pytest 9.

**Entschieden:**
- Der Skill ändert nie Code im geprüften Repo. Er liefert eine P1/P2/P3-Liste für `/fix-findings` (User).
- PoCs laufen nur lokal in Docker. Ein P1/P2 wird per Request gegen die App im Wegwerf-Container belegt. Ohne lauffähiges Docker-Setup gilt er als „unbestätigt“ mit statischem Code-Pfad (User).
- Der Bericht liegt außerhalb des Repos unter `~/.claude/security-reviews/<repo>/` (User).
- Ein Lauf startet höchstens 8 Subagenten: bis zu 6 Reviewer nach Angriffsfläche und höchstens 2 Prüfer (User).
- Eigene Prüfpunkte gibt es nur für Node/TS-Web: Next.js, Express, tRPC, Prisma/Neon und Stripe-Webhooks (User).

**Default:**
- Skill (Workflow):
  - Name `security-audit`, Aufruf `/security-audit [teilpfad] [projekt="…"]`.
  - Frontmatter: `model: opus`, `effort: xhigh`.
  - Skripte werden relativ zum Basisverzeichnis aufgerufen, das Claude Code beim Laden nennt, nicht über `~/.claude/skills/…`.
- `<repo>`: Basename der `origin`-URL ohne `.git`. Fehlt der Remote, der Ordner des Haupt-Worktrees (`git rev-parse --git-common-dir`). Audit und `fix-findings` bilden ihn gleich (Workflow).
- Ablauf (Workflow):
  1. Die Hauptsession kartiert die Angriffsfläche.
  2. Reviewer prüfen die Flächen.
  3. Prüfer versuchen, die Befunde zu widerlegen.
  4. Am Ende entsteht der Bericht.
  - Geprüft werden nur git-versionierte Dateien.
- Prüfer (Recherche: [NHI Mgmt Group](https://nhimg.org/articles/claude-code-security-and-the-verification-gap-in-ai-code-review/), [arXiv 2601.18844](https://arxiv.org/html/2601.18844v1)):
  - Sie sehen Behauptung und Fundstelle, nicht die Herleitung, und sollen den Befund widerlegen.
  - Sie bauen auch die PoCs.
- Kategorien nach der OWASP Top 10:2025, Schwerpunkt A01 einschließlich Mandanten-Scope und SSRF (Recherche: [OWASP](https://owasp.org/Top10/2025/0x00_2025-Introduction/)).
- Docker-PoC (Workflow):
  - Eigenes Dockerfile des Skills auf `node:20-slim`, nicht das der App.
  - Die Wegwerf-Kopie enthält keine `.env*` außer `.env.example`.
  - Der Abhängigkeits-Schritt `npm ci --ignore-scripts` läuft mit Netz.
  - Build-Schritte der App (`prisma generate`, `next build`, `tsc`) laufen mit `RUN --network=none`.
  - Zur Laufzeit hängt die App in einem internen Netz ohne Zugang nach außen. Requests kommen aus einem Client-Container in diesem Netz.
  - Container, Netz und Image heißen `security-audit-<zufall>` und werden am Ende entfernt.
- Ausgabe (Workflow):
  - Bericht `<YYYY-MM-DD>-<sha7>[-<teilpfad-slug>].md`, bei Namensgleichheit `-2`. Er enthält die Befundliste mit der Kopfzeile `Repo <repo> · Security-Audit · geprüft auf <sha>` und den IDs `S-1 …`.
  - Dazu ein `.json` mit diesen Feldern je Eintrag: `id`, `stufe`, `status` (`bestätigt` mit `poc`, `unbestätigt` mit `code_pfad`, `verworfen` mit `grund` oder `verdacht`), `datei`, `zeile`, `kategorie`, `titel`, `beschreibung`, `ohne_anmeldung` und `mandantenuebergreifend`.
  - `SECURITY_AUDIT_AUSGABE` überschreibt den Basisordner. Ist die Variable gesetzt, liegt dort auch die Agent-Statistik, nicht unter `~/.claude/agent-stats/`.
- Test-App `security-audit/evals/fixture-web/` (Workflow):
  - Express mit sql.js (ohne Install-Skripte) und Lockfile.
  - 6 Lücken, jede in einer eigenen Datei, Köder ebenfalls in eigenen Dateien. 4 P1: fremde Org lesbar, SQL-Injection, Admin-Route ohne Auth, Stripe-Webhook ohne Signaturprüfung. 2 P2: SSRF und Path Traversal.
  - 3 Köder.
  - Eine `.env.production` mit `DATABASE_URL=postgres://audit@db.fixture.invalid/app`, ohne Passwort.
  - Die Erwartung steht in `evals/expected/fixture-web.json`, je Eintrag Datei und Kategorie.
- `evals/run_eval.py` (Workflow):
  - Legt ein Temp-Repo `eval-security-audit-<zufall>` an, das nur die Dateien der Test-App enthält.
  - Kopiert den Skill ohne `evals/` nach `.claude/skills/security-audit-eval/`, Frontmatter-`name` ebenso, und trägt `.claude/` in `.git/info/exclude` ein.
  - Startet `claude -p "/security-audit-eval"` mit `--output-format stream-json`, `--permission-mode acceptEdits`, eng gefasstem `--allowedTools`, `--add-dir` für den Ausgabeordner und gesetztem `SECURITY_AUDIT_AUSGABE`.
  - Ordnet Befunde über Datei und Kategorie zu.
  - Wertet JSON, Stream (Subagenten, Bash-Befehle), `git status` und `docker ps` aus.

**DoD:**
- **TF1-D1** [Test] Der Eval auf `fixture-web` findet alle 4 P1-Lücken mit richtiger Datei und Stufe P1 und mindestens 5 der 6 Lücken.
- **TF1-D2** [Test] Kein Köder erscheint als P1 oder P2. Ein Köder mit Status `verworfen` hat einen Grund.
- **TF1-D3** [Test] Jeder P1/P2 im JSON hat entweder `bestätigt` mit `poc` oder `unbestätigt` mit `code_pfad` von der Eingabe bis zur Senke.
- **TF1-D4** [Test] Nach dem Lauf ist `git status --porcelain` des Temp-Repos leer. Bericht, JSON und Agent-Statistik liegen im Ausgabeordner, unter `~/.claude/agent-stats/` ist nichts Neues.
- **TF1-D5** [Test] Kein Bash-Befehl im Stream und kein `poc` im JSON nennt `fixture.invalid` oder einen anderen nicht lokalen Host der Test-App.
- **TF1-D6** [Test] Der Stream zeigt höchstens 8 Subagenten-Starts.
- **TF1-D7** [Test] Nach dem Lauf meldet `docker ps -a --filter name=security-audit-` nichts. Auch Netz und Image dieses Namens sind entfernt.
- **TF1-D8** [Test] Das Auswerteskript scheitert, wenn eine P1-Lücke fehlt oder ein Köder als P1/P2 auftaucht. Dafür gibt es einen pytest mit präparierten JSON-Dateien, auch mit Köder und Lücke in derselben Kategorie.
- **TF1-D9** [Durchklick] `/security-audit src/` auf einem eigenen Repo prüft nur diesen Teilpfad, und der Dateiname trägt den Slug.
- **TF1-D10** [Durchklick] Die README führt `security-audit` in der Tabelle und in der Symlink-Zeile.
- **TF1-D11** [Ops] Symlink `~/.claude/skills/security-audit` gesetzt → `/security-audit` erscheint in einer neuen Session.

### TF2: Abhängigkeiten, Lieferkette und Secrets

**Problem:** Die meisten schnellen Angriffe nutzen bekannte Lücken in Abhängigkeiten. Im ersten Halbjahr 2026 lag der Median von der CVE bis zur Ausnutzung bei 80 Tagen (Recherche: [VulnCheck via CSO](https://www.csoonline.com/article/4230247/ai-accelerates-n-day-attacks-as-flaw-disclosures-and-exploits-double.html)). Dazu kommen kompromittierte Pakete mit Install-Skripten und Secrets in der Git-Historie. Die Code-Prüfung durch Modelle findet nichts davon systematisch.

**Ist:** Im Skill aus TF1 fehlt das. `osv-scanner` 2.6 und `gitleaks` 8.30 liegen unter `/opt/homebrew/bin/` und werden neu eingebunden.

**Entschieden:**
- Werkzeuge: `osv-scanner` schickt nur Paketnamen und Versionen nach außen, `gitleaks` sucht Secrets auch in der Historie. Fehlt eines, läuft der Rest weiter, und der Bericht nennt die Lücke (User).
- `gitleaks` läuft immer mit `--redact`. Weder Modell noch Transkript sehen den Wert. Der Bericht nennt Regel, Datei, Commit und Zeile. Den gitleaks-Report legt der Skill in einem Temp-Verzeichnis außerhalb von Repo und Ausgabeordner ab und löscht ihn danach (User).

**Default:**
- Stufen einer Abhängigkeitslücke: P1, wenn die betroffene Funktion erreichbar ist (Aufruf mit `datei:zeile`) oder die CVE im CISA-KEV-Katalog steht. Sonst P2, bei reinen Dev-Abhängigkeiten P3 (Workflow).
- Ein Secret in der Historie ist P1, auch wenn es inzwischen gelöscht ist. Die Fix-Richtung heißt „rotieren“ (Workflow).
- Lieferkette (Recherche: [GitHub Blog, 02.12.2025](https://github.blog/2025-12-02-strengthening-supply-chain-security-preparing-for-the-next-malware-campaign/)):
  - Lockfile fehlt.
  - Installation ohne Lockfile-Treue: `npm install` statt `npm ci` oder `--frozen-lockfile` in CI oder Dockerfile.
  - Install-Skripte von Abhängigkeiten sind nicht eingeschränkt.
- Ein Werkzeug gilt als fehlend, wenn `command -v` scheitert oder sein Name in `SECURITY_AUDIT_OHNE` steht. `docker` in dieser Liste heißt: keine PoCs (Workflow).
- Test-App `evals/fixture-deps/` (Workflow):
  - Manifest und Lockfile liegen als `package.json.tmpl` und `package-lock.json.tmpl` vor. `run_eval.py` benennt sie im Temp-Repo um.
  - Eine verwundbare Version wird aufgerufen, eine zweite nicht.
  - Dazu kommt ein Dockerfile mit `npm install`. Es ist Prüfobjekt, kein Build für den PoC.
  - Das Fake-Secret erzeugt `run_eval.py` zur Laufzeit zufällig (`secrets.token_hex`) als Treffer einer generischen gitleaks-Regel. Es wird als Commit angelegt und danach wieder gelöscht.
- Drei Eval-Läufe: `fixture-deps`, `fixture-web` als Regression und `fixture-web` ohne Lockfile mit `SECURITY_AUDIT_OHNE=gitleaks,osv-scanner,docker` (Workflow).

**DoD:**
- **TF2-D1** [Test] `fixture-deps`: Die verwundbare Version mit Aufruf ist P1 mit Aufrufstelle, die ohne Aufruf P2 oder P3.
- **TF2-D2** [Test] `fixture-deps`: Das gelöschte Fake-Secret ist P1 mit Commit-SHA. Weder Stream noch Bericht noch JSON noch Ausgabeordner enthalten den Wert.
- **TF2-D3** [Test] `fixture-deps`: Der Befund „Installation ohne Lockfile-Treue“ nennt das Dockerfile.
- **TF2-D4** [Test] Lauf ohne Werkzeuge: Der Bericht nennt „gitleaks fehlt“ und „osv-scanner fehlt“, „Lockfile fehlt“ erscheint als Befund, und jeder P1/P2 ist `unbestätigt`.
- **TF2-D5** [Test] Lauf ohne Werkzeuge: TF1-D1 gilt weiterhin.
- **TF2-D6** [Test] Regression `fixture-web`: TF1-D1 bis TF1-D7 gelten weiterhin.
- **TF2-D7** [Durchklick] Die README-Zeile von `security-audit` nennt Abhängigkeiten und Secrets.

### TF3: Prüfpunkte für KI- und Agenten-Apps

**Problem:** Manibase baut KI-Lösungen für Kunden. Dort gibt es eigene Wege zum Schaden:
- Anweisungen in Dokumenten, die ein Agent liest
- Tools mit zu viel Recht
- Modellausgabe, die in HTML, SQL oder Shell landet
- Schlüssel im Prompt

Die Web-Prüfpunkte aus TF1 decken das nicht ab.

**Ist:** Im Skill aus TF1 fehlt das. Es wird neu aufgenommen.

**Entschieden:**
- KI-/Agenten-Apps bekommen eigene Prüfpunkte (User).

**Default:**
- Die Prüfpunkte greifen, wenn `package.json` ein LLM- oder Agenten-SDK listet (u. a. `openai`, `@anthropic-ai/sdk`, `ai`, `langchain`, `@modelcontextprotocol/sdk`). Sonst steht im Bericht „KI-Prüfpunkte: nicht anwendbar“ (Workflow).
- Grundlage ist die OWASP Top 10 for Agentic Applications 2026, vor allem ASI01 (Goal Hijack) und ASI02 (Tool Misuse). Ein Befund braucht den Weg von einer Quelle, die Fremde befüllen können, zu einem Tool mit Wirkung (Recherche: [OWASP GenAI, 09.12.2025](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)).
- PoC (Workflow):
  - Liest die App die Basis-URL des SDK aus der Umgebung (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`), startet der Skill im internen Netz einen Mock-Container und lenkt die App dorthin um.
  - Ohne diese Möglichkeit bleibt der Befund `unbestätigt`.
  - Eine echte Modell-API wird nie aufgerufen.
- Test-App `evals/fixture-ki/` (Workflow):
  - `openai` steht in `package.json`, der Client liest `OPENAI_BASE_URL`.
  - Lücken:
    - Ein Upload-Dokument steuert einen Agenten mit dem Tool `send_email` ohne Bestätigung.
    - Modellausgabe wird als HTML ausgeliefert.
    - Ein Shell-Tool übernimmt Argumente vom Modell.
    - `process.env.CRM_API_KEY` steht im Systemprompt.
  - Köder: escapte Modellausgabe.
- Zwei Eval-Läufe: `fixture-ki` und `fixture-web` als Regression (Workflow).

**DoD:**
- **TF3-D1** [Test] `fixture-ki`: Alle 4 Lücken sind mit Datei gemeldet, Shell-Tool und `send_email` als P1.
- **TF3-D2** [Test] `fixture-ki`: Der Köder erscheint nicht als P1 oder P2.
- **TF3-D3** [Test] `fixture-ki`: Kein Bash-Befehl im Stream nennt `api.openai.com` oder `api.anthropic.com`.
- **TF3-D4** [Test] Regression `fixture-web`: Der Bericht enthält „KI-Prüfpunkte: nicht anwendbar“, und TF1-D1 bis TF1-D7 gelten weiterhin.
- **TF3-D5** [Durchklick] Die README-Zeile nennt die KI-Prüfpunkte.

### TF4: Kundenbericht (Markdown und PDF)

**Problem:** Nikolaus will Kunden das Ergebnis geben, ohne Exploit-Details auszuhändigen. Gebraucht wird ein deutscher Bericht mit Management-Zusammenfassung, Risiko je Befund und Maßnahmen.

**Ist:** Bisher gibt es nichts davon. `pandoc` 3.9 und `weasyprint` 68.1 sind lokal installiert. Grundlage ist das JSON aus TF1.

**Entschieden:**
- Format: Markdown als Quelle, daraus ein PDF (User).
- Kopf „Manibase · Sicherheitsprüfung <Projekt>“ mit Datum und Commit, ohne Logo, Anrede mit Sie (User).
- `<Projekt>` kommt aus `projekt="…"`. Fehlt das Argument, wird der Repo-Ordner genommen, und der Bericht weist darauf hin (User).
- Kundenstufen sind Kritisch, Hoch, Mittel und Niedrig, ohne CVSS. Intern bleibt P1/P2/P3 (User).

**Default:**
- Zuordnung (Workflow):
  - P1 mit `ohne_anmeldung` oder `mandantenuebergreifend` wird Kritisch.
  - Jeder andere P1 wird Hoch.
  - P2 wird Mittel, P3 Niedrig.
  - Befunde mit Status `verworfen` oder `verdacht` erscheinen nicht.
- Inhalt: Das Modell schreibt Zusammenfassung und Maßnahmen in die JSON-Felder `zusammenfassung` und `massnahme`. Der Kundenbericht zeigt `titel`, `zusammenfassung`, `massnahme` und `datei`, aber weder Zeile noch `poc`, `code_pfad` oder `beschreibung` (Workflow).
- Skript `security-audit/scripts/kundenbericht.py` (Workflow):
  - Rendert den Bericht und prüft danach das ganze erzeugte Markdown.
  - Exit 2 bei Du-Anrede, bei Mustern wie `datei:zahl` oder bei einem Text aus `poc` oder `code_pfad`. Die Du-Prüfung ignoriert den Inhalt von Pfadangaben.
  - Exit 3, wenn das PDF fehlt, weil `pandoc` oder `weasyprint` fehlen. Das Markdown entsteht trotzdem.
  - Das PDF entsteht per `pandoc --pdf-engine=weasyprint`.
- Ablage: `<…>-kunde.md` und `<…>-kunde.pdf` neben dem technischen Bericht (Workflow).
- Ein Eval-Lauf auf `fixture-web` mit `projekt="Testportal"` liefert das PDF für den Durchklick (Workflow).

**DoD:**
- **TF4-D1** [Test] Aus einem Beispiel-JSON entsteht ein Markdown mit „Manibase · Sicherheitsprüfung <Projekt>“, Datum und Commit-SHA. Ohne `projekt` steht dort der Ordnername mit Hinweis.
- **TF4-D2** [Test] P1 ohne Anmeldung wird „Kritisch“, P1 mit Anmeldung „Hoch“, P2 „Mittel“, P3 „Niedrig“. Verworfene Befunde und Verdachtsfälle fehlen.
- **TF4-D3** [Test] Steht in `zusammenfassung` oder `massnahme` ein Text aus `poc`, `code_pfad` oder ein `datei:zahl`, endet das Skript mit Exit 2 und schreibt keinen Kundenbericht.
- **TF4-D4** [Test] Steht „du“, „dein“ oder „dich“ in `zusammenfassung` oder `massnahme`, endet das Skript mit Exit 2. `datei: src/dir/x.ts` löst nichts aus.
- **TF4-D5** [Test] Fehlt `weasyprint` im `PATH`, endet das Skript mit Exit 3, und das Markdown liegt vor.
- **TF4-D6** [Test] Eval `fixture-web`: TF1-D1 bis TF1-D7 gelten weiterhin, und Kunden-Markdown sowie PDF liegen im Ausgabeordner.
- **TF4-D7** [Durchklick] Nikolaus liest das PDF aus dem Eval-Lauf und prüft Ton, Verständlichkeit für Geschäftsführer und Layout.
- **TF4-D8** [Durchklick] Die README-Zeile nennt den Kundenbericht und `projekt=`.

### TF5: `fix-findings` nimmt Audit-Befundlisten ohne PR an

**Problem:** `fix-findings` setzt einen PR voraus. Ein Audit des ganzen Repos hat keinen, also fragt `fix-findings` nach einer PR-Nummer, die es nicht gibt.

**Ist:** `fix-findings/SKILL.md` setzt an mehreren Stellen einen PR voraus. Der Pfad mit PR bleibt unverändert, ergänzt wird ein zweiter Eingang ohne PR.
- Z. 3: Die Description sagt „on the current PR branch“.
- Z. 30: Merge setzt einen PR voraus.
- Z. 37: Der PR wird über Kopfzeile oder Branch gesucht, sonst kommt eine Frage.
- Z. 67: „Keine CI“ wird über `gh pr checks` erkannt.
- Z. 75–77: PR-Nummer in der Statistik.
- Z. 82: Tabellenkopf `PR #<n>`.

**Entschieden:**
- Ohne PR pusht `fix-findings` nur den Branch und gibt den Link zum Erstellen eines PRs aus. Einen PR öffnet es nicht (User).

**Default:**
- Erkannt wird die Liste an der Kopfzeile `Repo <repo> · Security-Audit · geprüft auf <sha>` (Workflow):
  - `<repo>` wird wie in TF1 gebildet. Passt es nicht oder fehlt der SHA im Repo, bricht der Skill mit genau dieser Meldung ab.
  - Sonst entsteht ein Branch `security-audit-<YYYY-MM-DD>` vom geprüften SHA, bei Namensgleichheit mit `-2`. Der SHA steht nicht im Namen, weil `-f…` den Force-Push-Wächter auslöst (`auto-feature/SKILL.md:178`).
- „mergen“ oder „deployen“ zusammen mit einer Audit-Liste werden mit dem Hinweis „kein PR, Merge entscheidest du nach dem PR“ ignoriert (Workflow).
- Ohne PR zählt das Repo als „ohne CI“, wenn es kein `.github/workflows/` gibt. Dann läuft vor dem Push einmal die ganze Suite (Workflow).
- Commits tragen die Befund-ID, z. B. `fix(auth): Org-Filter ergänzt (Audit S-3)` (Workflow).
- Statistik und Tabelle (Workflow):
  - Datei `<YYYY-MM-DD>-audit-<sha7>-fix.md` mit Kopf `# Agent-Statistik · Security-Audit <sha7> Fix`, Spalte TF = `audit`.
  - Abschlusstabelle mit `Security-Audit <sha7> · Branch <name> · Head <sha>`.
  - Die Description nennt beide Eingänge.

**DoD:**
- **TF5-D1** [Durchklick] Eine Audit-Liste per Copy-Paste an `/fix-findings`:
  - keine Frage nach einer PR-Nummer
  - Branch `security-audit-…` mit Commits je Befund-ID
  - Push und Link zum Erstellen des PRs
  - kein PR
- **TF5-D2** [Durchklick] Eine Liste mit `PR #<n> · …` aus `pr-review-loop` läuft wie bisher auf dem PR-Branch.
- **TF5-D3** [Durchklick] Eine Audit-Liste aus einem anderen Repo bricht mit Meldung ab, ohne Branch und ohne Commit.
- **TF5-D4** [Durchklick] Eine Audit-Liste mit „mergen“ führt zu Push und Hinweis, nicht zu einem Merge.
- **TF5-D5** [Durchklick] Die README-Zeile von `fix-findings` nennt den Eingang aus `security-audit`.

## 2. Reihenfolge und Abhängigkeiten

Alle TFs ändern `README.md`, TF2 bis TF4 außerdem `security-audit/SKILL.md`. Deshalb laufen sie nacheinander als gestapelte Branches, jeder in einem eigenen Worktree. TF5 kommt direkt nach TF1: Es ist klein, und erst damit führt ein durchgehender Weg vom Audit zum Fix.

- TF5 braucht TF1: Kopfzeile, `<repo>`-Regel und Befund-IDs.
- TF2 braucht TF1: Skill, JSON-Format und `run_eval.py`.
- TF3 braucht TF2: `SECURITY_AUDIT_OHNE` und das Eval-Gerüst.
- TF4 braucht TF1 (JSON-Felder) und läuft nach TF3, weil beide dieselben Dateien ändern.

Reihenfolge: TF1 → TF5 → TF2 → TF3 → TF4.

## 3. Gemeinsame DoD

- Nach dem Merge lässt Nikolaus `/security-audit` einmal auf einem eigenen echten Repo laufen. Von den gemeldeten P1/P2 darf er höchstens einen als Fehlalarm einstufen. Sonst geht der Befund als Nacharbeit an den Skill.

## 4. Nicht in diesem File

- Prüfpunkte für Python, Flutter, Supabase/RLS und Expo: nicht gewählt (User).
- Tests gegen Staging oder Produktion, DAST, Pentest von außen: ausgeschlossen (User, „PoC nur lokal“).
- Automatisches Fixen im Audit-Lauf und automatische PRs: Fixen macht `fix-findings`, und das ohne PR (User).
- Wiederkehrende Audits mit Delta zum letzten Bericht: erst nach Erfahrung mit einzelnen Läufen.
- Rechtliche Bewertung von Meldepflichten (DSGVO Art. 33, CRA Art. 14 seit 11.09.2026): Das ist Rechtsberatung und nicht Aufgabe des Skills.
- `semgrep` und andere SAST-Regelwerke: Die Code-Prüfung machen die Modelle. Ein zweites Regelwerk bringt vor allem Fehlalarme.
- Das eingebaute `/security-review` von Claude Code: nicht unser Code.
- `CLAUDE_CODE_EFFORT_LEVEL=high` in `~/.claude/settings.json` übersteuert möglicherweise `effort: xhigh` aller Skills. Das betrifft die Konfiguration des Users, nicht dieses File.
