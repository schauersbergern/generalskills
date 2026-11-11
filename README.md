# nikskills

Sammlung lokaler Skills fuer agentische Coding- und Content-Workflows.
Jeder Skill liegt in einem eigenen Verzeichnis mit einer `SKILL.md` als
Einstiegspunkt und optionalen Referenzen oder Scripts.

Der aktuelle Stand des Repos umfasst zehn produktiv nutzbare Skills plus drei Agent-Definitionen:

| Skill | Zweck | Wichtige Dateien |
|---|---|---|
| `gpt-image-skill` | Generiert Bilder ueber OpenAI `gpt-image-*` und speichert das Ergebnis als PNG | `gpt-image-skill/SKILL.md`, `gpt-image-skill/generate_image.js` |
| `seo-ecommerce-pdp` | Erstellt SEO- und GEO-optimierte E-Commerce Product Detail Pages (HTML + JSON-LD) oder bewertet bestehende Produktseiten mit Score 0-100 | `seo-ecommerce-pdp/SKILL.md`, `seo-ecommerce-pdp/references/pdp-regelwerk.md`, `seo-ecommerce-pdp/scripts/analyze_pdp.py`, `seo-ecommerce-pdp/templates/*` |
| `seo-geo-writer` | Erstellt oder optimiert SEO- und GEO-orientierte Blogartikel mit fester Recherche- und Strukturvorgabe | `seo-geo-writer/SKILL.md`, `seo-geo-writer/references/regelwerk.md` |
| `seo-page-review` | Auditiert eine einzelne URL und vergibt einen gewichteten Score (50% SEO + 50% GEO) mit priorisierten Befunden und Empfehlungen | `seo-page-review/SKILL.md`, `seo-page-review/references/checkliste.md`, `seo-page-review/scripts/analyze_page.py` |
| `viral-post-wizard` | Erstellt LinkedIn-Posts im Stil von Nikolaus Schausberger auf Basis fester Schreibregeln | `viral-post-wizard/SKILL.md`, `viral-post-wizard/references/*` |
| `pr-review-loop` | Reviewer-Thread: startet ohne Fixer-Namen sofort je PR einen eigenen Fixer, prueft Runde 1 mit 1–3 Opus-Reviewern je nach PR-Art (Doku/Ops 1, Code klein 1, Code 2, Code mit Risiko 3 inkl. Tests-Fokus), Fixer auf Sonnet/high, eigene Test-DB je mutierendem Reviewer, reproduziert Befunde, liefert P1/P2/P3-Liste an den Fixer-Thread, re-reviewt nur das Delta mit einem `sonnet-high` (kleine, Doku- und P3-Deltas selbst, Merges nur per `--remerge-diff`), zweiter P2 an derselben Heuristik geht als Entscheidung an den User, Runde 3+ nur nach P1/P2, ohne `runden=<n>` bis sauber oder Stillstand; Agent-Statistik unter `~/.claude/agent-stats/` inkl. Thread-Tokens per Skript; aendert nie Code, merged nie | `pr-review-loop/SKILL.md` |
| `fix-findings` | Fixer-Thread (Effort high, von `pr-review-loop` mit Sonnet gestartet): prueft eingefuegte Review-Befunde, setzt angenommene per Test → Fix → Commit um, vor dem Push nur Typecheck und abhaengige Tests (ganze Suite in der CI, ohne CI einmal vor dem Push), pusht, liefert Entscheidungstabelle; Merge/Deploy nur auf Befehlswort; nimmt auch die Befundliste aus `security-audit` ohne PR an (eigener Worktree vom geprueften SHA, Push des Branches ausser bei oeffentlichen Repos, PR-Link, kein PR) | `fix-findings/SKILL.md` |
| `auto-feature` | Autonomer Feature-Workflow aus einem Feature-File ohne Zwischenhalt: Spec (Opus 5.5) → Opus-Review max. 2 → Plan (Opus 5.5) → Opus-Review max. 2 → Sonnet-5.5-Umsetzung → Haertung → PRs → harter Stopp (HITL); Effort xhigh, nur Re-Reviews, lesende Refactor-/UI-Reviews und mechanische Tasks mit `sonnet-high`; ganze Suite einmal je TF; Agent-Statistik Pflicht (Format gilt fuer alle Skills, Skript `scripts/agent-stats.py` fuer Eintrag, Auswertung (auch je Skill-Stand), Thread-Tokens aus Transkripten und den Stempel `Skills: generalskills@<sha>` im Kopf jeder Statistik); kein PR-Review-Loop, kein Merge; Format des Feature-Files mit DoD-IDs und Nachweis-Art in `references/feature-file.md` | `auto-feature/SKILL.md`, `auto-feature/references/feature-file.md`, `auto-feature/scripts/agent-stats.py` |
| `feature-file` | Macht aus Kundenwunsch, Call-Notiz oder Idee ein Feature-File fuer `auto-feature`: Ist-Stand im Code zuerst, Interview nur fuer Entscheidungen von User oder Kunde, Recherche nur als Default mit Quelle, Builder-Check durch einen frischen `opus-xhigh`, Freigabe-Zeile erst nach OK | `feature-file/SKILL.md` |
| `security-audit` | Auditiert ganze Node/TS-Repos auf ausnutzbare Luecken: Karte der Angriffsflaeche, bis zu 6 Opus-Reviewer, 2 Pruefer, die jeden P1/P2 widerlegen oder per Docker-PoC im internen Netz belegen; dazu Abhaengigkeiten (osv-scanner, CISA KEV, Erreichbarkeit im Code), Lieferkette (Lockfile, `npm install` statt `npm ci`, offene Install-Skripte) und Secrets in der Git-Historie (gitleaks, Arbeitskopie vor dem Lesen geschwaerzt, Werte nie im Bericht); KI- und Agenten-Apps: Erkennung ueber `package.json` (`ki.py`), eigene Pruefpunkte K1 bis K7 (fremde Inhalte steuern Agenten, Tools mit Wirkung, Modellausgabe in Senken, Geheimnisse im Prompt), belegt per Modell-Mock im internen Docker-Netz, nie gegen eine echte Modell-API; Bericht ausserhalb des Repos unter `~/.claude/security-reviews/<repo>/`, Befundliste fuer `/fix-findings`; dazu ein Kundenbericht (Markdown und PDF, Sie-Form, Kundenstufen, Risiko und Massnahme je Befund, ohne Exploit-Details; Kopf mit dem Projektnamen aus `projekt=`); aendert das Repo nie | `security-audit/SKILL.md`, `security-audit/references/*`, `security-audit/scripts/bericht.py`, `security-audit/scripts/poc.py`, `security-audit/scripts/netzregel.py`, `security-audit/scripts/gitkopie.py`, `security-audit/scripts/lieferkette.py`, `security-audit/scripts/ki.py`, `security-audit/scripts/kundenbericht.py`, `security-audit/scripts/kundenbericht.html5`, `security-audit/docker/llm-mock.mjs`, `security-audit/evals/run_eval.py` |
| `agents/opus-xhigh`, `agents/sonnet-xhigh`, `agents/sonnet-high` | Subagent-Definitionen mit `effort: xhigh` fuer Reviews bzw. Umsetzung, genutzt von `pr-review-loop`, `auto-feature`, `feature-file` (Builder-Check) und `security-audit` (Reviewer und Pruefer); `sonnet-high` (`effort: high`) fuer die Delta-Reviews in `pr-review-loop` und die Abschlaege nach der Effort-Regel in `auto-feature` | `agents/*.md` |

## Repository-Struktur

```text
nikskills/
  README.md
  gpt-image-skill/
    SKILL.md
    generate_image.js
  seo-ecommerce-pdp/
    SKILL.md
    references/
      pdp-regelwerk.md
    scripts/
      analyze_pdp.py
    templates/
      pdp-snippet.html
      product-schema.jsonld
  seo-geo-writer/
    SKILL.md
    references/
      regelwerk.md
  seo-page-review/
    SKILL.md
    references/
      checkliste.md
    scripts/
      analyze_page.py
  viral-post-wizard/
    SKILL.md
    references/
      disallow_list.md
      ghostwriter_spickzettel.md
      viral_framework.md
      voiceprint.md
  pr-review-loop/
    SKILL.md
  fix-findings/
    SKILL.md
  auto-feature/
    SKILL.md
    references/
      feature-file.md
    scripts/
      agent-stats.py
      test_agent_stats.py
  feature-file/
    SKILL.md
  security-audit/
    SKILL.md
    docker/
      Dockerfile.poc
      Dockerfile.poc.dockerignore
      anfrage.mjs
      llm-mock.mjs
    evals/
      auswertung.py
      run_eval.py
      test_auswertung.py
      test_fixture.py
      expected/
      fixture-web/
      sdk-vertrag/
      testdaten/
    references/
      agenten-briefings.md
      bericht-format.md
      pruefpunkte-ki.md
      pruefpunkte-web.md
    scripts/
      bericht.py
      gitkopie.py
      ki.py
      kundenbericht.html5
      kundenbericht.py
      netzregel.py
      poc.py
      test_*.py
  agents/
    opus-xhigh.md
    sonnet-xhigh.md
    sonnet-high.md
```

## Skill-Details

### `gpt-image-skill`

Dieser Skill ist fuer Bildgenerierung mit der OpenAI Images API ausgelegt.
Er wird laut `SKILL.md` verwendet, wenn ein Nutzer ein Bild generieren,
zeichnen oder visualisieren lassen will.

**Workflow**
- Uebernimmt den Nutzerprompt und uebersetzt ihn bei Bedarf nach Englisch.
- Ruft `generate_image.js` mit Prompt, optionalem Modell und optionaler Bildgroesse auf.
- Speichert das Ergebnis als `/mnt/user-data/outputs/generated_image.png`.
- Praesentiert das Bild anschliessend im Chat.

**Technische Eckdaten**
- API: `POST /v1/images/generations`
- Standardmodell: `gpt-image-1`
- Weitere vorgesehene Modelle: `gpt-image-1.5`, `gpt-image-1-mini`
- Standardgroesse: `1024x1024`
- Alternative Groessen: `1536x1024`, `1024x1536`

**Voraussetzungen**
- `OPENAI_API_KEY` muss gesetzt sein
- Node.js muss verfuegbar sein
- Schreibzugriff auf `/mnt/user-data/outputs/`

**Beispiel**

```bash
node /home/claude/gpt-image-skill/generate_image.js \
  "A chrome banana floating in space, cyberpunk style, 8k"
```

### `seo-ecommerce-pdp`

Dieser Skill ist auf E-Commerce Product Detail Pages (PDP) spezialisiert. Er deckt
sowohl die klassische Suchsichtbarkeit (Google Shopping, organische Treffer, Rich
Results) als auch die Sichtbarkeit in KI-Systemen (ChatGPT, Gemini, Perplexity,
AI Overviews) ab.

**Zwei Betriebsmodi**
- Schreib-Modus: erstellt oder ueberarbeitet eine Produktseite und liefert ein
  fertiges HTML-Snippet plus JSON-LD Schema, einsetzbar in Shopify, WooCommerce,
  Shopware oder Custom Shops.
- Score-Modus: bewertet eine bestehende PDP per URL und gibt einen Score von
  0 bis 100 (50 Prozent SEO, 50 Prozent GEO) plus priorisierte Empfehlungen aus.

**Workflow Schreib-Modus**
- Laedt zuerst `references/pdp-regelwerk.md`.
- Sammelt Pflichtfelder (Name, Kategorie, Marke, Preis, Verfuegbarkeit, USPs)
  und optionale Score-Hebel (GTIN, MPN, SKU, Reviews, Versand, Rueckgabe etc.).
- Generiert Title, Meta, H1, Hero, USP-Bullets, Langtext, Spec-Tabelle,
  FAQs und Bilder-Spezifikation.
- Befuellt die Templates `templates/pdp-snippet.html` und
  `templates/product-schema.jsonld` und gibt copy-paste-fertigen Output aus.

**Workflow Score-Modus**
- Ruft `scripts/analyze_pdp.py <URL>` auf (Playwright/Chromium mit HTML-Fallback).
- Extrahiert Product-Schema, Preise, Reviews, Variants, Trust-Signale,
  Versand- und Rueckgabe-Hinweise, Bilder und prueft AI-Crawler-Zugriffe.
- Bewertet 12 Kategorien (6 SEO, 6 GEO) und liefert einen Score-Bericht mit
  priorisierten Befunden, Schema-Vorschlaegen und naechsten Schritten.

**Voraussetzungen**
- Python 3 fuer den Analyzer, Dependencies werden bei Bedarf selbst installiert
- Webzugriff fuer Modus B
- Im Schreib-Modus reicht reine Promptarbeit, optional mit Webrecherche fuer
  Wettbewerber-PDPs

**Wichtige Regeln aus dem Skill**
- Niemals Reviews, Ratings oder GTINs erfinden, fehlende Felder weglassen
- Keine Hersteller-Texte 1:1 uebernehmen
- Keine HowTo- oder FAQPage-Schemas als Rich-Result-Hebel verkaufen
- Keine generischen SEO-Floskeln, kein Keyword-Stuffing, keine Gedankenstriche
- Im Score-Modus keine Werte raten, was nicht messbar ist, klar als
  "nicht messbar" ausweisen

**Referenzen**
- `references/pdp-regelwerk.md`: Schreib-Regeln (Teil A), Bewertungsmatrix
  (Teil B), Plattform-Spezifika (Teil C)
- `templates/pdp-snippet.html`: HTML-Vorlage fuer Shopify, WooCommerce,
  Shopware und Custom Shops
- `templates/product-schema.jsonld`: JSON-LD Vorlage fuer Product Schema
- `scripts/analyze_pdp.py`: Headless-Chromium-Analyzer mit HTML-Fallback

### `seo-geo-writer`

Dieser Skill ist fuer lange Blogartikel gedacht, die gleichzeitig klassisch fuer
Suchmaschinen und zusaetzlich fuer KI-Systeme wie ChatGPT, Gemini, Perplexity
oder AI Overviews optimiert werden sollen.

**Workflow**
- Laedt immer zuerst `references/regelwerk.md`.
- Erkennt automatisch, ob ein bestehender Artikel optimiert, ein Thema
  recherchiert oder ein Keyword direkt ausgearbeitet werden soll.
- Fuehrt je nach Modus Webrecherche zu Suchintention, Top-Ergebnissen,
  aktuellen Daten und Content-Luecken durch.
- Erstellt den Artikel nach festen SEO- und GEO-Vorgaben inklusive Metadaten,
  TL;DR, H2-Struktur, FAQ, Quellen und Nachbereitung.
- Prueft den Output gegen eine explizite interne Checkliste.

**Eingabemodi**
- Bestehenden Artikel optimieren
- Recherche plus Artikel schreiben
- Keyword-basierten Artikel erstellen

**Wichtige Regeln aus dem Skill**
- Zielkeyword muss im ersten Satz und in der ersten H2 stehen
- 50 bis 60 Prozent der H2-Sektionen sollen als Content Capsules aufgebaut sein
- Quellen muessen kontextuell im Fliesstext erscheinen, nicht gesammelt am Ende
- Der Artikel soll konkrete Daten, Entitaeten, interne Link-Vorschlaege,
  externe Quellen, FAQ und Bildvorschlaege enthalten
- Keine generischen SEO-Floskeln, kein Keyword-Stuffing, keine Gedankenstriche

**Referenzen**
- `regelwerk.md`: vollstaendiges SEO- und GEO-Regelwerk mit Recherche-,
  Struktur-, Quellen-, E-E-A-T- und Technikvorgaben

### `seo-page-review`

Dieser Skill ist ein Single-Page-Auditor. Er analysiert genau eine URL technisch
exakt und gibt einen gewichteten Score (0-100, 50 Prozent SEO + 50 Prozent GEO)
plus eine priorisierte Maengelliste mit konkreten Handlungsempfehlungen aus.
Im Unterschied zu `seo-ecommerce-pdp` ist er nicht produktseitenspezifisch,
sondern fuer beliebige Seitentypen (Artikel, Landingpage, Service-Seite etc.).

**Workflow**
- Laedt zuerst `references/checkliste.md` als Single Source of Truth fuer
  Punkteschema und Schwellenwerte.
- Fuehrt `scripts/analyze_page.py <URL>` aus (Playwright/Chromium mit
  HTML-Fallback ueber requests + BeautifulSoup).
- Extrahiert Title, Meta, Headings, Links, Bilder, Schema, robots.txt-Hinweise,
  Groessen und Ladezeit-Indikatoren als JSON.
- Prueft GEO-spezifisch: AI-Crawler-Zugriff (GPTBot, ClaudeBot, PerplexityBot,
  Google-Extended, OAI-SearchBot), llms.txt, Content Capsule Coverage,
  Entity Density.
- Bewertet 12 Kategorien (6 SEO, 6 GEO) und liefert einen Bericht mit
  Score-Card, priorisierten Befunden, Empfehlungen nach Aufwand,
  Schema-Vorschlaegen als JSON-LD und naechsten Schritten.

**Voraussetzungen**
- Python 3, Dependencies werden vom Skript bei Bedarf selbst installiert
- Webzugriff zur URL und zur robots.txt der Domain
- Optional Webrecherche fuer SERP- und Wettbewerbskontext

**Wichtige Regeln aus dem Skill**
- Nur eine URL pro Review, kein Bulk-Audit
- Keine erfundenen Werte, was nicht messbar ist (z.B. echte Core Web Vitals,
  INP, Backlinks), wird explizit als "nicht messbar" ausgewiesen
- Keine HowTo- oder FAQPage-Schemas als Rich-Result-Hebel verkaufen
- Render-Modus (Playwright vs. HTML-Fallback) immer offenlegen
- Keine generischen Floskeln, keine Gedankenstriche, direkter und
  technisch-praeziser Ton

**Referenzen**
- `references/checkliste.md`: vollstaendige Bewertungsmatrix mit Punkteschema,
  Schwellenwerten und Output-Format
- `scripts/analyze_page.py`: Headless-Chromium-Analyzer mit HTML-Fallback

### `viral-post-wizard`

Dieser Skill ist ein spezialisierter Schreibassistent fuer LinkedIn-Posts im
Stil von Nikolaus Schausberger. Er ist auf Personal-Brand-Content, Post-Ideen,
Umschreiben bestehender Entwuerfe und das Ausarbeiten von Voice Notes oder
Themen in postfaehige Fassungen ausgelegt.

**Workflow**
- Analysiert das Nutzer-Input und waehlt einen passenden Content-Typ.
- Laedt vor jeder Ausgabe vier Referenzdateien aus `references/`.
- Erstellt standardmaessig drei Varianten eines Posts.
- Fuehrt eine Qualitaetskontrolle gegen Voiceprint, Identitaet und Disallow List durch.
- Verlangt explizit einen Faktencheck statt freier Erfindungen.

**Referenzen**
- `viral_framework.md`: Hook-Regeln, SLAY-Framework, Formatierung
- `ghostwriter_spickzettel.md`: Persona, Werte, rote Linien
- `voiceprint.md`: Sprachstil, Tonalitaet, syntaktische Muster
- `disallow_list.md`: verbotene Woerter, Phrasen und Satzzeichen

**Wichtige Regeln aus dem Skill**
- Keine halluzinierten Fakten, Zahlen oder Erfahrungen
- Hook in der ersten Zeile mit weniger als 8 Woertern
- Abschnitte kurz halten, mit Leerzeilen dazwischen
- Disallow List als harte Abschlusskontrolle behandeln
- Im Regelfall drei Varianten liefern, ausser der Nutzer will gezielt nur eine

## Coding-Workflow-Skills (Claude Code)

`pr-review-loop`, `fix-findings`, `auto-feature`, `feature-file` und `security-audit` sind globale Claude-Code-Skills.
Sie werden per Symlink eingebunden:

```bash
for s in pr-review-loop fix-findings auto-feature feature-file security-audit; do ln -sfn ~/Projects/skillz/nikskills/$s ~/.claude/skills/$s; done
for a in opus-xhigh sonnet-xhigh sonnet-high; do ln -sfn ~/Projects/skillz/nikskills/agents/$a.md ~/.claude/agents/$a.md; done
```

`pr-review-loop`, `auto-feature` und `feature-file` setzen `effort: xhigh` im Frontmatter, `auto-feature` und `feature-file` zusaetzlich `model: opus`; `fix-findings` setzt `effort: high`.
Die Subagenten bekommen Effort ueber die Agent-Typen `opus-xhigh`/`sonnet-xhigh`/`sonnet-high`; fehlen sie,
weichen die Skills auf `general-purpose` mit explizitem `model` aus und melden „Effort nicht garantiert“.
`security-audit` nutzt `opus-xhigh` fuer Reviewer und Pruefer, sonst `general-purpose` mit `model: opus` und „Effort nicht garantiert“.

`security-audit` (nur pruefen, aendert das Repo nie): Kundenrepos frisch klonen. Enthaelt das Repo eigene
`.claude/`- oder `.mcp.json`-Konfiguration, die Session mit `claude --setting-sources user --strict-mcp-config`
starten und `/security-audit … repo-konfig-geprueft` aufrufen. Die Netzregel (`scripts/netzregel.py`) ist nur
Erkennung; die eigentliche Sperre ist die Rechtekonfiguration der Session.

Werkzeuge fuer Abhaengigkeiten und Secrets: `brew install osv-scanner gitleaks`. Fehlt eines, laeuft das Audit
weiter und der Bericht nennt „osv-scanner fehlt“ bzw. „gitleaks fehlt“. Netz nutzen nur die Skripte selbst
(OSV-API ueber osv-scanner, CISA-KEV-Katalog).

KI- und Agenten-Apps (TF3): `ki.py erkennen` findet LLM- und Agenten-SDKs in den `package.json` der Arbeitskopie
und meldet „KI-Pruefpunkte: angewendet (…)“ bzw. „nicht anwendbar (…)“ im Bericht. Bei Treffern kommt eine Flaeche
„KI/Agent“ dazu (Pruefpunkte `references/pruefpunkte-ki.md`). `poc.py starten --modell-mock openai,anthropic` startet
einen Modell-Mock als Container `llm` im internen Netz der Rolle; die Pruefer belegen Befunde mit Marker und
Protokoll (`poc.py modell`), der Befund traegt dann `annahme_modell` („Modell folgt“). Eine echte Modell-API wird nie
aufgerufen. Azure, Bedrock, Vertex und Gemini laufen nicht ueber den Mock.

Kundenbericht (TF4): `kundenbericht.py erstellen --json <ausgabe_ordner>/<basisname>.json` schreibt `<basisname>-kunde.md` und
`<basisname>-kunde.pdf` neben das Bericht-JSON. Das PDF entsteht in zwei Stufen ohne Netz und ohne Dateizugriff aus Daten (pandoc
`--sandbox`, HTML-Pruefung, weasyprint `--allowed-protocols ''`). Mindestversionen: pandoc ≥ 2.15 (fuer `--sandbox`), weasyprint mit
Option `--allowed-protocols` (geprueft mit 68.1). Fehlt eines der Werkzeuge, bleibt das Markdown (Exit 3). Der Projektname im Kopf
kommt aus `projekt="…"` im Aufruf von `/security-audit`; ohne ihn steht dort der Ordner- bzw. Repo-Name samt Hinweis.

Tests fuer `security-audit`:

```bash
python3 -m pytest security-audit -q
# Docker-Integration (braucht Docker)
SECURITY_AUDIT_DOCKER=1 python3 -m pytest security-audit/scripts/test_poc_docker.py -q
# Modell-Mock gegen die echten SDKs (braucht npm, Netz zur npm-Registry und Node ≥ 22)
SECURITY_AUDIT_SDK_VERTRAG=1 SECURITY_AUDIT_SDK_NODE=<node ≥ 22> python3 -m pytest security-audit/scripts/test_llm_mock.py -k vertrag -q
# Abnahme-Eval: startet `claude -p` mit Opus und bis zu 8 Subagenten,
# grob 0,5–1 Mio. Tokens je Lauf; braucht Docker
SECURITY_AUDIT_EVAL=1 python3 -m pytest security-audit/evals -q
# Kundenbericht mit den echten Werkzeugen pandoc und weasyprint (ohne Docker, ohne Netz; die Standard-Suite stubbt sie)
SECURITY_AUDIT_PDF=1 python3 -m pytest security-audit/scripts/test_kundenbericht.py -q
# TF2-Evals einzeln: Lieferkette/Secrets, Regression, Lauf ohne Werkzeuge
SECURITY_AUDIT_EVAL=1 python3 security-audit/evals/run_eval.py --fixture fixture-deps
SECURITY_AUDIT_EVAL=1 python3 security-audit/evals/run_eval.py --fixture fixture-web --ohne-lockfile --ohne gitleaks,osv-scanner,docker --erwartung expected/fixture-web-ohne.json
```

`SECURITY_AUDIT_SDK_NODE` muss auf die echte Node-Binaerdatei zeigen, nicht auf einen Versions-Manager-Shim (nvm, volta,
asdf, mise): Ein Shim setzt `PWD` und `SHLVL`, und der Lauf endet dann mit Exit 4 (Fehlalarm des Waechters).

Aufruf mit Argumenten, z. B. `/pr-review-loop 214 215` (je PR ein neuer Fixer, keine Rundengrenze) oder `/pr-review-loop 214 "Fixer 214" runden=3`, `/fix-findings <Liste> [mergen] [deployen]`,
`/auto-feature docs/features/<datei>.md`. Projektspezifische Befehle (Tests, Lint, Deploy)
stehen im jeweiligen Repo-`CLAUDE.md`, nicht in den Skills.

Gemeinsame harte Regel: Kein Skill merged oder deployt von sich aus. `fix-findings` tut es
nur auf ausdrückliches Befehlswort des Users (in den Argumenten oder im eigenen Begleitsatz,
bzw. ein „ja“ auf die Rückfrage, wenn der Merge automatisch deployt); die anderen nie. Auf dem Audit-Weg (Befundliste aus `security-audit`, kein PR) tut es auch `fix-findings` nie.

## Laufzeitannahmen

Die Skills sind nicht als generisches NPM-Paket aufgebaut, sondern als
Prompt-Dateien plus Hilfsartefakte fuer eine agentische Laufzeitumgebung.

Insbesondere `gpt-image-skill` erwartet in seiner aktuellen Form:
- eine Skill-Installation unter `/home/claude/<skill-name>/`
- einen Output-Ordner unter `/mnt/user-data/outputs/`
- eine Laufzeit, die Shell-Kommandos und Dateipraesentation im Chat unterstuetzt

`seo-geo-writer` setzt zusaetzlich eine Umgebung voraus, in der Webrecherche
moeglich ist, weil der Skill explizit auf aktuelle Suchergebnisse, Daten,
Studien und Quellen aufbaut.

Wenn du die Skills in einer anderen Umgebung einsetzen willst, musst du
insbesondere Pfade und Ausgabehandling anpassen.

## Pflegehinweise

- `SKILL.md` ist jeweils die kanonische Quelle fuer Trigger und Workflow.
- Support-Dateien in `references/` und Scripts muessen zur `SKILL.md` passen.
