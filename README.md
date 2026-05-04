# nikskills

Sammlung lokaler Skills fuer agentische Coding- und Content-Workflows.
Jeder Skill liegt in einem eigenen Verzeichnis mit einer `SKILL.md` als
Einstiegspunkt und optionalen Referenzen oder Scripts.

Der aktuelle Stand des Repos umfasst fuenf produktiv nutzbare Skills:

| Skill | Zweck | Wichtige Dateien |
|---|---|---|
| `gpt-image-skill` | Generiert Bilder ueber OpenAI `gpt-image-*` und speichert das Ergebnis als PNG | `gpt-image-skill/SKILL.md`, `gpt-image-skill/generate_image.js` |
| `seo-ecommerce-pdp` | Erstellt SEO- und GEO-optimierte E-Commerce Product Detail Pages (HTML + JSON-LD) oder bewertet bestehende Produktseiten mit Score 0-100 | `seo-ecommerce-pdp/SKILL.md`, `seo-ecommerce-pdp/references/pdp-regelwerk.md`, `seo-ecommerce-pdp/scripts/analyze_pdp.py`, `seo-ecommerce-pdp/templates/*` |
| `seo-geo-writer` | Erstellt oder optimiert SEO- und GEO-orientierte Blogartikel mit fester Recherche- und Strukturvorgabe | `seo-geo-writer/SKILL.md`, `seo-geo-writer/references/regelwerk.md` |
| `seo-page-review` | Auditiert eine einzelne URL und vergibt einen gewichteten Score (50% SEO + 50% GEO) mit priorisierten Befunden und Empfehlungen | `seo-page-review/SKILL.md`, `seo-page-review/references/checkliste.md`, `seo-page-review/scripts/analyze_page.py` |
| `viral-post-wizard` | Erstellt LinkedIn-Posts im Stil von Nikolaus Schausberger auf Basis fester Schreibregeln | `viral-post-wizard/SKILL.md`, `viral-post-wizard/references/*` |

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
