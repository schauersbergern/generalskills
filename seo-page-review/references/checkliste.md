# SEO & GEO Page Review: Bewertungsmatrix

## Zweck dieses Dokuments

Diese Matrix definiert das vollständige Punkteschema für den Page Review. Jede Kategorie wird auf 0 bis 100 Punkte normalisiert. Der Gesamtscore ist der gewichtete Durchschnitt aus SEO-Score (50%) und GEO-Score (50%).

Alle Schwellenwerte basieren auf aktuellen Studien (Stand 2025/2026), Google-Dokumentation und Best Practices aus dem GEO-Forschungsfeld (Princeton GEO Paper, Botify-Studien zu LLM-Citations, Search Engine Land, Search Engine Journal).

---

## Gesamtgewichtung

```
Gesamtscore = 0,5 × SEO-Score + 0,5 × GEO-Score

SEO-Score (gewichteter Durchschnitt):
  On-Page SEO         25%
  Content-Qualität    20%
  Technik & Meta      20%
  Schema Markup       15%
  Bilder & Medien     10%
  Performance         10%

GEO-Score (gewichteter Durchschnitt):
  Content-Struktur    25%
  E-E-A-T Signale     20%
  AI-Crawler-Zugriff  15%
  Citability          20%
  Entitäten           10%
  Aktualität          10%
```

---

## TEIL A: SEO-KATEGORIEN

### A.1 On-Page SEO (25% des SEO-Scores)

Maximalpunkte: 100. Verteilt auf folgende Kriterien:

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Title Tag vorhanden | 5 | Ja: 5, Nein: 0 |
| Title-Länge | 10 | 50-60 Zeichen: 10, 40-49 oder 61-65: 7, 30-39 oder 66-70: 4, sonst: 0 |
| Title enthält Zielkeyword | 10 | Vorne (erste 30 Zeichen): 10, irgendwo: 6, nicht: 0 |
| Meta Description vorhanden | 5 | Ja: 5, Nein: 0 |
| Meta Description Länge | 8 | 140-160 Zeichen: 8, 120-139 oder 161-170: 5, sonst: 2, fehlt: 0 |
| Meta Description Keyword | 5 | Enthält Zielkeyword: 5, sonst: 0 |
| H1 vorhanden, genau eine | 10 | Genau 1: 10, 0 oder >1: 0 |
| H1 enthält Zielkeyword | 5 | Ja: 5, Nein: 0 |
| H2-H6 Hierarchie korrekt | 10 | Keine übersprungenen Level: 10, ein Sprung: 6, mehrere Sprünge: 2 |
| Mind. 4 H2-Überschriften | 5 | Ja: 5, 2-3: 3, weniger: 0 |
| URL-Struktur | 10 | Kurz (≤75 Zeichen), bindestrich-getrennt, keine Query-Parameter, Keyword enthalten: 10. Pro Verstoß: -2 |
| Interne Links vorhanden | 8 | ≥3: 8, 1-2: 4, 0: 0 |
| Externe Links zu Autoritäten | 5 | ≥2: 5, 1: 3, 0: 0 |
| Anchor-Text aussagekräftig | 4 | <20% generisch ("hier", "klick"): 4, 20-50%: 2, mehr: 0 |

**Hinweis:** Wenn der User kein Zielkeyword angibt, wird heuristisch das häufigste mehrwortige Substantiv-Cluster aus Title/H1/Meta als Zielkeyword angenommen und in der Annahmensektion offengelegt.

### A.2 Content-Qualität (20% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Wortzahl angemessen | 15 | Informational ≥1500: 15, ≥1000: 10, ≥600: 6, <600: 2 |
| Lesbarkeit (Flesch DE / Amstad) | 10 | 50-70: 10, 40-49 oder 71-80: 7, 30-39 oder 81-90: 4, sonst: 1 |
| Absatzlänge | 10 | Durchschnittlich 80-180 Wörter: 10, 50-79 oder 181-220: 6, sonst: 3 |
| Listen oder Tabellen vorhanden | 10 | Mindestens 1 strukturierte Liste UND 1 Tabelle: 10. Nur eines: 6. Keines: 0 |
| Keine Keyword-Stuffing | 10 | Keyword-Vorkommen <3% relativ: 10, 3-5%: 5, >5%: 0. Hinweis: Dichte ist nicht ranking-relevant, aber Stuffing schadet |
| Erkennbare Originalität | 15 | Manuell zu prüfen: enthält Beispiele, Fallzahlen, Zitate, Erfahrungsmarker (Pronomen "wir", "ich", "unsere Kunden") und Quellen-Verlinkungen im Fließtext. Voll: 15, teilweise: 8, fehlt: 0 |
| Aktualitätshinweis (Datum) | 10 | "Zuletzt aktualisiert" oder Datums-Markup ≤12 Monate: 10, ≤24 Monate: 6, älter oder fehlt: 0 |
| Keine Boilerplate-Floskeln | 10 | Manuell: kein "In der heutigen digitalen Welt", "Zweifellos", "Im Folgenden werden wir": 10. 1-2 Vorkommen: 5, mehr: 0 |
| Inhalts-Tiefe (über Definition hinaus) | 10 | Liefert Daten, Vergleiche, Anwendungsbeispiele: 10, nur generische Erklärung: 4, oberflächlich: 0 |

### A.3 Technik & Meta (20% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Canonical Tag korrekt | 10 | Self-referencing oder zielrichtig: 10, fehlt: 5, falsch (zeigt auf andere Domain): 0 |
| Meta Robots | 10 | index,follow (oder leer = default): 10, noindex unbeabsichtigt: 0 |
| HTTP-Status 200 | 10 | 200: 10, 301/302 mit Final 200: 6, 4xx/5xx: 0 |
| HTTPS aktiv | 10 | HTTPS: 10, HTTP: 0 |
| Open Graph komplett | 10 | og:title, og:description, og:image, og:url, og:type alle vorhanden: 10. Pro fehlendes Pflichtfeld: -2 |
| Twitter Card | 5 | twitter:card vorhanden: 5, fehlt: 0 |
| Hreflang (wenn multilingual) | 10 | Korrekte Implementierung: 10, fehlt: 5, fehlerhaft: 0. Wenn nicht multilingual: 10 (default) |
| Sprachattribut html lang | 5 | Vorhanden und korrekt: 5, fehlt: 0 |
| Charset deklariert | 5 | UTF-8 deklariert: 5, fehlt: 0 |
| Mobile Viewport Meta | 5 | width=device-width: 5, fehlt: 0 |
| Sitemap referenziert (robots.txt) | 5 | Sitemap-Link in robots.txt: 5, sonst: 0 |
| Keine fatalen Konsole-Errors | 5 | Aus HTML allein nicht messbar, default 5. Wenn Browser-Render Fehler liefert: -X |
| robots.txt erreichbar und gültig | 10 | 200 + parsbar: 10, fehlt oder 5xx: 4 |

### A.4 Schema Markup (15% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Mind. ein Schema vorhanden | 20 | Ja: 20, Nein: 0 |
| Schema im JSON-LD Format | 10 | JSON-LD: 10, Microdata: 6, RDFa: 4, fehlt: 0 |
| Schema-Typ passt zum Seitentyp | 20 | Article auf Blog, Product auf PDP, Organization auf Homepage etc.: 20. Falsch: 5, fehlt: 0 |
| Alle Pflichtfelder gefüllt | 20 | Alle erforderlichen Properties ausgefüllt: 20. Pro fehlendes Pflichtfeld: -4 |
| Mehrere passende Schemas | 15 | Article + BreadcrumbList + Person/Organization: 15. Zwei: 10, eines: 5 |
| Validität (kein @context-Fehler) | 15 | Korrekt: 15, fehlerhaft: 0 |

**Wichtige Klarstellung:**
- **HowTo und FAQPage** sind NICHT deprecated. Sie werden seit August 2023 nur noch eingeschränkt für Rich Snippets in den SERPs angezeigt (FAQPage: nur autoritative Behörden- und Gesundheitsseiten, HowTo: stark zurückgefahren).
- Für **GEO** (KI-Lesbarkeit) bleiben sie nützlich.
- Empfehle sie also **nicht aktiv für Rich Snippets**, aber **markiere sie nicht als fehlerhaft**, wenn sie vorhanden sind. Keine Punkte abziehen.

### A.5 Bilder & Medien (10% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Alle Bilder haben alt-Attribut | 25 | 100%: 25, 80-99%: 18, 50-79%: 10, <50%: 0 |
| Alt-Texte beschreibend | 15 | Stichprobe: nicht generisch ("image1.jpg", "Bild"): 15, gemischt: 8, schlecht: 0 |
| width/height gesetzt (CLS) | 15 | 100%: 15, ≥80%: 10, <80%: 4 |
| loading="lazy" auf Below-Fold | 10 | Vorhanden auf späteren Bildern: 10, teilweise: 5, nie: 0 |
| Modernes Format (WebP/AVIF) | 15 | ≥80% modern: 15, gemischt: 8, nur JPEG/PNG: 4 |
| Dateigrößen (heuristisch) | 10 | Aus HTTP-Headern, falls verfügbar: keine Datei >500KB: 10, eine: 5, mehrere: 0. Nicht messbar: default 7 |
| Bilder vorhanden | 5 | Mindestens 1 Bild: 5, keines: 0. Texte ohne Bilder ranken schlechter |
| OG Image vorhanden | 5 | og:image gesetzt UND erreichbar: 5, gesetzt aber 404: 2, fehlt: 0 |

### A.6 Performance (10% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| HTML-Größe | 15 | <100KB: 15, <300KB: 10, <600KB: 5, mehr: 0 |
| Anzahl Render-blocking Scripts | 15 | 0: 15, 1-2: 10, 3-5: 5, mehr: 0. Render-blocking = `<script>` ohne async/defer im Head |
| Anzahl externe CSS-Dateien | 10 | ≤3: 10, 4-6: 6, mehr: 2 |
| Anzahl Fonts | 10 | ≤2 Family: 10, 3-4: 6, mehr: 2 |
| Preload für LCP-Ressourcen | 10 | Vorhanden: 10, fehlt aber LCP-Bild groß: 0, neutral: 7 |
| Lazy-loading für Iframes | 5 | Alle Iframes lazy: 5, keine Iframes: 5, sonst: 0 |
| Total Resource Count | 10 | <50: 10, 50-100: 6, mehr: 2 |
| Server-Response-Zeit (TTFB) | 15 | <500ms: 15, <1000ms: 10, <2000ms: 5, mehr: 0 |
| HTTP/2 oder HTTP/3 | 10 | Ja: 10, HTTP/1.1: 4 |

**Hinweis:** Echte Core Web Vitals (LCP, INP, CLS) sind aus HTML allein nicht messbar. Wenn du Live-Daten brauchst, empfiehl dem User, zusätzlich PageSpeed Insights laufen zu lassen, oder integriere die PSI-API in einer späteren Skill-Version.

---

## TEIL B: GEO-KATEGORIEN

### B.1 Content-Struktur (25% des GEO-Scores)

GEO-Studien (u.a. Princeton GEO 2023, Botify 2024, Search Engine Land 2025) zeigen klar, dass strukturierter Content mit klaren Frage-Antwort-Mustern signifikant häufiger von LLMs zitiert wird.

| Kriterium | Punkte | Bewertung |
|---|---|---|
| TL;DR oder Kurz-Zusammenfassung am Anfang | 15 | Vorhanden, 3-5 Sätze, Keyword im ersten Satz: 15. Vorhanden ohne Keyword: 10. Fehlt: 0 |
| Content Capsule Coverage | 25 | Anteil der H2 mit Frage-Format und 40-80 Wort-Antwort: ≥50%: 25, 30-49%: 15, 10-29%: 8, <10%: 0 |
| Inverted Pyramid je Sektion | 15 | Stichprobe: Kernaussage in den ersten 80 Tokens jeder Sektion: konsistent: 15, gemischt: 8, fehlt: 0 |
| FAQ-Sektion vorhanden | 15 | 5-8 Fragen mit Antworten 40-60 Wörter: 15. 3-4 Fragen oder kürzere/längere Antworten: 8. Fehlt: 0 |
| Tabellen oder Vergleiche | 10 | Mind. eine HTML-Tabelle oder strukturierter Vergleich: 10, fehlt: 0 |
| Listen-Anteil | 10 | 10-30% des Contents in Listenform: 10. <10% oder >40%: 5 |
| Aussagen-Pro-Absatz | 10 | Heuristik: Absätze 80-180 Wörter, eine Hauptaussage: 10, gemischt: 5, schlecht: 0 |

### B.2 E-E-A-T Signale (20% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Autor sichtbar | 15 | Autorname mit Verlinkung zur Bio: 15, nur Name: 8, fehlt: 0 |
| Autoren-Schema (Person) | 10 | Person-Schema mit jobTitle, sameAs: 10, ohne sameAs: 5, fehlt: 0 |
| Veröffentlichungsdatum | 10 | datePublished sichtbar UND im Schema: 10, nur sichtbar: 6, fehlt: 0 |
| Aktualisierungsdatum | 10 | dateModified ≤12 Monate: 10, ≤24 Monate: 6, älter oder fehlt: 0 |
| Quellenangaben im Fließtext | 15 | ≥1 externe Quelle pro 200 Wörter, kontextuell verlinkt: 15. Weniger: 8. Keine: 0. Quellen am Ende als "Literatur" zählen NICHT |
| Erfahrungsmarker | 10 | "Wir haben getestet", "In meinen 5 Jahren", "unsere Kunden": 10. Vereinzelt: 5. Fehlt: 0 |
| Über-Uns / Impressum verlinkt | 10 | Beide aus Footer erreichbar: 10, eines: 5, keines: 0 |
| Kontakt sichtbar | 5 | E-Mail oder Formular im Footer: 5, fehlt: 0 |
| Erkennbare Marke | 10 | Logo, konsistente Domain, Organization-Schema: 10, teilweise: 5, fehlt: 0 |
| HTTPS + Trust-Indikatoren | 5 | HTTPS und Datenschutz-Link sichtbar: 5, fehlt: 0 |

### B.3 AI-Crawler-Zugriff (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| GPTBot erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0 |
| OAI-SearchBot erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0 |
| ChatGPT-User erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| ClaudeBot erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| Anthropic-AI erlaubt | 5 | Allow oder kein Eintrag: 5. Disallow: 0 |
| PerplexityBot erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| Google-Extended erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0. **Wichtig:** Google-Extended steuert die Verwendung in Gemini und AI Overviews |
| CCBot erlaubt | 5 | Allow oder kein Eintrag: 5. Disallow: 0. (Common Crawl, Trainingsdaten vieler LLMs) |
| Bytespider erlaubt | 5 | Allow oder kein Eintrag: 5. Disallow: 0. (ByteDance, für Doubao etc.) |
| Sitemap zugänglich | 10 | Sitemap-Pfad in robots.txt UND erreichbar: 10, fehlt: 0 |

**Hinweis:** Wenn die Domain bewusst manche Crawler blockiert (z.B. CCBot wegen Trainingsdaten-Bedenken), kann das eine bewusste Entscheidung sein. Trotzdem hart bewerten, der User soll die Trade-offs sehen.

### B.4 Citability (20% des GEO-Scores)

Citability misst, wie zitierfähig die Inhalte für LLMs sind. Studien (Botify, Search Engine Land) zeigen, dass optimal zitierte Passagen 134-167 Wörter umfassen, eigenständig sind und faktendicht.

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Optimale Passagen-Länge | 20 | Anteil der Absätze 120-180 Wörter: ≥60%: 20, 40-59%: 12, 20-39%: 6, <20%: 0 |
| Faktendichte | 15 | Heuristik: Anteil der Sätze mit konkreten Zahlen, Daten, Eigennamen: ≥30%: 15, 15-29%: 8, <15%: 0 |
| Eigenständige Sektionen | 15 | Jede H2 funktioniert als Mini-Landing (kein "Wie oben erwähnt..."): durchgängig: 15, gemischt: 8, schlecht: 0 |
| Antwort vor Erklärung | 15 | Sektionen beantworten ihre Frage in den ersten 2-3 Sätzen: durchgängig: 15, gemischt: 8, schlecht: 0 |
| Klare Definitionen | 10 | Mind. 1 sauber definierter Schlüsselbegriff (X ist Y, das macht Z): 10, fehlt: 0 |
| Vergleichende Aussagen | 10 | Mind. ein expliziter Vergleich (X vs Y, im Gegensatz zu, besser als): 10, fehlt: 0 |
| Quotierbare Statements | 10 | Kurze, eigenständige Aussagen, die isoliert Sinn ergeben: durchgängig: 10, gemischt: 5, fehlt: 0 |
| Keine Marketing-Lyrik | 5 | Niedriger Anteil an Superlativen ohne Beleg ("die beste", "revolutionär"): 5, hoch: 0 |

### B.5 Entitäten (10% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Entitätendichte | 25 | Mind. 15 benannte Entitäten pro 1000 Wörter: 25. 10-14: 15, 5-9: 7, <5: 0 |
| Marken/Tools/Frameworks namentlich | 20 | Konkret benannt statt "ein bekanntes Tool": 20, gemischt: 10, generisch: 0 |
| Personen mit Position | 15 | Wenn Personen zitiert: Name + Funktion + Quelle: 15, nur Name: 7, anonyme Aussagen: 0. Falls keine Personen-Zitate: neutral 12 |
| Verlinkungen zu Wikipedia/Wikidata | 10 | Mind. 1 Wikipedia/Wikidata-Link für zentrale Entität: 10, fehlt: 0 |
| sameAs in Schema | 10 | Person-/Organization-Schema mit sameAs zu LinkedIn, Wikipedia, etc.: 10, fehlt: 0 |
| Konsistente Schreibweise | 10 | Markenname/Begriffe einheitlich geschrieben: 10, inkonsistent: 0 |
| Branchenspezifische Begriffe | 10 | Fachbegriffe statt Umschreibungen: 10, gemischt: 5, vermieden: 0 |

### B.6 Aktualität (10% des GEO-Scores)

LLMs bevorzugen frische Inhalte, insbesondere für transaktionale und News-Themen.

| Kriterium | Punkte | Bewertung |
|---|---|---|
| dateModified im Schema | 25 | Vorhanden und ≤6 Monate: 25, ≤12 Monate: 18, ≤24 Monate: 10, älter: 3, fehlt: 0 |
| Sichtbares Aktualisierungsdatum | 15 | Auf der Seite sichtbar (z.B. "Zuletzt aktualisiert: ..."): 15, fehlt: 0 |
| Verweise auf aktuelle Daten | 20 | Studien/Statistiken aus dem laufenden oder Vorjahr: 20, ältere referenziert: 10, datumlose Behauptungen: 0 |
| Aktuelle Tools/Begriffe | 15 | Erwähnt aktuelle Versionen, aktuelle Tools (z.B. nicht "GPT-3" wenn GPT-5 etabliert): 15, gemischt: 7, veraltet: 0 |
| Keine "broken" Verweise | 10 | Stichprobe externe Links: alle erreichbar: 10. 1 Bruch: 5. Mehrere: 0. Aus HTML nicht direkt prüfbar, Skript versucht HEAD-Requests |
| News/Update-Marker | 15 | Sichtbarer Hinweis auf jüngste Änderungen (z.B. "Update: ...", "Neu seit ..."): 15, fehlt: 0 |

---

## TEIL C: PÖNALEN UND BONI (kategorieübergreifend)

Diese werden zusätzlich auf den jeweils betroffenen Kategorie-Score angewendet, **nach** der Berechnung des Rohwerts. Floor bleibt 0.

### Pönalen
| Verstoß | Abzug | Kategorie |
|---|---|---|
| noindex aktiv ohne Grund | -50 | Technik & Meta |
| Cloaking erkennbar (verschiedene Inhalte für User vs. Bot) | -100 (Score=0) | Technik & Meta |
| Auto-generated Content ohne Mehrwert (heuristisch) | -25 | Content-Qualität |
| Mehrere H1 | -20 | On-Page SEO |
| Massives Keyword-Stuffing (>5% Dichte) | -30 | Content-Qualität |
| Wichtige AI-Crawler komplett blockiert (GPTBot+ClaudeBot+Google-Extended alle Disallow) | -40 | AI-Crawler-Zugriff |
| Schema mit Syntax-Errors | -15 | Schema |
| Inhalt nur per JS sichtbar (kein SSR/SSG) | -15 | Technik & Meta + Content-Qualität |

### Boni
| Stärke | Bonus | Kategorie |
|---|---|---|
| llms.txt vorhanden und gepflegt | +5 | AI-Crawler-Zugriff |
| Author-Bio mit Credentials und sameAs | +5 | E-E-A-T |
| Originaldaten/Studien auf der Seite | +10 | Content-Qualität |
| Mehrere passende Schemas korrekt verschachtelt | +5 | Schema |
| Sehr gute interne Verlinkung (≥10 thematisch relevant) | +5 | On-Page SEO |

---

## TEIL D: BERECHNUNGSALGORITHMUS

Pseudo-Code, den Claude bei der Auswertung anwendet:

```
für jede der 12 Kategorien:
    rohwert = summe der erreichten Punkte
    rohwert += boni_dieser_kategorie
    rohwert -= pönalen_dieser_kategorie
    rohwert = max(0, min(100, rohwert))
    kategoriescore = rohwert

seo_score = round(
    0.25 * onpage +
    0.20 * content_qualitaet +
    0.20 * technik_meta +
    0.15 * schema +
    0.10 * bilder_medien +
    0.10 * performance
)

geo_score = round(
    0.25 * content_struktur +
    0.20 * eeat +
    0.15 * ai_crawler +
    0.20 * citability +
    0.10 * entitaeten +
    0.10 * aktualitaet
)

gesamt = round(0.5 * seo_score + 0.5 * geo_score)
```

---

## TEIL E: BENCHMARK-INTERPRETATION

| Score | Einstufung | Bedeutung |
|---|---|---|
| 90-100 | Exzellent | Sowohl bei Google als auch bei KI-Systemen optimal aufgestellt |
| 75-89 | Gut | Solide Basis, einige Optimierungen können noch deutliche Wirkung haben |
| 60-74 | Mittelmäßig | Klare Schwächen vorhanden, Wettbewerb wird schneller ranken |
| 40-59 | Schwach | Mehrere kritische Defizite, hoher Handlungsbedarf |
| <40 | Mangelhaft | Grundlegende SEO/GEO-Hygiene fehlt, Komplettüberarbeitung nötig |

Werte unter 40 sollten besonders ausführlich erläutert werden, weil dort meist mehrere Grundlagen-Fehler zusammenkommen.

---

## TEIL F: HÄUFIGE FALLSTRICKE BEI DER BEWERTUNG

1. **Sprache der Seite beachten:** Die Flesch-Reading-Ease-Formel ist sprachspezifisch. Für Deutsch wird die Amstad-Anpassung verwendet. Das Skript erkennt die Sprache aus dem `lang`-Attribut.

2. **Single-Page-Apps:** Wenn der Render-Modus auf Fallback gesprungen ist, fehlen JS-gerenderte Inhalte. Das wird im Header explizit ausgewiesen. Absolute Score-Bewertungen bei reinem Fallback sind weniger zuverlässig.

3. **Branchenkontext:** B2B-SaaS-Landingpages sind anders zu bewerten als Blog-Artikel. Wenn der erkannte Seitentyp nicht zur erwarteten Tiefe passt (z.B. eine Service-Page mit 200 Wörtern), wird das nicht als "schlechte Wortzahl" gewertet, sondern in der Annahmensektion offengelegt.

4. **Lokale Domains:** Für lokale KMU-Seiten (de, at, ch) sollten lokale Schema-Properties (LocalBusiness, address, openingHours) bonusrelevant sein. Aktuell nicht in der Standardgewichtung, aber bei erkennbarem Local-Kontext explizit erwähnen.

5. **Forum/UGC/E-Commerce:** Diese Seitentypen haben andere Optimierungsschwerpunkte. Bei erkennbarem UGC-Anteil oder Produktdetailseiten klar im Bericht ausweisen, dass die Standardmatrix nur teilweise greift.

---

## TEIL G: KEINE-VOLLBEWERTUNG-OHNE-CONTEXT-REGEL

Wenn folgende Daten fehlen, gib **niemals einen Score** aus, sondern frage nach:

- Die URL ist nicht erreichbar (DNS, 4xx, 5xx)
- Die URL erfordert Login (401/403)
- Die Seite ist sehr klein (<100 Wörter sichtbarer Text) und scheint ein Platzhalter zu sein
- Der Content ist offensichtlich Auto-Generated/Spam und eine echte Bewertung wäre absurd

In diesen Fällen: Erkläre, was nicht funktioniert, biete Alternativen an (HTML einfügen, andere URL).
