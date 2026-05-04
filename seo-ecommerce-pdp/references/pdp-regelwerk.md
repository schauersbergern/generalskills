# SEO & GEO PDP Regelwerk

## Zweck dieses Dokuments

Dieses Regelwerk definiert alle Regeln für E-Commerce Product Detail Pages (PDP):
- **Teil A:** Schreibregeln für den Schreib-Modus (Modus A)
- **Teil B:** Bewertungsmatrix für den Score-Modus (Modus B)
- **Teil C:** Plattform-Spezifika (Shopify, WooCommerce, Shopware)
- **Teil D:** Schema.org Pflichten und Empfehlungen
- **Teil E:** Häufige Fehler und Anti-Patterns

Stand 2025/2026. Basierend auf: Google Search Central Documentation (Product structured data, Merchant Listings), schema.org/Product, GEO-Forschung (Princeton GEO Paper, Botify-Studien zu LLM-Citations), Search Engine Land, Search Engine Journal.

---

## TEIL A: SCHREIBREGELN

### A.1 Suchintention bei PDPs

PDPs bedienen primär **transaktionale** Intention. Nutzer wissen, was sie wollen, und wollen kaufen oder vergleichen. Daraus folgt:

- Wichtigste Information (Was ist das? Was kostet es? Ist es lieferbar?) muss in den ersten 200 Tokens stehen.
- USPs vor Hintergrundgeschichte. Niemand will erst 5 Absätze Markenphilosophie lesen.
- Preis-Anker, Trust-Signale und CTA müssen "above the fold" funktionieren.

### A.2 Title Tag

**Format:** `[Produktname] [Differenzierungsmerkmal] | [Marke]`

**Regeln:**
- Maximal 60 Zeichen (Pixel-Limit ~580px)
- Produktname vorne, Marke hinten
- Differenzierungsmerkmal nur wenn relevant: Größe, Farbe, Edition, Modelljahr
- Keine Keyword-Spam-Listen ("kaufen | bestellen | online | günstig")

**Gut:** `Brompton P-Line Urban 12 Speed | Klapprad | Gravity Bikes`
**Schlecht:** `Brompton kaufen, Brompton günstig, Brompton P-Line Klapprad online bestellen`

### A.3 Meta Description

- 140-160 Zeichen
- Enthält: USP + Preisindikator (optional) + CTA
- Niemals "Klick hier" oder "Lies mehr" als CTA
- Aktuelle Preise nur einbauen, wenn das CMS sie automatisch aktualisiert

**Gut:** `Brompton P-Line mit 12-Gang-Schaltung, nur 9,9 kg leicht, in 60 Sekunden gefaltet. Versandkostenfrei ab 50 €. Jetzt online bestellen.`

### A.4 H1

- Genau eine H1 pro Seite
- Enthält Produktname und idealerweise das wichtigste Differenzierungsmerkmal
- Identisch oder sehr ähnlich zum Title Tag, aber muss nicht 1:1 sein

### A.5 Hero-Statement (erste 1-2 Sätze unter H1)

**Pflicht. GEO-kritisch.** Diese 1-2 Sätze sind das, was LLMs zitieren, wenn sie das Produkt erwähnen.

Format: `[Produkt] ist [Kategorie] für [Zielgruppe], [Hauptnutzen/USP]. [Optional: Differenzierung zum Wettbewerb in einem Halbsatz].`

**Gut:** "Das Brompton P-Line ist ein Premium-Klapprad für Pendler mit langen Wegen. Mit 9,9 kg ist es 1,5 kg leichter als die C-Line und nutzt eine 12-Gang-Schaltung statt der üblichen 6 Gänge."

**Schlecht:** "Entdecken Sie unser hochwertiges Brompton P-Line, das Ihren Alltag revolutionieren wird."

### A.6 USP-Bullets (3-5 Stück)

Jeder Bullet:
- 8-15 Wörter
- Faktenbasiert (Zahlen, Maße, Materialien, Vergleichsdaten)
- Eigenständig zitierbar (auch ohne Kontext verständlich)
- Keine Marketing-Lyrik

**Gut:**
- "Faltgewicht 9,9 kg, mit nur 60 Sekunden Faltzeit pendlertauglich"
- "12-Gang-Schaltung mit 33,5% mehr Übersetzungsspanne als die C-Line"
- "MIK-kompatibler Frontträger, max. Zuladung 10 kg"
- "Rahmen aus Stahl 4130, lebenslange Garantie auf den Hauptrahmen"

**Schlecht:**
- "Höchste Qualität für anspruchsvolle Kunden"
- "Innovative Technologie für Ihren Alltag"
- "Garantiert ein einzigartiges Fahrerlebnis"

### A.7 Lange Produktbeschreibung (300-500 Wörter, in Subsektionen)

Struktur in **3-4 H3-Subsektionen**, jede 80-150 Wörter:

1. **Was ist das Produkt und für wen?** (Kontext, Zielgruppe, Hauptanwendung)
2. **Was unterscheidet es?** (Vergleich zum Vorgänger oder Wettbewerber, konkrete Differenzierung)
3. **Technische Highlights** (Materialien, Konstruktion, besondere Features)
4. **Anwendungs-Szenarien** (Optional: konkrete Use Cases, "Für wen lohnt sich das?")

Jede Subsektion muss eigenständig funktionieren (Inverted Pyramid: Kernantwort in den ersten 2-3 Sätzen, dann Detail).

### A.8 Spezifikationstabelle

**Pflicht für jedes physische Produkt mit messbaren Eigenschaften.**

HTML-`<table>` mit `<thead>` und `<tbody>`. Mindestens 5 Zeilen, idealerweise 8-15.

Beispiel-Properties:
- Marke
- Modell
- Material(ien)
- Maße (LxBxH oder Durchmesser/Länge)
- Gewicht
- Farbvarianten
- Garantie
- Herstellungsland
- Energieklasse (wenn relevant, EU-Pflicht)
- Lieferumfang

LLMs lieben Tabellen. Sie sind hochzitierbar und werden in AI Overviews bevorzugt extrahiert.

### A.9 Variants

Wenn das Produkt Varianten hat (Farbe, Größe, Edition):
- Jede Variant idealerweise als eigene URL oder mit `?variant=` Parameter (Shopify-Default)
- Im Schema: `hasVariant` mit ProductGroup-Pattern (Stand 2024) oder klassisch mehrere Product-Schemas
- Klar im HTML kommuniziert: "Verfügbar in 4 Farben: Black, Racing Green, Storm Grey, Flame Lacquer"

### A.10 Versand & Rückgabe Block

**Pflicht für Vertrauensaufbau und für Schema.shippingDetails / hasMerchantReturnPolicy.**

Mindestens diese Punkte sichtbar auf der Seite:
- Versandkosten (oder "ab X €" oder "kostenlos ab Y €")
- Lieferzeit (z.B. "1-3 Werktage")
- Rückgabefrist (z.B. "30 Tage Widerruf")
- Rückversandkosten (wer zahlt: Käufer oder Händler?)

Bei Versand ins EU-Ausland: Mindestens grobe Hinweise auf Versandländer und Zollthematik.

### A.11 FAQ-Sektion

5-7 echte Käuferfragen. **Nicht erfunden, sondern aus realer Customer-Service-Erfahrung oder aus den "People Also Ask" zum Produkt.**

Antworten:
- 40-60 Wörter
- Konkret und faktisch
- Keine Marketing-Antworten ("Das Beste, was Sie je hatten!")

Beispiele für gute Fragen bei einem Klapprad:
- "Wie lange dauert das Falten und Entfalten?"
- "Passt das Klapprad in einen ICE-Zug?"
- "Welche Reifen sind verbaut und wie hoch ist der Pannenschutz?"
- "Kann ich Zubehör (Tasche, Beleuchtung) nachträglich anbauen?"

### A.12 Cross-Sell / Komplementär

Mindestens 3-5 thematisch passende Produkte verlinken (Zubehör, Alternative Modelle, Komplementär-Produkte).

Anchor-Texte sprechend wählen: nicht "hier klicken", sondern "Brompton Front-Tasche S-Bag" oder "Klapprad-Wartungsset".

### A.13 Zielkeyword-Platzierung

Das Hauptzielkeyword muss vorkommen in:
- Title Tag (vorne)
- H1
- Hero-Statement (erste 100 Wörter)
- Mindestens einer H3-Überschrift
- URL-Slug
- Mindestens einem Alt-Text

**Niemals erzwungen.** Wenn die natürliche Formulierung gegen die Keyword-Platzierung spricht, gewinnt die natürliche Formulierung.

### A.14 GEO-Citability für PDPs

LLM-Citations für PDPs entstehen typischerweise bei:
- Produktvergleichen ("Vergleiche X und Y")
- Empfehlungen ("Welches X ist gut für Z?")
- Technischen Fragen ("Wie schwer ist X?")

Damit eine PDP als Quelle gezogen wird, braucht sie:
- **Faktendichte:** konkrete Zahlen, Maße, Vergleichswerte
- **Eigenständige Statements:** Sätze, die isoliert Sinn machen ("Mit 9,9 kg ist das P-Line 1,5 kg leichter als das C-Line.")
- **Klare Brand-Verlinkung:** Hersteller-Website verlinkt, Brand-Schema vorhanden
- **Authority-Signale:** Reviews mit Anzahl, Awards/Auszeichnungen falls vorhanden, Erscheinungsjahr

### A.15 Ton

- Du-Form oder Sie-Form: konsistent, je nach Markenrichtlinie. Default für DACH-KMU: Sie.
- Kein Corporate-Jargon ("ganzheitlich", "innovativ", "synergetisch")
- Aktiv statt passiv
- Konkret statt abstrakt

---

## TEIL B: BEWERTUNGSMATRIX (Score-Modus)

### B.0 Gesamtgewichtung

```
Gesamtscore = 0.5 × SEO-Score + 0.5 × GEO-Score

SEO-Score:
  On-Page                  20%
  Produkttext-Qualität     20%
  Bilder & Visuals         15%
  Technik & Meta           15%
  Schema (Product)         20%
  Trust & Konversion       10%

GEO-Score:
  Citability               25%
  Strukturierte Specs      15%
  FAQ                      15%
  AI-Crawler-Zugriff       15%
  Brand-Signale            15%
  Aktualität               15%
```

### B.1 SEO: On-Page (20% des SEO-Scores)

Maximalpunkte 100. Verteilt:

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Title Tag vorhanden | 5 | Ja: 5, Nein: 0 |
| Title-Länge | 10 | 50-60 Zeichen: 10. 40-49 oder 61-65: 6. Sonst: 0 |
| Title enthält Produktname | 10 | Vorne: 10, irgendwo: 6, nicht: 0 |
| Title enthält Marke | 5 | Ja (vorzugsweise hinten): 5, sonst: 0 |
| Meta Description vorhanden | 5 | Ja: 5, Nein: 0 |
| Meta Description Länge | 8 | 140-160 Zeichen: 8. 120-139 oder 161-170: 5. Sonst: 2. Fehlt: 0 |
| H1 vorhanden, genau eine | 10 | Genau 1: 10, 0 oder >1: 0 |
| H1 enthält Produktname | 10 | Ja: 10, Nein: 0 |
| URL-Struktur | 10 | Sprechender Slug, Produktname enthalten, kein Hash, ≤90 Zeichen: 10. Pro Verstoß: -2 |
| H2/H3-Struktur vorhanden | 10 | Mindestens 3 H2/H3 Sektionen mit echtem Inhalt: 10. 1-2: 5. 0: 0 |
| Mehrere H1 erkannt | -20 | Pönale, wird vom Rohwert abgezogen |
| Breadcrumb sichtbar | 7 | Ja: 7, Nein: 0 |
| Interne Links zu Cross-Sell | 10 | ≥3 Cross-Sell-Links: 10. 1-2: 5. 0: 0 |

### B.2 SEO: Produkttext-Qualität (20% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Wortzahl im Produkttext | 15 | ≥400 Wörter eigentlicher Produkttext: 15. 200-399: 8. <200: 0 |
| Hero-Statement vorhanden | 10 | Klare 1-2 Satz Einleitung mit Produktdefinition: 10. Schwammig: 5. Fehlt: 0 |
| USP-Bullets vorhanden | 15 | ≥3 Bullets, faktendicht: 15. ≥3 generisch: 7. <3: 0 |
| Subsektionen mit H3 | 10 | ≥3 H3-Subsektionen mit ≥80 Wörtern: 10. 2: 5. <2: 0 |
| Konkrete Faktenangaben | 15 | Anteil Sätze mit Zahlen/Maßen/Materialien ≥30%: 15. 15-29%: 8. <15%: 0 |
| Erkennbares Hersteller-Copy-Paste | -20 | Pönale, wenn Text identisch oder fast identisch mit anderen Shops (heuristisch nicht voll erkennbar, aber Marketing-Floskeln in hoher Dichte als Indikator) |
| Anti-Floskel-Score | 10 | Keine Floskel-Pattern ("hochwertige Verarbeitung", "innovative Technologie"): 10. 1-2: 5. ≥3: 0 |
| Keyword-Stuffing | 10 | Keine erkennbare Stuffing-Dichte (>5%): 10. Sonst: 0 |
| Lesbarkeit (Flesch DE Amstad) | 15 | 50-70: 15. 40-49 oder 71-80: 10. Sonst: 5 |

### B.3 SEO: Bilder & Visuals (15% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Anzahl Produktbilder | 20 | ≥5: 20. 3-4: 12. 2: 6. 1: 3. 0: 0 |
| Alt-Texte auf allen Bildern | 15 | 100%: 15. 80-99%: 10. <80%: 4 |
| Beschreibende Alt-Texte | 15 | Stichprobe: nicht generisch (img1.jpg, "Bild"): 15. Gemischt: 8. Generisch: 0 |
| Modernes Format (WebP/AVIF) | 15 | ≥80%: 15. 50-79%: 8. <50%: 3 |
| width/height Attribute (CLS) | 10 | 100%: 10. ≥80%: 6. <80%: 2 |
| Lazy Loading auf Below-Fold | 10 | Korrekt umgesetzt: 10. Teilweise: 5. Fehlt: 0 |
| OG Image vorhanden | 5 | og:image gesetzt UND erreichbar: 5. Fehlt: 0 |
| Mehrere Aspect Ratios | 10 | Mindestens ein 1:1 und ein 4:3 oder 16:9: 10. Nur ein Format: 5. Unklar: 3 |

### B.4 SEO: Technik & Meta (15% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| HTTPS aktiv | 15 | Ja: 15, Nein: 0 |
| Canonical Tag korrekt | 15 | Self-referencing, kein Variant-Mismatch: 15. Fehlt: 8. Falsch: 0 |
| Meta Robots | 10 | index,follow: 10. Noindex unbeabsichtigt: 0 |
| HTTP-Status 200 | 10 | 200 ohne Redirect-Chain: 10. 301/302 mit Final 200: 6. Sonst: 0 |
| Mobile Viewport | 10 | width=device-width: 10, fehlt: 0 |
| HTML lang Attribut | 5 | Vorhanden: 5, fehlt: 0 |
| Charset deklariert (UTF-8) | 5 | UTF-8: 5, anderes/fehlt: 0 |
| Hreflang (wenn multilingual) | 10 | Korrekt: 10. Fehlt: 5. Fehlerhaft: 0. Wenn nicht multilingual: 10 (default) |
| Open Graph komplett | 10 | og:title, og:description, og:image, og:url, og:type alle gesetzt: 10. Pro fehlend: -2 |
| Twitter Card | 5 | twitter:card vorhanden: 5, fehlt: 0 |
| Mobile Add-to-Cart sichtbar (heuristisch) | 5 | Erkannter "in den Warenkorb"-Button im DOM: 5. Sonst: 0 |

### B.5 SEO: Schema (Product) (20% des SEO-Scores)

Das ist die wichtigste E-Commerce-spezifische Kategorie.

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Product-Schema vorhanden (JSON-LD) | 25 | Ja, JSON-LD: 25. Microdata: 15. RDFa: 10. Fehlt: 0 |
| name gefüllt | 5 | Ja: 5, Nein: 0 |
| image vorhanden | 10 | ≥3 Bilder: 10. 1-2: 6. 0: 0 |
| description vorhanden | 5 | Ja, ≥50 Zeichen: 5. <50: 2. Fehlt: 0 |
| brand vorhanden (mit @type Brand) | 8 | Korrekt: 8. Nur String statt Brand-Object: 4. Fehlt: 0 |
| sku gefüllt | 5 | Ja: 5, Nein: 0 |
| GTIN oder MPN | 7 | gtin8/12/13/14 oder mpn: 7. Beides fehlt: 0 |
| offers vorhanden | 10 | Mit price + priceCurrency + availability: 10. Unvollständig: 5. Fehlt: 0 |
| offers.priceValidUntil | 3 | Vorhanden: 3, fehlt: 0 |
| aggregateRating (nur wenn echte Reviews) | 7 | Vorhanden mit ratingValue + reviewCount: 7. Unvollständig: 3. Fehlt aber Reviews da: -5 (Pönale). Nicht vorhanden weil keine Reviews: 0 (neutral) |
| review (mind. 1 Beispiel) | 5 | Ja: 5, Nein: 0 |
| MerchantReturnPolicy verschachtelt | 5 | Korrekt: 5, fehlt: 0 |
| OfferShippingDetails verschachtelt | 5 | Korrekt: 5, fehlt: 0 |
| Schema-Validität (JSON parst) | 0 | Nicht parsbar: -50 (Pönale, wirkt direkt) |
| Self-serving Reviews als AggregateRating | 0 | Wenn erkennbar (Reviews nur shop-eigene): -10 (Pönale). Sonst neutral |

### B.6 SEO: Trust & Konversion (10% des SEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Versandkosten sichtbar | 15 | Konkret im Text oder im Versand-Block: 15. "siehe Versandbedingungen": 8. Unklar: 0 |
| Lieferzeit sichtbar | 15 | Konkret (z.B. "1-3 Werktage"): 15. Vage: 8. Fehlt: 0 |
| Rückgaberecht sichtbar | 15 | Konkret (z.B. "30 Tage Widerruf"): 15. Vage: 8. Fehlt: 0 |
| Reviews sichtbar (echte) | 15 | ≥10 Reviews mit Sternen: 15. 1-9: 8. Keine: 0 |
| Trust-Logos (Trusted Shops, Käuferschutz) | 10 | Erkennbar: 10, fehlt: 0 |
| Sichere Zahlungsoptionen sichtbar | 10 | Mehrere Zahlungsmethoden im Footer/PDP: 10. 1-2: 5. Fehlt: 0 |
| Impressum/AGB im Footer | 10 | Beides: 10. Eines: 5. Keines: 0 (massive Trust-Schwäche und EU-Recht-Verstoß) |
| Kontakt sichtbar | 10 | E-Mail oder Tel: 10, fehlt: 0 |

### B.7 GEO: Citability (25% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Hero-Statement eigenständig zitierfähig | 20 | "X ist Y für Z" Pattern in den ersten 100 Wörtern: 20. Schwammig: 8. Fehlt: 0 |
| USP-Bullets faktendicht | 20 | ≥3 Bullets mit Zahlen/Vergleichswerten: 20. Generisch: 8. Keine Bullets: 0 |
| Faktendichte im Fließtext | 15 | Anteil Sätze mit Zahlen/Maßen ≥25%: 15. 10-24%: 8. <10%: 0 |
| Vergleichende Aussagen | 10 | Mind. ein expliziter Vergleich (X kg leichter, Y Gänge mehr, im Gegensatz zu): 10. Fehlt: 0 |
| Eigenständige H3-Sektionen | 15 | Jede Sektion funktioniert isoliert (Inverted Pyramid): 15. Gemischt: 8. Schlecht: 0 |
| Optimale Absatzlängen | 10 | Anteil Absätze 80-180 Wörter ≥50%: 10. 30-49%: 6. <30%: 2 |
| Marketing-Lyrik-Anteil | 10 | Niedrig (≤2 Floskel-Treffer): 10. 3-4: 5. ≥5: 0 |

### B.8 GEO: Strukturierte Specs (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Spezifikationstabelle vorhanden | 30 | HTML-table mit thead+tbody, ≥5 Zeilen: 30. ≥3 Zeilen: 18. Tabelle ohne thead: 12. Keine Tabelle: 0 |
| Spezifikationen vollständig | 25 | Maße, Gewicht, Material, Lieferumfang, Hersteller alle abgedeckt: 25. Pro fehlende Pflicht-Property: -4 |
| Bullet/Listen-Anteil | 20 | Strukturierte Listen außer Bullets vorhanden (z.B. Features-Liste, Lieferumfang-Liste): 20. Nur eine: 12. Keine: 0 |
| Variants klar dokumentiert | 15 | Wenn Variants existieren, sind sie aufgelistet: 15. Keine Variants: 15 (default) |
| Energiekennzeichnung (wenn Pflicht) | 10 | Wenn EU-Energielabel-Pflichtkategorie: vorhanden: 10, fehlt: -10. Sonst: 10 default |

### B.9 GEO: FAQ (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| FAQ-Sektion erkannt | 30 | Eigene Sektion mit "Häufige Fragen"/FAQ-Header: 30. Nicht erkannt: 0 |
| Anzahl Fragen | 20 | 5-7: 20. 3-4: 10. 1-2: 5. 0: 0 |
| Antwortlängen | 20 | Durchschnitt 40-80 Wörter pro Antwort: 20. <30 oder >100: 10. Stark abweichend: 0 |
| Echte Käufer-Fragen | 15 | Konkrete Produktfragen statt generischer Marketing-FAQ: 15. Gemischt: 8. Marketing-Slop: 0 |
| FAQPage-Schema vorhanden | 15 | Korrekt im JSON-LD: 15, fehlt: 0. **Wichtig:** kein Punktabzug, wenn kein FAQPage-Schema verwendet wird (sinnvoll, weil Rich Results eingeschränkt). Aber Bonus-Punkte, wenn vorhanden, weil GEO-Lesbarkeit besser |

### B.10 GEO: AI-Crawler-Zugriff (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| GPTBot erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0 |
| OAI-SearchBot erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0 |
| ChatGPT-User erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| ClaudeBot erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| PerplexityBot erlaubt | 10 | Allow oder kein Eintrag: 10. Disallow: 0 |
| Google-Extended erlaubt | 15 | Allow oder kein Eintrag: 15. Disallow: 0. **Wichtig**: steuert Gemini und Google AI Overviews |
| Sitemap erreichbar | 10 | Sitemap-Pfad in robots.txt UND erreichbar: 10. Fehlt: 0 |
| llms.txt vorhanden | 5 | Vorhanden: 5 (Bonus, weil noch experimentell) |
| Drei oder mehr wichtige AI-Crawler blockiert | -30 | Pönale, wenn GPTBot+ClaudeBot+Google-Extended alle disallow |

### B.11 GEO: Brand-Signale (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| Brand-Property im Schema | 25 | brand mit @type Brand und name: 25. Nur String: 12. Fehlt: 0 |
| Hersteller-Verlinkung | 20 | Externer Link zur Hersteller-Domain auf der PDP: 20. Fehlt: 0 |
| Organization-Schema des Shops | 20 | Auf Domain-Ebene erkennbar (z.B. via Homepage Schema): 20. Fehlt: 0. Heuristisch über Footer-Daten. |
| sameAs in Schema | 10 | Brand oder Org Schema mit sameAs (LinkedIn, Wikipedia, Wikidata): 10. Fehlt: 0 |
| Konsistente Markenschreibweise | 10 | Im Title, H1, Schema, Hero identisch: 10. Inkonsistent: 0 |
| About/Über-uns verlinkt | 10 | Erreichbar aus dem Footer: 10. Fehlt: 0 |
| Trust-Indikatoren auf Brand-Ebene | 5 | "Seit XXXX", "Familienbetrieb", Awards: 5. Fehlt: 0 |

### B.12 GEO: Aktualität (15% des GEO-Scores)

| Kriterium | Punkte | Bewertung |
|---|---|---|
| dateModified im Schema | 25 | Vorhanden, ≤6 Monate: 25. ≤12 Monate: 18. ≤24 Monate: 10. Älter: 3. Fehlt: 0 |
| priceValidUntil im Schema | 15 | In der Zukunft, max 12 Monate: 15. Vergangenheit: 0 (signalisiert outdated). Fehlt: 8 |
| Verfügbarkeit aktuell | 20 | offers.availability InStock und Stock-Indikator im HTML konsistent: 20. Inkonsistent: 5. Fehlt: 0 |
| Sichtbares "Zuletzt aktualisiert" oder ähnliches | 10 | Vorhanden: 10. Fehlt: 0 |
| Aktuelles Modelljahr/Edition | 15 | Wenn Produkt-Versionierung üblich (Mode, Tech, Räder): aktuelle Saison/Modell-Bezeichnung erkennbar: 15. Veraltet: 0. Sonst: 15 (default) |
| Saison-/Trend-Tags (wenn relevant) | 15 | Wenn Saisonprodukt: aktuelle Saison erwähnt: 15. Veraltet: 0. Sonst: 15 (default) |

---

## TEIL B.X: ALGORITHMUS

```
für jede der 12 Kategorien:
    rohwert = summe der erreichten Punkte
    rohwert = max(0, min(100, rohwert))
    kategoriescore = rohwert

seo_score = round(
    0.20 * onpage +
    0.20 * produkttext +
    0.15 * bilder +
    0.15 * technik +
    0.20 * schema +
    0.10 * trust
)

geo_score = round(
    0.25 * citability +
    0.15 * specs +
    0.15 * faq +
    0.15 * ai_crawler +
    0.15 * brand +
    0.15 * aktualitaet
)

gesamt = round(0.5 * seo_score + 0.5 * geo_score)
```

---

## TEIL C: PLATTFORM-SPEZIFIKA

### C.1 Shopify

**Wo HTML einfügen:**
- Produktbeschreibung im Admin → Produkte → [Produkt] → Beschreibung
- Bei Theme-Anpassungen: `templates/product.liquid` oder `sections/main-product.liquid`

**Wo JSON-LD einfügen:**
- Default: Shopify generiert eigenes JSON-LD automatisch im Theme. Das eigene zusätzliche JSON-LD muss manuell ins Theme eingefügt werden, idealerweise direkt vor dem schließenden `</head>` in `theme.liquid` oder konditional in `templates/product.liquid`.
- Achtung: doppeltes Schema (Theme-default + eigenes) führt zu Konflikten. Entweder das Theme-Default-Schema deaktivieren oder das eigene Schema mit anderer @id versehen und sehr sicher sein, dass keine Property-Konflikte entstehen.
- Bei modernen Shopify-Themes (Online Store 2.0): Liquid-Variablen einbinden mit `{{ product.title | json }}`, `{{ product.price | money_without_currency }}` etc. für dynamische Werte.

**Plattform-Footprints für Erkennung im Skript:**
- Domain endet auf `.myshopify.com` oder
- HTML enthält `Shopify.theme` oder `cdn.shopify.com` oder
- Header `x-shopid` oder `powered-by: Shopify`

### C.2 WooCommerce

**Wo HTML einfügen:**
- Produktbeschreibung im Block-Editor (Gutenberg) oder Classic-Editor des Produkts
- Custom HTML als HTML-Block einfügbar

**Wo JSON-LD einfügen:**
- WooCommerce generiert automatisch ein eigenes Product-Schema, allerdings oft minimalistisch
- Eigenes JSON-LD via Plugin (Yoast SEO, Rank Math, SEOPress) oder direkt im Theme `functions.php` mit Hook `wp_head`
- Auch hier auf Doppel-Schema achten

**Plattform-Footprints:**
- HTML enthält `woocommerce` Klassen oder `wc-` Präfixe
- WordPress Generator-Tag mit "WooCommerce"
- `/wp-content/plugins/woocommerce/` in den Asset-URLs

### C.3 Shopware 6

**Wo HTML einfügen:**
- "Produktbeschreibung lang" im Backend
- Storefront-Templates `@Storefront/storefront/page/product-detail/` für tiefere Anpassungen

**Wo JSON-LD einfügen:**
- Über Theme-Anpassung in `meta.html.twig` oder `base.html.twig`
- Oder via App/Plugin

**Plattform-Footprints:**
- HTML enthält `shopware` oder `sw-` Klassen
- `/bundles/storefront/` Asset-Pfad

### C.4 Magento (Adobe Commerce)

**Footprints:**
- `var BLANK_URL` oder `Mage.` JS-Globals
- `/static/version*/` Asset-Pfade

Für Magento ist der Skill weniger spezifisch, generische HTML/JSON-LD-Hinweise reichen. KMU-Fokus liegt auf Shopify/WooCommerce/Shopware.

### C.5 Custom/Headless

Bei Custom-Lösungen (Next.js Commerce, Medusa, Saleor, Sylius etc.):
- HTML kann direkt eingefügt werden
- JSON-LD typischerweise via `<head>`-Komponente (z.B. `next/head` oder `react-helmet`)

---

## TEIL D: SCHEMA.ORG PFLICHTEN UND EMPFEHLUNGEN

### D.1 Product (Pflicht)

```jsonld
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "PFLICHT",
  "image": ["PFLICHT - URL Array, mindestens 1"],
  "description": "PFLICHT",
  "brand": { "@type": "Brand", "name": "EMPFOHLEN" },
  "sku": "EMPFOHLEN",
  "gtin13": "EMPFOHLEN für Markenprodukte",
  "mpn": "EMPFOHLEN als GTIN-Alternative",
  "offers": "PFLICHT (oder review/aggregateRating als Alternative)"
}
```

### D.2 Offer (Pflicht innerhalb Product)

```jsonld
{
  "@type": "Offer",
  "url": "PFLICHT - PDP URL",
  "priceCurrency": "PFLICHT - ISO 4217 (EUR, USD)",
  "price": "PFLICHT - als String",
  "priceValidUntil": "EMPFOHLEN - ISO 8601 Datum",
  "availability": "PFLICHT - schema.org URL: InStock, OutOfStock, BackOrder, PreOrder, Discontinued",
  "itemCondition": "EMPFOHLEN - NewCondition, UsedCondition, RefurbishedCondition",
  "hasMerchantReturnPolicy": "EMPFOHLEN - verschachteltes MerchantReturnPolicy",
  "shippingDetails": "EMPFOHLEN - verschachteltes OfferShippingDetails"
}
```

### D.3 MerchantReturnPolicy

```jsonld
{
  "@type": "MerchantReturnPolicy",
  "applicableCountry": "DE",
  "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",
  "merchantReturnDays": 30,
  "returnMethod": "https://schema.org/ReturnByMail",
  "returnFees": "https://schema.org/FreeReturn"
}
```

### D.4 OfferShippingDetails

```jsonld
{
  "@type": "OfferShippingDetails",
  "shippingRate": {
    "@type": "MonetaryAmount",
    "value": "4.95",
    "currency": "EUR"
  },
  "shippingDestination": {
    "@type": "DefinedRegion",
    "addressCountry": "DE"
  },
  "deliveryTime": {
    "@type": "ShippingDeliveryTime",
    "handlingTime": { "@type": "QuantitativeValue", "minValue": 0, "maxValue": 1, "unitCode": "DAY" },
    "transitTime": { "@type": "QuantitativeValue", "minValue": 1, "maxValue": 3, "unitCode": "DAY" }
  }
}
```

### D.5 AggregateRating (nur bei echten Reviews)

```jsonld
{
  "@type": "AggregateRating",
  "ratingValue": "4.7",
  "reviewCount": "143",
  "bestRating": "5",
  "worstRating": "1"
}
```

**Niemals fälschen.** Google hat 2019 self-serving Reviews aus den SERPs entfernt und straft Manipulationen aktiv ab.

### D.6 Review

```jsonld
{
  "@type": "Review",
  "author": { "@type": "Person", "name": "Vorname N." },
  "datePublished": "2025-09-15",
  "reviewBody": "Echter Reviewtext, mind. 30 Wörter",
  "reviewRating": { "@type": "Rating", "ratingValue": "5", "bestRating": "5" }
}
```

### D.7 ProductGroup (für Variants, ab 2024 Standard)

Wenn Variants vorhanden sind (Farben, Größen):

```jsonld
{
  "@type": "ProductGroup",
  "name": "Brompton P-Line",
  "productGroupID": "P-LINE-2024",
  "variesBy": ["color", "size"],
  "hasVariant": [
    { "@type": "Product", "color": "Black", "sku": "...", "offers": {...} },
    { "@type": "Product", "color": "Racing Green", "sku": "...", "offers": {...} }
  ]
}
```

### D.8 BreadcrumbList (empfohlen auf jeder PDP)

```jsonld
{
  "@type": "BreadcrumbList",
  "itemListElement": [
    { "@type": "ListItem", "position": 1, "name": "Home", "item": "https://shop.example.com" },
    { "@type": "ListItem", "position": 2, "name": "Klappräder", "item": "https://shop.example.com/klapprad" },
    { "@type": "ListItem", "position": 3, "name": "Brompton P-Line", "item": "https://shop.example.com/klapprad/brompton-p-line" }
  ]
}
```

---

## TEIL E: ANTI-PATTERNS UND HÄUFIGE FEHLER

### E.1 Schema-Fehler

- **Self-serving AggregateRating:** Reviews kommen ausschließlich von der eigenen Webseite, nicht unabhängig verifiziert. Seit 2019 nicht mehr gültig für Rich Results.
- **AggregateRating ohne reviewCount:** Pflichtfeld vergessen. Schema validiert nicht.
- **Brand als String statt Object:** `"brand": "Brompton"` ist technisch erlaubt, aber `{ "@type": "Brand", "name": "Brompton" }` wird stärker gewichtet.
- **Mehrere konfligierende Schemas (Theme-Default + Custom):** Häufig in Shopify, führt zu Validierungswarnungen.
- **availability als String:** Muss eine schema.org URL sein, nicht "InStock" als String.
- **price mit Währungssymbol:** `"price": "€199.00"` ist falsch. Richtig: `"price": "199.00", "priceCurrency": "EUR"`.

### E.2 Schreibfehler

- **Hersteller-Texte 1:1 übernehmen.** Google straft Duplicate Content. Bei Marken-Produkten: anders strukturieren, eigene Akzente, eigene FAQ.
- **Marketing-Lyrik ohne Substanz.** "Hochwertige Verarbeitung" ohne konkrete Materialangabe.
- **Keyword-Stuffing.** Mehrfache Wiederholung des Keywords in unnatürlicher Dichte.
- **Keine Spezifikationstabelle.** Massiver GEO-Verlust und SEO-Verlust.
- **Keine echten FAQs, sondern Marketing-Fragen** wie "Warum ist [Marke] das Beste?".

### E.3 Technische Fehler

- **Variants ohne Canonical-Strategie.** Jede Variant gleicher Canonical → schlechte SEO-Aufmerksamkeit pro Variant.
- **Faceted Navigation indexierbar.** Filter-URLs (color=red&size=L) ohne noindex erzeugen Duplicate-Content-Albträume.
- **Bilder als Base64 inline.** Riesige HTML-Größe, schlecht für Performance und nicht crawlbar als Bild.
- **Kein OG Image.** Produkt wird in Social Sharing schlecht dargestellt.

### E.4 GEO-Fehler

- **AI-Crawler blockiert.** Klassischer Reflex bei Online-Shops aus DSGVO-/Wettbewerbssorge. Konsequenz: das Produkt erscheint nicht in ChatGPT-Empfehlungen, Perplexity-Rankings, AI Overviews. Der Score-Modus muss das hart bewerten.
- **Keine Brand-Verlinkung.** LLMs verstehen das Produkt nicht im Markenkontext und können es nicht in Empfehlungen einordnen.
- **Hero-Statement fehlt oder schwammig.** Keine zitierfähigen Aussagen.
- **Keine Vergleichswerte.** "Sehr leicht" statt "9,9 kg, 1,5 kg leichter als Vorgänger".

---

## TEIL F: NICHT-GENUG-DATEN-REGEL

In folgenden Fällen darf der Skill keinen Score ausgeben, sondern muss zurückfragen:

- URL ist keine PDP (z.B. Category, Cart, Account)
- HTTP-Fehler (4xx, 5xx)
- Login-Schutz
- Geo-Blocking, das die Domain für die User-Region sperrt
- JS-Rendering scheitert UND der Fallback liefert <100 Wörter Text (klassischer SPA-Shop)

In diesen Fällen: erklären, was nicht funktioniert, Alternativen anbieten (öffentliche URL, gerenderter HTML-Snippet als Input, anderer Skill).
