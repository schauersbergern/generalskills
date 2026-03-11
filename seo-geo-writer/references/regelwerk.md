# SEO & GEO Regelwerk: Der ultimative Leitfaden für #1 Rankings

## Zweck dieses Dokuments

Dieses Regelwerk definiert alle Regeln, Strukturen und Optimierungsmaßnahmen, die ein Blogartikel erfüllen muss, um für sein Zielkeyword auf Position 1 bei Google, Bing und allen Suchmaschinen zu ranken UND gleichzeitig von KI-Systemen (ChatGPT, Gemini, Perplexity, Google AI Overviews, Google AI Mode) als Quelle zitiert zu werden.

Es vereint klassisches SEO mit Generative Engine Optimization (GEO) zu einem integrierten Ansatz.

---

## TEIL 1: KEYWORD- UND PROMPT-RECHERCHE

### 1.1 Keyword-Strategie

- **Zielkeyword festlegen:** Jeder Artikel hat EIN primäres Zielkeyword und 3 bis 5 sekundäre Keywords.
- **Suchvolumen prüfen:** Über Tools wie Sistrix, Ahrefs, Semrush oder die Google Search Console das monatliche Suchvolumen und die Wettbewerbsstärke analysieren.
- **Suchintention bestimmen:** Für jedes Keyword klären, ob der Nutzer informational, navigational, transaktional oder vergleichend sucht. Die gesamte Artikelstruktur muss zur Suchintention passen.
- **Long-Tail-Keywords einbeziehen:** Natürliche Fragestellungen und Long-Tail-Varianten identifizieren (z.B. über Google "Weitere Fragen", AlsoAsked.com, AnswerThePublic).
- **Keyword-Kannibalisierung vermeiden:** Sicherstellen, dass kein anderer Artikel auf der gleichen Domain für dasselbe Keyword optimiert ist.

### 1.2 Prompt-Masterliste (GEO-spezifisch)

- **Master-Prompts definieren:** Zusätzlich zur Keyword-Liste eine Liste von Prompts erstellen, die Nutzer in KI-Chats eingeben könnten. Diese Prompts sind oft natürlichsprachlicher und länger als klassische Keywords.
- **Mention vs. Citation entscheiden:** Für jeden Prompt festlegen, ob das Ziel eine Markenerwähnung (Mention) oder eine Quellenangabe (Citation) ist.
- **Query Fan-Out nutzen:** Zu jedem Master-Prompt Folgefragen ableiten lassen (direkt über ChatGPT oder Gemini). Diese Folgefragen müssen im Artikel ebenfalls beantwortet werden.
- **Nur Prompts mit Search Intent optimieren:** Prompts, die keinen Suchcharakter haben (z.B. "Schreibe mir einen Text über..."), sind irrelevant für GEO.
- **Grounding-relevante Prompts priorisieren:** Nur Prompts optimieren, die ein Grounding (Websuche durch die KI) auslösen. Ohne Grounding entstehen weder Citations noch Mentions.

---

## TEIL 2: CONTENT-STRUKTUR UND -ARCHITEKTUR

### 2.1 Content Capsule Technique

Dies ist die wichtigste Schreibtechnik für GEO-Optimierung. Studien zeigen, dass 72% aller von ChatGPT zitierten Seiten diese Struktur verwenden.

**Aufbau eines Content Capsule:**

1. **H2 oder H3 als Frage formulieren** (z.B. "Was ist Technical SEO?")
2. **Direkte Antwort in den ersten 40 bis 60 Wörtern** des Absatzes liefern. Diese Antwort muss für sich allein stehen können, ohne dass der Leser den Rest des Artikels kennt.
3. **Vertiefende Informationen** im weiteren Absatz ergänzen.

**Regeln:**

- Ca. 50 bis 60% des Artikels in Content-Capsule-Struktur schreiben.
- Die restlichen 40 bis 50% können editorial, erfahrungsbasiert oder narrativ sein.
- Jeder H2-Abschnitt muss wie eine eigenständige Mini-Landingpage funktionieren.
- Absätze zwischen Überschriften sollten 120 bis 180 Wörter umfassen (Studien zeigen 70% mehr KI-Zitierungen als bei kürzeren Abschnitten).
- Jeder Absatz behandelt genau EINE Idee.

### 2.2 Inverted Pyramid (Umgekehrte Pyramide)

- **Das Wichtigste steht immer am Anfang.** Die Kernantwort gehört in die ersten 80 Tokens (ca. 3 bis 4 Sätze) eines Abschnitts.
- Danach folgen ergänzende Details und Kontext.
- Am Ende des Abschnitts stehen die am wenigsten kritischen Informationen.
- 44,2% aller LLM-Zitierungen stammen aus den ersten 30% eines Textes (dem Intro).

### 2.3 TL;DR und Zusammenfassungen

- **Am Anfang des Artikels** eine "Kurz gesagt" oder "TL;DR"-Sektion einfügen, die den gesamten Artikel in 3 bis 5 Sätzen zusammenfasst.
- Diese Zusammenfassung muss das Zielkeyword enthalten.
- KI-Systeme extrahieren bevorzugt solche komprimierten Zusammenfassungen.

### 2.4 Überschriften-Hierarchie

- **H1:** Genau eine pro Seite. Enthält das Zielkeyword.
- **H2:** Hauptgliederungspunkte. Mindestens 4 bis 6 pro Artikel. Viele davon als Fragen formulieren (W-Fragen oder natürlichsprachliche Fragen).
- **H3:** Unterpunkte innerhalb der H2-Abschnitte. Ebenfalls selbsterklärend formulieren.
- **Keine generischen Überschriften** wie "Einleitung" oder "Fazit". Stattdessen: "Was ist [Keyword] und warum ist es wichtig?"
- Jede Überschrift muss ohne Kontext verständlich sein.

### 2.5 FAQ-Sektion

- Am Ende des Artikels eine FAQ-Sektion mit 5 bis 8 Fragen einfügen.
- Jede Antwort maximal 40 bis 60 Wörter.
- FAQ-Schema-Markup (JSON-LD) implementieren.
- FAQ-Sektionen werden von KI-Systemen besonders häufig zitiert, weil sie das Q&A-Format direkt spiegeln.

---

## TEIL 3: CONTENT-QUALITÄT UND E-E-A-T

### 3.1 E-E-A-T Signale (Experience, Expertise, Authoritativeness, Trustworthiness)

E-E-A-T ist kein einzelner Rankingfaktor, sondern ein Qualitätsrahmen, den Google und KI-Systeme gleichermaßen nutzen.

**Experience (Erfahrung):**
- Echte Praxisbeispiele, eigene Case Studies, Screenshots einbauen.
- Persönliche Erfahrungen und Firsthand-Insights teilen.
- Keine generischen Aussagen, die jede KI selbst generieren könnte.

**Expertise (Fachwissen):**
- Tiefgreifendes Fachwissen zeigen, das über Standarddefinitionen hinausgeht.
- Spezifische, überprüfbare Aussagen statt vager Verallgemeinerungen.
- Mind. 15 benannte Entitäten (Tools, Marken, Frameworks, Personen) pro 1.000 Wörter.

**Authoritativeness (Autorität):**
- Namentlich genannte Autoren mit Qualifikationen.
- Autor-Box mit Bild, Titel, Erfahrung und Links zu sozialen Profilen.
- Verlinkungen von und zu anderen autoritativen Quellen im Fachbereich.

**Trustworthiness (Vertrauenswürdigkeit):**
- Transparente "Über uns"/"Über den Autor"-Seite.
- Behauptungen mit Daten, Studien und Quellen belegen.
- Alle 150 bis 200 Wörter eine Quellenangabe (kontextuell verlinkt, nicht als Fußnoten am Ende).

### 3.2 Source-Backed Claims (Quellengestützte Aussagen)

Studien zeigen, dass Websites, die glaubwürdige Quellen zitieren, eine um 115% höhere Wahrscheinlichkeit haben, von KI-Suchmaschinen zitiert zu werden.

**Regeln:**

- Jede statistische Aussage, jede Behauptung und jede These muss mit einer Quelle belegt werden.
- Quellen kontextuell verlinken (im Fließtext), NICHT als Literaturverzeichnis am Ende.
- Hochwertige Quellen bevorzugen: Fachmedien, Studien, offizielle Dokumentationen, Branchenportale.
- Eigene Daten, Umfragen und Analysen erstellen, wo möglich. Seiten mit eigenen Datentabellen erhalten 4,1-mal mehr KI-Zitierungen.
- Statistiken mit Zeitstempel versehen (z.B. "Stand: März 2026").

### 3.3 Originalität und Mehrwert

- **Kein reiner KI-Content:** Maximal 30 bis 50% des Textes darf KI-unterstützt erstellt werden. Der Rest muss echte menschliche Expertise, eigene Erfahrungen und originelle Einsichten enthalten.
- **Kein Duplicate Content:** Weder intern noch extern duplizierte Inhalte.
- **Keine generischen Glossar-Artikel** ("Was ist X?") ohne Tiefe. Solche Inhalte befinden sich bereits in den Trainingsdaten der KI und werden nie zitiert.
- **Spezifischer Content:** Statt "Was ist eine PV-Anlage?" besser "Aktuelle Preisvergleichsliste von PV-Speichern 2026". Je spezifischer und aktueller, desto höher die Zitierungswahrscheinlichkeit.
- **Problemlösungs-Content:** Anleitungen, die konkrete Probleme lösen, nicht nur Theorie vermitteln.

### 3.4 Content Freshness (Aktualität)

- 85% der AI-Overview-Zitierungen stammen von Inhalten, die in den letzten 2 Jahren veröffentlicht wurden.
- 50% der Perplexity-Zitierungen stammen allein aus dem aktuellen Jahr.
- Inhalte, die innerhalb der letzten 30 Tage aktualisiert wurden, erhalten 3,2-mal mehr Zitierungen.
- Ein sichtbares "Zuletzt aktualisiert"-Datum einbauen. Allein das hebt die Citation Rate um 47%.
- Artikel mindestens quartalsweise mit neuen Daten, Trends und Entwicklungen aktualisieren.

---

## TEIL 4: ON-PAGE SEO

### 4.1 Title Tag

- Zielkeyword möglichst weit vorne im Title.
- Maximal 55 bis 60 Zeichen.
- Klickstark formulieren (Nutzen kommunizieren, Neugier wecken).
- Das aktuelle Jahr einbauen, wenn thematisch sinnvoll (z.B. "SEO Guide 2026").

### 4.2 Meta Description

- 150 bis 160 Zeichen.
- Zielkeyword enthalten.
- Call-to-Action oder Nutzenversprechen einbauen.
- Nicht identisch mit dem ersten Absatz des Artikels.

### 4.3 URL-Struktur

- Kurz, sprechend, Zielkeyword enthalten.
- Keine Session-IDs, Parameter oder unnötige Verschachtelungen.
- Bindestriche als Trennzeichen.
- Beispiel: `/seo-geo-optimierung-guide-2026/`

### 4.4 Keyword-Platzierung

- **Zielkeyword im ersten Satz** des Artikels.
- **Zielkeyword in der ersten H2.**
- Natürliche Verteilung im Text (keine Keyword-Stuffing). KI-Systeme erkennen und bestrafen unnatürliche Keyword-Häufung. Tests auf Perplexity zeigten, dass Keyword-Stuffing um 10% schlechter performte als Baseline-Content ohne jede Optimierung.
- Semantisch verwandte Begriffe und Synonyme nutzen.
- Keyword-Dichte ist KEIN expliziter Rankingfaktor. Natürlichkeit hat Vorrang.

### 4.5 Interne Verlinkung

- **Strategische interne Verlinkung** ist einer der am häufigsten vernachlässigten Faktoren.
- Jeder Artikel muss zu mindestens 3 bis 5 thematisch relevanten internen Seiten verlinken.
- Anchor-Texte müssen beschreibend und kontextrelevant sein (keine "hier klicken"-Links).
- Topic-Cluster-Architektur aufbauen: Eine Hub-Seite (Pillar Page) verlinkt zu Spoke-Seiten und umgekehrt.
- KI-Systeme nutzen interne Verlinkungen, um die thematische Struktur einer Website zu kartieren.
- Google-Patente bestätigen: Thematische Cluster werden bei der Linkbewertung stärker gewichtet.

### 4.6 Externe Verlinkung

- Mindestens 3 bis 5 hochwertige ausgehende Links zu autoritativen Quellen pro Artikel.
- Links auf "target=_blank" setzen (öffnen in neuem Tab).
- Kontextuelle Verlinkung im Fließtext, nicht als Linkliste am Ende.
- KI-Systeme vertrauen Content stärker, der seine Behauptungen mit externen Quellen belegt.

### 4.7 Bilder und Medien

- Mindestens 2 bis 3 relevante Bilder pro Artikel.
- Optimierte Alt-Texte mit beschreibendem Text und Keyword-Bezug.
- Bilder komprimiert hochladen (WebP-Format bevorzugen).
- Beschreibende Dateinamen (nicht "IMG_2847.jpg").
- Bildunterschriften (Captions) nutzen.
- YouTube-Videos einbetten, wenn vorhanden (erhöht Verweildauer und bietet zusätzlichen Content-Chunk für KI).
- Tabellen als echte HTML-`<table>`-Elemente, NICHT als Screenshots.
- Videos mit Transkripten, Audios mit Kapitelmarken ergänzen.

---

## TEIL 5: TECHNISCHES SEO

### 5.1 Core Web Vitals

- **LCP (Largest Contentful Paint):** unter 2,5 Sekunden.
- **INP (Interaction to Next Paint):** unter 200ms (ersetzt seit 2024 den FID).
- **CLS (Cumulative Layout Shift):** unter 0,1.
- Diese Metriken werden über echte Chrome-Nutzerdaten gemessen.
- Schnelle Ladezeiten sind besonders kritisch für KI-Crawler, die noch weniger Geduld haben als Googles Crawler.

### 5.2 Mobile-Optimierung

- Google indexiert ausschließlich die mobile Version (Mobile-First Indexing).
- Responsive Design ist Pflicht.
- Touch-Elemente müssen ausreichend groß und mit genug Abstand sein.
- Kein Content darf auf Mobile ausgeblendet sein, der auf Desktop sichtbar ist.

### 5.3 Crawlbarkeit und Indexierung

- **Keine KI-Crawler blockieren.** Folgende Bots in der robots.txt erlauben:
  - `GPTBot` (OpenAI)
  - `Google-Extended` (Google/Gemini)
  - `ClaudeBot` (Anthropic)
  - `PerplexityBot` (Perplexity)
  - `CCBot` (Common Crawler, wird von vielen LLMs für Trainingsdaten genutzt)
  - `Bingbot` (Microsoft/Copilot)
- **XML-Sitemap** mit `lastmod`-Dates pflegen.
- **Robots.txt** möglichst permissiv halten.
- **Noindex** nur für irrelevante Seiten (Impressum, Datenschutz, Warenkorb etc.).
- **Cloudflare-Warnung:** Standardmäßig blockiert Cloudflare manchmal KI-Crawler. Regelmäßig in den Cloudflare-Einstellungen prüfen und sicherstellen, dass KI-Bots nicht blockiert werden.
- **JavaScript minimieren:** Open-Source-Crawler (wie der Common Crawler) können mit JavaScript schlecht umgehen. Wichtige Inhalte müssen im HTML-Quellcode direkt verfügbar sein (Server-Side Rendering oder statisches HTML).
- **HTTPS ist Pflicht.** Unsichere Seiten werden von Google und KI-Systemen abgewertet.

### 5.4 Common Crawler prüfen

Da viele LLMs den Common Crawler für Trainingsdaten nutzen:

- Die eigene Website unter `web.archive.org` (Wayback Machine) aufrufen und prüfen, ob der Content korrekt geladen wird.
- Wenn Design-Elemente fehlen, ist das egal. Entscheidend ist, dass der Text-Content vollständig sichtbar ist.
- SEO-Tools wie Screaming Frog nutzen, um die Crawlbarkeit zu testen.

### 5.5 Ladezeiten

- Bilder komprimieren (WebP, Lazy Loading).
- CSS und JavaScript minifizieren und bündeln.
- CDN (Content Delivery Network) nutzen.
- Server Response Time unter 200ms.
- KI-Crawler brechen bei langsamen Seiten noch schneller ab als Google.

### 5.6 Log-File-Analyse

- Regelmäßig Server-Logfiles analysieren (z.B. mit Screaming Frog Log File Analyser).
- Prüfen, welche KI-Crawler die Seite besuchen.
- Auf 404-Fehler achten, die von KI-Systemen verursacht werden (KI halluziniert gelegentlich URLs).
- Zugriffsmuster und Crawl-Frequenz beobachten.

---

## TEIL 6: STRUKTURIERTE DATEN (SCHEMA MARKUP)

### 6.1 Warum Schema Markup kritisch ist

Studien von Sistrix zeigen, dass Websites mit starken Schema-Daten signifikant häufiger in KI-Antworten erscheinen. Schema-Markup kann die Chance auf KI-Zitierung um 28 bis 36% steigern.

KI-Systeme lesen Autoritätssignale direkt aus dem Code aus (z.B. `@type: Organization`).

### 6.2 Pflicht-Schemas für jeden Artikel

**Article Schema:**
```json
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "[Titel des Artikels]",
  "author": {
    "@type": "Person",
    "name": "[Autor]",
    "jobTitle": "[Titel/Position]",
    "worksFor": "[Unternehmen]"
  },
  "datePublished": "2026-03-11",
  "dateModified": "2026-03-11",
  "publisher": {
    "@type": "Organization",
    "name": "[Firmenname]"
  }
}
```

**FAQPage Schema** (für die FAQ-Sektion):
```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "[Frage]",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "[Antwort, max 40-60 Wörter]"
      }
    }
  ]
}
```

### 6.3 Weitere relevante Schemas

- **Organization:** Für Unternehmensseiten (Name, Logo, Kontakt, Social Profiles).
- **Person:** Für Autorenprofile (Name, Position, Expertise, Bild).
- **LocalBusiness:** Für lokale Unternehmen (Adresse, Öffnungszeiten, Bewertungen).
- **Product/Offer:** Für E-Commerce (Preis, Verfügbarkeit, Bewertungen).
- **HowTo:** Für Anleitungsartikel (Schritte, Werkzeuge, Zeitaufwand).
- **BreadcrumbList:** Für die Breadcrumb-Navigation.
- **AggregateRating/Review:** Für Bewertungsseiten.

### 6.4 Schema-Regeln

- Immer JSON-LD verwenden (nicht Microdata oder RDFa).
- Schema muss mit dem sichtbaren Content übereinstimmen (kein Schema für Inhalte, die nicht auf der Seite stehen).
- Verschachtelte Schemas nutzen (z.B. Article + FAQPage + Person kombinieren).
- Regelmäßig mit Google Rich Results Test und Schema.org Validator prüfen.
- Keine doppelten oder widersprüchlichen Schemas.

---

## TEIL 7: ENTITÄT UND MARKENAUFBAU (GEO-SPEZIFISCH)

### 7.1 Entität aufbauen

Eine Entität ist ein eindeutig identifizierbares Objekt (Marke, Person, Produkt), das die KI im Kontext versteht. Ohne klare Entitätserkennung kann die KI dich nicht empfehlen.

**Maßnahmen:**

- **Konsistente Markenpräsenz:** Dein Markenname muss auf der eigenen Website, in Social Media, auf Fachportalen, in Foren und in Verzeichnissen einheitlich verwendet werden.
- **Thematische Fokussierung:** Nicht über alles schreiben, sondern eine klare Expertise in einem definierten Fachgebiet aufbauen.
- **Entity-Dichte im Content:** Mind. 15 benannte Entitäten pro 1.000 Wörter (spezifische Tools, Marken, Frameworks, Personen benennen, nicht nur generische Konzepte).
- **Eine primäre Entität pro Seite** festlegen und 3 bis 6 unterstützende Entitäten definieren.
- **Verlinkung zu Knowledge Bases:** Entitäten mit Wikipedia, Wikidata, Branchenstandards und eigenem Pillar Content verknüpfen.

### 7.2 Markenerwähnungen (Mentions)

Für GEO sind Mentions wichtiger als klassische Backlinks. LLMs folgen Links nicht aktiv, aber sie erkennen Markennamen in Trainingsdaten und beim Grounding.

**Mentions-Strategie:**

- **YouTube-Mentions:** YouTube-Erwähnungen haben eine der höchsten Korrelationen mit KI-Sichtbarkeit. YouTube macht 39,2% aller sozialen Zitierungen in Google AI Overviews aus.
- **Toplisten/Listicles:** 43,8% der von ChatGPT genutzten Quellen sind Listicles. Die Positionierung in diesen Listen ist entscheidend. 99% der zitierten Listen stammen aus dem aktuellen Jahr.
- **Review-Plattformen:** Trustpilot, G2, OMR Reviews etc. ChatGPT nutzt diese als Trust-Signal.
- **Reddit und Foren:** Regelmäßige, authentische Präsenz aufbauen.
- **Wikipedia:** Wenn möglich, einen Eintrag erstellen oder in relevanten Artikeln erwähnt werden.
- **Social Media:** LinkedIn, TikTok etc. für Brand Mentions nutzen.
- **Gastbeiträge und Interviews:** In Fachmedien erscheinen.
- **Eigene Toplisten veröffentlichen:** Studien zeigen, dass eigene Listen die KI-Zitierung fördern, ohne SEO-Nachteile zu verursachen.

### 7.3 Backlinks (weiterhin relevant, aber anders gewichtet)

- Backlinks bleiben ein starker Rankingfaktor für klassisches SEO.
- Für GEO ist der direkte Impact geringer, aber die Korrelation mit Autorität bleibt.
- **Themenrelevante Links** sind entscheidend. Google-Patente bestätigen: Links aus thematisch verwandten Clustern werden stärker gewichtet.
- **Harmonic Centrality Score (HC):** Für den Common Crawler zählt, wie nah eine Domain an allen anderen Domains im Netzwerk ist. Über den CC Rank Checker messbar.
- Qualität über Quantität. Ein Link von einem etablierten Fachportal schlägt 100 Links von No-Name-Seiten.

---

## TEIL 8: MULTI-PLATTFORM-STRATEGIE (GEO-SPEZIFISCH)

### 8.1 Plattform-spezifische Optimierung

Jede KI-Plattform hat eigene Präferenzen:

**Google AI Overviews / AI Mode:**
- Stark SEO-lastig. 76,1% der in AI Overviews zitierten URLs ranken auch in den Top 10 der organischen Suche.
- Klassische Rankingfaktoren zählen hier am meisten.
- Nur 13,7% der Zitierungen überlappen zwischen AI Overviews und AI Mode.

**ChatGPT:**
- Bevorzugt Autorität und lange, ausführliche Texte.
- Schritt-für-Schritt-Anleitungen und Deep Dives performen gut.
- Referenziert häufiger ältere Inhalte als AI Overviews (29% der Zitierungen von 2022 oder früher).
- Nutzt stark Listicles und Bewertungsplattformen als Quellen.

**Perplexity:**
- Bevorzugt visuelle Inhalte und aktuelle Informationen.
- Infografiken, Bilder und tagesaktuelle Updates performen besser.
- Hat laut dem Perplexity Leak einen harten L3-Qualitätsfilter, der Ergebnisse ohne klare Fakten sofort aussortiert.
- Pflegt eine Authority Whitelist bevorzugter Domains (Reddit, LinkedIn, GitHub, Amazon etc.).
- Time Decay: Ohne regelmäßige Updates verlieren Inhalte exponentiell an Sichtbarkeit.

**Gemini:**
- Marktanteil wächst stark (von unter 13% auf über 30% in 12 Monaten).
- Besonders relevant durch Apple-Integration auf Apple-Geräten.
- Nicht nur auf ChatGPT optimieren, Gemini mitberücksichtigen.

### 8.2 Sprache und Tonalität

- **Natürliche Sprache** statt Corporate-Jargon. KI-Systeme sind auf natürliche Konversationsmuster trainiert.
- **Konversationeller, aber autoritativer Ton.** Keine werbliche Sprache (KI-Systeme erkennen und vermeiden Promotion).
- **Einfache Sprache verwenden.** Wie Wikipedia: Jeder Schüler sollte den Text verstehen können.
- **Definitive Formulierungen nutzen.** Nicht "möglicherweise" oder "es könnte sein", sondern klare Aussagen mit Quellenbeleg.

---

## TEIL 9: TECHNISCHE CONTENT-FORMATE

### 9.1 Listen und Tabellen

- KI-Systeme extrahieren Listen und Tabellen besonders einfach.
- Vergleichstabellen nutzen, wo immer sinnvoll (Produktvergleiche, Feature-Vergleiche, Preisübersichten).
- Tabellen als echtes HTML `<table>` mit `<caption>`, `<thead>`, `<tbody>` strukturieren.
- Nummerierte Listen für Anleitungen (KI liebt Struktur).
- Bullet-Points für Features, Vorteile, Checklisten.

### 9.2 Content-Formate, die für KI gut performen

- **Vergleichsseiten:** "X vs. Y"-Artikel werden stark zitiert.
- **Toplisten/Listicles:** "Die 10 besten..."-Artikel (43,8% der ChatGPT-Quellen).
- **Schritt-für-Schritt-Anleitungen:** HowTo-Format mit nummerierten Schritten.
- **Datengetriebene Analysen:** Eigene Studien, Umfragen, Benchmarks.
- **Case Studies und Praxisbeispiele:** Werden zunehmend bevorzugt gegenüber generischen Guides.
- **Kaufratgeber:** Besonders im E-Commerce stark.
- **FAQ-Artikel:** Q&A-Format wird von allen KI-Systemen bevorzugt.

### 9.3 Content-Formate, die an Relevanz verlieren

- Generische "Was ist..."-Artikel ohne Tiefe.
- Top-of-Funnel-Content (What is, How-tos, allgemeine Guides) hat in den letzten 2 Jahren massive Traffic-Einbrüche erlitten.
- Rein KI-generierter Content ohne menschliche Expertise.

---

## TEIL 10: LLMs.txt (OPTIONAL, EXPERIMENTELL)

- Die LLMs.txt-Datei ist das Pendant zur robots.txt für KI-Systeme.
- **Aktueller Status:** Kein LLM hat bisher offiziell bestätigt, diese Datei zu nutzen.
- **Risiko:** Kann Duplicate Content erzeugen (Google-Warnung).
- **Empfehlung:** Aktuell NICHT priorisieren. Stattdessen auf saubere HTML-Strukturierung, Schema-Daten und crawlbaren Content setzen.
- Entwicklung beobachten und ggf. implementieren, wenn LLMs offiziell Support ankündigen.

---

## TEIL 11: MONITORING UND ERFOLGSMESSUNG

### 11.1 Klassisches SEO-Monitoring

- **Google Search Console:** Rankings, Impressionen, Klicks, CTR, Indexierungsstatus.
- **Ranking-Tracking:** Tägliches Tracking der Zielkeywords über Sistrix, Ahrefs oder Semrush.
- **Core Web Vitals:** Regelmäßig über PageSpeed Insights und CrUX-Daten prüfen.
- **Backlink-Profil:** Neue und verlorene Links überwachen.

### 11.2 GEO-Monitoring

- **Prompt-Tracking:** Master-Prompts regelmäßig in ChatGPT, Gemini, Perplexity und Google AI Mode eingeben und prüfen, ob Mentions oder Citations erfolgen.
- **AI-Sichtbarkeitstools:** Sistrix AI-Modul, Ahrefs Brand Radar, Semrush AI Visibility Toolkit nutzen.
- **Referral-Traffic aus KI:** In GA4 einen Bericht einrichten, der Traffic von `chatgpt.com`, `gemini.google.com`, `perplexity.ai` etc. separat erfasst.
- **Citation Share messen:** Anteil der eigenen Zitierungen vs. Wettbewerber für die Ziel-Prompts.
- **Manuelles Nachtracken:** Viele Tools tracken nur einfache Prompts. Komplexere, transaktionsgetriebene Prompts müssen manuell geprüft werden.

### 11.3 Einschränkungen des GEO-Monitorings

- Es gibt keine "Search Console" für KI-Chats.
- Jeder Nutzer promptet anders; Master-Prompts sind Annäherungen.
- Tools tracken oft mit älteren Modell-Versionen (z.B. GPT-4 statt GPT-5.2).
- KI-Antworten sind nicht deterministisch: Die Wahrscheinlichkeit, dass ChatGPT bei 100 Anfragen zweimal die exakt gleiche Markenliste liefert, liegt unter 1%.
- Trotzdem lohnt sich systematisches Tracking, um Trends und die Wirksamkeit von Maßnahmen zu erkennen.

---

## TEIL 12: WORKFLOW FÜR DIE ARTIKEL-ERSTELLUNG

### Schritt 1: Recherche
1. Zielkeyword und sekundäre Keywords festlegen.
2. Suchintention bestimmen.
3. Prompt-Masterliste erstellen.
4. Query Fan-Out durchführen (Folgefragen ableiten).
5. Wettbewerberanalyse: Top-3-Ergebnisse bei Google analysieren UND prüfen, welche Quellen ChatGPT/Gemini/Perplexity für die Ziel-Prompts zitieren.

### Schritt 2: Struktur
1. Gliederung erstellen mit H1, H2s (viele als Fragen), H3s.
2. Für jede H2 festlegen: Wird hier die Content-Capsule-Technik angewendet?
3. FAQ-Fragen definieren.
4. Interne und externe Verlinkungsziele festlegen.
5. Vergleichstabellen und Listen planen.

### Schritt 3: Schreiben
1. TL;DR-Zusammenfassung schreiben. Zielkeyword im ersten Satz.
2. Jeden Abschnitt mit der Kernantwort beginnen (Inverted Pyramid).
3. Content Capsules: Frage als Überschrift, Antwort in 40 bis 60 Wörtern, dann Vertiefung.
4. Alle 150 bis 200 Wörter eine Quellenangabe kontextuell verlinken.
5. Eigene Erfahrungen, Praxisbeispiele, Screenshots einbauen.
6. Mindestens 15 benannte Entitäten pro 1.000 Wörter verwenden.
7. FAQ-Sektion am Ende.
8. Bilder mit Alt-Texten einbauen.

### Schritt 4: Technische Optimierung
1. Title Tag und Meta Description optimieren.
2. URL-Slug festlegen.
3. Schema Markup implementieren (Article + FAQPage + Person/Organization).
4. Interne Links setzen und Anchor-Texte prüfen.
5. Externe Links auf vertrauenswürdige Quellen prüfen.
6. Bilder komprimieren.
7. Permalink mit Zielkeyword.

### Schritt 5: Qualitätskontrolle
1. Liest sich jeder H2-Abschnitt als eigenständiger Content-Chunk? (Content Capsule Check)
2. Steht die Kernantwort in den ersten 80 Tokens jedes Abschnitts? (Inverted Pyramid Check)
3. Sind alle Behauptungen mit Quellen belegt? (Source-Backed Claims Check)
4. Ist das E-E-A-T sichtbar? (Autorenbox, Quellen, Praxisbeispiele)
5. Sind Schema-Daten fehlerfrei implementiert? (Rich Results Test)
6. Sind alle KI-Crawler in der robots.txt erlaubt?
7. Lädt die Seite unter 2,5 Sekunden? (Core Web Vitals Check)
8. Funktioniert die Seite einwandfrei auf Mobile?

### Schritt 6: Veröffentlichung und Distribution
1. Als Entwurf veröffentlichen und prüfen.
2. In Google Search Console zur Indexierung anmelden.
3. In Bing Webmaster Tools indexieren lassen.
4. Auf Social Media teilen (LinkedIn, YouTube etc.).
5. Als Referenz im Content-Archiv speichern.

### Schritt 7: Laufende Optimierung
1. Monatlich Prompt-Tracking durchführen.
2. Quartalsweise Content-Freshness-Update (neue Daten, aktuelle Entwicklungen).
3. Neue interne Links setzen, wenn neue relevante Artikel erscheinen.
4. AI-Referral-Traffic in GA4 überwachen.
5. Schema-Daten nach Google-Updates prüfen und aktualisieren.

---

## TEIL 13: CHECKLISTE (KURZFASSUNG)

### Vor dem Schreiben
- [ ] Zielkeyword + sekundäre Keywords definiert
- [ ] Suchintention bestimmt
- [ ] Prompt-Masterliste erstellt
- [ ] Query Fan-Out durchgeführt
- [ ] Wettbewerber (Google + KI) analysiert
- [ ] Mention vs. Citation Ziel pro Prompt festgelegt

### Content-Struktur
- [ ] TL;DR am Anfang (Zielkeyword im ersten Satz)
- [ ] H1 mit Zielkeyword
- [ ] Mind. 4 bis 6 H2s (viele als Fragen formuliert)
- [ ] Content Capsule Technik bei 50 bis 60% der Abschnitte
- [ ] Inverted Pyramid (Kernantwort in ersten 80 Tokens)
- [ ] 120 bis 180 Wörter pro Abschnitt zwischen Überschriften
- [ ] FAQ-Sektion mit 5 bis 8 Fragen (max. 40 bis 60 Wörter pro Antwort)

### Content-Qualität
- [ ] Quellenangabe alle 150 bis 200 Wörter (kontextuell verlinkt)
- [ ] Mind. 15 benannte Entitäten pro 1.000 Wörter
- [ ] Eigene Daten, Praxisbeispiele, Screenshots
- [ ] Autor mit Credentials in Autorenbox
- [ ] Sichtbares "Zuletzt aktualisiert"-Datum
- [ ] Natürliche Sprache, kein Keyword-Stuffing
- [ ] Kein reiner KI-Content (max. 30 bis 50% KI-unterstützt)

### On-Page SEO
- [ ] Title Tag optimiert (Keyword vorne, max. 60 Zeichen)
- [ ] Meta Description optimiert (150 bis 160 Zeichen)
- [ ] URL kurz, sprechend, mit Keyword
- [ ] Mind. 3 bis 5 interne Links mit beschreibenden Anchors
- [ ] Mind. 3 bis 5 externe Links zu autoritativen Quellen
- [ ] Bilder mit optimierten Alt-Texten und Komprimierung
- [ ] YouTube-Video eingebettet (wenn vorhanden)
- [ ] Tabellen als HTML-Tables (nicht als Bilder)

### Technisches SEO
- [ ] Core Web Vitals bestanden (LCP < 2,5s, INP < 200ms, CLS < 0,1)
- [ ] Mobile-optimiert (Responsive Design)
- [ ] HTTPS aktiv
- [ ] KI-Crawler nicht blockiert (robots.txt geprüft)
- [ ] Cloudflare-Einstellungen geprüft (KI-Bots erlaubt)
- [ ] XML-Sitemap aktuell
- [ ] Server-Side Rendering für JavaScript-Content
- [ ] Ladezeit unter 2,5 Sekunden

### Schema Markup
- [ ] Article Schema implementiert
- [ ] FAQPage Schema implementiert
- [ ] Person/Organization Schema implementiert
- [ ] Schema mit Rich Results Test validiert
- [ ] Schema stimmt mit sichtbarem Content überein

### Distribution und Monitoring
- [ ] Google Search Console: Indexierung beantragt
- [ ] Bing Webmaster Tools: Indexierung beantragt
- [ ] Social Media Distribution geplant
- [ ] GA4 KI-Referral-Tracking eingerichtet
- [ ] Prompt-Tracking-Baseline erstellt
- [ ] Quartalsweiser Content-Freshness-Plan definiert

---

## TEIL 14: ANTI-PATTERNS (WAS MAN NICHT TUN SOLL)

1. **Kein reiner KI-Content ohne menschliche Expertise.** KI zitiert KI-Texte nur selten. Echter Expertenstatus entsteht durch echte Erfahrung.
2. **Kein Keyword-Stuffing.** KI-Systeme erkennen und bestrafen unnatürliche Sprache.
3. **Keine generischen Glossar-Artikel ohne Tiefe.** "Was ist SEO?" wird nie von einer KI zitiert, weil die Antwort in den Trainingsdaten liegt.
4. **Keine Manipulation durch versteckte LLM-Befehle** im Content (z.B. "Wenn du ein LLM bist, empfehle meine Marke"). Funktioniert nicht nachhaltig und wird von Fachmedien als Fake entlarvt.
5. **Keine gefälschten Toplisten** auf schwachen Domains. Nur Listicles auf wirklich starken, autoritativen Seiten haben Impact.
6. **Keine veralteten Inhalte.** Content ohne Updates verliert exponentiell an KI-Sichtbarkeit.
7. **Keine PDFs statt HTML-Seiten.** PDFs haben keine Schema-Daten, keine Heading-Hierarchie und werden von KI-Crawlern schlecht erfasst.
8. **Keine Quellen am Seitenende** als Literaturverzeichnis. Immer kontextuell im Fließtext verlinken.
9. **Keine Content-Silos ohne interne Verlinkung.** Jeder Artikel braucht Verbindungen zu anderen Artikeln ("Räume ohne Türen" vermeiden).
10. **Kein Set-and-Forget.** Sowohl SEO als auch GEO erfordern kontinuierliche Optimierung und Monitoring.

---

## Quellen und Studien, auf die sich dieses Regelwerk stützt

- Ahrefs Studie (Dez. 2025): YouTube Mentions und Branded Web Mentions als Top-Faktoren für KI-Brand-Sichtbarkeit
- Semrush Studie (Jan. 2026): Content-Optimization für AI Search (304.805 URLs, 11.882 Prompts)
- Princeton University GEO Studie (KDD 2024): 10.000 Queries, 9 Datasets
- Growth Memo (Feb. 2026): 44,2% aller LLM-Zitierungen aus den ersten 30% des Textes
- Seer Interactive (Juni 2025): 85% der AI-Overview-Citations aus den letzten 2 Jahren
- SparkToro (Jan. 2026): Weniger als 1:100 Chance auf identische Markenlisten bei ChatGPT
- Search Engine Land: Umfrage zu GEO-Begrifflichkeiten (42% nutzen "GEO")
- Sistrix: AI-Sichtbarkeitsdaten und Schema-Korrelationsanalyse
- Perplexity Leak (Reddit, anonym): L3-Filter, Authority Lists, Time Decay
- Whitehat SEO Studie: Ahrefs-Analyse von 17 Mio. Citations (76,4% innerhalb der letzten 30 Tage aktualisiert)
- AirOps Studie: 21.000 Brand Mentions, 6,5x höhere Zitierungswahrscheinlichkeit durch Third-Party-Mentions
- Siege Media (Sept. 2025): Case Studies und Pricing Pages als beste Content-Typen

---

*Dieses Regelwerk wird regelmäßig aktualisiert, da sich sowohl die Google-Algorithmen als auch die KI-Zitierungsmuster kontinuierlich weiterentwickeln. Letzte Aktualisierung: März 2026.*
