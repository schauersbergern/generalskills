# Feature-File: Vorlage und Regeln

Das Feature-File ist die Eingabe von `auto-feature` und zugleich das Approval. Weil der Lauf keine Rückfragen stellt, muss hier alles stehen, was nur der User oder der Kunde entscheiden kann. Wie gebaut wird, entscheiden Spec und Plan.

Erzeugt wird es mit dem Skill `feature-file` (Interview, Recherche, Builder-Check) oder von Hand nach dieser Vorlage.

## Regeln

1. **Was und warum, nicht wie.** Das File besteht genau aus den Abschnitten der Vorlage, und jedes TF genau aus Problem, Ist, Entschieden, Default und DoD. Andockpunkte, Härtungsschwerpunkte, Review Focus, Effort, Prüfbefehle und Task-Schnitt erzeugt der Lauf selbst in Spec und Plan. Pfade stehen im Ist-Stand und dort, wo eine Entscheidung an einer bestimmten Stelle hängt. Richtwert: Ein TF passt auf eine Bildschirmseite (etwa 40 Zeilen). Was länger wird, ist Spec-Inhalt oder ein zweites TF.
2. **Ist-Stand mit Pfaden.** Je TF steht, was es schon gibt (Datei mit Zeile, Spalte, Config-Wert, Abhängigkeit) und ob es übernommen, erweitert oder ersetzt wird. Sonst bauen Agenten Vorhandenes neu. Beim Builder-Check vom 2026-10-23 stand ein bereits vorhandener DOCX-Renderer als neu zu bauen im File.
3. **Verbindlichkeit je Punkt:**
   - `Entschieden`: bindend, die Spec darf nicht abweichen. Entscheiden dürfen nur der User oder der Kunde.
   - `Default`: Die Spec darf mit Begründung abweichen. Rechercheergebnisse und Vorschläge des Workflows sind immer `Default`, nie `Entschieden`.
   - Herkunft in Klammern, wo sie nicht offensichtlich ist: `(User)`, `(Kunde)`, `(Recherche: <Quelle>)`, `(Workflow)`.
4. **DoD-Punkte mit ID und Nachweis.**
   - ID `TF<n>-D<m>`. IDs werden nie umnummeriert, ein gestrichener Punkt bleibt als „gestrichen“ stehen. Spec, Plan, Tests und PR-Haken verweisen auf diese IDs.
   - Jeder Punkt beschreibt beobachtbares Verhalten von außen: Antwort, DB-Zustand, Datei, Anzeige, Rechte. „Test X ist grün“ ist kein DoD-Punkt, denn den kann man durch Abschwächen des Tests erfüllen.
   - Jeder Punkt nennt seinen Nachweis: `[Test]` (automatisiert), `[Durchklick]` (bleibt beim User und kommt als Checkliste in den PR) oder `[Ops]` (Schritt außerhalb des Codes).
   - Keine Wörter wie „sauber“, „robust“ oder „schnell“ ohne Schwelle.
   - Fehlerpfade und Grenzfälle sind eigene Punkte: falsche Eingabe, fremde Org, fehlende Rechte, doppelte Auslösung, alter Client.
   - Given/When/Then nur, wenn ein Ausgangszustand das Verhalten bestimmt. Keine User Stories.
   - Gilt ein Verhalten in mehreren TFs (z. B. „PDF bleibt unverändert“), steht es als eigener DoD-Punkt in jedem TF, das es berühren kann. Die gemeinsame DoD (Abschnitt 3) enthält nur Prüfbefehle und was beim User bleibt.
5. **Größe passend zum Problem.** Ein TF ergibt einen PR und ist für sich testbar und auslieferbar. Ein TF mit zwei voneinander unabhängigen Nutzen wird geteilt. Ein kleiner Fix bekommt Problem und wenige DoD-Punkte, nicht künstlich viele.
6. **Keine offenen Fragen.** Ein übergebenes File enthält keine offene Frage. Was ungeklärt bleibt, wird `Default` mit dem Vermerk `offen: <Frage>`. Der Lauf führt diese Punkte im Abschlussbericht.
7. **Grenzen statt Rückfragen.** Abschnitt 0 nennt unter „Nie“, was der Lauf nicht tun darf, auch wenn es naheliegt: zum Beispiel deployen, fremde Module anfassen oder einen kostenpflichtigen Anbieter live schalten. Invarianten aus `CLAUDE.md` werden referenziert, nicht abgeschrieben.
8. **Abgrenzung.** „Nicht in diesem File“ nennt, was naheliegt, aber nicht gebaut wird, und warum. Agenten erweitern sonst den Umfang.
9. **Im Lauf schreibgeschützt.** `auto-feature` ändert das File nicht, außer im Abschnitt „Offene Review-Punkte“. Abweichungen stehen in Spec, PR und Abschlussbericht.

## Vorlage

```markdown
# Feature-File: <Thema>

**Datum:** <YYYY-MM-DD> · **Typ:** Feature-File für `auto-feature` · **Quelle:** <Mail, Call, Kundendoc mit Pfad>
· **Freigabe:** <YYYY-MM-DD>, <Name> · **Builder-Check:** <YYYY-MM-DD>, <Ergebnis in einem Satz>

Pro Teilfeature gibt es eine eigene Spec und einen eigenen PR. Dieses File ist das Approval. „Entschieden“ ist
bindend, bei „Default“ darf die Spec mit Begründung abweichen.

## 0. Rahmen (gilt für alle Teilfeatures)

- **Leitsatz:** <ein Satz, der Abwägungen entscheidet>
- **Invarianten:** <Verweise auf `CLAUDE.md`-Abschnitte, nur lauf-spezifische Ergänzungen ausschreiben>
- **Was nicht brechen darf:** <bestehende Pfade, Clients, Daten>
- **Teststrategie:** <was getestet wird und was nicht>
- **Nie:** <Handlungen, die der Lauf auch dann unterlässt, wenn sie naheliegen>
- **Auslieferung:** <was nicht zur DoD gehört, z. B. Deploy durch den User; was der PR-Body unter „Ops“ nennt>

## 1. Teilfeatures

### TF1: <Titel>

**Problem:** <wer will was und warum, in zwei bis vier Sätzen>

**Ist:** <was es schon gibt, mit Pfad:Zeile; übernehmen, erweitern oder ersetzen>

**Entschieden:**
- <bindende Vorgabe> (<Herkunft>)

**Default:**
- <Vorschlag mit Spielraum> (<Herkunft>)
- <Vorschlag> (offen: <Frage, die niemand beantwortet hat>)

**DoD:**
- **TF1-D1** [Test] <beobachtbares Verhalten>
- **TF1-D2** [Test] <Fehlerpfad oder Grenzfall>
- **TF1-D3** [Durchklick] <was der User am Gerät prüft>
- **TF1-D4** [Ops] <Schritt außerhalb des Codes>

## 2. Reihenfolge und Abhängigkeiten

<Reihenfolge mit Begründung (Nutzen, Abhängigkeit). Abhängigkeiten als Liste oder kleiner Graph:
TF2 braucht TF1 (<was genau>). Entfällt bei einem einzigen TF.>

## 3. Gemeinsame DoD

<nur repo- oder lauf-spezifisch: Prüfbefehle, die grün sein müssen; was beim User bleibt. Den Ablauf
von `auto-feature` (Reviews, Härtung) hier nicht wiederholen.>

## 4. Nicht in diesem File

- <naheliegendes Thema>: <warum nicht, wer es macht oder wann>

## 5. Offene Review-Punkte

(füllen die Spec-Reviews des Laufs)
```

## Herkunft der Regeln (Stand 2026-11-09)

Übernommen:
- **Eigene Läufe:** die Struktur aus Rahmen, Teilfeatures mit Entschieden/Default/DoD und Abgrenzung aus den Feature-Files vom Oktober 2026. Den Builder-Check als Pflicht vor der Übergabe: 1 Opus-Lauf mit 107k Tokens fand 2 Faktenfehler gegen den Code und 5 Fragen, darunter 2 betriebsrelevante (Agent-Statistik 2026-10-23).
- **Anthropic, „Effective harnesses for long-running agents“ (Nov. 2025):** Agenten erklären Arbeit zu früh für fertig, markieren Features ohne End-to-End-Test als erledigt und verändern Anforderungsdateien. Daraus folgen beobachtbare DoD-Punkte, die Nachweis-Art je Punkt und das schreibgeschützte File.
- **GitHub spec-kit, `spec-template.md`:** fortlaufende IDs für Anforderungen, ein eigener Abschnitt für Annahmen und Markierungen für Unklares. Hier wird daraus `Default` mit `offen:`, denn der autonome Lauf kann nicht nachfragen.
- **B. Böckeler, „Understanding Spec-Driven-Development“ (martinfowler.com, 15.10.2025):** Agenten bauen vorhandenen Code neu, statt ihn zu nutzen, und ein einziger Ablauf passt nicht für jede Größe. Lange Markdown-Specs sind mühsamer zu prüfen als Code. Daraus folgen der Ist-Stand mit Pfaden, die Größe passend zum Problem und „Was und warum, nicht wie“.
- **A. Osmani, „How to write a good spec for AI agents“ (13.01.2026):** explizite Grenzen und Abgrenzung des Umfangs.

Bewusst nicht übernommen:
- **EARS oder Gherkin als Pflichtformat:** Unter Praktikern ist das Format umstritten, unstrittig ist nur die Prüfbarkeit. Die Pflicht zum Nachweis je Punkt deckt das ab.
- **User Stories („Als … möchte ich …“):** Sie machen das File länger, ohne dass ein Punkt dadurch prüfbarer wird.
- **Technologieneutrale Geschäftskennzahlen** wie „90 % schaffen es beim ersten Versuch“: Im Lauf sind sie nicht prüfbar.
- **Ein zusätzlicher JSON-Vertrag:** ein zweites Artefakt, das synchron gehalten werden muss. Den Nutzen (Agenten überschreiben Anforderungen nicht) bringt die Regel „im Lauf schreibgeschützt“, den Fortschritt halten PRs und Haken fest.
- **„Constitution“ als eigene Datei:** Diese Rolle hat die Repo-`CLAUDE.md`.
