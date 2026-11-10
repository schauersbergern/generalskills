---
name: architektur-rat
description: Use only when the user explicitly asks for an "Architektur-Rat" or for two independent agent opinions (Pragmatiker, Risiko) on an open, hard-to-reverse code or operations decision. Research and development skill, not part of any workflow; never invoke it on your own from auto-feature, pr-review-loop or another skill.
argument-hint: <Frage oder Spec-Abschnitt>
---

# Architektur-Rat (Forschung und Entwicklung)

> **Status F&E, Stand 2026-11-09.** Dieser Skill ist in keinen Workflow eingebunden und wird nur auf ausdrücklichen Wunsch des Users genutzt. Im ersten Test hat er die Entscheidung nicht verbessert (siehe „Stand der Belege“). Er bleibt für weitere Versuche erhalten. Testbericht und Testmaterial: `~/Projects/tools/agentic_engineering/werkzeuge/2026-11-09-architektur-rat-test.md`.

**Kern:** Zwei frische Subagenten bewerten dieselbe offene Entscheidung unabhängig: **Pragmatiker** und **Risiko**. Die Hauptsession entscheidet und dokumentiert beide Voten. Der Rat ist keine Abstimmung und kein Ersatz für ein Spec-Review.

## Auslöser

Der Rat tritt nur auf Wunsch des Users zusammen. Sinnvoll ist er, wenn **alle drei** Bedingungen gelten:

1. **Offen:** Die Frage ist weder im Feature-File `Entschieden` noch durch `CLAUDE.md` vorgegeben.
2. **Code oder Betrieb:** Was Kunden oder Nutzer sehen oder bemerken, entscheidet der User, nie der Rat. Dazu gehören auch Anmeldewege und Rechte, die Nutzer bemerken, sowie Kosten und Anbieterwahl.
3. **Schwer umkehrbar:** Die Option, die du ohne Rat wählen würdest, fällt in eine dieser Klassen:

| Klasse | Löst aus | Löst nicht aus |
|---|---|---|
| Bestandsdaten | Migration, die vorhandene Zeilen umschreibt, löscht oder einschränkt: Backfill, NOT NULL auf Bestand, Typ- oder Schlüsselwechsel, Spalte oder Tabelle entfernen, neuer Unique-/Check-/FK-Constraint auf Bestand, Umzug von Daten oder Dateien | neue Tabelle; neue Spalte, nullable oder mit konstantem Default |
| Vertrag nach außen | Schnittstelle oder persistiertes Format, das außerhalb des Deploys gelesen wird: öffentliche API, Webhook, Offline-Queue oder IndexedDB-Schema, Storage-Key-Schema, Export-Format | rein additive, optionale Felder |
| Auth und Rechte | Anmeldeweg, Sitzungsart, Rollen- oder Scope-Modell (Org, Besitzer) | Bibliothekswahl hinter unverändertem Modell |
| Datenhaltung | wie Nutzerdaten gelöscht oder überschrieben werden: Hard- oder Soft-Delete, Kaskaden, Aufbewahrung im Log | interne Caches, abgeleitete Daten, die sich neu erzeugen lassen |

## Ablauf

1. **Briefing** (für beide wörtlich gleich, ohne eigene Vorliebe der Hauptsession, damit es nicht verankert):
   - Frage in einem Satz
   - 2–3 Optionen, „weitere sind erlaubt“
   - Vorgaben wörtlich aus dem Feature-File (`Entschieden`, `Default`, betroffene DoD-IDs), Pfad der Repo-`CLAUDE.md`
   - Ist-Stand mit Pfaden und Repo-Pfad
   - Verbote: nichts ändern, keine schreibenden git-Befehle, keine Subagenten
2. **Beide in einer Nachricht parallel starten**, jeweils `Agent(subagent_type: "sonnet-high", model: "sonnet")`, Briefing plus Rolle:
   - **Pragmatiker:** „Empfiehl die einfachste Option, die alle DoD-Punkte und Vorgaben erfüllt. Prüfe gegen den Code, was sie wirklich kostet und was eine spätere Änderung kosten würde.“
   - **Risiko:** „Prüfe jede Option gegen den Code auf Fehlermodi, Datenverlust, Sicherheit, Lock-in und Migrationspfad: Wie käme man zurück? Lies dafür auch die Quellen der beteiligten Bibliotheken.“
3. **Ausgabe je Votum**, höchstens 25 Zeilen:
   ```
   **Empfehlung:** <Option> – <ein Satz>
   **Gründe:** 1. … 2. … 3. … (je mit Datei:Zeile; Unbelegtes als „Verdacht“)
   **Umkehrbar machen:** <was einen späteren Wechsel billig hält: Adapter, Flag, erst additiv migrieren, Doppelschreiben …>
   **Knackpunkt:** <die Annahme, an der die Empfehlung scheitert, und wie man sie prüft>
   **Nutzersichtbar:** <Folgen, die Kunden oder Nutzer bemerken, oder „keine“>
   ```
4. **Entscheiden:** Die Hauptsession prüft die Belege der Voten gegen den Code (`superpowers:receiving-code-review`) und entscheidet. Bei Dissens begründet sie, welcher Knackpunkt schwerer wiegt. Übernommene Maßnahmen zur Umkehrbarkeit und Knackpunkte werden Anforderungen der Spec. Ein Punkt unter „Nutzersichtbar“, den das Feature-File nicht deckt, wird nicht entschieden, sondern als Default mit `offen:` geführt.
5. **Dokumentieren** unter „Entscheidungen/Annahmen“:
   ```
   - **<Frage>** (Architektur-Rat, Klasse <…>): gewählt <Option>, weil <…>.
     - Pragmatiker: <Empfehlung> – Knackpunkt <…>
     - Risiko: <Empfehlung> – Knackpunkt <…>
     - Übernommen: <Maßnahmen>; verworfen: <Punkt> (<Grund>)
     - Wirkung: <Wahl geändert | Anforderung ergänzt | offen: ergänzt | keine>
   ```
6. **Agent-Statistik** nach `auto-feature`, Abschnitt „Agent-Statistik“: Rollen `Rat-Pragmatiker` und `Rat-Risiko`. In die Spalte `angenommen` kommt die Wirkung aus Schritt 5. So lassen sich spätere Versuche auswerten.

## Modellwahl und Kosten

Beide Personas laufen auf `sonnet-high`. Eine Runde kostete im Test rund 360k Sonnet-Input-Äquivalent (Pragmatiker ~160k, Risiko ~205k, parallel etwa 1,5 min). Das ist etwa so viel wie die Entscheidung selbst.

## Stand der Belege (2026-11-09)

- **Getestet:** eine echte Auth-Entscheidung (Passwort-Login mit gleitender Sitzung), Repo-Stand vor der Spec, je 2 Läufe mit und ohne Rat. Alle Entscheider liefen auf `sonnet-high`, nicht auf Opus. Bewertet wurde nach vier Fallen, die damals erst die Opus-Spec-Reviews fanden.
- **Ergebnis:**
  - Mit Rat 3,0 von 4, ohne Rat ebenfalls 3,0. Alle vier Läufe wählten dieselbe Architektur.
  - Ein Risiko-Votum fand den damaligen Blocker fast wörtlich. Für das gewählte Design war er aber irrelevant.
  - Kleiner Gewinn: Die nutzersichtbare Annahme stand mit Rat als `offen:` da.
  - Kleiner Rückschritt: Die Entscheider übernahmen aus den Voten einen Vorschlag, den eine Baseline als Hash-Leck belegt hatte.
- **Auslösetest:** 9/9 in 2 Läufen auf `haiku`, davon 3 zurückgehaltene Fälle. Weil 6 Fälle beim Formulieren vorlagen, ist das ein Konsistenztest, kein Beleg für Trennschärfe bei neuen Fallarten.
- **Warum weitere Forschung nötig ist:** Der Testbericht nennt die offenen Fragen und die nächsten Versuche, unter anderem Opus als Entscheider, lokale Modelle, Ratsmitglieder mit unterschiedlichen Modellen oder Informationen, die anderen Auslöser-Klassen und den Vergleich bei gleichem Budget.
