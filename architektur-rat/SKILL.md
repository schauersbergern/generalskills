---
name: architektur-rat
description: Use when a spec (auto-feature Phase A or by hand) has to settle an open code or operations decision that a PR revert would not undo: migration of existing data, contract or persisted format read outside the deploy, auth/session/permission model, or how user data is deleted or overwritten ("Architektur-Rat", "zweite Meinung zur Architektur", "schwer umkehrbare Entscheidung").
argument-hint: <Frage oder Spec-Abschnitt>
---

# Architektur-Rat

**Kern:** Zwei frische Subagenten bewerten dieselbe offene Entscheidung unabhängig: **Pragmatiker** und **Risiko**. Die Hauptsession entscheidet und dokumentiert beide Voten. Der Rat ist keine Abstimmung und kein Ersatz für das Spec-Review.

## Auslöser

Der Rat tritt zusammen, wenn **alle drei** Bedingungen gelten:

1. **Offen:** Die Frage ist weder im Feature-File `Entschieden` noch durch `CLAUDE.md` vorgegeben.
2. **Code oder Betrieb:** Was Kunden oder Nutzer sehen oder bemerken, entscheidet der User im Feature-File, nie der Rat. Dazu gehören auch Anmeldewege und Rechte, die Nutzer bemerken, sowie Kosten und Anbieterwahl. Fehlt es dort, gilt `auto-feature` Start 3 (Default, offene Frage im Abschlussbericht).
3. **Schwer umkehrbar:** Die Option, die du ohne Rat wählen würdest, fällt in eine dieser Klassen:

| Klasse | Löst aus | Löst nicht aus |
|---|---|---|
| Bestandsdaten | Migration, die vorhandene Zeilen umschreibt, löscht oder einschränkt: Backfill, NOT NULL auf Bestand, Typ- oder Schlüsselwechsel, Spalte oder Tabelle entfernen, neuer Unique-/Check-/FK-Constraint auf Bestand, Umzug von Daten oder Dateien | neue Tabelle; neue Spalte, nullable oder mit konstantem Default |
| Vertrag nach außen | Schnittstelle oder persistiertes Format, das außerhalb des Deploys gelesen wird: öffentliche API, Webhook, Offline-Queue oder IndexedDB-Schema, Storage-Key-Schema, Export-Format | rein additive, optionale Felder |
| Auth und Rechte | Anmeldeweg, Sitzungsart, Rollen- oder Scope-Modell (Org, Besitzer) | Bibliothekswahl hinter unverändertem Modell |
| Datenhaltung | wie Nutzerdaten gelöscht oder überschrieben werden: Hard- oder Soft-Delete, Kaskaden, Aufbewahrung im Log | interne Caches, abgeleitete Daten, die sich neu erzeugen lassen |

**Obergrenze:** 2 Runden je TF, 4 je Lauf, eine Frage je Runde. Darüber hinaus gilt der vorsichtigste umkehrbare Default mit dem Vermerk „ohne Rat (Obergrenze)“ im Abschlussbericht.

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
4. **Entscheiden:** Die Hauptsession prüft die Belege der Voten gegen den Code (`superpowers:receiving-code-review`) und entscheidet. Bei Dissens begründet sie, welcher Knackpunkt schwerer wiegt. Übernommene Maßnahmen zur Umkehrbarkeit und Knackpunkte werden zu Anforderungen der Spec und landen im „Review Focus“ des Plans. Ein Punkt unter „Nutzersichtbar“, den das Feature-File nicht deckt, wird nicht entschieden. Er wird als Default mit `offen:` geführt und gehört in den Abschlussbericht.
5. **Dokumentieren** unter „Entscheidungen/Annahmen“:
   ```
   - **<Frage>** (Architektur-Rat, Klasse <…>): gewählt <Option>, weil <…>.
     - Pragmatiker: <Empfehlung> – Knackpunkt <…>
     - Risiko: <Empfehlung> – Knackpunkt <…>
     - Übernommen: <Maßnahmen>; verworfen: <Punkt> (<Grund>)
     - Wirkung: <Wahl geändert | Anforderung ergänzt | offen: ergänzt | keine>
   ```
6. **Agent-Statistik** nach `auto-feature`, Abschnitt „Agent-Statistik“: Rollen `Rat-Pragmatiker` und `Rat-Risiko`, `--tf` wie das TF. In die Spalte `angenommen` kommt die Wirkung aus Schritt 5.

## Modellwahl und Kosten

Beide Personas laufen auf `sonnet-high`, ohne Opus. Im Test vom 2026-11-09 kostete eine Runde rund 360k Sonnet-Input-Äquivalent (Pragmatiker ~160k, Risiko ~205k, je 1–1,7 min parallel). Das ist etwa so viel wie die Entscheidung selbst. Opus kostet ein Vielfaches und kommt im Spec-Review (Phase B) ohnehin. Ein Rats-Votum auf Opus würde dieses Review nur vorwegnehmen.

## Stand der Belege (2026-11-09)

Getestet an einer echten Auth-Entscheidung (Passwort-Login mit gleitender Sitzung, Stand vor der Spec), je 2 Läufe mit und ohne Rat. Bewertet wurde nach vier Fallen, die damals erst die Opus-Reviews fanden:
- **Wahl und Fallen nicht besser:** Mit Rat 3,0 von 4, ohne Rat ebenfalls 3,0. Beide Seiten wählten dieselbe Architektur. Ein Risiko-Votum fand den damaligen Blocker wörtlich. Die Entscheider kamen aber unabhängig von den Voten zum selben Ergebnis.
- **Kleiner Gewinn:** Die nutzersichtbare Annahme (Passwort-Modus schließt Microsoft-Login aus) stand mit Rat als `offen:` im Abschnitt, ohne Rat nur als Annahme im Text.
- **Erprobung:** Nach 5 echten Runden die Spalte `angenommen` auswerten. Steht dort nie „Wahl geändert“ oder „Anforderung ergänzt“ mit betriebsrelevantem Inhalt, wird die Einbindung in `auto-feature` wieder entfernt.

## Fehler, die vorkommen

| Fehler | Stattdessen |
|---|---|
| Rat für Bibliotheks- oder Strukturfragen, die ein Revert zurücknimmt | Default mit Begründung, kein Rat |
| Der Rat entscheidet über einen Anmeldeweg, den Nutzer bemerken | `Nutzersichtbar` → `offen:` im Abschlussbericht |
| Die Hauptsession schreibt ihre Vorliebe ins Briefing | Optionen neutral, die Wahl erst nach den Voten |
| Voten nur in der Statistik, nicht in der Spec | beide Voten unter „Entscheidungen/Annahmen“ |
