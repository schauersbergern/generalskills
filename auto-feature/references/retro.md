# Retro: Kandidaten für neue Fehlerklassen

Am Ende eines Laufs macht die Hauptsession eine Retro. Sie arbeitet selbst, ohne Subagent. Aus den Befunden des Laufs leitet sie Kandidaten für neue Prüfpunkte ab, legt sie mit Status `offen` ab und nennt sie im Abschlussbericht. Übernommen wird nichts automatisch. Ändern darf eine Session einen Prüfpunkt erst, wenn der User „übernimm K-<n>“ sagt.

- **Kandidatendatei:** `~/Projects/tools/agentic_engineering/werkzeuge/fehlerklassen-kandidaten.md`
- **Werkzeug:** `python3 ~/.claude/skills/auto-feature/scripts/fehlerklassen.py` mit `liste`, `zeige`, `neu`, `beleg` und `status`. Die schreibenden Befehle sperren die Datei, damit parallele Review-Threads keine ID doppelt vergeben. `neu` lehnt einen Block mit fehlendem Feld, leerem Wert, Zaunzeile oder fremder Zeile ab und schreibt dann nichts, auch bei mehreren Blöcken. `beleg` überspringt einen Beleg, den der Kandidat schon hat (gleiche Quelle und Befund-ID), meldet ihn auf stderr und schreibt die übrigen, auch aus einem Aufruf mit mehreren Belegen; ohne neuen Beleg endet es mit Exit 1. Jeden Beleg an einen verworfenen Kandidaten lehnt es ab. Nur ein offener Kandidat wechselt den Status.

## Material

Ausgewertet wird nur das Material des Laufs, das schon im Kontext ist: Befundlisten mit Urteilen, der Abschnitt „Review Focus“ des Plans und der Härtungsabschnitt im PR-Body, falls vorhanden. Kein `git log`, keine anderen PRs, keine Messskripte.

Welche Befunde Material sind, legt der aufrufende Skill fest. Für P3 und „Klein“ gilt die **P3-Regel**: Sie zählen nur in zwei Fällen, `liste` führt schon einen Kandidaten derselben Klasse (`offen` oder `übernommen`, kein verworfener), oder die Klasse kam im Lauf mindestens zweimal vor. Befunde aus Spec- und Plan-Reviews zählen nicht, denn dort wurden sie so früh gefangen wie möglich.

## Ablauf

1. `fehlerklassen.py liste <datei>` aufrufen. Das ergibt eine Zeile je Kandidat; die ganze Datei wird nicht gelesen. **Eine Retro je PR bzw. Lauf:** Läuft sie nach einer freigegebenen weiteren Runde ein zweites Mal, belegt sie nur Befunde der neuen Runden. Meldet `beleg` einen Beleg als übersprungen, ist der Befund erfasst; weiteres ist nicht nötig.
2. Die Befunde nach Klasse gruppieren. Die Klasse ist die verletzte Eigenschaft, nicht der Fundort. Mehrere Befunde derselben Klasse ergeben einen Kandidaten mit mehreren Belegen.
3. Je Klasse genau eine Aktion:
   - **Die Klasse steht schon in `liste`:** Der neue Beleg kommt per `fehlerklassen.py beleg <datei> K-<n> <<'EOF' … EOF` (die Zeile „- Beleg: …“ von stdin) an diesen Kandidaten. Ist er `übernommen` und der PR gemergt, hat der übernommene Prüfpunkt nicht gegriffen. Dann kommt zusätzlich ein neuer Kandidat zur Schärfung, dessen Feld „Durchgerutscht“ den alten nennt.
   - **Die Klasse steht als `verworfen` in `liste`:** Sie bekommt keinen Beleg. Kam sie als P1/P2 wieder, entsteht ein neuer Kandidat, dessen Feld „Durchgerutscht“ den verworfenen K-<n> samt Grund nennt. Sonst gilt die P3-Regel.
   - **Sonst:** ein neuer Kandidat per `fehlerklassen.py neu <datei> <<'EOF' … EOF`. Mehrere Blöcke passen in einen Aufruf, die IDs stehen in der Ausgabe.
   - **Lässt sich kein Konstrukt benennen** (siehe „Klasse und Prüfpunkt“): kein Kandidat. Der Befund erscheint im Bericht unter „ohne Kandidat“.
4. Bericht schreiben, siehe unten.

## Ein Kandidat

```
## K-? · <Klasse: die verletzte Eigenschaft als Satz über ein Code-Konstrukt>
- Beleg: <PR #n oder Lauf/TF> <Befund-ID> [<P1|P2|P3|Blocker|Wichtig|Klein|Mutation|Härtung|Design>], `<datei>:<zeile>` oder `<datei> §<abschnitt>`, <YYYY-MM-DD> — <Befund in einem Satz>
- Durchgerutscht: <zuständige vorhandene Prüfung mit Nummer und was sie im Lauf geliefert hat> | keine vorhandene Prüfung fragt nach <Konstrukt> | nicht feststellbar: <welches Material fehlt>
- Prüfpunkt (<Ort>): „<Auslöser: Konstrukt, das man in Plan oder Diff erkennt> → <Nachweis: Test oder Messung mit beobachtbarem Ergebnis>“
- Deterministisch: <Werkzeug und Regel, Test-Muster, Hook oder CI-Schritt, der die Klasse ohne Modell fängt> | keine, weil <Grund>
- Status: offen
```

- **Klasse und Prüfpunkt** benennen ein Konstrukt, das man beim Lesen eines Plans oder Diffs erkennt. Beispiele: eine neue Sperre, eine Methode mit Claim-Token, die Einstufung eines Fehlers als endgültig, ein Versionssprung der DB, ein Befehl in einem Ops-Text. Der Nachweis ist ein Test, eine Mutation oder eine Messung, deren Ergebnis man ablesen kann. Vorbild ist die Checkliste „Review Focus“ in `auto-feature`: „Jede neue Sperre … bekommt einen Test, der nachweist, dass der zweite Aufrufer tatsächlich wartet“.
- **Durchgerutscht** hält fest, was im Lauf zu beobachten war: welcher Review-Focus-Punkt im Plan stand, was die Härtung zu ihrer Frage notiert hat, welchen Fokus die Reviewer hatten. Vermutungen gehören nicht hierher.
- **Ort** ist die Stelle, an der der Punkt künftig geprüft wird:
  - `auto-feature Review Focus`: Der Plan prüft vor dem Bauen. Das ist die früheste und billigste Stelle.
  - `auto-feature Härtung Frage <n>, ergänzen`, `auto-feature Härtung Frage <n>, ersetzen` oder `auto-feature Härtung neu`
  - `auto-feature Spec-Review` oder `auto-feature Plan-Review` (Briefing)
  - `pr-review-loop Reviewer-Briefing`
  - `fix-findings Schritt <n>`
  - `Repo <name>: CLAUDE.md`, `Repo <name>: Test` oder `Repo <name>: Lint`, wenn das Konstrukt nur in einem Repo vorkommt, etwa dessen API, Image oder Konvention
- **Alles, was im Skill-Repo landet,** kommt ohne Kunden- und Repo-Namen aus, denn das Repo ist öffentlich: der Wortlaut des Prüfpunkts, die Begründung, die Commit-Message und der PR-Text. Diese Namen stehen nur im Beleg in der Kandidatendatei.
- **Deterministisch** wird vor dem Prüfpunkt durchdacht: grep im CI, eine Lint-Regel (z. B. ESLint `no-restricted-syntax`, ruff), ein wiederverwendbares Test-Muster oder ein Hook. Gibt es eine solche Alternative, ist sie der Hauptvorschlag, und der Prüfpunkt dient als Rückfall.

## Bericht

Die Retro steht als eigener Abschnitt im Abschlussbericht bzw. in der Abschlussmeldung, mit einer Zeile je Kandidat:

```
Retro: K-7 neu · <Klasse> · <Ort>
Retro: K-3 +Beleg (jetzt 2) · <Klasse>
Ohne Kandidat: R1-5, R1-6 (kein Konstrukt benennbar)
Freigabe: „übernimm K-<n>“ oder „verwirf K-<n> <Grund>“
```

Gibt es kein Material, genügt eine Zeile: `Retro: kein Material (<was gezählt wurde, z. B. 0 P1/P2>)`.

## Übernahme

Der User sagt „übernimm K-<n>“. Die Session, die das hört, baut die Änderung nicht selbst. Ein Reviewer-Thread darf keine Dateien ändern, die `auto-feature`-Hauptsession schreibt keinen Code, und die Arbeit gehört nicht in den Kontext des Laufs. Sie startet eine eigene Session (Desktop-App: `start_session`) bzw. einen Subagenten. Der Brief ist die Ausgabe von `fehlerklassen.py zeige <datei> K-<n>` im Wortlaut plus der Auftrag.

1. **Ort ist ein Skill:** Die Session legt einen Worktree im Skill-Repo `~/Projects/skillz/nikskills` auf einem eigenen Branch an. Dort baut sie die deterministische Alternative bzw. fügt den Prüfpunkt im Wortlaut ein und testet nach `superpowers:writing-skills`. Den PR stellt sie erst nach OK des Users. **Ort ist ein Repo:** Die Änderung folgt dessen eigenen Regeln.
2. **Die hörende Session setzt nur den Status,** erst nachdem der User den Merge des PRs gemeldet hat: `fehlerklassen.py status <datei> K-<n> übernommen "<PR-Link>, <Datum>"`. Bis dahin bleibt der Kandidat `offen`. So zählt ein neuer Beleg nicht als „hat nicht gegriffen“, solange der Prüfpunkt nicht gemergt ist.

Bei „verwirf K-<n> <Grund>“ setzt die hörende Session sofort: `fehlerklassen.py status <datei> K-<n> verworfen "<Grund>"`. Ein übernommener oder verworfener Kandidat wechselt den Status nicht mehr, der Vermerk bleibt stehen.
