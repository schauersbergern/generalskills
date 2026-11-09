# Retro: Kandidaten für neue Fehlerklassen

Am Ende eines Laufs macht die Hauptsession eine Retro. Sie arbeitet selbst, ohne Subagent. Aus den Befunden des Laufs leitet sie Kandidaten für neue Prüfpunkte ab, legt sie mit Status `offen` ab und nennt sie im Abschlussbericht. Übernommen wird nichts automatisch. Ändern darf eine Session einen Prüfpunkt erst, wenn der User „übernimm K-<n>“ sagt.

- **Kandidatendatei:** `~/Projects/tools/agentic_engineering/werkzeuge/fehlerklassen-kandidaten.md`
- **Werkzeug:** `python3 ~/.claude/skills/auto-feature/scripts/fehlerklassen.py` mit `liste`, `neu`, `beleg` und `status`. Die schreibenden Befehle sperren die Datei, damit parallele Review-Threads keine ID doppelt vergeben. `neu` lehnt einen Kandidaten mit fehlendem Feld ab und schreibt dann nichts.

## Material

Ausgewertet wird nur das Material des Laufs, das schon im Kontext ist: Befundlisten mit Urteilen, der Abschnitt „Review Focus“ des Plans und der Härtungsabschnitt im PR-Body, falls vorhanden. Kein `git log`, keine anderen PRs, keine Messskripte.

Welche Befunde Material sind, legt der aufrufende Skill fest. Für P3 und „Klein“ gilt die **P3-Regel**: Sie zählen nur in zwei Fällen, `liste` führt schon einen Kandidaten derselben Klasse, oder die Klasse kam im Lauf mindestens zweimal vor. Befunde aus Spec- und Plan-Reviews zählen nicht, denn dort wurden sie so früh gefangen wie möglich.

## Ablauf

1. `fehlerklassen.py liste <datei>` aufrufen. Das ergibt eine Zeile je Kandidat; die ganze Datei wird nicht gelesen.
2. Die Befunde nach Klasse gruppieren. Die Klasse ist die verletzte Eigenschaft, nicht der Fundort. Mehrere Befunde derselben Klasse ergeben einen Kandidaten mit mehreren Belegen.
3. Je Klasse genau eine Aktion:
   - **Die Klasse steht schon in `liste`:** Der neue Beleg kommt per `fehlerklassen.py beleg <datei> K-<n>` an diesen Kandidaten. Ist er `übernommen`, hat der übernommene Prüfpunkt nicht gegriffen. Dann kommt zusätzlich ein neuer Kandidat zur Schärfung, dessen Feld „Durchgerutscht“ den alten nennt.
   - **Sonst:** ein neuer Kandidat per `fehlerklassen.py neu <datei> <<'EOF' … EOF`. Mehrere Blöcke passen in einen Aufruf, die IDs stehen in der Ausgabe.
   - **Lässt sich kein Konstrukt benennen** (siehe „Klasse und Prüfpunkt“): kein Kandidat. Der Befund erscheint im Bericht unter „ohne Kandidat“.
4. Bericht schreiben, siehe unten.

## Ein Kandidat

```
## K-? · <Klasse: die verletzte Eigenschaft als Satz über ein Code-Konstrukt>
- Beleg: <PR #n oder Lauf/TF> <Befund-ID> [<P1|P2|P3|Blocker|Wichtig|Mutation|Härtung>], `<datei>:<zeile>` oder `<datei> §<abschnitt>`, <YYYY-MM-DD> — <Befund in einem Satz>
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
- **Wortlaut für einen Skill-Ort** kommt ohne Kunden- und Repo-Namen aus, denn das Skill-Repo ist öffentlich. Diese Namen stehen nur im Beleg.
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

Der User sagt „übernimm K-<n>“. Die Session, die das hört, geht so vor:
1. Sie liest den Kandidaten: `grep -A6 '^## K-<n> ·' <datei>`.
2. **Ort ist ein Skill:** Sie legt einen Worktree im Skill-Repo `~/Projects/skillz/nikskills` auf einem eigenen Branch an. Dort baut sie die deterministische Alternative bzw. fügt den Prüfpunkt im Wortlaut ein und testet nach `superpowers:writing-skills`. Den PR stellt sie erst nach OK. **Ort ist ein Repo:** Die Änderung folgt dessen eigenen Regeln.
3. Sie setzt den Status: `fehlerklassen.py status <datei> K-<n> übernommen "<PR-Link>, <Datum>"`.

Bei „verwirf K-<n> <Grund>“: `fehlerklassen.py status <datei> K-<n> verworfen "<Grund>"`.
