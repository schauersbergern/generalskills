"""Vertragstests für die Skill-Prosa (SKILL.md, references/): Frontmatter, Aufrufformen, Unterbefehle und Optionen
der Skripte, Pflichtabschnitte, Beispiel-JSON gegen das Schema, keine Pfade der Test-App.

Geprüft wird nur der Vertrag mit den Skripten und dem Eval, nie die Formulierung der Prosa.

Aufruf: python3 -m pytest security-audit/scripts/test_skill_text.py -q
"""
import json
import os
import re
import subprocess
import sys

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HIER)
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")
REFERENCES = os.path.join(SKILL_DIR, "references")
BRIEFINGS = os.path.join(REFERENCES, "agenten-briefings.md")
BERICHT_FORMAT = os.path.join(REFERENCES, "bericht-format.md")
ERWARTUNG = os.path.join(SKILL_DIR, "evals", "expected", "fixture-web.json")
# Geschwister-Skill (TF5): per realpath, damit auch ein Symlink ~/.claude/skills/security-audit den Pfad findet
PR_REVIEW_LOOP_MD = os.path.join(os.path.dirname(os.path.realpath(SKILL_DIR)), "pr-review-loop", "SKILL.md")
FIX_FINDINGS_MD = os.path.join(os.path.dirname(os.path.realpath(SKILL_DIR)), "fix-findings", "SKILL.md")

sys.path.insert(0, HIER)
import bericht  # noqa: E402
import poc  # noqa: E402

PRAEFIX_SKILL = ("python3 -I ${CLAUDE_SKILL_DIR}/scripts/", "python3 ~/.claude/skills/auto-feature/scripts/agent-stats.py")
PRAEFIX_REFERENZ = ("python3 -I <SKILL_DIR>/scripts/",)
SKRIPTE = ("poc", "bericht")


def _lies(pfad: str) -> str:
    with open(pfad, encoding="utf-8") as f:
        return f.read()


def _referenzen() -> list[str]:
    assert os.path.isdir(REFERENCES), "references/ fehlt"
    return sorted(os.path.join(REFERENCES, n) for n in os.listdir(REFERENCES) if n.endswith(".md"))


def _bloecke(text: str) -> list[tuple[str, str]]:
    """Codeblöcke (Zaun aus ≥ 3 Backticks, auch länger) als (Info-Zeile, Inhalt)."""
    ergebnis, zeilen, i = [], text.split("\n"), 0
    while i < len(zeilen):
        m = re.match(r"^(\s*)(`{3,})(.*)$", zeilen[i])
        if not m:
            i += 1
            continue
        zaun, info, inhalt = m.group(2), m.group(3).strip(), []
        i += 1
        while i < len(zeilen) and not re.match(r"^\s*" + zaun + r"`*\s*$", zeilen[i]):
            inhalt.append(zeilen[i])
            i += 1
        i += 1
        ergebnis.append((info, "\n".join(inhalt)))
    return ergebnis


def _code_zeilen(text: str, bloecke: bool = True) -> list[str]:
    """Zeilen aus Codeblöcken (nur mit `bloecke`) plus alle Inline-Code-Spans außerhalb der Blöcke, gestrippt."""
    zeilen = [z.strip() for _info, inhalt in _bloecke(text) for z in inhalt.split("\n")] if bloecke else []
    ohne_bloecke = re.sub(r"(?ms)^\s*(`{3,}).*?^\s*\1`*\s*$", "", text)
    zeilen += [s.strip() for s in re.findall(r"`([^`\n]+)`", ohne_bloecke)]
    return [z for z in zeilen if z]


def _aufrufzeilen(text: str) -> list[str]:
    return [z for z in _code_zeilen(text) if z.startswith("python3")]


def _frontmatter_roh(text: str) -> dict[str, str]:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert m, "Frontmatter fehlt"
    werte = {}
    for zeile in m.group(1).split("\n"):
        schluessel, doppelpunkt, wert = zeile.partition(":")
        if doppelpunkt:
            werte[schluessel.strip()] = wert.strip()
    return werte


def _frontmatter(text: str) -> dict[str, str]:
    """Werte ohne die einfachen Anführungszeichen, mit denen YAML sie einfasst."""
    return {k: (v[1:-1].replace("''", "'") if len(v) >= 2 and v[0] == v[-1] == "'" else v)
            for k, v in _frontmatter_roh(text).items()}


def _hilfe(skript: str, *unterbefehl: str) -> str:
    r = subprocess.run([sys.executable, "-I", os.path.join(HIER, f"{skript}.py"), *unterbefehl, "--help"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


def _unterbefehle(skript: str) -> set[str]:
    m = re.search(r"\{([^}]+)\}", _hilfe(skript))
    assert m, f"{skript}.py --help nennt keine Unterbefehle"
    return set(m.group(1).split(","))


def _aufrufe(text: str) -> list[tuple[str, str, str]]:
    """(skript, unterbefehl, ganze Zeile) für jede Aufrufzeile (`python3 …` in Blöcken) und jeden Inline-Span, in dem
    `poc.py <wort>` oder `bericht.py <wort>` steht. Fließtext in Codeblöcken (Briefing-Vorlagen) zählt nicht."""
    zeilen = [z for z in _code_zeilen(text) if z.startswith("python3")] + _code_zeilen(text, bloecke=False)
    gefunden = []
    for zeile in zeilen:
        for m in re.finditer(r"\b(poc|bericht)\.py\s+([A-Za-zÄÖÜäöüß][\w-]*)", zeile):
            gefunden.append((m.group(1), m.group(2), zeile))
    return gefunden


# ------------------------------------------------------------------------------------ Frontmatter

def test_frontmatter():
    fm = _frontmatter(_lies(SKILL_MD))
    assert fm["name"] == "security-audit"
    assert fm["model"] == "opus"
    assert fm["effort"] == "xhigh"
    assert fm["disallowed-tools"] == "WebFetch, WebSearch"
    assert fm["argument-hint"] == '[teilpfad] [projekt="…"] [repo-konfig-geprueft]'
    assert fm.get("description"), "description fehlt"


def test_frontmatter_ist_gueltiges_yaml():
    """Ungequotete Werte dürfen nicht mit `[`, `{`, `"`, `'`, `*`, `&`, `!`, `|`, `>`, `%`, `@` oder `` ` `` beginnen und
    kein `: ` oder ` #` enthalten (YAML-Plain-Scalar); mit PyYAML, falls vorhanden, wird zusätzlich echt geparst."""
    text = _lies(SKILL_MD)
    for schluessel, wert in _frontmatter_roh(text).items():
        if wert[:1] == "'":
            assert wert[-1] == "'" and len(wert) >= 2, f"{schluessel}: Anführungszeichen nicht geschlossen"
            continue
        assert wert[:1] not in set("[{\"*&!|>%@`"), f"{schluessel}: Plain-Scalar beginnt mit {wert[:1]!r}"
        assert ": " not in wert and " #" not in wert, f"{schluessel}: Plain-Scalar enthält ': ' oder ' #'"
    yaml = pytest.importorskip("yaml")
    daten = yaml.safe_load(re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL).group(1))
    assert daten["argument-hint"] == '[teilpfad] [projekt="…"] [repo-konfig-geprueft]'
    assert all(isinstance(v, str) for v in daten.values())


# ------------------------------------------------------------------------------------ Aufrufformen

def test_aufrufzeilen_skill_md():
    zeilen = _aufrufzeilen(_lies(SKILL_MD))
    assert zeilen, "SKILL.md enthält keine Aufrufzeilen"
    schlecht = [z for z in zeilen if not z.startswith(PRAEFIX_SKILL)]
    assert not schlecht, schlecht


@pytest.mark.parametrize("pfad", _referenzen() if os.path.isdir(REFERENCES) else [], ids=os.path.basename)
def test_references_platzhalter_und_aufrufzeilen(pfad):
    text = _lies(pfad)
    assert "${CLAUDE_SKILL_DIR}" not in text
    schlecht = [z for z in _aufrufzeilen(text) if not z.startswith(PRAEFIX_REFERENZ)]
    assert not schlecht, schlecht


def test_briefings_haben_aufrufzeilen_mit_platzhalter():
    assert _aufrufzeilen(_lies(BRIEFINGS)), "agenten-briefings.md enthält keine Aufrufzeilen"


def test_alle_drei_references_vorhanden():
    namen = {os.path.basename(p) for p in _referenzen()}
    assert {"agenten-briefings.md", "bericht-format.md", "pruefpunkte-web.md"} <= namen


# ------------------------------------------------------------------------------------ Unterbefehle und Optionen

@pytest.mark.parametrize("pfad", [SKILL_MD, BRIEFINGS, BERICHT_FORMAT, FIX_FINDINGS_MD], ids=lambda p: os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p))
def test_unterbefehle_existieren(pfad):
    erlaubt = {s: _unterbefehle(s) for s in SKRIPTE}
    aufrufe = _aufrufe(_lies(pfad))
    schlecht = [(s, u) for s, u, _z in aufrufe if u not in erlaubt[s]]
    assert not schlecht, schlecht


@pytest.mark.parametrize("pfad", [SKILL_MD, BRIEFINGS, BERICHT_FORMAT, FIX_FINDINGS_MD], ids=lambda p: os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p))
def test_optionen_existieren(pfad):
    """Jede `--option` einer Aufrufzeile steht in der --help des Unterbefehls."""
    hilfen: dict[tuple[str, str], str] = {}
    schlecht = []
    for skript, unter, zeile in _aufrufe(_lies(pfad)):
        if unter not in _unterbefehle(skript) or not zeile.startswith("python3"):
            continue
        hilfe = hilfen.setdefault((skript, unter), _hilfe(skript, unter))
        for option in re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", zeile):
            if option != "--help" and option not in hilfe:
                schlecht.append((skript, unter, option))
    assert not schlecht, schlecht


def test_skill_md_nennt_jeden_poc_unterbefehl():
    """Der Ablauf braucht alle Unterbefehle von poc.py und bericht.py."""
    gesehen = {(s, u) for s, u, _z in _aufrufe(_lies(SKILL_MD))}
    fehlt = [(s, u) for s in SKRIPTE for u in sorted(_unterbefehle(s)) if (s, u) not in gesehen]
    assert not fehlt, fehlt


# ------------------------------------------------------------------------------------ Abschnitte

def test_briefings_abschnitte():
    ueberschriften = re.findall(r"(?m)^## (.+?)\s*$", _lies(BRIEFINGS))
    assert "Reviewer" in ueberschriften
    assert "Prüfer" in ueberschriften


# ------------------------------------------------------------------------------------ Härtung TF1-A6

BASH_TIMEOUT = "timeout: 600000"
# laufen länger als der Bash-Standard (120 s); jeder hat ein eigenes Zeitbudget (Härtung B1, I3)
LANGE_UNTERBEFEHLE = ("vorbereiten", "bauen", "starten", "neustart", "ausfuehren", "aufraeumen")
NICHT_GEPRUEFT = "nicht geprüft (Budget)"


def test_timeout_liste_nennt_alle_langen_unterbefehle_haertung_a6():
    """Jede Zeile mit dem 600000-ms-Timeout nennt alle langen poc.py-Unterbefehle (keine Teilliste in SKILL.md)."""
    zeilen = [z for z in _lies(SKILL_MD).splitlines() if BASH_TIMEOUT in z]
    assert zeilen, "kein Hinweis auf Bash-timeout 600000 in SKILL.md"
    for zeile in zeilen:
        assert all(f"poc.py {u}" in zeile for u in LANGE_UNTERBEFEHLE), zeile
        assert "bericht.py kontext" in zeile, zeile
    briefing = [z for z in _lies(BRIEFINGS).splitlines() if "timeout 600000" in z]
    assert briefing and all(u in briefing[0] for u in ("neustart", "ausfuehren"))


def test_zeitbudgets_in_skill_md_entsprechen_den_skripten_haertung_i3():
    """Die Zeitbudget-Zusage in SKILL.md nennt je Befehl den Wert, den das Skript wirklich verwendet, und die Umgebungsvariable."""
    zeile = next(z for z in _lies(SKILL_MD).splitlines() if BASH_TIMEOUT in z)
    erwartet = {"bericht.py kontext": bericht.KONTEXT_BUDGET, "poc.py vorbereiten": poc.VORBEREITEN_BUDGET,
                "poc.py starten": poc.START_BUDGET, "poc.py neustart": poc.START_BUDGET,
                "poc.py aufraeumen": poc.AUFRAEUMEN_BUDGET, "poc.py bauen": poc.BAU_TIMEOUT,
                "poc.py ausfuehren": poc.EXEC_TIMEOUT}
    zusage = zeile[zeile.index("Jeder dieser Aufrufe"):]
    for befehl, sekunden in erwartet.items():
        assert re.search(rf"`{re.escape(befehl)}`[^`]*?{sekunden} s", zusage), (befehl, sekunden)
    assert "SECURITY_AUDIT_KONTEXT_TIMEOUT" in zusage and "SECURITY_AUDIT_KONTEXT_TIMEOUT" in _lies(os.path.join(HIER, "bericht.py"))
    assert "nur für `kontext` und `vorbereiten` zugesichert" in zusage          # keine pauschale Zusage unter 600 s
    assert "unter 600 s" not in zusage


def test_budget_vermerk_in_skill_und_format_haertung_a6():
    """Mehr als 12 P1/P2 je Prüfer: der Grund steht in `beschreibung`, mit dem festen Vermerk."""
    for pfad in (SKILL_MD, BERICHT_FORMAT):
        assert NICHT_GEPRUEFT in _lies(pfad), pfad
    zeile = next(z for z in _lies(SKILL_MD).splitlines() if NICHT_GEPRUEFT in z)
    assert "beschreibung" in zeile and "unbestätigt" in zeile


def test_kern_behauptet_keinen_widerlegungsversuch_fuer_jedes_unbestaetigt_haertung_a6():
    """P3, ungeprüfter Rest und von der Hauptsession übernommene Aufträge sind `unbestätigt` ohne Prüfer-Widerlegung:
    der Kern-Absatz sagt das (Verweis auf `beschreibung`) und nennt den Widerlegungsversuch nur für geprüfte Befunde."""
    kern = next(z for z in _lies(SKILL_MD).splitlines() if z.startswith("**Kern:**"))
    assert "beschreibung" in kern and "geprüft" in kern
    assert "P3" in kern


def test_vorbereiten_wird_mit_dem_ermittelten_sha_aufgerufen_haertung_b3():
    """Die Arbeitskopie stammt vom SHA, den der Bericht nennt: `vorbereiten` bekommt `--sha <sha>` aus dem Kontext."""
    zeilen = [z for z in _aufrufzeilen(_lies(SKILL_MD)) if "poc.py vorbereiten" in z]
    assert zeilen and all("--sha <sha>" in z for z in zeilen), zeilen


def test_alle_hinweis_kategorien_von_poc_sind_dokumentiert_haertung_b5():
    """Jede Kategorie, die `poc.py bauen` als `hinweis:` ausgeben kann, steht in SKILL.md und im Berichtsformat."""
    import poc
    assert set(poc.HINWEIS_KATEGORIEN) >= {"native-module", "prisma-engines", "node-range-zu-lang",
                                           "node-engines-ignoriert", "lockfile-ohne-paketliste"}
    quelle = _lies(os.path.join(HIER, "poc.py"))
    verwendet = set(re.findall(r'"((?:native-module|prisma-engines|node-[a-z-]+|lockfile-ohne-[a-z-]+))"', quelle))
    assert verwendet <= set(poc.HINWEIS_KATEGORIEN), verwendet - set(poc.HINWEIS_KATEGORIEN)
    for pfad in (SKILL_MD, BERICHT_FORMAT):
        text = _lies(pfad)
        fehlt = [k for k in poc.HINWEIS_KATEGORIEN if k not in text]
        assert not fehlt, (pfad, fehlt)


def test_request_dateien_der_pruefer_kollidieren_nicht_haertung_b6():
    """Beide Prüfer laufen gleichzeitig und teilen `<DATEIORDNER>`: jeder `--daten-datei`-Name trägt die Rolle."""
    beispiele = re.findall(r"--daten-datei (\S+)", _lies(BRIEFINGS))
    assert beispiele, "kein --daten-datei-Beispiel im Prüfer-Briefing"
    assert all("<ROLLE>" in b for b in beispiele), beispiele
    assert "<ROLLE>" in next(z for z in _lies(BRIEFINGS).splitlines() if "Request-Body kommt nie per --daten" in z)


# ------------------------------------------------------------------------------------ Härtung TF1-B7 (Zusagen)

def test_briefings_versprechen_keine_nachtraegliche_erkennung_im_echten_lauf_haertung_b7():
    """Nur Eval und `rendern` erkennen Verstöße im Nachhinein; in einem echten Audit gibt es das nicht."""
    text = _lies(BRIEFINGS)
    assert "sie wird im Nachhinein erkannt" not in text
    for zeile in (z for z in text.splitlines() if z.startswith("GRUNDREGELN")):
        assert "Eval" in zeile, zeile


def test_regel_9_nennt_die_grenze_der_bestaetigt_pruefung_haertung_b7():
    regel = next(z for z in _lies(SKILL_MD).splitlines() if z.startswith("9. **Die Netzregel"))
    assert "nicht, dass der Request lief" in regel and "Gegenlesen" in regel


def test_skill_md_nennt_teilpfad_pruefung_und_reservierung_haertung_b7():
    text = _lies(SKILL_MD)
    assert ".reserviert" in _lies(BERICHT_FORMAT)
    assert "Ausgabeordner" in text and "im geprüften Repo" in text           # Exit 3 auch dafür
    exit3 = next(z for z in text.splitlines() if z.startswith("- Exit 3"))   # die Abbruchzeile von `kontext`, nicht irgendeine Stelle
    assert "Ausgabeordner im geprüften Repo" in exit3 and "stderr dem User melden" in exit3
    assert "rendern" in next(z for z in text.splitlines() if "Befunde außerhalb von `teilpfad`" in z)


# ------------------------------------------------------------------------------------ Beispiel-JSON

def _beispiel_json() -> dict:
    """Das erste vollständige JSON-Beispiel mit `befunde` aus bericht-format.md."""
    kandidaten = []
    for info, inhalt in _bloecke(_lies(BERICHT_FORMAT)):
        if info.startswith("json"):
            try:
                daten = json.loads(inhalt)
            except ValueError:
                continue
            if isinstance(daten, dict) and "befunde" in daten:
                kandidaten.append(daten)
    assert kandidaten, "kein vollständiges JSON-Beispiel mit `befunde` in bericht-format.md"
    return kandidaten[0]


def test_beispiel_json_ist_gueltig():
    """Das JSON-Beispiel in bericht-format.md besteht das Schema von bericht.py und zeigt jeden Status."""
    daten = _beispiel_json()
    assert bericht.pruefe_schema(daten) == []
    assert {b["status"] for b in daten["befunde"]} == set(bericht.STATUS)


# ------------------------------------------------------------------------------------ TF5: Vertrag mit fix-findings

AUDIT_MARKER = "<!-- audit-kopfzeile -->"


def _audit_muster() -> str:
    """Die eine Regex-Zeile im Codezaun, die nach dem Marker in fix-findings/SKILL.md folgt (Einrückung erlaubt)."""
    zeilen = _lies(FIX_FINDINGS_MD).split("\n")
    marker = [i for i, z in enumerate(zeilen) if z.strip() == AUDIT_MARKER]
    assert len(marker) == 1, f"{AUDIT_MARKER} muss genau einmal in fix-findings/SKILL.md stehen"
    rest = [z for z in zeilen[marker[0] + 1:] if z.strip()]
    zaun = re.match(r"^\s*(`{3,})\s*$", rest[0])
    assert zaun, "direkt nach dem Marker muss ein Codezaun öffnen"
    inhalt = []
    for z in rest[1:]:
        if re.match(r"^\s*" + zaun.group(1) + r"`*\s*$", z):
            break
        inhalt.append(z)
    else:
        raise AssertionError("Codezaun nach dem Marker nicht geschlossen")
    assert len(inhalt) == 1, f"der Codezaun enthält genau eine Zeile, nicht {len(inhalt)}"
    return inhalt[0].strip()


def test_audit_kopfzeile_vertrag():
    """Das Erkennungsmuster in fix-findings passt auf die Kopfzeile von bericht.markdown, auch eingerückt und mit Begleittext
    davor, und nie auf die PR-Kopfzeile von pr-review-loop."""
    muster = _audit_muster()
    kopf = _bloecke(bericht.markdown(_beispiel_json()))[0][1].split("\n")[0]
    assert re.fullmatch(muster, kopf), (muster, kopf)
    assert re.fullmatch(muster, ("    " + kopf).strip())
    assert re.fullmatch(muster, ("\t" + kopf + "  ").strip())
    assert not re.fullmatch(muster, "PR #12 · Code · Runde 1/3 · geprüft auf abc1234")
    eingabe = "mergen\nbitte fixen:\n```\n" + kopf + "\n```"
    assert sum(1 for z in eingabe.split("\n") if re.fullmatch(muster, z.strip())) == 1


@pytest.mark.parametrize("repo, sha", [
    ("My_App.v2", "0123456"),
    ("Web_App", "a" * 64),
    ("a", "b" * 40),
    ("x.y-z_9", "0123456789abcdef"),
], ids=["gross-punkt-unterstrich-sha7", "unterstrich-sha64", "ein-zeichen", "mischform"])
def test_audit_kopfzeile_vertrag_schemaraender(repo, sha):
    """Review R1-2: Die Regex deckt den ganzen Wertebereich des Schemas ab (repo [A-Za-z0-9._-]+, sha 7 bis 64 Hex), nicht nur die
    Beispielzeile; eine Verengung (z. B. `[a-z-]+`, `{40}`) wird rot."""
    daten = json.loads(json.dumps(_beispiel_json()))
    daten["repo"], daten["sha"] = repo, sha
    assert bericht.pruefe_schema(daten) == []
    kopf = _bloecke(bericht.markdown(daten))[0][1].split("\n")[0]
    assert kopf == f"Repo {repo} · Security-Audit · geprüft auf {sha}", kopf
    assert re.fullmatch(_audit_muster(), kopf), (_audit_muster(), kopf)


def _audit_erkennung() -> str:
    text = _lies(FIX_FINDINGS_MD)
    m = re.search(r"\*\*Erkennung:\*\*.*?(?=\n\s*<!-- audit-kopfzeile -->)", text, re.S)
    assert m, "Erkennungsabsatz vor dem Marker nicht gefunden"
    return m.group(0)


def test_audit_erkennung_pr_kopfzeile_hat_vorrang():
    """Review R1-5: Zitiert eine pr-review-loop-Liste die Audit-Kopfzeile in einem Befund, gewinnt der PR-Weg."""
    erkennung = _audit_erkennung()
    assert "Vorrang" in erkennung and "PR #[0-9]+ · " in erkennung
    m = re.search(r"`(PR #\[0-9\]\+ · )`", erkennung)
    assert m, "Vorrangmuster nicht im Erkennungsabsatz"
    vorlage = [z for z in _lies(PR_REVIEW_LOOP_MD).split("\n") if z.startswith("PR #<n> · ")]
    assert vorlage, "Kopfzeilen-Vorlage in pr-review-loop/SKILL.md nicht gefunden"
    pr_kopf = vorlage[0].replace("<n>", "12")
    assert re.match("^" + m.group(1), pr_kopf), (m.group(1), pr_kopf)
    assert not re.match("^" + m.group(1), "Repo beispiel-shop · Security-Audit · geprüft auf abc1234")


def test_fix_findings_audit_weg_zielt_gh_explizit_auf_origin():
    """Review R1-1/R2-2: Ohne Argument löst gh das Repo über `gh repo set-default`/upstream auf, gepusht wird aber nach origin, und
    zwar an dessen Push-URL (`remote.origin.pushurl`). Sichtbarkeit und compare-Link prüfen daher `get-url --push`, die Basis (aus
    origin/* gefetcht) die Fetch-URL."""
    text = _lies(FIX_FINDINGS_MD)
    aufrufe = re.findall(r"gh repo view[^`]*", text)
    assert len(aufrufe) == 3, aufrufe
    erwartet = {"defaultBranchRef": "get-url origin", "visibility": "get-url --push origin", "url": "get-url --push origin"}
    for a in aufrufe:
        feld = a.rsplit("--json ", 1)[1].strip()
        assert a.startswith(f'gh repo view "$(git remote {erwartet[feld]})"'), a
    assert "gh repo view --json" not in text


def test_fix_findings_kein_unerreichbarer_ohne_github_zweig():
    """Review R2-1: Gepusht wird nur nach erfolgreichem `gh repo view <origin>`, also immer bei GitHub-Origin; ein Sonst-Zweig für
    „Branch gepusht“ ohne compare-Link ist unerreichbar."""
    assert "Branch gepusht" not in _lies(FIX_FINDINGS_MD)


def test_fix_findings_basis_hereinholen_ist_fast_forward():
    """Review R1-3: Die Basis enthält den geprüften SHA immer, `git merge` ist daher ein Fast-forward ohne Konfliktzweig."""
    text = _lies(FIX_FINDINGS_MD)
    punkt = re.search(r"\*\*Basis hereinholen:\*\*[^\n]*", text).group(0)
    assert "git merge --ff-only origin/<basis>" in punkt
    assert "eigener Merge-Commit" not in punkt and "Konflikt" not in punkt


def test_fix_findings_audit_ohne_push_gilt_als_ohne_ci():
    """Review R1-4: Wird nicht gepusht (öffentlich/unbestimmbar), läuft nie eine CI, also läuft die ganze Suite vor dem Abschluss."""
    text = _lies(FIX_FINDINGS_MD)
    punkt = re.search(r"- \*\*Audit-Liste:\*\* Fehlt `\.github/workflows/`[^\n]*", text).group(0)
    assert "nicht gepusht" in punkt and "ohne CI" in punkt and "Sichtbarkeit" in punkt


def test_fix_findings_nennt_bericht_repo():
    assert "bericht.py repo" in _lies(FIX_FINDINGS_MD)


def test_fix_findings_description_ist_gueltiges_plain_scalar():
    """Beide Eingänge stehen in der Description, ohne `: ` (YAML-Plain-Scalar)."""
    beschreibung = _frontmatter_roh(_lies(FIX_FINDINGS_MD))["description"]
    assert ": " not in beschreibung and " #" not in beschreibung and beschreibung[:1] not in set("[{\"'*&!|>%@`")
    assert "security-audit" in beschreibung


# ------------------------------------------------------------------------------------ Test-App nicht verraten

def _verbotene_texte() -> list[str]:
    erwartung = json.loads(_lies(ERWARTUNG))
    texte = list(erwartung.get("verbotene_muster", []))
    for eintrag in erwartung["eintraege"]:
        texte += eintrag["dateien"]
    assert texte
    return texte


@pytest.mark.parametrize("pfad", [SKILL_MD] + (_referenzen() if os.path.isdir(REFERENCES) else []), ids=os.path.basename)
def test_keine_pfade_der_test_app(pfad):
    """Beispielpfade sind neutral: weder Dateien aus evals/expected/fixture-web.json noch fixture.invalid."""
    text = _lies(pfad)
    treffer = [t for t in _verbotene_texte() if t in text]
    assert not treffer, treffer
    assert "fixture.invalid" not in text


def test_fix_findings_oeffentliches_repo_kein_push():
    """Entscheidung 2026-11-11 (PR #9): Audit-Listen werden bei öffentlichem oder unbestimmbarem Repo nicht gepusht."""
    text = _lies(FIX_FINDINGS_MD)
    assert "Bei `PUBLIC` oder wenn sie sich nicht bestimmen lässt: **kein Push**" in text
    assert "Nicht gepusht: öffentliches Repo — Branch, Commits und Tests würden die Lücken vor dem Deploy offenlegen." in text
    assert "Vor dem Push die Sichtbarkeit" in text
    assert "Öffentliches Repo: Branch, Commits und Tests beschreiben die Lücken" not in text
