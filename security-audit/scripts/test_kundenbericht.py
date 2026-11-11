"""Tests für kundenbericht.py (TF4, Teil 2a: CLI, Exit-Codes, Eingabe, Prüfung, Ablage; Teil 2b: Inhalt des Markdowns, Escaping;
Teil 3: PDF-Kette mit pandoc und weasyprint).

Aufruf: python3 -m pytest security-audit/scripts/test_kundenbericht.py -q
Alle Berichte sind synthetisch und liegen in tmp_path. Ein autouse-Fixture und der Helfer `lauf` setzen standardmäßig
SECURITY_AUDIT_OHNE=pandoc,weasyprint: es läuft nie ein echtes PDF-Werkzeug, und jeder Lauf, der bis zur PDF-Stufe kommt, endet mit
Exit 3. Die PDF-Tests (Teil 3) nutzen Attrappen als Skripte im PATH, die ihre Argumente und ihre Umgebung protokollieren. Echte
Werkzeuge laufen nur mit SECURITY_AUDIT_PDF=1.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
import zlib

import pytest

SKRIPTE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SKRIPTE)
import bericht  # noqa: E402
import gitkopie  # noqa: E402
import kundenbericht  # noqa: E402

KUNDENBERICHT = os.path.join(SKRIPTE, "kundenbericht.py")
BASIS = "2026-11-11-abc1234"

POC = ("poc.py anfrage --rolle p1 --methode GET --pfad /api/orders/9 --header 'Authorization: Bearer <TOKEN_A>' "
       "-> 200, Body enthält die Bestellung 9 mit org_id 2 (Organisation B)")
ZUSAMMENFASSUNG = ("Fremde Organisationen können Bestellungen anderer Kunden einsehen. "
                   "Dadurch drohen Datenabfluss und ein Vertrauensverlust.")
MASSNAHME = "Wir empfehlen, die Zugriffsprüfung für Bestellungen zu ergänzen."
VORSPANN = "Wir empfehlen, den Zugriff zu begrenzen. "


@pytest.fixture(autouse=True)
def _ohne_pdf_werkzeuge(monkeypatch):
    """R1-W2: Standard ohne echte PDF-Werkzeuge (auch für In-Process-Aufrufe); die Tests der PDF-Kette überschreiben das gezielt."""
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "pandoc,weasyprint")


def befund(nr=1, **kw):
    b = {"id": f"S-{nr}", "stufe": "P1", "status": "bestätigt", "datei": "src/api/orders.ts", "zeile": 11,
         "kategorie": "A01", "titel": "Fremde Bestellungen einsehbar", "beschreibung": "Erste Zeile\nZweite Zeile",
         "szenario": "Nutzer A liest Bestellung von B", "erwartet": "Mandanten-Scope prüfen", "klasse": "keine weiteren",
         "ohne_anmeldung": False, "mandantenuebergreifend": True, "poc": POC,
         "code_pfad": ["src/api/orders.ts:11", "src/lib/fetch.ts:18"],
         "zusammenfassung": ZUSAMMENFASSUNG, "massnahme": MASSNAHME}
    b.update(kw)
    return b


def bericht_daten(*befunde, **kopf):
    d = {"version": 1, "repo": "portal-repo", "sha": "a" * 40, "datum": "2026-11-11", "teilpfad": None, "projekt": "Portal",
         "karte": [{"flaeche": "API", "dateien": ["src/api/orders.ts"]}], "hinweise": [],
         "befunde": list(befunde) if befunde else [befund()]}
    d.update(kopf)
    return d


def schreibe(ordner, daten, name=BASIS + ".json"):
    ordner.mkdir(exist_ok=True)
    pfad = ordner / name
    pfad.write_text(json.dumps(daten, ensure_ascii=False), encoding="utf-8")
    return pfad


def lauf(pfad, env=None, argumente=None):
    """Aufruf als Kindprozess; SECURITY_AUDIT_OHNE=pandoc,weasyprint (R1-W2) ist der Standard."""
    umgebung = {**os.environ, "SECURITY_AUDIT_OHNE": "pandoc,weasyprint", **(env or {})}
    return subprocess.run([sys.executable, "-I", KUNDENBERICHT, *(["erstellen", "--json", str(pfad)] if argumente is None else argumente)],
                          capture_output=True, text=True, env=umgebung)


def zeilen(p):
    return p.stdout.splitlines()


def inhalt(ordner):
    return sorted(os.listdir(ordner))


def kunde_pfad(pfad, endung):
    return str(pfad)[:-len(".json")] + "-kunde." + endung


# ------------------------------------------------------------------------------------ TF4-D3: Exploit-Spuren

def test_poc_text_exit2_keine_datei(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(massnahme=VORSPANN + "Die Stelle /api/orders/9 wird geändert.")))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: inhalt"
    assert "S-1 massnahme: Regel a (/api/orders/9)" in zeilen(p)
    assert inhalt(tmp_path / "out") == [BASIS + ".json"], "bei Exit 2 entstehen keine Kundendateien"


def test_titel_mit_exploit_text_exit2_keine_datei(tmp_path):
    """TF4 Review 2 (I1): der Titel steht in jeder Befundüberschrift und darf keinen Exploit-Text tragen (Regeln a, b, c)."""
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(titel="Fehlende Prüfung bei GET /api/orders/9 mit org_id und `X-Token`")))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: inhalt"
    regeln = [z.split(": Regel ")[1][0] for z in zeilen(p)[1:] if z.startswith("S-1 titel: Regel ")]
    assert sorted(set(regeln)) == ["a", "b", "c"], zeilen(p)
    assert inhalt(tmp_path / "out") == [BASIS + ".json"], "bei Exit 2 entstehen keine Kundendateien"


@pytest.mark.parametrize("titel", ["Verwundbare Abhängigkeit name@1.2.3", "Zugangsschlüssel in der Versionsgeschichte (generic-api-key)",
                                   "Version < 2.0 und Größe > 5 nicht geprüft"])
def test_werkzeugtitel_bleiben_erlaubt(tmp_path, titel):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(titel=titel)))
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr          # Titelprüfung ohne Treffer: weiter bis zur PDF-Stufe (ohne Werkzeuge: Exit 3)
    assert os.path.isfile(kunde_pfad(pfad, "md"))


def test_5100_poc_token_mit_leck_exit2(tmp_path):
    """TF4 Review 2 (N-1): auch bei mehr als 5000 Token im poc wird das Leck gemeldet (früher fiel Regel a still aus)."""
    poc = " ".join(f"/api/pfad/{i}" for i in range(5100)) + " /api/orders/9"
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(poc=poc, massnahme=VORSPANN + "Die Stelle /api/orders/9 wird geändert.")))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: inhalt", "S-1 massnahme: Regel a (/api/orders/9)"] and p.stderr == ""
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


def test_zu_viele_poc_token_fail_closed_exit2(tmp_path, monkeypatch, capsys):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(poc=" ".join(f"/api/pfad/{i}" for i in range(11)))))
    monkeypatch.setattr(bericht, "_MAX_TOKEN", 10)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 2
    aus = capsys.readouterr()
    assert aus.out.splitlines() == ["kategorie: inhalt", "S-1 zusammenfassung: Regel a (zu viele Token zum Prüfen)",
                                    "S-1 massnahme: Regel a (zu viele Token zum Prüfen)", "S-1 titel: Regel a (zu viele Token zum Prüfen)"]
    assert aus.err == "" and inhalt(tmp_path / "out") == [BASIS + ".json"]


def test_code_pfad_exit2_keine_datei(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(massnahme=VORSPANN + "Ändern Sie die Datei src/lib/fetch.ts im Projekt.")))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: inhalt"
    assert any(z.startswith("S-1 massnahme: Regel e") for z in zeilen(p))
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


@pytest.mark.parametrize("satz", ["Passen Sie Dockerfile:6 an.", "Passen Sie Dockerfile Zeile 6 an.", "Prüfen Sie Zeile 42 der Datei.",
                                  "Prüfen Sie lib/util.ts:18 im Projekt.", "Prüfen Sie die Stelle bei #L42 im Projekt."])
def test_datei_zahl_exit2_keine_datei(tmp_path, satz):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(datei="Dockerfile", zeile=6, code_pfad=["Dockerfile:6", "src/lib/fetch.ts:18"],
                                                          massnahme=VORSPANN + satz)))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: inhalt"
    assert any(z.startswith("S-1 massnahme: Regel d") for z in zeilen(p)), zeilen(p)
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


# ------------------------------------------------------------------------------------ TF4-D4: Du-Anrede

def test_du_exit2(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(massnahme="Prüfe, ob du Zugriff auf die Bestellungen hast.")))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: inhalt", "S-1 massnahme: Regel du (du)"]
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


def test_datei_mit_dir_loest_nichts_aus(tmp_path):
    """R2-K-10: `dir` im Dateipfad löst nichts aus; der Lauf kommt bis zur PDF-Stufe (ohne Werkzeuge: Exit 3)."""
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(datei="src/dir/x.ts", code_pfad=["src/dir/x.ts:3", "src/lib/fetch.ts:18"])))
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr
    assert os.path.isfile(kunde_pfad(pfad, "md"))


# ------------------------------------------------------------------------------------ Meldungen und Fehler

TREFFER = "GEHEIMTEXT"


@pytest.mark.parametrize("feld,wert,regel", [
    ("massnahme", VORSPANN + f"Sperren Sie GET /api/{TREFFER}/x.", "b"),
    ("zusammenfassung", ZUSAMMENFASSUNG + f" Betrifft x={TREFFER}.", "c"),
    ("massnahme", VORSPANN + f"Ändern Sie `{TREFFER}` im Projekt.", "c"),
    ("massnahme", VORSPANN + f"Prüfen Sie {TREFFER}/lib.ts:18 im Projekt.", "d"),
    ("massnahme", VORSPANN + f"Prüfen Sie {TREFFER} Zeile 18 im Projekt.", "d"),
    ("massnahme", VORSPANN + "Ändern Sie src/lib/fetch.ts im Projekt.", "e"),
    ("titel", "Fehler in src/api/orders.ts", "e"),
    ("massnahme", VORSPANN + f"Lesen Sie https://{TREFFER.lower()}.example/x nach.", "url"),
    ("massnahme", VORSPANN + f"Schreiben Sie an {TREFFER.lower()}@example.org im Haus.", "email"),
])
def test_meldung_ohne_treffertext(tmp_path, feld, wert, regel):
    """W6: bei b bis e, url und email nennt die Meldung nur ID, Feld und Regel (und einen festen Text), nie den Treffertext."""
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(**{feld: wert})))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    treffer = [z for z in zeilen(p)[1:] if z.startswith(f"S-1 {feld}: Regel {regel}")]
    assert treffer, zeilen(p)
    for z in zeilen(p)[1:]:
        assert re.fullmatch(r"S-1 (zusammenfassung|massnahme|titel): Regel [a-z]+( \([^()]*\))?", z), z
    ausgabe = (p.stdout + p.stderr).lower()
    for geheim in (TREFFER.lower(), "fetch.ts", "orders.ts", "/api/", "example"):
        assert geheim not in ausgabe, (geheim, ausgabe)


def test_fehlendes_feld_exit2(tmp_path):
    d = bericht_daten(befund(1), befund(2))
    del d["befunde"][0]["zusammenfassung"]
    del d["befunde"][1]["massnahme"]
    pfad = schreibe(tmp_path / "out", d)
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: inhalt", "S-1 zusammenfassung: Regel fehlt", "S-2 massnahme: Regel fehlt"]
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


def test_feld_fehlt_und_zu_kurz_exit2(tmp_path):
    """R2-K-1: `fehlt` und `schema`; Detail der Schemameldung ohne den Wert."""
    d = bericht_daten(befund(1, massnahme="Zu kurz."), befund(2), befund(3))
    del d["befunde"][1]["massnahme"]
    d["befunde"][2]["zusammenfassung"] = "x" * 601
    pfad = schreibe(tmp_path / "out", d)
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: inhalt", "S-1 massnahme: Regel schema (kürzer als 20 Zeichen)", "S-2 massnahme: Regel fehlt",
                         "S-3 zusammenfassung: Regel schema (länger als 600 Zeichen)"]


def test_verworfen_und_verdacht_brauchen_keine_kundenfelder(tmp_path):
    verworfen = befund(2, status="verworfen", grund="nur im Testmodus aktiv", massnahme="kurz")
    verdacht = befund(3, status="verdacht")
    del verdacht["zusammenfassung"]
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(1), verworfen, verdacht))
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr


def test_meldungen_hoechstens_30(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(*[befund(i, massnahme="Prüfe, ob du Zugriff auf die Daten hast.")
                                                      for i in range(1, 41)]))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    z = zeilen(p)
    assert z[0] == "kategorie: inhalt"
    assert len(z) == 1 + 30 + 1
    assert z[1] == "S-1 massnahme: Regel du (du)" and z[30] == "S-30 massnahme: Regel du (du)"
    assert z[-1] == "… und 10 weitere"


@pytest.mark.parametrize("n,weitere", [(29, None), (30, None), (31, 1), (32, 2)])
def test_meldungszeilen_grenze_30_ohne_kategorie_zeile(tmp_path, n, weitere):
    """TF4 Review 2 (I3): höchstens 30 Meldungszeilen, ohne `kategorie:` (und `kunde-md:`/`kunde-pdf:`); der Rest wird zu `… und <n> weitere`.
    Genau 30 Treffer erscheinen vollständig, ohne `… und 0 weitere`."""
    pfad = schreibe(tmp_path / "out", bericht_daten(*[befund(i, massnahme="Prüfe, ob du Zugriff auf die Daten hast.") for i in range(1, n + 1)]))
    p = lauf(pfad)
    assert p.returncode == 2, p.stdout + p.stderr
    z = zeilen(p)
    assert z[0] == "kategorie: inhalt"
    meldungen = z[1:]
    if weitere is None:
        assert len(meldungen) == n and all(m.startswith("S-") for m in meldungen)
        assert not any("weitere" in m for m in meldungen)
    else:
        assert len(meldungen) == 30 + 1 and meldungen[-1] == f"… und {weitere} weitere"
        assert all(m.startswith("S-") for m in meldungen[:30])


def test_unerwarteter_fehler_exit1_kategorie_intern(tmp_path, monkeypatch, capsys):
    pfad = schreibe(tmp_path / "out", bericht_daten())

    def kaputt(daten):
        raise RuntimeError("GEHEIMTEXT aus dem Fehler")

    monkeypatch.setattr(kundenbericht, "markdown_erzeugen", kaputt)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 1
    aus = capsys.readouterr()
    assert aus.out.splitlines()[0] == "kategorie: intern"
    assert "Traceback" not in aus.out + aus.err and "GEHEIMTEXT" not in aus.out
    assert inhalt(tmp_path / "out") == [BASIS + ".json"], "kein Markdown, keine Reste"


def test_pfad_mit_zeilenumbruch_wird_entschaerft(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(), name="x\nkategorie: ok.json")
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: pdf-werkzeug-fehlt"
    assert [z for z in zeilen(p) if z.startswith("kategorie:")] == ["kategorie: pdf-werkzeug-fehlt"]


# ------------------------------------------------------------------------------------ Eingabe und Ablage

def test_eingabe_ohne_json_endung_exit5(tmp_path):
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten(), name="bericht.dat")
    (ordner / "bericht-kunde.md").write_text("alt")
    (ordner / "bericht.dat-kunde.md").write_text("alt")
    p = lauf(pfad)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"
    assert inhalt(ordner) == ["bericht-kunde.md", "bericht.dat", "bericht.dat-kunde.md"]
    assert (ordner / "bericht-kunde.md").read_text() == "alt"


def test_datei_fehlt_exit5(tmp_path):
    p = lauf(tmp_path / "gibt-es-nicht.json")
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe" and "Traceback" not in p.stderr


def test_verzeichnis_als_eingabe_exit5(tmp_path):
    (tmp_path / "ordner.json").mkdir()
    p = lauf(tmp_path / "ordner.json")
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"


def test_symlink_eingabe_exit5(tmp_path):
    ordner = tmp_path / "out"
    echt = schreibe(ordner, bericht_daten(), name="echt.json")
    link = ordner / "link.json"
    link.symlink_to(echt)
    (ordner / "link-kunde.md").write_text("alt")
    p = lauf(link)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"
    assert (ordner / "link-kunde.md").read_text() == "alt", "nichts entfernt"
    assert inhalt(ordner) == ["echt.json", "link-kunde.md", "link.json"]


def _kollision(tmp_path, endung):
    """R2-K-5 und R1-K8: `<basis>-kunde.json` und `<basis>-kunde.reserviert` gehören einem Audit mit Teilpfad `kunde`."""
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten())
    (ordner / f"{BASIS}-kunde.{endung}").write_text("{}")
    (ordner / f"{BASIS}-kunde.md").write_text("alt")
    (ordner / f"{BASIS}-kunde.pdf").write_text("alt")
    p = lauf(pfad)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"
    assert (ordner / f"{BASIS}-kunde.md").read_text() == "alt" and (ordner / f"{BASIS}-kunde.pdf").read_text() == "alt"
    assert (ordner / f"{BASIS}-kunde.{endung}").read_text() == "{}"


def test_kunde_json_kollision_exit5(tmp_path):
    _kollision(tmp_path, "json")


def test_kunde_reserviert_kollision_exit5(tmp_path):
    _kollision(tmp_path, "reserviert")


def test_alte_kundendateien_entfernt(tmp_path):
    """W8/K-6: direkt nach der Pfadprüfung, vor dem Lesen; nur diese zwei Pfade."""
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten(befund(massnahme="Prüfe, ob du Zugriff hast.")))
    (ordner / f"{BASIS}-kunde.md").write_text("alt")
    (ordner / f"{BASIS}-kunde.pdf").write_text("alt")
    (ordner / f"{BASIS}.md").write_text("technischer Bericht")
    (ordner / "fremd-kunde.md").write_text("anderer Lauf")
    p = lauf(pfad)                                   # Exit 2: danach gibt es keine Kundendateien
    assert p.returncode == 2, p.stdout + p.stderr
    assert inhalt(ordner) == sorted(["fremd-kunde.md", f"{BASIS}.json", f"{BASIS}.md"])
    assert (ordner / f"{BASIS}.md").read_text() == "technischer Bericht"
    schreibe(ordner, bericht_daten())
    (ordner / f"{BASIS}-kunde.md").write_text("alt")
    (ordner / f"{BASIS}-kunde.pdf").write_text("alt")
    p = lauf(pfad)                                   # Exit 3: nur das neue Markdown, kein altes PDF
    assert p.returncode == 3, p.stdout + p.stderr
    assert inhalt(ordner) == sorted(["fremd-kunde.md", f"{BASIS}-kunde.md", f"{BASIS}.json", f"{BASIS}.md"])
    assert (ordner / f"{BASIS}-kunde.md").read_text(encoding="utf-8").startswith("# Manibase · Sicherheitsprüfung Portal")


@pytest.mark.parametrize("ziel", ["md", "pdf"])
@pytest.mark.parametrize("art", ["symlink", "verzeichnis"])
def test_symlink_ziel_exit5_nichts_entfernt(tmp_path, ziel, art):
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten())
    anderes = "pdf" if ziel == "md" else "md"
    (ordner / f"{BASIS}-kunde.{anderes}").write_text("alt")
    fremd = tmp_path / "fremd.txt"
    fremd.write_text("fremd")
    ort = ordner / f"{BASIS}-kunde.{ziel}"
    if art == "symlink":
        ort.symlink_to(fremd)
    else:
        ort.mkdir()
    p = lauf(pfad)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"
    assert (ordner / f"{BASIS}-kunde.{anderes}").read_text() == "alt", "auch die reguläre Datei bleibt"
    assert os.path.islink(ort) if art == "symlink" else os.path.isdir(ort)
    assert fremd.read_text() == "fremd"


def test_ablage_atomar(tmp_path, monkeypatch, capsys):
    """Temp-Datei im Zielordner, dann `os.replace`; vorher gibt es das Ziel nicht, nach einem Fehler keine Reste."""
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten())
    ziel = kunde_pfad(pfad, "md")
    echt = os.replace
    aufrufe = []

    def replace(quelle, nach, *a, **kw):
        aufrufe.append((quelle, nach, os.path.exists(nach), open(quelle, encoding="utf-8").read()))
        return echt(quelle, nach, *a, **kw)

    monkeypatch.setattr(kundenbericht.os, "replace", replace)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 3
    assert len(aufrufe) == 1
    quelle, nach, gab_es, text = aufrufe[0]
    assert nach == ziel and os.path.dirname(quelle) == str(ordner) and quelle != ziel
    assert gab_es is False and text.startswith("# Manibase")
    assert inhalt(ordner) == [os.path.basename(ziel), BASIS + ".json"], "keine Temp-Reste"
    capsys.readouterr()

    os.unlink(ziel)

    def kaputt(quelle, nach, *a, **kw):
        raise OSError("Platte voll")

    monkeypatch.setattr(kundenbericht.os, "replace", kaputt)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 5
    aus = capsys.readouterr().out.splitlines()
    assert aus[0] == "kategorie: eingabe"
    assert inhalt(ordner) == [BASIS + ".json"], "weder Markdown noch Temp-Datei"


# ------------------------------------------------------------------------------------ Schema und Ablage ohne Werkzeuge

def test_schema_fehler_ausserhalb_kundenfelder_exit5(tmp_path):
    ordner = tmp_path / "out"
    d = bericht_daten()
    d["datum"] = "morgenGEHEIM"
    pfad = schreibe(ordner, d)
    p = lauf(pfad)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe"
    assert inhalt(ordner) == [BASIS + ".json"]
    # Kundenfelder allein ändern daran nichts: die Prüfung läuft auf einer Kopie ohne beide Felder
    d = bericht_daten(befund(massnahme="kurz"))
    d["befunde"][0]["stufe"] = "P9"
    pfad = schreibe(ordner, d)
    p = lauf(pfad)
    assert p.returncode == 5 and zeilen(p)[0] == "kategorie: eingabe"


def test_schema_meldungen_exit5_nur_id_und_feld(tmp_path):
    """TF4 Review 2 (Minor): Exit 5 nennt ID und Feld, nie einen Datenwert."""
    d = bericht_daten(befund(1, stufe="P9GEHEIM"), befund(2), befund(3, kategorie="Z99GEHEIM"))
    d["datum"] = "morgenGEHEIM"
    d["repo"] = "repo GEHEIM"
    del d["befunde"][1]["titel"]
    d["befunde"][2]["poc"] = "poc.py anfrage --pfad http://GEHEIM.example/x"
    p = lauf(schreibe(tmp_path / "out", d))
    assert p.returncode == 5, p.stdout + p.stderr
    z = zeilen(p)
    assert z[0] == "kategorie: eingabe" and re.fullmatch(r"Schemafehler außerhalb der Kundenfelder \(\d+\):", z[1]), z
    assert sorted(z[2:]) == sorted(["- datum", "- repo", "- S-1 stufe", "- S-2 titel", "- S-3 kategorie", "- S-3 poc"]), z
    assert "GEHEIM" not in p.stdout + p.stderr


def test_schema_stelle_hilfsfunktion():
    f = kundenbericht._stelle
    assert f("Pflichtfeld fehlt: repo") == "repo"
    assert f("S-4: Pflichtfeld fehlt: titel") == "S-4 titel"
    assert f("befunde[2]: id muss S-<Zahl> sein, ist 'x'") == "befunde[2] id"
    assert f("befunde[3] muss ein Objekt sein") == "befunde[3]"
    assert f("S-1: code_pfad[0] muss datei:zeile sein, ist 'x'") == "S-1 code_pfad[0]"
    assert f("Wurzel muss ein JSON-Objekt sein") == "Schemafehler"


def test_stellen_ohne_datenwerte_und_ohne_doppelte():
    meldungen = ["S-1: poc enthält nicht erlaubten Host: GEHEIM.example", "S-1: poc enthält nicht erlaubten Host: ANDERER.example", "datum ungültig: ist 'GEHEIM'"]
    assert kundenbericht._stellen(meldungen) == ["- S-1 poc", "- datum"]


def test_schema_meldungen_der_zweiten_pruefung_ohne_datenwerte(tmp_path, monkeypatch, capsys):
    """Der Zweig `fremd` (Schemameldung außerhalb der Kundenfelder erst bei der zweiten Prüfung) nennt ebenfalls nur ID und Feld."""
    pfad = schreibe(tmp_path / "out", bericht_daten())
    aufrufe = []

    def schema(daten):
        aufrufe.append(1)
        return [] if len(aufrufe) == 1 else ["S-1: poc enthält nicht erlaubten Host: GEHEIM.example"]

    monkeypatch.setattr(bericht, "pruefe_schema", schema)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 5
    assert capsys.readouterr().out.splitlines() == ["kategorie: eingabe", "Schemafehler:", "- S-1 poc"]


def test_json_nicht_lesbar_exit5(tmp_path):
    ordner = tmp_path / "out"
    ordner.mkdir()
    pfad = ordner / (BASIS + ".json")
    pfad.write_text("{kein json", encoding="utf-8")
    p = lauf(pfad)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p)[0] == "kategorie: eingabe" and "Traceback" not in p.stdout + p.stderr
    pfad.write_bytes(b"\xff\xfe\x00")
    assert lauf(pfad).returncode == 5
    pfad.write_text("[" * 100000, encoding="utf-8")        # RecursionError im Parser
    p = lauf(pfad)
    assert p.returncode == 5 and "Traceback" not in p.stdout + p.stderr


def test_json_zu_gross_exit5(tmp_path, monkeypatch, capsys):
    pfad = schreibe(tmp_path / "out", bericht_daten())
    monkeypatch.setattr(bericht, "MAX_JSON_BYTES", 100)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 5
    assert capsys.readouterr().out.splitlines()[0] == "kategorie: eingabe"
    assert inhalt(tmp_path / "out") == [BASIS + ".json"]


def test_ohne_werkzeuge_exit3_markdown_liegt(tmp_path):
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten())
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-werkzeug-fehlt", "kunde-md: " + kunde_pfad(pfad, "md"), "Werkzeug fehlt: pandoc, weasyprint"]
    md = open(kunde_pfad(pfad, "md"), encoding="utf-8").read()
    assert md.startswith("# Manibase · Sicherheitsprüfung Portal\n")
    assert "S-1" in md and "Fremde Bestellungen einsehbar" in md
    assert inhalt(ordner) == [BASIS + "-kunde.md", BASIS + ".json"], "kein PDF, keine Temp-Reste"


def test_pdf_erstellen_signatur_und_rueckgabe_ohne_werkzeuge(monkeypatch):
    """Rückgabe (Exit-Code, Kategorie, Meldungen), nie stdout; ohne Werkzeuge startet kein Kindprozess."""
    def nie(*a, **kw):
        raise AssertionError("kein Kindprozess ohne Werkzeuge")

    monkeypatch.setattr(kundenbericht.gitkopie, "werkzeug_ausfuehren", nie)
    assert kundenbericht.pdf_erstellen("a.md", "a.pdf", "Titel", time.monotonic() + 5) == (3, "pdf-werkzeug-fehlt", ["Werkzeug fehlt: pandoc, weasyprint"])


def test_main_gibt_zeilen_in_reihenfolge_aus(tmp_path, monkeypatch, capsys):
    pfad = schreibe(tmp_path / "out", bericht_daten())
    md = kunde_pfad(pfad, "md")
    monkeypatch.setattr(kundenbericht, "pdf_erstellen", lambda *a: (4, "pdf-fehler", ["Tag img nicht erlaubt", "zweite"]))
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 4
    assert capsys.readouterr().out.splitlines() == ["kategorie: pdf-fehler", "kunde-md: " + md, "Tag img nicht erlaubt", "zweite"]
    monkeypatch.setattr(kundenbericht, "pdf_erstellen", lambda *a: (0, None, []))
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 0
    assert capsys.readouterr().out.splitlines() == ["kunde-md: " + md, "kunde-pdf: " + kunde_pfad(pfad, "pdf")]
    monkeypatch.setattr(kundenbericht, "pdf_erstellen", lambda *a: (4, "pdf-fehler", [f"m{i}" for i in range(35)]))
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 4
    z = capsys.readouterr().out.splitlines()
    assert z[:2] == ["kategorie: pdf-fehler", "kunde-md: " + md] and len(z) == 2 + 30 + 1 and z[-1] == "… und 5 weitere"


def test_pdf_erstellen_bekommt_pfade_titel_und_frist(tmp_path, monkeypatch):
    pfad = schreibe(tmp_path / "out", bericht_daten())
    gesehen = []
    monkeypatch.setattr(kundenbericht, "pdf_erstellen", lambda *a: gesehen.append(a) or (3, "pdf-werkzeug-fehlt", []))
    vorher = time.monotonic()
    kundenbericht.main(["erstellen", "--json", str(pfad)])
    (md, pdf, titel, ende), = gesehen
    assert md == kunde_pfad(pfad, "md") and pdf == kunde_pfad(pfad, "pdf") and titel == "Manibase · Sicherheitsprüfung Portal"
    assert vorher < ende <= time.monotonic() + kundenbericht.KUNDE_BUDGET


def test_pdf_erstellen_wirft_markdown_bleibt_und_wird_genannt(tmp_path, monkeypatch, capsys):
    """TF4 Review 2 (Minor): scheitert die PDF-Stufe mit einer unerwarteten Ausnahme, bleibt das Markdown liegen und stdout nennt es."""
    pfad = schreibe(tmp_path / "out", bericht_daten())

    def kaputt(*a):
        raise RuntimeError("GEHEIMTEXT aus dem Fehler")

    monkeypatch.setattr(kundenbericht, "pdf_erstellen", kaputt)
    assert kundenbericht.main(["erstellen", "--json", str(pfad)]) == 1
    aus = capsys.readouterr()
    assert aus.out.splitlines() == ["kategorie: intern", "kunde-md: " + kunde_pfad(pfad, "md"), "Unerwarteter Fehler (RuntimeError)."]
    assert "GEHEIMTEXT" not in aus.out + aus.err and "Traceback" not in aus.out + aus.err
    assert os.path.isfile(kunde_pfad(pfad, "md")) and inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


@pytest.mark.parametrize("maske,modus", [(0o022, 0o644), (0o077, 0o600), (0o002, 0o644)])
def test_kundendateien_haben_die_rechte_des_json(tmp_path, maske, modus):
    """TF4 Review 2 (Minor): `-kunde.md` und `-kunde.pdf` bekommen 0644 maskiert mit der umask (mkstemp legt sonst 0600 an), wie das JSON."""
    alt = os.umask(maske)
    try:
        ordner = tmp_path / "out"
        pfad = schreibe(ordner, bericht_daten())
        kundenbericht._ablegen(kunde_pfad(pfad, "md"), "# Text\n")
        kundenbericht._pdf_ablegen(b"%PDF-1.7\n", kunde_pfad(pfad, "pdf"))
    finally:
        os.umask(alt)
    assert os.stat(kunde_pfad(pfad, "md")).st_mode & 0o777 == modus
    assert os.stat(kunde_pfad(pfad, "pdf")).st_mode & 0o777 == modus
    assert os.stat(pfad).st_mode & 0o777 == 0o666 & ~maske, "das JSON dient als Vergleich"


def test_erstellen_lauf_markdown_hat_rechte_644(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten())
    assert lauf(pfad).returncode == 3
    assert os.stat(kunde_pfad(pfad, "md")).st_mode & 0o777 == 0o644 & ~_prozess_umask()


def _prozess_umask():
    alt = os.umask(0)
    os.umask(alt)
    return alt


# ------------------------------------------------------------------------------------ CLI

def test_hilfe_nennt_unterbefehl_erstellen():
    p = subprocess.run([sys.executable, "-I", KUNDENBERICHT, "--help"], capture_output=True, text=True)
    assert p.returncode == 0
    assert re.search(r"\{erstellen\}", p.stdout)


@pytest.mark.parametrize("argumente", [[], ["erstellen"], ["unbekannt"], ["erstellen", "--json"], ["erstellen", "--json", "x.json", "y"]])
def test_argumentfehler_exit5_nicht_exit2(tmp_path, argumente):
    """argparse würde mit 2 enden und damit eine Feldkorrektur auslösen; Eingabefehler sind Exit 5."""
    p = lauf(None, argumente=argumente)
    assert p.returncode == 5, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: eingabe"] and p.stderr.strip()


def test_escape_k1_menge():
    for zeichen in "\\`*_{}[]<>!$^~@&|#":
        assert kundenbericht.escape(zeichen) == "\\" + zeichen
    assert kundenbericht.escape("Fremde Bestellungen") == "Fremde Bestellungen"


# ------------------------------------------------------------------------------------ 2b: Inhalt des Markdowns

def md_von(*befunde, **kopf):
    return kundenbericht.markdown_erzeugen(bericht_daten(*befunde, **kopf))


def md_zeilen(text):
    return text.splitlines()


def abschnitt(text, kopf):
    """Zeilen zwischen der Überschrift `kopf` und der nächsten `## `-Überschrift."""
    z = md_zeilen(text)
    i = z.index(kopf)
    j = next((k for k in range(i + 1, len(z)) if z[k].startswith("## ")), len(z))
    return z[i + 1:j]


def tabelle(text):
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^\| (Kritisch|Hoch|Mittel|Niedrig) \| (\d+) \|$", text, re.M)}


# --- TF4-D1: Kopf

def test_kopf_mit_projekt():
    md = md_von(befund(), datum="2026-11-03", sha="1234567" + "a" * 33)
    z = md_zeilen(md)
    assert z[0] == "# Manibase · Sicherheitsprüfung Portal"
    kopf = "\n".join(z[:abschnitt_ende(md)])
    assert "03.11.2026" in kopf and "1234567" in kopf and "1234567a" not in kopf
    assert "**Geprüfter Stand (Commit):** 1234567" in z and "Geprüfter Commit" not in md
    assert "kein Projektname" not in md
    assert "Teilbereich" not in kopf


def abschnitt_ende(text):
    z = md_zeilen(text)
    return next(i for i, x in enumerate(z) if x.startswith("## "))


def test_kopf_ohne_projekt_ordner_hinweis():
    md = md_von(befund(), projekt=None, ordner="kundenordner", repo="repo-name")
    assert md.startswith("# Manibase · Sicherheitsprüfung kundenordner\n")
    assert "Hinweis: Es wurde kein Projektname angegeben; verwendet wird der Name des Repository-Ordners." in md
    assert "Name des Repositorys" not in md


def test_kopf_ohne_ordner_repo_hinweis():
    for kopf in ({"projekt": None}, {"projekt": None, "ordner": None}):
        md = md_von(befund(), repo="repo-name", **kopf)
        assert md.startswith("# Manibase · Sicherheitsprüfung repo-name\n")
        assert "Hinweis: Es wurde kein Projektname angegeben; verwendet wird der Name des Repositorys." in md
        assert "Repository-Ordners" not in md


def test_kopf_name_und_teilpfad_escaped():
    md = md_von(befund(), projekt="Mein_Portal [neu]", teilpfad="apps/web_ui")
    assert md.startswith("# Manibase · Sicherheitsprüfung Mein\\_Portal \\[neu\\]\n")
    kopf = md_zeilen(md)[:abschnitt_ende(md)]
    assert any("nur der Teilbereich apps/web\\_ui" in x for x in kopf), kopf


def test_pagetitle_unescaped():
    assert kundenbericht.pagetitle(bericht_daten(projekt="Mein_Portal [x]")) == "Manibase · Sicherheitsprüfung Mein_Portal [x]"
    assert kundenbericht.pagetitle(bericht_daten(projekt=None, ordner=None, repo="r_1")) == "Manibase · Sicherheitsprüfung r_1"
    assert kundenbericht.pagetitle(bericht_daten(projekt=None, ordner="o", repo="r")) == "Manibase · Sicherheitsprüfung o"


# --- TF4-D2: Stufen und Filter

def stufe_von(md, nr=1):
    m = re.search(rf"^### S-{nr} · (Kritisch|Hoch|Mittel|Niedrig) · ", md, re.M)
    assert m, md
    return m.group(1)


def test_stufe_p1_ohne_anmeldung_kritisch():
    assert stufe_von(md_von(befund(ohne_anmeldung=True, mandantenuebergreifend=False))) == "Kritisch"


def test_stufe_p1_mandantenuebergreifend_kritisch():
    assert stufe_von(md_von(befund(ohne_anmeldung=False, mandantenuebergreifend=True))) == "Kritisch"


def test_stufe_p1_hoch():
    assert stufe_von(md_von(befund(ohne_anmeldung=False, mandantenuebergreifend=False))) == "Hoch"


def test_stufe_p2_mittel():
    assert stufe_von(md_von(befund(stufe="P2", ohne_anmeldung=True, mandantenuebergreifend=True))) == "Mittel"


def test_stufe_p3_niedrig():
    assert stufe_von(md_von(befund(stufe="P3", ohne_anmeldung=True, mandantenuebergreifend=True))) == "Niedrig"


def test_stufe_status_nfc_normalisiert():
    """M05: auch Tabelle, Sätze und Nachweis beruhen auf dem NFC-normalisierten Status, nicht nur die Überschrift."""
    import unicodedata
    unb = unicodedata.normalize("NFD", "unbestätigt")
    md = md_von(befund(status=unb, poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"]))
    assert "### S-1 · " in md and "im Test nicht bestätigt (mögliche Schwachstelle)" in md
    assert tabelle(md) == {"Kritisch": 1, "Hoch": 0, "Mittel": 0, "Niedrig": 0}
    assert "Es besteht eine mögliche Schwachstelle der Stufe Kritisch" in zus(md) and "ausnutzbar" not in zus(md)
    best = unicodedata.normalize("NFD", "bestätigt")
    md = md_von(befund(status=best))
    assert tabelle(md) == {"Kritisch": 1, "Hoch": 0, "Mittel": 0, "Niedrig": 0}
    assert "Es besteht eine Schwachstelle der Stufe Kritisch, die ohne Anmeldung" in zus(md)
    assert "**Nachweis:** im Test nachgestellt" in md_zeilen(md)


def test_verworfen_und_verdacht_fehlen():
    md = md_von(befund(1, titel="Gelistet eins"),
                befund(2, status="verworfen", titel="Verworfener Titel", grund="Kein Fehler"),
                befund(3, status="verdacht", titel="Verdacht Titel"),
                befund(4, status="unbestätigt", titel="Gelistet vier", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"]))
    assert "Gelistet eins" in md and "Gelistet vier" in md
    assert "Verworfener Titel" not in md and "Verdacht Titel" not in md and "S-2" not in md and "S-3" not in md
    assert tabelle(md) == {"Kritisch": 2, "Hoch": 0, "Mittel": 0, "Niedrig": 0}


def test_sortierung_stufe_dann_id_numerisch():
    md = md_von(befund(10, titel="Zehn"), befund(2, titel="Zwei"), befund(3, stufe="P3", titel="Drei"),
                befund(4, stufe="P2", titel="Vier"), befund(5, ohne_anmeldung=False, mandantenuebergreifend=False, titel="Fünf"))
    ids = re.findall(r"^### (S-\d+) · ", md, re.M)
    assert ids == ["S-2", "S-10", "S-5", "S-4", "S-3"]


# --- Nachweis, Titel, Datei

def test_nachweis_je_herkunft():
    def nachweis(**kw):
        md = md_von(befund(**kw))
        m = re.search(r"^\*\*Nachweis:\*\* (.+)$", md, re.M)
        assert m, md
        return m.group(1)

    assert nachweis() == "im Test nachgestellt"
    assert nachweis(annahme_modell=True) == "im Test nachgestellt unter der Annahme, dass das KI-Modell einer eingeschleusten Anweisung folgt"
    assert nachweis(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"]) == \
        "aus dem Quellcode abgeleitet, im Test nicht bestätigt (mögliche Schwachstelle)"
    assert nachweis(werkzeug="osv-scanner") == "aus der Abhängigkeitsliste mit bekannten Sicherheitslücken abgeglichen"
    assert nachweis(werkzeug="gitleaks") == "Zugangsschlüssel in der Versionsgeschichte gefunden (Wert nicht wiedergegeben)"
    assert nachweis(werkzeug="lieferkette") == "aus der Build- und Installationskonfiguration abgeleitet"


def test_gitleaks_titel_fest():
    md = md_von(befund(werkzeug="gitleaks", titel="Geheimer Schlüssel sk_live_abc im Commit"))
    assert "### S-1 · Kritisch · Zugangsschlüssel in der Versionsgeschichte\n" in md
    assert "sk\\_live" not in md and "Geheimer Schlüssel" not in md
    md2 = md_von(befund(werkzeug="osv-scanner", titel="Bekannte Lücke in einem Paket"))
    assert "· Bekannte Lücke in einem Paket\n" in md2


def test_titel_gekuerzt():
    lang = "x" * 130
    md = md_von(befund(titel=lang))
    assert f"### S-1 · Kritisch · {'x' * 119}…\n" in md and "x" * 120 not in md
    genau = "y" * 120
    assert f"· {genau}\n" in md_von(befund(titel=genau))
    kurz = md_von(befund(titel="z" * 119 + "_" * 5))
    assert "z" * 119 + "…\n" in kurz and "\\_" not in kurz, "Kürzung auf dem Rohwert, danach Escaping"


def test_datei_null_gesamtes_projekt():
    md = md_von(befund(datei=None, zeile=None, code_pfad=["a/b.ts:1", "c/d.ts:2"]))
    assert "**Betroffene Datei:** gesamtes Projekt" in md_zeilen(md)
    md2 = md_von(befund(datei="src/api/orders.ts"))
    assert "**Betroffene Datei:** src/api/orders.ts" in md_zeilen(md2)
    assert "orders.ts:" not in md2 and "11" not in re.search(r"\*\*Betroffene Datei:\*\* (.+)", md2).group(1)


def test_befund_felder_in_fester_reihenfolge_ohne_exploit_details():
    md = md_von(befund())
    block = md[md.index("### S-1"):]
    pos = [block.index(x) for x in ("**Risiko:** ", "**Maßnahme:** ", "**Betroffene Datei:** ", "**Nachweis:** ")]
    assert pos == sorted(pos)
    assert ZUSAMMENFASSUNG in block and MASSNAHME in block
    for geheim in ("Bearer", "poc.py", "org_id", "/api/orders/9", "Erste Zeile", "Nutzer A liest", "Mandanten-Scope", "src/lib/fetch.ts"):
        assert geheim not in md


# --- Zusammenfassung

EINORDNUNG = ("- Kritisch: von außen ohne Anmeldung oder über Kundengrenzen ausnutzbar.", "- Hoch: ausnutzbar mit Anmeldung.",
              "- Mittel: begrenzte Auswirkung.", "- Niedrig: geringe Auswirkung oder nur in Entwicklungsumgebungen.")
UNB = dict(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"])
HOCH = dict(ohne_anmeldung=False, mandantenuebergreifend=False)


def zus(md):
    """Management-Zusammenfassung als Fließtext, ohne die feste Einordnung der Stufen (sie nennt „ausnutzbar“ unabhängig vom Status)."""
    return " ".join(x for x in abschnitt(md, "## Management-Zusammenfassung") if x not in EINORDNUNG)


def test_zusammenfassung_singular_plural():
    md1 = md_von(befund(1))
    assert tabelle(md1) == {"Kritisch": 1, "Hoch": 0, "Mittel": 0, "Niedrig": 0}
    assert "Es besteht eine Schwachstelle der Stufe Kritisch" in zus(md1) and "bestehen" not in zus(md1)
    md3 = md_von(befund(1), befund(2), befund(3, stufe="P2"), befund(4, stufe="P2"), befund(5, stufe="P3"),
                 befund(6, stufe="P3"), befund(7, stufe="P3"), befund(8, **HOCH), befund(9, **HOCH))
    assert tabelle(md3) == {"Kritisch": 2, "Hoch": 2, "Mittel": 2, "Niedrig": 3}
    z = zus(md3)
    assert "Es bestehen zwei Schwachstellen der Stufe Kritisch" in z and "Es bestehen zwei Schwachstellen der Stufe Hoch" in z
    assert "Es bestehen zwei Schwachstellen der Stufe Mittel" in z and "Es bestehen drei Schwachstellen der Stufe Niedrig" in z
    assert "Es besteht eine Schwachstelle der Stufe Niedrig" in zus(md_von(befund(1, stufe="P3")))
    assert "Es besteht eine Schwachstelle der Stufe Hoch" in zus(md_von(befund(1, **HOCH)))
    assert "Es besteht eine Schwachstelle der Stufe Mittel" in zus(md_von(befund(1, stufe="P2")))
    for alt in ("hohe", "kritische", "mittlere", "niedrige", "1 Schwachstelle", "2 Schwachstellen"):
        assert alt not in z, alt


def test_zusammenfassung_zahlwoerter():
    """„eine“ für 1, Zahlwort für 2 bis 12, ab 13 die Ziffer."""
    woerter = ["zwei", "drei", "vier", "fünf", "sechs", "sieben", "acht", "neun", "zehn", "elf", "zwölf"]
    for n, wort in zip(range(2, 13), woerter):
        assert f"Es bestehen {wort} Schwachstellen der Stufe Kritisch" in zus(md_von(*[befund(i) for i in range(1, n + 1)])), n
    assert "Es bestehen 13 Schwachstellen der Stufe Kritisch" in zus(md_von(*[befund(i) for i in range(1, 14)]))
    assert "Es bestehen drei mögliche Schwachstellen der Stufe Hoch, die im Test nicht nachgestellt werden konnten." in \
        zus(md_von(*[befund(i, **HOCH, **UNB) for i in range(1, 4)]))


def test_zusammenfassung_kritisch_umgehend():
    assert "Lassen Sie die betroffenen Stellen umgehend beheben." in zus(md_von(befund(1)))
    z = zus(md_von(befund(1, **UNB)))
    assert "Lassen Sie diese Stellen umgehend prüfen und, falls sie sich bestätigen, beheben." in z
    assert "umgehend beheben" not in z
    assert "umgehend" not in zus(md_von(befund(1, stufe="P2")))


def test_zusammenfassung_ausnutzbar_nur_bestaetigt():
    z = zus(md_von(befund(1, **UNB), befund(2, stufe="P2", **UNB)))
    assert "ausnutzbar" not in z
    assert "eine mögliche Schwachstelle der Stufe Kritisch" in z and "eine mögliche Schwachstelle der Stufe Mittel" in z
    z = zus(md_von(befund(1)))
    assert "ausnutzbar" in z and "mögliche Schwachstelle" not in z
    for stufe in ("P2", "P3"):
        assert "ausnutzbar" in zus(md_von(befund(1, stufe=stufe)))
    # gemischter Status in einer Stufe: ein Satz je Status (R1-K11), danach die Empfehlung für die bestätigte Lage (N15/N16)
    z = zus(md_von(befund(1), befund(2), befund(3, **UNB)))
    assert "Es bestehen zwei Schwachstellen der Stufe Kritisch" in z and "ausnutzbar" in z
    assert "Es besteht eine mögliche Schwachstelle der Stufe Kritisch" in z
    assert z.count("umgehend beheben") == 1 and "umgehend prüfen" not in z


def test_zusammenfassung_empfehlung_je_stufe_und_status():
    """N15/N16: je Stufe gilt bei gemischtem Status die Empfehlung für bestätigte Lagen, bei nur unbestätigt die zum Prüfen."""
    for stufe, extra, best, unbest in (
            ("P1", HOCH, "vor dem nächsten Release zu beheben", "vor dem nächsten Release zu prüfen und bei Bestätigung zu beheben"),
            ("P2", {}, "zeitnah einzuplanen und zu beheben", "zeitnah zu prüfen und bei Bestätigung zu beheben"),
            ("P3", {}, "bei nächster Gelegenheit zu beheben", "bei nächster Gelegenheit zu prüfen und bei Bestätigung zu beheben")):
        nur_best = zus(md_von(befund(1, stufe=stufe, **extra)))
        nur_unb = zus(md_von(befund(1, stufe=stufe, **extra, **UNB)))
        gemischt = zus(md_von(befund(1, stufe=stufe, **extra), befund(2, stufe=stufe, **extra, **UNB)))
        assert best in nur_best and unbest not in nur_best
        assert unbest in nur_unb and best not in nur_unb
        assert best in gemischt and unbest not in gemischt, (stufe, gemischt)


def test_zusammenfassung_ton_der_bausteine():
    z = zus(md_von(befund(1), befund(2), befund(3, stufe="P2"), befund(4, stufe="P2"), befund(5, stufe="P3"), befund(6, stufe="P3")))
    assert "Mandanten" not in z
    assert "die ohne Anmeldung oder über die Grenzen zwischen Kundenkonten hinweg ausnutzbar sind" in z
    assert "deren Auswirkungen aber begrenzt bleiben" in z and "deren Auswirkungen aber gering sind" in z
    assert "deren Auswirkung aber begrenzt bleibt" in zus(md_von(befund(1, stufe="P2")))
    assert "deren Auswirkung aber gering ist" in zus(md_von(befund(1, stufe="P3")))
    assert "die ohne Anmeldung oder über die Grenzen zwischen Kundenkonten hinweg ausnutzbar ist" in zus(md_von(befund(1)))


def test_empfehlungen_in_sie_form():
    """Jede Empfehlung enthält „Sie“ oder beginnt mit „Wir empfehlen“; Du-Imperative („Prüfe“, „Plane“) erkennt text_verstoesse nicht."""
    for stufe, (_auswirkung, best, unbest) in kundenbericht._STUFE_TEXT.items():
        for satz in (best, unbest):
            assert satz.startswith("Wir empfehlen") or re.search(r"\bSie\b", satz), (stufe, satz)
    assert set(kundenbericht._STUFE_TEXT) == set(kundenbericht.KUNDENSTUFEN)


def test_einordnung_der_stufen_nach_der_tabelle():
    for md in (md_von(befund(1)), md_von(befund(1, status="verdacht"))):          # auch ohne gelistete Befunde
        z = abschnitt(md, "## Management-Zusammenfassung")
        gefunden = [x for x in z if x in EINORDNUNG]
        assert gefunden == list(EINORDNUNG), z
        letzte_tabellenzeile = max(i for i, x in enumerate(z) if x.startswith("| "))
        assert z.index(EINORDNUNG[0]) > letzte_tabellenzeile
    md = md_von(befund(1))
    z = abschnitt(md, "## Management-Zusammenfassung")
    assert z.index(EINORDNUNG[-1]) < next(i for i, x in enumerate(z) if x.startswith("Es besteht"))


def test_befunde_nach_dringlichkeit_sortiert_satz():
    md = md_von(befund(1))
    assert abschnitt(md, "## Befunde")[:2] == ["", "Die Befunde sind nach Dringlichkeit sortiert."]
    ohne = md_von(befund(1, status="verdacht"))
    assert "nach Dringlichkeit sortiert" not in ohne


def test_zusammenfassung_ohne_befunde_entwarnung():
    md = md_von(befund(1, status="verworfen", grund="Kein Fehler"))
    assert tabelle(md) == {"Kritisch": 0, "Hoch": 0, "Mittel": 0, "Niedrig": 0}
    assert "In der geprüften Version wurden keine ausnutzbaren Schwachstellen gefunden." in zus(md)
    assert "Die Prüfung war eingeschränkt" not in md


# --- Eingeschränkte Prüfung

EINGESCHRAENKT = [
    ("gitleaks fehlt (Standardausnahmen)", "Suche nach Zugangsschlüsseln"),
    ("osv-scanner fehlt", "Abgleich der Abhängigkeiten"),
    ("abhaengigkeiten fehlgeschlagen (Exit 2)", "Abgleich der Abhängigkeiten"),
    ("lieferkette fehlgeschlagen (Exit 1)", "Prüfung der Build-Konfiguration"),
    ("docker-fehlt", "Nachstellung in einer Testumgebung"), ("build-fehler", "Nachstellung in einer Testumgebung"),
    ("build-timeout", "Nachstellung in einer Testumgebung"),
    ("start-fehler", "Nachstellung in einer Testumgebung"), ("lockfile-fehlt", "Nachstellung in einer Testumgebung"),
    ("lockfile-fremde-quelle", "Nachstellung in einer Testumgebung"), ("nicht-npm", "Nachstellung in einer Testumgebung"),
    ("Zeitbudget von bericht.py kontext erschöpft", "Abschluss einzelner Prüfungen (Zeitlimit)"),
    ("ki.py erkennen fehlgeschlagen (Exit 1)", "Prüfung der KI-Funktionen"),
    ("Modell-Mock nicht möglich: kein Modell", "Prüfung der KI-Funktionen"),
]


@pytest.mark.parametrize("hinweis,text", EINGESCHRAENKT)
def test_eingeschraenkt_tabelle(hinweis, text):
    md = md_von(befund(), hinweise=[hinweis])
    satz = [x for x in abschnitt(md, "## Umfang und Grenzen") if x.startswith("Die Prüfung war eingeschränkt (")]
    assert satz == [f"Die Prüfung war eingeschränkt ({text}); das Ergebnis ist deshalb nicht vollständig."]


def test_eingeschraenkt_mehrere_hinweise():
    md = md_von(befund(), hinweise=["KI-Prüfpunkte: angewendet (sdk)", "gitleaks fehlt (nicht im PATH)", "osv-scanner fehlt", "docker-fehlt",
                                    "build-fehler", "Zeitbudget erschöpft", "ki.py erkennen fehlgeschlagen (Exit 1)", "Modell-Mock nicht möglich: x",
                                    "gitleaks-Standardausnahmen nicht geprüft: abc", "native-module"], teilpfad="apps/web")
    satz = next(x for x in abschnitt(md, "## Umfang und Grenzen") if x.startswith("Die Prüfung war eingeschränkt ("))
    for text in ("nur der Teilbereich apps/web", "Suche nach Zugangsschlüsseln", "Abgleich der Abhängigkeiten",
                 "Nachstellung in einer Testumgebung", "Abschluss einzelner Prüfungen (Zeitlimit)", "Prüfung der KI-Funktionen"):
        assert satz.count(text) == 1, (text, satz)
    assert "Prüfung der Build-Konfiguration" not in satz
    assert satz.endswith("; das Ergebnis ist deshalb nicht vollständig.")
    # nichts zutreffend: kein Satz (auch kein Treffer auf bloße Erwähnung ähnlicher Hinweise)
    ohne = md_von(befund(), hinweise=["KI-Prüfpunkte: nicht anwendbar (kein LLM- oder Agenten-SDK in package.json)", "native-module"])
    assert "Die Prüfung war eingeschränkt" not in ohne


def test_eingeschraenkt_keine_befunde_kein_entwarnungssatz():
    md = md_von(befund(1, status="verworfen", grund="Kein Fehler"), hinweise=["gitleaks fehlt (nicht im PATH)"])
    z = zus(md)
    assert "keine ausnutzbaren Schwachstellen" not in md and "keine Schwachstellen" not in md
    assert "Die Prüfung war eingeschränkt (Suche nach Zugangsschlüsseln); das Ergebnis ist deshalb nicht vollständig." in z
    assert "Die Prüfung war eingeschränkt" in "\n".join(abschnitt(md, "## Umfang und Grenzen"))
    assert tabelle(md) == {"Kritisch": 0, "Hoch": 0, "Mittel": 0, "Niedrig": 0}


def test_teilpfad_eingeschraenkt():
    md = md_von(befund(1, status="verworfen", grund="Kein Fehler"), teilpfad="apps/web")
    assert "In der geprüften Version wurden keine ausnutzbaren Schwachstellen gefunden." not in md
    assert "Die Prüfung war eingeschränkt (nur der Teilbereich apps/web); das Ergebnis ist deshalb nicht vollständig." in md
    kopf = md_zeilen(md)[:abschnitt_ende(md)]
    assert any("nur der Teilbereich apps/web" in x for x in kopf)
    mit = md_von(befund(), teilpfad="apps/web")
    assert "Die Prüfung war eingeschränkt (nur der Teilbereich apps/web)" in "\n".join(abschnitt(mit, "## Umfang und Grenzen"))


def test_teilpfad_im_eingeschraenkt_satz_escaped():
    """M22: der Teilpfad im Satz „Die Prüfung war eingeschränkt“ geht wie im Kopf durch escape()."""
    md = md_von(befund(), teilpfad="apps/web_ui")
    satz = "Die Prüfung war eingeschränkt (nur der Teilbereich apps/web\\_ui); das Ergebnis ist deshalb nicht vollständig."
    assert satz in abschnitt(md, "## Umfang und Grenzen")
    assert satz in abschnitt(md, "## Management-Zusammenfassung")


def test_eingeschraenkt_satz_auch_am_ende_der_zusammenfassung_mit_befunden():
    """TF4 Review 2 (I4): bei eingeschränkter Prüfung steht der Satz am Ende der Management-Zusammenfassung und unter „Umfang und Grenzen“."""
    md = md_von(befund(), hinweise=["osv-scanner fehlt"])
    satz = "Die Prüfung war eingeschränkt (Abgleich der Abhängigkeiten); das Ergebnis ist deshalb nicht vollständig."
    z = [x for x in abschnitt(md, "## Management-Zusammenfassung") if x]
    assert z[-1] == satz and z.count(satz) == 1
    assert abschnitt(md, "## Umfang und Grenzen").count(satz) == 1
    assert md.count(satz) == 2
    assert md_von(befund(), hinweise=[]).count("Die Prüfung war eingeschränkt") == 0


# --- Aufbau

def test_abschnittsfolge_und_fuss():
    md = md_von(befund(1), befund(2, stufe="P3"))
    ueberschriften = [x for x in md_zeilen(md) if x.startswith("#") and not x.startswith("###")]
    assert ueberschriften == ["# Manibase · Sicherheitsprüfung Portal", "## Management-Zusammenfassung", "## Befunde", "## Umfang und Grenzen"]
    assert md_zeilen(md).index("## Befunde") < md.splitlines().index("### S-1 · Kritisch · Fremde Bestellungen einsehbar") < md_zeilen(md).index("## Umfang und Grenzen")
    assert md.endswith("\n\nManibase · vertraulich\n") and md.count("Manibase · vertraulich") == 1
    grenzen = "\n".join(abschnitt(md, "## Umfang und Grenzen"))
    for satz in ("Geprüft wurde der oben genannte Commit.", "Code-Analyse durch KI-Agenten", "isolierten Testumgebung ohne Zugriff auf Produktivsysteme",
                 "keine Garantie auf Vollständigkeit", "Der technische Bericht mit Details liegt Manibase vor.",
                 "Nach Umsetzung der Maßnahmen empfehlen wir eine erneute Prüfung."):
        assert satz in grenzen, satz


def test_ohne_befunde_befunde_abschnitt_bleibt():
    md = md_von(befund(1, status="verdacht"))
    assert "## Befunde" in md and "### " not in md


# --- Escaping (nur escape() und die Ausgabe; kein pandoc)

SONDER = ("Titel [Klick](http://x.example/a)", "![Bild](http://x.example/b.png)", "<img src=x onerror=1> <b>fett</b>",
          "Titel {.klasse width=10}", "[Text]{.klasse}", "Titel ##", "# Überschrift", "*kursiv* _kursiv_ `code` ~~weg~~ $x$ ^hoch^ @quelle &amp; a|b")


def test_escaping_link():
    e = kundenbericht.escape("Titel [Klick](http://x.example/a)")
    assert e == "Titel \\[Klick\\](http://x.example/a)"
    assert not re.search(r"(?<!\\)\[|(?<!\\)\]", e)


def test_escaping_bild():
    e = kundenbericht.escape("![Bild](http://x.example/b.png)")
    assert e.startswith("\\!\\[") and not re.search(r"(?<!\\)[!\[\]]", e)


def test_escaping_html():
    e = kundenbericht.escape("<img src=x onerror=1> <b>fett</b>")
    assert not re.search(r"(?<!\\)[<>]", e) and e.startswith("\\<img")


def test_escaping_attribut_klammer():
    e = kundenbericht.escape("Titel {.klasse width=10}")
    assert not re.search(r"(?<!\\)[{}]", e)


def test_escaping_span():
    e = kundenbericht.escape("[Text]{.klasse}")
    assert e == "\\[Text\\]\\{.klasse\\}"


def test_escaping_atx_schluss():
    assert kundenbericht.escape("Titel ##") == "Titel \\#\\#"
    assert kundenbericht.escape("# Überschrift").startswith("\\#")


def test_escaping_in_ausgabe_und_daten_nie_am_zeilenanfang():
    daten = bericht_daten(befund(titel="Tit [a](b) {.c} <i> #", zusammenfassung="ZQX " + "[Link](http://x.example) " * 3 + "ende ende ende ende",
                                 massnahme="Wir empfehlen, ZQX _fett_ und `code` zu entfernen.", datei="src/a_b/c*.ts"),
                          projekt="ZQX_Projekt [x]", teilpfad="ZQX/dir_1")
    md = kundenbericht.markdown_erzeugen(daten)
    assert "### S-1 · Kritisch · Tit \\[a\\](b) \\{.c\\} \\<i\\> \\#\n" in md
    assert "**Betroffene Datei:** src/a\\_b/c\\*.ts" in md_zeilen(md)
    assert "**Maßnahme:** Wir empfehlen, ZQX \\_fett\\_ und \\`code\\` zu entfernen." in md_zeilen(md)          # M19
    assert md.startswith("# Manibase · Sicherheitsprüfung ZQX\\_Projekt \\[x\\]\n")
    for zeile in md_zeilen(md):
        assert not zeile.startswith("ZQX"), zeile
        assert not zeile.startswith(("[", "!", "<", "{", ">", "`", "~", "ZQX")), zeile
    assert not re.search(r"(?<![\\])\[[^\]]*\]\(", md.replace("\\[", "")), "kein Link aus Daten"
    assert "<" not in md.replace("\\<", "") and ">" not in md.replace("\\>", "")


# --- Feste Texte

NEUTRAL = "Platzhalter"


def neutral_daten(n=2, status=("bestätigt", "unbestätigt"), **kopf):
    """Berichte über alle Stufen, Singular und Plural, je `status` (Standard: beide); Datenfelder sind neutrale Platzhalter."""
    unb = dict(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"])
    bef = []
    nr = 0
    for stufe, kritisch in (("P1", True), ("P1", False), ("P2", False), ("P3", False)):
        for extra in ({"bestätigt": {}, "unbestätigt": unb}[st] for st in status):
            for _ in range(n):
                nr += 1
                bef.append(befund(nr, stufe=stufe, ohne_anmeldung=kritisch, mandantenuebergreifend=False, titel=NEUTRAL,
                                  zusammenfassung=NEUTRAL * 5, massnahme=NEUTRAL * 3, datei=NEUTRAL, **extra))
    d = bericht_daten(*bef, projekt=NEUTRAL, hinweise=[h for h, _ in EINGESCHRAENKT], teilpfad=NEUTRAL)
    d.update(kopf)
    return d


def feste_texte_faelle():
    yield neutral_daten(1)
    yield neutral_daten(2)
    for status in (("bestätigt",), ("unbestätigt",)):          # reiner Status je Stufe: sonst läuft die jeweils andere Empfehlung nie (N01 bis N03, M45)
        yield neutral_daten(1, status=status)
        yield neutral_daten(2, status=status)
    yield neutral_daten(befunde=[], hinweise=[], teilpfad=None)
    yield neutral_daten(befunde=[], hinweise=[], teilpfad=NEUTRAL)
    yield neutral_daten(befunde=[], hinweise=["gitleaks fehlt"], teilpfad=None)
    yield neutral_daten(projekt=None, ordner=NEUTRAL, hinweise=[], teilpfad=None)
    yield neutral_daten(projekt=None, ordner=None, hinweise=[], teilpfad=None)
    for h, _ in EINGESCHRAENKT:
        yield neutral_daten(hinweise=[h], teilpfad=None)
    b = [befund(1, titel=NEUTRAL, zusammenfassung=NEUTRAL * 5, massnahme=NEUTRAL * 3, datei=None, werkzeug=w) for w in ("gitleaks", "osv-scanner", "lieferkette")]
    for i, x in enumerate(b, 1):
        x["id"] = f"S-{i}"
    yield neutral_daten(befunde=b, hinweise=[], teilpfad=None)
    yield neutral_daten(befunde=[befund(1, annahme_modell=True, titel=NEUTRAL, zusammenfassung=NEUTRAL * 5, massnahme=NEUTRAL * 3, datei=NEUTRAL)])


def test_feste_texte_ohne_du_und_spuren():
    anzahl = 0
    for daten in feste_texte_faelle():
        md = kundenbericht.markdown_erzeugen(daten)
        anzahl += 1
        # text_verstoesse prüft höchstens die ersten 5000 Zeichen eines Textes; bei langen Berichten trägt die zeilenweise Prüfung unten die Last
        assert bericht.text_verstoesse(md) == [], (anzahl, bericht.text_verstoesse(md))
        for zeile in md_zeilen(md):
            assert not re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\s+/", zeile)
    assert anzahl >= 24
    # Bausteine einzeln: jede Zeile aus allen Fällen auch ohne Markdown-Zeichen geprüft
    texte = {z for d in feste_texte_faelle() for z in md_zeilen(kundenbericht.markdown_erzeugen(d))}
    assert any("Es bestehen zwei Schwachstellen der Stufe Kritisch" in t for t in texte)
    for stufe in kundenbericht.KUNDENSTUFEN:               # alle Empfehlungen sind in den Fällen enthalten und bestehen die Prüfung
        for satz in kundenbericht._STUFE_TEXT[stufe][1:]:
            assert any(satz in t for t in texte), satz
            assert bericht.text_verstoesse(satz) == [], satz
    for t in texte:
        assert bericht.text_verstoesse(t) == [], t


def test_feste_texte_enthalten_keine_nachtraeglichen_datenwerte():
    """Mit Platzhalter-Daten besteht jede Zeile entweder aus festem Text oder trägt den Platzhalter hinter einem festen Präfix."""
    md = kundenbericht.markdown_erzeugen(neutral_daten())
    for zeile in md_zeilen(md):
        if NEUTRAL in zeile:
            assert zeile.startswith(("# Manibase · Sicherheitsprüfung ", "### S-", "**Risiko:** ", "**Maßnahme:** ", "**Betroffene Datei:** ",
                                     "**Geprüfter Bereich:** ", "Die Prüfung war eingeschränkt (", "**Geprüfter Bereich:** ")), zeile


def test_erstellen_schreibt_neues_markdown(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(1), befund(2, stufe="P3")), name=BASIS + ".json")
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr
    md = open(kunde_pfad(pfad, "md"), encoding="utf-8").read()
    assert "## Management-Zusammenfassung" in md and "## Umfang und Grenzen" in md and md.endswith("Manibase · vertraulich\n")


# ====================================================================================== Teil 3: PDF-Kette

SHIM = '''#!@@PYTHON@@
import json, os, sys, time
cfg = json.load(open("@@CFG@@"))
with open(cfg["log"], "a") as f:
    f.write(json.dumps({"name": cfg["name"], "argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ)}) + "\\n")
if cfg.get("schlaf"):
    time.sleep(cfg["schlaf"])
args = sys.argv[1:]
if cfg["name"] == "pandoc":
    ziel = args[args.index("-o") + 1]
    vorlage = open(args[args.index("--template") + 1], encoding="utf-8").read()
    html = cfg["html"] if "html" in cfg else vorlage.replace("$pagetitle$", "Titel").replace("$body$", cfg.get("body", "<h1>Kopf</h1>"))
    if cfg.get("schreiben", True):
        open(ziel, "w", encoding="utf-8").write(html)
elif cfg.get("pdf") is not None:
    open(args[-1], "wb").write(cfg["pdf"].encode("latin-1"))
sys.stderr.write(cfg.get("stderr", ""))
sys.exit(cfg.get("rc", 0))
'''
PDF_OK = "%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


def attrappen(tmp_path, pandoc=None, weasyprint=None, name="shim"):
    """Legt Attrappen als Skripte in einen eigenen Ordner (nur dieser steht im PATH). None = das Werkzeug fehlt, dict = Verhalten
    der Attrappe. Sie protokollieren Argumente, cwd und Umgebung in einer Logdatei. Gibt (Umgebung für `lauf`, Logdatei) zurück."""
    ordner = tmp_path / name
    ordner.mkdir(exist_ok=True)
    log = ordner / "log.jsonl"
    for werkzeug, cfg in (("pandoc", pandoc), ("weasyprint", weasyprint)):
        if cfg is None:
            continue
        cfgdatei = ordner / f"{werkzeug}.cfg.json"
        cfgdatei.write_text(json.dumps({"pdf": PDF_OK, **cfg, "name": werkzeug, "log": str(log)}), encoding="utf-8")
        skript = ordner / werkzeug
        skript.write_text(SHIM.replace("@@PYTHON@@", sys.executable).replace("@@CFG@@", str(cfgdatei)), encoding="utf-8")
        skript.chmod(0o755)
    return {"SECURITY_AUDIT_OHNE": "", "PATH": str(ordner)}, log


def protokoll(log):
    return [json.loads(z) for z in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def aufruf(log, name):
    treffer = [e for e in protokoll(log) if e["name"] == name]
    assert len(treffer) == 1, treffer
    return treffer[0]


def real(pfad):
    """macOS: /var ist ein Link auf /private/var; getcwd() im Kindprozess liefert die aufgelöste Form."""
    return os.path.realpath(pfad)


def beide(**kw):
    return {"pandoc": kw.get("pandoc", {}), "weasyprint": kw.get("weasyprint", {})}


@pytest.fixture
def bericht_pfad(tmp_path):
    return schreibe(tmp_path / "out", bericht_daten())


# ------------------------------------------------------------------------------------ Template

def test_template_aufbau():
    text = open(kundenbericht.TEMPLATE, encoding="utf-8").read()
    assert '<html lang="de">' in text and text.count("<style>") == 1 and text.count("</style>") == 1
    css = text.split("<style>")[1].split("</style>")[0]
    assert "$" not in css, "pandoc-Template-Syntax im CSS"
    assert "size: A4" in css and "counter(page)" in css and "@bottom-center" in css
    assert not re.search(r"url\(|@import|https?:|//", css), "keine externen Ressourcen"
    assert "$pagetitle$" in text and "$body$" in text and text.count("$") == 4


def test_template_style_ist_der_sollwert_der_html_pruefung():
    assert kundenbericht.html_pruefen(html_mit("<p>x</p>")) == []


# ------------------------------------------------------------------------------------ Aufruf der Werkzeuge

def test_erfolg_beide_werkzeuge_in_reihenfolge(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, **beide())
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 0, p.stdout + p.stderr
    assert zeilen(p) == ["kunde-md: " + kunde_pfad(bericht_pfad, "md"), "kunde-pdf: " + kunde_pfad(bericht_pfad, "pdf")]
    assert [e["name"] for e in protokoll(log)] == ["pandoc", "weasyprint"]
    assert open(kunde_pfad(bericht_pfad, "pdf"), "rb").read() == PDF_OK.encode()
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + "-kunde.pdf", BASIS + ".json"]


PANDOC_ERWEITERUNGEN = ("markdown-smart-auto_identifiers-yaml_metadata_block-pandoc_title_block-citations-tex_math_dollars-implicit_figures"
                        "-raw_html-raw_attribute-raw_tex-header_attributes-bracketed_spans-fenced_divs-link_attributes"
                        "-native_spans-native_divs-fenced_code_attributes-inline_code_attributes-footnotes-inline_notes")


def test_pandoc_args(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, **beide())
    assert lauf(bericht_pfad, env=env).returncode == 0
    e = aufruf(log, "pandoc")
    argv = e["argv"]
    assert os.path.isabs(argv[0]) and os.path.basename(argv[0]) == "pandoc", "absoluter Werkzeugpfad"
    assert "--sandbox" in argv
    assert argv[argv.index("--from") + 1] == PANDOC_ERWEITERUNGEN
    assert argv[argv.index("--to") + 1] == "html5"
    assert argv[argv.index("--template") + 1] == kundenbericht.TEMPLATE and os.path.isabs(kundenbericht.TEMPLATE)
    assert argv[argv.index("--metadata") + 1] == "pagetitle=Manibase · Sicherheitsprüfung Portal"
    assert not {"-V", "--variable", "--title"} & set(argv) and not any(a.startswith(("--variable", "--metadata=title", "title=")) for a in argv)
    assert "--columns=1000" in argv
    assert argv[-1] == kunde_pfad(bericht_pfad, "md") and os.path.isabs(argv[-1]), "Eingabe per absolutem Pfad, nicht per stdin"
    ausgabe = argv[argv.index("-o") + 1]
    assert real(os.path.dirname(ausgabe)) == real(e["cwd"]) and ausgabe.endswith(".html")


def test_weasyprint_args(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, **beide())
    assert lauf(bericht_pfad, env=env).returncode == 0
    e, pe = aufruf(log, "weasyprint"), aufruf(log, "pandoc")
    argv = e["argv"]
    assert os.path.isabs(argv[0]) and os.path.basename(argv[0]) == "weasyprint"
    assert argv[1:3] == ["--allowed-protocols", ""], "kein Protokoll erlaubt"
    eingabe, ausgabe = argv[3:]
    assert eingabe == pe["argv"][pe["argv"].index("-o") + 1], "weasyprint liest genau die von pandoc geschriebene Datei"
    assert real(os.path.dirname(eingabe)) == real(os.path.dirname(ausgabe)) == real(e["cwd"]) == real(pe["cwd"])


def test_cwd_ist_eigener_tempordner_und_wird_aufgeraeumt(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, **beide())
    assert lauf(bericht_pfad, env=env).returncode == 0
    cwd = aufruf(log, "pandoc")["cwd"]
    assert os.path.basename(cwd).startswith("kunde-pdf-")
    assert os.path.realpath(os.path.dirname(cwd)) == os.path.realpath(tempfile.gettempdir())
    assert cwd not in (str(tmp_path / "out"), os.getcwd())
    assert not os.path.exists(cwd), "Temp-Ordner entfernt"


@pytest.mark.parametrize("pandoc,weasyprint", [({"rc": 1}, {}), ({"body": "<img src=x>"}, {}), ({}, {"rc": 1}), ({}, {"stderr": "Error: x"}),
                                               ({}, {"pdf": None}), ({"schlaf": 30}, {})])
def test_tempordner_aufgeraeumt(tmp_path, bericht_pfad, pandoc, weasyprint):
    """Auch nach jedem Fehlerpfad: der eigene Temp-Ordner ist weg, im Zielordner bleibt kein Rest."""
    env, log = attrappen(tmp_path, pandoc=pandoc, weasyprint=weasyprint)
    p = lauf(bericht_pfad, env={**env, "SECURITY_AUDIT_KUNDE_BUDGET": "3" if pandoc.get("schlaf") else "90"})
    assert p.returncode == 4, p.stdout + p.stderr
    cwds = {e["cwd"] for e in protokoll(log)}
    assert len(cwds) == 1 and not os.path.exists(cwds.pop())
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


def test_werkzeug_umgebung_ohne_proxy(tmp_path, monkeypatch, bericht_pfad):
    """R1-W6/K3: die Umgebung der Werkzeuge ist eine Whitelist; Proxy, PYTHONPATH und fremde Variablen kommen nicht an."""
    for k, v in (("HTTPS_PROXY", "http://p:1"), ("http_proxy", "http://p:1"), ("ALL_PROXY", "http://p:1"), ("NO_PROXY", "x"),
                 ("PYTHONPATH", "/nirgends"), ("PYTHONSTARTUP", "/nirgends"), ("GEHEIMNIS_X", "wert"), ("LANG", "de_DE.UTF-8")):
        monkeypatch.setenv(k, v)
    env, log = attrappen(tmp_path, **beide())
    assert lauf(bericht_pfad, env=env).returncode == 0
    for name in ("pandoc", "weasyprint"):
        e = aufruf(log, name)
        umgebung = e["env"]
        assert not [k for k in umgebung if "PROXY" in k.upper()] and not any(k.startswith("PYTHON") for k in umgebung)
        assert "GEHEIMNIS_X" not in umgebung
        assert umgebung["PATH"] == env["PATH"] and umgebung["LANG"] == "de_DE.UTF-8"
        assert real(umgebung["HOME"]) == real(umgebung["TMPDIR"]) == real(e["cwd"])
        assert set(umgebung) <= {"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "LC_CTYPE", "PWD", "__CF_USER_TEXT_ENCODING", "__PYVENV_LAUNCHER__"}, sorted(umgebung)


def test_werkzeug_env_funktion(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "x")
    monkeypatch.delenv("LC_ALL", raising=False)
    assert kundenbericht._werkzeug_env("/t") == {"PATH": os.environ["PATH"], "HOME": "/t", "TMPDIR": "/t", **({"LANG": os.environ["LANG"]} if "LANG" in os.environ else {})}


# ------------------------------------------------------------------------------------ TF4-D5: Werkzeug fehlt

def test_weasyprint_fehlt_exit3_markdown_liegt(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, pandoc={})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-werkzeug-fehlt", "kunde-md: " + kunde_pfad(bericht_pfad, "md"), "Werkzeug fehlt: weasyprint"]
    assert protokoll(log) == [], "pandoc wurde nicht aufgerufen: Werkzeuge werden vor dem ersten Kindprozess geprüft"
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


def test_pandoc_fehlt_exit3(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, weasyprint={})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-werkzeug-fehlt", "kunde-md: " + kunde_pfad(bericht_pfad, "md"), "Werkzeug fehlt: pandoc"]
    assert protokoll(log) == []
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


def test_werkzeug_ausgeschlossen_per_umgebung_exit3(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, **beide())
    p = lauf(bericht_pfad, env={**env, "SECURITY_AUDIT_OHNE": "WeasyPrint"})
    assert p.returncode == 3 and zeilen(p)[-1] == "Werkzeug fehlt: weasyprint" and protokoll(log) == []


@pytest.mark.parametrize("kaputt", ["pandoc", "weasyprint"])
def test_werkzeug_nicht_startbar_exit3(tmp_path, bericht_pfad, kaputt):
    env, log = attrappen(tmp_path, **beide())
    (tmp_path / "shim" / kaputt).write_text("#!/nicht/vorhanden/interpreter\n")
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-werkzeug-fehlt", "kunde-md: " + kunde_pfad(bericht_pfad, "md"), f"Werkzeug nicht startbar: {kaputt}"]
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


def test_nul_im_titel_exit4(tmp_path, monkeypatch):
    """M-2: `Popen` wirft bei einem NUL im Argument ValueError (nicht OSError); `pdf_erstellen` meldet Exit 4 und räumt auf."""
    env, log = attrappen(tmp_path, **beide())
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    monkeypatch.setenv("PATH", env["PATH"])
    md, pdf = md_datei(tmp_path)
    code, kategorie, meldungen = kundenbericht.pdf_erstellen(md, pdf, "Ti\x00tel", time.monotonic() + 30)
    assert (code, kategorie) == (4, "pdf-fehler") and meldungen == ["Werkzeug nicht aufrufbar: pandoc"], (code, kategorie, meldungen)
    assert protokoll(log) == [] and not os.path.exists(pdf)
    assert not [n for n in os.listdir(tempfile.gettempdir()) if n.startswith("kunde-pdf-") and os.path.getmtime(os.path.join(tempfile.gettempdir(), n)) > time.time() - 30]


@pytest.mark.parametrize("name", ["kunde.html", "kunde.pdf"])
def test_datei_nicht_lesbar_exit4(tmp_path, monkeypatch, name):
    """M-3: ein OSError beim Lesen von HTML oder PDF aus dem eigenen Temp-Ordner ergibt Exit 4 statt eines internen Fehlers."""
    env, log = attrappen(tmp_path, **beide())
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    monkeypatch.setenv("PATH", env["PATH"])
    echtes_open = open

    def open_(pfad, *a, **kw):
        if os.path.basename(str(pfad)) == name:
            raise PermissionError(13, "Zugriff verweigert")
        return echtes_open(pfad, *a, **kw)

    monkeypatch.setattr(kundenbericht, "open", open_, raising=False)
    md, pdf = md_datei(tmp_path)
    code, kategorie, meldungen = kundenbericht.pdf_erstellen(md, pdf, "T", time.monotonic() + 30)
    assert (code, kategorie) == (4, "pdf-fehler") and len(meldungen) == 1 and "nicht lesbar" in meldungen[0], (code, kategorie, meldungen)
    assert not os.path.exists(pdf)
    cwd = aufruf(log, "pandoc")["cwd"]
    assert not os.path.exists(cwd), "Temp-Ordner entfernt"


def test_datei_nicht_lesbar_ende_zu_ende_exit4(tmp_path, bericht_pfad, monkeypatch):
    """M-3 über die CLI: Exit 4 mit Kategorie pdf-fehler, das Markdown liegt, nichts Weiteres."""
    env, _ = attrappen(tmp_path, **beide())
    echtes_lstat = kundenbericht._lstat

    def lstat(pfad):
        if pfad.endswith(".html"):
            raise PermissionError(13, "Zugriff verweigert")
        return echtes_lstat(pfad)

    monkeypatch.setattr(kundenbericht, "_lstat", lstat)
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    monkeypatch.setenv("PATH", env["PATH"])
    assert kundenbericht.main(["erstellen", "--json", str(bericht_pfad)]) == 4
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


# ------------------------------------------------------------------------------------ HTML-Prüfung

def html_mit(body, kopf=""):
    """Das Template mit eingesetztem Text, wie pandoc es erzeugt (`kopf` ergänzt den Kopf für Tests der Prüfung)."""
    text = open(kundenbericht.TEMPLATE, encoding="utf-8").read()
    return text.replace("$pagetitle$", "Titel").replace("$body$", body).replace("</head>", kopf + "</head>")


@pytest.mark.parametrize("body", [
    "<h1>Kopf</h1>\n<p><strong>a</strong> <em>b</em> <code>c</code><br />\n<span class=\"x\" id=\"y\">d</span></p>",
    "<table>\n<thead>\n<tr>\n<th>A</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>1</td>\n</tr>\n</tbody>\n</table>\n<hr />\n<ul>\n<li>x</li>\n</ul>",
    "<p>Titel &lt;img src=x onerror=y&gt; url(file:///etc/hosts) ![x](/etc/hosts) &amp; &#60;link&#62;</p>",
    "<header><main><section><div><h2>x</h2><h3>y</h3></div></section></main></header><footer>f</footer>",
])
def test_html_pruefung_erlaubt(body):
    assert kundenbericht.html_pruefen(html_mit(body)) == []


def test_html_pruefung_escapter_text_ist_erlaubt():
    assert kundenbericht.html_pruefen(html_mit("<p>&lt;img src=&quot;http://x/a.png&quot;&gt; &lt;script&gt;</p>")) == []


def test_html_pruefung_img():
    m = kundenbericht.html_pruefen(html_mit('<p><img src="http://x.example/a.png"></p>'))
    assert "Tag nicht erlaubt: img" in m and "x.example" not in " ".join(m), "Tagname, nie der Wert"


def test_html_pruefung_link():
    m = kundenbericht.html_pruefen(html_mit("", kopf='<link rel="stylesheet" href="http://x.example/a.css">'))
    assert "Tag nicht erlaubt: link" in m and "x.example" not in " ".join(m)


def test_html_pruefung_object():
    assert "Tag nicht erlaubt: object" in kundenbericht.html_pruefen(html_mit('<object data="file:///etc/hosts"></object>'))


@pytest.mark.parametrize("body,erwartet", [('<p href="http://x.example/">a</p>', "href"), ('<p src="x">a</p>', "src"), ('<p onclick="x">a</p>', "onclick"),
                                           ('<td colspan="2">a</td>', "colspan"), ('<span data-x="1">a</span>', "data-x")])
def test_html_pruefung_href_extern(body, erwartet):
    m = kundenbericht.html_pruefen(html_mit(body))
    assert any(z.startswith(f"Attribut nicht erlaubt: {erwartet} an ") for z in m) and "x.example" not in " ".join(m)


@pytest.mark.parametrize("tag,body,kopf", [
    ("svg", '<svg><image href="file:///etc/hosts"/></svg>', ""),
    ("math", "<math><mi>x</mi></math>", ""),
    ("base", "", '<base href="http://x.example/">'),
    ("script", "<script>alert(1)</script>", ""),
    ("iframe", '<iframe src="file:///etc/hosts"></iframe>', ""),
    ("textarea", "<textarea>x</textarea>", ""),
    ("template", "<template><p>x</p></template>", ""),
    ("form", '<form action="http://x.example/"></form>', ""),
    ("noscript", "<noscript>x</noscript>", ""),
    ("embed", '<embed src="file:///etc/hosts">', ""),
    ("image", '<image href="file:///etc/hosts">', ""),
    ("use", '<use href="#x">', ""),
])
def test_html_pruefung_verbotene_tags(tag, body, kopf):
    """Die Erlaubtliste ist festgenagelt: jeder dieser Tags wird mit Namen gemeldet, nie mit Werten."""
    m = kundenbericht.html_pruefen(html_mit(body, kopf))
    assert f"Tag nicht erlaubt: {tag}" in m and "x.example" not in " ".join(m) and "etc/hosts" not in " ".join(m)


def test_html_pruefung_meta_http_equiv_ist_verboten():
    m = kundenbericht.html_pruefen(html_mit("", kopf='<meta http-equiv="refresh" content="0;url=http://x.example/">'))
    assert m == ["Attribut nicht erlaubt: http-equiv an meta"]


@pytest.mark.parametrize("attribut", ["onload", "xmlns", "style", "href", "dir"])
def test_html_pruefung_html_tag_nur_lang(attribut):
    m = kundenbericht.html_pruefen(html_mit("<p>a</p>").replace('<html lang="de">', f'<html lang="de" {attribut}="x">'))
    assert m == [f"Attribut nicht erlaubt: {attribut} an html"]


def test_html_pruefung_body_onload():
    m = kundenbericht.html_pruefen(html_mit("<p>a</p>").replace("<body>", '<body onload="x">'))
    assert m == ["Attribut nicht erlaubt: onload an body"]


def test_html_pruefung_a_tag():
    m = kundenbericht.html_pruefen(html_mit('<p><a href="http://x.example/">y</a></p>'))
    assert "Tag nicht erlaubt: a" in m and "x.example" not in " ".join(m)


def test_html_pruefung_style_attribut():
    m = kundenbericht.html_pruefen(html_mit('<h3 style="background:url(http://x.example/a.png)">x</h3>'))
    assert "Attribut nicht erlaubt: style an h3" in m and "x.example" not in " ".join(m)


def test_html_pruefung_zweites_style():
    m = kundenbericht.html_pruefen(html_mit("<p>a</p><style>p { color: red; }</style>"))
    assert m == ["style: genau ein Element erlaubt"]


def test_html_pruefung_style_inhalt_geaendert():
    html = html_mit("<p>a</p>").replace("size: A4;", "size: A4; background: url(http://x.example/a.png);")
    m = kundenbericht.html_pruefen(html)
    assert m and any("style" in z for z in m) and "x.example" not in " ".join(m)


def test_html_pruefung_ohne_style():
    html = re.sub(r"<style>.*?</style>", "", html_mit("<p>a</p>"), flags=re.S)
    assert any("style" in z for z in kundenbericht.html_pruefen(html))


def test_html_pruefung_kommentar():
    assert kundenbericht.html_pruefen(html_mit("<p>a</p><!-- <img src=x> -->"))


def test_html_pruefung_pi_und_deklarationen():
    assert kundenbericht.html_pruefen(html_mit('<?xml-stylesheet href="x.css"?>'))
    assert kundenbericht.html_pruefen(html_mit("<![CDATA[ x ]]>"))
    assert kundenbericht.html_pruefen(html_mit("<p>a</p>").replace("<!DOCTYPE html>", '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://x.example/dtd">'))


def test_html_pruefung_doctype_html_ist_erlaubt():
    assert kundenbericht.html_pruefen(html_mit("<p>a</p>").replace("<!DOCTYPE html>", "<!doctype HTML>")) == []


def test_html_pruefung_kommentar_und_pi():
    """K4: Kommentare und Processing Instructions ergeben Exit 4."""
    html = html_mit("<p>a</p>")
    assert kundenbericht.html_pruefen(html.replace("<body>", "<body><!--x-->"))
    assert kundenbericht.html_pruefen(html.replace("<body>", "<body><?php x ?>"))


def test_html_pruefung_lang_nur_de_nur_an_html():
    html = html_mit("<p>a</p>")
    assert any("lang" in z for z in kundenbericht.html_pruefen(html.replace('lang="de"', 'lang="en"')))
    assert any("lang" in z for z in kundenbericht.html_pruefen(html.replace("<body>", '<body lang="de">')))


def test_html_pruefung_meta_attribute():
    assert kundenbericht.html_pruefen(html_mit("", kopf='<meta name="viewport" content="width=device-width">')) == []
    m = kundenbericht.html_pruefen(html_mit("", kopf='<meta http-equiv="refresh" content="0;url=http://x.example/">'))
    assert "Attribut nicht erlaubt: http-equiv an meta" in m and "x.example" not in " ".join(m)


def test_html_pruefung_endtag_ohne_starttag():
    assert "Tag nicht erlaubt: img" in kundenbericht.html_pruefen(html_mit("<p>a</p></img>"))


def test_html_pruefung_meldung_ohne_steuerzeichen_und_begrenzt():
    m = kundenbericht.html_pruefen(html_mit("<" + "x" * 500 + ' a="b">'))
    assert m and all(len(z) < 200 and "\n" not in z for z in m)


def test_html_pruefung_ende_zu_ende_exit4(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, pandoc={"body": '<p><img src="http://x.example/a.png"></p>'}, weasyprint={})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 4, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-fehler", "kunde-md: " + kunde_pfad(bericht_pfad, "md"), "Tag nicht erlaubt: img"]
    assert [e["name"] for e in protokoll(log)] == ["pandoc"], "weasyprint startet nach einem Verstoß nicht"
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


# ------------------------------------------------------------------------------------ Fehlerpfade von pandoc und weasyprint

@pytest.mark.parametrize("stderr", ["ERROR: Failed to load image at 'file:///x'", "WARNING: disallowed protocol 'file' in url", "Failed to load stylesheet",
                                    "Error: boom", "error", "DISALLOWED PROTOCOL"])
@pytest.mark.parametrize("rc", [0, 1])
def test_weasyprint_stderr_fehler_exit4(tmp_path, bericht_pfad, stderr, rc):
    env, log = attrappen(tmp_path, pandoc={}, weasyprint={"stderr": stderr, "rc": rc})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 4, p.stdout + p.stderr
    assert zeilen(p)[:2] == ["kategorie: pdf-fehler", "kunde-md: " + kunde_pfad(bericht_pfad, "md")]
    assert "file:///x" not in p.stdout, "stderr wird nicht wiedergegeben"
    assert not os.path.exists(kunde_pfad(bericht_pfad, "pdf")), "ein PDF mit Ladefehler wird nicht abgelegt"
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + ".json"]


def test_weasyprint_warnung_ist_kein_fehler(tmp_path, bericht_pfad):
    env, _ = attrappen(tmp_path, pandoc={}, weasyprint={"stderr": "WARNING: Ignored `x: y` at 3:5, unknown property.\n"})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 0, p.stdout + p.stderr


@pytest.mark.parametrize("pdf", [None, "", "<html>kein pdf</html>", " %PDF-1.7"])
def test_weasyprint_kein_pdf_exit4(tmp_path, bericht_pfad, pdf):
    env, _ = attrappen(tmp_path, pandoc={}, weasyprint={"pdf": pdf})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 4, p.stdout + p.stderr
    assert zeilen(p)[:2] == ["kategorie: pdf-fehler", "kunde-md: " + kunde_pfad(bericht_pfad, "md")]
    assert not os.path.exists(kunde_pfad(bericht_pfad, "pdf"))


@pytest.mark.parametrize("werkzeug", ["pandoc", "weasyprint"])
def test_werkzeug_rc_ungleich_null_exit4(tmp_path, bericht_pfad, werkzeug):
    env, _ = attrappen(tmp_path, **{**beide(), werkzeug: {"rc": 3}})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 4, p.stdout + p.stderr
    assert zeilen(p)[:2] == ["kategorie: pdf-fehler", "kunde-md: " + kunde_pfad(bericht_pfad, "md")]
    assert not os.path.exists(kunde_pfad(bericht_pfad, "pdf"))


def test_pandoc_schreibt_keine_datei_exit4(tmp_path, bericht_pfad):
    env, log = attrappen(tmp_path, pandoc={"schreiben": False}, weasyprint={})
    p = lauf(bericht_pfad, env=env)
    assert p.returncode == 4 and [e["name"] for e in protokoll(log)] == ["pandoc"]


def test_pandoc_timeout_exit4(tmp_path, bericht_pfad):
    """Die Attrappe schläft; das kleine Budget lässt `werkzeug_ausfuehren` nach Ablauf die eigene Gruppe beenden (nichts sonst)."""
    env, log = attrappen(tmp_path, pandoc={"schlaf": 30}, weasyprint={})
    vorher = time.monotonic()
    p = lauf(bericht_pfad, env={**env, "SECURITY_AUDIT_KUNDE_BUDGET": "2"})
    assert p.returncode == 4, p.stdout + p.stderr
    assert zeilen(p)[:2] == ["kategorie: pdf-fehler", "kunde-md: " + kunde_pfad(bericht_pfad, "md")]
    assert time.monotonic() - vorher < 25
    assert [e["name"] for e in protokoll(log)] == ["pandoc"], "nach dem Timeout startet weasyprint nicht"
    assert not os.path.exists(kunde_pfad(bericht_pfad, "pdf"))


# ------------------------------------------------------------------------------------ Budget (kein Kindprozess: werkzeug_ausfuehren ist ersetzt)

class Uhr:
    def __init__(self, start=1000.0):
        self.jetzt = start

    def monotonic(self):
        return self.jetzt


def falsche_werkzeuge(monkeypatch, tmp_path, verbrauch=None):
    """Ersetzt `werkzeug_ausfuehren` und die Uhr des Moduls; protokolliert die Timeouts. Schreibt wie die Attrappen HTML bzw. PDF."""
    env, _ = attrappen(tmp_path, **beide(), name="fake")
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    monkeypatch.setenv("PATH", env["PATH"])
    uhr = Uhr()
    monkeypatch.setattr(kundenbericht, "time", types.SimpleNamespace(monotonic=uhr.monotonic))
    aufrufe = []

    def fake(args, timeout, cwd, env=None, ausgabe_max=0):
        name = os.path.basename(args[0])
        aufrufe.append({"name": name, "timeout": timeout, "cwd": cwd, "args": args})
        uhr.jetzt += (verbrauch or {}).get(name, 0)
        if name == "pandoc":
            vorlage = open(args[args.index("--template") + 1], encoding="utf-8").read()
            open(args[args.index("-o") + 1], "w", encoding="utf-8").write(vorlage.replace("$pagetitle$", "T").replace("$body$", "<p>x</p>"))
        else:
            open(args[-1], "wb").write(PDF_OK.encode())
        return gitkopie.Lauf(0, b"", b"")

    monkeypatch.setattr(kundenbericht.gitkopie, "werkzeug_ausfuehren", fake)
    return uhr, aufrufe


def md_datei(tmp_path):
    (tmp_path / "out").mkdir(exist_ok=True)
    md = tmp_path / "out" / "x-kunde.md"
    md.write_text("# x\n", encoding="utf-8")
    return str(md), str(tmp_path / "out" / "x-kunde.pdf")


def test_budget_konstanten():
    assert (kundenbericht.KUNDE_BUDGET, kundenbericht.PANDOC_MAX, kundenbericht.WEASYPRINT_MAX) == (90, 20, 60)


def test_budget_anteile(monkeypatch, tmp_path):
    uhr, aufrufe = falsche_werkzeuge(monkeypatch, tmp_path)
    md, pdf = md_datei(tmp_path)
    assert kundenbericht.pdf_erstellen(md, pdf, "T", uhr.jetzt + 90) == (0, None, [])
    assert [(a["name"], a["timeout"]) for a in aufrufe] == [("pandoc", 20), ("weasyprint", 60)]


def test_budget_rest_kuerzt_weasyprint(monkeypatch, tmp_path):
    uhr, aufrufe = falsche_werkzeuge(monkeypatch, tmp_path, verbrauch={"pandoc": 10})
    md, pdf = md_datei(tmp_path)
    assert kundenbericht.pdf_erstellen(md, pdf, "T", uhr.jetzt + 25)[0] == 0
    assert [(a["name"], a["timeout"]) for a in aufrufe] == [("pandoc", 20), ("weasyprint", 15)]


def test_budget_rest_kuerzt_pandoc(monkeypatch, tmp_path):
    uhr, aufrufe = falsche_werkzeuge(monkeypatch, tmp_path)
    md, pdf = md_datei(tmp_path)
    kundenbericht.pdf_erstellen(md, pdf, "T", uhr.jetzt + 7)
    assert aufrufe[0]["timeout"] == 7 and aufrufe[1]["timeout"] == 7


def test_budget_rest_null_exit4(monkeypatch, tmp_path):
    """Ist der Rest ≤ 0, startet kein Werkzeug."""
    uhr, aufrufe = falsche_werkzeuge(monkeypatch, tmp_path)
    md, pdf = md_datei(tmp_path)
    for ende in (uhr.jetzt, uhr.jetzt - 5):
        code, kategorie, meldungen = kundenbericht.pdf_erstellen(md, pdf, "T", ende)
        assert (code, kategorie) == (4, "pdf-fehler") and meldungen and "pandoc" in meldungen[0]
    assert aufrufe == [] and not os.path.exists(pdf)


def test_budget_erschoepft_vor_weasyprint_exit4(monkeypatch, tmp_path):
    uhr, aufrufe = falsche_werkzeuge(monkeypatch, tmp_path, verbrauch={"pandoc": 10})
    md, pdf = md_datei(tmp_path)
    code, kategorie, meldungen = kundenbericht.pdf_erstellen(md, pdf, "T", uhr.jetzt + 10)
    assert (code, kategorie) == (4, "pdf-fehler") and "weasyprint" in meldungen[0]
    assert [a["name"] for a in aufrufe] == ["pandoc"] and not os.path.exists(pdf)


def test_budget_override_nur_kuerzer(monkeypatch, tmp_path):
    pfad = schreibe(tmp_path / "o", bericht_daten())
    gesehen = []
    monkeypatch.setattr(kundenbericht, "pdf_erstellen", lambda md, pdf, titel, ende: gesehen.append(ende - time.monotonic()) or (3, "pdf-werkzeug-fehlt", []))
    for wert, erwartet in (("5", 5), ("1000", 90), ("0", 90), ("-3", 90), ("abc", 90), ("", 90), (None, 90)):
        if wert is None:
            monkeypatch.delenv("SECURITY_AUDIT_KUNDE_BUDGET", raising=False)
        else:
            monkeypatch.setenv("SECURITY_AUDIT_KUNDE_BUDGET", wert)
        gesehen.clear()
        kundenbericht.main(["erstellen", "--json", str(pfad)])
        assert erwartet - 5 < gesehen[0] <= erwartet, (wert, gesehen)


# ------------------------------------------------------------------------------------ Ablage des PDFs

def test_pdf_atomar(tmp_path, monkeypatch, capsys, bericht_pfad):
    """Das PDF entsteht über eine Temp-Datei im Zielordner und `os.replace`; nach einem Fehler bleibt kein Rest."""
    env, _ = attrappen(tmp_path, **beide())
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    monkeypatch.setenv("PATH", env["PATH"])
    ordner = tmp_path / "out"
    ziel = kunde_pfad(bericht_pfad, "pdf")
    original = os.replace
    aufrufe = []

    def replace(quelle, nach, *a, **kw):
        if str(nach).endswith(".pdf"):
            aufrufe.append((quelle, nach, os.path.exists(nach), open(quelle, "rb").read()))
        return original(quelle, nach, *a, **kw)

    monkeypatch.setattr(kundenbericht.os, "replace", replace)
    assert kundenbericht.main(["erstellen", "--json", str(bericht_pfad)]) == 0
    (quelle, nach, gab_es, inh), = aufrufe
    assert nach == ziel and os.path.dirname(quelle) == str(ordner) and quelle != ziel
    assert gab_es is False and inh == PDF_OK.encode()
    assert inhalt(ordner) == [BASIS + "-kunde.md", BASIS + "-kunde.pdf", BASIS + ".json"]
    capsys.readouterr()

    def kaputt(quelle, nach, *a, **kw):
        if str(nach).endswith(".pdf"):
            raise OSError("Platte voll")
        return original(quelle, nach, *a, **kw)

    monkeypatch.setattr(kundenbericht.os, "replace", kaputt)
    assert kundenbericht.main(["erstellen", "--json", str(bericht_pfad)]) == 5
    aus = capsys.readouterr().out.splitlines()
    assert aus[:2] == ["kategorie: eingabe", "kunde-md: " + kunde_pfad(bericht_pfad, "md")]
    assert inhalt(ordner) == [BASIS + "-kunde.md", BASIS + ".json"], "kein PDF, keine Temp-Datei"


def test_pdf_altes_ziel_bleibt_nicht_liegen(tmp_path, bericht_pfad):
    """Scheitert weasyprint, bleibt vom vorigen Lauf nichts liegen (die alten Kundendateien werden vor jedem Lauf entfernt)."""
    ziel = kunde_pfad(bericht_pfad, "pdf")
    open(ziel, "wb").write(b"%PDF-1.7 alt")
    env, _ = attrappen(tmp_path, pandoc={}, weasyprint={"rc": 1})
    assert lauf(bericht_pfad, env=env).returncode == 4
    assert not os.path.exists(ziel)


# ------------------------------------------------------------------------------------ Opt-in: echte Werkzeuge (SECURITY_AUDIT_PDF=1)

nur_echt = pytest.mark.skipif(os.environ.get("SECURITY_AUDIT_PDF") != "1", reason="echte pandoc und weasyprint nur mit SECURITY_AUDIT_PDF=1")


def entpackte_streams(pdf: bytes) -> list[bytes]:
    daten = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        try:
            daten.append(zlib.decompress(m.group(1)))
        except zlib.error:
            continue
    return daten


def seitenzahl(pdf: bytes) -> int:
    """R1-K12: alle Streams per zlib entpacken (Fehler überspringen), dann `/Type /Pages … /Count n` suchen."""
    zahlen = [int(m.group(1)) for d in [pdf, *entpackte_streams(pdf)] for m in re.finditer(rb"/Type\s*/Pages\b.*?/Count\s+(\d+)", d, re.S)]
    return max(zahlen, default=0)


def test_seitenzahl_helfer():
    objekt = zlib.compress(b"<< /Type /Pages /Kids [3 0 R] /Count 4 >>")
    assert seitenzahl(b"%PDF-1.7\n5 0 obj\n<<>>\nstream\n" + objekt + b"\nendstream\nendobj\n") == 4
    assert seitenzahl(b"%PDF-1.7\n<< /Type /Pages /Count 2 >>\n") == 2
    assert seitenzahl(b"%PDF-1.7\nstream\nkein zlib\nendstream\n") == 0


@nur_echt
def test_pdf_echt(tmp_path):
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(1), befund(2, stufe="P3", titel="Zweiter Befund")))
    p = lauf(pfad, env={"SECURITY_AUDIT_OHNE": ""})
    assert p.returncode == 0, p.stdout + p.stderr
    assert zeilen(p) == ["kunde-md: " + kunde_pfad(pfad, "md"), "kunde-pdf: " + kunde_pfad(pfad, "pdf")]
    pdf = open(kunde_pfad(pfad, "pdf"), "rb").read()
    assert pdf.startswith(b"%PDF") and seitenzahl(pdf) >= 1
    assert inhalt(tmp_path / "out") == [BASIS + "-kunde.md", BASIS + "-kunde.pdf", BASIS + ".json"]


@nur_echt
def test_pdf_echt_ohne_dateizugriff(tmp_path):
    """Escapte Ladeversuche im Titel bleiben Text: das PDF entsteht ohne Ladefehler, und /etc/hosts wird nicht gelesen."""
    titel = "Probe url(file:///etc/hosts) und ![x](/etc/hosts) und <img src:file:///etc/hosts>"     # ohne `=`: Titelregel c lässt es sonst nicht durch
    pfad = schreibe(tmp_path / "out", bericht_daten(befund(1, titel=titel)))
    p = lauf(pfad, env={"SECURITY_AUDIT_OHNE": ""})
    assert p.returncode == 0, p.stdout + p.stderr
    assert zeilen(p) == ["kunde-md: " + kunde_pfad(pfad, "md"), "kunde-pdf: " + kunde_pfad(pfad, "pdf")]
    pdf = open(kunde_pfad(pfad, "pdf"), "rb").read()
    assert pdf.startswith(b"%PDF") and seitenzahl(pdf) >= 1
    inhalte = [t for z in open("/etc/hosts", encoding="utf-8", errors="replace").read().splitlines() if not z.lstrip().startswith("#")
               for t in z.split() if "." in t or "::" in t or t == "localhost"]
    assert inhalte, "Erwartung: /etc/hosts hat Einträge"
    pdftotext = shutil.which("pdftotext")
    if pdftotext:
        gelaufen = gitkopie.werkzeug_ausfuehren([pdftotext, kunde_pfad(pfad, "pdf"), "-"], 30, str(tmp_path), {"PATH": os.environ["PATH"]})
        assert gelaufen.rc == 0
        text = "".join(gelaufen.out.decode("utf-8", "replace").split())
        assert "url(file:///etc/hosts)" in text, "der Titel steht als Text im PDF"
        assert not any(t in text for t in inhalte), "Inhalt von /etc/hosts steht nicht im PDF"
    else:
        roh = b"\n".join([pdf, *entpackte_streams(pdf)])
        assert not any(t.encode() in roh for t in inhalte)


@nur_echt
@pytest.mark.parametrize("markdown,meldung", [
    ("![x](file:///etc/hosts)\n", "Tag nicht erlaubt: img"),
    ("[a](http://poc-fremd.invalid/)\n", "Tag nicht erlaubt: a"),
    ("<http://poc-fremd.invalid/>\n", "Tag nicht erlaubt: a"),
    ("Text[^1]\n\n[^1]: http://poc-fremd.invalid/\n", "Tag nicht erlaubt: a"),
])
def test_pdf_echt_schichten_greifen(tmp_path, monkeypatch, markdown, meldung):
    """Feindliches Markdown ohne Escaping direkt an `pdf_erstellen`: die Kette bricht mit Exit 4 ab und schreibt kein PDF.
    Gegenprobe: ohne die Schichten (`--sandbox`, `raw_html` aus, HTML-Prüfung) ergäbe das Exit 0, ein PDF und beim Rendern einen
    Zugriff auf Datei bzw. Host. `poc-fremd.invalid` wird nie aufgelöst, weil die Kette vorher abbricht; es braucht kein Netz."""
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    md, pdf = tmp_path / "feind.md", tmp_path / "feind.pdf"
    md.write_text(markdown, encoding="utf-8")
    code, kategorie, meldungen = kundenbericht.pdf_erstellen(str(md), str(pdf), "Titel", time.monotonic() + 90)
    assert (code, kategorie) == (4, "pdf-fehler") and meldung in meldungen, (code, kategorie, meldungen)
    assert not pdf.exists() and sorted(os.listdir(tmp_path)) == ["feind.md"], "kein PDF und keine Reste"


@nur_echt
@pytest.mark.parametrize("markdown", [
    '<span style="background:url(http://poc-fremd.invalid/)">x</span>\n',
    '<div style="background:url(http://poc-fremd.invalid/)">x</div>\n',
    '`a`{style="background:url(http://poc-fremd.invalid/)"}\n',
    '```{style="background:url(http://poc-fremd.invalid/)"}\nx\n```\n',
    "Text^[Notiz]\n",
])
def test_pdf_echt_erweiterungen_erzeugen_keine_attribute(tmp_path, monkeypatch, markdown):
    """Die Erweiterungsliste (`-native_spans-native_divs-fenced_code_attributes-inline_code_attributes-footnotes-inline_notes`) ist
    die erste Schicht gegen Attribute: pandoc macht aus diesen Konstrukten Text, die HTML-Prüfung findet nichts (Exit 0). Fehlte
    eine der Erweiterungen im Ausschluss, entstünde ein `span`/`div`/`code` mit `style` bzw. ein Link `a`, und die HTML-Prüfung
    ergäbe Exit 4."""
    monkeypatch.setenv("SECURITY_AUDIT_OHNE", "")
    md, pdf = tmp_path / "x.md", tmp_path / "x.pdf"
    md.write_text(markdown, encoding="utf-8")
    assert kundenbericht.pdf_erstellen(str(md), str(pdf), "Titel", time.monotonic() + 90) == (0, None, [])
    assert open(pdf, "rb").read(4) == b"%PDF"
