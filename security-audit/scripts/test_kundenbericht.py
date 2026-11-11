"""Tests für kundenbericht.py (TF4, Teil 2a: CLI, Exit-Codes, Eingabe, Prüfung, Ablage, PDF-Stub).

Aufruf: python3 -m pytest security-audit/scripts/test_kundenbericht.py -q
Alle Berichte sind synthetisch und liegen in tmp_path. Der Helfer `lauf` setzt standardmäßig SECURITY_AUDIT_OHNE=pandoc,weasyprint:
es läuft nie ein echtes PDF-Werkzeug, und jeder Lauf, der bis zur PDF-Stufe kommt, endet mit Exit 3.
"""
import json
import os
import re
import subprocess
import sys
import time

import pytest

SKRIPTE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SKRIPTE)
import bericht  # noqa: E402
import kundenbericht  # noqa: E402

KUNDENBERICHT = os.path.join(SKRIPTE, "kundenbericht.py")
BASIS = "2026-11-11-abc1234"

POC = ("poc.py anfrage --rolle p1 --methode GET --pfad /api/orders/9 --header 'Authorization: Bearer <TOKEN_A>' "
       "-> 200, Body enthält die Bestellung 9 mit org_id 2 (Organisation B)")
ZUSAMMENFASSUNG = ("Fremde Organisationen können Bestellungen anderer Kunden einsehen. "
                   "Dadurch drohen Datenabfluss und ein Vertrauensverlust.")
MASSNAHME = "Wir empfehlen, die Zugriffsprüfung für Bestellungen zu ergänzen."
VORSPANN = "Wir empfehlen, den Zugriff zu begrenzen. "


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
    """R2-K-10: `dir` im Dateipfad löst nichts aus; der Lauf kommt bis zur PDF-Stufe (Stub: Exit 3)."""
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


# ------------------------------------------------------------------------------------ Schema und Stub

def test_schema_fehler_ausserhalb_kundenfelder_exit5(tmp_path):
    ordner = tmp_path / "out"
    d = bericht_daten()
    d["datum"] = "morgen"
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


def test_stub_exit3_markdown_liegt(tmp_path):
    ordner = tmp_path / "out"
    pfad = schreibe(ordner, bericht_daten())
    p = lauf(pfad)
    assert p.returncode == 3, p.stdout + p.stderr
    assert zeilen(p) == ["kategorie: pdf-werkzeug-fehlt", "kunde-md: " + kunde_pfad(pfad, "md")]
    md = open(kunde_pfad(pfad, "md"), encoding="utf-8").read()
    assert md.startswith("# Manibase · Sicherheitsprüfung Portal\n")
    assert "S-1" in md and "Fremde Bestellungen einsehbar" in md
    assert inhalt(ordner) == [BASIS + "-kunde.md", BASIS + ".json"], "kein PDF, keine Temp-Reste"


def test_pdf_stub_signatur_und_rueckgabe():
    assert kundenbericht.pdf_erstellen("a.md", "a.pdf", "Titel", time.monotonic() + 5) == (3, "pdf-werkzeug-fehlt", [])


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
