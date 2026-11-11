"""Tests für kundenbericht.py (TF4, Teil 2a: CLI, Exit-Codes, Eingabe, Prüfung, Ablage, PDF-Stub; Teil 2b: Inhalt des Markdowns, Escaping).

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
    import unicodedata
    zerlegt = unicodedata.normalize("NFD", "unbestätigt")
    md = md_von(befund(status=zerlegt, poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"]))
    assert "### S-1 · " in md and "aus dem Quellcode abgeleitet" in md


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
    assert nachweis(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"]) == "aus dem Quellcode abgeleitet"
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

def zus(md):
    return " ".join(abschnitt(md, "## Management-Zusammenfassung"))


def test_zusammenfassung_singular_plural():
    md1 = md_von(befund(1))
    assert tabelle(md1) == {"Kritisch": 1, "Hoch": 0, "Mittel": 0, "Niedrig": 0}
    assert "Es besteht 1 kritische Schwachstelle" in zus(md1) and "bestehen" not in zus(md1)
    md3 = md_von(befund(1), befund(2), befund(3, stufe="P2"), befund(4, stufe="P2"), befund(5, stufe="P3"),
                 befund(6, stufe="P3"), befund(7, stufe="P3"), befund(8, ohne_anmeldung=False, mandantenuebergreifend=False),
                 befund(9, ohne_anmeldung=False, mandantenuebergreifend=False))
    assert tabelle(md3) == {"Kritisch": 2, "Hoch": 2, "Mittel": 2, "Niedrig": 3}
    z = zus(md3)
    assert "Es bestehen 2 kritische Schwachstellen" in z and "Es bestehen 2 hohe Schwachstellen" in z
    assert "Es bestehen 2 mittlere Schwachstellen" in z and "Es bestehen 3 niedrige Schwachstellen" in z
    z1 = zus(md_von(befund(1, stufe="P3")))
    assert "Es besteht 1 niedrige Schwachstelle" in z1
    assert "Es besteht 1 hohe Schwachstelle" in zus(md_von(befund(1, ohne_anmeldung=False, mandantenuebergreifend=False)))
    assert "Es besteht 1 mittlere Schwachstelle" in zus(md_von(befund(1, stufe="P2")))


def test_zusammenfassung_kritisch_umgehend_beheben():
    assert "umgehend beheben" in zus(md_von(befund(1)))
    assert "umgehend beheben" in zus(md_von(befund(1, status="unbestätigt", poc=None, code_pfad=["a/b.ts:1", "c/d.ts:2"])))
    assert "umgehend" not in zus(md_von(befund(1, stufe="P2")))


def test_zusammenfassung_ausnutzbar_nur_bestaetigt():
    unb = dict(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"])
    z = zus(md_von(befund(1, **unb), befund(2, stufe="P2", **unb)))
    assert "ausnutzbar" not in z
    assert "1 mögliche Schwachstelle der Stufe Kritisch" in z and "1 mögliche Schwachstelle der Stufe Mittel" in z
    z = zus(md_von(befund(1)))
    assert "ausnutzbar" in z and "mögliche Schwachstelle" not in z
    for stufe in ("P2", "P3"):
        assert "ausnutzbar" in zus(md_von(befund(1, stufe=stufe)))
    # gemischter Status in einer Stufe: ein Satz je Status (R1-K11)
    z = zus(md_von(befund(1), befund(2), befund(3, **unb)))
    assert "Es bestehen 2 kritische Schwachstellen" in z and "ausnutzbar" in z
    assert "Es besteht 1 mögliche Schwachstelle der Stufe Kritisch" in z
    assert z.count("umgehend beheben") == 1


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
    ("docker-fehlt", "Nachweis im Test"), ("build-fehler", "Nachweis im Test"), ("build-timeout", "Nachweis im Test"),
    ("start-fehler", "Nachweis im Test"), ("lockfile-fehlt", "Nachweis im Test"), ("lockfile-fremde-quelle", "Nachweis im Test"),
    ("nicht-npm", "Nachweis im Test"),
    ("Zeitbudget von bericht.py kontext erschöpft", "vollständige Laufzeit einzelner Prüfungen"),
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
    for text in ("nur der Teilbereich apps/web", "Suche nach Zugangsschlüsseln", "Abgleich der Abhängigkeiten", "Nachweis im Test",
                 "vollständige Laufzeit einzelner Prüfungen", "Prüfung der KI-Funktionen"):
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
    assert "Die Prüfung war eingeschränkt" not in zus(mit)


# --- Aufbau

def test_abschnittsfolge_und_fuss():
    md = md_von(befund(1), befund(2, stufe="P3"))
    ueberschriften = [x for x in md_zeilen(md) if x.startswith("#") and not x.startswith("###")]
    assert ueberschriften == ["# Manibase · Sicherheitsprüfung Portal", "## Management-Zusammenfassung", "## Befunde", "## Umfang und Grenzen"]
    assert md_zeilen(md).index("## Befunde") < md.splitlines().index("### S-1 · Kritisch · Fremde Bestellungen einsehbar") < md_zeilen(md).index("## Umfang und Grenzen")
    assert md.endswith("\n\nManibase · vertraulich\n") and md.count("Manibase · vertraulich") == 1
    grenzen = "\n".join(abschnitt(md, "## Umfang und Grenzen"))
    for satz in ("Geprüft wurde der oben genannte Commit.", "Code-Analyse durch KI-Agenten", "isolierten Testumgebung ohne Zugriff auf Produktivsysteme",
                 "keine Garantie auf Vollständigkeit", "Der technische Bericht mit Details liegt Manibase vor."):
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
    assert md.startswith("# Manibase · Sicherheitsprüfung ZQX\\_Projekt \\[x\\]\n")
    for zeile in md_zeilen(md):
        assert not zeile.startswith("ZQX"), zeile
        assert not zeile.startswith(("[", "!", "<", "{", ">", "`", "~", "ZQX")), zeile
    assert not re.search(r"(?<![\\])\[[^\]]*\]\(", md.replace("\\[", "")), "kein Link aus Daten"
    assert "<" not in md.replace("\\<", "") and ">" not in md.replace("\\>", "")


# --- Feste Texte

NEUTRAL = "Platzhalter"


def neutral_daten(n=2, **kopf):
    """Berichte über alle Stufen, Singular und Plural, bestätigt und unbestätigt; Datenfelder sind neutrale Platzhalter."""
    unb = dict(status="unbestätigt", poc=None, code_pfad=["src/a.ts:1", "src/b.ts:2"])
    bef = []
    nr = 0
    for stufe, kritisch in (("P1", True), ("P1", False), ("P2", False), ("P3", False)):
        for extra in ({}, unb):
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
        assert bericht.text_verstoesse(md) == [], (anzahl, bericht.text_verstoesse(md))
        for zeile in md_zeilen(md):
            assert not re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\s+/", zeile)
    assert anzahl >= 20
    # Bausteine einzeln: jede Zeile aus allen Fällen auch ohne Markdown-Zeichen geprüft
    texte = {z for d in feste_texte_faelle() for z in md_zeilen(kundenbericht.markdown_erzeugen(d))}
    assert any("Es bestehen 2 kritische Schwachstellen" in t for t in texte)
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
