#!/usr/bin/env python3
"""Tests für fehlerklassen.py. Aufruf: python3 auto-feature/scripts/test_fehlerklassen.py"""
import os
import subprocess
import sys
import tempfile
import threading
import unittest

SKRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fehlerklassen.py")

KOPF = "# Fehlerklassen-Kandidaten\n\nKopftext.\n\n## Kandidaten\n"

GUT = """## K-? · Token-Prüfung je schreibender Store-Methode getestet
- Beleg: PR #191 R1-2 [P2], `upload-store.ts:705`, 2026-11-06 — release ohne Token-Prüfung blieb 36/36 grün
- Durchgerutscht: Review Focus Plan Nr. 3 nannte nur delete; Härtungsfrage 3 meldete „Token-Semantik getestet“
- Prüfpunkt (auto-feature Review Focus): „Jede Methode, die einen Claim-Token annimmt, bekommt einen Test mit veraltetem Token.“
- Deterministisch: keine, weil die Token-Methoden je Repo anders heißen
- Status: offen
"""


def lauf(*args, eingabe=None):
    return subprocess.run([sys.executable, "-I", SKRIPT, *args], input=eingabe,
                          capture_output=True, text=True)


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.datei = os.path.join(self.tmp.name, "kandidaten.md")
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write(KOPF)

    def tearDown(self):
        self.tmp.cleanup()

    def text(self):
        with open(self.datei, encoding="utf-8") as f:
            return f.read()


class Neu(Basis):
    def test_vergibt_fortlaufende_ids_und_haengt_an(self):
        r1 = lauf("neu", self.datei, eingabe=GUT)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual(r1.stdout.strip(), "K-1")
        r2 = lauf("neu", self.datei, eingabe=GUT.replace("Token-Prüfung", "Upgrade schreibt nichts"))
        self.assertEqual(r2.stdout.strip(), "K-2")
        t = self.text()
        self.assertTrue(t.startswith(KOPF))
        self.assertIn("## K-1 · Token-Prüfung", t)
        self.assertIn("## K-2 · Upgrade schreibt nichts", t)
        self.assertNotIn("K-?", t)

    def test_mehrere_bloecke_in_einer_eingabe(self):
        r = lauf("neu", self.datei, eingabe=GUT + "\n" + GUT.replace("Token", "Lesefehler"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["K-1", "K-2"])

    def test_luecken_und_hoechste_id_zaehlen(self):
        with open(self.datei, "a", encoding="utf-8") as f:
            f.write("\n" + GUT.replace("K-?", "K-7"))
        r = lauf("neu", self.datei, eingabe=GUT)
        self.assertEqual(r.stdout.strip(), "K-8")

    def test_fehlendes_pflichtfeld_wird_abgelehnt_und_nichts_geschrieben(self):
        for feld in ("Beleg", "Durchgerutscht", "Prüfpunkt", "Deterministisch", "Status"):
            kaputt = "\n".join(z for z in GUT.splitlines() if not z.startswith(f"- {feld}"))
            r = lauf("neu", self.datei, eingabe=kaputt)
            self.assertNotEqual(r.returncode, 0, feld)
            self.assertIn(feld, r.stderr)
        self.assertEqual(self.text(), KOPF)

    def test_beleg_ohne_datei_zeile_oder_datum_wird_abgelehnt(self):
        ohne_ort = GUT.replace("`upload-store.ts:705`", "upload-store")
        self.assertNotEqual(lauf("neu", self.datei, eingabe=ohne_ort).returncode, 0)
        ohne_datum = GUT.replace("2026-11-06", "letzte Woche")
        self.assertNotEqual(lauf("neu", self.datei, eingabe=ohne_datum).returncode, 0)
        self.assertEqual(self.text(), KOPF)

    def test_pruefpunkt_braucht_ort_und_wortlaut(self):
        ohne_ort = GUT.replace("- Prüfpunkt (auto-feature Review Focus):", "- Prüfpunkt:")
        self.assertNotEqual(lauf("neu", self.datei, eingabe=ohne_ort).returncode, 0)
        ohne_zitat = GUT.replace("„Jede Methode", "Jede Methode").replace("veraltetem Token.“", "veraltetem Token.")
        self.assertNotEqual(lauf("neu", self.datei, eingabe=ohne_zitat).returncode, 0)

    def test_ort_mit_klammer_im_pruefpunkt(self):
        mit = GUT.replace("(auto-feature Review Focus)", "(auto-feature Härtung Frage 8 (ergänzen))")
        r = lauf("neu", self.datei, eingabe=mit)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_beleg_mit_abschnitt_statt_zeile(self):
        mit = GUT.replace("`upload-store.ts:705`", "`docs/plan.md §1.7`")
        r = lauf("neu", self.datei, eingabe=mit)
        self.assertEqual(r.returncode, 0, r.stderr)
        ohne = GUT.replace("`upload-store.ts:705`", "`docs/plan.md`")
        self.assertNotEqual(lauf("neu", self.datei, eingabe=ohne).returncode, 0)

    def test_status_muss_offen_sein(self):
        r = lauf("neu", self.datei, eingabe=GUT.replace("Status: offen", "Status: übernommen"))
        self.assertNotEqual(r.returncode, 0)

    def test_parallel_keine_doppelten_ids(self):
        ergebnisse = []

        def eins():
            ergebnisse.append(lauf("neu", self.datei, eingabe=GUT).stdout.strip())

        threads = [threading.Thread(target=eins) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(ergebnisse, key=lambda s: int(s[2:])), [f"K-{i}" for i in range(1, 9)])
        self.assertEqual(self.text().count("## K-"), 8)

    def test_vorlage_im_codeblock_des_kopfs_zaehlt_nicht(self):
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write("# Kopf\n\n```\n## K-? · <Klasse>\n## K-5 · Beispiel\n- Status: offen\n```\n\n## Kandidaten\n")
        r = lauf("neu", self.datei, eingabe=GUT)
        self.assertEqual(r.stdout.strip(), "K-1")
        self.assertEqual(lauf("liste", self.datei).stdout.strip().splitlines()[0][:4], "K-1 ")
        self.assertEqual(len(lauf("liste", self.datei).stdout.strip().splitlines()), 1)

    def test_fehlende_datei(self):
        r = lauf("neu", os.path.join(self.tmp.name, "gibtsnicht.md"), eingabe=GUT)
        self.assertNotEqual(r.returncode, 0)


class Liste(Basis):
    def test_eine_zeile_je_kandidat_mit_belegzahl(self):
        lauf("neu", self.datei, eingabe=GUT)
        lauf("neu", self.datei, eingabe=GUT.replace("Token-Prüfung", "Zweite"))
        lauf("beleg", self.datei, "K-1", eingabe="- Beleg: PR #200 R1-1 [P2], `a.ts:3`, 2026-11-10 — wieder\n")
        r = lauf("liste", self.datei)
        self.assertEqual(r.returncode, 0, r.stderr)
        zeilen = r.stdout.strip().splitlines()
        self.assertEqual(len(zeilen), 2)
        self.assertEqual(zeilen[0], "K-1 · offen · Token-Prüfung je schreibender Store-Methode getestet · Belege: 2")
        self.assertTrue(zeilen[1].startswith("K-2 · offen · Zweite"))

    def test_filter_nach_status(self):
        lauf("neu", self.datei, eingabe=GUT)
        lauf("neu", self.datei, eingabe=GUT.replace("Token-Prüfung", "Zweite"))
        lauf("status", self.datei, "K-1", "verworfen", "zu repo-spezifisch")
        r = lauf("liste", self.datei, "--status", "offen")
        self.assertEqual(len(r.stdout.strip().splitlines()), 1)
        self.assertIn("K-2", r.stdout)


class Beleg(Basis):
    def test_beleg_landet_beim_richtigen_kandidaten(self):
        lauf("neu", self.datei, eingabe=GUT)
        lauf("neu", self.datei, eingabe=GUT.replace("Token-Prüfung", "Zweite"))
        r = lauf("beleg", self.datei, "K-1", eingabe="- Beleg: PR #200 R1-1 [P2], `a.ts:3`, 2026-11-10 — wieder\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        t = self.text()
        k1, k2 = t.split("## K-2")
        self.assertIn("PR #200", k1)
        self.assertNotIn("PR #200", k2)
        # neuer Beleg direkt nach dem letzten vorhandenen Beleg
        zeilen = k1.splitlines()
        i = next(n for n, z in enumerate(zeilen) if "PR #200" in z)
        self.assertTrue(zeilen[i - 1].startswith("- Beleg:"))

    def test_beleg_wird_geprueft(self):
        lauf("neu", self.datei, eingabe=GUT)
        r = lauf("beleg", self.datei, "K-1", eingabe="- Beleg: kam wieder vor\n")
        self.assertNotEqual(r.returncode, 0)

    def test_unbekannte_id(self):
        lauf("neu", self.datei, eingabe=GUT)
        r = lauf("beleg", self.datei, "K-9", eingabe="- Beleg: PR #2 R1-1 [P2], `a.ts:3`, 2026-11-10 — x\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("K-9", r.stderr)


class Status(Basis):
    def test_status_setzen_mit_vermerk(self):
        lauf("neu", self.datei, eingabe=GUT)
        r = lauf("status", self.datei, "K-1", "übernommen", "generalskills PR #9, 2026-11-10")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("- Status: übernommen (generalskills PR #9, 2026-11-10)", self.text())
        self.assertNotIn("- Status: offen", self.text())

    def test_verworfen_braucht_grund(self):
        lauf("neu", self.datei, eingabe=GUT)
        r = lauf("status", self.datei, "K-1", "verworfen")
        self.assertNotEqual(r.returncode, 0)

    def test_unbekannter_status(self):
        lauf("neu", self.datei, eingabe=GUT)
        self.assertNotEqual(lauf("status", self.datei, "K-1", "vielleicht", "x").returncode, 0)


if __name__ == "__main__":
    unittest.main()
