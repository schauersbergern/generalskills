#!/usr/bin/env python3
"""Tests für agent-stats.py. Aufruf: python3 auto-feature/scripts/test_agent_stats.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

SKRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent-stats.py")


def lauf(*args, home=None, stand=None, skript=SKRIPT):
    env = dict(os.environ)
    if home:
        env["HOME"] = home
    env.pop("CLAUDE_CODE_HOST_SESSION_ID", None)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    env.pop("AGENT_STATS_SKILLS_STAND", None)
    if stand:
        env["AGENT_STATS_SKILLS_STAND"] = stand
    return subprocess.run([sys.executable, "-I", skript, *args], capture_output=True, text=True, env=env)


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.datei = os.path.join(self.d, "stats.md")

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, rolle, tokens, *extra):
        r = lauf("add", self.datei, "--rolle", rolle, "--typ", "opus-xhigh", "--tokens", str(tokens),
                 "--zeit", "2026-10-24 10:00", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def zeilen(self):
        out = {}
        for z in open(self.datei, encoding="utf-8"):
            c = [x.strip() for x in z.strip().strip("|").split("|")]
            if z.startswith("|") and c[0].isdigit():
                out[int(c[0])] = c
        return out


class Fortsetzung(Basis):
    def test_exakter_abgleich_statt_teilstring(self):  # R1-1
        self.add("Fix 1", 1000)
        for i in range(2, 12):
            self.add(f"Agent {i}", 500)
        self.add("Agent 11", 60000, "--fortsetzung-von", "11")
        self.add("Fix 1", 70000, "--fortsetzung-von", "1")
        z = self.zeilen()[13]
        self.assertEqual(z[7], "70000 (kum.)")
        self.assertEqual(z[8], "69000")

    def test_fortsetzung_einer_fortsetzung(self):  # R1-1 Klasse
        self.add("Fix 1", 1000)
        self.add("Fix 1", 2000, "--fortsetzung-von", "1")
        self.add("Fix 1", 3000, "--fortsetzung-von", "2")
        self.add("Fix 1", 4000, "--fortsetzung-von", "1")
        z = self.zeilen()
        self.assertIn("(Forts. #1)", z[3][3])
        self.assertEqual([z[i][8] for i in (2, 3, 4)], ["1000", "1000", "1000"])

    def test_tokens_mit_tausenderpunkt(self):  # R1-16c
        self.add("Review", "254.691")
        self.assertEqual(self.zeilen()[1][8], "254691")

    def test_tokens_unlesbar_bricht_ab(self):  # R1-16c
        r = lauf("add", self.datei, "--rolle", "X", "--typ", "opus-xhigh", "--tokens", "viel")
        self.assertNotEqual(r.returncode, 0)

    def test_pipe_in_rolle(self):  # R1-16b
        self.add("Review a|b", 1000)
        self.add("Review a|b", 3000, "--fortsetzung-von", "1")
        r = lauf("summarize", self.datei)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = open(self.datei, encoding="utf-8").read()
        self.assertIn("a\\|b", text)
        self.assertIn("| 2000 |", text)


class Schreiben(Basis):
    def test_write_laesst_fremden_text_und_datenzeilen_stehen(self):  # R1-2
        self.add("Review R1 Korrektheit", 1000)
        with open(self.datei, "a", encoding="utf-8") as f:
            f.write("\n## Auswertung je Rolle (von Hand)\n\nWanduhr 40 min\n\n"
                    "| 9 | 2026-10-24 11:00 | – | Nachtrag | opus-xhigh | opus | xhigh | 500 | 500 | n/a | n/a"
                    " | – | – | – | – | fertig |\n\n### Lehren\n\nNotiz\n")
        for _ in range(2):
            r = lauf("summarize", self.datei, "--write")
            self.assertEqual(r.returncode, 0, r.stderr)
        text = open(self.datei, encoding="utf-8").read()
        for teil in ("Wanduhr 40 min", "| 9 |", "### Lehren", "Notiz", "(von Hand)"):
            self.assertIn(teil, text)
        self.assertEqual(text.count("<!-- agent-stats:auswertung -->"), 1)

    def test_marker_ohne_ende_bricht_ab(self):  # R2-1
        self.add("A", 1000)
        self.assertEqual(lauf("summarize", self.datei, "--write").returncode, 0)
        text = open(self.datei, encoding="utf-8").read()
        text = text.replace("<!-- /agent-stats:auswertung -->\n", "") + "\n## Notizen\n\nNotiz\n"
        open(self.datei, "w", encoding="utf-8").write(text)
        for _ in range(2):
            r = lauf("summarize", self.datei, "--write")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Marker", r.stderr)
        self.assertEqual(open(self.datei, encoding="utf-8").read(), text)

    def test_add_fuegt_in_agenten_tabelle_ein(self):  # R1-2
        self.add("A", 1000)
        with open(self.datei, "a", encoding="utf-8") as f:
            f.write("\n## Notizen\n\n| 7 | x | – | Nachtrag | opus-xhigh | opus | xhigh | 5 | 5 | n/a | n/a"
                    " | – | – | – | – | fertig |\n")
        self.add("B", 2000)
        zeilen = open(self.datei, encoding="utf-8").read().splitlines()
        b = next(i for i, z in enumerate(zeilen) if "| B |" in z)
        self.assertLess(b, zeilen.index("## Notizen"))
        self.assertTrue(zeilen[b].startswith("| 8 |"))

    def test_leere_vorbereitete_tabelle(self):  # R1-16a
        kopf = ("| # | Zeitpunkt | TF | Rolle | Agent-Typ | Modell | Effort | tokens | Δ tokens | duration_ms"
                " | tool_uses | B/W/K | angenommen | betriebsrelevant | Fix-Runden | Status |")
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write("# Stats\n\n## Agenten\n\n" + kopf + "\n|" + "---|" * 16 + "\n\n## Threads\n")
        self.add("A", 1000)
        text = open(self.datei, encoding="utf-8").read()
        self.assertEqual(text.count("## Agenten"), 1)
        self.assertLess(text.index("| 1 |"), text.index("## Threads"))


class Auswertung(Basis):
    def test_nenner_nur_erhobene_laeufe(self):  # R1-5
        self.add("Review R1 Korrektheit", 100000, "--bwk", "0/1/0", "--betrieb", "1: x")
        self.add("Review R1 Korrektheit", 100000)
        r = lauf("summarize", self.datei)
        self.assertEqual(r.returncode, 0, r.stderr)
        zeile = next(z for z in r.stdout.splitlines() if z.startswith("| Review R1 Korrektheit"))
        self.assertIn("1,00 (1 von 2)", zeile)
        self.assertNotIn("0,50", zeile)

    def test_uebersprungene_zeilen_werden_genannt(self):  # R1-16e
        self.add("A", 1000)
        self.add("B", "n/a")
        r = lauf("summarize", self.datei)
        self.assertIn("#2", r.stderr)

    def test_summarize_all_nennt_dateien_ohne_zeilen(self):  # R1-16e
        root = os.path.join(self.d, "root", "repo")
        os.makedirs(root)
        self.datei = os.path.join(root, "2026-10-24-a.md")
        self.add("A", 1000)
        open(os.path.join(root, "2026-10-24-hand.md"), "w").write("| Rolle | tokens |\n|---|---|\n| A | 5 |\n")
        r = lauf("summarize-all", "--root", os.path.join(self.d, "root"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2026-10-24-hand.md", r.stderr)


class SkillStand(Basis):
    A, B = "generalskills@aaaaaaa (2026-10-24, main)", "generalskills@bbbbbbb (2026-10-25, main)"

    def add_mit(self, stand, rolle="Review R1 Korrektheit", tokens=1000):
        r = lauf("add", self.datei, "--rolle", rolle, "--typ", "opus-xhigh", "--tokens", str(tokens),
                 "--zeit", "2026-10-24 10:00", stand=stand)
        self.assertEqual(r.returncode, 0, r.stderr)

    def text(self):
        with open(self.datei, encoding="utf-8") as f:
            return f.read()

    def kopf(self):
        return [z.strip() for z in self.text().splitlines() if z.startswith("- Skills")]

    def test_neue_datei_stempelt_stand_einmal(self):
        self.add_mit(self.A)
        self.add_mit(self.A)
        self.assertEqual(self.kopf(), [f"- Skills: {self.A}"])

    def test_wechsel_im_lauf_gilt_ab_der_zeile(self):
        self.add_mit(self.A)
        self.add_mit(self.A)
        self.add_mit(self.B)
        self.add_mit(self.B)
        self.assertEqual(self.kopf(), [f"- Skills: {self.A}", f"- Skills ab #3: {self.B}"])

    def test_datei_ohne_stempel_bekommt_ab_zeile(self):
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write("# Alt\n\nRepo x, ohne Stempel.\n\n## Agenten\n\n")
        self.add_mit(self.A)
        self.assertEqual(self.kopf(), [f"- Skills ab #1: {self.A}"])
        self.assertEqual(self.text().splitlines()[2], f"- Skills ab #1: {self.A}")

    def test_summarize_all_trennt_nach_stand(self):
        self.add_mit(self.A, tokens=1000)
        self.add_mit(self.B, tokens=3000)
        alt = os.path.join(self.d, "alt.md")
        with open(alt, "w", encoding="utf-8") as f:  # Datei ohne Stempel
            f.write(self.text().replace("- Skills", "- Notiz"))
        r = lauf("summarize-all", "--root", self.d, "--nach-version")
        self.assertEqual(r.returncode, 0, r.stderr)
        teile = r.stdout.split("### Skills: ")
        self.assertTrue(teile[1].startswith("unbekannt (2 Läufe)"), r.stdout)
        self.assertTrue(teile[2].startswith(f"{self.A} (1 Läufe)") and "| 1.000 |" in teile[2], r.stdout)
        self.assertTrue(teile[3].startswith(f"{self.B} (1 Läufe)") and "| 3.000 |" in teile[3], r.stdout)

    def test_stamp_schreibt_verweigert_und_ersetzt(self):
        self.add_mit(self.A)
        r = lauf("stamp", self.datei, "--stand", self.B)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.kopf(), [f"- Skills: {self.A}"])
        r = lauf("stamp", self.datei, "--stand", self.B, "--hinweis", "nachgetragen", "--ersetzen")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.kopf(), [f"- Skills: {self.B} · nachgetragen"])
        r = lauf("summarize-all", "--root", self.d, "--nach-version")
        self.assertIn(f"### Skills: {self.B} (1 Läufe)", r.stdout)  # Hinweis gehört nicht zum Stand

    def test_stand_aus_dem_git_checkout_des_skripts(self):
        repo = os.path.join(self.d, "generalskills")
        os.makedirs(os.path.join(repo, "auto-feature", "scripts"))
        ziel = os.path.join(repo, "auto-feature", "scripts", "agent-stats.py")
        with open(SKRIPT, encoding="utf-8") as q, open(ziel, "w", encoding="utf-8") as z:
            z.write(q.read())
        g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True).stdout
        g("init", "-q", "-b", "main")
        g("add", ".")
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")
        sha = g("log", "-1", "--format=%h").strip()
        link = os.path.join(self.d, "skills-link")
        os.symlink(os.path.join(repo, "auto-feature"), link)  # wie ~/.claude/skills/auto-feature
        r = lauf("add", self.datei, "--rolle", "Impl T1", "--typ", "sonnet-xhigh", "--tokens", "1",
                 skript=os.path.join(link, "scripts", "agent-stats.py"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(self.kopf()[0], rf"^- Skills: generalskills@{sha} \(\d{{4}}-\d{{2}}-\d{{2}}, main\)$")
        with open(ziel, "a", encoding="utf-8") as z:
            z.write("# lokal geändert\n")
        r = lauf("add", self.datei, "--rolle", "Impl T2", "--typ", "sonnet-xhigh", "--tokens", "1",
                 skript=os.path.join(link, "scripts", "agent-stats.py"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(self.kopf()[1], rf"^- Skills ab #2: generalskills@{sha}-dirty ")


class Threads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.proj = os.path.join(self.home, ".claude", "projects")

    def tearDown(self):
        self.tmp.cleanup()

    def transkript(self, ordner, sid, nachrichten):
        p = os.path.join(self.proj, ordner)
        os.makedirs(p, exist_ok=True)
        with open(os.path.join(p, f"{sid}.jsonl"), "w", encoding="utf-8") as f:
            for i, (modell, usage, stop) in enumerate(nachrichten):
                f.write(json.dumps({"uuid": str(i), "message": {"id": f"m{i}", "model": modell,
                                                                "stop_reason": stop, "usage": usage}}) + "\n")

    def test_cache_write_1h_doppelt_gewichtet(self):  # R1-4
        u = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
             "cache_creation_input_tokens": 1000,
             "cache_creation": {"ephemeral_1h_input_tokens": 1000, "ephemeral_5m_input_tokens": 0}}
        self.transkript("p", "s1", [("claude-opus-5-5", u, "end_turn")])
        r = lauf("threads", "s1", home=self.home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2000", r.stdout.splitlines()[0])
        self.assertIn("opus-5-5", r.stdout.split("Σ")[1])

    def test_synthetic_zaehlt_nicht(self):  # R1-16d
        u = {"input_tokens": 10, "output_tokens": 1}
        self.transkript("p", "s1", [("claude-opus-5-5", u, "end_turn"), ("<synthetic>", {"input_tokens": 0}, None)])
        r = lauf("threads", "s1", home=self.home)
        self.assertEqual(r.stdout.splitlines()[0].split("\t")[2], "1")

    def test_unvollstaendiger_stream_wird_gemeldet(self):  # R1-16f
        self.transkript("p", "s1", [("claude-opus-5-5", {"input_tokens": 10, "output_tokens": 3}, None)])
        r = lauf("threads", "s1", home=self.home)
        self.assertIn("stop_reason", r.stderr)

    def test_laengste_kopie(self):  # R1-6
        u = {"input_tokens": 10, "output_tokens": 1}
        for kurz, lang in (("a", "b"), ("d", "c")):  # beide Reihenfolgen, glob ist unsortiert
            self.transkript(kurz, f"s{kurz}", [("claude-opus-5-5", u, "end_turn")] * 1)
            self.transkript(lang, f"s{kurz}", [("claude-opus-5-5", u, "end_turn")] * 3)
            r = lauf("threads", f"s{kurz}", home=self.home)
            self.assertEqual(r.stdout.splitlines()[0].split("\t")[2], "3")

    def test_fehlende_id_sichtbar_und_exit(self):  # R1-7
        self.transkript("p", "s1", [("claude-opus-5-5", {"input_tokens": 10}, "end_turn")])
        r = lauf("threads", "s1", "fehlt-uuid", "--md", home=self.home)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fehlt-uuid", r.stdout)


if __name__ == "__main__":
    unittest.main()
