#!/usr/bin/env python3
"""Tests für agent-stats.py. Aufruf: python3 auto-feature/scripts/test_agent_stats.py"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SKRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent-stats.py")


def lauf(*args, home=None, stand=None, skript=SKRIPT, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
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

    def checkout(self):
        """Skript in einem echten git-Checkout hinter einem Symlink; liefert (repo, skript-pfad, sha)."""
        repo = os.path.join(self.d, "generalskills")
        os.makedirs(os.path.join(repo, "auto-feature", "scripts"))
        ziel = os.path.join(repo, "auto-feature", "scripts", "agent-stats.py")
        with open(SKRIPT, encoding="utf-8") as q, open(ziel, "w", encoding="utf-8") as z:
            z.write(q.read())
        g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True).stdout
        g("init", "-q", "-b", "main")
        g("add", ".")
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")
        link = os.path.join(self.d, "skills-link")
        os.symlink(os.path.join(repo, "auto-feature"), link)  # wie ~/.claude/skills/auto-feature
        return repo, os.path.join(link, "scripts", "agent-stats.py"), g("log", "-1", "--format=%h").strip()

    def fake_git(self, koerper):
        """Verzeichnis mit einem `git`, das vor dem echten im PATH liegt; $@ steht als Argumente bereit."""
        echt = shutil.which("git")
        bin_ = os.path.join(self.d, "fakebin")
        os.makedirs(bin_, exist_ok=True)
        pfad = os.path.join(bin_, "git")
        with open(pfad, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\n{koerper}\nexec "{echt}" "$@"\n')
        os.chmod(pfad, 0o755)
        return {"PATH": bin_ + os.pathsep + os.environ["PATH"]}

    def add_skript(self, skript, rolle, **kw):
        return lauf("add", self.datei, "--rolle", rolle, "--typ", "sonnet-xhigh", "--tokens", "1",
                    "--zeit", "2026-10-24 10:00", skript=skript, **kw)

    def test_stand_aus_dem_git_checkout_des_skripts(self):
        repo, skript, sha = self.checkout()
        r = self.add_skript(skript, "Impl T1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(self.kopf()[0], rf"^- Skills: generalskills@{sha} \(\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}, main\)$")
        with open(os.path.join(repo, "neu.txt"), "w", encoding="utf-8") as f:  # unversioniert: kein -dirty  # R1-4
            f.write("x\n")
        self.assertEqual(self.add_skript(skript, "Impl T2").returncode, 0)
        self.assertEqual(len(self.kopf()), 1, self.text())
        with open(os.path.join(repo, "auto-feature", "scripts", "agent-stats.py"), "a", encoding="utf-8") as z:
            z.write("# lokal geändert\n")
        r = self.add_skript(skript, "Impl T3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(self.kopf()[1], rf"^- Skills ab #3: generalskills@{sha}-dirty ")

    def test_scheiternder_git_aufruf_stempelt_keinen_teilstand(self):  # R1-2 a, b
        _, skript, _ = self.checkout()
        for befehl in ("rev-parse", "log", "status"):
            with self.subTest(befehl=befehl):
                if os.path.exists(self.datei):
                    os.remove(self.datei)
                env = self.fake_git(f'for a in "$@"; do [ "$a" = {befehl} ] && exit 128; done')
                r = self.add_skript(skript, "Impl T1", env_extra=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("nicht ermittelbar", r.stderr)
                self.assertEqual(self.kopf(), [], self.text())

    def test_stand_unbekannt_nach_bekanntem_schreibt_ab_zeile(self):  # R1-2 c
        _, skript, _ = self.checkout()
        self.assertEqual(self.add_skript(skript, "Impl T1", stand=self.A).returncode, 0)
        env = self.fake_git('[ "$1" = "-C" ] && exit 128')
        self.assertEqual(self.add_skript(skript, "Impl T2", env_extra=env).returncode, 0)
        self.assertEqual(self.add_skript(skript, "Impl T3", env_extra=env).returncode, 0)  # bleibt eine Zeile
        self.assertEqual(self.kopf(), [f"- Skills: {self.A}", "- Skills ab #2: unbekannt"])
        r = lauf("summarize-all", "--root", self.d, "--nach-version")
        self.assertIn("### Skills: unbekannt (2 Läufe)", r.stdout)
        self.assertIn(f"### Skills: {self.A} (1 Läufe)", r.stdout)

    def test_nach_timeout_kein_weiterer_git_aufruf(self):  # R1-2 Klasse
        _, skript, _ = self.checkout()
        log = os.path.join(self.d, "git.log")
        env = self.fake_git(f'echo "$@" >> "{log}"; exec sleep 5')
        env["AGENT_STATS_GIT_TIMEOUT"] = "1"
        t0 = time.monotonic()
        r = self.add_skript(skript, "Impl T1", env_extra=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.monotonic() - t0, 4)
        self.assertEqual(len(open(log, encoding="utf-8").read().splitlines()), 1)
        self.assertEqual(self.kopf(), [])

    def test_hang_bei_spaeterem_aufruf_liefert_keinen_teilstand(self):  # R2-1
        _, skript, _ = self.checkout()
        for befehl, aufrufe in (("remote", 5), ("status", 3)):
            with self.subTest(befehl=befehl):
                if os.path.exists(self.datei):
                    os.remove(self.datei)
                log = os.path.join(self.d, f"git-{befehl}.log")
                env = self.fake_git(f'echo "$@" >> "{log}"; for a in "$@"; do [ "$a" = {befehl} ] && exec sleep 5; done')
                env["AGENT_STATS_GIT_TIMEOUT"] = "1"
                r = self.add_skript(skript, "Impl T1", env_extra=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.kopf(), [], self.text())  # kein Teilstand mit Ordnernamen als Repo
                with open(log, encoding="utf-8") as f:
                    gerufen = f.read().splitlines()
                self.assertEqual(len(gerufen), aufrufe, gerufen)  # der hängende Aufruf war der letzte
                self.assertIn(befehl, gerufen[-1])

    def test_gleicher_stand_mit_und_ohne_uhrzeit_ist_kein_wechsel(self):  # R2-2
        alt = "generalskills@aaaaaaa (2026-10-24, main)"
        neu = "generalskills@aaaaaaa (2026-10-24 10:00, main)"
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write(f"# Alt\n\n- Skills: {alt} · nachgetragen\n\n## Agenten\n\n")
        self.add_mit(neu)
        self.assertEqual(self.kopf(), [f"- Skills: {alt} · nachgetragen"])
        self.add_mit("generalskills@aaaaaaa-dirty (2026-10-24 10:00, main)")  # -dirty und Branch zählen
        self.add_mit("generalskills@aaaaaaa-dirty (2026-10-24 10:00, andere)")
        self.assertEqual(len(self.kopf()), 3, self.text())

    def test_sortierung_nach_commit_zeit_nicht_alphabetisch(self):  # R1-3
        staende = ["generalskills@9999999 (2026-10-20, main)",            # älter, aber alphabetisch zuletzt
                   "generalskills@1111111 (2026-10-24 14:08, main)",
                   "generalskills@5555555 (2026-10-24 09:00, main)"]      # selber Tag, früher
        for st in staende:
            self.add_mit(st)
        r = lauf("summarize-all", "--root", self.d, "--nach-version")
        self.assertEqual(r.returncode, 0, r.stderr)
        reihe = [m for m in re.findall(r"### Skills: generalskills@(\w+)", r.stdout)]
        self.assertEqual(reihe, ["9999999", "5555555", "1111111"], r.stdout)


class Stempel(Basis):
    S = "generalskills@aaaaaaa (2026-10-24 10:00, main)"

    def stamp(self, inhalt):
        with open(self.datei, "w", encoding="utf-8") as f:
            f.write(inhalt)
        r = lauf("stamp", self.datei, "--stand", self.S)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.datei, encoding="utf-8") as f:
            return f.read().splitlines()

    def test_datei_die_mit_tabelle_beginnt(self):  # R1-1
        tabelle = ["| Thread | Modell |", "| --- | --- |", "| a | opus |"]
        z = self.stamp("\n".join(tabelle) + "\n")
        self.assertEqual(z, [f"- Skills: {self.S}", ""] + tabelle)

    def test_verschachtelte_kopfliste(self):  # R1-1 Klasse
        z = self.stamp("# T\n\n- Runden:\n  - R1 x\n  - R2 y\n\n## Threads\n")
        self.assertEqual(z, ["# T", "", "- Runden:", "  - R1 x", "  - R2 y", f"- Skills: {self.S}", "",
                             "## Threads"])

    def test_kopf_ohne_leerzeile_vor_fliesstext(self):  # R1-1 Klasse
        z = self.stamp("# T\n- Repo: x\nFließtext\n")
        self.assertEqual(z, ["# T", "- Repo: x", f"- Skills: {self.S}", "", "Fließtext"])

    def test_titel_ohne_liste_bekommt_eigenen_kopf(self):  # R1-1 Klasse
        self.assertEqual(self.stamp("# T\nFließtext\n"), ["# T", "", f"- Skills: {self.S}", "", "Fließtext"])
        self.assertEqual(self.stamp(""), [f"- Skills: {self.S}"])


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


class Import(Basis):
    """import liest fertige Subagenten aus den Transkripten, bewerte trägt Urteile gebündelt nach."""

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.d, "home")
        self.sub = os.path.join(self.home, ".claude", "projects", "p", "s1", "subagents")
        os.makedirs(self.sub)
        open(os.path.join(self.home, ".claude", "projects", "p", "s1.jsonl"), "w").close()

    def agent(self, aid, beschr, typ="sonnet-xhigh", fertig=True, aufrufe=None, coordinator=0, nach=(),
              synthetic=False, still=False, meta_extra=None, stop="end_turn"):
        """nach: Fortsetzungen (Zeit der Nachricht, Zeit der Antwort, usage, Werkzeuge); still: Transkript
        seit Stunden unverändert; synthetic: lokale <synthetic>-Nachricht am Ende."""
        with open(os.path.join(self.sub, f"agent-{aid}.meta.json"), "w", encoding="utf-8") as f:
            json.dump({"agentType": typ, "description": beschr, "model": "sonnet", "finished": fertig,
                       **(meta_extra or {})}, f)
        aufrufe = aufrufe or [("2026-11-10T10:00:00Z", {"input_tokens": 2, "cache_read_input_tokens": 1000,
                                                          "cache_creation_input_tokens": 98, "output_tokens": 50}, 2)]
        with open(os.path.join(self.sub, f"agent-{aid}.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "user", "timestamp": aufrufe[0][0], "message": {"content": "Auftrag"}}) + "\n")
            for i, (ts, u, werkzeuge) in enumerate(aufrufe):
                inhalt = [{"type": "tool_use", "id": f"{aid}-{i}-{k}"} for k in range(werkzeuge)]
                # gestreamt: dieselbe Message-ID steht zweimal im Transkript
                for _ in range(2):
                    f.write(json.dumps({"type": "assistant", "timestamp": ts, "message": {
                        "id": f"{aid}-m{i}", "model": "claude-sonnet-5-5", "usage": u, "content": inhalt,
                        "stop_reason": stop}}) + "\n")
            for k in range(coordinator):
                f.write(json.dumps({"type": "user", "timestamp": aufrufe[-1][0], "isMeta": True,
                                    "origin": {"kind": "coordinator"}, "message": {"content": "Fix"}}) + "\n")
            for k, (t_msg, t_antwort, u, werkzeuge) in enumerate(nach):
                f.write(json.dumps({"type": "user", "timestamp": t_msg, "isMeta": True,
                                    "origin": {"kind": "coordinator"}, "message": {"content": "Fix"}}) + "\n")
                f.write(json.dumps({"type": "assistant", "timestamp": t_antwort, "message": {
                    "id": f"{aid}-n{k}", "model": "claude-sonnet-5-5", "usage": u, "stop_reason": "end_turn",
                    "content": [{"type": "tool_use", "id": f"{aid}-n{k}-{j}"} for j in range(werkzeuge)]}}) + "\n")
            if synthetic:
                f.write(json.dumps({"type": "assistant", "timestamp": aufrufe[-1][0], "message": {
                    "id": f"{aid}-syn", "model": "<synthetic>", "stop_reason": "stop_sequence",
                    "usage": {"input_tokens": 0, "output_tokens": 0}, "content": []}}) + "\n")
        if still:
            alt = time.time() - 3 * 3600
            os.utime(os.path.join(self.sub, f"agent-{aid}.jsonl"), (alt, alt))

    def importiere(self, *extra, stand="gs@abc (2026-11-12 10:00, main)"):
        r = lauf("import", self.datei, "s1", "--kopf", "Repo: x", *extra, home=self.home, stand=stand)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def test_zeile_aus_transkript(self):
        self.agent("a1", "TF2 Spec-Review R1", typ="opus-xhigh", coordinator=1, aufrufe=[
            ("2026-11-10T10:00:00Z", {"input_tokens": 1, "cache_read_input_tokens": 500, "output_tokens": 9}, 1),
            ("2026-11-10T10:05:00Z", {"input_tokens": 2, "cache_read_input_tokens": 1000,
                                      "cache_creation_input_tokens": 98, "output_tokens": 50}, 2)])
        self.importiere()
        z = self.zeilen()[1]
        self.assertEqual(z[2:7], ["TF2", "Spec-Review R1", "opus-xhigh", "opus", "xhigh"])
        self.assertEqual(z[7:11], ["1150", "1150", "300000", "3"])  # letzter Aufruf, Dauer, 3 Werkzeuge
        self.assertEqual(z[14], "1")  # eine Fortsetzung per SendMessage
        self.assertIn("- Repo: x", open(self.datei, encoding="utf-8").read())

    def test_praefix_pr_und_ohne(self):
        self.agent("a1", "PR12 Review R1 Tests")
        self.agent("a2", "freie Beschreibung")
        self.importiere()
        z = self.zeilen()
        self.assertEqual({(z[i][2], z[i][3]) for i in z}, {("12", "Review R1 Tests"), ("–", "freie Beschreibung")})

    def test_pausen_zaehlen_nicht_zur_dauer(self):  # R1-3
        u = {"input_tokens": 1, "output_tokens": 1}
        self.agent("a1", "TF1 Impl T1", aufrufe=[("2026-11-10T10:00:00Z", u, 0), ("2026-11-10T10:01:00Z", u, 0),
                                                 ("2026-11-10T13:00:00Z", u, 0)])
        self.importiere()
        self.assertEqual(self.zeilen()[1][9], "60000")  # 3 h Pause fällt weg, wird nicht auf 10 min gekappt

    def test_wartezeit_auf_fortsetzung_zaehlt_nicht(self):  # R1-3
        u = {"input_tokens": 1, "output_tokens": 1}
        self.agent("a1", "TF1 Impl T1", aufrufe=[("2026-11-10T10:00:00Z", u, 0), ("2026-11-10T10:01:00Z", u, 0)],
                   nach=[("2026-11-10T10:08:00Z", "2026-11-10T10:09:00Z", u, 0)])
        self.importiere()
        self.assertEqual(self.zeilen()[1][9], "120000")  # 60 s + 60 s, nicht 9 min

    def test_fortsetzung_nach_dem_import_aktualisiert_die_zeile(self):  # R1-1
        self.agent("a1", "TF2 Impl T1", aufrufe=[("2026-11-10T10:00:00Z", {"input_tokens": 10, "output_tokens": 1000}, 1)])
        self.agent("a2", "TF2 Task-Review T1")
        self.importiere()
        eingabe = json.dumps({"nr": 1, "bwk": "0/1/0", "angenommen": 1})
        subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=eingabe, text=True)
        self.assertEqual(self.zeilen()[1][7:11], ["1010", "1010", "0", "1"])
        self.agent("a1", "TF2 Impl T1", aufrufe=[("2026-11-10T10:00:00Z", {"input_tokens": 10, "output_tokens": 1000}, 1)],
                   nach=[("2026-11-10T10:30:00Z", "2026-11-10T10:31:00Z",
                          {"input_tokens": 10, "cache_read_input_tokens": 49000, "output_tokens": 1000}, 7)])
        r = self.importiere()
        self.assertIn("#1 aktualisiert", r.stdout)
        z = self.zeilen()
        self.assertEqual(len(z), 2)  # keine neue Zeile
        self.assertEqual(z[1][7:11], ["50010", "50010", "60000", "8"])
        self.assertEqual(z[1][11:13], ["0/1/0", "1"])  # Urteile bleiben
        self.assertEqual(z[1][14], "1")  # Fix-Runden aus der Fortsetzung
        self.assertIn("Nichts Neues", self.importiere().stdout)  # danach wieder stabil

    def test_filter_tf_trennt_dateien_einer_session(self):  # R1-2
        self.agent("a1", "PR12 Review R1 Korrektheit")
        self.agent("a2", "PR13 Review R1 Korrektheit")
        self.agent("a3", "FF Builder-Check")
        self.importiere("--tf", "PR12")
        self.assertEqual([z[2] for z in self.zeilen().values()], ["12"])
        datei2 = self.datei
        self.datei = os.path.join(self.d, "pr13.md")
        self.importiere("--tf", "13")
        self.assertEqual([z[2] for z in self.zeilen().values()], ["13"])
        self.datei = datei2
        self.importiere("--tf", "TF9", "--tf", "ff")  # mehrfach; Groß/Klein egal; TF9 gibt es nicht
        self.assertEqual(sorted(z[2] for z in self.zeilen().values()), ["12", "FF"])

    def test_abgebrochener_agent_wird_als_abgebrochen_eingetragen(self):  # R1-4
        self.agent("a1", "TF1 Härtung", fertig=False, still=True, stop="tool_use")
        self.agent("a2", "TF1 Task-Review T1", fertig=False, still=True)  # regulär beendet, nur ohne finished
        self.agent("a3", "TF1 Impl T2", fertig=False)  # läuft (Transkript frisch)
        r = self.importiere()
        self.assertIn("1 Subagenten noch nicht fertig", r.stderr)
        z = self.zeilen()
        self.assertEqual([(z[i][3], z[i][15]) for i in sorted(z)], [("Härtung", "abgebrochen"), ("Task-Review T1", "fertig")])
        self.assertNotIn("noch nicht fertig", self.importiere().stderr.replace("1 Subagenten noch nicht fertig", ""))

    def test_verschachtelte_agenten_werden_uebersprungen(self):  # R1-4
        self.agent("a1", "TF1 Impl T1")
        self.agent("a2", "TF1 Sucher", fertig=False, still=True, meta_extra={"spawnDepth": 2, "parentAgentId": "a1"})
        r = self.importiere()
        self.assertIn("1 verschachtelte Subagenten übersprungen", r.stderr)
        self.assertEqual([z[3] for z in self.zeilen().values()], ["Impl T1"])

    def test_zeilenumbruch_in_description_zerreisst_die_tabelle_nicht(self):  # R1-5
        self.agent("a1", "TF1 Impl T1\nzweite Zeile\u2028dritte")
        self.agent("a2", "TF1 Task-Review T1")
        self.importiere()
        self.assertEqual([z[3] for z in self.zeilen().values()], ["Impl T1 zweite Zeile dritte", "Task-Review T1"])
        eingabe = json.dumps({"nr": 1, "betrieb": "2: Leck\nAbsturz\r\nAus"})
        r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=eingabe,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.zeilen()[1][13], "2: Leck Absturz Aus")
        self.assertEqual(lauf("summarize", self.datei).returncode, 0)

    def test_stand_wechsel_beim_import_steht_in_der_datei(self):  # R1-7a
        self.add("Eval fixture-web", 1000, "--tf", "x")
        # add schreibt ohne Stand nichts; Stand per Stempel, dann Import unter neuem Stand
        lauf("stamp", self.datei, "--stand", "gs@alt (2026-11-01 10:00, main)", home=self.home)
        self.agent("a1", "TF1 Impl T1")
        self.importiere(stand="gs@neu (2026-11-12 10:00, main)")
        text = open(self.datei, encoding="utf-8").read()
        self.assertIn("- Skills ab #2: gs@neu", text)
        self.agent("a2", "TF1 Impl T2")
        self.importiere(stand="gs@neu (2026-11-12 11:00, main)")  # gleicher Kern: kein weiterer Eintrag
        self.assertEqual(open(self.datei, encoding="utf-8").read().count("- Skills ab #"), 1)

    def test_import_nach_summarize_write_landet_in_der_tabelle(self):  # R1-7b
        self.agent("a1", "TF1 Impl T1")
        self.importiere()
        self.assertEqual(lauf("summarize", self.datei, "--write").returncode, 0)
        self.agent("a2", "TF1 Task-Review T1")
        self.importiere()
        zeilen = open(self.datei, encoding="utf-8").read().splitlines()
        marke = next(i for i, z in enumerate(zeilen) if "agent-stats:auswertung" in z)
        zeile2 = next(i for i, z in enumerate(zeilen) if z.startswith("| 2 |"))
        self.assertLess(zeile2, marke)

    def test_synthetic_nachricht_verfaelscht_tokens_nicht(self):  # R1-7c
        self.agent("a1", "TF1 Impl T1", synthetic=True)
        self.importiere()
        self.assertEqual(self.zeilen()[1][7], "1150")

    def test_idempotent_und_unfertige_spaeter(self):
        self.agent("a1", "TF1 Impl T1")
        self.agent("a2", "TF1 Task-Review T1", fertig=False)
        r = self.importiere()
        self.assertIn("1 Subagenten noch nicht fertig", r.stderr)
        self.assertEqual(len(self.zeilen()), 1)
        self.agent("a2", "TF1 Task-Review T1")
        self.importiere()
        r = self.importiere()
        self.assertIn("Nichts Neues", r.stdout)
        self.assertEqual([z[3] for z in self.zeilen().values()], ["Impl T1", "Task-Review T1"])

    def test_haengt_an_add_zeilen_an(self):
        self.add("Eval fixture-web", 1000)
        self.agent("a1", "TF1 Impl T1")
        self.importiere()
        self.assertEqual(sorted(self.zeilen()), [1, 2])

    def test_fertig_ohne_stop_reason_bei_reiner_textantwort(self):  # R1-4 (Runde 2)
        u = {"input_tokens": 1, "output_tokens": 1}
        self.agent("a1", "TF1 Impl T1", fertig=False, still=True, stop=None,
                   aufrufe=[("2026-11-10T10:00:00Z", u, 2), ("2026-11-10T10:01:00Z", u, 0)])  # letzte Antwort nur Text
        self.agent("a2", "TF1 Impl T2", fertig=False, still=True, stop=None,
                   aufrufe=[("2026-11-10T10:00:00Z", u, 2)])  # endet mit tool_use: abgebrochen
        self.importiere()
        z = self.zeilen()
        self.assertEqual([(z[i][3], z[i][15]) for i in sorted(z)], [("Impl T1", "fertig"), ("Impl T2", "abgebrochen")])

    def test_rueckwaerts_laufende_zeitstempel_zaehlen_einmal(self):  # R2-1
        u = {"input_tokens": 1, "output_tokens": 1}
        self.agent("a1", "TF1 Impl T1", aufrufe=[("2026-11-10T10:00:00Z", u, 0), ("2026-11-10T10:00:10Z", u, 0),
                                                 ("2026-11-10T10:00:20Z", u, 0)])
        pfad = os.path.join(self.sub, "agent-a1.jsonl")
        zeilen = open(pfad, encoding="utf-8").read().splitlines()
        zeilen.insert(5, json.dumps({"type": "attachment", "timestamp": "2026-11-10T10:00:07Z"}))  # vor dem Eintrag davor
        open(pfad, "w", encoding="utf-8").write("\n".join(zeilen) + "\n")
        self.importiere()
        self.assertEqual(self.zeilen()[1][9], "20000")

    def test_tf_filter_praefix_variationen_und_hinweis(self):  # R2-2
        self.agent("a1", "TF2: Spec-Review R1")
        self.agent("a2", "tf2 Plan-Review R1")
        self.agent("a3", "Freitext ohne Präfix")
        r = self.importiere("--tf", "TF2")
        z = self.zeilen()
        self.assertEqual(sorted((z[i][2], z[i][3]) for i in z), [("TF2", "Plan-Review R1"), ("TF2", "Spec-Review R1")])
        self.assertIn("1 Agenten ohne erkanntes Präfix", r.stderr)
        self.assertIn("Freitext ohne Präfix", r.stderr)

    def test_import_ueberschreibt_keine_fix_runden_von_hand(self):  # R2-3
        self.agent("a1", "TF2 Impl T1")
        self.importiere()
        r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei],
                           input=json.dumps({"nr": 1, "fix_runden": "2"}), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)  # Spalte führt der Import, nicht bewerte
        self.assertIn("unbekannte Felder", r.stderr)
        self.agent("a1", "TF2 Impl T1", nach=[("2026-11-10T10:30:00Z", "2026-11-10T10:31:00Z", {"input_tokens": 5, "output_tokens": 5}, 0)])
        self.importiere()
        self.assertEqual(self.zeilen()[1][14], "1")

    def test_update_ueberschreibt_fremde_zeile_nicht(self):  # R2-4
        self.agent("a1", "TF1 Impl T1")
        self.agent("a2", "TF1 Impl T2")
        self.importiere()
        text = open(self.datei, encoding="utf-8").read()
        zeilen = text.splitlines()
        i = next(k for k, z in enumerate(zeilen) if z.startswith("| 2 |"))
        del zeilen[i]  # letzte Zeile von Hand gelöscht, Marker bleibt
        open(self.datei, "w", encoding="utf-8").write("\n".join(zeilen) + "\n")
        self.agent("a3", "TF1 Impl T3")
        self.importiere()
        self.assertEqual(sorted(self.zeilen()), [1, 3])  # #2 wird nicht neu vergeben (a3 → #3)
        z = open(self.datei, encoding="utf-8").read().replace("| Impl T1 |", "| Fremde Rolle |")
        open(self.datei, "w", encoding="utf-8").write(z)
        self.agent("a1", "TF1 Impl T1", nach=[("2026-11-10T10:30:00Z", "2026-11-10T10:31:00Z", {"input_tokens": 5, "output_tokens": 5}, 0)])
        self.importiere()
        z = self.zeilen()
        self.assertEqual(z[1][3], "Fremde Rolle")  # nicht überschrieben
        self.assertEqual(z[1][14], "–")
        self.assertEqual(sorted(z), [1, 3, 4])
        self.assertEqual(z[4][3], "Impl T1")  # stattdessen neue Zeile

    def test_alter_marker_mit_nackter_id_bleibt_uebersprungen(self):  # Hinweis Runde 2
        self.agent("a1", "TF1 Impl T1")
        self.importiere()
        text = open(self.datei, encoding="utf-8").read()
        text = re.sub(r"<!-- agent-stats:importiert .*? -->", "<!-- agent-stats:importiert a1 -->", text)
        open(self.datei, "w", encoding="utf-8").write(text)
        self.agent("a1", "TF1 Impl T1", nach=[("2026-11-10T10:30:00Z", "2026-11-10T10:31:00Z", {"input_tokens": 5, "output_tokens": 5}, 0)])
        self.assertIn("Nichts Neues", self.importiere().stdout)

    def test_bewerte_gebuendelt(self):
        self.agent("a1", "TF2 Spec-Review R1", typ="opus-xhigh")
        self.agent("a2", "TF3 Spec-Review R1", typ="opus-xhigh")
        self.importiere()
        eingabe = "\n".join([json.dumps({"tf": "TF2", "rolle": "Spec-Review R1", "bwk": "1/2/3",
                                         "angenommen": 3, "betrieb": "1: Leck | Pfad"}),
                             json.dumps({"nr": 2, "bwk": "0/0/1"})])
        r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=eingabe,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        z = self.zeilen()
        self.assertEqual(z[1][11:13], ["1/2/3", "3"])
        self.assertIn("| 1: Leck \\| Pfad |", open(self.datei, encoding="utf-8").read())  # Strich maskiert
        self.assertEqual(z[2][11], "0/0/1")
        r = lauf("summarize", self.datei)
        self.assertIn("| Spec-Review | opus-xhigh | 2 |", r.stdout)
        self.assertIn("1/2/4", r.stdout)

    def test_bewerte_mehrdeutig_schreibt_nichts(self):
        self.agent("a1", "TF2 Spec-Review R1")
        self.agent("a2", "TF3 Spec-Review R1")
        self.importiere()
        vorher = open(self.datei, encoding="utf-8").read()
        eingabe = json.dumps({"nr": 1, "bwk": "0/0/1"}) + "\n" + json.dumps({"rolle": "Spec-Review R1", "bwk": "1/1/1"})
        r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=eingabe,
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("2 passende Zeilen", r.stderr)
        self.assertEqual(open(self.datei, encoding="utf-8").read(), vorher)

    def test_bewerte_nr_widerspricht_rolle_schreibt_nichts(self):  # R1-14
        self.agent("a1", "TF2 Spec-Review R1")
        self.agent("a2", "TF3 Spec-Review R1")
        self.importiere()
        vorher = open(self.datei, encoding="utf-8").read()
        for falsch in ({"nr": 1, "rolle": "Spec-Review R1", "tf": "TF3", "bwk": "1/1/1"},
                       {"nr": 1, "rolle": "Plan-Review R1", "bwk": "1/1/1"}):
            r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=json.dumps(falsch),
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("passt nicht", r.stderr)
            self.assertEqual(open(self.datei, encoding="utf-8").read(), vorher)

    def test_bewerte_tf_pr_schreibweise(self):  # R1-12b
        self.agent("a1", "PR12 Review R1 Korrektheit")
        self.importiere()
        eingabe = json.dumps({"tf": "PR12", "rolle": "Review R1 Korrektheit", "bwk": "0/1/0"})
        r = subprocess.run([sys.executable, "-I", SKRIPT, "bewerte", self.datei], input=eingabe,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.zeilen()[1][11], "0/1/0")


if __name__ == "__main__":
    unittest.main()
