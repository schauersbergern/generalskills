"""Tests für gitkopie.py (Sicherheitsgrenze: Arbeitskopie aus rohen Blobs, sichere git-Aufrufe).

Aufruf: python3 -m pytest security-audit/scripts/test_gitkopie.py -q
Alle Repos und Marker liegen in tmp_path; nichts wird außerhalb angelegt.
"""
import os
import shlex
import stat
import subprocess
import sys
import unicodedata

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402

SYMLINK = "120000"
DATEI = "100644"
AUSFUEHRBAR = "100755"
LFS = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"ab" * 32 + b"\nsize 12345\n"


@pytest.fixture(autouse=True)
def sauberes_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in list(os.environ):
        if name.startswith("GIT_") and name not in ("GIT_CONFIG_NOSYSTEM", "GIT_EXEC_PATH"):
            monkeypatch.delenv(name)


def roh(repo, *args, eingabe=None):
    """Test-eigener git-Aufruf (nicht über gitkopie), nur für den Aufbau der Repos."""
    r = subprocess.run(["git", "-C", str(repo), "-c", "core.precomposeunicode=false",
                        "-c", "commit.gpgsign=false", *args],
                       input=eingabe, capture_output=True)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    return r.stdout


def neues_repo(pfad):
    pfad.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(pfad)], check=True)
    return pfad


def bauen(repo, eintraege, nachricht="c"):
    """eintraege: Pfad -> Bytes (Mode 100644) oder (Mode, Bytes). Baut den Index per cacheinfo und committet."""
    for pfad, wert in eintraege.items():
        modus, inhalt = wert if isinstance(wert, tuple) else (DATEI, wert)
        if modus == "160000":
            sha = inhalt.decode()
        else:
            sha = roh(repo, "hash-object", "-w", "--stdin", eingabe=inhalt).decode().strip()
        roh(repo, "update-index", "--add", "--cacheinfo", f"{modus},{sha},{pfad}")
    roh(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", nachricht,
        "--allow-empty")
    roh(repo, "reset", "-q", "--hard")   # Arbeitsbaum passend zum Index herstellen (noch ohne Filter)
    return repo


def repo_mit(tmp_path, eintraege, name="repo"):
    return bauen(neues_repo(tmp_path / name), eintraege)


def kopie(tmp_path, repo, name="ziel"):
    ziel = tmp_path / name
    meldungen = gitkopie.arbeitskopie(str(repo), str(ziel))
    return ziel, meldungen


def alle_dateien(wurzel):
    gefunden = []
    for ordner, ordnernamen, dateien in os.walk(wurzel):
        for n in ordnernamen + dateien:
            gefunden.append(os.path.relpath(os.path.join(ordner, n), wurzel))
    return sorted(gefunden)


def marker_skript(tmp_path, name, rumpf="", marker="MARKER"):
    skript = tmp_path / name
    skript.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(tmp_path / marker))}\n{rumpf}\n")
    skript.chmod(0o755)
    return skript


# ---------------------------------------------------------------- Kopie, Grundverhalten

def test_export_ignore_wird_ignoriert(tmp_path):
    repo = repo_mit(tmp_path, {".gitattributes": b"src/x.js export-ignore\n", "src/x.js": b"x\n"})
    ziel, _ = kopie(tmp_path, repo)
    assert (ziel / "src" / "x.js").read_bytes() == b"x\n"


def test_smudge_filter_laeuft_nicht(tmp_path):
    repo = repo_mit(tmp_path, {".gitattributes": b"*.js filter=pw\n", "src/x.js": b"x\n"})
    smudge = marker_skript(tmp_path, "smudge.sh", "cat")
    roh(repo, "config", "filter.pw.smudge", str(smudge))
    roh(repo, "config", "filter.pw.required", "true")
    # Positivkontrolle: ein normales git checkout würde den Filter starten.
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "x.js").unlink(missing_ok=True)
    roh(repo, "checkout", "--", "src/x.js")
    assert (tmp_path / "MARKER").exists()
    (tmp_path / "MARKER").unlink()
    ziel, _ = kopie(tmp_path, repo)
    assert not (tmp_path / "MARKER").exists()
    assert (ziel / "src" / "x.js").read_bytes() == b"x\n"


def test_arbeitskopie_binaer_identisch(tmp_path):
    repo = repo_mit(tmp_path, {"bin/a.dat": b"\x00\xff\n\x01", "ohne-umbruch.txt": b"abc"})
    ziel, _ = kopie(tmp_path, repo)
    assert (ziel / "bin" / "a.dat").read_bytes() == b"\x00\xff\n\x01"
    assert (ziel / "ohne-umbruch.txt").read_bytes() == b"abc"


def test_arbeitskopie_ausfuehrbar_und_modus(tmp_path):
    repo = repo_mit(tmp_path, {"run.sh": (AUSFUEHRBAR, b"#!/bin/sh\n"), "x.txt": b"x"})
    ziel, _ = kopie(tmp_path, repo)
    assert os.stat(ziel / "run.sh").st_mode & 0o111 == 0o111
    assert os.stat(ziel / "x.txt").st_mode & 0o111 == 0


def test_arbeitskopie_pfad_mit_leerzeichen(tmp_path):
    repo = repo_mit(tmp_path, {"src/ä b.js": b"ok\n"}, name="Kunde Müller GmbH")
    ziel, meldungen = kopie(tmp_path, repo, name="Ziel Ordner")
    assert (ziel / "src" / "ä b.js").read_bytes() == b"ok\n"
    assert meldungen == []


def test_name_mit_doppelpunkt_punkt(tmp_path):
    repo = repo_mit(tmp_path, {"..foo": b"a", "dir/...": b"b", "dir/..bar/x": b"c"})
    ziel, meldungen = kopie(tmp_path, repo)
    assert (ziel / "..foo").read_bytes() == b"a"
    assert (ziel / "dir" / "...").read_bytes() == b"b"
    assert (ziel / "dir" / "..bar" / "x").read_bytes() == b"c"
    assert meldungen == []


def test_env_dateien(tmp_path):
    repo = repo_mit(tmp_path, {".env": b"A=1", ".env.production": b"B=2", "config/.env.local": b"C=3",
                               ".env.example": b"A=", "x/.ENV": b"D=4", "ok.txt": b"ok"})
    ziel, meldungen = kopie(tmp_path, repo)
    assert alle_dateien(ziel) == [".env.example", "ok.txt"]
    for pfad in (".env", ".env.production", "config/.env.local", "x/.ENV"):
        assert any(pfad in m for m in meldungen), pfad


def test_ungetrackte_und_env_des_repos_werden_nie_gelesen(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a"})
    (repo / ".env").write_text("GEHEIM=1")
    (repo / "neu.txt").write_text("ungetrackt")
    ziel, _ = kopie(tmp_path, repo)
    assert alle_dateien(ziel) == ["a.txt"]


def test_arbeitskopie_liest_head_nicht_arbeitsbaum(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"alt\n"})
    (repo / "a.txt").write_text("neu\n")
    ziel, _ = kopie(tmp_path, repo)
    assert (ziel / "a.txt").read_bytes() == b"alt\n"


# ---------------------------------------------------------------- Symlinks

def test_symlinks_nie_angelegt(tmp_path):
    tief = "/".join(f"d{i}" for i in range(20))
    eintraege = {
        "src/a.js": b"console.log(1)\n",
        "abs": (SYMLINK, b"/etc/hosts"),
        "raus": (SYMLINK, b"../../x"),
        "innen": (SYMLINK, b"src/a.js"),
        f"{tief}/x": (SYMLINK, b"../" * 20),            # zeigt lexikalisch genau auf die Wurzel
        f"{tief}/a": (SYMLINK, b"x/" + b"../" * 22 + b"etc/hosts"),
        f"{tief}/b": (SYMLINK, b"x/../../../etc/hosts"),
    }
    repo = repo_mit(tmp_path, eintraege)
    ziel, meldungen = kopie(tmp_path, repo)
    for ordner, ordnernamen, dateien in os.walk(ziel):
        for n in ordnernamen + dateien:
            assert not os.path.islink(os.path.join(ordner, n)), os.path.join(ordner, n)
    # innen -> src/a.js liegt als normale Datei mit dem Inhalt vor
    assert (ziel / "innen").read_bytes() == b"console.log(1)\n"
    assert not os.path.islink(ziel / "innen")
    for pfad, ziel_text in (("abs", "/etc/hosts"), ("raus", "../../x"), (f"{tief}/a", "etc/hosts"),
                            (f"{tief}/x", "../")):
        treffer = [m for m in meldungen if pfad in m and ziel_text in m]
        assert treffer, (pfad, meldungen)
    assert not os.path.exists(ziel / tief / "a")
    assert not os.path.exists(ziel / tief / "b")
    assert not os.path.exists(ziel / "abs")
    assert not os.path.exists(ziel / "raus")


def test_symlink_kette_ueber_andere_symlinks(tmp_path):
    repo = repo_mit(tmp_path, {
        "src/a.js": b"A\n",
        "k1": (SYMLINK, b"k2"),
        "k2": (SYMLINK, b"src/a.js"),
        "src/rel": (SYMLINK, b"../src/./a.js"),
    })
    ziel, _ = kopie(tmp_path, repo)
    assert (ziel / "k1").read_bytes() == b"A\n"
    assert (ziel / "k2").read_bytes() == b"A\n"
    assert (ziel / "src" / "rel").read_bytes() == b"A\n"
    assert not os.path.islink(ziel / "k1")


def test_symlink_kette_zu_tief_oder_zyklus(tmp_path):
    eintraege = {"src/a.js": b"A\n", "z1": (SYMLINK, b"z2"), "z2": (SYMLINK, b"z1")}
    for i in range(9):
        eintraege[f"l{i}"] = (SYMLINK, f"l{i + 1}".encode())
    eintraege["l9"] = (SYMLINK, b"src/a.js")
    repo = repo_mit(tmp_path, eintraege)
    ziel, meldungen = kopie(tmp_path, repo)
    assert not os.path.exists(ziel / "z1")
    assert not os.path.exists(ziel / "l0")        # Tiefe 10 > 8
    assert (ziel / "l5").read_bytes() == b"A\n"   # Tiefe 5 genügt
    assert any("z1" in m for m in meldungen) and any("l0" in m for m in meldungen)


def test_symlink_auf_ordner_oder_ins_leere_wird_gemeldet(tmp_path):
    repo = repo_mit(tmp_path, {"src/a.js": b"A\n", "ordner": (SYMLINK, b"src"),
                               "leer": (SYMLINK, b"gibt-es-nicht")})
    ziel, meldungen = kopie(tmp_path, repo)
    assert not os.path.exists(ziel / "ordner") and not os.path.exists(ziel / "leer")
    assert any("ordner" in m and "src" in m for m in meldungen)
    assert any("leer" in m and "gibt-es-nicht" in m for m in meldungen)


def baum_commit(repo, wurzel_eintraege):
    """Commit mit Baum aus `git mktree` (erlaubt Namen, die update-index ablehnt, z. B. `.git`).
    wurzel_eintraege: Name -> ("blob", Mode, Bytes) | ("tree", {…})."""
    def mk(eintraege):
        zeilen = ""
        for name, wert in eintraege.items():
            if wert[0] == "tree":
                zeilen += f"040000 tree {mk(wert[1])}\t{name}\n"
            else:
                sha = roh(repo, "hash-object", "-w", "--stdin", eingabe=wert[2]).decode().strip()
                zeilen += f"{wert[1]} blob {sha}\t{name}\n"
        return roh(repo, "mktree", eingabe=zeilen.encode()).decode().strip()
    commit = roh(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", mk(wurzel_eintraege),
                 "-m", "x").decode().strip()
    roh(repo, "update-ref", "HEAD", commit)
    return repo


def test_symlink_auf_env_oder_git_wird_nicht_zur_datei(tmp_path):
    repo = baum_commit(neues_repo(tmp_path / "repo"), {
        ".env": ("blob", DATEI, b"GEHEIM=1"),
        "config.txt": ("blob", SYMLINK, b".env"),
        "x": ("tree", {".git": ("tree", {"config": ("blob", DATEI, b"[core]\n")})}),
        "g": ("blob", SYMLINK, b"x/.git/config"),
        "ok.txt": ("blob", DATEI, b"ok"),
    })
    ziel, meldungen = kopie(tmp_path, repo)
    assert alle_dateien(ziel) == ["ok.txt"]
    assert any("config.txt" in m for m in meldungen)
    assert any(m.startswith("Pfad übersprungen") and "x/.git/config" in m for m in meldungen)
    assert any("g" == m.split()[2] for m in meldungen if m.startswith("Symlink übersprungen"))


def test_symlink_ueber_symlink_ordner_wird_nicht_aufgeloest(tmp_path):
    repo = repo_mit(tmp_path, {"a/f": b"F\n", "dir": (SYMLINK, b"a"), "via": (SYMLINK, b"dir/f"),
                               "pop": (SYMLINK, b"dir/../a/f")})
    ziel, meldungen = kopie(tmp_path, repo)
    assert not os.path.exists(ziel / "via")
    assert not os.path.exists(ziel / "pop")
    assert any("via" in m for m in meldungen) and any("pop" in m for m in meldungen)


def test_kein_schreiben_ausserhalb(tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    (aussen / "marker.txt").write_text("unberuehrt")
    repo = repo_mit(tmp_path, {"A": (SYMLINK, str(aussen).encode()), "a/f": b"F\n",
                               "B": (SYMLINK, b"../aussen")})
    vorher = alle_dateien(tmp_path)
    ziel, _ = kopie(tmp_path, repo)
    assert (ziel / "a" / "f").read_bytes() == b"F\n"
    assert alle_dateien(aussen) == ["marker.txt"]
    nachher = set(alle_dateien(tmp_path)) - set(vorher)
    assert all(n == "ziel" or n.startswith("ziel" + os.sep) for n in nachher), nachher


def test_ziel_mit_vorhandenem_symlink_wird_nicht_durchschrieben(tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    ziel = tmp_path / "ziel"
    ziel.mkdir()
    os.symlink(aussen, ziel / "a")
    repo = repo_mit(tmp_path, {"a/f": b"F\n", "b.txt": b"B"})
    meldungen = gitkopie.arbeitskopie(str(repo), str(ziel))
    assert alle_dateien(aussen) == []
    assert (ziel / "b.txt").read_bytes() == b"B"
    assert any("a/f" in m for m in meldungen)


def test_pfade_mit_punkt_punkt_komponente_werden_uebersprungen(tmp_path):
    repo = neues_repo(tmp_path / "repo")
    blob = roh(repo, "hash-object", "-w", "--stdin", eingabe=b"boese").decode().strip()
    ok = roh(repo, "hash-object", "-w", "--stdin", eingabe=b"ok").decode().strip()
    innen = roh(repo, "mktree", eingabe=f"100644 blob {blob}\t..\n100644 blob {ok}\tgut\n".encode()).decode().strip()
    wurzel = roh(repo, "mktree", eingabe=(f"040000 tree {innen}\tsub\n"
                                          f"100644 blob {blob}\t..\n100644 blob {ok}\tok.txt\n").encode()).decode().strip()
    commit = roh(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", wurzel, "-m", "x").decode().strip()
    roh(repo, "update-ref", "HEAD", commit)
    ziel, meldungen = kopie(tmp_path, repo)
    assert (ziel / "ok.txt").read_bytes() == b"ok"
    assert (ziel / "sub" / "gut").read_bytes() == b"ok"
    assert alle_dateien(ziel) == ["ok.txt", "sub", "sub/gut"]
    uebersprungen = [m for m in meldungen if m.startswith("Pfad übersprungen")]
    assert len(uebersprungen) == 2, meldungen
    assert any("sub/.." in m for m in uebersprungen)


# ---------------------------------------------------------------- Namenskollisionen

def test_namenskollision(tmp_path):
    nfc = unicodedata.normalize("NFC", "café.js")
    nfd = unicodedata.normalize("NFD", "café.js")
    assert nfc != nfd
    repo = repo_mit(tmp_path, {"Readme.md": b"1", "README.md": b"2", nfc: b"nfc", nfd: b"nfd",
                               "ok.txt": b"ok"})
    ziel, meldungen = kopie(tmp_path, repo)
    kollisionen = [m for m in meldungen if "Namenskollision" in m]
    assert len(kollisionen) == 2, meldungen
    assert any("Readme.md" in m or "README.md" in m for m in kollisionen)
    assert any("caf" in m for m in kollisionen)
    namen = os.listdir(ziel)
    assert len([n for n in namen if n.casefold() == "readme.md"]) == 1
    assert len([n for n in namen if unicodedata.normalize("NFC", n).casefold().startswith("café")]) == 1
    # erste Datei (in ls-tree-Reihenfolge) geschrieben
    assert (ziel / "README.md").read_bytes() == b"2"
    assert (ziel / "ok.txt").exists()


def test_namenskollision_datei_und_ordner(tmp_path):
    repo = repo_mit(tmp_path, {"A": b"datei", "a/b": b"ordner-inhalt", "c/D": b"1", "C": b"2"})
    ziel, meldungen = kopie(tmp_path, repo)
    kollisionen = [m for m in meldungen if "Namenskollision" in m]
    assert len(kollisionen) == 2, meldungen
    assert any("a/b" in m for m in kollisionen) and any("c/D" in m for m in kollisionen)
    assert alle_dateien(ziel) == ["A", "C"]
    assert (ziel / "A").is_file() and (ziel / "C").is_file()


# ---------------------------------------------------------------- Submodule, LFS

def test_submodul_gemeldet(tmp_path):
    repo = repo_mit(tmp_path, {"lib/sub": ("160000", b"1" * 40), "ok.txt": b"ok"})
    ziel, meldungen = kopie(tmp_path, repo)
    assert any("lib/sub" in m and "Submodul" in m for m in meldungen)
    assert not os.path.exists(ziel / "lib" / "sub")
    assert any("lib/sub" in h and "Submodul" in h for h in gitkopie.repo_hinweise(str(repo)))


def test_lfs_pointer_gemeldet(tmp_path):
    repo = repo_mit(tmp_path, {"assets/big.bin": LFS, "normal.txt": b"hallo"})
    ziel, meldungen = kopie(tmp_path, repo)
    assert any("assets/big.bin" in m and "LFS" in m for m in meldungen)
    assert (ziel / "assets" / "big.bin").read_bytes() == LFS  # Pointer wird kopiert, nur gemeldet
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("assets/big.bin" in h and "LFS" in h for h in hinweise)
    assert not any("normal.txt" in h for h in hinweise)


# ---------------------------------------------------------------- Ausführungsschutz in git()

def test_fsmonitor_laeuft_nicht(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    fsm = marker_skript(tmp_path, "fsm.sh")
    roh(repo, "config", "core.fsmonitor", str(fsm))
    # Positivkontrolle: git status würde den Monitor starten.
    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
    assert (tmp_path / "MARKER").exists()
    (tmp_path / "MARKER").unlink()
    gitkopie.repo_hinweise(str(repo))
    gitkopie.repo_konfiguration(str(repo))
    gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"))
    assert not (tmp_path / "MARKER").exists()


def test_clean_filter_laeuft_nicht(tmp_path):
    repo = repo_mit(tmp_path, {".gitattributes": b"*.js filter=pw\n", "src/x.js": b"aaaa\n"})
    clean = marker_skript(tmp_path, "clean.sh", "cat")
    roh(repo, "config", "filter.pw.clean", str(clean))
    (repo / "src" / "x.js").write_bytes(b"bbbb\n")      # gleiche Größe, anderer Inhalt
    # Positivkontrolle: git status würde den Clean-Filter starten.
    subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
    assert (tmp_path / "MARKER").exists()
    (tmp_path / "MARKER").unlink()
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("src/x.js" in h for h in hinweise), hinweise
    assert not (tmp_path / "MARKER").exists()


def test_geerbte_git_umgebung(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    fsm = marker_skript(tmp_path, "fsm.sh")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(fsm))
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", str(tmp_path / "hooks"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.fsmonitor={fsm}'")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "gibt-es-nicht"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "nirgends"))
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", str(fsm))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "fremder-index"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "alt"))
    # Kontrolle: die geerbte Umgebung greift bei einem ungeschützten git-Aufruf
    r = subprocess.run(["git", "-C", str(repo), "status"], capture_output=True)
    assert r.returncode != 0 or (tmp_path / "MARKER").exists()
    if (tmp_path / "MARKER").exists():
        (tmp_path / "MARKER").unlink()
    gitkopie.repo_hinweise(str(repo))
    ziel, _ = kopie(tmp_path, repo)
    assert not (tmp_path / "MARKER").exists()
    assert (ziel / "a.txt").read_bytes() == b"a\n"
    assert gitkopie.git(str(repo), "rev-parse", "--show-toplevel").stdout.strip()


def test_git_wirft_giterror_und_liefert_bytes(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    r = gitkopie.git(str(repo), "cat-file", "-p", "HEAD:a.txt")
    assert r.stdout == b"a\n"
    r = gitkopie.git(str(repo), "hash-object", "--stdin", eingabe=b"a\n")
    assert len(r.stdout.strip()) in (40, 64)
    with pytest.raises(gitkopie.GitFehler):
        gitkopie.git(str(repo), "cat-file", "-p", "HEAD:gibt-es-nicht")
    with pytest.raises(gitkopie.GitFehler):
        gitkopie.git(str(tmp_path / "kein-repo"), "status")


def test_git_setzt_sicherheitsoptionen(tmp_path, monkeypatch):
    """Die Aufrufform selbst: -c-Optionen und Umgebung (über einen Shim-git im PATH)."""
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    protokoll = tmp_path / "protokoll.txt"
    shim = shim_dir / "git"
    shim.write_text(f"#!/bin/sh\n{{ echo \"ARGS: $*\"; env | grep '^GIT_' | sort; }} > {shlex.quote(str(protokoll))}\n")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("GIT_ASKPASS", "boese")
    monkeypatch.setenv("GIT_SSH_COMMAND", "boese")
    monkeypatch.setenv("GIT_EXEC_PATH", "/opt/git-exec")
    gitkopie.git(str(tmp_path), "rev-parse", "HEAD")
    text = protokoll.read_text()
    assert "core.fsmonitor=false" in text and "core.hooksPath=/dev/null" in text
    assert "GIT_OPTIONAL_LOCKS=0" in text and "GIT_TERMINAL_PROMPT=0" in text and "GIT_NO_LAZY_FETCH=1" in text
    assert "GIT_EXEC_PATH=/opt/git-exec" in text
    assert "boese" not in text


# ---------------------------------------------------------------- repo_konfiguration

def test_repo_konfiguration(tmp_path):
    repo = repo_mit(tmp_path, {
        ".mcp.json": b"{}",
        ".claude/settings.json": b'{"env":{"PYTHONPATH":"tools"}}',
        ".claude/settings.local.json": b"{}",
        "apps/web/.claude/skills/x/SKILL.md": b"# x",
        "apps/web/.claude/agents/a.md": b"a",
        "pkg/.claude/commands/c.md": b"c",
        "pkg/sub/.mcp.json": b"{}",
        ".claude/CLAUDE.md": b"# nur Doku",
        "docs/settings.json": b"{}",
        "README.md": b"hi",
    })
    (repo / "ungetrackt").mkdir()
    (repo / "ungetrackt" / ".mcp.json").write_text("{}")
    (repo / "apps" / "web" / ".mcp.json").write_text("{}")   # ungetrackt
    gefunden = gitkopie.repo_konfiguration(str(repo))
    assert sorted(gefunden) == sorted([
        ".mcp.json", ".claude/settings.json", ".claude/settings.local.json",
        "apps/web/.claude/skills/x/SKILL.md", "apps/web/.claude/agents/a.md",
        "pkg/.claude/commands/c.md", "pkg/sub/.mcp.json"])


def test_repo_konfiguration_leer(tmp_path):
    repo = repo_mit(tmp_path, {"README.md": b"hi"})
    assert gitkopie.repo_konfiguration(str(repo)) == []


def test_repo_konfiguration_gross_klein(tmp_path):
    repo = repo_mit(tmp_path, {".Claude/Settings.JSON": b"{}", ".MCP.json": b"{}"})
    assert len(gitkopie.repo_konfiguration(str(repo))) == 2


# ---------------------------------------------------------------- repo_hinweise

def test_repo_hinweise_uncommittet(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"alt\n", "b.txt": b"b\n"})
    assert gitkopie.repo_hinweise(str(repo)) == []
    (repo / "a.txt").write_bytes(b"neu\n")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert len(hinweise) == 1 and "a.txt" in hinweise[0]


def test_repo_hinweise_geloescht_und_typ_geaendert(tmp_path):
    repo = repo_mit(tmp_path, {"weg.txt": b"x", "wird-link.txt": b"y", "bleibt.txt": b"z"})
    (repo / "weg.txt").unlink()
    (repo / "wird-link.txt").unlink()
    os.symlink("/dev/zero", repo / "wird-link.txt")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("weg.txt" in h and "elöscht" in h for h in hinweise), hinweise
    assert any("wird-link.txt" in h for h in hinweise), hinweise
    assert not any("bleibt.txt" in h for h in hinweise)


def test_repo_hinweise_fifo_haengt_nicht(tmp_path):
    repo = repo_mit(tmp_path, {"f.txt": b"x"})
    (repo / "f.txt").unlink()
    os.mkfifo(repo / "f.txt")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("f.txt" in h for h in hinweise)


def test_repo_hinweise_symlink_im_arbeitsbaum_wird_nicht_gefolgt(tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    (aussen / "f").write_text("fremd")
    repo = repo_mit(tmp_path, {"d/f": b"fremd"})
    import shutil
    shutil.rmtree(repo / "d")
    os.symlink(aussen, repo / "d")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("d/f" in h for h in hinweise), hinweise


def test_repo_hinweise_unveraenderter_symlink_ohne_hinweis_aber_mit_ziel(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a", "link": (SYMLINK, b"a.txt"), "abs": (SYMLINK, b"/etc/hosts")})
    assert os.path.islink(repo / "link") and os.path.islink(repo / "abs")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Symlink" in h and "link" in h and "a.txt" in h for h in hinweise)
    assert any("Symlink" in h and "abs" in h and "/etc/hosts" in h for h in hinweise)
    assert not any("ändert" in h or "elöscht" in h for h in hinweise)


def test_repo_hinweise_gestagte_aenderung(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"alt\n", "b.txt": b"b\n", "c.txt": b"c\n"})
    (repo / "a.txt").write_bytes(b"neu\n")
    roh(repo, "add", "a.txt")
    (repo / "neu.txt").write_bytes(b"n\n")
    roh(repo, "add", "neu.txt")
    roh(repo, "rm", "-q", "--cached", "c.txt")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("a.txt" in h for h in hinweise)
    assert any("neu.txt" in h for h in hinweise)
    assert any("c.txt" in h for h in hinweise)
    assert not any("b.txt" in h for h in hinweise)


def test_repo_hinweise_namenskollision(tmp_path):
    repo = repo_mit(tmp_path, {"Readme.md": b"1", "README.md": b"2"})
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Namenskollision" in h and "README.md" in h and "Readme.md" in h for h in hinweise)


def test_repo_hinweise_ohne_head_ist_kein_abbruch(tmp_path):
    repo = neues_repo(tmp_path / "leer")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert hinweise and all(isinstance(h, str) for h in hinweise)


def test_arbeitskopie_ohne_head_wirft_giterror(tmp_path):
    repo = neues_repo(tmp_path / "leer")
    with pytest.raises(gitkopie.GitFehler):
        gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"))
