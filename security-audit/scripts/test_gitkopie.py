"""Tests für gitkopie.py (Sicherheitsgrenze: Arbeitskopie aus rohen Blobs, sichere git-Aufrufe).

Aufruf: python3 -m pytest security-audit/scripts/test_gitkopie.py -q
Alle Repos und Marker liegen in tmp_path; nichts wird außerhalb angelegt.
"""
import os
import shlex
import shutil
import stat
import subprocess
import sys
import time
import unicodedata

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitkopie  # noqa: E402

SYMLINK = "120000"
DATEI = "100644"
AUSFUEHRBAR = "100755"
LFS = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"ab" * 32 + b"\nsize 12345\n"


@pytest.fixture(autouse=True)
def ohne_frist():
    gitkopie.frist_setzen(None)
    yield
    gitkopie.frist_setzen(None)


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


def neues_repo(pfad, *optionen):
    pfad.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", *optionen, str(pfad)], check=True)
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
    """Commit mit Baum aus `git mktree -z` (erlaubt Namen, die update-index ablehnt, z. B. `.git`, Newline).
    wurzel_eintraege: Name -> ("blob", Mode, Bytes) | ("tree", {…}). Der Arbeitsbaum bleibt leer."""
    def mk(eintraege):
        zeilen = b""
        for name, wert in eintraege.items():
            if wert[0] == "tree":
                zeilen += f"040000 tree {mk(wert[1])}\t{name}".encode() + b"\0"
            else:
                sha = roh(repo, "hash-object", "-w", "--stdin", eingabe=wert[2]).decode().strip()
                zeilen += f"{wert[1]} blob {sha}\t{name}".encode() + b"\0"
        return roh(repo, "mktree", "-z", eingabe=zeilen).decode().strip()
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


# ---------------------------------------------------------------- Aufrufform von git() (Shim im PATH)

ERLAUBTE_GIT_VARIABLEN = {"GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT", "GIT_NO_LAZY_FETCH", "GIT_EXEC_PATH"}
GEERBT = {"GIT_CONFIG_PARAMETERS": "'core.fsmonitor=boese'", "GIT_CONFIG_COUNT": "1",
          "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "boese", "GIT_EXTERNAL_DIFF": "boese",
          "GIT_INDEX_FILE": "boese-index", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "boese-alt",
          "GIT_DIR": "boese-dir", "GIT_WORK_TREE": "boese-wt", "GIT_ASKPASS": "boese",
          "GIT_SSH_COMMAND": "boese", "GIT_CONFIG_GLOBAL": "boese", "GIT_NAMESPACE": "boese"}


def shim_git(tmp_path, monkeypatch, durchreichen=True, vorab=""):
    """Legt ein `git`-Shim in den PATH. Es protokolliert Argumente und GIT_*-Umgebung je Aufruf und
    reicht dann an das echte git durch (oder beendet sich ohne es). `vorab` läuft vor dem Durchreichen."""
    ordner = tmp_path / "shim"
    ohne_shim = os.pathsep.join(d for d in os.environ["PATH"].split(os.pathsep) if d != str(ordner))
    echtes = shutil.which("git", path=ohne_shim)      # nie ein früher installiertes Shim als "echtes" git
    ordner.mkdir(exist_ok=True)
    log = tmp_path / "git-protokoll.txt"
    ende = f'exec {shlex.quote(echtes)} "$@"' if durchreichen else "exit 0"
    skript = ordner / "git"
    skript.write_text(f"#!/bin/sh\n{{ echo \"ARGS: $*\"; env | grep '^GIT_' | sort; echo '--'; }} >> "
                      f"{shlex.quote(str(log))}\n{vorab}\n{ende}\n")
    skript.chmod(0o755)
    monkeypatch.setenv("PATH", f"{ordner}{os.pathsep}{ohne_shim}")
    return log


def protokoll(log):
    """Liste von (argumentzeile, {variablenname: wert}) je git-Aufruf."""
    aufrufe = []
    for block in log.read_text().split("--\n"):
        zeilen = [z for z in block.splitlines() if z]
        if not zeilen:
            continue
        assert zeilen[0].startswith("ARGS: ")
        umgebung = dict(z.split("=", 1) for z in zeilen[1:])
        aufrufe.append((zeilen[0], umgebung))
    return aufrufe


def pruefe_aufrufe(aufrufe):
    assert aufrufe
    for args, umgebung in aufrufe:
        assert "-c core.fsmonitor=false -c core.hooksPath=/dev/null" in args, args
        assert set(umgebung) <= ERLAUBTE_GIT_VARIABLEN, (args, sorted(umgebung))
        assert umgebung["GIT_OPTIONAL_LOCKS"] == "0"
        assert umgebung["GIT_TERMINAL_PROMPT"] == "0"
        assert umgebung["GIT_NO_LAZY_FETCH"] == "1"


def test_git_setzt_sicherheitsoptionen(tmp_path, monkeypatch):
    log = shim_git(tmp_path, monkeypatch, durchreichen=False)
    for name, wert in GEERBT.items():
        monkeypatch.setenv(name, wert)
    monkeypatch.setenv("GIT_EXEC_PATH", "/opt/git-exec")
    gitkopie.git(str(tmp_path), "rev-parse", "HEAD")
    aufrufe = protokoll(log)
    assert len(aufrufe) == 1
    pruefe_aufrufe(aufrufe)
    assert aufrufe[0][1]["GIT_EXEC_PATH"] == "/opt/git-exec"
    assert "rev-parse HEAD" in aufrufe[0][0]


def test_alle_git_aufrufe_der_funktionen_sind_gesichert(tmp_path, monkeypatch):
    """Auch der cat-file-Batch-Prozess (eigenes Popen) und alle Aufrufe von repo_hinweise/repo_konfiguration."""
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "l": (SYMLINK, b"a.txt"), "p.bin": LFS})
    (repo / "a.txt").write_bytes(b"x\n")
    log = shim_git(tmp_path, monkeypatch)
    for name, wert in GEERBT.items():
        if name not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_GLOBAL"):   # würden auch das echte git stören
            monkeypatch.setenv(name, wert)
    gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"))
    gitkopie.repo_hinweise(str(repo))
    gitkopie.repo_konfiguration(str(repo))
    aufrufe = protokoll(log)
    pruefe_aufrufe(aufrufe)
    befehle = " | ".join(a for a, _ in aufrufe)
    for erwartet in ("cat-file --batch", "ls-tree", "ls-files", "rev-parse --show-object-format"):
        assert erwartet in befehle, erwartet


# ---------------------------------------------------------------- Fehlerpfade von git()

def test_git_timeout_wird_giterror(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a"})
    shim_git(tmp_path, monkeypatch, durchreichen=False, vorab="exec sleep 10")
    with pytest.raises(gitkopie.GitFehler, match="Timeout"):
        gitkopie.git(str(repo), "status", timeout=1)


def test_git_exit_ungleich_null_traegt_returncode_und_stderr(tmp_path, monkeypatch):
    shim_git(tmp_path, monkeypatch, durchreichen=False, vorab="echo boom >&2; exit 1")
    with pytest.raises(gitkopie.GitFehler) as info:
        gitkopie.git(str(tmp_path), "status")
    assert info.value.returncode == 1
    assert b"boom" in info.value.stderr and "boom" in str(info.value)


def test_git_nicht_startbar_wird_giterror(tmp_path, monkeypatch):
    leer = tmp_path / "leer"
    leer.mkdir()
    monkeypatch.setenv("PATH", str(leer))
    with pytest.raises(gitkopie.GitFehler, match="nicht startbar"):
        gitkopie.git(str(tmp_path), "status")


@pytest.mark.parametrize("scheitert, erwartet", [
    ("ls-tree", "Kein HEAD lesbar"),
    ("cat-file", "Symlinks und LFS-Pointern nicht möglich"),
    ("ls-files", "Index nicht lesbar"),
    ("--show-object-format", "Objektformat nicht ermittelbar"),       # rev-parse --verify (Commit) darf klappen
])
def test_repo_hinweise_git_fehler_werden_hinweise(tmp_path, monkeypatch, scheitert, erwartet):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "l": (SYMLINK, b"a.txt")})
    shim_git(tmp_path, monkeypatch, vorab='case " $* " in *" $SHIM_FAIL "*) echo kaputt >&2; exit 1;; esac')
    monkeypatch.setenv("SHIM_FAIL", scheitert)
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any(erwartet in h for h in hinweise), hinweise


# ---------------------------------------------------------------- Fehlerpfade des Batch-Prozesses

def test_batch_muellantwort_und_abgeschnitten_sind_meldungen(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "b.txt": b"b\n"})
    vorab = {
        "muell": 'case " $* " in *" cat-file "*) read x; echo garbage; cat >/dev/null; exit 0;; esac',
        "abgeschnitten": 'case " $* " in *" cat-file "*) read x; printf "%s blob 10\\n" "$x"; printf abc; exit 0;; esac',
    }
    for name, skript in vorab.items():
        shim_git(tmp_path, monkeypatch, vorab=skript)
        meldungen = gitkopie.arbeitskopie(str(repo), str(tmp_path / f"ziel-{name}"))
        assert any("Arbeitskopie unvollständig" in m for m in meldungen), (name, meldungen)
        assert alle_dateien(tmp_path / f"ziel-{name}") == []   # nichts aus einem unzuverlässigen Strom geschrieben


@pytest.mark.parametrize("groesse", ["xyz", "-1", "1e3", "", "0x10"])
def test_batch_ungueltige_groesse_ist_giterror_haertung_a3(tmp_path, monkeypatch, groesse):
    """Antwort `<sha> blob <nicht-Zahl>`: GitFehler statt ValueError (die Aufrufer fangen nur GitFehler)."""
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "l": (SYMLINK, b"a.txt")})
    shim_git(tmp_path, monkeypatch, vorab='case " $* " in *" cat-file "*) read x; '
             f'echo "$x blob {groesse}"; cat >/dev/null; exit 0;; esac')
    with gitkopie._Batch(str(repo)) as batch, pytest.raises(gitkopie.GitFehler, match="unerwartete Antwort"):
        batch.lies("0" * 40)
    meldungen = gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"))
    assert any("Arbeitskopie unvollständig" in m for m in meldungen), meldungen
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Symlinks und LFS-Pointern nicht möglich" in h for h in hinweise), hinweise


@pytest.mark.parametrize("groesse", ["999999999999999", "1000000000000000", "99999999999999999999999", "9" * 5000])
def test_batch_absurde_groesse_ist_giterror_ohne_speicherfehler_haertung_a3(tmp_path, monkeypatch, groesse):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    shim_git(tmp_path, monkeypatch, vorab='case " $* " in *" cat-file "*) read x; '
             f'echo "$x blob {groesse}"; printf abc; exit 0;; esac')
    with gitkopie._Batch(str(repo)) as batch, pytest.raises(gitkopie.GitFehler, match="abgeschnitten|unerwartete Antwort"):
        batch.lies("0" * 40)


def test_fehlendes_objekt_wird_gemeldet(tmp_path):
    repo = repo_mit(tmp_path, {"src/a.js": b"einmalig-a\n", "ln": (SYMLINK, b"src/a.js"), "ok.txt": b"ok\n"})
    sha = roh(repo, "rev-parse", "HEAD:src/a.js").decode().strip()
    os.unlink(repo / ".git" / "objects" / sha[:2] / sha[2:])
    ziel, meldungen = kopie(tmp_path, repo)
    assert any(m.startswith("Objekt fehlt") and "src/a.js" in m for m in meldungen), meldungen
    assert any("ln" in m and "Ziel-Objekt fehlt" in m for m in meldungen), meldungen
    assert alle_dateien(ziel) == ["ok.txt"]


# ---------------------------------------------------------------- Schreiben ins Ziel

def test_vorhandene_dateien_und_blatt_symlinks_im_ziel_werden_nicht_durchschrieben(tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    (aussen / "x").write_text("unberuehrt")
    ziel = tmp_path / "ziel"
    ziel.mkdir()
    os.symlink(aussen / "x", ziel / "f")              # Blatt-Symlink auf vorhandene Datei
    os.symlink(aussen / "neu", ziel / "d")            # hängender Blatt-Symlink
    (ziel / "g").write_text("vorhanden")              # vorhandene normale Datei
    repo = repo_mit(tmp_path, {"f": b"neu", "d": b"neu", "g": b"neu2", "h": b"h"})
    meldungen = gitkopie.arbeitskopie(str(repo), str(ziel))
    assert (aussen / "x").read_text() == "unberuehrt"
    assert not (aussen / "neu").exists()
    assert os.path.islink(ziel / "f") and os.path.islink(ziel / "d")
    assert (ziel / "g").read_text() == "vorhanden"
    assert (ziel / "h").read_bytes() == b"h"
    for pfad in ("f", "d", "g"):
        assert any(m.startswith(f"Schreiben fehlgeschlagen: {pfad} ") for m in meldungen), (pfad, meldungen)


# ---------------------------------------------------------------- Symlink-Randfälle

def test_symlink_randfaelle_werden_abgelehnt(tmp_path):
    repo = repo_mit(tmp_path, {
        "src/a.js": b"A\n",
        "abs2": (SYMLINK, b"/src/a.js"),                # absolut, obwohl relativ im Baum vorhanden
        "top": (SYMLINK, b"../src/a.js"),               # am Wurzelrand
        "d/e": (SYMLINK, b"../../src/a.js"),
        "lnk": (SYMLINK, b"nope/../src/a.js"),          # Zwischenkomponente existiert nicht
        "ok": (SYMLINK, b"src/../src/a.js"),            # Kontrolle: gültig
    })
    ziel, meldungen = kopie(tmp_path, repo)
    for abgelehnt, grund in (("abs2", "absolutes Ziel"), ("top", "verlässt das Repo"),
                             ("d/e", "verlässt das Repo"), ("lnk", "existiert nicht")):
        assert not os.path.lexists(ziel / abgelehnt), abgelehnt
        assert any(m.startswith(f"Symlink übersprungen: {abgelehnt} ") and grund in m for m in meldungen), \
            (abgelehnt, meldungen)
    assert (ziel / "ok").read_bytes() == b"A\n"


def test_symlink_kettengrenze_exakt(tmp_path):
    eintraege = {"src/a.js": b"A\n"}
    for i in range(7):
        eintraege[f"c{i}"] = (SYMLINK, f"c{i + 1}".encode())
    eintraege["c7"] = (SYMLINK, b"src/a.js")           # c0: 8 Symlinks
    for i in range(8):
        eintraege[f"d{i}"] = (SYMLINK, f"d{i + 1}".encode())
    eintraege["d8"] = (SYMLINK, b"src/a.js")           # d0: 9 Symlinks
    repo = repo_mit(tmp_path, eintraege)
    ziel, meldungen = kopie(tmp_path, repo)
    assert (ziel / "c0").read_bytes() == b"A\n"
    assert (ziel / "d1").read_bytes() == b"A\n"        # 8 Symlinks
    assert not os.path.lexists(ziel / "d0")
    assert any(m.startswith("Symlink übersprungen: d0 ") and "tiefer als 8" in m for m in meldungen)


def test_symlink_blob_groesse_grenze(tmp_path):
    repo = baum_commit(neues_repo(tmp_path / "repo"), {
        "src": ("tree", {"a.js": ("blob", DATEI, b"A\n")}),
        "lang": ("blob", SYMLINK, b"x" * 4097),
        "grenze": ("blob", SYMLINK, b"x" * 4096),
        "kette": ("blob", SYMLINK, b"lang"),
    })
    ziel, meldungen = kopie(tmp_path, repo)
    lang = [m for m in meldungen if m.startswith("Symlink übersprungen: lang ")]
    assert len(lang) == 1 and "zu lang" in lang[0] and "xxxx" not in lang[0]
    grenze = [m for m in meldungen if m.startswith("Symlink übersprungen: grenze ")]
    assert len(grenze) == 1 and "zu lang" not in grenze[0] and "nicht im HEAD-Baum" in grenze[0]
    kette = [m for m in meldungen if m.startswith("Symlink übersprungen: kette ")]
    assert len(kette) == 1 and "zu lang" in kette[0]
    assert any("Symlink: lang" in h and "zu lang" in h and "xxxx" not in h
               for h in gitkopie.repo_hinweise(str(repo)))


# ---------------------------------------------------------------- .git-Sperre, Kollision Ordner/Datei

def test_git_komponenten_werden_gesperrt(tmp_path):
    datei = ("tree", {"x": ("blob", DATEI, b"boese")})
    repo = baum_commit(neues_repo(tmp_path / "repo"), {
        ".GIT": datei, ".g​it": datei, "GIT~1": datei, ".gitignore": ("blob", DATEI, b"ok"),
        "ok.txt": ("blob", DATEI, b"ok"),
    })
    ziel, meldungen = kopie(tmp_path, repo)
    assert alle_dateien(ziel) == [".gitignore", "ok.txt"]
    gesperrt = [m for m in meldungen if m.startswith("Pfad übersprungen") and "Komponente .git" in m]
    assert len(gesperrt) == 3, meldungen
    assert any(".GIT/x" in m for m in gesperrt) and any("GIT~1/x" in m for m in gesperrt)
    assert any("\\u200b" in m for m in gesperrt)       # Zero-Width-Space sichtbar escaped


def test_namenskollision_ordner_zuerst_dann_datei(tmp_path):
    repo = baum_commit(neues_repo(tmp_path / "repo"), {
        "B": ("tree", {"x": ("blob", DATEI, b"1")}), "b": ("blob", DATEI, b"2")})
    ziel, meldungen = kopie(tmp_path, repo)
    assert alle_dateien(ziel) == ["B", "B/x"]
    assert any(m.startswith("Namenskollision: b ") and "kollidiert mit B;" in m for m in meldungen)


# ---------------------------------------------------------------- Meldungen entschärfen

UNSICHTBARE_ZEICHEN = [
    "\ufe00", "\ufe0f", "\U000e0100", "\U000e01ef",      # Variation Selectors
    "\u034f", "\u180b", "\u180c", "\u180d", "\u180f", "\u17b4", "\u17b5",   # CGJ, Mongolisch, Khmer
    "\u115f", "\u1160", "\u3164", "\uffa0", "\u2800",  # Hangul-/Braille-Füller
    "\u2028", "\u2029", "\u0378", "\U0010ffff",          # Zeilentrenner, nicht zugewiesen (Cn)
]


@pytest.mark.parametrize("zeichen", UNSICHTBARE_ZEICHEN)
def test_t_escaped_alle_unsichtbaren_zeichen_haertung_a2(zeichen):
    aus = gitkopie._t(f"a{zeichen}b")
    assert zeichen not in aus and aus.startswith("a\\") and aus.endswith("b"), ascii(aus)


def test_unsichtbar_ist_die_gemeinsame_funktion_von_poc_haertung_a2():
    import poc
    assert poc._unsichtbar is gitkopie.unsichtbar


def test_t_laesst_normalen_text_haertung_a2():
    assert gitkopie._t("Grüße, 世界 é\u0301 😀 .env") == "Grüße, 世界 é\u0301 😀 .env"


def test_t_escaped_und_kappt():
    assert gitkopie._t("a\nb\r\tc") == "a\\nb\\r\\tc"
    assert gitkopie._t("\x1b[31mrot") == "\\x1b[31mrot"
    assert gitkopie._t("‮​ ") == "\\u202e\\u200b\\u2028"
    assert gitkopie._t(os.fsdecode(b"\xff")) == "\\xff"
    assert gitkopie._t("ä b.js") == "ä b.js"
    kurz = gitkopie._t("a" * 301)
    assert kurz == "a" * 300 + "…"
    assert gitkopie._t("a" * 300) == "a" * 300


def test_meldungen_sind_einzeilig_ohne_steuerzeichen(tmp_path):
    boese_name = ".env\n\x1b[31mROT‮"
    lang = ".env" + "a" * 400
    repo = baum_commit(neues_repo(tmp_path / "repo"), {
        boese_name: ("blob", DATEI, b"x"),
        lang: ("blob", DATEI, b"x"),
        "l\nink": ("blob", SYMLINK, b"ziel\n\x1b[31m"),
        "ok.txt": ("blob", DATEI, b"ok"),
    })
    ziel, meldungen = kopie(tmp_path, repo)
    hinweise = gitkopie.repo_hinweise(str(repo))
    for text in meldungen + hinweise:
        assert "\n" not in text and "\x1b" not in text and "‮" not in text, repr(text)
    assert any("\\n\\x1b[31mROT\\u202e" in m for m in meldungen)
    assert any("l\\nink -> ziel\\n\\x1b[31m" in m for m in meldungen)
    assert any("l\\nink -> ziel\\n\\x1b[31m" in h for h in hinweise)
    gekappt = [m for m in meldungen if "aaaa" in m]
    assert len(gekappt) == 1 and "…" in gekappt[0] and len(gekappt[0]) < 400


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


# ---------------------------------------------------------------- repo_hinweise: weitere Fälle

def test_repo_hinweise_unlesbare_datei(tmp_path):
    repo = repo_mit(tmp_path, {"geheim.txt": b"x\n", "ok.txt": b"ok\n"})
    os.chmod(repo / "geheim.txt", 0)
    try:
        hinweise = gitkopie.repo_hinweise(str(repo))
    finally:
        os.chmod(repo / "geheim.txt", 0o644)
    assert any("geheim.txt" in h and "nicht prüfbar" in h for h in hinweise), hinweise
    assert not any("ok.txt" in h for h in hinweise)


def test_repo_hinweise_merge_konflikt(tmp_path):
    repo = repo_mit(tmp_path, {"f.txt": b"base\n", "g.txt": b"g\n"})
    shas = [roh(repo, "hash-object", "-w", "--stdin", eingabe=t).decode().strip()
            for t in (b"base\n", b"ours\n", b"theirs\n")]
    index_info = "".join(f"100644 {sha} {stufe}\tf.txt\n" for stufe, sha in enumerate(shas, 1))
    roh(repo, "update-index", "--index-info", eingabe=index_info.encode())
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Merge-Konflikt" in h and "f.txt" in h for h in hinweise), hinweise


@pytest.mark.parametrize("groesse, gemeldet", [(1023, True), (1024, True), (1025, False)])
def test_lfs_pointer_groessenlimit(tmp_path, groesse, gemeldet):
    inhalt = LFS + b"#" * (groesse - len(LFS))
    assert len(inhalt) == groesse
    repo = repo_mit(tmp_path, {"p.bin": inhalt})
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("LFS-Pointer" in h and "p.bin" in h for h in hinweise) == gemeldet


def test_blob_hash_laengenpruefung_und_formate(tmp_path):
    datei = tmp_path / "f"
    datei.write_bytes(b"hallo")
    for algo in ("sha1", "sha256"):
        fd = os.open(datei, os.O_RDONLY)
        try:
            assert gitkopie._blob_hash(algo, fd, 5) is not None
            os.lseek(fd, 0, os.SEEK_SET)
            assert gitkopie._blob_hash(algo, fd, 7) is None    # Datei kürzer als angekündigt
            os.lseek(fd, 0, os.SEEK_SET)
            assert gitkopie._blob_hash(algo, fd, 3) is None    # Datei länger als angekündigt
        finally:
            os.close(fd)
    echt = subprocess.run(["git", "hash-object", "--no-filters", str(datei)], capture_output=True,
                          text=True).stdout.strip()
    fd = os.open(datei, os.O_RDONLY)
    try:
        assert gitkopie._blob_hash("sha1", fd, 5) == echt
    finally:
        os.close(fd)


def test_repo_hinweise_sha256_repo(tmp_path):
    repo = bauen(neues_repo(tmp_path / "repo", "--object-format=sha256"), {"a.txt": b"alt\n", "b.txt": b"b\n"})
    roh(repo, "reset", "-q", "--hard")
    assert gitkopie.repo_hinweise(str(repo)) == []
    (repo / "a.txt").write_bytes(b"neu\n")
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert len(hinweise) == 1 and "a.txt" in hinweise[0]


# ---------------------------------------------------------------- Härtung TF1-B1 (lange Operationen)

def test_blob_hash_liest_nie_mehr_als_die_groesse_haertung_b1():
    """Eine Datei, die beim Lesen weiter wächst (hier /dev/zero), ergibt None statt einer Endlosschleife."""
    import signal
    fd = os.open("/dev/zero", os.O_RDONLY)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError("Endlosschleife")))
    signal.alarm(10)
    try:
        assert gitkopie._blob_hash("sha1", fd, 100) is None
    finally:
        signal.alarm(0)
        os.close(fd)


def test_blob_hash_exakte_groesse_bleibt_gueltig_haertung_b1(tmp_path):
    import hashlib
    datei = tmp_path / "f"
    datei.write_bytes(b"abc" * 1000)
    fd = os.open(datei, os.O_RDONLY)
    try:
        erwartet = hashlib.sha1(b"blob 3000\0" + b"abc" * 1000).hexdigest()
        assert gitkopie._blob_hash("sha1", fd, 3000) == erwartet
    finally:
        os.close(fd)


def test_hinweise_arbeitsbaum_zeitbudget_haertung_b1(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "b.txt": b"b\n", "c.txt": b"c\n"})
    assert gitkopie.repo_hinweise(str(repo)) == []
    monkeypatch.setattr(gitkopie, "HINWEIS_BUDGET", -1)
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Zeitbudget" in h and "0 von 3" in h for h in hinweise), hinweise


def test_batch_timeout_liegt_unter_dem_bash_limit_haertung_b1():
    assert gitkopie.BATCH_TIMEOUT + 120 + 60 < 600       # ls-tree + Batch + Reste unter den 600 s des Skills


# ---------------------------------------------------------------- Härtung TF1-B3 (Zeitpunkt: gepinnter Commit)

def zwei_staende(tmp_path):
    """Repo mit zwei Commits; Rückgabe (repo, sha1, sha2). Stand 1: a.txt=eins; Stand 2: a.txt=zwei, Symlink, .mcp.json."""
    repo = repo_mit(tmp_path, {"a.txt": b"eins\n"})
    sha1 = roh(repo, "rev-parse", "HEAD").decode().strip()
    bauen(repo, {"a.txt": b"zwei\n", "l": (SYMLINK, b"a.txt"), ".mcp.json": b"{}\n"})
    sha2 = roh(repo, "rev-parse", "HEAD").decode().strip()
    return repo, sha1, sha2


def test_arbeitskopie_kopiert_den_gepinnten_commit_haertung_b3(tmp_path):
    repo, sha1, sha2 = zwei_staende(tmp_path)
    ziel = tmp_path / "ziel"
    assert gitkopie.arbeitskopie(str(repo), str(ziel), rev=sha1) == []
    assert (ziel / "a.txt").read_bytes() == b"eins\n" and alle_dateien(ziel) == ["a.txt"]
    ziel2 = tmp_path / "ziel2"
    gitkopie.arbeitskopie(str(repo), str(ziel2))
    assert (ziel2 / "a.txt").read_bytes() == b"zwei\n"                 # Standard bleibt HEAD


def test_repo_konfiguration_und_hinweise_nutzen_den_gepinnten_commit_haertung_b3(tmp_path):
    repo, sha1, sha2 = zwei_staende(tmp_path)
    assert gitkopie.repo_konfiguration(str(repo), rev=sha1) == []
    assert gitkopie.repo_konfiguration(str(repo), rev=sha2) == [".mcp.json"]
    assert not any("Symlink" in h for h in gitkopie.repo_hinweise(str(repo), rev=sha1))
    assert any("Symlink" in h for h in gitkopie.repo_hinweise(str(repo), rev=sha2))


@pytest.mark.parametrize("rev", ["--output=x", "-x", "HEAD~1", "main", "abc", "A" * 40, "", "0" * 40 + "\n", "HEAD^{tree}"])
def test_ungueltige_revision_wird_abgelehnt_haertung_b3(tmp_path, rev):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    with pytest.raises(ValueError):
        gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"), rev=rev)
    with pytest.raises(ValueError):
        gitkopie.repo_konfiguration(str(repo), rev=rev)


def test_revision_die_kein_commit_ist_ist_giterror_haertung_b3(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    baum = roh(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    for rev in (baum, "0" * 40):
        with pytest.raises(gitkopie.GitFehler):
            gitkopie.arbeitskopie(str(repo), str(tmp_path / "ziel"), rev=rev)
    hinweise = gitkopie.repo_hinweise(str(repo), rev="0" * 40)
    assert any("Kein HEAD lesbar" in h for h in hinweise), hinweise


# ---------------------------------------------------------------- Härtung TF1-B5 (keine stillen Fallbacks)

def test_index_mit_ungueltiger_zeile_ist_hinweis_statt_stilles_ueberspringen_haertung_b5(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    shim_git(tmp_path, monkeypatch, vorab='case " $* " in *" ls-files "*) printf "garbage\\0"; exit 0;; esac')
    hinweise = gitkopie.repo_hinweise(str(repo))
    assert any("Index nicht lesbar" in h for h in hinweise), hinweise


def test_fehlende_objekte_werden_gemeldet_haertung_b5(tmp_path):
    """Partial Clone ohne Lazy Fetch: fehlende kleine Blobs wurden bisher stillschweigend übergangen (LFS-Prüfung)."""
    repo = repo_mit(tmp_path, {"a.txt": b"einmalig-a\n", "b.txt": b"einmalig-b\n", "c.txt": b"ok-c\n"})
    for name in ("a.txt", "b.txt"):
        sha = roh(repo, "rev-parse", f"HEAD:{name}").decode().strip()
        os.unlink(repo / ".git" / "objects" / sha[:2] / sha[2:])
    hinweise = gitkopie.repo_hinweise(str(repo))
    fehlt = [h for h in hinweise if "Objekt" in h and "fehlen" in h]
    assert len(fehlt) == 1 and "2" in fehlt[0] and "a.txt" in fehlt[0], hinweise


# ---------------------------------------------------------------- Härtung TF1-I3 (Gesamtfrist)

def test_frist_erschoepft_startet_kein_git_haertung_i3(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    log = shim_git(tmp_path, monkeypatch)
    gitkopie.frist_setzen(time.monotonic() - 1)
    with pytest.raises(gitkopie.ZeitbudgetFehler, match="Zeitbudget"):
        gitkopie.git(str(repo), "rev-parse", "HEAD")
    with pytest.raises(gitkopie.ZeitbudgetFehler):
        gitkopie._Batch(str(repo))
    with pytest.raises(gitkopie.GitFehler):                  # ist ein GitFehler: bestehende Fehlerpfade greifen
        gitkopie.git(str(repo), "rev-parse", "HEAD")
    assert not log.exists(), "nach Ablauf der Frist darf kein git-Prozess starten"
    gitkopie.frist_setzen(None)
    assert gitkopie.git(str(repo), "rev-parse", "HEAD").stdout.strip()      # ohne Frist läuft es wieder


def test_frist_kuerzt_den_timeout_und_meldet_zeitbudget_haertung_i3(tmp_path, monkeypatch):
    gesehen = {}

    def falsches_run(cmd, **kw):
        gesehen["timeout"] = kw["timeout"]
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(gitkopie.subprocess, "run", falsches_run)
    gitkopie.frist_setzen(time.monotonic() + 5)
    with pytest.raises(gitkopie.ZeitbudgetFehler):
        gitkopie.git(str(tmp_path), "status", timeout=60)
    assert 0 < gesehen["timeout"] <= 5
    gitkopie.frist_setzen(None)
    with pytest.raises(gitkopie.GitFehler) as e:             # ohne Frist: gewöhnlicher Timeout, kein Zeitbudget
        gitkopie.git(str(tmp_path), "status", timeout=60)
    assert not isinstance(e.value, gitkopie.ZeitbudgetFehler) and gesehen["timeout"] == 60


def test_abbruch_durch_den_eigenen_zeitgeber_ist_zeitbudget_r1_15(tmp_path, monkeypatch):
    """R1-15: Der Zeitgeber des cat-file-Prozesses (BATCH_TIMEOUT) beendet git auch bei noch nicht erschöpfter Gesamtfrist;
    das ist ein Zeitbudget-Abbruch („Zeitbudget“ in der Meldung, wie SKILL.md zusagt), kein „Broken pipe“."""
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    sha = gitkopie.git(str(repo), "rev-parse", "HEAD:a.txt").stdout.decode().strip()
    monkeypatch.setattr(gitkopie, "BATCH_TIMEOUT", 0.05)
    gitkopie.frist_setzen(time.monotonic() + 600)             # Gesamtfrist weit weg
    try:
        with gitkopie._Batch(str(repo)) as batch:
            time.sleep(0.4)
            with pytest.raises(gitkopie.ZeitbudgetFehler, match="Zeitbudget"):
                batch.lies(sha)
        assert not gitkopie.frist_erschoepft()
    finally:
        gitkopie.frist_setzen(None)


def test_batch_ohne_ablauf_des_zeitgebers_liest_normal_r1_15(tmp_path):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n"})
    sha = gitkopie.git(str(repo), "rev-parse", "HEAD:a.txt").stdout.decode().strip()
    with gitkopie._Batch(str(repo)) as batch:
        assert batch.lies(sha) == b"a\n"


def test_arbeitskopie_bricht_bei_erschoepfter_frist_ab_haertung_i3(tmp_path, monkeypatch):
    repo = repo_mit(tmp_path, {"a.txt": b"a\n", "b.txt": b"b\n"})
    monkeypatch.setattr(gitkopie, "frist_erschoepft", lambda: True)
    ziel = tmp_path / "ziel"
    meldungen = gitkopie.arbeitskopie(str(repo), str(ziel))
    assert any("Arbeitskopie unvollständig" in m and "Zeitbudget" in m for m in meldungen), meldungen
    assert not (ziel / "a.txt").exists() and not (ziel / "b.txt").exists()
