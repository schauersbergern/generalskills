#!/usr/bin/env python3
"""Sichere git-Zugriffe und Arbeitskopie für den Skill security-audit (nur Standardbibliothek).

Sicherheitsgrenze: Der Stand von HEAD wird so kopiert, dass kein Code aus dem geprüften Repo auf dem
Host läuft und nichts außerhalb des Zielordners geschrieben oder gelesen wird.

- Alle git-Aufrufe laufen über `git()`: Fsmonitor und Hooks aus, geerbte GIT_*-Umgebung entfernt.
- Die Kopie besteht aus rohen Blobs (`ls-tree` + `cat-file --batch`): kein `export-ignore`, keine
  Smudge-Filter. Symlinks werden nie als Symlink angelegt; ihr Ziel wird lexikalisch im HEAD-Baum
  aufgelöst und dessen Inhalt als normale Datei geschrieben, sonst wird der Eintrag gemeldet.
- `repo_hinweise` erkennt Änderungen ohne `git status`/`git diff`/`hash-object` (Clean-Filter): Index
  gegen HEAD per `ls-tree`/`ls-files -s`, Arbeitsbaum-Dateien per Hash in Python.

Die Funktionen nehmen die Repo-Wurzel (nicht ein Unterverzeichnis) entgegen.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import threading
import unicodedata
from typing import NamedTuple

MAX_SYMLINK_KETTE = 8
BATCH_TIMEOUT = 600
LFS_PREFIX = b"version https://git-lfs"
LFS_MAX_GROESSE = 1024
DATEI_MODI = ("100644", "100755")
UNSICHTBAR = dict.fromkeys(list(range(0x200B, 0x2010)) + list(range(0x202A, 0x202F))
                           + list(range(0x2060, 0x2070)) + [0xFEFF])


class GitFehler(Exception):
    """git beendete sich mit Exit ≠ 0, lief in den Timeout oder war nicht startbar."""

    def __init__(self, nachricht: str, returncode: int | None = None, stderr: bytes = b""):
        super().__init__(nachricht)
        self.returncode = returncode
        self.stderr = stderr


# ------------------------------------------------------------------------------------ git-Aufruf

def _umgebung() -> dict[str, str]:
    """Eigene Umgebung ohne geerbte GIT_*-Variablen (außer GIT_EXEC_PATH), mit Sicherheitswerten."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1")
    return env


def _befehl(repo: str, args: tuple[str, ...]) -> list[str]:
    return ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo, *args]


def git(repo: str, *args: str, eingabe: bytes | None = None,
        timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    """git im Repo ausführen; wirft GitFehler bei Exit ≠ 0, Timeout oder fehlendem git."""
    try:
        r = subprocess.run(_befehl(repo, args), input=eingabe, capture_output=True, timeout=timeout,
                           env=_umgebung(), stdin=None if eingabe is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        raise GitFehler(f"git {' '.join(args)}: Timeout nach {timeout} s") from e
    except OSError as e:
        raise GitFehler(f"git nicht startbar: {e}") from e
    if r.returncode != 0:
        fehler = r.stderr.decode(errors="replace").strip()
        raise GitFehler(f"git {' '.join(args)} fehlgeschlagen (Exit {r.returncode}): {fehler}",
                        r.returncode, r.stderr)
    return r


class _Batch:
    """Ein `git cat-file --batch`-Prozess; liest Blobs per SHA im Gleichschritt (Anfrage, Antwort)."""

    def __init__(self, repo: str):
        try:
            self.proc = subprocess.Popen(_befehl(repo, ("cat-file", "--batch")), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_umgebung())
        except OSError as e:
            raise GitFehler(f"git nicht startbar: {e}") from e
        self.timer = threading.Timer(BATCH_TIMEOUT, self.proc.kill)
        self.timer.daemon = True
        self.timer.start()

    def lies(self, sha: str) -> bytes | None:
        """Inhalt des Blobs oder None, wenn das Objekt fehlt (z. B. Partial Clone ohne Lazy Fetch)."""
        try:
            self.proc.stdin.write(sha.encode() + b"\n")
            self.proc.stdin.flush()
            kopf = self.proc.stdout.readline()
        except (BrokenPipeError, OSError) as e:
            raise GitFehler(f"git cat-file --batch abgebrochen: {e}") from e
        teile = kopf.split()
        if len(teile) == 2 and teile[1] == b"missing":
            return None
        if len(teile) != 3 or teile[1] != b"blob":
            raise GitFehler(f"git cat-file --batch: unerwartete Antwort {kopf!r}")
        groesse = int(teile[2])
        inhalt = self.proc.stdout.read(groesse)
        ende = self.proc.stdout.read(1)
        if len(inhalt) != groesse or ende != b"\n":
            raise GitFehler("git cat-file --batch: Antwort abgeschnitten (Timeout oder Abbruch)")
        return inhalt

    def __enter__(self) -> "_Batch":
        return self

    def __exit__(self, *_):
        self.timer.cancel()
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()


# ------------------------------------------------------------------------------------ Baum lesen

class Eintrag(NamedTuple):
    modus: str
    art: str
    sha: str
    groesse: int
    pfad: str


def _baum(repo: str) -> list[Eintrag]:
    """`git ls-tree -r -z -l --full-tree HEAD` als Liste (Reihenfolge wie git)."""
    ausgabe = git(repo, "ls-tree", "-r", "-z", "-l", "--full-tree", "HEAD", timeout=120).stdout
    eintraege = []
    for rec in ausgabe.split(b"\0"):
        if not rec:
            continue
        meta, _, pfad = rec.partition(b"\t")
        teile = meta.split()
        if len(teile) != 4:
            raise GitFehler(f"git ls-tree: unerwartete Zeile {rec!r}")
        groesse = int(teile[3]) if teile[3].isdigit() else 0
        eintraege.append(Eintrag(teile[0].decode(), teile[1].decode(), teile[2].decode(), groesse,
                                 os.fsdecode(pfad)))
    return eintraege


def _schluessel(text: str) -> str:
    return unicodedata.normalize("NFC", text).casefold()


def _komponente_gesperrt(komp: str) -> bool:
    """`.git` (auch mit unsichtbaren Zeichen, NTFS-Kurzname): würde ein späteres git im Ziel vergiften."""
    k = _schluessel(komp.translate(UNSICHTBAR))
    return k in (".git", "git~1")


def _env_datei(pfad: str) -> bool:
    name = _schluessel(pfad.rsplit("/", 1)[-1])
    return name.startswith(".env") and name != ".env.example"


def _pfad_problem(pfad: str) -> str | None:
    """Grund, warum ein Pfad nie geschrieben wird (außer .env, das hat eine eigene Meldung)."""
    if pfad.startswith("/"):
        return "absoluter Pfad"
    for komp in pfad.split("/"):
        if komp in ("", ".", ".."):
            return f"Pfadkomponente '{komp}'"
        if _komponente_gesperrt(komp):
            return "Komponente .git"
    return None


class _Namensraum:
    """Kollisionserkennung nach NFC + casefold, auch zwischen Datei und Ordner (`A` und `a/b`)."""

    def __init__(self):
        self._belegt: dict[str, tuple[str, str]] = {}

    def kollision(self, pfad: str) -> str | None:
        komps = pfad.split("/")
        for i in range(1, len(komps)):
            art = self._belegt.get(_schluessel("/".join(komps[:i])))
            if art and art[0] == "datei":
                return art[1]
        art = self._belegt.get(_schluessel(pfad))
        return art[1] if art else None

    def belege(self, pfad: str) -> None:
        komps = pfad.split("/")
        for i in range(1, len(komps)):
            self._belegt.setdefault(_schluessel("/".join(komps[:i])), ("ordner", "/".join(komps[:i])))
        self._belegt[_schluessel(pfad)] = ("datei", pfad)


# ------------------------------------------------------------------------------------ Symlinks

def _loese_auf(basis: list[str], text: str, eintraege: dict[str, Eintrag],
               ordner: set[str]) -> tuple[str | None, str | None]:
    """Symlink-Ziel lexikalisch im HEAD-Baum auflösen: (Pfad, None) oder (None, Grund).

    Eine Zwischenkomponente, die selbst Datei oder Symlink ist, wird nicht durchschritten (das Betriebs-
    system würde sie anders auflösen als die lexikalische Rechnung)."""
    if text == "":
        return None, "leeres Ziel"
    if text.startswith("/"):
        return None, "absolutes Ziel"
    stapel = list(basis)
    for komp in text.split("/"):
        if komp in ("", "."):
            continue
        aktuell = "/".join(stapel)
        if komp == "..":
            if not stapel:
                return None, "Ziel verlässt das Repo"
            if aktuell in eintraege:
                return None, "Zwischenkomponente ist Symlink oder Datei"
            if aktuell not in ordner:
                return None, "Zwischenkomponente existiert nicht"
            stapel.pop()
        else:
            if aktuell in eintraege:
                return None, "Zwischenkomponente ist Symlink oder Datei"
            stapel.append(komp)
    return "/".join(stapel), None


def _symlink_ziel(pfad: str, text: str, eintraege: dict[str, Eintrag], ordner: set[str],
                  batch: _Batch) -> tuple[Eintrag | None, str]:
    """(Ziel-Blob, Meldungsgrund). Folgt Ketten über andere Tree-Symlinks bis MAX_SYMLINK_KETTE."""
    aktuell, ziel_text = pfad, text
    for _ in range(MAX_SYMLINK_KETTE):
        aufgeloest, grund = _loese_auf(aktuell.split("/")[:-1], ziel_text, eintraege, ordner)
        if aufgeloest is None:
            return None, grund
        e = eintraege.get(aufgeloest)
        if e is None:
            return None, "Ziel ist ein Ordner" if aufgeloest in ordner else "Ziel nicht im HEAD-Baum"
        if e.modus in DATEI_MODI and e.art == "blob":
            return e, ""
        if e.modus != "120000":
            return None, "Ziel ist weder Datei noch Symlink"
        inhalt = batch.lies(e.sha)
        if inhalt is None:
            return None, "Ziel-Objekt fehlt"
        aktuell, ziel_text = aufgeloest, os.fsdecode(inhalt)
    return None, f"Symlink-Kette tiefer als {MAX_SYMLINK_KETTE} oder Zyklus"


# ------------------------------------------------------------------------------------ Schreiben

def _schreibe(wurzel: str, pfad: str, inhalt: bytes, ausfuehrbar: bool) -> None:
    """Datei sicher unter `wurzel` (realpath) anlegen; nie einem Symlink folgen, nie überschreiben."""
    komps = pfad.split("/")
    akt = wurzel
    for komp in komps[:-1]:
        akt = os.path.join(akt, komp)
        if os.path.islink(akt):
            raise OSError("Elternordner ist ein Symlink")
        if not os.path.lexists(akt):
            os.mkdir(akt, 0o755)
        elif not os.path.isdir(akt):
            raise OSError("Elternpfad ist kein Ordner")
    real = os.path.realpath(akt)
    if os.path.commonpath([real, wurzel]) != wurzel:
        raise OSError("Elternordner liegt außerhalb des Ziels")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(os.path.join(real, komps[-1]), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(inhalt)
        f.flush()
        os.fchmod(f.fileno(), 0o755 if ausfuehrbar else 0o644)


# ------------------------------------------------------------------------------------ Arbeitskopie

def arbeitskopie(repo: str, ziel: str) -> list[str]:
    """Stand von HEAD als rohe Blobs nach `ziel` schreiben; Rückgabe: Meldungen (deutsch).

    Wirft GitFehler, wenn HEAD nicht lesbar ist."""
    baum = _baum(repo)
    eintraege = {e.pfad: e for e in baum}
    ordner = {"/".join(e.pfad.split("/")[:i]) for e in baum for i in range(1, len(e.pfad.split("/")))}
    os.makedirs(ziel, exist_ok=True)
    wurzel = os.path.realpath(ziel)
    meldungen: list[str] = []
    namen = _Namensraum()

    with _Batch(repo) as batch:
        for e in baum:
            pfad = e.pfad
            grund = _pfad_problem(pfad)
            if grund:
                meldungen.append(f"Pfad übersprungen: {pfad} ({grund})")
                continue
            if e.art == "commit" or e.modus == "160000":
                meldungen.append(f"Submodul nicht kopiert: {pfad}")
                continue
            if _env_datei(pfad):
                meldungen.append(f"Übersprungen (.env-Datei): {pfad}")
                continue
            try:
                inhalt = batch.lies(e.sha)
                if inhalt is None:
                    meldungen.append(f"Objekt fehlt, übersprungen: {pfad}")
                    continue
                herkunft = ""
                if e.modus == "120000":
                    text = os.fsdecode(inhalt)
                    ziel_blob, grund = _symlink_ziel(pfad, text, eintraege, ordner, batch)
                    if ziel_blob is None:
                        meldungen.append(f"Symlink übersprungen: {pfad} -> {text} ({grund})")
                        continue
                    ziel_grund = _pfad_problem(ziel_blob.pfad)
                    if ziel_grund or _env_datei(ziel_blob.pfad):
                        meldungen.append(f"Symlink übersprungen: {pfad} -> {text} "
                                         f"(Ziel {ziel_blob.pfad} ist gesperrt)")
                        continue
                    inhalt = batch.lies(ziel_blob.sha)
                    if inhalt is None:
                        meldungen.append(f"Symlink übersprungen: {pfad} -> {text} (Ziel-Objekt fehlt)")
                        continue
                    herkunft = f"Symlink {pfad} -> {text} als normale Datei kopiert (Inhalt von {ziel_blob.pfad})"
                    ausfuehrbar = False
                elif e.art == "blob":
                    ausfuehrbar = bool(int(e.modus, 8) & 0o100)
                else:
                    meldungen.append(f"Eintrag übersprungen: {pfad} (Typ {e.art})")
                    continue
                erster = namen.kollision(pfad)
                if erster:
                    meldungen.append(f"Namenskollision: {pfad} kollidiert mit {erster}; übersprungen")
                    continue
                _schreibe(wurzel, pfad, inhalt, ausfuehrbar)
                namen.belege(pfad)
                if herkunft:
                    meldungen.append(herkunft)
                if inhalt.startswith(LFS_PREFIX):
                    meldungen.append(f"LFS-Pointer: {pfad} (nur der Pointer wurde kopiert, nicht der Inhalt)")
            except OSError as err:
                meldungen.append(f"Schreiben fehlgeschlagen: {pfad} ({err})")
    return meldungen


# ------------------------------------------------------------------------------------ Konfiguration

def repo_konfiguration(repo: str) -> list[str]:
    """In HEAD versionierte Claude-/MCP-Konfiguration (auch verschachtelt); wirft GitFehler ohne HEAD."""
    ausgabe = git(repo, "ls-tree", "-r", "-z", "--name-only", "--full-tree", "HEAD", timeout=120).stdout
    gefunden = []
    for roh in ausgabe.split(b"\0"):
        if not roh:
            continue
        pfad = os.fsdecode(roh)
        komps = [_schluessel(k) for k in pfad.split("/")]
        name = komps[-1]
        treffer = name == ".mcp.json"
        if not treffer and len(komps) >= 2 and komps[-2] == ".claude":
            treffer = name.startswith("settings") and name.endswith(".json")
        if not treffer:
            treffer = any(komps[i] == ".claude" and komps[i + 1] in ("skills", "agents", "commands")
                          for i in range(len(komps) - 2))
        if treffer:
            gefunden.append(pfad)
    return sorted(gefunden)


# ------------------------------------------------------------------------------------ Hinweise

def _blob_hash(algo: str, fd: int, groesse: int) -> str | None:
    h = hashlib.new(algo)
    h.update(b"blob %d\0" % groesse)
    gelesen = 0
    while True:
        stueck = os.read(fd, 1 << 20)
        if not stueck:
            break
        gelesen += len(stueck)
        h.update(stueck)
    return h.hexdigest() if gelesen == groesse else None


def _index(repo: str) -> tuple[dict[str, tuple[str, str]], list[str]]:
    ausgabe = git(repo, "ls-files", "-s", "-z", "--full-name", timeout=120).stdout
    index: dict[str, tuple[str, str]] = {}
    konflikte = []
    for rec in ausgabe.split(b"\0"):
        if not rec:
            continue
        meta, _, pfad = rec.partition(b"\t")
        teile = meta.split()
        if len(teile) != 3:
            continue
        name = os.fsdecode(pfad)
        if teile[2] != b"0":
            konflikte.append(name)
        else:
            index[name] = (teile[0].decode(), teile[1].decode())
    return index, konflikte


def repo_hinweise(repo: str) -> list[str]:
    """Hinweise zum Repo (deutsch); Fehler und Timeouts werden zu Hinweisen, nie zum Abbruch."""
    hinweise: list[str] = []
    try:
        baum = _baum(repo)
    except GitFehler as e:
        return [f"Kein HEAD lesbar, Prüfung nicht möglich: {e}"]

    eintraege = {e.pfad: e for e in baum}
    namen = _Namensraum()
    for e in baum:
        if e.art == "commit" or e.modus == "160000":
            hinweise.append(f"Submodul: {e.pfad} (nicht in der Arbeitskopie)")
            continue
        erster = namen.kollision(e.pfad)
        if erster:
            hinweise.append(f"Namenskollision: {e.pfad} und {erster} (gleicher Name nach NFC/casefold)")
        else:
            namen.belege(e.pfad)

    try:
        with _Batch(repo) as batch:
            for e in baum:
                if e.modus == "120000":
                    inhalt = batch.lies(e.sha)
                    ziel = os.fsdecode(inhalt) if inhalt is not None else "?"
                    hinweise.append(f"Symlink: {e.pfad} -> {ziel}")
                elif e.art == "blob" and e.groesse <= LFS_MAX_GROESSE:
                    inhalt = batch.lies(e.sha)
                    if inhalt is not None and inhalt.startswith(LFS_PREFIX):
                        hinweise.append(f"LFS-Pointer: {e.pfad} (Inhalt liegt nicht im Repo)")
    except (GitFehler, OSError) as err:
        hinweise.append(f"Prüfung von Symlinks und LFS-Pointern nicht möglich: {err}")

    try:
        index, konflikte = _index(repo)
    except GitFehler as err:
        hinweise.append(f"Index nicht lesbar, Prüfung auf Änderungen nicht möglich: {err}")
        return hinweise
    for pfad in konflikte:
        hinweise.append(f"Merge-Konflikt im Index: {pfad}")
    for pfad, (modus, sha) in sorted(index.items()):
        kopf = eintraege.get(pfad)
        if kopf is None:
            hinweise.append(f"Gestagt hinzugefügt (nicht in HEAD): {pfad}")
        elif (kopf.modus, kopf.sha) != (modus, sha):
            hinweise.append(f"Gestagte Änderung gegenüber HEAD: {pfad}")
    for pfad in sorted(eintraege):
        if pfad not in index and eintraege[pfad].art == "blob":
            hinweise.append(f"Gestagt gelöscht (in HEAD, nicht im Index): {pfad}")

    try:
        algo = "sha256" if git(repo, "rev-parse", "--show-object-format").stdout.strip() == b"sha256" else "sha1"
    except GitFehler as err:
        hinweise.append(f"Objektformat nicht ermittelbar, Prüfung auf Änderungen im Arbeitsbaum "
                        f"nicht möglich: {err}")
        return hinweise

    wurzel = os.path.realpath(repo)
    ordner_ok: dict[str, bool] = {}
    for pfad, (modus, sha) in sorted(index.items()):
        if modus not in DATEI_MODI:
            continue
        voll = os.path.join(wurzel, pfad)
        eltern = os.path.dirname(voll)
        if eltern not in ordner_ok:
            real = os.path.realpath(eltern)
            ordner_ok[eltern] = os.path.commonpath([real, wurzel]) == wurzel
        if not ordner_ok[eltern]:
            hinweise.append(f"Typ im Arbeitsbaum geändert (Elternordner führt aus dem Repo): {pfad}")
            continue
        try:
            st = os.lstat(voll)
            if not stat.S_ISREG(st.st_mode):
                hinweise.append(f"Typ im Arbeitsbaum geändert (keine normale Datei mehr): {pfad}")
                continue
            fd = os.open(voll, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    hinweise.append(f"Typ im Arbeitsbaum geändert (keine normale Datei mehr): {pfad}")
                    continue
                aktuell = _blob_hash(algo, fd, fst.st_size)
            finally:
                os.close(fd)
        except FileNotFoundError:
            hinweise.append(f"Im Arbeitsbaum gelöscht: {pfad}")
            continue
        except OSError as err:
            hinweise.append(f"Datei im Arbeitsbaum nicht prüfbar: {pfad} ({err})")
            continue
        if aktuell != sha:
            hinweise.append(f"Uncommittete Änderung im Arbeitsbaum: {pfad}")
    return hinweise
