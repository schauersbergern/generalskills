#!/usr/bin/env python3
"""Sichere git-Zugriffe und Arbeitskopie für den Skill security-audit (nur Standardbibliothek).

Sicherheitsgrenze: Der Stand eines Commits (HEAD oder ein gepinnter Hash) wird so kopiert, dass kein Code aus dem geprüften Repo auf dem
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
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
import unicodedata
from typing import NamedTuple

MAX_SYMLINK_KETTE = 8
MAX_SYMLINK_GROESSE = 4096
MAX_TEXT = 300
BATCH_TIMEOUT = 400          # ganzer cat-file-Prozess; mit ls-tree (120 s) unter dem 600-s-Limit des Skills
HINWEIS_BUDGET = 90          # Sekunden für das Hashen des Arbeitsbaums in repo_hinweise
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


class ZeitbudgetFehler(GitFehler):
    """Das Gesamtbudget des laufenden Befehls (`frist_setzen`) ist aufgebraucht; es wird kein weiterer git-Aufruf gestartet."""


_ENDE: float | None = None          # monotone Frist des laufenden Befehls (bericht.py kontext, poc.py vorbereiten)


def frist_setzen(ende: float | None) -> None:
    """Gesamtfrist (Wert von `time.monotonic()`) für alle folgenden git-Aufrufe dieses Prozesses; `None` hebt sie auf.
    `git` kürzt seinen Timeout auf die Restzeit und startet danach nichts mehr (ZeitbudgetFehler), `_Batch` kürzt den
    Zeitgeber des cat-file-Prozesses."""
    global _ENDE
    _ENDE = ende


def frist_rest() -> float | None:
    return None if _ENDE is None else _ENDE - time.monotonic()


def frist_erschoepft() -> bool:
    rest = frist_rest()
    return rest is not None and rest <= 0


# ------------------------------------------------------------------------------------ git-Aufruf

def _umgebung() -> dict[str, str]:
    """Eigene Umgebung ohne geerbte GIT_*-Variablen (außer GIT_EXEC_PATH), mit Sicherheitswerten."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k == "GIT_EXEC_PATH"}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1")
    return env


def werkzeug_umgebung() -> dict[str, str]:
    """Umgebung für Werkzeuge (gitleaks, osv-scanner) und deren git-Aufrufe auf Kundenmaterial: ohne `GIT_*`, `GITLEAKS_*`
    und `OSV_*` aus der Prozessumgebung (kein umgeleitetes Repo, keine Konfiguration, Allowlist oder Baseline von außen),
    mit `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`,
    `GIT_OPTIONAL_LOCKS=0`. Jeder Aufruf liefert ein neues Dict."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITLEAKS_", "OSV_"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
               GIT_OPTIONAL_LOCKS="0")
    return env


AUSGABE_MAX = 16 * 1024 * 1024   # Bytes je Strom (stdout, stderr), die `werkzeug_ausfuehren` höchstens in den Speicher liest


class Lauf(NamedTuple):
    rc: int | None      # None = Zeitüberschreitung (die eigene Prozessgruppe wurde beendet)
    out: bytes
    err: bytes
    abgeschnitten: bool = False      # stdout oder stderr war länger als `ausgabe_max`; `out`/`err` enthalten nur den Anfang


def _gruppe_beenden(proc: subprocess.Popen) -> tuple[bytes, bytes]:
    """Eigene, per `start_new_session=True` gestartete Prozessgruppe nach Zeitüberschreitung beenden (erst SIGTERM, nach 5 s
    SIGKILL) und die Ströme einsammeln. `proc.pid` ist zugleich die Gruppen-ID; es gibt nie ein anderes Ziel, und der Prozess
    ist hier noch nicht eingesammelt (keine PID-Wiederverwendung)."""
    for sig, warten in ((signal.SIGTERM, 5), (signal.SIGKILL, 10)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            return proc.communicate(timeout=warten)
        except subprocess.TimeoutExpired:
            continue
    proc.kill()                                       # letzte Rückfallebene: nur das eigene direkte Kind
    return proc.communicate()


def _anfang_lesen(datei, grenze: int) -> tuple[bytes, bool]:
    """Die ersten `grenze` Bytes einer Ausgabedatei und ob sie länger war."""
    groesse = datei.seek(0, os.SEEK_END)
    datei.seek(0)
    return datei.read(grenze), groesse > grenze


def werkzeug_ausfuehren(args: list[str], timeout: float, cwd: str, env: dict[str, str] | None = None,
                        ausgabe_max: int = AUSGABE_MAX) -> Lauf:
    """Werkzeug (gitleaks, osv-scanner, `git clone`) als eigene Sitzung starten (`start_new_session=True`), mit `timeout`
    Sekunden. Bei Zeitüberschreitung wird nur diese selbst gestartete Gruppe beendet (`rc` ist dann None). Ohne `env` gilt
    `werkzeug_umgebung()`; stdin ist /dev/null. stdout und stderr gehen in unbenannte Temp-Dateien (nie eine Pipe: auch ein
    ausgebrochener Enkel kann nichts offen halten) und werden danach höchstens bis `ausgabe_max` Bytes je Strom gelesen
    (`abgeschnitten`). Wirft GitFehler, wenn das Programm nicht startbar ist."""
    with tempfile.TemporaryFile() as aus, tempfile.TemporaryFile() as fehler:
        try:
            proc = subprocess.Popen(args, cwd=cwd, env=env if env is not None else werkzeug_umgebung(),
                                    stdin=subprocess.DEVNULL, stdout=aus, stderr=fehler, start_new_session=True)
        except OSError as e:
            raise GitFehler(f"{os.path.basename(args[0])} nicht startbar: {e}") from e
        rc: int | None
        try:
            proc.communicate(timeout=max(timeout, 0.01))
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            _gruppe_beenden(proc)
            rc = None
        out, k1 = _anfang_lesen(aus, ausgabe_max)
        err, k2 = _anfang_lesen(fehler, ausgabe_max)
    return Lauf(rc, out, err, k1 or k2)


def _befehl(repo: str, args: tuple[str, ...]) -> list[str]:
    return ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo, *args]


def git(repo: str, *args: str, eingabe: bytes | None = None,
        timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    """git im Repo ausführen; wirft GitFehler bei Exit ≠ 0, Timeout oder fehlendem git, ZeitbudgetFehler (eine GitFehler),
    wenn das Gesamtbudget (`frist_setzen`) aufgebraucht ist oder den Timeout gekürzt und erreicht hat."""
    rest = frist_rest()
    if rest is not None:
        if rest <= 0:
            raise ZeitbudgetFehler(f"git {' '.join(args)}: Zeitbudget erschöpft, nicht gestartet")
        if rest < timeout:
            try:
                return _git_ausfuehren(repo, args, eingabe, rest)
            except GitFehler as e:
                if "Timeout nach" in str(e) and e.returncode is None:
                    raise ZeitbudgetFehler(f"git {' '.join(args)}: Zeitbudget erschöpft") from e
                raise
    return _git_ausfuehren(repo, args, eingabe, timeout)


def _git_ausfuehren(repo: str, args: tuple[str, ...], eingabe: bytes | None, timeout: float) -> subprocess.CompletedProcess[bytes]:
    try:
        r = subprocess.run(_befehl(repo, args), input=eingabe, capture_output=True, timeout=timeout,
                           env=_umgebung(), stdin=None if eingabe is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        raise GitFehler(f"git {' '.join(args)}: Timeout nach {timeout:g} s") from e
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
        rest = frist_rest()
        if rest is not None and rest <= 0:
            raise ZeitbudgetFehler("git cat-file --batch: Zeitbudget erschöpft, nicht gestartet")
        try:
            self.proc = subprocess.Popen(_befehl(repo, ("cat-file", "--batch")), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_umgebung())
        except OSError as e:
            raise GitFehler(f"git nicht startbar: {e}") from e
        self.timer = threading.Timer(BATCH_TIMEOUT if rest is None else min(BATCH_TIMEOUT, rest), self.proc.kill)
        self.timer.daemon = True
        self.timer.start()

    def lies(self, sha: str) -> bytes | None:
        """Inhalt des Blobs oder None, wenn das Objekt fehlt (z. B. Partial Clone ohne Lazy Fetch). Ein Abbruch nach Ablauf
        der Gesamtfrist (der Zeitgeber hat git beendet) ist ein ZeitbudgetFehler."""
        try:
            return self._lies(sha)
        except ZeitbudgetFehler:
            raise
        except GitFehler as e:
            if frist_erschoepft():
                raise ZeitbudgetFehler(f"git cat-file --batch: Zeitbudget erschöpft ({e})") from e
            raise

    def _lies(self, sha: str) -> bytes | None:
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
        if not teile[2].isdigit() or len(teile[2]) > 15:  # `-1` läse bis EOF (Hänger), `xyz` und Zifferngebirge wären ValueError
            raise GitFehler(f"git cat-file --batch: unerwartete Antwort {kopf!r}")
        groesse = int(teile[2])
        stuecke: list[bytes] = []
        rest = groesse
        while rest > 0:                                   # in Stücken: eine absurde Größe belegt keinen Speicher vorab
            stueck = self.proc.stdout.read(min(rest, 1 << 20))
            if not stueck:
                break
            stuecke.append(stueck)
            rest -= len(stueck)
        inhalt = b"".join(stuecke)
        ende = self.proc.stdout.read(1) if rest == 0 else b""
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


_REV = re.compile(r"HEAD|[0-9a-f]{40}|[0-9a-f]{64}")


def _commit(repo: str, rev: str) -> str:
    """Revision `rev` (`HEAD` oder voller Commit-Hash, nichts sonst: keine Optionen, keine Ausdrücke) als Commit-Hash; wirft
    ValueError bei ungültiger Schreibweise, GitFehler, wenn es kein Commit des Repos ist. Alle Lesezugriffe eines Audits
    beziehen sich auf diesen einen Commit, nicht auf das wandernde HEAD."""
    if not isinstance(rev, str) or not _REV.fullmatch(rev):
        raise ValueError(f"ungültige Revision (erwartet HEAD oder voller Commit-Hash): {_t(rev)}")
    return git(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").stdout.decode().strip()


def _baum(repo: str, rev: str = "HEAD") -> list[Eintrag]:
    """`git ls-tree -r -z -l --full-tree <commit>` als Liste (Reihenfolge wie git)."""
    ausgabe = git(repo, "ls-tree", "-r", "-z", "-l", "--full-tree", _commit(repo, rev), timeout=120).stdout
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


_UNSICHTBAR_BEREICHE = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF), (0x034F, 0x034F), (0x180B, 0x180F), (0x17B4, 0x17B5),
                        (0x115F, 0x1160), (0x3164, 0x3164), (0xFFA0, 0xFFA0), (0x2800, 0x2800))


def unsichtbar(ch: str) -> bool:
    """Zeichen, das in Terminal/LLM-Kontext unsichtbar ist oder den Text umlenkt: Kategorien Cc, Cf, Cs, Co, Cn, Zl, Zp
    sowie Variation Selectors, CGJ, Mongolisch-/Khmer-Steuerzeichen, Hangul- und Braille-Füller. Die eine Quelle für alle
    Meldungen und Ausgaben des Skills (`_t` hier, `poc._entschaerfen`)."""
    o = ord(ch)
    return (unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
            or any(von <= o <= bis for von, bis in _UNSICHTBAR_BEREICHE))


def escape_zeichen(ch: str) -> str:
    """`\\xNN`, `\\uNNNN` oder `\\UNNNNNNNN` für ein Zeichen."""
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}"


def _t(text: object, grenze: int = MAX_TEXT) -> str:
    """Repo-stämmigen Text für Meldungen entschärfen: unsichtbare Zeichen (`unsichtbar`: Newline, ESC, Bidi, Zero-Width,
    Variation Selectors …) als Escape-Sequenz, Länge auf `grenze` Zeichen kappen. Meldungen fließen in den LLM-Kontext."""
    kurz = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
    aus = []
    for ch in str(text):
        o = ord(ch)
        if ch in kurz:
            aus.append(kurz[ch])
        elif 0xDC80 <= o <= 0xDCFF:                      # surrogateescape: ungültiges UTF-8 im Namen
            aus.append(f"\\x{o - 0xDC00:02x}")
        elif unsichtbar(ch):
            aus.append(escape_zeichen(ch))
        else:
            aus.append(ch)
    ergebnis = "".join(aus)
    return ergebnis if len(ergebnis) <= grenze else ergebnis[:grenze] + "…"


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
        if e.groesse > MAX_SYMLINK_GROESSE:
            return None, "Symlink-Ziel zu lang"
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

def arbeitskopie(repo: str, ziel: str, rev: str = "HEAD") -> list[str]:
    """Stand des Commits `rev` (Standard HEAD, besser der im Bericht genannte Hash) als rohe Blobs nach `ziel` schreiben;
    Rückgabe: Meldungen (deutsch).

    Wirft GitFehler, wenn der Commit nicht lesbar ist, ValueError bei ungültiger Revision."""
    baum = _baum(repo, rev)
    eintraege = {e.pfad: e for e in baum}
    ordner = {"/".join(e.pfad.split("/")[:i]) for e in baum for i in range(1, len(e.pfad.split("/")))}
    os.makedirs(ziel, exist_ok=True)
    wurzel = os.path.realpath(ziel)
    meldungen: list[str] = []
    namen = _Namensraum()

    with _Batch(repo) as batch:
        for e in baum:
            if frist_erschoepft():
                meldungen.append("Arbeitskopie unvollständig: Zeitbudget erschöpft; alle weiteren Dateien fehlen")
                break
            pfad = e.pfad
            p = _t(pfad)
            grund = _pfad_problem(pfad)
            if grund:
                meldungen.append(f"Pfad übersprungen: {p} ({grund})")
                continue
            if e.art == "commit" or e.modus == "160000":
                meldungen.append(f"Submodul nicht kopiert: {p}")
                continue
            if _env_datei(pfad):
                meldungen.append(f"Übersprungen (.env-Datei): {p}")
                continue
            if e.modus == "120000" and e.groesse > MAX_SYMLINK_GROESSE:
                meldungen.append(f"Symlink übersprungen: {p} (Symlink-Ziel zu lang: {e.groesse} Bytes)")
                continue
            try:
                inhalt = batch.lies(e.sha)
                if inhalt is None:
                    meldungen.append(f"Objekt fehlt, übersprungen: {p}")
                    continue
                herkunft = ""
                if e.modus == "120000":
                    text = os.fsdecode(inhalt)
                    t = _t(text)
                    ziel_blob, grund = _symlink_ziel(pfad, text, eintraege, ordner, batch)
                    if ziel_blob is None:
                        meldungen.append(f"Symlink übersprungen: {p} -> {t} ({grund})")
                        continue
                    if _pfad_problem(ziel_blob.pfad) or _env_datei(ziel_blob.pfad):
                        meldungen.append(f"Symlink übersprungen: {p} -> {t} "
                                         f"(Ziel {_t(ziel_blob.pfad)} ist gesperrt)")
                        continue
                    inhalt = batch.lies(ziel_blob.sha)
                    if inhalt is None:
                        meldungen.append(f"Symlink übersprungen: {p} -> {t} (Ziel-Objekt fehlt)")
                        continue
                    herkunft = (f"Symlink {p} -> {t} als normale Datei kopiert "
                                f"(Inhalt von {_t(ziel_blob.pfad)})")
                    ausfuehrbar = False
                elif e.art == "blob":
                    ausfuehrbar = bool(int(e.modus, 8) & 0o100)
                else:
                    meldungen.append(f"Eintrag übersprungen: {p} (Typ {_t(e.art)})")
                    continue
                erster = namen.kollision(pfad)
                if erster:
                    meldungen.append(f"Namenskollision: {p} kollidiert mit {_t(erster)}; übersprungen")
                    continue
                _schreibe(wurzel, pfad, inhalt, ausfuehrbar)
                namen.belege(pfad)
                if herkunft:
                    meldungen.append(herkunft)
                if inhalt.startswith(LFS_PREFIX):
                    meldungen.append(f"LFS-Pointer: {p} (nur der Pointer wurde kopiert, nicht der Inhalt)")
            except OSError as err:
                meldungen.append(f"Schreiben fehlgeschlagen: {p} ({_t(err)})")
            except GitFehler as err:
                # Der Batch-Strom ist nach einem Fehler nicht mehr verlässlich: abbrechen, nicht raten.
                meldungen.append(f"Arbeitskopie unvollständig: git cat-file abgebrochen bei {p} ({_t(err)}); "
                                 f"alle weiteren Dateien fehlen")
                break
    return meldungen


# ------------------------------------------------------------------------------------ Konfiguration

def repo_konfiguration(repo: str, rev: str = "HEAD") -> list[str]:
    """Im Commit `rev` versionierte Claude-/MCP-Konfiguration (auch verschachtelt); wirft GitFehler ohne lesbaren Commit."""
    ausgabe = git(repo, "ls-tree", "-r", "-z", "--name-only", "--full-tree", _commit(repo, rev), timeout=120).stdout
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
    """Git-Blob-Hash der Datei hinter `fd`; None, wenn sie nicht genau `groesse` Bytes hat. Liest höchstens `groesse + 1`
    Bytes: eine Datei, die beim Lesen weiter wächst, ergibt None statt einer Endlosschleife."""
    h = hashlib.new(algo)
    h.update(b"blob %d\0" % groesse)
    gelesen = 0
    while gelesen <= groesse:
        stueck = os.read(fd, min(1 << 20, groesse - gelesen + 1))
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
            raise GitFehler(f"git ls-files: unerwartete Zeile {rec!r}")
        name = os.fsdecode(pfad)
        if teile[2] != b"0":
            konflikte.append(name)
        else:
            index[name] = (teile[0].decode(), teile[1].decode())
    return index, konflikte


def repo_hinweise(repo: str, rev: str = "HEAD") -> list[str]:
    """Hinweise zum Repo (deutsch), bezogen auf den Commit `rev`; git-/Datei-Fehler und Timeouts werden zu Hinweisen, nie zum
    Abbruch (eine ungültige Schreibweise von `rev` ist ein Programmierfehler und wirft ValueError)."""
    hinweise: list[str] = []
    try:
        baum = _baum(repo, rev)
    except GitFehler as e:
        return [f"Kein HEAD lesbar, Prüfung nicht möglich: {_t(e)}"]

    eintraege = {e.pfad: e for e in baum}
    namen = _Namensraum()
    for e in baum:
        if e.art == "commit" or e.modus == "160000":
            hinweise.append(f"Submodul: {_t(e.pfad)} (nicht in der Arbeitskopie)")
            continue
        erster = namen.kollision(e.pfad)
        if erster:
            hinweise.append(f"Namenskollision: {_t(e.pfad)} und {_t(erster)} (gleicher Name nach NFC/casefold)")
        else:
            namen.belege(e.pfad)

    fehlend: list[str] = []
    try:
        with _Batch(repo) as batch:
            for e in baum:
                if e.modus == "120000":
                    if e.groesse > MAX_SYMLINK_GROESSE:
                        hinweise.append(f"Symlink: {_t(e.pfad)} (Symlink-Ziel zu lang: {e.groesse} Bytes)")
                        continue
                    inhalt = batch.lies(e.sha)
                    ziel = _t(os.fsdecode(inhalt)) if inhalt is not None else "?"
                    hinweise.append(f"Symlink: {_t(e.pfad)} -> {ziel}")
                elif e.art == "blob" and e.groesse <= LFS_MAX_GROESSE:
                    inhalt = batch.lies(e.sha)
                    if inhalt is None:
                        fehlend.append(e.pfad)
                    elif inhalt.startswith(LFS_PREFIX):
                        hinweise.append(f"LFS-Pointer: {_t(e.pfad)} (Inhalt liegt nicht im Repo)")
    except (GitFehler, OSError) as err:
        hinweise.append(f"Prüfung von Symlinks und LFS-Pointern nicht möglich: {_t(err)}")
    if fehlend:
        hinweise.append(f"Objekte fehlen im Repo (Partial Clone ohne Lazy Fetch?): {len(fehlend)} Dateien, "
                        f"z. B. {_t(fehlend[0])}; LFS-Prüfung für sie nicht möglich")

    try:
        index, konflikte = _index(repo)
    except GitFehler as err:
        hinweise.append(f"Index nicht lesbar, Prüfung auf Änderungen nicht möglich: {_t(err)}")
        return hinweise
    for pfad in konflikte:
        hinweise.append(f"Merge-Konflikt im Index: {_t(pfad)}")
    for pfad, (modus, sha) in sorted(index.items()):
        kopf = eintraege.get(pfad)
        if kopf is None:
            hinweise.append(f"Gestagt hinzugefügt (nicht in HEAD): {_t(pfad)}")
        elif (kopf.modus, kopf.sha) != (modus, sha):
            hinweise.append(f"Gestagte Änderung gegenüber HEAD: {_t(pfad)}")
    for pfad in sorted(eintraege):
        if pfad not in index and eintraege[pfad].art == "blob":
            hinweise.append(f"Gestagt gelöscht (in HEAD, nicht im Index): {_t(pfad)}")

    try:
        algo = "sha256" if git(repo, "rev-parse", "--show-object-format").stdout.strip() == b"sha256" else "sha1"
    except GitFehler as err:
        hinweise.append(f"Objektformat nicht ermittelbar, Prüfung auf Änderungen im Arbeitsbaum "
                        f"nicht möglich: {_t(err)}")
        return hinweise

    wurzel = os.path.realpath(repo)
    ordner_ok: dict[str, bool] = {}
    kandidaten = [(pfad, ms) for pfad, ms in sorted(index.items()) if ms[0] in DATEI_MODI]
    ende = time.monotonic() + HINWEIS_BUDGET
    if _ENDE is not None:
        ende = min(ende, _ENDE)
    for geprueft, (pfad, (modus, sha)) in enumerate(kandidaten):
        if time.monotonic() > ende:
            hinweise.append(f"Prüfung auf Änderungen im Arbeitsbaum abgebrochen (Zeitbudget {HINWEIS_BUDGET} s): "
                            f"{geprueft} von {len(kandidaten)} Dateien geprüft")
            break
        voll = os.path.join(wurzel, pfad)
        eltern = os.path.dirname(voll)
        if eltern not in ordner_ok:
            real = os.path.realpath(eltern)
            ordner_ok[eltern] = os.path.commonpath([real, wurzel]) == wurzel
        if not ordner_ok[eltern]:
            hinweise.append(f"Typ im Arbeitsbaum geändert (Elternordner führt aus dem Repo): {_t(pfad)}")
            continue
        try:
            st = os.lstat(voll)
            if not stat.S_ISREG(st.st_mode):
                hinweise.append(f"Typ im Arbeitsbaum geändert (keine normale Datei mehr): {_t(pfad)}")
                continue
            fd = os.open(voll, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    hinweise.append(f"Typ im Arbeitsbaum geändert (keine normale Datei mehr): {_t(pfad)}")
                    continue
                aktuell = _blob_hash(algo, fd, fst.st_size)
            finally:
                os.close(fd)
        except FileNotFoundError:
            hinweise.append(f"Im Arbeitsbaum gelöscht: {_t(pfad)}")
            continue
        except OSError as err:
            hinweise.append(f"Datei im Arbeitsbaum nicht prüfbar: {_t(pfad)} ({_t(err)})")
            continue
        if aktuell != sha:
            hinweise.append(f"Uncommittete Änderung im Arbeitsbaum: {_t(pfad)}")
    return hinweise


# ------------------------------------------------------------------------------------ Spiegel für die Secret-Prüfung

def _refs(repo: str) -> set[str]:
    ausgabe = git(repo, "for-each-ref", "--format=%(refname)", timeout=120).stdout
    return {os.fsdecode(z) for z in ausgabe.split(b"\n") if z}


def spiegel(repo: str, ziel: str, frist: float) -> list[str]:
    """Spiegelklon (`git clone --mirror --no-local`) der Repo-Wurzel `repo` nach `ziel` (darf nicht existieren), damit Werkzeuge
    die Historie in einem Repo mit frischer Konfiguration lesen: kein Filter, kein Textconv, kein Fsmonitor und kein Hook aus der
    Konfiguration des Kundenrepos. Der Klon läuft als eigene Prozessgruppe mit `werkzeug_umgebung()` und höchstens `frist`
    Sekunden. Rückgabe: Hinweise (deutsch) zu Refs, die im Spiegel fehlen (z. B. `transfer.hideRefs`), und zu einer flachen
    Quelle. Wirft ZeitbudgetFehler bei Fristablauf, GitFehler bei Fehlschlag; ein Teilklon bleibt dann liegen (der Aufrufer
    löscht `ziel`)."""
    if frist <= 0:
        raise ZeitbudgetFehler("git clone --mirror: Zeitbudget erschöpft, nicht gestartet")
    quelle = os.path.realpath(repo)
    elternordner = os.path.dirname(os.path.realpath(ziel))
    r = werkzeug_ausfuehren(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "clone", "--mirror",
                             "--no-local", "--quiet", "--", quelle, ziel], frist, elternordner)
    if r.rc is None:
        raise ZeitbudgetFehler(f"git clone --mirror: Zeitbudget erschöpft (Timeout nach {frist:g} s)")
    if r.rc != 0:
        raise GitFehler(f"git clone --mirror fehlgeschlagen (Exit {r.rc}): {_t(r.err.decode(errors='replace').strip(), 200)}",
                        r.rc, r.err)
    hinweise: list[str] = []
    fehlend = sorted(_refs(quelle) - _refs(ziel))
    if fehlend:
        hinweise.append(f"Refs fehlen im Spiegel: {len(fehlend)} (z. B. {_t(fehlend[0])}); ihre Historie wurde nicht geprüft "
                        f"(versteckt per transfer.hideRefs/uploadpack.hideRefs?)")
    if git(quelle, "rev-parse", "--is-shallow-repository").stdout.strip() == b"true":
        hinweise.append("Quelle ist flach (shallow): ältere Historie fehlt, Secret-Prüfung der Historie unvollständig")
    return hinweise
