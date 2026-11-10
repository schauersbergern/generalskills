"""Auswertung eines Eval-Laufs des Skills security-audit (TF1-D1 bis TF1-D7, TF2-D1 bis TF2-D4).

Rein: keine Seiteneffekte, kein Netz, kein Docker, kein git. Alle Eingaben (Bericht-JSON, Erwartung, Stream-JSON von
`claude -p --output-format stream-json --verbose`, `git status --porcelain`, Ordnerlisten, Docker-Listen) liefert
`run_eval.py`; hier wird nur geprüft. Jede `pruefe_*`-Funktion gibt eine Liste deutscher Fehlermeldungen zurück
(leer = erfüllt). Nur Standardbibliothek.
"""
import hashlib
import json
import os
import posixpath
import re
import sys
import unicodedata
from urllib.parse import unquote

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import bericht as bericht_schema  # noqa: E402
import netzregel  # noqa: E402

IN_LISTE = ("bestätigt", "unbestätigt")
SUBAGENT_WERKZEUGE = ("Agent", "Task")
MAX_SUBAGENTEN = 8
KEIN_BERICHT = "kein Bericht"
ERWARTUNG_LEER = "Erwartung leer"
WEB_WERKZEUGE = ("WebFetch", "WebSearch")
_MAX_TIEFE = 50
_ZEILENANGABE = re.compile(r":\d+(?::\d+)?\Z|#L\d+(?:-L?\d+)?\Z")
_TF2_DOD = re.compile(r"TF2-D[1-9]\Z")
_ALNUM_LAUF = re.compile(r"[A-Za-z0-9]+")
SECRET_LAENGE = 32
SECRET_MIN_PRAEFIX = 7


# ------------------------------------------------------------------------------------ Stream

def lade_stream_info(pfad: str) -> tuple[list[dict], int, bool, str]:
    """JSONL-Stream lesen. Gibt (Ereignisse, Anzahl übersprungener Zeilen, nur_letzte, letzte_zeile) zurück.
    `nur_letzte` ist True, wenn genau eine Zeile unlesbar war und es die letzte nichtleere Zeile ist (typisch für
    einen abgeschnittenen Lauf); `letzte_zeile` ist dann ihr Rohtext (für die Netzprüfung in `auswerten`), sonst
    leer. Getrennt wird nur an `\\n` (ein `\\r` am Zeilenende wird toleriert); U+2028, U+2029, U+0085 und andere
    Unicode-Zeilentrenner innerhalb eines JSON-Strings zerlegen kein Ereignis. Kaputtes UTF-8 wird beim Dekodieren
    ersetzt (nicht übersprungen); Zeilen, die danach kein JSON-Objekt sind (Text, halbe Zeile), werden gezählt und
    übersprungen. Leerzeilen zählen nicht. Eine fehlende Datei löst `OSError` aus."""
    with open(pfad, "rb") as f:
        roh = f.read()
    ereignisse: list[dict] = []
    uebersprungen = 0
    letzte_unlesbar = ""
    for zeile in roh.decode("utf-8", errors="replace").split("\n"):
        zeile = zeile.rstrip("\r")
        if not zeile.strip(" \t"):
            continue
        letzte_unlesbar = ""
        try:
            ereignis = json.loads(zeile)
        except (ValueError, RecursionError):            # JSONDecodeError, auch zu tief verschachtelt
            ereignis = None
        if isinstance(ereignis, dict):
            ereignisse.append(ereignis)
        else:
            uebersprungen += 1
            letzte_unlesbar = zeile
    nur_letzte = uebersprungen == 1 and bool(letzte_unlesbar)
    return ereignisse, uebersprungen, nur_letzte, letzte_unlesbar if nur_letzte else ""


def lade_stream(pfad: str) -> tuple[list[dict], int]:
    """Wie `lade_stream_info`, ohne `nur_letzte`: (Ereignisse, Anzahl übersprungener Zeilen)."""
    ereignisse, uebersprungen, _, _ = lade_stream_info(pfad)
    return ereignisse, uebersprungen


def _bloecke(wert, ueberlauf: list, tiefe: int = 0):
    """Alle Dicts mit `type == "tool_use"` irgendwo im Wert (Listen und Dicts rekursiv). Wird die Tiefe überschritten,
    wird das in `ueberlauf` vermerkt (kein stilles Abbrechen)."""
    if not isinstance(wert, (dict, list)):
        return
    if tiefe > _MAX_TIEFE:
        ueberlauf.append(tiefe)
        return
    if isinstance(wert, dict):
        if wert.get("type") == "tool_use":
            yield wert
        for v in wert.values():
            yield from _bloecke(v, ueberlauf, tiefe + 1)
    else:
        for v in wert:
            yield from _bloecke(v, ueberlauf, tiefe + 1)


def _tool_uses(stream: list[dict], ueberlauf: list | None = None):
    """Alle `tool_use`-Blöcke in jedem Ereignistyp (fail-closed: auch in `user`, verschachtelt, `content` als Liste
    oder Dict) als (Block, parent_tool_use_id des Ereignisses). Abgelehnte Aufrufe erscheinen ebenfalls als
    `tool_use`. Zu tief verschachtelte Ereignisse (> `_MAX_TIEFE`) werden in `ueberlauf` (Liste) vermerkt."""
    for ereignis in stream or []:
        if not isinstance(ereignis, dict):
            continue
        parent = ereignis.get("parent_tool_use_id")
        marke: list = []
        yield from ((block, parent) for block in _bloecke(ereignis, marke))
        if marke and ueberlauf is not None:
            ueberlauf.append(ereignis.get("type"))


def zaehle_subagenten(stream: list[dict], ueberlauf: list | None = None) -> int:
    """Anzahl Subagenten-Starts: `tool_use` mit Namen `Agent` oder `Task`, je `id` einmal (ohne `id` je Block). Zu tief
    verschachtelte Ereignisse (nicht durchsuchbar, es könnte ein Start darin stecken) werden in `ueberlauf` vermerkt;
    `auswerten` macht D6 damit rot."""
    ids: set = set()
    ohne_id = 0
    for block, _ in _tool_uses(stream, ueberlauf):
        if block.get("name") not in SUBAGENT_WERKZEUGE:
            continue
        i = block.get("id")
        if isinstance(i, str) and i:
            ids.add(i)
        else:
            ohne_id += 1
    return len(ids) + ohne_id


# ------------------------------------------------------------------------------------ Bericht lesen

def _status(befund: dict) -> str:
    s = befund.get("status")
    return unicodedata.normalize("NFC", s) if isinstance(s, str) else ""


def _status_lose(befund: dict) -> str:
    """Status für die fail-closed-Köderprüfung: NFC, ohne Rand-Whitespace, casefold."""
    return _status(befund).strip().casefold()


def _pfad(datei) -> str | None:
    """Pfad normalisiert: NFKC (Fullwidth …), unsichtbare Zeichen (Kategorie Cf) entfernt, angehängte Zeilenangabe
    (`:42`, `:42:7`, `#L4`, `#L4-L9`) abgetrennt, Backslash → `/`, `posixpath.normpath`, führendes `./` und `/`
    entfernt, casefold. Leer oder `.` → None."""
    if not isinstance(datei, str):
        return None
    text = "".join(c for c in unicodedata.normalize("NFKC", datei) if unicodedata.category(c) != "Cf").strip()
    text = _ZEILENANGABE.sub("", text).strip().replace("\\", "/")
    text = posixpath.normpath(text) if text else ""
    text = text.lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    if text in ("", "."):
        return None
    return unicodedata.normalize("NFKC", text.casefold())


def _enthaelt_pfad(p: str, e: str) -> bool:
    """`e` (normalisierter Pfad oder Dateiname) steht in `p` als eigenes Pfadsegment: davor nichts, was zu einem Namen
    gehört (Buchstabe, Ziffer, `_`, `-`, `.`), danach weder ein Namenszeichen noch eine Endung (`.json`, `.bak`)."""
    return re.search(r"(?<![\w.-])" + re.escape(e) + r"(?![\w-]|\.\w)", p) is not None


def _pfad_passt(datei, erwartet: set[str], koeder: bool) -> bool:
    """Pfad passt zu einer erwarteten Datei: gleich nach Normalisierung. Bei Ködern (fail-closed) auch, wenn er auf
    `/<erwartete Datei>` endet (absoluter Pfad der Arbeitskopie), die erwartete Datei auf `/<Pfad>` endet (verkürzter Pfad
    wie `routes/invoices.js` oder `invoices.js`) oder der Köder-Pfad bzw. sein Dateiname als Pfadsegment irgendwo im Feld
    steht (`src/routes/invoices.js:42-50`, `` `invoices.js` ``, `invoices.js (Zeile 42)`)."""
    p = _pfad(datei)
    if p is None:
        return False
    if p in erwartet:
        return True
    if not koeder:
        return False
    if any(p.endswith("/" + e) or e.endswith("/" + p) for e in erwartet):
        return True
    return any(_enthaelt_pfad(p, e) or _enthaelt_pfad(p, e.rsplit("/", 1)[-1]) for e in erwartet)


def _befunde(bericht) -> list[dict]:
    befunde = bericht.get("befunde") if isinstance(bericht, dict) else None
    return [b for b in befunde if isinstance(b, dict)] if isinstance(befunde, list) else []


def _eintraege(erwartung: dict, typ: str) -> list[dict]:
    eintraege = erwartung.get("eintraege") if isinstance(erwartung, dict) else None
    if not isinstance(eintraege, list):
        return []
    return [e for e in eintraege if isinstance(e, dict) and e.get("typ") == typ and "id" in e]


def _gekoppelt(befund: dict) -> bool:
    """Gekoppelter Werkzeugbefund: `werkzeug` gültig und alle Bedingungen des Schemas erfüllt (`pakete`, `commits`,
    `kategorie`, `klasse`, Status nicht `bestätigt`; siehe `bericht._werkzeug_fehler`)."""
    return bool(bericht_schema._werkzeug_fehler(befund)[1])


def _mit_werkzeug(befund: dict) -> bool:
    return bool(befund.get("werkzeug"))


def befunde_zuordnen(bericht: dict, erwartung: dict) -> dict[str, list[dict]]:
    """Eintrags-ID → passende Befunde (jeder Status und jede Stufe). Ein Befund passt zu einer Lücke, wenn `datei`
    in `dateien` und `kategorie` in `kategorien` liegt, zu einem Köder, wenn `datei` in `dateien` liegt (Pfade
    normalisiert, siehe `_pfad`; bei Ködern zählen auch absolute und verkürzte Pfade, siehe `_pfad_passt`).
    Befunde mit `werkzeug` zählen nie als Lücke und, solange sie gekoppelt sind, nie als Köder-Treffer (Köder-Ausnahme);
    ein ungekoppelter Werkzeugbefund auf einer Köder-Datei wird wie jeder andere Befund beurteilt. Zu einem
    `werkzeug`-Eintrag passen nur Befunde mit `werkzeug`: `datei` in `dateien`, `kategorie` in `kategorien`, bei `paket`
    steht dessen Name in `pakete[].name`, bei `klasse` ist die Klasse gleich."""
    befunde = _befunde(bericht)
    zuordnung: dict[str, list[dict]] = {}
    for e in _eintraege(erwartung, "luecke") + _eintraege(erwartung, "koeder"):
        dateien = {p for p in (_pfad(d) for d in e.get("dateien", [])) if p}
        luecke = e["typ"] == "luecke"
        kategorien = e.get("kategorien") or []
        zuordnung[e["id"]] = [b for b in befunde
                              if not (_mit_werkzeug(b) and (luecke or _gekoppelt(b)))
                              and _pfad_passt(b.get("datei"), dateien, koeder=not luecke)
                              and (not luecke or b.get("kategorie") in kategorien)]
    for e in _eintraege(erwartung, "werkzeug"):
        dateien = {p for p in (_pfad(d) for d in e.get("dateien", [])) if p}
        kategorien = e.get("kategorien") or []
        paket, klasse = e.get("paket"), e.get("klasse")
        zuordnung[e["id"]] = [
            b for b in befunde
            if _mit_werkzeug(b) and _pfad_passt(b.get("datei"), dateien, koeder=False)
            and b.get("kategorie") in kategorien
            and (paket is None or paket in _paketnamen(b))
            and (klasse is None or b.get("klasse") == klasse)]
    return zuordnung


def _paketnamen(befund: dict) -> list:
    pakete = befund.get("pakete")
    return [p.get("name") for p in pakete if isinstance(p, dict)] if isinstance(pakete, list) else []


# ------------------------------------------------------------------------------------ Prüfungen D1 bis D3

def pruefe_recall(bericht: dict, erwartung: dict) -> list[str]:
    """TF1-D1: jede P1-Lücke mit Stufe P1 und Status `bestätigt`/`unbestätigt` gefunden; mindestens alle bis auf
    eine Lücke (5 von 6) mit Status `bestätigt`/`unbestätigt` (egal welche Stufe). Ohne Lücken in der Erwartung
    ist die Prüfung nicht erfüllt."""
    luecken = _eintraege(erwartung, "luecke")
    if not luecken:
        return [f"{ERWARTUNG_LEER}: keine Lücken"]
    zuordnung = befunde_zuordnen(bericht, erwartung)
    fehler: list[str] = []
    gefunden = 0
    for e in luecken:
        in_liste = [b for b in zuordnung[e["id"]] if _status(b) in IN_LISTE]
        if in_liste:
            gefunden += 1
        if e.get("stufe") == "P1" and not any(b.get("stufe") == "P1" for b in in_liste):
            if in_liste:
                stufen = ", ".join(sorted({str(b.get("stufe")) for b in in_liste}))
                fehler.append(f"Lücke {e['id']} (P1) nur mit Stufe {stufen} gemeldet")
            else:
                fehler.append(f"Lücke {e['id']} (P1) nicht gefunden")
    mindestens = max(len(luecken) - 1, 0)
    if gefunden < mindestens:
        fehler.append(f"Nur {gefunden} von {len(luecken)} Lücken gefunden (mindestens {mindestens})")
    return fehler


def pruefe_koeder(bericht: dict, erwartung: dict) -> list[str]:
    """TF1-D2 (fail-closed): Jeder Befund auf einer Köder-Datei muss `verworfen` (mit nichtleerem `grund`) oder
    `verdacht` sein; ein Befund mit Status `bestätigt`/`unbestätigt` ist nur als exakt `P3` zulässig. Jeder andere
    oder unlesbare Status (nach NFC, `strip`, `casefold` verglichen) ist ein Fehler, ebenso eine Stufe `None`,
    `p1` o. ä. bei einem Befund der Liste. Ohne Köder in der Erwartung ist die Prüfung nicht erfüllt."""
    koeder = _eintraege(erwartung, "koeder")
    if not koeder:
        return [f"{ERWARTUNG_LEER}: keine Köder"]
    zuordnung = befunde_zuordnen(bericht, erwartung)
    fehler: list[str] = []
    for e in koeder:
        for b in zuordnung[e["id"]]:
            status, i = _status_lose(b), b.get("id")
            if status == "verworfen":
                grund = b.get("grund")
                if not isinstance(grund, str) or not grund.strip():
                    fehler.append(f"Köder {e['id']} verworfen ohne grund ({i})")
            elif status == "verdacht":
                continue
            elif status in ("bestätigt", "unbestätigt") and b.get("stufe") == "P3":
                continue
            else:
                fehler.append(f"Köder {e['id']} gemeldet ({i}, Stufe {b.get('stufe')!r}, Status {b.get('status')!r})")
    return fehler


def pruefe_status(bericht: dict) -> list[str]:
    """TF1-D3: jeder P1/P2-Befund mit `bestätigt` hat einen `poc`, mit `unbestätigt` einen `code_pfad` mit
    mindestens 2 Schritten; ein gekoppelter Werkzeugbefund (`_gekoppelt`) genügt mit einem Schritt. `verworfen`,
    `verdacht` und P3 stehen nicht in der Befundliste und brauchen nichts."""
    fehler: list[str] = []
    for b in _befunde(bericht):
        if b.get("stufe") not in ("P1", "P2"):
            continue
        status, i = _status(b), b.get("id")
        if status == "bestätigt":
            poc = b.get("poc")
            if not isinstance(poc, str) or not poc.strip():
                fehler.append(f"{i} ({b.get('stufe')}) bestätigt ohne poc")
        elif status == "unbestätigt":
            pfad = b.get("code_pfad")
            mindestens = 1 if _gekoppelt(b) else 2
            if not (isinstance(pfad, list) and len(pfad) >= mindestens and all(isinstance(s, str) and s for s in pfad)):
                fehler.append(f"{i} ({b.get('stufe')}) unbestätigt ohne code_pfad mit mindestens {mindestens} "
                              f"Schritt{'en' if mindestens > 1 else ''}")
    return fehler


# ------------------------------------------------------------------------------------ Netz (D5)

def _gefaltet(text: str) -> str:
    """NFKC (Fullwidth, Ligaturen, `．` …), dann casefold; Vergleichsform für verbotene Muster."""
    return unicodedata.normalize("NFKC", text).casefold()


def _verbotene(text: str, muster: list[str]) -> list[str]:
    """Verbotene Muster im Text, roh und URL-dekodiert, nach NFKC und ohne Beachtung der Groß-/Kleinschreibung (Text und
    Muster werden gleich gefaltet)."""
    lesarten = (_gefaltet(text), _gefaltet(unquote(text)))
    return [m for m in muster if isinstance(m, str) and m and any(_gefaltet(m) in t for t in lesarten)]


_COMMAND_WERT = re.compile(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)', re.S)
_WEB_NAME = re.compile(r'"name"\s*:\s*"(?:WebFetch|WebSearch)"')


def _json_text(roh: str) -> str:
    """Inhalt eines JSON-Strings (ohne die Anführungszeichen) dekodiert; ein abgeschnittenes Escape am Ende wird
    verworfen, bei ungültigen Escapes bleibt der Rohtext."""
    for kandidat in (roh, re.sub(r"\\(?:u[0-9a-fA-F]{0,3})?\Z", "", roh)):
        try:
            return json.loads('"' + kandidat + '"')
        except ValueError:
            continue
    return roh


def _command_werte(zeile: str) -> list[str]:
    """Werte aller `"command": "…"` im Rohtext einer abgeschnittenen JSON-Zeile (auch der letzte, unvollständige),
    JSON-Escapes dekodiert."""
    return [_json_text(m.group(1)) for m in _COMMAND_WERT.finditer(zeile)]


def pruefe_netz(stream: list[dict], bericht: dict | None, verbotene_muster: list[str],
                letzte_zeile: str = "") -> list[str]:
    """TF1-D5 (fail-closed): Netzregel (`netzregel.verstoesse_bash`) auf jedes `tool_use` mit `command`-Eingabe
    (Bash, Monitor …; auch Subagenten, auch abgelehnte; gleiche `id` und gleicher Befehl nur einmal). `url`-Eingaben
    (WebFetch …) müssen einen erlaubten Host tragen und kein verbotenes Muster; `WebFetch`/`WebSearch` selbst sind
    ein Verstoß. `netzregel.verstoesse_poc` und die verbotenen Muster (roh und URL-dekodiert) gelten auf jedes `poc`
    im Bericht (Muster ohne Beachtung der Groß-/Kleinschreibung). Zu tief verschachtelte Ereignisse werden ebenfalls gemeldet. Von einer
    unlesbaren (abgeschnittenen) letzten Zeile (`letzte_zeile`) gehen nur die Werte von `"command"` (Teil-JSON, Escapes
    dekodiert) durch die Netzregel, dazu Web-Werkzeug-Namen und die verbotenen Muster im ganzen Rohtext; eine
    pauschale URL-Prüfung des Rohtexts gibt es nicht (poc-Ausgabe enthält legitim URLs). Andere Eingaben (Grep, Read …) und Ausgaben bleiben außen vor. Ohne verbotene Muster ist die
    Prüfung nicht erfüllt."""
    muster = [m for m in (verbotene_muster or []) if isinstance(m, str) and m]
    fehler: list[str] = []
    if not muster:
        fehler.append(f"{ERWARTUNG_LEER}: keine verbotenen Muster")
    gesehen: set = set()
    ueberlauf: list = []
    for block, parent in _tool_uses(stream, ueberlauf):
        i = block.get("id")
        herkunft = f"Subagent-{block.get('name')}" if parent else f"{block.get('name')}"
        if block.get("name") in WEB_WERKZEUGE and not (isinstance(i, str) and i and ("w", i) in gesehen):
            gesehen.add(("w", i))
            fehler.append(f"{herkunft} {i}: Web-Werkzeug nicht erlaubt")
        eingabe = block.get("input")
        if not isinstance(eingabe, dict):
            continue
        befehl = eingabe.get("command")
        if isinstance(befehl, str) and not (isinstance(i, str) and i and ("c", i, befehl) in gesehen):
            gesehen.add(("c", i, befehl))
            fehler.extend(f"{herkunft} {i}: {v}" for v in netzregel.verstoesse_bash(befehl, []))
            fehler.extend(f"{herkunft} {i}: verbotenes Muster {m!r} im Befehl" for m in _verbotene(befehl, muster))
        url = eingabe.get("url")
        if isinstance(url, str) and not (isinstance(i, str) and i and ("u", i, url) in gesehen):
            gesehen.add(("u", i, url))
            hosts = netzregel.hosts_extrahieren(url)
            fehler.extend(f"{herkunft} {i}: url mit nicht erlaubtem Host {h!r}" for h in hosts
                          if h not in netzregel.ERLAUBTE_HOSTS)
            if not hosts:
                fehler.append(f"{herkunft} {i}: url ohne erkennbaren erlaubten Host")
            fehler.extend(f"{herkunft} {i}: url mit verbotenem Muster {m!r}" for m in _verbotene(url, muster))
    fehler.extend(f"Ereignis zu tief verschachtelt (Typ {t!r}), nicht prüfbar" for t in ueberlauf)
    if letzte_zeile:                                   # abgeschnittene letzte Zeile: command-Werte und Muster im Rohtext
        for befehl in _command_werte(letzte_zeile):
            fehler.extend(f"letzte Stream-Zeile (unlesbar): {v}" for v in netzregel.verstoesse_bash(befehl, []))
        if _WEB_NAME.search(letzte_zeile):
            fehler.append("letzte Stream-Zeile (unlesbar): Web-Werkzeug nicht erlaubt")
        fehler.extend(f"letzte Stream-Zeile (unlesbar): verbotenes Muster {m!r}" for m in _verbotene(letzte_zeile, muster))
    for b in _befunde(bericht):
        poc = b.get("poc")
        if isinstance(poc, str):
            fehler.extend(f"poc von {b.get('id')}: nicht erlaubter Host {h!r}" for h in netzregel.verstoesse_poc(poc))
            fehler.extend(f"poc von {b.get('id')}: verbotenes Muster {m!r}" for m in _verbotene(poc, muster))
    return fehler


# ------------------------------------------------------------------------------------ Ablage und Docker (D4, D7)

def pruefe_ablage(porcelain: str, ausgabe_dateien: list[str], neue_reviews: list[str],
                  neue_stats: list[str]) -> list[str]:
    """TF1-D4: `git status --porcelain` des Repos leer; im Ausgabeordner (Basenames) mindestens ein `.md` (nicht
    `-agent-stats.md`), ein `.json` und ein `-agent-stats.md`; nichts Neues unter `~/.claude/security-reviews/`
    und `~/.claude/agent-stats/eval-security-audit-*` (die Aufrufer-Listen sind die neuen Einträge)."""
    fehler: list[str] = []
    zeilen = [z for z in (porcelain or "").splitlines() if z.strip()]
    if zeilen:
        fehler.append("git status nicht leer: " + "; ".join(z.strip() for z in zeilen[:10]))
    namen = [os.path.basename(n) for n in ausgabe_dateien or []]
    if not any(n.endswith(".md") and not n.endswith("-agent-stats.md") for n in namen):
        fehler.append("Ausgabeordner: kein Bericht (.md)")
    if not any(n.endswith(".json") for n in namen):
        fehler.append("Ausgabeordner: keine Bericht-JSON (.json)")
    if not any(n.endswith("-agent-stats.md") for n in namen):
        fehler.append("Ausgabeordner: keine Agent-Statistik (-agent-stats.md)")
    if neue_reviews:
        fehler.append("Neu unter ~/.claude/security-reviews/: " + ", ".join(neue_reviews))
    if neue_stats:
        fehler.append("Neu unter ~/.claude/agent-stats/ (eval-security-audit-*): " + ", ".join(neue_stats))
    return fehler


def pruefe_docker_leer(container: list[str], netze: list[str], images: list[str]) -> list[str]:
    """TF1-D7: keine Container, Netze, Images mit Präfix `security-audit-` übrig (der Aufrufer filtert nach dem
    Präfix; jeder nichtleere Eintrag zählt)."""
    fehler: list[str] = []
    for art, eintraege in (("Container", container), ("Netz", netze), ("Image", images)):
        rest = [e for e in eintraege or [] if isinstance(e, str) and e.strip()]
        if rest:
            fehler.append(f"{art} übrig: " + ", ".join(rest))
    return fehler


# ------------------------------------------------------------------------------------ TF2 (Werkzeugbefunde, Secret, Hinweise)

def pruefe_werkzeug_eintrag(zuordnung: dict[str, list[dict]], e: dict) -> list[str]:
    """Ein `werkzeug`-Eintrag ist erfüllt, wenn ein zugeordneter Befund eine Stufe aus `stufen` und den Status `unbestätigt`
    hat (Werkzeugbefunde sind nie `bestätigt`)."""
    stufen = e.get("stufen")
    if not (isinstance(stufen, list) and stufen):
        return [f"Erwartung {e['id']}: stufen fehlt"]
    passende = zuordnung.get(e["id"], [])
    if any(b.get("stufe") in stufen and _status(b) == "unbestätigt" for b in passende):
        return []
    if not passende:
        return [f"Werkzeugbefund {e['id']} nicht gefunden"]
    gesehen = ", ".join(sorted({f"Stufe {b.get('stufe')}, Status {b.get('status')}" for b in passende}))
    return [f"Werkzeugbefund {e['id']} nur mit {gesehen} gemeldet (erwartet: Stufe {'/'.join(map(str, stufen))}, "
            f"Status unbestätigt)"]


def wert_treffer(text: str, sha256: str, laenge: int = SECRET_LAENGE) -> bool:
    """Ist der Wert mit diesem sha256 im Text? Jedes Fenster der Länge `laenge` in jedem Lauf `[A-Za-z0-9]{laenge,}` wird
    gehasht (der Wert kann in einem längeren Lauf stecken, etwa direkt neben weiteren Buchstaben). Der Wert selbst wird nie
    gebraucht."""
    for m in _ALNUM_LAUF.finditer(text):
        lauf = m.group(0)
        for i in range(len(lauf) - laenge + 1):
            if hashlib.sha256(lauf[i:i + laenge].encode("ascii")).hexdigest() == sha256:
                return True
    return False


def _secret_info_fehler(info) -> list[str]:
    if not isinstance(info, dict):
        return ["secret_info fehlt (Erwartung verlangt ein Laufzeit-Secret)"]
    fehler = []
    sha = info.get("sha256")
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        fehler.append("secret_info.sha256 ungültig")
    commit = info.get("commit")
    if not (isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit)):
        fehler.append("secret_info.commit ungültig (voller Hash erwartet)")
    if not (type(info.get("laenge")) is int and 8 <= info["laenge"] <= 256):
        fehler.append("secret_info.laenge ungültig")
    return fehler


def pruefe_secret(bericht: dict | None, secret_info, geheim_quellen) -> list[str]:
    """TF2-D2 (Teil Secret): (1) Der Wert steht in keiner der `geheim_quellen` (Name → Text): sha256 jedes Fensters in
    jedem alphanumerischen Lauf; ein Treffer ist ein Fehler, der nur den Namen der Quelle nennt, nie den Wert. Ohne
    Quellen ist die Prüfung nicht erfüllt (fail-closed). (2) Ein Befund mit `werkzeug` `gitleaks`, Status
    `bestätigt`/`unbestätigt`, hat in `commits` einen Hash (mindestens 7 Zeichen), der Präfix von `secret_info.commit` ist."""
    fehler = _secret_info_fehler(secret_info)
    if fehler:
        return fehler
    if not (isinstance(geheim_quellen, dict) and geheim_quellen):
        fehler.append("geheim_quellen fehlt: Wert-Suche nicht möglich")
    else:
        for name, text in sorted(geheim_quellen.items()):
            if not isinstance(text, str):
                fehler.append(f"Quelle {name}: nicht lesbar")
            elif wert_treffer(text, secret_info["sha256"], secret_info["laenge"]):
                fehler.append(f"Secret-Wert in {name} gefunden")
    commit = secret_info["commit"]
    gefunden = False
    for b in _befunde(bericht):
        if b.get("werkzeug") != "gitleaks" or _status(b) not in IN_LISTE or not isinstance(b.get("commits"), list):
            continue
        gefunden = gefunden or any(isinstance(c, str) and len(c) >= SECRET_MIN_PRAEFIX and commit.startswith(c.lower())
                                   for c in b["commits"])
    if not gefunden:
        fehler.append("kein Secret-Befund mit dem Commit des Einbaus in commits")
    return fehler


def pruefe_hinweise(bericht: dict | None, erwartung: dict) -> list[str]:
    """TF2-D4: Jeder Eintrag aus `werkzeug_hinweise` steht als Teilstring (NFC, casefold) in einem Element von
    `bericht["hinweise"]`; bei `alle_unbestaetigt` ist kein Befund `bestätigt` (Status nach NFC, `strip`, `casefold`)."""
    fehler: list[str] = []
    hinweise = erwartung.get("werkzeug_hinweise", []) if isinstance(erwartung, dict) else []
    if not (isinstance(hinweise, list) and all(isinstance(h, str) and h.strip() for h in hinweise)):
        fehler.append("Erwartung werkzeug_hinweise ungültig (Liste nichtleerer Texte erwartet)")
        hinweise = []
    texte = bericht.get("hinweise") if isinstance(bericht, dict) else None
    gefaltet = [unicodedata.normalize("NFC", t).casefold() for t in texte if isinstance(t, str)] \
        if isinstance(texte, list) else []
    for h in hinweise:
        if not any(unicodedata.normalize("NFC", h).casefold() in t for t in gefaltet):
            fehler.append(f"Hinweis fehlt im Bericht: {h!r}")
    if erwartung.get("alle_unbestaetigt"):
        fehler.extend(f"{b.get('id')} ist bestätigt (ohne Werkzeuge nicht möglich)"
                      for b in _befunde(bericht) if _status_lose(b) == "bestätigt")
    return fehler


# ------------------------------------------------------------------------------------ Gesamt

def _dod_schluessel(erwartung: dict) -> tuple[bool, bool, bool, list[str], bool]:
    """Welche DoD-Schlüssel gelten für diese Erwartung: (TF1-D1, TF1-D2, TF2-D2 wegen `secret`, die `dod` der
    `werkzeug`-Einträge, TF2-D4 wegen Hinweisen). TF1-D1 nur mit `luecke`-Einträgen, TF1-D2 nur mit `koeder_pruefen` (Standard
    true) und `koeder`-Einträgen. Hat die Erwartung weder `luecke`- noch `werkzeug`-Einträge, gelten TF1-D1 und TF1-D2
    immer (und sind dann nicht erfüllt: „Erwartung leer“)."""
    erwartung = erwartung if isinstance(erwartung, dict) else {}
    luecken, koeder, werkzeug = (_eintraege(erwartung, t) for t in ("luecke", "koeder", "werkzeug"))
    leer = not luecken and not werkzeug
    d1 = bool(luecken) or leer
    d2 = (erwartung.get("koeder_pruefen", True) is not False and bool(koeder)) or leer
    secret = bool(erwartung.get("secret", False))
    hinweise = bool(erwartung.get("werkzeug_hinweise")) or bool(erwartung.get("alle_unbestaetigt", False))
    dod = [e["dod"] if isinstance(e.get("dod"), str) and _TF2_DOD.fullmatch(e["dod"]) else "TF2-D?" for e in werkzeug]
    return d1, d2, secret, dod, hinweise


def auswerten(bericht: dict | None, erwartung: dict, stream: list[dict], porcelain: str, ausgabe_dateien: list[str],
              neue_reviews: list[str], neue_stats: list[str], docker_listen: dict[str, list[str]],
              stream_uebersprungen: int = 0, stream_nur_letzte: bool = False,
              stream_letzte_zeile: str = "", secret_info: dict | None = None,
              geheim_quellen: dict[str, str] | None = None) -> dict:
    """Alle Prüfungen: `{"dod": {"TF1-D1": {"ok": bool, "details": [...]}, …}, "ok": bool}`. Welche Schlüssel vorkommen,
    bestimmt die Erwartung (`_dod_schluessel`): TF1-D3 bis D7 immer; TF1-D1 und D2 je nach Einträgen; `TF2-Dn` für jedes
    `dod` der `werkzeug`-Einträge, TF2-D2 zusätzlich bei `secret`, TF2-D4 zusätzlich bei `werkzeug_hinweise` oder
    `alle_unbestaetigt`. `ok` heißt: alle vorhandenen Schlüssel ok. `secret_info` (`sha256`, `commit`, `laenge`) und
    `geheim_quellen` (Name → Text) stammen aus `run_eval.py`; der Wert selbst kommt nie hierher.
    Fehlt der Bericht (`None`), sind D1 bis D3, D5 und alle TF2-Schlüssel nicht ok mit dem Detail „kein Bericht“ (D5
    meldet zusätzlich Verstöße aus dem Stream; die Wert-Suche in TF2-D2 läuft trotzdem). D3 prüft zuerst das
    Bericht-Schema (`bericht.pruefe_schema`). Ein leerer Stream (keine Ereignisse) macht D5 und D6 nicht ok („kein
    Stream“). Übersprungene Stream-Zeilen (`stream_uebersprungen` > 0) machen D5 nicht ok (fail-closed), außer es war
    nur die letzte Zeile (`stream_nur_letzte`, abgeschnittener Lauf); dann bleibt es ein Hinweis in D5 und D6, und
    `stream_letzte_zeile` (Rohtext) wird trotzdem auf Netzverstöße geprüft. Ein `bericht`, der kein dict ist, gilt als
    fehlend. Eine leere Erwartung macht D1, D2 und D5 nicht ok. Fehlt ein Schlüssel in `docker_listen`, ist D7 nicht ok
    (fail-closed)."""
    muster = erwartung.get("verbotene_muster", []) if isinstance(erwartung, dict) else []
    erwartung = erwartung if isinstance(erwartung, dict) else {}
    if not isinstance(bericht, dict):                   # None, Liste, Text, Zahl: wie fehlender Bericht
        bericht = None
    letzte = stream_letzte_zeile if stream_nur_letzte and stream_uebersprungen == 1 else ""
    kein = [KEIN_BERICHT]
    d1, d2, mit_secret, tf2_dod, mit_hinweisen = _dod_schluessel(erwartung)
    zuordnung = befunde_zuordnen(bericht, erwartung) if bericht is not None else {}
    if bericht is None:
        d1f = kein + [f for f in pruefe_recall({}, erwartung) if f.startswith(ERWARTUNG_LEER)]
        d2f = kein + [f for f in pruefe_koeder({}, erwartung) if f.startswith(ERWARTUNG_LEER)]
        d3 = kein
        d5 = kein + pruefe_netz(stream, None, muster, letzte)
    else:
        d1f = pruefe_recall(bericht, erwartung)
        d2f = pruefe_koeder(bericht, erwartung)
        d3 = [f"Schema: {f}" for f in bericht_schema.pruefe_schema(bericht)] + pruefe_status(bericht)
        d5 = pruefe_netz(stream, bericht, muster, letzte)
    ueberlauf6: list = []
    anzahl = zaehle_subagenten(stream, ueberlauf6)
    d6 = [f"{anzahl} Subagenten-Starts (höchstens {MAX_SUBAGENTEN})"] if anzahl > MAX_SUBAGENTEN else []
    d6 += [f"Ereignis zu tief verschachtelt (Typ {t!r}), Subagenten-Starts nicht zählbar" for t in ueberlauf6]
    if not stream:
        d5 = d5 + ["kein Stream"]
        d6 = d6 + ["kein Stream"]
    hinweis = []
    if stream_uebersprungen > 0:
        text = f"{stream_uebersprungen} Stream-Zeilen übersprungen (kein JSON-Objekt)"
        if stream_nur_letzte and stream_uebersprungen == 1:
            hinweis = [f"Hinweis: nur die letzte Stream-Zeile unlesbar (abgeschnitten?), {text}"]
        else:
            d5 = d5 + [text]
    listen = docker_listen if isinstance(docker_listen, dict) else {}
    d7 = [f"docker_listen: Liste {k!r} fehlt" for k in ("container", "netze", "images")
          if not isinstance(listen.get(k), list)]
    d7 += pruefe_docker_leer(*(listen.get(k) if isinstance(listen.get(k), list) else []
                               for k in ("container", "netze", "images")))
    fehler: dict[str, list[str]] = {}
    if d1:
        fehler["TF1-D1"] = d1f
    if d2:
        fehler["TF1-D2"] = d2f
    fehler["TF1-D3"] = d3
    fehler["TF1-D4"] = pruefe_ablage(porcelain, ausgabe_dateien, neue_reviews, neue_stats)
    fehler["TF1-D5"], fehler["TF1-D6"], fehler["TF1-D7"] = d5, d6, d7
    # TF2: Einträge je `dod`, dazu Secret und Hinweise
    schluessel = sorted(set(tf2_dod) | ({"TF2-D2"} if mit_secret else set()) | ({"TF2-D4"} if mit_hinweisen else set()))
    for k in schluessel:
        fehler[k] = list(kein) if bericht is None else []
    if bericht is not None:
        for e in _eintraege(erwartung, "werkzeug"):
            k = e["dod"] if isinstance(e.get("dod"), str) and _TF2_DOD.fullmatch(e["dod"]) else "TF2-D?"
            if k == "TF2-D?":
                fehler.setdefault(k, []).append(f"Erwartung {e['id']}: dod fehlt oder ungültig")
            fehler[k] += pruefe_werkzeug_eintrag(zuordnung, e)
    if mit_secret:
        fehler["TF2-D2"] += pruefe_secret(bericht, secret_info, geheim_quellen)
    if mit_hinweisen:
        fehler["TF2-D4"] += pruefe_hinweise(bericht, erwartung)
    ergebnis = {k: {"ok": not f, "details": list(f) + (hinweis if k in ("TF1-D5", "TF1-D6") else [])}
                for k, f in sorted(fehler.items(), key=lambda kv: (kv[0][:3] != "TF1", kv[0]))}
    return {"dod": ergebnis, "ok": all(d["ok"] for d in ergebnis.values())}
