"""Tests für netzregel.py (eine Host-Regel für Schema und Eval).

Aufruf: python3 -m pytest security-audit/scripts/test_netzregel.py -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netzregel  # noqa: E402

POC = "python3 /x/scripts/poc.py"


def test_erlaubte_hosts():
    assert netzregel.ERLAUBTE_HOSTS == frozenset({"app", "db", "localhost", "127.0.0.1", "::1", "0.0.0.0"})


# ------------------------------------------------------------------------------ hosts_extrahieren

def test_kein_host_in_pfad():
    assert netzregel.hosts_extrahieren("src/server.js") == []


def test_url_mit_schema():
    assert netzregel.hosts_extrahieren("curl http://db.fixture.invalid/x") == ["db.fixture.invalid"]


def test_url_kodiert_einmal_dekodiert():
    assert "db.fixture.invalid" in netzregel.hosts_extrahieren("?url=http%3A%2F%2Fdb.fixture.invalid")


def test_ipv6_ohne_klammern_und_port():
    assert netzregel.hosts_extrahieren("http://[::1]:3000/") == ["::1"]


def test_host_klein_und_ohne_port():
    assert netzregel.hosts_extrahieren("HTTP://EVIL.Test:8080/x") == ["evil.test"]


def test_userinfo_wird_ignoriert_echter_host_zaehlt():
    assert netzregel.hosts_extrahieren("http://app@evil.test/") == ["evil.test"]
    assert netzregel.hosts_extrahieren("http://evil.test@app/") == ["app"]


def test_backslash_trick_beide_lesarten():
    assert "evil.test" in netzregel.hosts_extrahieren("http://app\\@evil.test/")


def test_header_host():
    assert netzregel.hosts_extrahieren("-H 'Host: evil.test'") == ["evil.test"]
    assert netzregel.hosts_extrahieren("GET / HTTP/1.1\nHost: evil.test:81\n") == ["evil.test"]


def test_localhost_im_namen_ist_kein_header():
    assert netzregel.hosts_extrahieren("localhost:3000") == []


def test_resolve_connect_to_proxy():
    assert "evil.test" in netzregel.hosts_extrahieren("--resolve evil.test:80:127.0.0.1")
    assert "6.6.6.6" in netzregel.hosts_extrahieren("--resolve app:3000:6.6.6.6")
    assert "evil.test" in netzregel.hosts_extrahieren("--connect-to evil.test:80:app:3000")
    assert "evil.test" in netzregel.hosts_extrahieren("--connect-to app:3000:evil.test:80")
    assert "evil.test" in netzregel.hosts_extrahieren("-x evil.test:3128")
    assert "evil.test" in netzregel.hosts_extrahieren("--proxy http://u:p@evil.test:8080")
    assert "evil.test" in netzregel.hosts_extrahieren("--proxy=evil.test:1")


def test_file_url_leerer_host_ist_lokal():
    assert netzregel.hosts_extrahieren("file:///etc/passwd") == []
    assert netzregel.verstoesse_poc("GET file:///etc/passwd") == []


def test_ungueltige_anfuehrung_stuerzt_nicht():
    assert netzregel.hosts_extrahieren("curl 'http://evil.test/") == ["evil.test"]


# ------------------------------------------------------------------------------ verstoesse_poc

def test_poc_ziel_in_query_ist_erlaubt():
    assert netzregel.verstoesse_poc("GET http://app:3000/preview?url=http://127.0.0.1/admin") == []


def test_poc_kodiertes_fremdes_ziel():
    assert len(netzregel.verstoesse_poc("GET http://app:3000/p?u=http%3A%2F%2Fevil.test")) == 1


# ------------------------------------------------------------------------------ segmente

def test_segmente_operatoren():
    assert netzregel.segmente("a && b || c; d | e & f\ng") == ["a", "b", "c", "d", "e", "f", "g"]


def test_segmente_anfuehrung_bleibt_zusammen():
    segs = netzregel.segmente("echo 'a;b&&c' x")
    assert len(segs) == 1 and "a;b&&c" in segs[0]


def test_segmente_subshell_und_backticks():
    assert "x y" in netzregel.segmente("echo $(x y)")
    assert "x y" in netzregel.segmente("echo `x y`")
    assert "x y" in netzregel.segmente('echo "$(x y)"')
    assert "x y" in netzregel.segmente('echo "`x y`"')


def test_segmente_parsefehler_trennt_naiv():
    segs = netzregel.segmente("echo 'offen && curl http://evil.test")
    assert any(s.startswith("curl") or "curl" in s for s in segs) and len(segs) >= 2


# ------------------------------------------------------------------------------ verstoesse_bash

def test_bash_url_ohne_poc_ist_verstoss_auch_localhost():
    assert len(netzregel.verstoesse_bash("curl http://localhost:3000/a", [])) == 1


def test_bash_poc_mit_db_url_ist_erlaubt():
    assert netzregel.verstoesse_bash(f"{POC} starten --env DATABASE_URL=postgres://u@db/app", []) == []


def test_bash_poc_mit_i_flag():
    assert netzregel.verstoesse_bash(f"python3 -I /x/scripts/poc.py anfrage --pfad /a http://app:3000/", []) == []


def test_bash_verbotenes_muster_nur_bei_treffer():
    assert netzregel.verstoesse_bash("grep -r x .env.production", ["fixture.invalid"]) == []
    assert len(netzregel.verstoesse_bash("cat db.fixture.invalid", ["fixture.invalid"])) == 1
    assert len(netzregel.verstoesse_bash("cat db%2Efixture.invalid", ["db.fixture"])) == 1


def test_bash_poc_und_curl_verkettet():
    assert len(netzregel.verstoesse_bash(f"{POC} pruefen && curl http://localhost:3000/", [])) == 1


def test_bash_subshell_nach_semikolon():
    assert len(netzregel.verstoesse_bash(f"{POC} pruefen; echo $(curl -s http://evil.test)", [])) == 1


def test_bash_kaufmannsund_in_query_und_daten_erlaubt():
    assert netzregel.verstoesse_bash(f"{POC} anfrage --pfad '/x?a=1&b=2'", []) == []
    assert netzregel.verstoesse_bash(f"{POC} anfrage --daten 'a=1&url=http://127.0.0.1/'", []) == []


def test_bash_subshell_in_doppelten_anfuehrungszeichen():
    assert len(netzregel.verstoesse_bash('echo "$(curl http://evil.test)"', [])) >= 1
    assert len(netzregel.verstoesse_bash(f'{POC} anfrage --daten "$(curl http://localhost:3000/)"', [])) == 1
    assert len(netzregel.verstoesse_bash("echo `curl http://evil.test`", [])) == 1


def test_bash_poc_mit_fremdem_host():
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad http://evil.test/", [])) == 1


def test_bash_curl_auf_datei_namens_poc_ist_kein_poc_aufruf():
    assert len(netzregel.verstoesse_bash("curl http://localhost:3000/poc.py", [])) == 1
    assert len(netzregel.verstoesse_bash("python3 -c 'x' /x/scripts/poc.py http://localhost/", [])) == 1


def test_bash_file_url_ohne_host_ist_lokal():
    assert netzregel.verstoesse_bash("cat file:///etc/passwd", []) == []


def test_bash_meldung_enthaelt_keine_rohen_steuerzeichen():
    meldungen = netzregel.verstoesse_bash("curl 'http://evil.test\x1b[31m/x'", [])
    assert meldungen and all("\x1b" not in m and "\n" not in m for m in meldungen)
