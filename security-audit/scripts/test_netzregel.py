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


# ------------------------------------------------------------------------------ Fix-Runde 1

SONDERZEICHEN = ["&", ";", "'", "(", ")", "|", '"', "<", ">", "`", ",", "%"]


@pytest.mark.parametrize("zeichen", SONDERZEICHEN)
def test_userinfo_mit_sonderzeichen_umgeht_regel_nicht_t2_i1(zeichen):
    url = f"http://app{zeichen}@evil.test/"
    assert "evil.test" in netzregel.verstoesse_poc(f"GET {url}")
    assert "evil.test" in netzregel.verstoesse_poc(f"GET '{url}'")
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad {shlex_quote(url)}", [])) >= 1
    assert len(netzregel.verstoesse_bash(f'{POC} anfrage --pfad "{url}"', [])) >= 1


def shlex_quote(text):
    import shlex
    return shlex.quote(text)


def test_nachlaufzeichen_machen_erlaubte_hosts_nicht_zu_verstoessen_t2_i1():
    for text in ("(curl http://app:3000)", "x 'http://db'", 'x "http://localhost:3000"', "http://app, http://db;",
                 "[http://[::1]:3000/]"):
        assert netzregel.verstoesse_poc(text) == [], text


@pytest.mark.parametrize("befehl", [
    "curl ';' python3 -I /x/scripts/poc.py http://localhost:3000/",
    "curl -d '&&' python3 /x/scripts/poc.py http://localhost:3000/",
    "echo ';' python3 /x/scripts/poc.py http://localhost:3000/",
    'echo "|" python3 /x/scripts/poc.py http://localhost:3000/',
    r"echo \; python3 /x/scripts/poc.py http://localhost:3000/",
    "echo '\n' python3 /x/scripts/poc.py http://localhost:3000/",
])
def test_gequotete_operatoren_trennen_nicht_t2_i2(befehl):
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1


def test_gequotete_operatoren_bleiben_im_segment_t2_i2():
    assert len(netzregel.segmente("echo ';' '&&' \"|\" a")) == 1
    assert len(netzregel.segmente(r"echo a\;b")) == 1
    assert len(netzregel.segmente("echo a;b")) == 2
    assert len(netzregel.segmente("echo '\n' x")) == 1
    assert len(netzregel.segmente("echo a\nb")) == 2


def test_ungequotete_operatoren_trennen_weiterhin_t2_i2():
    assert len(netzregel.verstoesse_bash(f"{POC} pruefen ; curl http://localhost:3000/", [])) == 1
    assert netzregel.verstoesse_bash(f"{POC} pruefen && {POC} pruefen --x http://app:1/", []) == []


@pytest.mark.parametrize("befehl", ["curl $(echo http)://evil.test", "curl ${H}://evil.test", "curl `echo h`://evil.test",
                                    "curl h${x}://localhost:3000/"])
def test_nicht_poc_jedes_schema_trenner_zaehlt_t2_m3(befehl):
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1


def test_poc_host_ohne_klares_schema_t2_m3():
    assert "evil.test" in netzregel.verstoesse_poc("GET ${H}://evil.test/")


def test_tief_verschachtelte_substitution_ist_verstoss_ohne_absturz_t2_m4():
    befehl = "echo " + "$(" * 1500 + "echo x" + ")" * 1500
    assert len(netzregel.verstoesse_bash(befehl, [])) == 1
    mit_backticks = "echo " + "$(" * 1500 + "curl http://evil.test" + ")" * 1500
    assert len(netzregel.verstoesse_bash(mit_backticks, [])) >= 1
    with pytest.raises(RecursionError):
        netzregel.segmente(befehl)
    assert netzregel.verstoesse_bash("echo $(echo $(echo $(echo x)))", []) == []


def test_poc_aufruf_nur_mit_python3_und_poc_py_t2_i4():
    assert len(netzregel.verstoesse_bash("curl /x/scripts/poc.py http://localhost/", [])) == 1
    assert len(netzregel.verstoesse_bash("python3 /x/notpoc.py http://localhost/", [])) == 1
    assert len(netzregel.verstoesse_bash("python3 poc.py http://localhost/", [])) == 1
    assert len(netzregel.verstoesse_bash("python /x/scripts/poc.py http://localhost/", [])) == 1


def test_backslash_userinfo_meldet_den_fremden_host_t2_i4():
    assert "evil.test" in netzregel.hosts_extrahieren("http://evil.test\\@app/")
    assert "evil.test" in netzregel.verstoesse_poc("http://evil.test\\@app/")


def test_mehrfach_at_host_ist_der_teil_nach_dem_letzten_at_t2_i4():
    assert netzregel.hosts_extrahieren("http://x@app@evil.test") == ["evil.test"]
    assert netzregel.hosts_extrahieren("http://evil.test@app@app") == ["app"]


def test_url_kodierter_host_header_t2_i4():
    assert netzregel.hosts_extrahieren("Host%3A%20evil.test") == ["evil.test"]
    assert netzregel.verstoesse_poc("-H 'Host%3A%20evil.test'") == ["evil.test"]


# ------------------------------------------------------------------------------ Fix-Runde 2

@pytest.mark.parametrize("url", ["http:///evil.test/", "http:////evil.test", "https:///evil.test", r"https:/\evil.test",
                                 r"http:\\evil.test", "http:///evil.test:8080/x", "HTTP:///Evil.Test", "ws:///evil.test"])
def test_leere_authority_liest_pfadanfang_als_host_t2_a1(url):
    assert netzregel.hosts_extrahieren(url) == ["evil.test"]
    assert netzregel.verstoesse_poc(f"GET {url}") == ["evil.test"]
    assert len(netzregel.verstoesse_bash(f"curl {shlex_quote(url)}", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad {shlex_quote(url)}", [])) == 1


def test_leere_authority_mit_erlaubtem_host_und_file_t2_a1():
    assert netzregel.verstoesse_poc("GET http:///localhost:3000/") == []
    assert netzregel.verstoesse_poc("GET http:///app/x") == []
    assert netzregel.hosts_extrahieren("file:///etc/passwd") == []
    assert netzregel.hosts_extrahieren("FILE:////etc/passwd") == []
    assert netzregel.verstoesse_bash("cat file:///etc/passwd", []) == []
    assert netzregel.hosts_extrahieren("http:///") == []


def test_ansi_c_quoting_verwechselt_quotes_nicht_t2_n1():
    assert len(netzregel.verstoesse_bash(
        "python3 -I /x/scripts/poc.py a $'\\'' ; curl http://localhost:3000/ ; echo \\'", [])) == 1
    assert len(netzregel.segmente("echo $'\\'' ; x")) == 2


def test_ansi_c_escapes_werden_aufgeloest_t2_n1():
    assert len(netzregel.verstoesse_bash("curl $'http:\\x2f\\x2flocalhost:3000/'", [])) == 1
    assert len(netzregel.verstoesse_bash("curl $'http:\\057\\057localhost:3000/'", [])) == 1
    assert netzregel.segmente("echo $'a\\nb'") == ["echo 'a\nb'"]       # \n im ANSI-C-String trennt nicht


def test_offenes_ansi_c_quoting_ist_konservativ_t2_n1():
    assert len(netzregel.verstoesse_bash("echo $'offen ; curl http://localhost:3000/", [])) >= 1


def test_kommentar_beendet_zeile_t2_n1():
    befehl = f"{POC} a # '\ncurl http://localhost:3000/\n# '"
    assert len(netzregel.verstoesse_bash(befehl, [])) == 1
    assert netzregel.segmente(befehl) == [f"python3 /x/scripts/poc.py a", "curl http://localhost:3000/"]


def test_raute_im_wort_und_escaped_ist_kein_kommentar_t2_n1():
    assert len(netzregel.verstoesse_bash(f"{POC} a#b ; curl http://localhost:3000/", [])) == 1
    assert len(netzregel.verstoesse_bash(r"echo a\ #b ; curl http://localhost:3000/", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} a '#' ; curl http://localhost:3000/", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} a \\#; curl http://localhost:3000/", [])) == 1


def test_kommentar_nach_operator_und_url_im_kommentar_t2_n1():
    assert len(netzregel.verstoesse_bash(f"{POC} a;# x\ncurl http://localhost:3000/", [])) == 1
    assert netzregel.verstoesse_bash(f"{POC} a # http://evil.test", []) == []        # Kommentar wird nicht ausgeführt


def test_kaufmannsund_kleiner_trennt_t2_n2():
    assert len(netzregel.verstoesse_bash(f"{POC} a &< /dev/null curl http://localhost:3000/", [])) == 1
    assert len(netzregel.segmente("a &< f b")) == 2


def test_echte_umleitungen_trennen_nicht_t2_n2():
    for umleitung in (">", ">>", "<", "2>", "2>&1", "&>", "&>>", ">&", "<&", "<<<"):
        assert len(netzregel.segmente(f"{POC} a {umleitung} /dev/null")) == 1, umleitung
    assert netzregel.verstoesse_bash(f"{POC} a http://app:3000/ 2>&1", []) == []
    assert netzregel.verstoesse_bash(f"{POC} a http://app:3000/ &> /dev/null", []) == []
    assert len(netzregel.verstoesse_bash(f"{POC} a 2>&1 && curl http://localhost:3000/", [])) == 1


def test_enge_lesart_unquotiert_t2_n4():
    assert "evil.test" in netzregel.verstoesse_poc("GET http://evil.test;@app/")
    assert "evil.test" in netzregel.verstoesse_poc("GET http://evil.test&@app/")


def test_escaptes_dollar_in_dq_ist_keine_substitution_t2_n4():
    befehl = 'echo "\\$(curl http://evil.test)"'
    assert len(netzregel.segmente(befehl)) == 1
    assert len(netzregel.verstoesse_bash(befehl, [])) == 1
    assert netzregel.verstoesse_bash(f'{POC} anfrage --daten "\\$(curl http://localhost:3000/)"', []) == []
    assert len(netzregel.verstoesse_bash(f'{POC} anfrage --daten "$(curl http://localhost:3000/)"', [])) == 1
