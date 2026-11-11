"""Tests für `lieferkette.py lieferkette` (TF2, Task 3): statische Lieferketten-Prüfung ohne Werkzeug, Kindprozess und Netz.

Aufruf: python3 -m pytest security-audit/scripts/test_lieferkette_statisch.py -q

Alle Testdaten (Lockfiles, Dockerfiles, Workflows) entstehen zur Laufzeit in tmp_path; im Repo liegt kein Lockfile mit
verwundbaren Versionen. Der Unterbefehl startet keine Kindprozesse; die Tests enthalten keine Signal- oder Kill-Logik.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import pytest

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HIER)
import bericht  # noqa: E402
import lieferkette  # noqa: E402

LIEFERKETTE = os.path.join(HIER, "lieferkette.py")
LAUF = "0a1b2c3d"
BESCHREIBUNG_GRUND = "Werkzeugbefund, kein Request-Beleg möglich"
PKG = json.dumps({"name": "x", "dependencies": {"express": "^4.0.0"}})
NPM_LOCK = json.dumps({"name": "x", "lockfileVersion": 3, "packages": {"": {"name": "x"}}})


# ------------------------------------------------------------------------------------ Bausteine

class Umgebung:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.tmp = tmp_path / "tmp"
        self.tmp.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        os.makedirs(self.zustand(), mode=0o700)
        os.makedirs(self.quelle())
        open(os.path.join(self.zustand(), "quelle.fertig"), "w").close()

    def env(self, **extra):
        env = {"PATH": "/nonexistent", "HOME": str(self.home), "TMPDIR": str(self.tmp)}
        env.update(extra)
        return env

    def zustand(self):
        return os.path.join(os.path.realpath(self.tmp), f"security-audit-{LAUF}")

    def quelle(self):
        return os.path.join(self.zustand(), "quelle")

    def schreibe(self, rel, inhalt):
        ziel = os.path.join(self.quelle(), rel)
        os.makedirs(os.path.dirname(ziel), exist_ok=True)
        with open(ziel, "wb") as f:
            f.write(inhalt if isinstance(inhalt, bytes) else inhalt.encode())

    def lauf(self, *extra, env=None, quelle=None, timeout=120):
        return subprocess.run([sys.executable, "-I", LIEFERKETTE, "lieferkette", "--lauf", LAUF, "--quelle",
                               quelle or self.quelle(), *extra], env=env or self.env(), capture_output=True, text=True,
                              timeout=timeout)

    def ergebnis(self, **kw):
        r = self.lauf(**kw)
        assert r.returncode == 0, r.stdout + r.stderr
        return json.loads(r.stdout)

    def entwuerfe(self, klasse=None, **kw):
        alle = self.ergebnis(**kw)["entwuerfe"]
        return [e for e in alle if klasse is None or e["klasse"] == klasse]


@pytest.fixture
def umg(tmp_path):
    return Umgebung(tmp_path)


@pytest.fixture(autouse=True)
def hermetisch(tmp_path, monkeypatch):
    home = tmp_path / "home-inproc"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in list(os.environ):
        if name.startswith(("GIT_", "GITLEAKS_", "OSV_", "SECURITY_AUDIT_")):
            monkeypatch.delenv(name)


def npm_lock_mit_skripten(skript_namen, *, normale=("plain",)):
    """package-lock.json (lockfileVersion 3): je Name in `skript_namen` ein Paket mit `hasInstallScript: true`."""
    pk = {"": {"name": "x", "version": "1.0.0"}}
    for n in normale:
        pk[f"node_modules/{n}"] = {"version": "1.0.0"}
    for n in skript_namen:
        pk[f"node_modules/{n}"] = {"version": "2.0.0", "hasInstallScript": True}
    return json.dumps({"name": "x", "lockfileVersion": 3, "packages": pk}, indent=2) + "\n"


PNPM_LOCK_V6 = ("lockfileVersion: '6.0'\n\npackages:\n\n  /plain@1.0.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n\n"
                "  /esbuild@0.19.0:\n    resolution: {integrity: sha512-y}\n    requiresBuild: true\n    dev: true\n")
PNPM_LOCK_V9 = ("lockfileVersion: '9.0'\n\npackages:\n\n  esbuild@0.19.0:\n    resolution: {integrity: sha512-y}\n"
                "    engines: {node: '>=18'}\n\nsnapshots:\n\n  esbuild@0.19.0: {}\n")


def je_datei(entwuerfe):
    return {(e["datei"], e["zeile"]): e for e in entwuerfe}


# ------------------------------------------------------------------------------------ Entwurf: Form

def test_entwurf_hat_alle_pflichtfelder_ohne_id(umg):
    umg.schreibe("package.json", PKG)
    out = umg.ergebnis()
    assert set(out) == {"entwuerfe", "hinweise"}
    (e,) = out["entwuerfe"]
    assert "id" not in e
    assert e["kategorie"] == "A03" and e["werkzeug"] == "lieferkette" and e["status"] == "unbestätigt"
    assert e["klasse"] == "lockfile-fehlt" and e["stufe"] == "P2"
    assert e["datei"] == "package.json" and e["zeile"] == 1 and e["code_pfad"] == ["package.json:1"]
    assert BESCHREIBUNG_GRUND in e["beschreibung"]
    assert e["ohne_anmeldung"] is False and e["mandantenuebergreifend"] is False
    for feld in ("titel", "szenario", "erwartet"):
        assert isinstance(e[feld], str) and e[feld].strip() and "\n" not in e[feld]
    assert "Lockfile" in e["erwartet"]


def test_lieferkette_schreibt_nichts_und_braucht_keinen_zustand(umg):
    umg.schreibe("package.json", PKG)
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")

    def stand():
        h = hashlib.sha256()
        for ordner, unter, dateien in sorted(os.walk(umg.zustand())):
            unter.sort()
            for n in sorted(dateien):
                p = os.path.join(ordner, n)
                h.update(p.encode() + open(p, "rb").read())
        return h.hexdigest(), sorted(os.listdir(umg.zustand()))
    vorher = stand()
    umg.ergebnis()
    assert stand() == vorher                                          # nichts angelegt, nichts verändert (auch kein lieferkette/)


def test_lieferkette_quelle_ausserhalb_exit_2(umg, tmp_path):
    fremd = tmp_path / "fremd"
    fremd.mkdir()
    (fremd / "package.json").write_text(PKG)
    r = umg.lauf(quelle=str(fremd))
    assert r.returncode == 2 and r.stdout == ""
    assert "Arbeitskopie" in r.stderr


def test_lieferkette_ohne_fertig_marker_exit_2(umg):
    os.unlink(os.path.join(umg.zustand(), "quelle.fertig"))
    assert umg.lauf().returncode == 2


# ------------------------------------------------------------------------------------ lockfile-fehlt

def test_lockfile_fehlt_workspace_mit_root_lockfile_kein_befund(umg):
    umg.schreibe("package.json", json.dumps({"name": "root", "workspaces": ["packages/*"], "devDependencies": {"a": "1"}}))
    umg.schreibe("package-lock.json", NPM_LOCK)
    umg.schreibe("packages/a/package.json", PKG)
    umg.schreibe("packages/a/sub/tief/package.json", PKG)
    assert umg.entwuerfe("lockfile-fehlt") == []


def test_lockfile_fehlt_einzelnes_package_json_befund(umg):
    umg.schreibe("package.json", PKG)
    (e,) = umg.entwuerfe("lockfile-fehlt")
    assert e["datei"] == "package.json" and e["stufe"] == "P2"


def test_lockfile_fehlt_lockfile_im_unterordner_schuetzt_elternordner_nicht(umg):
    """Ein Lockfile im Unterordner schützt den Elternordner nicht."""
    umg.schreibe("package.json", PKG)
    umg.schreibe("app/package.json", PKG)
    umg.schreibe("app/yarn.lock", "# yarn lockfile v1\n")
    e = umg.entwuerfe("lockfile-fehlt")
    assert [x["datei"] for x in e] == ["package.json"]


@pytest.mark.parametrize("lockfile", ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
                                      "bun.lockb"])
def test_lockfile_fehlt_alle_lockfile_namen_zaehlen(umg, lockfile):
    umg.schreibe("package.json", PKG)
    umg.schreibe(lockfile, "")
    assert umg.entwuerfe("lockfile-fehlt") == []


def test_lockfile_fehlt_bun_lock_im_elternordner_zaehlt(umg):
    umg.schreibe("bun.lock", "{}")
    umg.schreibe("pkg/package.json", PKG)
    assert umg.entwuerfe("lockfile-fehlt") == []


@pytest.mark.parametrize("inhalt", [
    "{}", '{"name": "x", "version": "1.0.0"}', '{"dependencies": {}, "devDependencies": {}}',
    '{"dependencies": {}, "optionalDependencies": {}, "peerDependencies": {}, "scripts": {"a": "b"}}'])
def test_lockfile_fehlt_ohne_abhaengigkeiten_kein_befund(umg, inhalt):
    umg.schreibe("package.json", inhalt)
    assert umg.entwuerfe("lockfile-fehlt") == []


@pytest.mark.parametrize("feld", ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"])
def test_lockfile_fehlt_jede_abhaengigkeitsart_zaehlt(umg, feld):
    umg.schreibe("package.json", json.dumps({feld: {"a": "1"}}))
    assert len(umg.entwuerfe("lockfile-fehlt")) == 1


def test_lockfile_fehlt_unparsebares_package_json_gilt_als_mit_abhaengigkeiten(umg):
    umg.schreibe("package.json", "{ das ist kein json")
    (e,) = umg.entwuerfe("lockfile-fehlt")
    assert e["datei"] == "package.json"


def test_lockfile_fehlt_befund_im_unterordner_hat_relativen_pfad(umg):
    umg.schreibe("services/api/package.json", PKG)
    (e,) = umg.entwuerfe("lockfile-fehlt")
    assert e["datei"] == "services/api/package.json" and e["code_pfad"] == ["services/api/package.json:1"]


# ------------------------------------------------------------------------------------ installation-ohne-lockfile-treue

def test_installation_dockerfile_fortsetzung(umg):
    """W8/TF2-D3: Fortsetzungszeile mit `\\` ergibt einen Entwurf; `zeile` ist die erste physische Zeile."""
    umg.schreibe("Dockerfile", "FROM node:20\nRUN apt-get update && \\\n    npm install\nCMD [\"node\", \"x.js\"]\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == "Dockerfile" and e["zeile"] == 2 and e["code_pfad"] == ["Dockerfile:2"]
    assert e["stufe"] == "P2" and e["status"] == "unbestätigt" and e["werkzeug"] == "lieferkette"
    assert "`npm install`" in e["beschreibung"] and BESCHREIBUNG_GRUND in e["beschreibung"]
    assert "npm ci" in e["erwartet"]


def test_installation_dockerfile_mehrere_fortsetzungen_und_crlf(umg):
    umg.schreibe("Dockerfile", "FROM node\r\nRUN a && \\\r\n    b && \\\r\n    npm install\r\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 2


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.prod", "dockerfile", "DOCKERFILE.dev", "api.dockerfile",
                                  "Api.Dockerfile"])
def test_installation_dockerfile_namen(umg, name):
    umg.schreibe(f"build/{name}", "FROM node\nRUN npm install\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == f"build/{name}" and e["zeile"] == 2


@pytest.mark.parametrize("name", ["Makefile", "makefile", "GNUmakefile"])
def test_installation_makefile(umg, name):
    umg.schreibe(name, "all: install\n\ninstall:\n\t@npm install\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == name and e["zeile"] == 4


def test_installation_makefile_minus_praefix_und_variable(umg):
    umg.schreibe("Makefile", "a:\n\t-pnpm install\nb:\n\tNODE_ENV=prod yarn\n")
    e = je_datei(umg.entwuerfe("installation-ohne-lockfile-treue"))
    assert set(e) == {("Makefile", 2), ("Makefile", 4)}


def test_installation_package_json_scripts_zeile_des_schluessels(umg):
    umg.schreibe("package.json", '{\n  "name": "x",\n  "scripts": {\n    "build": "tsc",\n    "setup": "npm install && node x.js",\n'
                                 '    "ok": "npm ci"\n  }\n}\n')
    umg.schreibe("package-lock.json", NPM_LOCK)
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == "package.json" and e["zeile"] == 5 and e["code_pfad"] == ["package.json:5"]


def test_installation_package_json_nicht_scripts_werte_zaehlen_nicht(umg):
    umg.schreibe("package.json", json.dumps({"name": "npm install", "description": "yarn", "dependencies": {"a": "1"},
                                             "scripts": {"x": "echo npm install"}}))
    umg.schreibe("yarn.lock", "")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_installation_scripts_schluessel_fehlt_im_text_zeile_1(umg):
    """Der Schlüssel steht nur als Escape im Text: Fallback Zeile 1."""
    umg.schreibe("package.json", '{"scripts": {"se\\u0074up": "yarn"}}')
    umg.schreibe("pnpm-lock.yaml", "")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 1


NEGATIV = [
    "RUN npm install -g x", "RUN npm i --global x", "RUN npm install --package-lock-only", "RUN npm ci",
    "RUN npm ci --ignore-scripts", "RUN pnpm install --frozen-lockfile", "RUN pnpm i --frozen-lockfile",
    "RUN pnpm add express", "RUN yarn add express", "RUN yarn install --immutable", "RUN yarn install --frozen-lockfile",
    "RUN yarn --immutable", "RUN npm run build", "RUN npm test", "RUN yarn build", "RUN pnpm run build",
    "RUN echo npm install", "RUN echo 'x' > /tmp/npm", "COPY package.json package-lock.json ./", "CMD yarn",
    "ENTRYPOINT pnpm", "# RUN npm install", "RUN npm ci && npm run build", "RUN npm install-test-extra-nope-x",
    "RUN [\"npm\", \"ci\"]", "RUN [\"npm\", \"install\", \"-g\", \"x\"]", "RUN npx something", "RUN apt-get install -y npm",
    "ENV npm_config_install=1",
    # Review I4: Trenner in Anführungszeichen trennen nicht
    'RUN echo "see docs; npm install foo"', "RUN echo 'a && npm install'", 'RUN sh -c "echo hi; true"',
    'RUN ["/bin/sh","-c","echo npm install"]',
    # Review Minor: ausdrücklich lockfile-treu
    "RUN pnpm install --frozen-lockfile=true", "RUN yarn install --immutable=true", "RUN pnpm i --frozen-lockfile=1",
]


@pytest.mark.parametrize("zeile", NEGATIV)
def test_installation_negativfaelle_kein_befund(umg, zeile):
    umg.schreibe("Dockerfile", f"FROM node\n{zeile}\n")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


POSITIV = [
    ("RUN npm install", "`npm install`"), ("RUN npm i", "`npm i`"), ("RUN npm install express", "`npm install`"),
    ("RUN npm install --ignore-scripts", "`npm install`"), ("RUN pnpm install", "`pnpm install`"),
    ("RUN pnpm i", "`pnpm i`"), ("RUN pnpm", "nacktes `pnpm`"), ("RUN yarn", "nacktes `yarn`"),
    ("RUN yarn install", "`yarn install`"), ("RUN yarn install --check-files", "`yarn install`"),
    ('RUN ["npm","install"]', "`npm install`"), ('RUN ["pnpm", "i"]', "`pnpm i`"), ('RUN ["yarn"]', "nacktes `yarn`"),
    ("RUN FOO=bar npm install", "`npm install`"), ("RUN sudo npm install", "`npm install`"),
    ("RUN env A=1 B=2 npm install", "`npm install`"), ("RUN exec npm install", "`npm install`"),
    ("RUN --mount=type=cache,target=/root/.npm npm install", "`npm install`"),
    ("RUN cd /app; npm install", "`npm install`"), ("RUN true || npm install", "`npm install`"),
    ("RUN cd /app && pnpm", "nacktes `pnpm`"), ("ONBUILD RUN npm install", "`npm install`"),
    ("run npm install", "`npm install`"), ("RUN npm --prefix web install", "`npm install`"),
    ("RUN pnpm install --no-frozen-lockfile", "`pnpm install`"),
    # Review I4: sh -c / bash -c auch mit zusammengesetzten Befehlen, Exec-Form
    ('RUN sh -c "cd app && npm install"', "`npm install`"), ("RUN bash -c 'set -e; npm install'", "`npm install`"),
    ('RUN bash -o pipefail -c "npm install"', "`npm install`"),
    ('RUN ["/bin/bash", "-o", "pipefail", "-c", "npm install"]', "`npm install`"),
    ('RUN ["/bin/sh","-c","npm install"]', "`npm install`"), ('RUN ["/bin/sh", "-c", "cd a && yarn"]', "nacktes `yarn`"),
    ("RUN /bin/bash -lc 'cd x && pnpm install'", "`pnpm install`"), ("RUN sh -c \"sh -c 'npm install'\"", "`npm install`"),
    ("RUN echo ok && sh -c 'npm install'", "`npm install`"),
    # Review Minor: Tab, Kontrollwörter, Klammer, Präfixe, nicht treue Flags
    ("RUN\tnpm install", "`npm install`"), ("ONBUILD\tRUN npm install", "`npm install`"),
    ("RUN if [ -f p ]; then npm install; fi", "`npm install`"), ("RUN for d in a b; do npm install; done", "`npm install`"),
    ("RUN if x; then y; else npm install; fi", "`npm install`"), ("RUN (cd app && npm install)", "`npm install`"),
    ("RUN timeout 300 npm install", "`npm install`"), ("RUN timeout -s KILL 5m npm install", "`npm install`"),
    ("RUN sudo -u app npm install", "`npm install`"), ("RUN sudo -E npm install", "`npm install`"),
    ("RUN sudo -E -u app npm install", "`npm install`"),
    ("RUN pnpm install --frozen-lockfile=false", "`pnpm install`"), ("RUN yarn install --immutable=false", "`yarn install`"),
    ("RUN yarn install --frozen-lockfile=false", "`yarn install`"), ("RUN yarn --immutable=false", "nacktes `yarn`"),
]


@pytest.mark.parametrize("zeile,genannt", POSITIV)
def test_installation_positivfaelle_befund(umg, zeile, genannt):
    umg.schreibe("Dockerfile", f"FROM node\n{zeile}\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 2 and genannt in e["beschreibung"]


def test_installation_exec_form_nacktes_pnpm_und_yarn_im_dockerfile(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN pnpm\nRUN yarn\n")
    e = je_datei(umg.entwuerfe("installation-ohne-lockfile-treue"))
    assert set(e) == {("Dockerfile", 2), ("Dockerfile", 3)}
    assert "nacktes `pnpm`" in e[("Dockerfile", 2)]["beschreibung"] and "nacktes `yarn`" in e[("Dockerfile", 3)]["beschreibung"]


def test_installation_umgebungszuweisung_wert_nicht_in_der_ausgabe(umg):
    """Die Befehlszeile darf nie wörtlich in die Ausgabe (Token in der Zuweisung)."""
    umg.schreibe("Dockerfile", "FROM node\nRUN NPM_TOKEN=npm_geheimer-wert-4711 npm install --registry https://x.invalid\n")
    r = umg.lauf()
    assert r.returncode == 0
    out = json.loads(r.stdout)
    (e,) = [x for x in out["entwuerfe"] if x["klasse"] == "installation-ohne-lockfile-treue"]
    assert e["zeile"] == 2
    assert "geheimer-wert" not in r.stdout and "NPM_TOKEN" not in r.stdout and "x.invalid" not in r.stdout


def test_installation_hoechstens_ein_entwurf_je_datei_und_zeile(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install && yarn && pnpm install\nRUN npm i\n")
    e = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert sorted((x["datei"], x["zeile"]) for x in e) == [("Dockerfile", 2), ("Dockerfile", 3)]


def test_installation_befehlstrenner_pipe_und_semikolon(umg):
    umg.schreibe("Makefile", "a:\n\techo x | npm install\nb:\n\tfalse; yarn\n")
    assert len(umg.entwuerfe("installation-ohne-lockfile-treue")) == 2


def test_installation_ungueltiges_quoting_faellt_auf_leerzeichen_split_zurueck(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install \"offene anfuehrung\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 2


def test_installation_kommentar_mit_backslash_verbindet_nicht(umg):
    umg.schreibe("Dockerfile", "FROM node\n# Hinweis \\\nRUN npm install\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 3


def test_installation_heredoc_zeilen_im_dockerfile(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN <<EOF\nnpm install\nEOF\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["zeile"] == 3


# ------------------------------------------------------------------------------------ CI (W8)

WORKFLOW = "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: {befehl}\n"


def test_ci_workflow_npm_install_befund(umg):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="npm install"))
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == ".github/workflows/ci.yml" and e["zeile"] == 8


def test_ci_workflow_yaml_endung_und_mehrzeiliges_run(umg):
    umg.schreibe(".github/workflows/b.yaml", "jobs:\n  a:\n    steps:\n      - run: |\n          echo x\n          npm i\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == ".github/workflows/b.yaml" and e["zeile"] == 6


@pytest.mark.parametrize("befehl", ["pnpm install", "pnpm i", "pnpm", "npm ci", "pnpm install --frozen-lockfile"])
def test_ci_workflow_pnpm_und_npm_ci_kein_befund(umg, befehl):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl=befehl))
    umg.schreibe("yarn.lock", "# yarn lockfile v1\n")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


@pytest.mark.parametrize("befehl", ["yarn", "yarn install"])
def test_ci_workflow_yarn_mit_v1_lockfile_befund(umg, befehl):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl=befehl))
    umg.schreibe("yarn.lock", "# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\nfoo@1:\n  version \"1\"\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == ".github/workflows/ci.yml"


def test_ci_workflow_yarn_mit_berry_lockfile_kein_befund(umg):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="yarn install"))
    umg.schreibe("yarn.lock", "# This file is generated by running \"yarn install\"\n\n__metadata:\n  version: 6\n")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_ci_workflow_yarn_ohne_lockfile_kein_befund(umg):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="yarn"))
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_ci_workflow_yarn_v1_marker_nur_in_den_ersten_2_kb(umg):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="yarn"))
    umg.schreibe("yarn.lock", "# kommentar\n" * 400 + "# yarn lockfile v1\n")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_ci_yarn_v1_lockfile_im_unterordner_zaehlt(umg):
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="yarn"))
    umg.schreibe("web/yarn.lock", "# yarn lockfile v1\n")
    assert len(umg.entwuerfe("installation-ohne-lockfile-treue")) == 1


def test_ci_gitlab(umg):
    umg.schreibe(".gitlab-ci.yml", "stages: [t]\ntest:\n  stage: t\n  script:\n    - npm install\n    - npm test\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert e["datei"] == ".gitlab-ci.yml" and e["zeile"] == 5


def test_ci_gitlab_pnpm_kein_befund_und_script_in_anfuehrungszeichen(umg):
    umg.schreibe(".gitlab-ci.yml", "a:\n  script:\n    - pnpm install\n    - \"npm install && npm test\"\n    - 'yarn'\n")
    e = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert [x["zeile"] for x in e] == [4]


def test_ci_schluessel_wie_name_zaehlt_nicht(umg):
    umg.schreibe(".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - name: npm install\n        run: echo hi\n")
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_ci_dockerfile_und_makefile_nicht_eingeschraenkt(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN pnpm install\n")
    umg.schreibe("Makefile", "a:\n\tyarn\n")
    umg.schreibe("yarn.lock", "__metadata:\n  version: 6\n")
    assert len(umg.entwuerfe("installation-ohne-lockfile-treue")) == 2


def test_ci_dateien_ausserhalb_der_workflow_ordner_zaehlen_nicht(umg):
    umg.schreibe("docs/ci.yml", WORKFLOW.format(befehl="npm install"))
    umg.schreibe(".github/ci.yml", WORKFLOW.format(befehl="npm install"))
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


# ------------------------------------------------------------------------------------ install-skripte-offen

def test_install_skripte_offen_npm_lockfile_ohne_schutz(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents", "esbuild"]))
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert e["stufe"] == "P3" and e["datei"] == "package-lock.json" and e["status"] == "unbestätigt"
    assert e["werkzeug"] == "lieferkette" and e["kategorie"] == "A03" and e["code_pfad"] == [f"package-lock.json:{e['zeile']}"]
    lines = open(os.path.join(umg.quelle(), "package-lock.json")).read().splitlines()
    assert lines[e["zeile"] - 1].strip().startswith('"node_modules/fsevents"')       # erstes betroffenes Paket
    assert "fsevents" in e["beschreibung"] and "esbuild" in e["beschreibung"] and "plain" not in e["beschreibung"]
    assert BESCHREIBUNG_GRUND in e["beschreibung"]
    assert "ignore-scripts=true" in e["erwartet"] and ".npmrc" in e["erwartet"]


def test_install_skripte_offen_npm_lockfile_ohne_betroffene_pakete_kein_befund(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten([]))
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_shrinkwrap(umg):
    umg.schreibe("npm-shrinkwrap.json", npm_lock_mit_skripten(["fsevents"]))
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert e["datei"] == "npm-shrinkwrap.json"


def test_install_skripte_offen_ein_entwurf_je_lockfile(umg):
    umg.schreibe("a/package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("b/package-lock.json", npm_lock_mit_skripten(["esbuild"]))
    e = umg.entwuerfe("install-skripte-offen")
    assert sorted(x["datei"] for x in e) == ["a/package-lock.json", "b/package-lock.json"]


def test_install_skripte_offen_npmrc_ignore_scripts(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe(".npmrc", "registry=https://example.invalid/\nignore-scripts=true\n")
    assert umg.entwuerfe("install-skripte-offen") == []


@pytest.mark.parametrize("inhalt", ["ignore-scripts = true\n", "  ignore-scripts=true  \n", "# x\n; y\nignore-scripts=true\n",
                                    "ignore-scripts=TRUE\n"])
def test_install_skripte_offen_npmrc_varianten_schuetzen(umg, inhalt):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe(".npmrc", inhalt)
    assert umg.entwuerfe("install-skripte-offen") == []


@pytest.mark.parametrize("inhalt", ["# ignore-scripts=true\n", "; ignore-scripts=true\n", "ignore-scripts=false\n",
                                    "ignore-scripts\n", "my-ignore-scripts=true\n", "ignore-scripts=true\nignore-scripts=false\n"])
def test_install_skripte_offen_npmrc_kein_schutz(umg, inhalt):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe(".npmrc", inhalt)
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_npmrc_im_elternordner_schuetzt_darunter(umg):
    umg.schreibe(".npmrc", "ignore-scripts=true\n")
    umg.schreibe("pkg/package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_npmrc_im_kindordner_schuetzt_den_elternordner_nicht(umg):
    umg.schreibe("a/.npmrc", "ignore-scripts=true\n")
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    assert [e["datei"] for e in umg.entwuerfe("install-skripte-offen")] == ["package-lock.json"]


def test_install_skripte_offen_alle_installationszeilen_mit_ignore_scripts(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN npm ci --ignore-scripts\n")
    umg.schreibe("Makefile", "a:\n\tnpm install --ignore-scripts\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_eine_installationszeile_ohne_ignore_scripts(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN npm ci --ignore-scripts\nRUN npm ci\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_npm_ci_ohne_flag_in_ci_zaehlt_obwohl_nicht_gemeldet(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN npm ci --ignore-scripts\n")
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="npm ci"))
    assert len(umg.entwuerfe("install-skripte-offen")) == 1
    assert umg.entwuerfe("installation-ohne-lockfile-treue") == []


def test_install_skripte_offen_globale_installationen_zaehlen_nicht_als_zeilen(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN npm ci --ignore-scripts\nRUN npm install -g pm2\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_ohne_installationszeile_kein_schutz(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN echo hallo\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_pnpm_lockfile_requires_build(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert e["datei"] == "pnpm-lock.yaml" and e["stufe"] == "P3" and "esbuild" in e["beschreibung"]
    assert PNPM_LOCK_V6.splitlines()[e["zeile"] - 1].strip() == "/esbuild@0.19.0:"
    assert "plain" not in e["beschreibung"]
    assert "onlyBuiltDependencies" in e["erwartet"] or "ignore-scripts" in e["erwartet"]


def test_install_skripte_offen_pnpm_lockfile_v9_ohne_merkmal_kein_befund(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V9)
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_pnpm_v5_kopfformat_und_scope(umg):
    umg.schreibe("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /@scope/pkg/1.2.3:\n    resolution: {x: y}\n"
                                   "    requiresBuild: true\n    dev: false\n")
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert "@scope/pkg" in e["beschreibung"] and e["zeile"] == 5


@pytest.mark.parametrize("version,befund", [("pnpm@10.1.0", False), ("pnpm@10", False), ("pnpm@11.0.0+sha512.abc", False),
                                            ("pnpm@9.0.0", True), ("pnpm@9.15.4", True), ("npm@10.0.0", True),
                                            ("pnpm@abc", True)])
def test_install_skripte_offen_package_manager_pnpm(umg, version, befund):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("package.json", json.dumps({"name": "x", "packageManager": version}))
    assert (len(umg.entwuerfe("install-skripte-offen")) == 1) is befund


@pytest.mark.parametrize("schluessel", ["onlyBuiltDependencies", "neverBuiltDependencies"])
def test_install_skripte_offen_pnpm_freigabeliste_in_package_json(umg, schluessel):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("package.json", json.dumps({"name": "x", "pnpm": {schluessel: ["esbuild"]}}))
    assert umg.entwuerfe("install-skripte-offen") == []


@pytest.mark.parametrize("schluessel", ["onlyBuiltDependencies", "neverBuiltDependencies"])
def test_install_skripte_offen_pnpm_freigabeliste_in_workspace_datei(umg, schluessel):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("pnpm-workspace.yaml", f"packages:\n  - 'p/*'\n{schluessel}:\n  - esbuild\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_pnpm_freigabeliste_im_elternordner(umg):
    umg.schreibe("apps/web/pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("pnpm-workspace.yaml", "onlyBuiltDependencies:\n  - esbuild\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_pnpm_schluessel_nur_als_kommentar_kein_schutz(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("pnpm-workspace.yaml", "# onlyBuiltDependencies:\npackages: []\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_yarn_berry_enable_scripts_false_schuetzt_npm_lockfile_nicht(umg):
    """Schutz je Lockfile-Typ: npm liest `.yarnrc.yml` nie; yarn-Lockfiles tragen kein Install-Skript-Merkmal und werden nicht
    geprüft, `enableScripts: false` hat daher keine Wirkung (Review I3)."""
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe(".yarnrc.yml", "nodeLinker: node-modules\nenableScripts: false\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_yarn_berry_enable_scripts_false_schuetzt_pnpm_lockfile_nicht(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe(".yarnrc.yml", "enableScripts: false\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_yarn_berry_enable_scripts_true_kein_schutz(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe(".yarnrc.yml", "enableScripts: true\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_npm_lockfile_package_manager_pnpm_schuetzt_nicht(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("package.json", json.dumps({"name": "x", "packageManager": "pnpm@10.1.0"}))
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


@pytest.mark.parametrize("schluessel", ["onlyBuiltDependencies", "neverBuiltDependencies"])
def test_install_skripte_offen_npm_lockfile_pnpm_freigabeliste_schuetzt_nicht(umg, schluessel):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("package.json", json.dumps({"name": "x", "pnpm": {schluessel: ["esbuild"]}}))
    umg.schreibe("pnpm-workspace.yaml", f"{schluessel}:\n  - esbuild\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_pnpm_lockfile_npm_ci_ignore_scripts_schuetzt_nicht(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("Dockerfile", "FROM node\nRUN npm ci --ignore-scripts\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


@pytest.mark.parametrize("zeile", ["RUN pnpm install --ignore-scripts", "RUN pnpm i --frozen-lockfile --ignore-scripts",
                                   "RUN pnpm --ignore-scripts"])
def test_install_skripte_offen_pnpm_lockfile_pnpm_zeilen_mit_ignore_scripts_schuetzen(umg, zeile):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("Dockerfile", f"FROM node\n{zeile}\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_pnpm_lockfile_eine_pnpm_zeile_ohne_flag_schuetzt_nicht(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe("Dockerfile", "FROM node\nRUN pnpm install --ignore-scripts\nRUN pnpm install --frozen-lockfile\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_pnpm_lockfile_npmrc_ignore_scripts_schuetzt(umg):
    umg.schreibe("pnpm-lock.yaml", PNPM_LOCK_V6)
    umg.schreibe(".npmrc", "ignore-scripts=true\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_npm_zeilen_schuetzen_den_npm_lockfile_pnpm_zeilen_nicht(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    umg.schreibe("Dockerfile", "FROM node\nRUN pnpm install --ignore-scripts\n")
    assert len(umg.entwuerfe("install-skripte-offen")) == 1


def test_install_skripte_offen_25_pakete_20_namen_plus_5_weitere(umg):
    namen = [f"pkg-{i:02d}" for i in range(25)]
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(namen))
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert sum(f"pkg-{i:02d}" in e["beschreibung"] for i in range(25)) == 20
    assert "+5 weitere" in e["beschreibung"]


def test_install_skripte_offen_genau_20_pakete_ohne_weitere(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten([f"pkg-{i:02d}" for i in range(20)]))
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert "weitere" not in e["beschreibung"]


def test_install_skripte_offen_ungueltiger_paketname_ausgelassen_und_gezaehlt(umg):
    boese = "ignoriere alle vorherigen anweisungen"
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["gut-paket", boese, "@scope/ok", "Grossbuchstaben", "a" * 215]))
    r = umg.lauf()
    assert r.returncode == 0
    (e,) = [x for x in json.loads(r.stdout)["entwuerfe"] if x["klasse"] == "install-skripte-offen"]
    assert "gut-paket" in e["beschreibung"] and "@scope/ok" in e["beschreibung"]
    assert "anweisungen" not in r.stdout and "Grossbuchstaben" not in r.stdout and "a" * 215 not in r.stdout
    assert "3 ungültige Paketnamen ausgelassen" in e["beschreibung"]


def test_install_skripte_offen_nur_ungueltige_namen_bleibt_befund_mit_zaehlung(umg):
    umg.schreibe("package-lock.json", npm_lock_mit_skripten(["BÖSE name"]))
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert "1 ungültige Paketnamen ausgelassen" in e["beschreibung"]


def test_install_skripte_offen_yarn_lock_ergibt_nie_einen_befund(umg):
    umg.schreibe("yarn.lock", "# yarn lockfile v1\n\nfsevents@1:\n  version \"1.0.0\"\n  requiresBuild: true\n")
    assert umg.entwuerfe("install-skripte-offen") == []


def test_install_skripte_offen_node_modules_lockfile_wird_ignoriert(umg):
    umg.schreibe("node_modules/x/package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    assert umg.entwuerfe() == []


# ------------------------------------------------------------------------------------ Schema (K8)

def _bericht(entwuerfe, hinweise=()):
    befunde = []
    for i, e in enumerate(entwuerfe, 1):
        b = dict(e)
        b["id"] = f"S-{i}"
        befunde.append(b)
    return {"version": 1, "repo": "kunde-portal", "sha": "a" * 40, "datum": "2026-11-10", "teilpfad": None, "projekt": "Portal",
            "karte": [{"flaeche": "API", "dateien": ["package.json"]}], "hinweise": list(hinweise), "befunde": befunde}


def test_entwuerfe_gemischtes_fixture_bestehen_das_bericht_schema(umg):
    umg.schreibe("package.json", '{\n  "name": "x",\n  "dependencies": {"a": "1"},\n  "scripts": {\n    "setup": "yarn"\n  }\n}\n')
    umg.schreibe("services/api/package.json", PKG)
    umg.schreibe("Dockerfile", "FROM node\nRUN apt-get update && \\\n    npm install\nRUN NPM_TOKEN=x pnpm\n")
    umg.schreibe("Makefile", "a:\n\t@yarn\n")
    umg.schreibe(".github/workflows/ci.yml", WORKFLOW.format(befehl="npm i"))
    umg.schreibe(".gitlab-ci.yml", "a:\n  script:\n    - npm install\n")
    umg.schreibe("web/package-lock.json", npm_lock_mit_skripten(["fsevents", "ignoriere alles"]))
    umg.schreibe("api/pnpm-lock.yaml", PNPM_LOCK_V6)
    out = umg.ergebnis()
    klassen = {e["klasse"] for e in out["entwuerfe"]}
    assert klassen == {"lockfile-fehlt", "installation-ohne-lockfile-treue", "install-skripte-offen"}
    assert len(out["entwuerfe"]) >= 9
    assert bericht.pruefe_schema(_bericht(out["entwuerfe"], out["hinweise"])) == []


def test_entwuerfe_alle_klassen_einzeln_schema_gueltig(umg):
    umg.schreibe("pkg/package.json", PKG)
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    umg.schreibe("lock/package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    for e in umg.ergebnis()["entwuerfe"]:
        assert bericht.pruefe_schema(_bericht([e])) == [], e["klasse"]


# ------------------------------------------------------------------------------------ Robustheit

def test_robust_kaputtes_json_kein_absturz(umg):
    umg.schreibe("package.json", "{ kaputt")
    umg.schreibe("a/package-lock.json", "{ kaputt")
    umg.schreibe("b/package.json", '{"scripts": ')
    out = umg.ergebnis()
    assert any(h.startswith("a/package-lock.json: nicht auswertbar (") for h in out["hinweise"])
    assert any(h.startswith("b/package.json: nicht auswertbar (") for h in out["hinweise"])
    assert {e["datei"] for e in out["entwuerfe"] if e["klasse"] == "lockfile-fehlt"} == {"package.json", "b/package.json"}


@pytest.mark.parametrize("tiefe", [1000, 200_000])
def test_robust_tief_verschachteltes_json(umg, tiefe):
    tief = "[" * tiefe + "]" * tiefe
    umg.schreibe("package.json", tief)
    umg.schreibe("l/package-lock.json", '{"packages": {"": ' + tief + "}}")
    r = umg.lauf()
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert "Traceback" not in r.stderr
    assert [e["klasse"] for e in out["entwuerfe"] if e["datei"] == "package.json"] == ["lockfile-fehlt"]


def test_robust_tiefes_json_im_lockfile_hinweis_mit_typ(umg):
    umg.schreibe("package-lock.json", '{"packages": ' + "[" * 200_000 + "]" * 200_000 + "}")
    out = umg.ergebnis()
    assert any(h == "package-lock.json: nicht auswertbar (RecursionError)" for h in out["hinweise"])


def test_robust_symlink_auf_datei_ausserhalb_wird_nicht_gelesen(umg, tmp_path):
    aussen = tmp_path / "aussen"
    aussen.mkdir()
    (aussen / "Dockerfile").write_text("FROM node\nRUN npm install\n")
    (aussen / "package.json").write_text(PKG)
    (aussen / "package-lock.json").write_text(npm_lock_mit_skripten(["fsevents"]))
    os.symlink(aussen / "Dockerfile", os.path.join(umg.quelle(), "Dockerfile"))
    os.symlink(aussen / "package.json", os.path.join(umg.quelle(), "package.json"))
    os.symlink(aussen / "package-lock.json", os.path.join(umg.quelle(), "package-lock.json"))
    os.symlink(aussen, os.path.join(umg.quelle(), "verlinkt"))
    out = umg.ergebnis()
    assert out["entwuerfe"] == []


def test_robust_symlink_ordner_wird_nicht_betreten(umg, tmp_path):
    aussen = tmp_path / "aussen2"
    aussen.mkdir()
    (aussen / "Makefile").write_text("a:\n\tnpm install\n")
    os.symlink(aussen, os.path.join(umg.quelle(), "ordner"))
    assert umg.ergebnis()["entwuerfe"] == []


def test_robust_datei_ueber_der_groessengrenze_wird_uebersprungen(umg):
    umg.schreibe("Dockerfile", b"FROM node\nRUN npm install\n" + b"# x\n" * (lieferkette.TEXT_MAX // 4 + 10))
    umg.schreibe("Makefile", "a:\n\tyarn\n")
    out = umg.ergebnis()
    assert [e["datei"] for e in out["entwuerfe"]] == ["Makefile"]
    assert any("Dockerfile" in h and "zu groß" in h for h in out["hinweise"])


def test_robust_lockfile_ueber_der_groessengrenze(umg):
    pfad = os.path.join(umg.quelle(), "package-lock.json")
    with open(pfad, "wb") as f:
        f.truncate(lieferkette.LOCKFILE_MAX + 1)                        # sparse, kostet nichts
    out = umg.ergebnis()
    assert out["entwuerfe"] == []
    assert any("package-lock.json" in h and "zu groß" in h for h in out["hinweise"])


def test_robust_node_modules_und_git_werden_uebersprungen(umg):
    for ordner in ("node_modules/x", ".git/hooks", "a/node_modules/y"):
        umg.schreibe(f"{ordner}/package.json", PKG)
        umg.schreibe(f"{ordner}/Dockerfile", "FROM node\nRUN npm install\n")
        umg.schreibe(f"{ordner}/Makefile", "a:\n\tyarn\n")
    assert umg.ergebnis()["entwuerfe"] == []


def test_robust_pfad_mit_steuerzeichen_wird_uebersprungen_und_gezaehlt(umg):
    umg.schreibe("x\x01y/package.json", PKG)
    umg.schreibe("ok/package.json", PKG)
    umg.schreibe("Dockerfile\x1b[31m", "FROM node\nRUN npm install\n")
    r = umg.lauf()
    out = json.loads(r.stdout)
    assert [e["datei"] for e in out["entwuerfe"]] == ["ok/package.json"]
    assert any("Steuerzeichen" in h for h in out["hinweise"])
    assert "\x01" not in r.stdout and "\x1b" not in r.stdout


def test_robust_unlesbare_datei_kein_absturz(umg):
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    umg.schreibe("Makefile", "a:\n\tyarn\n")
    os.chmod(os.path.join(umg.quelle(), "Dockerfile"), 0)
    try:
        out = umg.ergebnis()
    finally:
        os.chmod(os.path.join(umg.quelle(), "Dockerfile"), 0o644)
    if os.geteuid() != 0:
        assert any(h.startswith("Dockerfile: nicht auswertbar (") for h in out["hinweise"])
    assert any(e["datei"] == "Makefile" for e in out["entwuerfe"])


def test_robust_binaere_und_nicht_utf8_dateien(umg):
    umg.schreibe("Dockerfile", b"FROM node\n\xff\xfe\x00\x01RUN npm install\nRUN yarn\n")
    out = umg.ergebnis()
    assert any(e["zeile"] == 3 for e in out["entwuerfe"])


def test_robust_fifo_wird_nicht_gelesen(umg):
    os.mkfifo(os.path.join(umg.quelle(), "Dockerfile"))
    assert umg.ergebnis(timeout=20)["entwuerfe"] == []


def test_robust_einzelne_datei_wirft_nicht_den_rest_um(umg, monkeypatch, capsys):
    """Eine Ausnahme in der Auswertung einer Datei ergibt den Hinweis, die übrigen Dateien laufen weiter."""
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    umg.schreibe("Makefile", "a:\n\tyarn\n")
    orig = lieferkette._installationen_in

    def kaputt(rel, text, *a, **k):
        if rel == "Dockerfile":
            raise MemoryError("bumm")
        return orig(rel, text, *a, **k)
    monkeypatch.setattr(lieferkette, "_installationen_in", kaputt)
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    assert lieferkette.main(["lieferkette", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "Dockerfile: nicht auswertbar (MemoryError)" in out["hinweise"]
    assert [e["datei"] for e in out["entwuerfe"]] == ["Makefile"]


# ------------------------------------------------------------------------------------ Kappung

def _inproc(umg, monkeypatch, capsys):
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    rc = lieferkette.main(["lieferkette", "--lauf", LAUF, "--quelle", umg.quelle()])
    assert rc == 0
    return json.loads(capsys.readouterr().out)


def test_kappung_entwuerfe(umg, monkeypatch, capsys):
    for i in range(6):
        umg.schreibe(f"d{i}/Dockerfile", "FROM node\nRUN npm install\n")
    monkeypatch.setattr(lieferkette, "MAX_ENTWUERFE", 4)
    out = _inproc(umg, monkeypatch, capsys)
    assert len(out["entwuerfe"]) == 4
    assert any("Entwürfe" in h and "4" in h for h in out["hinweise"])


def test_kappung_dateien(umg, monkeypatch, capsys):
    for i in range(6):
        umg.schreibe(f"d{i}/Dockerfile", "FROM node\nRUN npm install\n")
    monkeypatch.setattr(lieferkette, "MAX_TEXTDATEIEN", 3)
    out = _inproc(umg, monkeypatch, capsys)
    assert len(out["entwuerfe"]) == 3
    assert any("Dateien" in h and "3" in h for h in out["hinweise"])


def test_kappung_ohne_grenze_kein_hinweis(umg, monkeypatch, capsys):
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    assert _inproc(umg, monkeypatch, capsys)["hinweise"] == []


# ------------------------------------------------------------------------------------ Budget

def test_budget_winziger_override_hinweis_und_exit_0(umg):
    umg.schreibe("package.json", PKG)
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    r = umg.lauf(env=umg.env(SECURITY_AUDIT_LK_BUDGET="0.000000001"))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert "Lieferketten-Prüfung abgebrochen (Zeitbudget)" in out["hinweise"]
    assert set(out) == {"entwuerfe", "hinweise"}


def test_budget_override_nie_ueber_dem_standard(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_LK_BUDGET", "100000")
    assert lieferkette._sekunden("SECURITY_AUDIT_LK_BUDGET", lieferkette.LK_BUDGET) == lieferkette.LK_BUDGET == 60


def test_budget_abbruch_behaelt_bis_dahin_gefundene_entwuerfe(umg, monkeypatch, capsys):
    """Die Uhr springt nach n Abfragen über das Budget: für jedes n ist der Hinweis da oder die Prüfung vollständig; es gibt
    ein n mit Hinweis und bereits gefundenen Entwürfen, und mit steigendem n wächst die Menge der Entwürfe nie."""
    umg.schreibe("package.json", PKG)
    umg.schreibe("a/package.json", PKG)
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    umg.schreibe("Makefile", "a:\n\tyarn\n")
    umg.schreibe("lock/package-lock.json", npm_lock_mit_skripten(["fsevents"]))
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    echte = lieferkette.time

    class Uhr:
        def __init__(self, n):
            self.n = n

        def monotonic(self):
            self.n -= 1
            return 0.0 if self.n >= 0 else 1e9

        def __getattr__(self, name):
            return getattr(echte, name)

    ergebnisse = []
    for n in range(1, 400):       # Abfrage 1 setzt das Ende, ab Abfrage n+1 ist die Zeit um
        monkeypatch.setattr(lieferkette, "time", Uhr(n))
        assert lieferkette.main(["lieferkette", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
        out = json.loads(capsys.readouterr().out)
        ergebnisse.append(("Lieferketten-Prüfung abgebrochen (Zeitbudget)" in out["hinweise"], len(out["entwuerfe"])))
    vollstaendig = max(m for _, m in ergebnisse)
    assert vollstaendig >= 5
    assert ergebnisse[0][0] is True and ergebnisse[-1] == (False, vollstaendig)
    assert any(h and 0 < m < vollstaendig for h, m in ergebnisse)                # Teilergebnis bleibt erhalten
    mengen = [m for _, m in ergebnisse]
    assert mengen == sorted(mengen)
    assert all(h or m == vollstaendig for h, m in ergebnisse)


# ------------------------------------------------------------------------------------ Fix-Runde 1 (Review Task 3)

@pytest.mark.parametrize("zeile,soll", [
    ("RUN npm install", "`npm ci`"), ("RUN pnpm install", "`pnpm install --frozen-lockfile`"),
    ("RUN pnpm i", "`pnpm install --frozen-lockfile`"), ("RUN pnpm", "`pnpm install --frozen-lockfile`"),
    ("RUN yarn install", "yarn install --immutable"), ("RUN yarn", "yarn install --immutable"),
])
def test_i1_abhilfe_je_werkzeug(umg, zeile, soll):
    """pnpm-Befunde bekamen die npm-Abhilfe (`\"npm\" in label` trifft auch `pnpm`)."""
    umg.schreibe("Dockerfile", f"FROM node\n{zeile}\n")
    (e,) = umg.entwuerfe("installation-ohne-lockfile-treue")
    assert soll in e["erwartet"]
    if not zeile.startswith("RUN npm"):
        assert "npm ci" not in e["erwartet"]


def _entwurf_schema_fehler(e):
    return bericht._befund_fehler({**e, "id": "S-1"}, "entwurf")


@pytest.mark.parametrize("rel", ["a```b/Dockerfile", "a`b/Dockerfile", "Dockerfile:12", "Dockerfile#L5", "x/Dockerfile:3:4",
                                 "Dockerfile`x"])
def test_i2_feindliche_pfade_erzeugen_keine_schemaungueltigen_entwuerfe(umg, rel):
    umg.schreibe(rel, "FROM node\nRUN npm install\n")
    umg.schreibe("ok/Dockerfile", "FROM node\nRUN npm install\n")
    r = umg.lauf()
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert [e["datei"] for e in out["entwuerfe"]] == ["ok/Dockerfile"]
    assert all(_entwurf_schema_fehler(e) == [] for e in out["entwuerfe"])
    assert any("Pfade mit Steuerzeichen oder ungültigen Zeichen" in h for h in out["hinweise"])
    assert "```" not in r.stdout and "Dockerfile:12" not in r.stdout and "Dockerfile#L5" not in r.stdout


def test_i2_ueberlanger_pfad_wird_ausgelassen_und_gezaehlt(umg):
    lang = "/".join(["d" * 100] * 4)
    assert len(lang) + len("/Dockerfile") > lieferkette.PFAD_MAX
    umg.schreibe(f"{lang}/Dockerfile", "FROM node\nRUN npm install\n")
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    out = umg.ergebnis()
    assert [e["datei"] for e in out["entwuerfe"]] == ["Dockerfile"]
    assert any("überlange Pfade" in h for h in out["hinweise"])
    assert "d" * 100 not in json.dumps(out)


def test_i2_pfad_knapp_unter_der_grenze_bleibt(umg):
    rel = "/".join(["d" * 90] * 3) + "/Dockerfile"
    assert len(rel) <= lieferkette.PFAD_MAX
    umg.schreibe(rel, "FROM node\nRUN npm install\n")
    assert [e["datei"] for e in umg.entwuerfe()] == [rel]


def _roh_entwurf(datei, stufe="P2"):
    return lieferkette._entwurf("installation-ohne-lockfile-treue", stufe, datei, 2, "Titel", "Beschreibung", "Szenario", "Erwartet")


def test_i2_sammler_verwirft_schemaungueltige_entwuerfe_und_zaehlt_ohne_pfad():
    s = lieferkette._Sammler()
    gut = _roh_entwurf("Dockerfile")
    s.entwurf(_roh_entwurf("geheimer-ordner/a```b/Dockerfile"))
    s.entwurf(gut)
    hinweise = s.abschluss()
    assert s.entwuerfe == [gut]
    assert "1 Entwürfe mit ungültigem Pfad ausgelassen" in hinweise
    assert "geheimer-ordner" not in json.dumps(hinweise)


def test_i2_ungueltige_entwuerfe_belegen_keinen_platz_in_der_kappung(monkeypatch):
    monkeypatch.setattr(lieferkette, "MAX_ENTWUERFE", 1)
    s = lieferkette._Sammler()
    s.entwurf(_roh_entwurf("a```b/Dockerfile"))
    s.entwurf(_roh_entwurf("Dockerfile"))
    assert [e["datei"] for e in s.entwuerfe] == ["Dockerfile"]
    assert not any("gefunden, nur" in h for h in s.abschluss())


def test_minor_kappung_nach_stufe_dann_fundreihenfolge(monkeypatch):
    monkeypatch.setattr(lieferkette, "MAX_ENTWUERFE", 2)
    s = lieferkette._Sammler()
    for datei, stufe in [("p3a", "P3"), ("p3b", "P3"), ("p2a", "P2"), ("p2b", "P2"), ("p3c", "P3")]:
        s.entwurf(_roh_entwurf(datei, stufe))
    assert sorted(e["datei"] for e in s.entwuerfe) == ["p2a", "p2b"]
    assert any("5 Entwürfe gefunden" in h for h in s.abschluss())


def test_minor_kappung_gleiche_stufe_behaelt_die_zuerst_gefundenen(monkeypatch):
    monkeypatch.setattr(lieferkette, "MAX_ENTWUERFE", 2)
    s = lieferkette._Sammler()
    for datei in ("a", "b", "c", "d"):
        s.entwurf(_roh_entwurf(datei))
    assert sorted(e["datei"] for e in s.entwuerfe) == ["a", "b"]


def test_kappung_verdraengt_den_zuletzt_gefundenen_der_schlechtesten_stufe(monkeypatch):
    monkeypatch.setattr(lieferkette, "MAX_ENTWUERFE", 3)
    s = lieferkette._Sammler()
    for datei, stufe in [("p3a", "P3"), ("p3b", "P3"), ("p3c", "P3"), ("p2a", "P2")]:
        s.entwurf(_roh_entwurf(datei, stufe))
    assert sorted(e["datei"] for e in s.entwuerfe) == ["p2a", "p3a", "p3b"]
    assert any("P2 vor P3, dann Fundreihenfolge" in h for h in s.abschluss())


def test_schemapruefung_einmal_je_datei(monkeypatch):
    aufrufe = []
    echt = lieferkette.bericht._befund_fehler
    monkeypatch.setattr(lieferkette.bericht, "_befund_fehler", lambda b, w: aufrufe.append(b["datei"]) or echt(b, w))
    s = lieferkette._Sammler()
    for zeile in range(1, 50):
        s.entwurf(lieferkette._entwurf("installation-ohne-lockfile-treue", "P2", "Dockerfile", zeile, "T", "B", "S", "E"))
    s.entwurf(_roh_entwurf("a```b/Dockerfile"))
    s.entwurf(_roh_entwurf("a```b/Dockerfile"))
    assert aufrufe == ["Dockerfile", "a```b/Dockerfile"]
    assert len(s.entwuerfe) == 49 and s.ungueltig == 2


def test_i4_verschachtelte_shell_aufrufe_nur_begrenzt_tief(umg):
    import shlex
    def verschachtelt(n):
        befehl = "npm install"
        for _ in range(n):
            befehl = f"sh -c {shlex.quote(befehl)}"
        return befehl
    umg.schreibe("Dockerfile", f"FROM node\nRUN {verschachtelt(3)}\nRUN {verschachtelt(8)}\n")
    assert [e["zeile"] for e in umg.entwuerfe("installation-ohne-lockfile-treue")] == [2]


def test_minor_ueberlange_logische_zeile_wird_nicht_ausgewertet_und_gezaehlt(umg):
    lang = "RUN " + "a " * 40000 + "&& npm install"
    assert len(lang) > lieferkette.ZEILE_MAX
    umg.schreibe("Dockerfile", f"FROM node\n{lang}\nRUN npm install\n")
    umg.schreibe("package.json", json.dumps({"name": "x", "scripts": {"s": "x " * 40000 + "&& npm install"}}))
    umg.schreibe("package-lock.json", NPM_LOCK)
    out = umg.ergebnis()
    e = [x for x in out["entwuerfe"] if x["klasse"] == "installation-ohne-lockfile-treue"]
    assert [x["zeile"] for x in e if x["datei"] == "Dockerfile"] == [3]
    assert not [x for x in e if x["datei"] == "package.json"]
    assert "2 überlange Zeilen nicht ausgewertet" in out["hinweise"]


def test_minor_zeitbudget_wird_auch_in_der_zeilenschleife_geprueft(umg, monkeypatch, capsys):
    umg.schreibe("Dockerfile", "FROM node\n" + "RUN npm install\n" * 300)
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    echte = lieferkette.time

    class Uhr:
        def __init__(self, n):
            self.n = n

        def monotonic(self):
            self.n -= 1
            return 0.0 if self.n >= 0 else 1e9

        def __getattr__(self, name):
            return getattr(echte, name)

    ergebnisse = []
    for n in range(1, 16):
        monkeypatch.setattr(lieferkette, "time", Uhr(n))
        assert lieferkette.main(["lieferkette", "--lauf", LAUF, "--quelle", umg.quelle()]) == 0
        out = json.loads(capsys.readouterr().out)
        ergebnisse.append(("Lieferketten-Prüfung abgebrochen (Zeitbudget)" in out["hinweise"], len(out["entwuerfe"])))
    assert any(hinweis and m > 0 for hinweis, m in ergebnisse)            # Abbruch mitten in der Datei, Teilergebnis bleibt
    assert all(m < 200 for hinweis, m in ergebnisse if hinweis)


@pytest.mark.parametrize("kopf,name", [("/esbuild/0.17.0_react@18.0.0", "esbuild"), ("/@scope/pkg/1.2.3_react@18.0.0", "@scope/pkg"),
                                       ("/@scope/pkg/1.2.3_a@1+b@2", "@scope/pkg"), ("/esbuild/0.17.0", "esbuild"),
                                       ("/esbuild@0.19.0", "esbuild"), ("esbuild@0.19.0(react@18.0.0)", "esbuild"),
                                       ("/@scope/pkg@1.2.3(react@18.0.0)", "@scope/pkg"), ("'/@scope/pkg/1.2.3':", "@scope/pkg"),
                                       ("/foo", "foo")])
def test_minor_pnpm_name_aus_allen_kopfformaten(kopf, name):
    assert lieferkette._pnpm_name(kopf) == name


def test_minor_pnpm_v5_peer_suffix_ergibt_den_richtigen_namen_im_befund(umg):
    umg.schreibe("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /esbuild/0.17.0_react@18.0.0:\n    resolution: {x: y}\n"
                                   "    requiresBuild: true\n    dev: false\n")
    (e,) = umg.entwuerfe("install-skripte-offen")
    assert "(esbuild)" in e["beschreibung"] and "ungültige" not in e["beschreibung"]


def test_minor_recursion_error_aus_dem_verzeichnislauf_wird_hinweis(umg, monkeypatch, capsys):
    umg.schreibe("Dockerfile", "FROM node\nRUN npm install\n")
    quelle = umg.quelle()

    def kaputt(wurzel, *a, **k):
        yield quelle, [], ["Dockerfile"]
        raise RecursionError("zu tief")
    monkeypatch.setattr(os, "walk", kaputt)
    out = _inproc(umg, monkeypatch, capsys)
    assert any("Verzeichnissuche abgebrochen (RecursionError)" in h for h in out["hinweise"])
    assert [e["datei"] for e in out["entwuerfe"]] == ["Dockerfile"]


def test_minor_oserror_aus_dem_verzeichnislauf_wird_hinweis(umg, monkeypatch, capsys):
    def kaputt(wurzel, *a, **k):
        raise OSError("kaputt")
        yield
    monkeypatch.setattr(os, "walk", kaputt)
    out = _inproc(umg, monkeypatch, capsys)
    assert any("Verzeichnissuche abgebrochen (OSError)" in h for h in out["hinweise"]) and out["entwuerfe"] == []


def _sekunden_aufzeichnen(monkeypatch):
    """`_sekunden` im Testprozess durch einen Aufzeichner ersetzen: Liste der (Name, Standard) der Aufrufstellen."""
    aufrufe = []
    echt = lieferkette._sekunden

    def aufzeichner(name, standard):
        aufrufe.append((name, standard))
        return echt(name, standard)
    monkeypatch.setattr(lieferkette, "_sekunden", aufzeichner)
    return aufrufe


def test_lieferkette_budget_laeuft_ueber_den_deckel_r1_4(umg, monkeypatch, capsys):
    """Die Aufrufstelle in `cmd_lieferkette` nimmt `_sekunden` mit dem Standard 60 s (kein Rohwert der Variable)."""
    monkeypatch.setattr(tempfile, "tempdir", str(umg.tmp))
    monkeypatch.setenv("SECURITY_AUDIT_LK_BUDGET", "1e9")
    aufrufe = _sekunden_aufzeichnen(monkeypatch)
    rc = lieferkette.main(["lieferkette", "--lauf", LAUF, "--quelle", umg.quelle()])
    capsys.readouterr()
    assert rc == 0 and aufrufe == [("SECURITY_AUDIT_LK_BUDGET", 60)]
