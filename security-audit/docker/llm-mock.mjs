// Modell-Mock für den Security-Audit-PoC. Läuft nur im Wegwerf-Container im internen Netz (oder lokal auf 127.0.0.1).
// Nur node:-Builtins, keine ausgehenden Requests, Zustand nur im Prozessspeicher.
//
//   node llm-mock.mjs --server [--host <h>] [--port <n>] [--steuer-port <n>]
//       API-Listener (Standard 0.0.0.0:4010, ohne Steuerpfade) und Steuerung (immer 127.0.0.1, Standard 4011).
//       Ist --port oder --steuer-port 0, steht als erste stdout-Zeile `bereit api=<p> steuer=<p>`.
//       Danach schreibt der Server nichts mehr auf stdout oder stderr (kein Echo, keine Body-Logs).
//   node llm-mock.mjs --bereit   [--steuer-port <n>]            Exit 0, wenn die Steuerung antwortet, sonst 1. Keine Ausgabe.
//   node llm-mock.mjs --setzen   [--steuer-port <n>]            stdin: Antwortliste (JSON-Array). Ersetzt die Warteschlange.
//   node llm-mock.mjs --protokoll [--suche <m>] [--steuer-port <n>]
//       stdin: {"werte":[{"name":"N","wert":"..."}]}. stdout: {"eintraege":[{nr,methode,pfad,body}],"gekuerzt":n},
//       reines ASCII, höchstens 64 KiB. Die Werte werden roh und JSON-escaped durch <ENV:N> ersetzt (längste zuerst),
//       erst danach wird jeder Body auf 8 KiB gekürzt. --suche sucht im maskierten Body.
// Exit-Codes: 0 = ok, 1 = Fehler (Steuerung nicht erreichbar, Port belegt, …), 2 = ungültige Argumente oder ungültiger stdin.

import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { parseArgs } from "node:util";

const MODELL = "poc-mock";
const RING_MAX = 50;
const BODY_MAX_REQUEST = 1024 * 1024;
const BODY_MAX_STEUER = 256 * 1024;
const STDIN_MAX = 64 * 1024;
const BODY_MAX_AUSGABE = 8192;
const AUSGABE_MAX = 65536;
const PFAD_MAX = 512;
const EMBED_STANDARD = 1536;
const EMBED_MAX_DIM = 8192;
const EMBED_MAX_ANZAHL = 2048;

const zustand = { warteschlange: [], ring: [], nr: 0, kennung: 0 };

// ---------------------------------------------------------------- Hilfen

function abbruch(text, code) {
  process.stderr.write(`fehler: ${text}\n`);
  process.exit(code);
}

function istObjekt(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function ascii(text) {
  return text.replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function jsonAscii(wert) {
  return ascii(JSON.stringify(wert));
}

function parseJson(text) {
  // Nie die Meldung des Parsers weitergeben: Sie kann Teile der Eingabe enthalten.
  try {
    return { ok: true, wert: JSON.parse(text) };
  } catch {
    return { ok: false, wert: null };
  }
}

function eindeutigeKennung(praefix) {
  zustand.kennung += 1;
  return `${praefix}poc_${zustand.kennung}_${randomBytes(6).toString("hex")}`;
}

async function bodyLesen(req, limit) {
  const teile = [];
  let gesamt = 0;
  let zuGross = false;
  for await (const teil of req) {
    gesamt += teil.length;
    if (gesamt > limit) {
      zuGross = true;
      continue; // weiter lesen und verwerfen, damit die Antwort ankommt
    }
    teile.push(teil);
  }
  return { text: zuGross ? "" : Buffer.concat(teile).toString("utf8"), zuGross };
}

function antwortJson(res, status, objekt) {
  const text = JSON.stringify(objekt);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

function fehler(res, status, art, text) {
  antwortJson(res, status, { error: { message: text, type: art, param: null, code: null } });
}

function sse(res, objekt) {
  res.write(`data: ${JSON.stringify(objekt)}\n\n`);
}

function stuecke(text, laenge) {
  const aus = [];
  for (let i = 0; i < text.length; i += laenge) aus.push(text.slice(i, i + laenge));
  return aus;
}

function tokenZahl(zeichen) {
  return Math.max(1, Math.ceil(zeichen / 4));
}

// ---------------------------------------------------------------- Antwortliste

const NAME_MUSTER = /^[A-Za-z0-9_.-]{1,64}$/;
const ENV_NAME_MUSTER = /^[A-Za-z0-9_.-]{1,64}$/;

// Liefert null bei gültiger Liste, sonst eine feste Meldung ohne Inhalte der Eingabe.
function pruefeAntworten(daten) {
  if (!Array.isArray(daten) || daten.length > 100) return "Antwortliste ungültig";
  for (const e of daten) {
    if (!istObjekt(e)) return "Antwortliste ungültig";
    for (const k of Object.keys(e)) {
      if (!["text", "werkzeug", "wenn_enthaelt"].includes(k)) return "Antwortliste ungültig";
    }
    const hatText = Object.hasOwn(e, "text");
    const hatWerkzeug = Object.hasOwn(e, "werkzeug");
    if (hatText === hatWerkzeug) return "Antwortliste ungültig";
    if (hatText && (typeof e.text !== "string" || e.text.length > 16384)) return "Antwortliste ungültig";
    if (hatWerkzeug) {
      const w = e.werkzeug;
      if (!istObjekt(w)) return "Antwortliste ungültig";
      for (const k of Object.keys(w)) {
        if (!["name", "argumente"].includes(k)) return "Antwortliste ungültig";
      }
      if (typeof w.name !== "string" || !NAME_MUSTER.test(w.name)) return "Antwortliste ungültig";
      if (Object.hasOwn(w, "argumente") && !istObjekt(w.argumente)) return "Antwortliste ungültig";
    }
    if (Object.hasOwn(e, "wenn_enthaelt")) {
      const m = e.wenn_enthaelt;
      if (typeof m !== "string" || m.length < 1 || m.length > 200) return "Antwortliste ungültig";
    }
  }
  return null;
}

function normalisiereAntworten(daten) {
  return daten.map((e) => {
    const eintrag = Object.hasOwn(e, "text")
      ? { text: e.text }
      : { werkzeug: { name: e.werkzeug.name, argumente: e.werkzeug.argumente ?? {} } };
    if (Object.hasOwn(e, "wenn_enthaelt")) eintrag.wenn_enthaelt = e.wenn_enthaelt;
    return eintrag;
  });
}

// Erster passender Eintrag: ohne Marker passt jeder Request, mit Marker nur ein Request, dessen Body ihn enthält.
// Der Eintrag wird verbraucht. Ohne Treffer antwortet der Mock mit „ok“.
function naechsteAntwort(body) {
  const i = zustand.warteschlange.findIndex((e) => e.wenn_enthaelt === undefined || body.includes(e.wenn_enthaelt));
  if (i < 0) return { typ: "text", text: "ok" };
  const [e] = zustand.warteschlange.splice(i, 1);
  if (e.werkzeug) return { typ: "werkzeug", name: e.werkzeug.name, argumente: e.werkzeug.argumente };
  return { typ: "text", text: e.text };
}

// ---------------------------------------------------------------- Protokoll und Maskierung

function ringEintragen(methode, pfad, body) {
  zustand.nr += 1;
  zustand.ring.push({ nr: zustand.nr, methode: String(methode).slice(0, 16), pfad: String(pfad).slice(0, 2048), body });
  while (zustand.ring.length > RING_MAX) zustand.ring.shift();
}

// Liefert null bei gültiger Eingabe, sonst eine feste Meldung.
function pruefeWerte(daten) {
  if (!istObjekt(daten) || !Array.isArray(daten.werte) || daten.werte.length > 200) return "Werteliste ungültig";
  for (const k of Object.keys(daten)) {
    if (k !== "werte") return "Werteliste ungültig";
  }
  for (const w of daten.werte) {
    if (!istObjekt(w) || Object.keys(w).length !== 2) return "Werteliste ungültig";
    if (typeof w.name !== "string" || !ENV_NAME_MUSTER.test(w.name)) return "Werteliste ungültig";
    if (typeof w.wert !== "string" || w.wert.length > 4096) return "Werteliste ungültig";
  }
  return null;
}

function regexMaske(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Ersetzt Rohform und JSON-escapte Form (auch mit \uXXXX), längste zuerst, in einem Durchgang.
// Der Ersatztext wird nicht erneut durchsucht.
function maskierer(werte) {
  const formen = [];
  for (const { name, wert } of werte) {
    if (wert.length === 0) continue;
    const jsonForm = JSON.stringify(wert).slice(1, -1);
    const grossHex = jsonForm.replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0").toUpperCase()}`);
    const kandidaten = new Set([wert, jsonForm, ascii(jsonForm), grossHex]);
    for (const form of kandidaten) {
      if (form.length > 0) formen.push({ form, name });
    }
  }
  formen.sort((a, b) => b.form.length - a.form.length); // stabil: bei gleichem Wert gilt der erste Name
  const ersatz = new Map();
  for (const { form, name } of formen) {
    if (!ersatz.has(form)) ersatz.set(form, `<ENV:${name}>`);
  }
  if (ersatz.size === 0) return (text) => text;
  const muster = new RegExp([...ersatz.keys()].map(regexMaske).join("|"), "g");
  return (text) => text.replace(muster, (treffer) => ersatz.get(treffer));
}

function kuerzen(text) {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= BODY_MAX_AUSGABE) return text;
  return bytes.subarray(0, BODY_MAX_AUSGABE).toString("utf8");
}

function protokollAusgabe(werte, suche) {
  const maske = maskierer(werte);
  let eintraege = zustand.ring.map((e) => ({
    nr: e.nr,
    methode: maske(e.methode),
    pfad: maske(e.pfad).slice(0, PFAD_MAX),
    body: maske(e.body), // erst maskieren, dann kürzen
  }));
  if (suche !== null) eintraege = eintraege.filter((e) => e.body.includes(suche));
  const strings = eintraege.map((e) => jsonAscii({ ...e, body: kuerzen(e.body) }));
  let gekuerzt = 0;
  const gesamt = () => {
    const kopf = `{"eintraege":[`;
    const fuss = `],"gekuerzt":${gekuerzt}}`;
    return Buffer.byteLength(kopf) + Buffer.byteLength(fuss) + strings.reduce((s, x) => s + Buffer.byteLength(x), 0) + Math.max(0, strings.length - 1);
  };
  while (strings.length > 0 && gesamt() > AUSGABE_MAX) {
    strings.shift(); // die ältesten Einträge zuerst
    gekuerzt += 1;
  }
  return `{"eintraege":[${strings.join(",")}],"gekuerzt":${gekuerzt}}`;
}

// ---------------------------------------------------------------- Chat Completions

function chatNichtStreamend(res, antwort, bodyLaenge) {
  const nachricht = { role: "assistant", content: antwort.typ === "text" ? antwort.text : null, refusal: null };
  let ende = "stop";
  let ausgabeZeichen = antwort.typ === "text" ? antwort.text.length : 0;
  if (antwort.typ === "werkzeug") {
    const argumente = JSON.stringify(antwort.argumente);
    nachricht.tool_calls = [{ id: eindeutigeKennung("call_"), type: "function", function: { name: antwort.name, arguments: argumente } }];
    ende = "tool_calls";
    ausgabeZeichen = argumente.length + antwort.name.length;
  }
  const prompt = tokenZahl(bodyLaenge);
  const ausgabe = tokenZahl(ausgabeZeichen);
  antwortJson(res, 200, {
    id: eindeutigeKennung("chatcmpl-"),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: MODELL,
    choices: [{ index: 0, message: nachricht, logprobs: null, finish_reason: ende }],
    usage: { prompt_tokens: prompt, completion_tokens: ausgabe, total_tokens: prompt + ausgabe },
  });
}

function chatStreamend(res, antwort, bodyLaenge, mitUsage) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  const id = eindeutigeKennung("chatcmpl-");
  const erstellt = Math.floor(Date.now() / 1000);
  const chunk = (delta, ende) => {
    const o = { id, object: "chat.completion.chunk", created: erstellt, model: MODELL, choices: [{ index: 0, delta, logprobs: null, finish_reason: ende }] };
    if (mitUsage) o.usage = null;
    sse(res, o);
  };
  let ausgabeZeichen = 0;
  if (antwort.typ === "text") {
    chunk({ role: "assistant", content: "", refusal: null }, null);
    for (const s of stuecke(antwort.text, 12)) chunk({ content: s }, null);
    ausgabeZeichen = antwort.text.length;
    chunk({}, "stop");
  } else {
    const argumente = JSON.stringify(antwort.argumente);
    chunk({ role: "assistant", content: null, refusal: null }, null);
    chunk({ tool_calls: [{ index: 0, id: eindeutigeKennung("call_"), type: "function", function: { name: antwort.name, arguments: "" } }] }, null);
    for (const s of stuecke(argumente, 12)) chunk({ tool_calls: [{ index: 0, function: { arguments: s } }] }, null);
    ausgabeZeichen = argumente.length + antwort.name.length;
    chunk({}, "tool_calls");
  }
  if (mitUsage) {
    const prompt = tokenZahl(bodyLaenge);
    const ausgabe = tokenZahl(ausgabeZeichen);
    sse(res, { id, object: "chat.completion.chunk", created: erstellt, model: MODELL, choices: [], usage: { prompt_tokens: prompt, completion_tokens: ausgabe, total_tokens: prompt + ausgabe } });
  }
  res.write("data: [DONE]\n\n");
  res.end();
}

function chatCompletions(res, daten, body) {
  const antwort = naechsteAntwort(body);
  if (daten.stream === true) {
    const mitUsage = istObjekt(daten.stream_options) && daten.stream_options.include_usage === true;
    chatStreamend(res, antwort, Buffer.byteLength(body), mitUsage);
  } else {
    chatNichtStreamend(res, antwort, Buffer.byteLength(body));
  }
}

// ---------------------------------------------------------------- Embeddings

function einzelVektor(eingabe, dimension) {
  const werte = new Float64Array(dimension);
  let i = 0;
  let zaehler = 0;
  while (i < dimension) {
    const h = createHash("sha256").update(eingabe).update(`#${zaehler}`).digest();
    zaehler += 1;
    for (let j = 0; j + 1 < h.length && i < dimension; j += 2) werte[i++] = h.readUInt16BE(j) / 32767.5 - 1;
  }
  let norm = 0;
  for (const w of werte) norm += w * w;
  norm = Math.sqrt(norm) || 1;
  return werte.map((w) => w / norm);
}

function embeddings(res, daten) {
  let dimension = EMBED_STANDARD;
  if (daten.dimensions !== undefined && daten.dimensions !== null) {
    if (!Number.isInteger(daten.dimensions) || daten.dimensions < 1 || daten.dimensions > EMBED_MAX_DIM) {
      return fehler(res, 400, "invalid_request_error", "dimensions ungültig");
    }
    dimension = daten.dimensions;
  }
  let eingaben;
  if (typeof daten.input === "string") eingaben = [daten.input];
  else if (Array.isArray(daten.input) && daten.input.length > 0 && daten.input.every((x) => typeof x === "number")) eingaben = [JSON.stringify(daten.input)];
  else if (Array.isArray(daten.input) && daten.input.length > 0 && daten.input.length <= EMBED_MAX_ANZAHL) eingaben = daten.input.map((x) => (typeof x === "string" ? x : JSON.stringify(x)));
  else return fehler(res, 400, "invalid_request_error", "input ungültig");
  const base64 = daten.encoding_format === "base64";
  const data = eingaben.map((e, index) => {
    const v = einzelVektor(e, dimension);
    const embedding = base64 ? Buffer.from(Float32Array.from(v).buffer).toString("base64") : Array.from(v, (w) => Math.round(w * 1e8) / 1e8);
    return { object: "embedding", index, embedding };
  });
  const token = eingaben.reduce((s, e) => s + tokenZahl(e.length), 0);
  antwortJson(res, 200, { object: "list", data, model: MODELL, usage: { prompt_tokens: token, total_tokens: token } });
}

function modelle(res) {
  antwortJson(res, 200, { object: "list", data: [{ id: MODELL, object: "model", created: 1700000000, owned_by: "poc" }] });
}

// ---------------------------------------------------------------- API-Listener

// Pfad ohne Query, ohne ein einzelnes abschließendes „/“, das führende /v1 ist optional.
function normalisierePfad(url) {
  let pfad = url.split("?")[0].split("#")[0];
  if (!pfad.startsWith("/")) return null;
  if (pfad.length > 1 && pfad.endsWith("/")) pfad = pfad.slice(0, -1);
  if (pfad === "/v1") return "/";
  if (pfad.startsWith("/v1/")) pfad = pfad.slice(3);
  return pfad;
}

const ROUTEN = {
  "POST /chat/completions": { json: true, ablauf: (res, daten, body) => chatCompletions(res, daten, body) },
  "POST /embeddings": { json: true, ablauf: (res, daten) => embeddings(res, daten) },
  "GET /models": { json: false, ablauf: (res) => modelle(res) },
};

async function apiBehandeln(req, res) {
  const { text: body, zuGross } = await bodyLesen(req, BODY_MAX_REQUEST);
  // Ein zu großer Body wird nicht protokolliert: Maskierung braucht den ganzen Wert.
  ringEintragen(req.method, req.url ?? "", body);
  if (zuGross) return fehler(res, 413, "invalid_request_error", "Body zu groß");
  const pfad = normalisierePfad(req.url ?? "");
  const pfadBekannt = pfad !== null && Object.keys(ROUTEN).some((k) => k.endsWith(` ${pfad}`));
  const route = pfad === null ? undefined : ROUTEN[`${req.method} ${pfad}`];
  if (!route) {
    if (pfadBekannt) return fehler(res, 405, "invalid_request_error", "Methode nicht erlaubt");
    return fehler(res, 404, "invalid_request_error", "Pfad unbekannt");
  }
  let daten = null;
  if (route.json) {
    const geparst = parseJson(body);
    if (!geparst.ok || !istObjekt(geparst.wert)) return fehler(res, 400, "invalid_request_error", "Body ist kein gültiges JSON-Objekt");
    daten = geparst.wert;
  }
  route.ablauf(res, daten, body);
}

// ---------------------------------------------------------------- Steuerung (nur 127.0.0.1)

async function steuerBehandeln(req, res) {
  if (req.method === "GET" && req.url === "/bereit") return antwortJson(res, 200, { bereit: true });
  if (req.method === "POST" && (req.url === "/setzen" || req.url === "/protokoll")) {
    const { text, zuGross } = await bodyLesen(req, BODY_MAX_STEUER);
    if (zuGross) return antwortJson(res, 400, { fehler: "Eingabe zu groß" });
    const geparst = parseJson(text);
    if (!geparst.ok) return antwortJson(res, 400, { fehler: "kein gültiges JSON" });
    if (req.url === "/setzen") {
      const problem = pruefeAntworten(geparst.wert);
      if (problem) return antwortJson(res, 400, { fehler: problem });
      zustand.warteschlange = normalisiereAntworten(geparst.wert);
      return antwortJson(res, 200, { gesetzt: zustand.warteschlange.length });
    }
    const daten = geparst.wert;
    const problem = pruefeWerte(istObjekt(daten) ? { werte: daten.werte } : daten);
    let suche = null;
    if (istObjekt(daten) && Object.hasOwn(daten, "suche") && daten.suche !== null) {
      if (typeof daten.suche !== "string" || daten.suche.length < 1 || daten.suche.length > 200) return antwortJson(res, 400, { fehler: "suche ungültig" });
      suche = daten.suche;
    }
    if (problem) return antwortJson(res, 400, { fehler: problem });
    const text2 = protokollAusgabe(daten.werte, suche);
    res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(text2) });
    return res.end(text2);
  }
  return antwortJson(res, 404, { fehler: "unbekannt" });
}

function absichern(behandler) {
  return (req, res) => {
    behandler(req, res).catch(() => {
      if (!res.headersSent) {
        try {
          fehler(res, 500, "api_error", "interner Fehler");
        } catch {
          res.destroy();
        }
      } else {
        res.destroy();
      }
    });
  };
}

function lauschen(server, port, host) {
  return new Promise((ok, nein) => {
    server.once("error", nein);
    server.listen({ port, host }, () => {
      server.off("error", nein);
      ok(server.address().port);
    });
  });
}

async function serverStarten(a) {
  const api = http.createServer(absichern(apiBehandeln));
  const steuer = http.createServer(absichern(steuerBehandeln));
  let apiPort;
  let steuerPort;
  try {
    apiPort = await lauschen(api, a.port, a.host);
    steuerPort = await lauschen(steuer, a.steuerPort, "127.0.0.1");
  } catch {
    abbruch("Port nicht verfügbar", 1);
  }
  if (a.port === 0 || a.steuerPort === 0) process.stdout.write(`bereit api=${apiPort} steuer=${steuerPort}\n`);
}

// ---------------------------------------------------------------- Clientmodi

function steuerAnfrage(port, methode, pfad, body) {
  return new Promise((ok, nein) => {
    const req = http.request({ host: "127.0.0.1", port, method: methode, path: pfad, agent: false, timeout: 10000, headers: body === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (res) => {
      const teile = [];
      res.on("data", (t) => teile.push(t));
      res.on("end", () => ok({ status: res.statusCode, text: Buffer.concat(teile).toString("utf8") }));
      res.on("error", nein);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", nein);
    if (body !== null) req.write(body);
    req.end();
  });
}

async function stdinLesen() {
  const teile = [];
  let gesamt = 0;
  for await (const t of process.stdin) {
    gesamt += t.length;
    if (gesamt > STDIN_MAX) abbruch("stdin zu groß", 2);
    teile.push(t);
  }
  return Buffer.concat(teile).toString("utf8");
}

function portWert(text, name, null0Erlaubt) {
  if (text === undefined) return undefined;
  if (!/^\d{1,5}$/.test(text) || Number(text) > 65535 || (!null0Erlaubt && Number(text) === 0)) abbruch(`${name}: ungültig`, 2);
  return Number(text);
}

function beenden(code) {
  process.stdout.write("", () => process.exit(code));
}

async function main() {
  let werte;
  try {
    werte = parseArgs({
      args: process.argv.slice(2),
      allowPositionals: false,
      strict: true,
      options: {
        server: { type: "boolean" },
        bereit: { type: "boolean" },
        setzen: { type: "boolean" },
        protokoll: { type: "boolean" },
        host: { type: "string" },
        port: { type: "string" },
        "steuer-port": { type: "string" },
        suche: { type: "string" },
      },
    }).values;
  } catch {
    abbruch("ungültige Argumente", 2);
  }
  const modi = ["server", "bereit", "setzen", "protokoll"].filter((m) => werte[m]);
  if (modi.length !== 1) abbruch("genau einen Modus angeben: --server, --bereit, --setzen oder --protokoll", 2);
  const modus = modi[0];
  if ((werte.host !== undefined || werte.port !== undefined) && modus !== "server") abbruch("--host und --port gehören nur zu --server", 2);
  if (werte.suche !== undefined && modus !== "protokoll") abbruch("--suche gehört nur zu --protokoll", 2);
  if (werte.suche !== undefined && (werte.suche.length < 1 || werte.suche.length > 200)) abbruch("--suche: ungültig", 2);

  if (modus === "server") {
    const port = portWert(werte.port, "--port", true) ?? 4010;
    const steuerPort = portWert(werte["steuer-port"], "--steuer-port", true) ?? 4011;
    if (werte.host !== undefined && werte.host.length === 0) abbruch("--host: ungültig", 2);
    await serverStarten({ host: werte.host ?? "0.0.0.0", port, steuerPort });
    return;
  }

  const steuerPort = portWert(werte["steuer-port"], "--steuer-port", false) ?? 4011;
  if (modus === "bereit") {
    try {
      const r = await steuerAnfrage(steuerPort, "GET", "/bereit", null);
      beenden(r.status === 200 ? 0 : 1);
    } catch {
      beenden(1);
    }
    return;
  }

  const eingabe = parseJson(await stdinLesen());
  if (!eingabe.ok) abbruch("stdin ist kein gültiges JSON", 2);
  let pfad;
  let body;
  if (modus === "setzen") {
    if (pruefeAntworten(eingabe.wert)) abbruch("Antwortliste ungültig", 2);
    pfad = "/setzen";
    body = JSON.stringify(eingabe.wert);
  } else {
    if (pruefeWerte(eingabe.wert)) abbruch("Werteliste ungültig", 2);
    pfad = "/protokoll";
    body = JSON.stringify({ werte: eingabe.wert.werte, suche: werte.suche ?? null });
  }
  let r;
  try {
    r = await steuerAnfrage(steuerPort, "POST", pfad, body);
  } catch {
    abbruch("Steuerung nicht erreichbar", 1);
  }
  if (r.status === 400) abbruch("Eingabe abgelehnt", 2);
  if (r.status !== 200) abbruch("Steuerung antwortet mit Fehler", 1);
  if (modus === "protokoll") process.stdout.write(`${r.text}\n`, () => process.exit(0));
  else beenden(0);
}

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));
process.on("uncaughtException", () => {
  process.stderr.write("fehler: interner Fehler\n");
  process.exit(1);
});
process.on("unhandledRejection", () => {
  process.stderr.write("fehler: interner Fehler\n");
  process.exit(1);
});

await main();
