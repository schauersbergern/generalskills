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
//       stdin: {"werte":[{"name":"N","wert":"..."}]}. stdout: {"eintraege":[{nr,methode,pfad,body[,standard][,fundstelle]}],"gekuerzt":n,"aelter":m},
//       reines ASCII, höchstens 64 KiB. Die Werte werden roh und JSON-escaped durch <ENV:N> ersetzt (längste zuerst),
//       erst danach wird jeder Body auf 8 KiB gekürzt. --suche sucht im maskierten Body und liefert je Eintrag zusätzlich
//       `fundstelle`: der einzeilige Ausschnitt (höchstens 300 Zeichen) um das erste Vorkommen, auch hinter der Kürzung.
//       `standard: true` heißt: kein Eintrag der Antwortliste passte, der Mock antwortete mit „ok“. `aelter` ist die Zahl der Requests, die der
//       Ring (die letzten 50) schon verdrängt hat; `gekuerzt` zählt dagegen die wegen der Ausgabegrenze weggelassenen Einträge (zuerst die mit `standard: true`, dann die ältesten).
// API-Endpunkte (mit oder ohne /v1): POST chat/completions, responses, messages, embeddings sowie GET models.
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
const AUSGABE_MAX = 65536 - 1; // die Ausgabe des CLI hat einen abschließenden Zeilenumbruch und darf höchstens 65 536 Bytes haben
const MAX_VERBINDUNGEN = 64;
const ZEITGRENZE_MS = 30_000;
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

// Liest den Body bis `limit`. Wird das Limit überschritten, endet das Lesen sofort (zuGross), der Rest des Requests wird nicht gelesen.
// Der Aufrufer antwortet dann mit 413 und `Connection: close` (siehe `zuGrossAntworten`).
function bodyLesen(req, limit) {
  return new Promise((ok, nein) => {
    const teile = [];
    let gesamt = 0;
    let fertig = false;
    const ende = (ergebnis) => {
      if (fertig) return;
      fertig = true;
      req.off("data", beiDaten);
      ok(ergebnis);
    };
    const beiDaten = (teil) => {
      gesamt += teil.length;
      if (gesamt > limit) {
        teile.length = 0;
        req.pause();
        ende({ text: "", zuGross: true });
        return;
      }
      teile.push(teil);
    };
    req.on("data", beiDaten);
    req.on("end", () => ende({ text: Buffer.concat(teile).toString("utf8"), zuGross: false }));
    req.on("error", (e) => {
      if (!fertig) {
        fertig = true;
        nein(e);
      }
    });
    req.on("close", () => {
      if (!fertig && !req.complete) {
        fertig = true;
        nein(new Error("abgebrochen"));
      }
    });
  });
}

// 413 sofort, Verbindung danach schließen: ein Dauerstrom wird nicht bis zum Ende gelesen.
function zuGrossAntworten(res) {
  res.setHeader("connection", "close");
  fehler(res, 413, "invalid_request_error", "Body zu groß");
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

// Benanntes SSE-Ereignis (`event:` plus `data:`), wie es die Responses-API und die Messages-API senden.
function sseEreignis(res, name, objekt) {
  res.write(`event: ${name}\ndata: ${JSON.stringify(objekt)}\n\n`);
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
// Der Eintrag wird verbraucht. Ohne Treffer antwortet der Mock mit „ok“ und markiert den Protokolleintrag des Requests mit `standard`,
// damit die Rückfallantwort im Protokoll sichtbar ist (ein Marker, der nicht passte, oder ein schon verbrauchter Eintrag).
function naechsteAntwort(body, eintrag) {
  const i = zustand.warteschlange.findIndex((e) => e.wenn_enthaelt === undefined || body.includes(e.wenn_enthaelt));
  if (i < 0) {
    eintrag.standard = true;
    return { typ: "text", text: "ok" };
  }
  const [e] = zustand.warteschlange.splice(i, 1);
  if (e.werkzeug) return { typ: "werkzeug", name: e.werkzeug.name, argumente: e.werkzeug.argumente };
  return { typ: "text", text: e.text };
}

// ---------------------------------------------------------------- Protokoll und Maskierung

function ringEintragen(methode, pfad, body) {
  zustand.nr += 1;
  // Methode und Pfad werden hier nicht gekürzt: erst die Ausgabe maskiert und kürzt (Node begrenzt die Request-Zeile über die Headergrenze).
  const eintrag = { nr: zustand.nr, methode: String(methode), pfad: String(pfad), body };
  zustand.ring.push(eintrag);
  while (zustand.ring.length > RING_MAX) zustand.ring.shift();
  return eintrag;
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

// Ersetzt Rohform, einfach und doppelt JSON-escapte Form (auch mit \uXXXX), längste zuerst, in einem Durchgang.
// Nicht erfasst: dreifaches Escapen, URL-Kodierung, Base64 und Teilstücke über Feldgrenzen.
// Der Ersatztext wird nicht erneut durchsucht.
function maskierer(werte) {
  const formen = [];
  for (const { name, wert } of werte) {
    if (wert.length === 0) continue;
    // Rohform, einmal escapt (JSON-Body) und zweimal escapt (Tool-Ergebnis als JSON-String in einem JSON-Body). Nicht-ASCII-Zeichen
    // stehen roh oder als \uXXXX (klein oder groß); in der zweiten Stufe kann schon die erste Stufe \uXXXX enthalten (Python-Standard),
    // dann steht der Backslash doppelt im Body.
    const grossHex = (f) => f.replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0").toUpperCase()}`);
    const jsonForm = JSON.stringify(wert).slice(1, -1);
    const kandidaten = new Set([wert]);
    for (const stufe1 of [jsonForm, ascii(jsonForm), grossHex(jsonForm)]) {
      kandidaten.add(stufe1);
      const doppel = JSON.stringify(stufe1).slice(1, -1);
      for (const f of [doppel, ascii(doppel), grossHex(doppel)]) kandidaten.add(f);
    }
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

const FUNDSTELLE_MAX = 300;
const FUNDSTELLE_VOR = 60;

// Ausschnitt des (maskierten, ungekürzten) Bodys um das erste Vorkommen von `suche`, höchstens 300 Zeichen, einzeilig.
// Der Marker (höchstens 200 Zeichen) steht immer vollständig darin.
function fundstelle(body, suche) {
  const i = body.indexOf(suche);
  if (i < 0) return "";
  let von = Math.max(0, i - FUNDSTELLE_VOR);
  let bis = Math.min(body.length, von + FUNDSTELLE_MAX);
  if (von > 0 && von < i && /[\udc00-\udfff]/.test(body[von])) von += 1; // kein halbes Ersatzzeichenpaar am Rand
  if (bis < body.length && bis > i + suche.length && /[\ud800-\udbff]/.test(body[bis - 1])) bis -= 1;
  return body.slice(von, bis).replace(/[\r\n\u2028\u2029]/g, " ");
}

function protokollAusgabe(werte, suche) {
  const maske = maskierer(werte);
  let eintraege = zustand.ring.map((e) => ({
    nr: e.nr,
    methode: maske(e.methode).slice(0, 16),
    pfad: maske(e.pfad).slice(0, PFAD_MAX), // erst maskieren, dann kürzen
    body: maske(e.body), // erst maskieren, dann kürzen
    ...(e.standard ? { standard: true } : {}),
  }));
  const aelter = zustand.nr - zustand.ring.length; // Requests, die der Ring schon verdrängt hat (auch bei --suche der Gesamtstand)
  if (suche !== null) eintraege = eintraege.filter((e) => e.body.includes(suche));
  const strings = eintraege.map((e) => {
    const ausgabe = { ...e, body: kuerzen(e.body) };
    if (suche !== null) ausgabe.fundstelle = fundstelle(e.body, suche);
    return { text: jsonAscii(ausgabe), standard: e.standard === true };
  });
  let gekuerzt = 0;
  const gesamt = () => {
    const kopf = `{"eintraege":[`;
    const fuss = `],"gekuerzt":${gekuerzt},"aelter":${aelter}}`;
    return Buffer.byteLength(kopf) + Buffer.byteLength(fuss) + strings.reduce((s, x) => s + Buffer.byteLength(x.text), 0) + Math.max(0, strings.length - 1);
  };
  // Erst fallen Rückfallantworten (`standard: true`) weg, die ältesten zuerst: Der Request, der einen Antworteintrag verbraucht hat,
  // ist der Beleg und bleibt so lange wie möglich. Erst danach fallen die übrigen Einträge weg, wieder die ältesten zuerst.
  while (strings.length > 0 && gesamt() > AUSGABE_MAX) {
    const i = strings.findIndex((x) => x.standard);
    strings.splice(i < 0 ? 0 : i, 1);
    gekuerzt += 1;
  }
  return `{"eintraege":[${strings.map((x) => x.text).join(",")}],"gekuerzt":${gekuerzt},"aelter":${aelter}}`;
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

function chatCompletions(res, daten, body, eintrag) {
  const antwort = naechsteAntwort(body, eintrag);
  if (daten.stream === true) {
    const mitUsage = istObjekt(daten.stream_options) && daten.stream_options.include_usage === true;
    chatStreamend(res, antwort, Buffer.byteLength(body), mitUsage);
  } else {
    chatNichtStreamend(res, antwort, Buffer.byteLength(body));
  }
}

// ---------------------------------------------------------------- Responses

function antwortZeichen(antwort) {
  return antwort.typ === "text" ? antwort.text.length : JSON.stringify(antwort.argumente).length + antwort.name.length;
}

function usageResponses(bodyLaenge, antwort) {
  const eingabe = tokenZahl(bodyLaenge);
  const ausgabe = tokenZahl(antwortZeichen(antwort));
  return {
    input_tokens: eingabe,
    input_tokens_details: { cached_tokens: 0 },
    output_tokens: ausgabe,
    output_tokens_details: { reasoning_tokens: 0 },
    total_tokens: eingabe + ausgabe,
  };
}

function responseObjekt(id, erstellt, status, output, usage) {
  return {
    id,
    object: "response",
    created_at: erstellt,
    status,
    error: null,
    incomplete_details: null,
    instructions: null,
    max_output_tokens: null,
    model: MODELL,
    output,
    parallel_tool_calls: true,
    previous_response_id: null,
    reasoning: { effort: null, summary: null },
    store: false,
    temperature: 1,
    text: { format: { type: "text" } },
    tool_choice: "auto",
    tools: [],
    top_p: 1,
    truncation: "disabled",
    usage,
    user: null,
    metadata: {},
  };
}

// Das fertige Output-Item. `status` ist beim Anlegen „in_progress“ (ohne Inhalt), am Ende „completed“.
function responsesItem(antwort, ids, status, fertig) {
  if (antwort.typ === "text") {
    return {
      id: ids.item,
      type: "message",
      status,
      role: "assistant",
      content: fertig ? [{ type: "output_text", text: antwort.text, annotations: [] }] : [],
    };
  }
  return {
    id: ids.item,
    type: "function_call",
    status,
    call_id: ids.aufruf,
    name: antwort.name,
    arguments: fertig ? JSON.stringify(antwort.argumente) : "",
  };
}

function responsesIds(antwort) {
  const ids = { antwort: eindeutigeKennung("resp_") };
  if (antwort.typ === "text") ids.item = eindeutigeKennung("msg_");
  else {
    ids.item = eindeutigeKennung("fc_");
    ids.aufruf = eindeutigeKennung("call_");
  }
  return ids;
}

function responsesNichtStreamend(res, antwort, bodyLaenge) {
  const ids = responsesIds(antwort);
  const item = responsesItem(antwort, ids, "completed", true);
  antwortJson(res, 200, responseObjekt(ids.antwort, Math.floor(Date.now() / 1000), "completed", [item], usageResponses(bodyLaenge, antwort)));
}

function responsesStreamend(res, antwort, bodyLaenge) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  const ids = responsesIds(antwort);
  const erstellt = Math.floor(Date.now() / 1000);
  let folge = 0;
  const ereignis = (typ, felder) => sseEreignis(res, typ, { type: typ, ...felder, sequence_number: folge++ });
  const fertig = responsesItem(antwort, ids, "completed", true);

  ereignis("response.created", { response: responseObjekt(ids.antwort, erstellt, "in_progress", [], null) });
  ereignis("response.output_item.added", { output_index: 0, item: responsesItem(antwort, ids, "in_progress", false) });
  if (antwort.typ === "text") {
    const teil = { item_id: ids.item, output_index: 0, content_index: 0 };
    ereignis("response.content_part.added", { ...teil, part: { type: "output_text", text: "", annotations: [] } });
    for (const s of stuecke(antwort.text, 12)) ereignis("response.output_text.delta", { ...teil, delta: s, logprobs: [] });
    ereignis("response.output_text.done", { ...teil, text: antwort.text, logprobs: [] });
    ereignis("response.content_part.done", { ...teil, part: fertig.content[0] });
  } else {
    const teil = { item_id: ids.item, output_index: 0 };
    for (const s of stuecke(fertig.arguments, 12)) ereignis("response.function_call_arguments.delta", { ...teil, delta: s });
    ereignis("response.function_call_arguments.done", { ...teil, name: antwort.name, arguments: fertig.arguments });
  }
  ereignis("response.output_item.done", { output_index: 0, item: fertig });
  ereignis("response.completed", { response: responseObjekt(ids.antwort, erstellt, "completed", [fertig], usageResponses(bodyLaenge, antwort)) });
  res.end();
}

function responses(res, daten, body, eintrag) {
  const antwort = naechsteAntwort(body, eintrag);
  if (daten.stream === true) responsesStreamend(res, antwort, Buffer.byteLength(body));
  else responsesNichtStreamend(res, antwort, Buffer.byteLength(body));
}

// ---------------------------------------------------------------- Messages (Anthropic)

function usageMessages(eingabe, ausgabe) {
  return { input_tokens: eingabe, output_tokens: ausgabe, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
}

function messagesNichtStreamend(res, antwort, bodyLaenge) {
  const block =
    antwort.typ === "text"
      ? { type: "text", text: antwort.text }
      : { type: "tool_use", id: eindeutigeKennung("toolu_"), name: antwort.name, input: antwort.argumente };
  antwortJson(res, 200, {
    id: eindeutigeKennung("msg_"),
    type: "message",
    role: "assistant",
    model: MODELL,
    content: [block],
    stop_reason: antwort.typ === "text" ? "end_turn" : "tool_use",
    stop_sequence: null,
    usage: usageMessages(tokenZahl(bodyLaenge), tokenZahl(antwortZeichen(antwort))),
  });
}

function messagesStreamend(res, antwort, bodyLaenge) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  const eingabe = tokenZahl(bodyLaenge);
  const ausgabe = tokenZahl(antwortZeichen(antwort));
  const ereignis = (typ, felder) => sseEreignis(res, typ, { type: typ, ...felder });
  ereignis("message_start", {
    message: {
      id: eindeutigeKennung("msg_"),
      type: "message",
      role: "assistant",
      model: MODELL,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { ...usageMessages(eingabe, 1) },
    },
  });
  if (antwort.typ === "text") {
    ereignis("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
    for (const s of stuecke(antwort.text, 12)) ereignis("content_block_delta", { index: 0, delta: { type: "text_delta", text: s } });
  } else {
    ereignis("content_block_start", { index: 0, content_block: { type: "tool_use", id: eindeutigeKennung("toolu_"), name: antwort.name, input: {} } });
    for (const s of stuecke(JSON.stringify(antwort.argumente), 12)) ereignis("content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: s } });
  }
  ereignis("content_block_stop", { index: 0 });
  ereignis("message_delta", { delta: { stop_reason: antwort.typ === "text" ? "end_turn" : "tool_use", stop_sequence: null }, usage: { output_tokens: ausgabe } });
  ereignis("message_stop", {});
  res.end();
}

function messages(res, daten, body, eintrag) {
  const antwort = naechsteAntwort(body, eintrag);
  if (daten.stream === true) messagesStreamend(res, antwort, Buffer.byteLength(body));
  else messagesNichtStreamend(res, antwort, Buffer.byteLength(body));
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
  "POST /chat/completions": { json: true, ablauf: (res, daten, body, eintrag) => chatCompletions(res, daten, body, eintrag) },
  "POST /responses": { json: true, ablauf: (res, daten, body, eintrag) => responses(res, daten, body, eintrag) },
  "POST /messages": { json: true, ablauf: (res, daten, body, eintrag) => messages(res, daten, body, eintrag) },
  "POST /embeddings": { json: true, ablauf: (res, daten) => embeddings(res, daten) },
  "GET /models": { json: false, ablauf: (res) => modelle(res) },
};

async function apiBehandeln(req, res) {
  const { text: body, zuGross } = await bodyLesen(req, BODY_MAX_REQUEST);
  // Ein zu großer Body steht mit leerem Body im Ring (verbraucht eine nr): Die Maskierung braucht den ganzen Wert.
  const eintrag = ringEintragen(req.method, req.url ?? "", body);
  if (zuGross) return zuGrossAntworten(res);
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
  route.ablauf(res, daten, body, eintrag);
}

// ---------------------------------------------------------------- Steuerung (nur 127.0.0.1)

async function steuerBehandeln(req, res) {
  if (req.method === "GET" && req.url === "/bereit") return antwortJson(res, 200, { bereit: true });
  if (req.method === "POST" && (req.url === "/setzen" || req.url === "/protokoll")) {
    const { text, zuGross } = await bodyLesen(req, BODY_MAX_STEUER);
    if (zuGross) {
      res.setHeader("connection", "close");
      return antwortJson(res, 400, { fehler: "Eingabe zu groß" });
    }
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
  for (const server of [api, steuer]) {
    server.maxConnections = MAX_VERBINDUNGEN;
    server.requestTimeout = ZEITGRENZE_MS;
    server.headersTimeout = ZEITGRENZE_MS;
  }
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
