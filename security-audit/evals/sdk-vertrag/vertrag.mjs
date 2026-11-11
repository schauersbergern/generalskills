import "./waechter.mjs";
// SDK-Vertragstest: Die echten Clients (openai, @anthropic-ai/sdk, ai mit @ai-sdk/openai und @ai-sdk/anthropic) sprechen
// gegen den Modell-Mock. Die Basis-URL steht NIE im Code: Sie kommt allein aus OPENAI_BASE_URL und ANTHROPIC_BASE_URL
// (der Mock-Port steckt darin). Vor dem ersten SDK-Import gilt der Wächter (erste Zeile). Die SDKs laden nur per await import().
//
//   node vertrag.mjs              führt alle Fälle aus und schreibt je Fall eine JSON-Zeile
//                                 {paket, weg, stream, art, ergebnis, waechter}
//                                 ergebnis: "gruen", "rot: <Grund>" oder "liest Env nicht" (der Wächter hat ausgelöst)
//   node vertrag.mjs --faelle     die Fallliste als JSON (kein SDK-Import)
//   node vertrag.mjs --antworten  die Antwortliste für `llm-mock.mjs --setzen` als JSON (kein SDK-Import)
// Exit-Codes: 0 = alle Zeilen geschrieben (rot ist keine Fehlermeldung des Skripts), 3 = Selbsttest des Wächters
// gescheitert (es wird kein SDK importiert), 4 = Umgebung ungültig (Basis-URL nicht 127.0.0.1 oder Schlüssel nicht poc-dummy-).

import { treffer } from "./waechter.mjs";
import http from "node:http";

const WERKZEUG = "wetter_abfragen";
const ARGUMENTE = { ort: "Berlin", tage: 3 };
const SCHEMA = { type: "object", properties: { ort: { type: "string" }, tage: { type: "integer" } }, required: ["ort"] };
const BESCHREIBUNG = "Gibt die Wettervorhersage für einen Ort zurück.";
const FRIST_MS = 20000;

// ------------------------------------------------------------------ Selbsttest (vor jedem SDK-Import)

async function selbsttest() {
  let fetchAbgewiesen = false;
  let httpAbgewiesen = false;
  try {
    await fetch("http://192.0.2.1:9/", { signal: AbortSignal.timeout(500) });
  } catch (e) {
    fetchAbgewiesen = e?.code === "EWAECHTER";
  }
  try {
    const r = http.request({ host: "192.0.2.1", port: 9, path: "/" });
    r?.destroy?.();
  } catch (e) {
    httpAbgewiesen = e?.code === "EWAECHTER";
  }
  treffer.length = 0;
  if (!fetchAbgewiesen || !httpAbgewiesen) {
    process.stderr.write(`Selbsttest des Wächters gescheitert (fetch abgewiesen: ${fetchAbgewiesen}, http.request abgewiesen: ${httpAbgewiesen}), es wird kein SDK importiert.\n`);
    process.exit(3);
  }
}

await selbsttest();

// ------------------------------------------------------------------ Umgebung

function umgebungPruefen() {
  for (const name of ["OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"]) {
    let ok = false;
    try {
      const u = new URL(process.env[name] ?? "");
      ok = u.protocol === "http:" && u.hostname === "127.0.0.1" && u.port !== "" && !u.username && !u.password;
    } catch {}
    if (!ok) {
      process.stderr.write(`Umgebung ungültig: ${name} muss http://127.0.0.1:<port> sein (der Mock-Port kommt nur aus der Umgebung).\n`);
      process.exit(4);
    }
  }
  for (const name of ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]) {
    if (!String(process.env[name] ?? "").startsWith("poc-dummy-")) {
      process.stderr.write(`Umgebung ungültig: ${name} muss ein poc-dummy-Wert sein.\n`);
      process.exit(4);
    }
  }
}

umgebungPruefen();

// ------------------------------------------------------------------ Fälle

// [paket, weg, stream, art]
const FAELLE = [];
for (const [paket, weg] of [
  ["openai", "chat"],
  ["openai", "responses"],
  ["@anthropic-ai/sdk", "messages"],
  ["ai+@ai-sdk/openai", "responses"],
  ["ai+@ai-sdk/openai", "chat"],
  ["ai+@ai-sdk/anthropic", "messages"],
]) {
  for (const stream of [false, true]) {
    for (const art of ["text", "tool"]) FAELLE.push({ paket, weg, stream, art });
  }
}
FAELLE.push({ paket: "openai", weg: "embeddings", stream: false, art: "embedding" });

const nummer = (i) => String(i).padStart(2, "0");
const marker = (i) => `POCMARKER-vertrag-${nummer(i)}`;
const textVon = (i) => `vertrag-antwort-${nummer(i)}`;
const frage = (i) => `${marker(i)} Wie wird das Wetter in Berlin?`;

function antworten() {
  const liste = [];
  FAELLE.forEach((f, i) => {
    if (f.art === "text") liste.push({ wenn_enthaelt: marker(i), text: textVon(i) });
    if (f.art === "tool") liste.push({ wenn_enthaelt: marker(i), werkzeug: { name: WERKZEUG, argumente: ARGUMENTE } });
  });
  return liste;
}

if (process.argv.includes("--faelle")) {
  process.stdout.write(JSON.stringify(FAELLE) + "\n", () => process.exit(0));
  await new Promise(() => {});
}
if (process.argv.includes("--antworten")) {
  process.stdout.write(JSON.stringify(antworten()) + "\n", () => process.exit(0));
  await new Promise(() => {});
}

// ------------------------------------------------------------------ Ausführung je Weg

const gleich = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function parseArgumente(roh) {
  return typeof roh === "string" ? JSON.parse(roh) : roh;
}

// Gemeinsame Bewertung: Text oder genau ein Werkzeugaufruf, dazu die wegspezifischen Prüfungen (`bedingungen`).
function bewerte(f, i, ist) {
  const probleme = [...(ist.probleme ?? [])];
  if (f.art === "text") {
    if (ist.text !== textVon(i)) probleme.push(`Text ${JSON.stringify(ist.text)} statt ${JSON.stringify(textVon(i))}`);
    if (ist.werkzeuge.length) probleme.push("unerwarteter Werkzeugaufruf");
  } else {
    if (ist.werkzeuge.length !== 1) probleme.push(`${ist.werkzeuge.length} Werkzeugaufrufe statt 1`);
    else {
      if (ist.werkzeuge[0].name !== WERKZEUG) probleme.push(`Werkzeugname ${JSON.stringify(ist.werkzeuge[0].name)}`);
      if (!gleich(ist.werkzeuge[0].argumente, ARGUMENTE)) probleme.push(`Argumente ${JSON.stringify(ist.werkzeuge[0].argumente)}`);
    }
    if (ist.text) probleme.push("unerwarteter Text neben dem Werkzeugaufruf");
  }
  return probleme;
}

async function openaiChat(f, i) {
  const { default: OpenAI } = await import("openai");
  const client = new OpenAI({ maxRetries: 0, timeout: FRIST_MS }); // Basis-URL und Schlüssel nur aus der Umgebung
  const anfrage = {
    model: "poc-mock",
    messages: [{ role: "user", content: frage(i) }],
    tools: [{ type: "function", function: { name: WERKZEUG, description: BESCHREIBUNG, parameters: SCHEMA } }],
  };
  const erwartetEnde = f.art === "tool" ? "tool_calls" : "stop";
  const probleme = [];
  let text = "";
  const werkzeuge = [];
  if (!f.stream) {
    const res = await client.chat.completions.create(anfrage);
    const c = res.choices[0];
    text = c.message.content ?? "";
    for (const t of c.message.tool_calls ?? []) werkzeuge.push({ name: t.function.name, argumente: parseArgumente(t.function.arguments) });
    if (c.finish_reason !== erwartetEnde) probleme.push(`finish_reason ${c.finish_reason}`);
    if (!res.usage || typeof res.usage.total_tokens !== "number") probleme.push("usage fehlt");
  } else {
    const strom = await client.chat.completions.create({ ...anfrage, stream: true, stream_options: { include_usage: true } });
    const teile = new Map();
    let ende = null;
    let usage = null;
    for await (const chunk of strom) {
      if (chunk.usage) usage = chunk.usage;
      const c = chunk.choices?.[0];
      if (!c) continue;
      text += c.delta?.content ?? "";
      for (const t of c.delta?.tool_calls ?? []) {
        const z = teile.get(t.index) ?? { name: "", roh: "" };
        z.name += t.function?.name ?? "";
        z.roh += t.function?.arguments ?? "";
        teile.set(t.index, z);
      }
      if (c.finish_reason) ende = c.finish_reason;
    }
    for (const z of teile.values()) werkzeuge.push({ name: z.name, argumente: parseArgumente(z.roh) });
    if (ende !== erwartetEnde) probleme.push(`finish_reason ${ende}`);
    if (!usage) probleme.push("usage-Chunk fehlt");
  }
  return { text, werkzeuge, probleme };
}

async function openaiResponses(f, i) {
  const { default: OpenAI } = await import("openai");
  const client = new OpenAI({ maxRetries: 0, timeout: FRIST_MS });
  const anfrage = {
    model: "poc-mock",
    input: frage(i),
    tools: [{ type: "function", name: WERKZEUG, description: BESCHREIBUNG, parameters: SCHEMA, strict: false }],
  };
  const probleme = [];
  let text = "";
  const werkzeuge = [];
  if (!f.stream) {
    const res = await client.responses.create(anfrage);
    text = res.output_text ?? "";
    for (const item of res.output ?? []) {
      if (item.type === "function_call") werkzeuge.push({ name: item.name, argumente: parseArgumente(item.arguments) });
    }
    if (res.status !== "completed") probleme.push(`status ${res.status}`);
    if (!res.usage) probleme.push("usage fehlt");
  } else {
    const strom = await client.responses.create({ ...anfrage, stream: true });
    let deltaText = "";
    let deltaArgumente = "";
    let fertig = null;
    for await (const ereignis of strom) {
      if (ereignis.type === "response.output_text.delta") deltaText += ereignis.delta;
      if (ereignis.type === "response.function_call_arguments.delta") deltaArgumente += ereignis.delta;
      if (ereignis.type === "response.completed") fertig = ereignis.response;
    }
    if (!fertig) probleme.push("response.completed fehlt");
    else {
      for (const item of fertig.output ?? []) {
        if (item.type === "function_call") werkzeuge.push({ name: item.name, argumente: parseArgumente(item.arguments) });
        if (item.type === "message") text += (item.content ?? []).filter((c) => c.type === "output_text").map((c) => c.text).join("");
      }
      if (!fertig.usage) probleme.push("usage fehlt");
    }
    if (deltaText !== text) probleme.push("Text-Deltas und fertige Antwort weichen ab");
    if (f.art === "tool" && !gleich(parseArgumente(deltaArgumente), ARGUMENTE)) probleme.push("Argument-Deltas weichen ab");
  }
  return { text, werkzeuge, probleme };
}

async function openaiEmbeddings() {
  const { default: OpenAI } = await import("openai");
  const client = new OpenAI({ maxRetries: 0, timeout: FRIST_MS });
  const res = await client.embeddings.create({ model: "poc-mock", input: "hallo" });
  const v = res.data?.[0]?.embedding;
  const probleme = [];
  if (!Array.isArray(v) || v.length !== 1536 || !v.every((x) => typeof x === "number")) probleme.push("Vektor ungültig");
  return { embedding: true, probleme };
}

async function anthropicMessages(f, i) {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const client = new Anthropic({ maxRetries: 0, timeout: FRIST_MS }); // Basis-URL und Schlüssel nur aus der Umgebung
  const anfrage = {
    model: "poc-mock",
    max_tokens: 256,
    messages: [{ role: "user", content: frage(i) }],
    tools: [{ name: WERKZEUG, description: BESCHREIBUNG, input_schema: SCHEMA }],
  };
  const probleme = [];
  let nachricht;
  if (!f.stream) nachricht = await client.messages.create(anfrage);
  else nachricht = await client.messages.stream(anfrage).finalMessage();
  let text = "";
  const werkzeuge = [];
  for (const b of nachricht.content ?? []) {
    if (b.type === "text") text += b.text;
    if (b.type === "tool_use") werkzeuge.push({ name: b.name, argumente: b.input });
  }
  const erwartetEnde = f.art === "tool" ? "tool_use" : "end_turn";
  if (nachricht.stop_reason !== erwartetEnde) probleme.push(`stop_reason ${nachricht.stop_reason}`);
  if (!nachricht.usage || typeof nachricht.usage.output_tokens !== "number") probleme.push("usage fehlt");
  return { text, werkzeuge, probleme };
}

async function aiSdk(f, i, modellErzeuger) {
  const { generateText, streamText, jsonSchema, tool } = await import("ai");
  const model = await modellErzeuger();
  const tools = { [WERKZEUG]: tool({ description: BESCHREIBUNG, inputSchema: jsonSchema(SCHEMA) }) };
  const gemeinsam = { model, prompt: frage(i), tools, maxRetries: 0, abortSignal: AbortSignal.timeout(FRIST_MS) };
  const probleme = [];
  let text = "";
  const werkzeuge = [];
  const erwartetEnde = f.art === "tool" ? "tool-calls" : "stop";
  if (!f.stream) {
    const res = await generateText(gemeinsam);
    text = res.text ?? "";
    for (const t of res.toolCalls ?? []) werkzeuge.push({ name: t.toolName, argumente: t.input });
    if (res.finishReason !== erwartetEnde) probleme.push(`finishReason ${res.finishReason}`);
  } else {
    const fehler = [];
    const res = streamText({ ...gemeinsam, onError: ({ error }) => fehler.push(error) });
    for await (const teil of res.fullStream) {
      if (teil.type === "text-delta") text += teil.text ?? teil.delta ?? "";
      if (teil.type === "tool-call") werkzeuge.push({ name: teil.toolName, argumente: teil.input });
      if (teil.type === "error") fehler.push(teil.error);
    }
    if (fehler.length) throw fehler[0] instanceof Error ? fehler[0] : new Error(String(fehler[0]));
    const ende = await res.finishReason;
    if (ende !== erwartetEnde) probleme.push(`finishReason ${ende}`);
  }
  return { text, werkzeuge, probleme };
}

const LAUF = {
  "openai|chat": openaiChat,
  "openai|responses": openaiResponses,
  "openai|embeddings": openaiEmbeddings,
  "@anthropic-ai/sdk|messages": anthropicMessages,
  "ai+@ai-sdk/openai|responses": (f, i) => aiSdk(f, i, async () => (await import("@ai-sdk/openai")).openai.responses("poc-mock")),
  "ai+@ai-sdk/openai|chat": (f, i) => aiSdk(f, i, async () => (await import("@ai-sdk/openai")).openai.chat("poc-mock")),
  "ai+@ai-sdk/anthropic|messages": (f, i) => aiSdk(f, i, async () => (await import("@ai-sdk/anthropic")).anthropic("poc-mock")),
};

function kurz(e) {
  const text = `${e?.name ?? "Fehler"}: ${e?.message ?? e}`.replace(/\s+/g, " ");
  return text.length > 200 ? `${text.slice(0, 200)}...` : text;
}

async function mitFrist(p) {
  let timer;
  const frist = new Promise((_, nein) => {
    timer = setTimeout(() => nein(new Error("Frist überschritten")), FRIST_MS + 10000);
  });
  try {
    return await Promise.race([p, frist]);
  } finally {
    clearTimeout(timer);
  }
}

const zeilen = [];
for (let i = 0; i < FAELLE.length; i++) {
  const f = FAELLE[i];
  const vor = treffer.length;
  let ergebnis;
  try {
    const ist = await mitFrist(LAUF[`${f.paket}|${f.weg}`](f, i));
    const probleme = ist.embedding ? ist.probleme : bewerte(f, i, ist);
    ergebnis = probleme.length ? `rot: ${probleme.join("; ")}` : "gruen";
  } catch (e) {
    ergebnis = `rot: ${kurz(e)}`;
  }
  const hits = treffer.slice(vor).map((t) => ({ art: t.art, ziel: t.ziel }));
  if (hits.length) ergebnis = "liest Env nicht";
  zeilen.push(JSON.stringify({ paket: f.paket, weg: f.weg, stream: f.stream, art: f.art, ergebnis, waechter: hits }) + "\n");
}
process.stdout.write(zeilen.join(""), () => process.exit(0));
