// HTTP-Client für den Security-Audit-PoC. Läuft nur im Wegwerf-Container im internen Netz.
//   node /poc/anfrage.mjs --url http://app:3000/pfad [--methode GET] [--header 'K: V']... [--warten <sek>]
// Body kommt von stdin. Ausgabe: status, header, body (höchstens 4096 Bytes). Redirects werden nicht verfolgt.
// Exit 0 = Antwort erhalten (jeder Status), 1 = Fehler/Timeout, 2 = ungültige Argumente.

const MAX_BODY = 4096;
const TIMEOUT_MS = 20000;

function abbruch(text, code) {
  console.error(`fehler: ${text}`);
  process.exit(code);
}

function argumente(argv) {
  const a = { methode: "GET", header: [], warten: 0, url: null };
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i];
    const wert = argv[i + 1];
    if (!["--url", "--methode", "--header", "--warten"].includes(name)) abbruch(`unbekannte Option ${name}`, 2);
    if (wert === undefined) abbruch(`${name} braucht einen Wert`, 2);
    i++;
    if (name === "--url") a.url = wert;
    else if (name === "--methode") a.methode = wert.toUpperCase();
    else if (name === "--header") a.header.push(wert);
    else a.warten = Number(wert);
  }
  if (!a.url) abbruch("--url fehlt", 2);
  if (!Number.isFinite(a.warten) || a.warten < 0) abbruch("--warten: ungültig", 2);
  return a;
}

async function stdinLesen() {
  const teile = [];
  for await (const teil of process.stdin) teile.push(teil);
  return Buffer.concat(teile);
}

const a = argumente(process.argv.slice(2));
let ziel;
try {
  ziel = new URL(a.url);
} catch {
  abbruch("URL ungültig", 2);
}
// Zusätzliche Sperre im Container: nur der Dienst `app` im internen Netz.
if (ziel.protocol !== "http:" || ziel.hostname !== "app") abbruch("nur http://app:<port> erlaubt", 2);

if (a.warten > 0) {
  const ende = Date.now() + a.warten * 1000;
  for (;;) {
    try {
      await fetch(ziel, { redirect: "manual", signal: AbortSignal.timeout(3000) });
      console.log("bereit");
      process.exit(0);
    } catch {
      if (Date.now() >= ende) abbruch(`app nicht erreichbar nach ${a.warten} s`, 1);
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

const header = new Headers();
for (const zeile of a.header) {
  const i = zeile.indexOf(":");
  if (i < 1) abbruch(`Header ungültig: ${zeile}`, 2);
  header.append(zeile.slice(0, i).trim(), zeile.slice(i + 1).trim());
}
const body = a.methode === "GET" || a.methode === "HEAD" ? null : await stdinLesen();

let antwort;
try {
  antwort = await fetch(ziel, {
    method: a.methode,
    headers: header,
    body: body && body.length > 0 ? body : undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
} catch (e) {
  abbruch(`Anfrage fehlgeschlagen: ${e && e.name === "TimeoutError" ? "Timeout" : (e && e.cause && e.cause.code) || (e && e.message)}`, 1);
}

console.log(`status: ${antwort.status}`);
for (const [k, v] of antwort.headers) console.log(`header: ${k}: ${v}`);

const teile = [];
let gesamt = 0;
let gekuerzt = false;
try {
  if (antwort.body) {
    const leser = antwort.body.getReader();
    for (;;) {
      const { done, value } = await leser.read();
      if (done) break;
      const rest = MAX_BODY - gesamt;
      if (value.length > rest) {
        teile.push(value.subarray(0, rest));
        gesamt += rest;
        gekuerzt = true;
        await leser.cancel();
        break;
      }
      teile.push(value);
      gesamt += value.length;
    }
  }
} catch (e) {
  abbruch(`Body nicht lesbar: ${e && e.name === "TimeoutError" ? "Timeout" : e && e.message}`, 1);
}
console.log(`body${gekuerzt ? " (auf 4096 Bytes gekürzt)" : ""}:`);
console.log(Buffer.concat(teile).toString("utf8"));
