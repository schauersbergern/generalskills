// Wächter für den SDK-Vertragstest: Dieses Modul muss der ERSTE Import von vertrag.mjs sein, die SDKs folgen
// ausschließlich per `await import()`. Er weist jede ausgehende Verbindung ab, deren Ziel nicht genau 127.0.0.1 ist,
// und hält jeden Treffer in `treffer` fest, auch wenn ein SDK den Fehler fängt oder wiederholt.
//
// Ersetzt werden: globalThis.fetch, http.request/get, https.request/get, net.connect/createConnection, tls.connect
// und als unterste Schicht net.Socket.prototype.connect (dort laufen auch Agents, undici und TLS vorbei).
// Danach gleicht module.syncBuiltinESMExports() die benannten ESM-Exporte (`import { request } from "node:http"`) an.
// Ein Treffer ist {art, ziel} mit dem reinen Host (ohne Pfad, Query und Zugangsdaten) und nie ein Request-Inhalt.

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import module from "node:module";

export const ERLAUBTER_HOST = "127.0.0.1";
export const treffer = [];

function abweisen(art, ziel) {
  const host = String(ziel ?? "?").slice(0, 200);
  treffer.push({ art, ziel: host });
  const fehler = new Error(`waechter: Verbindung (${art}) zu ${host} abgewiesen, erlaubt ist nur ${ERLAUBTER_HOST}`);
  fehler.code = "EWAECHTER";
  return fehler;
}

// Ziel einer URL (string, URL oder Request) als reiner Host; null, wenn sie sich nicht lesen lässt.
function hostAusUrl(wert) {
  try {
    const url = wert instanceof URL ? wert : new URL(typeof wert === "string" ? wert : wert.url);
    return url.hostname;
  } catch {
    return null;
  }
}

// Host aus den Argumenten von http.request/https.request (url, options, cb) oder (options, cb).
function hostAusHttpArgumenten(args) {
  const [a, b] = args;
  let host;
  if (typeof a === "string" || a instanceof URL) host = hostAusUrl(a);
  else if (a && typeof a === "object") host = a.hostname ?? a.host ?? "localhost";
  else host = "localhost";
  if (b && typeof b === "object" && typeof b !== "function" && (typeof a === "string" || a instanceof URL)) {
    host = b.hostname ?? b.host ?? host;
  }
  if (host === null) return "unlesbar";
  // `host` darf in options auch "name:port" sein; für die Prüfung zählt der Teil vor dem Doppelpunkt nicht,
  // eine solche Angabe ist also nie 127.0.0.1 und wird abgewiesen.
  return String(host);
}

// Host aus den Argumenten von net.connect/Socket.prototype.connect: (options) | (port[, host]) | (path).
function hostAusNetArgumenten(args) {
  let a = args[0];
  if (Array.isArray(a)) a = a[0]; // intern normalisierte Form [options, cb]
  if (a && typeof a === "object") {
    if (a.path) return `ipc:${String(a.path).slice(0, 80)}`; // wie net: nur ein nichtleerer path ist ein IPC-Ziel (der Agent setzt path: null)
    return String(a.host ?? a.hostname ?? "localhost");
  }
  if (typeof a === "string" && !/^\d+$/.test(a)) return `ipc:${a.slice(0, 80)}`;
  return typeof args[1] === "string" ? args[1] : "localhost";
}

function wache(art, original, hostAus) {
  const wrapper = function (...args) {
    const host = hostAus(args);
    if (host !== ERLAUBTER_HOST) throw abweisen(art, host);
    return original.apply(this, args);
  };
  return wrapper;
}

// fetch weist asynchron ab (abgelehntes Promise), wie ein echter Netzfehler.
const fetchOriginal = globalThis.fetch;
globalThis.fetch = function fetch(eingabe, ...rest) {
  const host = hostAusUrl(eingabe);
  if (host !== ERLAUBTER_HOST) return Promise.reject(abweisen("fetch", host ?? "unlesbar"));
  return fetchOriginal.call(this, eingabe, ...rest);
};

http.request = wache("http.request", http.request, hostAusHttpArgumenten);
http.get = wache("http.get", http.get, hostAusHttpArgumenten);
https.request = wache("https.request", https.request, hostAusHttpArgumenten);
https.get = wache("https.get", https.get, hostAusHttpArgumenten);
net.connect = wache("net.connect", net.connect, hostAusNetArgumenten);
net.createConnection = wache("net.createConnection", net.createConnection, hostAusNetArgumenten);
tls.connect = wache("tls.connect", tls.connect, hostAusNetArgumenten);
net.Socket.prototype.connect = wache("socket.connect", net.Socket.prototype.connect, hostAusNetArgumenten);

module.syncBuiltinESMExports();
