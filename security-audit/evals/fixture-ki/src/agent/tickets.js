const express = require("express");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { chat } = require("../llm");
const { mitarbeiter } = require("../auth");

const router = express.Router();
const tickets = new Map();
let naechsteId = 1;

const SYSTEM = "Du bearbeitest Support-Tickets. Beantworte jedes Ticket mit einer E-Mail an den Kunden über das Tool send_email.";

const TOOLS = [
  {
    type: "function",
    function: {
      name: "send_email",
      description: "Sendet eine E-Mail",
      parameters: {
        type: "object",
        properties: {
          an: { type: "string", description: "Empfänger" },
          betreff: { type: "string" },
          text: { type: "string" },
        },
        required: ["an", "text"],
      },
    },
  },
];

function mailSenden(args) {
  const zeile = JSON.stringify({ an: args.an, betreff: args.betreff || "", text: args.text });
  fs.appendFileSync(path.join(os.tmpdir(), "ausgang.jsonl"), zeile + "\n");
  return "E-Mail gesendet";
}

async function schleife(messages) {
  for (let runde = 0; runde < 5; runde++) {
    const antwort = await chat(messages, TOOLS);
    messages.push(antwort);
    if (!antwort.tool_calls || antwort.tool_calls.length === 0) return antwort.content;
    for (const aufruf of antwort.tool_calls) {
      let ergebnis = "unbekanntes Tool";
      if (aufruf.function.name === "send_email") ergebnis = mailSenden(JSON.parse(aufruf.function.arguments));
      messages.push({ role: "tool", tool_call_id: aufruf.id, content: ergebnis });
    }
  }
  return null;
}

router.post("/tickets", (req, res) => {
  const { text, dokument } = req.body || {};
  if (typeof text !== "string" || !text) return res.status(400).json({ fehler: "text fehlt" });
  const id = naechsteId++;
  tickets.set(id, { id, text, dokument: typeof dokument === "string" ? dokument : "" });
  res.status(201).json({ id });
});

router.post("/agent/tickets/:id/bearbeiten", mitarbeiter, async (req, res, next) => {
  const ticket = tickets.get(Number(req.params.id));
  if (!ticket) return res.status(404).json({ fehler: "Ticket nicht gefunden" });
  try {
    const inhalt = `Ticket ${ticket.id}\n\n${ticket.text}\n\nAnhang:\n${ticket.dokument}`;
    const antwort = await schleife([
      { role: "system", content: SYSTEM },
      { role: "user", content: inhalt },
    ]);
    res.json({ ticket: ticket.id, antwort });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
