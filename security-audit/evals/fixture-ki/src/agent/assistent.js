const express = require("express");
const { exec } = require("child_process");
const { chat } = require("../llm");
const { mitarbeiter } = require("../auth");
const { systemPrompt } = require("./prompt");

const router = express.Router();

const TOOLS = [
  {
    type: "function",
    function: {
      name: "datei_suchen",
      description: "Listet Dateien in einem Ordner auf",
      parameters: {
        type: "object",
        properties: { pfad: { type: "string", description: "Ordner" } },
        required: ["pfad"],
      },
    },
  },
];

function dateiSuchen(args) {
  return new Promise((resolve) => {
    exec("ls " + args.pfad, { timeout: 5000 }, (fehler, stdout, stderr) => {
      resolve(String(stdout) + String(stderr));
    });
  });
}

async function schleife(messages, werkzeuge) {
  for (let runde = 0; runde < 5; runde++) {
    const antwort = await chat(messages, TOOLS);
    messages.push(antwort);
    if (!antwort.tool_calls || antwort.tool_calls.length === 0) return antwort.content;
    for (const aufruf of antwort.tool_calls) {
      let ausgabe = "unbekanntes Tool";
      if (aufruf.function.name === "datei_suchen") ausgabe = await dateiSuchen(JSON.parse(aufruf.function.arguments));
      werkzeuge.push({ name: aufruf.function.name, ausgabe });
      messages.push({ role: "tool", tool_call_id: aufruf.id, content: ausgabe });
    }
  }
  return null;
}

router.post("/assistent", mitarbeiter, async (req, res, next) => {
  const { frage } = req.body || {};
  if (typeof frage !== "string" || !frage) return res.status(400).json({ fehler: "frage fehlt" });
  try {
    const werkzeuge = [];
    const antwort = await schleife(
      [
        { role: "system", content: systemPrompt() },
        { role: "user", content: frage },
      ],
      werkzeuge,
    );
    res.json({ antwort, werkzeuge });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
