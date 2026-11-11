const express = require("express");
const { chat } = require("../llm");

const router = express.Router();

router.get("/antwort", async (req, res, next) => {
  const frage = String(req.query.frage || "");
  if (!frage) return res.status(400).json({ fehler: "frage fehlt" });
  try {
    const antwort = await chat([
      { role: "system", content: "Beantworte Fragen zum Produkt kurz und freundlich." },
      { role: "user", content: frage },
    ]);
    res.type("html").send(`<!doctype html><html><body><h1>Antwort</h1><div>${antwort.content}</div></body></html>`);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
