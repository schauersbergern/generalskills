const express = require("express");

const router = express.Router();

router.get("/", async (req, res) => {
  if (!req.query.url) return res.status(400).json({ error: "url fehlt" });
  try {
    const upstream = await fetch(req.query.url);
    const body = await upstream.text();
    res.status(200).type("text/plain").send(body.slice(0, 20000));
  } catch (err) {
    res.status(502).json({ error: "Vorschau nicht verfügbar" });
  }
});

module.exports = router;
