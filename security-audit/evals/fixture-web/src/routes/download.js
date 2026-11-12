const express = require("express");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "..", "data", "files");

const router = express.Router();

router.get("/", (req, res) => {
  const name = req.query.name;
  if (!name) return res.status(400).json({ error: "name fehlt" });
  res.sendFile(path.join(DATA_DIR, name), (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: "nicht gefunden" });
  });
});

module.exports = router;
