const express = require("express");
const path = require("path");

const AVATAR_DIR = path.join(__dirname, "..", "..", "data", "avatars");

const router = express.Router();

router.get("/", (req, res) => {
  const name = path.basename(String(req.query.name || ""));
  if (!name) return res.status(400).json({ error: "name fehlt" });
  const resolved = path.resolve(AVATAR_DIR, name);
  if (!resolved.startsWith(AVATAR_DIR + path.sep)) {
    return res.status(400).json({ error: "ungültiger Name" });
  }
  res.sendFile(resolved, (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: "nicht gefunden" });
  });
});

module.exports = router;
