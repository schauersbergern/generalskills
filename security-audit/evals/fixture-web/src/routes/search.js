const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/", (req, res) => {
  const q = req.query.q || "";
  try {
    const rows = db.exec(
      `SELECT id, name, status FROM projects WHERE org_id = ${req.session.orgId} AND name LIKE '%${q}%' ORDER BY id`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Suche fehlgeschlagen" });
  }
});

module.exports = router;
