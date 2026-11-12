const express = require("express");
const db = require("../db");

const SORT_COLUMNS = new Set(["created_at", "amount"]);

const router = express.Router();

router.get("/", (req, res) => {
  const sort = req.query.sort || "created_at";
  if (!SORT_COLUMNS.has(sort)) return res.status(400).json({ error: "ungültige Sortierung" });
  const min = Number(req.query.min || 0);
  const rows = db.all(
    `SELECT id, label, amount, paid, created_at FROM invoices WHERE org_id = ? AND amount >= ? ORDER BY ${sort}`,
    [req.session.orgId, min]
  );
  res.json(rows);
});

module.exports = router;
