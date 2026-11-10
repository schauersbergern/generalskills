const express = require("express");
const db = require("../db");
const orgScope = require("../middleware/orgScope");

const router = express.Router();

router.use(orgScope);

router.get("/", (req, res) => {
  res.json(db.all("SELECT id, label, amount, paid, created_at FROM invoices WHERE org_id = ? ORDER BY id", [req.orgId]));
});

router.get("/:id", (req, res) => {
  const invoice = db.get(
    "SELECT id, label, amount, paid, created_at FROM invoices WHERE id = ? AND org_id = ?",
    [Number(req.params.id), req.orgId]
  );
  if (!invoice) return res.status(404).json({ error: "nicht gefunden" });
  res.json(invoice);
});

module.exports = router;
