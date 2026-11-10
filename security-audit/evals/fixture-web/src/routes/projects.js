const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/", (req, res) => {
  const rows = db.all("SELECT id, name, status FROM projects WHERE org_id = ? ORDER BY id", [req.session.orgId]);
  res.json(rows);
});

router.get("/:id", (req, res) => {
  const project = db.get("SELECT id, org_id, name, status FROM projects WHERE id = ?", [Number(req.params.id)]);
  if (!project) return res.status(404).json({ error: "nicht gefunden" });
  res.json(project);
});

module.exports = router;
