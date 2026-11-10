const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/users", (req, res) => {
  res.json(db.all("SELECT id, org_id, name, role FROM users ORDER BY id"));
});

module.exports = router;
