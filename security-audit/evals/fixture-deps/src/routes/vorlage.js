const express = require("express");
const _ = require("lodash");

const router = express.Router();

const vorlage = "Hallo <%= daten.name %>, willkommen beim Vorlagen-Dienst.";

router.get("/", (req, res) => {
  const fuellen = _.template(vorlage, { variable: req.query.v });
  res.type("text/plain").send(String(fuellen({ name: req.query.name || "Gast" })));
});

module.exports = router;
