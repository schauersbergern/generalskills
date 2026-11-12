const express = require("express");
const db = require("../db");

const router = express.Router();

router.post("/stripe", express.json(), (req, res) => {
  const event = req.body || {};
  if (event.type === "invoice.paid") {
    const meta = event.data && event.data.object && event.data.object.metadata;
    const invoiceId = meta && Number(meta.invoice_id);
    if (invoiceId) {
      db.run("UPDATE invoices SET paid = 1 WHERE id = ?", [invoiceId]);
    }
  }
  res.json({ received: true });
});

module.exports = router;
