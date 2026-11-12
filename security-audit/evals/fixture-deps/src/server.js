const express = require("express");
const vorlage = require("./routes/vorlage");

const app = express();
app.disable("x-powered-by");

app.get("/health", (req, res) => res.json({ status: "ok" }));
app.use("/api/vorlage", vorlage);

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(400).json({ fehler: "ungültige Anfrage" });
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
app.listen(port, host, () => console.log(`Vorlagen-Dienst auf ${host}:${port}`));
