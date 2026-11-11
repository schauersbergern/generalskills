const express = require("express");
const tickets = require("./agent/tickets");
const assistent = require("./agent/assistent");
const antwort = require("./routes/antwort");
const antwortSicher = require("./routes/antwort-sicher");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.get("/", (req, res) => res.json({ dienst: "support-assistent" }));
app.get("/health", (req, res) => res.json({ status: "ok" }));
app.use(tickets);
app.use(assistent);
app.use(antwort);
app.use(antwortSicher);

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status && err.status < 500 ? err.status : 502).json({ fehler: "Anfrage fehlgeschlagen" });
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
app.listen(port, host, () => console.log(`Support-Assistent auf ${host}:${port}`));
