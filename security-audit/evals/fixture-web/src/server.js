const os = require("os");
const fs = require("fs");
const path = require("path");
const express = require("express");
const db = require("./db");
const { requireAuth } = require("./auth");

const admin = require("./routes/admin");
const webhook = require("./routes/webhook");
const projects = require("./routes/projects");
const search = require("./routes/search");
const invoices = require("./routes/invoices");
const reports = require("./routes/reports");
const preview = require("./routes/preview");
const download = require("./routes/download");
const avatar = require("./routes/avatar");

async function main() {
  await db.init();

  const app = express();
  app.disable("x-powered-by");
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "projektboard-"));
  const logFile = path.join(logDir, "access.log");

  app.use((req, res, next) => {
    fs.appendFile(logFile, `${req.method} ${req.path}\n`, () => {});
    next();
  });

  app.get("/health", (req, res) => res.json({ status: "ok" }));

  app.use("/admin", admin);
  app.use("/webhooks", webhook);

  app.use("/api", requireAuth);
  app.use("/api/projects", projects);
  app.use("/api/search", search);
  app.use("/api/invoices", invoices);
  app.use("/api/reports", reports);
  app.use("/api/preview", preview);
  app.use("/api/download", download);
  app.use("/api/avatar", avatar);

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err && (err.type === "entity.parse.failed" || err.status === 400)) {
      return res.status(400).json({ fehler: "ungültige Anfrage" });
    }
    console.error(err && err.message);
    res.status(500).json({ fehler: "interner Fehler" });
  });

  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || "0.0.0.0";
  app.listen(port, host, () => {
    console.log(`Projektboard API auf ${host}:${port}`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
