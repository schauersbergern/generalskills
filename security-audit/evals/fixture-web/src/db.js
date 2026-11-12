const path = require("path");
const initSqlJs = require("sql.js");

let db;

async function init() {
  const SQL = await initSqlJs({
    locateFile: (file) => path.join(__dirname, "..", "node_modules", "sql.js", "dist", file),
  });
  db = new SQL.Database();
  db.run(`
    CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT);
    CREATE TABLE users (id INTEGER PRIMARY KEY, org_id INTEGER, name TEXT, role TEXT);
    CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER, org_id INTEGER);
    CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id INTEGER, name TEXT, status TEXT);
    CREATE TABLE invoices (id INTEGER PRIMARY KEY, org_id INTEGER, label TEXT, amount INTEGER, paid INTEGER DEFAULT 0, created_at TEXT);
  `);
  run("INSERT INTO orgs VALUES (1, 'acme'), (2, 'globex')");
  run("INSERT INTO users VALUES (1, 1, 'Anna Acme', 'owner'), (2, 2, 'Gerd Globex', 'owner')");
  run("INSERT INTO sessions VALUES ('tok-acme', 1, 1), ('tok-globex', 2, 2)");
  run(
    "INSERT INTO projects VALUES (1, 1, 'Acme Relaunch', 'aktiv'), (2, 1, 'Acme Wartung', 'aktiv'), (3, 2, 'Globex Rollout', 'aktiv'), (4, 2, 'Globex Audit', 'geplant')"
  );
  run(
    "INSERT INTO invoices VALUES (1, 1, 'INV-A-1', 1200, 0, '2026-01-10'), (2, 1, 'INV-A-2', 800, 1, '2026-02-10'), (3, 2, 'INV-G-1', 5400, 0, '2026-01-15'), (4, 2, 'INV-G-2', 300, 0, '2026-03-01')"
  );
}

function run(sql, params = []) {
  db.run(sql, params);
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    return rows;
  } finally {
    stmt.free();
  }
}

function get(sql, params = []) {
  return all(sql, params)[0];
}

function exec(sql) {
  const result = db.exec(sql);
  if (!result.length) return [];
  const { columns, values } = result[0];
  return values.map((row) => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
}

module.exports = { init, run, all, get, exec };
