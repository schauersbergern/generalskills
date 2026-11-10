const db = require("./db");

function requireAuth(req, res, next) {
  const token = req.get("x-token");
  if (!token) return res.status(401).json({ error: "token fehlt" });
  const session = db.get("SELECT token, user_id, org_id FROM sessions WHERE token = ?", [token]);
  if (!session) return res.status(401).json({ error: "token ungültig" });
  req.session = { userId: session.user_id, orgId: session.org_id };
  next();
}

module.exports = { requireAuth };
