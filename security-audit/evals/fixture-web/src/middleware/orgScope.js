function orgScope(req, res, next) {
  if (!req.session || typeof req.session.orgId !== "number") {
    return res.status(401).json({ error: "keine Sitzung" });
  }
  req.orgId = req.session.orgId;
  next();
}

module.exports = orgScope;
