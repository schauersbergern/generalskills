const MITARBEITER = {
  "tok-mitarbeiter-a": { id: "A", name: "Mitarbeiter A" },
  "tok-mitarbeiter-b": { id: "B", name: "Mitarbeiter B" },
};

function mitarbeiter(req, res, next) {
  const token = req.get("x-token");
  const eintrag = typeof token === "string" && Object.hasOwn(MITARBEITER, token) ? MITARBEITER[token] : undefined;
  if (!eintrag) return res.status(401).json({ fehler: "nicht angemeldet" });
  req.mitarbeiter = eintrag;
  next();
}

module.exports = { mitarbeiter };
