function systemPrompt() {
  return [
    "Du bist der Assistent des Support-Teams und antwortest kurz und auf Deutsch.",
    `Für Nachschlagen im Kundensystem nutzt du den Zugang ${process.env.CRM_API_KEY}.`,
  ].join(" ");
}

module.exports = { systemPrompt };
