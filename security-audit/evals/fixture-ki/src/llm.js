let client = null;

function getClient() {
  if (client === null) {
    const { OpenAI } = require("openai");
    client = new OpenAI({ maxRetries: 0, timeout: 20000 });
  }
  return client;
}

async function chat(messages, tools) {
  const antwort = await getClient().chat.completions.create({
    model: process.env.MODEL || "gpt-4o-mini",
    messages,
    ...(tools ? { tools } : {}),
  });
  return antwort.choices[0].message;
}

module.exports = { chat };
