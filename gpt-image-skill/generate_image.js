#!/usr/bin/env node
// Image Generator — OpenAI gpt-image-1
// Speichert das Bild unter /mnt/user-data/outputs/generated_image.png

const https = require("https");
const fs = require("fs");
const path = require("path");

const API_KEY = process.env.OPENAI_API_KEY;
const MODEL  = process.argv[3] || "gpt-image-1";   // gpt-image-1 | gpt-image-1.5 | gpt-image-1-mini
const SIZE   = process.argv[4] || "1024x1024";      // 1024x1024 | 1536x1024 | 1024x1536
const OUTPUT_PATH = "/mnt/user-data/outputs/generated_image.png";

if (!API_KEY) {
  console.error("ERROR: OPENAI_API_KEY environment variable is not set.");
  process.exit(1);
}

const prompt = process.argv[2];
if (!prompt) {
  console.error("ERROR: No prompt provided.");
  console.error("Usage: node generate_image.js \"your prompt\" [model] [size]");
  console.error("  model: gpt-image-1 (default) | gpt-image-1.5 | gpt-image-1-mini");
  console.error("  size:  1024x1024 (default) | 1536x1024 (landscape) | 1024x1536 (portrait)");
  process.exit(1);
}

const requestBody = JSON.stringify({
  model:           MODEL,
  prompt:          prompt,
  n:               1,
  size:            SIZE,
  response_format: "b64_json"
});

const options = {
  hostname: "api.openai.com",
  path:     "/v1/images/generations",
  method:   "POST",
  headers: {
    "Content-Type":   "application/json",
    "Content-Length": Buffer.byteLength(requestBody),
    "Authorization":  `Bearer ${API_KEY}`
  }
};

console.log(`Generating image with ${MODEL}...`);
console.log(`Prompt: "${prompt}"`);
console.log(`Size: ${SIZE}`);

const req = https.request(options, (res) => {
  let data = "";
  res.on("data", (chunk) => { data += chunk; });

  res.on("end", () => {
    let parsed;
    try {
      parsed = JSON.parse(data);
    } catch (e) {
      console.error("ERROR: Failed to parse API response as JSON.");
      console.error(data);
      process.exit(1);
    }

    if (res.statusCode !== 200) {
      console.error(`ERROR: API returned status ${res.statusCode}`);
      console.error(parsed?.error?.message || data);
      process.exit(1);
    }

    const b64 = parsed?.data?.[0]?.b64_json;
    if (!b64) {
      console.error("ERROR: No image data in response.");
      console.error(JSON.stringify(parsed, null, 2));
      process.exit(1);
    }

    const outputDir = path.dirname(OUTPUT_PATH);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(OUTPUT_PATH, Buffer.from(b64, "base64"));
    console.log(`SUCCESS: Image saved to ${OUTPUT_PATH}`);
  });
});

req.on("error", (e) => {
  console.error(`ERROR: Request failed: ${e.message}`);
  process.exit(1);
});

req.write(requestBody);
req.end();
