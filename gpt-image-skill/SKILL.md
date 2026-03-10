---
name: gpt-image
description: >
  Generiert Bilder mit OpenAI gpt-image-1 (und Varianten) über die OpenAI API
  und zeigt sie direkt im Chat an.
  Verwende diesen Skill immer dann, wenn der Nutzer ein Bild generieren,
  erstellen, zeichnen oder visualisieren möchte, insbesondere wenn er
  gpt-image, OpenAI Image, DALL-E oder ähnliche Begriffe erwähnt.
  Auch bei allgemeinen Anfragen wie "Erstelle ein Bild von..." oder
  "Generiere ein Foto von..." soll dieser Skill bevorzugt eingesetzt werden.
---

# GPT-Image Skill

Generiert Bilder über die OpenAI Image API (`gpt-image-1`) und gibt sie direkt im Chat aus.

## Voraussetzungen

- Umgebungsvariable `OPENAI_API_KEY` muss gesetzt sein
- Node.js verfügbar im Container

## Technische Details

- **Standard-Modell:** `gpt-image-1` (alternativ: `gpt-image-1.5`, `gpt-image-1-mini`)
- **API:** OpenAI REST API (`api.openai.com/v1/images/generations`)
- **Response-Format:** Base64-kodiertes PNG im `data[0].b64_json`-Feld
- **Output:** Bild wird als PNG-Datei gespeichert und dem Nutzer präsentiert

## Workflow

### Schritt 1: Prompt vorbereiten

Nimm den Prompt des Nutzers. Wenn er auf Deutsch ist, übersetze ihn ins
Englische, da das Modell mit englischen Prompts bessere Ergebnisse liefert.
Teile dem Nutzer kurz mit, welchen Prompt du verwendest.

### Schritt 2: Script ausführen

```bash
node /home/claude/gpt-image-skill/generate_image.js "PROMPT_HERE" [MODEL] [SIZE]
```

Parameter:
- `PROMPT_HERE`: Der Bildprompt (Pflicht, auf Englisch)
- `MODEL`: Optional (Default: `gpt-image-1`) — Alternativen: `gpt-image-1.5`, `gpt-image-1-mini`
- `SIZE`: Optional (Default: `1024x1024`) — Alternativen: `1536x1024` (Landscape), `1024x1536` (Portrait)

Beispiele:
```bash
node generate_image.js "A chrome banana floating in space, cyberpunk style, 8k"
node generate_image.js "A wide mountain landscape at sunset" "gpt-image-1" "1536x1024"
node generate_image.js "Portrait photo of a robot" "gpt-image-1.5" "1024x1536"
```

Das Script speichert das generierte Bild unter `/mnt/user-data/outputs/generated_image.png`.

### Schritt 3: Bild präsentieren

Nutze das `present_files` Tool, um das Bild dem Nutzer anzuzeigen:

```
present_files(["/mnt/user-data/outputs/generated_image.png"])
```

### Schritt 4: Kurze Beschreibung

Gib dem Nutzer nach dem Bild eine kurze (1-2 Sätze) Erläuterung,
was generiert wurde. Frage ggf. ob er Anpassungen möchte.

## Fehlerbehandlung

- **API Key fehlt:** Weise den Nutzer darauf hin, dass `OPENAI_API_KEY` gesetzt werden muss.
- **401 Unauthorized:** Key ungültig oder Organization Verification bei OpenAI ausstehend.
- **429 Rate Limit:** Kurz warten, dann erneut versuchen.
- **400 / Content Policy:** Prompt anpassen, keine verbotenen Inhalte.

## Hinweise zur Promptqualität

- Englische Prompts liefern konsistent bessere Ergebnisse
- Stilangaben verbessern die Qualität (z.B. "photorealistic", "oil painting", "isometric 3D cartoon")
- Komposition, Beleuchtung und Perspektive explizit angeben wenn relevant
- `gpt-image-1-mini` für schnelle Tests, `gpt-image-1.5` für maximale Qualität
