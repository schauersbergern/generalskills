# Vorlagen-Dienst

Kleiner HTTP-Dienst, der Textvorlagen mit Platzhaltern ausfüllt.

## Start

    npm ci
    node src/server.js

Der Dienst lauscht standardmäßig auf Port 3000 (`PORT`, `HOST` überschreiben das).

## Endpunkte

- `GET /health`
- `GET /api/vorlage?v=daten&name=Anna`: füllt die Begrüßungsvorlage; `v` ist der Name der Variablen, unter der die
  Vorlage die Daten anspricht
