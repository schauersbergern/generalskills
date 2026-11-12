# Support-Assistent

Kleiner HTTP-Dienst für Support-Tickets mit Modell-Anbindung.

## Start

    npm ci
    node src/server.js

Der Dienst lauscht standardmäßig auf Port 3000 (`PORT`, `HOST` überschreiben das). Das Modell-SDK liest seine Einstellungen aus
der Umgebung; `CRM_API_KEY` (siehe `.env.example`) ist der Zugang zum Kundensystem.
Mitarbeiter melden sich mit dem Header `x-token` an.

## Endpunkte

- `GET /`, `GET /health`
- `POST /tickets`: legt ein Ticket mit `text` und `dokument` an
- `POST /agent/tickets/:id/bearbeiten`: lässt das Modell ein Ticket bearbeiten (Mitarbeiter)
- `POST /assistent`: Fragen an den Support-Assistenten (Mitarbeiter)
- `GET /antwort?frage=`, `GET /antwort-sicher?frage=`: Antwort des Modells als Seite

Tickets liegen im Speicher. Versendete Mails landen in `ausgang.jsonl` im temporären Ordner des Systems.
