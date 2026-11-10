# Projektboard API

Kleine HTTP-API für Projekte, Rechnungen und Berichte mehrerer Organisationen.

## Start

    npm ci
    node src/server.js

Die API lauscht standardmäßig auf Port 3000 (`PORT`, `HOST` überschreiben das).
Anfragen tragen den Sitzungs-Token im Header `x-token`.

## Endpunkte

- `GET /health`
- `GET /api/projects`, `GET /api/projects/:id`
- `GET /api/search?q=`
- `GET /api/invoices`, `GET /api/invoices/:id`
- `GET /api/reports?sort=`
- `GET /api/preview?url=`
- `GET /api/download?name=`
- `GET /api/avatar?name=`
- `POST /webhooks/stripe`
- `GET /admin/users`

Beim Start legt die App eine In-Memory-Datenbank mit Beispieldaten an.
