# Prüfpunkte Web (OWASP Top 10:2025, TF1)

Nur, was in Next.js, Express, tRPC, Prisma/Neon und Stripe-Webhooks als Weg von einer Eingabe zu einem Schaden vorkommt. Je Punkt: Angriffsweg, typische Senke, nötiger Beleg. A03 (Lieferkette) gehört zu TF2. A06 und A09 entfallen, sie sind selten als Weg von Eingabe zu Schaden belegbar.

Kategorie im Bericht ist `A01` bis `A10` ohne Jahr. Ein Befund bekommt die Kategorie der **Wurzel** (der fehlenden Prüfung), nicht die der Wirkung; bei Zweifel die nächstliegende.

## Stufen

- **P1:** Ein Angreifer ohne Konto oder mit beliebigem Konto liest oder ändert fremde Mandantendaten, umgeht die Anmeldung, führt SQL oder Befehle aus oder fälscht zahlungs- und rechterelevante Ereignisse.
- **P2:** ausnutzbar, aber mit eingeschränkter Wirkung oder Voraussetzung (Konto nötig, einzelne Datei, interne Ziele per SSRF, begrenzter Informationsabfluss).
- **P3:** Härtung oder schwer ausnutzbar, kein belegter vollständiger Weg.

## Gegenprüfung (vor jedem Befund)

Ein Befund ist erst einer, wenn dich keine dieser Stellen entkräftet. Suche sie aktiv, auch außerhalb der eigenen Fläche:

- **Schutz an anderer Stelle:** Middleware (`app.use`, Router-Ebene, Next `middleware.ts`), Wrapper um Handler, Prisma-Extension, tRPC-Middleware, Mandantenfilter in einer gemeinsamen Funktion, RLS in der DB.
- **Whitelist statt Eingabe:** Spalten-, Pfad- oder Zielnamen aus einer festen Liste, Werte parametrisiert.
- **Normalisierung mit Prüfung:** `path.basename` oder `path.resolve` plus Vergleich mit dem Basisordner, `new URL()` plus Host-Prüfung.
- Hängt die Wirkung an einem Zustand, den ein Angreifer nicht herstellen kann (Secret, Rolle, Netzzugang), ist es höchstens P3.

## A01 Broken Access Control

- **Angriffsweg:** IDOR, fehlender Mandanten-Scope, fehlende Rollenprüfung, SSRF, Path Traversal, Open Redirect, Mass Assignment.
- **Senken:**
  - IDOR/Scope: `prisma.<modell>.findUnique({ where: { id } })` ohne `orgId`/`userId`, tRPC-Prozedur mit `input.id` ohne Besitzprüfung, Route Handler und Server Actions, die `params.id` direkt laden, Express `req.params.id` in einer Abfrage ohne Mandantenfilter.
  - Rollen: `role`/`isAdmin` aus Body, Cookie oder ungeprüftem JWT-Payload; `prisma.<modell>.update({ data: req.body })`.
  - SSRF: `fetch`, `axios`, `got` mit Nutzer-URL (`req.query.url`, `searchParams`), Webhook- und Bild-Proxys, Next `remotePatterns` mit Wildcard.
  - Path Traversal: `fs.readFile`/`createReadStream`/`res.sendFile` mit `path.join(base, eingabe)` ohne Basisordner-Prüfung nach der Auflösung.
  - Open Redirect: `res.redirect(req.query.next)`, `redirect(searchParams.get('next'))`.
- **Beleg:** Zwei Mandanten oder Rollen im Seed: Nutzer A ruft die Ressource von B auf (PoC mit Antwort, die B-Daten enthält), eine Admin-Route ohne Token, ein SSRF-Request, dessen Antwort Inhalt eines internen Ziels zeigt, ein `../`-Pfad, der eine Datei außerhalb des Basisordners liefert. Ohne Instanz: Code-Pfad von der Eingabe bis zum Datenzugriff, Mandantenfilter fehlt auf **jedem** Schritt.

## A02 Security Misconfiguration

- **Angriffsweg:** Browser eines Opfers sendet Anfragen mit Anmeldedaten an eine fremde Origin; Angreifer ruft Debug-Funktionen auf.
- **Senken:** `cors({ origin: true })` oder gespiegelte `Origin` zusammen mit `credentials: true`, `Access-Control-Allow-Origin` aus dem Request, `/debug`-, `/_internal`-, `/api/debug`-Routen, Ausgabe von `process.env` oder Konfiguration, Stacktraces in Antworten, Next-API-Routen für Wartung ohne Auth.
- **Beleg:** Antwort mit gespiegeltem `Access-Control-Allow-Origin` und `Access-Control-Allow-Credentials: true` auf einer Route mit Sitzungsdaten; Debug-Route, die Geheimnisse oder Interna liefert. Fehlende Security-Header allein sind kein Befund.

## A04 Cryptographic Failures

- **Angriffsweg:** gefälschte Token, erratbare Geheimnisse, Abgreifen von Passwörtern bei DB-Zugriff, Timing.
- **Senken:** Passwort-Hash mit `md5`/`sha1`/`sha256` ohne Salt und KDF (statt `bcrypt`/`argon2`/`scrypt`); JWT mit `jwt.decode` statt `verify`, nicht festgelegtem `algorithms`, `alg: none`, Fallback-Secret (`process.env.JWT_SECRET || '…'`), hartcodiertem Secret; Token-Vergleich mit `===` statt `crypto.timingSafeEqual`; Tokens aus `Math.random`.
- **Beleg:** Code-Pfad bis zur Prüfung, Fallback oder Algorithmus; PoC mit einem selbst signierten Token, das die App akzeptiert (Secret aus dem Fallback oder `alg: none`). Timing-Befunde bleiben P3.

## A05 Injection

- **Angriffsweg:** Eingabe verändert Struktur einer SQL-, Shell-, Template- oder NoSQL-Anweisung.
- **Senken:**
  - SQL: `prisma.$queryRawUnsafe`/`$executeRawUnsafe`, `$queryRaw` als normaler Aufruf mit gebautem String (nur das Tagged Template `$queryRaw\`…\`` parametrisiert), `knex.raw`, `sequelize.query`, `pg`/`mysql2`/`sql.js` mit Template-Literal oder `+`.
  - Befehl: `child_process.exec`/`execSync`, `spawn` mit `shell: true`.
  - Template: `ejs.render`, `Handlebars.compile`, `pug.render` mit Nutzertext.
  - NoSQL: `find(req.body)` mit Operatoren (`$ne`, `$where`).
- **Beleg:** PoC mit einer Eingabe, die das Ergebnis erkennbar ändert (zusätzliche Zeilen, Fehlertext der DB, verzögerte Antwort, Dateiinhalt). Code-Pfad zeigt, dass die Eingabe **ohne Parametrisierung** in die Senke gelangt. Spalten- oder Tabellennamen aus einer Whitelist sind kein Befund.

## A07 Authentication Failures

- **Angriffsweg:** Aufruf ohne Anmeldung; Übernahme einer Sitzung.
- **Senken:** Route außerhalb von `middleware.ts` (`matcher` schließt `/api` aus) oder vor dem Auth-Middleware gemountet (`app.use('/admin', router)` ohne `requireAuth`); Server Actions (`'use server'`) ohne eigene Prüfung (sie sind per POST direkt erreichbar); tRPC `publicProcedure` für Mutationen; fehlendes `req.session.regenerate` nach dem Login (Session-Fixierung); Token in der URL; vorhersagbare Reset-Token.
- **Beleg:** PoC ohne Token oder Cookie, der Daten liefert oder ändert; für Fixierung eine Sitzungs-ID, die vor und nach dem Login gleich bleibt. Code-Pfad: Route, Montagereihenfolge, fehlende Prüfung.

## A08 Software or Data Integrity Failures

- **Angriffsweg:** gefälschte Ereignisse, manipulierte serialisierte Daten.
- **Senken:** Stripe-Webhook ohne `stripe.webhooks.constructEvent(rawBody, signatur, secret)`; `express.json()` vor der Webhook-Route, sodass `rawBody` fehlt oder die Prüfung ins Leere läuft; `JSON.parse(req.body)` und direkte Auswertung von `event.type`; `eval`, `vm`, `node-serialize`, unsichere YAML-Loader auf Eingabe; vom Client gelieferte, unsignierte Cookies mit Rechten oder Preisen.
- **Beleg:** PoC mit einem selbst gebauten Event ohne gültige Signatur, das einen Zustand ändert (z. B. Rechnung als bezahlt). Ohne Instanz: Code-Pfad von der Route bis zur Zustandsänderung ohne Signaturprüfung.

## A10 Mishandling of Exceptional Conditions

- **Angriffsweg:** Fehlerfall führt zu Zugriff (fail-open) oder zu Absturz.
- **Senken:** `try { await verify() } catch { return next() }`, `catch { return true }` in Berechtigungsprüfungen, `.catch(() => null)`, dessen Ergebnis als „erlaubt“ gilt, fehlendes `await` vor einer async Prüfung (das Promise ist immer truthy), Default-Erlaubnis bei unbekannter Rolle, unbehandelte Ablehnung in einer öffentlichen Route (Prozess stürzt ab), Stacktraces oder Interna in Fehlerantworten.
- **Beleg:** PoC, der den Fehlerfall auslöst (kaputtes Token, nicht erreichbarer Dienst, ungültiges Format) und Zugriff oder Absturz zeigt. Code-Pfad: Prüfung, Fehlerzweig, Ergebnis.

## Belegstufen

- **bestätigt:** PoC-Request und beobachtete Antwort gegen die laufende Instanz.
- **unbestätigt:** Code-Pfad von der Eingabe bis zur Senke (Liste `datei:zeile`, mindestens 2 Schritte), die Gegenprüfung ist durchlaufen und keine Entkräftung gefunden.
- **verdacht:** Auffälligkeit ohne vollständigen Pfad.
