# Whistleblower

A progressive web app (PWA) for reporting illegal activity at any company, anonymously.
There are no user accounts or profiles.

## How login works

1. **Access key.** A user generates a key on their own device
   (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`: 100 random bits and a 20-bit SHA-256 checksum).
   The key is shown once. The user has to write it down because nobody can recover it.
2. **Local validation.** At login the app checks the key's checksum **on the device**
   (`public/js/key.js`). The key is never sent over the network and never written to
   localStorage, sessionStorage, cookies or the database.
3. **Random session ID.** Once the key passes the check, the app calls `POST /api/session`
   with an empty body. The server creates a new random 256-bit session ID, stores only its
   SHA-256 hash with a 30-minute expiry, and returns it.
4. The session ID is kept in a JavaScript variable, so it is gone when the tab is
   reloaded or closed. It is sent as a `Bearer` token when the user submits a report.
   Logging out deletes the session on the server.

Every login creates a new, unrelated session ID, even with the same key.

## Privacy measures

- Reports are **not linked** to the session that submitted them. Only the submission
  **day** is stored, not the exact time.
- No request logging, and client IP addresses are never read or stored.
- Strict security headers: a CSP allowing only `'self'`, `no-referrer`, no framing, and
  no camera, microphone or location access.
- The service worker caches only the app shell, never API responses.
- Zero runtime dependencies (Node's built-in `http`, `crypto` and `node:sqlite`),
  so there is no third-party code in the server.

## Running it

Requires Node.js 22.13 or newer.

```sh
npm start          # http://localhost:3000  (PORT and DB_FILE can be set via env vars)
npm test
```

Browsers only allow PWA installation and service workers over HTTPS (or on `localhost`),
so put the app behind TLS in production.

## Known limitations and next steps

- **The key is a local gate, not a credential.** The server never sees the key, so it
  cannot tell one user from another. That is the anonymity guarantee, but it also means
  anyone can generate a valid key. Abuse is limited by a global cap on new sessions per
  minute and a limit of 5 reports per session. A bot-resistance step (for example proof of
  work) would be a good next addition.
- **Following up on a report.** Sessions are deliberately unlinkable, so a user cannot
  come back later to their report. A follow-up feature could use per-report secrets
  derived from the key on the device.
- **Reviewer side.** There is no admin or investigator interface yet, and reports are
  stored in plain text. Before production, encrypt report contents with the
  investigators' public key so the server and database only hold ciphertext.
- **Network-level anonymity.** The app cannot hide the user's IP address from their ISP or
  hosting provider. Advise high-risk users to use Tor Browser and consider hosting a
  `.onion` address.
- **Icons.** The manifest ships a single SVG icon. Add 192px and 512px PNG icons for the
  widest install support (older iOS in particular).
