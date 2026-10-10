# Whistleblower

A progressive web app (PWA) for reporting illegal activity at any company, anonymously.
There are no user accounts. Reports and messages are encrypted on the reporter's device, so
the server only ever stores ciphertext.

## How it works

### Reporting
1. Anyone opens the app and fills in a report. No login is needed.
2. The device generates a random **case code**
   (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`: 100 random bits and a typo-catching checksum).
3. From the code, the device derives two separate secrets with HKDF:
   - an **auth value**, which the server stores only as a SHA-256 hash
   - a **case key** (AES-256-GCM), which encrypts the report and every message
4. The case key is encrypted with the investigators' RSA public key and uploaded with the
   encrypted report. The case code and case key never leave the device.
5. The reporter is shown the case code once and must save it. Nobody can recover it.

### Returning to a case
The reporter enters their case code. The device checks the checksum, derives the auth
value and sends only that. If it matches a case, the server issues a **new random session
ID** (256 bits, stored as a hash, 30-minute expiry). The session ID is held only in
memory, so a reload or a closed tab ends it. The reporter can see the case status, read
investigators' questions and reply.

### Investigators
`/investigator.html` is the reviewer interface. An investigator logs in with a token and
loads the private key file in the browser. The key is used locally to decrypt cases and is
never uploaded. Investigators can read cases, message the reporter, and set the status
(Received, In review, Needs more information, Closed). A case marked **Reporter replied**
is waiting for them.

Both sides show a **key fingerprint** so they can check they are using the same key pair.

## What the server can and cannot see

| Stored or seen by the server | Never seen by the server |
|---|---|
| Encrypted report and messages | Case codes and case keys |
| Hash of each case's auth value | Report or message contents (including the company name) |
| Who sent each message (reporter or investigator) and the **day** it was sent | Exact times, IP addresses, any identity |
| Case status | |

- Messages are bound to their sender role through AES-GCM associated data, so the server
  cannot pass off a reporter's message as an investigator's, or the reverse.
- The server keeps no request logs and never reads client IP addresses.
- Strict security headers: a CSP allowing only `'self'`, `no-referrer`, no framing, and
  no camera, microphone or location access.
- The service worker caches only the app shell, never API responses.
- No runtime dependencies (Node's built-in `http`, `crypto`, `node:sqlite` and Web Crypto).

## Running it

Requires Node.js 22.13 or newer.

```sh
npm run keygen   # creates keys/ (public key, private key, investigator token)
npm start        # http://localhost:3000 and http://localhost:3000/investigator.html
npm test
```

Environment variables: `PORT`, `DB_FILE`, `INVESTIGATOR_PUBLIC_KEY_FILE`, and
`INVESTIGATOR_TOKEN` (falls back to `keys/investigator-token.txt`).

For production:
- **Move `keys/investigator-private.jwk.json` off the server** and keep it only with
  investigators. If it stays on the server, a server breach exposes every case.
- Serve over HTTPS. Browsers only allow PWA installation and service workers over HTTPS
  (or on `localhost`).
- Back up the private key. If it's lost, every case becomes unreadable. Running
  `npm run keygen --force` creates a new pair and has the same effect.

## Known limitations and next steps

- **The server is trusted to serve honest code and the honest public key.** A compromised
  server could send reporters altered JavaScript or a different public key. The fingerprint
  lets people check the key, but not the code. Stronger options include publishing the
  fingerprint elsewhere, a `.onion` mirror, or signed releases.
- **One shared investigator key pair and token.** Per-investigator accounts and keys would
  allow access control and revoking access.
- **The server can drop or reorder messages**, though it can't read or forge them.
- **No timing delay.** New reports are visible to investigators immediately. A random delay
  before cases appear would make it harder to link a report to a specific meeting or event.
- **Network-level anonymity.** The app cannot hide the user's IP address from their ISP or
  the host. The home screen tells high-risk users to use Tor Browser and to avoid work
  devices and networks.
- **Abuse limits are basic.** Global caps on new cases and sessions per minute, plus 20
  reporter messages per session. Proof of work or a similar bot-resistance step would help.
- **Icons.** The manifest ships a single SVG icon. Add 192px and 512px PNG icons for the
  widest install support (older iOS in particular).
