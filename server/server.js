import { createServer } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { openDatabase } from './db.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const port = Number(process.env.PORT ?? 3000);
const dbFile = process.env.DB_FILE ?? `${root}data/whistleblower.db`;
const publicKeyFile = process.env.INVESTIGATOR_PUBLIC_KEY_FILE ?? `${root}keys/investigator-public.jwk.json`;
const tokenFile = `${root}keys/investigator-token.txt`;

const investigatorPublicKey = existsSync(publicKeyFile) ? JSON.parse(readFileSync(publicKeyFile, 'utf8')) : null;
const investigatorToken =
  process.env.INVESTIGATOR_TOKEN ?? (existsSync(tokenFile) ? readFileSync(tokenFile, 'utf8').trim() : null);

if (!investigatorPublicKey) console.warn(`No investigator public key at ${publicKeyFile}; run "npm run keygen".`);
if (!investigatorToken) console.warn('No investigator token configured; investigator login is disabled.');

const handler = createApp({
  db: openDatabase(dbFile),
  publicDir: fileURLToPath(new URL('../public', import.meta.url)),
  investigatorPublicKey,
  investigatorToken,
});

createServer(handler).listen(port, () => {
  console.log(`Whistleblower running on http://localhost:${port}`);
});
