import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { openDatabase } from './db.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const port = Number(process.env.PORT ?? 3000);
const dbFile = process.env.DB_FILE ?? `${root}data/whistleblower.db`;

const db = openDatabase(dbFile);
const handler = createApp({ db, publicDir: fileURLToPath(new URL('../public', import.meta.url)) });

createServer(handler).listen(port, () => {
  console.log(`Whistleblower running on http://localhost:${port}`);
});
