import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createApp, MAX_REPORTS_PER_SESSION, SESSION_TTL_MS } from '../server/app.js';
import { openDatabase } from '../server/db.js';

let server, base, db;
let clock = Date.parse('2026-06-01T12:00:00Z');

before(async () => {
  db = openDatabase(':memory:');
  const publicDir = fileURLToPath(new URL('../public', import.meta.url));
  server = createServer(createApp({ db, publicDir, now: () => clock }));
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});

after(() => server.close());

const startSession = async () => (await (await fetch(`${base}/api/session`, { method: 'POST' })).json()).sessionId;

const report = (sessionId, body) =>
  fetch(`${base}/api/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(sessionId && { Authorization: `Bearer ${sessionId}` }) },
    body: JSON.stringify(body),
  });

const validReport = {
  company: 'Acme Corp',
  category: 'fraud',
  description: 'Invoices are being duplicated to inflate revenue figures.',
  incidentDate: '2026-05-01',
};

test('every login gets a new random session ID, stored only as a hash', async () => {
  const res = await fetch(`${base}/api/session`, { method: 'POST' });
  assert.equal(res.status, 201);
  const { sessionId, expiresAt } = await res.json();
  assert.match(sessionId, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(expiresAt, clock + SESSION_TTL_MS);
  assert.notEqual(await startSession(), sessionId);

  const stored = db.prepare('SELECT token_hash FROM sessions').all().map((r) => r.token_hash);
  assert.ok(!stored.includes(sessionId));
});

test('reports require a valid session', async () => {
  assert.equal((await report(null, validReport)).status, 401);
  assert.equal((await report('x'.repeat(43), validReport)).status, 401);
});

test('a valid report is stored without any link to the session', async () => {
  const sessionId = await startSession();
  const res = await report(sessionId, validReport);
  assert.equal(res.status, 201);
  const { reference } = await res.json();
  assert.match(reference, /^WB-[0-9A-F]{12}$/);

  const row = db.prepare('SELECT * FROM reports WHERE reference = ?').get(reference);
  assert.equal(row.company, 'Acme Corp');
  assert.equal(row.submitted_on, '2026-06-01');
  assert.deepEqual(
    Object.keys(row).sort(),
    ['category', 'company', 'description', 'id', 'incident_date', 'location', 'reference', 'submitted_on'],
  );
});

test('invalid reports are rejected', async () => {
  const sessionId = await startSession();
  const cases = [
    { ...validReport, company: '' },
    { ...validReport, category: 'gossip' },
    { ...validReport, description: 'too short' },
    { ...validReport, incidentDate: '2099-01-01' },
    { ...validReport, incidentDate: 'yesterday' },
    { ...validReport, company: 'x'.repeat(201) },
  ];
  for (const body of cases) assert.equal((await report(sessionId, body)).status, 400, JSON.stringify(body));
});

test('sessions expire', async () => {
  const sessionId = await startSession();
  clock += SESSION_TTL_MS + 1;
  assert.equal((await report(sessionId, validReport)).status, 401);
});

test('logout invalidates the session', async () => {
  const sessionId = await startSession();
  const res = await fetch(`${base}/api/session`, { method: 'DELETE', headers: { Authorization: `Bearer ${sessionId}` } });
  assert.equal(res.status, 204);
  assert.equal((await report(sessionId, validReport)).status, 401);
});

test('reports per session are capped', async () => {
  const sessionId = await startSession();
  for (let i = 0; i < MAX_REPORTS_PER_SESSION; i++) assert.equal((await report(sessionId, validReport)).status, 201);
  assert.equal((await report(sessionId, validReport)).status, 429);
});

test('serves the PWA with security headers and blocks path traversal', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(`${base}/manifest.webmanifest`)).status, 200);
  assert.equal((await fetch(`${base}/..%2fpackage.json`)).status, 404);
});
