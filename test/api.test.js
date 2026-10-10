import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createApp, MAX_MESSAGES_PER_SESSION, SESSION_TTL_MS } from '../server/app.js';
import { openDatabase } from '../server/db.js';
import {
  CONTEXT, decryptText, deriveCaseSecrets, encryptText, importInvestigatorPrivateKey, unwrapCaseKey,
} from '../public/js/crypto.js';
import { buildCase, investigatorKeyPair } from './helpers.js';

const TOKEN = 'test-investigator-token';
const REPORT = {
  company: 'Acme Corp',
  category: 'fraud',
  description: 'Invoices are being duplicated to inflate revenue figures.',
};

let server, base, db, keys;
let clock = Date.parse('2026-06-01T12:00:00Z');

before(async () => {
  keys = await investigatorKeyPair();
  db = openDatabase(':memory:');
  const publicDir = fileURLToPath(new URL('../public', import.meta.url));
  server = createServer(createApp({
    db, publicDir, investigatorPublicKey: keys.publicJwk, investigatorToken: TOKEN, now: () => clock,
  }));
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});

after(() => server.close());

async function call(method, path, { session, body } = {}) {
  const headers = {};
  if (session) headers.Authorization = `Bearer ${session}`;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body && JSON.stringify(body) });
  return { status: res.status, data: res.status === 204 ? null : await res.json() };
}

async function submitCase(report = REPORT) {
  const c = await buildCase(keys.publicJwk, report);
  assert.equal((await call('POST', '/api/cases', { body: c.body })).status, 201);
  return c;
}

const reporterSession = async (auth) => (await call('POST', '/api/session', { body: { auth } })).data.sessionId;
const investigatorSession = async () =>
  (await call('POST', '/api/investigator/session', { body: { token: TOKEN } })).data.sessionId;

test('config serves the investigator public key', async () => {
  const { status, data } = await call('GET', '/api/config');
  assert.equal(status, 200);
  assert.deepEqual(data.investigatorPublicKey, keys.publicJwk);
});

test('the server stores only ciphertext and a hash of the auth value', async () => {
  const { code, auth } = await submitCase();
  const row = db.prepare('SELECT * FROM cases ORDER BY id DESC LIMIT 1').get();
  const stored = JSON.stringify(row);
  for (const secret of [code, code.replace(/-/g, ''), auth, REPORT.company, REPORT.description]) {
    assert.ok(!stored.includes(secret), `database row contains ${secret}`);
  }
  assert.equal(row.created_on, '2026-06-01');
});

test('every login with a case code gets a new random session ID, stored only as a hash', async () => {
  const { auth } = await submitCase();
  const first = await call('POST', '/api/session', { body: { auth } });
  assert.equal(first.status, 201);
  assert.match(first.data.sessionId, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(first.data.expiresAt, clock + SESSION_TTL_MS);
  const second = await reporterSession(auth);
  assert.notEqual(second, first.data.sessionId);
  const hashes = db.prepare('SELECT token_hash FROM sessions').all().map((r) => r.token_hash);
  assert.ok(!hashes.includes(first.data.sessionId) && !hashes.includes(second));
});

test('unknown case codes are rejected', async () => {
  const { auth } = await deriveCaseSecrets('0000-0000-0000-0000-0000-0000');
  assert.equal((await call('POST', '/api/session', { body: { auth } })).status, 401);
  assert.equal((await call('POST', '/api/session', { body: { auth: 'short' } })).status, 400);
});

test('reporter and investigator can hold an encrypted conversation', async () => {
  const { auth, key } = await submitCase();
  const reporter = await reporterSession(auth);
  const investigator = await investigatorSession();

  // Investigator finds the case, decrypts it and asks a question.
  const { data: list } = await call('GET', '/api/investigator/cases', { session: investigator });
  const summary = list.cases[0];
  const privateKey = await importInvestigatorPrivateKey(keys.privateJwk);
  const caseKey = await unwrapCaseKey(privateKey, summary.wrappedKey);
  assert.deepEqual(JSON.parse(await decryptText(caseKey, summary.report, CONTEXT.report)), REPORT);
  assert.equal(summary.awaitingReply, false);

  const question = await encryptText(caseKey, 'Which department?', CONTEXT.investigator);
  assert.equal((await call('POST', `/api/investigator/cases/${summary.id}/messages`, {
    session: investigator, body: { message: question },
  })).status, 201);
  assert.equal((await call('PATCH', `/api/investigator/cases/${summary.id}`, {
    session: investigator, body: { status: 'needs-info' },
  })).status, 200);

  // Reporter sees the question and the new status, and replies.
  const { data: view } = await call('GET', '/api/case', { session: reporter });
  assert.equal(view.status, 'needs-info');
  assert.equal(view.wrappedKey, undefined);
  assert.equal(await decryptText(key, view.messages[0].body, CONTEXT.investigator), 'Which department?');
  assert.equal((await call('POST', '/api/case/messages', {
    session: reporter, body: { message: await encryptText(key, 'Accounts payable.', CONTEXT.reporter) },
  })).status, 201);

  const { data: detail } = await call('GET', `/api/investigator/cases/${summary.id}`, { session: investigator });
  assert.deepEqual(detail.messages.map((m) => m.sender), ['investigator', 'reporter']);
  assert.equal(await decryptText(caseKey, detail.messages[1].body, CONTEXT.reporter), 'Accounts payable.');
  const { data: relisted } = await call('GET', '/api/investigator/cases', { session: investigator });
  assert.equal(relisted.cases.find((c) => c.id === summary.id).awaitingReply, true);
});

test('roles are enforced', async () => {
  const { auth } = await submitCase();
  const reporter = await reporterSession(auth);
  const investigator = await investigatorSession();
  assert.equal((await call('GET', '/api/investigator/cases', { session: reporter })).status, 403);
  assert.equal((await call('GET', '/api/case', { session: investigator })).status, 403);
  assert.equal((await call('GET', '/api/investigator/cases')).status, 401);
  assert.equal((await call('POST', '/api/investigator/session', { body: { token: 'wrong' } })).status, 401);
});

test('a reporter session only ever sees its own case', async () => {
  const a = await submitCase({ ...REPORT, company: 'A' });
  const b = await submitCase({ ...REPORT, company: 'B' });
  const { data } = await call('GET', '/api/case', { session: await reporterSession(a.auth) });
  assert.equal(JSON.parse(await decryptText(a.key, data.report, CONTEXT.report)).company, 'A');
  await assert.rejects(decryptText(b.key, data.report, CONTEXT.report));
});

test('closed cases accept no new messages', async () => {
  const { auth, key } = await submitCase();
  const investigator = await investigatorSession();
  const { data } = await call('GET', '/api/investigator/cases', { session: investigator });
  await call('PATCH', `/api/investigator/cases/${data.cases[0].id}`, { session: investigator, body: { status: 'closed' } });
  const reporter = await reporterSession(auth);
  const message = await encryptText(key, 'hello', CONTEXT.reporter);
  assert.equal((await call('POST', '/api/case/messages', { session: reporter, body: { message } })).status, 409);
});

test('malformed input is rejected', async () => {
  const { body } = await buildCase(keys.publicJwk, REPORT);
  const bad = [
    { ...body, auth: 'x' },
    { ...body, report: 'not base64url!' },
    { ...body, report: 'A'.repeat(30_001) },
    { ...body, wrappedKey: undefined },
  ];
  for (const b of bad) assert.equal((await call('POST', '/api/cases', { body: b })).status, 400);
  assert.equal((await call('POST', '/api/cases', { body })).status, 201);
  assert.equal((await call('POST', '/api/cases', { body })).status, 409);

  const investigator = await investigatorSession();
  assert.equal((await call('PATCH', '/api/investigator/cases/1', { session: investigator, body: { status: 'nope' } })).status, 400);
  assert.equal((await call('GET', '/api/investigator/cases/999999', { session: investigator })).status, 404);
});

test('reporter messages per session are capped', async () => {
  const { auth, key } = await submitCase();
  const reporter = await reporterSession(auth);
  const message = await encryptText(key, 'hi', CONTEXT.reporter);
  for (let i = 0; i < MAX_MESSAGES_PER_SESSION; i++) {
    assert.equal((await call('POST', '/api/case/messages', { session: reporter, body: { message } })).status, 201);
  }
  assert.equal((await call('POST', '/api/case/messages', { session: reporter, body: { message } })).status, 429);
});

test('sessions expire and logout ends them', async () => {
  const { auth } = await submitCase();
  const s1 = await reporterSession(auth);
  assert.equal((await call('DELETE', '/api/session', { session: s1 })).status, 204);
  assert.equal((await call('GET', '/api/case', { session: s1 })).status, 401);

  const s2 = await reporterSession(auth);
  clock += SESSION_TTL_MS + 1;
  assert.equal((await call('GET', '/api/case', { session: s2 })).status, 401);
});

test('serves the PWA with security headers and blocks path traversal', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(`${base}/investigator.html`)).status, 200);
  assert.equal((await fetch(`${base}/..%2fpackage.json`)).status, 404);
});
