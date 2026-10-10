import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTEXT, decryptText, deriveCaseSecrets, encryptText, importInvestigatorPrivateKey, keyFingerprint, unwrapCaseKey,
} from '../public/js/crypto.js';
import { buildCase, investigatorKeyPair } from './helpers.js';

let keys;
before(async () => {
  keys = await investigatorKeyPair();
});

test('the same case code always derives the same secrets, ignoring formatting', async () => {
  const { code, auth } = await buildCase(keys.publicJwk, {});
  const again = await deriveCaseSecrets(code.toLowerCase().replace(/-/g, ' '));
  assert.equal(again.auth, auth);
  assert.match(auth, /^[A-Za-z0-9_-]{43}$/);
});

test('auth value reveals neither the code nor the encryption key', async () => {
  const { code, auth } = await buildCase(keys.publicJwk, {});
  const { rawKey } = await deriveCaseSecrets(code);
  assert.ok(!auth.includes(code.replace(/-/g, '')));
  assert.notEqual(Buffer.from(auth, 'base64url').toString('hex'), Buffer.from(rawKey).toString('hex'));
});

test('investigator can unwrap the case key and read the report', async () => {
  const report = { company: 'Acme', description: 'Something bad happened here.' };
  const { body } = await buildCase(keys.publicJwk, report);
  const caseKey = await unwrapCaseKey(await importInvestigatorPrivateKey(keys.privateJwk), body.wrappedKey);
  assert.deepEqual(JSON.parse(await decryptText(caseKey, body.report, CONTEXT.report)), report);
});

test('a different key pair cannot unwrap the case key', async () => {
  const { body } = await buildCase(keys.publicJwk, {});
  const other = await investigatorKeyPair();
  await assert.rejects(unwrapCaseKey(await importInvestigatorPrivateKey(other.privateJwk), body.wrappedKey));
});

test('ciphertexts are bound to their context and tamper-evident', async () => {
  const { key } = await buildCase(keys.publicJwk, {});
  const blob = await encryptText(key, 'hello', CONTEXT.reporter);
  assert.equal(await decryptText(key, blob, CONTEXT.reporter), 'hello');
  await assert.rejects(decryptText(key, blob, CONTEXT.investigator));
  const tampered = blob.slice(0, -2) + (blob.at(-2) === 'A' ? 'B' : 'A') + blob.at(-1);
  await assert.rejects(decryptText(key, tampered, CONTEXT.reporter));
});

test('encrypting the same text twice gives different ciphertexts', async () => {
  const { key } = await buildCase(keys.publicJwk, {});
  assert.notEqual(await encryptText(key, 'same', CONTEXT.reporter), await encryptText(key, 'same', CONTEXT.reporter));
});

test('public and private keys share a fingerprint', async () => {
  assert.equal(await keyFingerprint(keys.publicJwk), await keyFingerprint(keys.privateJwk));
  assert.match(await keyFingerprint(keys.publicJwk), /^([0-9A-F]{4} ){4}[0-9A-F]{4}$/);
});
