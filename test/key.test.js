import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, isValidKey, normalizeKey } from '../public/js/key.js';

test('generated keys are valid and well-formed', async () => {
  for (let i = 0; i < 200; i++) {
    const key = await generateKey();
    assert.match(key, /^([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.equal(await isValidKey(key), true);
  }
});

test('generated keys are unique', async () => {
  const keys = new Set();
  for (let i = 0; i < 500; i++) keys.add(await generateKey());
  assert.equal(keys.size, 500);
});

test('tolerates formatting and lookalike characters', async () => {
  const key = await generateKey();
  assert.equal(await isValidKey(key.toLowerCase()), true);
  assert.equal(await isValidKey(key.replace(/-/g, ' ')), true);
  assert.equal(await isValidKey(key.replace(/-/g, '')), true);
  assert.equal(normalizeKey('o-i-l'), '011');
});

test('rejects typos, wrong length and junk', async () => {
  const key = await generateKey();
  const flipped = key.slice(0, 2) + (key[2] === 'A' ? 'B' : 'A') + key.slice(3);
  assert.equal(await isValidKey(flipped), false);
  assert.equal(await isValidKey(key.slice(0, -1)), false);
  assert.equal(await isValidKey(key + 'A'), false);
  assert.equal(await isValidKey(''), false);
  assert.equal(await isValidKey('UUUU-UUUU-UUUU-UUUU-UUUU-UUUU'), false);
});
