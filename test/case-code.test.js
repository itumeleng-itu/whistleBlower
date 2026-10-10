import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateCaseCode, isValidCaseCode, normalizeCaseCode } from '../public/js/case-code.js';

test('generated codes are valid and well-formed', async () => {
  for (let i = 0; i < 200; i++) {
    const code = await generateCaseCode();
    assert.match(code, /^([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.equal(await isValidCaseCode(code), true);
  }
});

test('generated codes are unique', async () => {
  const codes = new Set();
  for (let i = 0; i < 500; i++) codes.add(await generateCaseCode());
  assert.equal(codes.size, 500);
});

test('tolerates formatting and lookalike characters', async () => {
  const code = await generateCaseCode();
  assert.equal(await isValidCaseCode(code.toLowerCase()), true);
  assert.equal(await isValidCaseCode(code.replace(/-/g, ' ')), true);
  assert.equal(await isValidCaseCode(code.replace(/-/g, '')), true);
  assert.equal(normalizeCaseCode('o-i-l'), '011');
});

test('rejects typos, wrong length and junk', async () => {
  const code = await generateCaseCode();
  const flipped = code.slice(0, 2) + (code[2] === 'A' ? 'B' : 'A') + code.slice(3);
  assert.equal(await isValidCaseCode(flipped), false);
  assert.equal(await isValidCaseCode(code.slice(0, -1)), false);
  assert.equal(await isValidCaseCode(code + 'A'), false);
  assert.equal(await isValidCaseCode(''), false);
  assert.equal(await isValidCaseCode('UUUU-UUUU-UUUU-UUUU-UUUU-UUUU'), false);
});
