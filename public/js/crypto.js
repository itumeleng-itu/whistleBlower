// End-to-end encryption between reporters and investigators.
//
// From a case code the device derives two independent secrets with HKDF:
//   auth - proves knowledge of the code; the server stores only its SHA-256
//   key  - AES-256-GCM key that encrypts the report and every message
// The case key is also encrypted ("wrapped") with the investigators' RSA public
// key so they can read the case. The server never sees the code, the key or
// any plaintext.

import { normalizeCaseCode } from './case-code.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const RSA = { name: 'RSA-OAEP', hash: 'SHA-256' };
const IV_BYTES = 12;

// Bound into each ciphertext so the server cannot pass one kind off as another,
// e.g. relabel a reporter's message as coming from the investigator.
export const CONTEXT = { report: 'report', reporter: 'message:reporter', investigator: 'message:investigator' };

export function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(str) {
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const importCaseKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

export async function deriveCaseSecrets(caseCode) {
  const base = await crypto.subtle.importKey('raw', enc.encode(normalizeCaseCode(caseCode)), 'HKDF', false, ['deriveBits']);
  const derive = async (info) =>
    new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('whistleblower-v1'), info: enc.encode(info) },
      base,
      256,
    ));
  const rawKey = await derive('encryption');
  return { auth: toBase64Url(await derive('auth')), rawKey, key: await importCaseKey(rawKey) };
}

export async function encryptText(key, text, context) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(context) },
    key,
    enc.encode(text),
  ));
  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv);
  out.set(ct, IV_BYTES);
  return toBase64Url(out);
}

export async function decryptText(key, blob, context) {
  const bytes = fromBase64Url(blob);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, IV_BYTES), additionalData: enc.encode(context) },
    key,
    bytes.slice(IV_BYTES),
  );
  return dec.decode(pt);
}

export const importInvestigatorPublicKey = (jwk) => crypto.subtle.importKey('jwk', jwk, RSA, false, ['encrypt']);
export const importInvestigatorPrivateKey = (jwk) => crypto.subtle.importKey('jwk', jwk, RSA, false, ['decrypt']);

export async function wrapCaseKey(publicKey, rawKey) {
  return toBase64Url(new Uint8Array(await crypto.subtle.encrypt(RSA, publicKey, rawKey)));
}

export async function unwrapCaseKey(privateKey, wrapped) {
  return importCaseKey(new Uint8Array(await crypto.subtle.decrypt(RSA, privateKey, fromBase64Url(wrapped))));
}

// Short, human-comparable fingerprint of an RSA key (public or private JWK),
// so reporters and investigators can check they are using the same key pair.
export async function keyFingerprint(jwk) {
  const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonical)));
  const hex = Array.from(digest.slice(0, 10), (b) => b.toString(16).padStart(2, '0')).join('');
  return hex.toUpperCase().match(/.{4}/g).join(' ');
}
