// Shared test fixtures: an investigator key pair and a reporter client that
// does exactly what the browser does (derive secrets, encrypt, wrap the key).
import { generateCaseCode } from '../public/js/case-code.js';
import { CONTEXT, deriveCaseSecrets, encryptText, importInvestigatorPublicKey, wrapCaseKey } from '../public/js/crypto.js';

export async function investigatorKeyPair() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  return {
    publicJwk: await crypto.subtle.exportKey('jwk', publicKey),
    privateJwk: await crypto.subtle.exportKey('jwk', privateKey),
  };
}

export async function buildCase(publicJwk, report) {
  const code = await generateCaseCode();
  const { auth, rawKey, key } = await deriveCaseSecrets(code);
  const body = {
    auth,
    wrappedKey: await wrapCaseKey(await importInvestigatorPublicKey(publicJwk), rawKey),
    report: await encryptText(key, JSON.stringify(report), CONTEXT.report),
  };
  return { code, auth, key, body };
}
