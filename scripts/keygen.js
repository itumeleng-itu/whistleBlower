// Creates the investigators' RSA key pair and login token.
//   keys/investigator-public.jwk.json  - served to reporters' devices
//   keys/investigator-private.jwk.json - decrypts cases; keep OFF the server in production
//   keys/investigator-token.txt        - investigator login token
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { keyFingerprint } from '../public/js/crypto.js';

const dir = fileURLToPath(new URL('../keys/', import.meta.url));
const files = {
  public: `${dir}investigator-public.jwk.json`,
  private: `${dir}investigator-private.jwk.json`,
  token: `${dir}investigator-token.txt`,
};

if (existsSync(files.private) && !process.argv.includes('--force')) {
  console.error('Keys already exist. Replacing them makes every existing case unreadable.');
  console.error('Re-run with --force if you really mean it.');
  process.exit(1);
}

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['encrypt', 'decrypt'],
);
const publicJwk = await crypto.subtle.exportKey('jwk', publicKey);

mkdirSync(dir, { recursive: true });
writeFileSync(files.public, JSON.stringify(publicJwk, null, 2));
writeFileSync(files.private, JSON.stringify(await crypto.subtle.exportKey('jwk', privateKey), null, 2), { mode: 0o600 });
writeFileSync(files.token, randomBytes(32).toString('base64url'), { mode: 0o600 });

console.log(`Wrote ${files.public}\nWrote ${files.private}\nWrote ${files.token}`);
console.log(`Key fingerprint: ${await keyFingerprint(publicJwk)}`);
