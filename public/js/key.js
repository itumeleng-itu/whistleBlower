// Access-key format and validation. Runs entirely on the user's device:
// the key itself is never sent to the server or written to storage.
//
// A key is 20 random Crockford-base32 characters (100 bits) followed by a
// 4-character checksum derived from SHA-256, shown as six groups of four:
//   XXXX-XXXX-XXXX-XXXX-XXXX-CCCC

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const BODY_LENGTH = 20;
const CHECKSUM_LENGTH = 4;
const CHECKSUM_DOMAIN = 'whistleblower-key-v1:';

// Accept common typing mistakes: lowercase, spaces/dashes, O for 0, I/L for 1.
export function normalizeKey(input) {
  return String(input)
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

export function formatKey(normalized) {
  return normalized.match(/.{1,4}/g).join('-');
}

async function checksum(body) {
  const data = new TextEncoder().encode(CHECKSUM_DOMAIN + body);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  // First 20 bits of the digest -> 4 base32 characters.
  const bits = (digest[0] << 12) | (digest[1] << 4) | (digest[2] >> 4);
  let out = '';
  for (let i = CHECKSUM_LENGTH - 1; i >= 0; i--) {
    out += ALPHABET[(bits >> (i * 5)) & 31];
  }
  return out;
}

export async function generateKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(BODY_LENGTH));
  // 256 is divisible by 32, so masking keeps the distribution uniform.
  const body = Array.from(bytes, (b) => ALPHABET[b & 31]).join('');
  return formatKey(body + (await checksum(body)));
}

export async function isValidKey(input) {
  const key = normalizeKey(input);
  if (key.length !== BODY_LENGTH + CHECKSUM_LENGTH) return false;
  for (const ch of key) {
    if (!ALPHABET.includes(ch)) return false;
  }
  const body = key.slice(0, BODY_LENGTH);
  return (await checksum(body)) === key.slice(BODY_LENGTH);
}
