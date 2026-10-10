// Case codes: the one secret a reporter needs to return to their report.
// Generated on the device and shown once. The server only ever receives a
// value derived from it (see crypto.js), never the code itself.
//
// A code is 20 random Crockford-base32 characters (100 bits) followed by a
// 4-character checksum that catches typos before anything is sent:
//   XXXX-XXXX-XXXX-XXXX-XXXX-CCCC

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const BODY_LENGTH = 20;
const CHECKSUM_LENGTH = 4;
const CHECKSUM_DOMAIN = 'whistleblower-case-code-v1:';

// Accept common typing mistakes: lowercase, spaces/dashes, O for 0, I/L for 1.
export function normalizeCaseCode(input) {
  return String(input)
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

export function formatCaseCode(normalized) {
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

export async function generateCaseCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(BODY_LENGTH));
  // 256 is divisible by 32, so masking keeps the distribution uniform.
  const body = Array.from(bytes, (b) => ALPHABET[b & 31]).join('');
  return formatCaseCode(body + (await checksum(body)));
}

export async function isValidCaseCode(input) {
  const code = normalizeCaseCode(input);
  if (code.length !== BODY_LENGTH + CHECKSUM_LENGTH) return false;
  for (const ch of code) {
    if (!ALPHABET.includes(ch)) return false;
  }
  return (await checksum(code.slice(0, BODY_LENGTH))) === code.slice(BODY_LENGTH);
}
