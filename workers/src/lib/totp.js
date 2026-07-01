// TOTP implementation per RFC 6238 / RFC 4226
// Uses HMAC-SHA1 via Web Crypto (CF Workers native).
// Compatible with Google Authenticator, Authy, 1Password, Bitwarden, etc.

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateSecret(byteLength = 20) {
  return base32Encode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const s = str.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  const bytes = [];
  let bits = 0, value = 0;
  for (const c of s) {
    const idx = BASE32.indexOf(c);
    if (idx === -1) throw new Error(`Invalid base32 character: ${c}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(bytes);
}

// HOTP counter as 8-byte big-endian Uint8Array
function counterToBytes(counter) {
  const buf = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { buf[i] = c & 0xff; c = Math.floor(c / 256); }
  return buf;
}

export async function generateTOTP(secret, { timeStep = 30, digits = 6, now = Date.now() } = {}) {
  const counter = Math.floor(now / 1000 / timeStep);
  const key = await crypto.subtle.importKey(
    'raw', base32Decode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterToBytes(counter)));
  const offset = sig[sig.length - 1] & 0x0f;
  const code = (
    ((sig[offset]     & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) <<  8) |
     (sig[offset + 3] & 0xff)
  ) % (10 ** digits);
  return String(code).padStart(digits, '0');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Accepts a ±1 window (±30 seconds) to tolerate device clock skew
export async function verifyTOTP(secret, token, { window = 1, timeStep = 30 } = {}) {
  if (!/^\d{6}$/.test(token)) return false;
  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    const expected = await generateTOTP(secret, { timeStep, now: now + i * timeStep * 1000 });
    if (timingSafeEqual(expected, token)) return true;
  }
  return false;
}

export function buildOtpauthUrl(secret, email, issuer = 'CyberDudeBivash Security Hub') {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${params}`;
}

// Backup codes: 8-char hex pairs (e.g. "A3F2-9C1E") — easy to read/type
export function generateBackupCodes(count = 8) {
  return Array.from({ length: count }, () => {
    const b = crypto.getRandomValues(new Uint8Array(4));
    const hex = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
    return `${hex.slice(0, 4)}-${hex.slice(4)}`;
  });
}

async function sha256hex(str) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function hashBackupCode(code) {
  return sha256hex(code.replace(/-/g, '').toUpperCase());
}

export async function verifyBackupCode(code, hashedCodes) {
  const h = await sha256hex(code.replace(/-/g, '').toUpperCase());
  for (const stored of hashedCodes) {
    if (timingSafeEqual(h, stored)) return true;
  }
  return false;
}
