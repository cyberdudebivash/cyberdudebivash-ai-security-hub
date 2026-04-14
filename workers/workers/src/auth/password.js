/**
 * CYBERDUDEBIVASH AI Security Hub — Password Security v5.0
 * PBKDF2-SHA256 via Web Crypto API (CF Workers native)
 * 200,000 iterations — NIST SP 800-132 compliant
 * No external dependencies. Timing-safe comparison.
 */

const PBKDF2_ITERATIONS = 200_000;
const PBKDF2_HASH       = 'SHA-256';
const KEY_LENGTH_BITS   = 256; // 32 bytes
const SALT_BYTES        = 32;

// ─── Generate cryptographically random salt ───────────────────────────────────
export function generateSalt() {
  const raw = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(raw);
  return [...raw].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Derive key from password + salt ─────────────────────────────────────────
async function deriveKey(password, saltHex) {
  const saltBytes = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name:       'PBKDF2',
      salt:       saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash:       PBKDF2_HASH,
    },
    keyMaterial,
    KEY_LENGTH_BITS
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Hash password → returns { hash, salt } ──────────────────────────────────
export async function hashPassword(password) {
  const salt = generateSalt();
  const hash = await deriveKey(password, salt);
  return { hash, salt };
}

// ─── Verify password against stored hash + salt ──────────────────────────────
export async function verifyPassword(password, storedHash, storedSalt) {
  try {
    const derived = await deriveKey(password, storedSalt);
    // Constant-time comparison to prevent timing attacks
    return timingSafeEqual(derived, storedHash);
  } catch { return false; }
}

// ─── Constant-time string comparison ─────────────────────────────────────────
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // Still iterate to prevent length-based timing leak
    let acc = 1;
    for (let i = 0; i < a.length; i++) acc |= a.charCodeAt(i) ^ (b.charCodeAt(i % b.length) || 0);
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return acc === 0;
}

// ─── Password strength validation ────────────────────────────────────────────
export function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'Password is required' };
  }
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters' };
  }
  if (password.length > 128) {
    return { valid: false, message: 'Password must be at most 128 characters' };
  }
  const hasUpper  = /[A-Z]/.test(password);
  const hasLower  = /[a-z]/.test(password);
  const hasDigit  = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);

  const score = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  if (score < 3) {
    return {
      valid: false,
      message: 'Password must contain at least 3 of: uppercase, lowercase, digit, special character',
    };
  }
  return { valid: true, strength: score === 4 ? 'strong' : 'medium' };
}

// ─── Email validation ─────────────────────────────────────────────────────────
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

export function validateEmail(email) {
  if (!email || typeof email !== 'string') return { valid: false, message: 'Email is required' };
  const e = email.trim().toLowerCase();
  if (e.length > 254) return { valid: false, message: 'Email too long' };
  if (!EMAIL_RE.test(e)) return { valid: false, message: 'Invalid email format' };
  return { valid: true, value: e };
}
