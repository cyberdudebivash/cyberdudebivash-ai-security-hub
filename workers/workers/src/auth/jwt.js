/**
 * CYBERDUDEBIVASH AI Security Hub — JWT Engine v5.0
 * Standard HS256 JWT using Web Crypto API (CF Workers native)
 * No external dependencies. Fully edge-native.
 *
 * Access tokens:  15-minute TTL (short-lived)
 * Refresh tokens: 7-day TTL   (stored in D1, revocable)
 */

const ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };
const ACCESS_TOKEN_TTL  = 15 * 60;       // 15 minutes (seconds)
const REFRESH_TOKEN_TTL = 7 * 24 * 3600; // 7 days (seconds)

// ─── Base64URL encode/decode ──────────────────────────────────────────────────
function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64urlDecode(str) {
  const pad = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = pad + '='.repeat((4 - (pad.length % 4)) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

function encodeJSON(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

// ─── Import HMAC key from secret string ──────────────────────────────────────
async function importKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    ALGORITHM,
    false,
    ['sign', 'verify']
  );
}

// ─── Sign JWT ─────────────────────────────────────────────────────────────────
export async function signJWT(payload, secret) {
  const header  = encodeJSON({ alg: 'HS256', typ: 'JWT' });
  const body    = encodeJSON(payload);
  const signing = `${header}.${body}`;
  const key     = await importKey(secret);
  const sigBuf  = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signing));
  return `${signing}.${b64url(sigBuf)}`;
}

// ─── Verify + decode JWT ──────────────────────────────────────────────────────
export async function verifyJWT(token, secret) {
  if (!token || typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, bodyB64, sigB64] = parts;

  // Verify signature (constant-time via subtle.verify)
  try {
    const key       = await importKey(secret);
    const data      = new TextEncoder().encode(`${headerB64}.${bodyB64}`);
    const sigBytes  = b64urlDecode(sigB64);
    const valid     = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;
  } catch { return null; }

  // Decode payload
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(bodyB64)));

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;

    // Check not-before
    if (payload.nbf && payload.nbf > now) return null;

    return payload;
  } catch { return null; }
}

// ─── Create access token ──────────────────────────────────────────────────────
export async function createAccessToken(user, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signJWT({
    sub:   user.id,
    email: user.email,
    tier:  user.tier,
    type:  'access',
    iat:   now,
    exp:   now + ACCESS_TOKEN_TTL,
    iss:   'cyberdudebivash-security-hub',
  }, secret);
}

// ─── Create refresh token (opaque, stored in D1) ─────────────────────────────
export async function createRefreshToken() {
  const raw = new Uint8Array(48);
  crypto.getRandomValues(raw);
  const token = b64url(raw); // ~64 char URL-safe token
  const hash  = await hashToken(token);
  const expires = new Date(Date.now() + REFRESH_TOKEN_TTL * 1000).toISOString();
  return { token, hash, expires };
}

// ─── SHA-256 hash of a token (for safe storage) ───────────────────────────────
export async function hashToken(token) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Store refresh token in D1 ────────────────────────────────────────────────
export async function storeRefreshToken(db, userId, tokenData, ip, ua) {
  await db.prepare(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(userId, tokenData.hash, tokenData.expires, ip || null, ua || null).run();
}

// ─── Validate refresh token from D1 ──────────────────────────────────────────
export async function validateRefreshToken(db, token) {
  const hash = await hashToken(token);
  const row  = await db.prepare(
    `SELECT rt.*, u.id as uid, u.email, u.tier, u.status
     FROM refresh_tokens rt
     JOIN users u ON rt.user_id = u.id
     WHERE rt.token_hash = ? AND rt.revoked = 0 AND rt.expires_at > datetime('now')`
  ).bind(hash).first();
  return row || null;
}

// ─── Revoke refresh token ─────────────────────────────────────────────────────
export async function revokeRefreshToken(db, token) {
  const hash = await hashToken(token);
  await db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?`).bind(hash).run();
}

// ─── Revoke all refresh tokens for a user (logout all sessions) ──────────────
export async function revokeAllUserTokens(db, userId) {
  await db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`).bind(userId).run();
}

// ─── Extract token from request (Authorization: Bearer <token>) ──────────────
export function extractBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

export { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL };
