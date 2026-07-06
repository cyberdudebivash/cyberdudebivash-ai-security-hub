/**
 * CYBERDUDEBIVASH AI Security Hub — Scan Transaction Token Engine v30.0
 * P1 REMEDIATION: Cryptographically signed scan tokens prevent abuse queue flooding.
 *
 * Every public domain scan request MUST carry a valid scan token obtained via:
 *   POST /api/scan/token  →  issueScanToken()   (1 token per IP per request)
 *   (Token is HMAC-SHA-256 signed; valid for 5 minutes; single-use via KV burn)
 *
 * Domain handler validates token with:
 *   const { valid, reason } = await verifyScanToken(request, env);
 *   if (!valid) return scanTokenError(reason);
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const TOKEN_TTL_SEC    = 300;           // 5 minutes validity window
const TOKEN_KV_PREFIX  = 'scan:tok:';
const HMAC_ALGO        = 'SHA-256';
const TOKEN_VERSION    = 'cdb30';

// ─── HMAC helpers (Web Crypto — available in Cloudflare Workers) ──────────────

async function importKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: HMAC_ALGO }, false, ['sign', 'verify']
  );
}

async function signPayload(payload, secret) {
  const key = await importKey(secret);
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifySignature(payload, signature, secret) {
  try {
    const key      = await importKey(secret);
    const enc      = new TextEncoder();
    const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    return await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payload));
  } catch { return false; }
}

// ─── Token Structure: <version>.<ip_hash>.<issued_at>.<nonce>.<hmac> ─────────

function getSecret(env) {
  return env.JWT_SECRET || env.SCAN_TOKEN_SECRET || 'cdb-fallback-dev-secret-change-in-prod';
}

function hashIP(ip) {
  // One-way pseudo-hash (non-reversible) for token binding without storing raw IP
  let h = 0x811c9dc5;
  for (let i = 0; i < ip.length; i++) {
    h ^= ip.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

// ─── Issue Scan Token ─────────────────────────────────────────────────────────
/**
 * POST /api/scan/token
 * Issues a single-use HMAC scan token bound to the caller's IP.
 * Rate: 10 tokens per IP per minute (burst-limited in KV).
 */
export async function issueScanToken(request, env) {
  const cors = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type':                 'application/json',
  };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST')    return new Response(null, { status: 405, headers: cors });

  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  // ── Burst gate: max 10 token issuances per IP per minute ──────────────────
  const kv = env.SECURITY_HUB_KV;
  if (kv) {
    const burstKey = `scan:tok:burst:${hashIP(ip)}:${new Date().toISOString().slice(0,16)}`;
    try {
      const cnt = parseInt(await kv.get(burstKey) || '0', 10);
      if (cnt >= 10) {
        return new Response(JSON.stringify({
          error:        'token_rate_limited',
          message:      'Too many scan token requests. Try again in 60 seconds.',
          retry_after:  60,
        }), { status: 429, headers: { ...cors, 'Retry-After': '60' } });
      }
      kv.put(burstKey, String(cnt + 1), { expirationTtl: 60 }).catch(() => {});
    } catch {}
  }

  const nonce      = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const issuedAt   = Math.floor(Date.now() / 1000);
  const ipHash     = hashIP(ip);
  const payload    = `${TOKEN_VERSION}.${ipHash}.${issuedAt}.${nonce}`;
  const hmac       = await signPayload(payload, getSecret(env));
  const token      = `${payload}.${hmac}`;

  // Store in KV as single-use (burn on verify)
  if (kv) {
    kv.put(`${TOKEN_KV_PREFIX}${nonce}`, JSON.stringify({ ipHash, issuedAt, used: false }),
      { expirationTtl: TOKEN_TTL_SEC }).catch(() => {});
  }

  return new Response(JSON.stringify({
    token,
    expires_in: TOKEN_TTL_SEC,
    issued_at:  issuedAt,
  }), { status: 200, headers: cors });
}

// ─── Verify Scan Token (called from domain scan handler) ─────────────────────
/**
 * @param {Request} request  — inbound scan request
 * @param {object}  env      — Cloudflare env
 * @returns {Promise<{ valid: boolean, reason?: string, nonce?: string }>}
 */
export async function verifyScanToken(request, env) {
  const token = request.headers.get('X-Scan-Token') ||
                new URL(request.url).searchParams.get('scan_token');

  if (!token) return { valid: false, reason: 'missing_scan_token' };

  const parts = token.split('.');
  if (parts.length !== 5) return { valid: false, reason: 'malformed_token' };

  const [ver, ipHash, issuedAtStr, nonce, hmac] = parts;

  if (ver !== TOKEN_VERSION) return { valid: false, reason: 'invalid_token_version' };

  // ── Expiry check ──────────────────────────────────────────────────────────
  const issuedAt = parseInt(issuedAtStr, 10);
  const now      = Math.floor(Date.now() / 1000);
  if (isNaN(issuedAt) || now - issuedAt > TOKEN_TTL_SEC) {
    return { valid: false, reason: 'token_expired' };
  }

  // ── HMAC integrity check ─────────────────────────────────────────────────
  const payload  = `${ver}.${ipHash}.${issuedAtStr}.${nonce}`;
  const sigOk    = await verifySignature(payload, hmac, getSecret(env));
  if (!sigOk) return { valid: false, reason: 'invalid_signature' };

  // ── IP binding check ──────────────────────────────────────────────────────
  // Fallback must match issueScanToken()'s exactly ('unknown', not '') — a
  // divergent fallback here hashes to a different value than the one baked
  // into the token, so every caller lacking CF-Connecting-IP would get a
  // false ip_mismatch. Only caught now because this function was never
  // actually called from anywhere before this gate went live.
  const callerIP     = request.headers.get('CF-Connecting-IP') ||
                       request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
  const callerIPHash = hashIP(callerIP);
  if (callerIPHash !== ipHash) {
    return { valid: false, reason: 'ip_mismatch' };
  }

  // ── Single-use burn (KV) ──────────────────────────────────────────────────
  const kv = env.SECURITY_HUB_KV;
  if (kv) {
    const kvKey = `${TOKEN_KV_PREFIX}${nonce}`;
    try {
      const raw = await kv.get(kvKey);
      if (!raw) return { valid: false, reason: 'token_already_used_or_expired' };
      const rec = JSON.parse(raw);
      if (rec.used)    return { valid: false, reason: 'token_already_used' };

      // Burn immediately
      await kv.put(kvKey, JSON.stringify({ ...rec, used: true }),
        { expirationTtl: 30 });  // keep tombstone for 30s to prevent replay race
    } catch {
      // KV unavailable — fall through (fail-open for availability, log for monitoring)
      console.warn('[ScanToken] KV unavailable during burn — allowing request');
    }
  }

  return { valid: true, nonce };
}

// ─── Standard 403 response for failed token verification ─────────────────────
export function scanTokenError(reason) {
  const messages = {
    missing_scan_token:             'Scan request must include a valid X-Scan-Token header. Obtain one via POST /api/scan/token.',
    malformed_token:                'Token format is invalid.',
    invalid_token_version:          'Token was issued by an incompatible version of the platform.',
    token_expired:                  'Token has expired. Tokens are valid for 5 minutes.',
    invalid_signature:              'Token signature verification failed.',
    ip_mismatch:                    'Token was issued to a different IP address.',
    token_already_used:             'This token has already been used. Each scan token is single-use.',
    token_already_used_or_expired:  'Token has already been consumed or expired.',
  };
  return Response.json({
    error:   'scan_token_invalid',
    reason,
    message: messages[reason] || 'Scan token validation failed.',
    hint:    'POST /api/scan/token to obtain a fresh token, then include it as: X-Scan-Token: <token>',
  }, { status: 403 });
}
