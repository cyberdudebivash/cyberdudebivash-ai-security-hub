// ============================================================
// workers/lib/utils.ts — Production utilities for all Workers
// ============================================================

import type { ApiResponse, Env } from '../../types/index.js';

// ── UUID v4 (Web Crypto — CF Workers compatible) ──────────────
export function uuid(): string {
  return crypto.randomUUID();
}

// ── Current unix epoch seconds ────────────────────────────────
export function nowEpoch(): number {
  return Math.floor(Date.now() / 1000);
}

// ── JSON response builder ─────────────────────────────────────
export function jsonResponse<T>(
  data: ApiResponse<T>,
  status = 200,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      ...headers,
    },
  });
}

export function ok<T>(data: T, meta?: ApiResponse<T>['meta']): ApiResponse<T> {
  return { ok: true, data, meta };
}

export function err(code: string, message: string): ApiResponse<never> {
  return { ok: false, error: { code, message } };
}

// ── HMAC-SHA256 for Razorpay webhook validation ───────────────
export async function hmacSha256(
  secret: string,
  payload: string
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── SHA-256 of arbitrary string (for payload deduplication) ──
export async function sha256(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Constant-time string comparison (timing-attack safe) ──────
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  const aKey = await crypto.subtle.importKey(
    'raw', aBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const bKey = await crypto.subtle.importKey(
    'raw', bBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const msg = encoder.encode('sentinel-apex-compare');
  const aSig = new Uint8Array(await crypto.subtle.sign('HMAC', aKey, msg));
  const bSig = new Uint8Array(await crypto.subtle.sign('HMAC', bKey, msg));
  let diff = 0;
  for (let i = 0; i < aSig.length; i++) diff |= aSig[i] ^ bSig[i];
  return diff === 0;
}

// ── CORS headers for API responses ───────────────────────────
export function corsHeaders(origin?: string): Record<string, string> {
  const allowed = [
    'https://cyberdudebivash.in',
    'https://cyberdudebivash.com',
    'https://intel.cyberdudebivash.com',
    'https://tools.cyberdudebivash.com',
  ];
  const o = origin && allowed.includes(origin) ? origin : allowed[0];
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// ── Rate limiting via KV ──────────────────────────────────────
// Key: `rate:<identifier>:<window_start_minute>`
// Value: count as string
export async function checkRateLimit(
  kv: KVNamespace,
  identifier: string,
  limitPerMinute: number
): Promise<{ allowed: boolean; remaining: number; reset: number }> {
  const now = Date.now();
  const windowStart = Math.floor(now / 60_000);
  const key = `rate:${identifier}:${windowStart}`;
  const reset = (windowStart + 1) * 60_000;

  const raw = await kv.get(key);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= limitPerMinute) {
    return { allowed: false, remaining: 0, reset };
  }

  await kv.put(key, String(count + 1), { expirationTtl: 120 });
  return { allowed: true, remaining: limitPerMinute - count - 1, reset };
}

// ── JWT (HS256) — lightweight, no library dependency ─────────
export async function signJwt(
  payload: Record<string, unknown>,
  secret: string,
  expiresInSeconds = 3600
): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const body = btoa(JSON.stringify({ ...payload, iat: nowEpoch(), exp: nowEpoch() + expiresInSeconds }))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const sig = await hmacSha256(secret, `${header}.${body}`);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(Buffer.from(sig, 'hex'))))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${header}.${body}.${sigB64}`;
}

export async function verifyJwt(
  token: string,
  secret: string
): Promise<Record<string, unknown> | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expectedSig = await hmacSha256(secret, `${header}.${body}`);
    const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(Buffer.from(expectedSig, 'hex'))))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (!(await safeEqual(sig, expectedB64))) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < nowEpoch()) return null;
    return payload;
  } catch {
    return null;
  }
}

// ── Tier pricing map (paise) ──────────────────────────────────
export const TIER_PRICE_PAISE: Record<string, number> = {
  starter:    99900,    // ₹999/mo
  pro:       149900,    // ₹1499/mo
  enterprise: 499900,   // ₹4999/mo
  mssp:       999900,   // ₹9999/mo
};

// ── Tier from Razorpay notes or amount ───────────────────────
export function tierFromNotes(
  notes: Record<string, string>,
  amount: number
): string {
  if (notes.tier && ['starter','pro','enterprise','mssp'].includes(notes.tier)) {
    return notes.tier;
  }
  // Fall back to amount matching
  for (const [tier, price] of Object.entries(TIER_PRICE_PAISE)) {
    if (amount === price) return tier;
  }
  return 'starter';
}

// ── Subscription expiry (1 month from now) ───────────────────
export function expiresAt(months = 1): number {
  const d = new Date();
  d.setMonth(d.getMonth() + months);
  return Math.floor(d.getTime() / 1000);
}

// ── Severity normalizer for NVD CVSS ─────────────────────────
export function normalizeSeverity(raw: string | undefined): string {
  if (!raw) return 'unknown';
  const r = raw.toUpperCase();
  if (r === 'CRITICAL') return 'critical';
  if (r === 'HIGH') return 'high';
  if (r === 'MEDIUM') return 'medium';
  if (r === 'LOW') return 'low';
  return 'unknown';
}
