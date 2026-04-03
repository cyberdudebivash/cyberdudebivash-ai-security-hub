/**
 * CYBERDUDEBIVASH AI Security Hub — Security Headers & Hardening Middleware
 * Applies OWASP-recommended headers to ALL responses
 * CSP, HSTS, X-Frame-Options, input sanitization guards
 */

// ─── Security Headers ─────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'Strict-Transport-Security':  'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options':             'DENY',
  'X-Content-Type-Options':      'nosniff',
  'X-XSS-Protection':            '1; mode=block',
  'Referrer-Policy':             'strict-origin-when-cross-origin',
  'Permissions-Policy':          'geolocation=(), microphone=(), camera=(), payment=()',
  'X-DNS-Prefetch-Control':      'off',
  'X-Download-Options':          'noopen',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "connect-src 'self' https://*.workers.dev https://cyberdudebivash.in https://*.cyberdudebivash.in",
    "font-src 'self' https://fonts.gstatic.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://rzp.io",
  ].join('; '),
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  'Pragma': 'no-cache',
};

const POWERED_BY_HEADERS = {
  'X-Powered-By':    'CYBERDUDEBIVASH AI Security Hub v3.0',
  'X-API-Version':   '3.0.0',
  'X-Security-Hub':  'cyberdudebivash.in',
};

// ─── Apply Security Headers ───────────────────────────────────────────────────
export function withSecurityHeaders(response) {
  const h = new Headers(response.headers);
  Object.entries(SECURITY_HEADERS).forEach(([k, v]) => h.set(k, v));
  Object.entries(POWERED_BY_HEADERS).forEach(([k, v]) => h.set(k, v));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
}

// ─── Cache Headers for static-like responses ─────────────────────────────────
export function withCacheHeaders(response, maxAge = 300) {
  const h = new Headers(response.headers);
  h.set('Cache-Control', `public, max-age=${maxAge}, s-maxage=${maxAge}`);
  h.set('Vary', 'Accept-Encoding, x-api-key');
  return new Response(response.body, { status: response.status, headers: h });
}

// ─── Request Body Size Guard ─────────────────────────────────────────────────
export function checkBodySize(request, maxBytes = 8192) {
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > maxBytes) {
    return Response.json({
      error: 'Payload too large',
      max_size_bytes: maxBytes,
      message: `Request body must be under ${Math.round(maxBytes/1024)}KB`,
    }, { status: 413 });
  }
  return null;
}

// ─── Suspicious Pattern Detection (basic WAF) ────────────────────────────────
const BLOCKED_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /on\w+\s*=/i,        // onerror=, onclick=
  /union.*select/i,
  /exec\s*\(/i,
  /\.\.\//,            // path traversal
  /etc\/passwd/i,
];

export function inspectForAttacks(str) {
  if (!str || typeof str !== 'string') return false;
  return BLOCKED_PATTERNS.some(p => p.test(str));
}

export function sanitizeString(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/[<>]/g, '')                // strip angle brackets
    .replace(/javascript:/gi, '')        // strip JS URIs
    .replace(/on\w+\s*=/gi, '')          // strip event handlers
    .trim()
    .slice(0, 500);                      // hard truncate
}

// ─── Log suspicious requests ─────────────────────────────────────────────────
export async function logSuspicious(env, request, reason) {
  if (!env?.SECURITY_HUB_KV) return;
  const ip  = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `suspicious:${ip}:${new Date().toISOString().slice(0,10)}`;
  try {
    const cur = parseInt(await env.SECURITY_HUB_KV.get(key) || '0', 10);
    await env.SECURITY_HUB_KV.put(key, String(cur + 1), { expirationTtl: 86400 });
    if (cur + 1 >= 10) {
      await env.SECURITY_HUB_KV.put(`abuse:ip:${ip}`, reason, { expirationTtl: 86400 });
    }
  } catch {}
}
