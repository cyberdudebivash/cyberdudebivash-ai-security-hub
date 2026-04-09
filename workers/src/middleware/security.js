/**
 * CYBERDUDEBIVASH AI Security Hub — Security Headers & Hardening Middleware v9.0
 * Zero Trust edge security: OWASP headers, WAF, SSRF guard, input validation,
 * bot detection, per-tenant isolation, and abuse auto-ban.
 */

// ─── Security Headers ─────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'Strict-Transport-Security':  'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options':             'DENY',
  'X-Content-Type-Options':      'nosniff',
  'X-XSS-Protection':            '1; mode=block',
  'Referrer-Policy':             'strict-origin-when-cross-origin',
  'Permissions-Policy':          'geolocation=(), microphone=(), camera=(), payment=(self "https://rzp.io"), usb=(), display-capture=()',
  'X-DNS-Prefetch-Control':      'off',
  'X-Download-Options':          'noopen',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'Cross-Origin-Opener-Policy':  'same-origin',
  'Cross-Origin-Resource-Policy':'same-origin',
  'Cross-Origin-Embedder-Policy':'require-corp',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://*.workers.dev https://cyberdudebivash.in https://*.cyberdudebivash.in https://api.epss.cyentia.com https://services.nvd.nist.gov",
    "font-src 'self' https://fonts.gstatic.com",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://rzp.io",
    "object-src 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "upgrade-insecure-requests",
  ].join('; '),
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  'Pragma':        'no-cache',
};

const POWERED_BY_HEADERS = {
  'X-Powered-By':    'CYBERDUDEBIVASH AI Security Hub v11.0',
  'X-API-Version':   '11.0.0',
  'X-Security-Hub':  'cyberdudebivash.in',
  'X-Zero-Trust':    'enforced',
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
export function checkBodySize(request, maxBytes = 16384) {
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > maxBytes) {
    return Response.json({
      error: 'Payload too large',
      max_size_bytes: maxBytes,
      message: `Request body must be under ${Math.round(maxBytes / 1024)}KB`,
    }, { status: 413 });
  }
  return null;
}

// ─── Enhanced WAF Pattern Set ─────────────────────────────────────────────────
// Covers: XSS, SQLi, NoSQLi, SSRF, XXE, Path Traversal, Command Injection,
//         Template Injection, LDAP Injection, Log4Shell, prototype pollution.
const BLOCKED_PATTERNS = [
  // XSS vectors
  /<script[\s>]/i,
  /<iframe[\s>]/i,
  /<object[\s>]/i,
  /<embed[\s>]/i,
  /<svg[\s>]/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
  /on\w{2,20}\s*=/i,                     // onerror=, onload=, onclick=

  // SQL injection
  /\bunion\b.{0,20}\bselect\b/i,
  /\bselect\b.{0,30}\bfrom\b/i,
  /\bdrop\b.{0,20}\b(table|database|schema)\b/i,
  /\binsert\b.{0,20}\binto\b/i,
  /\bupdate\b.{0,20}\bset\b/i,
  /\bdelete\b.{0,20}\bfrom\b/i,
  /\bexec\s*\(/i,
  /\bexecute\s*\(/i,
  /\bxp_cmdshell\b/i,
  /--\s*$/m,                             // SQL comment

  // NoSQL injection
  /\$where\s*:/i,
  /\$ne\s*:/i,
  /\$gt\s*:/i,
  /\$regex\s*:/i,
  /\$expr\s*:/i,

  // Path traversal / LFI
  /\.\.[\/\\]/,
  /%2e%2e[%2f%5c]/i,
  /etc\/passwd/i,
  /etc\/shadow/i,
  /proc\/self/i,
  /windows\/system32/i,

  // Command injection
  /[;&|`].*\b(cat|ls|id|whoami|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\b/i,
  /\$\(.*\)/,                            // $(command)
  /`[^`]+`/,                             // backtick execution

  // SSRF
  /\b(file|gopher|dict|ftp|ldap|ldaps):\/\//i,
  /\b127\.0\.0\.1\b/,
  /\b0\.0\.0\.0\b/,
  /\blocalhost\b/i,
  /\b169\.254\.169\.254\b/,             // AWS metadata endpoint
  /\b100\.100\.100\.200\b/,             // Alibaba Cloud metadata
  /\bmetadata\.google\.internal\b/i,    // GCP metadata

  // XXE
  /<!ENTITY/i,
  /<!DOCTYPE/i,
  /SYSTEM\s+"file:/i,

  // Template injection
  /\{\{.*\}\}/,                          // Jinja2 / Handlebars
  /\$\{.*\}/,                            // JS template literal in input
  /<%[=\-]?.*%>/,                        // ERB / EJS

  // LDAP injection
  /[()\\*\x00]/,                         // LDAP special chars (conservative)

  // Log4Shell / JNDI
  /\$\{jndi:/i,
  /\$\{lower:/i,
  /\$\{upper:/i,

  // Prototype pollution
  /__proto__/i,
  /constructor\s*\[/i,
  /prototype\s*\[/i,
];

export function inspectForAttacks(str) {
  if (!str || typeof str !== 'string') return false;
  return BLOCKED_PATTERNS.some(p => p.test(str));
}

// ─── Deep body inspection ─────────────────────────────────────────────────────
// Recursively checks all string values in a parsed JSON body for attack patterns.
export function inspectBodyForAttacks(obj, depth = 0) {
  if (depth > 8) return false;  // prevent stack exhaustion on deep nesting
  if (typeof obj === 'string')  return inspectForAttacks(obj);
  if (Array.isArray(obj))       return obj.some(v => inspectBodyForAttacks(v, depth + 1));
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).some(([k, v]) =>
      inspectForAttacks(k) || inspectBodyForAttacks(v, depth + 1)
    );
  }
  return false;
}

// ─── Input Sanitization ────────────────────────────────────────────────────────
export function sanitizeString(str, maxLen = 500) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/[<>]/g, '')
    .replace(/javascript\s*:/gi, '')
    .replace(/on\w{2,20}\s*=/gi, '')
    .replace(/__proto__/gi, '')
    .replace(/\$\{/g, '')
    .replace(/\{\{/g, '')
    .trim()
    .slice(0, maxLen);
}

// ─── Domain / Target Validation ───────────────────────────────────────────────
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fc|fd)/i;

export function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return { valid: false, reason: 'empty' };
  const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (d.length > 253) return { valid: false, reason: 'too_long' };
  if (PRIVATE_IP_RE.test(d)) return { valid: false, reason: 'private_ip_ssrf' };
  if (!DOMAIN_RE.test(d))    return { valid: false, reason: 'invalid_format' };
  return { valid: true, domain: d };
}

// ─── Request Fingerprint (bot/automation detection) ──────────────────────────
export function getBotScore(request) {
  const ua = request.headers.get('User-Agent') || '';
  let score = 0;
  if (!ua)                          score += 40;
  if (/curl|wget|python|java|go-http|libwww|okhttp|axios|node-fetch/i.test(ua)) score += 20;
  if (!/Mozilla|Chrome|Safari|Firefox|Edge/i.test(ua)) score += 15;
  if (!request.headers.get('Accept'))         score += 10;
  if (!request.headers.get('Accept-Language')) score += 5;
  return score;  // 0–100: 0=human, 100=bot
}

// ─── IP Abuse Check ───────────────────────────────────────────────────────────
export async function isIPAbusive(env, ip) {
  if (!env?.SECURITY_HUB_KV || !ip) return false;
  try {
    const flag = await env.SECURITY_HUB_KV.get(`abuse:ip:${ip}`);
    return !!flag;
  } catch { return false; }
}

// ─── Log suspicious requests ─────────────────────────────────────────────────
export async function logSuspicious(env, request, reason) {
  if (!env?.SECURITY_HUB_KV) return;
  const ip  = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `suspicious:${ip}:${new Date().toISOString().slice(0, 10)}`;
  try {
    const cur  = parseInt(await env.SECURITY_HUB_KV.get(key) || '0', 10);
    const next = cur + 1;
    await env.SECURITY_HUB_KV.put(key, String(next), { expirationTtl: 86400 });
    // Auto-ban after 20 suspicious hits in a day (raised from 5 to reduce false-positive bans
    // on legitimate API users/developers running test scripts).
    // Ban TTL: 1 hour (reduced from 3 days — shorter TTL prevents permanent lockouts).
    if (next >= 20) {
      await env.SECURITY_HUB_KV.put(`abuse:ip:${ip}`, reason, { expirationTtl: 3600 });
    }
  } catch {}
}

// ─── Tenant Isolation Guard ───────────────────────────────────────────────────
// Ensures a user cannot access resources belonging to a different org/tenant.
export function assertTenantAccess(authCtx, resourceOwnerId, resourceOrgId) {
  if (!authCtx || authCtx.tier === 'IP') return false; // unauthenticated
  // ENTERPRISE admin bypass
  if (authCtx.role === 'ADMIN' && authCtx.tier === 'ENTERPRISE') return true;
  // Direct owner match
  if (resourceOwnerId && authCtx.userId === resourceOwnerId) return true;
  // Org member match
  if (resourceOrgId && authCtx.orgId === resourceOrgId) return true;
  return false;
}

// ─── JSON Schema Validator (lightweight) ─────────────────────────────────────
// schema: { fieldName: { type, required, minLen, maxLen, pattern, enum } }
export function validateSchema(body, schema) {
  const errors = [];
  for (const [field, rules] of Object.entries(schema)) {
    const value = body?.[field];
    if (rules.required && (value === undefined || value === null || value === '')) {
      errors.push({ field, message: `${field} is required` });
      continue;
    }
    if (value === undefined || value === null) continue;
    if (rules.type === 'string' && typeof value !== 'string') {
      errors.push({ field, message: `${field} must be a string` });
    } else if (rules.type === 'string') {
      if (rules.minLen && value.length < rules.minLen)
        errors.push({ field, message: `${field} must be at least ${rules.minLen} characters` });
      if (rules.maxLen && value.length > rules.maxLen)
        errors.push({ field, message: `${field} must be at most ${rules.maxLen} characters` });
      if (rules.pattern && !rules.pattern.test(value))
        errors.push({ field, message: `${field} format is invalid` });
      if (rules.enum && !rules.enum.includes(value))
        errors.push({ field, message: `${field} must be one of: ${rules.enum.join(', ')}` });
    }
    if (rules.type === 'number' && typeof value !== 'number') {
      errors.push({ field, message: `${field} must be a number` });
    }
    if (rules.type === 'boolean' && typeof value !== 'boolean') {
      errors.push({ field, message: `${field} must be a boolean` });
    }
  }
  return errors;
}

// Common reusable schemas
export const SCHEMAS = {
  signup: {
    email:    { type: 'string', required: true, maxLen: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
    password: { type: 'string', required: true, minLen: 8, maxLen: 128 },
    name:     { type: 'string', required: false, maxLen: 100 },
  },
  domainScan: {
    domain: { type: 'string', required: true, maxLen: 253 },
  },
  aiScan: {
    model_name: { type: 'string', required: true, maxLen: 200 },
    use_case:   { type: 'string', required: false, maxLen: 100 },
  },
  monitorCreate: {
    name:     { type: 'string', required: true, maxLen: 100 },
    module:   { type: 'string', required: true, enum: ['domain','ai','redteam','identity','compliance'] },
    schedule: { type: 'string', required: false, enum: ['hourly','daily','weekly','monthly'] },
  },
};
