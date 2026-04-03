/**
 * CYBERDUDEBIVASH AI Security Hub — API Key Auth Middleware
 * Tier system: FREE (5 req/day) | PRO (500/day) | ENTERPRISE (unlimited)
 * Keys stored in Cloudflare KV: apikey:{key} → JSON config
 * IP fallback for keyless FREE tier access
 */

// ─── Tier Definitions ────────────────────────────────────────────────────────
export const TIERS = {
  FREE:       { daily_limit: 5,    burst_per_min: 2,  priority: 0, label: 'Free'       },
  PRO:        { daily_limit: 500,  burst_per_min: 20, priority: 1, label: 'Pro'        },
  ENTERPRISE: { daily_limit: -1,   burst_per_min: 60, priority: 2, label: 'Enterprise' },
};

export const UPGRADE_URL   = 'https://cyberdudebivash.in/#pricing';
export const CONTACT_EMAIL = 'cyberdudebivash@gmail.com';

// ─── Validate API Key from KV ─────────────────────────────────────────────────
async function resolveApiKey(key, env) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(`apikey:${key}`);
    if (!raw) return null;
    const cfg = JSON.parse(raw);
    if (!cfg.active) return null;
    return cfg; // { tier, owner_email, created_at, active, label }
  } catch { return null; }
}

// ─── Derive identity: key → ctx or IP → ctx ──────────────────────────────────
export async function resolveAuth(request, env) {
  const apiKey = request.headers.get('x-api-key') ||
                 request.headers.get('X-Api-Key')  ||
                 request.headers.get('Authorization')?.replace('Bearer ', '');
  const ip     = request.headers.get('CF-Connecting-IP') ||
                 request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';

  if (apiKey) {
    const cfg = await resolveApiKey(apiKey, env);
    if (cfg) {
      return {
        authenticated: true,
        method: 'api_key',
        identity: `key:${apiKey.slice(0,8)}...`,
        key: apiKey,
        tier: cfg.tier || 'FREE',
        limits: TIERS[cfg.tier] || TIERS.FREE,
        owner_email: cfg.owner_email || null,
        label: cfg.label || TIERS[cfg.tier]?.label || 'Free',
        ip,
      };
    }
    // Key provided but invalid
    return {
      authenticated: false,
      method: 'api_key',
      identity: null,
      tier: null,
      error: 'invalid_key',
      ip,
    };
  }

  // No key → FREE tier via IP
  return {
    authenticated: true,
    method: 'ip_fallback',
    identity: `ip:${ip}`,
    key: null,
    tier: 'FREE',
    limits: TIERS.FREE,
    owner_email: null,
    label: 'Free (IP)',
    ip,
  };
}

// ─── Auth Guard Middleware ────────────────────────────────────────────────────
export function authError(type = 'missing') {
  const messages = {
    missing:  { error: 'API key required', hint: 'Add header: x-api-key: YOUR_KEY' },
    invalid:  { error: 'Invalid API key', hint: 'Check your key or generate a new one' },
    inactive: { error: 'API key inactive', hint: 'Contact support to reactivate' },
    banned:   { error: 'Access denied', hint: 'This key has been suspended for abuse' },
  };
  return Response.json({
    ...(messages[type] || messages.missing),
    plan: 'FREE',
    upgrade_url: UPGRADE_URL,
    docs: 'https://cyberdudebivash.in/docs',
    contact: CONTACT_EMAIL,
  }, { status: 401 });
}
