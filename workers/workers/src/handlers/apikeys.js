/**
 * CYBERDUDEBIVASH AI Security Hub — API Key Handler v5.0
 * GET    /api/keys           — list user's API keys
 * POST   /api/keys           — generate a new API key
 * DELETE /api/keys/:id       — revoke a key
 * GET    /api/keys/:id/usage — usage stats for a key
 */

import { createApiKey, listUserApiKeys, revokeApiKey, getKeyUsageSummary, TIER_LIMITS } from '../auth/apiKeys.js';
import { parseBody } from '../middleware/validation.js';

export async function handleListKeys(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const keys = await listUserApiKeys(env.DB, authCtx.user_id);
  return Response.json({
    keys,
    count:       keys.length,
    max_keys:    authCtx.tier === 'ENTERPRISE' ? 20 : authCtx.tier === 'PRO' ? 5 : 2,
    tier_limits: TIER_LIMITS[authCtx.tier] || TIER_LIMITS.FREE,
  });
}

export async function handleCreateKey(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body  = await parseBody(request);
  const label = (body?.label || 'New Key').toString().slice(0, 60);

  // Enforce per-tier key limit
  const maxKeys  = authCtx.tier === 'ENTERPRISE' ? 20 : authCtx.tier === 'PRO' ? 5 : 2;
  const existing = await listUserApiKeys(env.DB, authCtx.user_id);
  const active   = existing.filter(k => k.active);

  if (active.length >= maxKeys) {
    return Response.json({
      error: `Key limit reached (${maxKeys} keys for ${authCtx.tier} tier)`,
      hint:  'Revoke an existing key first, or upgrade your plan',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 409 });
  }

  const result = await createApiKey(env.DB, authCtx.user_id, authCtx.tier, label);

  return Response.json({
    success:   true,
    message:   'API key generated. Save it now — this is the only time you will see the full key.',
    key:       result.raw_key,     // shown ONCE — never retrievable again
    prefix:    result.prefix,
    label:     result.label,
    tier:      result.tier,
    limits:    TIER_LIMITS[result.tier] || TIER_LIMITS.FREE,
    warning:   'Store this key securely. It cannot be retrieved after this response.',
  }, { status: 201 });
}

export async function handleRevokeKey(request, env, authCtx, keyId) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!keyId) return Response.json({ error: 'Key ID required' }, { status: 400 });

  const revoked = await revokeApiKey(env.DB, keyId, authCtx.user_id);
  if (!revoked) {
    return Response.json({ error: 'Key not found or already revoked' }, { status: 404 });
  }

  return Response.json({ success: true, message: 'Key revoked', key_id: keyId });
}

export async function handleKeyUsage(request, env, authCtx, keyId) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!keyId) return Response.json({ error: 'Key ID required' }, { status: 400 });

  const usage = await getKeyUsageSummary(env.DB, keyId, authCtx.user_id);
  return Response.json({ key_id: keyId, ...usage });
}
