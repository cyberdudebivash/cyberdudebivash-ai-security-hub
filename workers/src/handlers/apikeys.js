/**
 * CYBERDUDEBIVASH AI Security Hub — API Key Handler v5.0
 * GET    /api/keys           — list user's API keys
 * POST   /api/keys           — generate a new API key
 * DELETE /api/keys/:id       — revoke a key
 * GET    /api/keys/:id/usage — usage stats for a key
 */

import { createApiKey, listUserApiKeys, revokeApiKey, getKeyUsageSummary, TIER_LIMITS } from '../auth/apiKeys.js';
import { parseBody } from '../middleware/validation.js';

// Per-tier API key allowance — must match the pricing page's advertised
// "API Keys" row exactly (Free 1 / Starter 2 / Pro 5 / Enterprise 20 / MSSP
// Unlimited). MSSP was previously missing here and fell through to the
// generic 2-key default — the platform's top-paying tier (₹9,999/mo,
// advertised "Unlimited" API keys) was silently capped at 2.
const MAX_KEYS_BY_TIER = { FREE: 1, STARTER: 2, PRO: 5, ENTERPRISE: 20, MSSP: Infinity };
function maxKeysForTier(tier) { return MAX_KEYS_BY_TIER[tier] ?? MAX_KEYS_BY_TIER.FREE; }

export async function handleListKeys(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  // listUserApiKeys() intentionally returns every key regardless of active
  // status — handleRotateKey/handleKeyUsage need that to make their own
  // active/ownership decisions. But this is the endpoint the dashboard's "My
  // API Keys" table and stat count render directly, with no revoked-state UI
  // at all (renderKeys() always shows a live "Revoke" button); handleCreateKey
  // already filters to active-only for its own limit check. Not filtering
  // here left a revoked key permanently visible in the table — confirmed
  // live: after a real DELETE /api/keys/:id (200, key correctly set
  // active=0), the very next GET /api/keys still listed it and reported
  // count:1, count of 1 (limit for FREE), even though the customer had zero
  // usable keys.
  const allKeys = await listUserApiKeys(env.DB, authCtx.user_id);
  const keys = allKeys.filter(k => k.active);
  const maxKeys = maxKeysForTier(authCtx.tier);
  return Response.json({
    keys,
    count:       keys.length,
    max_keys:    Number.isFinite(maxKeys) ? maxKeys : -1, // -1 = unlimited (MSSP)
    tier_limits: TIER_LIMITS[authCtx.tier] || TIER_LIMITS.FREE,
  });
}

export async function handleCreateKey(request, env, authCtx) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });

  const body  = await parseBody(request);
  // Accept `label` or `name` (the developer-portal UI sends `name`).
  const label = (body?.label || body?.name || 'New Key').toString().slice(0, 60);

  // Enforce per-tier key limit
  const maxKeys  = maxKeysForTier(authCtx.tier);
  const existing = await listUserApiKeys(env.DB, authCtx.user_id);
  const active   = existing.filter(k => k.active);

  if (active.length >= maxKeys) {
    return Response.json({
      error: `Key limit reached (${maxKeys} keys for ${authCtx.tier} tier)`,
      hint:  'Revoke an existing key first, or upgrade your plan',
      upgrade_url: '/#pricing',
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

/**
 * POST /api/keys/:id/rotate — atomic key rotation.
 * Revokes the old key and issues a replacement with the same label on the
 * user's CURRENT tier (so a rotated key picks up plan upgrades). Because the
 * old key is revoked first, rotation never trips the per-tier key limit.
 */
export async function handleRotateKey(request, env, authCtx, keyId) {
  if (!authCtx.user_id) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!env?.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!keyId) return Response.json({ error: 'Key ID required' }, { status: 400 });

  // Verify ownership and active status before revoking anything
  const existing = (await listUserApiKeys(env.DB, authCtx.user_id)).find(k => k.id === keyId);
  if (!existing) return Response.json({ error: 'Key not found' }, { status: 404 });
  if (!existing.active) {
    return Response.json({ error: 'Key is already revoked — create a new key instead', hint: 'POST /api/keys' }, { status: 409 });
  }

  const revoked = await revokeApiKey(env.DB, keyId, authCtx.user_id);
  if (!revoked) return Response.json({ error: 'Key not found or already revoked' }, { status: 404 });

  try {
    const result = await createApiKey(env.DB, authCtx.user_id, authCtx.tier, existing.label || 'Rotated Key');
    return Response.json({
      success:     true,
      message:     'Key rotated. The old key is revoked immediately. Save the new key now — this is the only time you will see it.',
      old_key_id:  keyId,
      old_prefix:  existing.key_prefix,
      key:         result.raw_key,   // shown ONCE — never retrievable again
      key_id:      result.id,
      prefix:      result.prefix,
      label:       result.label,
      tier:        result.tier,
      limits:      TIER_LIMITS[result.tier] || TIER_LIMITS.FREE,
      warning:     'Update every integration using the old key — it stopped working the moment this rotation completed.',
    }, { status: 201 });
  } catch (e) {
    // Old key is already revoked; surface that honestly rather than pretending rotation succeeded
    return Response.json({
      error:      'Rotation partially failed: the old key was revoked but the replacement could not be created. Create a new key with POST /api/keys.',
      old_key_id: keyId,
      detail:     e?.message,
    }, { status: 500 });
  }
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

  // Ownership check (BOLA/IDOR — CWE-639): getKeyUsageSummary queries
  // api_key_usage by key_id ALONE (userId is ignored), so without this guard any
  // authenticated caller could read another tenant's request volume + module
  // breakdown by enumerating key ids. Mirror the rotate/revoke ownership pattern:
  // 404 for a key the caller does not own (no existence oracle, no data leak).
  const owns = (await listUserApiKeys(env.DB, authCtx.user_id)).some(k => k.id === keyId);
  if (!owns) return Response.json({ error: 'Key not found' }, { status: 404 });

  const usage = await getKeyUsageSummary(env.DB, keyId, authCtx.user_id);
  return Response.json({ key_id: keyId, ...usage });
}
