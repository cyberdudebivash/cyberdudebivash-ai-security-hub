/**
 * SENTINEL APEX™ Automated Provisioning Engine
 * Automatically provisions tenant, entitlements, API keys, and access
 * after every purchase or subscription activation.
 *
 * Routes:
 *   POST /api/provision/purchase        - Trigger provisioning after one-time purchase
 *   POST /api/provision/subscription    - Trigger provisioning after subscription
 *   POST /api/provision/trial           - Activate trial provisioning
 *   GET  /api/provision/status/:userId  - Check provisioning status for user
 *   POST /api/provision/revoke          - Revoke entitlements (cancel/refund)
 *   GET  /api/provision/audit/:userId   - Audit log of provisioning events
 */

// ─── Entitlement Map ─────────────────────────────────────────────────────────
// Maps plan/product → features granted
const PLAN_ENTITLEMENTS = {
  'api-free': [
    { feature: 'api_access', tier: 'FREE' },
    { feature: 'threat_feed_basic', tier: 'FREE' },
    { feature: 'dashboard_basic', tier: 'FREE' },
  ],
  'api-pro': [
    { feature: 'api_access', tier: 'PRO' },
    { feature: 'threat_feed_full', tier: 'PRO' },
    { feature: 'dashboard_pro', tier: 'PRO' },
    { feature: 'stix_21_export', tier: 'PRO' },
    { feature: 'ai_predictions', tier: 'PRO' },
    { feature: 'actor_attribution', tier: 'PRO' },
    { feature: 'report_download', tier: 'PRO' },
    { feature: 'pdf_reports', tier: 'PRO' },
  ],
  'api-team': [
    { feature: 'api_access', tier: 'TEAM' },
    { feature: 'threat_feed_full', tier: 'TEAM' },
    { feature: 'dashboard_pro', tier: 'TEAM' },
    { feature: 'stix_21_export', tier: 'TEAM' },
    { feature: 'ai_predictions', tier: 'TEAM' },
    { feature: 'actor_attribution', tier: 'TEAM' },
    { feature: 'siem_webhook', tier: 'TEAM' },
    { feature: 'kill_chain_mapping', tier: 'TEAM' },
    { feature: 'report_download', tier: 'TEAM' },
    { feature: 'pdf_reports', tier: 'TEAM' },
    { feature: 'multi_seat', tier: 'TEAM' },
  ],
  'api-enterprise': [
    { feature: 'api_access', tier: 'ENTERPRISE' },
    { feature: 'threat_feed_full', tier: 'ENTERPRISE' },
    { feature: 'dashboard_pro', tier: 'ENTERPRISE' },
    { feature: 'dashboard_executive', tier: 'ENTERPRISE' },
    { feature: 'stix_21_export', tier: 'ENTERPRISE' },
    { feature: 'ai_predictions', tier: 'ENTERPRISE' },
    { feature: 'actor_attribution', tier: 'ENTERPRISE' },
    { feature: 'siem_webhook', tier: 'ENTERPRISE' },
    { feature: 'kill_chain_mapping', tier: 'ENTERPRISE' },
    { feature: 'report_download', tier: 'ENTERPRISE' },
    { feature: 'pdf_reports', tier: 'ENTERPRISE' },
    { feature: 'board_reports', tier: 'ENTERPRISE' },
    { feature: 'multi_seat', tier: 'ENTERPRISE' },
    { feature: 'dedicated_endpoint', tier: 'ENTERPRISE' },
    { feature: 'analyst_briefings', tier: 'ENTERPRISE' },
    { feature: 'custom_integrations', tier: 'ENTERPRISE' },
    { feature: 'white_label', tier: 'ENTERPRISE' },
    { feature: 'sla_guarantee', tier: 'ENTERPRISE' },
  ],
};

// Report purchase grants
const REPORT_ENTITLEMENTS = (reportId) => [
  { feature: `report_download:${reportId}`, tier: 'FREE' },
];

// Bundle entitlements
const BUNDLE_ENTITLEMENTS = [
  { feature: 'report_download:all_q2_2026', tier: 'FREE' },
  { feature: 'threat_feed_basic', tier: 'FREE' },
];

// ─── Core Provisioning Functions ─────────────────────────────────────────────

async function getOrCreateTenant(db, userId, tier, companyName = null) {
  let tenant = await db.prepare(
    `SELECT * FROM customer_tenants WHERE user_id = ? LIMIT 1`
  ).bind(userId).first().catch(() => null);

  if (!tenant) {
    const tenantId = crypto.randomUUID();
    await db.prepare(
      `INSERT INTO customer_tenants (id, user_id, company_name, tier, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'active', datetime('now'), datetime('now'))`
    ).bind(tenantId, userId, companyName, tier).run();
    tenant = { id: tenantId, user_id: userId, tier, status: 'active' };
  } else if (tenant.tier !== tier) {
    // Upgrade/downgrade tier
    await db.prepare(
      `UPDATE customer_tenants SET tier = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(tier, tenant.id).run();
    tenant.tier = tier;
  }

  return tenant;
}

async function grantEntitlements(db, userId, tenantId, entitlements, source, sourceRef, expiresAt = null) {
  const granted = [];
  for (const ent of entitlements) {
    try {
      await db.prepare(
        `INSERT OR REPLACE INTO customer_entitlements
         (id, user_id, tenant_id, feature, source, source_ref, tier_required, enabled, expires_at, granted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))`
      ).bind(
        crypto.randomUUID(), userId, tenantId,
        ent.feature, source, sourceRef, ent.tier, expiresAt
      ).run();
      granted.push(ent.feature);
    } catch (e) {
      // Duplicate — update instead
      try {
        await db.prepare(
          `UPDATE customer_entitlements SET enabled=1, expires_at=?, updated_at=datetime('now')
           WHERE user_id=? AND feature=?`
        ).bind(expiresAt, userId, ent.feature).run();
        granted.push(ent.feature + ':renewed');
      } catch {}
    }
  }
  return granted;
}

async function generateAPIKey(db, userId, tier, planId) {
  // Check if a key already exists for this user+plan
  const existing = await db.prepare(
    `SELECT api_key FROM api_keys WHERE user_id = ? AND tier = ? AND status = 'active' LIMIT 1`
  ).bind(userId, tier).first().catch(() => null);

  if (existing) return { key: existing.api_key, created: false };

  const key = `apex_${tier.toLowerCase()}_${crypto.randomUUID().replace(/-/g, '')}`;
  const rateLimit = tier === 'ENTERPRISE' ? 999999 : tier === 'TEAM' ? 100000 : tier === 'PRO' ? 10000 : 3000;

  try {
    await db.prepare(
      `INSERT INTO api_keys (id, user_id, api_key, tier, plan_id, rate_limit_daily, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'))`
    ).bind(crypto.randomUUID(), userId, key, tier, planId, rateLimit).run();
    return { key, created: true };
  } catch {
    return { key, created: false };
  }
}

async function writeProvisioningLog(db, data) {
  try {
    await db.prepare(
      `INSERT INTO provisioning_log
       (id, user_id, tenant_id, trigger_type, trigger_ref, actions_taken, entitlements_granted,
        api_keys_created, tenant_created, status, error_detail, duration_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      crypto.randomUUID(),
      data.user_id, data.tenant_id, data.trigger_type, data.trigger_ref,
      JSON.stringify(data.actions || []),
      JSON.stringify(data.entitlements || []),
      data.api_keys_created || 0,
      data.tenant_created || 0,
      data.status || 'success',
      data.error_detail || null,
      data.duration_ms || null,
    ).run();
  } catch (e) {
    console.error('[Provisioning] Log write failed:', e?.message);
  }
}

// ─── Provision After Purchase ─────────────────────────────────────────────────
async function handleProvisionPurchase(request, env) {
  const t0 = Date.now();
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { order_id, user_id, product_id, product_name, category } = body;
  if (!user_id || !product_id)
    return Response.json({ error: 'user_id and product_id required' }, { status: 400 });

  const actions = [];
  const allGranted = [];
  let tenantCreated = 0;
  let apiKeysCreated = 0;
  let tenantId = null;
  const errors = [];

  try {
    // 1. Determine tier and entitlements
    const tier = PLAN_ENTITLEMENTS[product_id] ? (
      product_id.includes('enterprise') ? 'ENTERPRISE' :
      product_id.includes('team') ? 'TEAM' :
      product_id.includes('pro') ? 'PRO' : 'FREE'
    ) : 'FREE';

    // 2. Get or create tenant
    const tenant = await getOrCreateTenant(env.DB, user_id, tier);
    tenantId = tenant.id;
    tenantCreated = tenant.id ? 1 : 0;
    actions.push(`tenant:${tenant.id}`);

    // 3. Grant entitlements
    let entitlements = [];
    if (PLAN_ENTITLEMENTS[product_id]) {
      entitlements = PLAN_ENTITLEMENTS[product_id];
    } else if (category === 'report') {
      entitlements = REPORT_ENTITLEMENTS(product_id);
    } else if (product_id === 'bundle-all-q2' || category === 'bundle') {
      entitlements = BUNDLE_ENTITLEMENTS;
    }

    if (entitlements.length > 0) {
      const granted = await grantEntitlements(env.DB, user_id, tenantId, entitlements, 'purchase', order_id);
      allGranted.push(...granted);
      actions.push(`entitlements:${granted.length}`);
    }

    // 4. Create API key for subscription products
    if (PLAN_ENTITLEMENTS[product_id]) {
      const keyResult = await generateAPIKey(env.DB, user_id, tier, product_id);
      if (keyResult.created) {
        apiKeysCreated = 1;
        actions.push(`api_key:${tier}`);
      }
    }

    // 5. Grant report access if it's a report purchase
    if (category === 'report' && order_id) {
      try {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO report_access (id, user_id, report_id, order_id, granted_via, created_at)
           VALUES (?, ?, ?, ?, 'purchase', datetime('now'))`
        ).bind(crypto.randomUUID(), user_id, product_id, order_id).run();
        actions.push(`report_access:${product_id}`);
      } catch (e) { errors.push(`report_access: ${e?.message}`); }
    }

    // 6. Log provisioning
    await writeProvisioningLog(env.DB, {
      user_id, tenant_id: tenantId, trigger_type: 'purchase', trigger_ref: order_id,
      actions, entitlements: allGranted, api_keys_created: apiKeysCreated,
      tenant_created: tenantCreated, status: errors.length > 0 ? 'partial' : 'success',
      error_detail: errors.length > 0 ? errors.join('; ') : null,
      duration_ms: Date.now() - t0,
    });

    return Response.json({
      success: true,
      provisioned: {
        user_id, tenant_id: tenantId,
        tier, entitlements_granted: allGranted.length,
        api_key_created: apiKeysCreated > 0,
        actions,
        duration_ms: Date.now() - t0,
      },
      warnings: errors.length > 0 ? errors : undefined,
    });

  } catch (err) {
    await writeProvisioningLog(env.DB, {
      user_id, tenant_id: tenantId, trigger_type: 'purchase', trigger_ref: order_id,
      actions, status: 'failed', error_detail: err?.message, duration_ms: Date.now() - t0,
    }).catch(() => {});
    return Response.json({ error: 'Provisioning failed', detail: err?.message }, { status: 500 });
  }
}

// ─── Provision After Subscription ────────────────────────────────────────────
async function handleProvisionSubscription(request, env) {
  const t0 = Date.now();
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const { subscription_id, user_id, plan_id, billing_period, trial } = body;
  if (!user_id || !plan_id)
    return Response.json({ error: 'user_id and plan_id required' }, { status: 400 });

  const tier = plan_id.includes('enterprise') ? 'ENTERPRISE'
    : plan_id.includes('team') ? 'TEAM'
    : plan_id.includes('pro') ? 'PRO' : 'FREE';

  // Subscription entitlement expiry = end of billing period
  const daysToAdd = billing_period === 'annual' ? 366 : 32;
  const expiresAt = new Date(Date.now() + daysToAdd * 86400_000).toISOString();

  const actions = [];
  const allGranted = [];
  let tenantCreated = 0;
  let apiKeysCreated = 0;
  let tenantId = null;

  try {
    const tenant = await getOrCreateTenant(env.DB, user_id, tier);
    tenantId = tenant.id;
    tenantCreated = 1;
    actions.push(`tenant:${tenantId}`);

    const entitlements = PLAN_ENTITLEMENTS[plan_id] || PLAN_ENTITLEMENTS['api-free'];
    const granted = await grantEntitlements(
      env.DB, user_id, tenantId, entitlements, 'subscription', subscription_id, trial ? expiresAt : null
    );
    allGranted.push(...granted);
    actions.push(`entitlements:${granted.length}`);

    const keyResult = await generateAPIKey(env.DB, user_id, tier, plan_id);
    if (keyResult.created) { apiKeysCreated = 1; actions.push(`api_key:${tier}`); }

    await writeProvisioningLog(env.DB, {
      user_id, tenant_id: tenantId,
      trigger_type: trial ? 'trial' : 'subscription',
      trigger_ref: subscription_id,
      actions, entitlements: allGranted, api_keys_created: apiKeysCreated,
      tenant_created: tenantCreated, status: 'success', duration_ms: Date.now() - t0,
    });

    return Response.json({
      success: true,
      provisioned: {
        user_id, tenant_id: tenantId, tier,
        entitlements_granted: allGranted.length,
        api_key_created: apiKeysCreated > 0,
        actions, duration_ms: Date.now() - t0,
      },
    });
  } catch (err) {
    return Response.json({ error: 'Subscription provisioning failed', detail: err?.message }, { status: 500 });
  }
}

// ─── Provision Trial ──────────────────────────────────────────────────────────
async function handleProvisionTrial(request, env) {
  const body = await request.json().catch(() => ({}));
  const { user_id, plan_id = 'api-pro', trial_days = 7 } = body;
  if (!user_id) return Response.json({ error: 'user_id required' }, { status: 400 });

  const expiresAt = new Date(Date.now() + trial_days * 86400_000).toISOString();
  return handleProvisionSubscription(
    new Request(request.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id, plan_id, billing_period: 'monthly', trial: true, subscription_id: `trial_${user_id}` }),
    }),
    env
  );
}

// ─── Provisioning Status ──────────────────────────────────────────────────────
async function handleProvisioningStatus(request, env, userId) {
  const [tenant, entitlements, logs] = await Promise.all([
    env.DB.prepare(`SELECT * FROM customer_tenants WHERE user_id = ? LIMIT 1`).bind(userId).first().catch(() => null),
    env.DB.prepare(`SELECT feature, source, tier_required, enabled, expires_at FROM customer_entitlements WHERE user_id = ? AND enabled = 1`).bind(userId).all().catch(() => ({ results: [] })),
    env.DB.prepare(`SELECT trigger_type, trigger_ref, status, actions_taken, created_at FROM provisioning_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10`).bind(userId).all().catch(() => ({ results: [] })),
  ]);

  const ents = (entitlements.results || []).map(e => ({
    feature: e.feature,
    tier: e.tier_required,
    source: e.source,
    expires_at: e.expires_at,
    active: !e.expires_at || new Date(e.expires_at) > new Date(),
  }));

  return Response.json({
    user_id: userId,
    tenant: tenant || null,
    entitlements: ents,
    active_entitlements: ents.filter(e => e.active).length,
    provisioning_history: logs.results || [],
  });
}

// ─── Revoke Entitlements ──────────────────────────────────────────────────────
async function handleProvisionRevoke(request, env) {
  const body = await request.json().catch(() => ({}));
  const { user_id, reason = 'cancelled', subscription_id } = body;
  if (!user_id) return Response.json({ error: 'user_id required' }, { status: 400 });

  try {
    const whereClause = subscription_id
      ? `user_id = ? AND source_ref = ?`
      : `user_id = ?`;
    const params = subscription_id ? [user_id, subscription_id] : [user_id];

    const result = await env.DB.prepare(
      `UPDATE customer_entitlements SET enabled = 0, revoked_at = datetime('now'), revoke_reason = ? WHERE ${whereClause}`
    ).bind(reason, ...params).run();

    // Log it
    await writeProvisioningLog(env.DB, {
      user_id, trigger_type: 'cancel', trigger_ref: subscription_id,
      actions: [`revoked:${result.changes || 0} entitlements`],
      status: 'success',
    });

    return Response.json({ success: true, revoked: result.changes || 0, reason });
  } catch (err) {
    return Response.json({ error: 'Revocation failed', detail: err?.message }, { status: 500 });
  }
}

// ─── Audit Log ────────────────────────────────────────────────────────────────
async function handleProvisionAudit(request, env, userId) {
  const logs = await env.DB.prepare(
    `SELECT * FROM provisioning_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`
  ).bind(userId).all().catch(() => ({ results: [] }));

  return Response.json({ user_id: userId, audit_log: logs.results || [] });
}

// ─── Main Dispatcher ─────────────────────────────────────────────────────────
export async function handleProvisioning(request, env, authCtx, path, method) {
  try {
    if (path === '/api/provision/purchase' && method === 'POST')
      return handleProvisionPurchase(request, env);

    if (path === '/api/provision/subscription' && method === 'POST')
      return handleProvisionSubscription(request, env);

    if (path === '/api/provision/trial' && method === 'POST')
      return handleProvisionTrial(request, env);

    const statusMatch = path.match(/^\/api\/provision\/status\/(.+)$/);
    if (statusMatch && method === 'GET')
      return handleProvisioningStatus(request, env, statusMatch[1]);

    if (path === '/api/provision/revoke' && method === 'POST')
      return handleProvisionRevoke(request, env);

    const auditMatch = path.match(/^\/api\/provision\/audit\/(.+)$/);
    if (auditMatch && method === 'GET')
      return handleProvisionAudit(request, env, auditMatch[1]);

    return Response.json({
      error: 'Provisioning route not found',
      available: [
        'POST /api/provision/purchase',
        'POST /api/provision/subscription',
        'POST /api/provision/trial',
        'GET  /api/provision/status/:userId',
        'POST /api/provision/revoke',
        'GET  /api/provision/audit/:userId',
      ],
    }, { status: 404 });
  } catch (err) {
    console.error('[Provisioning] Error:', err?.message);
    return Response.json({ error: 'Provisioning engine error', detail: err?.message }, { status: 500 });
  }
}
