/**
 * CYBERDUDEBIVASH® AI Security Hub
 * P9.0 MSSP Tenant Platform — Enterprise Multi-Tenancy & MSSP Platform
 *
 * P9.2  Customer labels and grouping
 * P9.5  Customer dashboard aggregation
 * P9.6  Sub-tenant management and hierarchy
 * P9.7  Per-customer notification preferences, ticket routing, API keys
 * P9.8  Tenant-aware billing metadata and usage tracking
 *
 * Invariants:
 *  - SECURITY_HUB_DB and SECURITY_HUB_KV exclusively
 *  - partnerScope fail-closed: no scope → empty data, never cross-tenant
 *  - All tables auto-bootstrap on first use
 *  - No placeholder logic; no fake data
 */

const nanoid = (n = 21) => crypto.randomUUID().replace(/-/g, '').slice(0, n);

// A real MSSP partner session (workers/src/handlers/partnerAuth.js, magic-link
// login) resolves to authCtx.partnerId with authCtx.userId/user_id both null
// (see workers/src/auth/middleware.js's resolvePartnerSession + withAuthAliases,
// which derives role:'partner' from partnerId) — was previously unreachable
// here, since userId was the only scope this function checked. Every one of
// the 18 handlers below already child-scopes its D1 queries by whatever this
// returns, so a null/undefined scope already fails closed (empty results, not
// a leak) rather than being unsafe — this just makes the real, paying partner
// identity resolve like it already does in the sibling workers/src/handlers/
// msspWorkspace.js (which backs the 2 already-wired /api/mssp/customers
// handlers), instead of only the legacy JWT-user-with-tier-MSSP identity.
function partnerScope(authCtx) {
  return authCtx?.partnerId ?? authCtx?.userId ?? authCtx?.user_id ?? null;
}

// Previously only admitted authCtx.isAdmin or tier==='MSSP' (a JWT/API-key
// user whose own subscription tier is literally 'MSSP') — never
// authCtx.role==='partner', the identity partner-portal.html's magic-link
// session actually produces. That meant every one of this file's 18 handlers
// 403'd for every real MSSP reseller partner, even on their own data, while
// the 2 handlers in msspWorkspace.js (the only ones partner-portal.html
// currently calls) worked, because that sibling file's requireMSSPAdmin
// already included role==='partner' (see its own comment, 2026-07-06 revenue-
// mechanisms audit). Mirrors that same, already-shipped, already-safe fix.
function requireMSSPAdmin(authCtx) {
  return authCtx?.isAdmin === true || (authCtx?.tier || '').toUpperCase() === 'MSSP' || authCtx?.role === 'partner';
}

let _tenantTablesReady = false;
async function ensureTenantTables(db) {
  if (_tenantTablesReady) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS mssp_customer_labels (
        id          TEXT PRIMARY KEY,
        partner_id  TEXT NOT NULL,
        customer_id TEXT NOT NULL,
        label       TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        UNIQUE(partner_id, customer_id, label)
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS mssp_notification_prefs (
        id          TEXT PRIMARY KEY,
        partner_id  TEXT NOT NULL,
        customer_id TEXT NOT NULL,
        channel     TEXT NOT NULL DEFAULT 'email',
        event_type  TEXT NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        config_json TEXT,
        updated_at  TEXT NOT NULL,
        UNIQUE(partner_id, customer_id, channel, event_type)
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS mssp_ticket_rules (
        id          TEXT PRIMARY KEY,
        partner_id  TEXT NOT NULL,
        rule_name   TEXT NOT NULL,
        conditions  TEXT NOT NULL,
        actions     TEXT NOT NULL,
        priority    INTEGER NOT NULL DEFAULT 0,
        enabled     INTEGER NOT NULL DEFAULT 1,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS mssp_customer_api_keys (
        id           TEXT PRIMARY KEY,
        partner_id   TEXT NOT NULL,
        customer_id  TEXT NOT NULL,
        key_prefix   TEXT NOT NULL,
        key_hash     TEXT NOT NULL,
        name         TEXT NOT NULL,
        scopes       TEXT NOT NULL DEFAULT '["read"]',
        status       TEXT NOT NULL DEFAULT 'active',
        last_used_at TEXT,
        expires_at   TEXT,
        created_at   TEXT NOT NULL,
        revoked_at   TEXT
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS mssp_tenant_usage (
        id              TEXT PRIMARY KEY,
        partner_id      TEXT NOT NULL,
        customer_id     TEXT NOT NULL,
        period_start    TEXT NOT NULL,
        period_end      TEXT NOT NULL,
        api_calls       INTEGER NOT NULL DEFAULT 0,
        scans_run       INTEGER NOT NULL DEFAULT 0,
        threats_fetched INTEGER NOT NULL DEFAULT 0,
        storage_bytes   INTEGER NOT NULL DEFAULT 0,
        report_count    INTEGER NOT NULL DEFAULT 0,
        recorded_at     TEXT NOT NULL,
        UNIQUE(partner_id, customer_id, period_start)
      )`),
    ]);
    _tenantTablesReady = true;
  } catch (e) {
    console.error('[P9.0] Table bootstrap error:', e?.message);
  }
}

// ── P9.2: Customer Labels ─────────────────────────────────────────────────────

export async function handleListCustomerLabels(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ success: true, labels: [] });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    const rows = await db.prepare(
      `SELECT label, created_at FROM mssp_customer_labels WHERE partner_id = ? AND customer_id = ? ORDER BY label ASC`
    ).bind(scope, customerId).all();
    return Response.json({ success: true, customer_id: customerId, labels: (rows?.results || []).map(r => r.label) });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleAddCustomerLabel(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body;
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const label = (body.label || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
  if (!label) return Response.json({ error: 'label required (alphanumeric, dash, underscore only)' }, { status: 400 });
  if (label.length > 50) return Response.json({ error: 'label max 50 characters' }, { status: 400 });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    await db.prepare(
      `INSERT OR IGNORE INTO mssp_customer_labels (id, partner_id, customer_id, label, created_at) VALUES (?, ?, ?, ?, ?)`
    ).bind(`lbl_${nanoid(12)}`, scope, customerId, label, new Date().toISOString()).run();
    return Response.json({ success: true, customer_id: customerId, label });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleRemoveCustomerLabel(request, env, authCtx, customerId, label) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    await db.prepare(
      `DELETE FROM mssp_customer_labels WHERE partner_id = ? AND customer_id = ? AND label = ?`
    ).bind(scope, customerId, label).run();
    return Response.json({ success: true });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// ── P9.5: Customer Dashboard Aggregation ─────────────────────────────────────

export async function handleCustomerDashboard(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const db = env.SECURITY_HUB_DB;
  const kv = env.SECURITY_HUB_KV;

  const customer = await db.prepare(
    `SELECT * FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(customerId, customerId, scope).first().catch(() => null);
  if (!customer) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const cacheKey = `mssp:dashboard:${scope}:${customer.id}`;
  if (kv) {
    const cached = await kv.get(cacheKey, { type: 'json' }).catch(() => null);
    if (cached) return Response.json({ ...cached, cached: true });
  }

  await ensureTenantTables(db);

  let assetCount = 0;
  try {
    const aQ = await db.prepare(`SELECT COUNT(*) as cnt FROM customer_assets WHERE customer_id = ?`).bind(customer.id).first();
    assetCount = aQ?.cnt || 0;
  } catch (_) {}

  let scanMetrics = { total: 0, critical: 0, high: 0, avg_risk: 0 };
  try {
    const sQ = await db.prepare(`
      SELECT COUNT(*) as total,
             SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high,
             AVG(risk_score) as avg_risk
      FROM scan_results WHERE org_id = ?
    `).bind(customer.id).first();
    if (sQ) scanMetrics = { total: sQ.total||0, critical: sQ.critical||0, high: sQ.high||0, avg_risk: Math.round(sQ.avg_risk||0) };
  } catch (_) {}

  let threatMetrics = { critical: 0, high: 0, total_active: 0 };
  try {
    const tQ = await db.prepare(`
      SELECT COUNT(*) as total,
             SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high
      FROM threat_intel_cache WHERE expires_at > datetime('now')
    `).first();
    if (tQ) threatMetrics = { critical: tQ.critical||0, high: tQ.high||0, total_active: tQ.total||0 };
  } catch (_) {}

  let apiUsage = { calls_30d: 0, calls_today: 0 };
  try {
    const aQ = await db.prepare(`
      SELECT COUNT(*) as calls_30d,
             SUM(CASE WHEN ts >= date('now') THEN 1 ELSE 0 END) as calls_today
      FROM ops_usage_events WHERE user_id = ? AND ts >= datetime('now','-30 days')
    `).bind(customer.id).first();
    if (aQ) apiUsage = { calls_30d: aQ.calls_30d||0, calls_today: aQ.calls_today||0 };
  } catch (_) {}

  let labels = [];
  try {
    const lQ = await db.prepare(
      `SELECT label FROM mssp_customer_labels WHERE partner_id = ? AND customer_id = ? ORDER BY label`
    ).bind(scope, customer.id).all();
    labels = (lQ?.results || []).map(r => r.label);
  } catch (_) {}

  let subTenantCount = 0;
  try {
    const stQ = await db.prepare(
      `SELECT COUNT(*) as cnt FROM mssp_customers WHERE parent_customer_id = ? AND partner_id = ?`
    ).bind(customer.id, scope).first();
    subTenantCount = stQ?.cnt || 0;
  } catch (_) {}

  const dashboard = {
    success: true,
    customer: {
      id:               customer.id,
      org_name:         customer.org_name,
      org_slug:         customer.org_slug,
      tier:             customer.tier,
      status:           customer.status,
      mrr_usd:          (customer.mrr_cents || 0) / 100,
      last_activity_at: customer.last_activity_at,
      created_at:       customer.created_at,
    },
    security_posture: {
      risk_score:       customer.risk_score || 0,
      compliance_score: customer.compliance_score || 0,
    },
    assets:      { total: assetCount },
    scans:       scanMetrics,
    threats:     threatMetrics,
    api_usage:   apiUsage,
    labels,
    sub_tenants: { total: subTenantCount },
    as_of: new Date().toISOString(),
  };

  if (kv) kv.put(cacheKey, JSON.stringify(dashboard), { expirationTtl: 180 }).catch(() => {});

  return Response.json(dashboard);
}

// ── P9.6: Sub-Tenant Management ───────────────────────────────────────────────

async function addParentCustomerIdColumn(db) {
  try { await db.prepare(`ALTER TABLE mssp_customers ADD COLUMN parent_customer_id TEXT`).run(); } catch (_) {}
}

export async function handleListSubTenants(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ success: true, sub_tenants: [], total: 0 });

  const db = env.SECURITY_HUB_DB;
  await addParentCustomerIdColumn(db);

  try {
    const rows = await db.prepare(`
      SELECT id, org_name, org_slug, tier, status, risk_score, compliance_score, mrr_cents, created_at
      FROM mssp_customers
      WHERE parent_customer_id = ? AND partner_id = ?
      ORDER BY org_name ASC
    `).bind(customerId, scope).all();
    return Response.json({ success: true, parent_id: customerId, sub_tenants: rows?.results || [], total: rows?.results?.length || 0 });
  } catch (_) {
    return Response.json({ success: true, parent_id: customerId, sub_tenants: [], total: 0 });
  }
}

export async function handleCreateSubTenant(request, env, authCtx, parentCustomerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body;
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { org_name, contact_email, tier = 'starter', contact_name } = body;
  if (!org_name) return Response.json({ error: 'org_name required' }, { status: 400 });

  const db = env.SECURITY_HUB_DB;
  await addParentCustomerIdColumn(db);

  const parent = await db.prepare(
    `SELECT id FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(parentCustomerId, parentCustomerId, scope).first().catch(() => null);
  if (!parent) return Response.json({ error: 'Parent customer not found' }, { status: 404 });

  const id       = `cust_${nanoid(12)}`;
  const org_slug = org_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const now      = new Date().toISOString();

  try {
    await db.prepare(`
      INSERT INTO mssp_customers
        (id, org_name, org_slug, contact_name, contact_email, tier, partner_id, parent_customer_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, org_name, org_slug, contact_name||null, contact_email||null, tier, scope, parent.id, now, now).run();
    return Response.json({ success: true, sub_tenant: { id, org_name, org_slug, tier, parent_customer_id: parent.id } }, { status: 201 });
  } catch (e) {
    if (e.message?.includes('UNIQUE')) return Response.json({ error: 'Customer with this name already exists' }, { status: 409 });
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleGetHierarchy(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const db = env.SECURITY_HUB_DB;
  await addParentCustomerIdColumn(db);

  const root = await db.prepare(
    `SELECT id, org_name, org_slug, tier, status, risk_score, compliance_score, parent_customer_id
     FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(customerId, customerId, scope).first().catch(() => null);
  if (!root) return Response.json({ error: 'Customer not found' }, { status: 404 });

  let children = [];
  try {
    const cQ = await db.prepare(`
      SELECT id, org_name, org_slug, tier, status, risk_score FROM mssp_customers
      WHERE parent_customer_id = ? AND partner_id = ? ORDER BY org_name
    `).bind(root.id, scope).all();
    children = cQ?.results || [];
  } catch (_) {}

  let parent = null;
  if (root.parent_customer_id) {
    try {
      parent = await db.prepare(
        `SELECT id, org_name, org_slug, tier FROM mssp_customers WHERE id = ? AND partner_id = ?`
      ).bind(root.parent_customer_id, scope).first();
    } catch (_) {}
  }

  return Response.json({ success: true, root, parent: parent || null, children, total_children: children.length });
}

// ── P9.7: Per-Customer Notification Preferences ───────────────────────────────

const VALID_NOTIF_CHANNELS = ['email', 'webhook', 'slack', 'siem', 'pagerduty'];
const VALID_NOTIF_EVENTS   = [
  'threat.critical', 'threat.high', 'scan.completed', 'scan.high_risk',
  'report.ready', 'customer.risk_change', 'api.quota_80pct', 'api.quota_exceeded',
  'compliance.violation', 'asset.new', 'incident.created', 'incident.escalated',
];

export async function handleGetNotifPrefs(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ success: true, prefs: [] });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    const rows = await db.prepare(`
      SELECT channel, event_type, enabled, config_json, updated_at
      FROM mssp_notification_prefs
      WHERE partner_id = ? AND customer_id = ?
      ORDER BY event_type ASC
    `).bind(scope, customerId).all();
    return Response.json({
      success: true,
      customer_id: customerId,
      prefs: (rows?.results || []).map(r => ({
        channel:    r.channel,
        event_type: r.event_type,
        enabled:    Boolean(r.enabled),
        config:     r.config_json ? JSON.parse(r.config_json) : null,
        updated_at: r.updated_at,
      })),
      valid_channels: VALID_NOTIF_CHANNELS,
      valid_events:   VALID_NOTIF_EVENTS,
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleSetNotifPrefs(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body;
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { prefs } = body;
  if (!Array.isArray(prefs) || prefs.length === 0) return Response.json({ error: 'prefs array required' }, { status: 400 });

  const db  = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);
  const now = new Date().toISOString();
  let saved = 0;

  for (const pref of prefs) {
    const { channel, event_type, enabled = true, config } = pref;
    if (!VALID_NOTIF_CHANNELS.includes(channel) || !VALID_NOTIF_EVENTS.includes(event_type)) continue;
    try {
      await db.prepare(`
        INSERT INTO mssp_notification_prefs (id, partner_id, customer_id, channel, event_type, enabled, config_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(partner_id, customer_id, channel, event_type) DO UPDATE SET
          enabled = excluded.enabled, config_json = excluded.config_json, updated_at = excluded.updated_at
      `).bind(`np_${nanoid(12)}`, scope, customerId, channel, event_type, enabled ? 1 : 0, config ? JSON.stringify(config) : null, now).run();
      saved++;
    } catch (_) {}
  }

  return Response.json({ success: true, customer_id: customerId, saved });
}

// ── P9.7: Ticket Routing Rules ────────────────────────────────────────────────

export async function handleListTicketRules(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ success: true, rules: [] });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    const rows = await db.prepare(`
      SELECT id, rule_name, conditions, actions, priority, enabled, created_at
      FROM mssp_ticket_rules WHERE partner_id = ? ORDER BY priority DESC, created_at ASC
    `).bind(scope).all();
    return Response.json({
      success: true,
      rules: (rows?.results || []).map(r => ({
        id:         r.id,
        rule_name:  r.rule_name,
        conditions: JSON.parse(r.conditions),
        actions:    JSON.parse(r.actions),
        priority:   r.priority,
        enabled:    Boolean(r.enabled),
        created_at: r.created_at,
      })),
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleCreateTicketRule(request, env, authCtx) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body;
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { rule_name, conditions, actions, priority = 0, enabled = true } = body;
  if (!rule_name || !conditions || !actions) return Response.json({ error: 'rule_name, conditions, and actions required' }, { status: 400 });

  const db  = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);
  const id  = `rule_${nanoid(12)}`;
  const now = new Date().toISOString();

  try {
    await db.prepare(`
      INSERT INTO mssp_ticket_rules (id, partner_id, rule_name, conditions, actions, priority, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, scope, rule_name, JSON.stringify(conditions), JSON.stringify(actions), priority, enabled ? 1 : 0, now, now).run();
    return Response.json({ success: true, rule: { id, rule_name, conditions, actions, priority, enabled } }, { status: 201 });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleDeleteTicketRule(request, env, authCtx, ruleId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    const r = await db.prepare(`DELETE FROM mssp_ticket_rules WHERE id = ? AND partner_id = ?`).bind(ruleId, scope).run();
    if (!r?.meta?.changes) return Response.json({ error: 'Rule not found' }, { status: 404 });
    return Response.json({ success: true, deleted: ruleId });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// ── P9.7: Per-Customer API Keys ───────────────────────────────────────────────

async function hashApiKey(key) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(key));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function handleListCustomerAPIKeys(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ success: true, keys: [] });

  const db = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);

  try {
    const rows = await db.prepare(`
      SELECT id, name, key_prefix, scopes, status, last_used_at, expires_at, created_at
      FROM mssp_customer_api_keys
      WHERE partner_id = ? AND customer_id = ? AND status = 'active'
      ORDER BY created_at DESC
    `).bind(scope, customerId).all();
    return Response.json({
      success: true,
      customer_id: customerId,
      keys: (rows?.results || []).map(r => ({ ...r, scopes: JSON.parse(r.scopes || '["read"]') })),
    });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleGenerateCustomerAPIKey(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  let body;
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { name, scopes = ['read'], expires_in_days } = body;
  if (!name) return Response.json({ error: 'name required' }, { status: 400 });

  const VALID_SCOPES    = ['read', 'write', 'threats', 'scans', 'reports', 'assets'];
  const filteredScopes  = (scopes || []).filter(s => VALID_SCOPES.includes(s));
  if (!filteredScopes.length) return Response.json({ error: 'At least one valid scope required (read, write, threats, scans, reports, assets)' }, { status: 400 });

  const db       = env.SECURITY_HUB_DB;
  const customer = await db.prepare(
    `SELECT id FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(customerId, customerId, scope).first().catch(() => null);
  if (!customer) return Response.json({ error: 'Customer not found' }, { status: 404 });

  await ensureTenantTables(db);

  const rawKey    = `cak_${nanoid(32)}`;
  const prefix    = rawKey.slice(0, 12);
  const keyHash   = await hashApiKey(rawKey);
  const id        = `cak_${nanoid(12)}`;
  const now       = new Date().toISOString();
  const expiresAt = expires_in_days
    ? new Date(Date.now() + expires_in_days * 86400 * 1000).toISOString()
    : null;

  try {
    await db.prepare(`
      INSERT INTO mssp_customer_api_keys (id, partner_id, customer_id, key_prefix, key_hash, name, scopes, status, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `).bind(id, scope, customer.id, prefix, keyHash, name, JSON.stringify(filteredScopes), expiresAt, now).run();
    return Response.json({
      success: true,
      key: rawKey,
      id, name, prefix,
      scopes: filteredScopes,
      expires_at: expiresAt,
      created_at: now,
      warning: 'Store this key securely — it will not be shown again',
    }, { status: 201 });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

export async function handleRevokeCustomerAPIKey(request, env, authCtx, customerId, keyId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'No partner scope' }, { status: 403 });

  const db  = env.SECURITY_HUB_DB;
  await ensureTenantTables(db);
  const now = new Date().toISOString();

  try {
    const r = await db.prepare(`
      UPDATE mssp_customer_api_keys SET status = 'revoked', revoked_at = ?
      WHERE id = ? AND partner_id = ? AND customer_id IN (
        SELECT id FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?
      )
    `).bind(now, keyId, scope, customerId, customerId, scope).run();
    if (!r?.meta?.changes) return Response.json({ error: 'Key not found' }, { status: 404 });
    return Response.json({ success: true, revoked_at: now });
  } catch (e) {
    return Response.json({ success: false, error: e.message }, { status: 500 });
  }
}

// ── P9.8: Tenant-Aware Billing Metadata & Usage Tracking ─────────────────────

export async function handleGetTenantBilling(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const db       = env.SECURITY_HUB_DB;
  const customer = await db.prepare(
    `SELECT id, org_name, tier, status, mrr_cents, created_at FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(customerId, customerId, scope).first().catch(() => null);
  if (!customer) return Response.json({ error: 'Customer not found' }, { status: 404 });

  await ensureTenantTables(db);

  let currentPeriod = null;
  let history       = [];
  try {
    currentPeriod = await db.prepare(`
      SELECT * FROM mssp_tenant_usage WHERE partner_id = ? AND customer_id = ? ORDER BY period_start DESC LIMIT 1
    `).bind(scope, customer.id).first();
    const hQ = await db.prepare(`
      SELECT period_start, period_end, api_calls, scans_run, threats_fetched, storage_bytes, report_count
      FROM mssp_tenant_usage WHERE partner_id = ? AND customer_id = ? ORDER BY period_start DESC LIMIT 6
    `).bind(scope, customer.id).all();
    history = hQ?.results || [];
  } catch (_) {}

  return Response.json({
    success: true,
    customer: {
      id:             customer.id,
      org_name:       customer.org_name,
      tier:           customer.tier,
      status:         customer.status,
      mrr_usd:        (customer.mrr_cents || 0) / 100,
      customer_since: customer.created_at,
    },
    current_period: currentPeriod || null,
    history,
    as_of: new Date().toISOString(),
  });
}

export async function handleGetTenantUsage(request, env, authCtx, customerId) {
  if (!requireMSSPAdmin(authCtx)) return Response.json({ error: 'MSSP admin role required' }, { status: 403 });
  const scope = partnerScope(authCtx);
  if (!scope) return Response.json({ error: 'Customer not found' }, { status: 404 });

  const db       = env.SECURITY_HUB_DB;
  const customer = await db.prepare(
    `SELECT id, org_name, tier FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
  ).bind(customerId, customerId, scope).first().catch(() => null);
  if (!customer) return Response.json({ error: 'Customer not found' }, { status: 404 });

  await ensureTenantTables(db);

  let apiUsage = { calls_30d: 0, calls_today: 0 };
  try {
    const aQ = await db.prepare(`
      SELECT COUNT(*) as calls_30d,
             SUM(CASE WHEN ts >= date('now') THEN 1 ELSE 0 END) as calls_today
      FROM ops_usage_events WHERE user_id = ? AND ts >= datetime('now','-30 days')
    `).bind(customer.id).first();
    if (aQ) apiUsage = { calls_30d: aQ.calls_30d||0, calls_today: aQ.calls_today||0 };
  } catch (_) {}

  let scanUsage = { total_30d: 0, critical_30d: 0 };
  try {
    const sQ = await db.prepare(`
      SELECT COUNT(*) as total,
             SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) as critical
      FROM scan_jobs WHERE org_id = ? AND created_at >= datetime('now','-30 days')
    `).bind(customer.id).first();
    if (sQ) scanUsage = { total_30d: sQ.total||0, critical_30d: sQ.critical||0 };
  } catch (_) {}

  let assetCount = 0;
  try {
    const aQ = await db.prepare(`SELECT COUNT(*) as cnt FROM customer_assets WHERE customer_id = ?`).bind(customer.id).first();
    assetCount = aQ?.cnt || 0;
  } catch (_) {}

  return Response.json({
    success:     true,
    customer_id: customer.id,
    org_name:    customer.org_name,
    tier:        customer.tier,
    api_usage:   apiUsage,
    scan_usage:  scanUsage,
    assets:      { registered: assetCount },
    period:      'last_30_days',
    as_of:       new Date().toISOString(),
  });
}

// ── Main Route Dispatcher ─────────────────────────────────────────────────────

// ─── Tenant provisioning CRUD (/api/mssp/tenants) ────────────────────────────
async function ensureMsspTenantsTable(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS mssp_tenants (
    id           TEXT PRIMARY KEY,
    partner_id   TEXT NOT NULL,
    name         TEXT NOT NULL,
    domain       TEXT,
    plan         TEXT NOT NULL DEFAULT 'ENTERPRISE',
    status       TEXT NOT NULL DEFAULT 'active',
    contact_name TEXT,
    contact_email TEXT,
    api_key      TEXT,
    config_json  TEXT,
    seats        INTEGER DEFAULT 10,
    monthly_fee_inr INTEGER DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
  )`).run().catch(() => {});
}

async function handleListTenants(request, env, authCtx) {
  const partnerId = partnerScope(authCtx);
  if (!partnerId) return Response.json({ error: 'Authentication required.' }, { status: 401 });
  const tier = authCtx?.tier || 'FREE';
  if (!['ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'ENTERPRISE or MSSP tier required for multi-tenant management.', upgrade_url: '/pricing' }, { status: 403 });
  }
  await ensureMsspTenantsTable(env.DB);
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');
  const rows = await env.DB.prepare(
    `SELECT id, name, domain, plan, status, contact_name, contact_email, seats, monthly_fee_inr, created_at, updated_at
     FROM mssp_tenants WHERE partner_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).bind(partnerId, limit, offset).all();
  const countRow = await env.DB.prepare(`SELECT COUNT(*) as cnt FROM mssp_tenants WHERE partner_id = ?`).bind(partnerId).first();
  return Response.json({ success: true, data: { tenants: rows?.results || [], total: countRow?.cnt || 0, limit, offset } });
}

async function handleCreateTenant(request, env, authCtx) {
  const partnerId = partnerScope(authCtx);
  if (!partnerId) return Response.json({ error: 'Authentication required.' }, { status: 401 });
  const tier = authCtx?.tier || 'FREE';
  if (!['ENTERPRISE', 'MSSP'].includes(tier)) {
    return Response.json({ error: 'ENTERPRISE or MSSP tier required.', upgrade_url: '/pricing' }, { status: 403 });
  }
  await ensureMsspTenantsTable(env.DB);
  let body = {};
  try { body = await request.json(); } catch (_) {}
  const { name, domain, plan = 'ENTERPRISE', contact_name, contact_email, seats = 10, monthly_fee_inr = 0 } = body;
  if (!name) return Response.json({ error: 'Tenant name is required.' }, { status: 400 });

  const tenantId = 'ten_' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const apiKey   = 'cdb_tenant_' + crypto.randomUUID().replace(/-/g, '');
  const now      = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO mssp_tenants (id, partner_id, name, domain, plan, status, contact_name, contact_email, api_key, seats, monthly_fee_inr, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`
  ).bind(tenantId, partnerId, name, domain || null, plan, contact_name || null, contact_email || null, apiKey, seats, monthly_fee_inr, now, now).run();

  return Response.json({ success: true, data: { id: tenantId, name, domain, plan, status: 'active', api_key: apiKey, api_key_note: 'Tenant API key — share with the tenant. Cannot be retrieved again.', seats, monthly_fee_inr, created_at: now } }, { status: 201 });
}

async function handleGetTenant(request, env, authCtx, tenantId) {
  const partnerId = partnerScope(authCtx);
  if (!partnerId) return Response.json({ error: 'Authentication required.' }, { status: 401 });
  await ensureMsspTenantsTable(env.DB);
  const row = await env.DB.prepare(`SELECT * FROM mssp_tenants WHERE id = ? AND partner_id = ?`).bind(tenantId, partnerId).first();
  if (!row) return Response.json({ error: 'Tenant not found.' }, { status: 404 });
  const { api_key, ...safeRow } = row;
  return Response.json({ success: true, data: safeRow });
}

async function handleDeleteTenant(request, env, authCtx, tenantId) {
  const partnerId = partnerScope(authCtx);
  if (!partnerId) return Response.json({ error: 'Authentication required.' }, { status: 401 });
  await ensureMsspTenantsTable(env.DB);
  await env.DB.prepare(`UPDATE mssp_tenants SET status = 'suspended', updated_at = datetime('now') WHERE id = ? AND partner_id = ?`).bind(tenantId, partnerId).run();
  return Response.json({ success: true, message: 'Tenant suspended.' });
}

export async function handleMsspTenantRoute(request, env, authCtx, path, method) {
  const segments = path.split('/');

  // /api/mssp/tenants[/:id]
  if (path === '/api/mssp/tenants') {
    if (method === 'GET')  return handleListTenants(request, env, authCtx);
    if (method === 'POST') return handleCreateTenant(request, env, authCtx);
  }
  if (segments[3] === 'tenants' && segments[4]) {
    const tenantId = segments[4];
    if (method === 'GET')    return handleGetTenant(request, env, authCtx, tenantId);
    if (method === 'DELETE') return handleDeleteTenant(request, env, authCtx, tenantId);
  }

  // /api/mssp/ticket-rules[/:ruleId]
  if (path === '/api/mssp/ticket-rules') {
    if (method === 'GET')  return handleListTicketRules(request, env, authCtx);
    if (method === 'POST') return handleCreateTicketRule(request, env, authCtx);
  }
  if (segments[3] === 'ticket-rules' && segments[4] && method === 'DELETE') {
    return handleDeleteTicketRule(request, env, authCtx, segments[4]);
  }

  // /api/mssp/customers/:id/...
  const customerId = segments[4];
  const resource   = segments[5];
  const subId      = segments[6];
  if (!customerId || !resource) return Response.json({ error: 'Not found' }, { status: 404 });

  switch (resource) {
    case 'dashboard':
      return handleCustomerDashboard(request, env, authCtx, customerId);
    case 'labels':
      if (!subId) {
        if (method === 'GET')  return handleListCustomerLabels(request, env, authCtx, customerId);
        if (method === 'POST') return handleAddCustomerLabel(request, env, authCtx, customerId);
      } else if (method === 'DELETE') {
        return handleRemoveCustomerLabel(request, env, authCtx, customerId, decodeURIComponent(subId));
      }
      break;
    case 'hierarchy':
      if (method === 'GET') return handleGetHierarchy(request, env, authCtx, customerId);
      break;
    case 'sub-tenants':
      if (method === 'GET')  return handleListSubTenants(request, env, authCtx, customerId);
      if (method === 'POST') return handleCreateSubTenant(request, env, authCtx, customerId);
      break;
    case 'notifications':
      if (method === 'GET') return handleGetNotifPrefs(request, env, authCtx, customerId);
      if (method === 'PUT') return handleSetNotifPrefs(request, env, authCtx, customerId);
      break;
    case 'api-keys':
      if (!subId) {
        if (method === 'GET')  return handleListCustomerAPIKeys(request, env, authCtx, customerId);
        if (method === 'POST') return handleGenerateCustomerAPIKey(request, env, authCtx, customerId);
      } else if (method === 'DELETE') {
        return handleRevokeCustomerAPIKey(request, env, authCtx, customerId, subId);
      }
      break;
    case 'billing':
      if (method === 'GET') return handleGetTenantBilling(request, env, authCtx, customerId);
      break;
    case 'usage':
      if (method === 'GET') return handleGetTenantUsage(request, env, authCtx, customerId);
      break;
  }

  return Response.json({ error: 'Not found' }, { status: 404 });
}
