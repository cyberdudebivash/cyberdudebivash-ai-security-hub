/**
 * CYBERDUDEBIVASH® AI Security Hub — MSSP Revenue Share (real implementation)
 *
 * Backs the "Revenue Share 60/40" claim advertised on mssp.html. Previously
 * that number had zero backend support anywhere in the codebase — no payout
 * calculation, no ledger, nothing computed it. This module is the real thing:
 *
 *   - Every captured payment from a customer who was onboarded by an MSSP
 *     partner is automatically split (default 60% partner / 40% platform,
 *     per-partner configurable via mssp_partners.partner_share_pct) and
 *     recorded as an immutable ledger entry.
 *   - GET /api/mssp/revenue       — partner sees their own ledger + totals
 *   - GET /api/mssp/revenue/admin — owner/mssp_admin sees all partners
 *
 * Self-bootstrapping: tables/columns are created on first use via
 * CREATE TABLE IF NOT EXISTS / ALTER TABLE ADD COLUMN wrapped in try/catch,
 * matching this codebase's existing pattern (msspTenantPlatform.js) — no
 * manual migration step required before this code can run safely.
 *
 * Invariant: never throws into the payment webhook path. If revenue-share
 * bootstrap or insert fails, the payment itself still completes — the split
 * is best-effort accounting, not a blocker for customer payment delivery.
 */

let _revenueTablesReady = false;
async function ensureRevenueTables(db) {
  if (_revenueTablesReady) return;
  try {
    await db.prepare(`ALTER TABLE payments ADD COLUMN partner_id TEXT`).run();
  } catch (_) { /* column already exists */ }
  try {
    await db.prepare(`ALTER TABLE mssp_partners ADD COLUMN partner_share_pct REAL NOT NULL DEFAULT 60.0`).run();
  } catch (_) { /* column already exists */ }
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS mssp_revenue_ledger (
        id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        partner_id            TEXT NOT NULL,
        payment_id            TEXT NOT NULL UNIQUE,
        customer_email        TEXT,
        module                TEXT,
        gross_amount_paise    INTEGER NOT NULL,
        partner_share_pct     REAL NOT NULL,
        partner_share_paise   INTEGER NOT NULL,
        platform_share_paise  INTEGER NOT NULL,
        status                TEXT NOT NULL DEFAULT 'accrued' CHECK (status IN ('accrued','paid_out','reversed')),
        created_at            TEXT NOT NULL DEFAULT (datetime('now')),
        paid_out_at           TEXT
      )
    `).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_mssp_revenue_ledger_partner ON mssp_revenue_ledger(partner_id)`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_mssp_revenue_ledger_status  ON mssp_revenue_ledger(status)`).run();
  } catch (_) { /* table already exists */ }
  _revenueTablesReady = true;
}

/**
 * Looks up which MSSP partner (if any) owns the paying customer, by matching
 * the order's email against mssp_customers.contact_email. Called at order
 * creation time so the attribution is locked in before payment capture.
 * Returns null (no partner) for ordinary direct customers — the common case.
 */
export async function resolvePartnerIdForEmail(env, email) {
  if (!env.DB || !email) return null;
  try {
    // Bootstrap here too — this runs at order-creation time, before the webhook
    // ever fires, so payments.partner_id must already exist by the time the
    // INSERT in handleCreateOrder runs.
    await ensureRevenueTables(env.DB);
    const row = await env.DB.prepare(
      `SELECT partner_id FROM mssp_customers WHERE contact_email = ? AND partner_id IS NOT NULL LIMIT 1`
    ).bind(email.toLowerCase()).first();
    return row?.partner_id || null;
  } catch (_) {
    return null; // mssp_customers/partner_id not bootstrapped yet, or lookup failed — fail open to "no partner"
  }
}

/**
 * Computes and records the revenue split for a captured payment. Call this
 * from the Razorpay webhook handler immediately after marking a payment paid,
 * passing the partner_id that was stamped on the payments row at order time.
 * Idempotent: payment_id is UNIQUE, so a duplicate webhook delivery (already
 * deduplicated upstream, but defense-in-depth) won't double-count revenue.
 */
export async function recordRevenueShare(env, { paymentId, partnerId, grossAmountPaise, customerEmail, module }) {
  if (!env.DB || !partnerId || !paymentId || !grossAmountPaise) return { recorded: false, reason: 'missing_fields' };
  try {
    await ensureRevenueTables(env.DB);

    const partner = await env.DB.prepare(
      `SELECT partner_share_pct FROM mssp_partners WHERE id = ?`
    ).bind(partnerId).first();
    const sharePct = partner?.partner_share_pct ?? 60.0;

    const partnerSharePaise  = Math.round(grossAmountPaise * (sharePct / 100));
    const platformSharePaise = grossAmountPaise - partnerSharePaise;

    await env.DB.prepare(
      `INSERT INTO mssp_revenue_ledger
         (partner_id, payment_id, customer_email, module, gross_amount_paise,
          partner_share_pct, partner_share_paise, platform_share_paise)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      partnerId, paymentId, customerEmail || null, module || null,
      grossAmountPaise, sharePct, partnerSharePaise, platformSharePaise
    ).run();

    return { recorded: true, partnerSharePaise, platformSharePaise, sharePct };
  } catch (e) {
    // UNIQUE constraint on payment_id = already recorded for this payment (idempotent no-op)
    if (String(e.message || '').includes('UNIQUE')) return { recorded: false, reason: 'duplicate' };
    console.error('[MSSP Revenue] record failed:', e.message);
    return { recorded: false, reason: e.message };
  }
}

// GET /api/mssp/revenue?partner_id=... — owner views one partner's ledger + totals.
// NOTE: there is no partner self-serve login in this platform yet (mssp_partners.api_key
// exists in schema but nothing validates it against incoming requests — confirmed during
// audit). Until that self-serve auth is built, partner revenue visibility is owner-gated,
// same as every other MSSP admin route in this codebase (requireOwner below).
export async function handleGetPartnerRevenue(request, env, authCtx = {}, requireOwner) {
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!requireOwner(authCtx, env)) return Response.json({ error: 'This resource is restricted to the platform owner.' }, { status: 403 });

  const url0 = new URL(request.url);
  const partnerId = url0.searchParams.get('partner_id');
  if (!partnerId) return Response.json({ error: 'partner_id query param required' }, { status: 400 });

  try {
    await ensureRevenueTables(env.DB);

    const limit = Math.min(parseInt(url0.searchParams.get('limit') || '50', 10) || 50, 200);

    const [entries, totals, partner] = await Promise.all([
      env.DB.prepare(
        `SELECT id, customer_email, module, gross_amount_paise, partner_share_pct,
                partner_share_paise, platform_share_paise, status, created_at, paid_out_at
         FROM mssp_revenue_ledger WHERE partner_id = ? ORDER BY created_at DESC LIMIT ?`
      ).bind(partnerId, limit).all().catch(() => ({ results: [] })),
      env.DB.prepare(
        `SELECT
           COUNT(*) AS total_entries,
           COALESCE(SUM(gross_amount_paise), 0) AS total_gross_paise,
           COALESCE(SUM(partner_share_paise), 0) AS total_partner_earnings_paise,
           COALESCE(SUM(CASE WHEN status = 'accrued' THEN partner_share_paise ELSE 0 END), 0) AS pending_payout_paise,
           COALESCE(SUM(CASE WHEN status = 'paid_out' THEN partner_share_paise ELSE 0 END), 0) AS paid_out_paise
         FROM mssp_revenue_ledger WHERE partner_id = ?`
      ).bind(partnerId).first().catch(() => null),
      env.DB.prepare(`SELECT partner_share_pct FROM mssp_partners WHERE id = ?`).bind(partnerId).first().catch(() => null),
    ]);

    return Response.json({
      success: true,
      partner_id: partnerId,
      partner_share_pct: partner?.partner_share_pct ?? 60.0,
      totals: totals || { total_entries: 0, total_gross_paise: 0, total_partner_earnings_paise: 0, pending_payout_paise: 0, paid_out_paise: 0 },
      ledger: (entries.results || []).map(row => ({
        ...row,
        gross_amount_inr: row.gross_amount_paise / 100,
        partner_share_inr: row.partner_share_paise / 100,
        platform_share_inr: row.platform_share_paise / 100,
      })),
    });
  } catch (e) {
    return Response.json({ error: 'Failed to load revenue ledger', detail: e.message }, { status: 500 });
  }
}

// GET /api/mssp/revenue/admin — owner/mssp_admin sees every partner's ledger summary
export async function handleGetAllPartnerRevenue(request, env, authCtx = {}, requireOwner) {
  if (!env.DB) return Response.json({ error: 'Database unavailable' }, { status: 503 });
  if (!requireOwner(authCtx, env)) return Response.json({ error: 'This resource is restricted to the platform owner.' }, { status: 403 });

  try {
    await ensureRevenueTables(env.DB);

    const rows = await env.DB.prepare(
      `SELECT
         p.id AS partner_id, p.company, p.contact_email, p.partner_share_pct,
         COUNT(l.id) AS total_entries,
         COALESCE(SUM(l.gross_amount_paise), 0) AS total_gross_paise,
         COALESCE(SUM(l.partner_share_paise), 0) AS total_partner_earnings_paise,
         COALESCE(SUM(l.platform_share_paise), 0) AS total_platform_revenue_paise,
         COALESCE(SUM(CASE WHEN l.status = 'accrued' THEN l.partner_share_paise ELSE 0 END), 0) AS pending_payout_paise
       FROM mssp_partners p
       LEFT JOIN mssp_revenue_ledger l ON l.partner_id = p.id
       GROUP BY p.id
       ORDER BY total_gross_paise DESC`
    ).all().catch(() => ({ results: [] }));

    return Response.json({
      success: true,
      partners: (rows.results || []).map(r => ({
        ...r,
        total_gross_inr: r.total_gross_paise / 100,
        total_partner_earnings_inr: r.total_partner_earnings_paise / 100,
        total_platform_revenue_inr: r.total_platform_revenue_paise / 100,
        pending_payout_inr: r.pending_payout_paise / 100,
      })),
    });
  } catch (e) {
    return Response.json({ error: 'Failed to load partner revenue', detail: e.message }, { status: 500 });
  }
}
