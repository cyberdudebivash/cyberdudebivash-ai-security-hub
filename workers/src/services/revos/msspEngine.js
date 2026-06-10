/**
 * CYBERDUDEBIVASH AI Security Hub — MSSP Command Center + CS Copilot v23.0
 * Multi-tenant MSSP management + AI churn detection + success signals
 */

// ═══════════════════════════════════════════════════════════════════════════════
// MSSP COMMAND CENTER
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Get MSSP dashboard for a partner ────────────────────────────────────────
export async function getMSSPDashboard(db, msspUserId) {
  if (!db || !msspUserId) return {};
  try {
    const [clients, billing, incidents] = await Promise.all([
      db.prepare(`
        SELECT * FROM mssp_clients
        WHERE mssp_user_id=? ORDER BY health_score ASC
      `).bind(msspUserId).all(),

      db.prepare(`
        SELECT
          COALESCE(SUM(mrr_inr),0) as total_mrr,
          COUNT(*) as total_clients,
          COUNT(CASE WHEN status='invoiced' OR status='paid' THEN 1 END) as invoiced,
          COALESCE(SUM(CASE WHEN status='paid' THEN mrr_inr ELSE 0 END),0) as collected
        FROM mssp_billing
        WHERE mssp_user_id=? AND period=strftime('%Y-%m',datetime('now'))
      `).bind(msspUserId).first(),

      db.prepare(`
        SELECT SUM(open_incidents) as total_incidents, SUM(critical_findings) as total_critical
        FROM mssp_clients WHERE mssp_user_id=? AND status='active'
      `).bind(msspUserId).first(),
    ]);

    const clientList = clients.results || [];
    const activeClients = clientList.filter(c => c.status === 'active');
    const atRisk = clientList.filter(c => c.health_score < 50);
    const mrrArr = activeClients.reduce((s, c) => s + (c.mrr_inr || 0), 0);

    return {
      summary: {
        total_clients:    clientList.length,
        active_clients:   activeClients.length,
        at_risk_clients:  atRisk.length,
        mrr_inr:          mrrArr,
        arr_inr:          mrrArr * 12,
        open_incidents:   incidents?.total_incidents || 0,
        critical_findings: incidents?.total_critical || 0,
        monthly_collected: billing?.collected || 0,
        monthly_outstanding: (billing?.total_mrr || 0) - (billing?.collected || 0),
      },
      clients:          clientList,
      at_risk:          atRisk,
      billing_period:   billing,
      generated_at:     new Date().toISOString(),
    };
  } catch (e) { return { error: e.message }; }
}

// ─── Onboard new MSSP client ──────────────────────────────────────────────────
export async function onboardMSSPClient(db, msspUserId, clientData) {
  if (!db) return { ok: false };
  try {
    const clientId = `mssp-${Date.now().toString(36)}`;
    const period = new Date().toISOString().slice(0, 7);

    await db.prepare(`
      INSERT INTO mssp_clients
        (id, mssp_user_id, client_name, client_domain, client_email, contact_name,
         industry, employee_count, plan, mrr_inr, sla_tier, white_label_name, notes, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'onboarding')
    `).bind(
      clientId, msspUserId,
      clientData.client_name, clientData.client_domain,
      clientData.client_email, clientData.contact_name,
      clientData.industry, clientData.employee_count || 0,
      clientData.plan || 'STARTER',
      clientData.mrr_inr || 0,
      clientData.sla_tier || 'standard',
      clientData.white_label_name || clientData.client_name,
      clientData.notes || '',
    ).run();

    // Create first billing record
    await db.prepare(`
      INSERT OR IGNORE INTO mssp_billing (mssp_user_id, client_id, period, mrr_inr, status)
      VALUES (?, ?, ?, ?, 'pending')
    `).bind(msspUserId, clientId, period, clientData.mrr_inr || 0).run();

    return { ok: true, client_id: clientId };
  } catch (e) { return { ok: false, error: e.message }; }
}

// ─── Update client health score ───────────────────────────────────────────────
export async function updateClientHealth(db, clientId, metrics) {
  if (!db) return;
  try {
    // Health score algorithm (0-100)
    let health = 70; // baseline
    if (metrics.scans_this_month > 0)    health += 10;
    if (metrics.open_incidents === 0)    health += 10;
    if (metrics.compliance_score > 70)   health += 5;
    if (metrics.payment_status === 'paid') health += 5;
    if (metrics.last_active_days < 7)    health += 5;
    if (metrics.open_incidents > 5)      health -= 20;
    if (metrics.critical_findings > 3)   health -= 15;
    if (metrics.payment_status === 'overdue') health -= 20;

    health = Math.max(0, Math.min(100, health));

    await db.prepare(`
      UPDATE mssp_clients SET
        health_score = ?,
        open_incidents = ?,
        critical_findings = ?,
        last_scan_at = CASE WHEN ? > 0 THEN datetime('now') ELSE last_scan_at END,
        updated_at = datetime('now')
      WHERE id = ?
    `).bind(
      health,
      metrics.open_incidents || 0,
      metrics.critical_findings || 0,
      metrics.scans_this_month || 0,
      clientId,
    ).run();
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI CUSTOMER SUCCESS COPILOT (Phase 6)
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Analyze all users for CS signals ────────────────────────────────────────
export async function runCSAnalysis(db) {
  if (!db) return { analyzed: 0 };
  try {
    // Get users with activity data
    const users = await db.prepare(`
      SELECT
        u.id as user_id, u.email, u.plan, u.created_at,
        COALESCE(ltv.health_score, 50) as health_score,
        COALESCE(ltv.churn_risk_score, 0) as churn_risk,
        COALESCE(ltv.total_revenue_inr, 0) as total_rev,
        COALESCE(ltv.last_active_at, u.created_at) as last_active,
        (SELECT COUNT(*) FROM scan_jobs WHERE user_id=u.id AND created_at > datetime('now','-7 days')) as scans_7d,
        (SELECT COUNT(*) FROM scan_jobs WHERE user_id=u.id AND created_at > datetime('now','-30 days')) as scans_30d
      FROM users u
      LEFT JOIN customer_ltv ltv ON ltv.user_id = u.id
      WHERE u.plan != 'FREE'
      LIMIT 500
    `).all().catch(() => ({ results: [] }));

    let analyzed = 0;
    const signals = [];

    for (const user of (users.results || [])) {
      const userSignals = detectCSSignals(user);
      for (const signal of userSignals) {
        signals.push({ ...signal, user_id: user.user_id, email: user.email });
      }
      analyzed++;
    }

    // Batch insert signals (skip duplicates within 24h)
    for (const sig of signals) {
      await db.prepare(`
        INSERT INTO cs_signals (user_id, email, signal_type, score, message, recommended_action, auto_outreach)
        SELECT ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
          SELECT 1 FROM cs_signals
          WHERE user_id=? AND signal_type=? AND created_at > datetime('now','-1 day')
        )
      `).bind(
        sig.user_id, sig.email, sig.signal_type, sig.score,
        sig.message, sig.recommended_action, sig.auto_outreach ? 1 : 0,
        sig.user_id, sig.signal_type,
      ).run().catch(() => {});
    }

    return { analyzed, signals_generated: signals.length };
  } catch (e) { return { analyzed: 0, error: e.message }; }
}

// ─── Detect CS signals for a user ────────────────────────────────────────────
function detectCSSignals(user) {
  const signals = [];
  const daysSinceActive = Math.round(
    (Date.now() - new Date(user.last_active || user.created_at).getTime()) / 86400000
  );
  const tenureDays = Math.round(
    (Date.now() - new Date(user.created_at).getTime()) / 86400000
  );

  // Churn risk signals
  if (daysSinceActive > 14 && user.scans_7d === 0) {
    signals.push({
      signal_type: 'churn_risk',
      score: 0.8,
      message: `User inactive for ${daysSinceActive} days — no scans in last 7 days`,
      recommended_action: 'Send re-engagement email with platform update highlights',
      auto_outreach: true,
    });
  }

  if (daysSinceActive > 7 && user.scans_30d < 3 && user.plan === 'STARTER') {
    signals.push({
      signal_type: 'low_engagement',
      score: 0.6,
      message: `Low scan activity: only ${user.scans_30d} scans in 30 days`,
      recommended_action: 'Send usage tips + showcase unused features',
      auto_outreach: false,
    });
  }

  // Upsell signals
  if (user.plan === 'STARTER' && user.scans_30d >= 8) {
    signals.push({
      signal_type: 'upsell_ready',
      score: 0.85,
      message: `Heavy STARTER user: ${user.scans_30d} scans/mo — hitting plan limits`,
      recommended_action: 'Offer PRO upgrade at 20% discount before limit hit',
      auto_outreach: true,
    });
  }

  if (user.plan === 'PRO' && user.scans_30d > 50) {
    signals.push({
      signal_type: 'upgrade_trigger',
      score: 0.9,
      message: `Power user: ${user.scans_30d} scans/mo — ideal ENTERPRISE candidate`,
      recommended_action: 'Book enterprise demo call + send ROI analysis',
      auto_outreach: true,
    });
  }

  // Health milestones
  if (tenureDays === 30 && user.scans_30d > 5) {
    signals.push({
      signal_type: 'milestone',
      score: 0.7,
      message: '30-day active anniversary — healthy engagement',
      recommended_action: 'Send success milestone email + request testimonial',
      auto_outreach: false,
    });
  }

  // Renewal due (monthly)
  const renewalDays = tenureDays % 30;
  if (renewalDays <= 3 && renewalDays >= 0 && user.plan !== 'FREE') {
    signals.push({
      signal_type: 'renewal_due',
      score: 0.95,
      message: `Renewal in ${3 - renewalDays} days — ensure seamless billing`,
      recommended_action: 'Verify payment method + send renewal confirmation',
      auto_outreach: false,
    });
  }

  // Power user badge
  if (user.scans_30d > 100 && user.total_rev > 10000) {
    signals.push({
      signal_type: 'power_user',
      score: 1.0,
      message: 'Power user champion — high engagement + high LTV',
      recommended_action: 'Invite to advisory board + case study opportunity',
      auto_outreach: false,
    });
  }

  return signals;
}

// ─── Get CS dashboard ─────────────────────────────────────────────────────────
export async function getCSDashboard(db) {
  if (!db) return {};
  try {
    const [signals, summary] = await Promise.all([
      db.prepare(`
        SELECT * FROM cs_signals WHERE resolved=0
        ORDER BY score DESC, created_at DESC LIMIT 50
      `).all(),
      db.prepare(`
        SELECT
          signal_type,
          COUNT(*) as count,
          AVG(score) as avg_score,
          COUNT(CASE WHEN auto_outreach=1 THEN 1 END) as auto_count
        FROM cs_signals WHERE resolved=0
        GROUP BY signal_type
      `).all(),
    ]);

    return {
      active_signals:  signals.results || [],
      signal_summary:  summary.results || [],
      churn_risks:     (signals.results || []).filter(s => s.signal_type === 'churn_risk').length,
      upsell_ready:    (signals.results || []).filter(s => s.signal_type === 'upsell_ready').length,
      auto_outreach:   (signals.results || []).filter(s => s.auto_outreach).length,
      generated_at:    new Date().toISOString(),
    };
  } catch { return {}; }
}
