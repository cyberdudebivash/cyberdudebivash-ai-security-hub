/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — Enterprise Hardening v1.0 (GOD MODE v16)
 *
 * Adds MISSING enterprise automation on top of existing salesPipeline.js:
 *
 * Endpoints:
 *   POST /api/enterprise/auto-qualify   — batch auto-qualify high ICP leads
 *   GET  /api/enterprise/org-dashboard  — org-level pipeline + revenue view
 *   POST /api/enterprise/auto-proposal  — trigger auto proposal for demo_done leads
 *   GET  /api/enterprise/health         — CRM health check + metrics
 * ═══════════════════════════════════════════════════════════════════════════
 */

function jsonOk(data)         { return Response.json({ success: true, data }); }
function jsonErr(msg, s = 400){ return Response.json({ success: false, error: msg }, { status: s }); }

// ─── POST /api/enterprise/auto-qualify ────────────────────────────────────────
// Scans all NEW leads in D1 crm_leads; auto-advances to QUALIFIED if icp_score >= 60
export async function handleAutoQualify(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);

  if (!env.DB) return jsonErr('D1 not available', 503);

  // Fetch all NEW leads with high ICP score
  const leads = await env.DB.prepare(
    `SELECT id, name, email, company, icp_score, deal_value_inr, stage
     FROM crm_leads
     WHERE stage = 'NEW' AND icp_score >= 60
     ORDER BY icp_score DESC
     LIMIT 100`
  ).all().catch(() => ({ results: [] }));

  const toQualify = leads.results || [];
  if (!toQualify.length) return jsonOk({ qualified: 0, message: 'No leads to auto-qualify' });

  const ts = new Date().toISOString();
  let qualified = 0;

  for (const lead of toQualify) {
    try {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE crm_leads SET stage='QUALIFIED', stage_updated_at=?, updated_at=? WHERE id=?`
        ).bind(ts, ts, lead.id),
        env.DB.prepare(
          `INSERT INTO crm_pipeline_log (id, lead_id, from_stage, to_stage, actor, reason, icp_score, created_at)
           VALUES (?, ?, 'NEW', 'QUALIFIED', 'auto_qualify_engine', 'ICP score >= 60, auto-advanced', ?, ?)`
        ).bind(`plg_${Date.now()}_${qualified}`, lead.id, lead.icp_score, ts),
      ]);
      qualified++;
    } catch { /* skip failed lead */ }
  }

  return jsonOk({
    qualified,
    total_checked: toQualify.length,
    qualified_leads: toQualify.slice(0, 10).map(l => ({
      id: l.id, company: l.company, email: l.email, icp_score: l.icp_score,
    })),
    message: `Auto-qualified ${qualified} leads with ICP score ≥ 60`,
    run_at: ts,
  });
}

// ─── GET /api/enterprise/org-dashboard ────────────────────────────────────────
// Org-level pipeline view: stages, deal value, ICP distribution, top leads
export async function handleOrgDashboard(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);

  if (!env.DB) {
    return jsonOk({ error: 'D1 not connected', stub: true });
  }

  const [
    stageCountsRes,
    topLeadsRes,
    totalValueRes,
    avgIcpRes,
    recentActivityRes,
  ] = await Promise.allSettled([
    env.DB.prepare(
      `SELECT stage, COUNT(*) as count, SUM(deal_value_inr) as total_value
       FROM crm_leads GROUP BY stage ORDER BY count DESC`
    ).all(),
    env.DB.prepare(
      `SELECT id, name, company, email, stage, icp_score, deal_value_inr, stage_updated_at
       FROM crm_leads WHERE stage NOT IN ('CLOSED_LOST','CHURNED')
       ORDER BY icp_score DESC LIMIT 10`
    ).all(),
    env.DB.prepare(
      `SELECT SUM(deal_value_inr) as total, COUNT(*) as total_leads
       FROM crm_leads WHERE stage NOT IN ('CLOSED_LOST','CHURNED')`
    ).first(),
    env.DB.prepare(
      `SELECT AVG(icp_score) as avg_icp FROM crm_leads WHERE stage != 'CLOSED_LOST'`
    ).first(),
    env.DB.prepare(
      `SELECT lead_id, from_stage, to_stage, actor, created_at
       FROM crm_pipeline_log ORDER BY created_at DESC LIMIT 10`
    ).all(),
  ]);

  const stageCounts   = stageCountsRes.value?.results   || [];
  const topLeads      = topLeadsRes.value?.results      || [];
  const totals        = totalValueRes.value             || {};
  const avgIcp        = avgIcpRes.value                 || {};
  const recentActivity= recentActivityRes.value?.results|| [];

  // Pipeline velocity: % in each stage
  const pipelineByStage = {};
  for (const row of stageCounts) {
    pipelineByStage[row.stage] = { count: row.count, total_value: row.total_value || 0 };
  }

  // Revenue forecast: weighted by stage conversion probability
  const STAGE_PROBABILITY = {
    NEW: 0.05, QUALIFIED: 0.15, DEMO_BOOKED: 0.25,
    DEMO_DONE: 0.40, PROPOSAL_SENT: 0.60, NEGOTIATION: 0.80, CLOSED_WON: 1.0,
  };
  let weightedRevenue = 0;
  for (const row of stageCounts) {
    const prob = STAGE_PROBABILITY[row.stage] || 0;
    weightedRevenue += (row.total_value || 0) * prob;
  }

  return jsonOk({
    summary: {
      total_pipeline_value_inr: totals.total || 0,
      total_active_leads:       totals.total_leads || 0,
      avg_icp_score:            Math.round(avgIcp.avg_icp || 0),
      weighted_revenue_forecast:Math.round(weightedRevenue),
    },
    pipeline_by_stage:  pipelineByStage,
    top_leads:          topLeads,
    recent_activity:    recentActivity,
    health: {
      needs_auto_qualify:   (pipelineByStage['NEW']?.count || 0),
      demo_done_no_proposal:(pipelineByStage['DEMO_DONE']?.count || 0),
      stale_leads:          0, // can add: leads with no activity in 14+ days
    },
    generated_at: new Date().toISOString(),
  });
}

// ─── POST /api/enterprise/auto-proposal ───────────────────────────────────────
// For all leads in DEMO_DONE stage: generate a proposal stub + advance to PROPOSAL_SENT
export async function handleAutoProposal(request, env, authCtx = {}) {
  if (!authCtx?.authenticated) return jsonErr('Authentication required', 401);

  let body = {};
  try { body = await request.json(); } catch {}

  const { lead_id } = body; // optional: target a single lead

  if (!env.DB) return jsonErr('D1 not available', 503);

  const query = lead_id
    ? `SELECT id, name, email, company, icp_score, deal_value_inr FROM crm_leads WHERE id=? AND stage='DEMO_DONE' LIMIT 1`
    : `SELECT id, name, email, company, icp_score, deal_value_inr FROM crm_leads WHERE stage='DEMO_DONE' LIMIT 20`;

  const leads = lead_id
    ? [await env.DB.prepare(query).bind(lead_id).first().catch(() => null)].filter(Boolean)
    : (await env.DB.prepare(query).all().catch(() => ({ results: [] }))).results;

  if (!leads.length) return jsonOk({ proposals_generated: 0, message: 'No leads in DEMO_DONE stage' });

  const ts        = new Date().toISOString();
  const generated = [];

  for (const lead of leads) {
    const tier = lead.icp_score >= 80 ? 'ENTERPRISE'
               : lead.icp_score >= 55 ? 'PRO'
               : 'STARTER';

    const propId = `prop_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    const proposal = {
      id:             propId,
      lead_id:        lead.id,
      title:          `Security Assessment Proposal — ${lead.company}`,
      client_name:    lead.name,
      client_email:   lead.email,
      client_company: lead.company,
      tier:           tier,
      deal_value_inr: lead.deal_value_inr || (tier === 'ENTERPRISE' ? 500000 : tier === 'PRO' ? 150000 : 50000),
      status:         'sent',
      valid_until:    new Date(Date.now() + 14 * 86400000).toISOString(),
      sections: [
        { title: 'Executive Summary',        body: `Comprehensive security assessment for ${lead.company} identifying critical risk exposures and providing actionable remediation roadmap.` },
        { title: 'Scope of Work',            body: `Full ${tier} tier engagement: domain security audit, AI threat analysis, compliance gap assessment, continuous monitoring setup.` },
        { title: 'Investment',               body: `${tier} Plan at ₹${(lead.deal_value_inr || 0).toLocaleString('en-IN')}/year. ROI: prevents average ₹2.4CR breach cost.` },
        { title: 'Timeline',                 body: 'Onboarding within 48 hours. Full deployment in 7 days. Quarterly reviews included.' },
        { title: 'Next Steps',               body: 'Sign proposal → 30-min onboarding call → API keys issued → Go live' },
      ],
      created_at: ts,
    };

    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT OR IGNORE INTO proposals (id, lead_id, title, client_name, client_email, client_company, tier_recommended, deal_value_inr, status, valid_until, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sent', ?, ?, ?)`
        ).bind(propId, lead.id, proposal.title, lead.name, lead.email, lead.company, tier, proposal.deal_value_inr, proposal.valid_until, ts, ts),
        env.DB.prepare(
          `UPDATE crm_leads SET stage='PROPOSAL_SENT', stage_updated_at=?, updated_at=? WHERE id=?`
        ).bind(ts, ts, lead.id),
        env.DB.prepare(
          `INSERT INTO crm_pipeline_log (id, lead_id, from_stage, to_stage, actor, reason, created_at)
           VALUES (?, ?, 'DEMO_DONE', 'PROPOSAL_SENT', 'auto_proposal_engine', 'Auto-proposal generated', ?)`
        ).bind(`plg_p_${Date.now()}`, lead.id, ts),
      ]);
      generated.push({ lead_id: lead.id, company: lead.company, proposal_id: propId, tier });
    } catch { /* skip */ }
  }

  return jsonOk({
    proposals_generated: generated.length,
    proposals:           generated,
    run_at:              ts,
    message:             `Generated ${generated.length} proposals and advanced leads to PROPOSAL_SENT`,
  });
}

// ─── GET /api/enterprise/health ───────────────────────────────────────────────
export async function handleEnterpriseHealth(request, env, authCtx = {}) {
  const checks = {
    db_connected:    false,
    crm_leads_table: false,
    proposals_table: false,
    pipeline_log:    false,
    kv_connected:    false,
  };

  if (env.DB) {
    checks.db_connected = true;
    try {
      await env.DB.prepare('SELECT COUNT(*) FROM crm_leads LIMIT 1').first();
      checks.crm_leads_table = true;
    } catch {}
    try {
      await env.DB.prepare('SELECT COUNT(*) FROM proposals LIMIT 1').first();
      checks.proposals_table = true;
    } catch {}
    try {
      await env.DB.prepare('SELECT COUNT(*) FROM crm_pipeline_log LIMIT 1').first();
      checks.pipeline_log = true;
    } catch {}
  }

  if (env.SECURITY_HUB_KV) {
    checks.kv_connected = true;
  }

  const allHealthy = Object.values(checks).every(Boolean);

  return Response.json({
    status:  allHealthy ? 'healthy' : 'degraded',
    checks,
    ts:      new Date().toISOString(),
  }, { status: allHealthy ? 200 : 207 });
}
