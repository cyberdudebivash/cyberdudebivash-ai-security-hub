/**
 * CYBERDUDEBIVASH AI Security Hub — RevOS Handler v23.0
 * Unified HTTP handler for all Revenue Operating System routes
 *
 * Routes registered in index.js under /api/revos/*:
 *
 * PHASE 1 — MRR/Revenue
 *   GET  /api/revos/dashboard        Full RevOS KPI dashboard
 *   GET  /api/revos/mrr              Live MRR/ARR snapshot
 *   POST /api/revos/mrr/snapshot     Force write daily snapshot (admin)
 *
 * PHASE 2 — Enterprise CRM
 *   GET  /api/revos/crm/pipeline     Full deal pipeline
 *   POST /api/revos/crm/lead         Capture + ICP score lead
 *   POST /api/revos/crm/deal         Create/update deal stage
 *   POST /api/revos/crm/propose      Generate proposal
 *   GET  /api/revos/crm/proposals    List proposals
 *   GET  /api/revos/crm/forecast     90-day revenue forecast
 *
 * PHASE 3 — API Economy
 *   GET  /api/revos/developer        Developer portal data
 *   GET  /api/revos/api-usage        API key usage details
 *   GET  /api/revos/api-analytics    Platform-wide API analytics (admin)
 *
 * PHASE 4 — Defense Pipeline
 *   GET  /api/revos/product-pipeline Pipeline status
 *   POST /api/revos/product-pipeline/trigger  Trigger for CVE IDs
 *
 * PHASE 5 — MSSP
 *   GET  /api/revos/mssp/dashboard   MSSP partner dashboard
 *   POST /api/revos/mssp/client      Onboard MSSP client
 *   PUT  /api/revos/mssp/client/:id  Update client
 *   GET  /api/revos/mssp/billing     MSSP billing summary
 *
 * PHASE 6 — Customer Success
 *   GET  /api/revos/cs/dashboard     CS signals dashboard
 *   POST /api/revos/cs/analyze       Run CS analysis (admin/cron)
 *   POST /api/revos/cs/resolve/:id   Mark signal resolved
 *
 * PHASE 7 — CISO Reports
 *   POST /api/revos/ciso-report      Generate report
 *   GET  /api/revos/ciso-report/list List reports
 *   GET  /api/revos/ciso-report/:id  Get report
 *
 * PHASE 8 — Admin/Scaling
 *   GET  /api/revos/audit-log        Audit log
 *   GET  /api/revos/health           RevOS health check
 */

import { getRevOSDashboard, computeLiveMRR, writeMRRSnapshot, updateCustomerLTV, recordChurn } from '../services/revos/mrrEngine.js';
import { scoreICP, generateProposalContent, getPipelineMetrics, revenueForecast90d } from '../services/revos/salesEngine.js';
import { getAPIUsage, getDevPortalData, recordAPICall, queueCVEsForGeneration, runProductPipeline } from '../services/revos/apiEconomyEngine.js';
import { getMSSPDashboard, onboardMSSPClient, runCSAnalysis, getCSDashboard } from '../services/revos/msspEngine.js';
import { generateCISOReport } from '../services/revos/cisoReportEngine.js';
import { isOwner, isRealUser } from '../auth/middleware.js';

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400, code = 'ERR') {
  return json({ success: false, error: msg, code }, status);
}

async function parseBody(req) {
  try { return await req.json(); } catch { return {}; }
}

// RevOS PHASE 1/2/4/6/7/8 endpoints expose the platform OWNER's private business
// intelligence — MRR/ARR/churn/LTV/CAC, the full CRM deal pipeline, every customer
// proposal, platform-wide API analytics, and executive CISO reports. These are
// single-tenant owner tooling (see the /api/proposals + /api/keys/:id/usage twins,
// which are already isOwner-guarded). Historically this handler gated them on a weak
// `role==='admin'` check that the real owner login never satisfies (owner is isAdmin
// via ADMIN_KEY or an OWNER_EMAILS match), so most were effectively open to any
// caller. requireOwner() closes that with the canonical guard.
function requireOwner(authCtx, env) {
  return isOwner(authCtx, env) ? null : err('Owner access required', 403, 'FORBIDDEN');
}

// ─── Main RevOS route dispatcher ─────────────────────────────────────────────
export async function handleRevOS(request, env, authCtx, path, method) {
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const db = env?.DB;
  const kv = env?.SECURITY_HUB_KV;

  // ── PHASE 1: Revenue Dashboard ───────────────────────────────────────────
  if (path === '/api/revos/dashboard' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const data = await getRevOSDashboard(db);
    return json(data);
  }

  if (path === '/api/revos/mrr' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const live = await computeLiveMRR(db);
    return json({ success: true, ...live, generated_at: new Date().toISOString() });
  }

  if (path === '/api/revos/mrr/snapshot' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const result = await writeMRRSnapshot(db);
    return json({ success: true, result });
  }

  // ── PHASE 2: Enterprise CRM ──────────────────────────────────────────────
  if (path === '/api/revos/crm/pipeline' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const metrics = await getPipelineMetrics(db);
    return json({ success: true, ...metrics });
  }

  if (path === '/api/revos/crm/lead' && method === 'POST') {
    const body = await parseBody(request);
    if (!body.contact_email) return err('contact_email required');

    const icpScore = scoreICP(body);

    // Save to deal_pipeline
    const dealId = `deal-${Date.now().toString(36)}`;
    if (db) {
      await db.prepare(`
        INSERT INTO deal_pipeline
          (id, company, contact_name, contact_email, contact_phone, contact_title,
           company_size, industry, source, stage, icp_score, notes, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'lead', ?, ?, '[]')
      `).bind(
        dealId,
        body.company || 'Unknown',
        body.contact_name || '',
        body.contact_email,
        body.contact_phone || '',
        body.contact_title || '',
        body.company_size || '',
        body.industry || '',
        body.source || 'web',
        icpScore.total_score,
        body.message || body.notes || '',
      ).run().catch(() => {});

      // Save ICP score
      await db.prepare(`
        INSERT INTO icp_scores (deal_id, email, company, total_score, tier,
          industry_fit, size_fit, tech_stack_fit, pain_signal, budget_signal, urgency_signal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        dealId, body.contact_email, body.company || '',
        icpScore.total_score, icpScore.tier,
        icpScore.industry_fit, icpScore.size_fit, icpScore.tech_stack_fit,
        icpScore.pain_signal, icpScore.budget_signal, icpScore.urgency_signal,
      ).run().catch(() => {});
    }

    return json({
      success:  true,
      deal_id:  dealId,
      icp:      icpScore,
      qualified: icpScore.tier === 'A' || icpScore.tier === 'B',
      message:  icpScore.tier === 'A'
        ? '🔥 A-tier lead — schedule demo within 24 hours'
        : icpScore.tier === 'B'
        ? '✅ Qualified lead — add to nurture sequence'
        : 'Lead captured — low ICP fit, add to long-term nurture',
    });
  }

  if (path === '/api/revos/crm/deal' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const body = await parseBody(request);
    if (!body.deal_id && !body.contact_email) return err('deal_id or contact_email required');

    if (db && body.deal_id) {
      const updates = [];
      const vals = [];
      if (body.stage)           { updates.push('stage=?');           vals.push(body.stage); }
      if (body.deal_value_inr)  { updates.push('deal_value_inr=?');  vals.push(body.deal_value_inr); }
      if (body.probability_pct) { updates.push('probability_pct=?'); vals.push(body.probability_pct); }
      if (body.next_action)     { updates.push('next_action=?');     vals.push(body.next_action); }
      if (body.notes)           { updates.push('notes=?');           vals.push(body.notes); }
      updates.push('updated_at=datetime(\'now\')');
      vals.push(body.deal_id);

      if (updates.length > 1) {
        await db.prepare(`UPDATE deal_pipeline SET ${updates.join(',')} WHERE id=?`)
          .bind(...vals).run().catch(() => {});
      }
    }
    return json({ success: true, deal_id: body.deal_id });
  }

  if (path === '/api/revos/crm/propose' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const body = await parseBody(request);
    if (!body.company || !body.contact_email) return err('company and contact_email required');

    const content = generateProposalContent(body, body.type || 'enterprise');
    const propId = content.proposal_id;

    if (db) {
      await db.prepare(`
        INSERT INTO proposals
          (id, deal_id, type, company, contact_email, contact_name,
           value_inr, plan, status, content_json, valid_until)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
      `).bind(
        propId, body.deal_id || null, body.type || 'enterprise',
        body.company, body.contact_email, body.contact_name || '',
        body.value_inr || content.price_monthly, body.plan || 'ENTERPRISE',
        JSON.stringify(content),
        content.valid_until,
      ).run().catch(() => {});
    }

    return json({ success: true, proposal_id: propId, proposal: content });
  }

  if (path === '/api/revos/crm/proposals' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const rows = db ? await db.prepare(
      `SELECT id, type, company, contact_email, value_inr, status, created_at, valid_until
       FROM proposals ORDER BY created_at DESC LIMIT 50`
    ).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, proposals: rows.results || [], total: rows.results?.length || 0 });
  }

  if (path === '/api/revos/crm/forecast' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const live = await computeLiveMRR(db);
    const forecast = await revenueForecast90d(db, live.mrr_inr);
    return json({ success: true, current_mrr: live.mrr_inr, forecast });
  }

  // ── PHASE 3: API Economy ─────────────────────────────────────────────────
  if (path === '/api/revos/developer' && method === 'GET') {
    if (!isRealUser(authCtx)) return err('Authentication required', 401);
    const data = await getDevPortalData(db, authCtx.userId);
    return json({ success: true, ...data });
  }

  if (path === '/api/revos/api-usage' && method === 'GET') {
    if (!isRealUser(authCtx)) return err('Authentication required', 401);
    const url = new URL(request.url);
    const period = url.searchParams.get('period');
    // BOLA guard: a caller may only read usage for a key they own. The owner may
    // inspect any key via ?key_id=…; everyone else is forced to their own key,
    // ignoring an attacker-supplied key_id (was: keyId || authCtx.apiKeyId — and
    // apiKeyId is never set on the auth context, so the query param was the ONLY
    // input, letting any authenticated user read another tenant's key usage/cost).
    const ownKeyId = authCtx.keyId ?? authCtx.key_id ?? null;
    let keyId = ownKeyId;
    if (isOwner(authCtx, env)) {
      keyId = url.searchParams.get('key_id') || keyId;
    } else {
      const requested = url.searchParams.get('key_id');
      if (requested && requested !== ownKeyId) {
        return err('You can only view usage for your own API key', 403, 'FORBIDDEN');
      }
    }
    if (!keyId) return err('No API key in context — call with an API key or specify a key_id you own', 400);
    const usage = await getAPIUsage(db, keyId, period);
    return json({ success: true, usage });
  }

  if (path === '/api/revos/api-analytics' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const period = new URL(request.url).searchParams.get('period') || new Date().toISOString().slice(0, 7);
    const [totalCalls, topEndpoints, topUsers] = await Promise.all([
      db?.prepare(`SELECT COUNT(*) as calls, SUM(cost_paise) as revenue FROM api_billing WHERE billing_period=?`)
        .bind(period).first().catch(() => null),
      db?.prepare(`SELECT endpoint, COUNT(*) as calls, AVG(response_ms) as avg_ms FROM api_billing WHERE billing_period=? GROUP BY endpoint ORDER BY calls DESC LIMIT 10`)
        .bind(period).all().catch(() => ({ results: [] })),
      db?.prepare(`SELECT user_id, COUNT(*) as calls FROM api_billing WHERE billing_period=? AND user_id IS NOT NULL GROUP BY user_id ORDER BY calls DESC LIMIT 10`)
        .bind(period).all().catch(() => ({ results: [] })),
    ]);
    return json({
      success: true, period,
      total_calls: totalCalls?.calls || 0,
      revenue_paise: totalCalls?.revenue || 0,
      revenue_inr: ((totalCalls?.revenue || 0) / 100).toFixed(2),
      top_endpoints: topEndpoints?.results || [],
      top_users: topUsers?.results || [],
    });
  }

  // ── PHASE 4: Defense Product Pipeline ───────────────────────────────────
  if (path === '/api/revos/product-pipeline' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const rows = db ? await db.prepare(
      `SELECT * FROM product_pipeline ORDER BY created_at DESC LIMIT 50`
    ).all().catch(() => ({ results: [] })) : { results: [] };

    const summary = {
      queued:     (rows.results || []).filter(r => r.status === 'queued').length,
      generating: (rows.results || []).filter(r => r.status === 'generating').length,
      published:  (rows.results || []).filter(r => r.status === 'published').length,
      failed:     (rows.results || []).filter(r => r.status === 'failed').length,
    };
    return json({ success: true, summary, pipeline: rows.results || [] });
  }

  if (path === '/api/revos/product-pipeline/trigger' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const body = await parseBody(request);
    const cveIds = body.cve_ids || [];
    if (!cveIds.length) return err('cve_ids array required');

    const results = [];
    for (const cveId of cveIds.slice(0, 10)) { // max 10 per request
      const result = await runProductPipeline(db, cveId);
      results.push({ cve_id: cveId, ...result });
    }
    return json({ success: true, results });
  }

  // ── PHASE 5: MSSP ────────────────────────────────────────────────────────
  if (path === '/api/revos/mssp/dashboard' && method === 'GET') {
    if (!isRealUser(authCtx)) return err('Authentication required', 401);
    const data = await getMSSPDashboard(db, authCtx.userId);
    return json({ success: true, ...data });
  }

  if (path === '/api/revos/mssp/client' && method === 'POST') {
    if (!isRealUser(authCtx)) return err('Authentication required', 401);
    const body = await parseBody(request);
    if (!body.client_name || !body.client_email) return err('client_name and client_email required');
    const result = await onboardMSSPClient(db, authCtx.userId, body);
    return json(result);
  }

  if (path.startsWith('/api/revos/mssp/client/') && method === 'PUT') {
    if (!isRealUser(authCtx)) return err('Authentication required', 401);
    const clientId = path.replace('/api/revos/mssp/client/', '').split('/')[0];
    const body = await parseBody(request);
    if (db && clientId) {
      await db.prepare(`
        UPDATE mssp_clients SET
          health_score = COALESCE(?, health_score),
          risk_score   = COALESCE(?, risk_score),
          status       = COALESCE(?, status),
          notes        = COALESCE(?, notes),
          updated_at   = datetime('now')
        WHERE id=? AND mssp_user_id=?
      `).bind(body.health_score || null, body.risk_score || null,
               body.status || null, body.notes || null,
               clientId, authCtx.userId).run().catch(() => {});
    }
    return json({ success: true, client_id: clientId });
  }

  // ── PHASE 6: Customer Success ────────────────────────────────────────────
  if (path === '/api/revos/cs/dashboard' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const data = await getCSDashboard(db);
    return json({ success: true, ...data });
  }

  if (path === '/api/revos/cs/analyze' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const result = await runCSAnalysis(db);
    return json({ success: true, ...result });
  }

  if (path.startsWith('/api/revos/cs/resolve/') && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const sigId = path.replace('/api/revos/cs/resolve/', '').split('/')[0];
    if (db) {
      await db.prepare(`UPDATE cs_signals SET resolved=1, resolved_at=datetime('now') WHERE id=?`)
        .bind(sigId).run().catch(() => {});
    }
    return json({ success: true, signal_id: sigId });
  }

  // ── PHASE 7: CISO Reports ────────────────────────────────────────────────
  if (path === '/api/revos/ciso-report' && method === 'POST') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const body = await parseBody(request);
    const result = await generateCISOReport(db, kv, {
      reportType: body.report_type || 'monthly',
      userId:     authCtx?.userId,
      clientId:   body.client_id,
      period:     body.period,
    });
    return json(result);
  }

  if (path === '/api/revos/ciso-report/list' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const rows = db ? await db.prepare(
      `SELECT id, report_type, period, status, created_at FROM ciso_reports
       ORDER BY created_at DESC LIMIT 20`
    ).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, reports: rows.results || [] });
  }

  if (path.startsWith('/api/revos/ciso-report/') && method === 'GET') {
    // BOLA guard: CISO reports embed platform-wide financials (MRR/ARR/churn) and
    // executive intelligence. IDs are timestamp-derived and enumerable, so this must
    // be owner-only — previously any anonymous caller could read any report by id.
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const reportId = path.replace('/api/revos/ciso-report/', '').split('/')[0];
    if (reportId === 'list') return json({ success: false, error: 'Not found' }, 404);
    const row = db ? await db.prepare(`SELECT * FROM ciso_reports WHERE id=?`)
      .bind(reportId).first().catch(() => null) : null;
    if (!row) return err('Report not found', 404);
    const reportData = row.data_snapshot ? JSON.parse(row.data_snapshot) : {};
    return json({ success: true, report: reportData });
  }

  // ── PHASE 8: Admin/Scaling ───────────────────────────────────────────────
  if (path === '/api/revos/audit-log' && method === 'GET') {
    const gate = requireOwner(authCtx, env); if (gate) return gate;
    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
    const rows = db ? await db.prepare(
      `SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?`
    ).bind(limit).all().catch(() => ({ results: [] })) : { results: [] };
    return json({ success: true, logs: rows.results || [] });
  }

  if (path === '/api/revos/health' && method === 'GET') {
    const checks = {
      db:            !!db,
      kv:            !!kv,
      version:       '23.0.0',
      phases:        ['mrr','crm','api_economy','defense_pipeline','mssp','cs','ciso','scaling'],
      generated_at:  new Date().toISOString(),
    };
    if (db) {
      try {
        await db.prepare('SELECT 1').first();
        checks.db_latency = 'ok';
      } catch { checks.db_latency = 'error'; }
    }
    return json({ success: true, revos: checks });
  }

  return err('RevOS route not found', 404, 'NOT_FOUND');
}
