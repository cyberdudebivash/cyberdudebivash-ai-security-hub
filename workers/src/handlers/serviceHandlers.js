/**
 * CYBERDUDEBIVASH AI Security Hub — Service Catalog & Order Handlers v2.0
 * MYTHOS-Powered: All 18 services — direct scan routes + MYTHOS AI enrichment
 */

import {
  createServiceOrder,
  getReportByToken,
  listOrders,
  updateOrderStatus,
  getServiceCatalog,
  triggerManualAssessment,
  dispatchAssessment,
} from '../services/serviceOrderEngine.js';

// ── Original 10 engines ───────────────────────────────────────────────────────
import { runSSLCheck }                       from '../services/sslSecurityEngine.js';
import { generateCTIBrief, generateThreatIntelReport } from '../services/ctiReportEngine.js';
import { runComplianceAssessment }           from '../services/complianceEngine.js';
import { runAISecurityScan, runEnterpriseAIAssessment } from '../services/aiSecurityEngine.js';
import { runVulnAssessment }                 from '../services/vulnAssessmentEngine.js';
import { runThreatHuntingReview }            from '../services/threatHuntingEngine.js';
import { runAPISecurityAssessment }          from '../services/apiSecurityEngine.js';
import { runCloudSecurityAudit }             from '../services/cloudSecurityEngine.js';
// ── New 5 engines ─────────────────────────────────────────────────────────────
import { runSaaSSecurityAssessment }         from '../services/saasSecurityEngine.js';
import { runConfigReviewAssessment }         from '../services/configReviewEngine.js';
import { runAIGovernanceAssessment }         from '../services/aiGovernanceEngine.js';
import { runDevSecOpsAssessment }            from '../services/devSecOpsEngine.js';
import { runConsultationPreAssessment }      from '../services/consultationPreAssessEngine.js';
// ── MYTHOS enrichment ─────────────────────────────────────────────────────────
import { enrichAssessmentWithMYTHOS }        from '../services/mythosEnrichmentEngine.js';

function ok(data, status = 200) {
  return Response.json(data, { status });
}
function err(msg, status = 400, extra = {}) {
  return Response.json({ error: msg, ...extra }, { status });
}
async function parseBody(request) {
  try { return await request.json(); } catch { return {}; }
}

// ── GET /api/services — full catalog ─────────────────────────────────────────
export async function handleGetServiceCatalog(request, env, authCtx) {
  const url   = new URL(request.url);
  const tier  = url.searchParams.get('tier');
  const services = await getServiceCatalog(env, tier ? parseInt(tier) : null);
  return ok({
    success:   true,
    count:     services.length,
    services,
    tiers: {
      1: 'ENTRY (₹999–₹2,999)',
      2: 'SME (₹4,999–₹14,999)',
      3: 'ENTERPRISE (₹9,999–₹59,999)',
    },
    powered_by: 'CYBERDUDEBIVASH AI Security Hub™',
  });
}

// ── GET /api/services/:ref_id — single service ────────────────────────────────
export async function handleGetService(request, env, authCtx, refId) {
  const svc = await env.DB.prepare('SELECT * FROM services WHERE ref_id=? AND active=1')
    .bind(refId).first().catch(() => null);
  if (!svc) return err(`Service '${refId}' not found`, 404);
  const parseJSON = s => { try { return JSON.parse(s || '[]'); } catch { return []; } };
  return ok({
    ...svc,
    deliverables: parseJSON(svc.deliverables),
    ideal_for:    parseJSON(svc.ideal_for),
  });
}

// ── POST /api/services/orders — create order ──────────────────────────────────
export async function handleCreateOrder(request, env, authCtx, ctx) {
  const body = await parseBody(request);
  const result = await createServiceOrder(env, body);
  if (result.error) return err(result.error, result.status || 400);

  // If automated engine, background-dispatch with ctx
  if (result.auto_started && body.ref_id) {
    const svc = await env.DB.prepare('SELECT automated_engine FROM services WHERE ref_id=?')
      .bind(body.ref_id).first().catch(() => null);
    if (svc?.automated_engine && ctx?.waitUntil) {
      const inputs = {
        ...(typeof body.assessment_inputs === 'string' ? JSON.parse(body.assessment_inputs || '{}') : (body.assessment_inputs || {})),
        domain:         body.target_domain,
        target_domain:  body.target_domain,
        industry:       body.target_industry || 'General',
      };
      const promise = dispatchAssessment(env, svc.automated_engine, inputs, result.order_id)
        .catch(e => console.error('[ServiceHandlers] dispatch error:', e.message));
      ctx.waitUntil(promise);
    }
  }

  return ok(result, 201);
}

// ── GET /api/services/report/:token — get report by token ────────────────────
export async function handleGetReport(request, env, authCtx, token) {
  const result = await getReportByToken(env, token);
  if (result.error) return err(result.error, result.status || 404);
  return ok(result);
}

// ── GET /api/services/orders — admin: list orders ─────────────────────────────
export async function handleListOrders(request, env, authCtx) {
  if (!authCtx?.isAdmin && authCtx?.tier !== 'ENTERPRISE') {
    return err('Admin access required', 403);
  }
  const url    = new URL(request.url);
  const orders = await listOrders(env, {
    status: url.searchParams.get('status'),
    ref_id: url.searchParams.get('ref_id'),
    email:  url.searchParams.get('email'),
    limit:  url.searchParams.get('limit') || 50,
    offset: url.searchParams.get('offset') || 0,
  });
  return ok({ success: true, count: orders.length, orders });
}

// ── PUT /api/services/orders/:id/status — admin: update order ─────────────────
export async function handleUpdateOrderStatus(request, env, authCtx, orderId) {
  if (!authCtx?.isAdmin) return err('Admin access required', 403);
  const body = await parseBody(request);
  const result = await updateOrderStatus(env, orderId, body.status, body.admin_notes);
  if (result.error) return err(result.error, 400);
  return ok({ success: true, order_id: orderId, status: body.status });
}

// ── POST /api/services/orders/:id/trigger — admin: trigger assessment ─────────
export async function handleTriggerAssessment(request, env, authCtx, orderId, ctx) {
  if (!authCtx?.isAdmin && authCtx?.tier !== 'ENTERPRISE') {
    return err('Admin access required', 403);
  }
  const result = await triggerManualAssessment(env, orderId, ctx);
  if (result.error) return err(result.error, result.status || 400);
  return ok(result);
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT SCAN ENDPOINTS (instant, no order required — for API/demo access)
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/scan/ssl — instant SSL check ────────────────────────────────────
export async function handleSSLScan(request, env, authCtx) {
  const body   = await parseBody(request);
  const domain = body.domain || body.target;
  if (!domain) return err('domain is required', 400);

  const report = await runSSLCheck(env, domain, null);
  // Promote nested executive_summary fields to top level for API consumers
  const risk_score = report?.executive_summary?.risk_score ?? null;
  const risk_level = report?.executive_summary?.risk_level ?? null;
  return ok({ success: true, service: 'CDB-SSL-001', risk_score, risk_level, ...report });
}

// ── POST /api/scan/cti-brief — instant CTI brief ──────────────────────────────
export async function handleCTIBriefScan(request, env, authCtx) {
  const body     = await parseBody(request);
  const industry = body.industry || 'General';
  const report   = await generateCTIBrief(env, industry, null);
  return ok({ success: true, service: 'CDB-CTI-PRO-001', ...report });
}

// ── POST /api/scan/threat-intel-report — CTI report ───────────────────────────
export async function handleThreatIntelReport(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  const report = await generateThreatIntelReport(env, body.domain || '', body.industry || 'General', null);
  return ok({ success: true, service: 'CDB-TIR-001', ...report });
}

// ── POST /api/scan/compliance — compliance assessment ─────────────────────────
export async function handleComplianceScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  const report = await runComplianceAssessment(env, body, null);
  return ok({ success: true, service: 'CDB-COMP-001', ...report });
}

// ── POST /api/scan/ai-security — AI security scan ────────────────────────────
export async function handleAISecurityScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body     = await parseBody(request);
  let report     = await runAISecurityScan(env, body, null);
  // MYTHOS enrichment
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'AI Security Scan', service_ref: 'CDB-AISS-001',
      target: body.domain || body.target || '', sector: body.industry || 'Technology',
      tier: authCtx?.tier || 'PRO',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-AISS-001', ...report });
}

// ── POST /api/scan/ai-security-enterprise — enterprise AI assessment ──────────
export async function handleEnterpriseAIScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && authCtx?.tier !== 'ENTERPRISE') {
    return Response.json({
      error:       'ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  const report = await runEnterpriseAIAssessment(env, body, null);
  return ok({ success: true, service: 'CDB-AISA-001', ...report });
}

// ── POST /api/scan/vuln-assessment — vulnerability assessment ─────────────────
export async function handleVulnAssessmentScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  const domain = body.domain || body.target;
  if (!domain) return err('domain is required', 400);
  const report = await runVulnAssessment(env, domain, null);
  return ok({ success: true, service: 'CDB-VA-001', ...report });
}

// ── POST /api/scan/threat-hunting — threat hunting readiness ──────────────────
export async function handleThreatHuntingScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  const report = await runThreatHuntingReview(env, body, null);
  return ok({ success: true, service: 'CDB-THR-001', ...report });
}

// ── POST /api/scan/api-security — API security assessment ─────────────────────
export async function handleAPISecurityScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body    = await parseBody(request);
  const apiUrl  = body.api_base_url || body.domain || body.url;
  if (!apiUrl) return err('api_base_url is required', 400);
  const report  = await runAPISecurityAssessment(env, apiUrl, null, body);
  return ok({ success: true, service: 'CDB-APISEC-001', ...report });
}

// ── POST /api/scan/cloud-security — cloud security audit ──────────────────────
export async function handleCloudSecurityScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body     = await parseBody(request);
  let report     = await runCloudSecurityAudit(env, body, null);
  // MYTHOS enrichment
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'Cloud Security Audit', service_ref: 'CDB-CSAU-001',
      target: body.domain || body.cloud_provider || '', sector: body.industry || 'Technology',
      tier: authCtx?.tier || 'PRO',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-CSAU-001', ...report });
}

// ═══════════════════════════════════════════════════════════════════════════════
// NEW ENGINES — formerly manual services, now MYTHOS-automated
// ═══════════════════════════════════════════════════════════════════════════════

// ── POST /api/scan/saas-security — SaaS security assessment ──────────────────
export async function handleSaaSSecurityScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  let report   = await runSaaSSecurityAssessment(env, body, null);
  // MYTHOS enrichment
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'SaaS Security Assessment', service_ref: 'CDB-SAASSEC-001',
      target: body.domain || body.target_domain || '', sector: body.industry || 'Technology', tier: authCtx?.tier || 'PRO',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-SAASSEC-001', ...report });
}

// ── POST /api/scan/config-review — security configuration review ──────────────
export async function handleConfigReviewScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    return Response.json({
      error:       'PRO or ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  let report   = await runConfigReviewAssessment(env, body, null);
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'Security Configuration Review', service_ref: 'CDB-SCRA-001',
      target: body.company || body.organization || '', sector: body.industry || 'Technology', tier: authCtx?.tier || 'PRO',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-SCRA-001', ...report });
}

// ── POST /api/scan/ai-governance — AI governance assessment ───────────────────
export async function handleAIGovernanceScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && authCtx?.tier !== 'ENTERPRISE') {
    return Response.json({
      error:       'ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  let report   = await runAIGovernanceAssessment(env, body, null);
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'AI Governance Consulting', service_ref: 'CDB-AIGOV-001',
      target: body.company || body.organization || '', sector: body.industry || 'Technology', tier: 'ENTERPRISE',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-AIGOV-001', ...report });
}

// ── POST /api/scan/devsecops — DevSecOps security optimization ────────────────
export async function handleDevSecOpsScan(request, env, authCtx) {
  if (!authCtx?.isAdmin && authCtx?.tier !== 'ENTERPRISE') {
    return Response.json({
      error:       'ENTERPRISE plan required',
      upgrade_url: 'https://tools.cyberdudebivash.com/#pricing',
    }, { status: 403 });
  }
  const body   = await parseBody(request);
  let report   = await runDevSecOpsAssessment(env, body, null);
  try {
    report = await enrichAssessmentWithMYTHOS(env, {
      report, findings: report.findings || [],
      service_name: 'DevSecOps Security Optimization', service_ref: 'CDB-DSO-001',
      target: body.company || body.organization || '', sector: body.industry || 'Technology', tier: 'ENTERPRISE',
    });
  } catch {}
  return ok({ success: true, service: 'CDB-DSO-001', ...report });
}

// ── POST /api/scan/consultation-prep — consultation pre-assessment brief ──────
export async function handleConsultationPrep(request, env, authCtx) {
  const body       = await parseBody(request);
  const serviceRef = body.service_ref || 'CDB-CONSULT-001';
  const allowed    = ['CDB-CONSULT-001','CDB-AISEC-001','CDB-TI-001','CDB-SHC-001'];
  if (!allowed.includes(serviceRef)) {
    return err(`service_ref must be one of: ${allowed.join(', ')}`, 400);
  }
  body._service_ref = serviceRef;
  const report = await runConsultationPreAssessment(env, body, null, serviceRef);
  return ok({ success: true, service: serviceRef, ...report });
}
