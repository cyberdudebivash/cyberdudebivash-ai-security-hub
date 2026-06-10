/**
 * CYBERDUDEBIVASH AI Security Hub — Service Order Engine v1.0
 * Handles: order creation, payment webhooks, report token generation,
 *          automated assessment dispatch, report retrieval
 */

import { runSSLCheck }                  from './sslSecurityEngine.js';
import { generateCTIBrief, generateThreatIntelReport } from './ctiReportEngine.js';
import { runComplianceAssessment }      from './complianceEngine.js';
import { runAISecurityScan, runEnterpriseAIAssessment } from './aiSecurityEngine.js';
import { runVulnAssessment }            from './vulnAssessmentEngine.js';
import { runThreatHuntingReview }       from './threatHuntingEngine.js';
import { runAPISecurityAssessment }     from './apiSecurityEngine.js';
import { runCloudSecurityAudit }        from './cloudSecurityEngine.js';

// ── Engine dispatch map ───────────────────────────────────────────────────────
const ENGINE_DISPATCH = {
  ssl:                   (env, inputs, orderId) => runSSLCheck(env, inputs.domain || inputs.target_domain, orderId),
  cti_brief:             (env, inputs, orderId) => generateCTIBrief(env, inputs.industry || 'General', orderId),
  cti_report:            (env, inputs, orderId) => generateThreatIntelReport(env, inputs.domain || '', inputs.industry || 'General', orderId),
  compliance:            (env, inputs, orderId) => runComplianceAssessment(env, inputs, orderId),
  ai_security:           (env, inputs, orderId) => runAISecurityScan(env, inputs, orderId),
  ai_security_enterprise:(env, inputs, orderId) => runEnterpriseAIAssessment(env, inputs, orderId),
  vuln_assessment:       (env, inputs, orderId) => runVulnAssessment(env, inputs.domain || inputs.target_domain, orderId),
  threat_hunting:        (env, inputs, orderId) => runThreatHuntingReview(env, inputs, orderId),
  api_security:          (env, inputs, orderId) => runAPISecurityAssessment(env, inputs.api_base_url || inputs.domain, orderId),
  cloud_security:        (env, inputs, orderId) => runCloudSecurityAudit(env, inputs, orderId),
};

// ── Token generation ──────────────────────────────────────────────────────────
function generateReportToken() {
  // 32-byte hex token
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Create order ──────────────────────────────────────────────────────────────
export async function createServiceOrder(env, body) {
  const {
    ref_id, customer_name, customer_email, customer_phone,
    company, company_size, target_domain, target_industry,
    requirements, assessment_inputs, payment_method = 'razorpay',
    source = 'api', utm_source,
  } = body;

  if (!ref_id || !customer_name || !customer_email) {
    return { error: 'ref_id, customer_name, customer_email are required', status: 400 };
  }

  // Validate service exists
  const svc = await env.DB.prepare('SELECT * FROM services WHERE ref_id=? AND active=1')
    .bind(ref_id).first().catch(() => null);
  if (!svc) {
    return { error: `Service '${ref_id}' not found or inactive`, status: 404 };
  }

  // Merge assessment_inputs with top-level fields
  const inputs = {
    ...(typeof assessment_inputs === 'string' ? JSON.parse(assessment_inputs || '{}') : (assessment_inputs || {})),
    domain:          target_domain,
    target_domain,
    industry:        target_industry || 'General',
    target_industry: target_industry || 'General',
  };

  const orderId     = crypto.randomUUID();
  const reportToken = generateReportToken();

  await env.DB.prepare(
    `INSERT INTO service_orders
     (id, ref_id, customer_name, customer_email, customer_phone,
      company, company_size, target_domain, target_industry,
      requirements, assessment_inputs, payment_status, payment_method,
      payment_amount, order_status, report_token, source, utm_source)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    orderId, ref_id, customer_name, customer_email, customer_phone || null,
    company || null, company_size || null, target_domain || null, target_industry || 'General',
    requirements || null, JSON.stringify(inputs),
    'pending', payment_method,
    svc.price_inr, 'new', reportToken,
    source, utm_source || null
  ).run();

  // Auto-dispatch if service is automated (or skip payment for demo)
  let autoStarted = false;
  if (svc.delivery_type === 'automated' && svc.automated_engine) {
    autoStarted = true;
    // Fire-and-forget (no ctx.waitUntil here — caller wraps with ctx if available)
    dispatchAssessment(env, svc.automated_engine, inputs, orderId).catch(e => {
      console.error('[ServiceOrder] Auto-dispatch error:', svc.automated_engine, e.message);
    });
  }

  return {
    success:        true,
    order_id:       orderId,
    ref_id,
    service_name:   svc.name,
    delivery_type:  svc.delivery_type,
    price_inr:      svc.price_inr,
    price_usd:      svc.price_usd,
    report_token:   reportToken,          // share this to retrieve report
    order_status:   autoStarted ? 'in_progress' : 'new',
    payment_status: 'pending',
    auto_started:   autoStarted,
    message:        autoStarted
      ? 'Assessment started. Retrieve your report at /api/services/report/{report_token} in a few seconds.'
      : `Order created. Manual service — our team will contact ${customer_email} within ${svc.delivery_hours}h.`,
  };
}

// ── Dispatch the right engine ─────────────────────────────────────────────────
export async function dispatchAssessment(env, engineName, inputs, orderId) {
  const engine = ENGINE_DISPATCH[engineName];
  if (!engine) {
    console.error('[ServiceOrder] Unknown engine:', engineName);
    return null;
  }

  // Mark as running
  try {
    await env.DB.prepare(
      `UPDATE service_orders SET order_status='in_progress', updated_at=datetime('now') WHERE id=?`
    ).bind(orderId).run();
  } catch {}

  try {
    const result = await engine(env, inputs, orderId);
    return result;
  } catch (e) {
    console.error('[ServiceOrder] Engine error:', engineName, e.message);
    try {
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='failed', admin_notes=?, updated_at=datetime('now') WHERE id=?`
      ).bind(`Engine error: ${e.message}`, orderId).run();
    } catch {}
    return null;
  }
}

// ── Retrieve report by token ──────────────────────────────────────────────────
export async function getReportByToken(env, token) {
  if (!token || token.length < 32) {
    return { error: 'Invalid report token', status: 400 };
  }

  const order = await env.DB.prepare(
    `SELECT so.*, s.name as service_name, s.delivery_type, s.automated_engine
     FROM service_orders so
     LEFT JOIN services s ON so.ref_id = s.ref_id
     WHERE so.report_token = ?`
  ).bind(token).first().catch(() => null);

  if (!order) return { error: 'Report not found', status: 404 };

  // Get assessment results
  const assessment = await env.DB.prepare(
    `SELECT * FROM service_assessments WHERE order_id = ? ORDER BY created_at DESC LIMIT 1`
  ).bind(order.id).first().catch(() => null);

  // Get deliverables
  const deliverables = await env.DB.prepare(
    `SELECT * FROM service_deliverables WHERE order_id = ? ORDER BY created_at DESC`
  ).bind(order.id).all().catch(() => ({ results: [] }));

  // Parse JSON fields safely
  const parseJSON = (s) => { try { return JSON.parse(s || '{}'); } catch { return {}; } };

  return {
    order: {
      id:             order.id,
      ref_id:         order.ref_id,
      service_name:   order.service_name,
      customer_name:  order.customer_name,
      target_domain:  order.target_domain,
      order_status:   order.order_status,
      payment_status: order.payment_status,
      created_at:     order.created_at,
      delivery_type:  order.delivery_type,
    },
    assessment: assessment ? {
      id:               assessment.id,
      status:           assessment.status,
      risk_score:       assessment.risk_score,
      risk_grade:       assessment.risk_grade,
      findings_count:   assessment.findings_count,
      critical_count:   assessment.critical_count,
      high_count:       assessment.high_count,
      started_at:       assessment.started_at,
      completed_at:     assessment.completed_at,
      report:           parseJSON(assessment.report_json),
      findings:         parseJSON(assessment.findings_json),
      recommendations:  parseJSON(assessment.recommendations_json),
    } : null,
    deliverables: deliverables.results || [],
    status:       order.order_status,
    message:      order.order_status === 'delivered' ? 'Report ready'
                : order.order_status === 'in_progress' ? 'Assessment running — check back in a moment'
                : order.order_status === 'failed'      ? 'Assessment failed — our team has been notified'
                : 'Order received — processing pending',
  };
}

// ── List orders (admin) ───────────────────────────────────────────────────────
export async function listOrders(env, filters = {}) {
  const { status, ref_id, email, limit = 50, offset = 0 } = filters;
  let query = `SELECT so.*, s.name as service_name FROM service_orders so
               LEFT JOIN services s ON so.ref_id = s.ref_id WHERE 1=1`;
  const params = [];

  if (status) { query += ' AND so.order_status=?'; params.push(status); }
  if (ref_id) { query += ' AND so.ref_id=?'; params.push(ref_id); }
  if (email)  { query += ' AND so.customer_email=?'; params.push(email); }

  query += ` ORDER BY so.created_at DESC LIMIT ? OFFSET ?`;
  params.push(Math.min(Number(limit), 200), Number(offset));

  const rows = await env.DB.prepare(query).bind(...params).all().catch(() => ({ results: [] }));
  return rows.results || [];
}

// ── Update order status (admin) ───────────────────────────────────────────────
export async function updateOrderStatus(env, orderId, newStatus, adminNotes = null) {
  const result = await env.DB.prepare(
    `UPDATE service_orders SET order_status=?, admin_notes=COALESCE(?, admin_notes), updated_at=datetime('now') WHERE id=?`
  ).bind(newStatus, adminNotes, orderId).run().catch(e => ({ error: e.message }));
  return result;
}

// ── Get service catalog ───────────────────────────────────────────────────────
export async function getServiceCatalog(env, tier = null) {
  let query = 'SELECT * FROM services WHERE active=1';
  const params = [];
  if (tier) { query += ' AND tier=?'; params.push(tier); }
  query += ' ORDER BY sort_order ASC';

  const rows = await env.DB.prepare(query).bind(...params).all().catch(() => ({ results: [] }));
  return (rows.results || []).map(s => ({
    ...s,
    deliverables: (() => { try { return JSON.parse(s.deliverables); } catch { return []; } })(),
    ideal_for:    (() => { try { return JSON.parse(s.ideal_for); } catch { return []; } })(),
  }));
}

// ── Run assessment manually (admin) ──────────────────────────────────────────
export async function triggerManualAssessment(env, orderId, ctx = null) {
  const order = await env.DB.prepare(
    `SELECT so.*, s.automated_engine, s.delivery_type
     FROM service_orders so LEFT JOIN services s ON so.ref_id = s.ref_id
     WHERE so.id=?`
  ).bind(orderId).first().catch(() => null);

  if (!order) return { error: 'Order not found', status: 404 };
  if (!order.automated_engine) return { error: 'This service requires manual delivery', status: 400 };

  const inputs = (() => { try { return JSON.parse(order.assessment_inputs || '{}'); } catch { return {}; } })();
  const promise = dispatchAssessment(env, order.automated_engine, inputs, orderId);
  if (ctx?.waitUntil) ctx.waitUntil(promise.catch(() => {}));

  return { success: true, order_id: orderId, engine: order.automated_engine, message: 'Assessment triggered' };
}
