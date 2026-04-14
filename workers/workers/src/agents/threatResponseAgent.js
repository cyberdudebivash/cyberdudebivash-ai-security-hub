/**
 * THREAT RESPONSE AGENT — Detects CVE/threat events and executes responses
 * Consumes CVE_DETECTED events from bus, decides action, executes via actionExecutor
 */
import { decideCVEResponse } from './decisionEngine.js';
import { executeApplyVirtualPatch, createActionRecord, persistActionResult } from './actionExecutor.js';
import { publishEvent, EVENT_TYPES } from './agentBus.js';

function now() { return new Date().toISOString(); }

/**
 * Process a single CVE event
 */
export async function processCVEEvent(env, event) {
  const { cve_id, cvss, epss, is_kev, description } = event.payload || event;

  const decision = decideCVEResponse({ cve_id, cvss, epss, is_kev, description });

  const results = [];

  for (const action of decision.actions) {
    if (action.action_type === 'apply_virtual_patch') {
      const actionId = await createActionRecord(env, {
        agentType:       'threat_response',
        actionType:      'apply_virtual_patch',
        target:          cve_id,
        targetType:      'cve_id',
        triggerSource:   'cve_ingestion',
        triggerId:       cve_id,
        riskLevel:       decision.risk_level,
        decisionScore:   decision.decision_score,
        rollbackAvailable: true,
      });

      const result = await executeApplyVirtualPatch(env, actionId, cve_id, action.patch_config || {});
      await persistActionResult(env, actionId, result, 'threat_response', 'cve_ingestion', cve_id, {
        cvss, epss, is_kev, reasoning: decision.reasoning,
      });
      results.push({ actionId, ...result });
    }

    if (action.action_type === 'alert_admin') {
      // Publish to Telegram if configured
      if (env.ADMIN_TELEGRAM_CHAT_ID && env.TELEGRAM_BOT_TOKEN) {
        const msg = `🚨 THREAT AGENT ALERT\nCVE: ${cve_id}\nCVSS: ${cvss} | EPSS: ${(epss*100).toFixed(1)}%${is_kev ? ' | ⚠️ KEV' : ''}\nRisk: ${decision.risk_level} (${decision.decision_score}/100)\n${decision.reasoning}`;
        fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: env.ADMIN_TELEGRAM_CHAT_ID, text: msg, parse_mode: 'HTML' }),
        }).catch(() => {});
      }
    }
  }

  return {
    agent: 'threat_response',
    cve_id,
    risk_level:     decision.risk_level,
    decision_score: decision.decision_score,
    actions_taken:  results.length,
    results,
    reasoning:      decision.reasoning,
    timestamp:      now(),
  };
}

/**
 * Batch process multiple CVEs — called from cron
 */
export async function runThreatResponseBatch(env, cves = []) {
  const results = [];
  // Only process HIGH+ severity CVEs autonomously
  const targets = cves.filter(c => (c.cvss >= 7.0 || c.is_kev || c.epss >= 0.3));

  for (const cve of targets.slice(0, 10)) { // cap at 10 per run
    try {
      const r = await processCVEEvent(env, { payload: cve });
      results.push(r);
    } catch (e) {
      results.push({ cve_id: cve.cve_id, error: e.message, agent: 'threat_response' });
    }
  }

  return { processed: results.length, results };
}

/**
 * Handle manual execution request
 */
export async function executeThreatResponse(env, request, authCtx) {
  const body = await request.json().catch(() => ({}));
  const { cve_id, force = false } = body;

  if (!cve_id) return { error: 'cve_id required', status: 400 };

  // Fetch CVE data from DB
  const cve = await env.DB.prepare(
    `SELECT cve_id, cvss_score as cvss, epss_score as epss, is_kev, description FROM threat_intel WHERE cve_id=? LIMIT 1`
  ).bind(cve_id).first().catch(() => null);

  if (!cve && !force) return { error: `CVE ${cve_id} not found in threat intel DB`, status: 404 };

  const cveData = cve || { cve_id, cvss: body.cvss || 9.0, epss: body.epss || 0.5, is_kev: body.is_kev || false, description: body.description || '' };

  const result = await processCVEEvent(env, { payload: cveData });
  return { success: true, ...result };
}
