/**
 * CYBERDUDEBIVASH AI Security Hub — P12.2 Live Investigation Engine
 *
 * Endpoint:
 *   GET /api/soc/investigate/:caseId — AI-enriched investigation
 *
 * Extends (NEVER modifies) socInvestigations.js.
 * Adds AI enrichment: MITRE mapping, attack chain synthesis,
 * affected assets, business context, recommended response.
 *
 * Reuses:
 *   handlers/socInvestigations.js — D1 tables (soc_cases, soc_timeline, soc_evidence)
 *   core/adaptiveCyberBrain.js    — generateAdaptiveRecommendations()
 *   core/mythosAIProvider.js      — callClaude()
 *
 * Tier gate: PRO / ENTERPRISE / MSSP / OWNER / ADMIN
 */

import { generateAdaptiveRecommendations } from '../core/adaptiveCyberBrain.js';
import { callClaude }                      from '../core/mythosAIProvider.js';
import { isRealUser } from '../auth/middleware.js';

// MITRE ATT&CK phase taxonomy (static, no fabrication — reflects known stages)
const MITRE_PHASES = {
  'T1190': { stage: 'Initial Access',    name: 'Exploit Public-Facing Application' },
  'T1059': { stage: 'Execution',         name: 'Command and Scripting Interpreter' },
  'T1078': { stage: 'Persistence',       name: 'Valid Accounts' },
  'T1055': { stage: 'Defense Evasion',   name: 'Process Injection' },
  'T1021': { stage: 'Lateral Movement',  name: 'Remote Services' },
  'T1486': { stage: 'Impact',            name: 'Data Encrypted for Impact' },
  'T1041': { stage: 'Exfiltration',      name: 'Exfiltration Over C2 Channel' },
  'T1071': { stage: 'Command and Control', name: 'Application Layer Protocol' },
  'T1203': { stage: 'Execution',         name: 'Exploitation for Client Execution' },
  'T1110': { stage: 'Credential Access', name: 'Brute Force' },
  'T1562': { stage: 'Defense Evasion',   name: 'Impair Defenses' },
  'T1566': { stage: 'Initial Access',    name: 'Phishing' },
};

// ─── Tier gate ────────────────────────────────────────────────────────────────
const ALLOWED_TIERS = new Set(['PRO', 'ENTERPRISE', 'MSSP', 'OWNER', 'ADMIN']);

function checkTier(authCtx) {
  if (!isRealUser(authCtx)) {
    return Response.json(
      { success: false, error: 'Authentication required', service: 'CDB-AI-INVESTIGATION' },
      { status: 401 }
    );
  }
  if (!ALLOWED_TIERS.has((authCtx.tier || '').toUpperCase())) {
    return Response.json(
      { success: false, error: 'PRO plan or above required for AI Investigation Engine', upgrade: 'https://tools.cyberdudebivash.com/#pricing', service: 'CDB-AI-INVESTIGATION' },
      { status: 403 }
    );
  }
  return null;
}

// ─── P12.2 — AI-enriched investigation ───────────────────────────────────────
export async function handleAIInvestigation(request, env, authCtx) {
  const gate = checkTier(authCtx);
  if (gate) return gate;

  const caseId = new URL(request.url).pathname.split('/').at(-1);
  if (!caseId) return Response.json({ success: false, error: 'caseId required' }, { status: 400 });

  const db    = env.DB;
  const orgId = authCtx.org_id || 'default';

  if (!db) {
    return Response.json({
      success:     true,
      service:     'CDB-AI-INVESTIGATION',
      generated_at: new Date().toISOString(),
      case:        null,
      note:        'Database unavailable',
      mitre_mapping: [], attack_chain: [], affected_assets: [],
      business_context: '', evidence_summary: { total: 0, notes: 0 },
      recommended_response: [],
    });
  }

  // Fetch case + supporting data in parallel
  const [caseRow, timeline, evidenceCount, notesCount, tiRows, assetRows] = await Promise.all([
    db.prepare(
      `SELECT id, case_number, title, severity, status, assignee_id, source,
              mitre_tactics, ioc_list, sla_due_at, summary, created_at, updated_at
       FROM soc_cases WHERE id = ? AND (org_id = ? OR ? = 'admin')`
    ).bind(caseId, orgId, authCtx.role || '').first().catch(() => null),
    db.prepare(
      `SELECT event_type, description, actor, occurred_at
       FROM soc_timeline WHERE case_id = ? ORDER BY occurred_at ASC LIMIT 50`
    ).bind(caseId).all().then(r => r.results || []).catch(() => []),
    db.prepare(`SELECT COUNT(*) cnt FROM soc_evidence WHERE case_id = ?`).bind(caseId).first().catch(() => null),
    db.prepare(`SELECT COUNT(*) cnt FROM soc_notes WHERE case_id = ?`).bind(caseId).first().catch(() => null),
    db.prepare(
      `SELECT cve_id, title, cvss_score, epss_score, actively_exploited, severity, mitre_technique, description
       FROM threat_intel ORDER BY cvss_score DESC LIMIT 50`
    ).all().then(r => r.results || []).catch(() => []),
    db.prepare(
      `SELECT asset_value, asset_type FROM customer_assets LIMIT 50`
    ).all().then(r => r.results || []).catch(() => []),
  ]);

  if (!caseRow) return Response.json({ success: false, error: 'Case not found or access denied' }, { status: 404 });

  // ── MITRE mapping ─────────────────────────────────────────────────────────
  let mitreTactics = [];
  try { mitreTactics = JSON.parse(caseRow.mitre_tactics || '[]'); } catch {}

  // Extract MITRE techniques from CVEs in threat intel
  const techniques = new Set([
    ...mitreTactics,
    ...tiRows.filter(r => r.mitre_technique).map(r => r.mitre_technique),
  ]);
  const mitreMapping = [...techniques].slice(0, 10).map(t => ({
    technique_id: t,
    stage: MITRE_PHASES[t]?.stage || 'Unknown Stage',
    name:  MITRE_PHASES[t]?.name  || t,
    cves:  tiRows.filter(r => r.mitre_technique === t).map(r => r.cve_id).slice(0, 5),
  }));

  // ── Attack chain ──────────────────────────────────────────────────────────
  const stageOrder = [
    'Initial Access','Execution','Persistence','Privilege Escalation',
    'Defense Evasion','Credential Access','Discovery','Lateral Movement',
    'Collection','Command and Control','Exfiltration','Impact',
  ];
  const attackChain = mitreMapping
    .sort((a, b) => stageOrder.indexOf(a.stage) - stageOrder.indexOf(b.stage))
    .map((m, i) => ({
      step:        i + 1,
      stage:       m.stage,
      technique:   m.technique_id,
      description: m.name,
      related_cves: m.cves,
    }));

  // ── Affected assets ───────────────────────────────────────────────────────
  const iocList = (() => { try { return JSON.parse(caseRow.ioc_list || '[]'); } catch { return []; } })();
  const affectedAssets = [
    ...assetRows.filter(a => a.asset_type === 'cve_watchlist').slice(0, 5).map(a => ({
      asset:       a.asset_value,
      type:        'watched_cve',
      exposure:    'direct',
    })),
    ...assetRows.filter(a => a.asset_type === 'technology').slice(0, 5).map(a => ({
      asset:       a.asset_value,
      type:        'technology',
      exposure:    'indirect',
    })),
    ...iocList.slice(0, 5).map(ioc => ({
      asset:       String(ioc),
      type:        'ioc',
      exposure:    'flagged',
    })),
  ].slice(0, 10);

  // ── Business context ──────────────────────────────────────────────────────
  const critCVEs   = tiRows.filter(r => r.cvss_score >= 9).length;
  const kevCVEs    = tiRows.filter(r => r.actively_exploited).length;
  let businessContext = `Case "${caseRow.title}" (${caseRow.severity}) involves ${critCVEs} critical CVEs, ${kevCVEs} actively exploited. ${affectedAssets.length} assets potentially impacted. Timeline shows ${timeline.length} events.`;

  // Attempt AI enrichment (never fail)
  try {
    const prompt = `Write a 2-sentence business impact summary for a cybersecurity incident. Case: "${caseRow.title}", severity: ${caseRow.severity}. Data: ${critCVEs} critical CVEs, ${kevCVEs} CISA KEV, ${affectedAssets.length} affected assets. Focus on operational and financial risk.`;
    const aiRes = await callClaude(env, { prompt, tier: authCtx.tier || 'PRO', max_tokens: 150, temperature: 0.3 });
    if (aiRes?.content?.trim()) businessContext = aiRes.content.trim();
  } catch {}

  // ── Recommended response ──────────────────────────────────────────────────
  const vulns = tiRows.map(r => ({
    cve_id: r.cve_id, cvss: r.cvss_score, epss: r.epss_score,
    in_kev: Boolean(r.actively_exploited), severity: r.severity,
    title: r.title, mitre: r.mitre_technique,
  }));

  let recommendedResponse = [];
  try {
    const adaptive = await generateAdaptiveRecommendations(env, {
      findings:      [],
      vulns:         vulns.slice(0, 15),
      adaptiveScore: 60,
      attackChains:  attackChain,
      sector:        'technology',
      tier:          authCtx.tier || 'PRO',
      userId:        authCtx.userId || null,
    });
    recommendedResponse = (adaptive.actions || []).slice(0, 5).map(a => ({
      action:   a.title,
      priority: a.urgency || 'HIGH',
      effort:   a.effort || 'TBD',
      detail:   a.detail || '',
    }));
  } catch {}

  return Response.json({
    success:      true,
    service:      'CDB-AI-INVESTIGATION',
    generated_at: new Date().toISOString(),
    case: {
      id:          caseRow.id,
      case_number: caseRow.case_number,
      title:       caseRow.title,
      severity:    caseRow.severity,
      status:      caseRow.status,
      assignee_id: caseRow.assignee_id,
      sla_due_at:  caseRow.sla_due_at,
      created_at:  caseRow.created_at,
    },
    mitre_mapping:       mitreMapping,
    attack_chain:        attackChain,
    affected_assets:     affectedAssets,
    business_context:    businessContext,
    evidence_summary: {
      total: evidenceCount?.cnt || 0,
      notes: notesCount?.cnt || 0,
      timeline_events: timeline.length,
    },
    recommended_response: recommendedResponse,
    timeline:            timeline.slice(0, 10),
    powered_by:          'CYBERDUDEBIVASH SENTINEL APEX AI — P12.2',
  });
}
