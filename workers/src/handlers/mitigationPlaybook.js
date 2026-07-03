/**
 * CYBERDUDEBIVASH® AI Security Hub — Mitigation & Response Playbook Engine v1.0
 *
 * Deterministic, evidence-grounded generation of the response deliverables
 * analysts currently write by hand for every verified threat_intel item:
 *   - Immediate mitigation actions
 *   - Detection guidance
 *   - Threat hunting guide
 *   - SOC playbook (Triage -> Contain -> Eradicate -> Recover -> Post-Incident)
 *   - Incident response playbook (NIST SP 800-61 phases)
 *   - Executive advisory
 *   - Security architecture guidance
 *   - Operational checklist
 *   - References
 *   - Supporting evidence
 *
 * Every fact used (CVSS, EPSS, exploit status, affected products, IOCs,
 * ATT&CK techniques, CWE mappings) is read directly from the real
 * threat_intel row and the already-production mapToAttack()/scoreCVE()
 * engines — no field is invented. An item with no published IOCs or no
 * ATT&CK mapping says so explicitly instead of fabricating either.
 *
 *   POST /api/threat-intel/:id/playbook       — generate (and persist) a fresh playbook
 *   GET  /api/threat-intel/:id/playbook       — fetch latest persisted playbook
 *                                                (lazy-generates on first visit)
 *   GET  /api/threat-intel/playbooks/history  — org/user-scoped generation history
 */

import { mapToAttack } from '../services/mitreAttackService.js';
import { scoreCVE } from '../services/compositeRiskScoring.js';

const BASE_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
  'X-Content-Type-Options':       'nosniff',
  'X-Frame-Options':              'DENY',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...BASE_HEADERS, 'Content-Type': 'application/json' } });
}

// ─── Tactic → architecture control mapping ───────────────────────────────────
// Static, reviewable reference table (like the codebase's existing
// CWE_TO_TECHNIQUE map) — not fabricated per-item, applied uniformly.
const TACTIC_ARCHITECTURE_GUIDANCE = {
  'Reconnaissance':       'Reduce external attack-surface visibility: minimize public asset/DNS exposure and monitor for exposure via attack-surface-management tooling.',
  'Resource Development': 'No direct control point on customer infrastructure; maintain brand/domain monitoring to catch attacker-registered look-alike infrastructure.',
  'Initial Access':       'Enforce network segmentation, a web application firewall in front of public-facing services, and multi-factor authentication on all remote-access paths.',
  'Execution':            'Application allow-listing and script-execution controls (e.g. constrained language mode, AMSI) on endpoints that can reach the affected component.',
  'Persistence':          'EDR coverage tuned to detect new scheduled tasks, services, or startup-item creation on affected hosts.',
  'Privilege Escalation': 'Least-privilege service accounts and routine local-admin-rights review on systems running the affected component.',
  'Defense Evasion':      'Tamper-protection on security agents and centralized, immutable log shipping so evasion attempts remain observable.',
  'Credential Access':    'Enforce MFA, rotate credentials with access to the affected component, and deploy credential-guard / LSASS protection where applicable.',
  'Discovery':            'Alert on anomalous internal scanning or enumeration activity originating from or targeting the affected component.',
  'Lateral Movement':     'Network segmentation between the affected component and high-value systems; restrict lateral admin protocols (RDP/SMB/WinRM) by default.',
  'Collection':           'Data-loss-prevention controls on systems that process sensitive data via the affected component.',
  'Command and Control':  'Egress filtering and DNS monitoring to detect beaconing from systems running the affected component.',
  'Exfiltration':         'Egress data-volume monitoring and DLP enforcement on outbound channels available to the affected component.',
  'Impact':               'Verified, tested backups and a documented recovery runbook for systems running the affected component.',
};
const DEFAULT_ARCHITECTURE_GUIDANCE = 'Apply defense-in-depth: patch management, network segmentation, and endpoint monitoring covering the affected component.';

function safeArr(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
}

// ─── Pure, deterministic playbook builder ────────────────────────────────────
export function buildPlaybook(entry, opts = {}) {
  const attackMapping = opts.attackMapping || mapToAttack(entry);
  const risk          = opts.risk || scoreCVE(entry, entry.epss_score ?? null);

  const products = safeArr(entry.affected_products);
  const iocs     = safeArr(entry.iocs);
  const cwes     = safeArr(entry.weakness_types);
  const tags     = safeArr(entry.tags);
  const techniques = attackMapping.techniques || [];
  const tacticList  = attackMapping.tactics || [];

  const label = /^CVE-\d{4}-\d+$/i.test(entry.id || '') ? entry.id : (entry.title || entry.id || 'this item');

  // 1. Immediate actions (mitigation guidance)
  const immediate_actions = [];
  if (risk.is_kev || entry.actively_exploited || entry.exploit_status === 'confirmed') {
    immediate_actions.push(`Apply the vendor patch or documented mitigation for ${label} within ${risk.remediation_sla} — active exploitation is confirmed.`);
  } else if (entry.exploit_available || risk.risk_tier === 'HIGH' || risk.risk_tier === 'CRITICAL') {
    immediate_actions.push(`A public exploit is available or the composite risk is ${risk.risk_tier}; prioritize remediation within ${risk.remediation_sla} ahead of routine patch cycles.`);
  } else {
    immediate_actions.push(`Schedule remediation within the recommended timeframe (${risk.remediation_sla}).`);
  }
  if (products.length) {
    immediate_actions.push(`Confirm exposure by cross-referencing ${products.join(', ')} against your asset inventory/CMDB before prioritizing rollout.`);
  } else {
    immediate_actions.push(`An affected-product list has not been published for this item yet — confirm applicability directly against ${entry.source || 'the original advisory'}.`);
  }
  if (risk.is_ransomware) {
    immediate_actions.push('This item has documented ransomware linkage — isolate exposed hosts from backup infrastructure until patched.');
  }

  // 2. Detection guidance
  const detection_guidance = techniques.length
    ? techniques.map(t => `Monitor for ${t.technique_name} (${t.technique_id}, ${t.confidence} confidence) under the ${t.tactic_name} tactic. Reference: ${t.url}`)
    : ['No MITRE ATT&CK technique could be mapped from the available title/description/CWE data for this item — rely on vendor-published detection guidance directly.'];
  detection_guidance.push(iocs.length
    ? `Add the following published indicators to detection watchlists: ${iocs.join(', ')}`
    : 'No indicators of compromise have been published for this item yet — detection should rely on the behavioral techniques above rather than static IOCs.');

  // 3. Threat hunting guide
  const primaryTechniqueIds = techniques.slice(0, 3).map(t => t.technique_id);
  const threat_hunting_guide = {
    summary: techniques.length
      ? `Hunt for behaviors consistent with ${techniques.map(t => t.technique_name).join(', ')} across hosts and identities that can reach the affected component.`
      : 'No technique mapping is available for this item; hunt for anomalous activity on systems running the affected component using the indicators above, if any.',
    suggested_query: `(title:"${label}"${entry.id ? ` OR cve:"${entry.id}"` : ''})${primaryTechniqueIds.length ? ' AND technique:(' + primaryTechniqueIds.join(' OR ') + ')' : ''}`,
    run_via: 'POST /api/hunt — submit suggested_query as the "query" field to execute against your live telemetry.',
  };

  // 4. SOC playbook
  const soc_playbook = [
    { stage: 'Triage',        action: `Confirm ${label} affects an in-scope, reachable asset. Assign severity ${risk.risk_tier} (composite risk ${risk.priority_score}/100).` },
    { stage: 'Contain',       action: products.length ? `Restrict network/administrative access to systems running ${products.join(', ')} pending remediation.` : 'Restrict network/administrative access to the affected component pending remediation.' },
    { stage: 'Eradicate',     action: `Apply the vendor patch or mitigation for ${label}; if unavailable, apply the compensating controls listed under Security Architecture Guidance.` },
    { stage: 'Recover',       action: 'Validate patched systems against the detection guidance above before returning them to production traffic.' },
    { stage: 'Post-Incident', action: 'Record time-to-detect and time-to-remediate against your internal SLA; feed findings back into the asset inventory.' },
  ];

  // 5. Incident response playbook (NIST SP 800-61 phases)
  const incident_response_playbook = [
    { phase: 'Preparation',            action: 'Ensure on-call SOC/IR staff have this playbook and the affected-asset list before an incident is declared.' },
    { phase: 'Detection & Analysis',   action: detection_guidance[0] },
    { phase: 'Containment',            action: soc_playbook[1].action },
    { phase: 'Eradication & Recovery', action: `${soc_playbook[2].action} ${soc_playbook[3].action}` },
    { phase: 'Post-Incident Activity', action: soc_playbook[4].action },
  ];

  // 6. Executive advisory
  const executive_advisory =
    `${label} is rated ${entry.severity || risk.risk_tier} `
    + `(CVSS ${entry.cvss ?? 'n/a'}${entry.epss_score != null ? `, EPSS ${(entry.epss_score * 100).toFixed(1)}%` : ''}). `
    + (risk.is_kev ? 'This issue is being actively exploited in the wild. ' : '')
    + (tacticList.length ? `Successful exploitation maps to the ${tacticList.join(', ')} phase(s) of the attack lifecycle. ` : '')
    + `Recommended remediation SLA: ${risk.remediation_sla}. `
    + `Business impact scales with the number of ${products.length ? products.join('/') : 'affected'} instances exposed to untrusted networks.`;

  // 7. Security architecture guidance
  const security_architecture_guidance = tacticList.length
    ? tacticList.map(t => ({ tactic: t, guidance: TACTIC_ARCHITECTURE_GUIDANCE[t] || DEFAULT_ARCHITECTURE_GUIDANCE }))
    : [{ tactic: null, guidance: DEFAULT_ARCHITECTURE_GUIDANCE }];

  // 8. Operational checklist (derived, deduplicated intent — no new claims)
  const operational_checklist = [
    ...immediate_actions.map(item => ({ done: false, item })),
    { done: false, item: `Verify detection coverage: ${detection_guidance[0]}` },
    { done: false, item: 'Execute the suggested threat hunt against live telemetry.' },
    { done: false, item: 'Brief SOC on-call with the SOC Playbook stages above.' },
  ];

  // 9. References (real links only)
  const references = [];
  if (entry.source_url) references.push({ label: entry.source || 'Source advisory', url: entry.source_url });
  if (/^CVE-\d{4}-\d+$/i.test(entry.id || '')) references.push({ label: `NVD — ${entry.id}`, url: `https://nvd.nist.gov/vuln/detail/${entry.id}` });
  for (const t of techniques) references.push({ label: `MITRE ATT&CK ${t.technique_id} — ${t.technique_name}`, url: t.url });

  // 10. Supporting evidence — literal echo of every real field used above
  const supporting_evidence = {
    threat_intel_id:    entry.id ?? null,
    severity:           entry.severity ?? null,
    cvss:               entry.cvss ?? null,
    cvss_vector:        entry.cvss_vector ?? null,
    epss_score:         entry.epss_score ?? null,
    epss_percentile:    entry.epss_percentile ?? null,
    exploit_status:     entry.exploit_status ?? null,
    actively_exploited: !!entry.actively_exploited,
    exploit_available:  !!entry.exploit_available,
    known_ransomware:   !!entry.known_ransomware,
    weakness_types:     cwes,
    affected_products:  products,
    iocs,
    tags,
    published_at:       entry.published_at ?? null,
    source:             entry.source ?? null,
    risk_score:         risk,
    attack_mapping:     attackMapping,
  };

  return {
    threat_intel_id: entry.id ?? null,
    title:           entry.title ?? null,
    risk_tier:       risk.risk_tier,
    immediate_actions,
    detection_guidance,
    threat_hunting_guide,
    soc_playbook,
    incident_response_playbook,
    executive_advisory,
    security_architecture_guidance,
    operational_checklist,
    references,
    supporting_evidence,
    generated_at: new Date().toISOString(),
  };
}

// ─── Persistence (D1, self-healing schema) ───────────────────────────────────
async function ensureThreatPlaybooksTable(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS threat_playbooks (
      id TEXT PRIMARY KEY,
      threat_intel_id TEXT NOT NULL,
      org_id TEXT,
      generated_by TEXT,
      playbook_json TEXT NOT NULL,
      source_updated_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
  await db.prepare(
    `CREATE INDEX IF NOT EXISTS idx_threat_playbooks_intel ON threat_playbooks(threat_intel_id, created_at DESC)`
  ).run().catch(() => {});
}

function genPlaybookId() {
  return 'pbk_' + Date.now().toString(36) + '_' + crypto.randomUUID().slice(0, 8);
}

async function persistPlaybook(db, threatId, authCtx, entry, playbook) {
  await ensureThreatPlaybooksTable(db);
  const id = genPlaybookId();
  await db.prepare(
    `INSERT INTO threat_playbooks (id, threat_intel_id, org_id, generated_by, playbook_json, source_updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, threatId, authCtx.org_id ?? null, authCtx.user_id ?? 'system', JSON.stringify(playbook), entry.updated_at ?? null).run();
  return id;
}

function extractThreatId(pathname) {
  // /api/threat-intel/:id/playbook
  const parts = pathname.replace(/\/+$/, '').split('/').filter(Boolean);
  const idx = parts.indexOf('threat-intel');
  return idx >= 0 && parts[idx + 1] ? decodeURIComponent(parts[idx + 1]) : null;
}

// Auth is optional on both generate and fetch — anonymous callers get the
// full playbook computed on the fly, but nothing is written to D1 for them.
// This mirrors the platform's existing rule-generation convention
// (handlers/aiAnalysis.js: `if (env?.DB && authCtx?.user_id)`) and closes an
// unbounded-write abuse path: without this gate, an anonymous caller could
// spam POST on any real CVE id and grow threat_playbooks without limit.
const HISTORY_HINT = '/api/threat-intel/playbooks/history';

// ─── POST /api/threat-intel/:id/playbook — generate fresh; persist only for signed-in callers ──
export async function handleGeneratePlaybook(request, env, authCtx = {}) {
  if (!env?.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

  const threatId = extractThreatId(new URL(request.url).pathname);
  if (!threatId) return jsonResponse({ error: 'threat_intel id required' }, 400);

  const entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(threatId).first().catch(() => null);
  if (!entry) return jsonResponse({ error: 'threat_intel item not found', threat_intel_id: threatId }, 404);

  const playbook = buildPlaybook(entry);

  if (!authCtx?.user_id) {
    return jsonResponse({ success: true, playbook_id: null, persisted: false, stale: false, playbook, history: 'Sign in to save this playbook and track staleness over time' }, 200);
  }

  const playbookId = await persistPlaybook(env.DB, threatId, authCtx, entry, playbook);
  return jsonResponse({ success: true, playbook_id: playbookId, persisted: true, stale: false, playbook, history: HISTORY_HINT }, 201);
}

// ─── GET /api/threat-intel/:id/playbook — fetch latest; lazy-generate (persisting only for signed-in callers) ──
export async function handleGetPlaybook(request, env, authCtx = {}) {
  if (!env?.DB) return jsonResponse({ error: 'Database unavailable' }, 503);

  const threatId = extractThreatId(new URL(request.url).pathname);
  if (!threatId) return jsonResponse({ error: 'threat_intel id required' }, 400);

  const entry = await env.DB.prepare('SELECT * FROM threat_intel WHERE id = ?').bind(threatId).first().catch(() => null);
  if (!entry) return jsonResponse({ error: 'threat_intel item not found', threat_intel_id: threatId }, 404);

  await ensureThreatPlaybooksTable(env.DB);
  const latest = await env.DB.prepare(
    `SELECT * FROM threat_playbooks WHERE threat_intel_id = ? ORDER BY created_at DESC LIMIT 1`
  ).bind(threatId).first().catch(() => null);

  if (!latest) {
    const playbook = buildPlaybook(entry);
    if (!authCtx?.user_id) {
      return jsonResponse({ success: true, playbook_id: null, persisted: false, stale: false, generated_now: true, playbook, history: 'Sign in to save this playbook and track staleness over time' });
    }
    const playbookId = await persistPlaybook(env.DB, threatId, authCtx, entry, playbook);
    return jsonResponse({ success: true, playbook_id: playbookId, persisted: true, stale: false, generated_now: true, playbook, history: HISTORY_HINT });
  }

  const stale = !!(entry.updated_at && latest.source_updated_at && entry.updated_at !== latest.source_updated_at);
  return jsonResponse({
    success: true,
    playbook_id: latest.id,
    persisted: true,
    stale,
    stale_reason: stale ? 'The underlying threat_intel record has been updated since this playbook was generated — POST to regenerate current guidance.' : null,
    generated_at: latest.created_at,
    playbook: JSON.parse(latest.playbook_json),
    history: authCtx?.user_id ? HISTORY_HINT : 'Sign in to save future playbooks and track staleness over time',
  });
}

// ─── GET /api/threat-intel/playbooks/history — user/org-scoped history ─────
export async function handleListPlaybooks(request, env, authCtx = {}) {
  if (!env?.DB) return jsonResponse({ error: 'Database unavailable' }, 503);
  if (!authCtx?.user_id) return jsonResponse({ error: 'Authentication required to view playbook history' }, 401);

  await ensureThreatPlaybooksTable(env.DB);
  const url   = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '25', 10) || 25, 100);

  const rows = authCtx.org_id
    ? await env.DB.prepare(
        `SELECT id, threat_intel_id, created_at FROM threat_playbooks WHERE org_id = ? ORDER BY created_at DESC LIMIT ?`
      ).bind(authCtx.org_id, limit).all().catch(() => ({ results: [] }))
    : await env.DB.prepare(
        `SELECT id, threat_intel_id, created_at FROM threat_playbooks WHERE generated_by = ? ORDER BY created_at DESC LIMIT ?`
      ).bind(authCtx.user_id, limit).all().catch(() => ({ results: [] }));

  const history = rows.results || [];
  return jsonResponse({ success: true, count: history.length, history });
}
