/**
 * CYBERDUDEBIVASH AI Security Hub — SOC Response Engine v1.0
 * Sentinel APEX v3 Phase 2b: AI SOC Automation — Response Actions
 *
 * Given a SOC alert, generates prioritized response actions:
 *   - block_ip        → Add IP to blocklist / WAF rule
 *   - block_domain    → Block domain at DNS / WAF level
 *   - isolate_system  → Quarantine affected host
 *   - patch_advisory  → Fast-track patch recommendation with CVE detail
 *   - alert_admin     → Escalate to security team / on-call
 *   - enable_mfa      → Force MFA re-enrollment for affected accounts
 *   - rotate_secrets  → Credential rotation advisory
 *   - waf_rule        → Deploy WAF rule for specific attack pattern
 *   - ids_signature   → Enable IDS/IPS signature for CVE
 *   - threat_hunt     → Trigger threat hunting for related IOCs
 *
 * Integration points designed for:
 *   - Cloudflare Firewall API (IP/domain block)
 *   - Cloudflare WAF managed rules
 *   - Cloudflare Zero Trust (device isolation)
 *   - Generic SIEM webhook
 *   - PagerDuty/OpsGenie (alert admin)
 */

import { ALERT_TYPES } from './detectionEngine.js';

// ─── Response action catalog ──────────────────────────────────────────────────
export const ACTION_TYPES = {
  BLOCK_IP:         'block_ip',
  BLOCK_DOMAIN:     'block_domain',
  ISOLATE_SYSTEM:   'isolate_system',
  PATCH_ADVISORY:   'patch_advisory',
  ALERT_ADMIN:      'alert_admin',
  ENABLE_MFA:       'enable_mfa',
  ROTATE_SECRETS:   'rotate_secrets',
  WAF_RULE:         'waf_rule',
  IDS_SIGNATURE:    'ids_signature',
  THREAT_HUNT:      'threat_hunt',
  MONITOR_ENHANCED: 'monitor_enhanced',
};

// ─── Alert type → response action mapping ─────────────────────────────────────
const ALERT_TO_ACTIONS = {
  [ALERT_TYPES.CRITICAL_VULNERABILITY]:  [ACTION_TYPES.PATCH_ADVISORY, ACTION_TYPES.IDS_SIGNATURE,  ACTION_TYPES.ALERT_ADMIN],
  [ALERT_TYPES.KEV_CONFIRMED_EXPLOIT]:   [ACTION_TYPES.ISOLATE_SYSTEM, ACTION_TYPES.PATCH_ADVISORY,  ACTION_TYPES.ALERT_ADMIN, ACTION_TYPES.WAF_RULE],
  [ALERT_TYPES.ZERO_DAY_ACTIVE]:         [ACTION_TYPES.WAF_RULE,        ACTION_TYPES.BLOCK_IP,         ACTION_TYPES.ALERT_ADMIN, ACTION_TYPES.THREAT_HUNT],
  [ALERT_TYPES.HIGH_EPSS_RISK]:          [ACTION_TYPES.PATCH_ADVISORY,  ACTION_TYPES.MONITOR_ENHANCED],
  [ALERT_TYPES.RANSOMWARE_INDICATOR]:    [ACTION_TYPES.ISOLATE_SYSTEM,  ACTION_TYPES.BLOCK_IP,         ACTION_TYPES.ROTATE_SECRETS, ACTION_TYPES.ALERT_ADMIN],
  [ALERT_TYPES.IOC_PATTERN_REPEAT]:      [ACTION_TYPES.BLOCK_IP,        ACTION_TYPES.BLOCK_DOMAIN,     ACTION_TYPES.THREAT_HUNT],
  [ALERT_TYPES.ANOMALY_CLUSTER]:         [ACTION_TYPES.PATCH_ADVISORY,  ACTION_TYPES.MONITOR_ENHANCED, ACTION_TYPES.ALERT_ADMIN],
  [ALERT_TYPES.SUPPLY_CHAIN_THREAT]:     [ACTION_TYPES.ROTATE_SECRETS,  ACTION_TYPES.PATCH_ADVISORY,   ACTION_TYPES.ALERT_ADMIN],
  [ALERT_TYPES.EXPLOIT_PUBLIC]:          [ACTION_TYPES.WAF_RULE,        ACTION_TYPES.IDS_SIGNATURE,    ACTION_TYPES.PATCH_ADVISORY],
  [ALERT_TYPES.NEW_CRITICAL_CVE]:        [ACTION_TYPES.PATCH_ADVISORY,  ACTION_TYPES.IDS_SIGNATURE],
  [ALERT_TYPES.THREAT_ACTOR_ATTRIBUTED]: [ACTION_TYPES.THREAT_HUNT,     ACTION_TYPES.MONITOR_ENHANCED, ACTION_TYPES.ALERT_ADMIN],
};

// ─── Action metadata templates ────────────────────────────────────────────────
const ACTION_META = {
  [ACTION_TYPES.BLOCK_IP]: {
    description: 'Block malicious IP addresses at firewall/WAF level',
    integration: 'cloudflare_firewall',
    api_endpoint: 'POST /client/v4/zones/{zone_id}/firewall/rules',
    duration:    '24h',
    reversible:  true,
  },
  [ACTION_TYPES.BLOCK_DOMAIN]: {
    description: 'Block malicious domain at DNS/WAF level (Gateway policy)',
    integration: 'cloudflare_gateway',
    api_endpoint: 'POST /api/v4/accounts/{account_id}/gateway/rules',
    duration:    '7d',
    reversible:  true,
  },
  [ACTION_TYPES.ISOLATE_SYSTEM]: {
    description: 'Quarantine affected system from network via Zero Trust policy',
    integration: 'cloudflare_zero_trust',
    api_endpoint: 'POST /api/v4/accounts/{account_id}/devices/policy',
    duration:    'until_remediated',
    reversible:  true,
  },
  [ACTION_TYPES.PATCH_ADVISORY]: {
    description: 'Immediate patch recommendation with CVE detail and vendor links',
    integration: 'internal',
    api_endpoint: null,
    duration:    null,
    reversible:  false,
  },
  [ACTION_TYPES.ALERT_ADMIN]: {
    description: 'Escalate to security team via Telegram + email alert',
    integration: 'telegram_bot,email',
    api_endpoint: 'POST /api/alerts/broadcast',
    duration:    null,
    reversible:  false,
  },
  [ACTION_TYPES.ENABLE_MFA]: {
    description: 'Force MFA re-enrollment for accounts on affected systems',
    integration: 'identity_provider',
    api_endpoint: null,
    duration:    'permanent',
    reversible:  false,
  },
  [ACTION_TYPES.ROTATE_SECRETS]: {
    description: 'Immediately rotate credentials, API keys, and secrets',
    integration: 'secrets_manager',
    api_endpoint: null,
    duration:    null,
    reversible:  false,
  },
  [ACTION_TYPES.WAF_RULE]: {
    description: 'Deploy Cloudflare WAF rule to block known exploit patterns',
    integration: 'cloudflare_waf',
    api_endpoint: 'POST /client/v4/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint/rules',
    duration:    'permanent',
    reversible:  true,
  },
  [ACTION_TYPES.IDS_SIGNATURE]: {
    description: 'Enable IDS/IPS signature matching for known CVE exploit patterns',
    integration: 'ids_ips',
    api_endpoint: null,
    duration:    'permanent',
    reversible:  true,
  },
  [ACTION_TYPES.THREAT_HUNT]: {
    description: 'Trigger proactive threat hunting for related IOCs in environment',
    integration: 'siem',
    api_endpoint: 'POST /api/v1/hunting',
    duration:    '48h',
    reversible:  false,
  },
  [ACTION_TYPES.MONITOR_ENHANCED]: {
    description: 'Enable enhanced monitoring and logging for affected systems',
    integration: 'monitoring',
    api_endpoint: 'POST /api/monitors',
    duration:    '72h',
    reversible:  true,
  },
};

// ─── Priority matrix ──────────────────────────────────────────────────────────
function computePriority(alert, actionType) {
  const sevScore = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[alert.severity] || 1;
  const urgentActions = [ACTION_TYPES.ISOLATE_SYSTEM, ACTION_TYPES.ALERT_ADMIN, ACTION_TYPES.BLOCK_IP];
  const isUrgent = urgentActions.includes(actionType);

  if (sevScore >= 4 && isUrgent) return 'immediate';
  if (sevScore >= 3 && isUrgent) return 'high';
  if (sevScore >= 3)             return 'high';
  if (sevScore >= 2)             return 'medium';
  return 'low';
}

// ─── Build WAF rule expression for CVE ───────────────────────────────────────
function buildWAFExpression(alert) {
  const cveId = alert.cve_id || '';
  // Generic WAF expression skeleton — to be refined with actual IOC values
  const expressions = [];

  if (cveId.includes('CVE-2024-3400')) {
    expressions.push('(http.request.uri.path contains "/global-protect" and http.request.method eq "POST")');
  } else if (cveId.includes('CVE-2024-21762')) {
    expressions.push('(http.request.uri.path matches "^/remote/.*" and http.request.method eq "GET" and not cf.verified_bot_category in {"Search Engine" "Monitoring & Analytics"})');
  } else {
    // Generic malicious request pattern
    expressions.push(`(http.request.headers["X-CVE-ID"] eq "${cveId}" or http.request.uri.query contains "${cveId}")`);
  }

  return expressions.join(' or ');
}

// ─── Generate response actions for a single alert ─────────────────────────────
export function generateResponseActions(alert) {
  const actionTypes = ALERT_TO_ACTIONS[alert.alert_type] || [ACTION_TYPES.PATCH_ADVISORY, ACTION_TYPES.ALERT_ADMIN];
  const actions     = [];

  for (const actionType of actionTypes) {
    const meta     = ACTION_META[actionType] || {};
    const priority = computePriority(alert, actionType);

    const action = {
      action_id:   `ACT-${actionType.toUpperCase()}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`,
      action:      actionType,
      status:      'recommended',   // recommended | approved | executing | completed | failed
      priority,
      alert_id:    alert.alert_id,
      cve_id:      alert.cve_id,
      description: meta.description,
      integration: meta.integration,
      api_endpoint: meta.api_endpoint,
      duration:    meta.duration,
      reversible:  meta.reversible,
      requires_approval: ['isolate_system', 'block_ip', 'block_domain'].includes(actionType),
      // Payload for integration
      payload:     buildActionPayload(actionType, alert),
      created_at:  new Date().toISOString(),
    };

    actions.push(action);
  }

  return actions.sort((a, b) => {
    const p = { immediate: 0, high: 1, medium: 2, low: 3 };
    return (p[a.priority] ?? 4) - (p[b.priority] ?? 4);
  });
}

// ─── Build integration payload per action type ────────────────────────────────
function buildActionPayload(actionType, alert) {
  switch (actionType) {
    case ACTION_TYPES.BLOCK_IP:
      return {
        rule_type:   'ip',
        source:      'sentinel_apex',
        description: `Block IPs linked to ${alert.cve_id}`,
        mode:        'block',
        ips:         (alert.evidence?.repeated_iocs || [])
                       .filter(i => i.type === 'ip' || (i.ioc || '').match(/^\d+\.\d+\.\d+\.\d+$/))
                       .map(i => i.ioc || i.value).slice(0, 10),
      };

    case ACTION_TYPES.BLOCK_DOMAIN:
      return {
        rule_type:   'domain',
        source:      'sentinel_apex',
        description: `Block domains linked to ${alert.cve_id}`,
        domains:     (alert.evidence?.repeated_iocs || [])
                       .filter(i => i.type === 'domain' || (i.ioc || '').includes('.'))
                       .map(i => i.ioc || i.value).slice(0, 10),
      };

    case ACTION_TYPES.WAF_RULE:
      return {
        action:      'block',
        expression:  buildWAFExpression(alert),
        description: `Sentinel APEX auto-rule: ${alert.cve_id}`,
        enabled:     false,  // require manual approval to enable
      };

    case ACTION_TYPES.PATCH_ADVISORY:
      return {
        cve_id:      alert.cve_id,
        cvss:        alert.cvss,
        severity:    alert.severity,
        title:       alert.title,
        nvd_url:     `https://nvd.nist.gov/vuln/detail/${alert.cve_id}`,
        cisa_url:    alert.evidence?.kev ? `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` : null,
        deadline:    alert.evidence?.kev ? '24h (CISA mandated)' : alert.cvss >= 9.0 ? '72h' : '30d',
        vendor_advisory: null, // populated by enrichment
      };

    case ACTION_TYPES.ALERT_ADMIN:
      return {
        channels:  ['telegram', 'email'],
        priority:  alert.severity === 'CRITICAL' ? 'P1' : 'P2',
        subject:   `[SENTINEL APEX] ${alert.severity} — ${alert.cve_id}`,
        body:      `${alert.title}\n\nCVSS: ${alert.cvss || 'N/A'} | EPSS: ${((alert.epss_score || 0) * 100).toFixed(1)}%\n\nRecommendation: ${alert.recommendation}`,
        oncall:    true,
      };

    case ACTION_TYPES.THREAT_HUNT:
      return {
        hunt_type: 'ioc_scan',
        cve_id:    alert.cve_id,
        hunt_url:  '/api/v1/hunting',
        scope:     'all_entries',
      };

    default:
      return { cve_id: alert.cve_id, alert_type: alert.alert_type };
  }
}

// ─── Process full detection result → response plan ────────────────────────────
export function buildResponsePlan(detectionResult) {
  const allActions = [];

  for (const alert of (detectionResult.alerts || [])) {
    const actions = generateResponseActions(alert);
    allActions.push(...actions);
  }

  // Deduplicate: one action per action type per CVE
  const seen     = new Set();
  const deduped  = allActions.filter(a => {
    const key = `${a.action}:${a.cve_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort: immediate → high → medium → low
  const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3 };
  deduped.sort((a, b) => (priorityOrder[a.priority] ?? 4) - (priorityOrder[b.priority] ?? 4));

  const byAction = {};
  const byPriority = {};
  for (const a of deduped) {
    byAction[a.action]       = (byAction[a.action]       || 0) + 1;
    byPriority[a.priority]   = (byPriority[a.priority]   || 0) + 1;
  }

  return {
    actions:      deduped,
    total:        deduped.length,
    by_action:    byAction,
    by_priority:  byPriority,
    immediate_count: byPriority.immediate || 0,
    plan_built_at: new Date().toISOString(),
  };
}

// ─── Simulate executing an action (Cloudflare API integration stub) ───────────
export async function simulateActionExecution(action, env) {
  // In production: call actual Cloudflare API / webhook / SIEM
  // Here we simulate the integration call and return expected outcome

  const SIMULATION_OUTCOMES = {
    [ACTION_TYPES.BLOCK_IP]:         { status: 'simulated', result: 'IP block rule created in WAF (simulation mode)' },
    [ACTION_TYPES.BLOCK_DOMAIN]:     { status: 'simulated', result: 'Domain block policy created in Gateway (simulation mode)' },
    [ACTION_TYPES.ISOLATE_SYSTEM]:   { status: 'simulated', result: 'Device isolation policy prepared for Zero Trust (simulation mode)' },
    [ACTION_TYPES.WAF_RULE]:         { status: 'simulated', result: 'WAF custom rule prepared — awaiting manual approval to deploy' },
    [ACTION_TYPES.PATCH_ADVISORY]:   { status: 'dispatched', result: 'Patch advisory generated and queued for distribution' },
    [ACTION_TYPES.ALERT_ADMIN]:      { status: 'dispatched', result: 'Alert sent to admin via configured channels' },
    [ACTION_TYPES.THREAT_HUNT]:      { status: 'triggered',  result: 'Threat hunting job queued — check /api/v1/hunting for results' },
    [ACTION_TYPES.IDS_SIGNATURE]:    { status: 'simulated', result: 'IDS/IPS signature activation queued (simulation mode)' },
    [ACTION_TYPES.MONITOR_ENHANCED]: { status: 'triggered',  result: 'Enhanced monitoring enabled for affected assets' },
    [ACTION_TYPES.ROTATE_SECRETS]:   { status: 'advisory',   result: 'Secret rotation advisory dispatched to security team' },
  };

  const outcome = SIMULATION_OUTCOMES[action.action] || { status: 'unknown', result: 'No simulation available' };

  return {
    ...action,
    status:         outcome.status,
    execution_result: outcome.result,
    executed_at:    new Date().toISOString(),
    simulation:     true,
  };
}

// ─── Store response plan in D1 ────────────────────────────────────────────────
export async function storeResponsePlan(env, responsePlan) {
  if (!env?.DB || !responsePlan?.actions?.length) return;

  // Store first 10 high-priority actions
  const toStore = responsePlan.actions.filter(a =>
    ['immediate', 'high'].includes(a.priority)
  ).slice(0, 10);

  for (const action of toStore) {
    env.DB.prepare(`
      INSERT OR IGNORE INTO soc_response_actions
        (id, action, priority, alert_id, cve_id, status, payload, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      action.action_id,
      action.action,
      action.priority,
      action.alert_id || null,
      action.cve_id   || null,
      action.status,
      JSON.stringify(action.payload || {}),
    ).run().catch(() => {});
  }
}
