/**
 * CYBERDUDEBIVASH AI Security Hub — Autonomous Defense Engine v1.0
 * Sentinel APEX v3 Phase 3: Autonomous Cyber Defense
 *
 * Rule-based autonomous defense with:
 *   1. Defense policy evaluation (IF threat_condition THEN defense_action)
 *   2. Auto-mitigation hook design for Cloudflare APIs
 *   3. Threat containment simulation (lateral movement, data exfil blocking)
 *   4. Defense action log + audit trail
 *   5. Defense posture scoring (0–100)
 *
 * Defense actions:
 *   auto_block        → Block IP/domain automatically (policy-driven)
 *   emergency_patch   → Trigger emergency patch advisory
 *   waf_deploy        → Deploy WAF rule to Cloudflare zone
 *   isolate_segment   → Network segment isolation recommendation
 *   exfil_block       → Data exfiltration prevention rules
 *   lateral_prevent   → Lateral movement prevention via Zero Trust
 *   honeypot_trigger  → Alert on honeypot interaction (future)
 *   rate_limit        → Apply aggressive rate limiting to endpoint
 */

// ─── Defense rule engine ──────────────────────────────────────────────────────
const DEFENSE_RULES = [
  {
    id:       'RULE-001',
    name:     'Critical CVSS Auto-Block IOCs',
    priority: 1,
    condition: (entry, decision) =>
      (entry?.cvss || 0) >= 9.0 && entry?.actively_exploited,
    action:   'auto_block',
    target_type: 'ioc',
    duration: '24h',
    reason:   'CVSS ≥ 9.0 with active exploitation — auto-blocking known IOCs',
  },
  {
    id:       'RULE-002',
    name:     'KEV Emergency Response',
    priority: 1,
    condition: (entry) =>
      entry?.exploit_status === 'confirmed' && (entry?.known_ransomware || entry?.source === 'cisa_kev'),
    action:   'emergency_patch',
    target_type: 'system',
    duration: 'until_patched',
    reason:   'CISA KEV confirmed exploit — emergency patch + containment',
  },
  {
    id:       'RULE-003',
    name:     'Ransomware IOC Auto-Block',
    priority: 1,
    condition: (entry) => {
      try {
        const tags = JSON.parse(entry?.tags || '[]');
        return tags.some(t => ['Ransomware', 'RansomwareLinked'].includes(t)) && entry?.exploit_status === 'confirmed';
      } catch { return false; }
    },
    action:   'auto_block',
    target_type: 'ioc',
    duration: '7d',
    reason:   'Ransomware campaign IOCs — extended auto-block applied',
  },
  {
    id:       'RULE-004',
    name:     'WAF Deploy for Web Exploits',
    priority: 2,
    condition: (entry) => {
      try {
        const tags = JSON.parse(entry?.tags || '[]');
        return ['RCE', 'SQLi', 'XSS', 'CmdInjection', 'PathTraversal'].some(t => tags.includes(t))
               && (entry?.cvss || 0) >= 8.0;
      } catch { return false; }
    },
    action:   'waf_deploy',
    target_type: 'web_application',
    duration: 'permanent',
    reason:   'Web exploit CVE — WAF rule deployed to block attack patterns',
  },
  {
    id:       'RULE-005',
    name:     'Network Isolation for Container Escapes',
    priority: 1,
    condition: (entry) => {
      try {
        const tags = JSON.parse(entry?.tags || '[]');
        return tags.includes('ContainerEscape') || tags.includes('CloudSecurity');
      } catch { return false; }
    },
    action:   'isolate_segment',
    target_type: 'network_segment',
    duration: 'until_patched',
    reason:   'Container/cloud escape vulnerability — network segment isolation recommended',
  },
  {
    id:       'RULE-006',
    name:     'High EPSS Pre-emptive WAF',
    priority: 2,
    condition: (entry) => (entry?.epss_score || 0) >= 0.80 && (entry?.cvss || 0) >= 8.0,
    action:   'waf_deploy',
    target_type: 'web_application',
    duration: '72h',
    reason:   'EPSS ≥ 80% with high CVSS — pre-emptive WAF rule before exploitation',
  },
  {
    id:       'RULE-007',
    name:     'Auth Bypass Rate Limiting',
    priority: 2,
    condition: (entry) => {
      try {
        const cwes = JSON.parse(entry?.weakness_types || '[]');
        return cwes.some(w => ['CWE-287', 'CWE-288', 'CWE-306', 'CWE-798'].includes(w))
               && (entry?.cvss || 0) >= 8.5;
      } catch { return false; }
    },
    action:   'rate_limit',
    target_type: 'auth_endpoint',
    duration: '48h',
    reason:   'Auth bypass CVE — aggressive rate limiting on authentication endpoints',
  },
  {
    id:       'RULE-008',
    name:     'Data Exfiltration Prevention',
    priority: 2,
    condition: (entry, _, context = {}) => {
      return context?.exfil_risk || (entry?.exploit_status === 'confirmed' && (entry?.cvss || 0) >= 8.0);
    },
    action:   'exfil_block',
    target_type: 'data_channel',
    duration: '24h',
    reason:   'Confirmed exploit with high CVSS — data exfiltration prevention activated',
  },
  {
    id:       'RULE-009',
    name:     'Lateral Movement Prevention',
    priority: 2,
    condition: (entry) => {
      try {
        const tags = JSON.parse(entry?.tags || '[]');
        return tags.some(t => ['PrivEsc', 'LateralMovement', 'Ransomware'].includes(t))
               && entry?.exploit_status === 'confirmed';
      } catch { return false; }
    },
    action:   'lateral_prevent',
    target_type: 'network',
    duration: 'until_resolved',
    reason:   'Privilege escalation/lateral movement CVE — Zero Trust enforcement applied',
  },
  {
    id:       'RULE-010',
    name:     'Supply Chain Freeze',
    priority: 3,
    condition: (entry) => {
      const text = `${entry?.title || ''} ${entry?.description || ''}`.toLowerCase();
      return ['supply chain', 'npm', 'pypi', 'ci/cd'].some(k => text.includes(k))
             && (entry?.cvss || 0) >= 7.5;
    },
    action:   'emergency_patch',
    target_type: 'build_pipeline',
    duration: 'until_audited',
    reason:   'Supply chain threat — pipeline freeze and audit recommended',
  },
];

// ─── Defense action payloads ──────────────────────────────────────────────────
function buildDefensePayload(rule, entry) {
  const cveId = entry.id;
  const iocList = (() => {
    try {
      const v = entry.ioc_list || entry.iocs;
      return Array.isArray(v) ? v : JSON.parse(v || '[]');
    } catch { return []; }
  })();

  switch (rule.action) {
    case 'auto_block':
      return {
        ips:     iocList.filter(i => (i.type || '').includes('ip') || /^\d+\.\d+/.test(i.value || i)).map(i => i.value || i).slice(0, 20),
        domains: iocList.filter(i => (i.type || '').includes('domain')).map(i => i.value || i).slice(0, 20),
        // Cloudflare Firewall API stub
        cf_rule: {
          action:      'block',
          description: `Sentinel APEX v3 auto-block: ${cveId}`,
          expression:  iocList.slice(0, 5).map(i => {
            const val = i.value || i;
            return /^\d+\./.test(val)
              ? `ip.src eq ${val}`
              : `http.host eq "${val}"`;
          }).join(' or ') || `(http.request.headers["X-CVE-Ref"] eq "${cveId}")`,
        },
      };

    case 'waf_deploy':
      return {
        rule_name:  `sentinel-apex-${cveId.toLowerCase()}`,
        action:     'managed_challenge',
        expression: `(http.request.uri.path contains "/wp-admin" or http.request.uri.path contains "/admin") and not cf.verified_bot_category in {"Search Engine"}`,
        // Will be replaced with CVE-specific WAF expression in production
        enabled:    false, // require human approval in production
        cf_ruleset: 'http_request_firewall_custom',
      };

    case 'rate_limit':
      return {
        threshold:   20,  // requests per minute per IP
        period:      60,
        action:      'simulate_challenge',
        paths:       ['/api/auth', '/api/login', '/api/signin', '/wp-login.php'],
        description: `Rate limit for ${cveId} auth bypass risk`,
      };

    case 'exfil_block':
      return {
        dlp_policy:  'block_sensitive_outbound',
        patterns:    ['credit_card', 'ssn', 'api_key', 'private_key'],
        destinations: ['all_external'],
        cf_integration: 'cloudflare_gateway_dlp',
      };

    case 'lateral_prevent':
      return {
        zt_policy:   'deny_east_west_unauthenticated',
        scope:       'all_private_networks',
        cf_integration: 'cloudflare_zero_trust',
        verify_posture: true,
      };

    case 'isolate_segment':
      return {
        action:      'network_segment_isolate',
        scope:       rule.target_type,
        cf_integration: 'cloudflare_zero_trust',
        allow_management_access: true,
      };

    case 'emergency_patch':
      return {
        cve_id,
        cvss:        entry.cvss,
        nvd_url:     `https://nvd.nist.gov/vuln/detail/${cveId}`,
        vendor_url:  entry.source_url || null,
        deadline:    entry.known_ransomware ? '24h' : entry.cvss >= 9.0 ? '48h' : '72h',
        patch_status:'pending',
      };

    default:
      return { cve_id: cveId, rule_id: rule.id };
  }
}

// ─── Evaluate defense rules for a single entry ────────────────────────────────
export function evaluateDefenseRules(entry, decision = null, context = {}) {
  const triggered = [];

  for (const rule of DEFENSE_RULES.sort((a, b) => a.priority - b.priority)) {
    try {
      if (rule.condition(entry, decision, context)) {
        triggered.push({
          defense_id:   `DEF-${rule.id}-${entry.id}-${Date.now().toString(36)}`,
          rule_id:      rule.id,
          rule_name:    rule.name,
          defense_action: rule.action,
          target:       entry.id,
          target_type:  rule.target_type,
          duration:     rule.duration,
          priority:     rule.priority,
          reason:       rule.reason,
          status:       'triggered',   // triggered | approved | executing | completed
          simulation:   true,          // false in production with real CF API calls
          payload:      buildDefensePayload(rule, entry),
          triggered_at: new Date().toISOString(),
        });
      }
    } catch {}
  }

  return triggered;
}

// ─── Containment simulation: lateral movement ─────────────────────────────────
export function simulateLateralMovementPrevention(entries = []) {
  const highRiskEntries = entries.filter(e =>
    e.exploit_status === 'confirmed' && (e.cvss || 0) >= 8.0
  );

  if (highRiskEntries.length === 0) {
    return { simulation: 'no_action_required', blocked_paths: 0 };
  }

  // Generate simulated network path blocks
  const blockedPaths = highRiskEntries.slice(0, 5).map(e => ({
    cve_id:       e.id,
    blocked_from: 'compromised_endpoint',
    blocked_to:   'internal_network',
    method:       'zero_trust_policy',
    cf_action:    'Cloudflare Zero Trust device posture check',
    status:       'simulated',
  }));

  return {
    simulation:      'lateral_movement_prevention',
    blocked_paths:   blockedPaths.length,
    paths:           blockedPaths,
    cf_integration:  'cloudflare_zero_trust',
    policy_applied:  'deny_unverified_east_west',
    simulated_at:    new Date().toISOString(),
  };
}

// ─── Containment simulation: data exfiltration ───────────────────────────────
export function simulateExfiltrationBlocking(entries = []) {
  const exfilRisk = entries.filter(e =>
    (e.cvss || 0) >= 8.5 && e.exploit_status === 'confirmed'
  );

  if (exfilRisk.length === 0) {
    return { simulation: 'no_exfil_risk', blocked_channels: 0 };
  }

  return {
    simulation:       'data_exfiltration_blocking',
    risk_entries:     exfilRisk.length,
    blocked_channels: ['DNS_over_HTTPS', 'HTTPS_to_external', 'FTP', 'SMTP'],
    dlp_policies:     ['block_PII', 'block_API_keys', 'block_private_keys', 'block_credit_cards'],
    cf_integration:   'cloudflare_gateway_dlp',
    policy_status:    'simulated',
    simulated_at:     new Date().toISOString(),
  };
}

// ─── Run full autonomous defense for a feed ───────────────────────────────────
export function runAutonomousDefense(entries = [], decisions = []) {
  const allActions = [];
  const dedupeSet  = new Set();

  for (const entry of entries) {
    const entryDecision = decisions.find(d => d.cve_id === entry.id);
    const context = {
      exfil_risk: entryDecision?.decision === 'escalate' || entryDecision?.decision === 'auto_contain',
    };

    const triggered = evaluateDefenseRules(entry, entryDecision, context);

    for (const action of triggered) {
      const key = `${action.defense_action}:${action.target}`;
      if (!dedupeSet.has(key)) {
        dedupeSet.add(key);
        allActions.push(action);
      }
    }
  }

  // Sort by priority (ascending — priority 1 first)
  allActions.sort((a, b) => (a.priority || 3) - (b.priority || 3));

  // Compute defense posture score
  const criticalDefended = allActions.filter(a => a.priority === 1).length;
  const totalThreats     = entries.filter(e => (e.cvss || 0) >= 9.0 || e.exploit_status === 'confirmed').length;
  const postureScore     = totalThreats > 0
    ? Math.min(100, Math.round((criticalDefended / totalThreats) * 100))
    : 100;

  const byAction = {};
  for (const a of allActions) {
    byAction[a.defense_action] = (byAction[a.defense_action] || 0) + 1;
  }

  return {
    defense_actions:     allActions,
    total_actions:       allActions.length,
    by_action:           byAction,
    defense_posture:     postureScore,
    posture_level:       postureScore >= 80 ? 'STRONG' : postureScore >= 50 ? 'MODERATE' : 'WEAK',
    containment_sim:     {
      lateral_movement: simulateLateralMovementPrevention(entries),
      exfiltration:     simulateExfiltrationBlocking(entries),
    },
    defended_at:         new Date().toISOString(),
  };
}

// ─── Store defense actions in D1 ─────────────────────────────────────────────
export async function storeDefenseActions(env, defenseResult) {
  if (!env?.DB || !defenseResult?.defense_actions?.length) return;

  const toStore = defenseResult.defense_actions.slice(0, 20);

  for (const action of toStore) {
    env.DB.prepare(`
      INSERT OR IGNORE INTO soc_defense_actions
        (id, rule_id, defense_action, target, target_type, duration, status, payload, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      action.defense_id,
      action.rule_id,
      action.defense_action,
      action.target || null,
      action.target_type || null,
      action.duration || null,
      action.status || 'triggered',
      JSON.stringify(action.payload || {}),
    ).run().catch(() => {});
  }
}

// ─── Get defense posture summary ─────────────────────────────────────────────
export async function getDefensePosture(env) {
  if (!env?.DB) return { posture: 'UNKNOWN', actions_today: 0 };

  try {
    const [actionsToday, latestActions] = await Promise.all([
      env.DB.prepare(`
        SELECT COUNT(*) as n FROM soc_defense_actions
        WHERE created_at >= datetime('now', '-24 hours')
      `).first(),
      env.DB.prepare(`
        SELECT defense_action, COUNT(*) as n FROM soc_defense_actions
        GROUP BY defense_action ORDER BY n DESC LIMIT 10
      `).all(),
    ]);

    return {
      actions_today:  actionsToday?.n || 0,
      top_actions:    latestActions?.results || [],
      posture:        (actionsToday?.n || 0) > 0 ? 'ACTIVE' : 'STANDBY',
    };
  } catch {
    return { posture: 'UNKNOWN', actions_today: 0 };
  }
}
