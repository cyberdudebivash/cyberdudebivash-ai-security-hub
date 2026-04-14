/**
 * CYBERDUDEBIVASH AI Security Hub — SOC Detection Engine v1.0
 * Sentinel APEX v3 Phase 2a: AI SOC Automation — Detection
 *
 * Detects and generates structured SOC alerts from threat intel:
 *   - CVSS ≥ 9.0 critical vulnerability alerts
 *   - CISA KEV confirmed exploitation alerts
 *   - Repeated IOC pattern detection
 *   - Anomaly clusters (same vendor, same campaign)
 *   - EPSS spike detection (≥ 0.75 = imminent)
 *   - Ransomware campaign indicators
 *   - Zero-day exploitation in the wild
 *
 * Output: SOCAlert { alert_id, alert_type, severity, asset, recommendation, evidence }
 */

// ─── Alert type catalog ───────────────────────────────────────────────────────
export const ALERT_TYPES = {
  CRITICAL_VULNERABILITY:    'critical_vulnerability',
  KEV_CONFIRMED_EXPLOIT:     'kev_confirmed_exploit',
  ZERO_DAY_ACTIVE:           'zero_day_active',
  HIGH_EPSS_RISK:            'high_epss_risk',
  RANSOMWARE_INDICATOR:      'ransomware_indicator',
  IOC_PATTERN_REPEAT:        'ioc_pattern_repeat',
  ANOMALY_CLUSTER:           'anomaly_cluster',
  SUPPLY_CHAIN_THREAT:       'supply_chain_threat',
  EXPLOIT_PUBLIC:            'exploit_public',
  NEW_CRITICAL_CVE:          'new_critical_cve',
  THREAT_ACTOR_ATTRIBUTED:   'threat_actor_attributed',
};

// ─── Recommendation templates per alert type ──────────────────────────────────
const RECOMMENDATIONS = {
  [ALERT_TYPES.CRITICAL_VULNERABILITY]:  'Apply vendor patch immediately. Enable IDS/IPS signatures. Review affected systems.',
  [ALERT_TYPES.KEV_CONFIRMED_EXPLOIT]:   'CISA mandates remediation. Isolate affected systems. Apply emergency patch within 24h.',
  [ALERT_TYPES.ZERO_DAY_ACTIVE]:         'No patch available. Apply compensating controls. Monitor for IOCs. Restrict network access.',
  [ALERT_TYPES.HIGH_EPSS_RISK]:          'Exploit predicted with high probability. Pre-emptive patching strongly recommended.',
  [ALERT_TYPES.RANSOMWARE_INDICATOR]:    'Isolate affected endpoints. Block C2 IOCs. Engage IR team. Verify backup integrity.',
  [ALERT_TYPES.IOC_PATTERN_REPEAT]:      'Block all matching IOCs in firewall/WAF. Investigate network traffic. Check SIEM logs.',
  [ALERT_TYPES.ANOMALY_CLUSTER]:         'Investigate vendor patch status. Correlate internal scan findings. Review exposure surface.',
  [ALERT_TYPES.SUPPLY_CHAIN_THREAT]:     'Audit third-party dependencies. Freeze deployments pending investigation. Check SBOMs.',
  [ALERT_TYPES.EXPLOIT_PUBLIC]:          'Public exploit increases risk. Fast-track patching. Enable IPS rules if available.',
  [ALERT_TYPES.NEW_CRITICAL_CVE]:        'Assess exposure. Identify affected assets. Schedule emergency patch cycle.',
  [ALERT_TYPES.THREAT_ACTOR_ATTRIBUTED]: 'Review TTPs for this actor. Check MITRE ATT&CK. Hunt for IOCs in environment.',
};

// ─── Parse helpers ────────────────────────────────────────────────────────────
function parseTags(entry) {
  try { return JSON.parse(entry.tags || '[]'); } catch { return []; }
}
function parseIOCs(entry) {
  try {
    const v = entry.ioc_list || entry.iocs;
    return Array.isArray(v) ? v : JSON.parse(v || '[]');
  } catch { return []; }
}

// ─── Alert factory ─────────────────────────────────────────────────────────────
function makeAlert(type, severity, entry, extra = {}) {
  const tags    = parseTags(entry);
  const affected = (() => { try { return JSON.parse(entry.affected_products || '["unknown"]'); } catch { return ['unknown']; } })();

  return {
    alert_id:       `ALERT-${type.toUpperCase()}-${entry.id}-${Date.now().toString(36)}`,
    alert_type:     type,
    severity:       severity.toUpperCase(),
    cve_id:         entry.id,
    asset:          affected[0] || 'unknown',
    title:          entry.title || entry.id,
    cvss:           entry.cvss  || null,
    epss_score:     entry.epss_score || null,
    exploit_status: entry.exploit_status || 'unconfirmed',
    actively_exploited: !!(entry.actively_exploited || entry.exploit_status === 'confirmed'),
    recommendation: RECOMMENDATIONS[type] || 'Investigate and remediate as appropriate.',
    source:         entry.source || 'unknown',
    tags,
    evidence: {
      cvss:            entry.cvss,
      epss:            entry.epss_score,
      exploit_status:  entry.exploit_status,
      kev:             !!entry.known_ransomware,
      actively_expl:   !!(entry.actively_exploited || entry.exploit_status === 'confirmed'),
      ...extra,
    },
    generated_at: new Date().toISOString(),
  };
}

// ─── DETECTOR 1: Critical CVSS vulnerabilities (≥ 9.0) ───────────────────────
function detectCriticalCVSS(entries) {
  return entries
    .filter(e => (e.cvss || 0) >= 9.0 || e.severity === 'CRITICAL')
    .map(e => makeAlert(
      ALERT_TYPES.CRITICAL_VULNERABILITY,
      'CRITICAL',
      e,
      { trigger: `CVSS ${e.cvss} >= 9.0`, severity_label: e.severity }
    ));
}

// ─── DETECTOR 2: CISA KEV confirmed exploits ─────────────────────────────────
function detectKEVExploits(entries) {
  return entries
    .filter(e => e.exploit_status === 'confirmed' &&
                (e.source === 'cisa_kev' || e.known_ransomware || e.actively_exploited))
    .map(e => makeAlert(
      ALERT_TYPES.KEV_CONFIRMED_EXPLOIT,
      'CRITICAL',
      e,
      { trigger: 'CISA KEV confirmed exploitation', source: e.source }
    ));
}

// ─── DETECTOR 3: Zero-day active exploitation ─────────────────────────────────
function detectZeroDays(entries) {
  return entries
    .filter(e => {
      const tags = parseTags(e);
      return (tags.some(t => ['ZeroDay', '0day', 'zero-day'].includes(t))
              && e.exploit_status === 'confirmed')
          || (e.actively_exploited && (e.cvss || 0) >= 8.5);
    })
    .map(e => makeAlert(
      ALERT_TYPES.ZERO_DAY_ACTIVE,
      'CRITICAL',
      e,
      { trigger: 'Zero-day actively exploited in the wild' }
    ));
}

// ─── DETECTOR 4: High EPSS risk (≥ 0.75) ─────────────────────────────────────
function detectHighEPSS(entries) {
  return entries
    .filter(e => (e.epss_score || 0) >= 0.75 && e.exploit_status !== 'confirmed')
    .map(e => makeAlert(
      ALERT_TYPES.HIGH_EPSS_RISK,
      'HIGH',
      e,
      { trigger: `EPSS ${((e.epss_score || 0) * 100).toFixed(1)}% — imminent exploitation predicted` }
    ));
}

// ─── DETECTOR 5: Ransomware indicators ───────────────────────────────────────
function detectRansomware(entries) {
  return entries
    .filter(e => {
      const tags = parseTags(e);
      return e.known_ransomware
          || tags.some(t => ['Ransomware', 'RansomwareLinked'].includes(t));
    })
    .map(e => makeAlert(
      ALERT_TYPES.RANSOMWARE_INDICATOR,
      e.actively_exploited ? 'CRITICAL' : 'HIGH',
      e,
      { trigger: 'Ransomware campaign association confirmed' }
    ));
}

// ─── DETECTOR 6: Repeated IOC patterns (same IOC across ≥ 2 entries) ─────────
function detectRepeatedIOCs(entries) {
  const iocMap = {};

  for (const entry of entries) {
    const iocs = parseIOCs(entry);
    for (const ioc of iocs) {
      const val = typeof ioc === 'string' ? ioc : (ioc.value || '');
      if (!val || val.length < 4) continue;
      if (!iocMap[val]) iocMap[val] = [];
      iocMap[val].push(entry.id);
    }
  }

  const repeated = Object.entries(iocMap).filter(([, cves]) => cves.length >= 2);
  if (repeated.length === 0) return [];

  return [makeAlert(
    ALERT_TYPES.IOC_PATTERN_REPEAT,
    'HIGH',
    entries[0] || { id: 'multi', title: 'Multi-CVE IOC Pattern', source: 'federation' },
    {
      trigger:       `${repeated.length} IOCs appear across multiple CVEs`,
      repeated_iocs: repeated.slice(0, 5).map(([ioc, cves]) => ({ ioc, cve_count: cves.length })),
    }
  )];
}

// ─── DETECTOR 7: Anomaly cluster (≥ 3 CRITICAL CVEs same vendor) ─────────────
function detectAnomalyClusters(entries) {
  const VENDOR_KW = [
    ['palo alto', 'panos', 'pan-os'],
    ['fortinet', 'fortigate', 'fortios'],
    ['cisco', 'ios xe'],
    ['microsoft', 'windows', 'exchange'],
    ['ivanti', 'pulse'],
    ['citrix', 'netscaler'],
    ['apache', 'log4j'],
    ['vmware', 'vcenter'],
  ];

  const alerts = [];

  for (const kwGroup of VENDOR_KW) {
    const vendor  = kwGroup[0];
    const matched = entries.filter(e => {
      const text = `${e.title} ${e.description || ''}`.toLowerCase();
      return kwGroup.some(k => text.includes(k)) && ((e.cvss || 0) >= 8.0 || e.severity === 'CRITICAL');
    });

    if (matched.length >= 3) {
      const exploited = matched.filter(e => e.exploit_status === 'confirmed');
      alerts.push(makeAlert(
        ALERT_TYPES.ANOMALY_CLUSTER,
        exploited.length >= 2 ? 'CRITICAL' : 'HIGH',
        matched[0],
        {
          trigger:    `${matched.length} high-risk CVEs targeting ${vendor}`,
          vendor,
          count:      matched.length,
          exploited:  exploited.length,
          cve_ids:    matched.slice(0, 4).map(e => e.id),
        }
      ));
    }
  }

  return alerts;
}

// ─── DETECTOR 8: Supply chain threats ────────────────────────────────────────
function detectSupplyChain(entries) {
  const SC_KW = ['supply chain', 'ci/cd', 'npm', 'pypi', 'github actions', 'jenkins',
                 'teamcity', 'artifactory', 'sonar', 'maven', 'gradle'];
  const matched = entries.filter(e => {
    const text = `${e.title} ${e.description || ''}`.toLowerCase();
    const tags = parseTags(e).map(t => t.toLowerCase());
    return SC_KW.some(k => text.includes(k) || tags.includes(k));
  });

  return matched.slice(0, 3).map(e => makeAlert(
    ALERT_TYPES.SUPPLY_CHAIN_THREAT,
    'HIGH',
    e,
    { trigger: 'Supply chain component affected' }
  ));
}

// ─── DETECTOR 9: Public exploit now available ─────────────────────────────────
function detectPublicExploit(entries) {
  return entries
    .filter(e => e.exploit_available && e.exploit_status === 'poc_available'
              && (e.cvss || 0) >= 8.0)
    .map(e => makeAlert(
      ALERT_TYPES.EXPLOIT_PUBLIC,
      'HIGH',
      e,
      { trigger: 'Public PoC exploit available', exploit_source: e.source }
    ));
}

// ─── DEDUP alerts (same CVE + same type = one alert) ─────────────────────────
function deduplicateAlerts(alerts) {
  const seen = new Set();
  return alerts.filter(a => {
    const key = `${a.alert_type}:${a.cve_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── MASTER: Run detection on a feed of entries ───────────────────────────────
export function runDetection(entries = []) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return { alerts: [], total: 0, by_type: {}, by_severity: {}, detected_at: new Date().toISOString() };
  }

  const rawAlerts = [
    ...detectCriticalCVSS(entries),
    ...detectKEVExploits(entries),
    ...detectZeroDays(entries),
    ...detectHighEPSS(entries),
    ...detectRansomware(entries),
    ...detectRepeatedIOCs(entries),
    ...detectAnomalyClusters(entries),
    ...detectSupplyChain(entries),
    ...detectPublicExploit(entries),
  ];

  const alerts = deduplicateAlerts(rawAlerts).sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });

  // Aggregate counts
  const byType     = {};
  const bySeverity = {};
  for (const alert of alerts) {
    byType[alert.alert_type]  = (byType[alert.alert_type]  || 0) + 1;
    bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
  }

  return {
    alerts,
    total:       alerts.length,
    by_type:     byType,
    by_severity: bySeverity,
    detected_at: new Date().toISOString(),
  };
}

// ─── Store detection run in D1 ────────────────────────────────────────────────
export async function storeDetectionResults(env, detectionResult) {
  if (!env?.DB || !detectionResult?.alerts?.length) return;

  const critAlerts = detectionResult.alerts
    .filter(a => ['CRITICAL', 'HIGH'].includes(a.severity))
    .slice(0, 20);

  for (const alert of critAlerts) {
    env.DB.prepare(`
      INSERT OR IGNORE INTO soc_alerts
        (id, alert_type, severity, cve_id, title, asset, recommendation, evidence, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      alert.alert_id,
      alert.alert_type,
      alert.severity,
      alert.cve_id,
      (alert.title || '').slice(0, 200),
      alert.asset || 'unknown',
      alert.recommendation || '',
      JSON.stringify(alert.evidence || {}),
    ).run().catch(() => {});
  }
}

// ─── Get latest alerts from D1 ───────────────────────────────────────────────
export async function getStoredAlerts(env, limit = 50, severity = null) {
  if (!env?.DB) return [];
  try {
    const where    = severity ? 'WHERE severity = ?' : '';
    const bindings = severity ? [severity, limit] : [limit];
    const rows = await env.DB.prepare(
      `SELECT * FROM soc_alerts ${where} ORDER BY created_at DESC LIMIT ?`
    ).bind(...bindings).all();
    return rows?.results || [];
  } catch {
    return [];
  }
}
