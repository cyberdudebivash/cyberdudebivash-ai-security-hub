/**
 * CYBERDUDEBIVASH AI Security Hub
 * DECISION ENGINE — Rule + ML hybrid for autonomous remediation decisions
 * Determines WHAT action to take, WHEN, on WHICH target, at WHAT priority.
 */

// Risk thresholds
const RISK_THRESHOLDS = {
  CRITICAL: { min_cvss: 9.0, min_epss: 0.6,  auto_execute: true,  delay_ms: 0     },
  HIGH:     { min_cvss: 7.0, min_epss: 0.3,  auto_execute: true,  delay_ms: 5000  },
  MEDIUM:   { min_cvss: 4.0, min_epss: 0.1,  auto_execute: false, delay_ms: 30000 },
  LOW:      { min_cvss: 0.0, min_epss: 0.0,  auto_execute: false, delay_ms: 0     },
};

// Known attack patterns mapped to remediation actions
const ATTACK_PATTERNS = [
  {
    name:    'brute_force',
    signals: ['failed_login_burst', 'multiple_ips_same_user', 'rapid_auth_attempts'],
    actions: ['block_ip', 'rate_limit_ip', 'disable_session'],
    risk:    'HIGH',
    weight:  0.85,
  },
  {
    name:    'credential_stuffing',
    signals: ['many_failed_logins', 'distributed_ips', 'known_breach_passwords'],
    actions: ['block_ip', 'rotate_credentials', 'rate_limit_ip'],
    risk:    'CRITICAL',
    weight:  0.90,
  },
  {
    name:    'api_abuse',
    signals: ['api_rate_spike', 'unusual_endpoint_access', 'scraping_pattern'],
    actions: ['rate_limit_ip', 'block_ip'],
    risk:    'MEDIUM',
    weight:  0.70,
  },
  {
    name:    'session_hijack',
    signals: ['geo_jump', 'ip_change_active_session', 'ua_change'],
    actions: ['disable_session', 'rotate_credentials'],
    risk:    'HIGH',
    weight:  0.88,
  },
  {
    name:    'insider_threat',
    signals: ['off_hours_access', 'bulk_download', 'privilege_escalation'],
    actions: ['disable_session', 'rotate_credentials', 'alert_admin'],
    risk:    'CRITICAL',
    weight:  0.92,
  },
  {
    name:    'cve_exploitation',
    signals: ['known_cve_pattern', 'payload_match', 'exploit_path'],
    actions: ['apply_virtual_patch', 'block_ip', 'rate_limit_ip'],
    risk:    'CRITICAL',
    weight:  0.95,
  },
];

// CVE to patch config mapping (deterministic, based on CWE/attack vector)
const CVE_PATCH_CONFIGS = {
  // Path traversal
  'path_traversal':    { patch_type: 'path_block',       rule_pattern: '(\\.\\./|%2e%2e%2f|%252e%252e%252f)' },
  // SQL injection
  'sql_injection':     { patch_type: 'param_filter',     rule_pattern: '(\\bunion\\b.*\\bselect\\b|\\bor\\b\\s+1=1|\\bdrop\\b\\s+\\btable\\b)' },
  // XSS
  'xss':               { patch_type: 'header_injection', rule_pattern: '(<script|javascript:|onerror=|onload=)' },
  // RCE / command injection
  'rce':               { patch_type: 'path_block',       rule_pattern: '(;\\s*(cat|curl|wget|bash|sh|python|nc)|`.*`|\\$\\(.*\\))' },
  // Log4Shell style
  'jndi_injection':    { patch_type: 'param_filter',     rule_pattern: '(\\$\\{jndi:|\\$\\{\\$\\{|\\$\\{lower:)' },
  // File upload
  'file_upload':       { patch_type: 'path_block',       rule_pattern: '\\.(php|asp|aspx|jsp|exe|sh|bat)\\b' },
  // SSRF
  'ssrf':              { patch_type: 'param_filter',     rule_pattern: '(localhost|127\\.0\\.0\\.1|169\\.254\\.169\\.254|::1)' },
  // Default
  'default':           { patch_type: 'rate_limit',       rule_pattern: '' },
};

/**
 * Score a CVE event and decide what actions to take
 */
export function decideCVEResponse(cveData) {
  const { cvss = 0, epss = 0, is_kev = false, description = '', cve_id = '' } = cveData;

  // Base decision score: weighted combination
  let score = 0;
  score += (cvss / 10) * 40;       // CVSS: 0–40
  score += Math.min(epss, 1) * 35; // EPSS: 0–35
  score += is_kev ? 20 : 0;        // KEV: +20 bonus
  score += (cvss >= 9.0 ? 5 : 0);  // Critical CVSS: +5

  const riskLevel = score >= 85 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';

  // Determine patch type from description
  const desc = description.toLowerCase();
  let patchCategory = 'default';
  if (desc.includes('path traversal') || desc.includes('directory traversal')) patchCategory = 'path_traversal';
  else if (desc.includes('sql injection') || desc.includes('sql')) patchCategory = 'sql_injection';
  else if (desc.includes('cross-site scripting') || desc.includes('xss')) patchCategory = 'xss';
  else if (desc.includes('remote code execution') || desc.includes('command injection')) patchCategory = 'rce';
  else if (desc.includes('jndi') || desc.includes('log4')) patchCategory = 'jndi_injection';
  else if (desc.includes('file upload') || desc.includes('unrestricted upload')) patchCategory = 'file_upload';
  else if (desc.includes('server-side request forgery') || desc.includes('ssrf')) patchCategory = 'ssrf';

  const patchConfig = CVE_PATCH_CONFIGS[patchCategory] || CVE_PATCH_CONFIGS.default;

  const actions = [];

  // CRITICAL/HIGH CVEs with KEV: apply virtual patch + alert
  if (riskLevel === 'CRITICAL' || (riskLevel === 'HIGH' && is_kev)) {
    actions.push({
      action_type: 'apply_virtual_patch',
      priority: 1,
      patch_config: { ...patchConfig, expires_hours: 168, priority: riskLevel === 'CRITICAL' ? 10 : 50 },
    });
    if (riskLevel === 'CRITICAL') {
      actions.push({ action_type: 'alert_admin', priority: 2 });
    }
  }

  return {
    cve_id,
    risk_level: riskLevel,
    decision_score: Math.round(score * 10) / 10,
    should_auto_execute: score >= 60,
    actions,
    reasoning: `CVSS ${cvss} (${(cvss/10*40).toFixed(1)}pts) + EPSS ${(epss*100).toFixed(1)}% (${(epss*35).toFixed(1)}pts) + KEV ${is_kev ? 'YES (+20pts)' : 'NO'} = ${score.toFixed(1)}/100`,
    patch_category: patchCategory,
  };
}

/**
 * Score an anomaly event and decide what actions to take
 */
export function decideAnomalyResponse(anomalyData) {
  const { anomaly_score = 0, anomaly_types = [], user_id, ip } = anomalyData;

  const riskLevel = anomaly_score >= 80 ? 'CRITICAL' : anomaly_score >= 60 ? 'HIGH' : anomaly_score >= 40 ? 'MEDIUM' : 'LOW';
  const actions = [];

  if (anomaly_score >= 80) {
    // Critical: disable session + rotate credentials
    if (user_id) actions.push({ action_type: 'disable_session', target: user_id, target_type: 'user_id', priority: 1 });
    if (user_id) actions.push({ action_type: 'rotate_credentials', target: user_id, target_type: 'user_id', priority: 2 });
    if (ip) actions.push({ action_type: 'block_ip', target: ip, target_type: 'ip', priority: 1, expiry_hours: 12 });
  } else if (anomaly_score >= 60) {
    // High: rate limit + disable session
    if (ip) actions.push({ action_type: 'rate_limit_ip', target: ip, target_type: 'ip', priority: 1 });
    if (user_id && anomaly_types.includes('geo_anomaly')) {
      actions.push({ action_type: 'disable_session', target: user_id, target_type: 'user_id', priority: 2 });
    }
  } else if (anomaly_score >= 40) {
    // Medium: rate limit only
    if (ip) actions.push({ action_type: 'rate_limit_ip', target: ip, target_type: 'ip', priority: 1 });
  }

  return {
    risk_level: riskLevel,
    decision_score: anomaly_score,
    should_auto_execute: anomaly_score >= 60,
    actions,
    reasoning: `Anomaly score ${anomaly_score}/100. Types: ${anomaly_types.join(', ')}`,
  };
}

/**
 * Match incoming event against known attack patterns
 */
export function matchAttackPattern(signals = []) {
  let bestMatch = null;
  let bestScore = 0;

  for (const pattern of ATTACK_PATTERNS) {
    const matched = signals.filter(s => pattern.signals.includes(s)).length;
    const score = (matched / pattern.signals.length) * pattern.weight;
    if (score > bestScore && score >= 0.5) {
      bestScore = score;
      bestMatch = { ...pattern, match_score: Math.round(score * 100) };
    }
  }
  return bestMatch;
}

/**
 * Compute composite risk score for any event
 */
export function computeRiskScore({ cvss = 0, epss = 0, is_kev = false, anomaly_score = 0, pattern_score = 0 }) {
  const cvssWeight     = 0.30;
  const epssWeight     = 0.25;
  const kevBonus       = is_kev ? 15 : 0;
  const anomalyWeight  = 0.25;
  const patternWeight  = 0.20;

  return Math.min(100, Math.round(
    (cvss / 10 * 100) * cvssWeight +
    epss * 100 * epssWeight +
    anomaly_score * anomalyWeight +
    pattern_score * patternWeight +
    kevBonus
  ));
}
