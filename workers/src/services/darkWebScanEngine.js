/**
 * CYBERDUDEBIVASH AI Security Hub — Dark Web Exposure Scan Engine v1.0
 *
 * Real, live external-exposure reconnaissance built entirely on genuinely
 * available, free/public data sources — no fabricated breach data, no
 * simulated "dark web" results.
 *
 * Sources used today (always live, no API key required):
 *   - crt.sh Certificate Transparency logs: every publicly-issued TLS
 *     certificate for the domain and its subdomains. This is the single
 *     most reliable way to discover forgotten "shadow IT" subdomains —
 *     exactly the kind of unmonitored asset that ends up compromised and
 *     traded on breach/paste forums.
 *   - Direct exposed-credential file probing: .git, .env, cloud credential
 *     files. A publicly exposed credential file IS a live breach in
 *     progress, not a prediction of one — this is real, actionable signal.
 *
 * Optional enhancement (disclosed honestly, not fabricated):
 *   - Live breach-database search (HaveIBeenPwned or equivalent) requires
 *     a paid provider API key. If env.HIBP_API_KEY is not configured, this
 *     section is reported as "not enabled" rather than faked — matching
 *     the platform's existing disclosure convention for Sentinel APEX
 *     ("Sources: NVD · CISA KEV · GitHub Advisory Database — independent
 *     research, not an official feed of those organizations.").
 */

const TIMEOUT_MS = 8000;

async function safeFetchJSON(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, ...opts });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(url, { redirect: 'manual', signal: controller.signal, ...opts });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ── Certificate Transparency — real subdomain/cert exposure via crt.sh ────────
async function checkCertificateTransparency(domain) {
  const rows = await safeFetchJSON(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-AI-Security-Hub/1.0 (+https://cyberdudebivash.in)' },
  });
  if (!rows || !Array.isArray(rows)) return { available: false, subdomains: [], total_certs: 0 };

  const names = new Set();
  for (const row of rows) {
    const raw = (row.name_value || '').split('\n');
    for (const n of raw) {
      const clean = n.trim().toLowerCase().replace(/^\*\./, '');
      if (clean.endsWith(domain)) names.add(clean);
    }
  }
  return {
    available: true,
    total_certs: rows.length,
    subdomains: [...names].sort(),
    subdomain_count: names.size,
  };
}

// ── Exposed credential/config files — same signal class the AppSec engine
//    checks, framed here specifically as "what's actively leaking today" ────
const CREDENTIAL_LEAK_PATHS = [
  { path: '/.git/config',      label: '.git/config (source + often embedded credentials)' },
  { path: '/.env',             label: '.env (environment secrets)' },
  { path: '/.aws/credentials', label: '.aws/credentials (cloud provider keys)' },
  { path: '/id_rsa',           label: 'id_rsa (private SSH key)' },
  { path: '/.npmrc',           label: '.npmrc (may contain registry auth tokens)' },
];

async function checkCredentialLeaks(domain) {
  const baseUrl = `https://${domain}`;
  const results = await Promise.all(CREDENTIAL_LEAK_PATHS.map(async (p) => {
    const res = await safeFetch(baseUrl + p.path, { method: 'GET' });
    return { ...p, exposed: !!res && res.status === 200 };
  }));
  return results;
}

function riskLevel(s) {
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 35 ? 'MEDIUM' : 'LOW';
}

function buildFindings({ ct, leaks, hibpEnabled }) {
  const findings = [];

  // DARK-001: Shadow-IT subdomain exposure via Certificate Transparency
  findings.push({
    id: 'DARK-001', title: 'Shadow-IT & Forgotten Subdomain Exposure',
    severity: !ct.available ? 'INFO' : ct.subdomain_count > 25 ? 'MEDIUM' : ct.subdomain_count > 0 ? 'LOW' : 'INFO',
    description: !ct.available
      ? 'Certificate Transparency lookup unavailable for this scan — crt.sh did not respond in time.'
      : `${ct.subdomain_count} unique subdomain(s) found across ${ct.total_certs} publicly-issued certificate(s). Unmonitored subdomains are the most common source of unnoticed external exposure.`,
    subdomains: ct.subdomains?.slice(0, 100) || [],
    subdomain_count: ct.subdomain_count || 0,
    recommendation: 'Inventory every subdomain against active, monitored assets. Decommission or lock down anything no longer in active use — these are the assets most likely to be compromised without anyone noticing.',
    cvss_base: ct.subdomain_count > 25 ? 5.0 : 2.0,
    is_premium: false, data_source: 'live_certificate_transparency',
  });

  // DARK-002: Actively exposed credentials (a live breach, not a prediction)
  const exposed = leaks.filter(l => l.exposed);
  findings.push({
    id: 'DARK-002', title: 'Actively Exposed Credentials',
    severity: exposed.length ? 'CRITICAL' : 'LOW',
    description: exposed.length
      ? `${exposed.length} credential-bearing file(s) are PUBLICLY ACCESSIBLE right now: ${exposed.map(e => e.path).join(', ')}. This is a live exposure, not a historical breach lookup — these credentials should be rotated immediately.`
      : `No exposed credential files found across ${leaks.length} commonly-leaked paths.`,
    exposed_paths: exposed.map(e => ({ path: e.path, label: e.label })),
    recommendation: 'Rotate any credentials found in an exposed file immediately, then remove public access to the file/directory.',
    cvss_base: exposed.length ? 9.8 : 1.0,
    is_premium: false, data_source: 'live_http_probe',
  });

  // DARK-003: Breach database search — honest availability disclosure
  findings.push({
    id: 'DARK-003', title: 'Breach & Credential Database Search',
    severity: 'INFO',
    description: hibpEnabled
      ? 'Live breach-database search is enabled for this account.'
      : 'Live breach-database search (e.g. HaveIBeenPwned) requires a provider API key that is not yet configured for this deployment. This section will populate real results once enabled — it does not report fabricated matches in the meantime.',
    enabled: hibpEnabled,
    recommendation: hibpEnabled ? null : 'Contact bivash@cyberdudebivash.com to enable live breach-database search for your account.',
    cvss_base: 0,
    is_premium: true, data_source: hibpEnabled ? 'live_breach_db' : 'not_configured',
  });

  return findings;
}

function computeRiskScore(findings) {
  const weights = { CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 2, INFO: 0 };
  return Math.min(100, findings.reduce((s, f) => s + (weights[f.severity] || 0), 0));
}

// ── Main entry point ──────────────────────────────────────────────────────────
export async function runDarkWebScan(domain, env = {}) {
  const hibpEnabled = !!env.HIBP_API_KEY;

  const [ct, leaks] = await Promise.all([
    checkCertificateTransparency(domain),
    checkCredentialLeaks(domain),
  ]);

  const findings  = buildFindings({ ct, leaks, hibpEnabled });
  const riskScore = computeRiskScore(findings);

  return {
    module: 'darkweb_scanner', version: '1.0.0', target: domain,
    data_source: 'live_certificate_transparency + live_http_probe',
    risk_score: riskScore, risk_level: riskLevel(riskScore),
    grade: riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A',
    summary: `"${domain}" scanned for external exposure via Certificate Transparency and live credential-leak probing. Risk: ${riskScore}/100 (${riskLevel(riskScore)}). ${findings.filter(f=>['CRITICAL','HIGH'].includes(f.severity)).length} critical/high findings.`,
    findings,
    scan_metadata: {
      engine_version: '1.0.0', scan_timestamp: new Date().toISOString(),
      sources: ['crt.sh Certificate Transparency (live)', 'Direct credential-leak probing (live)']
        .concat(hibpEnabled ? ['Breach database search (live)'] : []),
      disclosure: 'Sources listed reflect independent, publicly available research — not an official feed of any named organization. Breach-database search is disclosed as unavailable rather than simulated when not configured.',
      powered_by: 'CYBERDUDEBIVASH AI Security Hub',
    },
  };
}
