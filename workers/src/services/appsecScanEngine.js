/**
 * CYBERDUDEBIVASH AI Security Hub — AppSec / DAST Scan Engine v1.0
 *
 * Real, live application-security reconnaissance against a customer-supplied
 * target — entirely passive/read-only. No injection payloads, no brute
 * force, no fuzzing, no destructive requests: every check is a plain GET/
 * HEAD/OPTIONS to a page the target already serves publicly. This mirrors
 * the deliberate scope decision already documented in devsecopsScanners.js
 * (active exploitation testing against arbitrary third-party targets is a
 * security- and legal-sensitive undertaking — consent/authorization and
 * safety guardrails come first, not a rushed DAST engine).
 *
 * Covers, via passive probing only:
 *   A05 Security Misconfiguration — headers, CORS, directory listing, exposed files
 *   A02 Cryptographic Failures    — cookie transport security (Secure/HttpOnly/SameSite)
 *   A01 Broken Access Control     — exposed admin/config/backup paths
 *   A09 Security Logging Failures — verbose error/stack-trace disclosure
 *   A06 Vulnerable Components     — server/framework version disclosure
 *
 * Every network call is a standard Cloudflare Workers fetch() to the
 * target's own public HTTP(S) surface — the same mechanism domain.js's
 * inferTLSGrade already uses in production.
 */

const TIMEOUT_MS = 6000;

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { redirect: 'manual', signal: controller.signal, ...opts });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ── Sensitive path exposure — passive GET, checking response status/size only ──
const SENSITIVE_PATHS = [
  { path: '/.git/config',              label: 'Exposed .git/config',                severity: 'CRITICAL', desc: 'Full source repository configuration publicly readable — commonly leads to full source disclosure.' },
  { path: '/.git/HEAD',                label: 'Exposed .git/HEAD',                  severity: 'CRITICAL', desc: 'Git repository metadata publicly readable — indicates the .git directory was deployed alongside the site.' },
  { path: '/.env',                     label: 'Exposed .env file',                  severity: 'CRITICAL', desc: 'Environment file publicly readable — commonly contains database credentials, API keys, and secrets.' },
  { path: '/.aws/credentials',         label: 'Exposed AWS credentials file',       severity: 'CRITICAL', desc: 'Cloud provider credential file publicly readable.' },
  { path: '/wp-config.php.bak',        label: 'Exposed WordPress config backup',    severity: 'HIGH',     desc: 'Backup file often contains database credentials in plaintext.' },
  { path: '/config.json',              label: 'Exposed config.json',                severity: 'MEDIUM',   desc: 'Application configuration file publicly readable.' },
  { path: '/actuator/env',             label: 'Exposed Spring Boot Actuator env',   severity: 'CRITICAL', desc: 'Spring Boot environment endpoint exposes runtime configuration and often secrets.' },
  { path: '/server-status',            label: 'Exposed Apache server-status',       severity: 'MEDIUM',   desc: 'Apache mod_status page discloses internal request/IP details.' },
  { path: '/.well-known/security.txt', label: 'security.txt present',               severity: 'INFO',     desc: 'RFC 9116 security contact file found — good practice.', positive: true },
];

async function checkSensitivePaths(baseUrl) {
  const results = await Promise.all(SENSITIVE_PATHS.map(async (p) => {
    const res = await safeFetch(baseUrl + p.path, { method: 'GET' });
    const exposed = !!res && res.status === 200;
    return { ...p, exposed, status: res?.status ?? 0 };
  }));
  return results;
}

// ── CORS misconfiguration — reflect an arbitrary test origin, inspect response ──
async function checkCORS(baseUrl) {
  const testOrigin = 'https://cors-probe.cyberdudebivash.in';
  const res = await safeFetch(baseUrl, { method: 'GET', headers: { Origin: testOrigin } });
  if (!res) return { reachable: false };
  const allowOrigin = res.headers.get('access-control-allow-origin');
  const allowCreds  = (res.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
  const reflectsArbitraryOrigin = allowOrigin === testOrigin || allowOrigin === '*';
  const misconfigured = allowOrigin === '*' && allowCreds
    ? false // browsers reject wildcard + credentials combo — not exploitable
    : (allowOrigin === testOrigin && allowCreds);
  return {
    reachable: true,
    allow_origin: allowOrigin || null,
    allow_credentials: allowCreds,
    reflects_arbitrary_origin: reflectsArbitraryOrigin,
    misconfigured, // reflected an unrecognized origin AND allows credentials
  };
}

// ── Cookie transport security — parse Set-Cookie flags ──────────────────────
function analyzeCookies(res) {
  // Workers' Headers API folds multiple Set-Cookie into one getSetCookie() array when available
  let raw = [];
  try { raw = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : []; } catch { raw = []; }
  if (!raw.length) {
    const single = res.headers.get('set-cookie');
    if (single) raw = [single];
  }
  return raw.map((c) => {
    const lower = c.toLowerCase();
    const name = c.split('=')[0].trim();
    return {
      name,
      secure:    lower.includes('secure'),
      http_only: lower.includes('httponly'),
      same_site: (lower.match(/samesite=(\w+)/) || [])[1] || 'none/unset',
    };
  });
}

// ── CSP directive strength — flag unsafe-inline/unsafe-eval/wildcard sources ──
function analyzeCSP(csp) {
  if (!csp) return { present: false };
  const weak = [];
  if (/unsafe-inline/i.test(csp)) weak.push("'unsafe-inline'");
  if (/unsafe-eval/i.test(csp))   weak.push("'unsafe-eval'");
  if (/(^|\s)\*(\s|;|$)/.test(csp)) weak.push('wildcard (*) source');
  if (!/default-src|script-src/i.test(csp)) weak.push('no default-src/script-src directive');
  return { present: true, weak_directives: weak, strong: weak.length === 0 };
}

function riskLevel(s) {
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 35 ? 'MEDIUM' : 'LOW';
}

// ── Build findings ────────────────────────────────────────────────────────────
function buildFindings({ headers, cookies, csp, cors, sensitivePaths, directoryListing, errorDisclosure, serverBanner }) {
  const findings = [];

  // APP-001: Exposed sensitive files (most severe category first)
  const exposedPaths = sensitivePaths.filter(p => p.exposed && !p.positive);
  findings.push({
    id: 'APP-001', title: 'Exposed Sensitive Files & Paths',
    severity: exposedPaths.some(p => p.severity === 'CRITICAL') ? 'CRITICAL'
             : exposedPaths.some(p => p.severity === 'HIGH') ? 'HIGH'
             : exposedPaths.length ? 'MEDIUM' : 'LOW',
    description: exposedPaths.length
      ? `${exposedPaths.length} sensitive path(s) publicly accessible: ${exposedPaths.map(p => p.path).join(', ')}.`
      : `No exposed source control, environment, or backup files found across ${sensitivePaths.filter(p=>!p.positive).length} common sensitive paths.`,
    exposed_paths: exposedPaths.map(p => ({ path: p.path, label: p.label, description: p.desc })),
    recommendation: 'Remove or block public access to source control directories, environment files, and backups via web server config (deny-all rules) or by not deploying them into the web root.',
    cvss_base: exposedPaths.some(p => p.severity === 'CRITICAL') ? 9.1 : exposedPaths.length ? 6.5 : 1.0,
    is_premium: false, data_source: 'live_http_probe',
  });

  // APP-002: CSP quality
  findings.push({
    id: 'APP-002', title: 'Content-Security-Policy Strength',
    severity: !csp.present ? 'HIGH' : csp.strong ? 'LOW' : 'MEDIUM',
    description: !csp.present
      ? 'No Content-Security-Policy header present — no defense-in-depth against XSS/injection.'
      : csp.strong
        ? 'CSP present with no obviously weak directives detected.'
        : `CSP present but contains weak directives: ${csp.weak_directives.join(', ')}.`,
    csp_present: csp.present, weak_directives: csp.weak_directives || [],
    recommendation: 'Adopt a strict CSP: avoid unsafe-inline/unsafe-eval, use nonces or hashes for inline scripts, and always set default-src.',
    cvss_base: !csp.present ? 5.4 : csp.strong ? 1.5 : 4.0,
    is_premium: false, data_source: 'live_http_probe',
  });

  // APP-003: Cookie transport security
  const insecureCookies = cookies.filter(c => !c.secure || !c.http_only || c.same_site === 'none/unset');
  findings.push({
    id: 'APP-003', title: 'Cookie Transport Security',
    severity: cookies.length === 0 ? 'INFO' : insecureCookies.length ? 'MEDIUM' : 'LOW',
    description: cookies.length === 0
      ? 'No cookies observed on the initial response — nothing to assess.'
      : insecureCookies.length
        ? `${insecureCookies.length}/${cookies.length} cookie(s) missing Secure, HttpOnly, or SameSite: ${insecureCookies.map(c=>c.name).join(', ')}.`
        : `All ${cookies.length} observed cookie(s) set Secure, HttpOnly, and SameSite.`,
    cookies: cookies.map(c => ({ name: c.name, secure: c.secure, http_only: c.http_only, same_site: c.same_site })),
    recommendation: 'Set Secure and HttpOnly on all session/auth cookies, and SameSite=Lax or Strict to mitigate CSRF.',
    cvss_base: insecureCookies.length ? 5.4 : 1.0,
    is_premium: true, data_source: 'live_http_probe',
  });

  // APP-004: CORS misconfiguration
  findings.push({
    id: 'APP-004', title: 'CORS Configuration',
    severity: !cors.reachable ? 'INFO' : cors.misconfigured ? 'HIGH' : 'LOW',
    description: !cors.reachable
      ? 'Could not probe CORS — target unreachable.'
      : cors.misconfigured
        ? `Reflects an arbitrary, unrecognized Origin (${cors.allow_origin}) while allowing credentials — any third-party site can make authenticated cross-origin requests on behalf of a logged-in victim.`
        : cors.reflects_arbitrary_origin
          ? 'Reflects arbitrary origins but does not allow credentials — lower risk, still broader than necessary.'
          : 'No overly permissive CORS behavior detected on the probed endpoint.',
    allow_origin: cors.allow_origin, allow_credentials: cors.allow_credentials,
    recommendation: 'Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins. Never combine a reflected/wildcard origin with Access-Control-Allow-Credentials: true.',
    cvss_base: cors.misconfigured ? 8.1 : cors.reflects_arbitrary_origin ? 4.3 : 1.0,
    is_premium: true, data_source: 'live_http_probe',
  });

  // APP-005: Directory listing
  findings.push({
    id: 'APP-005', title: 'Directory Listing Exposure',
    severity: directoryListing ? 'MEDIUM' : 'LOW',
    description: directoryListing
      ? 'A probed asset directory returned an auto-generated directory listing, disclosing file structure.'
      : 'No auto-generated directory listing detected on probed asset paths.',
    recommendation: 'Disable directory autoindex (Options -Indexes in Apache, autoindex off in nginx).',
    cvss_base: directoryListing ? 4.3 : 1.0,
    is_premium: true, data_source: 'live_http_probe',
  });

  // APP-006: Verbose error / stack trace disclosure
  findings.push({
    id: 'APP-006', title: 'Error Handling & Information Disclosure',
    severity: errorDisclosure ? 'MEDIUM' : 'LOW',
    description: errorDisclosure
      ? 'A request to a clearly invalid path returned a response containing framework/stack-trace details rather than a generic error page.'
      : 'Error responses did not disclose framework internals on the probed path.',
    recommendation: 'Configure custom, generic error pages in production; disable debug/verbose error output.',
    cvss_base: errorDisclosure ? 4.3 : 1.0,
    is_premium: true, data_source: 'live_http_probe',
  });

  // APP-007: Server/framework version disclosure
  findings.push({
    id: 'APP-007', title: 'Server Banner Disclosure',
    severity: serverBanner ? 'LOW' : 'LOW',
    description: serverBanner
      ? `Server header discloses: "${serverBanner}". Version-specific banners help attackers target known CVEs for that exact version.`
      : 'No version-specific server banner disclosed.',
    server_banner: serverBanner || null,
    recommendation: 'Suppress or genericize the Server/X-Powered-By response headers.',
    cvss_base: serverBanner ? 2.6 : 1.0,
    is_premium: false, data_source: 'live_http_probe',
  });

  return findings;
}

function computeRiskScore(findings) {
  const weights = { CRITICAL: 30, HIGH: 18, MEDIUM: 8, LOW: 2, INFO: 0 };
  const score = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  return Math.min(100, score);
}

// ── Main entry point ───────────────────────────────────────────────────────────
// pageUrl: the exact page to test (full URL, may include a path) — used for the
// homepage/headers/CSP/cookie/CORS checks, i.e. what the customer actually asked
// to have scanned.
// originUrl: protocol+host only — sensitive-path/directory-listing probes must
// use this, not pageUrl, so "https://example.com/app/login" doesn't produce
// nonsensical checks against "/app/login/.git/config".
export async function runAppSecScan(pageUrl, originUrl = pageUrl, target = pageUrl) {
  const homepage = await safeFetch(pageUrl, { method: 'GET' });

  if (!homepage) {
    return {
      module: 'appsec_scanner', version: '1.0.0', target,
      reachable: false, data_source: 'live_http_probe',
      summary: `"${target}" did not respond to an HTTPS request — cannot perform application-layer testing.`,
      risk_score: null, risk_level: null, grade: null, findings: [],
    };
  }

  const [sensitivePaths, cors] = await Promise.all([
    checkSensitivePaths(originUrl),
    checkCORS(pageUrl),
  ]);

  const csp     = analyzeCSP(homepage.headers.get('content-security-policy'));
  const cookies = analyzeCookies(homepage);
  const serverBanner = homepage.headers.get('server') || homepage.headers.get('x-powered-by') || null;

  // Directory listing probe — request a likely-existing asset directory
  const dirRes = await safeFetch(`${originUrl}/assets/`, { method: 'GET' });
  const dirText = dirRes && dirRes.status === 200 ? await dirRes.text().catch(() => '') : '';
  const directoryListing = /Index of \//i.test(dirText) || /<title>Directory listing/i.test(dirText);

  // Verbose error probe — request an implausible path
  const errRes  = await safeFetch(`${originUrl}/__cdb_appsec_probe_${Date.now()}__`, { method: 'GET' });
  const errText = errRes ? await errRes.text().catch(() => '') : '';
  const errorDisclosure = /stack trace|traceback \(most recent|at [\w.$]+\(.*:\d+:\d+\)|django\.core|werkzeug|laravel|System\.Exception/i.test(errText);

  const findings  = buildFindings({ headers: homepage.headers, cookies, csp, cors, sensitivePaths, directoryListing, errorDisclosure, serverBanner });
  const riskScore = computeRiskScore(findings);

  return {
    module: 'appsec_scanner', version: '1.0.0', target, scanned_url: pageUrl,
    reachable: true, data_source: 'live_http_probe',
    risk_score: riskScore, risk_level: riskLevel(riskScore),
    grade: riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A',
    summary: `"${target}" tested via passive application-security reconnaissance (no active exploitation). Risk: ${riskScore}/100 (${riskLevel(riskScore)}). ${findings.filter(f=>['CRITICAL','HIGH'].includes(f.severity)).length} critical/high findings.`,
    findings,
    scan_metadata: {
      engine_version: '1.0.0', scan_timestamp: new Date().toISOString(),
      methodology: 'Passive/read-only HTTP probing only — no injection payloads, brute force, or fuzzing were sent to the target.',
      scan_modules: ['sensitive_paths', 'csp_analysis', 'cookie_security', 'cors_analysis', 'directory_listing', 'error_disclosure', 'server_banner'],
      powered_by: 'CYBERDUDEBIVASH AI Security Hub',
    },
  };
}
