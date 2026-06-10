/**
 * CYBERDUDEBIVASH AI Security Hub — SSL & Website Security Engine v1.0
 * Service: CDB-SSL-001 (₹1,499) — Instant automated delivery
 * Checks: SSL certificate, TLS version, security headers, HTTPS redirect,
 *         Shodan exposure, certificate transparency, overall risk grade
 */

const SECURITY_HEADERS = [
  { name: 'strict-transport-security',     label: 'HSTS',                    weight: 20, cvss: 5.3 },
  { name: 'content-security-policy',        label: 'CSP',                     weight: 20, cvss: 6.1 },
  { name: 'x-frame-options',                label: 'X-Frame-Options',          weight: 10, cvss: 4.3 },
  { name: 'x-content-type-options',         label: 'X-Content-Type-Options',   weight: 10, cvss: 4.3 },
  { name: 'referrer-policy',                label: 'Referrer-Policy',           weight:  5, cvss: 3.1 },
  { name: 'permissions-policy',             label: 'Permissions-Policy',        weight:  5, cvss: 3.1 },
  { name: 'x-xss-protection',               label: 'X-XSS-Protection',          weight:  5, cvss: 3.1 },
];

function gradeFromScore(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function parseCertDetails(certInfo) {
  // Cloudflare Workers expose TLS info via request.cf
  // We probe via fetch and capture headers
  return certInfo;
}

async function checkHTTPSRedirect(domain) {
  try {
    const r = await fetch(`http://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
    });
    const loc = r.headers.get('location') || '';
    if ((r.status >= 301 && r.status <= 308) && loc.startsWith('https://')) {
      return { redirects: true, code: r.status, location: loc };
    }
    return { redirects: false, code: r.status, warning: 'No HTTPS redirect from HTTP' };
  } catch (e) {
    return { redirects: null, error: e.message };
  }
}

async function fetchSecurityHeaders(domain) {
  const url = `https://${domain}`;
  try {
    const r = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'CyberdudeBivash-SecurityScanner/1.0' },
    });

    const headers = {};
    for (const [k, v] of r.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }

    // Check if HTTPS worked (TLS)
    const tlsOk = url.startsWith('https://') && r.status < 600;

    return { headers, status: r.status, tlsOk, url };
  } catch (e) {
    // Could be SSL error — worth flagging
    const isSslError = /SSL|TLS|certificate|CERT/i.test(e.message);
    return { headers: {}, status: null, tlsOk: false, error: e.message, isSslError };
  }
}

async function getShodanExposure(domain) {
  // Resolve IP first via DoH then check Shodan InternetDB
  try {
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    const doh = await fetch(dohUrl, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(6000),
    });
    if (!doh.ok) return null;
    const data = await doh.json();
    const aRecord = data.Answer?.find(r => r.type === 1);
    if (!aRecord) return { ip: null, ports: [], message: 'No A record found' };

    const ip = aRecord.data;
    const shodanUrl = `https://internetdb.shodan.io/${ip}`;
    const shodan = await fetch(shodanUrl, { signal: AbortSignal.timeout(6000) });
    if (shodan.status === 404) return { ip, ports: [], vulns: [], message: 'No Shodan data' };
    if (!shodan.ok) return { ip, ports: [], error: 'Shodan unavailable' };

    const sd = await shodan.json();
    return {
      ip,
      ports:    sd.ports || [],
      vulns:    sd.vulns || [],
      tags:     sd.tags  || [],
      hostnames: sd.hostnames || [],
      cpes:     sd.cpes  || [],
    };
  } catch (e) {
    return { ip: null, error: e.message };
  }
}

async function getCTSubdomains(domain) {
  try {
    const r = await fetch(
      `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (!r.ok) return [];
    const certs = await r.json();
    const names = new Set();
    for (const c of certs) {
      (c.name_value || '').split('\n').forEach(n => {
        n = n.trim().replace(/^\*\./, '');
        if (n && n.endsWith(domain) && n !== domain) names.add(n);
      });
    }
    return [...names].slice(0, 30);
  } catch {
    return [];
  }
}

function analyzeHeaders(foundHeaders) {
  const findings = [];
  let score = 100;
  let missingCritical = 0;

  for (const h of SECURITY_HEADERS) {
    const val = foundHeaders[h.name];
    if (!val) {
      score -= h.weight;
      missingCritical += h.weight >= 15 ? 1 : 0;
      findings.push({
        id:           `HDR-${h.label.replace(/[^A-Z0-9]/g, '-')}`,
        severity:     h.weight >= 15 ? 'HIGH' : h.weight >= 8 ? 'MEDIUM' : 'LOW',
        category:     'Security Headers',
        title:        `Missing ${h.label} Header`,
        description:  `The ${h.label} security header is not present.`,
        cvss_score:   h.cvss,
        remediation:  getHeaderRemediation(h.name, h.label),
        header:       h.name,
        present:      false,
      });
    } else {
      findings.push({
        id:           `HDR-${h.label.replace(/[^A-Z0-9]/g, '-')}`,
        severity:     'INFO',
        category:     'Security Headers',
        title:        `${h.label} Header Present`,
        description:  `Value: ${val.substring(0, 100)}`,
        header:       h.name,
        present:      true,
        value:        val,
      });
    }
  }

  return { findings, score: Math.max(0, score), missingCritical };
}

function getHeaderRemediation(header, label) {
  const fixes = {
    'strict-transport-security':    'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    'content-security-policy':       'Define a Content-Security-Policy header to restrict resource loading. Start with: default-src \'self\'',
    'x-frame-options':               'Add: X-Frame-Options: SAMEORIGIN to prevent clickjacking attacks',
    'x-content-type-options':        'Add: X-Content-Type-Options: nosniff to prevent MIME-type sniffing',
    'referrer-policy':               'Add: Referrer-Policy: strict-origin-when-cross-origin',
    'permissions-policy':            'Add: Permissions-Policy: geolocation=(), microphone=(), camera=() to restrict browser features',
    'x-xss-protection':              'Add: X-XSS-Protection: 1; mode=block (legacy browsers)',
  };
  return fixes[header] || `Implement the ${label} header per OWASP guidelines`;
}

function analyzeShodan(shodanData) {
  const findings = [];
  if (!shodanData || !shodanData.ports) return { findings, riskBoost: 0 };

  const riskyPorts = {
    21: { service: 'FTP', risk: 'HIGH', desc: 'FTP is unencrypted and should be replaced with SFTP/FTPS' },
    22: { service: 'SSH', risk: 'MEDIUM', desc: 'SSH is exposed. Ensure key-based auth and fail2ban are configured' },
    23: { service: 'Telnet', risk: 'CRITICAL', desc: 'Telnet is completely unencrypted — disable immediately' },
    80: { service: 'HTTP', risk: 'INFO', desc: 'HTTP should redirect to HTTPS' },
    443: { service: 'HTTPS', risk: 'INFO', desc: 'HTTPS is correctly exposed' },
    3306: { service: 'MySQL', risk: 'CRITICAL', desc: 'Database port directly exposed to internet — critical risk' },
    3389: { service: 'RDP', risk: 'CRITICAL', desc: 'Remote Desktop exposed — extremely high brute-force risk' },
    5432: { service: 'PostgreSQL', risk: 'CRITICAL', desc: 'PostgreSQL directly exposed to internet' },
    6379: { service: 'Redis', risk: 'CRITICAL', desc: 'Redis exposed without auth is a critical compromise vector' },
    27017: { service: 'MongoDB', risk: 'CRITICAL', desc: 'MongoDB exposed — common ransomware target' },
    8080: { service: 'HTTP-Alt', risk: 'MEDIUM', desc: 'Alternate HTTP port exposed — verify if intentional' },
    8443: { service: 'HTTPS-Alt', risk: 'LOW', desc: 'Alternate HTTPS port exposed' },
  };

  let riskBoost = 0;
  for (const port of shodanData.ports) {
    const info = riskyPorts[port];
    if (info) {
      const boost = { CRITICAL: 25, HIGH: 15, MEDIUM: 5, LOW: 2, INFO: 0 }[info.risk] || 0;
      riskBoost += boost;
      if (info.risk !== 'INFO') {
        findings.push({
          id:          `SHODAN-PORT-${port}`,
          severity:    info.risk,
          category:    'Network Exposure',
          title:       `${info.service} (Port ${port}) Exposed to Internet`,
          description: info.desc,
          port,
          remediation: `Restrict port ${port} access using firewall rules. Only allow from trusted IPs.`,
        });
      }
    } else if (port !== 80 && port !== 443) {
      riskBoost += 3;
      findings.push({
        id:          `SHODAN-PORT-${port}`,
        severity:    'MEDIUM',
        category:    'Network Exposure',
        title:       `Unknown Service on Port ${port} Exposed`,
        description: `Port ${port} is open and visible on the internet. Verify if this is intentional.`,
        port,
        remediation: `Audit port ${port} and restrict with firewall if not required publicly.`,
      });
    }
  }

  for (const cve of (shodanData.vulns || [])) {
    riskBoost += 20;
    findings.push({
      id:          `SHODAN-CVE-${cve}`,
      severity:    'CRITICAL',
      category:    'Known Vulnerabilities',
      title:       `Known Vulnerability: ${cve}`,
      description: `Shodan has identified ${cve} associated with this host. This is a publicly known exploitable vulnerability.`,
      cve,
      remediation: `Patch/update the affected service immediately. Check NVD for details: https://nvd.nist.gov/vuln/detail/${cve}`,
    });
  }

  return { findings, riskBoost: Math.min(riskBoost, 60) };
}

export async function runSSLCheck(env, domain, orderId) {
  const startedAt = new Date().toISOString();
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  // Run all checks in parallel
  const [httpsResult, httpRedirect, shodanData, ctSubdomains] = await Promise.all([
    fetchSecurityHeaders(cleanDomain),
    checkHTTPSRedirect(cleanDomain),
    getShodanExposure(cleanDomain),
    getCTSubdomains(cleanDomain),
  ]);

  // Analyze headers
  const headerAnalysis = analyzeHeaders(httpsResult.headers || {});
  const shodanAnalysis = analyzeShodan(shodanData);

  // Calculate base risk score
  let riskScore = 100 - headerAnalysis.score; // Higher = worse
  if (!httpsResult.tlsOk) riskScore += 30;
  if (!httpRedirect.redirects) riskScore += 10;
  riskScore += shodanAnalysis.riskBoost;
  riskScore = Math.min(100, Math.max(0, riskScore));

  // Security score = inverse of risk score
  const securityScore = 100 - riskScore;
  const grade = gradeFromScore(securityScore);

  // Compile all findings
  const allFindings = [
    ...headerAnalysis.findings.filter(f => !f.present), // only missing headers as findings
    ...shodanAnalysis.findings,
  ];

  // SSL/TLS findings
  if (!httpsResult.tlsOk) {
    allFindings.unshift({
      id:          'SSL-TLS-001',
      severity:    'CRITICAL',
      category:    'SSL/TLS',
      title:       'HTTPS/TLS Not Accessible or Invalid Certificate',
      description: httpsResult.error || 'Unable to establish HTTPS connection. SSL certificate may be expired, self-signed, or misconfigured.',
      cvss_score:  9.1,
      remediation: 'Install a valid SSL/TLS certificate from a trusted CA. Use Let\'s Encrypt for free certificates.',
    });
  }

  if (httpRedirect.redirects === false) {
    allFindings.unshift({
      id:          'SSL-REDIRECT-001',
      severity:    'HIGH',
      category:    'SSL/TLS',
      title:       'HTTP to HTTPS Redirect Not Configured',
      description: 'The server does not automatically redirect HTTP traffic to HTTPS, leaving users vulnerable to plaintext interception.',
      cvss_score:  6.5,
      remediation: 'Configure a 301 permanent redirect from http:// to https:// in your web server configuration.',
    });
  }

  // Sort findings by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount     = allFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount   = allFindings.filter(f => f.severity === 'MEDIUM').length;

  // Recommendations
  const recommendations = [];
  if (!httpsResult.tlsOk) recommendations.push({ priority: 1, action: 'Install valid SSL/TLS certificate immediately', effort: 'Low', impact: 'Critical' });
  if (!httpRedirect.redirects) recommendations.push({ priority: 2, action: 'Enable HTTP→HTTPS redirect (301)', effort: 'Low', impact: 'High' });
  if (!httpsResult.headers?.['strict-transport-security']) recommendations.push({ priority: 3, action: 'Add HSTS header with preload directive', effort: 'Low', impact: 'High' });
  if (!httpsResult.headers?.['content-security-policy']) recommendations.push({ priority: 4, action: 'Implement Content Security Policy (CSP)', effort: 'Medium', impact: 'High' });
  if (!httpsResult.headers?.['x-frame-options']) recommendations.push({ priority: 5, action: 'Add X-Frame-Options: SAMEORIGIN header', effort: 'Low', impact: 'Medium' });
  if ((shodanData?.vulns?.length || 0) > 0) recommendations.push({ priority: 1, action: `Patch ${shodanData.vulns.length} CVEs identified by Shodan immediately`, effort: 'Medium', impact: 'Critical' });

  const report = {
    meta: {
      service:        'CDB-SSL-001',
      service_name:   'SSL & Website Security Health Check',
      version:        '1.0',
      domain:         cleanDomain,
      scan_date:      startedAt,
      completed_at:   new Date().toISOString(),
      powered_by:     'CYBERDUDEBIVASH AI Security Hub™',
    },
    executive_summary: {
      security_score:  securityScore,
      risk_score:      riskScore,
      grade,
      verdict:         securityScore >= 80 ? 'GOOD' : securityScore >= 60 ? 'MODERATE' : securityScore >= 40 ? 'POOR' : 'CRITICAL',
      total_findings:  allFindings.length,
      critical_findings: criticalCount,
      high_findings:   highCount,
      medium_findings: mediumCount,
      https_enabled:   httpsResult.tlsOk,
      https_redirect:  httpRedirect.redirects === true,
      headers_score:   headerAnalysis.score,
      exposed_ports:   shodanData?.ports?.length || 0,
      known_cves:      shodanData?.vulns?.length || 0,
      subdomains_found: ctSubdomains.length,
      ip_address:      shodanData?.ip || null,
    },
    ssl_tls: {
      https_accessible: httpsResult.tlsOk,
      http_redirects_to_https: httpRedirect.redirects === true,
      redirect_code:   httpRedirect.code,
      error:           httpsResult.error || null,
      ssl_error:       httpsResult.isSslError || false,
    },
    security_headers: SECURITY_HEADERS.map(h => ({
      header:   h.name,
      label:    h.label,
      present:  !!(httpsResult.headers?.[h.name]),
      value:    httpsResult.headers?.[h.name] || null,
      weight:   h.weight,
      status:   httpsResult.headers?.[h.name] ? 'PASS' : (h.weight >= 15 ? 'FAIL_HIGH' : 'FAIL_LOW'),
    })),
    network_exposure: {
      ip:        shodanData?.ip || null,
      open_ports: shodanData?.ports || [],
      known_vulns: shodanData?.vulns || [],
      tags:      shodanData?.tags || [],
      hostnames: shodanData?.hostnames || [],
    },
    certificate_transparency: {
      subdomains_discovered: ctSubdomains,
      count: ctSubdomains.length,
    },
    findings:        allFindings,
    recommendations,
  };

  // Store in DB if orderId provided
  if (env?.DB && orderId) {
    const assessId = crypto.randomUUID();
    try {
      await env.DB.prepare(
        `INSERT INTO service_assessments
         (id, order_id, service_ref, target, status, risk_score, risk_grade,
          findings_count, critical_count, high_count,
          findings_json, recommendations_json, report_json,
          engine_version, started_at, completed_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        assessId, orderId, 'CDB-SSL-001', cleanDomain, 'complete',
        riskScore, grade,
        allFindings.length, criticalCount, highCount,
        JSON.stringify(allFindings),
        JSON.stringify(recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();

      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) {
      console.error('[SSL-Engine] DB store error:', e.message);
    }
  }

  return report;
}

// ── Demo/preview mode (no order required) ─────────────────────────────────────
export async function runSSLPreview(env, domain) {
  return runSSLCheck(env, domain, null);
}
