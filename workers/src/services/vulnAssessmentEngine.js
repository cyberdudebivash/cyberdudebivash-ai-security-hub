/**
 * CYBERDUDEBIVASH AI Security Hub — Vulnerability Assessment Engine v1.0
 * Service: CDB-VA-001 (₹9,999) — Automated VA with subdomain discovery + CVE matching
 */

async function discoverSubdomains(domain) {
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
        if (n && n.endsWith(domain) && n !== domain && !n.includes(' ')) names.add(n);
      });
    }
    return [...names].slice(0, 50);
  } catch { return []; }
}

async function resolveHost(hostname) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
    );
    if (!r.ok) return null;
    const d = await r.json();
    return d.Answer?.find(a => a.type === 1)?.data || null;
  } catch { return null; }
}

async function getShodanData(ip) {
  if (!ip) return null;
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(6000) });
    if (r.status === 404 || !r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function fetchCISAKEV() {
  try {
    const r = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(10000) }
    );
    if (!r.ok) return [];
    const data = await r.json();
    return data.vulnerabilities || [];
  } catch { return []; }
}

function matchCVEsToServices(ports, cpes, kevList) {
  const matches = [];
  // Match based on CPEs from Shodan against CISA KEV
  for (const cpe of (cpes || [])) {
    // Extract product/vendor from CPE: cpe:/a:vendor:product:version
    const parts = cpe.split(':');
    const vendor  = parts[3] || '';
    const product = parts[4] || '';
    for (const kev of kevList) {
      if (
        (vendor  && kev.vendorProject?.toLowerCase().includes(vendor.toLowerCase())) ||
        (product && kev.product?.toLowerCase().includes(product.toLowerCase()))
      ) {
        matches.push({
          cve_id:      kev.cveID,
          vendor:      kev.vendorProject,
          product:     kev.product,
          vuln:        kev.vulnerabilityName,
          ransomware:  kev.knownRansomwareCampaignUse === 'Known',
          due_date:    kev.dueDate,
          source_cpe:  cpe,
        });
      }
    }
  }
  return matches;
}

const RISKY_PORTS = {
  21:    { service: 'FTP',       severity: 'HIGH',     desc: 'FTP unencrypted file transfer' },
  22:    { service: 'SSH',       severity: 'MEDIUM',   desc: 'SSH remote access' },
  23:    { service: 'Telnet',    severity: 'CRITICAL', desc: 'Telnet unencrypted remote access' },
  25:    { service: 'SMTP',      severity: 'MEDIUM',   desc: 'SMTP email relay' },
  110:   { service: 'POP3',      severity: 'HIGH',     desc: 'POP3 unencrypted email' },
  143:   { service: 'IMAP',      severity: 'HIGH',     desc: 'IMAP unencrypted email' },
  3306:  { service: 'MySQL',     severity: 'CRITICAL', desc: 'Database directly exposed' },
  3389:  { service: 'RDP',       severity: 'CRITICAL', desc: 'Remote Desktop exposed' },
  5432:  { service: 'PostgreSQL',severity: 'CRITICAL', desc: 'Database directly exposed' },
  5900:  { service: 'VNC',       severity: 'CRITICAL', desc: 'VNC remote access exposed' },
  6379:  { service: 'Redis',     severity: 'CRITICAL', desc: 'Redis without auth exposed' },
  8080:  { service: 'HTTP-Alt',  severity: 'MEDIUM',   desc: 'Alternate HTTP service' },
  8443:  { service: 'HTTPS-Alt', severity: 'LOW',      desc: 'Alternate HTTPS service' },
  27017: { service: 'MongoDB',   severity: 'CRITICAL', desc: 'MongoDB ransomware target' },
  9200:  { service: 'Elasticsearch', severity: 'CRITICAL', desc: 'Elasticsearch unauth exposure' },
  2375:  { service: 'Docker API',severity: 'CRITICAL', desc: 'Docker API exposed — full compromise' },
  5984:  { service: 'CouchDB',   severity: 'HIGH',     desc: 'CouchDB exposed' },
};

export async function runVulnAssessment(env, domain, orderId = null) {
  const startedAt  = new Date().toISOString();
  const cleanDomain = (domain || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  if (!cleanDomain) {
    return { error: 'Domain required for vulnerability assessment', status: 400 };
  }

  // Phase 1: Discovery
  const [subdomains, rootIP, kevList] = await Promise.all([
    discoverSubdomains(cleanDomain),
    resolveHost(cleanDomain),
    fetchCISAKEV(),
  ]);

  // Phase 2: Resolve all hosts (root + subdomains, capped at 20)
  const allHosts = [cleanDomain, ...subdomains.slice(0, 19)];
  const hostIPs  = await Promise.all(allHosts.map(h => resolveHost(h)));
  const hostMap  = allHosts.map((h, i) => ({ host: h, ip: hostIPs[i] })).filter(h => h.ip);

  // Phase 3: Shodan data for unique IPs (cap at 10)
  const uniqueIPs = [...new Set(hostMap.map(h => h.ip))].slice(0, 10);
  const shodanMap = {};
  await Promise.all(uniqueIPs.map(async ip => {
    shodanMap[ip] = await getShodanData(ip);
  }));

  // Phase 4: Build findings
  const findings = [];
  const assetVulns = [];
  let riskScore = 10; // baseline

  for (const { host, ip } of hostMap) {
    if (!ip) continue;
    const sd = shodanMap[ip];

    const asset = {
      host,
      ip,
      open_ports:  sd?.ports || [],
      vulns:       sd?.vulns || [],
      cpes:        sd?.cpes  || [],
      tags:        sd?.tags  || [],
      cve_matches: [],
    };

    // CVE matching
    if (sd?.cpes) {
      asset.cve_matches = matchCVEsToServices(sd.ports, sd.cpes, kevList);
    }

    // Direct Shodan CVE matches
    for (const cve of (sd?.vulns || [])) {
      riskScore += 15;
      findings.push({
        id:          `VA-CVE-${cve}`,
        severity:    'CRITICAL',
        category:    'Known Exploited Vulnerability',
        asset:       host,
        ip,
        title:       `Critical CVE: ${cve} on ${host}`,
        description: `Shodan has flagged ${cve} on this host. This is an actively exploited vulnerability.`,
        cvss:        null,
        cve_id:      cve,
        remediation: `Immediate patching required. Reference: https://nvd.nist.gov/vuln/detail/${cve}`,
      });
    }

    // Port-based findings
    for (const port of (sd?.ports || [])) {
      const info = RISKY_PORTS[port];
      if (info && info.severity !== 'LOW') {
        const boost = { CRITICAL: 20, HIGH: 12, MEDIUM: 5 }[info.severity] || 2;
        riskScore += boost;
        if (info.severity !== 'MEDIUM' || !findings.find(f => f.id === `VA-PORT-${port}`)) {
          findings.push({
            id:          `VA-PORT-${port}-${host}`,
            severity:    info.severity,
            category:    'Service Exposure',
            asset:       host,
            ip,
            title:       `${info.service} (Port ${port}) Exposed on ${host}`,
            description: info.desc,
            port,
            remediation: `Restrict port ${port} using firewall rules. Allow only from trusted networks.`,
          });
        }
      }
    }

    // CISA KEV matches
    for (const match of asset.cve_matches) {
      riskScore += match.ransomware ? 25 : 15;
      findings.push({
        id:          `VA-KEV-${match.cve_id}-${host}`,
        severity:    match.ransomware ? 'CRITICAL' : 'HIGH',
        category:    'CISA Known Exploited Vulnerability',
        asset:       host,
        ip,
        title:       `CISA KEV: ${match.cve_id} — ${match.product}`,
        description: `${match.vuln}. ${match.ransomware ? 'LINKED TO ACTIVE RANSOMWARE CAMPAIGNS.' : ''} Due: ${match.due_date}`,
        cve_id:      match.cve_id,
        remediation: `Patch ${match.product} immediately. Required action: ${match.vuln}`,
      });
    }

    assetVulns.push(asset);
  }

  riskScore = Math.min(100, riskScore);
  const secScore = 100 - riskScore;
  const grade    = secScore >= 80 ? 'A' : secScore >= 65 ? 'B' : secScore >= 50 ? 'C' : secScore >= 35 ? 'D' : 'F';

  findings.sort((a, b) => {
    const so = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (so[a.severity] ?? 4) - (so[b.severity] ?? 4);
  });

  const report = {
    meta: {
      service:      'CDB-VA-001',
      service_name: 'Vulnerability Assessment',
      version:      '1.0',
      domain:       cleanDomain,
      generated_at: startedAt,
      powered_by:   'CYBERDUDEBIVASH AI Security Hub™',
    },
    executive_summary: {
      security_score:    secScore,
      risk_score:        riskScore,
      grade,
      verdict:           riskScore >= 70 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW',
      assets_scanned:    hostMap.length,
      subdomains_found:  subdomains.length,
      total_findings:    findings.length,
      critical_count:    findings.filter(f => f.severity === 'CRITICAL').length,
      high_count:        findings.filter(f => f.severity === 'HIGH').length,
      known_cves:        findings.filter(f => f.cve_id).length,
      exposed_ports:     [...new Set(findings.filter(f => f.port).map(f => f.port))].length,
    },
    asset_inventory:  assetVulns,
    subdomain_discovery: { discovered: subdomains, count: subdomains.length },
    findings,
    remediation_plan: [
      { priority: 'P0 (24h)',  items: findings.filter(f => f.severity === 'CRITICAL').map(f => f.title) },
      { priority: 'P1 (1 week)', items: findings.filter(f => f.severity === 'HIGH').map(f => f.title) },
      { priority: 'P2 (1 month)', items: findings.filter(f => f.severity === 'MEDIUM').map(f => f.title) },
    ],
    recommendations: [
      { priority: 1, action: 'Patch all CISA KEV vulnerabilities immediately', impact: 'Critical' },
      { priority: 2, action: 'Close exposed database ports (3306, 5432, 6379, 27017)', impact: 'Critical' },
      { priority: 3, action: 'Implement Web Application Firewall (WAF)', impact: 'High' },
      { priority: 4, action: 'Enable continuous vulnerability scanning', impact: 'High' },
      { priority: 5, action: 'Conduct monthly subdomain discovery and asset review', impact: 'Medium' },
    ],
  };

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
        assessId, orderId, 'CDB-VA-001', cleanDomain, 'complete',
        riskScore, grade,
        findings.length,
        findings.filter(f => f.severity === 'CRITICAL').length,
        findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[VA-Engine] DB error:', e.message); }
  }

  return report;
}
