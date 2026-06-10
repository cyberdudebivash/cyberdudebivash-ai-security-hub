/**
 * CYBERDUDEBIVASH AI Security Hub — Attack Surface Management Engine v1.0
 * ─────────────────────────────────────────────────────────────────────────
 * External attack surface discovery:
 *   - Subdomain enumeration via Certificate Transparency (crt.sh — free)
 *   - DNS resolution via Cloudflare DoH
 *   - Open port/service data via Shodan InternetDB (free, no key)
 *   - Certificate validity checks
 *   - HTTP service fingerprinting
 *   - ASM risk scoring
 */

const DOH_BASE   = 'https://cloudflare-dns.com/dns-query';
const SHODAN_IDB = 'https://internetdb.shodan.io';
const CRT_SH     = 'https://crt.sh/?q=%25.{domain}&output=json';

async function safeFetch(url, opts = {}) {
  try {
    const res = await fetch(url, {
      ...opts,
      signal: AbortSignal.timeout(8000),
      cf: { cacheTtl: 300 },
    });
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('json')) return await res.json();
    return await res.text();
  } catch { return null; }
}

// ─── Certificate Transparency — subdomain discovery ──────────────────────────
export async function discoverSubdomainsViaCT(domain) {
  const url = CRT_SH.replace('{domain}', encodeURIComponent(domain));
  const data = await safeFetch(url, {
    headers: { Accept: 'application/json', 'User-Agent': 'CYBERDUDEBIVASH-ASM/1.0' },
  });
  if (!Array.isArray(data)) return [];

  const subdomains = new Set();
  for (const cert of data) {
    const names = (cert.name_value || '').split('\n');
    for (const name of names) {
      const clean = name.replace(/^\*\./, '').toLowerCase().trim();
      if (clean.endsWith(`.${domain}`) || clean === domain) {
        subdomains.add(clean);
      }
    }
  }

  // Also extract from common_name
  for (const cert of data) {
    const cn = (cert.common_name || '').toLowerCase().trim();
    if (cn.endsWith(`.${domain}`) || cn === domain) {
      subdomains.add(cn.replace(/^\*\./, ''));
    }
  }

  return [...subdomains].slice(0, 100); // limit to 100 subdomains
}

// ─── DNS Resolution ──────────────────────────────────────────────────────────
async function resolveA(hostname) {
  const data = await safeFetch(
    `${DOH_BASE}?name=${encodeURIComponent(hostname)}&type=A`,
    { headers: { Accept: 'application/dns-json' } }
  );
  return (data?.Answer || [])
    .filter(r => r.type === 1)  // A records
    .map(r => r.data)
    .filter(Boolean);
}

async function resolveCERT(hostname) {
  const data = await safeFetch(
    `${DOH_BASE}?name=${encodeURIComponent(hostname)}&type=TLSA`,
    { headers: { Accept: 'application/dns-json' } }
  );
  return data?.Answer || [];
}

// ─── HTTP Service Probe ───────────────────────────────────────────────────────
async function probeHTTP(hostname) {
  const urls = [`https://${hostname}`, `http://${hostname}`];
  for (const url of urls) {
    try {
      const res = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(5000),
        cf: { cacheTtl: 0 },
      });
      const server = res.headers.get('server') || '';
      const powered = res.headers.get('x-powered-by') || '';
      const title = '';  // would need GET + parse, skip for HEAD
      return {
        status:    res.status,
        protocol:  url.startsWith('https') ? 'HTTPS' : 'HTTP',
        server,
        powered_by: powered,
        headers: {
          hsts:    !!res.headers.get('strict-transport-security'),
          csp:     !!res.headers.get('content-security-policy'),
          xframe:  !!res.headers.get('x-frame-options'),
        },
        redirect_url: res.url !== url ? res.url : null,
      };
    } catch {}
  }
  return null;
}

// ─── Shodan InternetDB ────────────────────────────────────────────────────────
async function getShodanData(ip) {
  const data = await safeFetch(`${SHODAN_IDB}/${ip}`);
  if (!data || typeof data !== 'object') return null;
  return {
    ports:     data.ports || [],
    vulns:     data.vulns || [],
    tags:      data.tags || [],
    hostnames: data.hostnames || [],
    cpes:      data.cpes || [],
  };
}

// ─── Certificate validity check ───────────────────────────────────────────────
async function checkCertValidity(hostname) {
  try {
    const res = await fetch(`https://${hostname}`, {
      method:  'HEAD',
      signal:  AbortSignal.timeout(5000),
      cf:      { cacheTtl: 0 },
    });
    // If we got here without SSL error, cert is valid
    const cert = {
      valid:    true,
      hostname,
    };
    return cert;
  } catch (err) {
    const invalid = err.message?.includes('certificate') ||
                    err.message?.includes('SSL') ||
                    err.message?.includes('TLS');
    return { valid: !invalid, hostname, error: err.message?.slice(0, 100) };
  }
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────
function assessAssetRisk(asset) {
  const reasons = [];
  let score = 0;

  // Open RDP/SSH/Telnet
  if ((asset.ports || []).includes(3389)) { reasons.push('RDP exposed'); score += 25; }
  if ((asset.ports || []).includes(22))   { reasons.push('SSH exposed'); score += 10; }
  if ((asset.ports || []).includes(23))   { reasons.push('Telnet exposed'); score += 30; }
  if ((asset.ports || []).includes(21))   { reasons.push('FTP exposed'); score += 20; }
  if ((asset.ports || []).includes(445))  { reasons.push('SMB exposed'); score += 30; }
  if ((asset.ports || []).includes(1433)) { reasons.push('MSSQL exposed'); score += 35; }
  if ((asset.ports || []).includes(3306)) { reasons.push('MySQL exposed'); score += 30; }
  if ((asset.ports || []).includes(27017)) { reasons.push('MongoDB exposed'); score += 35; }
  if ((asset.ports || []).includes(6379)) { reasons.push('Redis exposed'); score += 35; }
  if ((asset.ports || []).includes(9200)) { reasons.push('Elasticsearch exposed'); score += 35; }

  // Known CVEs
  if ((asset.vulns || []).length > 0) {
    reasons.push(`${asset.vulns.length} known CVEs`);
    score += Math.min(asset.vulns.length * 10, 40);
  }

  // Invalid/missing cert
  if (asset.cert_valid === false) { reasons.push('Invalid SSL cert'); score += 20; }

  // Missing security headers
  if (asset.http_data && !asset.http_data.headers?.hsts) {
    reasons.push('Missing HSTS'); score += 5;
  }

  // HTTP instead of HTTPS
  if (asset.http_data?.protocol === 'HTTP') { reasons.push('Unencrypted HTTP'); score += 15; }

  const level =
    score >= 60 ? 'CRITICAL' :
    score >= 35 ? 'HIGH' :
    score >= 15 ? 'MEDIUM' :
    score > 0   ? 'LOW' : 'INFO';

  return { risk_score: Math.min(score, 100), risk_level: level, risk_reasons: reasons };
}

function calculateASMScore(assets) {
  if (!assets.length) return { score: 0, grade: 'A' };

  const critical = assets.filter(a => a.risk_level === 'CRITICAL').length;
  const high     = assets.filter(a => a.risk_level === 'HIGH').length;
  const medium   = assets.filter(a => a.risk_level === 'MEDIUM').length;

  // Score: higher = more exposed (worse)
  const raw = (critical * 25 + high * 10 + medium * 3);
  const score = Math.min(raw, 100);

  const grade =
    score === 0    ? 'A' :
    score <= 15    ? 'B' :
    score <= 35    ? 'C' :
    score <= 60    ? 'D' : 'F';

  return { score, grade };
}

// ─── Main ASM scan ────────────────────────────────────────────────────────────
export async function runASMScan(env, targetId, domain) {
  const startTime = Date.now();
  const assets    = [];
  const errors    = [];

  // Step 1: Discover subdomains via CT
  let subdomains = [];
  try {
    subdomains = await discoverSubdomainsViaCT(domain);
    // Always include the root domain
    if (!subdomains.includes(domain)) subdomains.unshift(domain);
  } catch (e) {
    errors.push(`CT discovery: ${e.message}`);
    subdomains = [domain];
  }

  // Limit to 25 subdomains for scan performance
  const scanTargets = subdomains.slice(0, 25);

  // Step 2: For each subdomain — resolve, probe, risk-assess
  for (const host of scanTargets) {
    try {
      // DNS resolution
      const ips = await resolveA(host);
      if (!ips.length && host !== domain) continue; // skip unresolvable subdomains

      const assetBase = {
        id:          `asm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        target_id:   targetId,
        asset_type:  host === domain ? 'root_domain' : 'subdomain',
        asset_value: host,
        ip_address:  ips[0] || null,
        first_seen:  new Date().toISOString(),
        last_seen:   new Date().toISOString(),
        new_asset:   1,
        resolved:    0,
      };

      // Shodan for each IP
      let shodanData = null;
      if (ips[0]) {
        try { shodanData = await getShodanData(ips[0]); } catch {}
      }

      // HTTP probe (up to 10 hosts to stay within time budget)
      let httpData = null;
      if (assets.length < 10) {
        try { httpData = await probeHTTP(host); } catch {}
      }

      // Cert check for HTTPS hosts
      let certData = null;
      if (httpData?.protocol === 'HTTPS' || assets.length < 5) {
        try { certData = await checkCertValidity(host); } catch {}
      }

      // Assemble asset
      const fullAsset = {
        ...assetBase,
        open_ports:   JSON.stringify(shodanData?.ports || []),
        technologies: JSON.stringify(
          [...(shodanData?.cpes || []), ...(httpData?.server ? [httpData.server] : [])].slice(0, 10)
        ),
        cert_valid:   certData?.valid ?? null,
        cert_issuer:  null,
        cert_expiry:  null,
        http_status:  httpData?.status || null,
        http_title:   httpData?.title || null,
        // Temp fields for risk assessment
        ports:        shodanData?.ports || [],
        vulns:        shodanData?.vulns || [],
        http_data:    httpData,
        cert_data:    certData,
      };

      const risk = assessAssetRisk(fullAsset);
      fullAsset.risk_level   = risk.risk_level;
      fullAsset.risk_score   = risk.risk_score;
      fullAsset.risk_reasons = JSON.stringify(risk.risk_reasons);

      // Remove temp fields
      delete fullAsset.ports;
      delete fullAsset.vulns;
      delete fullAsset.http_data;
      delete fullAsset.cert_data;

      assets.push(fullAsset);
    } catch (e) {
      errors.push(`${host}: ${e.message?.slice(0, 100)}`);
    }
  }

  // Step 3: Store assets in D1
  if (env.DB && assets.length > 0) {
    try {
      for (const asset of assets) {
        await env.DB.prepare(`
          INSERT OR REPLACE INTO asm_assets
            (id, target_id, asset_type, asset_value, ip_address, open_ports,
             technologies, cert_valid, http_status, risk_level, risk_reasons,
             first_seen, last_seen, new_asset)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          asset.id, asset.target_id, asset.asset_type, asset.asset_value,
          asset.ip_address, asset.open_ports, asset.technologies,
          asset.cert_valid, asset.http_status, asset.risk_level,
          asset.risk_reasons, asset.first_seen, asset.last_seen, asset.new_asset,
        ).run();
      }
    } catch (e) {
      errors.push(`D1 store: ${e.message}`);
    }
  }

  // Step 4: Calculate overall ASM score
  const { score, grade } = calculateASMScore(assets);
  const criticalCount = assets.filter(a => a.risk_level === 'CRITICAL').length;
  const highCount     = assets.filter(a => a.risk_level === 'HIGH').length;

  // Step 5: Update target record
  if (env.DB && targetId) {
    try {
      await env.DB.prepare(`
        UPDATE asm_targets SET
          scan_status  = 'complete',
          asm_score    = ?,
          risk_grade   = ?,
          total_assets = ?,
          last_scan    = datetime('now'),
          next_scan    = datetime('now', '+24 hours'),
          updated_at   = datetime('now')
        WHERE id = ?
      `).bind(score, grade, assets.length, targetId).run();
    } catch {}
  }

  return {
    target_domain:    domain,
    total_assets:     assets.length,
    subdomains_found: subdomains.length,
    scanned:          scanTargets.length,
    asm_score:        score,
    risk_grade:       grade,
    critical_assets:  criticalCount,
    high_risk_assets: highCount,
    assets:           assets.slice(0, 50).map(a => ({
      subdomain:   a.asset_value,
      ip:          a.ip_address,
      risk_level:  a.risk_level,
      risk_reasons: JSON.parse(a.risk_reasons || '[]'),
      http_status: a.http_status,
      cert_valid:  a.cert_valid,
    })),
    errors: errors.slice(0, 10),
    duration_ms: Date.now() - startTime,
  };
}

// ─── Get ASM target with assets ───────────────────────────────────────────────
export async function getASMReport(env, targetId) {
  if (!env.DB) return null;
  try {
    const [target, assets] = await Promise.all([
      env.DB.prepare('SELECT * FROM asm_targets WHERE id = ?').bind(targetId).first(),
      env.DB.prepare(`
        SELECT * FROM asm_assets WHERE target_id = ?
        ORDER BY CASE risk_level
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM'   THEN 3 WHEN 'LOW' THEN 4
          ELSE 5 END
      `).bind(targetId).all(),
    ]);
    if (!target) return null;
    return {
      ...target,
      assets: (assets.results || []).map(a => ({
        ...a,
        open_ports:   JSON.parse(a.open_ports || '[]'),
        technologies: JSON.parse(a.technologies || '[]'),
        risk_reasons: JSON.parse(a.risk_reasons || '[]'),
      })),
    };
  } catch { return null; }
}
