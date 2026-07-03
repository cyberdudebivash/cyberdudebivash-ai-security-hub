/**
 * GET /api/threat/ioc?ioc=<value>[&type=<auto|ipv4|domain|hash|cve|url|email>]
 *
 * Production IOC enrichment against:
 *   CVE     → Cloudflare D1 threat_intel
 *   IP      → AbuseIPDB v2 (if ABUSEIPDB_API_KEY configured)
 *   Domain  → VirusTotal v3 (if VIRUSTOTAL_API_KEY configured)
 *   Hash    → MalwareBazaar (free, no key needed)
 *   URL     → VirusTotal v3 URL scan (if VIRUSTOTAL_API_KEY configured)
 *   Email   → domain part enriched via VirusTotal
 *
 * Returns normalized verdict: MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN
 */

// ─── IOC type detection ───────────────────────────────────────────────────────
export function detectIOCType(value) {
  if (!value || typeof value !== 'string') return 'unknown';
  const v = value.trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(v))                  return 'cve';
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v))  return 'ipv4';
  if (/^[0-9a-f]{64}$/i.test(v))                       return 'sha256';
  if (/^[0-9a-f]{40}$/i.test(v))                       return 'sha1';
  if (/^[0-9a-f]{32}$/i.test(v))                       return 'md5';
  if (/^https?:\/\//i.test(v))                          return 'url';
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v))            return 'email';
  if (/^[a-z0-9][a-z0-9\-\.]{0,253}[a-z0-9]\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'unknown';
}

// ─── Verdict normalizer ───────────────────────────────────────────────────────
function buildVerdict(ioc, type, details, confidence, context = {}) {
  const { malicious = 0, suspicious = 0, harmless = 0, total = 0 } = context;
  let verdict = 'UNKNOWN';
  if (malicious > 0)                    verdict = 'MALICIOUS';
  else if (suspicious > 0)              verdict = 'SUSPICIOUS';
  else if (harmless > 0 && total > 2)   verdict = 'CLEAN';

  return {
    ioc,
    type,
    verdict,
    confidence,
    malicious_votes:  malicious,
    suspicious_votes: suspicious,
    harmless_votes:   harmless,
    total_engines:    total,
    details,
    enriched_at: new Date().toISOString(),
  };
}

// ─── CVE enrichment: D1 threat_intel ─────────────────────────────────────────
async function enrichCVE(ioc, env) {
  if (!env?.DB) {
    return buildVerdict(ioc, 'cve', { source: 'platform_d1', available: false,
      message: 'No threat intelligence database connected' }, 0);
  }

  try {
    const row = await env.DB.prepare(
      `SELECT cve_id, title, severity, cvss_score, epss_score,
              CASE WHEN exploit_status = 'confirmed' THEN 1 ELSE 0 END AS is_kev,
              description, published_at AS published_date, NULL AS mitre_technique, ingested_at
       FROM threat_intel WHERE cve_id = ? LIMIT 1`
    ).bind(ioc.toUpperCase()).first().catch(() => null);

    if (!row) {
      return buildVerdict(ioc, 'cve', {
        source: 'platform_d1',
        found:  false,
        message: 'CVE not found in platform threat intelligence database',
        note:    'Check NVD (nvd.nist.gov) for authoritative data',
      }, 0);
    }

    const cvss    = parseFloat(row.cvss_score) || 0;
    const epss    = parseFloat(row.epss_score) || 0;
    const is_kev  = !!row.is_kev;
    const sev     = (row.severity || '').toUpperCase();

    // Risk scoring: KEV = definite malicious (actively exploited), CVSS >=9 critical
    const malicious  = (is_kev || cvss >= 9.0) ? 1 : 0;
    const suspicious = (!malicious && (cvss >= 7.0 || epss >= 0.01)) ? 1 : 0;
    const harmless   = (!malicious && !suspicious && cvss < 4.0) ? 1 : 0;
    const confidence = is_kev ? 99 : Math.min(95, Math.round(cvss * 9.5 + epss * 100));

    return buildVerdict(ioc, 'cve', {
      source:          'platform_d1_threat_intel',
      found:           true,
      title:           row.title || row.cve_id,
      description:     (row.description || '').slice(0, 500),
      severity:        sev,
      cvss_score:      cvss,
      epss_score:      epss,
      epss_pct:        `${(epss * 100).toFixed(2)}% probability of exploitation`,
      is_kev:          is_kev,
      kev_note:        is_kev ? 'CISA KEV: actively exploited in the wild' : null,
      mitre_technique: row.mitre_technique || null,
      published_date:  row.published_date,
      ingested_at:     row.ingested_at,
      references: [
        `https://nvd.nist.gov/vuln/detail/${row.cve_id}`,
        is_kev ? 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' : null,
      ].filter(Boolean),
    }, confidence, { malicious, suspicious, harmless, total: 1 });
  } catch (err) {
    return buildVerdict(ioc, 'cve', { source: 'platform_d1', error: 'Query failed' }, 0);
  }
}

// ─── IP enrichment: AbuseIPDB v2 ─────────────────────────────────────────────
async function enrichIP(ioc, env) {
  const apiKey = env?.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return buildVerdict(ioc, 'ipv4', {
      source:    'abuseipdb',
      available: false,
      message:   'AbuseIPDB enrichment not configured (set ABUSEIPDB_API_KEY secret)',
    }, 0);
  }

  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90&verbose`,
      { headers: { Key: apiKey, Accept: 'application/json' }, cf: { cacheTtl: 3600 } }
    );
    if (!res.ok) {
      return buildVerdict(ioc, 'ipv4', { source: 'abuseipdb', http_status: res.status,
        message: 'AbuseIPDB API returned non-200 response' }, 0);
    }

    const json = await res.json();
    const d = json?.data || {};
    const score = d.abuseConfidenceScore || 0;

    const malicious  = score >= 75 ? 1 : 0;
    const suspicious = (!malicious && score >= 25) ? 1 : 0;
    const harmless   = score === 0 && (d.totalReports || 0) === 0 ? 1 : 0;

    return buildVerdict(ioc, 'ipv4', {
      source:                   'abuseipdb_v2',
      ip_address:               d.ipAddress,
      abuse_confidence_score:   score,
      total_reports:            d.totalReports || 0,
      distinct_users_reporting: d.numDistinctUsers || 0,
      country_code:             d.countryCode || null,
      usage_type:               d.usageType || null,
      isp:                      d.isp || null,
      domain:                   d.domain || null,
      is_tor:                   !!d.isTor,
      is_public:                !!d.isPublic,
      last_reported:            d.lastReportedAt || null,
      whitelisted:              !!d.isWhitelisted,
      categories: (d.reports || []).flatMap(r => r.categories || [])
        .filter((v, i, a) => a.indexOf(v) === i).slice(0, 10),
    }, score, { malicious, suspicious, harmless, total: Math.max(d.totalReports || 0, 1) });
  } catch (err) {
    return buildVerdict(ioc, 'ipv4', { source: 'abuseipdb', error: 'Request failed' }, 0);
  }
}

// ─── Domain enrichment: VirusTotal v3 ────────────────────────────────────────
async function enrichDomain(ioc, env) {
  const apiKey = env?.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return buildVerdict(ioc, 'domain', {
      source:    'virustotal',
      available: false,
      message:   'VirusTotal enrichment not configured (set VIRUSTOTAL_API_KEY secret)',
    }, 0);
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`, {
      headers: { 'x-apikey': apiKey }, cf: { cacheTtl: 3600 }
    });
    if (!res.ok) {
      return buildVerdict(ioc, 'domain', { source: 'virustotal', http_status: res.status,
        message: 'VirusTotal API returned non-200 response' }, 0);
    }

    const json = await res.json();
    const attr  = json?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};

    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const total      = Object.values(stats).reduce((a, b) => a + b, 0);
    const confidence = total > 0 ? Math.min(99, Math.round(((malicious + suspicious) / total) * 100)) : 0;

    // Top malicious detections
    const engines = attr.last_analysis_results || {};
    const malDetections = Object.entries(engines)
      .filter(([, v]) => v.category === 'malicious')
      .map(([engine, v]) => ({ engine, result: v.result }))
      .slice(0, 5);

    return buildVerdict(ioc, 'domain', {
      source:          'virustotal_v3',
      domain:          ioc,
      reputation:      attr.reputation || 0,
      categories:      attr.categories || {},
      registrar:       attr.registrar || null,
      creation_date:   attr.creation_date ? new Date(attr.creation_date * 1000).toISOString() : null,
      expiration_date: attr.expiration_date ? new Date(attr.expiration_date * 1000).toISOString() : null,
      last_analysis_date: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
      analysis_stats:  stats,
      malicious_detections: malDetections,
      tags:            attr.tags || [],
    }, confidence, { malicious, suspicious, harmless, total });
  } catch (err) {
    return buildVerdict(ioc, 'domain', { source: 'virustotal', error: 'Request failed' }, 0);
  }
}

// ─── Hash enrichment: MalwareBazaar (free, no key) ───────────────────────────
async function enrichHash(ioc, type, env) {
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    `query=get_info&hash=${encodeURIComponent(ioc)}`,
      cf:      { cacheTtl: 3600 },
    });
    if (!res.ok) {
      return buildVerdict(ioc, type, { source: 'malwarebazaar', http_status: res.status,
        message: 'MalwareBazaar API returned non-200 response' }, 0);
    }

    const json = await res.json();
    if (json.query_status === 'hash_not_found') {
      return buildVerdict(ioc, type, {
        source:  'malwarebazaar',
        found:   false,
        message: 'Hash not found in MalwareBazaar database — does not confirm clean',
      }, 0, { harmless: 1, total: 1 });
    }

    const sample = (json.data || [])[0] || {};
    const tags   = sample.tags || [];
    const malFamilies = sample.vendor_intel
      ? Object.values(sample.vendor_intel).map(v => v.detection).filter(Boolean)
      : [];

    const isMalware  = json.query_status === 'ok' && !!sample.sha256_hash;
    const confidence = isMalware ? 95 : 0;

    return buildVerdict(ioc, type, {
      source:        'malwarebazaar',
      found:         isMalware,
      sha256:        sample.sha256_hash || null,
      sha1:          sample.sha1_hash || null,
      md5:           sample.md5_hash || null,
      file_name:     sample.file_name || null,
      file_type:     sample.file_type || null,
      file_size:     sample.file_size || null,
      mime_type:     sample.mime_type || null,
      first_seen:    sample.first_seen || null,
      last_seen:     sample.last_seen || null,
      signature:     sample.signature || null,
      tags,
      malware_families: malFamilies.filter((v, i, a) => a.indexOf(v) === i).slice(0, 5),
      delivery_method: sample.delivery_method || null,
      intelligence:  sample.intelligence || null,
    }, confidence, isMalware
      ? { malicious: 1, suspicious: 0, harmless: 0, total: 1 }
      : { malicious: 0, suspicious: 0, harmless: 1, total: 1 });
  } catch (err) {
    return buildVerdict(ioc, type, { source: 'malwarebazaar', error: 'Request failed' }, 0);
  }
}

// ─── URL enrichment: VirusTotal v3 URL scan ──────────────────────────────────
async function enrichURL(ioc, env) {
  const apiKey = env?.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    // Extract domain and try domain enrichment without key hint
    return buildVerdict(ioc, 'url', {
      source:    'virustotal',
      available: false,
      message:   'VirusTotal enrichment not configured (set VIRUSTOTAL_API_KEY secret)',
    }, 0);
  }

  try {
    // VT URL lookup uses base64url of the URL as identifier
    const urlId = btoa(ioc).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey }, cf: { cacheTtl: 3600 }
    });
    if (!res.ok) {
      return buildVerdict(ioc, 'url', { source: 'virustotal', http_status: res.status,
        message: 'VirusTotal URL lookup returned non-200 response' }, 0);
    }

    const json   = await res.json();
    const attr   = json?.data?.attributes || {};
    const stats  = attr.last_analysis_stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const total      = Object.values(stats).reduce((a, b) => a + b, 0);
    const confidence = total > 0 ? Math.min(99, Math.round(((malicious + suspicious) / total) * 100)) : 0;

    return buildVerdict(ioc, 'url', {
      source:         'virustotal_v3',
      url:            ioc,
      final_url:      attr.last_final_url || ioc,
      reputation:     attr.reputation || 0,
      analysis_stats: stats,
      categories:     attr.categories || {},
      title:          attr.title || null,
      last_analysis:  attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
      tags:           attr.tags || [],
    }, confidence, { malicious, suspicious, harmless, total });
  } catch {
    return buildVerdict(ioc, 'url', { source: 'virustotal', error: 'Request failed' }, 0);
  }
}

// ─── Email enrichment: domain part via VirusTotal ────────────────────────────
async function enrichEmail(ioc, env) {
  const domain = ioc.split('@')[1] || '';
  if (!domain) {
    return buildVerdict(ioc, 'email', { source: 'virustotal',
      message: 'Cannot parse domain from email address' }, 0);
  }
  const domainResult = await enrichDomain(domain, env);
  return {
    ...domainResult,
    ioc,
    type:   'email',
    details: {
      ...domainResult.details,
      email:        ioc,
      email_domain: domain,
      note: 'Verdict based on email domain reputation via VirusTotal',
    },
  };
}

// ─── GET /api/threat/ioc ─────────────────────────────────────────────────────
export async function handleThreatIOC(request, env, authCtx) {
  const url  = new URL(request.url);
  const ioc  = (url.searchParams.get('ioc') || url.searchParams.get('value') || '').trim();
  const hint = (url.searchParams.get('type') || 'auto').toLowerCase();

  if (!ioc || ioc.length < 3) {
    return Response.json({
      error:   'ioc query parameter is required (min 3 chars)',
      example: '/api/threat/ioc?ioc=CVE-2024-21413',
    }, { status: 400 });
  }
  if (ioc.length > 2048) {
    return Response.json({ error: 'ioc value too long (max 2048 chars)' }, { status: 400 });
  }

  const type = hint === 'auto' ? detectIOCType(ioc) : hint;
  const start = Date.now();

  let result;
  switch (type) {
    case 'cve':    result = await enrichCVE(ioc, env);           break;
    case 'ipv4':   result = await enrichIP(ioc, env);            break;
    case 'domain': result = await enrichDomain(ioc, env);        break;
    case 'sha256':
    case 'sha1':
    case 'md5':    result = await enrichHash(ioc, type, env);    break;
    case 'url':    result = await enrichURL(ioc, env);           break;
    case 'email':  result = await enrichEmail(ioc, env);         break;
    default:
      return Response.json({
        error: `Cannot determine IOC type for: ${ioc}`,
        hint:  'Pass ?type=ipv4|domain|md5|sha1|sha256|url|email|cve to override',
      }, { status: 422 });
  }

  // Persist lookup in KV for audit log (no-wait)
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(
      `ioc:lookup:${crypto.randomUUID()}`,
      JSON.stringify({
        ioc, type,
        verdict:   result.verdict,
        queried_by: authCtx?.identity || 'anonymous',
        ts:        new Date().toISOString(),
      }),
      { expirationTtl: 2592000 } // 30 days
    ).catch(() => {});
  }

  return Response.json({
    ...result,
    query_duration_ms: Date.now() - start,
    platform: 'CYBERDUDEBIVASH AI Security Hub v22.0',
  });
}
