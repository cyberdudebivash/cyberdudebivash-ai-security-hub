/**
 * CYBERDUDEBIVASH AI Security Hub — Domain Scan Handler v4.0
 * Real DNS resolution via Cloudflare DoH + DNSBL threat intel
 * Deterministic engine fallback if live DNS fails
 * Full KV scan caching (TTL: 1h) to avoid redundant lookups
 */

import { domainScanEngine }      from '../engine.js';
import { addMonetizationFlags }  from '../middleware/monetization.js';
import { validateDomain, parseBody } from '../middleware/validation.js';
import { inspectForAttacks, sanitizeString } from '../middleware/security.js';
import { resolveDomain, inferTLSGrade }      from '../lib/dns.js';
import { fullBlacklistCheck }                from '../lib/dnsbl.js';

const CACHE_TTL_SECONDS = 3600; // 1 hour

function genScanId() {
  return 'sc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function riskLevel(s) {
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 35 ? 'MEDIUM' : 'LOW';
}

// ─── KV Cache ─────────────────────────────────────────────────────────────────
async function getCachedScan(env, domain) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(`scan:domain:${domain}`);
    if (!raw) return null;
    const cached = JSON.parse(raw);
    if (Date.now() - cached._cached_at > CACHE_TTL_SECONDS * 1000) return null;
    return cached;
  } catch { return null; }
}

async function cacheScan(env, domain, result) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    await env.SECURITY_HUB_KV.put(
      `scan:domain:${domain}`,
      JSON.stringify({ ...result, _cached_at: Date.now() }),
      { expirationTtl: CACHE_TTL_SECONDS }
    );
  } catch {}
}

// ─── Build findings from live DNS data ───────────────────────────────────────
function buildRealFindings(domain, dns, tls, bl) {
  const findings = [];

  // DOM-001: TLS/SSL & HSTS
  const tlsGrade = tls?.tls_grade ?? 'UNKNOWN';
  const tlsSev   = tlsGrade === 'STRONG' ? 'LOW' : tlsGrade === 'FAIR' ? 'MEDIUM' : 'CRITICAL';
  findings.push({
    id: 'DOM-001', title: 'TLS/SSL & HSTS Configuration', severity: tlsSev,
    description: tls?.reachable === false
      ? `Domain "${domain}" did not respond to HTTPS — may be offline or certificate invalid.`
      : `HSTS: ${tls.hsts_present ? `max-age=${tls.hsts_max_age}s${tls.hsts_preload ? ', preload' : ''}` : 'missing'}. TLS grade: ${tlsGrade}.`,
    hsts_present: tls?.hsts_present ?? false, hsts_max_age: tls?.hsts_max_age ?? 0,
    hsts_preload: tls?.hsts_preload ?? false, tls_grade: tlsGrade,
    recommendation: 'Enforce HSTS max-age ≥ 31536000 with includeSubDomains and preload. Use TLS 1.3 minimum.',
    cvss_base: tlsGrade === 'STRONG' ? 2.1 : tlsGrade === 'FAIR' ? 4.3 : 7.4,
    is_premium: false, data_source: 'live_http_probe',
  });

  // DOM-002: DNSSEC
  const dnssec = dns?.dnssec;
  findings.push({
    id: 'DOM-002', title: 'DNSSEC Validation', severity: dnssec?.enabled ? 'LOW' : 'HIGH',
    description: dnssec?.enabled
      ? `DNSSEC enabled. DS records: ${dnssec.ds_records}. DNSKEY: ${dnssec.dnskey}. Status: ${dnssec.status}.`
      : `DNSSEC NOT enabled (${dnssec?.status ?? 'MISSING'}). Vulnerable to DNS cache poisoning and BGP hijacking.`,
    dnssec_status: dnssec?.status ?? 'MISSING', ds_records: dnssec?.ds_records ?? false,
    recommendation: 'Enable DNSSEC at your registrar. Configure DS records and NSEC3.',
    cvss_base: dnssec?.enabled ? 2.0 : 6.8,
    is_premium: false, data_source: 'live_dns',
  });

  // DOM-003: HTTP Security Headers
  const liveHeaders = tls?.headers_found ?? {};
  const EXPECTED = [
    { name:'content-security-policy',   risk:20, label:'Content-Security-Policy'   },
    { name:'x-frame-options',            risk:10, label:'X-Frame-Options'            },
    { name:'x-content-type-options',     risk:8,  label:'X-Content-Type-Options'     },
    { name:'referrer-policy',            risk:6,  label:'Referrer-Policy'            },
    { name:'permissions-policy',         risk:5,  label:'Permissions-Policy'         },
    { name:'cross-origin-opener-policy', risk:5,  label:'Cross-Origin-Opener-Policy' },
  ];
  const missing    = EXPECTED.filter(h => !liveHeaders[h.name]);
  const headerRisk = missing.reduce((s, h) => s + h.risk, 0);
  findings.push({
    id: 'DOM-003', title: 'HTTP Security Headers', severity: headerRisk > 30 ? 'HIGH' : headerRisk > 10 ? 'MEDIUM' : 'LOW',
    description: tls?.reachable === false
      ? 'Could not probe HTTP headers — domain unreachable.'
      : `${missing.length} headers missing. Risk: ${headerRisk}/54. Missing: ${missing.map(h=>h.label).join(', ') || 'none'}.`,
    missing_headers: missing.map(h => ({ header: h.label, risk_score: h.risk })),
    present_headers: EXPECTED.filter(h => !!liveHeaders[h.name]).map(h => h.label),
    recommendation: 'Implement all OWASP security headers. Test at securityheaders.com.',
    cvss_base: headerRisk > 30 ? 6.1 : 4.3,
    is_premium: false, data_source: tls?.reachable !== false ? 'live_http_probe' : 'unavailable',
  });

  // DOM-004: SPF
  const spf    = dns?.spf;
  const spfSev = !spf?.present ? 'HIGH' : spf.policy === 'OPEN' ? 'CRITICAL' : spf.policy !== 'STRICT' ? 'MEDIUM' : 'LOW';
  findings.push({
    id: 'DOM-004', title: 'SPF (Sender Policy Framework)', severity: spfSev,
    description: !spf?.present
      ? `No SPF record at ${domain}. Any server can forge email from this domain.`
      : `SPF found. Policy: ${spf.policy}. ${spf.issues?.length ? 'Issues: ' + spf.issues.join(' | ') : 'Config OK.'}`,
    spf_present: spf?.present ?? false, spf_policy: spf?.policy ?? null,
    spf_record:  spf?.record  ?? null,  spf_issues:  spf?.issues  ?? [],
    recommendation: 'Publish SPF with -all (strict). Keep DNS lookup count ≤ 10.',
    cvss_base: !spf?.present ? 6.5 : spf.policy !== 'STRICT' ? 4.3 : 1.5,
    is_premium: false, data_source: 'live_dns',
  });

  // DOM-005: DMARC
  const dmarc    = dns?.dmarc;
  const dmarcSev = !dmarc?.present ? 'HIGH' : dmarc.enforcement_level === 'NONE' ? 'MEDIUM' : 'LOW';
  findings.push({
    id: 'DOM-005', title: 'DMARC Policy', severity: dmarcSev,
    description: !dmarc?.present
      ? `No DMARC record at _dmarc.${domain}. Email spoofing not blocked.`
      : `DMARC p=${dmarc.policy} (${dmarc.enforcement_level}). RUA: ${dmarc.rua || 'not set'}. ${dmarc.issues?.join(' | ') || ''}`,
    dmarc_present: dmarc?.present ?? false, dmarc_policy: dmarc?.policy ?? null,
    enforcement_level: dmarc?.enforcement_level ?? null, rua_configured: !!dmarc?.rua,
    recommendation: 'Set DMARC p=reject with rua= reporting address. Use a DMARC SaaS for visibility.',
    cvss_base: !dmarc?.present ? 6.5 : dmarc.enforcement_level === 'NONE' ? 4.3 : 2.0,
    is_premium: false, data_source: 'live_dns',
  });

  // DOM-006: DKIM (premium)
  const dkim = dns?.dkim;
  findings.push({
    id: 'DOM-006', title: 'DKIM Key Detection', severity: dkim?.found ? 'LOW' : 'HIGH',
    description: dkim?.found
      ? `DKIM found on selectors: ${dkim.selectors_found.map(s=>s.selector).join(', ')}.`
      : `No DKIM detected across ${dkim?.selectors_checked?.length ?? 11} common selectors. Unsigned email.`,
    dkim_found: dkim?.found ?? false, selectors_found: dkim?.selectors_found ?? [],
    recommendation: 'Configure DKIM with your ESP. Use 2048-bit keys. Rotate every 6 months.',
    cvss_base: dkim?.found ? 1.5 : 5.3,
    is_premium: true, data_source: 'live_dns',
  });

  // DOM-007: CAA (premium)
  const caa = dns?.caa;
  findings.push({
    id: 'DOM-007', title: 'CAA (Certificate Authority Authorization)', severity: caa?.present ? 'LOW' : 'MEDIUM',
    description: caa?.present
      ? `CAA records: ${caa.records.join(', ')}. SSL issuance restricted.`
      : `No CAA records. Any CA can issue certificates for ${domain}.`,
    caa_present: caa?.present ?? false, caa_records: caa?.records ?? [],
    recommendation: 'Add CAA issue records for your CA. Add iodef for mis-issuance alerts.',
    cvss_base: caa?.present ? 1.5 : 4.3,
    is_premium: true, data_source: 'live_dns',
  });

  // DOM-008: Threat Intelligence (premium)
  const blScore = bl?.combined_threat_score ?? 0;
  const blSev   = blScore >= 60 ? 'CRITICAL' : blScore >= 30 ? 'HIGH' : blScore > 0 ? 'MEDIUM' : 'LOW';
  findings.push({
    id: 'DOM-008', title: 'Threat Intelligence Feed Lookup', severity: blSev,
    description: bl?.any_blacklisted
      ? `⚠️ Listed on ${(bl.domain_check?.listed_count ?? 0) + (bl.ip_check?.listed_count ?? 0)} feed(s). ${bl.summary}`
      : `✅ Clean across ${bl?.feeds_total ?? 7} DNSBL / threat intelligence feeds. ${bl?.summary ?? ''}`,
    blacklisted: bl?.any_blacklisted ?? false, threat_score: blScore,
    risk_label: bl?.risk_label ?? 'CLEAN',
    domain_listed_on: bl?.domain_check?.listed_on ?? [],
    ip_listed_on:     bl?.ip_check?.listed_on     ?? [],
    feeds_checked:    bl?.feeds_total              ?? 7,
    recommendation: bl?.any_blacklisted
      ? 'Investigate blacklisting cause. Submit delisting requests. Check abuse.ch and Spamhaus.'
      : 'Monitor domain reputation continuously via automated feeds.',
    cvss_base: blScore >= 60 ? 9.1 : blScore >= 30 ? 6.5 : blScore > 0 ? 4.3 : 1.5,
    is_premium: true, data_source: 'live_dnsbl',
  });

  return findings;
}

// ─── Live risk score ──────────────────────────────────────────────────────────
function computeRealRiskScore(dns, tls, bl) {
  let score = 0;
  if (!tls?.reachable || tls?.tls_grade === 'WEAK') score += 20;
  else if (tls?.tls_grade === 'FAIR')               score += 8;
  if (!tls?.hsts_present)                           score += 10;
  if (!dns?.dnssec?.enabled)                        score += 15;
  if (!dns?.spf?.present)                           score += 15;
  else if (dns.spf.policy !== 'STRICT')             score += 7;
  if (!dns?.dmarc?.present)                         score += 15;
  else if (dns.dmarc.enforcement_level === 'NONE')  score += 8;
  if (!dns?.dkim?.found)                            score += 10;
  if (!dns?.caa?.present)                           score += 5;
  score += Math.round((bl?.combined_threat_score ?? 0) * 0.5);
  return Math.min(100, score);
}

// ─── buildRealResult — exported for queue consumer (no circular dep) ──────────
export function buildRealResult(domain, dns, tls, bl) {
  const scanId    = genScanId();
  const riskScore = computeRealRiskScore(dns, tls, bl);
  const findings  = buildRealFindings(domain, dns, tls, bl);
  return {
    module: 'domain_scanner', version: '5.0.0', target: domain,
    risk_score: riskScore, risk_level: riskLevel(riskScore),
    grade: riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A',
    data_source: 'live_dns',
    resolves: dns.resolves, ipv4: dns.ipv4, ipv6: dns.ipv6,
    nameservers: dns.nameservers, mx_records: dns.mx.records,
    tls_grade: tls?.tls_grade ?? 'UNKNOWN', hsts_present: tls?.hsts_present ?? false,
    dnssec_enabled: dns.dnssec.enabled, dnssec_status: dns.dnssec.status,
    spf_policy: dns.spf.policy, dmarc_policy: dns.dmarc.policy,
    dkim_found: dns.dkim.found, caa_present: dns.caa.present,
    blacklisted: bl?.any_blacklisted ?? false, threat_score: bl?.combined_threat_score ?? 0,
    summary: `"${domain}" scanned live. Risk: ${riskScore}/100 (${riskLevel(riskScore)}). ${findings.filter(f=>['CRITICAL','HIGH'].includes(f.severity)).length} critical/high findings.`,
    findings,
    email_security: { spf: dns.spf, dmarc: dns.dmarc, dkim: dns.dkim },
    threat_intelligence: bl ? {
      any_blacklisted: bl.any_blacklisted, combined_threat_score: bl.combined_threat_score,
      risk_label: bl.risk_label, feeds_total: bl.feeds_total, summary: bl.summary,
    } : null,
    scan_metadata: {
      engine_version: '5.0.0', scan_timestamp: new Date().toISOString(), scan_id: scanId,
      data_source: 'live_dns + cloudflare_doh + dnsbl',
      scan_modules: ['tls_probe','dnssec','spf','dmarc','dkim','caa','dnsbl_domain','dnsbl_ip'],
      powered_by: 'CYBERDUDEBIVASH AI Security Hub',
    },
  };
}

// ─── Main Handler ─────────────────────────────────────────────────────────────
export async function handleDomainScan(request, env, authCtx = {}) {
  const body = await parseBody(request);
  const raw  = body?.domain || body?.target || '';

  if (inspectForAttacks(raw)) {
    return Response.json({ error: 'Invalid input detected', field: 'domain' }, { status: 400 });
  }
  const validation = validateDomain(sanitizeString(raw));
  if (!validation.valid) {
    return Response.json({ error: 'Validation failed', message: validation.message, field: 'domain' }, { status: 400 });
  }

  const domain = validation.value;
  const scanId = genScanId();

  // Cache hit
  const cached = await getCachedScan(env, domain);
  if (cached && !body?.nocache) {
    return Response.json(addMonetizationFlags(cached, 'domain', authCtx, scanId), {
      status: 200,
      headers: { 'X-Scan-ID': scanId, 'X-Module': 'domain', 'X-Cache': 'HIT',
                 'X-Cache-Age': String(Math.round((Date.now() - cached._cached_at) / 1000)) + 's' },
    });
  }

  // Live DNS + DNSBL
  let dns = null, tls = null, bl = null, dataSource = 'deterministic_fallback';
  try {
    [dns, tls] = await Promise.all([ resolveDomain(domain), inferTLSGrade(domain) ]);
    bl         = await fullBlacklistCheck(domain, dns?.ipv4 ?? []);
    dataSource = 'live_dns';
  } catch { /* fallback below */ }

  let scanResult;

  if (dataSource === 'live_dns' && dns) {
    const riskScore = computeRealRiskScore(dns, tls, bl);
    const findings  = buildRealFindings(domain, dns, tls, bl);

    scanResult = {
      module: 'domain_scanner', version: '4.0.0', target: domain,
      risk_score: riskScore, risk_level: riskLevel(riskScore),
      grade: riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A',
      data_source:    'live_dns',
      resolves:       dns.resolves, ipv4: dns.ipv4, ipv6: dns.ipv6,
      nameservers:    dns.nameservers, mx_records: dns.mx.records,
      tls_grade:      tls?.tls_grade ?? 'UNKNOWN', hsts_present: tls?.hsts_present ?? false,
      dnssec_enabled: dns.dnssec.enabled, dnssec_status: dns.dnssec.status,
      spf_policy:     dns.spf.policy,  dmarc_policy: dns.dmarc.policy,
      dkim_found:     dns.dkim.found,  caa_present:  dns.caa.present,
      blacklisted:    bl?.any_blacklisted ?? false, threat_score: bl?.combined_threat_score ?? 0,
      summary: `"${domain}" scanned live via DoH across DNS, TLS, email security, and ${bl?.feeds_total ?? 7} threat feeds. Risk: ${riskScore}/100 (${riskLevel(riskScore)}). ${findings.filter(f=>['CRITICAL','HIGH'].includes(f.severity)).length} critical/high findings.`,
      findings,
      email_security: { spf: dns.spf, dmarc: dns.dmarc, dkim: dns.dkim },
      threat_intelligence: bl ? {
        any_blacklisted: bl.any_blacklisted, combined_threat_score: bl.combined_threat_score,
        risk_label: bl.risk_label, domain_listed_on: bl.domain_check?.listed_on,
        ip_listed_on: bl.ip_check?.listed_on, feeds_total: bl.feeds_total, summary: bl.summary,
      } : null,
      scan_metadata: {
        engine_version: '4.0.0', scan_timestamp: new Date().toISOString(), scan_id: scanId,
        data_source: 'live_dns + cloudflare_doh + dnsbl',
        scan_modules: ['tls_probe','dnssec','spf','dmarc','dkim','caa','dnsbl_domain','dnsbl_ip'],
        powered_by: 'CYBERDUDEBIVASH AI Security Hub',
      },
    };
    await cacheScan(env, domain, scanResult);

  } else {
    scanResult = {
      ...domainScanEngine(domain),
      data_source: dataSource,
      fallback_reason: 'Live DNS unavailable — deterministic engine used',
    };
  }

  return Response.json(addMonetizationFlags(scanResult, 'domain', authCtx, scanId), {
    status: 200,
    headers: { 'X-Scan-ID': scanId, 'X-Module': 'domain', 'X-Cache': 'MISS', 'X-Data-Source': dataSource },
  });
}
