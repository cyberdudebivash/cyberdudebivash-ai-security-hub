/**
 * CYBERDUDEBIVASH AI Security Hub — Real DNS Resolver v1.0
 * Uses Cloudflare DNS-over-HTTPS (DoH) — works natively in CF Workers
 * No external dependencies. Timeout-safe. Fails gracefully.
 *
 * Resolves: A, AAAA, MX, TXT, NS, CAA, DS, DNSKEY, SOA
 * Checks:   SPF, DMARC, DKIM, DNSSEC validation bit
 */

const DOH_URL   = 'https://cloudflare-dns.com/dns-query';
const DOH_TIMEOUT = 4000; // 4s per query

// ─── Core DoH Fetch ───────────────────────────────────────────────────────────
async function dohQuery(name, type) {
  const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT);
  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ─── Safe Record Extractor ────────────────────────────────────────────────────
function extractRecords(dohResp, type) {
  if (!dohResp?.Answer) return [];
  const typeNum = DNS_TYPES[type] ?? type;
  return dohResp.Answer
    .filter(r => r.type === typeNum || r.type === type)
    .map(r => r.data?.replace(/^"|"$/g, '').trim())
    .filter(Boolean);
}

const DNS_TYPES = { A:1, AAAA:28, NS:2, CNAME:5, SOA:6, MX:15, TXT:16, CAA:257, DS:43, DNSKEY:48 };

// ─── DNSSEC Status ────────────────────────────────────────────────────────────
async function checkDNSSEC(domain) {
  const [ds, dnskey] = await Promise.all([
    dohQuery(domain, 'DS'),
    dohQuery(domain, 'DNSKEY'),
  ]);
  const hasDS     = (ds?.Answer?.length ?? 0) > 0;
  const hasDNSKEY = (dnskey?.Answer?.length ?? 0) > 0;
  // Also check Authenticated Data (AD) bit — CF DoH sets this in the response
  const adBit     = ds?.AD === true || dnskey?.AD === true;

  return {
    enabled:     hasDS && hasDNSKEY,
    ds_records:  hasDS,
    dnskey:      hasDNSKEY,
    validated:   adBit,
    status:      hasDS && hasDNSKEY ? (adBit ? 'VALIDATED' : 'PRESENT') : 'MISSING',
  };
}

// ─── SPF Analysis ─────────────────────────────────────────────────────────────
function parseSPF(txtRecords) {
  const spf = txtRecords.find(r => r.toLowerCase().startsWith('v=spf1'));
  if (!spf) return { present: false, policy: null, issues: ['SPF record missing — email spoofing possible'], record: null };

  const issues = [];
  let policy = 'UNKNOWN';

  if (spf.includes(' -all'))       policy = 'STRICT';
  else if (spf.includes(' ~all'))  policy = 'SOFTFAIL';
  else if (spf.includes(' ?all'))  { policy = 'NEUTRAL'; issues.push('SPF ?all is permissive — use -all for strict enforcement'); }
  else if (spf.includes(' +all'))  { policy = 'OPEN';    issues.push('SPF +all allows ANY server to send — critical misconfiguration'); }
  else                             { policy = 'MISSING_QUALIFIER'; issues.push('SPF record has no -all/~all qualifier'); }

  // Count DNS lookup mechanisms (SPF limit is 10)
  const lookups = (spf.match(/\b(include:|a:|mx:|redirect=|exists:)/g) || []).length;
  if (lookups > 10) issues.push(`SPF DNS lookup count (${lookups}) exceeds RFC limit of 10 — validation will fail`);
  if (policy !== 'STRICT') issues.push(`SPF policy "${policy}" — recommend upgrading to -all (strict)`);

  return { present: true, policy, record: spf, lookup_count: lookups, issues };
}

// ─── DMARC Analysis ──────────────────────────────────────────────────────────
async function checkDMARC(domain) {
  const resp    = await dohQuery(`_dmarc.${domain}`, 'TXT');
  const records = extractRecords(resp, 16);
  const dmarc   = records.find(r => r.toLowerCase().startsWith('v=dmarc1'));

  if (!dmarc) return { present: false, policy: null, issues: ['DMARC record missing — domain vulnerable to email spoofing'], record: null };

  const issues  = [];
  let policy    = 'none';
  const pMatch  = dmarc.match(/\bp=([a-zA-Z]+)/i);
  if (pMatch) policy = pMatch[1].toLowerCase();

  if (policy === 'none')      issues.push('DMARC p=none — monitoring only, does NOT block spoofed emails');
  else if (policy === 'quarantine') issues.push('DMARC p=quarantine — improve to p=reject for full protection');

  const spMatch = dmarc.match(/\bsp=([a-zA-Z]+)/i);
  const subdomainPolicy = spMatch ? spMatch[1].toLowerCase() : 'inherited';

  const pctMatch = dmarc.match(/\bpct=(\d+)/i);
  const pct = pctMatch ? parseInt(pctMatch[1], 10) : 100;
  if (pct < 100) issues.push(`DMARC pct=${pct}% — only ${pct}% of emails subject to policy`);

  const ruaMatch = dmarc.match(/\brua=([^\s;]+)/i);
  const rufMatch = dmarc.match(/\bruf=([^\s;]+)/i);

  return {
    present: true, policy, subdomain_policy: subdomainPolicy,
    pct, rua: ruaMatch?.[1] || null, ruf: rufMatch?.[1] || null,
    record: dmarc, issues,
    enforcement_level: policy === 'reject' ? 'FULL' : policy === 'quarantine' ? 'PARTIAL' : 'NONE',
  };
}

// ─── DKIM Check (selector probe) ─────────────────────────────────────────────
async function checkDKIM(domain) {
  // Probe common selectors used by major ESPs
  const selectors = ['google', 'selector1', 'selector2', 'default', 'dkim', 'k1', 'mail', 'smtp', 'email', 'sendgrid', 'mailchimp'];
  const found = [];

  // Check first 5 in parallel, then next 5 if none found
  const batch1 = await Promise.all(
    selectors.slice(0, 5).map(async sel => {
      const resp = await dohQuery(`${sel}._domainkey.${domain}`, 'TXT');
      const recs = extractRecords(resp, 16);
      const key  = recs.find(r => r.toLowerCase().includes('v=dkim1') || r.toLowerCase().includes('p='));
      return key ? { selector: sel, record_length: key.length, has_key: key.includes('p=') && !key.includes('p=;') } : null;
    })
  );
  found.push(...batch1.filter(Boolean));

  if (found.length === 0) {
    const batch2 = await Promise.all(
      selectors.slice(5).map(async sel => {
        const resp = await dohQuery(`${sel}._domainkey.${domain}`, 'TXT');
        const recs = extractRecords(resp, 16);
        const key  = recs.find(r => r.toLowerCase().includes('v=dkim1') || r.toLowerCase().includes('p='));
        return key ? { selector: sel, record_length: key.length, has_key: key.includes('p=') && !key.includes('p=;') } : null;
      })
    );
    found.push(...batch2.filter(Boolean));
  }

  return {
    found: found.length > 0,
    selectors_found: found,
    selectors_checked: selectors,
    issues: found.length === 0 ? ['No DKIM selectors detected — outbound email not cryptographically signed'] : [],
  };
}

// ─── MX Records ──────────────────────────────────────────────────────────────
async function checkMX(domain) {
  const resp = await dohQuery(domain, 'MX');
  if (!resp?.Answer) return { records: [], count: 0, has_mx: false };
  const mxRecs = resp.Answer
    .filter(r => r.type === 15)
    .map(r => {
      const parts = (r.data || '').split(' ');
      return { priority: parseInt(parts[0], 10) || 0, host: parts[1]?.replace(/\.$/, '') || '' };
    })
    .filter(r => r.host)
    .sort((a, b) => a.priority - b.priority);
  return { records: mxRecs, count: mxRecs.length, has_mx: mxRecs.length > 0 };
}

// ─── A / AAAA Records ────────────────────────────────────────────────────────
async function checkARecords(domain) {
  const [a4, a6] = await Promise.all([
    dohQuery(domain, 'A'),
    dohQuery(domain, 'AAAA'),
  ]);
  const ipv4 = extractRecords(a4, 1);
  const ipv6 = extractRecords(a6, 28);
  return { ipv4, ipv6, resolves: ipv4.length > 0 || ipv6.length > 0, ip_count: ipv4.length + ipv6.length };
}

// ─── NS Records ──────────────────────────────────────────────────────────────
async function checkNS(domain) {
  const resp = await dohQuery(domain, 'NS');
  const ns   = (resp?.Answer || []).filter(r => r.type === 2).map(r => r.data?.replace(/\.$/, ''));
  return { nameservers: ns.filter(Boolean), count: ns.length };
}

// ─── CAA Records ─────────────────────────────────────────────────────────────
async function checkCAA(domain) {
  const resp = await dohQuery(domain, 'CAA');
  const recs = (resp?.Answer || []).filter(r => r.type === 257).map(r => r.data);
  return {
    present: recs.length > 0,
    records: recs,
    issues: recs.length === 0 ? ['CAA record missing — any CA can issue SSL certificates for this domain'] : [],
  };
}

// ─── TXT Records (raw) ───────────────────────────────────────────────────────
async function getTXTRecords(domain) {
  const resp = await dohQuery(domain, 'TXT');
  return extractRecords(resp, 16);
}

// ─── Master Domain DNS Resolve ────────────────────────────────────────────────
export async function resolveDomain(domain) {
  // Fan out all checks in parallel
  const [txtRecords, dmarc, dkim, mx, aRecs, ns, caa, dnssec] = await Promise.all([
    getTXTRecords(domain),
    checkDMARC(domain),
    checkDKIM(domain),
    checkMX(domain),
    checkARecords(domain),
    checkNS(domain),
    checkCAA(domain),
    checkDNSSEC(domain),
  ]);

  const spf = parseSPF(txtRecords);

  return {
    domain,
    resolved_at: new Date().toISOString(),
    data_source: 'live_dns',          // signals real data to the scan engine
    resolves:    aRecs.resolves,
    ipv4:        aRecs.ipv4,
    ipv6:        aRecs.ipv6,
    ip_count:    aRecs.ip_count,
    nameservers: ns.nameservers,
    mx:          mx,
    spf:         spf,
    dmarc:       dmarc,
    dkim:        dkim,
    caa:         caa,
    dnssec:      dnssec,
    txt_records: txtRecords,
  };
}

// ─── TLS Grade (CF always uses SNI — no direct TLS probe from Workers) ────────
// Cloudflare Workers cannot open raw TCP/TLS sockets.
// We infer TLS grade from CAA + HSTS header presence via a lightweight fetch.
export async function inferTLSGrade(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timer);
    const hsts = res.headers.get('Strict-Transport-Security');
    const hstsMaxAge = hsts ? parseInt((hsts.match(/max-age=(\d+)/)||[])[1]||'0',10) : 0;

    // Collect all visible security headers
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    return {
      reachable:   true,
      https:       true,
      final_url:   res.url,
      status_code: res.status,
      hsts_present: !!hsts,
      hsts_max_age: hstsMaxAge,
      hsts_preload: hsts?.includes('preload') ?? false,
      hsts_subdomains: hsts?.includes('includeSubDomains') ?? false,
      headers_found: headers,
      tls_grade: hstsMaxAge >= 31536000 ? 'STRONG' : hstsMaxAge > 0 ? 'FAIR' : 'WEAK',
    };
  } catch {
    clearTimeout(timer);
    // Domain unreachable or self-signed — still try HTTP
    try {
      const r2 = await fetch(`http://${domain}`, { method:'HEAD', signal: new AbortController().signal, redirect:'manual' });
      const redirectsToHTTPS = (r2.headers.get('location')||'').startsWith('https://');
      return {
        reachable: true, https: redirectsToHTTPS, final_url: null,
        hsts_present: false, tls_grade: redirectsToHTTPS ? 'FAIR' : 'WEAK', headers_found: {},
      };
    } catch {
      return {
        reachable: false, https: false, final_url: null,
        hsts_present: false, tls_grade: 'UNKNOWN', headers_found: {},
      };
    }
  }
}
