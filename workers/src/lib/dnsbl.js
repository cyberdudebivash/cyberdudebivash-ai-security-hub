/**
 * CYBERDUDEBIVASH AI Security Hub — DNS Blacklist (DNSBL) Checker v1.0
 * Checks domains against free, public threat intelligence feeds via DNS.
 * Uses DNS-over-HTTPS — no API keys required, fully edge-native.
 *
 * Feeds: Spamhaus DBL, SURBL Multi, URIBL Multi, ABUSE.CH (domain)
 * IP Feeds: Spamhaus ZEN (for resolved IPs), Barracuda, SORBS
 */

const DOH_URL     = 'https://cloudflare-dns.com/dns-query';
const DNSBL_TIMEOUT = 3000;

// ─── DoH-based blacklist query ────────────────────────────────────────────────
async function dnsblLookup(query) {
  const url = `${DOH_URL}?name=${encodeURIComponent(query)}&type=A`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNSBL_TIMEOUT);
  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { listed: false, answers: [] };
    const data = await res.json();
    const answers = (data?.Answer || []).filter(r => r.type === 1).map(r => r.data);
    return { listed: answers.length > 0, answers };
  } catch {
    clearTimeout(timer);
    return { listed: false, answers: [], error: 'timeout' };
  }
}

// ─── Domain-based DNSBL feeds ─────────────────────────────────────────────────
const DOMAIN_DNSBL_FEEDS = [
  {
    name:        'Spamhaus DBL',
    suffix:      'dbl.spamhaus.org',
    description: 'Spamhaus Domain Block List — spam, phishing, malware domains',
    severity:    'HIGH',
    url:         'https://www.spamhaus.org/dbl/',
    // Return codes: 127.0.1.2=spam, 127.0.1.4=phishing, 127.0.1.5=malware, 127.0.1.6=botnet C&C
    decode: (ips) => {
      const codes = { '127.0.1.2':'spam_domain', '127.0.1.4':'phishing', '127.0.1.5':'malware', '127.0.1.6':'botnet_cnc' };
      return ips.map(ip => codes[ip] || 'listed').join(', ');
    },
  },
  {
    name:        'SURBL Multi',
    suffix:      'multi.surbl.org',
    description: 'SURBL — spamvertised URLs (spam, phishing, malware, abuse)',
    severity:    'HIGH',
    url:         'https://surbl.org/',
    decode: (ips) => ips.length > 0 ? 'listed_surbl' : null,
  },
  {
    name:        'URIBL',
    suffix:      'multi.uribl.com',
    description: 'URIBL — domains found in unsolicited email messages',
    severity:    'MEDIUM',
    url:         'https://uribl.com/',
    decode: (ips) => {
      // Bit flags: 2=black, 4=grey, 8=red, 16=white
      const codes = { '127.0.0.2':'black', '127.0.0.4':'grey', '127.0.0.8':'red', '127.0.0.14':'all' };
      return ips.map(ip => codes[ip] || 'listed').join(', ');
    },
  },
  {
    name:        'ABUSE.CH Domain Feed',
    suffix:      'domain.abuse.ch',
    description: 'Abuse.ch malware/botnet domains (Feodo Tracker, URLhaus)',
    severity:    'CRITICAL',
    url:         'https://abuse.ch/',
    decode: (ips) => ips.length > 0 ? 'malware_botnet' : null,
  },
];

// ─── IP-based DNSBL feeds ─────────────────────────────────────────────────────
const IP_DNSBL_FEEDS = [
  {
    name:        'Spamhaus ZEN',
    suffix:      'zen.spamhaus.org',
    description: 'Spamhaus composite IP block list (SBL, XBL, PBL)',
    severity:    'HIGH',
    url:         'https://www.spamhaus.org/zen/',
    decode: (ips) => {
      const codes = {
        '127.0.0.2': 'SBL (Spamhaus Block List)',
        '127.0.0.3': 'SBL CSS (Compromised Server)',
        '127.0.0.4': 'XBL (Exploits Block List)',
        '127.0.0.9': 'SBL Drop',
        '127.0.0.10': 'PBL ISP',
        '127.0.0.11': 'PBL Spamhaus',
      };
      return ips.map(ip => codes[ip] || 'listed').join(', ');
    },
  },
  {
    name:        'Barracuda BRBL',
    suffix:      'b.barracudacentral.org',
    description: 'Barracuda Reputation Block List — sending IPs',
    severity:    'MEDIUM',
    url:         'https://www.barracudacentral.org/rbl',
    decode: (ips) => ips.length > 0 ? 'reputation_blocked' : null,
  },
  {
    name:        'SORBS DNSBL',
    suffix:      'dnsbl.sorbs.net',
    description: 'SORBS — spam, abuse, open relay sources',
    severity:    'MEDIUM',
    url:         'http://www.sorbs.net/',
    decode: (ips) => ips.length > 0 ? 'sorbs_listed' : null,
  },
];

// ─── Reverse IP for DNSBL (1.2.3.4 → 4.3.2.1) ───────────────────────────────
function reverseIP(ip) {
  return ip.split('.').reverse().join('.');
}

// ─── Check single domain against all domain-based DBLs ────────────────────────
export async function checkDomainBlacklists(domain) {
  // Strip www. prefix for cleaner lookups
  const cleanDomain = domain.replace(/^www\./i, '');

  const results = await Promise.all(
    DOMAIN_DNSBL_FEEDS.map(async feed => {
      const query  = `${cleanDomain}.${feed.suffix}`;
      const result = await dnsblLookup(query);
      return {
        feed:        feed.name,
        description: feed.description,
        severity:    feed.severity,
        url:         feed.url,
        listed:      result.listed,
        detail:      result.listed ? (feed.decode(result.answers) || 'listed') : 'clean',
        query:       query,
        timeout:     !!result.error,
      };
    })
  );

  const listedFeeds  = results.filter(r => r.listed);
  const timeouts     = results.filter(r => r.timeout).length;
  const criticalHits = listedFeeds.filter(r => r.severity === 'CRITICAL');

  return {
    domain:            cleanDomain,
    total_feeds:       DOMAIN_DNSBL_FEEDS.length,
    listed_count:      listedFeeds.length,
    critical_hits:     criticalHits.length,
    timeout_count:     timeouts,
    threat_score:      calculateThreatScore(listedFeeds),
    blacklisted:       listedFeeds.length > 0,
    listed_on:         listedFeeds.map(r => ({ feed: r.feed, severity: r.severity, detail: r.detail })),
    all_results:       results,
    checked_at:        new Date().toISOString(),
  };
}

// ─── Check IPs against IP-based DBLs ─────────────────────────────────────────
export async function checkIPBlacklists(ipv4Addresses) {
  if (!ipv4Addresses?.length) return { total_ips: 0, results: [], blacklisted: false };

  // Check first 3 IPs to avoid exhausting request budget
  const ipsToCheck = ipv4Addresses.slice(0, 3);
  const allResults = [];

  for (const ip of ipsToCheck) {
    const reversed = reverseIP(ip);
    const ipResults = await Promise.all(
      IP_DNSBL_FEEDS.map(async feed => {
        const query  = `${reversed}.${feed.suffix}`;
        const result = await dnsblLookup(query);
        return {
          ip,
          feed:     feed.name,
          severity: feed.severity,
          listed:   result.listed,
          detail:   result.listed ? (feed.decode(result.answers) || 'listed') : 'clean',
          timeout:  !!result.error,
        };
      })
    );
    allResults.push(...ipResults);
  }

  const listed = allResults.filter(r => r.listed);
  return {
    total_ips:      ipsToCheck.length,
    feeds_per_ip:   IP_DNSBL_FEEDS.length,
    blacklisted:    listed.length > 0,
    listed_count:   listed.length,
    threat_score:   calculateThreatScore(listed),
    listed_on:      listed.map(r => ({ ip: r.ip, feed: r.feed, severity: r.severity, detail: r.detail })),
    results:        allResults,
  };
}

// ─── Composite threat score ───────────────────────────────────────────────────
function calculateThreatScore(listedResults) {
  if (!listedResults?.length) return 0;
  const weights = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
  const raw = listedResults.reduce((sum, r) => sum + (weights[r.severity] || 5), 0);
  return Math.min(100, raw);
}

// ─── Full combined check (domain + IPs) ──────────────────────────────────────
export async function fullBlacklistCheck(domain, ipv4Addresses = []) {
  const [domainCheck, ipCheck] = await Promise.all([
    checkDomainBlacklists(domain),
    checkIPBlacklists(ipv4Addresses),
  ]);

  const combinedScore = Math.min(100, domainCheck.threat_score + ipCheck.threat_score);

  return {
    domain:               domain,
    combined_threat_score: combinedScore,
    any_blacklisted:      domainCheck.blacklisted || ipCheck.blacklisted,
    domain_check:         domainCheck,
    ip_check:             ipCheck,
    risk_label:           combinedScore >= 60 ? 'CRITICAL' : combinedScore >= 30 ? 'HIGH' : combinedScore > 0 ? 'MEDIUM' : 'CLEAN',
    feeds_total:          DOMAIN_DNSBL_FEEDS.length + IP_DNSBL_FEEDS.length,
    summary: domainCheck.blacklisted || ipCheck.blacklisted
      ? `⚠️ Domain/IP found on ${domainCheck.listed_count} domain feed(s) and ${ipCheck.listed_count} IP feed(s). Immediate action required.`
      : `✅ Domain and IPs are clean across ${DOMAIN_DNSBL_FEEDS.length + IP_DNSBL_FEEDS.length} threat intelligence feeds.`,
  };
}
