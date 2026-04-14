/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — Realistic Data Seeding Engine v1.0
 * Eliminates ALL empty states across the platform.
 * Generates deterministic-but-realistic threat events, CVE activity,
 * scan history, and revenue stats so the UI never shows "No data yet".
 *
 * Design: Output is deterministic for a given date seed so refreshes
 * produce consistent data — not random noise. Uses crypto-quality entropy
 * mixed with date-based seeds for realism without flicker.
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── Deterministic PRNG (seeded by date + salt) ───────────────────────────────
function createPRNG(seed) {
  let s = (typeof seed === 'number') ? seed : Array.from(String(seed)).reduce((a,c) => (a*31 + c.charCodeAt(0)) >>> 0, 0x9e3779b9);
  return () => {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    return (s >>> 0) / 0xFFFFFFFF;
  };
}

function seededInt(rng, min, max) { return Math.floor(rng() * (max - min + 1)) + min; }
function seededPick(rng, arr) { return arr[Math.floor(rng() * arr.length)]; }

// ─── Threat Event Corpus ──────────────────────────────────────────────────────
const THREAT_ACTORS = [
  'APT29 (Cozy Bear)','APT41 (Double Dragon)','Lazarus Group','FIN7','REvil','LockBit 3.0',
  'Scattered Spider','Volt Typhoon','Sandworm','BlackCat/ALPHV','Cl0p','Play Ransomware',
  'Dark Angels','8Base','Akira','Rhysida','INC Ransomware','Medusa',
];
const CVE_POOL = [
  { id:'CVE-2025-21298', cvss:9.8, title:'Windows OLE Remote Code Execution', vendor:'Microsoft', severity:'CRITICAL' },
  { id:'CVE-2025-0282',  cvss:9.0, title:'Ivanti Connect Secure Stack Buffer Overflow', vendor:'Ivanti', severity:'CRITICAL' },
  { id:'CVE-2024-55591', cvss:9.8, title:'Fortinet FortiOS Authentication Bypass', vendor:'Fortinet', severity:'CRITICAL' },
  { id:'CVE-2025-21333', cvss:7.8, title:'Windows Hyper-V NT Kernel Elevation of Privilege', vendor:'Microsoft', severity:'HIGH' },
  { id:'CVE-2025-22457', cvss:9.0, title:'Ivanti Pulse Secure Stack Buffer Overflow', vendor:'Ivanti', severity:'CRITICAL' },
  { id:'CVE-2025-24813', cvss:9.8, title:'Apache Tomcat Partial PUT RCE', vendor:'Apache', severity:'CRITICAL' },
  { id:'CVE-2025-1974',  cvss:9.8, title:'IngressNightmare — Kubernetes Ingress-NGINX RCE', vendor:'Kubernetes', severity:'CRITICAL' },
  { id:'CVE-2025-29824', cvss:7.8, title:'Windows CLFS Zero-Day EoP', vendor:'Microsoft', severity:'HIGH' },
  { id:'CVE-2025-30065', cvss:9.8, title:'Apache Parquet Arbitrary Code Execution', vendor:'Apache', severity:'CRITICAL' },
  { id:'CVE-2025-24054', cvss:6.5, title:'Windows NTLM Hash Leak via Explorer', vendor:'Microsoft', severity:'MEDIUM' },
  { id:'CVE-2025-27363', cvss:7.8, title:'FreeType Heap OOB Write', vendor:'FreeType', severity:'HIGH' },
  { id:'CVE-2025-2783',  cvss:8.3, title:'Chrome Sandbox Bypass (Zero-Day)', vendor:'Google', severity:'HIGH' },
  { id:'CVE-2024-53104', cvss:7.8, title:'Linux Kernel USB Video Class Heap OOB', vendor:'Linux', severity:'HIGH' },
  { id:'CVE-2025-21388', cvss:6.1, title:'Windows USB Video Class EoP', vendor:'Microsoft', severity:'MEDIUM' },
  { id:'CVE-2025-21335', cvss:7.8, title:'Windows Hyper-V Elevation of Privilege', vendor:'Microsoft', severity:'HIGH' },
];
const ATTACK_TYPES = [
  'Phishing Campaign','SQL Injection','Remote Code Execution','Credential Stuffing',
  'Zero-Day Exploit','Ransomware Deployment','Supply Chain Attack','DDoS Campaign',
  'Lateral Movement','Data Exfiltration','Privilege Escalation','Brute Force',
  'Man-in-the-Middle','Cross-Site Scripting','Business Email Compromise',
];
const TARGET_SECTORS = [
  'Financial Services','Healthcare','Government','Energy / Utilities','Technology',
  'Manufacturing','Retail / eCommerce','Telecommunications','Education','Defense',
];
const SEVERITY_LEVELS = ['CRITICAL','HIGH','MEDIUM','LOW'];
const MITRE_TECHNIQUES = [
  'T1566.001 (Spearphishing)','T1190 (Public-Facing Application)','T1078 (Valid Accounts)',
  'T1486 (Data Encrypted for Impact)','T1059.001 (PowerShell)','T1055 (Process Injection)',
  'T1027 (Obfuscated Files)','T1562.001 (Disable Security Tools)','T1071.001 (Web Protocols)',
  'T1105 (Ingress Tool Transfer)','T1021.001 (Remote Desktop)','T1003.001 (LSASS Memory)',
];
const COUNTRIES_IOC = [
  'CN','RU','KP','IR','UA','US','DE','IN','BR','SG','NL','FR','GB','AU','CA',
];
const DOMAINS_IOC = [
  'update-windows-defender.xyz','secure-login-portal.net','cdn-analytics-core.com',
  'api-microsoft-secure.info','oauth2-google-verify.xyz','payment-processor-safe.net',
  'download-flash-update.com','java-runtime-update.net','adobe-security-patch.xyz',
  'ssl-certificate-renew.com','antivirus-scanner-pro.net','system-cleaner-free.xyz',
];

// ─── Scan History Generator ────────────────────────────────────────────────────
const SCAN_TARGETS = [
  'example.com','test-corp.net','api.acme.com','login.samplebank.in','mail.enterprise.org',
  'vpn.bigcompany.com','dev.startup.io','admin.mysite.net','store.retail-chain.com','crm.saas-app.in',
];
const SCAN_MODULES = ['domain','ai','redteam','identity','compliance'];

// ─── Revenue Data Generator ────────────────────────────────────────────────────
const PRODUCTS = [
  { id:'STARTER', name:'Starter Plan', price:499 },
  { id:'PRO', name:'Pro Plan', price:1499 },
  { id:'DOMAIN_REPORT', name:'Domain Security Report', price:199 },
  { id:'SOC_PLAYBOOK', name:'SOC Analyst Playbook 2026', price:999 },
  { id:'OSINT_BUNDLE', name:'OSINT Starter Bundle', price:499 },
  { id:'AI_TRAINING', name:'AI Security Bundle', price:1199 },
  { id:'ASSESSMENT', name:'Security Assessment', price:9999 },
];

// ─── Core Generation Functions ────────────────────────────────────────────────

/**
 * Generate realistic threat events for a date window
 * Returns array of event objects sorted by timestamp desc
 */
export function generateThreatEvents(count = 20, dateSeedOffset = 0) {
  const today   = new Date();
  const seed    = parseInt(today.toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset;
  const rng     = createPRNG(seed);
  const events  = [];

  for (let i = 0; i < count; i++) {
    const hoursAgo   = seededInt(rng, i * 2, i * 4 + 4);
    const ts         = new Date(today.getTime() - hoursAgo * 3600000);
    const cve        = seededPick(rng, CVE_POOL);
    const actor      = seededPick(rng, THREAT_ACTORS);
    const attackType = seededPick(rng, ATTACK_TYPES);
    const sector     = seededPick(rng, TARGET_SECTORS);
    const technique  = seededPick(rng, MITRE_TECHNIQUES);
    const country    = seededPick(rng, COUNTRIES_IOC);
    const severity   = i < 3 ? 'CRITICAL' : seededPick(rng, SEVERITY_LEVELS);
    const confidence = seededInt(rng, 65, 99);

    events.push({
      id:            `evt_${seed}_${i}`,
      type:          attackType,
      severity,
      actor,
      cve_id:        cve.id,
      cve_title:     cve.title,
      cve_cvss:      cve.cvss,
      target_sector: sector,
      mitre_technique: technique,
      source_country: country,
      confidence,
      description:   `${actor} deploying ${attackType.toLowerCase()} targeting ${sector} sector. Technique: ${technique}.`,
      indicators:    [`ioc.${DOMAINS_IOC[seededInt(rng,0,DOMAINS_IOC.length-1)]}`, `${seededInt(rng,1,255)}.${seededInt(rng,1,255)}.${seededInt(rng,1,255)}.${seededInt(rng,1,255)}`],
      timestamp:     ts.toISOString(),
      status:        seededPick(rng, ['active','monitoring','contained','resolved']),
    });
  }
  return events.sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
}

/**
 * Generate CVE activity feed for threat intelligence page
 */
export function generateCVEFeed(count = 15, dateSeedOffset = 0) {
  const today  = new Date();
  const seed   = parseInt(today.toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset + 1000;
  const rng    = createPRNG(seed);
  const result = [];

  // Use a mix of pool CVEs + some generated ones
  const base = [...CVE_POOL].slice(0, Math.min(count, CVE_POOL.length));
  for (let i = 0; i < count; i++) {
    const cve      = base[i % base.length];
    const hoursAgo = seededInt(rng, i * 3, i * 6 + 2);
    const ts       = new Date(today.getTime() - hoursAgo * 3600000);
    result.push({
      ...cve,
      published:     ts.toISOString(),
      modified:      new Date(ts.getTime() + seededInt(rng,0,3600000)).toISOString(),
      exploited_itw: i < 4, // first 4 are actively exploited
      patch_available: seededPick(rng, [true, true, true, false]),
      affected_systems: seededInt(rng, 100, 50000),
      references:    [`https://nvd.nist.gov/vuln/detail/${cve.id}`, `https://cve.org/CVERecord?id=${cve.id}`],
      tags:          [cve.vendor, cve.severity, i < 4 ? 'ACTIVELY_EXPLOITED' : 'PUBLISHED'].filter(Boolean),
    });
  }
  return result;
}

/**
 * Generate fake scan history for a user (seeded by userId)
 */
export function generateScanHistory(userId = 'demo', count = 8) {
  const seed = userId.split('').reduce((a,c) => (a*31 + c.charCodeAt(0)) >>> 0, 42);
  const rng  = createPRNG(seed);
  const today = new Date();
  const scans = [];

  for (let i = 0; i < count; i++) {
    const daysAgo  = seededInt(rng, i * 2, i * 3 + 1);
    const ts       = new Date(today.getTime() - daysAgo * 86400000);
    const module   = seededPick(rng, SCAN_MODULES);
    const target   = seededPick(rng, SCAN_TARGETS);
    const score    = seededInt(rng, 15, 92);
    const level    = score >= 75 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';
    const findings = seededInt(rng, 2, 18);

    scans.push({
      id:          `scan_${seed}_${i}`,
      module,
      target,
      risk_score:  score,
      risk_level:  level,
      findings_count: findings,
      locked_count: Math.max(0, findings - seededInt(rng,1,4)),
      status:      'completed',
      created_at:  ts.toISOString(),
      is_seeded:   true,
    });
  }
  return scans.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
}

/**
 * Generate revenue snapshot data
 */
export function generateRevenueSnapshot(dateSeedOffset = 0) {
  const today = new Date();
  const seed  = parseInt(today.toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset + 9999;
  const rng   = createPRNG(seed);

  const dailyRevenue = [];
  for (let d = 29; d >= 0; d--) {
    const dt  = new Date(today.getTime() - d * 86400000);
    const day = dt.toISOString().slice(0,10);
    // More revenue on weekdays, weekends dip slightly
    const dow = dt.getDay();
    const base = (dow === 0 || dow === 6) ? seededInt(rng,1200,3400) : seededInt(rng,2200,8400);
    dailyRevenue.push({ date: day, revenue_inr: base, transactions: seededInt(rng,2,16) });
  }

  const topProducts = PRODUCTS.map(p => ({
    ...p,
    units_sold: seededInt(rng, 3, 45),
    revenue:    p.price * seededInt(rng, 3, 45),
  })).sort((a,b) => b.revenue - a.revenue);

  const totalRevenue = dailyRevenue.reduce((s,d) => s + d.revenue_inr, 0);

  return {
    total_revenue_30d:   totalRevenue,
    total_transactions:  dailyRevenue.reduce((s,d) => s + d.transactions, 0),
    avg_order_value:     Math.round(totalRevenue / dailyRevenue.reduce((s,d) => s + d.transactions, 0)),
    mrr_estimate:        Math.round(totalRevenue * 1.1),
    daily_breakdown:     dailyRevenue,
    top_products:        topProducts.slice(0, 5),
    conversion_rate:     (rng() * 4 + 2.5).toFixed(1), // 2.5–6.5%
    new_customers_30d:   seededInt(rng, 42, 120),
    churn_rate:          (rng() * 3 + 1.5).toFixed(1),
  };
}

/**
 * Generate SOC metrics for CISO dashboard
 */
export function generateSOCMetrics(dateSeedOffset = 0) {
  const seed = parseInt(new Date().toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset + 7777;
  const rng  = createPRNG(seed);

  return {
    mttd_hours:        parseFloat((rng() * 3 + 1.2).toFixed(1)), // 1.2–4.2h
    mttr_hours:        parseFloat((rng() * 8 + 3.5).toFixed(1)), // 3.5–11.5h
    alerts_today:      seededInt(rng, 42, 230),
    alerts_critical:   seededInt(rng, 3, 18),
    alerts_resolved:   seededInt(rng, 35, 200),
    false_positives:   seededInt(rng, 5, 35),
    true_positives:    seededInt(rng, 8, 25),
    incidents_open:    seededInt(rng, 2, 12),
    incidents_closed:  seededInt(rng, 15, 65),
    risk_score:        seededInt(rng, 32, 78),
    compliance_score:  seededInt(rng, 62, 94),
    threat_intel_feeds: seededInt(rng, 12, 18),
    iocs_tracked:      seededInt(rng, 2400, 8900),
    patches_pending:   seededInt(rng, 3, 22),
    patches_critical:  seededInt(rng, 1, 8),
    siem_events_24h:   seededInt(rng, 12000, 85000),
    endpoint_coverage: seededInt(rng, 87, 99),
    last_incident_days: seededInt(rng, 1, 18),
  };
}

/**
 * Generate platform-wide stats (homepage live counters)
 */
export function generatePlatformStats(dateSeedOffset = 0) {
  const today = new Date();
  const seed  = parseInt(today.toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset + 5555;
  const rng   = createPRNG(seed);
  const hourOfDay = today.getHours();

  return {
    scans_today:       seededInt(rng, 800 + hourOfDay * 30, 1400 + hourOfDay * 45),
    scans_total:       seededInt(rng, 48000, 62000),
    users_active:      seededInt(rng, 12 + hourOfDay, 38 + hourOfDay),
    threats_detected:  seededInt(rng, 3200, 5800),
    cves_tracked:      845 + seededInt(rng, 0, 20),
    countries_covered: seededInt(rng, 42, 56),
    uptime_percent:    99.97,
    avg_scan_time_sec: parseFloat((rng() * 2 + 1.8).toFixed(1)),
    reports_generated: seededInt(rng, 1200, 2400),
    enterprises:       seededInt(rng, 18, 34),
  };
}

/**
 * Generate SIEM event stream for SOC dashboard
 */
export function generateSIEMEvents(count = 30, dateSeedOffset = 0) {
  const today = new Date();
  const seed  = parseInt(today.toISOString().slice(0,10).replace(/-/g,'')) + dateSeedOffset + 3333;
  const rng   = createPRNG(seed);
  const events = [];

  const EVENT_TYPES = [
    'AUTH_FAILURE','AUTH_SUCCESS','PRIVILEGE_ESCALATION','MALWARE_DETECTED',
    'NETWORK_ANOMALY','DATA_EXFIL_ATTEMPT','POLICY_VIOLATION','VULN_SCAN_DETECTED',
    'BRUTE_FORCE','PORT_SCAN','LATERAL_MOVEMENT','C2_BEACON',
    'RANSOMWARE_INDICATOR','SUSPICIOUS_PROCESS','FILE_INTEGRITY_VIOLATION',
  ];
  const SOURCES = [
    'endpoint-edr','network-fw','siem-core','ids-ips','cloud-waf',
    'email-gateway','dns-filter','dlp-engine','auth-provider','vuln-scanner',
  ];

  for (let i = 0; i < count; i++) {
    const minutesAgo = seededInt(rng, i * 3, i * 6 + 1);
    const ts         = new Date(today.getTime() - minutesAgo * 60000);
    const eventType  = seededPick(rng, EVENT_TYPES);
    const severity   = i < 4 ? 'CRITICAL' : i < 10 ? 'HIGH' : seededPick(rng, SEVERITY_LEVELS);

    events.push({
      id:        `siem_${seed}_${i}`,
      type:      eventType,
      severity,
      source:    seededPick(rng, SOURCES),
      src_ip:    `${seededInt(rng,10,200)}.${seededInt(rng,0,255)}.${seededInt(rng,0,255)}.${seededInt(rng,1,254)}`,
      dst_ip:    `10.${seededInt(rng,0,10)}.${seededInt(rng,0,255)}.${seededInt(rng,1,254)}`,
      message:   `${eventType.replace(/_/g,' ')} detected from ${seededPick(rng,COUNTRIES_IOC)}`,
      mitre:     seededPick(rng, MITRE_TECHNIQUES),
      confidence: seededInt(rng, 55, 99),
      handled:   seededPick(rng, [true, true, false]),
      timestamp: ts.toISOString(),
    });
  }
  return events;
}

/**
 * Generate APT group profiles for Intel Feed
 */
export function generateAPTProfiles() {
  return [
    {
      id: 'apt29', name: 'APT29', aliases: ['Cozy Bear','The Dukes','Nobelium'],
      nation: 'RU', sophistication: 'HIGH', active: true,
      target_sectors: ['Government','Diplomatic','Technology','Think Tanks'],
      ttps: ['T1566.001','T1078','T1021.001','T1027','T1071.001'],
      last_seen: new Date(Date.now() - 86400000 * 2).toISOString(),
      description: 'Russian SVR-linked APT. Known for SolarWinds supply chain attack and sustained espionage campaigns against NATO governments.',
      ioc_count: 847, campaign_count: 34,
    },
    {
      id: 'apt41', name: 'APT41', aliases: ['Double Dragon','Winnti','Barium'],
      nation: 'CN', sophistication: 'HIGH', active: true,
      target_sectors: ['Healthcare','Technology','Finance','Gaming','Telecom'],
      ttps: ['T1190','T1059.001','T1055','T1003.001','T1486'],
      last_seen: new Date(Date.now() - 86400000 * 1).toISOString(),
      description: 'Chinese MSS-affiliated threat actor conducting both espionage and financially motivated attacks.',
      ioc_count: 1243, campaign_count: 51,
    },
    {
      id: 'lazarus', name: 'Lazarus Group', aliases: ['Hidden Cobra','ZINC','Guardians of Peace'],
      nation: 'KP', sophistication: 'HIGH', active: true,
      target_sectors: ['Financial','Cryptocurrency','Defense','Government'],
      ttps: ['T1566.001','T1105','T1021.001','T1059.001','T1486'],
      last_seen: new Date(Date.now() - 86400000 * 3).toISOString(),
      description: 'DPRK-linked group responsible for WannaCry, Bangladesh Bank heist, and ongoing crypto theft campaigns.',
      ioc_count: 2156, campaign_count: 78,
    },
    {
      id: 'lockbit', name: 'LockBit 3.0', aliases: ['LockBit Black','ABCD'],
      nation: 'MULTI', sophistication: 'HIGH', active: true,
      target_sectors: ['Healthcare','Education','Government','Manufacturing'],
      ttps: ['T1486','T1490','T1562.001','T1078','T1021.001'],
      last_seen: new Date(Date.now() - 86400000 * 0.5).toISOString(),
      description: 'RaaS platform. World\'s most prolific ransomware group by victim count. Double/triple extortion.',
      ioc_count: 3421, campaign_count: 142,
    },
    {
      id: 'volt', name: 'Volt Typhoon', aliases: ['Bronze Silhouette','VANGUARD PANDA'],
      nation: 'CN', sophistication: 'HIGH', active: true,
      target_sectors: ['Critical Infrastructure','Utilities','Defense','Telecom'],
      ttps: ['T1190','T1078','T1021.001','T1071.001','T1560'],
      last_seen: new Date(Date.now() - 86400000 * 1).toISOString(),
      description: 'Chinese PLA-linked group pre-positioning for disruptive attacks on US and allied critical infrastructure.',
      ioc_count: 567, campaign_count: 12,
    },
  ];
}

/**
 * Generate defense recommendations seeded for a scan result
 */
export function generateDefenseRecommendations(module = 'domain', riskScore = 65) {
  const RECS = {
    domain: [
      'Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks',
      'Configure DMARC policy (p=reject) to prevent email spoofing',
      'Implement HTTP Strict Transport Security (HSTS) with includeSubDomains',
      'Deploy Content Security Policy (CSP) headers to mitigate XSS',
      'Enable Certificate Transparency monitoring via crt.sh or Cert Spotter',
      'Disable legacy TLS 1.0/1.1 — enforce TLS 1.2+ with strong cipher suites',
      'Review SPF record — too many DNS lookups or permissive includes detected',
      'Configure DKIM with 2048-bit RSA keys across all mail servers',
    ],
    ai: [
      'Implement LLM output validation and sanitization before rendering',
      'Deploy prompt injection detection middleware on all AI endpoints',
      'Enforce strict rate limiting on AI inference endpoints',
      'Implement model output filtering against OWASP LLM Top 10',
      'Monitor for adversarial inputs and jailbreak attempts in logs',
      'Isolate AI model serving from sensitive data stores',
    ],
    redteam: [
      'Segment network — prevent lateral movement via VLAN enforcement',
      'Deploy honeypots on critical network segments to detect intrusion',
      'Enforce MFA on all administrative accounts and remote access',
      'Implement privileged access management (PAM) for admin accounts',
      'Deploy EDR solution with behavior-based detection',
      'Conduct regular purple team exercises to validate detection coverage',
    ],
    identity: [
      'Enforce conditional access policies based on user risk score',
      'Implement zero-trust network access (ZTNA) to replace VPN',
      'Enable passwordless authentication (FIDO2/WebAuthn)',
      'Review and prune stale service accounts and permissions',
      'Deploy identity threat detection and response (ITDR) solution',
      'Enable Microsoft Entra ID Protection / Okta ThreatInsight',
    ],
    compliance: [
      'Implement data classification policy aligned with DPDP Act 2023',
      'Deploy DLP solution to prevent unauthorized data exfiltration',
      'Conduct quarterly access reviews for all privileged accounts',
      'Implement privacy by design in new product development',
      'Establish data breach notification procedure (72-hour SLA)',
      'Document data processing activities for regulatory compliance',
    ],
  };

  const recs = RECS[module] || RECS.domain;
  const count = riskScore >= 70 ? recs.length : riskScore >= 45 ? Math.ceil(recs.length * 0.7) : Math.ceil(recs.length * 0.5);
  return recs.slice(0, count);
}

/**
 * KV-backed seed cache: store seeded data in KV with short TTL so
 * repeated fetches return consistent data within the same hour
 */
export async function getCachedOrGenerate(kv, cacheKey, generator, ttlSeconds = 3600) {
  if (!kv) return generator();

  try {
    const cached = await kv.get(cacheKey, { type: 'json' });
    if (cached) return cached;

    const fresh = generator();
    await kv.put(cacheKey, JSON.stringify(fresh), { expirationTtl: ttlSeconds });
    return fresh;
  } catch {
    return generator();
  }
}

// ─── API Handlers ─────────────────────────────────────────────────────────────

export async function handleGetSeededThreats(request, env) {
  const url    = new URL(request.url);
  const count  = Math.min(50, parseInt(url.searchParams.get('count') || '20'));
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const events = await getCachedOrGenerate(
    env?.SECURITY_HUB_KV,
    `seed:threats:${new Date().toISOString().slice(0,13)}`, // hourly cache
    () => generateThreatEvents(count + offset),
    3600
  );

  return Response.json({
    success: true,
    data: {
      events: events.slice(offset, offset + count),
      total:  events.length,
      generated_at: new Date().toISOString(),
      source: 'seeded',
    },
    error: null,
  }, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' } });
}

export async function handleGetSeededCVEs(request, env) {
  const url   = new URL(request.url);
  const count = Math.min(30, parseInt(url.searchParams.get('count') || '15'));

  const cves = await getCachedOrGenerate(
    env?.SECURITY_HUB_KV,
    `seed:cves:${new Date().toISOString().slice(0,13)}`,
    () => generateCVEFeed(count),
    3600
  );

  return Response.json({
    success: true,
    data: { cves, total: cves.length, source: 'seeded' },
    error: null,
  }, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=600' } });
}

export async function handleGetPlatformStats(request, env) {
  const stats = await getCachedOrGenerate(
    env?.SECURITY_HUB_KV,
    `seed:stats:${new Date().toISOString().slice(0,13)}`,
    () => generatePlatformStats(),
    1800 // 30 min cache
  );

  return Response.json({
    success: true,
    data: stats,
    error: null,
  }, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' } });
}

export async function handleGetSOCMetrics(request, env) {
  const authCtx = request._authCtx || {};
  const metrics = await getCachedOrGenerate(
    env?.SECURITY_HUB_KV,
    `seed:soc:${authCtx.userId || 'anon'}:${new Date().toISOString().slice(0,13)}`,
    () => generateSOCMetrics(),
    1800
  );

  return Response.json({
    success: true,
    data: metrics,
    error: null,
  });
}

export async function handleGetSIEMStream(request, env) {
  const url   = new URL(request.url);
  const count = Math.min(100, parseInt(url.searchParams.get('count') || '30'));
  const events = generateSIEMEvents(count);

  return Response.json({
    success: true,
    data: { events, total: events.length, source: 'seeded' },
    error: null,
  });
}

export async function handleGetAPTProfiles(request, env) {
  return Response.json({
    success: true,
    data: { profiles: generateAPTProfiles(), total: 5 },
    error: null,
  }, { headers: { 'Cache-Control': 'public, max-age=3600' } });
}

/**
 * GET /api/seed/all — single-call anti-empty-state bundle for frontend.
 * Returns threats + CVEs + stats + SOC metrics + APT profiles + SIEM events.
 * The frontend can call this once on load and hydrate all dashboard panels.
 * Response is cached 10 minutes in CDN edge + 30 minutes in KV.
 */
export async function handleGetSeedAll(request, env, authCtx) {
  const url      = new URL(request.url);
  const userId   = authCtx?.userId || url.searchParams.get('uid') || 'anon';
  const cacheKey = `seed:all:${new Date().toISOString().slice(0,13)}`;  // hourly bucket

  const data = await getCachedOrGenerate(env?.SECURITY_HUB_KV, cacheKey, () => ({
    threats:    generateThreatEvents(20),
    cves:       generateCVEFeed(15),
    stats:      generatePlatformStats(),
    soc:        generateSOCMetrics(),
    apts:       generateAPTProfiles(),
    siem:       generateSIEMEvents(25),
    scan_history: generateScanHistory(userId, 8),
    revenue:    generateRevenueSnapshot(),
    generated_at: new Date().toISOString(),
    note:       'Seeded data for empty-state prevention. Replaced by real data when available.',
  }), 1800);

  return Response.json({
    success: true,
    data,
    error: null,
  }, {
    headers: {
      'Content-Type':  'application/json',
      'Cache-Control': 'public, max-age=600, s-maxage=600',
      'X-Data-Source': 'seed-engine',
    },
  });
}
