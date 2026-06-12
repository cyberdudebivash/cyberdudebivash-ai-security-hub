/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Ingestion Engine v2.0
 * Autonomous pipeline: Fetch → Normalize → Deduplicate → Store in D1
 *
 * Sources:
 *   1. NIST NVD CVE API v2  — CRITICAL + HIGH CVEs (last 7 days)
 *   2. CISA KEV catalog     — actively exploited CVEs
 *   3. CERT-In advisories   — India-specific security bulletins
 *   4. GitHub Security RSS  — GitHub advisory feed (Atom XML)
 *   5. Built-in seed        — curated high-value entries for cold-start
 */

import { extractIOCs, extractIOCsFromText }   from './iocExtractor.js';
import { enrichEntry, enrichBatch }           from './enrichment.js';
import { triggerIntelAlerts }                 from '../lib/alerts.js';

const NVD_API_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_URL   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const GITHUB_RSS_URL = 'https://github.com/advisories.atom';
const EPSS_API_BASE  = 'https://api.first.org/data/1.0/epss';
const FETCH_TIMEOUT  = 10000; // 10s per source

// ─── Built-in seed data — REAL current CVEs, never empty feed ─────────────────
// Verified high-impact 2025 CVEs. Live NVD/CISA cron replaces these with
// current 2026 CVEs automatically on each ingestion run.
const SEED_ENTRIES = [
  // ── CRITICAL — CVSS 10.0 ─────────────────────────────────────────────────────
  {
    id: 'CVE-2025-32433', title: 'Erlang/OTP SSH Unauthenticated RCE — CVSS 10.0 CRITICAL', severity: 'CRITICAL',
    cvss: 10.0, description: 'A critical unauthenticated remote code execution vulnerability in Erlang/OTP SSH server allows attackers to execute arbitrary OS commands by sending crafted SSH messages before authentication completes. Any Erlang-based system exposing SSH (including RabbitMQ, CouchDB) is affected.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32433',
    published_at: '2025-04-16', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","SSH","Erlang","Network","ZeroDay","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:erlang:otp:*:*:*:*:*:*:*:*","cpe:2.3:a:rabbitmq:rabbitmq:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-306"]',
  },
  {
    id: 'CVE-2025-30065', title: 'Apache Parquet Java Deserialization RCE — CVSS 10.0 CRITICAL', severity: 'CRITICAL',
    cvss: 10.0, description: 'A critical deserialization vulnerability in Apache Parquet Java (< 1.15.1) allows remote code execution when processing maliciously crafted Parquet files. Big data pipelines, ETL systems, and analytics platforms reading from untrusted sources are fully compromised.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-30065',
    published_at: '2025-04-01', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","Apache","Deserialization","BigData","DataPipeline","SupplyChain"]',
    affected_products: '["cpe:2.3:a:apache:parquet:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-502"]',
  },
  // ── CRITICAL — CVSS 9.8 ──────────────────────────────────────────────────────
  {
    id: 'CVE-2025-31161', title: 'CrushFTP Authentication Bypass — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A session fixation vulnerability in CrushFTP 10/11 allows unauthenticated remote attackers to hijack admin sessions and execute arbitrary commands. Actively exploited in the wild with public PoC. Thousands of internet-exposed CrushFTP instances are affected.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-31161',
    published_at: '2025-04-03', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["AuthBypass","FTP","RCE","ActiveExploitation","SessionFixation"]',
    affected_products: '["cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-384"]',
  },
  {
    id: 'CVE-2025-3248', title: 'Langflow AI Platform Unauthenticated RCE — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A critical code injection vulnerability in Langflow AI platform (< 1.3.0) allows unauthenticated remote code execution through the /api/v1/validate/code endpoint. Any publicly exposed Langflow instance is fully compromised without credentials.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-3248',
    published_at: '2025-04-07', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","AISecuity","LLM","CodeInjection","ZeroDay","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-94"]',
  },
  {
    id: 'CVE-2025-23006', title: 'SonicWall SMA100 Pre-Auth Deserialization RCE — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A pre-authentication deserialization vulnerability in SonicWall Secure Mobile Access (SMA) 100 series allows remote attackers to execute arbitrary OS commands with root privileges. Actively exploited as a zero-day before patch availability.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-23006',
    published_at: '2025-01-22', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","VPN","SonicWall","ZeroDay","ActiveExploitation","Deserialization"]',
    affected_products: '["cpe:2.3:o:sonicwall:sma100_firmware:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-502"]',
  },
  {
    id: 'CVE-2025-21298', title: 'Windows OLE Remote Code Execution — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A critical use-after-free vulnerability in Windows Object Linking and Embedding (OLE) allows remote code execution when a victim opens a specially crafted email in Outlook. No interaction beyond opening the email is required — zero-click attack vector in preview pane.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-21298',
    published_at: '2025-01-14', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","Windows","OLE","Microsoft","EmailAttack","ZeroClick"]',
    affected_products: '["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
  {
    id: 'CVE-2025-24813', title: 'Apache Tomcat Partial PUT Remote Code Execution — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A remote code execution vulnerability in Apache Tomcat (10.1.0–10.1.33, 11.0.0–11.0.1) when partial PUT is enabled allows unauthenticated attackers to upload malicious JSP content and execute it remotely.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-24813',
    published_at: '2025-03-10', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","Apache","Tomcat","WebServer","FileUpload","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-44"]',
  },
  {
    id: 'CVE-2025-1974', title: 'Ingress NGINX IngressNightmare RCE — CVSS 9.8 CRITICAL', severity: 'CRITICAL',
    cvss: 9.8, description: 'A critical unauthenticated RCE in Kubernetes Ingress NGINX Controller allows attackers to inject arbitrary NGINX configurations via the admission controller webhook, enabling code execution and access to all cluster secrets across all namespaces.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-1974',
    published_at: '2025-03-24', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","Kubernetes","NGINX","CloudSecurity","IngressNightmare","ClusterTakeover"]',
    affected_products: '["cpe:2.3:a:kubernetes:ingress-nginx:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-94"]',
  },
  // ── CRITICAL — CVSS 9.0–9.1 ──────────────────────────────────────────────────
  {
    id: 'CVE-2025-29927', title: 'Next.js Middleware Authorization Bypass — CVSS 9.1 CRITICAL', severity: 'CRITICAL',
    cvss: 9.1, description: 'A critical authorization bypass in Next.js (< 15.2.3) allows attackers to skip middleware authentication by sending a forged x-middleware-subrequest header. Authentication walls protecting routes and API endpoints are completely bypassed without credentials.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
    published_at: '2025-03-21', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["AuthBypass","NextJS","WebApp","Middleware","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-285"]',
  },
  {
    id: 'CVE-2025-0282', title: 'Ivanti Connect Secure Stack Buffer Overflow RCE — CVSS 9.0 CRITICAL', severity: 'CRITICAL',
    cvss: 9.0, description: 'A stack-based buffer overflow in Ivanti Connect Secure (< 22.7R2.5) allows unauthenticated remote code execution. Exploited as a zero-day by China-nexus threat actor UNC5337 before patch release. Mass exploitation campaigns observed globally.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
    published_at: '2025-01-08', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","VPN","Ivanti","APT","BufferOverflow","ZeroDay","ActiveExploitation","China"]',
    affected_products: '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-121"]',
  },
  {
    id: 'CVE-2025-22457', title: 'Ivanti Connect Secure Stack Overflow RCE (UNC5221) — CVSS 9.0 CRITICAL', severity: 'CRITICAL',
    cvss: 9.0, description: 'A stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.5 allows unauthenticated remote code execution. Actively exploited by UNC5221 (China-nexus APT) deploying TRAILBLAZE and BRUSHFIRE malware implants.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-22457',
    published_at: '2025-04-03', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","VPN","Ivanti","APT","BufferOverflow","ActiveExploitation","China","Malware"]',
    affected_products: '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-121"]',
  },
  {
    id: 'CVE-2025-34028', title: 'Commvault Command Center Path Traversal RCE — CVSS 9.0 CRITICAL', severity: 'CRITICAL',
    cvss: 9.0, description: 'A path traversal vulnerability in Commvault Command Center allows unauthenticated remote attackers to upload ZIP archives to arbitrary server locations. ZIP entries traverse outside the intended directory, enabling webshell deployment and full server compromise.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-34028',
    published_at: '2025-04-28', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","PathTraversal","Commvault","BackupSoftware","ActiveExploitation","ZipSlip"]',
    affected_products: '["cpe:2.3:a:commvault:command_center:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-22"]',
  },
  // ── HIGH — CVSS 7.8–8.2 ──────────────────────────────────────────────────────
  {
    id: 'CVE-2025-29824', title: 'Windows CLFS Driver Privilege Escalation 0-day (RansomEXX) — CVSS 7.8 HIGH', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free in the Windows Common Log File System Driver allows local privilege escalation to SYSTEM. Exploited in the wild by the RansomEXX ransomware group as part of post-exploitation chains. Patches released April 2025 Patch Tuesday.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29824',
    published_at: '2025-04-08', exploit_status: 'confirmed', known_ransomware: 1,
    tags: '["PrivEsc","Windows","ZeroDay","Ransomware","CLFS","UseAfterFree"]',
    affected_products: '["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
  {
    id: 'CVE-2025-24085', title: 'Apple CoreMedia Use-After-Free 0-day (Active Exploitation) — CVSS 7.8 HIGH', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free in Apple CoreMedia was exploited against specific targeted individuals before patching. Successful exploitation elevates privileges on iOS and macOS. Apple confirmed active in-the-wild exploitation in the patch advisory.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-24085',
    published_at: '2025-01-27', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["PrivEsc","Apple","iOS","macOS","ZeroDay","ActiveExploitation","UseAfterFree"]',
    affected_products: '["cpe:2.3:o:apple:ios:*:*:*:*:*:*:*:*","cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
  {
    id: 'CVE-2025-24989', title: 'Microsoft Power Pages Improper Access Control (0-day) — CVSS 8.2 HIGH', severity: 'HIGH',
    cvss: 8.2, description: 'An improper access control vulnerability in Microsoft Power Pages allows unauthenticated attackers to elevate privileges over a network, bypassing registration controls to gain unauthorized access. Microsoft confirmed exploitation before patch release.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-24989',
    published_at: '2025-02-19', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["PrivEsc","Microsoft","PowerPages","Cloud","ActiveExploitation","ZeroDay"]',
    affected_products: '["cpe:2.3:a:microsoft:power_pages:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-284"]',
  },
  {
    id: 'CVE-2025-21444', title: 'Windows Kernel Use-After-Free Privilege Escalation — CVSS 7.8 HIGH', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free vulnerability in the Windows kernel allows a local attacker to escalate privileges to SYSTEM level, bypassing security zone restrictions. Part of the January 2025 Patch Tuesday batch.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-21444',
    published_at: '2025-01-14', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["PrivEsc","Windows","Kernel","LocalExploit","UseAfterFree"]',
    affected_products: '["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
];

// ─── Safe fetch with timeout ──────────────────────────────────────────────────
async function safeFetch(url, options = {}, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('json')) return await res.json();
    return await res.text();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ─── Normalize severity ───────────────────────────────────────────────────────
function normalizeSeverity(raw) {
  const s = (raw || '').toUpperCase();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH')     return 'HIGH';
  if (s === 'MEDIUM')   return 'MEDIUM';
  if (s === 'LOW')      return 'LOW';
  return 'MEDIUM';
}

// ─── Build tags from text + metadata ─────────────────────────────────────────
function buildTags(desc = '', cpes = [], weaknesses = []) {
  const tags = [];
  const d = desc.toLowerCase();
  if (d.includes('remote code execution') || d.includes(' rce ')) tags.push('RCE');
  if (d.includes('sql injection') || d.includes('sqli'))          tags.push('SQLi');
  if (d.includes('cross-site scripting') || d.includes(' xss '))  tags.push('XSS');
  if (d.includes('privilege escalation') || d.includes('privesc'))tags.push('PrivEsc');
  if (d.includes('denial of service') || d.includes(' dos '))     tags.push('DoS');
  if (d.includes('authentication bypass') || d.includes('auth bypass')) tags.push('AuthBypass');
  if (d.includes('path traversal') || d.includes('directory traversal')) tags.push('PathTraversal');
  if (d.includes('buffer overflow'))                               tags.push('BufferOverflow');
  if (d.includes('zero-day') || d.includes('0-day'))              tags.push('ZeroDay');
  if (d.includes('server-side request forgery') || d.includes('ssrf')) tags.push('SSRF');
  if (d.includes('command injection') || d.includes('os command')) tags.push('CmdInjection');
  if (d.includes('deserialization') || d.includes('unsafe deseriali')) tags.push('Deserialization');
  if (d.includes('use-after-free') || d.includes('use after free')) tags.push('UseAfterFree');
  if (d.includes('race condition'))                                tags.push('RaceCondition');
  if (d.includes('supply chain'))                                  tags.push('SupplyChain');
  if (d.includes('ransomware'))                                    tags.push('Ransomware');
  if (d.includes('container') || d.includes('docker') || d.includes('kubernetes')) tags.push('CloudSecurity');
  if (d.includes('prompt injection') || d.includes('llm'))        tags.push('AISecuity');
  if (cpes.some(c => c.includes('apache') || c.includes('nginx') || c.includes('iis'))) tags.push('WebServer');
  if (cpes.some(c => c.includes('linux')))                        tags.push('Linux');
  if (cpes.some(c => c.includes('windows')))                      tags.push('Windows');
  if (cpes.some(c => c.includes('android') || c.includes('ios'))) tags.push('Mobile');
  if (weaknesses.some(w => w.includes('CWE-79')))                 tags.push('XSS');
  if (weaknesses.some(w => w.includes('CWE-89')))                 tags.push('SQLi');
  if (weaknesses.some(w => w.includes('CWE-78')))                 tags.push('CmdInjection');
  if (weaknesses.some(w => w.includes('CWE-502')))                tags.push('Deserialization');
  if (weaknesses.some(w => w.includes('CWE-416')))                tags.push('UseAfterFree');
  return [...new Set(tags)];
}

// ─── MODULE 1: Fetch NVD CVEs ─────────────────────────────────────────────────
export async function fetchNVDCVEs(daysBack = 14) {
  const now   = new Date();
  const start = new Date(now.getTime() - daysBack * 86400 * 1000);
  // NVD date format: 2024-01-01T00:00:00.000 UTC%2B00:00
  const fmt = (d) => d.toISOString().replace(/\.\d+Z$/, '.000 UTC+00:00');
  const pubStart = encodeURIComponent(fmt(start));
  const pubEnd   = encodeURIComponent(fmt(now));

  const results = [];

  for (const sev of ['CRITICAL', 'HIGH']) {
    const limit = sev === 'CRITICAL' ? 20 : 15;
    const url   = `${NVD_API_BASE}?pubStartDate=${pubStart}&pubEndDate=${pubEnd}&cvssV3Severity=${sev}&resultsPerPage=${limit}`;
    const data  = await safeFetch(url, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0 (security-research@cyberdudebivash.in)' },
    }, 12000);

    if (!data?.vulnerabilities) continue;

    for (const item of data.vulnerabilities) {
      const cve      = item.cve;
      const id       = cve.id;
      const desc     = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      const metrics  = cve.metrics || {};
      const cvssData = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData;
      const cvssV2   = metrics.cvssMetricV2?.[0]?.cvssData;
      const cvss     = cvssData?.baseScore ?? cvssV2?.baseScore ?? null;
      const vector   = cvssData?.vectorString ?? null;
      const severity = normalizeSeverity(cvssData?.baseSeverity ?? sev);
      const refs     = (cve.references || []).slice(0, 3).map(r => r.url);
      const cpes     = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0, 5).map(c => c.criteria) || [];
      const cwes     = cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [];
      const tags     = buildTags(desc, cpes, cwes);

      results.push({
        id,
        title:            desc.length > 80 ? desc.slice(0, 77) + '...' : desc,
        severity,
        cvss,
        cvss_vector:      vector,
        description:      desc.length > 400 ? desc.slice(0, 397) + '...' : desc,
        source:           'nvd',
        source_url:       `https://nvd.nist.gov/vuln/detail/${id}`,
        published_at:     cve.published ? cve.published.split('T')[0] : null,
        exploit_status:   'unconfirmed',
        known_ransomware: 0,
        tags:             JSON.stringify(tags),
        affected_products: JSON.stringify(cpes),
        weakness_types:   JSON.stringify(cwes),
        iocs:             '[]',
        enriched:         0,
        references:       refs,
      });
    }

    // NVD rate limit: max 5 req/30s without API key — wait 1s between calls
    await new Promise(r => setTimeout(r, 1500));
  }

  return results;
}

// ─── MODULE 2: Fetch CISA KEV ─────────────────────────────────────────────────
export async function fetchCISAKEV(maxEntries = 25) {
  const data = await safeFetch(CISA_KEV_URL, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0' },
  });
  if (!data?.vulnerabilities) return [];

  // Sort by dateAdded DESC, take most recent N
  const recent = [...data.vulnerabilities]
    .sort((a, b) => new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0))
    .slice(0, maxEntries);

  return recent.map(v => {
    const desc = v.shortDescription || v.vulnerabilityName || '';
    const tags = buildTags(desc, [], []);
    if (!tags.includes('ActiveExploitation')) tags.push('ActiveExploitation');

    return {
      id:               v.cveID,
      title:            v.vulnerabilityName || v.cveID,
      severity:         'HIGH', // KEV entries are at minimum HIGH by definition
      cvss:             null,   // will be enriched
      cvss_vector:      null,
      description:      desc.length > 400 ? desc.slice(0, 397) + '...' : desc,
      source:           'cisa_kev',
      source_url:       `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      published_at:     v.dateAdded || null,
      exploit_status:   'confirmed', // KEV = confirmed exploitation
      known_ransomware: v.knownRansomwareCampaignUse === 'Known' ? 1 : 0,
      tags:             JSON.stringify([...new Set(tags)]),
      affected_products: JSON.stringify([`${v.vendorProject}: ${v.product}`]),
      weakness_types:   '[]',
      iocs:             '[]',
      enriched:         0,
      required_action:  v.requiredAction || null,
      due_date:         v.dueDate || null,
    };
  });
}

// ─── MODULE 3: Parse GitHub Advisory Atom Feed ────────────────────────────────
export async function fetchGitHubAdvisories() {
  const xml = await safeFetch(GITHUB_RSS_URL, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0' },
  });
  if (!xml || typeof xml !== 'string') return [];

  const entries = [];
  // Simple XML parsing — extract <entry> blocks
  const entryBlocks = xml.match(/<entry>[\s\S]*?<\/entry>/g) || [];

  for (const block of entryBlocks.slice(0, 15)) {
    const id      = (block.match(/<id>([^<]+)<\/id>/) || [])[1] || '';
    const title   = (block.match(/<title[^>]*>([^<]+)<\/title>/) || [])[1] || '';
    const updated = (block.match(/<updated>([^<]+)<\/updated>/) || [])[1] || '';
    const summary = (block.match(/<summary[^>]*>([\s\S]*?)<\/summary>/) || [])[1] || '';
    const link    = (block.match(/<link[^>]*href="([^"]+)"/) || [])[1] || '';

    // Extract CVE ID from content if present
    const cveMatch = (title + summary).match(/CVE-\d{4}-\d{4,}/);
    const cveId    = cveMatch ? cveMatch[0] : null;
    const entryId  = cveId || `GHSA-${id.split('/').pop()?.slice(-8) || Date.now()}`;

    const cleanSummary = summary.replace(/<[^>]+>/g, '').trim();
    const tags = buildTags(cleanSummary, [], []);
    if (!tags.includes('OpenSource')) tags.push('OpenSource');

    entries.push({
      id:               entryId,
      title:            title.slice(0, 150),
      severity:         'HIGH', // will be enriched
      cvss:             null,
      cvss_vector:      null,
      description:      cleanSummary.slice(0, 400),
      source:           'github',
      source_url:       link || `https://github.com/advisories`,
      published_at:     updated ? updated.split('T')[0] : null,
      exploit_status:   'unconfirmed',
      known_ransomware: 0,
      tags:             JSON.stringify([...new Set(tags)]),
      affected_products: '[]',
      weakness_types:   '[]',
      iocs:             '[]',
      enriched:         0,
    });
  }

  return entries;
}

// ─── MODULE 4: Fetch EPSS Scores from FIRST.org ──────────────────────────────
// EPSS = Exploit Prediction Scoring System (0–1, higher = more likely exploited)
export async function fetchEPSSScores(cveIds = []) {
  if (!cveIds.length) return {};

  const epssMap = {};

  // Batch in groups of 30 to stay within URL length limits
  for (let i = 0; i < cveIds.length; i += 30) {
    const batch = cveIds.slice(i, i + 30);
    const url   = `${EPSS_API_BASE}?cve=${batch.join(',')}`;
    const data  = await safeFetch(url, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0' },
    }, 8000);

    if (data?.data && Array.isArray(data.data)) {
      for (const item of data.data) {
        epssMap[item.cve] = {
          epss_score:      parseFloat(item.epss) || 0,
          epss_percentile: parseFloat(item.percentile) || 0,
          epss_date:       item.date || null,
        };
      }
    }

    // Polite delay between EPSS batches
    if (i + 30 < cveIds.length) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  return epssMap;
}

// ─── Apply EPSS scores to entries ────────────────────────────────────────────
export function applyEPSSScores(entries, epssMap) {
  for (const entry of entries) {
    const epss = epssMap[entry.id];
    if (epss) {
      entry.epss_score      = epss.epss_score;
      entry.epss_percentile = epss.epss_percentile;
      entry.epss_date       = epss.epss_date;

      // If EPSS ≥ 0.5 and not already confirmed, mark as high-risk
      if (epss.epss_score >= 0.5 && entry.exploit_status !== 'confirmed') {
        entry.exploit_status = 'poc_available'; // Likely being tested/exploited
      }
      // Synthesize exploit_available flag
      entry.exploit_available = epss.epss_score >= 0.3 || entry.exploit_status !== 'unconfirmed';
    } else {
      entry.epss_score        = null;
      entry.epss_percentile   = null;
      entry.exploit_available = entry.exploit_status !== 'unconfirmed';
    }

    // actively_exploited flag: confirmed OR KEV-listed
    entry.actively_exploited = entry.exploit_status === 'confirmed' || !!entry.known_ransomware;
  }
  return entries;
}

// ─── Deduplicate entries by ID ────────────────────────────────────────────────
function deduplicateEntries(entries) {
  const seen = new Map();
  for (const e of entries) {
    if (!seen.has(e.id)) {
      seen.set(e.id, e);
    } else {
      // Merge: prefer higher severity and confirmed exploit status
      const existing = seen.get(e.id);
      const sevRank  = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      if ((sevRank[e.severity] || 0) > (sevRank[existing.severity] || 0)) {
        seen.set(e.id, { ...existing, severity: e.severity, cvss: e.cvss ?? existing.cvss });
      }
      if (e.exploit_status === 'confirmed') {
        seen.get(e.id).exploit_status = 'confirmed';
      }
      // Merge tags
      try {
        const t1 = JSON.parse(existing.tags || '[]');
        const t2 = JSON.parse(e.tags || '[]');
        seen.get(e.id).tags = JSON.stringify([...new Set([...t1, ...t2])]);
      } catch {}
    }
  }
  return [...seen.values()];
}

// ─── Store entries in D1 (upsert) ────────────────────────────────────────────
export async function storeInD1(db, entries) {
  if (!db || !entries.length) return { inserted: 0, updated: 0, errors: [] };

  let inserted = 0, updated = 0;
  const errors = [];

  // Process in batches of 10 to avoid D1 batch limits
  for (let i = 0; i < entries.length; i += 10) {
    const batch = entries.slice(i, i + 10);
    const stmts = batch.map(e => db.prepare(`
      INSERT INTO threat_intel
        (id, title, severity, cvss, cvss_vector, description, source, source_url,
         published_at, exploit_status, known_ransomware, tags, iocs,
         affected_products, weakness_types, enriched,
         epss_score, epss_percentile, actively_exploited, exploit_available,
         updated_at)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        severity          = CASE WHEN excluded.severity = 'CRITICAL' THEN 'CRITICAL' ELSE threat_intel.severity END,
        cvss              = COALESCE(excluded.cvss, threat_intel.cvss),
        exploit_status    = CASE WHEN excluded.exploit_status = 'confirmed' THEN 'confirmed' ELSE threat_intel.exploit_status END,
        known_ransomware  = MAX(excluded.known_ransomware, threat_intel.known_ransomware),
        epss_score        = COALESCE(excluded.epss_score, threat_intel.epss_score),
        epss_percentile   = COALESCE(excluded.epss_percentile, threat_intel.epss_percentile),
        actively_exploited= MAX(excluded.actively_exploited, threat_intel.actively_exploited),
        exploit_available = MAX(excluded.exploit_available, threat_intel.exploit_available),
        updated_at        = datetime('now')
    `).bind(
      e.id, e.title, e.severity, e.cvss ?? null, e.cvss_vector ?? null,
      e.description || '', e.source, e.source_url || null,
      e.published_at || null, e.exploit_status || 'unconfirmed',
      e.known_ransomware ?? 0,
      typeof e.tags === 'string' ? e.tags : JSON.stringify(e.tags || []),
      typeof e.iocs === 'string' ? e.iocs : JSON.stringify(e.iocs || []),
      typeof e.affected_products === 'string' ? e.affected_products : JSON.stringify(e.affected_products || []),
      typeof e.weakness_types === 'string' ? e.weakness_types : JSON.stringify(e.weakness_types || []),
      e.enriched ?? 0,
      e.epss_score ?? null,
      e.epss_percentile ?? null,
      e.actively_exploited ? 1 : 0,
      e.exploit_available  ? 1 : 0,
    ));

    try {
      await db.batch(stmts);
      inserted += batch.length;
    } catch (err) {
      errors.push(`Batch ${i / 10}: ${err.message}`);
      // Fallback: insert one at a time to identify bad entries
      for (const e of batch) {
        try {
          await db.prepare(`
            INSERT OR REPLACE INTO threat_intel
              (id, title, severity, cvss, description, source, source_url, published_at,
               exploit_status, known_ransomware, tags, iocs, affected_products, weakness_types)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            e.id, (e.title || '').slice(0, 200), e.severity, e.cvss ?? null,
            (e.description || '').slice(0, 500), e.source, e.source_url || null,
            e.published_at || null, e.exploit_status || 'unconfirmed',
            e.known_ransomware ?? 0,
            typeof e.tags === 'string' ? e.tags : JSON.stringify(e.tags || []),
            typeof e.iocs === 'string' ? e.iocs : JSON.stringify(e.iocs || []),
            typeof e.affected_products === 'string' ? e.affected_products : JSON.stringify(e.affected_products || []),
            typeof e.weakness_types === 'string' ? e.weakness_types : JSON.stringify(e.weakness_types || []),
          ).run();
          inserted++;
        } catch (e2) {
          errors.push(`Entry ${e.id}: ${e2.message}`);
        }
      }
    }
  }

  return { inserted, updated, errors };
}

// ─── Seed D1 with built-in entries (cold-start) ───────────────────────────────
export async function seedD1(db) {
  if (!db) return { seeded: 0 };
  try {
    const result = await storeInD1(db, SEED_ENTRIES);
    return { seeded: result.inserted };
  } catch (e) {
    return { seeded: 0, error: e.message };
  }
}

// ─── Main ingestion runner ────────────────────────────────────────────────────
export async function runIngestion(env) {
  const startTime = Date.now();
  const sources   = [];
  const errors    = [];
  let   allEntries = [];

  // 1. Always start with seed data in case live sources fail
  const seedEntries = SEED_ENTRIES.map(e => ({ ...e }));
  allEntries.push(...seedEntries);
  sources.push('seed');

  // 2. Fetch CISA KEV (most reliable, no rate limits)
  try {
    const kev = await fetchCISAKEV(30);
    if (kev.length > 0) {
      allEntries.push(...kev);
      sources.push(`cisa_kev(${kev.length})`);
    }
  } catch (e) {
    errors.push(`CISA KEV: ${e.message}`);
  }

  // 3. Fetch NVD — 14-day wind