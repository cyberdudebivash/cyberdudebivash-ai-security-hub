/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Ingestion Engine v2.1
 * Autonomous pipeline: Fetch → Normalize → Deduplicate → Store in D1
 *
 * Sources:
 *   1. NIST NVD CVE API v2  — CRITICAL + HIGH CVEs (last 7 days)
 *   2. CISA KEV catalog     — actively exploited CVEs
 *   3. CERT-In advisories   — India-specific security bulletins
 *   4. GitHub Security RSS  — GitHub advisory feed (Atom XML)
 *   5. Built-in seed        — curated high-value entries for cold-start
 *
 * BINDING NOTE: D1 binding name is SECURITY_HUB_DB (not DB).
 * All env.DB references here use env.SECURITY_HUB_DB — do not change.
 */

import { enforceGovernanceBatch } from '../middleware/severityGovernanceGate.js';
import { extractIOCs, extractIOCsFromText }   from './iocExtractor.js';
import { enrichEntry, enrichBatch }           from './enrichment.js';
import { triggerIntelAlerts }                 from '../lib/alerts.js';
import { runAIThreatIngestion }               from './aiThreatIngestion.js';

const NVD_API_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_URL   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const GITHUB_RSS_URL = 'https://github.com/advisories.atom';
const EPSS_API_BASE  = 'https://api.first.org/data/v1/epss';
const FETCH_TIMEOUT  = 10000; // 10s per source

// ─── Built-in seed data — REAL current CVEs, never empty feed ─────────────────
// Real published CVEs as of June 2026. Refresh periodically.
// These cover 2024–2025 high-severity exploited vulnerabilities.
const SEED_ENTRIES = [
  // ── 2024 high-profile CVEs ────────────────────────────────────────────────
  {
    id: 'CVE-2024-3400', title: 'PAN-OS Command Injection (CRITICAL 0-day)', severity: 'CRITICAL',
    cvss: 10.0, description: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
    published_at: '2024-04-12', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","ZeroDay","NetworkDevice","PaloAlto"]',
    affected_products: '["cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-77"]',
  },
  {
    id: 'CVE-2024-21762', title: 'Fortinet FortiOS SSL VPN Out-of-Bounds Write', severity: 'CRITICAL',
    cvss: 9.6, description: 'An out-of-bounds write vulnerability in Fortinet FortiOS SSL VPN allows a remote unauthenticated attacker to execute arbitrary code or commands via HTTP requests.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
    published_at: '2024-02-08', exploit_status: 'confirmed', known_ransomware: 1,
    tags: '["RCE","VPN","Fortinet","ActiveExploitation"]',
    affected_products: '["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-787"]',
  },
  {
    id: 'CVE-2024-27198', title: 'JetBrains TeamCity Authentication Bypass', severity: 'CRITICAL',
    cvss: 9.8, description: 'An authentication bypass vulnerability in JetBrains TeamCity before 2023.11.4 allows an unauthenticated attacker to create admin accounts via the REST API.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-27198',
    published_at: '2024-03-04', exploit_status: 'confirmed', known_ransomware: 1,
    tags: '["AuthBypass","CI/CD","JetBrains","SupplyChain"]',
    affected_products: '["cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-288"]',
  },
  {
    id: 'CVE-2024-1709', title: 'ConnectWise ScreenConnect Authentication Bypass', severity: 'CRITICAL',
    cvss: 10.0, description: 'A path traversal vulnerability in ConnectWise ScreenConnect 23.9.7 and prior allows unauthenticated users to create admin accounts and gain access to confidential files.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1709',
    published_at: '2024-02-19', exploit_status: 'confirmed', known_ransomware: 1,
    tags: '["AuthBypass","PathTraversal","RMM","SupplyChain"]',
    affected_products: '["cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-22","CWE-288"]',
  },
  {
    id: 'CVE-2024-21893', title: 'Ivanti Pulse Secure SSRF (Server-Side Request Forgery)', severity: 'HIGH',
    cvss: 8.2, description: 'A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure and Ivanti Policy Secure allows an attacker to access certain restricted resources without authentication.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21893',
    published_at: '2024-02-02', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["SSRF","VPN","Ivanti","AuthBypass"]',
    affected_products: '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-918"]',
  },
  {
    id: 'CVE-2024-4577', title: 'PHP CGI Argument Injection (Windows)', severity: 'CRITICAL',
    cvss: 9.8, description: 'An argument injection vulnerability in PHP on Windows with CGI mode allows remote unauthenticated attackers to execute arbitrary code. Affects PHP 8.1, 8.2, 8.3 on Windows.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    published_at: '2024-06-06', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","PHP","CGI","Windows","WebServer"]',
    affected_products: '["cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-88"]',
  },
  {
    id: 'CVE-2024-38094', title: 'Microsoft SharePoint Remote Code Execution', severity: 'HIGH',
    cvss: 7.2, description: 'A deserialization vulnerability in Microsoft SharePoint Server allows an authenticated attacker with Site Owner permissions to execute arbitrary code remotely.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-38094',
    published_at: '2024-07-09', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","Microsoft","SharePoint","Deserialization"]',
    affected_products: '["cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-502"]',
  },
  {
    id: 'CVE-2024-21626', title: 'runc Container Escape (Leaky Vessels)', severity: 'HIGH',
    cvss: 8.6, description: 'A file descriptor leak in runc allows a malicious container to break out of the container namespace and gain full root access on the host system.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626',
    published_at: '2024-01-31', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["ContainerEscape","Docker","Kubernetes","runc","CloudSecurity"]',
    affected_products: '["cpe:2.3:a:opencontainers:runc:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-403"]',
  },
  {
    id: 'CVE-2024-6387', title: 'regreSSHion — OpenSSH Remote Code Execution', severity: 'CRITICAL',
    cvss: 8.1, description: 'A signal handler race condition in OpenSSH\'s server (sshd) on glibc-based Linux allows unauthenticated remote code execution as root. Affects OpenSSH < 4.4p1 and 8.5p1–9.8p1.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
    published_at: '2024-07-01', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","SSH","Linux","RaceCondition","RootAccess"]',
    affected_products: '["cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-362"]',
  },
  {
    id: 'CVE-2024-30078', title: 'Windows Wi-Fi Driver Remote Code Execution', severity: 'HIGH',
    cvss: 8.8, description: 'A remote code execution vulnerability in the Windows Wi-Fi Driver allows an unauthenticated attacker in Wi-Fi proximity to execute code on an affected system by sending specially crafted network packets.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-30078',
    published_at: '2024-06-11', exploit_status: 'unconfirmed', known_ransomware: 0,
    tags: '["RCE","Windows","WiFi","Network"]',
    affected_products: '["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-122"]',
  },
  {
    id: 'CVE-2024-23897', title: 'Jenkins Arbitrary File Read', severity: 'CRITICAL',
    cvss: 9.8, description: 'A path traversal vulnerability in Jenkins allows unauthenticated attackers to read arbitrary files on the Jenkins controller filesystem, potentially leading to RCE via credential extraction.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-23897',
    published_at: '2024-01-24', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["PathTraversal","CI/CD","Jenkins","CredentialLeak","SupplyChain"]',
    affected_products: '["cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-22"]',
  },
  // ── 2025 CVEs — active threat landscape ──────────────────────────────────
  {
    id: 'CVE-2025-0282', title: 'Ivanti Connect Secure Stack-Based Buffer Overflow (0-day)', severity: 'CRITICAL',
    cvss: 9.0, description: 'A stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.5, Policy Secure, and ZTA Gateways allows a remote unauthenticated attacker to achieve code execution. Actively exploited by China-nexus threat actors (UNC5221) since December 2024.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
    published_at: '2025-01-08', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","ZeroDay","VPN","Ivanti","APT","China","ActiveExploitation","BufferOverflow"]',
    affected_products: '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-121"]',
  },
  {
    id: 'CVE-2025-22457', title: 'Ivanti Connect Secure Stack Overflow RCE', severity: 'CRITICAL',
    cvss: 9.0, description: 'A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5 allows an unauthenticated remote attacker to achieve code execution. Actively exploited by UNC5221 (China-nexus).',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-22457',
    published_at: '2025-04-03', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","VPN","Ivanti","APT","BufferOverflow","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-121"]',
  },
  {
    id: 'CVE-2025-24085', title: 'Apple CoreMedia Use-After-Free (0-day)', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free issue in Apple CoreMedia was exploited in the wild against targeted individuals. Successfully exploiting this vulnerability may allow an attacker to elevate privileges.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-24085',
    published_at: '2025-01-27', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["PrivEsc","Apple","iOS","macOS","ZeroDay","ActiveExploitation"]',
    affected_products: '["cpe:2.3:o:apple:ios:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
  {
    id: 'CVE-2025-24200', title: 'Apple iOS USB Restricted Mode Authorization Bypass (0-day)', severity: 'HIGH',
    cvss: 7.1, description: 'An authorization issue in Apple iOS allows a physical attacker to disable USB Restricted Mode on a locked device, potentially exposing it to forensic extraction tools. Exploited in sophisticated targeted attacks against specific individuals. Fixed in iOS 18.3.2.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-24200',
    published_at: '2025-02-05', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["ZeroDay","Apple","iOS","AuthBypass","Physical","USBRestriction","TargetedAttack"]',
    affected_products: '["cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-285"]',
  },
  {
    id: 'CVE-2025-27363', title: 'FreeType Out-of-Bounds Write 0-day (Exploited in Wild)', severity: 'HIGH',
    cvss: 8.1, description: 'An out-of-bounds write in FreeType font rendering library when processing OTF/TrueType fonts with certain malformed table entries. Exploited in targeted attacks. Affects FreeType versions up to 2.13.0.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-27363',
    published_at: '2025-03-11', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","ZeroDay","FontRendering","FreeType","Linux","Android","TargetedAttack"]',
    affected_products: '["cpe:2.3:a:freetype:freetype:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-787"]',
  },
  {
    id: 'CVE-2025-26633', title: 'Microsoft Management Console Spoofing 0-day (TA569)', severity: 'HIGH',
    cvss: 7.0, description: 'A spoofing vulnerability in Microsoft Management Console (MMC) allows attackers to bypass the Mark-of-the-Web (MotW) security mechanism via crafted .msc files. Actively exploited by threat actor TA569 in phishing campaigns distributing malware.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-26633',
    published_at: '2025-03-11', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["ZeroDay","Windows","MMC","MotW","Phishing","TA569","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:microsoft:management_console:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-345"]',
  },
  {
    id: 'CVE-2025-29824', title: 'Windows CLFS Driver Privilege Escalation (0-day, RansomEXX)', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free vulnerability in the Windows Common Log File System Driver allows a local attacker to gain SYSTEM privileges. Exploited in the wild by ransomware operators (RansomEXX) as a post-compromise privilege escalation step.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29824',
    published_at: '2025-04-08', exploit_status: 'confirmed', known_ransomware: 1,
    tags: '["PrivEsc","Windows","ZeroDay","Ransomware","CLFS","RansomEXX"]',
    affected_products: '["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-416"]',
  },
  {
    id: 'CVE-2025-30406', title: 'Gladinet CentreStack Hardcoded Cryptographic Key RCE', severity: 'CRITICAL',
    cvss: 9.0, description: 'Gladinet CentreStack uses a hardcoded machineKey value for ASP.NET cryptographic operations, allowing unauthenticated attackers to forge ViewState data and achieve remote code execution via deserialization. Actively exploited since March 2025.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-30406',
    published_at: '2025-04-03', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","HardcodedKey","ViewState","Deserialization","FileSharing","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:gladinet:centrestack:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-321","CWE-502"]',
  },
  {
    id: 'CVE-2025-30065', title: 'Apache Parquet Java Deserialization Remote Code Execution', severity: 'CRITICAL',
    cvss: 10.0, description: 'A critical deserialization vulnerability in Apache Parquet Java (parquet-avro module) allows a remote attacker to execute arbitrary code when a system reads a specially crafted Parquet file from an untrusted source. Affects all versions up to 1.15.0.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-30065',
    published_at: '2025-04-01', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","Deserialization","Apache","BigData","DataPipeline","SupplyChain","CVSS10"]',
    affected_products: '["cpe:2.3:a:apache:parquet:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-502"]',
  },
  {
    id: 'CVE-2025-31200', title: 'Apple CoreAudio Heap Buffer Overflow 0-day (Targeted)', severity: 'HIGH',
    cvss: 7.5, description: 'A heap buffer overflow in Apple CoreAudio allows attackers to achieve code execution when processing a maliciously crafted audio stream. Actively exploited in sophisticated targeted attacks against specific high-value individuals. Fixed in iOS 18.4.1 and macOS Sequoia 15.4.1.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-31200',
    published_at: '2025-04-16', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","ZeroDay","Apple","iOS","macOS","TargetedAttack","CoreAudio","BufferOverflow"]',
    affected_products: '["cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*","cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-122"]',
  },
  {
    id: 'CVE-2025-32433', title: 'Erlang/OTP SSH Pre-Authentication Remote Code Execution', severity: 'CRITICAL',
    cvss: 10.0, description: 'A critical vulnerability in the Erlang/OTP SSH server implementation allows a remote unauthenticated attacker to execute arbitrary code on the target system. Any service using Erlang SSH (including RabbitMQ, CouchDB, and Ejabberd) is affected. Patch immediately — OTP 27.3.3, 26.2.5.11, 25.3.2.20 fix it.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32433',
    published_at: '2025-04-16', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","SSH","Erlang","PreAuth","CloudNative","RabbitMQ","CVSS10"]',
    affected_products: '["cpe:2.3:a:erlang:otp:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-306"]',
  },
  {
    id: 'CVE-2025-34028', title: 'Commvault Command Center Path Traversal RCE', severity: 'CRITICAL',
    cvss: 10.0, description: 'A path traversal vulnerability in Commvault Command Center allows unauthenticated remote attackers to upload and execute arbitrary files, achieving remote code execution. Affects Command Center versions 11.38.0 through 11.38.25. CISA added to KEV catalog.',
    source: 'cisa_kev', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-34028',
    published_at: '2025-05-01', exploit_status: 'confirmed', known_ransomware: 0,
    tags: '["RCE","PathTraversal","Backup","Enterprise","PreAuth","CVSS10","ActiveExploitation"]',
    affected_products: '["cpe:2.3:a:commvault:commvault:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-22"]',
  },
  {
    id: 'CVE-2025-20188', title: 'Cisco IOS XE Wireless Controller Pre-Auth RCE (CVSS 10)', severity: 'CRITICAL',
    cvss: 10.0, description: 'A vulnerability in the Out-of-Band Access Point (OOBAP) image download feature of Cisco IOS XE Software for Wireless LAN Controllers allows an unauthenticated remote attacker to upload arbitrary files and execute commands with root-level privileges on the underlying OS.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-20188',
    published_at: '2025-05-07', exploit_status: 'poc_available', known_ransomware: 0,
    tags: '["RCE","Cisco","Network","Wireless","PreAuth","CVSS10","IOS-XE"]',
    affected_products: '["cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"]',
    weakness_types: '["CWE-321"]',
  },
  {
    id: 'CVE-2025-21444', title: 'Windows Kernel Use-After-Free Privilege Escalation', severity: 'HIGH',
    cvss: 7.8, description: 'A use-after-free vulnerability in the Windows kernel allows a local attacker to escalate privileges to SYSTEM level, bypassing security boundaries. Part of January 2025 Patch Tuesday.',
    source: 'nvd', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-21444',
    published_at: '2025-01-14', exploit_status: 'unconfirmed', known_ransomware: 0,
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
export async function fetchNVDCVEs(daysBack = 7) {
  const now   = new Date();
  const start = new Date(now.getTime() - daysBack * 86400 * 1000);
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

    await new Promise(r => setTimeout(r, 1500));
  }

  return results;
}

// ─── Paginated NVD fetch (for bulk backfill) ──────────────────────────────────
export async function fetchNVDPage({ severity = 'CRITICAL', startIndex = 0, resultsPerPage = 500, daysBack = 120 } = {}) {
  const now   = new Date();
  const start = new Date(now.getTime() - daysBack * 86400 * 1000);
  const fmt   = (d) => d.toISOString().replace(/\.\d+Z$/, '.000 UTC+00:00');
  const params = new URLSearchParams({
    lastModStartDate: fmt(start),
    lastModEndDate:   fmt(now),
    cvssV3Severity:   severity,
    resultsPerPage:   String(Math.min(resultsPerPage, 2000)),
    startIndex:       String(startIndex),
  });
  const data = await safeFetch(`${NVD_API_BASE}?${params.toString()}`, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0 (security-research@cyberdudebivash.in)' },
  }, 25000);

  if (!data?.vulnerabilities) {
    return { entries: [], totalResults: 0, nextIndex: startIndex, done: true };
  }

  const entries = data.vulnerabilities.map(item => {
    const cve      = item.cve;
    const id       = cve.id;
    const desc     = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const metrics  = cve.metrics || {};
    const cvssData = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData;
    const cvssV2   = metrics.cvssMetricV2?.[0]?.cvssData;
    const cvss     = cvssData?.baseScore ?? cvssV2?.baseScore ?? null;
    const cpes     = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0, 5).map(c => c.criteria) || [];
    const cwes     = cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [];
    return {
      id,
      title:             desc.length > 80 ? desc.slice(0, 77) + '...' : (desc || id),
      severity:          normalizeSeverity(cvssData?.baseSeverity ?? severity),
      cvss,
      cvss_vector:       cvssData?.vectorString ?? null,
      description:       desc.length > 400 ? desc.slice(0, 397) + '...' : desc,
      source:            'nvd',
      source_url:        `https://nvd.nist.gov/vuln/detail/${id}`,
      published_at:      cve.published ? cve.published.split('T')[0] : null,
      exploit_status:    'unconfirmed',
      known_ransomware:  0,
      tags:              JSON.stringify(buildTags(desc, cpes, cwes)),
      affected_products: JSON.stringify(cpes),
      weakness_types:    JSON.stringify(cwes),
      iocs:              '[]',
      enriched:          0,
    };
  });

  const totalResults = data.totalResults || 0;
  const nextIndex    = startIndex + (data.resultsPerPage || entries.length);
  return { entries, totalResults, nextIndex, done: nextIndex >= totalResults || entries.length === 0 };
}

// ─── MODULE 2: Fetch CISA KEV ─────────────────────────────────────────────────
export async function fetchCISAKEV(maxEntries = 25) {
  const data = await safeFetch(CISA_KEV_URL, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/2.0' },
  }, 20000);
  if (!data?.vulnerabilities) return [];

  const recent = [...data.vulnerabilities]
    .sort((a, b) => new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0))
    .slice(0, maxEntries);

  return recent.map(v => {
    const desc = v.shortDescription || v.vulnerabilityName || '';
    const tags = buildTags(desc, [], v.cwes || []);
    if (!tags.includes('ActiveExploitation')) tags.push('ActiveExploitation');
    if (v.knownRansomwareCampaignUse === 'Known' && !tags.includes('Ransomware')) tags.push('Ransomware');

    return {
      id:               v.cveID,
      title:            v.vulnerabilityName || v.cveID,
      severity:         'HIGH',
      cvss:             null,
      cvss_vector:      null,
      description:      desc.length > 400 ? desc.slice(0, 397) + '...' : desc,
      source:           'cisa_kev',
      source_url:       `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      published_at:     v.dateAdded || null,
      exploit_status:   'confirmed',
      known_ransomware: v.knownRansomwareCampaignUse === 'Known' ? 1 : 0,
      tags:             JSON.stringify([...new Set(tags)]),
      affected_products: JSON.stringify([`${v.vendorProject}: ${v.product}`]),
      weakness_types:   JSON.stringify(v.cwes || []),
      iocs:             '[]',
      enriched:         0,
      actively_exploited: 1,
      exploit_available:  1,
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
  const entryBlocks = xml.match(/<entry>[\s\S]*?<\/entry>/g) || [];

  for (const block of entryBlocks.slice(0, 15)) {
    const id      = (block.match(/<id>([^<]+)<\/id>/) || [])[1] || '';
    const title   = (block.match(/<title[^>]*>([^<]+)<\/title>/) || [])[1] || '';
    const updated = (block.match(/<updated>([^<]+)<\/updated>/) || [])[1] || '';
    const summary = (block.match(/<summary[^>]*>([\s\S]*?)<\/summary>/) || [])[1] || '';
    const link    = (block.match(/<link[^>]*href="([^"]+)"/) || [])[1] || '';

    const cveMatch = (title + summary).match(/CVE-\d{4}-\d{4,}/);
    const cveId    = cveMatch ? cveMatch[0] : null;
    const entryId  = cveId || `GHSA-${id.split('/').pop()?.slice(-8) || Date.now()}`;

    const cleanSummary = summary.replace(/<[^>]+>/g, '').trim();
    const tags = buildTags(cleanSummary, [], []);
    if (!tags.includes('OpenSource')) tags.push('OpenSource');

    entries.push({
      id:               entryId,
      title:            title.slice(0, 150),
      severity:         'HIGH',
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
export async function fetchEPSSScores(cveIds = []) {
  if (!cveIds.length) return {};

  const epssMap = {};

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

      if (epss.epss_score >= 0.5 && entry.exploit_status !== 'confirmed') {
        entry.exploit_status = 'poc_available';
      }
      entry.exploit_available = epss.epss_score >= 0.3 || entry.exploit_status !== 'unconfirmed';
    } else {
      entry.epss_score        = null;
      entry.epss_percentile   = null;
      entry.exploit_available = entry.exploit_status !== 'unconfirmed';
    }

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
      const existing = seen.get(e.id);
      const sevRank  = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      if ((sevRank[e.severity] || 0) > (sevRank[existing.severity] || 0)) {
        seen.set(e.id, { ...existing, severity: e.severity, cvss: e.cvss ?? existing.cvss });
      }
      if (e.exploit_status === 'confirmed') {
        seen.get(e.id).exploit_status = 'confirmed';
      }
      try {
        const t1 = JSON.parse(existing.tags || '[]');
        const t2 = JSON.parse(e.tags || '[]');
        seen.get(e.id).tags = JSON.stringify([...new Set([...t1, ...t2])]);
      } catch {}
    }
  }
  return [...seen.values()];
}

// ─── Self-healing schema: ensure every column the upsert writes exists ────────
const THREAT_INTEL_COLUMNS = [
  ['title', 'TEXT'], ['severity', 'TEXT'], ['cvss', 'REAL'], ['cvss_vector', 'TEXT'],
  ['description', 'TEXT'], ['source', 'TEXT'], ['source_url', 'TEXT'], ['published_at', 'TEXT'],
  ['exploit_status', 'TEXT'], ['known_ransomware', 'INTEGER DEFAULT 0'],
  ['tags', "TEXT DEFAULT '[]'"], ['iocs', "TEXT DEFAULT '[]'"],
  ['affected_products', "TEXT DEFAULT '[]'"], ['weakness_types', "TEXT DEFAULT '[]'"],
  ['enriched', 'INTEGER DEFAULT 0'], ['epss_score', 'REAL'], ['epss_percentile', 'REAL'],
  ['actively_exploited', 'INTEGER DEFAULT 0'], ['exploit_available', 'INTEGER DEFAULT 0'],
  ['updated_at', 'TEXT'], ['created_at', 'TEXT'],
];
async function ensureThreatIntelColumns(db) {
  try {
    await db.prepare(
      `CREATE TABLE IF NOT EXISTS threat_intel (id TEXT PRIMARY KEY, title TEXT, severity TEXT)`
    ).run();
  } catch {}
  for (const [name, type] of THREAT_INTEL_COLUMNS) {
    try { await db.prepare(`ALTER TABLE threat_intel ADD COLUMN ${name} ${type}`).run(); } catch { /* already exists */ }
  }
}

// ─── Store entries in D1 (upsert) ────────────────────────────────────────────
export async function storeInD1(db, entries) {
  if (!db || !entries.length) return { inserted: 0, updated: 0, errors: [] };

  let inserted = 0, updated = 0;
  const errors = [];

  await ensureThreatIntelColumns(db);

  const BATCH = 25;
  for (let i = 0; i < entries.length; i += BATCH) {
    const batch = entries.slice(i, i + BATCH);
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
      errors.push(`Batch ${i / BATCH}: ${err.message}`);
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
          try {
            await db.prepare(`
              INSERT OR REPLACE INTO threat_intel
                (id, title, severity, cvss, description, source, published_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(
              e.id, (e.title || '').slice(0, 200), e.severity || 'MEDIUM',
              e.cvss ?? null, (e.description || '').slice(0, 500),
              e.source || 'nvd', e.published_at || null,
            ).run();
            inserted++;
          } catch (e3) {
            errors.push(`Entry ${e.id}: ${e2.message} | min: ${e3.message}`);
          }
        }
      }
    }
  }

  // ─── Canonical CVSS self-heal ──────────────────────────────────────────────
  // This ingestion path writes the score to `cvss`, but the canonical column —
  // the one 60+ readers query (critical/high counts, risk sorting, the frontend
  // feed) and the one indexed as idx_ti_cvss — is `cvss_score`. Left unset, every
  // CVSS-based business metric read NULL and silently returned 0. Backfill the
  // canonical column from `cvss` on every ingestion cycle so the whole platform's
  // CVSS truth self-heals (idempotent — only touches rows still out of sync).
  try {
    await db.prepare(
      `UPDATE threat_intel SET cvss_score = cvss
       WHERE cvss_score IS NULL AND cvss IS NOT NULL`
    ).run();
  } catch { /* non-fatal — never fail ingestion on the heal step */ }

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
// BINDING: uses env.SECURITY_HUB_DB (D1 binding name in wrangler.toml)
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

  // 3. Fetch NVD (may be rate-limited — graceful fallback)
  try {
    const nvd = await fetchNVDCVEs(7);
    if (nvd.length > 0) {
      allEntries.push(...nvd);
      sources.push(`nvd(${nvd.length})`);
    }
  } catch (e) {
    errors.push(`NVD: ${e.message}`);
  }

  // 4. GitHub advisories (best effort)
  try {
    const ghsa = await fetchGitHubAdvisories();
    if (ghsa.length > 0) {
      allEntries.push(...ghsa);
      sources.push(`github(${ghsa.length})`);
    }
  } catch (e) {
    errors.push(`GitHub: ${e.message}`);
  }

  // 5. Deduplicate all entries
  const deduped = deduplicateEntries(allEntries);

  // 6. Extract IOCs
  for (const entry of deduped) {
    try {
      const iocList = extractIOCsFromText(entry.description || '');
      if (iocList.length > 0) {
        entry.iocs = JSON.stringify(iocList);
      }
    } catch {}
  }

  // 7. Enrich entries
  for (const entry of deduped) {
    try {
      const enriched = enrichEntry(entry);
      Object.assign(entry, enriched);
    } catch {}
  }

  // 7b. Fetch EPSS scores
  try {
    const cveIds  = deduped.filter(e => /^CVE-\d{4}-\d{4,}$/.test(e.id)).map(e => e.id);
    const epssMap = await fetchEPSSScores(cveIds);
    applyEPSSScores(deduped, epssMap);
    sources.push(`epss(${Object.keys(epssMap).length})`);
  } catch (e) {
    errors.push(`EPSS: ${e.message}`);
    for (const entry of deduped) {
      entry.actively_exploited = entry.exploit_status === 'confirmed' || !!entry.known_ransomware;
      entry.exploit_available  = entry.exploit_status !== 'unconfirmed';
      entry.epss_score         = null;
    }
  }

  // 8. Store in D1 — uses SECURITY_HUB_DB binding (not DB)
  let stored = { inserted: 0, updated: 0, errors: [] };
  if (env?.SECURITY_HUB_DB) {
    stored = await storeInD1(env.SECURITY_HUB_DB, deduped);
    errors.push(...stored.errors);
  }

  // 8a. AI threat feed filter
  try {
    const aiResult = await runAIThreatIngestion(env, deduped);
    if (aiResult.matched > 0) sources.push(`ai_feed(${aiResult.inserted}/${aiResult.matched})`);
    errors.push(...aiResult.errors);
  } catch (e) {
    errors.push(`AI feed filter: ${e.message}`);
  }

  // 8b. Broadcast alerts for high-risk entries
  const alertCandidates = deduped.filter(e =>
    (parseFloat(e.cvss || 0) >= 9.0 || e.exploit_status === 'confirmed' || (e.epss_score || 0) >= 0.8)
  );
  if (alertCandidates.length > 0) {
    triggerIntelAlerts(env, alertCandidates).catch(() => {});
  }

  // 9. Log ingestion run — uses SECURITY_HUB_DB binding
  const runId = `run_${Date.now()}`;
  if (env?.SECURITY_HUB_DB) {
    try {
      await env.SECURITY_HUB_DB.prepare(`
        INSERT INTO ingestion_runs (id, sources, inserted, updated, errors, duration_ms, success)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        runId,
        JSON.stringify(sources),
        stored.inserted,
        stored.updated,
        JSON.stringify(errors),
        Date.now() - startTime,
        errors.length === 0 ? 1 : 0,
      ).run();
    } catch {}
  }

  // 10. Cache result summary in KV
  const summary = {
    ran_at:    new Date().toISOString(),
    sources,
    total:     deduped.length,
    inserted:  stored.inserted,
    errors:    errors.length,
    error_samples: errors.slice(0, 5),
    duration_ms: Date.now() - startTime,
  };
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put('sentinel:ingestion:last_run', JSON.stringify(summary), { expirationTtl: 86400 }).catch(() => {});
  }

  return { success: true, ...summary, entries: deduped };
}

// ─── Bounded incremental EPSS enrichment ─────────────────────────────────────
// BINDING: uses env.SECURITY_HUB_DB
export async function enrichUnscoredEPSS(env, limit = 120) {
  const db = env?.SECURITY_HUB_DB;
  if (!db) return { enriched: 0 };

  let rows = [];
  try {
    const res = await db.prepare(
      `SELECT id FROM threat_intel
       WHERE epss_score IS NULL AND id LIKE 'CVE-%'
       ORDER BY published_at DESC LIMIT ?`
    ).bind(limit).all();
    rows = res?.results || [];
  } catch { return { enriched: 0 }; }
  if (!rows.length) return { enriched: 0, scanned: 0 };

  const ids     = rows.map(r => r.id);
  const epssMap = await fetchEPSSScores(ids);
  let enriched  = 0;
  const scored  = Object.keys(epssMap);
  for (let i = 0; i < scored.length; i += 25) {
    const batch = scored.slice(i, i + 25);
    const stmts = batch.map(id => {
      const e = epssMap[id];
      return db.prepare(
        `UPDATE threat_intel
         SET epss_score = ?, epss_percentile = ?,
             exploit_available = MAX(COALESCE(exploit_available,0), ?),
             updated_at = datetime('now')
         WHERE id = ?`
      ).bind(e.epss_score, e.epss_percentile, e.epss_score >= 0.3 ? 1 : 0, id);
    });
    try { await db.batch(stmts); enriched += batch.length; } catch {}
  }
  return { enriched, scanned: ids.length };
}

// ─── BULK BACKFILL — grow the catalog from dozens to thousands ───────────────
// BINDING: uses env.SECURITY_HUB_DB
export async function runBulkBackfill(env, opts = {}) {
  const startTime = Date.now();
  const {
    kevLimit        = 5000,
    nvdBackfill     = false,
    nvdPerPage      = 500,
    nvdDaysBack     = 120,
    epssEnrichLimit = 120,
  } = opts;

  const db = env?.SECURITY_HUB_DB;
  if (!db) return { success: false, error: 'no_db' };

  const result = {
    success: true, kev_inserted: 0, nvd_inserted: 0,
    epss_enriched: 0, errors: [], sources: [],
  };

  // 1. Full CISA KEV
  try {
    const kev = await fetchCISAKEV(kevLimit);
    if (kev.length) {
      const r = await storeInD1(db, kev);
      result.kev_inserted = r.inserted;
      result.sources.push(`cisa_kev(${kev.length})`);
      if (r.errors?.length) result.errors.push(...r.errors.slice(0, 3));
    }
  } catch (e) { result.errors.push(`KEV: ${e.message}`); }

  // 2. NVD paginated backfill
  if (nvdBackfill) {
    for (const sev of ['CRITICAL', 'HIGH']) {
      const cursorKey = `nvd:backfill:cursor:${sev}`;
      let startIndex = 0;
      try {
        const raw = await env.SECURITY_HUB_KV?.get(cursorKey);
        startIndex = raw ? (parseInt(raw, 10) || 0) : 0;
      } catch {}
      try {
        const page = await fetchNVDPage({ severity: sev, startIndex, resultsPerPage: nvdPerPage, daysBack: nvdDaysBack });
        if (page.entries.length) {
          const r = await storeInD1(db, page.entries);
          result.nvd_inserted += r.inserted;
          result.sources.push(`nvd_${sev.toLowerCase()}(${page.entries.length}@${startIndex})`);
        }
        const nextCursor = page.done ? 0 : page.nextIndex;
        await env.SECURITY_HUB_KV?.put(cursorKey, String(nextCursor), { expirationTtl: 86400 * 30 }).catch(() => {});
      } catch (e) { result.errors.push(`NVD ${sev}: ${e.message}`); }
      await new Promise(r => setTimeout(r, 6500));
    }
  }

  // 3. Bounded incremental EPSS enrichment
  try {
    const e = await enrichUnscoredEPSS(env, epssEnrichLimit);
    result.epss_enriched = e.enriched || 0;
  } catch (e) { result.errors.push(`EPSS: ${e.message}`); }

  // 4. Current total
  try { result.total_now = (await db.prepare('SELECT COUNT(*) AS n FROM threat_intel').first())?.n || 0; }
  catch { result.total_now = null; }
  result.duration_ms = Date.now() - startTime;

  try {
    await db.prepare(
      `INSERT INTO ingestion_runs (id, sources, inserted, updated, errors, duration_ms, success)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      `bulk_${Date.now()}`, JSON.stringify(result.sources),
      result.kev_inserted + result.nvd_inserted, 0,
      JSON.stringify(result.errors), result.duration_ms,
      result.errors.length === 0 ? 1 : 0,
    ).run();
  } catch {}

  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put('sentinel:backfill:last_run',
      JSON.stringify({ ran_at: new Date().toISOString(), ...result }),
      { expirationTtl: 86400 }).catch(() => {});
  }

  return result;
}

// Export seed data for inline fallback in publicFeeds.js
export { SEED_ENTRIES };
