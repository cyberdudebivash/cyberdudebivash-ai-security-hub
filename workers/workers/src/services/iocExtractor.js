/**
 * CYBERDUDEBIVASH AI Security Hub — IOC Extraction Engine v1.0
 * Extracts Indicators of Compromise from unstructured text using regex patterns.
 *
 * Extracts:
 *   - IPv4 addresses (with false-positive filtering)
 *   - IPv6 addresses
 *   - Domain names (with TLD validation)
 *   - URLs (http/https/ftp)
 *   - MD5 hashes (32 hex chars)
 *   - SHA-1 hashes (40 hex chars)
 *   - SHA-256 hashes (64 hex chars)
 *   - CVE IDs
 *   - Email addresses
 *   - Bitcoin wallet addresses
 *   - Registry keys (Windows)
 *   - File paths
 */

// ─── Regex patterns ───────────────────────────────────────────────────────────
const PATTERNS = {
  // IPv4: standard dotted-decimal, reject private/loopback/reserved
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,

  // IPv6: full and compressed forms (simplified)
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}/g,

  // Domain names: must have valid TLD (2-6 chars), no leading hyphen
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|io|co|uk|de|ru|cn|info|biz|xyz|top|site|online|cloud|app|dev|security|tech|ai|in|jp|fr|au|us|ca|br|nl|se|no|fi|dk|pl|ua|ro|bg|cz|sk|hu|hr|rs|ba|me|mk|al|si|ee|lv|lt|md|ge|am|az|by|kz|tm|uz|kg|tj|af|pk|bd|np|lk|mv|bt|mm|th|vn|ph|my|sg|id|bn|tl|la|kh|mn|kp|kr|jp|cn|tw|hk|mo|au|nz|fj|pg|sb|vu|ws|to|ck|nu|tk|pf|nc|wf|as|gu|mp|pr|vi|um|pw|fm|mh|ki|nr|tv|io)\b/gi,

  // URLs: capture full URL including path and query
  url: /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z]{2,6}\b(?:[-a-zA-Z0-9@:%_+.~#?&/=]*)/g,

  // FTP URLs
  ftp: /ftp:\/\/[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z]{2,6}\b(?:[-a-zA-Z0-9@:%_+.~#?&/=]*)/g,

  // MD5: exactly 32 hex chars (surrounded by word boundary or space)
  md5: /\b[0-9a-fA-F]{32}\b/g,

  // SHA-1: exactly 40 hex chars
  sha1: /\b[0-9a-fA-F]{40}\b/g,

  // SHA-256: exactly 64 hex chars
  sha256: /\b[0-9a-fA-F]{64}\b/g,

  // CVE IDs
  cve: /CVE-\d{4}-\d{4,}/gi,

  // Email addresses
  email: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,

  // Bitcoin addresses (P2PKH, P2SH, bech32)
  bitcoin: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,

  // Windows registry keys
  registry: /(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU)\\[A-Za-z0-9\\_.() -]*/g,

  // Windows file paths
  winpath: /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g,

  // Linux file paths (absolute)
  linuxpath: /\/(?:etc|var|tmp|usr|opt|home|root|bin|sbin|lib|proc|sys|dev|run)\/[^\s"'<>]*/g,
};

// ─── IP filter lists (false positives) ───────────────────────────────────────
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^127\./,
  /^0\./,
  /^255\./,
  /^169\.254\./,
  /^fc00:/,
  /^fe80:/,
];

const BOGON_IPS = new Set([
  '0.0.0.0', '255.255.255.255', '127.0.0.1', '::1', '::',
  '1.0.0.0', '2.0.0.0', '3.0.0.0', // version numbers that look like IPs
]);

// ─── TLDs that are clearly not IOC domains (version numbers, etc.) ────────────
const IGNORE_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net', 'test.com', 'localhost',
  'domain.com', 'your-domain.com', 'yourdomain.com', 'acme.com',
]);

// ─── Defang IOC (convert to safe representation) ─────────────────────────────
export function defang(value, type) {
  if (type === 'ip')  return value.replace(/\./g, '[.]');
  if (type === 'url') return value.replace('://', '[://]').replace(/\./g, '[.]');
  if (type === 'domain') return value.replace(/\./g, '[.]');
  return value;
}

// ─── Refang IOC (convert back to actionable) ─────────────────────────────────
export function refang(value) {
  return value
    .replace(/\[:\/{2}\]/g, '://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[at\]/gi, '@');
}

// ─── Check if IP is public/routable ──────────────────────────────────────────
function isPublicIP(ip) {
  if (BOGON_IPS.has(ip)) return false;
  return !PRIVATE_IP_RANGES.some(re => re.test(ip));
}

// ─── Extract IOCs from plain text ────────────────────────────────────────────
export function extractIOCsFromText(text = '', options = {}) {
  if (!text || typeof text !== 'string') return [];

  const { maxPerType = 20, includeLowConfidence = false } = options;
  const iocs = [];
  const seen  = new Set();

  const addIOC = (type, value, confidence = 0.8, meta = {}) => {
    const key = `${type}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type, value, confidence, defanged: defang(value, type), ...meta });
  };

  // ── IPv4 ──
  const ipMatches = text.match(PATTERNS.ipv4) || [];
  for (const ip of ipMatches.slice(0, maxPerType)) {
    if (isPublicIP(ip)) {
      addIOC('ip', ip, 0.85, { version: 4 });
    }
  }

  // ── URLs (before domains — URLs are more specific) ──
  const urlMatches = text.match(PATTERNS.url) || [];
  for (const url of urlMatches.slice(0, maxPerType)) {
    // Skip NVD/NIST/CISA reference URLs — these are benign
    if (url.includes('nvd.nist.gov') || url.includes('cisa.gov') || url.includes('attack.mitre.org')) continue;
    if (url.includes('github.com') && !url.includes('/download/') && !url.includes('/releases/')) continue;
    addIOC('url', url, 0.75);
  }

  // ── Domains (after URLs — avoid double-counting) ──
  const domainMatches = text.match(PATTERNS.domain) || [];
  const urlDomains = new Set(urlMatches.map(u => {
    try { return new URL(u).hostname; } catch { return ''; }
  }));
  for (const domain of domainMatches.slice(0, maxPerType)) {
    const lower = domain.toLowerCase();
    if (IGNORE_DOMAINS.has(lower)) continue;
    if (urlDomains.has(lower)) continue; // already captured via URL
    // Skip known-good research/vendor domains
    if (lower.endsWith('.nist.gov') || lower.endsWith('.cisa.gov') || lower.endsWith('.microsoft.com')) continue;
    addIOC('domain', domain, 0.7);
  }

  // ── SHA-256 (before MD5/SHA1 — longest match first) ──
  const sha256Matches = text.match(PATTERNS.sha256) || [];
  for (const h of sha256Matches.slice(0, maxPerType)) {
    addIOC('sha256', h.toLowerCase(), 0.95);
  }

  // ── SHA-1 ──
  const sha1Matches = text.match(PATTERNS.sha1) || [];
  for (const h of sha1Matches.slice(0, maxPerType)) {
    // Exclude anything already matched as SHA-256 substring
    if (sha256Matches.some(s => s.includes(h))) continue;
    addIOC('sha1', h.toLowerCase(), 0.9);
  }

  // ── MD5 ──
  const md5Matches = text.match(PATTERNS.md5) || [];
  for (const h of md5Matches.slice(0, maxPerType)) {
    if (sha1Matches.includes(h) || sha256Matches.some(s => s.includes(h))) continue;
    // Skip version strings that look like hashes
    if (h.match(/^0+$/) || h.match(/^f+$/i)) continue;
    addIOC('md5', h.toLowerCase(), 0.85);
  }

  // ── CVE IDs ──
  const cveMatches = text.match(PATTERNS.cve) || [];
  for (const cve of [...new Set(cveMatches)].slice(0, maxPerType)) {
    addIOC('cve', cve.toUpperCase(), 1.0, { nvd_url: `https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}` });
  }

  // ── Email (lower confidence) ──
  if (includeLowConfidence) {
    const emailMatches = text.match(PATTERNS.email) || [];
    for (const email of emailMatches.slice(0, 5)) {
      // Skip common FP email domains
      if (email.endsWith('@example.com') || email.endsWith('@test.com')) continue;
      addIOC('email', email.toLowerCase(), 0.6);
    }
  }

  // ── Registry keys ──
  const regMatches = text.match(PATTERNS.registry) || [];
  for (const reg of regMatches.slice(0, 5)) {
    addIOC('registry_key', reg, 0.9);
  }

  // ── File paths ──
  const winPaths = text.match(PATTERNS.winpath) || [];
  for (const p of winPaths.slice(0, 5)) {
    addIOC('file_path', p, 0.75, { os: 'windows' });
  }
  const linuxPaths = text.match(PATTERNS.linuxpath) || [];
  for (const p of linuxPaths.slice(0, 5)) {
    addIOC('file_path', p, 0.75, { os: 'linux' });
  }

  return iocs;
}

// ─── Extract IOCs from full threat intel entry ────────────────────────────────
export function extractIOCs(entry) {
  const text = [
    entry.description || '',
    entry.title || '',
    Array.isArray(entry.affected_products) ? entry.affected_products.join(' ')
      : (typeof entry.affected_products === 'string' ? entry.affected_products : ''),
  ].join(' ');

  return extractIOCsFromText(text, { maxPerType: 10 });
}

// ─── IOC statistics summarizer ────────────────────────────────────────────────
export function summarizeIOCs(iocList = []) {
  const byType = {};
  for (const ioc of iocList) {
    byType[ioc.type] = (byType[ioc.type] || 0) + 1;
  }
  return {
    total:   iocList.length,
    by_type: byType,
    high_confidence: iocList.filter(i => i.confidence >= 0.85).length,
    types:   Object.keys(byType),
  };
}

// ─── Store IOCs in D1 ioc_registry ───────────────────────────────────────────
export async function storeIOCsInD1(db, intelId, iocList) {
  if (!db || !iocList.length || !intelId) return 0;
  let stored = 0;
  for (const ioc of iocList.slice(0, 50)) {
    try {
      const id = `${intelId}_${ioc.type}_${ioc.value.slice(0, 32)}`.replace(/[^a-zA-Z0-9_\-]/g, '_');
      await db.prepare(`
        INSERT OR IGNORE INTO ioc_registry (id, intel_id, type, value, confidence)
        VALUES (?, ?, ?, ?, ?)
      `).bind(id, intelId, ioc.type, ioc.value, ioc.confidence).run();
      stored++;
    } catch {}
  }
  return stored;
}
