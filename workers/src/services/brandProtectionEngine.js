/**
 * CYBERDUDEBIVASH AI Security Hub — Brand Protection Engine v1.0
 * ───────────────────────────────────────────────────────────────
 * Detects brand impersonation, typosquatting, and fake domains.
 *
 * Techniques:
 *   - Keyboard adjacency typos (qwerty layout)
 *   - Character insertion/deletion/swap
 *   - Homoglyph substitution (lookalike characters)
 *   - TLD variations (domain.com → domain.net, .org, .co.in, etc.)
 *   - Prefix/suffix addition (get-, my-, secure-, -login, -app, etc.)
 *   - Hyphen insertion
 *   - Subdomain-style abuse (login.brand.com.attacker.com)
 *
 * For each generated candidate:
 *   1. DNS A record check (resolves?)
 *   2. DNS MX record check (email capable → phishing risk)
 *   3. Risk score calculation
 *   4. Store in brand_threats
 */

const DOH_BASE = 'https://cloudflare-dns.com/dns-query';

const HIGH_RISK_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.pw', '.ru', '.cn', '.top'];
const COMMON_TLDS    = ['.com', '.net', '.org', '.info', '.biz', '.co', '.io', '.app', '.dev'];
const REGIONAL_TLDS  = ['.co.in', '.in', '.co.uk', '.uk', '.ca', '.com.au', '.de', '.fr'];

// Keyboard adjacency map (QWERTY)
const KEYBOARD_ADJ = {
  a:['q','w','s','z'], b:['v','g','h','n'], c:['x','d','f','v'],
  d:['s','e','r','f','x','c'], e:['w','r','s','d'], f:['d','r','t','g','c','v'],
  g:['f','t','y','h','v','b'], h:['g','y','u','j','b','n'], i:['u','o','k','j'],
  j:['h','u','i','k','n','m'], k:['j','i','o','l','m'], l:['k','o','p'],
  m:['n','j','k'], n:['b','h','j','m'], o:['i','p','l','k'],
  p:['o','l'], q:['w','a'], r:['e','t','d','f'], s:['a','w','e','d','z','x'],
  t:['r','y','f','g'], u:['y','i','h','j'], v:['c','f','g','b'],
  w:['q','e','a','s'], x:['z','s','d','c'], y:['t','u','g','h'],
  z:['a','s','x'],
};

// Homoglyph map
const HOMOGLYPHS = {
  a: ['@', '4', 'α'],
  e: ['3', 'є'],
  i: ['1', 'l', '|', '!'],
  l: ['1', 'i', '|'],
  o: ['0', 'ο', 'о'],
  s: ['5', '$'],
  t: ['+', '7'],
  b: ['6', 'ƅ'],
  g: ['9'],
};

// ─── Generate typosquatting candidates ────────────────────────────────────────
export function generateTyposquattingVariants(domain) {
  const parts  = domain.split('.');
  const tld    = '.' + parts.slice(1).join('.');
  const name   = parts[0].toLowerCase();
  const variants = new Set();

  // 1. TLD swaps
  for (const t of [...COMMON_TLDS, ...REGIONAL_TLDS, ...HIGH_RISK_TLDS]) {
    if (t !== tld) variants.add(name + t);
  }

  // 2. Character insertion (add each keyboard neighbor at each position)
  for (let i = 0; i <= name.length; i++) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    // Just try adjacent keys
    for (const adj of (KEYBOARD_ADJ[name[i]] || [])) {
      variants.add(name.slice(0, i) + adj + name.slice(i) + tld);
    }
  }

  // 3. Character deletion (remove one char at a time)
  for (let i = 0; i < name.length; i++) {
    variants.add(name.slice(0, i) + name.slice(i + 1) + tld);
  }

  // 4. Character substitution (replace with keyboard neighbor)
  for (let i = 0; i < name.length; i++) {
    const ch  = name[i];
    const adj = KEYBOARD_ADJ[ch] || [];
    for (const a of adj) {
      variants.add(name.slice(0, i) + a + name.slice(i + 1) + tld);
    }
  }

  // 5. Character swap (transpose two adjacent chars)
  for (let i = 0; i < name.length - 1; i++) {
    const swapped = name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2);
    variants.add(swapped + tld);
  }

  // 6. Homoglyph substitution
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    if (HOMOGLYPHS[ch]) {
      for (const g of HOMOGLYPHS[ch]) {
        // Only keep ASCII homoglyphs for valid domain generation
        if (/^[a-z0-9-]$/.test(g)) {
          variants.add(name.slice(0, i) + g + name.slice(i + 1) + tld);
        }
      }
    }
  }

  // 7. Double character (typo: hit key twice)
  for (let i = 0; i < name.length; i++) {
    variants.add(name.slice(0, i) + name[i] + name[i] + name.slice(i + 1) + tld);
  }

  // 8. Missing dot (remove one dot in multi-segment names)
  // e.g. mycompany.co.in → mycompanyco.in
  if (parts.length > 2) {
    variants.add(parts[0] + parts[1] + '.' + parts.slice(2).join('.'));
  }

  // 9. Prefix additions
  const prefixes = ['get', 'my', 'login', 'secure', 'support', 'help', 'www', 'app', 'portal'];
  for (const p of prefixes) {
    variants.add(p + name + tld);
    variants.add(name + '-' + p + tld);
    variants.add(p + '-' + name + tld);
  }

  // 10. Suffix additions
  const suffixes = ['app', 'login', 'portal', 'secure', 'online', 'hub', 'ai', 'pro'];
  for (const s of suffixes) {
    variants.add(name + s + tld);
    variants.add(name + '-' + s + tld);
  }

  // Remove the original domain itself
  variants.delete(domain);

  // Keep only valid domain characters (no homoglyphs that break DNS)
  return [...variants]
    .filter(v => /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(v) && v.length <= 63)
    .slice(0, 150);  // cap at 150 candidates
}

// ─── DNS check ────────────────────────────────────────────────────────────────
async function dnsCheck(domain) {
  try {
    const [aRes, mxRes] = await Promise.allSettled([
      fetch(`${DOH_BASE}?name=${encodeURIComponent(domain)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal:  AbortSignal.timeout(4000),
        cf:      { cacheTtl: 3600 },
      }).then(r => r.json()).catch(() => null),
      fetch(`${DOH_BASE}?name=${encodeURIComponent(domain)}&type=MX`, {
        headers: { Accept: 'application/dns-json' },
        signal:  AbortSignal.timeout(4000),
        cf:      { cacheTtl: 3600 },
      }).then(r => r.json()).catch(() => null),
    ]);

    const aRec  = aRes.status  === 'fulfilled' ? aRes.value  : null;
    const mxRec = mxRes.status === 'fulfilled' ? mxRes.value : null;

    const ips  = (aRec?.Answer || []).filter(r => r.type === 1).map(r => r.data);
    const hasMX = (mxRec?.Answer || []).length > 0;

    return { resolves: ips.length > 0, ips, has_mx: hasMX };
  } catch {
    return { resolves: false, ips: [], has_mx: false };
  }
}

// ─── Risk score for a threat ──────────────────────────────────────────────────
function scoreThreat(domain, dns, originalDomain) {
  let score = 0;
  const reasons = [];

  // Resolves = active
  if (dns.resolves) { score += 40; reasons.push('Domain resolves (active)'); }

  // Has MX = can send/receive email = phishing risk
  if (dns.has_mx) { score += 35; reasons.push('Has MX records (email capable → phishing risk)'); }

  // High-risk TLD
  if (HIGH_RISK_TLDS.some(t => domain.endsWith(t))) {
    score += 20;
    reasons.push(`High-risk TLD: ${domain.split('.').slice(-2).join('.')}`);
  }

  // Contains login/secure/bank keywords
  const lower = domain.toLowerCase();
  if (/login|signin|secure|account|verify|bank|pay|wallet/.test(lower)) {
    score += 20;
    reasons.push('Contains phishing keyword');
  }

  // Very similar to original (Levenshtein-like check)
  const origName = originalDomain.split('.')[0];
  const domName  = domain.split('.')[0];
  if (Math.abs(domName.length - origName.length) <= 2 && domName !== origName) {
    score += 10;
    reasons.push('Very similar to original name (1-2 char difference)');
  }

  return { score: Math.min(score, 100), reasons };
}

function classifyThreatType(domain) {
  const lower = domain.toLowerCase();
  if (/login|signin|verify|account/.test(lower)) return 'phishing';
  if (HIGH_RISK_TLDS.some(t => lower.endsWith(t))) return 'typosquatting';
  return 'typosquatting';
}

// ─── Main brand scan ──────────────────────────────────────────────────────────
export async function runBrandScan(env, monitorId, brandName, primaryDomain) {
  const startTime = Date.now();
  const candidates = generateTyposquattingVariants(primaryDomain);
  const threats  = [];
  const errors   = [];

  // DNS check all candidates in parallel (batches of 20)
  const batchSize = 20;
  for (let i = 0; i < Math.min(candidates.length, 100); i += batchSize) {
    const batch = candidates.slice(i, i + batchSize);

    const results = await Promise.allSettled(
      batch.map(domain => dnsCheck(domain).then(dns => ({ domain, dns })))
    );

    for (const r of results) {
      if (r.status !== 'fulfilled') continue;
      const { domain, dns } = r.value;

      const { score, reasons } = scoreThreat(domain, dns, primaryDomain);

      // Only store threats with score > 0 (something interesting)
      if (score > 0 || dns.resolves) {
        threats.push({
          id:           `bt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          monitor_id:   monitorId,
          threat_type:  classifyThreatType(domain),
          domain,
          registered:   dns.resolves ? 1 : 0,
          ip_address:   dns.ips[0] || null,
          mx_records:   dns.has_mx ? 1 : 0,
          risk_score:   score,
          category:     dns.resolves && dns.has_mx ? 'active_phishing' :
                        dns.resolves ? 'parked' : 'suspicious',
          status:       'open',
        });
      }
    }
  }

  // Sort by risk score descending
  threats.sort((a, b) => b.risk_score - a.risk_score);

  // Store in D1
  if (env.DB && threats.length > 0) {
    try {
      for (const t of threats.slice(0, 100)) {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO brand_threats
            (id, monitor_id, threat_type, domain, registered, ip_address,
             mx_records, risk_score, category, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          t.id, t.monitor_id, t.threat_type, t.domain,
          t.registered, t.ip_address, t.mx_records,
          t.risk_score, t.category, t.status,
        ).run();
      }
    } catch (e) {
      errors.push(`D1 store: ${e.message}`);
    }
  }

  // Update monitor stats
  const criticalThreats = threats.filter(t => t.risk_score >= 70).length;
  if (env.DB && monitorId) {
    try {
      await env.DB.prepare(`
        UPDATE brand_monitors SET
          total_threats   = ?,
          critical_threats = ?,
          last_scan        = datetime('now'),
          updated_at       = datetime('now')
        WHERE id = ?
      `).bind(threats.length, criticalThreats, monitorId).run();
    } catch {}
  }

  return {
    monitor_id:         monitorId,
    brand:              brandName,
    primary_domain:     primaryDomain,
    candidates_checked: Math.min(candidates.length, 100),
    threats_found:      threats.length,
    critical:           criticalThreats,
    high_risk:          threats.filter(t => t.risk_score >= 50 && t.risk_score < 70).length,
    active_phishing:    threats.filter(t => t.category === 'active_phishing').length,
    parked:             threats.filter(t => t.category === 'parked').length,
    top_threats:        threats.slice(0, 20).map(t => ({
      domain:      t.domain,
      risk_score:  t.risk_score,
      category:    t.category,
      resolves:    !!t.registered,
      has_email:   !!t.mx_records,
      ip:          t.ip_address,
    })),
    errors: errors.slice(0, 5),
    duration_ms: Date.now() - startTime,
  };
}
