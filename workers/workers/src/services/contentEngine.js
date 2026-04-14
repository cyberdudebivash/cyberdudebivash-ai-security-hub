/**
 * CYBERDUDEBIVASH AI Security Hub — Content Automation Engine v1.0
 * GTM Phase 1: Traffic Domination via AI-Generated Security Content
 *
 * Auto-generates daily multi-format content from live CVE/threat intel data:
 *   1. LinkedIn post (professional, engagement-optimized)
 *   2. Twitter/X post (punchy, hashtag-rich, under 280 chars)
 *   3. Telegram alert (markdown, direct CTAs)
 *   4. SEO blog article (1500+ words, keyword-rich, structured)
 *   5. Email newsletter digest
 *
 * Content is stored in D1 `content_queue` and optionally posted via
 * Telegram Bot API immediately. LinkedIn/X require OAuth (design-ready).
 */

const PLATFORM_URL   = 'https://tools.cyberdudebivash.com';
const BRAND_NAME     = 'CYBERDUDEBIVASH AI Security Hub';
const BRAND_SHORT    = 'CDB Security';
const TELEGRAM_JOIN  = 'https://t.me/cyberdudebivashSentinelApex';

// ─── SEO keywords per threat category ─────────────────────────────────────────
const SEO_KEYWORDS = {
  RCE:           ['remote code execution', 'RCE vulnerability', 'critical security patch', 'zero day exploit'],
  SQLi:          ['SQL injection vulnerability', 'database security', 'OWASP Top 10', 'web application security'],
  Ransomware:    ['ransomware attack', 'cyber extortion', 'data encryption attack', 'ransomware prevention'],
  ZeroDay:       ['zero-day vulnerability', 'unpatched exploit', 'CVE alert 2025', 'cyber threat intelligence'],
  AuthBypass:    ['authentication bypass', 'access control vulnerability', 'identity security', 'zero trust'],
  PrivEsc:       ['privilege escalation', 'lateral movement', 'endpoint security', 'EDR detection'],
  ContainerEsc:  ['container escape', 'Kubernetes security', 'cloud security vulnerability', 'DevSecOps'],
  SupplyChain:   ['supply chain attack', 'software supply chain security', 'SBOM', 'dependency vulnerability'],
  DEFAULT:       ['cybersecurity news', 'CVE alert', 'security advisory', 'vulnerability management'],
};

// ─── Emoji map ─────────────────────────────────────────────────────────────────
const SEV_EMOJI = { CRITICAL: '🚨', HIGH: '🔴', MEDIUM: '🟡', LOW: '🟢' };

// ─── Parse tags ───────────────────────────────────────────────────────────────
function parseTags(entry) {
  try { return JSON.parse(entry.tags || '[]'); } catch { return []; }
}

// ─── Get primary tag for content angle ───────────────────────────────────────
function getPrimaryTag(tags = []) {
  const priority = ['RCE', 'ZeroDay', 'Ransomware', 'SupplyChain', 'AuthBypass', 'SQLi', 'PrivEsc', 'ContainerEsc'];
  return priority.find(t => tags.includes(t)) || tags[0] || 'Cybersecurity';
}

// ─── Get SEO keywords for entry ──────────────────────────────────────────────
function getSEOKeywords(tags = []) {
  const primaryTag = getPrimaryTag(tags);
  return SEO_KEYWORDS[primaryTag] || SEO_KEYWORDS.DEFAULT;
}

// ─── Format CVE stat line ─────────────────────────────────────────────────────
function cveStatLine(entry) {
  const parts = [`CVE: ${entry.id}`];
  if (entry.cvss)          parts.push(`CVSS: ${entry.cvss}/10`);
  if (entry.epss_score)    parts.push(`EPSS: ${(entry.epss_score * 100).toFixed(0)}%`);
  if (entry.exploit_status === 'confirmed') parts.push('🚨 EXPLOITED IN THE WILD');
  return parts.join(' | ');
}

// ─── GENERATOR 1: LinkedIn post ───────────────────────────────────────────────
export function generateLinkedInPost(entry, correlations = null) {
  const emoji    = SEV_EMOJI[entry.severity] || '🔴';
  const tags     = parseTags(entry);
  const primary  = getPrimaryTag(tags);
  const keywords = getSEOKeywords(tags);
  const actor    = correlations?.threat_actor || null;
  const exploited = entry.exploit_status === 'confirmed' || entry.actively_exploited;

  const hooks = [
    `${emoji} Security teams — stop what you're doing.`,
    `I've been tracking this CVE for the last 24 hours. Here's what you need to know.`,
    `This vulnerability is different. Here's why CISOs should care.`,
    `If you run ${(entry.title || '').split(' ').slice(0, 3).join(' ')} in your stack — read this now.`,
  ];
  const hook = hooks[Math.floor(Math.random() * hooks.length)];

  const actorLine = actor
    ? `\n⚠️ Attributed to: ${actor}\n`
    : '';

  const body = `
${hook}

${emoji} ${entry.severity} SEVERITY — ${entry.id}
${cveStatLine(entry)}

📋 What happened:
${(entry.description || '').slice(0, 300)}${(entry.description || '').length > 300 ? '...' : ''}
${actorLine}
🎯 Who's at risk:
${((() => { try { return JSON.parse(entry.affected_products || '[]'); } catch { return []; } })()).slice(0, 2).join(', ') || 'Multiple vendors'}

✅ What you should do RIGHT NOW:
1️⃣ Assess your exposure — run a free scan at ${PLATFORM_URL}
2️⃣ Apply vendor patches immediately${exploited ? '\n3️⃣ Hunt for IOCs in your environment (contact us for threat intel)' : ''}
4️⃣ Enable real-time threat monitoring — Sentinel APEX is live

🤖 ${BRAND_NAME} provides:
→ Real-time CVE feed (NVD + CISA KEV + ExploitDB)
→ AI-powered SOC automation
→ Autonomous defense recommendations
→ Enterprise threat intelligence API

🔗 Free scan: ${PLATFORM_URL}
📡 Join Sentinel APEX feed: ${TELEGRAM_JOIN}

${keywords.slice(0, 3).map(k => `#${k.replace(/\s+/g, '')}`).join(' ')} #${primary} #CyberSecurity #InfoSec #ThreatIntelligence #CISO #SecurityOps
`.trim();

  return {
    platform:    'linkedin',
    content_type: 'cve_alert',
    title:       `${emoji} ${entry.severity}: ${entry.id} — ${primary} Vulnerability Alert`,
    body,
    char_count:  body.length,
    cve_id:      entry.id,
    tags:        [...keywords.slice(0, 3), primary, 'CyberSecurity', 'InfoSec'],
    cta_url:     PLATFORM_URL,
  };
}

// ─── GENERATOR 2: Twitter/X post ─────────────────────────────────────────────
export function generateTwitterPost(entry) {
  const emoji    = SEV_EMOJI[entry.severity] || '🔴';
  const tags     = parseTags(entry);
  const primary  = getPrimaryTag(tags);
  const exploited = entry.exploit_status === 'confirmed';

  const shortDesc = (entry.description || '').slice(0, 100);

  // Twitter has 280 char limit — keep it tight
  const variants = [
    `${emoji} ${entry.severity}: ${entry.id}\nCVSS ${entry.cvss}/10${exploited ? ' 🚨 EXPLOITED IN WILD' : ''}\n\n${shortDesc}...\n\nFree scan → ${PLATFORM_URL}\n#${primary} #CyberSecurity #CVE`,
    `🔥 NEW CVE ALERT: ${entry.id}\n${entry.severity} | CVSS ${entry.cvss}${entry.epss_score ? ` | EPSS ${(entry.epss_score*100).toFixed(0)}%` : ''}\n${exploited ? '⚠️ Actively exploited\n' : ''}Check your exposure FREE → ${PLATFORM_URL}\n#InfoSec #${primary} #ThreatIntel`,
    `PATCH NOW: ${entry.id} (${entry.severity})\n"${(entry.title || '').slice(0, 80)}"\n→ ${PLATFORM_URL}\n#CyberSecurity #${primary} #CybersecurityNews`,
  ];

  // Pick shortest that fits 280
  const post = variants.find(v => v.length <= 280) || variants[0].slice(0, 277) + '...';

  return {
    platform:    'twitter',
    content_type: 'cve_alert',
    title:       `${entry.id} ${entry.severity}`,
    body:        post,
    char_count:  post.length,
    cve_id:      entry.id,
    tags:        [primary, 'CyberSecurity', 'CVE', 'InfoSec'],
    cta_url:     PLATFORM_URL,
  };
}

// ─── GENERATOR 3: Telegram alert ─────────────────────────────────────────────
export function generateTelegramPost(entry, correlations = null) {
  const emoji    = SEV_EMOJI[entry.severity] || '🔴';
  const tags     = parseTags(entry);
  const actor    = correlations?.threat_actor || null;
  const exploited = entry.exploit_status === 'confirmed' || entry.actively_exploited;
  const epssLine = entry.epss_score ? `\n📈 *EPSS:* \`${(entry.epss_score*100).toFixed(1)}%\`` : '';

  const body = [
    `${emoji} *SENTINEL APEX — ${entry.severity} CVE ALERT*`,
    ``,
    `*${entry.id}* | CVSS: \`${entry.cvss || 'N/A'}\`${epssLine}`,
    exploited ? `🚨 *ACTIVELY EXPLOITED IN THE WILD*` : `⚡ Status: ${entry.exploit_status || 'unconfirmed'}`,
    ``,
    (entry.title || '').slice(0, 150),
    ``,
    (entry.description || '').slice(0, 250) + ((entry.description || '').length > 250 ? '…' : ''),
    actor ? `\n🕵️ *Threat Actor:* ${actor}` : '',
    ``,
    `🏷 *Tags:* ${tags.slice(0, 5).join(' · ')}`,
    ``,
    `[🔍 Free Security Scan](${PLATFORM_URL}) | [📡 Join Feed](${TELEGRAM_JOIN}) | [📊 Dashboard](${PLATFORM_URL}/#dashboard)`,
    ``,
    `_Powered by ${BRAND_NAME} — Sentinel APEX v3_`,
  ].filter(l => l !== '').join('\n');

  return {
    platform:    'telegram',
    content_type: 'cve_alert',
    title:       `${emoji} ${entry.severity}: ${entry.id}`,
    body,
    char_count:  body.length,
    cve_id:      entry.id,
    tags:        tags.slice(0, 6),
    cta_url:     PLATFORM_URL,
    parse_mode:  'Markdown',
  };
}

// ─── GENERATOR 4: SEO Blog Article ───────────────────────────────────────────
export function generateBlogPost(entry, huntingAlerts = [], correlations = null) {
  const emoji    = SEV_EMOJI[entry.severity] || '🔴';
  const tags     = parseTags(entry);
  const primary  = getPrimaryTag(tags);
  const keywords = getSEOKeywords(tags);
  const actor    = correlations?.threat_actor || null;
  const exploited = entry.exploit_status === 'confirmed' || entry.actively_exploited;
  const dateStr  = new Date().toLocaleDateString('en-IN', { year:'numeric', month:'long', day:'numeric' });
  const affected = (() => { try { return JSON.parse(entry.affected_products || '[]'); } catch { return []; } })();

  const slug = `${entry.id.toLowerCase()}-${primary.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}`;

  const body = `
# ${emoji} ${entry.id}: ${entry.title || primary + ' Critical Vulnerability'} — What You Must Know

**Published:** ${dateStr} | **Severity:** ${entry.severity} | **CVSS:** ${entry.cvss || 'N/A'}/10${entry.epss_score ? ` | **EPSS:** ${(entry.epss_score*100).toFixed(1)}%` : ''}

> **TL;DR:** ${entry.id} is a ${entry.severity.toLowerCase()}-severity ${primary} vulnerability${exploited ? ' actively being exploited in the wild' : ''}. Organizations running affected systems must patch immediately or apply compensating controls.

---

## What Is ${entry.id}?

${entry.description || `${entry.id} is a ${entry.severity.toLowerCase()} severity vulnerability affecting ${affected.slice(0,2).join(', ') || 'multiple systems'}.`}

This vulnerability has been assigned a **CVSS base score of ${entry.cvss || 'N/A'}**, placing it in the **${entry.severity}** category${exploited ? ' and has been confirmed as actively exploited in the wild by threat actors' : ''}.

${actor ? `\n## Threat Actor Attribution\n\nThis vulnerability has been attributed to **${actor}** (${correlations?.campaign || 'advanced persistent threat'}). Organizations in targeted sectors should treat this as an active threat requiring immediate response.\n` : ''}

## Who Is Affected?

${affected.length > 0
  ? `The following products and platforms are confirmed affected:\n\n${affected.slice(0,5).map(p => `- ${p}`).join('\n')}`
  : `Multiple enterprise systems may be affected. Check your vendor's security advisories for specific version information.`}

If you use any of these systems in your environment, **immediate action is required**.

## Technical Analysis

### Vulnerability Mechanics

${entry.severity === 'CRITICAL' || (entry.cvss || 0) >= 9.0
  ? `This is a **critical-severity** vulnerability that can be exploited **without authentication** (unauthenticated attack vector), making it particularly dangerous for internet-facing systems.`
  : `This ${entry.severity.toLowerCase()}-severity vulnerability requires careful analysis of your specific configuration and exposure level.`}

${tags.includes('RCE') ? `The vulnerability allows **Remote Code Execution (RCE)**, meaning attackers can run arbitrary code on vulnerable systems — effectively taking complete control.` : ''}
${tags.includes('AuthBypass') ? `The vulnerability enables **Authentication Bypass**, allowing attackers to skip login mechanisms entirely and access protected resources.` : ''}
${tags.includes('SQLi') ? `This **SQL Injection** vulnerability can expose sensitive database contents and potentially allow data manipulation or deletion.` : ''}
${tags.includes('ZeroDay') ? `\n> ⚠️ **ZERO-DAY STATUS:** This vulnerability was exploited before a vendor patch was available. Apply workarounds immediately.` : ''}

### Exploit Status

${exploited
  ? `**🚨 Actively Exploited:** This vulnerability has been confirmed as actively exploited in the wild. CISA has added it to the Known Exploited Vulnerabilities (KEV) catalog, meaning U.S. federal agencies are required to patch within 72 hours. Non-government organizations should treat this with equal urgency.`
  : entry.exploit_status === 'poc_available'
    ? `**⚡ PoC Available:** A proof-of-concept exploit exists publicly. Expect weaponized exploitation to begin within days. Pre-emptive patching is critical.`
    : `**✅ No Confirmed Exploit:** No confirmed in-the-wild exploitation at time of writing. This gives a brief window for methodical patching.`}

${huntingAlerts.length > 0 ? `\n## Threat Hunting Indicators\n\n${huntingAlerts.slice(0,2).map(a => `- **${a.type?.replace(/_/g,' ')}:** ${a.message}`).join('\n')}\n` : ''}

## Immediate Response Plan

### Step 1: Assess Your Exposure (Next 2 Hours)

1. Identify all instances of affected software in your environment
2. Check software versions against affected version ranges
3. Run a comprehensive security scan using our free tool: [${PLATFORM_URL}](${PLATFORM_URL})
4. Log all identified instances for tracking

### Step 2: Apply Patches (Within 24–72 Hours)

${exploited ? '**⚠️ CRITICAL:** Given active exploitation, patch within 24 hours or apply compensating controls immediately.' : `Apply vendor patches within the following timeframes:\n- CVSS ≥ 9.0 (Critical): 24–48 hours\n- CVSS 7.0–8.9 (High): 72 hours\n- CVSS 4.0–6.9 (Medium): 30 days`}

### Step 3: Compensating Controls (If Patching Is Delayed)

- Restrict network access to affected systems
- Enable Web Application Firewall (WAF) rules for known attack patterns
- Increase logging and monitoring on affected systems
- Deploy IDS/IPS signatures where available

### Step 4: Verify Remediation

After patching, verify remediation by:
1. Running a post-patch scan at [${PLATFORM_URL}](${PLATFORM_URL})
2. Checking application logs for exploitation attempts
3. Validating patch installation across all affected instances

## How ${BRAND_NAME} Detects This

Our **Sentinel APEX v3** platform automatically:
- Ingests this CVE from NVD, CISA KEV, and ExploitDB within minutes of publication
- Correlates it with related CVEs, known threat actors, and IOCs
- Generates SOC alerts and autonomous defense recommendations
- Sends real-time Telegram notifications to your security team

[**Start a free scan →**](${PLATFORM_URL}) | [**Join the Sentinel APEX feed →**](${TELEGRAM_JOIN})

## Frequently Asked Questions

**Q: Is my organization affected?**
A: Run a free domain scan at ${PLATFORM_URL} to identify exposed services.

**Q: Is there a patch available?**
A: Check the vendor advisory linked from the [NVD entry](https://nvd.nist.gov/vuln/detail/${entry.id}).

**Q: Should I report this incident?**
A: If you discover evidence of exploitation, report to CERT-In (India) or CISA (US).

## Conclusion

${entry.id} represents a ${entry.severity.toLowerCase()}-severity ${keywords[0]} that demands immediate attention from security teams. ${exploited ? 'With active exploitation confirmed, every hour of delay increases organizational risk.' : 'While not yet confirmed as exploited, the CVSS score and technical severity warrant urgent patching.'}

**[Run your free security assessment at ${PLATFORM_URL}](${PLATFORM_URL})**

---

*This article is generated by ${BRAND_NAME} Sentinel APEX v3 threat intelligence engine. Subscribe to our [Telegram channel](${TELEGRAM_JOIN}) for real-time alerts.*

**Keywords:** ${keywords.join(', ')}, ${entry.id}, vulnerability management, cybersecurity India
`.trim();

  return {
    platform:     'blog',
    content_type: 'seo_article',
    title:        `${entry.id}: ${primary} Vulnerability — Complete Security Guide (${dateStr})`,
    slug,
    body,
    word_count:   body.split(/\s+/).length,
    meta_description: `${entry.id} ${entry.severity} vulnerability (CVSS ${entry.cvss}): ${(entry.description || '').slice(0, 155)}`,
    focus_keyword: keywords[0],
    secondary_keywords: keywords.slice(1),
    cve_id:       entry.id,
    tags:         [...keywords.slice(0, 4), primary, 'CVE', 'CyberSecurity'],
    cta_url:      PLATFORM_URL,
    schema_markup: JSON.stringify({
      '@context': 'https://schema.org',
      '@type':    'Article',
      headline:   `${entry.id} Security Vulnerability Analysis`,
      author:     { '@type': 'Organization', name: BRAND_NAME },
      publisher:  { '@type': 'Organization', name: BRAND_NAME, url: PLATFORM_URL },
      datePublished: new Date().toISOString(),
      description: (entry.description || '').slice(0, 200),
    }),
  };
}

// ─── GENERATOR 5: Email Newsletter Digest ────────────────────────────────────
export function generateEmailDigest(entries = [], stats = {}) {
  const topEntries   = entries.filter(e => e.severity === 'CRITICAL' || e.cvss >= 9.0).slice(0, 3);
  const totalCrit    = entries.filter(e => e.severity === 'CRITICAL').length;
  const totalExploit = entries.filter(e => e.exploit_status === 'confirmed').length;
  const dateStr      = new Date().toLocaleDateString('en-IN', { weekday:'long', year:'numeric', month:'long', day:'numeric' });

  const body = `
Subject: 🚨 ${totalCrit} Critical CVEs This Week — Sentinel APEX Threat Digest

Hi {{first_name}},

Your weekly threat intelligence briefing from ${BRAND_NAME} is here.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 THIS WEEK'S THREAT SUMMARY (${dateStr})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Critical CVEs:     ${totalCrit}
⚠️  Actively Exploited: ${totalExploit}
📈 Avg CVSS Score:    ${stats.avg_cvss || 'N/A'}/10
🌍 Sources Monitored: NVD · CISA KEV · ExploitDB · GitHub · RSS

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 TOP CVEs REQUIRING YOUR ATTENTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${topEntries.map((e, i) => `
${i + 1}. ${e.id} — ${e.severity} (CVSS ${e.cvss || 'N/A'})
   ${(e.title || '').slice(0, 100)}
   ${e.exploit_status === 'confirmed' ? '🚨 ACTIVELY EXPLOITED' : `Status: ${e.exploit_status}`}
   ${e.source === 'cisa_kev' ? '📋 On CISA KEV list' : ''}
   → Full analysis: ${PLATFORM_URL}/?cve=${e.id}
`).join('')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 IS YOUR DOMAIN EXPOSED?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run a free comprehensive security scan to check your exposure:
👉 ${PLATFORM_URL}/?scan={{user_domain}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 UPGRADE TO PRO — GET MORE INTELLIGENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PRO users get:
✅ Full IOC details (IPs, domains, hashes)
✅ CVE correlation engine
✅ IOC graph visualization
✅ 50+ advisories per query (vs 5 on FREE)
✅ API access for automation

👉 Upgrade now: ${PLATFORM_URL}/#pricing (₹1499/mo)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stay secure,
${BRAND_NAME} Team
${PLATFORM_URL} | ${TELEGRAM_JOIN}

[Unsubscribe] | [Manage Preferences] | [View in Browser]
`.trim();

  return {
    platform:     'email',
    content_type: 'newsletter_digest',
    title:        `Sentinel APEX Weekly Threat Digest — ${dateStr}`,
    subject:      `🚨 ${totalCrit} Critical CVEs This Week — Your Threat Digest`,
    body,
    word_count:   body.split(/\s+/).length,
    personalization: ['first_name', 'user_domain'],
    cta_url:      `${PLATFORM_URL}/#pricing`,
  };
}

// ─── MASTER: Generate full content bundle for a CVE ──────────────────────────
export function generateContentBundle(entry, options = {}) {
  const { correlations = null, huntingAlerts = [] } = options;

  return {
    cve_id:      entry.id,
    severity:    entry.severity,
    generated_at: new Date().toISOString(),
    bundle: {
      linkedin:  generateLinkedInPost(entry, correlations),
      twitter:   generateTwitterPost(entry),
      telegram:  generateTelegramPost(entry, correlations),
      blog:      generateBlogPost(entry, huntingAlerts, correlations),
    },
  };
}

// ─── Store content in D1 ─────────────────────────────────────────────────────
export async function storeContentQueue(env, contentItems = []) {
  if (!env?.DB || !contentItems.length) return { stored: 0 };

  let stored = 0;
  for (const item of contentItems.slice(0, 20)) {
    try {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO content_queue
          (id, platform, content_type, title, body, cve_id, status, scheduled_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', datetime('now', '+1 hour'), datetime('now'))
      `).bind(
        `CONTENT-${item.platform}-${item.cve_id}-${Date.now()}`,
        item.platform,
        item.content_type,
        (item.title || '').slice(0, 300),
        (item.body || '').slice(0, 5000),
        item.cve_id || null,
      ).run();
      stored++;
    } catch {}
  }

  return { stored };
}

// ─── Get pending content queue ────────────────────────────────────────────────
export async function getPendingContent(env, limit = 20) {
  if (!env?.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT * FROM content_queue WHERE status = 'pending' ORDER BY scheduled_at ASC LIMIT ?`
    ).bind(limit).all();
    return rows?.results || [];
  } catch { return []; }
}

// ─── Post Telegram content immediately ───────────────────────────────────────
export async function postTelegramContent(env, telegramPost) {
  if (!env?.TELEGRAM_BOT_TOKEN || !env?.SENTINEL_CHANNEL_ID) {
    return { success: false, error: 'Telegram not configured' };
  }

  try {
    const res = await fetch(
      `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          chat_id:                  env.SENTINEL_CHANNEL_ID,
          text:                     telegramPost.body,
          parse_mode:               telegramPost.parse_mode || 'Markdown',
          disable_web_page_preview: false,
        }),
      }
    );
    return { success: res.ok, status: res.status };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ─── Auto-generate content for top 3 new CVEs (cron trigger) ─────────────────
export async function runContentAutomation(env, entries = []) {
  const topCVEs = entries
    .filter(e => e.severity === 'CRITICAL' || (e.cvss || 0) >= 9.0)
    .slice(0, 3);

  if (topCVEs.length === 0) return { generated: 0, posted: 0 };

  const allContent  = [];
  let   tgPosted    = 0;

  for (const entry of topCVEs) {
    const bundle = generateContentBundle(entry, {});

    // Store LinkedIn + Blog in queue
    await storeContentQueue(env, [bundle.bundle.linkedin, bundle.bundle.blog]);
    allContent.push(bundle);

    // Post Telegram immediately
    const tgResult = await postTelegramContent(env, bundle.bundle.telegram);
    if (tgResult.success) tgPosted++;
  }

  // Store digest in KV
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(
      'growth:content:latest_bundles',
      JSON.stringify(allContent.map(b => ({ cve_id: b.cve_id, severity: b.severity, titles: Object.fromEntries(Object.entries(b.bundle).map(([k,v]) => [k, v.title])) }))),
      { expirationTtl: 3600 }
    ).catch(() => {});
  }

  return { generated: allContent.length, posted_telegram: tgPosted, cvEs: topCVEs.map(e => e.id) };
}
