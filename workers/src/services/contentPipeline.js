/**
 * CYBERDUDEBIVASH AI Security Hub v10.0
 * Automated Content Pipeline — Phase 4
 * CVE → Blog → LinkedIn → Telegram → Platform
 * Full monetization funnel: Content → Traffic → Purchase
 */

// ─── Blog post generator from CVE / threat intel ─────────────────────────────
export async function generateBlogPost(env, intel) {
  const {
    cve_id, title, description, severity, cvss_score,
    affected_products, apt_groups, epss_score, cisa_kev,
    mitre_techniques, solution_ids = [],
  } = intel;

  const slug = buildSlug(cve_id || title);
  const tags  = buildTags(intel);
  const publishedAt = new Date().toISOString();

  // AI-generate content if Workers AI available, else use template engine
  let content = '';
  let excerpt = '';
  try {
    if (env.AI) {
      const prompt = buildBlogPrompt(intel);
      const aiResp = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
        messages: [
          { role: 'system', content: 'You are a world-class cybersecurity writer for CYBERDUDEBIVASH AI Security Hub. Write authoritative, SEO-optimized blog posts about threats and vulnerabilities. Always end with a CTA to purchase the matching defense solution. Be specific, technical, and urgent.' },
          { role: 'user',   content: prompt },
        ],
        max_tokens: 1800,
      });
      content = aiResp?.response || '';
    }
  } catch { /* fall to template */ }

  if (!content) content = buildBlogTemplate(intel);
  excerpt = buildExcerpt(content, intel);

  const seoTitle       = buildSEOTitle(intel);
  const seoDescription = buildSEODesc(intel);
  const seoKeywords    = buildSEOKeywords(intel);
  const htmlContent    = markdownToHtml(content);

  // Solution CTA — link to first matching defense solution
  const solutionCta = solution_ids.length
    ? `https://cyberdudebivash.com/#defense-solutions?cve_id=${cve_id || ''}`
    : `https://cyberdudebivash.com/#defense-solutions`;

  const post = {
    cve_id:          cve_id || null,
    slug,
    title:           seoTitle,
    excerpt,
    content,
    html_content:    htmlContent,
    author:          'CYBERDUDEBIVASH AI',
    tags:            JSON.stringify(tags),
    category:        mapCategory(severity),
    seo_title:       seoTitle,
    seo_description: seoDescription,
    seo_keywords:    seoKeywords,
    status:          'published',
    published_at:    publishedAt,
    solution_cta:    solutionCta,
  };

  // Store in D1
  try {
    const id = crypto.randomUUID();
    await env.SECURITY_HUB_DB.prepare(
      `INSERT OR REPLACE INTO blog_posts
       (id,cve_id,slug,title,excerpt,content,html_content,author,tags,category,
        seo_title,seo_description,seo_keywords,status,published_at,solution_cta)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(id, post.cve_id, post.slug, post.title, post.excerpt,
           post.content, post.html_content, post.author, post.tags,
           post.category, post.seo_title, post.seo_description,
           post.seo_keywords, post.status, post.published_at, post.solution_cta
    ).run();
    post.id = id;
  } catch (err) {
    console.error('[contentPipeline] D1 insert error:', err);
  }

  return post;
}

// ─── LinkedIn post generator ──────────────────────────────────────────────────
export function generateLinkedInPost(intel, blogPost) {
  const { cve_id, severity, title, cvss_score, affected_products, cisa_kev } = intel;
  const blogUrl = `https://cyberdudebivash.com/blog/${blogPost?.slug || 'threat-intel'}`;
  const defenseUrl = `https://cyberdudebivash.com/#defense-solutions`;
  const sevEmoji = { CRITICAL: '🚨', HIGH: '⚠️', MEDIUM: '🔍', LOW: '📡' }[severity] || '⚠️';
  const apts = intel.apt_groups || [];

  const post = `${sevEmoji} ${severity} Threat Alert: ${cve_id || title}
${cvss_score ? `CVSS Score: ${cvss_score}/10` : ''}${cisa_kev ? ' | ✅ CISA KEV' : ''}

${cve_id ? `A critical vulnerability (${cve_id}) has been identified` : `A ${severity?.toLowerCase()} threat has been identified`} affecting ${(affected_products || ['enterprise systems']).slice(0, 3).join(', ')}.

${apts.length ? `🎯 Threat actors: ${apts.join(', ')} are actively exploiting this.\n` : ''}Key risks:
→ Unauthorized remote access
→ Data exfiltration potential
→ Business continuity impact
→ Regulatory compliance exposure

🛡️ CYBERDUDEBIVASH AI has generated a production-ready defense solution:
→ Firewall block rules (deploy in 5 minutes)
→ IDS/SIEM detection signatures
→ IR playbook for your SOC team
→ Executive risk briefing

${defenseUrl}

Full technical breakdown + remediation guide:
${blogUrl}

Are you protected? Drop your tech stack below and I'll tell you if you're vulnerable.

#CyberSecurity #ThreatIntel #${cve_id?.replace(/-/g, '') || 'CyberThreat'} #CISO #SOC #InfoSec #CyberdudeBivash #SentinelAPEX`;

  return { platform: 'linkedin', content: post, url: blogUrl, char_count: post.length };
}

// ─── Telegram message generator ──────────────────────────────────────────────
export function generateTelegramMessage(intel, blogPost) {
  const { cve_id, severity, title, cvss_score, affected_products, cisa_kev, epss_score } = intel;
  const blogUrl    = `https://cyberdudebivash.com/blog/${blogPost?.slug || 'threat-intel'}`;
  const defenseUrl = `https://cyberdudebivash.com/#defense-solutions`;
  const sevEmoji   = { CRITICAL: '🚨', HIGH: '⚠️', MEDIUM: '🔍', LOW: '📡' }[severity] || '⚠️';

  const msg = `${sevEmoji} <b>${severity} THREAT: ${cve_id || title}</b>

📊 <b>Severity Metrics</b>
${cvss_score ? `• CVSS: <code>${cvss_score}/10</code>` : ''}
${epss_score ? `• EPSS: <code>${(epss_score * 100).toFixed(1)}%</code> exploitation prob.` : ''}
${cisa_kev ? '• ✅ <b>CISA KEV — actively exploited</b>' : ''}

🎯 <b>Affected:</b> ${(affected_products || ['Enterprise systems']).slice(0, 4).join(', ')}

🛡️ <b>Defense solution available now:</b>
• Firewall block rules
• Sigma/YARA detection
• IR playbook
• Python scanner

💰 Starting at ₹199

🔗 <a href="${defenseUrl}">Unlock Defense Solution</a>
📖 <a href="${blogUrl}">Read Full Analysis</a>

<i>Powered by @CyberdudeBivash Sentinel APEX</i>`;

  return { platform: 'telegram', content: msg, url: blogUrl, html: true };
}

// ─── Post to Telegram ─────────────────────────────────────────────────────────
export async function postToTelegram(env, message) {
  const botToken = env.TELEGRAM_BOT_TOKEN;
  const chatId   = env.TELEGRAM_CHANNEL_ID;
  if (!botToken || !chatId) return { success: false, reason: 'Telegram not configured' };

  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id:    chatId,
        text:       message.content,
        parse_mode: message.html ? 'HTML' : 'Markdown',
        disable_web_page_preview: false,
        reply_markup: {
          inline_keyboard: [[
            { text: '🛡️ Get Defense Solution', url: `https://cyberdudebivash.com/#defense-solutions` },
            { text: '📖 Read Analysis',         url: message.url || 'https://cyberdudebivash.com' },
          ]],
        },
      }),
    });
    if (!r.ok) {
      const err = await r.json();
      return { success: false, reason: err.description };
    }
    const data = await r.json();
    return { success: true, message_id: data.result?.message_id };
  } catch (err) {
    return { success: false, reason: err.message };
  }
}

// ─── Queue LinkedIn post (via KV — webhook picks it up) ──────────────────────
export async function queueLinkedInPost(env, liPost, blogPost) {
  try {
    const key = `social:queue:linkedin:${Date.now()}`;
    await env.SECURITY_HUB_KV?.put(key, JSON.stringify({
      type:        'linkedin',
      content:     liPost.content,
      blog_url:    liPost.url,
      cve_id:      blogPost?.cve_id,
      created_at:  new Date().toISOString(),
    }), { expirationTtl: 86400 * 7 });

    // Also post via LinkedIn API if token available
    const liToken = env.LINKEDIN_ACCESS_TOKEN;
    const liOrgId = env.LINKEDIN_ORG_ID;
    if (liToken && liOrgId) {
      await postToLinkedIn(liToken, liOrgId, liPost.content);
    }

    return { success: true, queued: key };
  } catch (err) {
    return { success: false, reason: err.message };
  }
}

// ─── Post to LinkedIn (Direct API) ───────────────────────────────────────────
async function postToLinkedIn(accessToken, authorId, text) {
  const r = await fetch('https://api.linkedin.com/v2/ugcPosts', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type':  'application/json',
      'X-Restli-Protocol-Version': '2.0.0',
    },
    body: JSON.stringify({
      author:          `urn:li:organization:${authorId}`,
      lifecycleState:  'PUBLISHED',
      specificContent: {
        'com.linkedin.ugc.ShareContent': {
          shareCommentary:   { text },
          shareMediaCategory:'NONE',
        },
      },
      visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' },
    }),
  });
  return r.ok;
}

// ─── Full automated pipeline: CVE → Blog → Social → Platform ─────────────────
export async function runContentPipeline(env, intel) {
  const results = {
    cve_id:    intel.cve_id || 'unknown',
    blog:      null,
    linkedin:  null,
    telegram:  null,
    errors:    [],
  };

  try {
    // Step 1: Generate and store blog post
    const blogPost = await generateBlogPost(env, intel);
    results.blog = { slug: blogPost.slug, title: blogPost.title, url: `https://cyberdudebivash.com/blog/${blogPost.slug}` };

    // Step 2: Generate LinkedIn post
    const liPost   = generateLinkedInPost(intel, blogPost);
    const liResult = await queueLinkedInPost(env, liPost, blogPost);
    results.linkedin = liResult;

    // Update blog LinkedIn status
    if (blogPost.id) {
      await env.SECURITY_HUB_DB?.prepare(
        `UPDATE blog_posts SET linkedin_posted=1 WHERE id=?`
      ).bind(blogPost.id).run().catch(() => {});
    }

    // Step 3: Generate and post Telegram message
    const tgMsg    = generateTelegramMessage(intel, blogPost);
    const tgResult = await postToTelegram(env, tgMsg);
    results.telegram = tgResult;

    // Update blog Telegram status
    if (blogPost.id && tgResult.success) {
      await env.SECURITY_HUB_DB?.prepare(
        `UPDATE blog_posts SET telegram_posted=1 WHERE id=?`
      ).bind(blogPost.id).run().catch(() => {});
    }

    // Step 4: Track funnel event
    await env.SECURITY_HUB_DB?.prepare(
      `INSERT INTO fomo_events (id, event_type, entity_type, entity_id, display_name) VALUES (?,?,?,?,?)`
    ).bind(crypto.randomUUID(), 'view', 'blog_post', blogPost.id || '', blogPost.title?.slice(0, 80)).run().catch(() => {});

    // Step 5: Cache blog post for fast retrieval
    await env.SECURITY_HUB_KV?.put(
      `blog:post:${blogPost.slug}`,
      JSON.stringify(blogPost),
      { expirationTtl: 86400 * 7 }
    );

    results.success = true;
  } catch (err) {
    results.errors.push(err.message);
    results.success = false;
    console.error('[contentPipeline] runContentPipeline error:', err);
  }

  return results;
}

// ─── Bulk pipeline runner (processes multiple CVEs) ──────────────────────────
export async function runBulkContentPipeline(env, limit = 5) {
  try {
    // Fetch unprocessed intel
    const rows = await env.SECURITY_HUB_DB?.prepare(
      `SELECT ti.*, GROUP_CONCAT(ds.id) as solution_ids
       FROM threat_intel ti
       LEFT JOIN defense_solutions ds ON ds.cve_id = ti.cve_id
       WHERE ti.blog_published IS NULL OR ti.blog_published = 0
       GROUP BY ti.id
       ORDER BY CASE ti.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END, ti.created_at DESC
       LIMIT ?`
    ).bind(limit).all();

    const items   = rows?.results || [];
    const results = [];

    for (const item of items) {
      const intel = {
        cve_id:           item.cve_id,
        title:            item.title || item.cve_id,
        description:      item.description,
        severity:         item.severity,
        cvss_score:       item.cvss_score,
        affected_products: item.affected_products ? JSON.parse(item.affected_products) : [],
        apt_groups:        item.apt_groups ? item.apt_groups.split(',') : [],
        epss_score:        item.epss_score,
        cisa_kev:          !!item.cisa_kev,
        mitre_techniques:  item.mitre_techniques ? item.mitre_techniques.split(',') : [],
        solution_ids:      item.solution_ids ? item.solution_ids.split(',') : [],
      };

      const result = await runContentPipeline(env, intel);
      results.push(result);

      // Mark as published in threat_intel
      await env.SECURITY_HUB_DB?.prepare(
        `UPDATE threat_intel SET blog_published=1 WHERE cve_id=?`
      ).bind(item.cve_id).run().catch(() => {});
    }

    return { success: true, processed: results.length, results };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ─── Handler: GET /api/blog/posts ────────────────────────────────────────────
export async function handleGetBlogPosts(request, env) {
  try {
    const url    = new URL(request.url);
    const page   = parseInt(url.searchParams.get('page') || '1');
    const limit  = Math.min(parseInt(url.searchParams.get('limit') || '10'), 50);
    const offset = (page - 1) * limit;
    const cat    = url.searchParams.get('category') || null;
    const cveId  = url.searchParams.get('cve_id') || null;

    const cacheKey = `cache:blog:list:${page}:${limit}:${cat || 'all'}`;
    const cached   = await env.SECURITY_HUB_KV?.get(cacheKey, 'json');
    if (cached) return json({ success: true, cached: true, ...cached });

    let where  = `WHERE status='published'`;
    const params = [];
    if (cat)   { where += ' AND category=?';  params.push(cat); }
    if (cveId) { where += ' AND cve_id=?';    params.push(cveId); }

    const [rows, countRow] = await Promise.all([
      env.SECURITY_HUB_DB.prepare(
        `SELECT id,cve_id,slug,title,excerpt,category,tags,seo_description,published_at,views,solution_cta
         FROM blog_posts ${where} ORDER BY published_at DESC LIMIT ? OFFSET ?`
      ).bind(...params, limit, offset).all(),
      env.SECURITY_HUB_DB.prepare(
        `SELECT COUNT(*) as total FROM blog_posts ${where}`
      ).bind(...params).first(),
    ]);

    const posts = rows.results || [];
    const total = countRow?.total || 0;
    const payload = { posts, pagination: { page, limit, total, pages: Math.ceil(total / limit) } };
    await env.SECURITY_HUB_KV?.put(cacheKey, JSON.stringify(payload), { expirationTtl: 300 });
    return json({ success: true, ...payload });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── Handler: GET /api/blog/posts/:slug ──────────────────────────────────────
export async function handleGetBlogPost(request, env, slug) {
  try {
    if (!slug) return json({ success: false, error: 'Slug required' }, 400);

    // Try KV cache first
    const kvKey  = `blog:post:${slug}`;
    const cached = await env.SECURITY_HUB_KV?.get(kvKey, 'json');
    if (cached) {
      env.SECURITY_HUB_DB?.prepare(`UPDATE blog_posts SET views=views+1 WHERE slug=?`).bind(slug).run().catch(() => {});
      return json({ success: true, cached: true, post: cached });
    }

    const post = await env.SECURITY_HUB_DB.prepare(
      `SELECT * FROM blog_posts WHERE slug=? AND status='published'`
    ).bind(slug).first();
    if (!post) return json({ success: false, error: 'Post not found' }, 404);

    env.SECURITY_HUB_DB.prepare(`UPDATE blog_posts SET views=views+1 WHERE slug=?`).bind(slug).run().catch(() => {});
    await env.SECURITY_HUB_KV?.put(kvKey, JSON.stringify(post), { expirationTtl: 3600 });
    return json({ success: true, post });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── Handler: POST /api/content/run — admin trigger ──────────────────────────
export async function handleRunContentPipeline(request, env, authCtx) {
  if (authCtx?.role !== 'admin') return json({ error: 'Admin only' }, 403);
  const body   = await request.json().catch(() => ({}));
  const limit  = Math.min(body.limit || 3, 10);
  const result = await runBulkContentPipeline(env, limit);
  return json(result);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function buildSlug(input) {
  if (!input) return `threat-${Date.now()}`;
  return input.toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80) + `-${Date.now().toString(36)}`;
}

function buildTags(intel) {
  const tags = ['cybersecurity', 'threat-intel'];
  if (intel.cve_id) tags.push(intel.cve_id.toLowerCase());
  if (intel.severity) tags.push(intel.severity.toLowerCase());
  if (intel.cisa_kev) tags.push('cisa-kev');
  if (intel.apt_groups?.length) tags.push(...intel.apt_groups.slice(0, 2).map(a => a.toLowerCase().replace(/\s/g, '-')));
  tags.push('sentinel-apex', 'cyberdudebivash');
  return [...new Set(tags)];
}

function buildSEOTitle(intel) {
  const sev    = intel.severity ? `[${intel.severity}] ` : '';
  const cve    = intel.cve_id ? `${intel.cve_id}: ` : '';
  const base   = intel.title || intel.cve_id || 'Critical Security Vulnerability';
  const suffix = intel.cisa_kev ? ' — CISA KEV Alert' : ' — Patch Now';
  return `${sev}${cve}${base}${suffix} | CYBERDUDEBIVASH`.slice(0, 60);
}

function buildSEODesc(intel) {
  const cve  = intel.cve_id ? `${intel.cve_id} ` : '';
  const sev  = intel.severity ? `${intel.severity} severity. ` : '';
  const desc = (intel.description || 'Critical security vulnerability').slice(0, 100);
  return `${cve}${sev}${desc}. Get instant firewall scripts, Sigma rules, and IR playbook from CYBERDUDEBIVASH Sentinel APEX.`.slice(0, 160);
}

function buildSEOKeywords(intel) {
  const kw = ['cybersecurity', 'vulnerability', 'CVE', 'threat intelligence', 'CYBERDUDEBIVASH'];
  if (intel.cve_id) kw.push(intel.cve_id);
  if (intel.severity) kw.push(`${intel.severity} vulnerability`);
  if (intel.affected_products?.length) kw.push(...intel.affected_products.slice(0, 3));
  return kw.join(', ');
}

function buildExcerpt(content, intel) {
  const first = content.split('\n\n').find(p => p.length > 80 && !p.startsWith('#'));
  return (first || intel.description || 'Critical threat intelligence from CYBERDUDEBIVASH Sentinel APEX.').slice(0, 200);
}

function mapCategory(severity) {
  return { CRITICAL: 'critical-threats', HIGH: 'high-risk', MEDIUM: 'threat-intel', LOW: 'security-news' }[severity] || 'threat-intel';
}

function buildBlogPrompt(intel) {
  return `Write a detailed, SEO-optimized cybersecurity blog post for CYBERDUDEBIVASH AI Security Hub.

THREAT: ${intel.cve_id || intel.title}
SEVERITY: ${intel.severity} ${intel.cvss_score ? `| CVSS: ${intel.cvss_score}` : ''}${intel.cisa_kev ? ' | CISA KEV (actively exploited)' : ''}
DESCRIPTION: ${intel.description || 'Critical security vulnerability'}
AFFECTED: ${(intel.affected_products || []).join(', ')}
${intel.apt_groups?.length ? `APT GROUPS: ${intel.apt_groups.join(', ')}` : ''}

STRUCTURE:
1. Executive Summary (2-3 sentences, urgency)
2. Technical Details (what, how it works, attack vectors)
3. Business Impact (data breach, downtime, compliance)
4. Attack Scenarios (real-world exploitation examples)
5. Immediate Actions (numbered steps, < 24h)
6. Long-term Hardening (strategic fixes)
7. CTA: "Deploy Instant Defense Solution from CYBERDUDEBIVASH Sentinel APEX → [₹199-₹999]"

Tone: Authoritative, urgent, technical but readable by CISO. 800-1000 words. Use markdown headings.`;
}

function buildBlogTemplate(intel) {
  const { cve_id, title, description, severity, cvss_score, affected_products = [], cisa_kev, apt_groups = [], epss_score } = intel;
  const sev     = severity || 'HIGH';
  const sevIcon = { CRITICAL: '🚨', HIGH: '⚠️', MEDIUM: '🔍', LOW: '📡' }[sev] || '⚠️';
  const urgency = { CRITICAL: 'immediate action required', HIGH: 'patch within 72 hours', MEDIUM: 'patch within 7 days', LOW: 'patch within 30 days' }[sev] || 'review recommended';
  const priceRange = { CRITICAL: '₹799', HIGH: '₹599', MEDIUM: '₹399', LOW: '₹199' }[sev] || '₹499';

  return `## ${sevIcon} Executive Summary

${cisa_kev ? '**⚡ CISA Known Exploited Vulnerability (KEV) — actively targeted in the wild.**\n\n' : ''}${cve_id ? `**${cve_id}** is a **${sev} severity** vulnerability` : `A **${sev} severity** security issue`} ${description ? `affecting ${(affected_products).slice(0,3).join(', ') || 'enterprise systems'}. ${description.slice(0, 200)}` : `requiring ${urgency}.`}

${cvss_score ? `**CVSS Score: ${cvss_score}/10**${epss_score ? ` | EPSS: ${(epss_score * 100).toFixed(1)}% exploitation probability` : ''}` : ''}

---

## 🔬 Technical Analysis

${description || `This vulnerability enables attackers to ${sev === 'CRITICAL' ? 'execute arbitrary code remotely without authentication' : 'gain unauthorized access to affected systems'}.`}

**Attack Vector:** Network-accessible, exploitable without authentication${cvss_score >= 9 ? ' — ZERO INTERACTION required' : ''}.

**Affected Components:**
${(affected_products.slice(0, 6)).map(p => `- ${p}`).join('\n') || '- Enterprise deployments\n- Cloud workloads\n- On-premises installations'}

${apt_groups.length ? `**⚔️ Threat Actors:** ${apt_groups.join(', ')} are actively weaponizing this vulnerability.` : ''}

---

## 💼 Business Impact

| Impact Category | Risk Level | Potential Cost |
|---|---|---|
| Data Breach | ${sev === 'CRITICAL' ? 'CRITICAL' : 'HIGH'} | $4.45M+ avg breach cost |
| Operational Downtime | HIGH | $5,600/min avg downtime |
| Regulatory Fines | MEDIUM | GDPR: 4% of annual revenue |
| Reputation Damage | HIGH | 3-year recovery average |

---

## 🎯 Attack Scenarios

**Scenario 1 — External Attacker:**
Threat actor scans internet-facing ${(affected_products[0] || 'application')}, identifies vulnerable version, executes exploit payload, establishes persistence via reverse shell.

**Scenario 2 — Supply Chain Attack:**
Malicious package update targeting ${(affected_products[0] || 'software')} deployments, lateral movement to production databases, exfiltration of customer PII.

---

## ⚡ Immediate Actions (Next 24 Hours)

1. **Identify exposure** — Run CYBERDUDEBIVASH scanner to map all vulnerable instances
2. **Apply network controls** — Deploy firewall block rules (available in our Defense Solution)
3. **Enable detection** — Import Sigma/YARA rules into your SIEM
4. **Patch or isolate** — Apply vendor patch or isolate system if patch unavailable
5. **Activate IR plan** — Brief SOC team and activate incident response procedures

---

## 🛡️ Long-term Hardening

- Implement zero-trust network segmentation
- Deploy web application firewall with CVE-specific rules
- Enable anomaly detection in SIEM for exploitation patterns
- Establish automated vulnerability scanning cadence
- Review and update incident response playbooks quarterly

---

## 🔓 Instant Defense Solution — ${priceRange}

CYBERDUDEBIVASH Sentinel APEX has generated a production-ready defense toolkit for this threat:

✅ **Firewall Block Rules** — iptables/nftables/pfSense (deploy in 5 min)
✅ **Sigma Detection Rule** — Splunk/Elastic/Chronicle/Sentinel
✅ **YARA Rule** — malware and exploit artifact detection
✅ **IR Playbook** — 5-phase response with SLA timers
✅ **Executive Briefing** — board-ready PDF report

**[→ Unlock Defense Solution — ${priceRange}](https://cyberdudebivash.com/#defense-solutions)**

*Trusted by enterprise SOC teams and MSSPs worldwide.*

---

*Powered by CYBERDUDEBIVASH AI Security Hub | Sentinel APEX Threat Intelligence*
*Stay protected: [cyberdudebivash.com](https://cyberdudebivash.com)*`;
}

function markdownToHtml(md) {
  return md
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/^---$/gm, '<hr>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(.+)$/gm, (line) => line.startsWith('<') ? line : `<p>${line}</p>`);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
