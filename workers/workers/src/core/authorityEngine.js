/**
 * CYBERDUDEBIVASH AI Security Hub — Global Authority Engine v20.0
 * ────────────────────────────────────────────────────────────────
 * Automatically generates:
 *   1. CVE Reports      — structured, PDF-ready technical advisories
 *   2. Blog Posts       — SEO-optimised threat intelligence articles
 *   3. Threat Bulletins — executive-level weekly intelligence digests
 *
 * All content is:
 *   • Generated with Workers AI (llama-3-8b-instruct) when available
 *   • Falls back to deterministic template engine (no AI token required)
 *   • Stored in KV with 24-hour TTL for rapid re-serving
 *   • Published to /blog feed via GET /api/authority/bulletin
 *   • Structured for Google rich snippets + Open Graph
 *
 * Endpoints:
 *   POST /api/authority/cve-report   — full CVE technical advisory
 *   POST /api/authority/blog-post    — SEO blog article from CVE or topic
 *   GET  /api/authority/bulletin     — latest threat intelligence digest
 *   GET  /api/authority/stats        — content generation statistics
 */

// ─── MITRE technique descriptions (subset) ───────────────────────────────────
const MITRE_LABELS = {
  'T1190': 'Exploit Public-Facing Application',
  'T1059': 'Command and Scripting Interpreter',
  'T1566': 'Phishing',
  'T1486': 'Data Encrypted for Impact (Ransomware)',
  'T1078': 'Valid Accounts',
  'T1547': 'Boot or Logon Autostart Execution',
  'T1071': 'Application Layer Protocol (C2)',
  'T1021': 'Remote Services (Lateral Movement)',
  'T1041': 'Exfiltration Over C2 Channel',
  'T1548': 'Abuse Elevation Control Mechanism',
  'T1195': 'Supply Chain Compromise',
  'T1110': 'Brute Force',
  'T1036': 'Masquerading',
  'T1090': 'Proxy (Obfuscate Infrastructure)',
  'T1005': 'Data from Local System',
};

// ─── Severity badge generator ─────────────────────────────────────────────────
function severityBadge(cvss) {
  if (cvss >= 9.0) return { label: 'CRITICAL', color: '#dc2626', emoji: '🔴' };
  if (cvss >= 7.0) return { label: 'HIGH',     color: '#ea580c', emoji: '🟠' };
  if (cvss >= 4.0) return { label: 'MEDIUM',   color: '#ca8a04', emoji: '🟡' };
  return              { label: 'LOW',      color: '#16a34a', emoji: '🟢' };
}

// ─── Template: CVE Report ─────────────────────────────────────────────────────
function buildCVEReportTemplate(cve) {
  const badge     = severityBadge(cve.cvss || 7.5);
  const published = cve.published || new Date().toISOString().slice(0, 10);
  const techniques = (cve.mitre_techniques || ['T1190']).map(t => `${t}: ${MITRE_LABELS[t] || 'Unknown Technique'}`);

  return {
    title:          `Security Advisory: ${cve.id} — ${cve.title || 'Critical Vulnerability'}`,
    cve_id:         cve.id,
    severity:       badge,
    cvss_score:     cve.cvss || 7.5,
    cvss_vector:    cve.cvss_vector || 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss_score:     cve.epss || 0.0,
    in_kev:         cve.in_kev || false,
    published_date: published,
    last_updated:   new Date().toISOString().slice(0, 10),

    executive_summary:
      `${badge.emoji} ${badge.label} severity vulnerability ${cve.id} has been identified in ${cve.affected_product || 'affected software'}. ` +
      `With a CVSS score of ${cve.cvss || 7.5}, this vulnerability ${cve.in_kev ? 'is actively exploited in the wild (CISA KEV confirmed) and' : ''} ` +
      `requires immediate attention. Organizations running ${cve.affected_product || 'the affected component'} should apply patches immediately.`,

    technical_details: {
      description:    cve.description || `A ${badge.label.toLowerCase()} severity vulnerability exists in ${cve.affected_product || 'the affected component'} that allows ${cve.impact || 'unauthorized access or code execution'}.`,
      affected:       cve.affected_versions || ['All versions prior to patch'],
      root_cause:     cve.root_cause || 'Improper input validation allowing memory corruption or injection.',
      attack_vector:  cve.attack_vector || 'Network accessible — no authentication required',
      prerequisites:  cve.prerequisites || 'Target must be running the vulnerable version with default configuration.',
    },

    impact_analysis: {
      confidentiality: cve.impact_c || 'HIGH',
      integrity:       cve.impact_i || 'HIGH',
      availability:    cve.impact_a || 'HIGH',
      scope:           cve.scope    || 'CHANGED',
      business_impact: `Exploitation could result in full system compromise, data exfiltration, ransomware deployment, or service disruption.`,
    },

    mitre_attack: {
      techniques: techniques,
      tactics:    cve.tactics || ['Initial Access', 'Execution'],
    },

    exploitation: {
      status:            cve.in_kev         ? 'Actively Exploited (CISA KEV)' : (cve.has_exploit ? 'PoC Available' : 'No Known Exploit'),
      threat_actors:     cve.threat_actors  || [],
      ransomware_groups: cve.ransomware     || [],
      campaign_activity: cve.in_kev ? 'Confirmed exploitation by threat actors. Treat as actively compromised until patched.' : 'Monitor threat intel feeds for emerging exploit activity.',
    },

    remediation: {
      immediate_actions: [
        `Apply vendor patch immediately: ${cve.patch_url || 'Check vendor security advisory'}`,
        'Isolate vulnerable systems from internet-facing exposure if patching is delayed',
        'Enable enhanced logging for exploitation indicators',
        `Block known IOCs associated with ${cve.id}`,
      ],
      patch_info:    cve.patch_version ? `Update to version ${cve.patch_version} or later` : 'Apply latest security patches from vendor',
      workaround:    cve.workaround    || 'Restrict network access to affected service; apply WAF rules if patch unavailable.',
      detection:     cve.detection     || 'Monitor for unusual process execution, network connections, and authentication events.',
      sigma_rule:    `title: Exploitation Attempt ${cve.id}\nstatus: experimental\nlogsource:\n  category: network\ndetection:\n  keywords:\n    - '${cve.id}'\n  condition: keywords`,
    },

    references: [
      { label: 'NVD Entry',         url: `https://nvd.nist.gov/vuln/detail/${cve.id}` },
      { label: 'CISA KEV',          url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      { label: 'MITRE ATT&CK',      url: `https://attack.mitre.org/techniques/${(cve.mitre_techniques || ['T1190'])[0]?.replace('.', '/')}` },
      ...(cve.vendor_advisory ? [{ label: 'Vendor Advisory', url: cve.vendor_advisory }] : []),
    ],

    seo: {
      slug:        `${cve.id?.toLowerCase()}-advisory-${new Date().getFullYear()}`,
      meta_title:  `${cve.id} Security Advisory | CYBERDUDEBIVASH`,
      meta_desc:   `${badge.label} severity vulnerability ${cve.id}. CVSS ${cve.cvss || 7.5}. Technical analysis, IOCs, and remediation guidance.`,
      keywords:    [cve.id, 'CVE', 'vulnerability', 'security advisory', cve.affected_product || 'cybersecurity', 'patch', badge.label.toLowerCase()],
      og_image:    `https://cyberdudebivash.in/og-image.png`,
    },

    generated_by:  'CYBERDUDEBIVASH AI Security Hub v20.0',
    generated_at:  new Date().toISOString(),
    author:        'Sentinel APEX Threat Intelligence Team',
    publication:   'cyberdudebivash.in',
  };
}

// ─── Template: Blog Post ──────────────────────────────────────────────────────
function buildBlogPostTemplate(topic, cve = null, sector = 'general') {
  const title  = cve
    ? `${cve.id}: What You Need to Know and How to Stay Protected`
    : `${topic}: A Complete Cybersecurity Guide for ${new Date().getFullYear()}`;

  const slug   = title.toLowerCase()
    .replace(/[^a-z0-9 ]/g, '')
    .replace(/\s+/g, '-')
    .slice(0, 80);

  const intro  = cve
    ? `A critical vulnerability has been disclosed — **${cve.id}** — affecting ${cve.affected_product || 'widely-used software'}. ` +
      `With a CVSS score of ${cve.cvss || 7.5} and ${cve.in_kev ? 'confirmed active exploitation' : 'growing threat actor interest'}, ` +
      `organizations must act immediately. This article provides a technical breakdown, real-world exploitation scenarios, and actionable hardening steps.`
    : `In today's threat landscape, ${topic} represents one of the most significant challenges for security teams. ` +
      `This comprehensive guide covers everything you need to know — from understanding the attack vectors to implementing enterprise-grade defenses.`;

  const sections = cve ? [
    {
      heading: `What is ${cve.id}?`,
      content: cve.description || `${cve.id} is a ${cve.cvss >= 9 ? 'critical' : 'high'}-severity vulnerability in ${cve.affected_product || 'affected software'} that enables ${cve.impact || 'unauthorized access or remote code execution'}.`,
    },
    {
      heading: 'Who Is at Risk?',
      content: `Any organization running ${cve.affected_product || 'the affected product'} ${cve.affected_versions ? 'version ' + cve.affected_versions.join(', ') : 'without the latest security patches'} is potentially vulnerable. ` +
               `This includes enterprises, SMBs, and cloud-hosted instances.`,
    },
    {
      heading: 'How Attackers Are Exploiting This',
      content: `Threat actors ${cve.in_kev ? 'are actively exploiting' : 'could exploit'} ${cve.id} through crafted HTTP requests targeting the vulnerable endpoint. ` +
               `Successful exploitation grants attackers ${cve.impact || 'full control of the affected system'}. ` +
               (cve.ransomware?.length ? `Known ransomware groups including ${cve.ransomware.join(', ')} have been observed leveraging this vulnerability.` : ''),
    },
    {
      heading: 'Detection and Monitoring',
      content: `Security teams should monitor for: unusual process spawning from web server processes, outbound connections to unknown IPs post-exploitation, ` +
               `authentication events with escalated privileges, and file system modifications in system directories. ` +
               `Deploy the Sigma rule included in our full advisory for automated detection.`,
    },
    {
      heading: 'Remediation Steps',
      content: `**Immediate (0–24 hours):** Apply the vendor patch ${cve.patch_version ? `(version ${cve.patch_version})` : ''}. ` +
               `If patching is not immediately possible, implement network-level restrictions to limit exposure. ` +
               `**Short-term (24–72 hours):** Conduct threat hunting for signs of prior compromise. ` +
               `Review authentication logs for anomalous access patterns.`,
    },
  ] : [
    {
      heading: `Understanding ${topic}`,
      content: `${topic} is a growing concern for security professionals. Understanding the fundamentals is the first step toward building effective defenses.`,
    },
    {
      heading: 'Top Attack Vectors',
      content: `Attackers leverage multiple techniques to exploit ${topic.toLowerCase()} weaknesses, including social engineering, unpatched vulnerabilities, and misconfigured services.`,
    },
    {
      heading: 'Enterprise Defense Framework',
      content: `A layered security approach is essential. Combine preventive controls with detective capabilities and a well-practiced response playbook.`,
    },
    {
      heading: 'Threat Intelligence Integration',
      content: `Integrate real-time threat intelligence feeds from platforms like CYBERDUDEBIVASH Sentinel APEX to stay ahead of emerging ${topic.toLowerCase()} threats.`,
    },
    {
      heading: 'Conclusion',
      content: `${topic} requires continuous attention from security teams. Use AI-powered tools to automate detection and response, and ensure your team is trained on the latest attack patterns.`,
    },
  ];

  return {
    title,
    slug,
    excerpt: intro.slice(0, 160),
    intro,
    sections,
    cve_ref:   cve?.id || null,
    tags:      cve
      ? [cve.id, 'CVE', 'Vulnerability', cve.affected_product || 'Security', 'Patch', sector]
      : [topic, 'Cybersecurity', 'Threat Intelligence', sector, 'Security Guide'],
    category:  cve ? 'CVE Advisory' : 'Security Guide',
    read_time: `${Math.max(3, Math.round(sections.length * 1.5))} min`,
    seo: {
      meta_title:  `${title} | CYBERDUDEBIVASH AI Security`,
      meta_desc:   intro.slice(0, 155),
      canonical:   `https://cyberdudebivash.in/blog/${slug}`,
      og_image:    `https://cyberdudebivash.in/og-image.png`,
      schema_type: 'Article',
    },
    cta: {
      text:  cve ? `Run a Free ${cve.id} Exposure Check` : `Scan Your Infrastructure for Free`,
      route: '/tools',
    },
    author:       'Sentinel APEX Threat Intelligence',
    published_at: new Date().toISOString(),
    platform:     'CYBERDUDEBIVASH AI Security Hub v20.0',
  };
}

// ─── Template: Threat Bulletin ────────────────────────────────────────────────
function buildBulletinTemplate(recentCVEs = [], topIOCs = []) {
  const week   = `Week of ${new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' })}`;
  const critical = recentCVEs.filter(c => (c.cvss || 0) >= 9.0);
  const high     = recentCVEs.filter(c => (c.cvss || 0) >= 7.0 && (c.cvss || 0) < 9.0);

  return {
    title:       `Threat Intelligence Bulletin — ${week}`,
    period:      week,
    threat_level: critical.length > 2 ? 'CRITICAL' : (critical.length > 0 ? 'HIGH' : 'MEDIUM'),

    executive_summary:
      `This week's threat landscape shows ${critical.length} critical and ${high.length} high-severity vulnerabilities requiring immediate attention. ` +
      `Ransomware activity remains elevated. State-sponsored APT groups continue targeting ${critical.length > 1 ? 'financial and critical infrastructure sectors' : 'technology and government sectors'}.`,

    top_vulnerabilities: recentCVEs.slice(0, 5).map(c => ({
      id:       c.id || c.cve_id,
      title:    c.title || c.description?.slice(0, 80) || 'Unknown',
      cvss:     c.cvss || c.cvss_score || 0,
      severity: severityBadge(c.cvss || 0).label,
      in_kev:   c.in_kev || false,
      action:   c.in_kev ? 'PATCH IMMEDIATELY' : 'Patch within 30 days',
    })),

    top_iocs: topIOCs.slice(0, 10).map(ioc => ({
      type:       ioc.type  || 'ip',
      value:      ioc.value || ioc.ioc_value || '',
      confidence: ioc.confidence || 75,
      threat:     ioc.threat_type || 'malware',
    })),

    threat_actor_spotlight: {
      name:        'APT-UNKNOWN',
      activity:    'Increased reconnaissance targeting exposed RDP and VPN services',
      ttps:        ['T1190 — Exploit Public-Facing Application', 'T1078 — Valid Accounts', 'T1486 — Ransomware'],
      target_sectors: ['Finance', 'Healthcare', 'Government'],
      confidence:  'MEDIUM',
    },

    recommended_actions: [
      { priority: 1, action: 'Patch all CISA KEV vulnerabilities within 24–72 hours',  impact: 'CRITICAL' },
      { priority: 2, action: 'Review and rotate privileged credentials',                 impact: 'HIGH'     },
      { priority: 3, action: 'Audit internet-exposed RDP, VPN, and management ports',    impact: 'HIGH'     },
      { priority: 4, action: 'Enable MFA on all admin and remote access accounts',       impact: 'HIGH'     },
      { priority: 5, action: 'Update EDR/AV signatures and review SIEM detection rules', impact: 'MEDIUM'   },
    ],

    statistics: {
      new_cves_this_week:    recentCVEs.length,
      critical_cves:         critical.length,
      actively_exploited:    recentCVEs.filter(c => c.in_kev).length,
      new_iocs_ingested:     topIOCs.length,
      threat_feeds_active:   9,
    },

    seo: {
      slug:       `threat-bulletin-${new Date().toISOString().slice(0,10)}`,
      meta_title: `Weekly Threat Intelligence Bulletin | CYBERDUDEBIVASH`,
      meta_desc:  `This week's top cybersecurity threats, vulnerabilities, and IOCs. ${critical.length} critical CVEs. Updated ${new Date().toLocaleDateString()}.`,
    },

    subscribe_cta: {
      text:    'Subscribe to Weekly Threat Bulletins',
      channel: 'https://t.me/cyberdudebivashSentinelApex',
    },

    generated_by:  'Sentinel APEX Threat Intelligence Engine',
    generated_at:  new Date().toISOString(),
    valid_until:   new Date(Date.now() + 7 * 86400000).toISOString(),
    platform:      'CYBERDUDEBIVASH AI Security Hub v20.0',
  };
}

// ─── AI Narrative Enhancer ────────────────────────────────────────────────────
async function enhanceWithAI(env, prompt, fallback) {
  if (!env?.AI) return fallback;
  try {
    const resp = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 400,
    });
    return resp?.response?.trim() || fallback;
  } catch {
    return fallback;
  }
}

// ─── Handler: POST /api/authority/cve-report ─────────────────────────────────
export async function handleCVEReport(request, env, authCtx) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { cve_id, cvss, title, description, affected_product, in_kev, patch_version,
          mitre_techniques, threat_actors, sector = 'technology' } = body;

  if (!cve_id) {
    return Response.json({ error: 'cve_id is required (e.g. "CVE-2024-1234")' }, { status: 400 });
  }

  // Check KV cache first
  const cacheKey = `authority:cve:${cve_id}:${new Date().toISOString().slice(0, 10)}`;
  if (env?.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(cacheKey).catch(() => null);
    if (cached) { try { return Response.json({ ...JSON.parse(cached), cached: true }); } catch {} }
  }

  const cveData = {
    id: cve_id, cvss: parseFloat(cvss || 7.5), title, description,
    affected_product, in_kev: Boolean(in_kev), patch_version,
    mitre_techniques: mitre_techniques || ['T1190'],
    threat_actors: threat_actors || [],
  };

  const report = buildCVEReportTemplate(cveData);

  // Optionally enhance executive summary with AI
  if (env?.AI && authCtx?.tier !== 'FREE') {
    const aiPrompt = `You are a senior threat intelligence analyst at a top cybersecurity firm.
Write a 2-paragraph executive summary for ${cve_id} (CVSS ${cvss || 7.5}) affecting ${affected_product || 'enterprise software'}.
Para 1: what the vulnerability is and why it matters.
Para 2: who is at risk and what they should do right now.
Be authoritative, specific, and concise. No filler.`;
    report.executive_summary = await enhanceWithAI(env, aiPrompt, report.executive_summary);
  }

  // Cache for 24 hours
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(report), { expirationTtl: 86400 }).catch(() => {});
  }

  return Response.json(report);
}

// ─── Handler: POST /api/authority/blog-post ───────────────────────────────────
export async function handleBlogPost(request, env, authCtx) {
  let body;
  try { body = await request.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { topic, cve_id, cvss, affected_product, description, in_kev,
          sector = 'technology', language = 'en' } = body;

  if (!topic && !cve_id) {
    return Response.json({ error: 'Provide either "topic" (string) or "cve_id" for CVE-based post' }, { status: 400 });
  }

  const cacheKey = `authority:blog:${cve_id || topic?.slice(0,30).replace(/\s/g,'-')}:${new Date().toISOString().slice(0,10)}`;
  if (env?.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(cacheKey).catch(() => null);
    if (cached) { try { return Response.json({ ...JSON.parse(cached), cached: true }); } catch {} }
  }

  const cveData = cve_id ? {
    id: cve_id, cvss: parseFloat(cvss || 7.5), affected_product, description, in_kev: Boolean(in_kev),
  } : null;

  const post = buildBlogPostTemplate(topic || cve_id, cveData, sector);

  // AI-enhanced intro for paid tiers
  if (env?.AI && authCtx?.tier !== 'FREE' && authCtx?.tier !== 'STARTER') {
    const aiPrompt = cve_id
      ? `Write a compelling 3-sentence intro paragraph for a cybersecurity blog post about ${cve_id}. ` +
        `Mention the severity (CVSS ${cvss}), the product affected (${affected_product}), and urgency. ` +
        `Tone: authoritative expert. Start directly without "In today's" or "In conclusion".`
      : `Write a compelling 3-sentence intro for a cybersecurity article titled "${topic}". ` +
        `Tone: authoritative expert. Target audience: CISOs and security engineers.`;
    post.intro = await enhanceWithAI(env, aiPrompt, post.intro);
  }

  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(post), { expirationTtl: 86400 }).catch(() => {});
  }

  return Response.json(post);
}

// ─── Handler: GET /api/authority/bulletin ────────────────────────────────────
export async function handleThreatBulletin(request, env, authCtx) {
  const cacheKey = `authority:bulletin:${new Date().toISOString().slice(0, 10)}`;

  if (env?.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get(cacheKey).catch(() => null);
    if (cached) { try { return Response.json({ ...JSON.parse(cached), cached: true }); } catch {} }
  }

  // Pull recent CVEs from D1 if available
  let recentCVEs = [];
  let topIOCs    = [];
  if (env?.SECURITY_HUB_DB) {
    try {
      const cveRows = await env.SECURITY_HUB_DB.prepare(
        `SELECT cve_id as id, title, cvss_score as cvss, epss_score as epss,
                in_kev, description
         FROM threat_intel
         WHERE type = 'vulnerability'
         ORDER BY cvss_score DESC, ingested_at DESC
         LIMIT 10`
      ).all();
      recentCVEs = cveRows?.results || [];
    } catch {}

    try {
      const iocRows = await env.SECURITY_HUB_DB.prepare(
        `SELECT type, value, confidence, threat_type
         FROM threat_intel
         WHERE type IN ('ip','domain','hash','url')
         ORDER BY confidence DESC, ingested_at DESC
         LIMIT 15`
      ).all();
      topIOCs = iocRows?.results || [];
    } catch {}
  }

  const bulletin = buildBulletinTemplate(recentCVEs, topIOCs);

  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(bulletin), { expirationTtl: 3600 * 6 }).catch(() => {});
  }

  return Response.json(bulletin);
}

// ─── Handler: GET /api/authority/stats ───────────────────────────────────────
export async function handleAuthorityStats(request, env) {
  let stats = {
    reports_generated_today:  0,
    blog_posts_generated_today: 0,
    bulletins_published:       0,
    total_content_pieces:      0,
    top_cve_this_week:         null,
    engine:                    'Authority Engine v20.0',
    ai_enhanced:               Boolean(env?.AI),
    platform:                  'CYBERDUDEBIVASH AI Security Hub v20.0',
    generated_at:              new Date().toISOString(),
  };

  if (env?.SECURITY_HUB_KV) {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const [rptRaw, blogRaw, bltnRaw] = await Promise.all([
        env.SECURITY_HUB_KV.get(`authority:counter:report:${today}`).catch(() => null),
        env.SECURITY_HUB_KV.get(`authority:counter:blog:${today}`).catch(() => null),
        env.SECURITY_HUB_KV.get(`authority:counter:bulletin:${today}`).catch(() => null),
      ]);
      stats.reports_generated_today    = parseInt(rptRaw  || '0', 10);
      stats.blog_posts_generated_today = parseInt(blogRaw || '0', 10);
      stats.bulletins_published        = parseInt(bltnRaw || '1', 10);
    } catch {}
  }

  return Response.json(stats);
}
