/**
 * CYBERDUDEBIVASH AI Security Hub — SEO Feeds & Discovery Handler v42.0
 * GET /api/rss          → RSS 2.0 feed (threat intel + blog)
 * GET /api/atom         → Atom 1.0 feed
 * GET /api/feed.json    → JSON Feed 1.1
 * POST /api/indexnow    → IndexNow submission endpoint (internal)
 * GET /sitemap-dynamic.xml → Dynamic sitemap with real CVE count
 */

const SITE = {
  url:   'https://cyberdudebivash.in',
  name:  'CYBERDUDEBIVASH AI Security Hub',
  desc:  'AI-Native Cybersecurity Platform — Threat Intelligence, SOC Operations, AI Red Teaming',
  email: 'info@cyberdudebivash.in',
  lang:  'en-US',
  logo:  'https://cyberdudebivash.in/assets/images/logo.png',
  og:    'https://cyberdudebivash.in/og-image.png',
};

const BLOG_POSTS = [
  {
    id:          '6',
    title:       'Cisco Enterprise Onboarding: AI-Native SOC Implementation',
    link:        `${SITE.url}/blog/cisco-enterprise-soc-implementation`,
    published:   '2026-06-30T00:00:00Z',
    updated:     '2026-06-30T00:00:00Z',
    summary:     'How Cisco SOC teams implemented AI-native threat detection using CYBERDUDEBIVASH AI Security Hub — covering threat intelligence integration, SIEM export configuration, and DPDP Act compliance.',
    tags:        ['enterprise', 'SOC', 'AI security', 'Cisco', 'threat intelligence'],
    author:      'CyberDudeBivash Security Team',
  },
  {
    id:          '5',
    title:       'The Future of AI Cybersecurity: Autonomous Defense Systems',
    link:        `${SITE.url}/blog/ai-cybersecurity-future`,
    published:   '2026-06-20T00:00:00Z',
    updated:     '2026-06-20T00:00:00Z',
    summary:     'How AI-native security platforms are replacing traditional SIEM and SOAR solutions. Analysis of autonomous threat detection, LLM-powered incident response, and the evolution of SOC operations.',
    tags:        ['AI security', 'autonomous SOC', 'threat detection', 'machine learning'],
    author:      'CyberDudeBivash Security Team',
  },
  {
    id:          '4',
    title:       'What is CVE? Complete Guide to Common Vulnerabilities and Exposures',
    link:        `${SITE.url}/blog/what-is-cve`,
    published:   '2026-06-15T00:00:00Z',
    updated:     '2026-06-15T00:00:00Z',
    summary:     'Complete guide to CVE — what it is, how CVSS scoring works, how CISA KEV tracks exploited vulnerabilities, and how to use EPSS for exploit probability scoring in your vulnerability management program.',
    tags:        ['CVE', 'vulnerability management', 'CVSS', 'CISA KEV', 'EPSS'],
    author:      'CyberDudeBivash Security Team',
  },
  {
    id:          '3',
    title:       'OWASP Top 10 2024: Web Application Security Vulnerabilities Explained',
    link:        `${SITE.url}/blog/owasp-top-10-2024`,
    published:   '2026-06-10T00:00:00Z',
    updated:     '2026-06-10T00:00:00Z',
    summary:     'Detailed breakdown of OWASP Top 10 2024 vulnerabilities with real-world examples, detection methods, and remediation guidance for development and security teams.',
    tags:        ['OWASP', 'web security', 'injection', 'XSS', 'API security'],
    author:      'CyberDudeBivash Security Team',
  },
  {
    id:          '2',
    title:       'MITRE ATT&CK Framework: Complete Enterprise Guide for SOC Teams',
    link:        `${SITE.url}/blog/mitre-attack-framework-guide`,
    published:   '2026-06-05T00:00:00Z',
    updated:     '2026-06-05T00:00:00Z',
    summary:     'Comprehensive guide to using MITRE ATT&CK for threat hunting, detection engineering, red team operations, and security control gap analysis in enterprise environments.',
    tags:        ['MITRE ATT&CK', 'threat hunting', 'SOC', 'detection engineering'],
    author:      'CyberDudeBivash Security Team',
  },
  {
    id:          '1',
    title:       'Zero-Day Vulnerabilities Explained: Detection, Response and Prevention',
    link:        `${SITE.url}/blog/zero-day-vulnerabilities-explained`,
    published:   '2026-05-28T00:00:00Z',
    updated:     '2026-05-28T00:00:00Z',
    summary:     'How zero-day vulnerabilities are discovered, exploited, and defended against. Covers threat intelligence-driven detection, patch management priorities using EPSS scoring, and incident response playbooks.',
    tags:        ['zero-day', 'vulnerability', 'patch management', 'threat intelligence'],
    author:      'CyberDudeBivash Security Team',
  },
];

// ─── GET /api/rss — RSS 2.0 ──────────────────────────────────────────────────
export async function handleRSSFeed(request, env) {
  // Get recent threat intel items from D1
  let intelItems = [];
  if (env.DB) {
    try {
      const result = await env.DB.prepare(
        `SELECT id, title, description, cve_id, severity, published_date, cvss_score
         FROM threat_intel ORDER BY published_date DESC LIMIT 10`
      ).all();
      intelItems = result.results || [];
    } catch (_) {}
  }

  const now = new Date().toUTCString();

  const items = [
    ...BLOG_POSTS.map(p => `
    <item>
      <title><![CDATA[${p.title}]]></title>
      <link>${p.link}</link>
      <guid isPermaLink="true">${p.link}</guid>
      <description><![CDATA[${p.summary}]]></description>
      <pubDate>${new Date(p.published).toUTCString()}</pubDate>
      <author>${SITE.email} (${p.author})</author>
      ${p.tags.map(t => `<category>${t}</category>`).join('')}
    </item>`),
    ...intelItems.map(ti => `
    <item>
      <title><![CDATA[${ti.severity || 'ADVISORY'}: ${ti.cve_id || ti.title || 'Security Advisory'}]]></title>
      <link>${SITE.url}/cve/${ti.cve_id || ti.id}</link>
      <guid isPermaLink="true">${SITE.url}/cve/${ti.cve_id || ti.id}</guid>
      <description><![CDATA[${ti.description ? ti.description.slice(0, 500) : 'Security advisory details available on the platform.'} ${ti.cvss_score ? `CVSS: ${ti.cvss_score}` : ''}]]></description>
      <pubDate>${ti.published_date ? new Date(ti.published_date).toUTCString() : now}</pubDate>
      <category>Threat Intelligence</category>
      ${ti.severity ? `<category>${ti.severity}</category>` : ''}
    </item>`),
  ];

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
     xmlns:atom="http://www.w3.org/2005/Atom"
     xmlns:dc="http://purl.org/dc/elements/1.1/"
     xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:sy="http://purl.org/rss/1.0/modules/syndication/">
  <channel>
    <title>${SITE.name} — Security Intelligence Feed</title>
    <link>${SITE.url}</link>
    <description>${SITE.desc}</description>
    <language>en-us</language>
    <managingEditor>${SITE.email}</managingEditor>
    <webMaster>${SITE.email}</webMaster>
    <lastBuildDate>${now}</lastBuildDate>
    <pubDate>${now}</pubDate>
    <ttl>60</ttl>
    <image>
      <url>${SITE.logo}</url>
      <title>${SITE.name}</title>
      <link>${SITE.url}</link>
      <width>144</width>
      <height>144</height>
    </image>
    <atom:link href="${SITE.url}/api/rss" rel="self" type="application/rss+xml"/>
    <sy:updatePeriod>hourly</sy:updatePeriod>
    <sy:updateFrequency>1</sy:updateFrequency>
    <category>Cybersecurity</category>
    <category>AI Security</category>
    <category>Threat Intelligence</category>
    ${items.join('')}
  </channel>
</rss>`;

  return new Response(xml, {
    headers: {
      'Content-Type':  'application/rss+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// ─── GET /api/atom — Atom 1.0 ────────────────────────────────────────────────
export async function handleAtomFeed(request, env) {
  const now = new Date().toISOString();

  const entries = BLOG_POSTS.map(p => `
  <entry>
    <id>${p.link}</id>
    <title type="html"><![CDATA[${p.title}]]></title>
    <link rel="alternate" type="text/html" href="${p.link}"/>
    <published>${p.published}</published>
    <updated>${p.updated}</updated>
    <author><name>${p.author}</name><email>${SITE.email}</email></author>
    <summary type="html"><![CDATA[${p.summary}]]></summary>
    ${p.tags.map(t => `<category term="${t}"/>`).join('')}
  </entry>`).join('');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <id>${SITE.url}/</id>
  <title type="text">${SITE.name} — Security Intelligence</title>
  <subtitle type="text">${SITE.desc}</subtitle>
  <link rel="alternate" type="text/html" href="${SITE.url}"/>
  <link rel="self" type="application/atom+xml" href="${SITE.url}/api/atom"/>
  <updated>${now}</updated>
  <author><name>CyberDudeBivash Security Team</name><email>${SITE.email}</email></author>
  <generator uri="${SITE.url}" version="42.0">${SITE.name}</generator>
  <icon>${SITE.logo}</icon>
  <logo>${SITE.og}</logo>
  <rights>Copyright 2024-2026 CYBERDUDEBIVASH AI Security Hub</rights>
  ${entries}
</feed>`;

  return new Response(xml, {
    headers: {
      'Content-Type':  'application/atom+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  });
}

// ─── GET /api/feed.json — JSON Feed 1.1 ─────────────────────────────────────
export async function handleJSONFeed(request, env) {
  const feed = {
    version:      'https://jsonfeed.org/version/1.1',
    title:        `${SITE.name} — Security Intelligence`,
    home_page_url: SITE.url,
    feed_url:     `${SITE.url}/api/feed.json`,
    description:  SITE.desc,
    icon:         SITE.logo,
    favicon:      `${SITE.url}/favicon.ico`,
    language:     'en-US',
    authors: [{
      name:  'CyberDudeBivash Security Team',
      url:   SITE.url,
      avatar: SITE.logo,
    }],
    items: BLOG_POSTS.map(p => ({
      id:             p.link,
      url:            p.link,
      title:          p.title,
      content_text:   p.summary,
      summary:        p.summary,
      date_published: p.published,
      date_modified:  p.updated,
      authors:        [{ name: p.author }],
      tags:           p.tags,
    })),
  };

  return Response.json(feed, {
    headers: {
      'Content-Type':  'application/feed+json; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  });
}

// ─── GET /sitemap-dynamic.xml — real-time sitemap with live CVE count ────────
export async function handleDynamicSitemap(request, env) {
  let cveCount = 1625;
  if (env.DB) {
    try {
      const r = await env.DB.prepare('SELECT COUNT(*) as cnt FROM threat_intel').first();
      if (r?.cnt > 0) cveCount = r.cnt;
    } catch (_) {}
  }

  const today = new Date().toISOString().slice(0, 10);

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${SITE.url}/</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>${SITE.url}/intel</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>0.9</priority></url>
  <url><loc>${SITE.url}/cve-hub</loc><lastmod>${today}</lastmod><changefreq>daily</changefreq><priority>0.9</priority></url>
  <!-- Live CVE count: ${cveCount} advisories tracked -->
</urlset>`;

  return new Response(xml, {
    headers: {
      'Content-Type':  'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600',
    },
  });
}
