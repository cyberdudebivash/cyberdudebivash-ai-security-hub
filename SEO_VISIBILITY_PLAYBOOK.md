# SEO & Global Visibility Playbook — CYBERDUDEBIVASH AI Security Hub

**Scope:** what makes https://cyberdudebivash.in maximally visible in search engines,
link previews, and the wider web — split honestly into what code has already done
and what only the owner can do. Per the Production Truth Law, every claim below is
verifiable against the live site or a named external console.

---

## 1. What the code now guarantees (verified by `scripts/seo-structure-lock.mjs`)

| Layer | State |
|---|---|
| Document structure | Homepage previously shipped a premature `</head></html>` that pushed **all** Open Graph, Twitter Card, and JSON-LD markup outside the document head — invisible or unreliable for Google's rich-result parser and every link-preview crawler. Fixed 2026-07-04; locked. |
| Rich results (JSON-LD) | Organization (full legal entity, postal address, contact points), WebSite + SearchAction, SoftwareApplication, FAQPage, BreadcrumbList, Service — all inside `<head>`, all valid JSON. |
| URL previews | `og:*` + `twitter:card` (summary_large_image, 1200×630 og-image.png/og-image-v2.png) on the homepage **and** on all 30 locked public pages, verified inside `<head>`. |
| Canonicals & descriptions | Every public page has exactly one canonical URL and a meta description. |
| Structured data coverage | 2026-07-12: every one of the 30 locked public pages now carries at least one JSON-LD block (AboutPage / ContactPage / CollectionPage / Service / WebPage / WebApplication as fits the page, plus a BreadcrumbList). Previously 19 sitemap-listed pages shipped zero JSON-LD — the lock script only validated blocks that existed, so a page with none silently passed. The check now fails on zero blocks, closing that gap for good. |
| Sitemaps | `sitemap-index.xml` → sitemap / blog / services / api / cve, all referenced from robots.txt, lastmod maintained. `ai-security-scorecard` and `cyber-signal-radar` — both complete, public tool pages — were missing from every sitemap file; added 2026-07-12. |
| Crawlability | robots.txt allows search crawlers; private dashboards are excluded from sitemaps. |

Run the lock any time: `node scripts/seo-structure-lock.mjs` (exit 0 = green).
It is the regression gate for this entire layer — run it in CI before deploy.

## 2. Owner actions — search engines (do once, ~1 hour total)

These cannot be done from the repository; they require account ownership.

1. **Google Search Console** (search.google.com/search-console)
   - Verify the **domain property** `cyberdudebivash.in` (DNS TXT record via Cloudflare).
   - Submit `https://cyberdudebivash.in/sitemap-index.xml`.
   - URL Inspection → `https://cyberdudebivash.in/` → **Request Indexing**
     (forces Google to re-crawl and pick up the repaired head — this is the single
     highest-impact action after this fix deploys).
   - Watch Coverage and Enhancements reports weekly (CORB input).
2. **Bing Webmaster Tools** (bing.com/webmasters) — import from Search Console,
   submit the same sitemap index. Bing feeds DuckDuckGo and Yahoo.
3. **IndexNow** — enable in Cloudflare (Websites → cyberdudebivash.in → Cache →
   Crawler Hints) for instant push-indexing to Bing/Yandex/Seznam on content change.

## 3. Owner actions — refresh stale preview caches (do after deploy)

Social platforms cache previews; the broken-head era preview may persist until purged:

- Facebook/WhatsApp: developers.facebook.com/tools/debug → enter URL → **Scrape Again**
- LinkedIn: linkedin.com/post-inspector → enter URL → Inspect
- X/Twitter: cards-dev.twitter.com/validator (or post the link once — X re-fetches)
- Telegram: message `@WebpageBot` with the URL to force a re-crawl

## 4. Owner actions — entity & brand presence (the "rich company listing")

The enhanced listing seen for large companies is a **Knowledge Panel**. It is earned
from corroborating entities, not markup alone. The Organization JSON-LD now carries
the legal name, address (29, Korai-Sukinda-Ramchandrapur Rd, Ragadi, Jajpur Road,
Odisha 755019), phone and contact email — Google cross-checks these against:

1. **Google Business Profile** — keep name/address/phone **byte-identical** to the
   site's Organization markup, set website to https://cyberdudebivash.in, post weekly.
2. **LinkedIn company page** — same NAP data, link to the site.
3. **Crunchbase / GitHub org profile / Medium** — consistent name + link back.
   (All are already in the Organization `sameAs` array — keep those URLs alive.)
4. **Wikidata entry** (optional, high leverage once the company has independent
   press coverage) — the strongest Knowledge-Panel signal that exists.

## 5. Ongoing visibility engine (weekly, feeds CIP)

- Publish CVE/threat write-ups on blog.cyberdudebivash.in linking to the relevant
  platform page — the CVE sitemap already gives each a crawlable URL; fresh,
  linked content is what compounds rankings worldwide.
- Cross-post summaries to Medium/LinkedIn with a canonical link back.
- Track in Search Console: impressions, average position for
  "AI security platform", "CVE threat intelligence", "MCP security scanner".
  These are the discovery-funnel KPIs; wire them into KPI_DASHBOARD.md once
  the first 28-day dataset exists.

## 6. What we deliberately did NOT do

- No fabricated ratings/reviews markup (Google penalty risk; removed in OBJ-09,
  still out).
- No keyword stuffing or hidden text (spam-policy violation → ranking loss).
- No paid-ads configuration from the repo — ad campaigns (Google Ads, LinkedIn Ads)
  are owner business decisions with budgets, not code artifacts.
