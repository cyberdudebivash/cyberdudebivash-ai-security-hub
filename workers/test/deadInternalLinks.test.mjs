/* CEAP/CIP lock: no public page links to a known-dead internal path.
 *
 * Commercial-readiness sweep (2026-07-06): a direct crawl of every internal
 * href across frontend/*.html against live production turned up dead links
 * across 22 pages — most were the right word/slug but the wrong exact path
 * (missing a trailing slash the Worker's Cloudflare route requires, a
 * renamed page, or a stale `.html`-less/`.html`-ful form). Two clusters
 * matter most commercially: the footer "Privacy"/"Terms" links (a security
 * vendor's own legal/trust pages) 404'd on five public pages, and several
 * "Dashboard"/upgrade CTAs 404'd on six pages. Exact per-file evidence:
 * CUSTOMER_OBJECTION_REGISTER.md OBJ-13.
 *
 * This suite locks the exact dead patterns found so they cannot silently
 * return via a copy-pasted template. It is deliberately a denylist of
 * observed dead paths, not a general crawler — see the recommended action
 * in PRODUCTION_HEALTH_SCORECARD.md for the broader, unverified remainder
 * (sitemap.html still lists a few pages that were never built:
 * /affiliate-hub, /developer-portal, /enterprise/welcome,
 * /enterprise/onboarding, /enterprise/contacts, /mssp-workspace).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const FRONTEND = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../frontend');
const htmlPages = readdirSync(FRONTEND).filter((f) => f.endsWith('.html'));
const allHtml = () => htmlPages.map((page) => [page, readFileSync(path.join(FRONTEND, page), 'utf8')]);

// Exact dead hrefs found and fixed this cycle (OBJ-13). Any exact match is a regression.
const DEAD_HREFS = [
  'href="/api"',            // bare /api 404s — Cloudflare route requires a trailing slash
  'href="/privacy"',        // real page is /privacy-policy
  'href="/terms"',          // real page is /terms-of-service
  'href="/privacy.html"',   // real page is /privacy-policy.html
  'href="/terms.html"',     // real page is /terms-of-service.html
  'href="/dashboard"',      // real page is /user-dashboard
  'href="/dashboard.html"', // real page is /user-dashboard.html
  'href="/login"',          // no such route — login lives at /user-dashboard.html
  'href="/zero-trust"',     // real page is /zero-trust-security
  'href="/compliance"',     // real page is /compliance-management
  'href="/mssp-dashboard.html"', // real page is /mssp-command-center.html
  'href="/cve-hub"',        // real page is /cve/
  'href="/customer-success"', // real page is /customer-success-dashboard
  'href="/keys"',           // no such route — key management lives at /user-dashboard.html
];

describe('No public page links to a known-dead internal path (OBJ-13)', () => {
  for (const dead of DEAD_HREFS) {
    it(`no page uses the dead pattern ${dead}`, () => {
      for (const [page, html] of allHtml()) {
        expect(html, `${page} must not use ${dead}`).not.toContain(dead);
      }
    });
  }

  it('every page carrying the "API Docs" label links to a real docs page, not the bare API root', () => {
    for (const [page, html] of allHtml()) {
      const idx = html.indexOf('API Docs</a>');
      if (idx === -1) continue;
      const tag = html.slice(html.lastIndexOf('<a ', idx), idx);
      // Either the canonical extensionless form or the legacy .html form is fine — both
      // resolve (the latter via a 308 to the former).
      expect(tag, `${page} "API Docs" link must point to /api-docs`).toMatch(/href="\/api-docs(\.html)?"/);
    }
  });
});
