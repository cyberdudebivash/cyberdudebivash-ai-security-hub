/* CEAP/CIP lock: SEO structured data must stay valid AND truthful.
 *
 * Discovery audit (2026-07-04, OBJ-09): the homepage shipped an
 * AggregateRating of "4.8 from 312 reviews" (and the marketplace "5 from 1")
 * with ZERO real customers — fabricated review markup violates both the
 * Verifiable-Statement Rule (ENGINEERING_STANDARDS §10) and Google's review
 * spam policy, which can suppress ALL rich results for the site. The
 * Organization block also lacked the registered legal entity and full
 * address, weakening knowledge-graph reconciliation with the owner's
 * Google Business Profile.
 *
 * This suite locks: every ld+json block parses; no review/rating markup
 * anywhere in customer-facing pages until real reviews exist; the
 * Organization carries the legal name + registered address; canonical +
 * og:image contracts hold and the og:image file actually exists.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const FRONTEND = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../frontend');
const pages = ['index.html', 'sentinel-apex-marketplace.html', 'mcp-security.html'];

const ldBlocks = (html) =>
  [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(m => m[1]);

describe('SEO structured data: valid and truthful', () => {
  it('every JSON-LD block on every audited page parses as valid JSON', () => {
    for (const p of pages) {
      const html = readFileSync(path.join(FRONTEND, p), 'utf8');
      const blocks = ldBlocks(html);
      expect(blocks.length, `${p} should carry structured data`).toBeGreaterThan(0);
      for (const [i, b] of blocks.entries()) {
        expect(() => JSON.parse(b), `${p} block ${i} must be valid JSON`).not.toThrow();
      }
    }
  });

  it('no fabricated review/rating markup anywhere (zero real customers)', () => {
    for (const p of pages) {
      const html = readFileSync(path.join(FRONTEND, p), 'utf8');
      expect(html.includes('AggregateRating'), `${p} must not carry AggregateRating`).toBe(false);
      expect(/"reviewCount"/.test(html), `${p} must not carry reviewCount`).toBe(false);
      expect(/"ratingValue"/.test(html), `${p} must not carry ratingValue`).toBe(false);
    }
  });

  it('Organization block carries the registered legal entity and address', () => {
    const html = readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    const org = ldBlocks(html).map(b => JSON.parse(b)).find(d => d['@type'] === 'Organization');
    expect(org).toBeTruthy();
    expect(org.legalName).toBe('CYBERDUDEBIVASH PRIVATE LIMITED');
    expect(org.address.postalCode).toBe('755019');
    expect(org.address.streetAddress).toContain('JAJPUR ROAD');
    expect(org.address.addressRegion).toBe('Odisha');
    expect(org.brand?.name).toBe('CYBERDUDEBIVASH AI SECURITY HUB');
  });

  it('canonical, og:image contract, and the image file itself all hold', () => {
    const html = readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    expect(html).toContain('rel="canonical"');
    const ogImage = html.match(/property="og:image"[^>]*|content="([^"]*og-image[^"]*)"[^>]*property="og:image"/);
    expect(html.includes('property="og:image"')).toBe(true);
    const imgUrl = html.match(/content="(https:\/\/cyberdudebivash\.in\/[^"]+\.png)"[^>]*property="og:image"/)?.[1]
                || html.match(/property="og:image"[^>]*content="(https:\/\/cyberdudebivash\.in\/[^"]+\.png)"/)?.[1];
    expect(imgUrl, 'og:image must be an absolute URL on the canonical host').toBeTruthy();
    const localFile = path.join(FRONTEND, new URL(imgUrl).pathname.slice(1));
    expect(existsSync(localFile), `og:image file must exist in frontend/ (${localFile})`).toBe(true);
  });

  it('preview copy contains no unverifiable claims', () => {
    const html = readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    const metas = [...html.matchAll(/<meta[^>]+(?:og:description|twitter:description)[^>]*>/g)].map(m => m[0]);
    for (const m of metas) {
      expect(/trusted by/i.test(m), 'no unverifiable "trusted by" claims in previews').toBe(false);
      expect(/\d{1,3},\d{3}\+/.test(m), 'no hardcoded live-count claims in static previews').toBe(false);
    }
  });
});
