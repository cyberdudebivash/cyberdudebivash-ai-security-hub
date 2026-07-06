/* CEAP/CIP lock: footer "API Docs" link must point to the real docs page.
 *
 * Commercial-readiness sweep (2026-07-06): the "📡 API Docs" footer link on
 * seven customer-facing pages (index, about, contact, services, tools,
 * booking, intel) pointed to `/api` — a bare path with no trailing slash.
 * This Worker's Cloudflare zone route is `cyberdudebivash.in/api/*`, which
 * requires the trailing slash to match; every click 404'd, served by a
 * stale non-Worker responder rather than this codebase. `/api-docs` is the
 * real, working, human-readable documentation page every page already
 * shipped. This suite fails the build if the dead pattern returns on any
 * public page.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const FRONTEND = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../frontend');
const htmlPages = readdirSync(FRONTEND).filter((f) => f.endsWith('.html'));

describe('Footer "API Docs" link integrity', () => {
  it('no public page links to the dead, route-mismatched bare /api path', () => {
    for (const page of htmlPages) {
      const html = readFileSync(path.join(FRONTEND, page), 'utf8');
      expect(html, `${page} must not use the dead href="/api" pattern`).not.toContain('href="/api"');
    }
  });

  it('every page carrying the "API Docs" label links to a real docs page, not the bare API root', () => {
    for (const page of htmlPages) {
      const html = readFileSync(path.join(FRONTEND, page), 'utf8');
      const idx = html.indexOf('API Docs</a>');
      if (idx === -1) continue;
      const tag = html.slice(html.lastIndexOf('<a ', idx), idx);
      // Either the canonical extensionless form or the legacy .html form is
      // fine — both resolve (the latter via a 308 to the former). The bug was
      // the bare `/api` root, which 404s because the Worker's Cloudflare
      // route (`cyberdudebivash.in/api/*`) never matches a path without a
      // trailing slash.
      expect(tag, `${page} "API Docs" link must point to /api-docs`).toMatch(/href="\/api-docs(\.html)?"/);
    }
  });
});
