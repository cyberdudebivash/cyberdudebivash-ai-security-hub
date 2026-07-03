/* Live-feed freshness guard — locks the P0 fixes that stopped the intel feeds
 * looking frozen (Amazon/Microsoft escalation).
 *
 * ROOT CAUSES fixed:
 *  1. A "LIVE" feed asking for the freshest items (sort=recent/date/newest/…)
 *     fell back to severity ordering, pinning old high-CVSS 2024 CVEs to the top.
 *     → orderMap must map every recency alias to a published_at-first ORDER BY.
 *  2. The hot KV cache used a single shared key with no sort suffix, so a
 *     sort=recent request was served a severity-ordered cache written by a
 *     different request — defeating fix #1.
 *     → the hot cache key must include the sort order.
 *  3. The main-dashboard LIVE THREAT FEED sent no sort param (→ severity default).
 *     → the frontend must request a recency sort for the live feed.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');

describe('live-feed freshness — recency ordering is never lost to caching or defaults', () => {
  const ti = read('src/handlers/threatIntel.js');

  it('orderMap maps every recency alias to a published_at-first ordering', () => {
    const recencyAliases = ['date', 'recent', 'newest', 'latest', 'published'];
    for (const alias of recencyAliases) {
      // e.g.  recent:   recency,   or   date:     recency,
      const re = new RegExp(`\\b${alias}:\\s*recency\\b`);
      expect(re.test(ti), `orderMap.${alias} must resolve to recency ordering`).toBe(true);
    }
    // and `recency` itself must sort by published_at DESC first
    expect(/const recency\s*=\s*`published_at DESC/.test(ti)).toBe(true);
  });

  it('hot cache key is sort-aware (never a single shared key)', () => {
    // getFromKVCache / writeHotCache must namespace the hot key by sort order.
    expect(/HOT_CACHE_KEY\}:\$\{sortBy/.test(ti)).toBe(true);
    // and the read path must pass pagination.sortBy through
    expect(/getFromKVCache\(env,\s*true,\s*pagination\.sortBy\)/.test(ti)).toBe(true);
    expect(/writeHotCache\(env,[\s\S]*?pagination\.sortBy\)/.test(ti)).toBe(true);
  });

  it('main-dashboard LIVE THREAT FEED requests a recency sort', () => {
    const fe = read('../frontend/index.html');
    // loadThreatIntel builds params then sets sort to recent (or a filter override).
    expect(/params\.set\('sort',\s*filter\.sort\s*\|\|\s*'recent'\)/.test(fe)).toBe(true);
  });

  it('homepage dashboard surfaces the Global Threat Intel Firehose section', () => {
    const fe = read('../frontend/index.html');
    expect(/id="global-firehose"/.test(fe)).toBe(true);       // the section
    expect(/id="gfh-list"/.test(fe)).toBe(true);              // the card grid
    expect(/\/api\/global-intel\/briefing/.test(fe)).toBe(true); // wired to the briefing
    expect(/\/api\/global-intel\?limit=/.test(fe)).toBe(true);   // and the feed
  });
});
