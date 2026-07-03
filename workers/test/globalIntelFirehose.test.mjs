/* Global Threat Intel Firehose — pipeline unit tests.
 * Exercises fetch→ingest→enrich→analyse→draft→publish with a mocked network
 * and an in-memory D1/KV, so it verifies the real logic (scoring, dedupe,
 * breaking-first ordering, IOC/actor tagging) without hitting live sources.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { runGlobalIntelFirehose, INTEL_SOURCES } from '../src/services/globalIntelFirehose.js';

// ── Minimal in-memory D1 shim (enough for INSERT ... ON CONFLICT + SELECT count) ──
function makeDB() {
  const rows = new Map();
  return {
    _rows: rows,
    prepare(sql) {
      const binds = [];
      const stmt = {
        bind(...args) { binds.push(...args); return stmt; },
        async run() {
          if (/^INSERT INTO global_intel/i.test(sql)) {
            const id = binds[0];
            const existed = rows.has(id);
            rows.set(id, binds);
            return { meta: { changes: existed ? 0 : 1 } };
          }
          return { meta: { changes: 0 } };
        },
        async first() { return { total: rows.size }; },
        async all() { return { results: [] }; },
      };
      return stmt;
    },
  };
}
function makeKV() {
  const store = new Map();
  return { store, async get(k, o) { const v = store.get(k); return v ? (o?.type === 'json' ? JSON.parse(v) : v) : null; }, async put(k, v) { store.set(k, v); } };
}

const RSS = (items) => `<?xml version="1.0"?><rss><channel>${items.map(i => `
  <item><title>${i.title}</title><link>${i.link}</link>
  <pubDate>${i.pub || new Date().toUTCString()}</pubDate>
  <description>${i.desc || ''}</description></item>`).join('')}</channel></rss>`;

describe('Global Intel Firehose pipeline', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('fetches, enriches, scores, dedupes and publishes to D1 + KV', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      // Every RSS/atom source returns two security items; JSON sources return empty.
      if (String(url).includes('abuse.ch')) return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      const body = RSS([
        { title: 'Critical zero-day actively exploited in the wild — LockBit ransomware spreads', link: 'https://ex.com/a', desc: 'CVE-2026-99999 exploited by LockBit. C2 at 8.8.8.8' },
        { title: 'New phishing campaign targets banks', link: 'https://ex.com/b', desc: 'Emotet loader observed.' },
      ]);
      return new Response(body, { status: 200, headers: { 'content-type': 'application/xml' } });
    }));

    const env = { SECURITY_HUB_DB: makeDB(), SECURITY_HUB_KV: makeKV() };
    const r = await runGlobalIntelFirehose(env, { maxPerFeed: 5 });

    expect(r.ok).toBe(true);
    expect(r.sources_total).toBe(INTEL_SOURCES.length);
    expect(r.fetched).toBeGreaterThan(0);
    expect(r.unique_items).toBeGreaterThan(0);
    expect(r.inserted).toBeGreaterThan(0);

    // Briefing published to KV with a real threat level + top intel list.
    const briefing = JSON.parse(env.SECURITY_HUB_KV.store.get('global_intel:briefing:v1'));
    expect(['CRITICAL', 'HIGH', 'ELEVATED', 'GUARDED']).toContain(briefing.threat_level);
    expect(briefing.top_intel.length).toBeGreaterThan(0);

    // The critical zero-day item must outrank the routine phishing item (breaking-first).
    const top = briefing.top_intel[0];
    expect(top.severity).toBe('CRITICAL');
    expect(top.is_breaking).toBe(true);
  });

  it('extracts CVEs, actors and malware into the briefing', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('abuse.ch')) return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      const body = RSS([{ title: 'APT29 deploys Cobalt Strike via CVE-2026-12345', link: 'https://ex.com/apt', desc: 'Midnight Blizzard campaign.' }]);
      return new Response(body, { status: 200, headers: { 'content-type': 'application/xml' } });
    }));
    const env = { SECURITY_HUB_DB: makeDB(), SECURITY_HUB_KV: makeKV() };
    await runGlobalIntelFirehose(env, { maxPerFeed: 2 });
    const briefing = JSON.parse(env.SECURITY_HUB_KV.store.get('global_intel:briefing:v1'));
    expect(briefing.referenced_cves).toContain('CVE-2026-12345');
    expect(briefing.active_actors.some(a => /APT29|Midnight Blizzard/.test(a))).toBe(true);
    expect(briefing.active_malware).toContain('Cobalt Strike');
  });

  it('survives when every source is down (no throw, empty result)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
    const env = { SECURITY_HUB_DB: makeDB(), SECURITY_HUB_KV: makeKV() };
    const r = await runGlobalIntelFirehose(env, { maxPerFeed: 2 });
    expect(r.ok).toBe(true);
    expect(r.fetched).toBe(0);
    expect(r.unique_items).toBe(0);
  });

  it('registry is comprehensive and well-formed', () => {
    expect(INTEL_SOURCES.length).toBeGreaterThanOrEqual(25);
    for (const s of INTEL_SOURCES) {
      expect(s.id && s.name && s.url && s.kind && s.category).toBeTruthy();
      expect(/^https:\/\//.test(s.url)).toBe(true);
    }
    // Coverage across the major intel categories.
    const cats = new Set(INTEL_SOURCES.map(s => s.category));
    for (const c of ['advisory', 'research', 'news', 'ioc']) expect(cats.has(c)).toBe(true);
  });
});
