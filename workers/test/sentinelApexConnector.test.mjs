/* Sentinel APEX connector — wires CYBERDUDEBIVASH's sister threat-intel
 * platform (https://intel.cyberdudebivash.com) into the live cron pipeline
 * (runIngestion in threatIngestion.js) as the highest-priority source.
 *
 * Fixture below mirrors the REAL shape of a live response from
 * GET https://intel.cyberdudebivash.com/api/v1/intel/latest.json (verified
 * directly before writing this connector — see the field-by-field notes in
 * fetchSentinelAPEX's header comment for what was checked and why each
 * mapping decision was made, e.g. epss_score on this feed is a 0–100
 * percentage, not the 0–1 probability every other row in threat_intel uses).
 *
 * Uses a stub global fetch + in-memory D1/KV, matching this repo's existing
 * threatIngestion.js test conventions (see ingestionBackfill.test.mjs) —
 * nothing hits the network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  fetchSentinelAPEX, runIngestion, deduplicateEntries,
} from '../src/services/threatIngestion.js';

// ── Fixture — shaped exactly like a real /api/v1/intel/latest.json response ──
const SENTINEL_APEX_JSON = {
  schema_version: '1.0',
  count: 4,
  items: [
    // A KEV-confirmed CVE — the highest-signal case.
    {
      id: 'intel--cbdaf51a538990cb',
      title: 'U.S. CISA adds a Cisco IOS flaw to its Known Exploited Vulnerabilities catalog',
      description: 'CISA added a Cisco IOS flaw, tracked as CVE-2008-4128, to its KEV catalog.',
      source_url: 'https://securityaffairs.com/195262/example.html',
      published_at: '2026-07-13T18:05:08Z',
      severity: 'CRITICAL',
      tlp: 'TLP:AMBER',
      actor_tag: 'UNC-CDB-INGEST',
      cve_id: 'CVE-2008-4128',
      cvss_score: 4.3,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
      epss_score: 12.04, // real feed: percentage scale, NOT 0-1 — must never land in entry.epss_score
      epss: '12.04%',
      kev_present: true,
      affected_products: [],
      _score_details: { kev: true, active_exploit: false, ransomware: false, zero_day: false, cvss: 7, epss: null },
    },
    // A plain CVE item, no KEV, ordinary confidence — the common case.
    {
      id: 'intel--86589890317832a8c76f5667',
      title: 'CVE-2026-58228 - Scheme validation bypass in Phoenix.LiveView.Utils leads to XSS via <.link>',
      description: 'A scheme validation bypass allows XSS via the <.link> component.',
      source_url: 'https://cvefeed.io/vuln/detail/CVE-2026-58228',
      published_at: '2026-07-13T18:04:30Z',
      severity: 'LOW',
      tlp: 'TLP:GREEN',
      actor_tag: 'CDB-UNATTR-CVE',
      cve_id: 'CVE-2026-58228',
      cvss_score: 6.1,
      cvss_vector: null,
      epss_score: null,
      kev_present: false,
      affected_products: ['Phoenix.LiveView'],
      _score_details: { kev: false, active_exploit: false, ransomware: false, zero_day: false, cvss: 6.1, epss: null },
    },
    // TLP:RED — must be excluded entirely (no-further-disclosure).
    {
      id: 'intel--redsecret',
      title: 'CVE-2026-99999 - Restricted-disclosure vulnerability',
      description: 'Sensitive coordinated-disclosure details.',
      source_url: 'https://example.com/restricted',
      published_at: '2026-07-12T00:00:00Z',
      severity: 'HIGH',
      tlp: 'TLP:RED',
      actor_tag: 'UNC-CDB-INGEST',
      cve_id: 'CVE-2026-99999',
      cvss_score: 8.1,
      kev_present: false,
      affected_products: [],
    },
    // Narrative intel with no CVE (APT/breach report) — not vulnerability-shaped,
    // must be skipped rather than force-fit into a CVE-oriented table.
    {
      id: 'intel--narrative1',
      title: 'Turla Hackers Exploit SharePoint Flaw to Access Thousands of French User Accounts',
      description: 'An APT campaign narrative with no single tracked CVE identifier.',
      source_url: 'https://example.com/turla-campaign',
      published_at: '2026-07-11T00:00:00Z',
      severity: 'HIGH',
      tlp: 'TLP:GREEN',
      actor_tag: 'Turla (Snake / Venomous Bear)',
      kev_present: false,
      affected_products: [],
    },
  ],
};

function stubFetch() {
  return vi.fn(async (url) => {
    const json = (o) => ({ ok: true, headers: { get: () => 'application/json' }, json: async () => o, text: async () => JSON.stringify(o) });
    let host = '';
    try { host = new URL(String(url)).hostname; } catch {}
    if (host === 'intel.cyberdudebivash.com') return json(SENTINEL_APEX_JSON);
    return { ok: false, headers: { get: () => '' }, json: async () => ({}), text: async () => '' };
  });
}

let origFetch;
beforeEach(() => { origFetch = globalThis.fetch; globalThis.fetch = stubFetch(); });
afterEach(() => { globalThis.fetch = origFetch; });

describe('fetchSentinelAPEX', () => {
  it('normalizes real-shaped CVE items into the canonical entry shape', async () => {
    const entries = await fetchSentinelAPEX();
    const kevEntry = entries.find(e => e.id === 'CVE-2008-4128');
    expect(kevEntry).toBeTruthy();
    expect(kevEntry.source).toBe('sentinel_apex');
    expect(kevEntry.severity).toBe('CRITICAL');
    expect(kevEntry.cvss).toBe(4.3);
    expect(kevEntry.cvss_vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N');
    expect(kevEntry.exploit_status).toBe('confirmed'); // kev_present === true
    expect(kevEntry.known_ransomware).toBe(0); // _score_details.ransomware === false
    expect(kevEntry.published_at).toBe('2026-07-13');
  });

  it('never copies the feed\'s percentage-scale epss_score into the entry (would corrupt the 0-1 column)', async () => {
    const entries = await fetchSentinelAPEX();
    for (const e of entries) {
      expect(e).not.toHaveProperty('epss_score');
      expect(e).not.toHaveProperty('epss_percentile');
    }
  });

  it('excludes TLP:RED items entirely', async () => {
    const entries = await fetchSentinelAPEX();
    expect(entries.find(e => e.id === 'CVE-2026-99999')).toBeUndefined();
  });

  it('flags TLP:AMBER items with a tag rather than dropping them', async () => {
    const entries = await fetchSentinelAPEX();
    const kevEntry = entries.find(e => e.id === 'CVE-2008-4128');
    expect(JSON.parse(kevEntry.tags)).toContain('TLP-AMBER');
  });

  it('skips narrative intel items with no extractable CVE id', async () => {
    const entries = await fetchSentinelAPEX();
    expect(entries).toHaveLength(2); // only the two genuine CVE items
    expect(entries.find(e => /Turla/.test(e.title))).toBeUndefined();
  });

  it('excludes placeholder ingestion/unattributed actor markers from tags, but keeps real attributions', async () => {
    const entries = await fetchSentinelAPEX();
    const kevEntry = entries.find(e => e.id === 'CVE-2008-4128'); // actor_tag: UNC-CDB-INGEST
    const plainEntry = entries.find(e => e.id === 'CVE-2026-58228'); // actor_tag: CDB-UNATTR-CVE
    expect(JSON.parse(kevEntry.tags)).not.toContain('UNC-CDB-INGEST');
    expect(JSON.parse(plainEntry.tags)).not.toContain('CDB-UNATTR-CVE');
  });

  it('always tags entries with SentinelAPEX for provenance', async () => {
    const entries = await fetchSentinelAPEX();
    for (const e of entries) expect(JSON.parse(e.tags)).toContain('SentinelAPEX');
  });

  it('returns an empty array (not a throw) when the feed is unreachable', async () => {
    globalThis.fetch = vi.fn(async () => ({ ok: false, headers: { get: () => '' }, json: async () => ({}), text: async () => '' }));
    const entries = await fetchSentinelAPEX();
    expect(entries).toEqual([]);
  });
});

describe('Sentinel APEX is highest-priority via dedup push-order', () => {
  it('a later, lower-fidelity duplicate cannot overwrite the Sentinel APEX title/source for the same CVE', () => {
    const apexEntry = {
      id: 'CVE-2026-58228', title: 'Sentinel APEX title', severity: 'LOW', cvss: 6.1,
      description: 'apex description', source: 'sentinel_apex', tags: '["SentinelAPEX"]',
      exploit_status: 'unconfirmed',
    };
    const nvdDuplicate = {
      id: 'CVE-2026-58228', title: 'NVD title', severity: 'HIGH', cvss: 6.1,
      description: 'nvd description', source: 'nvd', tags: '["RCE"]',
      exploit_status: 'confirmed',
    };
    // Sentinel APEX pushed first (matches runIngestion's step 1b ordering).
    const [merged] = deduplicateEntries([apexEntry, nvdDuplicate]);
    expect(merged.title).toBe('Sentinel APEX title');       // base record wins
    expect(merged.source).toBe('sentinel_apex');             // attribution preserved
    expect(merged.severity).toBe('HIGH');                    // later source can still raise severity
    expect(merged.exploit_status).toBe('confirmed');         // later source can still confirm exploitation
    expect(JSON.parse(merged.tags)).toEqual(expect.arrayContaining(['SentinelAPEX', 'RCE'])); // tags union
  });
});

describe('runIngestion wires Sentinel APEX in as a real source', () => {
  function memDB() {
    const rows = new Map();
    const mk = (sql) => ({
      _sql: sql, _b: [],
      bind(...a) { this._b = a; return this; },
      async run() {
        if (/^\s*INSERT INTO threat_intel/i.test(sql) || /INSERT OR REPLACE INTO threat_intel/i.test(sql)) {
          const id = this._b[0];
          rows.set(id, { id, title: this._b[1], severity: this._b[2], source: this._b[6] });
        }
        return { success: true };
      },
      async all() { return { results: [] }; },
      async first() { return null; },
    });
    return {
      rows,
      prepare(sql) { return mk(sql); },
      async batch(stmts) { for (const s of stmts) await s.run(); return stmts.map(() => ({ success: true })); },
    };
  }
  function memKV() {
    const m = new Map();
    return { async get(k) { return m.has(k) ? m.get(k) : null; }, async put(k, v) { m.set(k, v); } };
  }

  it('includes sentinel_apex in the sources list and stores its CVEs', async () => {
    const env = { SECURITY_HUB_DB: memDB(), SECURITY_HUB_KV: memKV() };
    const result = await runIngestion(env);
    expect(result.success).toBe(true);
    expect(result.sources.some(s => s.startsWith('sentinel_apex('))).toBe(true);
    expect(env.SECURITY_HUB_DB.rows.has('CVE-2008-4128')).toBe(true);
    expect(env.SECURITY_HUB_DB.rows.get('CVE-2008-4128').source).toBe('sentinel_apex');
  }, 20000);
});
