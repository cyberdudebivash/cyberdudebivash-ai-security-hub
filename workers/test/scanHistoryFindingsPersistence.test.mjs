/* Threat Graph could never show relationship edges for any customer,
 * regardless of scan volume: a real scan generates rich findings (MITRE
 * ATT&CK mappings, CVSS, CWE), but scan_history never had anywhere to
 * persist them (confirmed: neither workers/src/lib/queue.js
 * insertD1History() nor workers/src/handlers/domain.js trackDomainScan()
 * wrote anything beyond summary fields, and the schema had no column for
 * it). Live-verified end state before this fix: every real scan produced
 * exactly one isolated "domain" node on the Threat Graph and zero edges.
 *
 * FIX: schema_migration_scan_history_findings_2026_07.sql adds a nullable
 * scan_history.findings column. Both write paths now issue a SEPARATE
 * best-effort UPDATE (distillFindingsForHistory()) after their existing,
 * unchanged INSERT — deliberately separate so a production deploy of this
 * code before the manually-gated migration has actually been applied can
 * never take the core history row down with it (the UPDATE just no-ops).
 * handleScanHistory() tries the richer SELECT first and falls back to the
 * original column list if the column doesn't exist yet, for the same
 * zero-regression-before-migration reason.
 *
 * Also fixes a latent bug this change would otherwise have started
 * triggering the moment findings actually started flowing: the Threat
 * Graph's per-finding loop declared `const cveId` inside the `if
 * (f.cve_id)` block, then referenced that same identifier from the
 * sibling `if (f.actor)` block — out of scope, a guaranteed ReferenceError
 * for any finding with an actor. Never surfaced before because
 * s.findings was always empty in production. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { distillFindingsForHistory, parsePersistedFindings } from '../src/lib/findingsSummary.js';
import { handleDomainScan } from '../src/handlers/domain.js';
import { handleScanHistory } from '../src/handlers/history.js';

const root = resolve(import.meta.dirname, '..');
const dashboardHtml = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

const REAL_FINDINGS = [
  { id: 'DOM-001', title: 'TLS/SSL & HSTS Configuration', severity: 'CRITICAL', cvss_base: 7.4, cwe_ids: ['CWE-295', 'CWE-326'], description: 'HSTS missing.' },
  { id: 'DOM-002', title: 'DNSSEC Validation', severity: 'HIGH', cvss_base: 6.8, cwe_ids: ['CWE-350'] },
];

describe('distillFindingsForHistory / parsePersistedFindings', () => {
  it('round-trips a compact summary through JSON', () => {
    const json = distillFindingsForHistory(REAL_FINDINGS);
    expect(typeof json).toBe('string');
    const parsed = parsePersistedFindings(json);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toMatchObject({ id: 'DOM-001', title: 'TLS/SSL & HSTS Configuration', severity: 'critical', cvss: 7.4, cwe_ids: ['CWE-295', 'CWE-326'] });
  });

  it('preserves cve_id/ip/actor when a module\'s findings carry them, without requiring them', () => {
    const json = distillFindingsForHistory([{ id: 'X', severity: 'high', cve_id: 'CVE-2026-1234', ip: '1.2.3.4', actor: 'APT-Fake' }]);
    const [parsed] = parsePersistedFindings(json);
    expect(parsed.cve_id).toBe('CVE-2026-1234');
    expect(parsed.ip).toBe('1.2.3.4');
    expect(parsed.actor).toBe('APT-Fake');
  });

  it('returns null for empty/missing findings (nothing to persist)', () => {
    expect(distillFindingsForHistory([])).toBeNull();
    expect(distillFindingsForHistory(undefined)).toBeNull();
    expect(distillFindingsForHistory(null)).toBeNull();
  });

  it('caps at 20 findings so one scan cannot bloat a row indefinitely', () => {
    const many = Array.from({ length: 50 }, (_, i) => ({ id: `F-${i}`, severity: 'low' }));
    const parsed = parsePersistedFindings(distillFindingsForHistory(many));
    expect(parsed).toHaveLength(20);
  });

  it('parsePersistedFindings tolerates missing/corrupt data instead of throwing', () => {
    expect(parsePersistedFindings(null)).toBeUndefined();
    expect(parsePersistedFindings('not json')).toBeUndefined();
    expect(parsePersistedFindings('{"not":"an array"}')).toBeUndefined();
  });
});

function makeReq(body) {
  return new Request('https://x/api/scan/domain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function cachedKV(domain, cachedResult) {
  const store = new Map();
  store.set(`scan:domain:${domain}`, JSON.stringify({ ...cachedResult, _cached_at: Date.now() }));
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, v); } };
}

// Records every prepared statement; optionally throws on SELECTs that
// reference a given column, to simulate the pre-migration production
// database where scan_history.findings doesn't exist yet.
function recordingDB({ missingColumn } = {}) {
  const inserts = [];
  return {
    inserts,
    prepare(sql) {
      if (missingColumn && new RegExp(`SELECT[\\s\\S]*${missingColumn}`).test(sql)) {
        return { bind() { return this; }, async run() { throw new Error(`no such column: ${missingColumn}`); }, async first() { throw new Error(`no such column: ${missingColumn}`); }, async all() { throw new Error(`no such column: ${missingColumn}`); } };
      }
      let bound = [];
      return {
        bind(...args) { bound = args; return this; },
        async run() { inserts.push({ sql, bound }); return { success: true, meta: { changes: 1 } }; },
        async first() { return null; },
        async all() { return { results: [] }; },
      };
    },
  };
}

describe('domain.js trackDomainScan() persists findings via a separate, best-effort UPDATE', () => {
  const cached = {
    module: 'domain', target: 'example.com', risk_score: 70, risk_level: 'HIGH',
    grade: 'D', data_source: 'live_dns', findings: REAL_FINDINGS,
  };

  it('issues the UPDATE with a distilled findings JSON after the existing INSERT', async () => {
    const db = recordingDB();
    const env = { DB: db, SECURITY_HUB_KV: cachedKV('example.com', cached) };
    const res = await handleDomainScan(makeReq({ target: 'example.com' }), env, { user_id: 'user-123', tier: 'FREE' });
    expect(res.status).toBe(200);

    const insertCall = db.inserts.find(i => /INSERT OR IGNORE INTO scan_history/.test(i.sql));
    const updateCall = db.inserts.find(i => /UPDATE scan_history SET findings/.test(i.sql));
    expect(insertCall).toBeTruthy();
    expect(updateCall).toBeTruthy();

    const [findingsJson, scanId, userId] = updateCall.bound;
    expect(userId).toBe('user-123');
    expect(scanId).toBeTruthy();
    const parsed = JSON.parse(findingsJson);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].id).toBe('DOM-001');
  });

  it('the core INSERT still succeeds even when the findings column does not exist yet (pre-migration safety)', async () => {
    const db = recordingDB({ missingColumn: 'findings' });
    const env = { DB: db, SECURITY_HUB_KV: cachedKV('example.com', cached) };
    const res = await handleDomainScan(makeReq({ target: 'example.com' }), env, { user_id: 'user-456', tier: 'FREE' });
    expect(res.status).toBe(200);
    const insertCall = db.inserts.find(i => /INSERT OR IGNORE INTO scan_history/.test(i.sql));
    expect(insertCall).toBeTruthy(); // unaffected by the UPDATE's failure
  });

  it('skips the UPDATE entirely when the scan had no findings (nothing to persist)', async () => {
    const db = recordingDB();
    const env = { DB: db, SECURITY_HUB_KV: cachedKV('example.com', { ...cached, findings: [] }) };
    const res = await handleDomainScan(makeReq({ target: 'example.com' }), env, { user_id: 'user-789', tier: 'FREE' });
    expect(res.status).toBe(200);
    const updateCall = db.inserts.find(i => /UPDATE scan_history SET findings/.test(i.sql));
    expect(updateCall).toBeUndefined();
  });
});

describe('workers/src/lib/queue.js insertD1History() follows the same shared, safe pattern', () => {
  const src = readFileSync(resolve(root, 'src/lib/queue.js'), 'utf8');

  it('imports and uses distillFindingsForHistory', () => {
    expect(src).toContain("import { distillFindingsForHistory }");
    const start = src.indexOf('async function insertD1History');
    const body = src.slice(start, start + 1800);
    expect(body).toContain('distillFindingsForHistory(scanResult.findings)');
  });

  it('issues the findings UPDATE as its own statement, in its own try/catch, after the INSERT', () => {
    const start = src.indexOf('async function insertD1History');
    const body = src.slice(start, start + 1800);
    const insertIdx = body.indexOf('INSERT INTO scan_history');
    const updateIdx = body.indexOf('UPDATE scan_history SET findings');
    expect(insertIdx).toBeGreaterThan(-1);
    expect(updateIdx).toBeGreaterThan(insertIdx);
    // Its own try/catch: a second `try {` appears between the two statements
    const between = body.slice(insertIdx, updateIdx);
    expect(between).toMatch(/}\s*catch\s*{}/); // the INSERT's own catch closes before the UPDATE begins
  });
});

describe('handleScanHistory() reads findings with a safe pre-migration fallback', () => {
  it('returns parsed findings on a row that has them', async () => {
    const db = {
      prepare(sql) {
        return {
          bind() { return this; },
          async all() {
            return { results: [{ scan_id: 'sc_1', target: 'example.com', module: 'domain', risk_score: 70, risk_level: 'HIGH', grade: 'D', data_source: 'live_dns', status: 'completed', scanned_at: '2026-07-11 00:00:00', findings: distillFindingsForHistory(REAL_FINDINGS) }] };
          },
        };
      },
    };
    const res = await handleScanHistory(new Request('https://x/api/history'), { DB: db }, { user_id: 'u1', identity: 'u1' });
    const body = await res.json();
    expect(body.scans[0].findings).toHaveLength(2);
    expect(body.scans[0].findings[0].id).toBe('DOM-001');
  });

  it('falls back to the pre-migration column list when the findings column does not exist, instead of losing D1 history to the KV shadow copy', async () => {
    let callCount = 0;
    const db = {
      prepare(sql) {
        const isRicher = sql.includes(', findings');
        return {
          bind() { return this; },
          async all() {
            callCount++;
            if (isRicher) throw new Error('no such column: findings');
            return { results: [{ scan_id: 'sc_2', target: 'example.com', module: 'domain', risk_score: 40, risk_level: 'LOW', grade: 'B', data_source: 'live_dns', status: 'completed', scanned_at: '2026-07-11 00:00:00' }] };
          },
        };
      },
    };
    const res = await handleScanHistory(new Request('https://x/api/history'), { DB: db }, { user_id: 'u1', identity: 'u1' });
    const body = await res.json();
    expect(callCount).toBe(2); // richer attempt, then fallback
    expect(body.scans).toHaveLength(1);
    expect(body.scans[0].target).toBe('example.com');
    expect(body.scans[0].findings).toBeUndefined();
  });
});

describe('Threat Graph (frontend) — real finding shapes now produce nodes and edges', () => {
  function fnBody(name, window = 3500) {
    const start = dashboardHtml.indexOf(`function ${name}`);
    return start === -1 ? '' : dashboardHtml.slice(start, start + window);
  }

  it('initThreatGraph() no longer references cveId out of its declaring block scope', () => {
    const body = fnBody('initThreatGraph');
    expect(body).toContain('let cveId = null;');
    // the assignment must happen before any reference to cveId in the actor branch
    const declIdx = body.indexOf('let cveId = null;');
    const actorEdgeIdx = body.indexOf('edges.push({ source: cveId || domId, target: actId })');
    expect(declIdx).toBeGreaterThan(-1);
    expect(actorEdgeIdx).toBeGreaterThan(declIdx);
  });

  it('adds a generic "finding" node/edge for findings with none of cve_id/ip/actor', () => {
    const body = fnBody('initThreatGraph');
    expect(body).toContain("!f.cve_id && !f.ip && !f.actor && (f.id || f.title)");
    expect(body).toContain("addNode(findId, f.title || f.id, 'finding'");
    expect(body).toContain('edges.push({ source: domId, target: findId })');
  });

  it('tgNodeColor()/tgNodeRadius() handle the new "finding" type with severity-based styling', () => {
    const colorBody = fnBody('tgNodeColor', 400);
    const radiusBody = fnBody('tgNodeRadius', 400);
    expect(colorBody).toContain("n.type === 'cve' || n.type === 'finding'");
    expect(radiusBody).toContain("(n.type === 'cve' || n.type === 'finding')");
  });

  it('the Threat Graph type filter now offers a Findings option', () => {
    expect(dashboardHtml).toContain('<option value="finding">Findings</option>');
  });
});
