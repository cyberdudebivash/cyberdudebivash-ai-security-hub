/* MYTHOS AI Analyst CVE grounding (Cert Phase 6 — AI honesty).
 *
 * /api/ai/chat is advertised on the homepage as a "SOC-grade conversational
 * analyst" doing "CVE Analysis + MITRE ATT&CK mapping". It is a template engine
 * (no LLM) — which is fine for rule scaffolds, but the analyze_cve branch used
 * to report EVERY CVE as "Critical Remote Code Execution / Active exploitation
 * confirmed / CISA KEV listed / 9.4/10" regardless of the real CVE. That is
 * fabricated intelligence about real vulnerabilities.
 *
 * The fix grounds analyze_cve in the platform's own threat_intel table and,
 * when a CVE is unknown to us, acknowledges the gap instead of inventing a
 * verdict. This suite verifies both paths against a real SQL engine.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAIChat, lookupCveIntel } from '../src/handlers/aiAnalysis.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function makeEnv() {
  const db = makeRealD1();
  db._sqlite.exec(`CREATE TABLE threat_intel (
    id TEXT PRIMARY KEY, severity TEXT, cvss REAL, title TEXT, description TEXT,
    source TEXT, published_at TEXT, exploit_status TEXT, known_ransomware INTEGER
  )`);
  db._sqlite.prepare(
    `INSERT INTO threat_intel (id,severity,cvss,title,description,source,published_at,exploit_status,known_ransomware) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run('CVE-2024-3400', 'CRITICAL', 10.0, 'PAN-OS GlobalProtect command injection',
        'Unauthenticated RCE in Palo Alto PAN-OS.', 'cisa_kev', '2024-04-12', 'KEV — active exploitation', 1);
  // A genuinely moderate CVE — the anti-fabrication regression case.
  db._sqlite.prepare(
    `INSERT INTO threat_intel (id,severity,cvss,title,description,source,published_at,exploit_status,known_ransomware) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run('CVE-2019-0555', 'MEDIUM', 5.5, 'Windows information disclosure',
        'Local information disclosure vulnerability.', 'nvd', '2019-01-08', null, 0);
  return { SECURITY_HUB_DB: db };
}

const chat = (env, message) => handleAIChat(
  new Request('https://x/api/ai/chat', { method: 'POST', body: JSON.stringify({ message, session_id: null }) }),
  env,
);

describe('lookupCveIntel', () => {
  it('returns the real row for a known CVE', async () => {
    const row = await lookupCveIntel(makeEnv(), 'cve-2024-3400');
    expect(row.severity).toBe('CRITICAL');
    expect(row.cvss).toBe(10.0);
  });
  it('returns null for an unknown CVE (no fabrication)', async () => {
    expect(await lookupCveIntel(makeEnv(), 'CVE-1999-9999')).toBeNull();
  });
});

describe('analyze_cve — grounded in real data', () => {
  it('reports the real CRITICAL/KEV facts for a known critical CVE', async () => {
    const d = await (await chat(makeEnv(), 'Tell me about CVE-2024-3400')).json();
    expect(d.intent).toBe('analyze_cve');
    expect(d.response).toContain('CVE-2024-3400');
    expect(d.response).toContain('CRITICAL');
    expect(d.response).toMatch(/CISA KEV/);
    expect(d.response).toMatch(/ransomware/i);
  });

  it('does NOT inflate a real MEDIUM CVE into a critical RCE', async () => {
    const d = await (await chat(makeEnv(), 'analyze CVE-2019-0555')).json();
    expect(d.response).toContain('MEDIUM');
    // The old fabricated template strings must never appear for this CVE.
    expect(d.response).not.toContain('Critical Remote Code Execution');
    expect(d.response).not.toContain('9.4/10');
    expect(d.response).not.toMatch(/Active exploitation confirmed in the wild\. CISA KEV listed\./);
  });
});

describe('analyze_cve — honest about missing intel', () => {
  it('acknowledges no verified data for a CVE not in the DB', async () => {
    const d = await (await chat(makeEnv(), 'what is CVE-2023-40000')).json();
    expect(d.response).toMatch(/No verified intelligence/i);
    expect(d.response).toContain('CVE-2023-40000');
    // Must not fabricate severity/KEV/exploitation.
    expect(d.response).not.toContain('Critical Remote Code Execution');
    expect(d.response).not.toContain('9.4/10');
    expect(d.response).toMatch(/nvd\.nist\.gov/);
  });

  it('asks for a CVE id when none is provided instead of inventing a verdict', async () => {
    const d = await (await chat(makeEnv(), 'tell me about this vulnerability')).json();
    expect(d.intent).toBe('analyze_cve');
    expect(d.response).not.toContain('Critical Remote Code Execution');
    expect(d.response).toMatch(/provide a CVE ID/i);
  });
});
