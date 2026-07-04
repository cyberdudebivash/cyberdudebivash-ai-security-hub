/* Copilot CVE grounding (Cert Phase A — AI engine).
 *
 * The AI copilot is real (Groq llama-3.1-8b, live), but ungrounded: it was
 * observed calling CVE-2024-3400 (a real, critical, actively-exploited Palo Alto
 * CVE) "fictional or non-existent". buildCveGrounding() retrieves the platform's
 * OWN authoritative CVE data from D1 and injects it into the copilot context so
 * it answers from ground truth. This suite verifies the retrieval against a real
 * SQL engine.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { buildCveGrounding } from '../src/handlers/aiSecurityCopilot.js';

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

describe('copilot CVE grounding retrieves real platform data', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    env.SECURITY_HUB_DB._sqlite.exec(`CREATE TABLE threat_intel (
      id TEXT PRIMARY KEY, severity TEXT, cvss REAL, title TEXT, description TEXT,
      source TEXT, published_at TEXT, exploit_status TEXT, known_ransomware INTEGER
    )`);
    env.SECURITY_HUB_DB._sqlite.prepare(
      `INSERT INTO threat_intel (id,severity,cvss,title,description,source,published_at,exploit_status,known_ransomware) VALUES (?,?,?,?,?,?,?,?,?)`
    ).run('CVE-2024-3400', 'CRITICAL', 10.0, 'PAN-OS GlobalProtect command injection', 'Unauthenticated RCE in Palo Alto PAN-OS.', 'cisa_kev', '2024-04-12', 'confirmed', 1);
  });

  it('grounds a real CVE with authoritative facts + anti-hallucination instruction', async () => {
    const g = await buildCveGrounding(env, 'What is CVE-2024-3400 and how do I mitigate it?');
    expect(g).toBeTruthy();
    expect(g).toContain('CVE-2024-3400');
    expect(g).toContain('CRITICAL');
    expect(g).toMatch(/do NOT claim they are fictional/i);
    expect(g).toMatch(/known ransomware use/i);
  });

  it('returns null when the message names no CVE', async () => {
    expect(await buildCveGrounding(env, 'How is my security posture?')).toBeNull();
  });

  it('injects an uncertainty guard for a CVE not in the platform DB (no fabrication, no false "fictional")', async () => {
    const g = await buildCveGrounding(env, 'Tell me about CVE-1999-0001');
    expect(g).toBeTruthy();
    expect(g).toContain('NO record of: CVE-1999-0001');
    expect(g).toMatch(/Do NOT invent/i);
    expect(g).toMatch(/do NOT assert they are fictional/i);
    expect(g).toMatch(/NVD \/ CISA KEV/);
    // Must not carry the authoritative-data preamble when nothing was found.
    expect(g).not.toMatch(/AUTHORITATIVE PLATFORM THREAT-INTEL DATA/);
  });

  it('grounds found CVEs and flags missing ones in the same message', async () => {
    const g = await buildCveGrounding(env, 'Compare CVE-2024-3400 with CVE-1999-0001');
    expect(g).toContain('AUTHORITATIVE PLATFORM THREAT-INTEL DATA');
    expect(g).toContain('PAN-OS GlobalProtect command injection');
    expect(g).toContain('NO record of: CVE-1999-0001');
    // The missing-ID section must not swallow the found ID.
    expect(g).not.toContain('NO record of: CVE-2024-3400');
  });

  it('is case-insensitive and de-duplicates CVE ids', async () => {
    const g = await buildCveGrounding(env, 'cve-2024-3400 and CVE-2024-3400 again');
    expect((g.match(/CVE-2024-3400/g) || []).length).toBe(1);
  });
});
