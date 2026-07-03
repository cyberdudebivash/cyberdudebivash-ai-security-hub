// Enterprise AI Security Intelligence Platform Program.
//
// handleMCPThreatFeed shipped 5 static threat-pattern entries whose
// `last_seen` field was `new Date().toISOString().split('T')[0]` and whose
// top-level `last_updated` was `new Date().toISOString()` — both recomputed
// to "today"/"now" on every single request, making a 100% static catalog
// masquerade as a continuously-updated live feed forever. This locks in the
// fix: every date on the response is a fixed, real catalog value.
import { describe, it, expect } from 'vitest';
import { handleMCPThreatFeed } from '../src/handlers/mcpSecurityScanner.js';

describe('handleMCPThreatFeed — no fabricated "always fresh" timestamps', () => {
  it('never reports last_seen as today\'s date computed at request time', async () => {
    const res = await handleMCPThreatFeed(new Request('https://x/api/mcp-security/threats'));
    const body = await res.json();
    const today = new Date().toISOString().split('T')[0];
    for (const t of body.threats) {
      expect(t.last_seen).not.toBe(today);
      expect(t.last_seen).toBe(t.first_seen);
    }
  });

  it('catalog_last_updated is a fixed value derived from the entries, not Date.now()', async () => {
    const res = await handleMCPThreatFeed(new Request('https://x/api/mcp-security/threats'));
    const body = await res.json();
    expect(body.last_updated).toBeUndefined();
    expect(body.catalog_last_updated).toBeDefined();
    const maxSeen = body.threats.reduce((m, t) => (t.last_seen > m ? t.last_seen : m), body.threats[0].last_seen);
    expect(body.catalog_last_updated).toBe(maxSeen);
  });

  it('is honestly labeled as a curated catalog, not a live feed', async () => {
    const res = await handleMCPThreatFeed(new Request('https://x/api/mcp-security/threats'));
    const body = await res.json();
    expect(body.source).toMatch(/curated catalog/i);
  });

  it('repeated calls return identical dates (no per-request recomputation)', async () => {
    const res1 = await handleMCPThreatFeed(new Request('https://x/api/mcp-security/threats'));
    const body1 = await res1.json();
    const res2 = await handleMCPThreatFeed(new Request('https://x/api/mcp-security/threats'));
    const body2 = await res2.json();
    expect(body2.catalog_last_updated).toBe(body1.catalog_last_updated);
    expect(body2.threats[0].last_seen).toBe(body1.threats[0].last_seen);
  });
});
