// Post-deploy production audit (session covering PRs #194-214) found several
// real, live issues that shipped despite a fully green CI run — none of them
// were logic bugs the existing suite could catch, they were content/contract
// mismatches between frontend claims and real backend behavior. Locks each
// one so it can't silently reappear. Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(resolve(__dirname, '../../', p), 'utf8');

describe('mcp-security.html — API code samples match the real handler contract', () => {
  const html = read('frontend/mcp-security.html');

  it('does not reference a non-existent "free_findings" response field', () => {
    // The real handler (mcpSecurityScanner.js) returns the free subset under
    // the key `findings`, never `free_findings` — a sample using the latter
    // crashes (KeyError in Python, undefined in JS) for anyone who copies it.
    expect(html).not.toContain('free_findings');
  });

  it('code samples read the real "findings" field', () => {
    expect(html).toMatch(/result\['findings'\]/);
    expect(html).toContain('{ risk_score, risk_level, findings }');
  });

  it('does not claim x-api-key unlocks full reports on this endpoint (it only affects scan-history logging)', () => {
    expect(html).not.toMatch(/x-api-key required for Pro\+ full reports/);
  });
});

describe('MCP Security "World\'s First" claim — no dangling copies on other pages', () => {
  // #209/#210 removed this unverifiable claim from mcp-security.html itself.
  // A post-deploy audit found the identical claim, about the identical
  // product, still live on 3 other pages after that fix shipped.
  const files = ['frontend/ai-security-assessment.html', 'frontend/ciso-hub.html', 'frontend/index.html'];

  it('none of them claim MCP Security is "World\'s First" / "World\'s first"', () => {
    for (const f of files) {
      const html = read(f);
      // Match only MCP-specific occurrences — these files may legitimately
      // carry an unrelated, pre-existing whole-platform superlative claim
      // that this fix does not touch (out of scope: never contradicted).
      const mcpFirstClaims = [...html.matchAll(/World's [Ff]irst[^<]{0,60}(MCP|Claude MCP)/g)];
      expect(mcpFirstClaims, `${f} still claims MCP is World's First`).toHaveLength(0);
    }
  });
});

describe('devsecops.html — AI-BOM widget does not show a false "all clear"', () => {
  const html = read('frontend/devsecops.html');

  it('the clean-scan message is gated on both lookups actually having run', () => {
    const start = html.indexOf('async function devsecopsTryAIBOM()');
    const end   = html.indexOf('async function devsecopsTrySCA()');
    expect(start).toBeGreaterThan(-1);
    const fn = html.slice(start, end);
    const cleanMsgLine = fn.split('\n').find(l => l.includes('No known CVEs or framework advisories found'));
    expect(cleanMsgLine, 'clean-scan message line not found').toBeTruthy();
    expect(cleanMsgLine).toContain('data.osv_lookup_available');
    expect(cleanMsgLine).toContain('data.advisory_lookup_available');
  });

  it('warns the user when a lookup was unavailable rather than staying silent', () => {
    expect(html).toContain('Live CVE lookup was unavailable');
    expect(html).toContain('Framework advisory cross-reference was unavailable');
  });
});

describe('ai-trust-suite.html — pricing matches the real linked pages, not fabricated numbers', () => {
  const html = read('frontend/ai-trust-suite.html');
  const owaspPage = read('frontend/owasp-llm-security.html');

  it('does not contain the previously fabricated ₹999 / ₹799 price points', () => {
    expect(html).not.toContain('₹999');
    expect(html).not.toContain('₹799');
  });

  it('the one priced offer (OWASP LLM Top 10) matches the real price on its own page', () => {
    expect(html).toContain('₹9,999');
    expect(owaspPage).toContain('₹9,999');
  });

  it('no longer claims universally "no quote calls" / "every price is real and published" (3 of 4 disciplines are consultation-based)', () => {
    expect(html).not.toMatch(/no quote calls/i);
    expect(html).not.toMatch(/every price (below|is real)/i);
  });

  it('JSON-LD offers array only lists the one real self-serve offer', () => {
    const ldBlocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
    const serviceBlock = ldBlocks.map(m => JSON.parse(m[1])).find(b => b['@type'] === 'Service');
    expect(serviceBlock.offers).toHaveLength(1);
    expect(serviceBlock.offers[0].price).toBe('9999');
  });
});
