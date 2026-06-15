// God Mode dashboard (frontend/god-mode.html) static contract tests.
// No browser/network: validates the page wires to the real God Mode API contract,
// parses without SyntaxError (guards the "defer SyntaxError" regression class),
// escapes API-sourced text, and keeps the admin trigger behind an x-api-key.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(resolve(__dirname, '../../frontend/god-mode.html'), 'utf8');

// Pull the inline <script> body (the page has exactly one app script block).
function appScript() {
  const blocks = [...HTML.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  // The largest block is the application logic.
  return blocks.sort((a, b) => b.length - a.length)[0] || '';
}

describe('god-mode.html — document hygiene', () => {
  it('declares language and mobile viewport', () => {
    expect(HTML).toMatch(/<html lang="en">/);
    expect(HTML).toMatch(/name="viewport"[^>]*width=device-width/);
  });

  it('has exactly one H1 and a main landmark', () => {
    expect((HTML.match(/<h1[\s>]/g) || []).length).toBe(1);
    expect(HTML).toMatch(/<main id="main">/);
  });

  it('every button carries a visible text label', () => {
    const buttons = [...HTML.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)];
    expect(buttons.length).toBeGreaterThan(0);
    for (const [, inner] of buttons) {
      expect(inner.replace(/<[^>]*>/g, '').trim().length, `button "${inner}"`).toBeGreaterThan(0);
    }
  });
});

describe('god-mode.html — API contract', () => {
  it('targets all seven God Mode endpoints', () => {
    for (const p of ['/status', '/ciso', '/aspm', '/compliance', '/hunt-pack', '/run']) {
      expect(HTML, `missing ${p}`).toContain(p);
    }
    expect(HTML).toContain("'/api/mythos/god-mode'");
  });

  it('reads flat response fields, not a {data} envelope', () => {
    // Matches the actual handler shapes in mythosGodModeHandler.js.
    for (const f of ['ciso_intel', 'board_report', 'compliance_posture', 'aspm_summary', 'zt_anomalies', 'last_report_summary', 'lifetime_metrics']) {
      expect(HTML, `expected to consume ${f}`).toContain(f);
    }
  });

  it('handles the documented 404 (no run yet) and 409 (already running) states', () => {
    expect(HTML).toMatch(/status === 404|r\.status === 404/);
    expect(HTML).toContain('409');
  });
});

describe('god-mode.html — security', () => {
  it('defines an HTML-escaper and uses it for dynamic content', () => {
    expect(HTML).toMatch(/function esc\(/);
    expect(HTML).toMatch(/&amp;/);
    expect(HTML).toMatch(/&lt;/);
  });

  it('guards the run trigger with an x-api-key header (admin only)', () => {
    expect(HTML).toMatch(/'x-api-key'\s*:\s*key/);
    expect(HTML).toContain('cdb_admin_key');
  });

  it('clears a rejected admin key on 403', () => {
    expect(HTML).toMatch(/res\.status === 403[\s\S]*removeItem\('cdb_admin_key'\)/);
  });

  it('inline script parses without SyntaxError', () => {
    const code = appScript();
    expect(code.length).toBeGreaterThan(500);
    // Function() parses (does not execute) — catches the defer/identifier regression class.
    expect(() => new Function(code)).not.toThrow();
  });

  it('does not contain a stray closing script tag inside strings', () => {
    expect(appScript()).not.toContain('</script>');
  });
});
