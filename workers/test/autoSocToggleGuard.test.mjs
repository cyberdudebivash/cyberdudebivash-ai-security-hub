/* AUTO SOC MODE toggle guard — locks the P0 fix for the toggle that "won't
 * turn on" (Amazon/Microsoft escalation).
 *
 * ROOT CAUSE: /api/auto-soc/mode is enterprise-gated. The frontend POST sent no
 * Authorization header, so the server saw an anonymous FREE caller and returned
 * 403. The old handler read auto_mode off the 403 body (undefined) and left the
 * toggle silently stuck OFF with no explanation.
 *
 * FIX (this guard enforces it stays in place):
 *  - both load and toggle send the Bearer token,
 *  - a missing token short-circuits with an explanatory sign-in message,
 *  - a non-ok / error response does NOT flip the toggle and surfaces the reason.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

// Extract the cdbAutoSOCToggle function body.
function fnBody(name) {
  const start = fe.indexOf(`window.${name} = function`);
  if (start === -1) return '';
  // Grab a generous window — the function is well under 3k chars.
  return fe.slice(start, start + 3000);
}

describe('AUTO SOC MODE toggle — auth-aware, fail-safe', () => {
  it('the mode load request sends the Bearer token', () => {
    const load = fnBody('cdbAutoSOCLoad');
    expect(/Authorization['"]?\s*:\s*['"]Bearer ['"]\s*\+\s*_t/.test(load)).toBe(true);
  });

  it('the toggle POST sends the Bearer token', () => {
    const t = fnBody('cdbAutoSOCToggle');
    expect(/method:\s*['"]POST['"]/.test(t)).toBe(true);
    expect(/Authorization['"]?\s*:\s*['"]Bearer ['"]\s*\+\s*_t/.test(t)).toBe(true);
  });

  it('a missing token short-circuits instead of firing an anonymous 403', () => {
    const t = fnBody('cdbAutoSOCToggle');
    // if (!_t) { ...sign-in message...; return; }
    expect(/if\s*\(\s*!_t\s*\)/.test(t)).toBe(true);
  });

  it('a non-ok / error response does NOT flip the toggle', () => {
    const t = fnBody('cdbAutoSOCToggle');
    // Guard clause on !res.ok || body.error that returns before setting autoMode.
    expect(/if\s*\(\s*!res\.ok\s*\|\|\s*\(res\.body\s*&&\s*res\.body\.error\)\s*\)/.test(t)).toBe(true);
    // autoMode is only set from the server's auto_mode field (not optimistically).
    expect(/ASOC\.autoMode\s*=\s*!!\(res\.body\s*&&\s*res\.body\.auto_mode\)/.test(t)).toBe(true);
  });
});
