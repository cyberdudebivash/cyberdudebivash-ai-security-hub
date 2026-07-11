/* P0 — 2FA enrollment was completely broken for every real customer, plus a
 * mislabeled export button, both found while continuing the enterprise
 * dashboard audit into Organizations/API Keys/MFA/CISO-export mutation flows.
 *
 * ROOT CAUSE (MFA): frontend/user-dashboard.html has TWO elements with
 * id="mfa-code" — the login overlay's #mfa-view (pre-auth 2FA challenge,
 * doMfaVerify(), a working feature from a prior wave) is static HTML that
 * stays in the DOM forever (only display:none'd, never removed) after
 * login; the Settings page's 2FA-SETUP flow (mfaBeginSetup()) dynamically
 * injects its own #mfa-code input into #mfa-body. Once both exist
 * simultaneously, document.getElementById('mfa-code') — used by
 * mfaConfirmEnable() to read what the customer typed — always resolves to
 * the FIRST one in document order (the hidden, permanently-empty
 * login-overlay input), never the visible Settings-page one. Confirmed live:
 * typing a real, correctly-computed TOTP code into the visible field and
 * clicking "Verify & Enable" still showed "Enter the 6-digit code from your
 * app" every single time — 2FA could never be enabled by any customer.
 * Fixed by renaming the Settings-page instance to a unique id
 * ("mfa-setup-code"); the login-flow instance (id="mfa-code") and its
 * doMfaVerify()/keydown listener are untouched.
 *
 * ROOT CAUSE (export button): the Threat Graph's "Export SVG" button called
 * canvas.toDataURL('image/png') and downloaded a .png file — it has never
 * produced SVG (the graph has no retained vector scene graph, just a
 * force-directed canvas simulation). Confirmed live: real PNG magic bytes,
 * never XML. Renamed the button/function to say what it actually produces.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

describe('Settings-page MFA setup no longer collides with the login overlay\'s MFA-challenge input (P0)', () => {
  it('exactly one "mfa-code" id remains — the login overlay\'s (doMfaVerify, untouched)', () => {
    const matches = html.match(/<input id="mfa-code"/g) || [];
    expect(matches).toHaveLength(1);
  });

  it('the Settings-page setup input has its own unique id', () => {
    expect(html).toContain('id="mfa-setup-code"');
  });

  it('mfaConfirmEnable() reads the renamed, unique id — not the login overlay\'s', () => {
    const start = html.indexOf('async function mfaConfirmEnable');
    expect(start).toBeGreaterThan(-1);
    const body = html.slice(start, start + 800);
    expect(body).toContain("const code = (document.getElementById('mfa-setup-code')");
    expect(body).not.toContain("const code = (document.getElementById('mfa-code')");
  });

  it('the login-flow doMfaVerify() and its keydown listener still target the original id (untouched, still working)', () => {
    const start = html.indexOf('async function doMfaVerify');
    expect(start).toBeGreaterThan(-1);
    expect(html.slice(start, start + 300)).toContain("document.getElementById('mfa-code')");
    expect(html).toContain("document.getElementById('mfa-code').addEventListener('keydown'");
  });
});

describe('Threat Graph export button matches what it actually produces (cleanup)', () => {
  it('the button now says PNG, not SVG', () => {
    expect(html).toContain('⬇ Export PNG');
    expect(html).not.toContain('⬇ Export SVG');
  });

  it('exportGraphPNG() exists and exportGraphSVG() is gone', () => {
    expect(html).toContain('function exportGraphPNG()');
    expect(html).not.toContain('exportGraphSVG');
  });

  it('the button\'s onclick wires to the renamed function', () => {
    expect(html).toContain('onclick="exportGraphPNG()"');
  });
});
