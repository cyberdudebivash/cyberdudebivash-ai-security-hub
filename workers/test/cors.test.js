// CORS allowlist contract (security: prevents dev origins leaking to prod and
// prevents arbitrary cross-origin credentialed access).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { corsHeaders } from '../src/middleware/cors.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function reqWithOrigin(origin) {
  return new Request('https://api.cyberdudebivash.in/x', {
    headers: origin ? { Origin: origin } : {},
  });
}

describe('corsHeaders', () => {
  it('echoes a known production origin', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).toBe('https://cyberdudebivash.in');
  });

  it('falls back to the primary prod domain for unknown origins (browser will reject)', () => {
    const h = corsHeaders(reqWithOrigin('https://evil.example.com'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).toBe('https://cyberdudebivash.in');
    expect(h['Access-Control-Allow-Origin']).not.toBe('https://evil.example.com');
    expect(h['Access-Control-Allow-Origin']).not.toBe('*');
  });

  it('does NOT allow localhost origins in production', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), { ENVIRONMENT: 'production' });
    expect(h['Access-Control-Allow-Origin']).not.toBe('http://localhost:3000');
  });

  it('DOES allow localhost origins outside production', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), { ENVIRONMENT: 'development' });
    expect(h['Access-Control-Allow-Origin']).toBe('http://localhost:3000');
  });

  it('defaults to production behaviour when ENVIRONMENT is unset', () => {
    const h = corsHeaders(reqWithOrigin('http://localhost:3000'), {});
    expect(h['Access-Control-Allow-Origin']).not.toBe('http://localhost:3000');
  });

  it('always sets the standard CORS method/credential headers', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), {});
    expect(h['Access-Control-Allow-Methods']).toContain('POST');
    expect(h['Access-Control-Allow-Credentials']).toBe('true');
  });

  // Same bug class as the X-Scan-Token incident below, different axis: at
  // least 8 real routes dispatch on method === 'PATCH' (SOC case updates,
  // admin incident/maintenance updates, workflow updates, API key updates,
  // admin user status, MSSP partner status, webhook management), but PATCH
  // was never in this allowlist. The global preflight handler
  // (index.js: `if (method === 'OPTIONS') return new Response(null, {
  // status: 204, headers: corsHeaders(request) })`) is the sole preflight
  // path for every route, so this one list gates all of them. Any browser
  // fetch() with method:'PATCH' silently failed preflight -- "Failed to
  // fetch" in the browser, unaffected via curl/direct server calls.
  it('allows PATCH so browser-based PATCH routes (SOC cases, admin incidents/maintenance, workflows, API keys, admin user status, MSSP partner status, webhook mgmt) pass preflight', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), {});
    expect(h['Access-Control-Allow-Methods']).toContain('PATCH');
  });

  // P0 incident 2026-07-08: frontend/index.html's domain-scan flow sends
  // 'X-Scan-Token' (the P1 abuse-prevention token from POST /api/scan/token,
  // see executeScan() around frontend/index.html:9598). That header was never
  // added to Access-Control-Allow-Headers, so any cross-origin caller (5 of
  // the 6 PROD_ORIGINS entries share this API with a different frontend
  // origin) failed CORS preflight on every domain scan — the browser blocked
  // the actual POST before it was ever sent, surfacing to users as a generic
  // "Failed to fetch" with no server-side error to diagnose from (curl/direct
  // server calls are unaffected — CORS is enforced by the browser, not the
  // server, which is why this shipped unnoticed).
  it('allows X-Scan-Token so the domain-scan preflight (frontend/index.html executeScan) succeeds', () => {
    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), {});
    expect(h['Access-Control-Allow-Headers']).toContain('X-Scan-Token');
  });

  it('allows every custom X-* request header actually sent by the frontend', () => {
    // Regression guard for the whole bug class, not just X-Scan-Token: any
    // custom header a fetch() call sends that isn't in this allowlist breaks
    // silently in the browser (CORS preflight failure) while working fine
    // from curl/tests, so it's easy to ship undetected. Scan the frontend
    // source for literal 'X-...' header names and require each to be listed.
    const sources = [
      join(__dirname, '../../frontend/index.html'),
      join(__dirname, '../../frontend/assets/copilot-widget.js'),
      join(__dirname, '../../frontend/assets/checkout-modal.js'),
    ];
    const ignore = new Set(['X-UA-Compatible']); // meta tag, not a fetch header
    const found = new Set();
    for (const file of sources) {
      const text = readFileSync(file, 'utf8');
      for (const m of text.matchAll(/['"](X-[A-Za-z-]+)['"]\s*:/g)) {
        if (!ignore.has(m[1])) found.add(m[1]);
      }
    }
    expect(found.size).toBeGreaterThan(0); // sanity: the scan itself still finds headers

    const h = corsHeaders(reqWithOrigin('https://cyberdudebivash.in'), {});
    const allowed = h['Access-Control-Allow-Headers'].split(',').map(s => s.trim().toLowerCase());
    const missing = [...found].filter(header => !allowed.includes(header.toLowerCase()));
    expect(missing).toEqual([]);
  });
});
