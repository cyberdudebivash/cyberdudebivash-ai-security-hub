/* Regression tests — real AppSec/DAST + Dark Web Exposure scanners (closes
 * the "known unimplemented" gap the release gate previously accepted:
 * /api/scan/appsec and /api/scan/darkscan both 404'd while the pricing page
 * advertised them as included, working Pro/Enterprise/MSSP features).
 * Proves: both engines produce real findings from live-shaped responses
 * (not fabricated), fail safely on unreachable targets, honestly disclose
 * unavailable data sources rather than faking them, and both handlers
 * enforce the advertised tier gate + input validation. */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runAppSecScan } from '../src/services/appsecScanEngine.js';
import { runDarkWebScan } from '../src/services/darkWebScanEngine.js';
import { handleAppSecScan, handleDarkWebScan } from '../src/handlers/serviceHandlers.js';

function reqWithBody(body) {
  return { json: async () => body };
}

describe('AppSec/DAST engine — real passive reconnaissance', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });

  it('flags an exposed .git/config and a weak CSP from real-shaped responses', async () => {
    global.fetch.mockImplementation((url) => {
      if (String(url).includes('/.git/config')) {
        return Promise.resolve({ status: 200, headers: new Headers(), text: async () => '' });
      }
      if (String(url).endsWith('example.com/') || String(url) === 'https://example.com') {
        return Promise.resolve({
          status: 200,
          headers: new Headers({ 'content-security-policy': "default-src 'self' 'unsafe-inline'" }),
          text: async () => '',
        });
      }
      return Promise.resolve({ status: 404, headers: new Headers(), text: async () => '' });
    });

    const result = await runAppSecScan('https://example.com', 'https://example.com', 'example.com');
    expect(result.reachable).toBe(true);
    const gitFinding = result.findings.find(f => f.id === 'APP-001');
    expect(gitFinding.severity).toBe('CRITICAL');
    expect(gitFinding.exposed_paths.some(p => p.path === '/.git/config')).toBe(true);

    const cspFinding = result.findings.find(f => f.id === 'APP-002');
    expect(cspFinding.csp_present).toBe(true);
    expect(cspFinding.weak_directives).toContain("'unsafe-inline'");
  });

  it('reports unreachable target honestly instead of fabricating a result', async () => {
    global.fetch.mockRejectedValue(new Error('network unreachable'));
    const result = await runAppSecScan('https://unreachable-test-target.example', 'https://unreachable-test-target.example', 'unreachable-test-target.example');
    expect(result.reachable).toBe(false);
    expect(result.risk_score).toBeNull();
    expect(result.findings).toEqual([]);
  });

  it('detects a CORS misconfiguration that reflects an arbitrary origin with credentials', async () => {
    global.fetch.mockImplementation((url, opts) => {
      if (opts?.headers?.Origin) {
        return Promise.resolve({
          status: 200,
          headers: new Headers({
            'access-control-allow-origin': opts.headers.Origin,
            'access-control-allow-credentials': 'true',
          }),
          text: async () => '',
        });
      }
      return Promise.resolve({ status: 404, headers: new Headers(), text: async () => '' });
    });
    const result = await runAppSecScan('https://example.com', 'https://example.com', 'example.com');
    const corsFinding = result.findings.find(f => f.id === 'APP-004');
    expect(corsFinding.severity).toBe('HIGH');
  });
});

describe('Dark Web Exposure engine — real CT-log + credential-leak checks', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });

  it('parses real-shaped crt.sh certificate transparency data into unique subdomains', async () => {
    global.fetch.mockImplementation((url) => {
      if (String(url).includes('crt.sh')) {
        return Promise.resolve({
          ok: true,
          json: async () => ([
            { name_value: 'www.example.com\nexample.com' },
            { name_value: '*.staging.example.com' },
            { name_value: 'api.example.com' },
          ]),
        });
      }
      return Promise.resolve({ status: 404, headers: new Headers(), text: async () => '' });
    });

    const result = await runDarkWebScan('example.com', {});
    const ctFinding = result.findings.find(f => f.id === 'DARK-001');
    expect(ctFinding.subdomains).toEqual(
      expect.arrayContaining(['www.example.com', 'example.com', 'staging.example.com', 'api.example.com'])
    );
  });

  it('flags actively exposed credential files as CRITICAL — a live breach, not a prediction', async () => {
    global.fetch.mockImplementation((url) => {
      if (String(url).includes('crt.sh')) return Promise.resolve({ ok: true, json: async () => [] });
      if (String(url).includes('/.env')) return Promise.resolve({ status: 200, headers: new Headers(), text: async () => '' });
      return Promise.resolve({ status: 404, headers: new Headers(), text: async () => '' });
    });

    const result = await runDarkWebScan('example.com', {});
    const leakFinding = result.findings.find(f => f.id === 'DARK-002');
    expect(leakFinding.severity).toBe('CRITICAL');
    expect(leakFinding.exposed_paths.some(p => p.path === '/.env')).toBe(true);
  });

  it('discloses breach-database search as unavailable rather than fabricating matches when no API key is configured', async () => {
    global.fetch.mockResolvedValue({ ok: true, json: async () => [] });
    const result = await runDarkWebScan('example.com', {}); // no HIBP_API_KEY in env
    const breachFinding = result.findings.find(f => f.id === 'DARK-003');
    expect(breachFinding.enabled).toBe(false);
    expect(breachFinding.data_source).toBe('not_configured');
  });

  it('reports the search as enabled when a provider key is configured', async () => {
    global.fetch.mockResolvedValue({ ok: true, json: async () => [] });
    const result = await runDarkWebScan('example.com', { HIBP_API_KEY: 'fake-key-for-test' });
    const breachFinding = result.findings.find(f => f.id === 'DARK-003');
    expect(breachFinding.enabled).toBe(true);
  });

  it('handles crt.sh failure gracefully without crashing the whole scan', async () => {
    global.fetch.mockRejectedValue(new Error('crt.sh unreachable'));
    const result = await runDarkWebScan('example.com', {});
    expect(result.risk_score).toBeGreaterThanOrEqual(0);
    const ctFinding = result.findings.find(f => f.id === 'DARK-001');
    expect(ctFinding.severity).toBe('INFO');
  });
});

describe('handleAppSecScan / handleDarkWebScan — tier gate + validation', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 404, headers: new Headers(), json: async () => [], text: async () => '' })); });

  it('rejects FREE tier with 403 and an upgrade URL', async () => {
    const res = await handleAppSecScan(reqWithBody({ url: 'https://example.com' }), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.upgrade_url).toBeTruthy();
  });

  it('allows PRO tier through', async () => {
    const res = await handleAppSecScan(reqWithBody({ url: 'https://example.com' }), {}, { tier: 'PRO' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-APPSEC-001');
  });

  it('allows MSSP tier through for dark web scan (pricing table promises MSSP access)', async () => {
    const res = await handleDarkWebScan(reqWithBody({ target: 'example.com' }), {}, { tier: 'MSSP' });
    expect(res.status).toBe(200);
  });

  it('rejects an invalid url', async () => {
    const res = await handleAppSecScan(reqWithBody({ url: 'not-a-url' }), {}, { tier: 'PRO' });
    expect(res.status).toBe(400);
  });

  it('rejects a URL pointing at a private/internal host', async () => {
    const res = await handleAppSecScan(reqWithBody({ url: 'http://127.0.0.1/admin' }), {}, { tier: 'PRO' });
    expect(res.status).toBe(400);
  });

  it('rejects a request with no target', async () => {
    const res = await handleDarkWebScan(reqWithBody({}), {}, { tier: 'ENTERPRISE' });
    expect(res.status).toBe(400);
  });
});
