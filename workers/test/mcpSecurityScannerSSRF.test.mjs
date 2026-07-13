// handleMCPSecurityScan fetched a customer-controlled server_url server-side
// with zero validation — no scheme check, no private/link-local IP block,
// unlike the domain-validation guard already established elsewhere in this
// codebase. A request for server_url: "http://169.254.169.254" (cloud
// metadata) or an RFC1918 address would be fetched as-is. This locks in the
// fix: private/link-local hosts and non-http(s) schemes are rejected with a
// clear 400 before any fetch happens, and the real fetch path is never
// exercised for a blocked target (asserted via a stubbed global fetch that
// throws if called).
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleMCPSecurityScan } from '../src/handlers/mcpSecurityScanner.js';
import { validateDomain } from '../src/middleware/security.js';

describe('middleware/security.js validateDomain — link-local coverage (previously missing)', () => {
  it('blocks the IPv4 link-local range, including the cloud metadata address', () => {
    expect(validateDomain('169.254.169.254').valid).toBe(false);
    expect(validateDomain('169.254.169.254').reason).toBe('private_ip_ssrf');
    expect(validateDomain('169.254.0.1').valid).toBe(false);
  });

  it('blocks the IPv6 link-local range (fe80::/10)', () => {
    expect(validateDomain('fe80::1').valid).toBe(false);
    expect(validateDomain('fe80::1').reason).toBe('private_ip_ssrf');
  });

  it('still blocks the pre-existing private ranges (unaffected by this change)', () => {
    for (const host of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '::1']) {
      expect(validateDomain(host).valid).toBe(false);
    }
  });

  it('still accepts real public domains', () => {
    const r = validateDomain('example.com');
    expect(r.valid).toBe(true);
    expect(r.domain).toBe('example.com');
  });
});

function req(body) {
  return new Request('https://x/api/mcp-security/scan', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

const env = {}; // no env.DB — persistence is optional and skipped gracefully

describe('handleMCPSecurityScan — SSRF guard on server_url', () => {
  beforeEach(() => {
    // Any fetch during a "should be blocked" test is itself a test failure.
    vi.stubGlobal('fetch', vi.fn(() => { throw new Error('fetch should not have been called'); }));
  });

  it('rejects the cloud-metadata link-local address (169.254.169.254) with 400, no fetch', async () => {
    const res = await handleMCPSecurityScan(req({ server_url: 'http://169.254.169.254' }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.field).toBe('server_url');
    expect(body.reason).toBe('private_ip_ssrf');
  });

  it('rejects RFC1918 private addresses (10.x, 172.16-31.x, 192.168.x) with 400, no fetch', async () => {
    for (const host of ['http://10.0.0.5', 'http://172.16.0.1', 'http://192.168.1.1']) {
      const res = await handleMCPSecurityScan(req({ server_url: host }), env, {});
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.reason).toBe('private_ip_ssrf');
    }
  });

  it('rejects loopback (127.x, ::1) with 400, no fetch', async () => {
    for (const host of ['http://127.0.0.1', 'http://[::1]']) {
      const res = await handleMCPSecurityScan(req({ server_url: host }), env, {});
      expect(res.status).toBe(400);
    }
  });

  it('rejects non-http(s) schemes with 400, no fetch', async () => {
    const res = await handleMCPSecurityScan(req({ server_url: 'file:///etc/passwd' }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.reason).toBe('scheme_must_be_http_or_https');
  });

  it('rejects an unparseable server_url with 400, no fetch', async () => {
    const res = await handleMCPSecurityScan(req({ server_url: 'not a url at all' }), env, {});
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.reason).toBe('unparseable_url');
  });

  it('does NOT block a malicious server_url when a real config is already provided (fetch is never attempted either way)', async () => {
    const res = await handleMCPSecurityScan(req({
      server_url: 'http://169.254.169.254',
      config: { tools: [{ name: 't1' }], auth: { required: true } },
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.server_url).toBe('http://169.254.169.254');
  });
});

describe('handleMCPSecurityScan — legitimate requests still work', () => {
  it('a public https server_url passes the guard and reaches the real fetch attempt', async () => {
    const fetchMock = vi.fn(() => Promise.reject(new Error('simulated network failure')));
    vi.stubGlobal('fetch', fetchMock);
    const res = await handleMCPSecurityScan(req({ server_url: 'https://mcp.example.com' }), env, {});
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://mcp.example.com/.well-known/mcp-manifest.json');
    // Manifest fetch failed (simulated) — falls back to a defaults-only scan, not an error.
    expect(res.status).toBe(200);
  });

  it('a request with only config (no server_url) is entirely unaffected by the guard', async () => {
    vi.stubGlobal('fetch', vi.fn(() => { throw new Error('fetch should not have been called'); }));
    const res = await handleMCPSecurityScan(req({
      config: { tools: [{ name: 'read_file' }], auth: {} },
      server_name: 'Test Server',
    }), env, {});
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.server_name).toBe('Test Server');
  });
});
