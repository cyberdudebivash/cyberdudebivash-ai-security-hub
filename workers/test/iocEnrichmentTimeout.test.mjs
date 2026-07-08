/* Regression test — handlers/iocEnrichment.js (the live GET /api/threat/ioc
 * route — services/iocEnrichmentEngine.js is a separate, dead, never-imported
 * duplicate) called AbuseIPDB, VirusTotal (x3), and MalwareBazaar via raw
 * fetch() with no AbortSignal at all. An unresponsive upstream could hang the
 * request indefinitely — the same unbounded-fetch pattern that caused a prior
 * production incident in the AI router. Every external fetch here must now
 * carry an explicit AbortSignal. */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleThreatIOC } from '../src/handlers/iocEnrichment.js';

function fakeRequest(ioc, type) {
  const params = new URLSearchParams({ ioc, ...(type ? { type } : {}) });
  return new Request(`https://x/api/threat/ioc?${params.toString()}`);
}

describe('handleThreatIOC — every external fetch carries an AbortSignal', () => {
  let fetchSpy;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ data: {} }), { status: 200, headers: { 'content-type': 'application/json' } })
    );
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('AbuseIPDB (IP lookup) request carries an AbortSignal', async () => {
    await handleThreatIOC(fakeRequest('1.2.3.4', 'ipv4'), { ABUSEIPDB_API_KEY: 'k' }, {});
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('VirusTotal (domain lookup) request carries an AbortSignal', async () => {
    await handleThreatIOC(fakeRequest('example.com', 'domain'), { VIRUSTOTAL_API_KEY: 'k' }, {});
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('MalwareBazaar (hash lookup) request carries an AbortSignal', async () => {
    await handleThreatIOC(fakeRequest('a'.repeat(64), 'sha256'), {}, {});
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('VirusTotal (URL lookup) request carries an AbortSignal', async () => {
    await handleThreatIOC(fakeRequest('http://example.com/x', 'url'), { VIRUSTOTAL_API_KEY: 'k' }, {});
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });
});
