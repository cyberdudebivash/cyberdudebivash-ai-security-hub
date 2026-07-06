/* Locks CI-1's error-rate alert (scripts/error-rate-alert.mjs) in every
 * direction that matters: a real spike alerts, a quiet/healthy window
 * doesn't, a high rate on too few requests doesn't false-positive, and
 * monitor failures (bad token, malformed response) are distinguishable from
 * a genuine customer-impact alert (so the workflow never files an incident
 * issue for a bad token). The GraphQL call is exercised with an injected
 * fetch (real Response objects, zero network/sockets) so this suite has no
 * dependency on outbound or loopback networking; the CLI entry point
 * (env-var wiring, exit codes) is spawned once for the one path that needs
 * no network at all: missing credentials.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { evaluateErrorRate, queryWorkersAnalytics } from '../../scripts/error-rate-alert.mjs';

const SCRIPT = resolve(import.meta.dirname, '../../scripts/error-rate-alert.mjs');

function fakeFetch(status, jsonBody) {
  return async () => new Response(JSON.stringify(jsonBody), { status });
}

function fakeFetchSequence(...responses) {
  let call = 0;
  return async () => {
    const { status, jsonBody } = responses[Math.min(call++, responses.length - 1)];
    return new Response(JSON.stringify(jsonBody), { status });
  };
}

const baseOpts = {
  graphqlUrl: 'http://unused.invalid/graphql',
  apiToken: 'test-token',
  accountId: 'test-account',
  scriptName: 'cyberdudebivash-security-hub',
  windowMinutes: 30,
  retryDelayMs: 1,
};

describe('evaluateErrorRate (pure decision logic)', () => {
  it('OK on a healthy window (well under threshold)', () => {
    const r = evaluateErrorRate({ requests: 1000, errors: 5, thresholdPct: 5, minSampleRequests: 50 });
    expect(r.status).toBe('OK');
    expect(r.errorRatePct).toBe(0.5);
  });

  it('ALERTs when the error rate exceeds the threshold on a real sample', () => {
    const r = evaluateErrorRate({ requests: 1000, errors: 80, thresholdPct: 5, minSampleRequests: 50 });
    expect(r.status).toBe('ALERT');
    expect(r.errorRatePct).toBe(8);
  });

  it('does NOT alert on a high rate with too few requests (avoids quiet-period false positives)', () => {
    const r = evaluateErrorRate({ requests: 10, errors: 10, thresholdPct: 5, minSampleRequests: 50 });
    expect(r.status).toBe('INSUFFICIENT_SAMPLE');
    expect(r.errorRatePct).toBe(null);
  });

  it('respects a custom threshold', () => {
    const belowDefault = evaluateErrorRate({ requests: 1000, errors: 20, thresholdPct: 5, minSampleRequests: 50 });
    expect(belowDefault.status).toBe('OK'); // 2% under a 5% threshold

    const tightened = evaluateErrorRate({ requests: 1000, errors: 20, thresholdPct: 1, minSampleRequests: 50 });
    expect(tightened.status).toBe('ALERT'); // same data, tighter threshold now alerts
  });

  it('treats the threshold as exclusive (exactly-at-threshold does not alert)', () => {
    const r = evaluateErrorRate({ requests: 1000, errors: 50, thresholdPct: 5, minSampleRequests: 50 });
    expect(r.errorRatePct).toBe(5);
    expect(r.status).toBe('OK');
  });
});

describe('queryWorkersAnalytics (injected fetch, no real network)', () => {
  it('sums requests/errors across multiple returned rows', async () => {
    const body = {
      data: { viewer: { accounts: [{ workersInvocationsAdaptive: [{ sum: { requests: 600, errors: 3 } }, { sum: { requests: 400, errors: 3 } }] }] } },
    };
    const totals = await queryWorkersAnalytics({ ...baseOpts, fetchImpl: fakeFetch(200, body) });
    expect(totals).toEqual({ requests: 1000, errors: 6 });
  });

  it('treats an empty (but present) result set as zero traffic, not an error', async () => {
    const body = { data: { viewer: { accounts: [{ workersInvocationsAdaptive: [] }] } } };
    const totals = await queryWorkersAnalytics({ ...baseOpts, fetchImpl: fakeFetch(200, body) });
    expect(totals).toEqual({ requests: 0, errors: 0 });
  });

  it('throws on a GraphQL-level error (e.g. bad token scope) after one retry', async () => {
    const body = { errors: [{ message: 'invalid or unscoped token' }] };
    await expect(queryWorkersAnalytics({ ...baseOpts, fetchImpl: fakeFetch(200, body) })).rejects.toThrow(/GraphQL request failed/);
  });

  it('throws on a non-2xx HTTP status after one retry', async () => {
    await expect(queryWorkersAnalytics({ ...baseOpts, fetchImpl: fakeFetch(401, { error: 'unauthorized' }) })).rejects.toThrow(
      /HTTP 401/
    );
  });

  it('throws on a structurally malformed response (missing workersInvocationsAdaptive)', async () => {
    const body = { data: { viewer: { accounts: [] } } };
    await expect(queryWorkersAnalytics({ ...baseOpts, fetchImpl: fakeFetch(200, body) })).rejects.toThrow(/malformed response/);
  });

  it('recovers on the retry if only the first attempt fails (transient-blip tolerance)', async () => {
    const goodBody = { data: { viewer: { accounts: [{ workersInvocationsAdaptive: [{ sum: { requests: 100, errors: 1 } }] }] } } };
    const totals = await queryWorkersAnalytics({
      ...baseOpts,
      fetchImpl: fakeFetchSequence({ status: 500, jsonBody: { error: 'transient' } }, { status: 200, jsonBody: goodBody }),
    });
    expect(totals).toEqual({ requests: 100, errors: 1 });
  });
});

describe('CLI entry point', () => {
  it('exits CONFIG_ERROR(2) when credentials are missing — the one path that needs no network', () => {
    try {
      execFileSync('node', [SCRIPT], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, CF_API_TOKEN: '', CF_ACCOUNT_ID: '' },
      });
      throw new Error('expected non-zero exit');
    } catch (e) {
      expect(e.status).toBe(2);
      expect((e.stdout || '') + (e.stderr || '')).toContain('CONFIG_ERROR');
    }
  });
});
