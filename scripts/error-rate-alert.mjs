#!/usr/bin/env node
/**
 * Workers error-rate alert — the remaining half of CI-1
 * (OPERATIONAL_EXCELLENCE_REPORT.md §7): the CEAP sweep
 * (scripts/ceap-sweep.mjs, every 6h) catches synthetic customer-journey
 * regressions; this watches real production traffic in between via
 * Cloudflare's GraphQL Analytics API and alerts on a Workers error-rate spike.
 *
 * Measures the `workersInvocationsAdaptive` dataset's runtime-error rate
 * (uncaught exceptions, exceeded CPU/memory) — the verifiable proxy for
 * "5xx spikes" available without a zone tag. It does NOT see deliberately
 * -returned 5xx JSON responses from the app's own try/catch paths (the
 * canonical envelope in docs/ENGINEERING_STANDARDS.md §2); closing that gap
 * needs the zone-level httpRequestsAdaptiveGroups dataset and a real zone
 * tag, not wired here. Documented as a known limitation, not silently assumed
 * away (Production Truth Law, docs/ENGINEERING_STANDARDS.md §11).
 *
 * Exit codes: 0 OK (incl. insufficient sample) · 1 ALERT · 2 misconfigured ·
 * 3 monitor error (couldn't get a reliable reading — e.g. token lacks the
 * Account Analytics:Read scope).
 *
 * Env: CF_API_TOKEN, CF_ACCOUNT_ID (required); CF_WORKER_SCRIPT_NAME
 * (default cyberdudebivash-security-hub), CF_GRAPHQL_URL (default
 * Cloudflare's endpoint; override for tests), ERROR_RATE_THRESHOLD_PCT
 * (default 5), MIN_SAMPLE_REQUESTS (default 50), WINDOW_MINUTES (default 30),
 * RETRY_DELAY_MS (default 2000, one retry on transient failure).
 *
 * Usage: node scripts/error-rate-alert.mjs
 * No dependencies; Node 18+. The functions below are exported so
 * workers/test/errorRateAlert.test.mjs can exercise the decision logic and
 * the request/response handling directly (an injected fetch, no real
 * network) — only the CLI entry point below touches the real network.
 */
import { pathToFileURL } from 'node:url';

export function evaluateErrorRate({ requests, errors, thresholdPct, minSampleRequests }) {
  if (requests < minSampleRequests) {
    return {
      status: 'INSUFFICIENT_SAMPLE',
      requests,
      errors,
      errorRatePct: null,
      reason: `fewer than ${minSampleRequests} requests in the window`,
    };
  }

  const errorRatePct = Math.round((errors / requests) * 10000) / 100;

  if (errorRatePct > thresholdPct) {
    return {
      status: 'ALERT',
      requests,
      errors,
      errorRatePct,
      reason: `error rate ${errorRatePct}% exceeds threshold ${thresholdPct}%`,
    };
  }

  return { status: 'OK', requests, errors, errorRatePct };
}

function buildQuery({ accountId, scriptName, startIso, endIso }) {
  return `{
  viewer {
    accounts(filter: { accountTag: ${JSON.stringify(accountId)} }) {
      workersInvocationsAdaptive(
        limit: 100
        filter: {
          scriptName: ${JSON.stringify(scriptName)}
          datetime_geq: ${JSON.stringify(startIso)}
          datetime_leq: ${JSON.stringify(endIso)}
        }
      ) {
        sum { requests errors }
      }
    }
  }
}`;
}

/** Sums requests/errors from a single Cloudflare GraphQL Analytics call. Throws on any non-2xx, GraphQL-level error, or structurally unexpected body. */
async function queryOnce({ fetchImpl, graphqlUrl, apiToken, accountId, scriptName, windowMinutes }) {
  const now = new Date();
  const start = new Date(now.getTime() - windowMinutes * 60 * 1000);
  const query = buildQuery({ accountId, scriptName, startIso: start.toISOString(), endIso: now.toISOString() });

  const r = await fetchImpl(graphqlUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiToken}` },
    body: JSON.stringify({ query }),
  });
  const body = await r.json();
  if (!r.ok || body.errors) {
    throw new Error(`GraphQL request failed: HTTP ${r.status} ${JSON.stringify(body.errors ?? body).slice(0, 300)}`);
  }
  const rows = body?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive;
  if (!Array.isArray(rows)) {
    throw new Error('malformed response: workersInvocationsAdaptive missing');
  }
  return rows.reduce(
    (acc, row) => ({
      requests: acc.requests + (row.sum?.requests ?? 0),
      errors: acc.errors + (row.sum?.errors ?? 0),
    }),
    { requests: 0, errors: 0 }
  );
}

/** One retry on transient failure (matches the house pattern in scripts/ceap-sweep.mjs's neighbors); the second failure propagates to the caller. */
export async function queryWorkersAnalytics(opts) {
  const retryDelayMs = opts.retryDelayMs ?? 2000;
  try {
    return await queryOnce(opts);
  } catch {
    await new Promise((res) => setTimeout(res, retryDelayMs));
    return await queryOnce(opts);
  }
}

function reportAndExit(code, result, windowMinutes) {
  console.log(`ERROR_RATE_RESULT ${JSON.stringify(result)}`);
  const { status, requests, errors, errorRatePct, reason } = result;
  console.log(
    `status=${status} requests=${requests ?? 'n/a'} errors=${errors ?? 'n/a'} ` +
      `errorRate=${errorRatePct ?? 'n/a'}% window=${windowMinutes}m${reason ? ` reason=${reason}` : ''}`
  );
  process.exit(code);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const {
    CF_API_TOKEN,
    CF_ACCOUNT_ID,
    CF_WORKER_SCRIPT_NAME = 'cyberdudebivash-security-hub',
    CF_GRAPHQL_URL = 'https://api.cloudflare.com/client/v4/graphql',
    ERROR_RATE_THRESHOLD_PCT = '5',
    MIN_SAMPLE_REQUESTS = '50',
    WINDOW_MINUTES = '30',
    RETRY_DELAY_MS = '2000',
  } = process.env;

  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    reportAndExit(2, { status: 'CONFIG_ERROR', reason: 'CF_API_TOKEN and CF_ACCOUNT_ID are required' }, WINDOW_MINUTES);
  }

  const windowMinutes = Number(WINDOW_MINUTES);
  let totals;
  try {
    totals = await queryWorkersAnalytics({
      fetchImpl: fetch,
      graphqlUrl: CF_GRAPHQL_URL,
      apiToken: CF_API_TOKEN,
      accountId: CF_ACCOUNT_ID,
      scriptName: CF_WORKER_SCRIPT_NAME,
      windowMinutes,
      retryDelayMs: Number(RETRY_DELAY_MS),
    });
  } catch (e) {
    reportAndExit(3, { status: 'MONITOR_ERROR', reason: e.message }, windowMinutes);
  }

  const result = evaluateErrorRate({
    requests: totals.requests,
    errors: totals.errors,
    thresholdPct: Number(ERROR_RATE_THRESHOLD_PCT),
    minSampleRequests: Number(MIN_SAMPLE_REQUESTS),
  });

  reportAndExit(result.status === 'ALERT' ? 1 : 0, result, windowMinutes);
}
