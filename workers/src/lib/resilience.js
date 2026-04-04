/**
 * CYBERDUDEBIVASH AI Security Hub — Resilience Utilities v8.0
 * Circuit breaker, retry with exponential back-off, timeout wrapper,
 * and graceful degradation helpers for all external API calls.
 *
 * Designed for Cloudflare Workers (no Node.js APIs, no persistent state —
 * circuit breaker state is stored in KV for cross-isolate consistency).
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const CB_OPEN_TTL      = 60;       // seconds circuit stays OPEN before trying HALF-OPEN
const CB_FAILURE_LIMIT = 5;        // consecutive failures before tripping
const CB_SUCCESS_RESET = 2;        // successes in HALF-OPEN before closing
const DEFAULT_TIMEOUT  = 8000;     // ms — default fetch timeout
const MAX_RETRIES      = 3;
const BASE_BACKOFF_MS  = 200;      // first retry wait

// ─── Circuit Breaker State (KV-backed, per service name) ─────────────────────
// Key: cb:<service>        → JSON { state, failures, last_failure_at }
// States: CLOSED (healthy), OPEN (failing, fast-fail), HALF_OPEN (testing)

async function getCBState(env, service) {
  if (!env?.SECURITY_HUB_KV) return { state: 'CLOSED', failures: 0 };
  try {
    const raw = await env.SECURITY_HUB_KV.get(`cb:${service}`);
    return raw ? JSON.parse(raw) : { state: 'CLOSED', failures: 0 };
  } catch { return { state: 'CLOSED', failures: 0 }; }
}

async function setCBState(env, service, cbState) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    await env.SECURITY_HUB_KV.put(
      `cb:${service}`,
      JSON.stringify(cbState),
      { expirationTtl: CB_OPEN_TTL * 10 }
    );
  } catch {}
}

async function recordFailure(env, service) {
  const s = await getCBState(env, service);
  const failures = (s.failures || 0) + 1;
  const now = Date.now();
  if (failures >= CB_FAILURE_LIMIT) {
    await setCBState(env, service, { state: 'OPEN', failures, last_failure_at: now });
    console.warn(`[CircuitBreaker] ${service} → OPEN after ${failures} failures`);
  } else {
    await setCBState(env, service, { state: s.state === 'HALF_OPEN' ? 'OPEN' : 'CLOSED', failures, last_failure_at: now });
  }
}

async function recordSuccess(env, service) {
  const s = await getCBState(env, service);
  if (s.state === 'HALF_OPEN') {
    const successes = (s.successes || 0) + 1;
    if (successes >= CB_SUCCESS_RESET) {
      await setCBState(env, service, { state: 'CLOSED', failures: 0 });
      console.info(`[CircuitBreaker] ${service} → CLOSED (recovered)`);
    } else {
      await setCBState(env, service, { ...s, successes });
    }
  } else if (s.state === 'CLOSED' && s.failures > 0) {
    // Gradually decay failure count on success
    await setCBState(env, service, { ...s, failures: Math.max(0, s.failures - 1) });
  }
}

async function checkCircuit(env, service) {
  const s = await getCBState(env, service);
  if (s.state === 'CLOSED') return { allowed: true };

  if (s.state === 'OPEN') {
    const elapsed = (Date.now() - (s.last_failure_at || 0)) / 1000;
    if (elapsed > CB_OPEN_TTL) {
      // Transition to HALF_OPEN — allow one probe request through
      await setCBState(env, service, { ...s, state: 'HALF_OPEN', successes: 0 });
      console.info(`[CircuitBreaker] ${service} → HALF_OPEN (probing)`);
      return { allowed: true };
    }
    return { allowed: false, reason: `circuit_open:${service}`, retry_after: Math.ceil(CB_OPEN_TTL - elapsed) };
  }

  if (s.state === 'HALF_OPEN') return { allowed: true }; // let probe through
  return { allowed: true };
}

// ─── Timeout Wrapper ─────────────────────────────────────────────────────────
export function withTimeout(promise, ms = DEFAULT_TIMEOUT, label = 'request') {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout: ${label} exceeded ${ms}ms`)), ms)
    ),
  ]);
}

// ─── Fetch with Retry + Circuit Breaker ───────────────────────────────────────
/**
 * Resilient fetch wrapper.
 * @param {string}   service   — logical service name (e.g. 'telegram', 'nvd', 'epss')
 * @param {object}   env       — Cloudflare env (for KV circuit state)
 * @param {string}   url       — URL to fetch
 * @param {object}   [options] — fetch options
 * @param {number}   [timeoutMs] — per-attempt timeout
 * @returns {Promise<Response>}
 */
export async function resilientFetch(service, env, url, options = {}, timeoutMs = DEFAULT_TIMEOUT) {
  const circuitCheck = await checkCircuit(env, service);
  if (!circuitCheck.allowed) {
    throw Object.assign(
      new Error(`Circuit breaker OPEN for ${service}`),
      { code: 'CIRCUIT_OPEN', retry_after: circuitCheck.retry_after }
    );
  }

  let lastError;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      const backoff = BASE_BACKOFF_MS * Math.pow(2, attempt - 1) + Math.random() * 100;
      await new Promise(r => setTimeout(r, backoff));
    }
    try {
      const res = await withTimeout(fetch(url, options), timeoutMs, `${service} fetch`);
      if (res.status >= 500) {
        // Server error — treat as failure but maybe retry
        if (attempt === MAX_RETRIES - 1) {
          await recordFailure(env, service);
          throw new Error(`${service} responded with ${res.status}`);
        }
        continue;
      }
      await recordSuccess(env, service);
      return res;
    } catch (err) {
      lastError = err;
      if (err.code === 'CIRCUIT_OPEN') throw err; // don't retry open circuits
      // Retry on network errors or timeouts
      if (attempt === MAX_RETRIES - 1) {
        await recordFailure(env, service);
      }
    }
  }
  throw lastError || new Error(`${service} failed after ${MAX_RETRIES} attempts`);
}

// ─── Safe JSON fetch (returns null on error, never throws) ───────────────────
export async function safeFetchJSON(service, env, url, options = {}, timeoutMs = DEFAULT_TIMEOUT) {
  try {
    const res = await resilientFetch(service, env, url, options, timeoutMs);
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.warn(`[resilience] safeFetchJSON(${service}) failed:`, err.message);
    return null;
  }
}

// ─── Graceful Degradation Wrapper ─────────────────────────────────────────────
/**
 * Runs fn(); if it throws or times out, returns fallbackValue instead.
 * Logs the degradation but never propagates the error.
 */
export async function withFallback(label, fn, fallbackValue, timeoutMs = DEFAULT_TIMEOUT) {
  try {
    return await withTimeout(fn(), timeoutMs, label);
  } catch (err) {
    console.warn(`[degraded] ${label}:`, err.message);
    return fallbackValue;
  }
}

// ─── Retry helper (simple, no circuit breaker) ────────────────────────────────
export async function withRetry(fn, retries = 3, baseDelayMs = 300, label = 'operation') {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i < retries - 1) {
        const delay = baseDelayMs * Math.pow(2, i) + Math.random() * 50;
        console.warn(`[retry] ${label} attempt ${i + 1} failed: ${err.message}. Retrying in ${Math.round(delay)}ms`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }
  throw lastErr;
}

// ─── KV write with retry (D1 sometimes flaky on cold starts) ─────────────────
export async function kvSetWithRetry(kv, key, value, options = {}) {
  return withRetry(
    () => kv.put(key, typeof value === 'string' ? value : JSON.stringify(value), options),
    3, 100, `kv:set:${key}`
  );
}

// ─── D1 query with retry ─────────────────────────────────────────────────────
export async function d1QueryWithRetry(db, query, params = []) {
  return withRetry(
    async () => {
      const stmt   = db.prepare(query);
      const bound  = params.length ? stmt.bind(...params) : stmt;
      return await bound.all();
    },
    3, 150, `d1:${query.slice(0, 40)}`
  );
}
