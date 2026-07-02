/* Uptime engine — availability vs latency reconciliation (GET /api/uptime).
 *
 * The engine previously computed uptime_pct = COUNT(status='operational') / total,
 * so every "degraded" sample (service RESPONDED but slower than the 1000ms warn
 * threshold) was counted as downtime. That produced the indefensible, internally
 * contradictory figure the acceptance board flagged: ~95.8% "uptime" alongside
 * outage_events: 0. A slow-but-up service is available; degraded belongs to a
 * latency SLO, not to downtime.
 *
 * These tests lock: uptime_pct = availability (responded = operational + degraded,
 * i.e. NOT partial/major outage), with degraded reported separately so latency is
 * disclosed rather than hidden.
 */
import { describe, it, expect } from 'vitest';
import { handlePublicUptime } from '../src/handlers/eop/uptime.js';

// DB stub: the operational_history window aggregate returns a fixed row with a
// large degraded share and a small real-outage share. Everything else is empty.
function dbStub(agg) {
  return {
    prepare(sql) {
      return {
        bind() { return this; },
        async first() {
          // Window aggregate over operational_history (has our new `available` column)
          if (/FROM operational_history/.test(sql) && /AS available/.test(sql)) return agg;
          if (/AVG\(\s*\n?\s*\(julianday/.test(sql) || /avg_minutes/.test(sql)) return { avg_minutes: null };
          if (/FROM incidents/.test(sql)) return { c: 0 };
          return null;
        },
        async all() {
          if (/GROUP BY component/.test(sql)) return { results: [] };
          if (/FROM incidents/.test(sql)) return { results: [] };
          return { results: [] };
        },
      };
    },
  };
}

const req = new Request('https://cyberdudebivash.in/api/uptime');

describe('GET /api/uptime — availability, not latency', () => {
  it('counts degraded-but-responding samples as AVAILABLE (up), reports degraded separately', async () => {
    // 100 samples: 80 operational, 18 degraded (slow but up), 2 real outage.
    // Availability = (80 + 18) / 100 = 98.0%.  Old (broken) math = 80/100 = 80.0%.
    const agg = {
      total: 100, available: 98, fully_ok: 80, degraded_count: 18,
      avg_latency: 340, min_latency: 5, max_latency: 1500, outage_count: 2,
    };
    const res = await handlePublicUptime(req, { DB: dbStub(agg) });
    const body = await res.json();
    const w = body.uptime['24h'];

    expect(w.uptime_pct).toBe(98);          // availability, NOT 80
    expect(w.outage_events).toBe(2);        // only real outages count against availability
    expect(w.degraded_pct).toBe(18);        // latency disclosed, not hidden
    expect(w.degraded_samples).toBe(18);
    expect(w.avg_latency_ms).toBe(340);
  });

  it('a service that is slow on every sample but never down reports ~100% availability', async () => {
    // 50 samples, ALL degraded (up but slow), zero outages → 100% available.
    const agg = {
      total: 50, available: 50, fully_ok: 0, degraded_count: 50,
      avg_latency: 1200, min_latency: 1010, max_latency: 1490, outage_count: 0,
    };
    const res = await handlePublicUptime(req, { DB: dbStub(agg) });
    const w = (await res.json()).uptime['7d'];
    expect(w.uptime_pct).toBe(100);         // available the whole time
    expect(w.degraded_pct).toBe(100);       // but 100% slow — the honest latency signal
    expect(w.outage_events).toBe(0);
  });

  it('real outages DO reduce availability', async () => {
    const agg = {
      total: 100, available: 90, fully_ok: 90, degraded_count: 0,
      avg_latency: 200, min_latency: 5, max_latency: 900, outage_count: 10,
    };
    const res = await handlePublicUptime(req, { DB: dbStub(agg) });
    const w = (await res.json()).uptime['30d'];
    expect(w.uptime_pct).toBe(90);          // 10 genuine outages → 90% available
    expect(w.outage_events).toBe(10);
  });
});
