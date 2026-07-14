/* Priority 5 — Operational Quality: uptime/health-probe cron logging noise
 * (2026-07-14 commercial-integrity audit continuation). index.js's
 * scheduled() runs the EOP 9-component health probe on every one of the 5
 * cron schedules (~34 times/day) and, on success, used to log a fixed,
 * content-free string — '[CRON] EOP health probes: operational_history
 * seeded' — every single time. That line carried no diagnostic value beyond
 * "it ran" (already established by the '[CRON] Trigger:' line logged
 * immediately before it), while the actual observability — the probed
 * component statuses — is durably written to operational_history regardless
 * of whether this line exists. Removed the success-case log; the failure
 * case (console.error) is untouched, so a real probe failure still surfaces.
 *
 * A full behavioral test of scheduled() is impractical here — it fires ~15
 * unrelated cron tasks (threat intel ingestion, CVE feeds, etc.) as
 * fire-and-forget ctx.waitUntil() promises with real external fetches, none
 * of which should run in a unit test. This locks in the specific log-line
 * change via source inspection (the change is a straightforward removal of
 * one .then() callback, not new branching logic to unit-test), plus a direct
 * behavioral check that handleHealthV2 itself does not log anything on a
 * normal call. */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { handleHealthV2 } from '../src/handlers/eop/health.js';

const root = resolve(import.meta.dirname, '..');
const src = readFileSync(resolve(root, 'src/index.js'), 'utf8');

describe('scheduled() EOP health-probe block — no more content-free success log', () => {
  it('no longer logs the fixed "operational_history seeded" string on every cron tick', () => {
    expect(src).not.toContain('EOP health probes: operational_history seeded');
  });

  it('still logs a real error if the health probe itself throws', () => {
    const idx = src.indexOf('EVERY CRON FIRING: EOP 9-component health probe');
    expect(idx).toBeGreaterThan(-1);
    const block = src.slice(idx, idx + 1000);
    expect(block).toContain("console.error('[CRON] EOP health probe error:', e?.message)");
  });
});

describe('handleHealthV2 — does not log anything itself on a normal call', () => {
  afterEach(() => vi.restoreAllMocks());

  it('produces zero console.log/console.error output for a healthy probe pass', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const env = {
      DB: { prepare: () => ({ bind: () => ({ first: async () => ({ alive: 1, c: 0 }), run: async () => ({}) }), first: async () => ({ alive: 1, c: 0 }) }) },
      KV: { put: async () => {}, get: async () => '1', delete: async () => {} },
    };
    await handleHealthV2(new Request('https://internal/api/platform/health/v2'), env);

    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });
});
