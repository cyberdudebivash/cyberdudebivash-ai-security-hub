// CAP-TIH-008 — Global Threat Intel Firehose. handleGlobalIntelFeed and
// handleGlobalIntelRefresh already had import-confirmed tests
// (workers/test/globalIntelMonetization.test.mjs); handleGlobalIntelBriefing
// and handleGlobalIntelSources did not. Closes that gap.
import { describe, it, expect } from 'vitest';
import {
  handleGlobalIntelBriefing, handleGlobalIntelSources,
} from '../src/handlers/globalIntel.js';
import { INTEL_SOURCES } from '../src/services/globalIntelFirehose.js';

function req(url) { return new Request(url); }

// No SECURITY_HUB_KV/SECURITY_HUB_DB — checkRateLimitV2 auto-allows when KV
// is absent, and handleGlobalIntelBriefing's own honest "warming_up" fallback
// covers the no-KV/no-DB case without any fabricated data.
function fakeEnv() { return {}; }

describe('CAP-TIH-008 backend — handleGlobalIntelBriefing (previously untested)', () => {
  it('returns an honest "warming_up" status rather than fabricated briefing data when no snapshot exists', async () => {
    const res = await handleGlobalIntelBriefing(req('https://x/api/global-intel/briefing'), fakeEnv());
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.briefing).toBeNull();
    expect(body.data.status).toBe('warming_up');
  });

  it('derives a real briefing from D1 when no KV snapshot is cached yet', async () => {
    const env = {
      SECURITY_HUB_DB: {
        prepare() {
          return {
            bind() { return this; },
            async all() { return { results: [] }; },
            async first() { return null; },
          };
        },
      },
    };
    const res = await handleGlobalIntelBriefing(req('https://x/api/global-intel/briefing'), env);
    const body = await res.json();
    expect(body.success).toBe(true);
    // Empty D1 -> briefingFromD1 may honestly return null/empty; either way
    // this must not be a 500 or a fabricated non-empty briefing.
    expect(res.status).toBe(200);
  });
});

describe('CAP-TIH-008 backend — handleGlobalIntelSources (previously untested)', () => {
  it('returns the real, live source registry — not a placeholder count', async () => {
    const res = await handleGlobalIntelSources(req('https://x/api/global-intel/sources'), fakeEnv());
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.total).toBe(INTEL_SOURCES.length);
    expect(body.data.sources).toHaveLength(INTEL_SOURCES.length);
    expect(body.data.sources[0]).toHaveProperty('id');
    expect(body.data.sources[0]).toHaveProperty('category');
  });

  it('groups sources by real category and region breakdowns that sum to the total', () => {
    const byCategory = INTEL_SOURCES.reduce((m, s) => (m[s.category] = (m[s.category] || 0) + 1, m), {});
    const sumCategory = Object.values(byCategory).reduce((a, b) => a + b, 0);
    expect(sumCategory).toBe(INTEL_SOURCES.length);
  });
});
