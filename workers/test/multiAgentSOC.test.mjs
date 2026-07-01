/**
 * APEX Multi-Agent SOC (MASOC) v2.0 — unit tests
 *
 * Coverage:
 *   - classifyTask()       — task classifier routes to correct agent subsets
 *   - fetchCVEContext()    — CVE+EPSS enrichment (mocked fetch)
 *   - checkRateLimit()     — KV-backed rate limiting
 *   - runAgent()           — agent executor (mocked routeAICall)
 *   - handleAgentsStatus() — GET /api/agents/status
 *   - handleAgentsRun()    — POST /api/agents/run (mocked AI)
 *   - handleAgentDispatch()— POST /api/agents/dispatch/:id
 *   - Body size guard       — 413 on oversized body
 *   - Rate limit response   — 429 when limit exceeded
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Module under test ──────────────────────────────────────────────────────────
// We must mock routeAICall BEFORE importing the handler so the dynamic import
// resolves the mock. Use vi.mock() with a factory.
vi.mock('../src/core/aiProviderRouter.js', () => ({
  routeAICall: vi.fn().mockResolvedValue({
    content:  'Mocked AI response — CVE analysis complete.',
    model:    'mock-model',
    provider: 'mock-provider',
    tokens:   { total_tokens: 42 },
    latency_ms: 100,
  }),
}));

import {
  classifyTask,
  fetchCVEContext,
  fetchKEVStatus,
  fetchIOCContext,
  runAgent,
  handleAgentsStatus,
  handleAgentsRun,
  handleAgentDispatch,
} from '../src/handlers/multiAgentSOC.js';

// ── Helpers ────────────────────────────────────────────────────────────────────
function fakeEnv(overrides = {}) {
  return {
    GROQ_API_KEY:     'test-groq-key',
    DEEPSEEK_API_KEY: undefined,
    OPENROUTER_API_KEY: undefined,
    AI:               { run: vi.fn() },
    DB: {
      prepare: vi.fn(() => ({
        bind: vi.fn(() => ({ run: vi.fn().mockResolvedValue({ success: true }) })),
      })),
    },
    KV: {
      get: vi.fn().mockResolvedValue(null),
      put: vi.fn().mockResolvedValue(undefined),
    },
    ...overrides,
  };
}

function makeRequest(body, method = 'POST') {
  const json = JSON.stringify(body);
  return new Request('https://cyberdudebivash.in/api/agents/run', {
    method,
    headers: {
      'Content-Type':   'application/json',
      'Content-Length': String(new TextEncoder().encode(json).byteLength),
    },
    body: json,
  });
}

const fakeAuth = { user_id: 'test-user-123', tier: 'ENTERPRISE', authenticated: true };

// ── Default global fetch stub ──────────────────────────────────────────────────
// handleAgentsRun()/handleAgentDispatch() internally call fetchCVEContext(),
// which hits real NVD/EPSS endpoints for any CVE-containing message. Without a
// stub, those tests make live network calls — in a network-restricted CI
// runner the request blocks until fetchCVEContext's internal 6000ms
// AbortSignal.timeout fires, which exceeds vitest's 5000ms test timeout and
// causes an intermittent "Test timed out" failure unrelated to the code under
// test. The fetchCVEContext() describe block below stubs fetch per-test with
// specific payloads and cleans up via vi.unstubAllGlobals() — this default
// simply ensures every other test resolves fast and deterministically.
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false })));
});
afterEach(() => {
  vi.unstubAllGlobals();
});

// ── classifyTask ───────────────────────────────────────────────────────────────
describe('classifyTask()', () => {
  it('routes a CVE message to cve_intel agent', () => {
    const agents = classifyTask('CVE-2024-3400 detected on our firewall — what should we do?');
    expect(agents).toContain('cve_intel');
  });

  it('routes an IP address message to ioc_hunter', () => {
    const agents = classifyTask('suspicious IP 45.33.32.156 communicating with our server');
    expect(agents).toContain('ioc_hunter');
  });

  it('routes a ransomware message to ir_playbook', () => {
    const agents = classifyTask('ransomware compromised our endpoints — full incident response needed');
    expect(agents).toContain('ir_playbook');
  });

  it('routes a compliance message to compliance_guardian', () => {
    const agents = classifyTask('ISO 27001 compliance audit for our cloud infrastructure');
    expect(agents).toContain('compliance_guardian');
  });

  it('routes a SIEM message to siem_defender', () => {
    const agents = classifyTask('generate Sigma and Splunk SPL detection rules for this threat');
    expect(agents).toContain('siem_defender');
  });

  it('returns 4 default agents for a broad query with no domain keywords', () => {
    const agents = classifyTask('help me with security');
    expect(agents.length).toBeGreaterThanOrEqual(3);
    expect(agents.length).toBeLessThanOrEqual(9);
  });

  it('never includes risk_synthesizer in classified agent list', () => {
    const agents = classifyTask('CVE-2021-44228 Log4Shell — full analysis');
    expect(agents).not.toContain('risk_synthesizer');
  });

  it('returns at most 6 agents for any query', () => {
    const agents = classifyTask('CVE exploit IOC hunt sigma splunk sentinel compliance NIST ISO ransomware incident response');
    expect(agents.length).toBeLessThanOrEqual(6);
  });

  it('returns at least 3 agents even for weak matches', () => {
    const agents = classifyTask('ip address malware');
    expect(agents.length).toBeGreaterThanOrEqual(3);
  });
});

// ── fetchCVEContext ────────────────────────────────────────────────────────────
describe('fetchCVEContext()', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('returns null when no CVE in message', async () => {
    const result = await fetchCVEContext('check my firewall settings', {});
    expect(result).toBeNull();
  });

  it('fetches NVD + EPSS and returns merged result', async () => {
    const nvdPayload = {
      vulnerabilities: [{
        cve: {
          descriptions: [{ lang: 'en', value: 'Critical buffer overflow in Palo Alto GlobalProtect.' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0 } }] },
        },
      }],
    };
    const epssPayload = { data: [{ cve: 'CVE-2024-3400', epss: '0.97234', percentile: '0.99876' }] };

    let fetchCount = 0;
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      fetchCount++;
      if (String(url).includes('nvd.nist.gov')) return { ok: true, json: async () => nvdPayload };
      if (String(url).includes('first.org'))    return { ok: true, json: async () => epssPayload };
      return { ok: false };
    }));

    const result = await fetchCVEContext('CVE-2024-3400 on our firewall', {});
    expect(result).not.toBeNull();
    expect(result.cve_id).toBe('CVE-2024-3400');
    expect(result.cvss_score).toBe(10.0);
    expect(result.epss_score).toBeCloseTo(0.97234, 4);
    expect(result.epss_percentile).toBeCloseTo(0.99876, 4);
    expect(result.source).toBe('NVD+EPSS');
    expect(fetchCount).toBe(2); // both NVD and EPSS called
    vi.unstubAllGlobals();
  });

  it('returns partial result if EPSS fails but NVD succeeds', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('nvd.nist.gov')) return {
        ok: true,
        json: async () => ({
          vulnerabilities: [{ cve: {
            descriptions: [{ lang: 'en', value: 'Test CVE description' }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }] },
          }}],
        }),
      };
      return { ok: false }; // EPSS fails
    }));

    const result = await fetchCVEContext('analyze CVE-2021-44228', {});
    expect(result).not.toBeNull();
    expect(result.cvss_score).toBe(7.5);
    expect(result.epss_score).toBeNull();
    vi.unstubAllGlobals();
  });

  it('returns null when both NVD and EPSS fail', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('Network error'); }));
    const result = await fetchCVEContext('CVE-2024-9999', {});
    expect(result).toBeNull();
    vi.unstubAllGlobals();
  });

  it('normalises CVE ID to uppercase', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      expect(String(url)).toContain('CVE-2024-3400'); // not lowercase
      return { ok: false };
    }));
    await fetchCVEContext('cve-2024-3400 detected', {});
    vi.unstubAllGlobals();
  });
});

// ── fetchKEVStatus ─────────────────────────────────────────────────────────────
describe('fetchKEVStatus()', () => {
  it('returns {in_kev:false} when no KEV catalog in KV', async () => {
    const env = fakeEnv();
    const result = await fetchKEVStatus('CVE-2024-3400 analysis', env);
    expect(result).toEqual({ in_kev: false });
  });

  it('returns {in_kev:true} when CVE found in KV catalog', async () => {
    const env = fakeEnv({
      KV: { get: vi.fn().mockResolvedValue({ lookup: { 'CVE-2024-3400': { dateAdded: '2024-04-12' } } }) },
    });
    const result = await fetchKEVStatus('CVE-2024-3400', env);
    expect(result.in_kev).toBe(true);
    expect(result.details).toBeDefined();
  });

  it('returns null when no CVE in message', async () => {
    const result = await fetchKEVStatus('general security question', fakeEnv());
    expect(result).toBeNull();
  });
});

// ── runAgent ──────────────────────────────────────────────────────────────────
describe('runAgent()', () => {
  it('returns success result with all required fields', async () => {
    const env = fakeEnv();
    const result = await runAgent('cve_intel', 'CVE-2024-3400 analysis', {}, env, 'ENTERPRISE');
    expect(result.agent_id).toBe('cve_intel');
    expect(result.agent_name).toBe('CVE Intel Agent');
    expect(result.icon).toBe('🔍');
    expect(result.description).toBeTruthy();
    expect(result.status).toBe('success');
    expect(result.content).toBeTruthy();
    expect(typeof result.latency_ms).toBe('number');
    expect(result.model).toBeTruthy();
    expect(result.provider).toBeTruthy();
  });

  it('returns no_provider status when routeAICall returns null', async () => {
    const { routeAICall } = await import('../src/core/aiProviderRouter.js');
    routeAICall.mockResolvedValueOnce(null);

    const env = fakeEnv({ GROQ_API_KEY: undefined });
    const result = await runAgent('ioc_hunter', 'check IP 1.2.3.4', {}, env, 'ENTERPRISE');
    expect(result.status).toBe('no_provider');
    expect(result.content).toContain('GROQ_API_KEY');
  });

  it('throws on unknown agent id', async () => {
    await expect(runAgent('nonexistent_agent', 'test', {}, fakeEnv(), 'ENTERPRISE'))
      .rejects.toThrow('Unknown agent: nonexistent_agent');
  });

  it('enriches prompt with CVE context when provided', async () => {
    const { routeAICall } = await import('../src/core/aiProviderRouter.js');
    let capturedPrompt = '';
    routeAICall.mockImplementationOnce(async (env, opts) => {
      capturedPrompt = opts.prompt;
      return { content: 'ok', model: 'm', provider: 'p', tokens: null };
    });

    const ctx = {
      cve: { cve_id: 'CVE-2024-3400', cvss_score: 10.0, epss_score: 0.97, epss_percentile: 0.999, description: 'Critical vuln' },
      kev: { in_kev: true },
      ioc: null,
    };
    await runAgent('cve_intel', 'CVE-2024-3400 detected', ctx, fakeEnv(), 'ENTERPRISE');

    expect(capturedPrompt).toContain('CVSS v3.1:       10');
    expect(capturedPrompt).toContain('EPSS Score:      97.00%');
    expect(capturedPrompt).toContain('CISA KEV');
    expect(capturedPrompt).toContain('actively exploited');
  });

  it('handles agent timeout gracefully', async () => {
    const { routeAICall } = await import('../src/core/aiProviderRouter.js');
    // Simulate AbortError (timeout)
    routeAICall.mockRejectedValueOnce(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));

    const result = await runAgent('threat_hunter', 'hunt for lateral movement', {}, fakeEnv(), 'ENTERPRISE');
    expect(result.status).toBe('error');
    expect(result.content).toContain('timed out');
  });
});

// ── handleAgentsStatus ─────────────────────────────────────────────────────────
describe('handleAgentsStatus()', () => {
  it('returns 200 with all 9 agents when providers configured', async () => {
    const req = new Request('https://cyberdudebivash.in/api/agents/status');
    const env = fakeEnv();
    const resp = await handleAgentsStatus(req, env, fakeAuth);
    const body = await resp.json();

    expect(resp.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.total_agents).toBe(9);
    expect(body.status).toBe('OPERATIONAL');
    expect(body.ai_providers.groq).toBe(true);
    expect(body.agents.length).toBe(9);
    expect(body.rate_limits.run_per_minute).toBe(5);
    expect(body.enrichment.epss).toContain('first.org');
  });

  it('returns NO_PROVIDER_CONFIGURED when no keys set', async () => {
    const req = new Request('https://cyberdudebivash.in/api/agents/status');
    const env = fakeEnv({ GROQ_API_KEY: undefined, AI: undefined });
    const resp = await handleAgentsStatus(req, env, fakeAuth);
    const body = await resp.json();
    expect(body.status).toBe('NO_PROVIDER_CONFIGURED');
  });

  it('includes version MASOC_VERSION in response', async () => {
    const req = new Request('https://cyberdudebivash.in/api/agents/status');
    const resp = await handleAgentsStatus(req, fakeEnv(), fakeAuth);
    const body = await resp.json();
    expect(body.version).toBe('2.0');
  });
});

// ── handleAgentsRun ────────────────────────────────────────────────────────────
describe('handleAgentsRun()', () => {
  it('returns 400 on empty message', async () => {
    const req  = makeRequest({ message: '' });
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);
    expect(resp.status).toBe(400);
  });

  it('returns 400 on missing body', async () => {
    const req  = makeRequest({});
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);
    expect(resp.status).toBe(400);
  });

  it('returns 413 on body exceeding 8 KB', async () => {
    const bigMessage = 'x'.repeat(9000);
    const body = JSON.stringify({ message: bigMessage });
    const req  = new Request('https://cyberdudebivash.in/api/agents/run', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(body.length) },
      body,
    });
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);
    expect(resp.status).toBe(413);
  });

  it('returns 429 when rate limit exceeded', async () => {
    const env = fakeEnv({
      KV: { get: vi.fn().mockResolvedValue('5'), put: vi.fn() }, // already at limit
    });
    const req  = makeRequest({ message: 'CVE-2024-3400 analysis' });
    const resp = await handleAgentsRun(req, env, fakeAuth);
    expect(resp.status).toBe(429);
    const body = await resp.json();
    expect(body.error).toContain('rate limit');
  });

  it('returns success with agent_results and synthesis', async () => {
    const req  = makeRequest({ message: 'CVE-2024-3400 analysis', agents: ['cve_intel'] });
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);

    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.agents_activated).toBe(1);
    expect(Array.isArray(body.agent_results)).toBe(true);
    expect(body.agent_results[0].agent_id).toBe('cve_intel');
    expect(body.synthesis).toBeDefined();
    expect(typeof body.total_latency_ms).toBe('number');
    expect(body.context_enriched).toBeDefined();
    expect(body.timestamp).toBeTruthy();
  });

  it('filters unknown agent IDs from request', async () => {
    const req  = makeRequest({ message: 'malware hunt', agents: ['cve_intel', 'nonexistent_xyz'] });
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.agents_activated).toBe(1); // only cve_intel is valid
  });

  it('each agent_result contains all required fields', async () => {
    const req  = makeRequest({ message: 'ransomware incident', agents: ['ir_playbook'] });
    const resp = await handleAgentsRun(req, fakeEnv(), fakeAuth);
    const body = await resp.json();
    const r    = body.agent_results[0];
    expect(r).toHaveProperty('agent_id');
    expect(r).toHaveProperty('agent_name');
    expect(r).toHaveProperty('icon');
    expect(r).toHaveProperty('description');
    expect(r).toHaveProperty('status');
    expect(r).toHaveProperty('content');
    expect(r).toHaveProperty('model');
    expect(r).toHaveProperty('provider');
    expect(r).toHaveProperty('latency_ms');
    expect(r).toHaveProperty('tokens');
  });

  it('uses crypto.randomUUID for D1 task ID (not Math.random)', async () => {
    const insertedIds = [];
    const env = fakeEnv({
      DB: {
        prepare: vi.fn(() => ({
          bind: vi.fn((...args) => {
            insertedIds.push(args[0]); // first bind arg is task id
            return { run: vi.fn().mockResolvedValue({ success: true }) };
          }),
        })),
      },
    });
    const req = makeRequest({ message: 'CVE-2024-3400 analysis', agents: ['cve_intel'] });
    await handleAgentsRun(req, env, fakeAuth);
    // Task ID must NOT start with a Math.random pattern (pure hex) but must be masoc_ prefixed
    expect(insertedIds[0]).toMatch(/^masoc_/);
    // Must contain a UUID segment (8 hex chars from crypto.randomUUID)
    expect(insertedIds[0]).toMatch(/^masoc_[a-z0-9]+_[a-f0-9-]{8,}/);
  });
});

// ── handleAgentDispatch ────────────────────────────────────────────────────────
describe('handleAgentDispatch()', () => {
  it('returns 404 for unknown agent', async () => {
    const req  = makeRequest({ message: 'test query' });
    const resp = await handleAgentDispatch(req, fakeEnv(), fakeAuth, 'nonexistent_agent');
    expect(resp.status).toBe(404);
    const body = await resp.json();
    expect(body.error).toContain('nonexistent_agent');
    expect(body.error).toContain('Available:');
  });

  it('returns success for valid agent + message', async () => {
    const req  = makeRequest({ message: 'CVE-2024-3400 — what is the EPSS score?' });
    const resp = await handleAgentDispatch(req, fakeEnv(), fakeAuth, 'cve_intel');
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.agent.agent_id).toBe('cve_intel');
    expect(body.context_enriched).toBeDefined();
    expect(body.timestamp).toBeTruthy();
  });

  it('returns 400 for missing message', async () => {
    const req  = makeRequest({ message: '' });
    const resp = await handleAgentDispatch(req, fakeEnv(), fakeAuth, 'cve_intel');
    expect(resp.status).toBe(400);
  });

  it('dispatches all 9 valid agent IDs without error', async () => {
    const validIds = [
      'cve_intel','ioc_hunter','siem_defender','threat_hunter',
      'ir_playbook','compliance_guardian','red_team','zero_trust_sentinel','risk_synthesizer',
    ];
    for (const id of validIds) {
      const req  = makeRequest({ message: 'security analysis task for dispatch test' });
      const resp = await handleAgentDispatch(req, fakeEnv(), fakeAuth, id);
      expect(resp.status).toBe(200);
    }
  });
});
