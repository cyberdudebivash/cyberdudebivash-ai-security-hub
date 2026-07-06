/* Coverage for the second wave of copilot capabilities: real token streaming
 * (streamDirectAnswer), structured/JSON-mode output, org-role RBAC layered on
 * tier gating, KV-backed admin-configurable prompt/routing, the multi-agent
 * orchestration tool (composes with the existing multiAgentSOC.js rather than
 * reinventing it), and the suggested_actions side-channel that keeps payment
 * creation a human-only, explicit-confirmation action.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { PROVIDERS, PROVIDER_CONFIG } from '../src/core/aiProviderRouter.js';
import {
  streamDirectAnswer,
  generateStructuredOutput,
  resolveOrgRole,
  filterToolsByRole,
  getCopilotConfig,
  handleCopilotAdminConfigGet,
  handleCopilotAdminConfigPut,
  buildSuggestedActions,
  handleCopilotQuickAction,
  handleCopilotChatStream,
  executeTool,
  TOOL_REGISTRY,
} from '../src/handlers/aiSecurityCopilot.js';

vi.mock('../src/handlers/socInvestigations.js', () => ({
  handleInvestigationSummary: vi.fn(async (req) => Response.json({ received_org_id: req.user.org_id })),
  handleEscalateCase:         vi.fn(async (req) => Response.json({ received_org_id: req.user.org_id })),
}));

function sseBody(lines) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const line of lines) controller.enqueue(encoder.encode(line));
      controller.close();
    },
  });
}

function fakeGroqEnv() {
  return { GROQ_API_KEY: 'test-key-not-real' };
}

describe('streamDirectAnswer — real token streaming', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('relays content deltas as they arrive and returns the full concatenated text', async () => {
    const chunks = [
      `data: ${JSON.stringify({ model: 'llama-3.3-70b-versatile', choices: [{ delta: { content: 'Hello ' } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'world' } }] })}\n\n`,
      `data: [DONE]\n\n`,
    ];
    global.fetch = vi.fn(async () => new Response(sseBody(chunks), { status: 200 }));

    const deltas = [];
    const result = await streamDirectAnswer(
      fakeGroqEnv(), PROVIDERS.GROQ, 'llama-3.3-70b-versatile', 'sys', [{ role: 'user', content: 'hi' }], [], 512,
      (d) => deltas.push(d),
    );

    expect(result.ok).toBe(true);
    expect(result.content).toBe('Hello world');
    expect(deltas).toEqual(['Hello ', 'world']);
    expect(result.model).toBe('llama-3.3-70b-versatile');
  });

  it('aborts and reports needsTools when the model starts a tool call', async () => {
    const chunks = [
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'Let me check' } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { name: 'get_kev_feed' } }] } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'this should not be relayed' } }] })}\n\n`,
    ];
    global.fetch = vi.fn(async () => new Response(sseBody(chunks), { status: 200 }));

    const deltas = [];
    const result = await streamDirectAnswer(
      fakeGroqEnv(), PROVIDERS.GROQ, 'llama-3.3-70b-versatile', 'sys', [{ role: 'user', content: 'top KEV entries' }], [], 512,
      (d) => deltas.push(d),
    );

    expect(result.ok).toBe(false);
    expect(result.needsTools).toBe(true);
    // Content streamed before the tool call started is fine; nothing after it should leak.
    expect(deltas).toEqual(['Let me check']);
  });

  it('fails cleanly (ok:false) on a non-200 response, never throws', async () => {
    global.fetch = vi.fn(async () => new Response('rate limited', { status: 429 }));
    const result = await streamDirectAnswer(fakeGroqEnv(), PROVIDERS.GROQ, 'm', 'sys', [{ role: 'user', content: 'x' }], [], 512, () => {});
    expect(result.ok).toBe(false);
  });

  it('returns ok:false immediately (no network call) when the provider has no API key', async () => {
    global.fetch = vi.fn();
    const result = await streamDirectAnswer({}, PROVIDERS.GROQ, 'm', 'sys', [{ role: 'user', content: 'x' }], [], 512, () => {});
    expect(result.ok).toBe(false);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('generateStructuredOutput — opt-in JSON mode (additive, never touches the main chat path)', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('returns the parsed JSON object on success', async () => {
    const payload = { summary: 'CRITICAL RCE', key_points: ['unauthenticated', 'actively exploited'], severity: 'CRITICAL', recommended_actions: ['patch now'] };
    global.fetch = vi.fn(async () => Response.json({ choices: [{ message: { content: JSON.stringify(payload) } }] }));
    const result = await generateStructuredOutput(fakeGroqEnv(), PROVIDERS.GROQ, 'llama-3.3-70b-versatile', 'CVE-2024-3400 is a critical RCE.');
    expect(result).toEqual(payload);
  });

  it('fails open (returns null) when the provider rejects the request', async () => {
    global.fetch = vi.fn(async () => new Response('bad request', { status: 400 }));
    const result = await generateStructuredOutput(fakeGroqEnv(), PROVIDERS.GROQ, 'm', 'some answer');
    expect(result).toBeNull();
  });

  it('fails open (returns null) on malformed JSON from the model', async () => {
    global.fetch = vi.fn(async () => Response.json({ choices: [{ message: { content: 'not json{{{' } }] }));
    const result = await generateStructuredOutput(fakeGroqEnv(), PROVIDERS.GROQ, 'm', 'some answer');
    expect(result).toBeNull();
  });

  it('returns null with no network call when no provider key is configured', async () => {
    global.fetch = vi.fn();
    const result = await generateStructuredOutput({}, PROVIDERS.GROQ, 'm', 'some answer');
    expect(result).toBeNull();
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

function makeOrgDB() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE org_members (org_id TEXT, user_id TEXT, role TEXT, status TEXT)`);
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

describe('resolveOrgRole / filterToolsByRole — RBAC layered on top of tier gating', () => {
  it('returns null (fails open) when the user has no org membership', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    const role = await resolveOrgRole(env, { user_id: 'u1' });
    expect(role).toBeNull();
    const { tools, role: r } = await filterToolsByRole(env, { user_id: 'u1' }, TOOL_REGISTRY);
    expect(r).toBeNull();
    expect(tools.length).toBe(TOOL_REGISTRY.length); // no restriction applied
  });

  it('VIEWER role is restricted to read-only tools', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org1', 'u2', 'VIEWER', 'active');
    const { tools, role } = await filterToolsByRole(env, { user_id: 'u2' }, TOOL_REGISTRY);
    expect(role).toBe('VIEWER');
    expect(tools.length).toBeLessThan(TOOL_REGISTRY.length);
    expect(tools.every(t => t.readOnly !== false)).toBe(true);
    // A known write tool must be excluded for VIEWER.
    expect(tools.find(t => t.name === 'book_demo')).toBeUndefined();
  });

  it('ANALYST role (has write permission) keeps full tool access', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org1', 'u3', 'ANALYST', 'active');
    const { tools, role } = await filterToolsByRole(env, { user_id: 'u3' }, TOOL_REGISTRY);
    expect(role).toBe('ANALYST');
    expect(tools.length).toBe(TOOL_REGISTRY.length);
  });

  it('picks the highest-privilege role across multiple org memberships when no org_id is given', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org1', 'u4', 'VIEWER', 'active');
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org2', 'u4', 'OWNER', 'active');
    const role = await resolveOrgRole(env, { user_id: 'u4' });
    expect(role).toBe('OWNER');
  });

  it('respects a specific requested org_id over the highest-privilege fallback', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org1', 'u5', 'VIEWER', 'active');
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org2', 'u5', 'OWNER', 'active');
    const role = await resolveOrgRole(env, { user_id: 'u5' }, 'org1');
    expect(role).toBe('VIEWER');
  });

  it('ignores suspended/invited memberships', async () => {
    const env = { SECURITY_HUB_DB: makeOrgDB() };
    env.SECURITY_HUB_DB._sqlite.prepare('INSERT INTO org_members VALUES (?,?,?,?)').run('org1', 'u6', 'VIEWER', 'suspended');
    const role = await resolveOrgRole(env, { user_id: 'u6' });
    expect(role).toBeNull();
  });
});

function mapKV() {
  const store = new Map();
  return {
    async get(k, opts) {
      const raw = store.has(k) ? store.get(k) : null;
      if (raw === null) return null;
      return opts?.type === 'json' ? JSON.parse(raw) : raw;
    },
    async put(k, v) { store.set(k, v); },
  };
}

describe('Admin-configurable prompt/routing (hot-reload, no deploy)', () => {
  function makeReq(method, body) {
    return new Request('https://x/api/copilot/admin/config', {
      method, headers: { 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  }

  it('GET returns platform defaults when nothing has been configured', async () => {
    const env = { SECURITY_HUB_KV: mapKV() };
    const res = await handleCopilotAdminConfigGet(makeReq('GET'), env, { isAdmin: true });
    const body = await res.json();
    expect(body.data.config.system_prompt_addendum).toBe('');
    expect(body.data.config.tool_tier_overrides).toEqual({});
    expect(body.data.valid_tool_names).toContain('get_platform_health');
  });

  it('rejects non-admin callers on both GET and PUT', async () => {
    const env = { SECURITY_HUB_KV: mapKV() };
    const getRes = await handleCopilotAdminConfigGet(makeReq('GET'), env, { isAdmin: false });
    expect(getRes.status).toBe(403);
    const putRes = await handleCopilotAdminConfigPut(makeReq('PUT', { system_prompt_addendum: 'x' }), env, { isAdmin: false });
    expect(putRes.status).toBe(403);
  });

  it('PUT persists a system-prompt addendum and GET reflects it', async () => {
    const env = { SECURITY_HUB_KV: mapKV() };
    const putRes = await handleCopilotAdminConfigPut(makeReq('PUT', { system_prompt_addendum: 'Always mention our SOC2 report.' }), env, { isAdmin: true });
    expect(putRes.status).toBe(200);
    const config = await getCopilotConfig(env);
    expect(config.system_prompt_addendum).toBe('Always mention our SOC2 report.');
  });

  it('PUT persists per-tool tier overrides and rejects unknown tools/tiers', async () => {
    const env = { SECURITY_HUB_KV: mapKV() };
    const ok = await handleCopilotAdminConfigPut(makeReq('PUT', { tool_tier_overrides: { get_platform_health: ['ENTERPRISE'] } }), env, { isAdmin: true });
    expect(ok.status).toBe(200);
    const config = await getCopilotConfig(env);
    expect(config.tool_tier_overrides.get_platform_health).toEqual(['ENTERPRISE']);

    const badTool = await handleCopilotAdminConfigPut(makeReq('PUT', { tool_tier_overrides: { not_a_real_tool: ['FREE'] } }), env, { isAdmin: true });
    expect(badTool.status).toBe(400);

    const badTier = await handleCopilotAdminConfigPut(makeReq('PUT', { tool_tier_overrides: { get_platform_health: ['NOT_A_TIER'] } }), env, { isAdmin: true });
    expect(badTier.status).toBe(400);
  });

  it('a tool_tier_override actually changes what /api/copilot/chat exposes for that tier', async () => {
    const env = { SECURITY_HUB_KV: mapKV() };
    await handleCopilotAdminConfigPut(makeReq('PUT', { tool_tier_overrides: { get_kev_feed: ['ENTERPRISE'] } }), env, { isAdmin: true });

    // Simulate the same tier-filter logic handleCopilotChat/prepareChatTurn apply.
    const config = await getCopilotConfig(env);
    const tier = 'FREE';
    const effective = TOOL_REGISTRY.filter(t => {
      const tiers = config.tool_tier_overrides?.[t.name] !== undefined ? config.tool_tier_overrides[t.name] : t.tiers;
      return !tiers || tiers.includes(tier);
    });
    expect(effective.find(t => t.name === 'get_kev_feed')).toBeUndefined();
  });
});

describe('buildSuggestedActions — payment stays a human-click, never LLM-triggered', () => {
  it('emits a book_assessment action for a successful get_assessment_quote call', () => {
    const actions = buildSuggestedActions([
      { name: 'get_assessment_quote', args: {}, result: { plan: 'standard', label: 'Standard Assessment', price_inr: 9999, delivery_h: 72 } },
    ]);
    expect(actions).toEqual([{ type: 'book_assessment', label: 'Book Standard Assessment — ₹9999', plan: 'standard', price_inr: 9999, delivery_h: 72 }]);
  });

  it('emits nothing for a failed quote or unrelated tool calls', () => {
    expect(buildSuggestedActions([{ name: 'get_assessment_quote', result: { error: 'bad plan' } }])).toEqual([]);
    expect(buildSuggestedActions([{ name: 'get_platform_health', result: { status: 'OPERATIONAL' } }])).toEqual([]);
    expect(buildSuggestedActions([])).toEqual([]);
    expect(buildSuggestedActions(undefined)).toEqual([]);
  });
});

describe('run_multi_agent_analysis tool — composes with the existing multiAgentSOC.js', () => {
  afterEach(() => { vi.doUnmock('../src/handlers/multiAgentSOC.js'); vi.resetModules(); });

  it('delegates to handleAgentsRun with the task as the message', async () => {
    vi.doMock('../src/handlers/multiAgentSOC.js', () => ({
      handleAgentsRun: vi.fn(async (req) => {
        const body = await req.json();
        return Response.json({ success: true, task: body.message, agents_activated: body.agents?.length || 3, synthesis: { content: 'HIGH risk, Risk Score: 72' } });
      }),
    }));
    const { handleCopilotQuickAction: freshHandler } = await import('../src/handlers/aiSecurityCopilot.js');
    const req = new Request('https://x/api/copilot/quick-action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ skill: 'run_multi_agent_analysis', params: { task: 'Assess our vendor exposure to Log4Shell' } }),
    });
    const res = await freshHandler(req, {}, { tier: 'ENTERPRISE' });
    const body = await res.json();
    // multiAgentSOC.js's handleAgentsRun returns a flat Response.json(...), unlike
    // the ok()-wrapped handlers elsewhere — result is not double-nested under .data.
    expect(body.data.result.success).toBe(true);
    expect(body.data.result.task).toBe('Assess our vendor exposure to Log4Shell');
  });

  it('rejects a missing task before calling the agent system', async () => {
    const res = await handleCopilotQuickAction(new Request('https://x/api/copilot/quick-action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ skill: 'run_multi_agent_analysis', params: {} }),
    }), {}, { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.data.result.error).toMatch(/task is required/);
  });
});

describe('handleCopilotChatStream — SSE endpoint smoke test', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  async function collectSSE(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    const events = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    const blocks = buf.split('\n\n').filter(Boolean);
    for (const block of blocks) {
      const eventLine = block.split('\n').find(l => l.startsWith('event:'));
      const dataLine  = block.split('\n').find(l => l.startsWith('data:'));
      if (eventLine && dataLine) events.push({ type: eventLine.slice(6).trim(), data: JSON.parse(dataLine.slice(5).trim()) });
    }
    return events;
  }

  it('streams a direct answer end-to-end and emits a final done event', async () => {
    const chunks = [
      `data: ${JSON.stringify({ model: 'llama-3.3-70b-versatile', choices: [{ delta: { content: 'CVE-2024-3400 ' } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'is CRITICAL.' } }] })}\n\n`,
      `data: [DONE]\n\n`,
    ];
    global.fetch = vi.fn(async () => new Response(sseBody(chunks), { status: 200 }));

    const env = { GROQ_API_KEY: 'test-key', SECURITY_HUB_KV: mapKV() };
    const req = new Request('https://x/api/copilot/chat/stream', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'What is CVE-2024-3400?', session_id: 'sse-test' }),
    });
    const res = await handleCopilotChatStream(req, env, { tier: 'FREE', userId: 'u-sse' });
    expect(res.headers.get('Content-Type')).toContain('text/event-stream');

    const events = await collectSSE(res);
    const types = events.map(e => e.type);
    expect(types).toContain('status');
    expect(types).toContain('delta');
    expect(types).toContain('done');
    const deltaText = events.filter(e => e.type === 'delta').map(e => e.data.text).join('');
    expect(deltaText).toBe('CVE-2024-3400 is CRITICAL.');
    const done = events.find(e => e.type === 'done');
    expect(done.data.session_id).toBe('sse-test');
  });

  it('emits an error event (not a thrown exception) when burst-limited', async () => {
    const env = { GROQ_API_KEY: 'test-key', SECURITY_HUB_KV: mapKV() };
    const userId = 'burst-sse-user';
    // Exhaust the FREE tier burst budget (3/min) first via the JSON endpoint's helper path.
    const { checkBurstLimit } = await import('../src/handlers/aiSecurityCopilot.js');
    await checkBurstLimit(env, userId, 'FREE');
    await checkBurstLimit(env, userId, 'FREE');
    await checkBurstLimit(env, userId, 'FREE');

    const req = new Request('https://x/api/copilot/chat/stream', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    const res = await handleCopilotChatStream(req, env, { tier: 'FREE', userId });
    const events = await collectSSE(res);
    expect(events.some(e => e.type === 'error' && e.data.error === 'rate_limit_exceeded')).toBe(true);
  });
});

describe('executeTool — SOC tool dispatch preserves the caller\'s real org_id', () => {
  // Regression lock: get_soc_investigation/escalate_soc_case used to build an
  // internal request with `org_id: authCtx?.orgId || 'default'` — `orgId`
  // (camelCase) is never set anywhere, so every copilot-mediated SOC lookup
  // was silently rescoped to a shared 'default' tenant regardless of the
  // caller's real org — the same leak class middleware.js's withAuthAliases()
  // already fixed once for the direct HTTP route.
  const realAuthCtx = { org_id: 'u:real-org-123', user_id: 'u1', isAdmin: false };

  it('get_soc_investigation passes the real org_id through, not "default"', async () => {
    const result = await executeTool('get_soc_investigation', { case_id: 'c1' }, {}, realAuthCtx, 'u1', 'sess1');
    expect(result.received_org_id).toBe('u:real-org-123');
    expect(result.received_org_id).not.toBe('default');
  });

  it('escalate_soc_case passes the real org_id through, not "default"', async () => {
    const result = await executeTool('escalate_soc_case', { case_id: 'c1', reason: 'test' }, {}, realAuthCtx, 'u1', 'sess1');
    expect(result.received_org_id).toBe('u:real-org-123');
    expect(result.received_org_id).not.toBe('default');
  });
});
