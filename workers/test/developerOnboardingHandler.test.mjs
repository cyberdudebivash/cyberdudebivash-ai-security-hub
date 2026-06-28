/* Regression tests — P20.0 Developer Self-Serve Onboarding had zero test
 * coverage and shipped with multiple live-broken paths found during a
 * production walkthrough on 2026-06-29:
 *   - INSERT INTO users used columns that don't exist (`name`, `org_id`)
 *     and omitted NOT NULL columns (password_hash/password_salt), and
 *     wrote a tier value that violated users.tier's CHECK constraint.
 *   - resend-welcome's SELECT used `name` instead of `full_name`, so the
 *     D1 error was swallowed by .catch(() => null) and every real account
 *     silently reported "No account found".
 * These tests lock in the corrected behavior. */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  handleTrialKeyRequest,
  handleQuickstart,
  handleOnboardingStatus,
  handleResendWelcome,
} from '../src/handlers/developerOnboardingHandler.js';

function makeEnv({ users = [], apiKeys = [], onboardingState = {} } = {}) {
  const usersByEmail = new Map(users.map(u => [u.email, { ...u }]));
  const usersById    = new Map(users.map(u => [u.id, { ...u }]));
  const apiKeysByUserId = new Map(apiKeys.map(k => [k.user_id, { ...k }]));
  const kv = new Map(Object.entries(onboardingState));

  const env = {
    DB: {
      prepare(sql) {
        let b = [];
        return {
          bind(...a) { b = a; return this; },
          async run() {
            if (/CREATE TABLE/.test(sql)) return { success: true };

            if (/INSERT INTO users/.test(sql)) {
              // (id, email, password_hash, password_salt, full_name, company, tier='FREE', status='active', created_at)
              const [id, email, password_hash, password_salt, full_name, company] = b;
              const rec = { id, email, password_hash, password_salt, full_name, company, tier: 'FREE', status: 'active' };
              usersByEmail.set(email, rec); usersById.set(id, rec);
              return { success: true };
            }

            if (/INSERT INTO api_keys/.test(sql)) {
              // createApiKey(): (id, user_id, key_hash, key_prefix, label, tier, daily_limit, monthly_limit, active, created_at)
              const [id, user_id, key_hash, key_prefix, label, tier] = b;
              apiKeysByUserId.set(user_id, { id, user_id, key_hash, key_prefix, label, tier, active: 1 });
              return { success: true };
            }

            if (/INSERT INTO crm_leads/.test(sql)) return { success: true };

            return { success: true };
          },
          async first() {
            if (/SELECT id, tier FROM users WHERE email/.test(sql)) {
              const u = usersByEmail.get(b[0]);
              return u ? { id: u.id, tier: u.tier } : null;
            }
            if (/SELECT id, key_prefix FROM api_keys WHERE user_id/.test(sql)) {
              const k = apiKeysByUserId.get(b[0]);
              return k && k.active ? { id: k.id, key_prefix: k.key_prefix } : null;
            }
            if (/SELECT id, full_name AS name FROM users WHERE email/.test(sql)) {
              const u = usersByEmail.get(b[0]);
              return u ? { id: u.id, name: u.full_name } : null;
            }
            // Regression guard: the old buggy query selected a literal `name`
            // column that doesn't exist on the real table. If any code path
            // still issues that exact query, fail loudly instead of silently
            // returning null like the real D1 error did.
            if (/SELECT id, name FROM users WHERE email/.test(sql)) {
              throw new Error('D1_ERROR: table users has no column named name: SQLITE_ERROR');
            }
            if (/SELECT key_prefix FROM api_keys WHERE user_id/.test(sql)) {
              const k = apiKeysByUserId.get(b[0]);
              return k && k.active ? { key_prefix: k.key_prefix } : null;
            }
            if (/SELECT COUNT\(\*\) as cnt FROM api_key_usage/.test(sql)) {
              return { cnt: 0 };
            }
            if (/SELECT tier, status FROM subscriptions/.test(sql)) {
              return null;
            }
            if (/SELECT 1 FROM users LIMIT 1/.test(sql)) {
              return { 1: 1 };
            }
            return null;
          },
          async all() { return { results: [] }; },
        };
      },
    },
    KV: {
      async get(k, type) {
        const v = kv.get(k);
        if (v === undefined) return null;
        return type === 'json' ? JSON.parse(v) : v;
      },
      async put(k, v) { kv.set(k, v); return true; },
    },
  };
  return { env, usersByEmail, apiKeysByUserId, kv };
}

function req(url, body, headers = {}) {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

describe('trial-key signup — validation and live-schema correctness', () => {
  it('rejects an invalid email', async () => {
    const { env } = makeEnv();
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'not-an-email', name: 'QA', agree_terms: true,
    }, { 'CF-Connecting-IP': '1.1.1.1' }), env);
    expect(res.status).toBe(400);
  });

  it('rejects a missing name', async () => {
    const { env } = makeEnv();
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'a@b.com', agree_terms: true,
    }, { 'CF-Connecting-IP': '1.1.2.2' }), env);
    expect(res.status).toBe(400);
  });

  it('rejects when terms are not agreed', async () => {
    const { env } = makeEnv();
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'a@b.com', name: 'QA',
    }, { 'CF-Connecting-IP': '1.1.3.3' }), env);
    expect(res.status).toBe(400);
  });

  it('rate-limits trial key requests to 3 per IP per day', async () => {
    const { env } = makeEnv();
    const ip = { 'CF-Connecting-IP': '2.2.2.2' };
    for (let i = 0; i < 3; i++) {
      const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
        email: `user${i}@acme.com`, name: 'QA', agree_terms: true,
      }, ip), env);
      expect(res.status).toBe(201);
    }
    const res4 = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'user4@acme.com', name: 'QA', agree_terms: true,
    }, ip), env);
    expect(res4.status).toBe(429);
  });

  it('provisions a new user with a real API key and the correct tier/status, without 500ing on the live schema', async () => {
    const { env, usersByEmail, apiKeysByUserId } = makeEnv();
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'newdev@acme.com', name: 'New Dev', company: 'Acme', use_case: 'threat_intel', agree_terms: true,
    }, { 'CF-Connecting-IP': '3.3.3.3' }), env);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.api_key).toBeTruthy();
    expect(body.key_prefix).toBeTruthy();

    const stored = usersByEmail.get('newdev@acme.com');
    expect(stored.tier).toBe('FREE'); // CHECK(tier IN ('FREE','PRO','ENTERPRISE')) — not the raw 'COMMUNITY' label
    expect(stored.full_name).toBe('New Dev');
    expect(stored.password_hash).toBeTruthy(); // NOT NULL column — must be populated
    expect(stored.password_salt).toBeTruthy();
    expect(apiKeysByUserId.get(stored.id)).toBeTruthy();
  });

  it('returns the existing active key for an already-onboarded email instead of creating a duplicate', async () => {
    const { env } = makeEnv({
      users: [{ id: 'u1', email: 'existing@acme.com', tier: 'FREE' }],
      apiKeys: [{ id: 'k1', user_id: 'u1', key_prefix: 'cdb_existing12', active: 1 }],
    });
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'existing@acme.com', name: 'Existing', agree_terms: true,
    }, { 'CF-Connecting-IP': '4.4.4.4' }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.key_prefix).toBe('cdb_existing12');
  });

  it('rejects an invalid use_case', async () => {
    const { env } = makeEnv();
    const res = await handleTrialKeyRequest(req('https://x/api/onboarding/trial-key', {
      email: 'a@b.com', name: 'QA', use_case: 'not-a-real-use-case', agree_terms: true,
    }, { 'CF-Connecting-IP': '5.5.5.5' }), env);
    expect(res.status).toBe(400);
  });
});

describe('quickstart — every advertised endpoint is a real, live route', () => {
  // Routes verified live against production on 2026-06-29 (curl + real trial key).
  const LIVE_ROUTES = new Set([
    '/api/intel/ioc', '/api/intel/cve', '/api/intel/actor',
    '/api/scan/domain', '/api/scan/vuln-assessment',
    '/api/soc/cases', '/api/soc/dashboard', '/api/soc/cases/metrics',
    '/api/scan/ai-security', '/api/ai-redteam/probe/prompt-injection', '/api/ai-governance/pdf/generate',
    '/api/scan/compliance', '/api/reports/executive', '/api/ciso/metrics',
    '/api/mssp/clients', '/api/mssp/onboarding/tiers', '/api/mssp/overview',
  ]);

  it('only advertises recommended_apis that are known-live routes, for every use case', async () => {
    const { env } = makeEnv();
    for (const useCase of ['threat_intel', 'vulnerability', 'soc_automation', 'ai_security', 'compliance', 'mssp']) {
      const res = await handleQuickstart(new Request(`https://x/api/onboarding/quickstart?use_case=${useCase}`), env);
      const body = await res.json();
      for (const api of body.use_case.apis) {
        expect(LIVE_ROUTES.has(api), `${useCase} advertises dead route ${api}`).toBe(true);
      }
    }
  });

  it('falls back to threat_intel quickstart steps for an unknown use case', async () => {
    const { env } = makeEnv();
    const res = await handleQuickstart(new Request('https://x/api/onboarding/quickstart?use_case=nonexistent'), env);
    const body = await res.json();
    expect(body.quickstart_steps.length).toBeGreaterThan(0);
  });
});

describe('onboarding status', () => {
  it('requires a user_id', async () => {
    const { env } = makeEnv();
    const res = await handleOnboardingStatus(new Request('https://x/api/onboarding/status'), env);
    expect(res.status).toBe(400);
  });

  it('404s when no onboarding record exists for the user_id', async () => {
    const { env } = makeEnv();
    const res = await handleOnboardingStatus(new Request('https://x/api/onboarding/status?user_id=ghost'), env);
    expect(res.status).toBe(404);
  });

  it('returns a checklist for a known onboarding record', async () => {
    const { env } = makeEnv({
      onboardingState: { 'onboarding:u1': JSON.stringify({ email: 'a@b.com', tier: 'FREE', use_case: 'threat_intel', steps_completed: ['trial_key_issued'] }) },
    });
    const res = await handleOnboardingStatus(new Request('https://x/api/onboarding/status?user_id=u1'), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.checklist)).toBe(true);
    expect(body.checklist.find(c => c.id === 'trial_key').done).toBe(true);
  });
});

describe('resend-welcome — regression for the full_name/name column bug', () => {
  it('rejects an invalid email', async () => {
    const { env } = makeEnv();
    const res = await handleResendWelcome(req('https://x/api/onboarding/resend-welcome', { email: 'not-an-email' }), env);
    expect(res.status).toBe(400);
  });

  it('404s for an email with no account, without throwing', async () => {
    const { env } = makeEnv();
    const res = await handleResendWelcome(req('https://x/api/onboarding/resend-welcome', { email: 'ghost@acme.com' }), env);
    expect(res.status).toBe(404);
  });

  it('finds a real account by email via full_name (not the nonexistent `name` column) and sends the recovery hint', async () => {
    const { env } = makeEnv({
      users: [{ id: 'u1', email: 'real@acme.com', full_name: 'Real Dev', tier: 'FREE' }],
      apiKeys: [{ id: 'k1', user_id: 'u1', key_prefix: 'cdb_realkey123', active: 1 }],
    });
    const res = await handleResendWelcome(req('https://x/api/onboarding/resend-welcome', { email: 'real@acme.com' }), env);
    expect(res.status).toBe(200);
  });

  it('rate-limits resend requests to 3 per email per day', async () => {
    const { env } = makeEnv({
      users: [{ id: 'u1', email: 'limited@acme.com', full_name: 'Limited', tier: 'FREE' }],
    });
    for (let i = 0; i < 3; i++) {
      const res = await handleResendWelcome(req('https://x/api/onboarding/resend-welcome', { email: 'limited@acme.com' }), env);
      expect(res.status).toBe(200);
    }
    const res4 = await handleResendWelcome(req('https://x/api/onboarding/resend-welcome', { email: 'limited@acme.com' }), env);
    expect(res4.status).toBe(429);
  });
});
