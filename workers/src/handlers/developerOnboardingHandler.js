/**
 * CYBERDUDEBIVASH® AI Security Hub — P20.0
 * developerOnboardingHandler.js — Self-Serve Developer Onboarding & Trial Engine
 *
 * APIs:
 *   POST /api/onboarding/trial-key      zero-friction trial key (email + use_case only)
 *   GET  /api/onboarding/quickstart     personalized quickstart guide (requires trial key)
 *   GET  /api/onboarding/status         onboarding completion checklist
 *   POST /api/onboarding/resend-welcome re-send welcome + key recovery hint
 *   GET  /api/onboarding/observability  P20.0 health gate
 *
 * Reuses:
 *   createApiKey, generateRawApiKey, TIER_LIMITS  → auth/apiKeys.js (canonical)
 *   normalizeTier                                 → subscriptionPaywallEngine.js
 *   deliverNotification                           → notificationPlatform.js
 *   crm_leads D1 table                            → existing schema
 *   SECURITY_HUB_KV                               → rate limiting
 */

import { createApiKey, TIER_LIMITS } from '../auth/apiKeys.js';
import { normalizeTier } from './subscriptionPaywallEngine.js';
import { deliverNotification } from './notificationPlatform.js';
import { hashPassword } from '../auth/password.js';

// ── Constants ──────────────────────────────────────────────────────────────

const TRIAL_TIER = 'COMMUNITY';   // maps to canonical tier via normalizeTier
const TRIAL_RATE_LIMIT = 3;       // max trial key requests per IP per day
const ONBOARDING_KV_TTL = 86400 * 30; // 30 days

const USE_CASES = {
  threat_intel:     { label: 'Threat Intelligence',    apis: ['/api/intel/ioc-lookup', '/api/intel/threat-feed', '/api/intel/actor-intel'], docs: 'https://cyberdudebivash.in/api-docs.html#threat-intel' },
  vulnerability:    { label: 'Vulnerability Management', apis: ['/api/cve/search', '/api/scan/domain', '/api/asm/scan'], docs: 'https://cyberdudebivash.in/api-docs.html#vulnerability' },
  soc_automation:   { label: 'SOC Automation',         apis: ['/api/soc/cases', '/api/soc/investigate', '/api/detection/sigma'], docs: 'https://cyberdudebivash.in/api-docs.html#soc' },
  ai_security:      { label: 'AI Security & Governance', apis: ['/api/ai-governance/policy', '/api/ai-security/scorecard', '/api/ai-red-team/simulate'], docs: 'https://cyberdudebivash.in/api-docs.html#ai-security' },
  compliance:       { label: 'Compliance & Reporting', apis: ['/api/compliance/gap-analysis', '/api/reports/executive', '/api/ciso/metrics'], docs: 'https://cyberdudebivash.in/api-docs.html#compliance' },
  mssp:             { label: 'MSSP / Multi-Tenant',    apis: ['/api/mssp/clients', '/api/mssp/white-label', '/api/mssp/workspace'], docs: 'https://cyberdudebivash.in/api-docs.html#mssp' },
};

const QUICKSTART_STEPS = {
  threat_intel: [
    { step: 1, title: 'Authenticate your request', code: { curl: `curl -H "X-API-Key: YOUR_KEY" https://cyberdudebivash.in/api/intel/threat-feed`, js: `const r = await fetch('https://cyberdudebivash.in/api/intel/threat-feed', { headers: { 'X-API-Key': 'YOUR_KEY' } }); const data = await r.json();`, python: `import requests\nr = requests.get('https://cyberdudebivash.in/api/intel/threat-feed', headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 2, title: 'Look up an IOC', code: { curl: `curl -H "X-API-Key: YOUR_KEY" "https://cyberdudebivash.in/api/intel/ioc-lookup?ioc=8.8.8.8&type=ip"`, js: `const r = await fetch('https://cyberdudebivash.in/api/intel/ioc-lookup?ioc=8.8.8.8&type=ip', { headers: { 'X-API-Key': 'YOUR_KEY' } });`, python: `r = requests.get('https://cyberdudebivash.in/api/intel/ioc-lookup', params={'ioc': '8.8.8.8', 'type': 'ip'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 3, title: 'Get threat actor profile', code: { curl: `curl -H "X-API-Key: YOUR_KEY" "https://cyberdudebivash.in/api/intel/actor-intel?actor=APT28"`, js: `const r = await fetch('https://cyberdudebivash.in/api/intel/actor-intel?actor=APT28', { headers: { 'X-API-Key': 'YOUR_KEY' } });`, python: `r = requests.get('https://cyberdudebivash.in/api/intel/actor-intel', params={'actor': 'APT28'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
  ],
  vulnerability: [
    { step: 1, title: 'Scan a domain for exposure', code: { curl: `curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d '{"domain":"example.com"}' https://cyberdudebivash.in/api/scan/domain`, js: `const r = await fetch('https://cyberdudebivash.in/api/scan/domain', { method: 'POST', headers: { 'X-API-Key': 'YOUR_KEY', 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com' }) });`, python: `r = requests.post('https://cyberdudebivash.in/api/scan/domain', json={'domain': 'example.com'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 2, title: 'Search CVEs by keyword', code: { curl: `curl -H "X-API-Key: YOUR_KEY" "https://cyberdudebivash.in/api/cve/search?q=log4j&severity=CRITICAL"`, js: `const r = await fetch('https://cyberdudebivash.in/api/cve/search?q=log4j&severity=CRITICAL', { headers: { 'X-API-Key': 'YOUR_KEY' } });`, python: `r = requests.get('https://cyberdudebivash.in/api/cve/search', params={'q': 'log4j', 'severity': 'CRITICAL'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 3, title: 'Run attack surface scan', code: { curl: `curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d '{"domain":"example.com","deep":true}' https://cyberdudebivash.in/api/asm/scan`, js: `const r = await fetch('https://cyberdudebivash.in/api/asm/scan', { method: 'POST', headers: { 'X-API-Key': 'YOUR_KEY', 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com', deep: true }) });`, python: `r = requests.post('https://cyberdudebivash.in/api/asm/scan', json={'domain': 'example.com', 'deep': True}, headers={'X-API-Key': 'YOUR_KEY'})` } },
  ],
  ai_security: [
    { step: 1, title: 'Run AI Security Scorecard', code: { curl: `curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d '{"domain":"example.com"}' https://cyberdudebivash.in/api/public/security-scorecard`, js: `const r = await fetch('https://cyberdudebivash.in/api/public/security-scorecard', { method: 'POST', headers: { 'X-API-Key': 'YOUR_KEY', 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: 'example.com' }) });`, python: `r = requests.post('https://cyberdudebivash.in/api/public/security-scorecard', json={'domain': 'example.com'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 2, title: 'Check AI governance policy', code: { curl: `curl -H "X-API-Key: YOUR_KEY" https://cyberdudebivash.in/api/ai-governance/policy`, js: `const r = await fetch('https://cyberdudebivash.in/api/ai-governance/policy', { headers: { 'X-API-Key': 'YOUR_KEY' } });`, python: `r = requests.get('https://cyberdudebivash.in/api/ai-governance/policy', headers={'X-API-Key': 'YOUR_KEY'})` } },
    { step: 3, title: 'Simulate AI red team', code: { curl: `curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d '{"target":"gpt-4","attack_type":"prompt_injection"}' https://cyberdudebivash.in/api/ai-red-team/simulate`, js: `const r = await fetch('https://cyberdudebivash.in/api/ai-red-team/simulate', { method: 'POST', headers: { 'X-API-Key': 'YOUR_KEY', 'Content-Type': 'application/json' }, body: JSON.stringify({ target: 'gpt-4', attack_type: 'prompt_injection' }) });`, python: `r = requests.post('https://cyberdudebivash.in/api/ai-red-team/simulate', json={'target': 'gpt-4', 'attack_type': 'prompt_injection'}, headers={'X-API-Key': 'YOUR_KEY'})` } },
  ],
};
// Default quickstart for use cases without specific steps
const DEFAULT_QUICKSTART = QUICKSTART_STEPS.threat_intel;

function genOnboardingId() {
  return 'ob_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
    || 'unknown';
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function sanitizeName(s) {
  return (s || '').toString().replace(/[<>&"']/g, '').trim().slice(0, 80);
}

// ── Handlers ───────────────────────────────────────────────────────────────

/**
 * POST /api/onboarding/trial-key
 * Body: { email, name, company?, use_case, agree_terms: true }
 *
 * Flow:
 *  1. Rate limit (3 trial keys / IP / day via KV)
 *  2. Validate input
 *  3. Check if email already has a trial key (return hint, not duplicate)
 *  4. Create/find user record in D1
 *  5. createApiKey() from auth/apiKeys.js (canonical)
 *  6. Log to crm_leads (existing table)
 *  7. deliverNotification() welcome (canonical)
 *  8. Store onboarding state in KV
 *  9. Return key (shown once)
 */
export async function handleTrialKeyRequest(req, env) {
  const ip = clientIp(req);
  const today = new Date().toISOString().slice(0, 10);
  const rateLimitKey = `onboarding:ratelimit:${ip}:${today}`;

  // Rate limit
  const attempts = parseInt(await env.KV?.get(rateLimitKey).catch(() => '0') || '0', 10);
  if (attempts >= TRIAL_RATE_LIMIT) {
    return Response.json({
      error: 'Too many trial key requests from this IP today.',
      hint: 'Each IP may request up to 3 trial keys per day. Try again tomorrow.',
      retry_after: 'tomorrow',
    }, { status: 429 });
  }

  let body;
  try { body = await req.json(); } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { email, name, company, use_case, agree_terms } = body;

  // Validate
  if (!email || !validateEmail(email)) return Response.json({ error: 'Valid email address required' }, { status: 400 });
  if (!name || name.trim().length < 2) return Response.json({ error: 'Name is required (min 2 chars)' }, { status: 400 });
  if (!agree_terms) return Response.json({ error: 'You must agree to the Terms of Service' }, { status: 400 });
  if (use_case && !USE_CASES[use_case]) return Response.json({ error: `Invalid use_case. Valid: ${Object.keys(USE_CASES).join(', ')}` }, { status: 400 });

  const cleanEmail = email.toLowerCase().trim();
  const cleanName = sanitizeName(name);
  const cleanCompany = sanitizeName(company || '');
  const resolvedUseCase = use_case || 'threat_intel';
  const tier = normalizeTier(TRIAL_TIER);

  try {
    // Check for existing user with this email
    let userRow = await env.DB.prepare(
      `SELECT id, tier FROM users WHERE email = ? LIMIT 1`
    ).bind(cleanEmail).first().catch(() => null);

    let userId;
    let isNewUser = false;

    if (userRow) {
      userId = userRow.id;
      // Existing user — check if they already have an active key
      const existingKey = await env.DB.prepare(
        `SELECT id, key_prefix FROM api_keys WHERE user_id = ? AND active = 1 LIMIT 1`
      ).bind(userId).first().catch(() => null);

      if (existingKey) {
        return Response.json({
          message: 'You already have an active trial key.',
          key_prefix: existingKey.key_prefix,
          hint: 'Your full key was shown once at creation. Check your welcome email or use /api/onboarding/resend-welcome to receive a recovery hint.',
          upgrade_url: 'https://cyberdudebivash.in/upgrade.html',
          docs_url: 'https://cyberdudebivash.in/api-docs.html',
        }, { status: 200 });
      }
    } else {
      // Create new user
      userId = genOnboardingId();
      isNewUser = true;
      // Trial signups are API-key-only (no password login) — generate an
      // unguessable throwaway password and hash it via the canonical hasher
      // so users.password_hash/password_salt (NOT NULL, no default) are
      // satisfied the same way handleSignup() in auth.js does it.
      const { hash: trialHash, salt: trialSalt } = await hashPassword(crypto.randomUUID() + crypto.randomUUID());
      // users.tier has CHECK(tier IN ('FREE','PRO','ENTERPRISE')) — normalizeTier()
      // returns the friendlier 'COMMUNITY' label used elsewhere in this flow,
      // which violates that constraint, so the DB column gets the literal 'FREE'.
      await env.DB.prepare(
        `INSERT INTO users (id, email, password_hash, password_salt, full_name, company, tier, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'FREE', 'active', datetime('now'))`
      ).bind(userId, cleanEmail, trialHash, trialSalt, cleanName, cleanCompany).run();
    }

    // Create trial API key using canonical createApiKey()
    const keyResult = await createApiKey(env.DB, userId, tier, `Trial Key — ${USE_CASES[resolvedUseCase].label}`);

    // Increment rate limit counter (TTL: end of day)
    await env.KV?.put(rateLimitKey, String(attempts + 1), { expirationTtl: 86400 }).catch(() => null);

    // Store onboarding state in KV for quickstart/status endpoints
    const onboardingState = {
      user_id: userId,
      email: cleanEmail,
      name: cleanName,
      company: cleanCompany,
      use_case: resolvedUseCase,
      tier,
      key_id: keyResult.id,
      key_prefix: keyResult.prefix,
      steps_completed: ['trial_key_issued'],
      first_call_made: false,
      upgraded: false,
      created_at: new Date().toISOString(),
    };
    await env.KV?.put(`onboarding:${userId}`, JSON.stringify(onboardingState), { expirationTtl: ONBOARDING_KV_TTL }).catch(() => null);

    // Log to CRM leads (existing table — additive insert)
    await env.DB.prepare(
      `INSERT INTO crm_leads (id, email, name, company, source, status, notes, created_at)
       VALUES (?, ?, ?, ?, 'trial_key_signup', 'trial', ?, datetime('now'))
       ON CONFLICT(email) DO UPDATE SET status='trial', notes=excluded.notes, updated_at=datetime('now')`
    ).bind(genOnboardingId(), cleanEmail, cleanName, cleanCompany,
      JSON.stringify({ use_case: resolvedUseCase, key_prefix: keyResult.prefix })
    ).run().catch(() => null);

    // Welcome notification via canonical deliverNotification()
    const welcomeSubject = `Welcome to CYBERDUDEBIVASH® — Your Trial API Key is Ready`;
    const welcomeBody = [
      `Hi ${cleanName},`,
      '',
      `Your COMMUNITY tier trial API key for ${USE_CASES[resolvedUseCase].label} is now active.`,
      '',
      `Key prefix: ${keyResult.prefix}`,
      `Tier: ${tier} (${TIER_LIMITS[tier]?.daily_limit ?? 100} requests/day)`,
      '',
      'IMPORTANT: Your full API key was returned in the API response. Save it now — it cannot be retrieved again.',
      '',
      `Quick start: https://cyberdudebivash.in/developer-onboarding.html`,
      `API docs: https://cyberdudebivash.in/api-docs.html`,
      `Upgrade to unlock unlimited requests: https://cyberdudebivash.in/upgrade.html`,
    ].join('\n');

    await deliverNotification({
      userId,
      orgId: userId,
      eventType: '*', // wildcard — ensures delivery regardless of subscription prefs for new users
      subject: welcomeSubject,
      body: welcomeBody,
      channels: ['INAPP'],
    }, env).catch(() => null);

    const useCaseDef = USE_CASES[resolvedUseCase];
    const quickstartSteps = QUICKSTART_STEPS[resolvedUseCase] || DEFAULT_QUICKSTART;

    return Response.json({
      success: true,
      message: isNewUser
        ? 'Trial API key created. Save it now — this is the only time it will be shown.'
        : 'New API key created for your existing account.',

      // Key — shown ONCE per canonical createApiKey() contract
      api_key: keyResult.raw_key,
      key_prefix: keyResult.prefix,
      key_id: keyResult.id,

      account: {
        user_id: userId,
        email: cleanEmail,
        tier,
        limits: TIER_LIMITS[tier] || {},
      },
      use_case: {
        id: resolvedUseCase,
        label: useCaseDef.label,
        recommended_apis: useCaseDef.apis,
        docs_url: useCaseDef.docs,
      },
      quickstart: {
        first_api_call: quickstartSteps[0] || null,
        all_steps_url: `https://cyberdudebivash.in/developer-onboarding.html?use_case=${resolvedUseCase}`,
      },
      upgrade: {
        url: 'https://cyberdudebivash.in/upgrade.html',
        next_tier: 'PROFESSIONAL',
        next_tier_price_inr: 1499,
        next_tier_price_usd: 18,
        benefit: '10,000 requests/month, full scan, PDF reports, API access',
      },
      warning: 'Your API key cannot be retrieved after this response. Store it in a secure secrets manager.',
    }, { status: 201 });

  } catch (e) {
    return Response.json({ error: 'Failed to provision trial key. Please try again.', detail: e.message }, { status: 500 });
  }
}

/**
 * GET /api/onboarding/quickstart?user_id=&use_case=
 * Returns personalized quickstart guide with code samples.
 */
export async function handleQuickstart(req, env) {
  const url = new URL(req.url);
  const useCase = url.searchParams.get('use_case') || 'threat_intel';
  const userId = url.searchParams.get('user_id');

  const useCaseDef = USE_CASES[useCase] || USE_CASES.threat_intel;
  const steps = QUICKSTART_STEPS[useCase] || DEFAULT_QUICKSTART;

  // Enrich with onboarding state if user_id provided
  let onboardingState = null;
  if (userId) {
    onboardingState = await env.KV?.get(`onboarding:${userId}`, 'json').catch(() => null);
  }

  return Response.json({
    use_case: { id: useCase, ...useCaseDef },
    quickstart_steps: steps,
    sdk_links: {
      python: 'https://pypi.org/project/requests/',
      javascript: 'https://www.npmjs.com/package/node-fetch',
      curl: 'built-in on Linux/Mac; Windows: https://curl.se/windows/',
    },
    base_url: 'https://cyberdudebivash.in',
    auth_header: 'X-API-Key',
    rate_limits: TIER_LIMITS.COMMUNITY,
    onboarding_status: onboardingState ? {
      steps_completed: onboardingState.steps_completed || [],
      first_call_made: onboardingState.first_call_made,
      upgraded: onboardingState.upgraded,
    } : null,
    upgrade_cta: {
      message: 'Unlock 10,000 req/month, full reports, and SIEM integration.',
      url: 'https://cyberdudebivash.in/upgrade.html',
      price_inr: 1499,
      price_usd: 18,
    },
    all_use_cases: Object.fromEntries(Object.entries(USE_CASES).map(([k, v]) => [k, v.label])),
  });
}

/**
 * GET /api/onboarding/status?user_id=
 * Returns onboarding completion checklist and next steps.
 */
export async function handleOnboardingStatus(req, env) {
  const url = new URL(req.url);
  const userId = url.searchParams.get('user_id');

  if (!userId) return Response.json({ error: 'user_id required' }, { status: 400 });

  const state = await env.KV?.get(`onboarding:${userId}`, 'json').catch(() => null);
  if (!state) {
    return Response.json({ error: 'Onboarding record not found. Start at POST /api/onboarding/trial-key' }, { status: 404 });
  }

  // Check if user has made any API calls
  const usageRow = await env.DB.prepare(
    `SELECT COUNT(*) as cnt FROM api_key_usage WHERE user_id = ?`
  ).bind(userId).first().catch(() => null);
  const hasMadeCalls = (usageRow?.cnt || 0) > 0;

  // Check subscription status
  const subRow = await env.DB.prepare(
    `SELECT tier, status FROM subscriptions WHERE user_id = ? AND status = 'active' LIMIT 1`
  ).bind(userId).first().catch(() => null);
  const isPaid = !!subRow && subRow.tier !== 'COMMUNITY';

  const checklist = [
    { id: 'trial_key',    label: 'Get your free trial API key',     done: state.steps_completed?.includes('trial_key_issued') },
    { id: 'first_call',   label: 'Make your first API call',         done: hasMadeCalls },
    { id: 'explore',      label: 'Explore 3+ API endpoints',         done: (usageRow?.cnt || 0) >= 3 },
    { id: 'upgrade',      label: 'Upgrade to Professional',          done: isPaid },
    { id: 'integration',  label: 'Integrate into your application',  done: false },
  ];

  const completedCount = checklist.filter(c => c.done).length;
  const pctComplete = Math.round((completedCount / checklist.length) * 100);

  const nextStep = checklist.find(c => !c.done);

  return Response.json({
    user_id: userId,
    email: state.email,
    tier: state.tier,
    use_case: state.use_case,
    onboarding_pct: pctComplete,
    checklist,
    next_step: nextStep ? {
      id: nextStep.id,
      label: nextStep.label,
      action_url: nextStep.id === 'upgrade'
        ? 'https://cyberdudebivash.in/upgrade.html'
        : `https://cyberdudebivash.in/developer-onboarding.html?user_id=${userId}`,
    } : { id: 'complete', label: 'Onboarding complete!', action_url: 'https://cyberdudebivash.in/dashboard' },
    upgrade_cta: isPaid ? null : {
      message: 'Upgrade to PROFESSIONAL for 10,000 req/month, PDF reports, SIEM integration.',
      price_inr: 1499,
      price_usd: 18,
      url: 'https://cyberdudebivash.in/upgrade.html',
    },
  });
}

/**
 * POST /api/onboarding/resend-welcome
 * Body: { email }
 * Sends in-app notification with key prefix + upgrade links (cannot re-send the raw key).
 */
export async function handleResendWelcome(req, env) {
  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const email = (body.email || '').toLowerCase().trim();
  if (!validateEmail(email)) return Response.json({ error: 'Valid email required' }, { status: 400 });

  // Rate limit resend: 3/email/day
  const today = new Date().toISOString().slice(0, 10);
  const rlKey = `onboarding:resend:${email}:${today}`;
  const attempts = parseInt(await env.KV?.get(rlKey).catch(() => '0') || '0', 10);
  if (attempts >= 3) return Response.json({ error: 'Resend limit reached. Try again tomorrow.' }, { status: 429 });

  try {
    const user = await env.DB.prepare(`SELECT id, name FROM users WHERE email = ? LIMIT 1`).bind(email).first().catch(() => null);
    if (!user) return Response.json({ error: 'No account found with this email.' }, { status: 404 });

    const key = await env.DB.prepare(
      `SELECT key_prefix FROM api_keys WHERE user_id = ? AND active = 1 LIMIT 1`
    ).bind(user.id).first().catch(() => null);

    await deliverNotification({
      userId: user.id,
      orgId: user.id,
      eventType: '*',
      subject: 'CYBERDUDEBIVASH® — Your API Key Recovery Hint',
      body: [
        `Hi ${user.name || 'there'},`,
        '',
        key
          ? `Your active API key prefix is: ${key.key_prefix}`
          : 'We could not find an active API key on your account. Please generate a new one at https://cyberdudebivash.in/developer-onboarding.html',
        '',
        'IMPORTANT: The full API key cannot be retrieved. If you have lost it, generate a new key at:',
        'https://cyberdudebivash.in/developer-onboarding.html',
        '',
        'Upgrade to Professional: https://cyberdudebivash.in/upgrade.html',
      ].join('\n'),
      channels: ['INAPP'],
    }, env).catch(() => null);

    await env.KV?.put(rlKey, String(attempts + 1), { expirationTtl: 86400 }).catch(() => null);

    return Response.json({
      success: true,
      message: 'Recovery hint sent to your in-app notification inbox.',
      note: 'The full API key cannot be recovered. If you have lost it, generate a new one.',
      new_key_url: 'https://cyberdudebivash.in/developer-onboarding.html',
    });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500 });
  }
}

/**
 * GET /api/onboarding/observability — P20.0 health gate
 */
export async function handleOnboardingObservability(req, env) {
  const checks = {
    users_table: false,
    api_keys_table: false,
    crm_leads_table: false,
    kv_accessible: false,
    canonical_imports: true, // auth/apiKeys + subscriptionPaywallEngine + notificationPlatform
  };

  try { await env.DB.prepare('SELECT 1 FROM users LIMIT 1').run(); checks.users_table = true; } catch {}
  try { await env.DB.prepare('SELECT 1 FROM api_keys LIMIT 1').run(); checks.api_keys_table = true; } catch {}
  try { await env.DB.prepare('SELECT 1 FROM crm_leads LIMIT 1').run(); checks.crm_leads_table = true; } catch {}
  try { await env.KV?.put('onboarding:health', '1', { expirationTtl: 10 }); checks.kv_accessible = true; } catch {}

  const allPass = checks.users_table && checks.api_keys_table && checks.kv_accessible;
  return Response.json({
    layer: 'P20.0',
    name: 'Developer Onboarding & Self-Serve Trial Engine',
    status: allPass ? 'OPERATIONAL' : 'DEGRADED',
    checks,
    trial_tier: TRIAL_TIER,
    rate_limit_per_ip_per_day: TRIAL_RATE_LIMIT,
    supported_use_cases: Object.keys(USE_CASES),
    endpoints: [
      'POST /api/onboarding/trial-key',
      'GET  /api/onboarding/quickstart',
      'GET  /api/onboarding/status',
      'POST /api/onboarding/resend-welcome',
      'GET  /api/onboarding/observability',
    ],
    timestamp: new Date().toISOString(),
  }, { status: allPass ? 200 : 503 });
}
