/**
 * Security regression tests — OWASP API1 BOLA guards on proposal endpoints
 * and payment status information disclosure (amount_paise / report_token strip).
 *
 * Guards:
 *   • Every proposal write/read requires isOwner() — 403 for customers + anon
 *   • handlePaymentStatus never leaks amount or download_url to unauthenticated callers
 *   • Rejected proposals enroll client in enterprise_winback sequence
 *
 * These tests import the real handler code with heavy dependencies mocked,
 * so the business logic (isOwner guards, response shape) executes exactly
 * as it does in production.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Module mocks (hoisted above all imports by vitest) ────────────────────────

vi.mock('../src/lib/razorpay.js', () => ({
  MODULE_PRICES:          { domain: { amount: 99900, name: 'Domain Security Report' }, assessment: { amount: 299900, name: 'Full Security Assessment' } },
  SUBSCRIPTION_PRICES:    {},
  createRazorpayOrder:    vi.fn(async () => ({ id: 'order_test' })),
  verifyPaymentSignature: vi.fn(async () => true),
  verifyWebhookSignature: vi.fn(async () => true),
  generateReceiptId:      vi.fn(() => 'rcpt_test'),
  generateAccessToken:    vi.fn(() => 'tok_access_test'),
}));
vi.mock('../src/lib/htmlReport.js',         () => ({ generateHTMLReport: vi.fn(async () => '<html/>') }));
vi.mock('../src/lib/reportEngine.js',        () => ({ buildReport: vi.fn(async () => ({ summary: {} })) }));
vi.mock('../src/handlers/domain.js',         () => ({ handleDomainScan:   vi.fn() }));
vi.mock('../src/handlers/ai.js',             () => ({ handleAIScan:       vi.fn() }));
vi.mock('../src/handlers/redteam.js',        () => ({ handleRedteamScan:  vi.fn() }));
vi.mock('../src/handlers/identity.js',       () => ({ handleIdentityScan: vi.fn() }));
vi.mock('../src/handlers/compliance.js',     () => ({ handleCompliance:   vi.fn() }));
vi.mock('../src/handlers/analytics.js',      () => ({
  trackEvent:         vi.fn(async () => {}),
  handleGetAnalytics: vi.fn(),
  handleScanStats:    vi.fn(),
  handleApiUsage:     vi.fn(),
  meterApiRequest:    vi.fn(async () => {}),
}));
vi.mock('../src/services/v24/billingEngine.js', () => ({ createInvoice: vi.fn(async () => {}) }));

// Keep these as inspectable mocks — tests assert on their call signatures
vi.mock('../src/services/emailEngine.js', () => ({
  enrollInSequence:         vi.fn(async () => ({ enrolled: true })),
  sendPurchaseConfirmation: vi.fn(async () => {}),
  runDripAutomation:        vi.fn(async () => {}),
}));
vi.mock('../src/services/lifecycleEngine.js', () => ({
  triggerPostPurchase: vi.fn(async () => {}),
  normalizeRevenueSource: vi.fn(s => s),
}));

// ── Imports (after mocks) ─────────────────────────────────────────────────────
import {
  handleListProposals,
  handleGetProposal,
  handleMarkProposalSent,
  handleAcceptProposal,
  handleRejectProposal,
} from '../src/handlers/proposalGenerator.js';

import { handlePaymentStatus } from '../src/handlers/payments.js';
import { enrollInSequence }    from '../src/services/emailEngine.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeRequest(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  return new Request(`https://api.cyberdudebivash.test${path}`, opts);
}

// authCtx fixtures that mirror what resolveAuthV5 returns in production
const OWNER_CTX    = { isAdmin: true,  authenticated: true, email: 'bivash@cyberdudebivash.com', tier: 'ENTERPRISE' };
const CUSTOMER_CTX = { isAdmin: false, authenticated: true, email: 'attacker@evil.com',           tier: 'PRO'        };
const ANON_CTX     = { isAdmin: false, authenticated: true, method: 'ip_fallback', email: null,   tier: 'FREE'       };

const MOCK_PROPOSAL = {
  id:           'prop_test_001',
  lead_id:      'lead_abc',
  company:      'Acme Corp',
  client_email: 'cto@acme.com',
  email:        'cto@acme.com',
  package_id:   'ENTERPRISE_SHIELD',
  price_inr:    499900,
  status:       'draft',
};

function makeKV(proposal = MOCK_PROPOSAL) {
  const store = new Map([
    [`proposals:doc:${proposal.id}`, JSON.stringify(proposal)],
    ['proposals:index', JSON.stringify([{ id: proposal.id, company: proposal.company }])],
  ]);
  return {
    get:    vi.fn(async (key, opts) => {
      const val = store.get(key);
      if (!val) return null;
      return opts?.type === 'json' ? JSON.parse(val) : val;
    }),
    put:    vi.fn(async (key, val) => { store.set(key, val); }),
    delete: vi.fn(async () => {}),
  };
}

function makeDB(row = null) {
  return {
    prepare: vi.fn(() => ({
      bind: vi.fn(() => ({
        first: vi.fn(async () => row),
        all:   vi.fn(async () => ({ results: row ? [row] : [] })),
        run:   vi.fn(async () => {}),
      })),
    })),
  };
}

function makeEnv({ proposal = MOCK_PROPOSAL, dbRow = null } = {}) {
  return {
    SECURITY_HUB_KV: makeKV(proposal),
    KV:              null,
    DB:              makeDB(dbRow),
  };
}

// ── Proposal BOLA guard tests ──────────────────────────────────────────────────

describe('Proposal BOLA guards (OWASP API1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── handleListProposals ────────────────────────────────────────────────────

  describe('GET /api/proposals (handleListProposals)', () => {
    it('returns 403 for unauthenticated / anonymous caller', async () => {
      const res = await handleListProposals(makeRequest('/api/proposals'), makeEnv(), ANON_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 403 for authenticated paying customer (non-owner)', async () => {
      const res = await handleListProposals(makeRequest('/api/proposals'), makeEnv(), CUSTOMER_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 200 for platform owner (isAdmin=true)', async () => {
      const res = await handleListProposals(makeRequest('/api/proposals'), makeEnv(), OWNER_CTX);
      expect(res.status).toBe(200);
    });

    it('403 response body says "Owner access required"', async () => {
      const res = await handleListProposals(makeRequest('/api/proposals'), makeEnv(), CUSTOMER_CTX);
      const body = await res.json();
      expect(body.error).toMatch(/owner access required/i);
    });
  });

  // ── handleGetProposal ──────────────────────────────────────────────────────

  describe('GET /api/proposals/:id (handleGetProposal)', () => {
    const PATH = '/api/proposals/prop_test_001';

    it('returns 403 for anonymous caller — no auth bypass possible', async () => {
      const res = await handleGetProposal(makeRequest(PATH), makeEnv(), ANON_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 403 for PRO customer who knows the proposal ID', async () => {
      const res = await handleGetProposal(makeRequest(PATH), makeEnv(), CUSTOMER_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 200 with proposal data for owner', async () => {
      const res = await handleGetProposal(makeRequest(PATH), makeEnv(), OWNER_CTX);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe('prop_test_001');
    });

    it('403 body does not expose proposal content to non-owner', async () => {
      const res = await handleGetProposal(makeRequest(PATH), makeEnv(), CUSTOMER_CTX);
      const body = await res.json();
      // Must not contain pricing or company intelligence
      expect(JSON.stringify(body)).not.toContain('Acme Corp');
      expect(JSON.stringify(body)).not.toContain('499900');
    });
  });

  // ── handleMarkProposalSent ─────────────────────────────────────────────────

  describe('POST /api/proposals/:id/send (handleMarkProposalSent)', () => {
    const PATH = '/api/proposals/prop_test_001/send';

    it('returns 403 for anonymous caller', async () => {
      const res = await handleMarkProposalSent(makeRequest(PATH, 'POST'), makeEnv(), ANON_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 403 for PRO customer attempting to mutate proposal state', async () => {
      const res = await handleMarkProposalSent(makeRequest(PATH, 'POST'), makeEnv(), CUSTOMER_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 200 for owner and marks proposal sent', async () => {
      const env = makeEnv();
      const res = await handleMarkProposalSent(makeRequest(PATH, 'POST'), env, OWNER_CTX);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.sent).toBe(true);
    });
  });

  // ── handleAcceptProposal ───────────────────────────────────────────────────

  describe('POST /api/proposals/:id/accept (handleAcceptProposal)', () => {
    const PATH = '/api/proposals/prop_test_001/accept';

    it('returns 403 for anonymous caller', async () => {
      const res = await handleAcceptProposal(makeRequest(PATH, 'POST'), makeEnv(), ANON_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 403 for PRO customer — cannot self-accept enterprise proposals', async () => {
      const res = await handleAcceptProposal(makeRequest(PATH, 'POST'), makeEnv(), CUSTOMER_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 200 for owner and records acceptance', async () => {
      const env = makeEnv();
      const res = await handleAcceptProposal(makeRequest(PATH, 'POST'), env, OWNER_CTX);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.accepted).toBe(true);
    });
  });

  // ── handleRejectProposal ───────────────────────────────────────────────────

  describe('POST /api/proposals/:id/reject (handleRejectProposal)', () => {
    const PATH = '/api/proposals/prop_test_001/reject';

    it('returns 403 for anonymous caller', async () => {
      const res = await handleRejectProposal(makeRequest(PATH, 'POST'), makeEnv(), ANON_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 403 for PRO customer — cannot reject enterprise proposals', async () => {
      const res = await handleRejectProposal(makeRequest(PATH, 'POST', { reason: 'too expensive' }), makeEnv(), CUSTOMER_CTX);
      expect(res.status).toBe(403);
    });

    it('returns 200 for owner and records rejection', async () => {
      const env = makeEnv();
      const res = await handleRejectProposal(
        makeRequest(PATH, 'POST', { reason: 'budget cycle' }),
        env,
        OWNER_CTX,
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.rejected).toBe(true);
      expect(body.data.reason).toBe('budget cycle');
    });

    it('enrolls rejected client in enterprise_winback sequence (revenue recovery)', async () => {
      vi.clearAllMocks();
      const env = makeEnv();
      await handleRejectProposal(
        makeRequest(PATH, 'POST', { reason: 'chose competitor' }),
        env,
        OWNER_CTX,
      );
      // Give the non-blocking Promise a tick to resolve
      await new Promise(r => setTimeout(r, 10));
      expect(enrollInSequence).toHaveBeenCalledWith(
        env,
        'cto@acme.com',
        'enterprise_winback',
        expect.objectContaining({ proposal_id: 'prop_test_001' }),
      );
    });

    it('does NOT enroll in winback when rejected by non-owner (guard fires first)', async () => {
      vi.clearAllMocks();
      await handleRejectProposal(makeRequest(PATH, 'POST'), makeEnv(), CUSTOMER_CTX);
      expect(enrollInSequence).not.toHaveBeenCalled();
    });
  });
});

// ── Payment status BOLA tests ──────────────────────────────────────────────────

describe('Payment status BOLA — information disclosure prevention', () => {
  // A paid row that PREVIOUSLY exposed amount and report_token via the status endpoint.
  // These fields must be absent from the response after the API1 fix.
  const PAID_ROW = {
    module:       'domain',
    target:       'example.com',
    status:       'paid',
    amount:       99900,           // must NOT appear in response
    report_token: 'tok_secret_123', // must NOT appear in response (grants download access)
    paid_at:      '2026-06-18T04:00:00.000Z',
    created_at:   '2026-06-18T03:58:00.000Z',
  };

  it('never returns amount_paise in the status response', async () => {
    const env = { DB: makeDB(PAID_ROW) };
    const req = makeRequest('/api/payments/status/order_test123', 'GET');
    const res = await handlePaymentStatus(req, env, ANON_CTX);
    const body = await res.json();
    expect(body).not.toHaveProperty('amount_paise');
    expect(JSON.stringify(body)).not.toContain('99900');
  });

  it('never returns download_url in the status response', async () => {
    const env = { DB: makeDB(PAID_ROW) };
    const req = makeRequest('/api/payments/status/order_test123', 'GET');
    const res = await handlePaymentStatus(req, env, ANON_CTX);
    const body = await res.json();
    expect(body).not.toHaveProperty('download_url');
    expect(JSON.stringify(body)).not.toContain('tok_secret_123');
  });

  it('returns safe status fields — order_id, status, module, target, paid_at, created_at', async () => {
    const env = { DB: makeDB(PAID_ROW) };
    const req = makeRequest('/api/payments/status/order_test123', 'GET');
    const res = await handlePaymentStatus(req, env, ANON_CTX);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.order_id).toBe('order_test123');
    expect(body.status).toBe('paid');
    expect(body.module).toBe('domain');
    expect(body.target).toBe('example.com');
    expect(body.paid_at).toBeDefined();
    expect(body.created_at).toBeDefined();
  });

  it('returns 404 for unknown order — no enumeration data leaked', async () => {
    const env = { DB: makeDB(null) };
    const req = makeRequest('/api/payments/status/order_unknown999', 'GET');
    const res = await handlePaymentStatus(req, env, ANON_CTX);
    expect(res.status).toBe(404);
  });

  it('returns 503 when DB is unavailable — does not expose fallback data', async () => {
    const env = {};
    const req = makeRequest('/api/payments/status/order_test123', 'GET');
    const res = await handlePaymentStatus(req, env, ANON_CTX);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body).not.toHaveProperty('amount_paise');
    expect(body).not.toHaveProperty('download_url');
  });

  // Account-linked orders: an API-surface audit found every other order/key/job
  // lookup in this codebase enforces ownership except this one. Anonymous/guest
  // checkouts (no user_id on the row) intentionally stay pollable by anyone
  // holding the opaque order_id — that's the pre-existing, deliberate public
  // polling design tested above and must not regress.
  describe('account-linked orders are only readable by their owner', () => {
    const LINKED_ROW = { ...PAID_ROW, user_id: 'alice' };

    it('the owner (alice) can read their own linked order (200)', async () => {
      const env = { DB: makeDB(LINKED_ROW) };
      const req = makeRequest('/api/payments/status/order_test123', 'GET');
      const res = await handlePaymentStatus(req, env, { ...ANON_CTX, user_id: 'alice' });
      expect(res.status).toBe(200);
    });

    it('a different logged-in user (bob) gets 404, not the order', async () => {
      const env = { DB: makeDB(LINKED_ROW) };
      const req = makeRequest('/api/payments/status/order_test123', 'GET');
      const res = await handlePaymentStatus(req, env, { ...ANON_CTX, user_id: 'bob' });
      expect(res.status).toBe(404);
    });

    it('an anonymous caller gets 404 for a linked order (no user_id to match)', async () => {
      const env = { DB: makeDB(LINKED_ROW) };
      const req = makeRequest('/api/payments/status/order_test123', 'GET');
      const res = await handlePaymentStatus(req, env, ANON_CTX);
      expect(res.status).toBe(404);
    });

    it('an anonymous/guest order (no user_id on the row) stays publicly pollable', async () => {
      const env = { DB: makeDB(PAID_ROW) }; // PAID_ROW has no user_id
      const req = makeRequest('/api/payments/status/order_test123', 'GET');
      const res = await handlePaymentStatus(req, env, ANON_CTX);
      expect(res.status).toBe(200);
    });
  });
});
