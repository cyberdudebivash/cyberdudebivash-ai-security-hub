// Truth-claim + fabricated-fallback guards (Product Certification, Phase 3/9).
//
// Locks in three classes of fixes so they can never regress:
//  1. Customer-facing trust claims must not contradict the platform's real
//     behavior (external LLM processing, scan-history storage, GA4 analytics).
//  2. The LLM sub-processors actually wired in aiProviderRouter must be
//     disclosed in SUB_PROCESSOR_LIST.md and on the trust-center page.
//  3. Marketplace surfaces must never substitute fabricated catalogs/feeds
//     for live data (fallbacks must be honest error states, and the report
//     grid must read the real catalog shape/category).
//
// Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(resolve(__dirname, p), 'utf8');

const INDEX   = read('../../frontend/index.html');
const SEO_SCHEMA_JS = read('../../frontend/assets/js/seo-schema.js');
const TRUST   = read('../../frontend/trust-center.html');
const CONTACT = read('../../frontend/contact.html');
const BOOKING = read('../../frontend/booking.html');
const MARKET  = read('../../frontend/sentinel-apex-marketplace.html');
const SUBPROC = read('../../SUB_PROCESSOR_LIST.md');
const ROUTER  = read('../src/core/aiProviderRouter.js');
const SEARCH_JS = read('../../frontend/global-search-v2.js');
const CHECKOUT_MODAL   = read('../../frontend/assets/checkout-modal.js');
const COPILOT_WIDGET    = read('../../frontend/assets/copilot-widget.js');
const SEC_ASSESSMENT   = read('../../frontend/security-assessment.html');
const AI_ASSESSMENT    = read('../../frontend/ai-security-assessment.html');
const PAYMENTS_HANDLER = read('../src/handlers/payments.js');
const RAZORPAY_LIB     = read('../src/lib/razorpay.js');

import { handleTrustCenter as handleEnterpriseTrustCenter } from '../src/handlers/enterprisePortalHandlers.js';

// Permissive D1/KV stubs — this suite only cares about response *content*,
// not the underlying metric numbers (those are covered by
// trustMetricsContract.test.mjs).
function stubEnv() {
  const row = { cnt: 0, v: 0, checks: 0, ok_checks: 0 };
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first(col) { return col ? row[col] : row; },
          async all() { return { results: [] }; },
        };
      },
    },
    SECURITY_HUB_KV: { async get() { return null; }, async put() {} },
  };
}

describe('index.html — Security Transparency block tells the truth', () => {
  it('no longer claims zero data collection on scan targets (scan_history stores them)', () => {
    expect(INDEX).not.toContain('Zero data collection on scan targets');
  });

  it('no longer claims all AI processing is deterministic / no LLM data leaves', () => {
    expect(INDEX).not.toContain('All AI processing is deterministic');
  });

  it('discloses every tracker that actually loads, instead of an outdated "GA4 only" claim', () => {
    expect(INDEX).not.toContain('No third-party analytics SDKs');
    // GA4/GTM/Clarity/AdSense now load from the shared, consent-gated
    // seo-schema.js module (loaded by index.html) rather than inline — the
    // claim must name all of them, not just GA4, and must not undersell it.
    expect(INDEX).not.toContain('Google Analytics 4 only');
    expect(INDEX).toContain('Google Tag Manager');
    expect(INDEX).toContain('Microsoft Clarity');
    expect(INDEX).toContain('Google AdSense');
    // GA4 must be genuinely reachable from this page: it loads this module...
    expect(INDEX).toMatch(/<script type="module" src="\/assets\/js\/seo-schema\.js">/);
    // ...and the module actually contains GA4's loader, not just a claim.
    expect(SEO_SCHEMA_JS).toContain('googletagmanager.com/gtag/js');
  });

  it('links the LLM disclosure to the trust-center sub-processor section', () => {
    expect(INDEX).toContain('/trust-center#sub-processors');
  });

  it('does not advertise GPT-4 analysis (platform uses Groq/DeepSeek/CF-AI mesh)', () => {
    expect(INDEX).not.toContain('GPT-4 Threat Analysis');
    expect(INDEX).not.toContain('GPT-4 class');
  });
});

describe('trust-center.html — methodology claims match the code', () => {
  it('no longer claims scan data never reaches external LLM providers', () => {
    expect(TRUST).not.toContain('No scan data is sent to external LLM providers');
  });

  it('no longer claims scan targets are processed in-flight and not stored', () => {
    expect(TRUST).not.toContain('processed in-flight, not stored');
  });

  it('has a sub-processor disclosure section naming the primary LLM provider', () => {
    expect(TRUST).toContain('id="sub-processors"');
    expect(TRUST).toContain('Groq');
    expect(TRUST).toContain('Razorpay');
  });
});

describe('SUB_PROCESSOR_LIST.md — every wired LLM provider is disclosed', () => {
  // Providers the router is actually coded to call (external endpoints only;
  // Workers AI is Cloudflare infrastructure but is disclosed anyway).
  const disclosed = ['Groq', 'DeepSeek', 'OpenRouter', 'Together', 'Anthropic'];

  it.each(disclosed)('discloses %s', (name) => {
    // Guard the premise: the provider really is in the router…
    expect(ROUTER.toLowerCase()).toContain(name.toLowerCase());
    // …and really is in the disclosure.
    expect(SUBPROC).toContain(name);
  });

  it('discloses Google Analytics as a sub-processor (GA4 is loaded on index.html)', () => {
    expect(SUBPROC).toContain('Google Analytics 4');
  });

  it('states that prompt content may include scan targets and findings', () => {
    expect(SUBPROC).toMatch(/scan targets, and scan findings/);
  });
});

describe('index.html — defense marketplace fallback is an honest error state', () => {
  it('removed the fabricated 6-item fallback catalog', () => {
    // Signature entries of the old hardcoded catalog:
    expect(INDEX).not.toContain('Outlook RCE Firewall Block Rules');
    expect(INDEX).not.toContain("demand_score:.95");
  });

  it('renders an unavailable state with a working retry hook instead', () => {
    expect(INDEX).toContain('Live catalog temporarily unavailable');
    expect(INDEX).toContain('window.dsRetryLoad');
    // The retry hook must actually be defined (loadSolutions is IIFE-scoped).
    expect(INDEX).toMatch(/window\.dsRetryLoad\s*=\s*function/);
  });

  it('labels the hand-set demand_score weighting honestly', () => {
    expect(INDEX).not.toContain('<span>Demand Score</span>');
    expect(INDEX).toContain('<span>Remediation Priority</span>');
  });
});

describe('sentinel-apex-marketplace.html — report grid is wired to the real catalog', () => {
  it('queries the real category slug and parses the real response shape', () => {
    // The old code queried ?category=report (0 products, always) and read a
    // non-existent d.products field.
    expect(MARKET).not.toContain('category=report`');
    expect(MARKET).toContain('category=intelligence_report');
    expect(MARKET).toContain('d.catalog?.intelligence_report?.items');
  });

  it('buys through the server-issued checkout_url, not a client-set price modal', () => {
    expect(MARKET).toContain('checkout_url');
    expect(MARKET).toContain('price_display');
  });

  it('removed the fabricated purchasable report list', () => {
    expect(MARKET).not.toContain('Critical CVE Intelligence Report — Q2 2026');
    expect(MARKET).not.toContain('Complete Intelligence Bundle — Q2 2026');
    expect(MARKET).toContain('Report catalog temporarily unavailable');
  });

  it('removed the fabricated static CVE feed fallback', () => {
    // Signature entries of the old static list:
    expect(MARKET).not.toContain("'CVE-2024-21893'");
    expect(MARKET).not.toContain('Citrix Bleed NetScaler session token disclosure');
    expect(MARKET).toContain('Live CVE feed temporarily unavailable');
  });
});

describe('index.html — Recent Scans badges reflect real severity, not static HTML', () => {
  it('badges start neutral and carry ids so JS can update them', () => {
    for (let i = 1; i <= 5; i++) {
      expect(INDEX).toContain(`id="rs-b${i}"`);
    }
    // The static severity words must not be hardcoded into the initial badges.
    // (Grab the Recent Scans markup block and assert it has no baked-in badge.)
    const block = INDEX.slice(INDEX.indexOf('<!-- Recent Scans -->'), INDEX.indexOf('<!-- AI Risk Insights'));
    expect(block).not.toMatch(/scan-log-badge[^>]*>CRITICAL</);
    expect(block).not.toMatch(/scan-log-badge[^>]*>HIGH</);
  });

  it('JS drives the badge from scan.risk_level and neutralizes empty rows', () => {
    expect(INDEX).toContain("document.getElementById('rs-b'");
    expect(INDEX).toContain('bEl.textContent = rl');
    // The empty-row fill loop must reset the badge too.
    expect(INDEX).toMatch(/No recent scans[\s\S]{0,200}bEl\.textContent = '—'/);
  });
});

describe('global search — real backend is actually reachable from the live page', () => {
  // globalSearch.js (a real, D1-backed, unit-tested /api/search handler) had
  // no live path to it: its only frontend consumer was never <script>-included
  // anywhere, and that consumer's own DOM-readiness gate (#cdb-nav-actions)
  // was produced by a second script that was ALSO never included anywhere.
  // Locks both halves of the fix so this can't silently regress back to dark.
  it('index.html includes the global-search script', () => {
    expect(INDEX).toMatch(/<script src="\/global-search-v2\.js"/);
  });

  it('the nav-actions container carries the id global-search-v2.js waits for', () => {
    expect(INDEX).toMatch(/class="nav-actions"\s+id="cdb-nav-actions"/);
  });

  it('a visible, labeled search trigger exists in the nav', () => {
    expect(INDEX).toContain('id="cdb-search-trigger"');
    expect(INDEX).toMatch(/aria-label="Search/);
  });

  it('the search UI is a hidden-by-default modal, not a permanently-docked bar (this page\'s top chrome is already full)', () => {
    expect(SEARCH_JS).toContain("modal.style.cssText = 'display:none");
    expect(SEARCH_JS).not.toMatch(/position:fixed;top:12px/);
  });

  it('exposes a stable open hook for the nav trigger and the Cmd/Ctrl+K shortcut', () => {
    expect(SEARCH_JS).toContain('window.CDB_SEARCH_V2_OPEN = openModal');
    expect(SEARCH_JS).toMatch(/e\.metaKey \|\| e\.ctrlKey/);
  });
});

describe('GET /api/trust-center (enterprisePortalHandlers) — no fabricated compliance claims', () => {
  // This route (not /api/trust/center) is the one frontend/trust-center.html
  // actually fetches. It used to assert a specific false SOC 2/ISO 27001 audit
  // timeline and a hardcoded uptime figure — this locks the fix so a second,
  // divergent trust-center handler can never drift back into fabrication.
  const req = new Request('https://cyberdudebivash.in/api/trust-center');

  it('never claims a SOC 2 audit is in progress or scheduled for a specific quarter', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    const soc2 = body.compliance_status.frameworks.find(f => f.framework === 'SOC 2 Type II');
    expect(soc2.status).not.toBe('In Progress');
    expect(soc2.evidence).not.toMatch(/Q[1-4]\s*20\d\d/);
  });

  it('never claims an ISO 27001 gap assessment was completed', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    const iso = body.compliance_status.frameworks.find(f => f.framework === 'ISO 27001');
    expect(iso.evidence).not.toBe('Gap assessment completed');
  });

  it('does not expose a certifications_planned field with fabricated dates', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    expect(body.compliance_status.certifications_planned).toBeUndefined();
  });

  it('names Groq, not only Anthropic, as the primary AI sub-processor', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    expect(body.privacy_practices.subprocessors.join(' ')).toContain('Groq');
  });

  it('platform_uptime is not a hardcoded marketing percentage', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    expect(body.platform_stats.platform_uptime).not.toBe('99.9%+ (Cloudflare edge)');
  });

  // Commercial-readiness sweep (2026-07-06): trust_signals is a second,
  // separately-authored claims list in the same response as subprocessors.
  // The Groq-not-Anthropic fix above locked subprocessors but missed this
  // array — it still asserted "All AI processing via Anthropic API", which
  // directly contradicts subprocessors ("Groq (primary...)") in the very
  // same JSON payload, and contradicts wrangler.toml's own note that
  // ANTHROPIC_API_KEY is not used at all. Locks both halves so a future
  // provider-lineup edit can't silently re-diverge the two lists.
  it('trust_signals does not claim exclusive/sole use of Anthropic', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    const signals = body.trust_signals.join(' ');
    expect(signals).not.toContain('All AI processing via Anthropic API');
  });

  it('trust_signals AI claim is consistent with the subprocessors list (Groq primary)', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    const aiSignal = body.trust_signals.find(s => /AI/i.test(s));
    expect(aiSignal).toMatch(/Groq/);
  });

  it('policies_url and security_url point to real, reachable paths — not the dead /privacy shorthand or the intel. subdomain', async () => {
    const body = await (await handleEnterpriseTrustCenter(req, stubEnv(), {})).json();
    expect(body.policies_url).not.toBe('https://cyberdudebivash.in/privacy');
    expect(body.policies_url).toBe('https://cyberdudebivash.in/privacy-policy');
    expect(body.security_url).not.toContain('intel.cyberdudebivash.com');
    expect(body.security_url).toBe('https://cyberdudebivash.in/api/security-center');
  });
});

describe('contact.html — the sales/support form never claims success it did not achieve', () => {
  // Commercial-readiness sweep (2026-07-06): the form posted to
  // /api/leads/capture (a different feature — a pre-results email gate
  // expecting {email, scan_id, module}) with a field named workEmail where
  // that handler reads `email`, so every submission 400'd. The success
  // banner + ticket number were shown unconditionally — fetch() only
  // rejects on network failure, never on 4xx/5xx — so the inquiry was
  // silently lost while the customer was told it succeeded. Locks: it now
  // posts to the real /api/enterprise/inquire with matching field names,
  // and only shows success when the response actually says so.
  it('does not post to /api/leads/capture (wrong feature: pre-results email gate, not a sales inquiry)', () => {
    expect(CONTACT).not.toContain("fetch('/api/leads/capture'");
  });

  it('posts to /api/enterprise/inquire with field names that handler actually reads', () => {
    expect(CONTACT).toContain("fetch('/api/enterprise/inquire'");
    const block = CONTACT.slice(CONTACT.indexOf("fetch('/api/enterprise/inquire'"), CONTACT.indexOf("delivered = response.ok"));
    expect(block).toContain('company: formData.company');
    expect(block).toContain('email: formData.workEmail');
  });

  it('gates the success confirmation on the response actually succeeding', () => {
    expect(CONTACT).toMatch(/delivered\s*=\s*response\.ok\s*&&\s*data\.success\s*===\s*true/);
    expect(CONTACT).not.toContain('Show success confirmation regardless of API response');
  });

  it('shows an honest, actionable failure state with a direct fallback contact', () => {
    expect(CONTACT).toContain('Message not delivered');
    expect(CONTACT).toContain('wa.me/918179881447');
    expect(CONTACT).toContain('mailto:contact@cyberdudebivash.in');
  });
});

describe('booking.html — demo booking actually reaches the real sales pipeline', () => {
  // Commercial-readiness sweep (2026-07-06): this form's failure handling was
  // already correct (only shows success on response.ok) — but it posted to
  // /api/leads/capture, which expects {email, scan_id, module} and reads
  // `email` where this form sent `workEmail`. Every booking attempt 400'd,
  // so every visitor who tried to book a demo was shown the honest-but-total
  // failure message. Purpose-built endpoints already exist and are wired in
  // index.js: /api/sales/leads (CRM lead w/ ICP scoring) and
  // /api/sales/demo/book (the actual slot reservation). Locks both halves.
  it('does not post to /api/leads/capture (wrong feature: pre-results email gate, not a CRM lead)', () => {
    expect(BOOKING).not.toContain("fetch('/api/leads/capture'");
  });

  it('files a CRM lead via /api/sales/leads with field names that handler actually reads', () => {
    expect(BOOKING).toContain("fetch('/api/sales/leads'");
    const block = BOOKING.slice(BOOKING.indexOf("fetch('/api/sales/leads'"), BOOKING.indexOf("fetch('/api/sales/demo/book'"));
    expect(block).toContain('email: formData.workEmail');
    expect(block).toContain('company: formData.companyName');
  });

  it('books the actual slot via /api/sales/demo/book with the required fields', () => {
    expect(BOOKING).toContain("fetch('/api/sales/demo/book'");
    const block = BOOKING.slice(BOOKING.indexOf("fetch('/api/sales/demo/book'"));
    expect(block).toContain('preferred_slot: preferredSlot');
    expect(block).toContain('email: formData.workEmail');
  });

  it('still only shows success when the booking response actually confirms it', () => {
    // The pre-existing, already-correct gate — must survive the endpoint swap.
    expect(BOOKING).toMatch(/apiOk\s*=\s*response\.ok/);
    expect(BOOKING).toContain('Show success only on confirmed API receipt');
  });
});

describe('checkout-modal.js — every priced CTA creates a real, server-verified order', () => {
  // Commercial-readiness audit (2026-07-06): every "Book Assessment" button on
  // security-assessment.html/ai-security-assessment.html (plus ciso-hub.html,
  // mcp-security.html) called CDB_CHECKOUT_MODAL.open() with a tierName but no
  // module — triggerRazorpay() then fell through to a client-only
  // `new Razorpay({amount})` with no order_id and no verify call. A real
  // charge could fire with zero backend order record. Locks that this
  // dangerous fallback is gone and every named product is routed through a
  // real order-create → verify flow instead.
  it('no longer constructs a bare client-only Razorpay charge with no order_id', () => {
    const trigger = CHECKOUT_MODAL.slice(
      CHECKOUT_MODAL.indexOf('triggerRazorpay()'),
      CHECKOUT_MODAL.indexOf('_loadRazorpaySdk()'),
    );
    expect(trigger).not.toMatch(/new\s+window\.Razorpay\(\{\s*\n?\s*key,/);
    expect(trigger).not.toContain('amount:      opts.amount *');
  });

  it('treats any unrecognized tierName as a real, order-verified package purchase', () => {
    const trigger = CHECKOUT_MODAL.slice(
      CHECKOUT_MODAL.indexOf('triggerRazorpay()'),
      CHECKOUT_MODAL.indexOf('_loadRazorpaySdk()'),
    );
    expect(trigger).toContain("module: 'package'");
    expect(trigger).toContain('productId: opts.tierName');
  });

  it('strips a "_PLAN" suffix and routes it through the real subscription flow', () => {
    const trigger = CHECKOUT_MODAL.slice(
      CHECKOUT_MODAL.indexOf('triggerRazorpay()'),
      CHECKOUT_MODAL.indexOf('_loadRazorpaySdk()'),
    );
    expect(trigger).toMatch(/replace\(\/_PLAN\$\/, ''\)/);
    expect(trigger).toContain('_startSubscriptionCheckout({ ...opts, tierName: strippedTier })');
  });

  it('_startReportCheckout falls back the order target to the collected email for non-scan packages', () => {
    const block = CHECKOUT_MODAL.slice(CHECKOUT_MODAL.indexOf('_startReportCheckout(opts)'));
    expect(block).toContain("const target = (opts.target || '').trim() || email;");
  });

  it('_startReportCheckout forwards product_id to both create-order and verify', () => {
    const block = CHECKOUT_MODAL.slice(
      CHECKOUT_MODAL.indexOf('_startReportCheckout(opts)'),
      CHECKOUT_MODAL.indexOf('_onReportPaymentComplete'),
    );
    expect(block.match(/if \(opts\.productId\)/g)?.length).toBeGreaterThanOrEqual(2);
  });
});

describe('index.html — homepage MYTHOS checkout no longer fires an unreconcilable charge', () => {
  // The homepage's separate "MYTHOS" checkout widget built its own
  // `new Razorpay({amount})` with no order_id and no notes carrying
  // plan/tenant — /api/mythos/checkout/initialize never creates a Razorpay
  // order at all, so nothing (not even the async webhook) could ever
  // reconcile a captured charge to a plan. The handler then showed a fake
  // "activates within 2 minutes" toast unconditionally. Locks that rzpPay()
  // now delegates to the real, verified subscription checkout instead.
  it('rzpPay() no longer builds a bare Razorpay object with a fake unconditional success toast', () => {
    const fn = INDEX.slice(INDEX.indexOf('function rzpPay()'), INDEX.indexOf('function showToast'));
    expect(fn).not.toContain("showToast('✅ Payment successful! Your plan activates within 2 minutes.', 'success')");
    expect(fn).not.toMatch(/key:\s*_rzpKeyId/);
  });

  it('rzpPay() delegates to the real CDB_CHECKOUT_MODAL subscription flow', () => {
    const fn = INDEX.slice(INDEX.indexOf('function rzpPay()'), INDEX.indexOf('function showToast'));
    expect(fn).toContain('window.CDB_CHECKOUT_MODAL.open({');
  });
});

describe('sentinel-apex-marketplace.html — CVE/intel report purchases use the real order flow', () => {
  // The modal's "Proceed to Payment" CTA called triggerModalPayment(), which
  // opened the shared checkout modal with tierName:'INTEL_REPORT' — an
  // unrecognized product that fell into the same legacy no-order-id bypass.
  // The purpose-built, already-correct /api/sentinel/purchase + /verify flow
  // (cdbSentinelBuy) sat right next to it, unused. Locks the fix.
  it('triggerModalPayment() calls the real, order-verified cdbSentinelBuy()', () => {
    const fn = MARKET.slice(MARKET.indexOf('function triggerModalPayment()'), MARKET.indexOf('function closeModal()'));
    expect(fn).toContain('cdbSentinelBuy()');
    expect(fn).not.toContain('openReportCheckout');
  });

  it('the now-dead openReportCheckout legacy wrapper was removed rather than left unreachable', () => {
    expect(MARKET).not.toContain('function openReportCheckout(');
  });

  it('openPlanCheckout()\'s "_PLAN"-suffixed tierName is still safely handled (stripped centrally by checkout-modal.js)', () => {
    const fn = MARKET.slice(MARKET.indexOf('function openPlanCheckout('), MARKET.indexOf('function paintPlans('));
    expect(fn).toContain("tier + '_PLAN'");
  });
});

describe('copilot-widget.js — the site-wide chat widget proves who is asking', () => {
  // Embedded on user-dashboard.html and ~20 other pages, none of this
  // widget's fetch calls attached Authorization/x-api-key — every
  // conversation through it resolved through the backend's anonymous
  // IP-fallback auth branch (tier: FREE, always), silently capping every
  // paying customer at the free tier on their own dashboard. Locks that all
  // 6 call sites now attach the stored session token.
  it('defines a shared authHeaders() helper that reads the real session token', () => {
    expect(COPILOT_WIDGET).toContain('function authHeaders(');
    expect(COPILOT_WIDGET).toContain("localStorage.getItem('cdb_token')");
  });

  it('every /api/copilot/* fetch call site attaches authHeaders()', () => {
    const callSites = [
      '/api/copilot/capabilities`, { headers: authHeaders() }',
      "/api/copilot/quick-action`, {\n        method: 'POST', headers: authHeaders(",
      "/api/copilot/chat/stream`, {\n      method: 'POST', headers: authHeaders(",
      "/api/copilot/chat`, {\n        method: 'POST', headers: authHeaders(",
      '/api/copilot/session?session_id=${encodeURIComponent(sessionId)}`, { headers: authHeaders() }',
      "/api/copilot/session?session_id=${encodeURIComponent(sessionId)}`, { method: 'DELETE', headers: authHeaders() }",
    ];
    for (const snippet of callSites) {
      expect(COPILOT_WIDGET).toContain(snippet);
    }
  });

  it('no /api/copilot/* fetch call is left without a headers option', () => {
    const calls = COPILOT_WIDGET.match(/fetch\(`\$\{API_BASE\}\/api\/copilot\/[^;]*?\);/gs) || [];
    expect(calls.length).toBeGreaterThanOrEqual(6);
    for (const call of calls) {
      expect(call).toContain('authHeaders(');
    }
  });
});

describe('razorpay.js / payments.js — one-time marketing-page products are server-priced', () => {
  // PACKAGE_PRICES is the server-side allowlist checkout-modal.js's 'package'
  // module resolves against — the client-displayed amount is never trusted.
  it('PACKAGE_PRICES covers every product_id used by the assessment pages', () => {
    for (const id of ['SECURITY_ASSESSMENT', 'PROFESSIONAL_ASSESSMENT', 'ENTERPRISE_ASSESSMENT']) {
      expect(SEC_ASSESSMENT).toContain(`openPayment('${id}'`);
      expect(RAZORPAY_LIB).toContain(`${id}:`);
    }
    for (const id of [
      'AI_SECURITY_ASSESSMENT', 'OWASP_LLM_ASSESSMENT', 'AI_GOVERNANCE_ASSESSMENT',
      'AI_RED_TEAM', 'MCP_SECURITY_REVIEW', 'AI_AGENT_SECURITY', 'RAG_SECURITY_ASSESSMENT',
      'AI_SECURITY_STARTER', 'AI_SECURITY_PROFESSIONAL', 'ENTERPRISE_AI_SUITE',
    ]) {
      expect(AI_ASSESSMENT).toContain(`openPayment('${id}'`);
      expect(RAZORPAY_LIB).toContain(`${id}:`);
    }
  });

  it('handleCreateOrder validates product_id against PACKAGE_PRICES for module "package"', () => {
    const fn = PAYMENTS_HANDLER.slice(
      PAYMENTS_HANDLER.indexOf('export async function handleCreateOrder'),
      PAYMENTS_HANDLER.indexOf('export async function handleVerifyPayment'),
    );
    expect(fn).toContain("if (!PACKAGE_PRICES[packageId])");
    expect(fn).toContain('price = PACKAGE_PRICES[packageId]');
  });

  it('handleVerifyPayment fulfills "package" the same safe way as "assessment" (no scan step, payment confirmed only after HMAC verify)', () => {
    const fn = PAYMENTS_HANDLER.slice(PAYMENTS_HANDLER.indexOf('export async function handleVerifyPayment'));
    expect(fn).toContain("NON_SCAN_MODULES = ['assessment', 'package', 'subscription']");
    expect(fn).toContain("if (module === 'assessment' || module === 'package')");
  });
});
