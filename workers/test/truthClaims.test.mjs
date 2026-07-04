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
const TRUST   = read('../../frontend/trust-center.html');
const MARKET  = read('../../frontend/sentinel-apex-marketplace.html');
const SUBPROC = read('../../SUB_PROCESSOR_LIST.md');
const ROUTER  = read('../src/core/aiProviderRouter.js');

describe('index.html — Security Transparency block tells the truth', () => {
  it('no longer claims zero data collection on scan targets (scan_history stores them)', () => {
    expect(INDEX).not.toContain('Zero data collection on scan targets');
  });

  it('no longer claims all AI processing is deterministic / no LLM data leaves', () => {
    expect(INDEX).not.toContain('All AI processing is deterministic');
  });

  it('no longer claims "no third-party analytics" while loading GA4', () => {
    expect(INDEX).not.toContain('No third-party analytics SDKs');
    // GA4 is genuinely loaded — the claim must acknowledge it.
    expect(INDEX).toContain('googletagmanager.com/gtag/js');
    expect(INDEX).toContain('Google Analytics 4 only');
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
