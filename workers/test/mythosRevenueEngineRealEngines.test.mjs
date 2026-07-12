// CAP-MYTHOS-003 — mythosRevenueEngine.js previously fabricated every result.
//
// handleMythosScan returned a hardcoded findings_summary/global_threat_level
// (identical for any target once the KV intel cache was empty) plus static
// Sigma/YARA/KQL/Suricata/playbook string templates and a fixed 4-IP IOC list
// for literally any input. handleMythosCompliance returned a static per-
// framework lookup table with verification_status always 'ALIGNED',
// identical for any organization. Both were also reachable with zero
// authentication (isPremium() just treats a missing authCtx as free-tier).
//
// This test proves the replacement handlers (a) call the platform's real
// scan/compliance engines so different targets genuinely produce different
// results, (b) never emit the old fabricated strings/values, and (c) still
// gate premium content correctly. It also proves the multi-rail checkout
// (handleMythosCheckout/handleMythosWebhook) — a live, untested, duplicate
// tier-grant mechanism with zero real frontend callers — is gone from both
// the handler file and the route table.
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

vi.mock('../src/lib/dns.js', () => ({
  resolveDomain: vi.fn(),
  inferTLSGrade: vi.fn(),
}));
vi.mock('../src/lib/dnsbl.js', () => ({
  fullBlacklistCheck: vi.fn(),
}));
vi.mock('../src/services/mythosEnrichmentEngine.js', () => ({
  enrichAssessmentWithMYTHOS: vi.fn(async (env, { report }) => ({
    ...report,
    mythos_intelligence: {
      engine: 'CYBERDUDEBIVASH MYTHOS AI™',
      version: 'v4.0-SOVEREIGN',
      mythos_confidence: 82,
      cyber_brain: { risk_score: report.risk_score ?? 0, risk_level: report.risk_level ?? 'LOW' },
      mitre_attack: { tactics_identified: 1, mappings: [{ technique: 'T1583' }] },
      autonomous_remediation_plan: ['Publish a DMARC policy', 'Enable DNSSEC'],
      ai_executive_brief: { generated: false, narrative: null },
    },
    powered_by_mythos: true,
  })),
}));

const { resolveDomain, inferTLSGrade } = await import('../src/lib/dns.js');
const { fullBlacklistCheck } = await import('../src/lib/dnsbl.js');
const { handleMythosScan, handleMythosCompliance } = await import('../src/handlers/mythosRevenueEngine.js');

const root = resolve(import.meta.dirname, '..');
const rawHandlerSource = readFileSync(resolve(root, 'src/handlers/mythosRevenueEngine.js'), 'utf8');
const rawIndexSource = readFileSync(resolve(root, 'src/index.js'), 'utf8');

function req(body) {
  return new Request('https://x/api/mythos/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function cleanDomainResult(overrides = {}) {
  resolveDomain.mockResolvedValue({
    resolves: true, ipv4: ['93.184.216.34'], ipv6: [], nameservers: ['ns1.example.com'],
    mx: { records: [] },
    dnssec: { enabled: true, status: 'VALID' },
    spf: { present: true, policy: 'STRICT', record: 'v=spf1 -all', issues: [] },
    dmarc: { present: true, policy: 'reject', enforcement_level: 'REJECT', rua: 'mailto:d@example.com', issues: [] },
    dkim: { found: true, selectors_found: [{ selector: 'default' }] },
    caa: { present: true, records: ['0 issue "letsencrypt.org"'] },
    ...overrides.dns,
  });
  inferTLSGrade.mockResolvedValue({ tls_grade: 'A', hsts_present: true, reachable: true, ...overrides.tls });
  fullBlacklistCheck.mockResolvedValue({
    any_blacklisted: false, combined_threat_score: 0, feeds_total: 7,
    domain_check: { listed_on: [] }, ip_check: { listed_on: [] }, risk_label: 'CLEAN', summary: 'clean',
    ...overrides.bl,
  });
}

function flaggedDomainResult() {
  resolveDomain.mockResolvedValue({
    resolves: true, ipv4: ['185.220.101.1'], ipv6: [], nameservers: ['ns1.evil-host.test'],
    mx: { records: [] },
    dnssec: { enabled: false, status: 'ABSENT' },
    spf: { present: false, policy: null, issues: [] },
    dmarc: { present: false, policy: null, enforcement_level: null, issues: [] },
    dkim: { found: false, selectors_checked: new Array(11).fill(0) },
    caa: { present: false, records: [] },
  });
  inferTLSGrade.mockResolvedValue({ tls_grade: 'F', hsts_present: false, reachable: true });
  fullBlacklistCheck.mockResolvedValue({
    any_blacklisted: true, combined_threat_score: 95, feeds_total: 7,
    domain_check: { listed_on: ['SPAMHAUS_DBL'] }, ip_check: { listed_on: ['SPAMHAUS_ZEN'] },
    risk_label: 'MALICIOUS', summary: 'blacklisted on 2 feeds',
  });
}

describe('handleMythosScan — real engine, not fabricated (CAP-MYTHOS-003)', () => {
  it('rejects an invalid/empty target before ever calling the real scan engine', async () => {
    const res = await handleMythosScan(req({ target: '' }), {}, {});
    expect(res.status).toBe(400);
    expect(resolveDomain).not.toHaveBeenCalled();
  });

  it('calls the real DNS/TLS/blacklist engine with the submitted target', async () => {
    cleanDomainResult();
    const res = await handleMythosScan(req({ target: 'clean-example.test' }), {}, { tier: 'PRO' });
    expect(res.status).toBe(200);
    expect(resolveDomain).toHaveBeenCalledWith('clean-example.test');
    expect(inferTLSGrade).toHaveBeenCalledWith('clean-example.test');
    expect(fullBlacklistCheck).toHaveBeenCalledWith('clean-example.test', ['93.184.216.34']);
    const body = await res.json();
    expect(body.result.target).toBe('clean-example.test');
  });

  it('two different targets with different real signals produce different results (proves it is not a fixed template)', async () => {
    cleanDomainResult();
    const cleanRes = await handleMythosScan(req({ target: 'clean-example.test' }), {}, { tier: 'PRO' });
    const cleanBody = await cleanRes.json();

    flaggedDomainResult();
    const flaggedRes = await handleMythosScan(req({ target: 'flagged-example.test' }), {}, { tier: 'PRO' });
    const flaggedBody = await flaggedRes.json();

    expect(cleanBody.result.risk_level).not.toBe(flaggedBody.result.risk_level);
    expect(cleanBody.result.threat_intelligence.any_blacklisted).toBe(false);
    expect(flaggedBody.result.threat_intelligence.any_blacklisted).toBe(true);
    // The real blacklist finding must carry the genuinely-detected feed name,
    // never the old hardcoded fake IOC set.
    expect(flaggedBody.result.threat_intelligence.domain_listed_on).toEqual(['SPAMHAUS_DBL']);
  });

  it('never emits the old fabricated IOC/rule-template content', async () => {
    cleanDomainResult();
    const res = await handleMythosScan(req({ target: 'clean-example.test' }), {}, { tier: 'PRO' });
    const text = JSON.stringify(await res.json());
    expect(text).not.toContain('45.33.32.156');   // old fixed fake IP #1
    expect(text).not.toContain('185.220.101.1' /* as a fixed fake, not this test's real mock */);
    expect(text).not.toMatch(/CDB-MYTHOS-v30|CDB_MYTHOS_Exploit_/);
    expect(text).not.toContain('CYBERDUDEBIVASH MYTHOS AI v30.0.2');
  });

  it('falls back to the honest deterministic engine (not a crash, not a fabricated verdict) when live DNS throws', async () => {
    resolveDomain.mockRejectedValue(new Error('DoH unreachable'));
    inferTLSGrade.mockResolvedValue({ tls_grade: 'A' });
    fullBlacklistCheck.mockResolvedValue({ any_blacklisted: false });
    const res = await handleMythosScan(req({ target: 'unreachable-example.test' }), {}, { tier: 'PRO' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.result.data_source).toBe('deterministic_fallback');
    expect(body.result.fallback_reason).toMatch(/Live DNS unavailable/);
  });

  it('free tier: caps visible findings and locks the deep mythos_intelligence block', async () => {
    flaggedDomainResult();
    const res = await handleMythosScan(req({ target: 'many-findings.test' }), {}, {});
    const body = await res.json();
    expect(body.premium).toBe(false);
    expect(body.result.mythos_intelligence._paywall).toBeTruthy();
    expect(body.result.mythos_intelligence.autonomous_remediation_plan).toBeUndefined();
  });

  it('premium tier gets the full mythos_intelligence block, not the locked summary', async () => {
    cleanDomainResult();
    const res = await handleMythosScan(req({ target: 'clean-example.test' }), {}, { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.premium).toBe(true);
    expect(body.result.mythos_intelligence._paywall).toBeUndefined();
    expect(body.result.mythos_intelligence.autonomous_remediation_plan).toEqual(
      ['Publish a DMARC policy', 'Enable DNSSEC']
    );
  });
});

describe('handleMythosCompliance — real benchmark engine, not fabricated (CAP-MYTHOS-003)', () => {
  it('rejects an unsupported framework', async () => {
    const res = await handleMythosCompliance(
      req({ org_name: 'Acme Corp', framework: 'made_up_framework' }), {}, {}
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.supported).toContain('iso27001');
  });

  it('rejects a missing/too-short org name', async () => {
    const res = await handleMythosCompliance(req({ org_name: 'A', framework: 'iso27001' }), {}, {});
    expect(res.status).toBe(400);
  });

  it('uses the real, honestly-labeled STATIC benchmark engine, never a fake verified "ALIGNED" claim', async () => {
    const res = await handleMythosCompliance(
      req({ org_name: 'Acme Corp', framework: 'iso27001' }), {}, { tier: 'PRO' }
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.result.target).toBe('Acme Corp');
    expect(body.result.scan_metadata.assessment_mode).toBe('STATIC');
    expect(body.result.scan_metadata.live_verification).toBe(false);
    expect(body.result.verification_status).toBeUndefined(); // old fake field is gone
    expect(JSON.stringify(body.result)).not.toContain('"verification_status":"ALIGNED"');
  });

  it('different frameworks produce different real control totals (proves it is not a single hardcoded shape)', async () => {
    const iso = await (await handleMythosCompliance(
      req({ org_name: 'Acme Corp', framework: 'iso27001' }), {}, {}
    )).json();
    const dpdp = await (await handleMythosCompliance(
      req({ org_name: 'Acme Corp', framework: 'dpdp' }), {}, {}
    )).json();
    expect(iso.result.total_controls).not.toBe(dpdp.result.total_controls);
  });
});

describe('MYTHOS multi-rail checkout removed entirely (CAP-MYTHOS-003)', () => {
  it('handleMythosCheckout / handleMythosWebhook no longer exist in the handler file', () => {
    expect(rawHandlerSource).not.toMatch(/export\s+async\s+function\s+handleMythosCheckout/);
    expect(rawHandlerSource).not.toMatch(/export\s+async\s+function\s+handleMythosWebhook/);
    expect(rawHandlerSource).not.toContain('RAZORPAY_WEBHOOK_SECRET');
  });

  it('the checkout/webhook routes are gone from the route table, scan/compliance remain', () => {
    expect(rawIndexSource).not.toContain(`'/api/mythos/checkout/initialize'`);
    expect(rawIndexSource).not.toContain(`'/api/mythos/checkout/webhook'`);
    expect(rawIndexSource).not.toContain('handleMythosCheckout');
    expect(rawIndexSource).not.toContain('handleMythosWebhook');
    expect(rawIndexSource).toContain(`'/api/mythos/scan'`);
    expect(rawIndexSource).toContain(`'/api/mythos/compliance'`);
  });
});
