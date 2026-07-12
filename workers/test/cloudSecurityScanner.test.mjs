// CAP-SCAN-006 — Cloud Security Posture Scanner. Registry's own evidence:
// "grep for handleCloudSecurityScan across workers/test/**/*.mjs returns 0
// matches" — zero test coverage for either the real CIS-aligned scoring
// engine (27 controls across IAM/NETWORK/DATA/LOGGING/COMPUTE) or the
// PRO+/ENTERPRISE/MSSP tier gate. Its own notes explicitly recommended a
// regression test locking the tier gate, mirroring the pattern already used
// elsewhere in this suite (real tier admission, non-qualifying tiers
// rejected, admin bypass admitted).
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runCloudSecurityAudit } from '../src/services/cloudSecurityEngine.js';
import { handleCloudSecurityScan } from '../src/handlers/serviceHandlers.js';

function reqWithBody(body) {
  return { json: async () => body };
}

describe('Cloud Security Audit engine — real CIS-aligned scoring, not fabricated', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, headers: new Headers(), text: async () => '' }));
  });

  it('scores 0 / grade F / HIGH_RISK when every control is unimplemented', async () => {
    const report = await runCloudSecurityAudit({}, {}, null);
    expect(report.executive_summary.security_score).toBe(0);
    expect(report.executive_summary.grade).toBe('F');
    expect(report.executive_summary.verdict).toBe('HIGH_RISK');
    expect(report.executive_summary.controls_passing).toBe(0);
    // Every one of the 27 real controls (6 IAM + 6 NETWORK + 5 DATA + 5 LOGGING + 5 COMPUTE)
    // should produce a real, non-fabricated finding.
    expect(report.executive_summary.total_controls).toBe(27);
  });

  it('scores 100 / grade A / SECURE when every control is genuinely implemented', async () => {
    const allTrue = {
      has_root_mfa: true, has_least_privilege: true, rotates_keys: true, reviews_access: true,
      scoped_service_accounts: true, has_sso: true, least_priv_sg: true, no_open_db_ports: true,
      has_flow_logs: true, private_db_subnets: true, has_waf: true, has_ddos_protection: true,
      encrypt_at_rest: true, encrypt_in_transit: true, no_public_buckets: true, has_cmek: true,
      has_data_classification: true, has_audit_logging: true, adequate_log_retention: true,
      alerts_on_priv_actions: true, has_cloud_siem: true, validates_log_integrity: true,
      has_vm_scanning: true, has_auto_patching: true, scans_container_images: true,
      no_privileged_containers: true, has_imds_protection: true,
    };
    const report = await runCloudSecurityAudit({}, allTrue, null);
    expect(report.executive_summary.security_score).toBe(100);
    expect(report.executive_summary.grade).toBe('A');
    expect(report.executive_summary.verdict).toBe('SECURE');
    expect(report.findings ?? []).toEqual([]);
  });

  it('a real CRITICAL finding (no MFA on root) carries real, specific remediation text — not a placeholder', async () => {
    const report = await runCloudSecurityAudit({}, {}, null);
    const finding = report.findings.find(f => f.control_id === 'IAM-001');
    expect(finding.severity).toBe('CRITICAL');
    expect(finding.remediation).toContain('MFA');
    expect(finding.remediation.length).toBeGreaterThan(20);
  });

  it('detects a real, live-shaped public S3 bucket exposure and surfaces it as a CRITICAL finding', async () => {
    global.fetch.mockImplementation((url) => {
      if (new URL(String(url)).hostname.endsWith('.s3.amazonaws.com')) {
        return Promise.resolve({ status: 200, headers: new Headers() });
      }
      return Promise.resolve({ ok: false, status: 404, headers: new Headers() });
    });
    const report = await runCloudSecurityAudit({}, { domain: 'example.com' }, null);
    const bucketFinding = report.findings.find(f => f.id?.startsWith('CLOUD-PUBLIC-BUCKET-'));
    expect(bucketFinding).toBeTruthy();
    expect(bucketFinding.severity).toBe('CRITICAL');
  });

  it('detects real cloud provider from a live-shaped DNS CNAME lookup', async () => {
    global.fetch.mockImplementation((url) => {
      if (new URL(String(url)).hostname === 'cloudflare-dns.com') {
        return Promise.resolve({ ok: true, json: async () => ({ Answer: [{ type: 5, data: 'd123.cloudfront.amazonaws.com' }] }) });
      }
      return Promise.resolve({ ok: false, status: 404, headers: new Headers() });
    });
    const report = await runCloudSecurityAudit({}, { domain: 'example.com' }, null);
    expect(report.meta.cloud_provider).toBe('AWS');
  });

  it('runs fine with no domain at all — the exposure check is skipped, not faked', async () => {
    const report = await runCloudSecurityAudit({}, {}, null);
    expect(report.meta.domain).toBe('N/A');
    expect(report.findings.some(f => f.id?.startsWith('CLOUD-PUBLIC-BUCKET-'))).toBe(false);
  });
});

describe('handleCloudSecurityScan — tier gate (previously zero test coverage)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, headers: new Headers(), text: async () => '' }));
  });

  it('rejects FREE tier with 403 and an upgrade URL', async () => {
    const res = await handleCloudSecurityScan(reqWithBody({}), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.upgrade_url).toBeTruthy();
  });

  it('rejects STARTER tier with 403 — this is PRO-and-above, not STARTER-and-above', async () => {
    const res = await handleCloudSecurityScan(reqWithBody({}), {}, { tier: 'STARTER' });
    expect(res.status).toBe(403);
  });

  it('allows PRO tier through with a real report', async () => {
    const res = await handleCloudSecurityScan(reqWithBody({}), {}, { tier: 'PRO' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.service).toBe('CDB-CSAU-001');
  });

  it('allows ENTERPRISE and MSSP tiers through', async () => {
    for (const tier of ['ENTERPRISE', 'MSSP']) {
      const res = await handleCloudSecurityScan(reqWithBody({}), {}, { tier });
      expect(res.status, `tier ${tier}`).toBe(200);
    }
  });

  it('the isAdmin bypass admits a caller regardless of tier', async () => {
    const res = await handleCloudSecurityScan(reqWithBody({}), {}, { isAdmin: true, tier: 'FREE' });
    expect(res.status).toBe(200);
  });

  it('rejects an anonymous caller (no authCtx tier at all)', async () => {
    const res = await handleCloudSecurityScan(reqWithBody({}), {}, {});
    expect(res.status).toBe(403);
  });
});
