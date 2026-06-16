// Metric-integrity guard for the frontend dashboard adapter + SSE stream.
// Locks in Cluster 2: every headline counter is sourced from the single source
// of truth (/api/platform/metrics) and the fabricated "+3,841 CVE floor" can
// never be re-introduced. Pure static parse — no browser/network.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DASH   = readFileSync(resolve(__dirname, '../../frontend/dashboard-live.js'), 'utf8');
const STREAM = readFileSync(resolve(__dirname, '../src/handlers/dashboardStream.js'), 'utf8');
const HTML   = readFileSync(resolve(__dirname, '../../frontend/index.html'), 'utf8');

describe('dashboard-live.js — no fabricated CVE metrics', () => {
  it('removed the hardcoded +3,841 CVE floor', () => {
    expect(DASH).not.toContain('_CVE_FLOOR');
    expect(DASH).not.toContain('3841');
    expect(DASH).not.toMatch(/\+\s*_cveFloor/);
  });

  it('drives headline counters from the single source of truth', () => {
    expect(DASH).toContain("'/api/platform/metrics'");
    expect(DASH).toContain('total_cves_tracked');
    expect(DASH).toContain('critical_threats');
    expect(DASH).toContain('kev_count');
  });

  it('no longer mis-reads vulns/stats as the CVE total', () => {
    // The CVE tiles must not be fed from the internal vuln tracker (/api/vulns/stats).
    expect(DASH).not.toMatch(/vulns\.total[^_]/);
  });

  it('derives threat level from real critical/KEV counts (not a missing field)', () => {
    expect(DASH).toContain('threatFrom(');
    expect(DASH).not.toMatch(/threat_score \?\? .* \?\? 0/);
  });
});

describe('dashboardStream.js (SSE) — consistent with the polled dashboard', () => {
  it('emits cve_stats + threat_level from /api/platform/metrics', () => {
    expect(STREAM).toContain('/api/platform/metrics');
    expect(STREAM).toContain('total_cves_tracked');
    expect(STREAM).toContain('threatFrom(');
  });

  it('no longer hardcodes a default threat score of 62', () => {
    expect(STREAM).not.toContain('?? 62');
  });
});

describe('index.html — credibility baseline fabrication removed', () => {
  it('_applyFloor is a no-op (no `raw + baseline` inflation)', () => {
    expect(HTML).not.toMatch(/return\s+raw\s*\+\s*baseline/);
    expect(HTML).toMatch(/const _CVE_BASELINE\s*=\s*0/);
    expect(HTML).toMatch(/const _SCAN_BASELINE\s*=\s*0/);
  });

  it('no fabricated static defaults remain in the live trust/hero tiles', () => {
    expect(HTML).not.toMatch(/id="stat-cves"[^>]*>3,841\+/);
    expect(HTML).not.toMatch(/id="tm-cves"[^>]*>3,841\+/);
    expect(HTML).not.toMatch(/id="cdb-exec-cves"[^>]*>3,841\+/);
    expect(HTML).not.toMatch(/id="cdb-sentinel-total"[^>]*>3,841\+/);
    expect(HTML).not.toMatch(/id="stat-scans"[^>]*>1,247\+/);
    expect(HTML).not.toMatch(/id="tm-scans"[^>]*>1,247\+/);
  });

  it('removed the agent "Demo data" fallback counters', () => {
    expect(HTML).not.toContain('// Demo data if stats endpoint not live');
    expect(HTML).not.toMatch(/getElementById\('ag-a-scanned'\)\.textContent='1,247'/);
  });
});
