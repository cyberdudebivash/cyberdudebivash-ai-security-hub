// CAP-TIH-016 — Attack Graph from Scan Results (workers/src/lib/attackGraph.js).
// Previously flagged as "whether this is actually wired into the live
// post-scan results UI was not conclusively confirmed" — traced end-to-end
// this pass: frontend/index.html's real scan-result handler (module=domain
// etc.) calls window.CDB_ATTACKGRAPH.onScanComplete(module, data) with the
// REAL API response as `data` (frontend/index.html:9751, fixed same-commit
// as the fetch wiring itself, a427121, 2026-07-11 — the prior verification
// pass's grep simply missed it), which POSTs { scan_result: data, module }
// to POST /api/attack-graph (workers/src/index.js:2326-2341), which calls
// buildAttackGraph(scan_result, module) directly and returns
// { success, graph }. buildAttackGraph() reads scanResult.findings and
// .risk_score — confirmed to exist at the top level of every real domain
// scan response (workers/src/handlers/domain.js buildRealResult():
// risk_score, findings[].{id,title,severity,description,recommendation}).
// Zero test coverage existed for this module at all; added here.
import { describe, it, expect } from 'vitest';
import { buildAttackGraph, simulateExploitPaths, getThreatActorProfiles } from '../src/lib/attackGraph.js';

function realDomainScanResult(overrides = {}) {
  return {
    scan_id: 'scan_abc123', module: 'domain_scanner', target: 'example.com',
    risk_score: 72, risk_level: 'HIGH',
    findings: [
      { id: 'DOM-001', title: 'Missing DNSSEC', severity: 'HIGH', description: 'DNSSEC not enabled.', recommendation: 'Enable DNSSEC.' },
      { id: 'DOM-002', title: 'Weak TLS cipher suite', severity: 'CRITICAL', description: 'Server supports deprecated ciphers.', recommendation: 'Disable TLS 1.0/1.1.' },
      { id: 'DOM-003', title: 'Missing SPF record', severity: 'MEDIUM', description: 'No SPF record found.', recommendation: 'Add an SPF record.' },
    ],
    ...overrides,
  };
}

describe('CAP-TIH-016 — buildAttackGraph() builds a real D3 graph from a real scan shape', () => {
  it('produces nodes and links from real scan findings, matching the response shape POST /api/attack-graph returns', () => {
    const graph = buildAttackGraph(realDomainScanResult(), 'domain');
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.links.length).toBeGreaterThan(0);
    expect(graph.nodes.some(n => n.id === 'attacker')).toBe(true);
    expect(graph.metadata.module).toBe('domain');
    expect(graph.metadata.risk_score).toBe(72);
    expect(graph.metadata.node_count).toBe(graph.nodes.length);
    expect(graph.d3_config).toBeTruthy();
  });

  it('renders finding nodes labeled from the real finding titles, sorted by severity', () => {
    const graph = buildAttackGraph(realDomainScanResult(), 'domain');
    const findingNodes = graph.nodes.filter(n => n.type === 'finding');
    expect(findingNodes.length).toBe(3);
    // CRITICAL (Weak TLS cipher suite) should be scored/sorted first.
    expect(findingNodes[0].label).toContain('Weak TLS cipher suite');
    expect(findingNodes[0].severity).toBe('CRITICAL');
  });

  it('adds a pivot/chain node when there are 3+ findings and risk_score >= 50 (multi-step attack path)', () => {
    const graph = buildAttackGraph(realDomainScanResult({ risk_score: 72 }), 'domain');
    expect(graph.nodes.some(n => n.id === 'pivot_core')).toBe(true);
  });

  it('skips the pivot node for a low-risk scan with few findings (direct-only attack path)', () => {
    const graph = buildAttackGraph(realDomainScanResult({
      risk_score: 10,
      findings: [{ id: 'DOM-001', title: 'Info only', severity: 'INFO', description: '', recommendation: '' }],
    }), 'domain');
    expect(graph.nodes.some(n => n.id === 'pivot_core')).toBe(false);
  });

  it('handles an unmeasurable scan (empty findings, null risk_score) without throwing', () => {
    const graph = buildAttackGraph({ findings: [], risk_score: null }, 'domain');
    expect(graph.nodes.length).toBeGreaterThan(0); // attacker + entry/impact nodes still render
    expect(graph.links.length).toBeGreaterThanOrEqual(0);
  });

  it('falls back to the domain template for an unrecognized module', () => {
    const graph = buildAttackGraph(realDomainScanResult(), 'nonexistent_module');
    expect(graph.nodes.some(n => n.id === 'internet')).toBe(true); // domain template's entry node
  });

  it('includes locked_findings alongside findings (PRO-tier teaser content still graphs)', () => {
    const graph = buildAttackGraph(realDomainScanResult({
      findings: [],
      locked_findings: [{ id: 'DOM-LOCK-1', title: 'Locked finding', severity: 'HIGH', description: '', recommendation: '' }],
    }), 'domain');
    expect(graph.nodes.some(n => n.label?.includes('Locked finding'))).toBe(true);
  });
});

describe('CAP-TIH-016 — simulateExploitPaths()', () => {
  it('returns a real multi-step exploit chain when critical/high findings exist', () => {
    const paths = simulateExploitPaths(realDomainScanResult().findings, 'domain', 'example.com');
    expect(paths.length).toBeGreaterThanOrEqual(1);
    expect(paths[0].steps.length).toBeGreaterThan(0);
    expect(paths[0].steps[0].action).toContain('example.com');
  });

  it('returns a low-likelihood reconnaissance-only path when no critical/high findings exist', () => {
    const paths = simulateExploitPaths([{ severity: 'LOW' }], 'domain', 'example.com');
    expect(paths.length).toBe(1);
    expect(paths[0].likelihood).toBeLessThan(30);
    expect(paths[0].severity).toBe('LOW');
  });

  it('adds a second chained path when 2+ critical/high findings exist', () => {
    const paths = simulateExploitPaths(realDomainScanResult().findings, 'domain', 'example.com');
    expect(paths.length).toBe(2);
    expect(paths[1].attack_vector).toBe('Multi-step chain');
  });
});

describe('CAP-TIH-016 — getThreatActorProfiles()', () => {
  it('returns real per-module actor profiles, falling back to domain for unknown modules', () => {
    expect(getThreatActorProfiles('redteam').length).toBeGreaterThan(0);
    expect(getThreatActorProfiles('redteam')[0].name).toBeTruthy();
    expect(getThreatActorProfiles('nonexistent')).toEqual(getThreatActorProfiles('domain'));
  });
});
