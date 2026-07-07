/* Regression test — every mythosAIProvider.js export must pass an explicit
 * deadline_ms to routeAICall(). Before this fix, only mythosEnrichmentEngine.js
 * set a tight (6000ms) budget; these 8 functions relied on routeAICall's
 * 12000ms default, which exceeds the frontend's 8s hard timeout
 * (API_TIMEOUT_MS, frontend/index.html) — the same failure class as the
 * production incident aiProviderRouterDeadline.test.mjs covers for the router
 * itself. This test locks the call sites, not the router mechanism. */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock before importing the module under test so the static import resolves
// the mock (same pattern as multiAgentSOC.test.mjs).
vi.mock('../src/core/aiProviderRouter.js', () => ({
  routeAICall: vi.fn().mockResolvedValue({ content: 'stub', provider: 'stub', model: 'stub' }),
}));

import { routeAICall } from '../src/core/aiProviderRouter.js';
import {
  generateExecutiveNarrative,
  generateThreatAttribution,
  generateRemediationNarrative,
  analyzeCodeSecurity,
  investigateForensics,
  researchCVE,
  simulateRedTeam,
  generateComplianceNarrative,
} from '../src/core/mythosAIProvider.js';

describe('mythosAIProvider.js — every export bounds routeAICall to <= 8000ms', () => {
  beforeEach(() => {
    routeAICall.mockClear();
  });

  const cases = [
    ['generateExecutiveNarrative', () => generateExecutiveNarrative({}, { target: 't', service_name: 's', riskScore: 50, riskLevel: 'MEDIUM' })],
    ['generateThreatAttribution', () => generateThreatAttribution({}, { findings: [{ title: 'x', description: 'y', severity: 'HIGH' }] })],
    ['generateRemediationNarrative', () => generateRemediationNarrative({}, { findings: [{ title: 'x', severity: 'HIGH' }], riskScore: 50 })],
    ['analyzeCodeSecurity', () => analyzeCodeSecurity({}, { code: 'const x = 1;'.repeat(3) })],
    ['investigateForensics', () => investigateForensics({}, { incident_type: 'phishing' })],
    ['researchCVE', () => researchCVE({}, { cve_id: 'CVE-2026-0001' })],
    ['simulateRedTeam', () => simulateRedTeam({}, { target_profile: { name: 'acme' } })],
    ['generateComplianceNarrative', () => generateComplianceNarrative({}, { findings: [] })],
  ];

  for (const [name, invoke] of cases) {
    it(`${name} passes deadline_ms <= 8000`, async () => {
      await invoke();
      expect(routeAICall).toHaveBeenCalledTimes(1);
      const opts = routeAICall.mock.calls[0][1];
      expect(opts.deadline_ms).toBeDefined();
      expect(opts.deadline_ms).toBeLessThanOrEqual(8000);
    });
  }
});
