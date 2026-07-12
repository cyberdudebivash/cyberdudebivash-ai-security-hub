/* Regression test — v24/salesOS.js's generateProposal() (enterprise sales
 * proposal generator, personalized with the prospect's real company/contact
 * name) baked in an uncited "Phishing (+340% YoY)" attack-vector stat and an
 * uncited "growing 12% YoY" tacked onto an otherwise properly-cited IBM 2025
 * breach-cost figure — the same recycled fabricated-statistic pattern found
 * and fixed elsewhere this session (executiveRiskHandlers.js,
 * executiveCommandCenter.js, emailEngine.js).
 *
 * Proves: both uncited percentages are gone; the properly-cited IBM figure
 * remains intact. */
import { describe, it, expect } from 'vitest';
import { generateProposal } from '../src/services/v24/salesOS.js';

describe('generateProposal — threat-landscape/business-risk statistic honesty', () => {
  const deal = { company: 'Acme Corp', contact_name: 'Jane Doe', contact_email: 'jane@acme.test', industry: 'Technology' };

  it('does not cite the fabricated "340% YoY" phishing stat', () => {
    const proposal = generateProposal(deal, 'enterprise');
    expect(proposal.sections.threat_landscape.attack_vectors).not.toContain('Phishing (+340% YoY)');
    expect(proposal.sections.threat_landscape.attack_vectors).toContain('Phishing');
  });

  it('does not cite the uncited "12% YoY" growth figure, but keeps the real IBM-cited base stat', () => {
    const proposal = generateProposal(deal, 'enterprise');
    expect(proposal.sections.business_risk.financial_risk).not.toContain('12% YoY');
    expect(proposal.sections.business_risk.financial_risk).toContain('IBM 2025');
  });
});

describe('generateProposal — ROI is a labeled scenario model, not a fabricated personalized number', () => {
  const deal = { company: 'Acme Corp', contact_name: 'Jane Doe', contact_email: 'jane@acme.test', industry: 'Technology' };

  it('discloses the ROI is illustrative, not measured/personalized for this prospect', () => {
    const proposal = generateProposal(deal, 'enterprise');
    expect(proposal.sections.roi.disclosure).toMatch(/illustrative/i);
    expect(proposal.sections.roi.disclosure).toMatch(/not a measured or personalized/i);
  });

  it('the old flat fabricated fields (risk_reduction_pct: 78, single roi_multiplier/payback_months) are gone from the top level', () => {
    const proposal = generateProposal(deal, 'enterprise');
    expect(proposal.sections.roi.risk_reduction_pct).toBeUndefined();
    expect(proposal.sections.roi.roi_multiplier).toBeUndefined();
    expect(proposal.sections.roi.payback_months).toBeUndefined();
  });

  it('provides conservative/expected/best_case scenarios reusing cisoMetrics.js\'s real, audited risk-reduction formula bounds (20%/52-53%/85%), not independently invented percentages', () => {
    const proposal = generateProposal(deal, 'enterprise');
    const { conservative, expected, best_case } = proposal.sections.roi.scenarios;
    expect(conservative.risk_reduction_pct).toBe(20);
    expect(best_case.risk_reduction_pct).toBe(85);
    expect(expected.risk_reduction_pct).toBeGreaterThan(conservative.risk_reduction_pct);
    expect(expected.risk_reduction_pct).toBeLessThan(best_case.risk_reduction_pct);
    // Each scenario's roi_multiplier/payback reflects the same real priceInr input
    expect(conservative.roi_multiplier).toBeLessThan(best_case.roi_multiplier);
  });

  it('rendered HTML shows the labeled scenarios, not the old hardcoded "36x"/"4,200,000" fallback', () => {
    const proposal = generateProposal(deal, 'enterprise');
    expect(proposal.html).toContain('Illustrative ROI Scenarios');
    expect(proposal.html).toContain('Conservative');
    expect(proposal.html).toContain('Best Case');
    expect(proposal.html).not.toContain('36× return');
  });
});
