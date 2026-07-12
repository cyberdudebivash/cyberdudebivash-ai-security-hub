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
