/* Regression test — upsellEngine.js's generateLinkedInAuthorityPost() builds
 * real, public LinkedIn posts published under the company's own brand. The
 * cve_alert template claimed "We detected this... 3 hours before it hit
 * mainstream security news" (unverifiable, identical on every post) and
 * "Estimated 50,000+ internet-exposed instances" / "State-sponsored actors
 * already scanning" (fabricated, identical regardless of the real vendor).
 * The weekly_insight template hardcoded a static "Top threat actors active
 * this week" list (Volt Typhoon/APT41/LockBit, including a fake "3 new
 * campaigns" count) and invented statistics ("73% of breaches...", "40%
 * increase in RCE exploit attempts") that never varied and were not derived
 * from any real weekly data, despite the post's own "WEEKLY THREAT
 * INTELLIGENCE REPORT" framing implying they were.
 *
 * Proves: both templates keep their real, input-derived fields (EPSS score,
 * KEV status, attack vector, real critical/KEV counts) but no longer
 * publish the fabricated claims. */
import { describe, it, expect } from 'vitest';
import { generateLinkedInAuthorityPost } from '../src/services/upsellEngine.js';

describe('generateLinkedInAuthorityPost — public post content honesty', () => {
  it('cve_alert keeps real EPSS/KEV/attack-vector fields but drops the fabricated speed/scale/attribution claims', () => {
    const post = generateLinkedInAuthorityPost({
      entry: { id: 'CVE-2026-0001', cvss: 9.8, vendor: 'Acme Corp', epss_score: 0.82, exploit_status: 'confirmed', attack_vector: 'Network' },
      insight_type: 'cve_alert',
    });
    expect(post.content).toContain('CVE-2026-0001');
    expect(post.content).toContain('82%');
    expect(post.content).toContain('Actively exploited in the wild');
    expect(post.content).not.toContain('3 hours before it hit mainstream security news');
    expect(post.content).not.toContain('50,000+ internet-exposed instances');
    expect(post.content).not.toContain('State-sponsored actors already scanning');
  });

  it('weekly_insight keeps the real critical/KEV counts but drops the static fabricated "this week" actor list and invented statistics', () => {
    const post = generateLinkedInAuthorityPost({
      stats: { critical_cves: 12, kev_entries: 4 },
      insight_type: 'weekly_insight',
    });
    expect(post.content).toContain('12 CRITICAL CVEs published this week');
    expect(post.content).toContain('4 confirmed actively exploited');
    expect(post.content).not.toContain('Volt Typhoon');
    expect(post.content).not.toContain('3 new campaigns');
    expect(post.content).not.toContain('73% of breaches');
    expect(post.content).not.toContain('40% increase in RCE exploit attempts');
  });
});
