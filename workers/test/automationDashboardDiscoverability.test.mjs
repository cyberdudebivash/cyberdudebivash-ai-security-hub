// CAP-DEVPORTAL-002 — Self-Service Automation API Keys (automation-dashboard.html,
// P7.0-001..009: self-service API keys, webhooks, scheduled reports, team
// management, usage dashboard, governance, metrics) had a real, working,
// tested backend and frontend but zero discoverable path: the only reference
// to "automation-dashboard" anywhere under frontend/*.html was sitemap.html.
// A paying customer had no way to find this page short of guessing the URL.
//
// FIX: added a real nav-item link to /automation-dashboard.html in
// user-dashboard.html's "Developer" sidebar section, next to the canonical
// API Keys link, matching the already-established pattern used for
// threat-intel-workbench.html (a separate dedicated page, not an in-page tab).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const dash = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

describe('automation-dashboard.html is discoverable from the customer dashboard (CAP-DEVPORTAL-002)', () => {
  it('user-dashboard.html has a real nav-item linking to automation-dashboard.html', () => {
    expect(dash).toContain(`onclick="location.href='/automation-dashboard.html'"`);
  });

  it('the new nav-item sits in a real sidebar section (not orphaned markup outside the sidebar)', () => {
    const idx = dash.indexOf(`onclick="location.href='/automation-dashboard.html'"`);
    expect(idx).toBeGreaterThan(-1);
    const before = dash.slice(Math.max(0, idx - 400), idx);
    expect(before).toContain('sidebar-section');
    expect(before).toContain('Developer');
  });

  it('follows the same page-navigation pattern already established for threat-intel-workbench.html', () => {
    expect(dash).toContain(`onclick="location.href='/threat-intel-workbench.html'"`);
  });

  it('the API Keys tab (CAP-DEVPORTAL-001, in-page tab) is untouched by this fix', () => {
    expect(dash).toContain(`data-page="apikeys" onclick="showPage('apikeys',this)"`);
  });
});
