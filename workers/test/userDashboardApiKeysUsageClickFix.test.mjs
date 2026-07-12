/* P3 (Tier-3, cosmetic/minor class) — the API Keys page's "Usage" card
 * permanently read "Select a key to view usage" with no way to actually
 * select one: renderKeys() gave every key row a single "Revoke" button and
 * nothing else — no onclick anywhere on the row, no button, no link — even
 * though the backend it would need (GET /api/keys/:id/usage, handleKeyUsage)
 * already existed, worked, and was already covered by
 * workers/test/keyUsageBola.test.mjs. This is a frontend-only fix: a new
 * "Usage" button per row calling a new viewKeyUsage(id, label) that renders
 * the existing endpoint's response into #key-usage-table.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../frontend/user-dashboard.html', import.meta.url), 'utf8');

function fnBody(name) {
  const marker = `function ${name}(`;
  const start = html.indexOf(marker);
  expect(start, `${name} should be defined`).toBeGreaterThan(-1);
  const bodyStart = html.indexOf('{', start);
  let depth = 0, i = bodyStart;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}') { depth--; if (depth === 0) break; }
  }
  return html.slice(start, i + 1);
}

describe('user-dashboard.html API Keys "Usage" card — previously dead, no way to select a key (static parse)', () => {
  it('defines viewKeyUsage()', () => {
    const body = fnBody('viewKeyUsage');
    expect(body).toContain("apiFetch('/api/keys/' + id + '/usage')");
  });

  it('viewKeyUsage() renders into the real #key-usage-table element', () => {
    const body = fnBody('viewKeyUsage');
    expect(body).toContain("getElementById('key-usage-table')");
    expect(html).toMatch(/id="key-usage-table"/);
  });

  it('every rendered key row now has a working "Usage" button wired to viewKeyUsage() — the actual bug', () => {
    const body = fnBody('renderKeys');
    expect(body).toMatch(/onclick="viewKeyUsage\(/);
  });

  it('the Usage button sits alongside the pre-existing Revoke button, not in place of it', () => {
    const body = fnBody('renderKeys');
    expect(body).toContain('openRevokeKey');
    expect(body).toMatch(/onclick="viewKeyUsage\([\s\S]*?onclick="openRevokeKey\(/);
  });

  it('viewKeyUsage() renders both the today per-module breakdown and the month total the backend actually returns (today.by_module, month.total)', () => {
    const body = fnBody('viewKeyUsage');
    expect(body).toContain('d.today?.by_module');
    expect(body).toContain('d.month?.total');
  });

  it('viewKeyUsage() handles a failed fetch without leaving the table stuck on a loading spinner', () => {
    const body = fnBody('viewKeyUsage');
    expect(body).toContain('res.ok');
    expect(body).toMatch(/catch\s*\(e\)\s*\{[\s\S]*?tbody\.innerHTML/);
  });
});
