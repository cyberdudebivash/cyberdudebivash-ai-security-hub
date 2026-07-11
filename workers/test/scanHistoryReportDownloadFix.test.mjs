/* P1 — found while continuing the "test everything the way customers use it"
 * dashboard audit: traced a real, live scan all the way through to the
 * Scans page and found the "Download" column showed "—" for every single
 * completed scan of every customer, with no way to ever get a real one.
 *
 * ROOT CAUSE: renderAllScans() gated the Download link on `s.report_url`
 * from GET /api/history — but nothing anywhere in the backend ever writes a
 * report_url onto a scan_history row (confirmed: workers/src/lib/queue.js
 * insertD1History() and workers/src/handlers/domain.js trackDomainScan()
 * both persist only summary fields — scan_id, target, module, risk_score,
 * risk_level, grade, data_source, status, scanned_at — never a report
 * reference). So the field this button checked was permanently undefined,
 * for every scan, for every customer, since the day this table shipped.
 *
 * The backend capability to actually build a report already existed and was
 * already fully tested (see reportGeneration.test.mjs): POST
 * /api/report/generate accepts just a scan_id, resolves the identity-scoped
 * cache cacheScanResultForReport() already writes on every scan (domain.js
 * calls it on both the fresh-scan and cache-hit paths), and returns a real
 * download_url. It simply had zero caller anywhere on the Scans page.
 *
 * FIX: the Download cell now renders a button (whenever the row has a
 * scan_id — effectively always) that calls downloadScanReport(), which
 * POSTs /api/report/generate with that scan_id through the same apiFetch()
 * every other authenticated call on this page uses, then opens the real
 * returned download_url. A 422 (scan older than the 7-day cache window) is
 * shown as a friendly toast instead of a silent failure. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const html = readFileSync(resolve(root, '../frontend/user-dashboard.html'), 'utf8');

function fnBody(name, window = 1500) {
  const start = html.indexOf(`function ${name}`);
  if (start === -1) return '';
  return html.slice(start, start + window);
}

describe('Scans page Download button now generates a real report instead of always showing "—" (P1)', () => {
  it('renderAllScans() no longer gates Download on the never-populated report_url field', () => {
    const body = fnBody('renderAllScans');
    expect(body).not.toBe('');
    expect(body).not.toContain('s.report_url');
  });

  it('renderAllScans() renders a Download button keyed on scan_id, wired to downloadScanReport()', () => {
    const body = fnBody('renderAllScans');
    expect(body).toContain('s.scan_id');
    expect(body).toMatch(/onclick="downloadScanReport\('\$\{s\.scan_id\}',\s*this\)"/);
  });

  it('downloadScanReport() POSTs /api/report/generate with the scan_id via the page\'s authenticated apiFetch()', () => {
    const body = fnBody('downloadScanReport', 1200);
    expect(body).not.toBe('');
    const fetchIdx = body.indexOf("apiFetch('/api/report/generate'");
    expect(fetchIdx).toBeGreaterThan(-1);
    const callSite = body.slice(fetchIdx, fetchIdx + 200);
    expect(callSite).toContain("method: 'POST'");
    expect(callSite).toContain('scan_id: scanId');
  });

  it('downloadScanReport() opens the real download_url from the response instead of assuming one is pre-built', () => {
    const body = fnBody('downloadScanReport', 1200);
    expect(body).toContain('d.download_url');
    expect(body).toContain("window.open(d.download_url");
  });

  it('downloadScanReport() surfaces an expired-cache (422) case as a friendly message, not a silent failure', () => {
    const body = fnBody('downloadScanReport', 1200);
    expect(body).toMatch(/res\.status === 422/);
    expect(body).toContain('showToast(');
  });
});
