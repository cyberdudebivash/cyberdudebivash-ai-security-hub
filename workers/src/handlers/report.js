/**
 * CYBERDUDEBIVASH AI Security Hub — Report Handler v1.0
 * GET  /api/report/:token    — download report by token
 * GET  /api/report/id/:id    — download report by report ID
 * POST /api/report/generate  — generate report from last scan result
 */

import { buildReport, storeReport, getReportByToken, getReportById } from '../lib/reportEngine.js';
import { parseBody } from '../middleware/validation.js';
import { getCachedScanResult } from '../lib/scanResultCache.js';
import { generateHTMLReport } from '../lib/htmlReport.js';
import { isRealUser } from '../auth/middleware.js';

// ─── GET /api/report/:token ───────────────────────────────────────────────────
export async function handleReportDownload(request, env, authCtx = {}) {
  const url     = new URL(request.url);
  const pathParts = url.pathname.split('/').filter(Boolean);
  // pathParts: ['api','report','TOKEN'] or ['api','report','id','REPORT_ID']

  const byId    = pathParts[2] === 'id';
  const lookup  = pathParts[byId ? 3 : 2];

  if (!lookup || lookup.length < 8) {
    return Response.json({ error: 'Invalid report token or ID', hint: 'Use the download_token from your scan response' }, { status: 400 });
  }

  const report = byId
    ? await getReportById(env, lookup)
    : await getReportByToken(env, lookup);

  if (!report) {
    return Response.json({
      error: 'Report not found',
      hint: 'Reports expire after 7 days. Re-run the scan to generate a new report.',
      docs: 'https://cyberdudebivash.in/docs',
    }, { status: 404 });
  }

  // Check expiry
  if (report.expires_at && new Date(report.expires_at) < new Date()) {
    return Response.json({ error: 'Report expired', expires_at: report.expires_at }, { status: 410 });
  }

  // Private reports (visibility:'private' at generation) are owner-bound: the
  // capability token alone is NOT sufficient — the caller must authenticate as
  // the user who generated the report. Default (shareable-link) reports are
  // unchanged.
  if (report.access?.private) {
    if (!isRealUser(authCtx)) {
      return Response.json({
        error: 'Authentication required',
        hint:  'This report was generated with visibility:"private" — sign in as its owner to download it.',
      }, { status: 401 });
    }
    const callerId = authCtx.user_id ?? authCtx.userId;
    if (authCtx.isAdmin !== true && String(callerId) !== String(report.access.owner_id)) {
      return Response.json({ error: 'Forbidden', hint: 'This private report belongs to another account.' }, { status: 403 });
    }
  }

  // Serve the styled, print-to-PDF HTML report when available — this is what
  // "Download PDF" in the UI actually promises. Falls back to raw JSON for
  // older cached reports generated before HTML rendering was wired in.
  if (report._html) {
    return new Response(report._html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Report-ID':  report.report_id,
        'X-Generated':  report.generated_at,
        'X-Expires':    report.expires_at,
        'Content-Disposition': `inline; filename="cyberdudebivash-report-${report.target}-${report.report_id.slice(0,8)}.html"`,
      },
    });
  }

  return Response.json(report, {
    status: 200,
    headers: {
      'X-Report-ID':  report.report_id,
      'X-Generated':  report.generated_at,
      'X-Expires':    report.expires_at,
      'Content-Disposition': `attachment; filename="cyberdudebivash-report-${report.target}-${report.report_id.slice(0,8)}.json"`,
    },
  });
}

// ─── POST /api/report/generate ────────────────────────────────────────────────
export async function handleReportGenerate(request, env, authCtx = {}) {
  const body = await parseBody(request);

  // Accept scan_id or raw scan_result JSON
  if (!body?.scan_result && !body?.scan_id) {
    return Response.json({
      error: 'Missing required field',
      hint: 'Provide scan_result (full scan JSON) or scan_id to generate a report',
      example: { scan_result: '{ ...scan response JSON... }' },
    }, { status: 400 });
  }

  let scanResult = body.scan_result;

  // If scan_id provided, pull the exact response the customer already saw
  // (scoped to their identity to prevent cross-tenant reads)
  if (!scanResult && body.scan_id) {
    scanResult = await getCachedScanResult(env, authCtx, body.scan_id);
  }

  if (!scanResult || typeof scanResult !== 'object') {
    return Response.json({
      error: 'Could not resolve scan result',
      hint: 'Provide the full scan_result JSON, or a scan_id from a scan run within the last 7 days',
    }, { status: 422 });
  }

  // Optional enterprise mode: visibility:'private' binds the report to the
  // generating account — the download link then requires authentication as
  // that owner instead of being an anyone-with-the-link capability URL.
  const wantsPrivate = body?.visibility === 'private';
  if (wantsPrivate && !isRealUser(authCtx)) {
    return Response.json({
      error: 'Authentication required for private reports',
      hint:  'visibility:"private" binds the report to your account — call this endpoint with a valid session token or API key.',
    }, { status: 401 });
  }

  const meta = {
    email:  authCtx.owner_email || body.email || null,
    tier:   authCtx.tier || 'FREE',
  };

  const report     = buildReport(scanResult, meta);
  if (wantsPrivate) {
    report.access = { private: true, owner_id: authCtx.user_id ?? authCtx.userId };
  }
  let htmlContent  = null;
  try {
    htmlContent = generateHTMLReport(scanResult, { report_id: report.report_id });
  } catch { /* JSON report still ships even if HTML rendering fails */ }
  const storeInfo  = await storeReport(env, report, htmlContent);

  // Build the download URL on the SAME origin the customer called (e.g.
  // https://cyberdudebivash.in) instead of hardcoding the raw workers.dev
  // subdomain — the hardcoded host is off-brand and, behind the custom-domain
  // proxy, may not be directly reachable when a customer copies the link.
  const origin = (() => {
    try { return new URL(request.url).origin; }
    catch { return 'https://cyberdudebivash.in'; }
  })();

  return Response.json({
    success:        true,
    report_id:      report.report_id,
    generated_at:   report.generated_at,
    expires_at:     report.expires_at,
    target:         report.target,
    visibility:     wantsPrivate ? 'private' : 'shareable',
    download_token: storeInfo?.download_token ?? null,
    download_url:   storeInfo ? `${origin}/api/report/${storeInfo.download_token}` : null,
    report:         report,  // inline for convenience
  }, {
    status: 201,
    headers: { 'X-Report-ID': report.report_id },
  });
}
