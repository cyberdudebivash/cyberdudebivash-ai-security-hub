/**
 * CYBERDUDEBIVASH AI Security Hub — Report Handler v1.0
 * GET  /api/report/:token    — download report by token
 * GET  /api/report/id/:id    — download report by report ID
 * POST /api/report/generate  — generate report from last scan result
 */

import { buildReport, storeReport, getReportByToken, getReportById } from '../lib/reportEngine.js';
import { parseBody } from '../middleware/validation.js';

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

  // If scan_id provided, try to pull from cache
  if (!scanResult && body.scan_id && env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get(`scan:${body.scan_id}`);
      if (raw) scanResult = JSON.parse(raw);
    } catch {}
  }

  if (!scanResult || typeof scanResult !== 'object') {
    return Response.json({ error: 'Could not resolve scan result', hint: 'Provide the full scan_result JSON from a previous scan' }, { status: 422 });
  }

  const meta = {
    email:  authCtx.owner_email || body.email || null,
    tier:   authCtx.tier || 'FREE',
  };

  const report     = buildReport(scanResult, meta);
  const storeInfo  = await storeReport(env, report);

  return Response.json({
    success:        true,
    report_id:      report.report_id,
    generated_at:   report.generated_at,
    expires_at:     report.expires_at,
    target:         report.target,
    download_token: storeInfo?.download_token ?? null,
    download_url:   storeInfo ? `https://cyberdudebivash-security-hub.workers.dev/api/report/${storeInfo.download_token}` : null,
    report:         report,  // inline for convenience
  }, {
    status: 201,
    headers: { 'X-Report-ID': report.report_id },
  });
}
