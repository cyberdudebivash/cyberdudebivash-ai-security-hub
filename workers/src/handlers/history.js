/**
 * CYBERDUDEBIVASH AI Security Hub — Scan History Handler v1.0
 * GET /api/history         — list past scans for this identity
 * DEL /api/history         — clear all history for this identity
 */

import { getScanHistory } from '../lib/reportEngine.js';

export async function handleScanHistory(request, env, authCtx = {}) {
  if (request.method === 'DELETE') {
    if (env?.SECURITY_HUB_KV && authCtx.identity) {
      try {
        await env.SECURITY_HUB_KV.delete(`history:${authCtx.identity}`);
      } catch {}
    }
    return Response.json({ success: true, message: 'Scan history cleared' }, { status: 200 });
  }

  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);
  const module = url.searchParams.get('module') || null;

  let history = await getScanHistory(env, authCtx, limit);
  if (module) history = history.filter(s => s.module === module);

  return Response.json({
    identity:   authCtx.identity,
    tier:       authCtx.tier || 'FREE',
    count:      history.length,
    limit,
    scans:      history,
    note:       authCtx.tier === 'FREE'
      ? 'Upgrade to PRO for 90-day history and CSV export'
      : 'Full history available. Use ?module=domain_scanner to filter.',
  }, { status: 200 });
}
