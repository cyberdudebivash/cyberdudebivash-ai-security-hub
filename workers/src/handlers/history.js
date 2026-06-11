/**
 * CYBERDUDEBIVASH AI Security Hub — Scan History Handler v41.0
 * GET /api/history         — list past scans for this identity
 * DEL /api/history         — clear all history for this identity
 *
 * v41.0 changes:
 *  - D1 scan_history is PRIMARY source (reads from actual persisted rows)
 *  - Falls back to KV getScanHistory when D1 is empty (backward-compat)
 *  - Merges and deduplicates both sources by scan_id
 *  - DELETE clears both D1 rows AND KV key for full cleanup
 *  - Returns rich metadata per scan entry
 */

import { getScanHistory } from '../lib/reportEngine.js';

export async function handleScanHistory(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get('limit') || '20', 10), 50);
  const module = url.searchParams.get('module') || null;

  // ─── DELETE: clear both D1 rows and KV ───────────────────────────────────
  if (request.method === 'DELETE') {
    const clearPromises = [];
    if (env?.SECURITY_HUB_KV && authCtx.identity) {
      clearPromises.push(
        env.SECURITY_HUB_KV.delete(`history:${authCtx.identity}`).catch(() => {})
      );
    }
    if (env?.DB && authCtx?.user_id) {
      clearPromises.push(
        env.DB.prepare(`DELETE FROM scan_history WHERE user_id = ?`)
          .bind(authCtx.user_id).run().catch(() => {})
      );
    }
    await Promise.allSettled(clearPromises);
    return Response.json({ success: true, message: 'Scan history cleared' }, { status: 200 });
  }

  // ─── GET: D1 first, KV fallback, merge ───────────────────────────────────
  let d1Scans  = [];
  let kvScans  = [];
  const seenIds = new Set();

  // 1. Read from D1 scan_history (primary source — written by all scan handlers v41.0+)
  if (env?.DB && authCtx?.user_id) {
    try {
      const rows = await env.DB.prepare(
        `SELECT scan_id, target, module, risk_score, risk_level, grade, data_source, status, scanned_at
         FROM scan_history
         WHERE user_id = ?
         ORDER BY scanned_at DESC
         LIMIT ?`
      ).bind(authCtx.user_id, limit).all();

      if (rows?.results?.length > 0) {
        d1Scans = rows.results.map(r => ({
          scan_id:     r.scan_id,
          target:      r.target,
          module:      r.module,
          risk_score:  r.risk_score,
          risk_level:  r.risk_level,
          grade:       r.grade || 'N/A',
          data_source: r.data_source,
          status:      r.status,
          scanned_at:  r.scanned_at,
          source:      'd1',
        }));
      }
    } catch { /* fall through to KV */ }
  }

  // Mark all D1 scan_ids as seen
  d1Scans.forEach(s => { if (s.scan_id) seenIds.add(s.scan_id); });

  // 2. Read from KV (backward-compat for scans before v41.0)
  try {
    const raw = await getScanHistory(env, authCtx, limit);
    kvScans = raw
      .filter(s => !seenIds.has(s.scan_id))
      .map(s => ({ ...s, source: 'kv' }));
  } catch { /* non-critical */ }

  // 3. Merge: D1 rows take precedence; KV fills gaps
  let history = [...d1Scans, ...kvScans];

  // 4. Module filter
  if (module) history = history.filter(s => s.module === module);

  // 5. Sort by scanned_at desc, cap to limit
  history.sort((a, b) => {
    const ta = a.scanned_at ? new Date(a.scanned_at).getTime() : 0;
    const tb = b.scanned_at ? new Date(b.scanned_at).getTime() : 0;
    return tb - ta;
  });
  history = history.slice(0, limit);

  return Response.json({
    identity:  authCtx.identity,
    user_id:   authCtx.user_id   || null,
    tier:      authCtx.tier      || 'FREE',
    count:     history.length,
    limit,
    scans:     history,
    note: authCtx.tier === 'FREE'
      ? 'Upgrade to PRO for 90-day history, CSV export, and trend analysis'
      : 'Full history available. Filter by module with ?module=domain_scanner',
  }, { status: 200 });
}
