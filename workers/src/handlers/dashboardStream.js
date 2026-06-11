/**
 * CYBERDUDEBIVASH® AI Security Hub
 * /api/dashboard/stream — Enterprise SSE Aggregator
 *
 * Streams real-time platform metrics to all 5 Command Centers.
 * Public endpoint — no auth required for baseline metrics.
 * Keep-alive sent every 25s to stay under CF 100s idle timeout.
 *
 * Event types:
 *   scan_count      — {total, today, critical, delta}
 *   cve_stats       — {total, critical, kev_count, cve_count}
 *   threat_level    — {level, score, source}
 *   platform_health — {status, latency_ms, timestamp}
 *   keepalive       — {} (comment, no data field)
 */

const POLL_INTERVAL_MS   = 30_000;   // 30s fast metrics
const HEALTH_INTERVAL_MS = 60_000;   // 60s health check
const KEEPALIVE_MS       = 25_000;   // 25s keep-alive (< CF 100s timeout)

export async function handleDashboardStream(request, env, authCtx) {
  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();

  const send = (eventType, data) => {
    try {
      const payload = (eventType === 'keepalive')
        ? ': keepalive\n\n'
        : `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
      return writer.write(encoder.encode(payload));
    } catch (_) {
      return Promise.resolve();
    }
  };

  // Internal fetch helper — uses Workers self-fetch via env base URL or relative
  const workerFetch = async (path) => {
    const base = env.WEBSITE || 'https://cyberdudebivash.in';
    const workerBase = base.replace('https://', 'https://').replace(/\/$/, '');
    // For internal calls, use the request URL's origin to avoid DNS round-trip
    const origin = new URL(request.url).origin;
    const url = `${origin}${path}`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: { 'Accept': 'application/json', 'X-Internal-SSE': '1' },
    });
    if (!resp.ok) throw new Error(`${resp.status}`);
    return resp.json();
  };

  let lastScanTotal = 0;
  let closed = false;

  // Close guard — CF Workers abort signal
  request.signal?.addEventListener('abort', () => {
    closed = true;
    writer.close().catch(() => {});
  });

  // ── Initial burst ─────────────────────────────────────────────────────────
  const sendInitial = async () => {
    // Scan stats
    try {
      const s = await workerFetch('/api/scan/stats');
      if (s?.success !== false) {
        const total = s.total_scans ?? s.stats?.total_scans ?? 0;
        const delta = total - lastScanTotal;
        lastScanTotal = total;
        await send('scan_count', {
          total,
          today:    s.today ?? s.stats?.scans_today ?? 0,
          critical: s.critical ?? 0,
          delta:    Math.max(0, delta),
        });
      }
    } catch (_) {}

    // CVE stats — try /api/vulns/stats first, fallback to /api/threat-intel/stats
    try {
      const v = await workerFetch('/api/vulns/stats');
      await send('cve_stats', {
        total:      v.total ?? v.total_cves ?? 0,
        critical:   v.critical ?? v.critical_cves ?? 0,
        kev_count:  v.kev_count ?? 0,
        cve_count:  v.cve_count ?? v.total ?? 0,
      });
    } catch (_) {
      try {
        const t = await workerFetch('/api/threat-intel/stats');
        await send('cve_stats', {
          total:     t.total_cves ?? 0,
          critical:  t.critical_cves ?? 0,
          kev_count: t.kev_count ?? 0,
          cve_count: t.total_cves ?? 0,
        });
      } catch (_2) {}
    }

    // Health check
    try {
      const h = await workerFetch('/api/health');
      await send('platform_health', {
        status:     h.status ?? 'operational',
        latency_ms: 0,
        timestamp:  new Date().toISOString(),
        version:    h.version ?? '30.0.0',
      });
    } catch (_) {}
  };

  // ── Threat level helper ───────────────────────────────────────────────────
  const sendThreatLevel = async () => {
    try {
      const g = await workerFetch('/api/global-threat-feed/stats');
      const score    = g.threat_score ?? g.threat_level ?? 62;
      const level    = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
      await send('threat_level', { level, score, source: 'global-threat-feed' });
    } catch (_) {}
  };

  // ── Main streaming loop ───────────────────────────────────────────────────
  const runStream = async () => {
    await sendInitial();
    await sendThreatLevel();

    let scanTick    = 0;
    let healthTick  = 0;
    let threatTick  = 0;
    const TICK_MS   = 5_000;  // timer resolution

    // CF Workers: use a loop with 5s sleeps — no setInterval available
    while (!closed) {
      await new Promise(r => setTimeout(r, TICK_MS));
      if (closed) break;

      scanTick   += TICK_MS;
      healthTick += TICK_MS;
      threatTick += TICK_MS;

      // Keep-alive every 25s
      await send('keepalive', {});

      // Scan metrics every 30s
      if (scanTick >= POLL_INTERVAL_MS) {
        scanTick = 0;
        try {
          const s = await workerFetch('/api/scan/stats');
          if (s?.success !== false) {
            const total = s.total_scans ?? 0;
            const delta = total - lastScanTotal;
            lastScanTotal = total;
            await send('scan_count', {
              total,
              today:    s.today ?? 0,
              critical: s.critical ?? 0,
              delta:    Math.max(0, delta),
            });
          }
        } catch (_) {}

        // CVE stats
        try {
          const v = await workerFetch('/api/vulns/stats');
          await send('cve_stats', {
            total:     v.total ?? 0,
            critical:  v.critical ?? 0,
            kev_count: v.kev_count ?? 0,
            cve_count: v.total ?? 0,
          });
        } catch (_) {}
      }

      // Health every 60s
      if (healthTick >= HEALTH_INTERVAL_MS) {
        healthTick = 0;
        try {
          const h = await workerFetch('/api/health');
          await send('platform_health', {
            status:    h.status ?? 'operational',
            latency_ms: 0,
            timestamp: new Date().toISOString(),
            version:   h.version ?? '30.0.0',
          });
        } catch (_) {}
      }

      // Threat level every 90s
      if (threatTick >= 90_000) {
        threatTick = 0;
        await sendThreatLevel();
      }
    }
  };

  // Run in background — do not await (allows response to start streaming)
  runStream().catch(() => { closed = true; writer.close().catch(() => {}); });

  return new Response(readable, {
    status: 200,
    headers: {
      'Content-Type':                'text/event-stream; charset=utf-8',
      'Cache-Control':               'no-cache, no-store, must-revalidate',
      'Connection':                  'keep-alive',
      'X-Accel-Buffering':           'no',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
