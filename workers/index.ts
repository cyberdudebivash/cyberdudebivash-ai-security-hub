// ============================================================
// workers/index.ts — Main router
// Single Cloudflare Worker entry point.
// Routes all /api/* requests to the correct handler module.
// Handles CORS preflight globally.
// ============================================================

import type { Env } from '../types/index.js';
import healthWorker from './health.js';
import webhookWorker from './webhook.js';
import trustWorker from './trust-center.js';
import ingesterWorker from './cve-ingester.js';
import { corsHeaders, jsonResponse, err } from './lib/utils.js';

export default {
  // ── Scheduled (Cron Triggers) ────────────────────────────
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const cron = event.cron;

    if (cron === '0 */4 * * *') {
      // CVE ingestion — every 4 hours
      await ingesterWorker.scheduled(event, env, ctx);
    } else if (cron === '*/5 * * * *') {
      // Health check log — every 5 minutes
      await writePeriodicHealthLog(env);
    }
  },

  // ── HTTP requests ─────────────────────────────────────────
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = request.headers.get('Origin') ?? '';

    // Global CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    // ── Route dispatch ──────────────────────────────────────
    if (path.startsWith('/api/health') || path.startsWith('/api/mythos/status')) {
      return healthWorker.fetch(request, env);
    }

    if (
      path === '/api/mythos/checkout/webhook' ||
      path === '/api/webhook'
    ) {
      return webhookWorker.fetch(request, env);
    }

    if (path.startsWith('/api/trust')) {
      return trustWorker.fetch(request, env);
    }

    // Internal: manual CVE ingestion trigger
    if (path === '/api/internal/ingest-cve' && request.method === 'POST') {
      return ingesterWorker.fetch(request, env);
    }

    // 404 for unmatched API routes
    if (path.startsWith('/api/')) {
      return jsonResponse(
        err('NOT_FOUND', `No handler for ${request.method} ${path}`),
        404,
        corsHeaders(origin)
      );
    }

    // Non-API paths — pass through to origin (static assets, pages)
    return fetch(request);
  },
};

// ── Periodic health log ──────────────────────────────────────
async function writePeriodicHealthLog(env: Env): Promise<void> {
  const { getPlatformMetrics } = await import('./lib/metrics.js');
  try {
    const metrics = await getPlatformMetrics(env);
    const now = Math.floor(Date.now() / 1000);

    await env.SENTINEL_DB.batch([
      env.SENTINEL_DB.prepare(`
        INSERT INTO health_log (component, status, latency_ms, detail, checked_at)
        VALUES ('api', 'ok', 0, 'Periodic check', ?)
      `).bind(now),
      env.SENTINEL_DB.prepare(`
        INSERT INTO health_log (component, status, detail, checked_at)
        VALUES ('mythos', ?, ?, ?)
      `).bind(
        metrics.health.mythos,
        `Periodic check: ${JSON.stringify(metrics.health)}`,
        now
      ),
    ]);
  } catch (e) {
    console.error('[index] Periodic health log failed:', e);
  }
}
