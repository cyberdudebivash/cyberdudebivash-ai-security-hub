// ============================================================
// workers/lib/metrics.ts
// Single source of truth for all platform metrics.
// All dashboard counters read from this module — zero hardcoding.
// Cache TTL: 60 seconds in KV. DB queries on cache miss.
// ============================================================

import type { Env, PlatformMetrics, HealthProbeResult, HealthComponent } from '../../types/index.js';
import { nowEpoch } from './utils.js';

const METRICS_CACHE_KEY = 'metrics:platform:v1';
const METRICS_CACHE_TTL = 60; // seconds

// ── Main entry point ─────────────────────────────────────────
export async function getPlatformMetrics(env: Env): Promise<PlatformMetrics> {
  // 1. Try KV cache first
  const cached = await env.SENTINEL_CACHE.get(METRICS_CACHE_KEY, 'json') as PlatformMetrics | null;
  if (cached && cached.computed_at && (nowEpoch() - cached.computed_at) < METRICS_CACHE_TTL) {
    return cached;
  }

  // 2. Compute from DB
  const [cveMetrics, scanMetrics, subscriptionMetrics, soarMetrics, health] =
    await Promise.allSettled([
      computeCveMetrics(env),
      computeScanMetrics(env),
      computeSubscriptionMetrics(env),
      computeSoarMetrics(env),
      computeHealth(env),
    ]);

  const metrics: PlatformMetrics = {
    cve: cveMetrics.status === 'fulfilled' ? cveMetrics.value : {
      total_tracked: 0, critical_count: 0, kev_count: 0,
      ingested_last_24h: 0, last_ingestion_at: null,
    },
    scans: scanMetrics.status === 'fulfilled' ? scanMetrics.value : {
      total_completed: 0, active_now: 0, completed_today: 0, avg_duration_ms: 0,
    },
    subscriptions: subscriptionMetrics.status === 'fulfilled' ? subscriptionMetrics.value : {
      total_active: 0,
      by_tier: { free: 0, starter: 0, pro: 0, enterprise: 0, mssp: 0 },
      mrr_paise: 0, arr_paise: 0, revenue_today_paise: 0,
    },
    soar: soarMetrics.status === 'fulfilled' ? soarMetrics.value : {
      total_generated: 0,
      by_type: { sigma: 0, yara: 0, kql: 0, suricata: 0, splunk: 0 },
    },
    health: health.status === 'fulfilled' ? health.value : {
      api: 'down', db: 'down', cache: 'down',
      sentinel_apex: 'down', mythos: 'down',
      cve_ingester: 'down', webhook: 'down', overall: 'down',
    },
    computed_at: nowEpoch(),
    cache_ttl_seconds: METRICS_CACHE_TTL,
  };

  // 3. Write to KV cache (fire-and-forget — do not block response)
  env.SENTINEL_CACHE.put(
    METRICS_CACHE_KEY,
    JSON.stringify(metrics),
    { expirationTtl: METRICS_CACHE_TTL * 2 }
  );

  return metrics;
}

// ── CVE metrics ───────────────────────────────────────────────
async function computeCveMetrics(env: Env) {
  const dayAgo = nowEpoch() - 86400;

  const [total, critical, kev, last24h, lastIngest] = await Promise.all([
    env.SENTINEL_DB.prepare('SELECT COUNT(*) as n FROM cve_feed').first<{ n: number }>(),
    env.SENTINEL_DB.prepare("SELECT COUNT(*) as n FROM cve_feed WHERE severity='critical'").first<{ n: number }>(),
    env.SENTINEL_DB.prepare('SELECT COUNT(*) as n FROM cve_feed WHERE is_kev=1').first<{ n: number }>(),
    env.SENTINEL_DB.prepare('SELECT COUNT(*) as n FROM cve_feed WHERE ingested_at > ?').bind(dayAgo).first<{ n: number }>(),
    env.SENTINEL_DB.prepare('SELECT MAX(ingested_at) as t FROM cve_feed').first<{ t: number | null }>(),
  ]);

  return {
    total_tracked: total?.n ?? 0,
    critical_count: critical?.n ?? 0,
    kev_count: kev?.n ?? 0,
    ingested_last_24h: last24h?.n ?? 0,
    last_ingestion_at: lastIngest?.t ?? null,
  };
}

// ── Scan metrics ──────────────────────────────────────────────
async function computeScanMetrics(env: Env) {
  const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);

  const [total, active, today, avgDuration] = await Promise.all([
    env.SENTINEL_DB.prepare("SELECT COUNT(*) as n FROM scans WHERE status='completed'").first<{ n: number }>(),
    env.SENTINEL_DB.prepare("SELECT COUNT(*) as n FROM scans WHERE status IN ('queued','running')").first<{ n: number }>(),
    env.SENTINEL_DB.prepare("SELECT COUNT(*) as n FROM scans WHERE status='completed' AND created_at > ?").bind(todayStart).first<{ n: number }>(),
    env.SENTINEL_DB.prepare("SELECT AVG(duration_ms) as avg FROM scans WHERE status='completed' AND duration_ms IS NOT NULL").first<{ avg: number | null }>(),
  ]);

  return {
    total_completed: total?.n ?? 0,
    active_now: active?.n ?? 0,
    completed_today: today?.n ?? 0,
    avg_duration_ms: Math.round(avgDuration?.avg ?? 0),
  };
}

// ── Subscription metrics ──────────────────────────────────────
async function computeSubscriptionMetrics(env: Env) {
  const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);

  const [active, byTier, revenueToday] = await Promise.all([
    env.SENTINEL_DB.prepare("SELECT COUNT(*) as n FROM subscriptions WHERE status='active'").first<{ n: number }>(),
    env.SENTINEL_DB.prepare(
      "SELECT tier, COUNT(*) as n FROM subscriptions WHERE status='active' GROUP BY tier"
    ).all<{ tier: string; n: number }>(),
    env.SENTINEL_DB.prepare(
      "SELECT SUM(amount_paise) as total FROM subscriptions WHERE status='active' AND activated_at > ?"
    ).bind(todayStart).first<{ total: number | null }>(),
  ]);

  const tierMap: Record<string, number> = { free: 0, starter: 0, pro: 0, enterprise: 0, mssp: 0 };
  for (const row of (byTier.results ?? [])) {
    tierMap[row.tier] = row.n;
  }

  // MRR = sum of active subscription amounts
  const mrrResult = await env.SENTINEL_DB.prepare(
    "SELECT SUM(amount_paise) as total FROM subscriptions WHERE status='active'"
  ).first<{ total: number | null }>();
  const mrr = mrrResult?.total ?? 0;

  return {
    total_active: active?.n ?? 0,
    by_tier: tierMap as Record<string, number>,
    mrr_paise: mrr,
    arr_paise: mrr * 12,
    revenue_today_paise: revenueToday?.total ?? 0,
  };
}

// ── SOAR rule metrics ─────────────────────────────────────────
async function computeSoarMetrics(env: Env) {
  const [total, byType] = await Promise.all([
    env.SENTINEL_DB.prepare('SELECT COUNT(*) as n FROM soar_rules').first<{ n: number }>(),
    env.SENTINEL_DB.prepare(
      'SELECT rule_type, COUNT(*) as n FROM soar_rules GROUP BY rule_type'
    ).all<{ rule_type: string; n: number }>(),
  ]);

  const typeMap: Record<string, number> = { sigma: 0, yara: 0, kql: 0, suricata: 0, splunk: 0 };
  for (const row of (byType.results ?? [])) {
    typeMap[row.rule_type] = row.n;
  }

  return {
    total_generated: total?.n ?? 0,
    by_type: typeMap as Record<string, number>,
  };
}

// ── Health computation ────────────────────────────────────────
async function computeHealth(env: Env) {
  const components: HealthComponent[] = [
    'api', 'db', 'cache', 'sentinel_apex', 'mythos', 'cve_ingester', 'webhook'
  ];

  const results = await Promise.allSettled(
    components.map((c) => probeComponent(c, env))
  );

  const healthMap: Record<string, string> = {};
  for (let i = 0; i < components.length; i++) {
    const r = results[i];
    healthMap[components[i]] = r.status === 'fulfilled' ? r.value.status : 'down';
  }

  // Overall = worst status
  const statuses = Object.values(healthMap);
  const overall = statuses.includes('down')
    ? 'down'
    : statuses.includes('degraded')
      ? 'degraded'
      : 'ok';

  return { ...healthMap, overall } as PlatformMetrics['health'];
}

async function probeComponent(
  component: HealthComponent,
  env: Env
): Promise<HealthProbeResult> {
  const start = Date.now();
  try {
    switch (component) {
      case 'api':
        // API is responding (we're in a Worker — always ok if we got here)
        return { component, status: 'ok', latency_ms: Date.now() - start, checked_at: nowEpoch() };

      case 'db': {
        await env.SENTINEL_DB.prepare('SELECT 1 as ping').first();
        const latency = Date.now() - start;
        return { component, status: latency < 2000 ? 'ok' : 'degraded', latency_ms: latency, checked_at: nowEpoch() };
      }

      case 'cache': {
        const testKey = 'health:probe:cache';
        await env.SENTINEL_CACHE.put(testKey, '1', { expirationTtl: 10 });
        const val = await env.SENTINEL_CACHE.get(testKey);
        const latency = Date.now() - start;
        return {
          component,
          status: val === '1' ? (latency < 500 ? 'ok' : 'degraded') : 'down',
          latency_ms: latency,
          checked_at: nowEpoch(),
        };
      }

      case 'cve_ingester': {
        // Check recency: ingested_at within last 6 hours = ok, 24h = degraded, older = down
        const result = await env.SENTINEL_DB.prepare(
          'SELECT MAX(ingested_at) as t FROM cve_feed'
        ).first<{ t: number | null }>();
        const latency = Date.now() - start;
        const lastIngest = result?.t;
        if (!lastIngest) return { component, status: 'down', latency_ms: latency, detail: 'No CVEs ingested', checked_at: nowEpoch() };
        const ageSeconds = nowEpoch() - lastIngest;
        const status = ageSeconds < 21600 ? 'ok' : ageSeconds < 86400 ? 'degraded' : 'down';
        return { component, status, latency_ms: latency, detail: `Last ingest ${Math.round(ageSeconds / 60)}m ago`, checked_at: nowEpoch() };
      }

      case 'webhook': {
        // Check last processed webhook within 24h (or no webhooks = ok for new deployments)
        const result = await env.SENTINEL_DB.prepare(
          "SELECT COUNT(*) as n FROM webhook_events WHERE processed_at > ? AND outcome='failed'"
        ).bind(nowEpoch() - 3600).first<{ n: number }>();
        const latency = Date.now() - start;
        const recentFailures = result?.n ?? 0;
        return {
          component,
          status: recentFailures === 0 ? 'ok' : recentFailures < 3 ? 'degraded' : 'down',
          latency_ms: latency,
          detail: recentFailures > 0 ? `${recentFailures} failures in last hour` : undefined,
          checked_at: nowEpoch(),
        };
      }

      case 'sentinel_apex': {
        // Check CVE ingestion and health log
        const result = await env.SENTINEL_DB.prepare(
          "SELECT status FROM health_log WHERE component='sentinel_apex' ORDER BY checked_at DESC LIMIT 1"
        ).first<{ status: string }>();
        const latency = Date.now() - start;
        return {
          component,
          status: (result?.status as HealthProbeResult['status']) ?? 'degraded',
          latency_ms: latency,
          checked_at: nowEpoch(),
        };
      }

      case 'mythos': {
        const result = await env.SENTINEL_DB.prepare(
          "SELECT status FROM health_log WHERE component='mythos' ORDER BY checked_at DESC LIMIT 1"
        ).first<{ status: string }>();
        const latency = Date.now() - start;
        return {
          component,
          status: (result?.status as HealthProbeResult['status']) ?? 'degraded',
          latency_ms: latency,
          checked_at: nowEpoch(),
        };
      }

      default:
        return { component, status: 'ok', latency_ms: Date.now() - start, checked_at: nowEpoch() };
    }
  } catch (e) {
    return {
      component,
      status: 'down',
      latency_ms: Date.now() - start,
      detail: e instanceof Error ? e.message : 'Unknown error',
      checked_at: nowEpoch(),
    };
  }
}

// ── Invalidate cache (call after writes: subscriptions, scans) ─
export async function invalidateMetricsCache(env: Env): Promise<void> {
  await env.SENTINEL_CACHE.delete(METRICS_CACHE_KEY);
}
