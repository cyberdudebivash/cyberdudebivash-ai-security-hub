// ============================================================
// workers/trust-center.ts
// GET /api/trust/compliance          — framework alignment list
// GET /api/trust/compliance/:id      — single framework detail
// GET /api/trust/metrics             — real transparency metrics
// GET /api/trust/security-practices  — security transparency section
//
// This replaces all hardcoded compliance badge claims with
// DB-backed, honestly-scoped alignment records.
// The UI must read from this endpoint — never hardcode badges.
// ============================================================

import type { Env } from '../types/index.js';
import { getPlatformMetrics } from './lib/metrics.js';
import { corsHeaders, jsonResponse, ok, err } from './lib/utils.js';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin') ?? '';
    const cors = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== 'GET') {
      return jsonResponse(err('METHOD_NOT_ALLOWED', 'GET only'), 405, cors);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '');
    const pathParts = path.split('/');

    try {
      if (path === '/api/trust/compliance') {
        return handleComplianceList(env, cors);
      }

      if (pathParts[3] && pathParts[2] === 'compliance') {
        return handleComplianceDetail(env, cors, pathParts[3]);
      }

      if (path === '/api/trust/metrics') {
        return handleTrustMetrics(env, cors);
      }

      if (path === '/api/trust/security-practices') {
        return handleSecurityPractices(env, cors);
      }

      return jsonResponse(err('NOT_FOUND', 'Endpoint not found'), 404, cors);
    } catch (e) {
      console.error('[trust-center] Error:', e);
      return jsonResponse(err('INTERNAL_ERROR', 'Trust center error'), 500, cors);
    }
  },
};

// ── Compliance list ───────────────────────────────────────────
async function handleComplianceList(env: Env, cors: Record<string, string>): Promise<Response> {
  const result = await env.SENTINEL_DB.prepare(
    'SELECT * FROM compliance_alignments ORDER BY framework'
  ).all<Record<string, unknown>>();

  return jsonResponse(ok({
    notice: 'Alignment means controls are addressed in platform design. Formal certification is noted where achieved.',
    frameworks: (result.results ?? []).map(formatAlignment),
    count: result.results?.length ?? 0,
  }), 200, { ...cors, 'Cache-Control': 'public, max-age=3600' });
}

// ── Single framework detail ───────────────────────────────────
async function handleComplianceDetail(
  env: Env, cors: Record<string, string>, id: string
): Promise<Response> {
  const row = await env.SENTINEL_DB.prepare(
    'SELECT * FROM compliance_alignments WHERE id = ? OR framework = ?'
  ).bind(id, id).first<Record<string, unknown>>();

  if (!row) {
    return jsonResponse(err('NOT_FOUND', 'Framework not found'), 404, cors);
  }

  return jsonResponse(ok(formatAlignment(row)), 200, {
    ...cors, 'Cache-Control': 'public, max-age=3600',
  });
}

// ── Trust metrics (real numbers from DB) ─────────────────────
async function handleTrustMetrics(env: Env, cors: Record<string, string>): Promise<Response> {
  const metrics = await getPlatformMetrics(env);

  // Only show numbers we can substantiate
  return jsonResponse(ok({
    verified_metrics: {
      scans_completed: {
        value: metrics.scans.total_completed,
        label: metrics.scans.total_completed > 0
          ? `${metrics.scans.total_completed.toLocaleString('en-IN')}+`
          : '0',
        source: 'D1 database — scans table, status=completed',
        verified: true,
      },
      cves_tracked: {
        value: metrics.cve.total_tracked,
        label: metrics.cve.total_tracked > 0
          ? `${metrics.cve.total_tracked.toLocaleString('en-IN')}+`
          : 'Pipeline initializing',
        source: 'D1 database — cve_feed table, NVD + CISA KEV',
        verified: true,
      },
      paying_customers: {
        value: metrics.subscriptions.total_active,
        label: String(metrics.subscriptions.total_active),
        source: 'D1 database — subscriptions table, status=active',
        note: 'Only counting customers with verified payment via Razorpay webhook',
        verified: true,
      },
      soar_rules_generated: {
        value: metrics.soar.total_generated,
        label: metrics.soar.total_generated > 0
          ? `${metrics.soar.total_generated}+`
          : '0',
        source: 'D1 database — soar_rules table',
        verified: true,
      },
      platform_uptime: {
        value: '99.9%',
        source: 'Cloudflare network SLA — not independently measured at platform layer',
        note: 'This represents Cloudflare Workers SLA, not application-level uptime measurement',
        verified: false,
        verified_note: 'Independent uptime monitoring not yet configured',
      },
    },
    unverified_claims_removed: [
      '3,841+ CVEs tracked (was hardcoded — now live from DB)',
      '47+ verified paying customers (was hardcoded — now live from DB)',
      '1,247+ scans (was hardcoded — now live from DB)',
      '312+ SOAR rules (was hardcoded — now live from DB)',
    ],
    computed_at: metrics.computed_at,
  }), 200, { ...cors, 'Cache-Control': `public, max-age=${metrics.cache_ttl_seconds}` });
}

// ── Security practices transparency ───────────────────────────
async function handleSecurityPractices(env: Env, cors: Record<string, string>): Promise<Response> {
  return jsonResponse(ok({
    practices: [
      {
        claim: 'Zero data retention on scan targets',
        status: 'verified',
        detail: 'Scan results reference domain names and findings only. No full page content, no credentials, no user data from scanned targets is stored.',
      },
      {
        claim: 'Payment data security',
        status: 'verified',
        detail: 'All payment processing handled by Razorpay. Platform stores only payment IDs and order IDs, never card numbers or bank credentials. PCI compliance via Razorpay.',
      },
      {
        claim: 'AI processing',
        status: 'verified',
        detail: 'MYTHOS uses Cloudflare AI Workers. Scan inputs are not used for model training. Queries are processed in-session only.',
      },
      {
        claim: 'Cloudflare edge network',
        status: 'verified',
        detail: 'All Worker routes run on Cloudflare edge. Data residency follows Cloudflare regional tiering.',
      },
      {
        claim: 'Full audit log on Enterprise plan',
        status: 'partial',
        detail: 'Webhook events and health logs are stored in D1 and accessible on Enterprise plan. Comprehensive user action audit log is in development.',
      },
      {
        claim: 'No third-party analytics SDKs',
        status: 'verified',
        detail: 'No Google Analytics, Segment, Mixpanel, or similar SDKs. Platform analytics are internal via D1.',
      },
      {
        claim: 'Open API inspection',
        status: 'verified',
        detail: 'All API endpoints are documented at /api/docs. Request and response shapes are inspectable.',
      },
    ],
  }), 200, { ...cors, 'Cache-Control': 'public, max-age=3600' });
}

// ── Formatter ─────────────────────────────────────────────────
function formatAlignment(row: Record<string, unknown>) {
  const level = row.alignment_level as string;
  return {
    id: row.id,
    framework: row.framework,
    alignment_level: level,
    alignment_label: level === 'certified'
      ? 'Certified'
      : level === 'aligned'
        ? 'Aligned (not certified)'
        : 'Partially aligned',
    scope_note: row.scope_note,
    auditor: row.auditor ?? null,
    cert_number: row.cert_number ?? null,
    valid_from: row.valid_from ?? null,
    valid_until: row.valid_until ?? null,
    evidence_url: row.evidence_url ?? null,
  };
}
