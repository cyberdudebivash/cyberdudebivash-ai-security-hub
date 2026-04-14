/**
 * CYBERDUDEBIVASH AI Security Hub — Centralized Response Formatter v1.0
 *
 * All API responses MUST go through these helpers to guarantee consistent shape:
 *   { success: true,  data: {...},  error: null,   meta: {...} }
 *   { success: false, data: null,   error: "msg",  code: "ERR_CODE" }
 *
 * Usage:
 *   import { ok, fail, paginated, noContent } from '../lib/response.js';
 *   return ok(request, { user, token });
 *   return fail(request, 'Invalid plan', 400, 'ERR_INVALID_PLAN');
 */

import { corsHeaders } from '../middleware/cors.js';

// ─── Base headers builder ─────────────────────────────────────────────────────
function baseHeaders(request, extra = {}) {
  return {
    ...corsHeaders(request),
    'Content-Type': 'application/json',
    'X-Platform':   'CYBERDUDEBIVASH-AI-HUB',
    'X-Version':    '10.0',
    ...extra,
  };
}

// ─── Success response ─────────────────────────────────────────────────────────
export function ok(request, data = {}, status = 200, meta = {}) {
  const body = {
    success:   true,
    data,
    error:     null,
    timestamp: new Date().toISOString(),
    ...(Object.keys(meta).length ? { meta } : {}),
  };
  return new Response(JSON.stringify(body), {
    status,
    headers: baseHeaders(request),
  });
}

// ─── Created response (201) ───────────────────────────────────────────────────
export function created(request, data = {}) {
  return ok(request, data, 201);
}

// ─── Error response ───────────────────────────────────────────────────────────
export function fail(request, message = 'Internal error', status = 500, code = null) {
  const body = {
    success:   false,
    data:      null,
    error:     message,
    code:      code || httpCodeToErrCode(status),
    timestamp: new Date().toISOString(),
  };
  return new Response(JSON.stringify(body), {
    status,
    headers: baseHeaders(request),
  });
}

// ─── Paginated response ───────────────────────────────────────────────────────
export function paginated(request, items = [], total = 0, page = 1, limit = 20) {
  return ok(request, items, 200, {
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
      has_more: page * limit < total,
    },
  });
}

// ─── No-content (204) ────────────────────────────────────────────────────────
export function noContent(request) {
  return new Response(null, {
    status:  204,
    headers: corsHeaders(request),
  });
}

// ─── Rate-limit response (429) ────────────────────────────────────────────────
export function rateLimited(request, plan, remaining = 0, resetDate = null) {
  return fail(request,
    `Scan limit reached for ${plan} plan. ${remaining === 0 ? 'Upgrade to continue.' : `${remaining} scans remaining.`}`,
    429,
    'ERR_QUOTA_EXCEEDED'
  );
}

// ─── Unauthorized (401) ───────────────────────────────────────────────────────
export function unauthorized(request, reason = 'Authentication required') {
  return fail(request, reason, 401, 'ERR_UNAUTHORIZED');
}

// ─── Forbidden (403) ─────────────────────────────────────────────────────────
export function forbidden(request, reason = 'Insufficient plan for this feature') {
  return fail(request, reason, 403, 'ERR_FORBIDDEN');
}

// ─── Not found (404) ─────────────────────────────────────────────────────────
export function notFound(request, resource = 'Resource') {
  return fail(request, `${resource} not found`, 404, 'ERR_NOT_FOUND');
}

// ─── Validation error (400) ──────────────────────────────────────────────────
export function badRequest(request, message = 'Invalid request parameters') {
  return fail(request, message, 400, 'ERR_BAD_REQUEST');
}

// ─── CORS preflight ───────────────────────────────────────────────────────────
export function preflight(request) {
  return new Response(null, {
    status:  204,
    headers: corsHeaders(request),
  });
}

// ─── Wrap a handler in a try/catch — returns structured error on throw ────────
export function withErrorBoundary(handler) {
  return async (request, env, ...args) => {
    try {
      return await handler(request, env, ...args);
    } catch (err) {
      console.error(`[ERROR] ${request?.url}`, err?.message, err?.stack?.slice(0, 300));
      return fail(request, err?.message || 'Unexpected server error', 500, 'ERR_INTERNAL');
    }
  };
}

// ─── HTTP status → error code ────────────────────────────────────────────────
function httpCodeToErrCode(status) {
  const map = {
    400: 'ERR_BAD_REQUEST',
    401: 'ERR_UNAUTHORIZED',
    403: 'ERR_FORBIDDEN',
    404: 'ERR_NOT_FOUND',
    409: 'ERR_CONFLICT',
    422: 'ERR_UNPROCESSABLE',
    429: 'ERR_QUOTA_EXCEEDED',
    500: 'ERR_INTERNAL',
    502: 'ERR_BAD_GATEWAY',
    503: 'ERR_SERVICE_UNAVAILABLE',
  };
  return map[status] || `ERR_HTTP_${status}`;
}
