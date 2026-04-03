/**
 * CYBERDUDEBIVASH AI Security Hub — Cloudflare Workers Router
 * Edge API Gateway | 100K req/day free tier | <1ms cold start
 */

import { handleDomainScan }     from './handlers/domain.js';
import { handleAIScan }         from './handlers/ai.js';
import { handleRedteamScan }    from './handlers/redteam.js';
import { handleIdentityScan }   from './handlers/identity.js';
import { handleCompliance }     from './handlers/compliance.js';
import { corsHeaders, withCors } from './middleware/cors.js';

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method.toUpperCase();

    // ── CORS preflight ──────────────────────────────────────────────────────
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // ── Health check ────────────────────────────────────────────────────────
    if (path === '/api/health' && method === 'GET') {
      return withCors(Response.json({
        status: 'ok',
        service: 'CYBERDUDEBIVASH AI Security Hub',
        version: '2.0.0',
        modules: ['domain','ai','redteam','identity','compliance'],
        timestamp: new Date().toISOString(),
      }), request);
    }

    // ── API info ─────────────────────────────────────────────────────────────
    if ((path === '/api' || path === '/api/') && method === 'GET') {
      return withCors(Response.json({
        name: 'CYBERDUDEBIVASH AI Security Hub API',
        version: '2.0.0',
        company: 'CyberDudeBivash Pvt. Ltd.',
        website: 'https://cyberdudebivash.in',
        endpoints: {
          domain:     'POST /api/scan/domain',
          ai:         'POST /api/scan/ai',
          redteam:    'POST /api/scan/redteam',
          identity:   'POST /api/scan/identity',
          compliance: 'POST /api/generate/compliance',
        },
        docs: 'https://cyberdudebivash.in/docs',
      }), request);
    }

    // ── Route table ──────────────────────────────────────────────────────────
    const routes = {
      'POST /api/scan/domain':          handleDomainScan,
      'POST /api/scan/ai':              handleAIScan,
      'POST /api/scan/redteam':         handleRedteamScan,
      'POST /api/scan/identity':        handleIdentityScan,
      'POST /api/generate/compliance':  handleCompliance,
    };

    const routeKey = `${method} ${path}`;
    const handler  = routes[routeKey];

    if (handler) {
      try {
        const response = await handler(request, env);
        return withCors(response, request);
      } catch (err) {
        console.error(`[${routeKey}] Error:`, err.message);
        return withCors(Response.json({
          error: 'Internal server error',
          message: err.message,
          module: routeKey,
          timestamp: new Date().toISOString(),
        }, { status: 500 }), request);
      }
    }

    // ── 404 ──────────────────────────────────────────────────────────────────
    return withCors(Response.json({
      error: 'Not Found',
      path,
      available_endpoints: Object.keys(routes),
      docs: 'https://cyberdudebivash.in',
    }, { status: 404 }), request);
  },
};
