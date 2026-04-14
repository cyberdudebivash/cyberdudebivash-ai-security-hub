/**
 * ═══════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — Visitor Intelligence v21.0
 * Real-time visitor tracking, geo intelligence, live dashboard feed
 *
 * Endpoints:
 *   POST /api/visitor/track  — Record visitor session
 *   GET  /api/visitor/live   — Live online users + visitor list
 *   GET  /api/visitor/stats  — Aggregate stats (admin)
 * ═══════════════════════════════════════════════════════════════
 */

const VISITOR_TTL      = 15 * 60;       // 15 min online window
const LIVE_CACHE_TTL   = 60;            // 1 min cache for /live
const STATS_CACHE_TTL  = 300;           // 5 min cache for /stats
const MAX_LIVE_LIST    = 25;            // cap returned visitor list
const COUNTRY_FLAGS    = {
  IN:'🇮🇳',US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',SG:'🇸🇬',AU:'🇦🇺',CA:'🇨🇦',FR:'🇫🇷',
  JP:'🇯🇵',KR:'🇰🇷',BR:'🇧🇷',NL:'🇳🇱',RU:'🇷🇺',CN:'🇨🇳',AE:'🇦🇪',SA:'🇸🇦',
  ZA:'🇿🇦',PK:'🇵🇰',BD:'🇧🇩',ID:'🇮🇩',MY:'🇲🇾',TH:'🇹🇭',VN:'🇻🇳',PH:'🇵🇭',
  TR:'🇹🇷',IT:'🇮🇹',ES:'🇪🇸',PL:'🇵🇱',UA:'🇺🇦',SE:'🇸🇪',NO:'🇳🇴',FI:'🇫🇮',
};

// ─── helpers ─────────────────────────────────────────────────────────────────

function maskIP(ip) {
  if (!ip) return 'x.x.x.x';
  const parts = String(ip).split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.xxx.xxx`;
  // IPv6 — mask last 4 groups
  const seg = ip.split(':');
  return seg.slice(0, 4).join(':') + ':xxxx:xxxx:xxxx:xxxx';
}

function detectDevice(ua = '') {
  if (/Mobi|Android|iPhone|iPod/i.test(ua)) return 'mobile';
  if (/iPad|Tablet|PlayBook/i.test(ua)) return 'tablet';
  return 'desktop';
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  });
}

function kvKey(type, suffix) { return `vi:${type}:${suffix}`; }

// ─── POST /api/visitor/track ──────────────────────────────────────────────────
export async function handleVisitorTrack(request, env) {
  try {
    const cf = request.cf || {};
    const ip = request.headers.get('CF-Connecting-IP')
             || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
             || 'unknown';

    let body = {};
    try { body = await request.json(); } catch(_) {}

    const country     = cf.country     || body.country_code || 'XX';
    const city        = cf.city        || body.city         || '';
    const timezone    = cf.timezone    || body.timezone     || '';
    const ua          = (body.ua       || request.headers.get('User-Agent') || '').substring(0, 200);
    const device      = body.device    || detectDevice(ua);
    const page        = (body.page     || '/').substring(0, 100);
    const referrer    = (body.referrer || '').substring(0, 200);
    const now         = Math.floor(Date.now() / 1000);

    // Fingerprint: IP + country (no PII beyond what Cloudflare already has)
    const fingerprint = `${ip.split('.').slice(0,2).join('.')}.${country}`;
    const visitorKey  = kvKey('session', fingerprint);

    const session = {
      ip_masked:    maskIP(ip),
      country_code: country,
      flag:         COUNTRY_FLAGS[country] || '🌐',
      city:         city.substring(0, 30),
      timezone,
      device,
      page,
      referrer,
      last_seen:    now,
      first_seen:   now,
    };

    // Check if this session already exists (extend TTL if so)
    const existing = await env.SECURITY_HUB_KV.get(visitorKey, 'json').catch(() => null);
    if (existing) {
      session.first_seen = existing.first_seen || now;
      session.page_views = (existing.page_views || 0) + 1;
    } else {
      session.page_views = 1;
      // Increment unique visitor counter (fire-and-forget)
      env.SECURITY_HUB_KV.get(kvKey('counter', 'total_visitors'), 'json')
        .then(c => env.SECURITY_HUB_KV.put(
          kvKey('counter', 'total_visitors'),
          JSON.stringify({ count: ((c?.count) || 0) + 1 }),
          { expirationTtl: 86400 * 365 }
        ))
        .catch(() => {});

      // Track country stats (fire-and-forget)
      env.SECURITY_HUB_KV.get(kvKey('country', country), 'json')
        .then(c => env.SECURITY_HUB_KV.put(
          kvKey('country', country),
          JSON.stringify({ count: ((c?.count) || 0) + 1, flag: COUNTRY_FLAGS[country] || '🌐', country }),
          { expirationTtl: 86400 * 7 }
        ))
        .catch(() => {});
    }

    // Store session with 15-min TTL
    await env.SECURITY_HUB_KV.put(visitorKey, JSON.stringify(session), {
      expirationTtl: VISITOR_TTL,
    }).catch(() => {});

    // Add to live index (sorted list for the live feed widget)
    // We store a small index of active session keys
    const idxKey = kvKey('index', 'active');
    let activeIdx = [];
    try {
      activeIdx = (await env.SECURITY_HUB_KV.get(idxKey, 'json')) || [];
    } catch(_) {}

    // Remove expired or this fingerprint if already present, then prepend
    activeIdx = activeIdx.filter(k => k !== visitorKey);
    activeIdx.unshift(visitorKey);
    activeIdx = activeIdx.slice(0, 200); // cap index at 200 entries

    env.SECURITY_HUB_KV.put(idxKey, JSON.stringify(activeIdx), {
      expirationTtl: VISITOR_TTL,
    }).catch(() => {});

    return jsonResponse({ ok: true, tracked: true });
  } catch (err) {
    // Never fail the visitor — silent error
    return jsonResponse({ ok: true, tracked: false });
  }
}

// ─── GET /api/visitor/live ────────────────────────────────────────────────────
export async function handleVisitorLive(request, env) {
  try {
    // Check cache first
    const cacheKey = kvKey('cache', 'live');
    const cached   = await env.SECURITY_HUB_KV.get(cacheKey, 'json').catch(() => null);
    if (cached && (Date.now() / 1000 - cached._ts) < LIVE_CACHE_TTL) {
      return jsonResponse(cached);
    }

    // Load active session index
    const idxKey   = kvKey('index', 'active');
    let activeIdx  = [];
    try { activeIdx = (await env.SECURITY_HUB_KV.get(idxKey, 'json')) || []; } catch(_) {}

    const now    = Math.floor(Date.now() / 1000);
    const cutoff = now - VISITOR_TTL;

    // Load sessions in parallel (cap at 50 to stay fast)
    const toLoad  = activeIdx.slice(0, 50);
    const results = await Promise.allSettled(
      toLoad.map(k => env.SECURITY_HUB_KV.get(k, 'json'))
    );

    const visitors = [];
    const validKeys = [];

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.status !== 'fulfilled' || !r.value) continue;
      const s = r.value;
      if ((s.last_seen || 0) < cutoff) continue; // expired
      visitors.push({
        ip:           s.ip_masked,
        country_code: s.country_code,
        flag:         s.flag || '🌐',
        city:         s.city || '',
        device:       s.device || 'desktop',
        page:         s.page || '/',
        last_seen:    s.last_seen,
        page_views:   s.page_views || 1,
      });
      validKeys.push(toLoad[i]);
    }

    // Sort by most recent first
    visitors.sort((a, b) => b.last_seen - a.last_seen);

    const response = {
      online_users:  visitors.length,
      onlineUsers:   visitors.length, // alias for legacy
      visitors:      visitors.slice(0, MAX_LIVE_LIST),
      total_tracked: activeIdx.length,
      updated_at:    now,
      _ts:           now,
    };

    // Update cleaned index and cache (fire-and-forget)
    if (validKeys.length < activeIdx.length) {
      env.SECURITY_HUB_KV.put(idxKey, JSON.stringify(validKeys), {
        expirationTtl: VISITOR_TTL,
      }).catch(() => {});
    }
    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(response), {
      expirationTtl: LIVE_CACHE_TTL + 10,
    }).catch(() => {});

    return jsonResponse(response);
  } catch (err) {
    console.error('[visitor/live]', err?.message);
    return jsonResponse({
      online_users: 0,
      onlineUsers:  0,
      visitors:     [],
      error:        'unavailable',
    });
  }
}

// ─── GET /api/visitor/stats ───────────────────────────────────────────────────
export async function handleVisitorStats(request, env) {
  try {
    const cacheKey = kvKey('cache', 'stats');
    const cached   = await env.SECURITY_HUB_KV.get(cacheKey, 'json').catch(() => null);
    if (cached && (Date.now() / 1000 - cached._ts) < STATS_CACHE_TTL) {
      return jsonResponse(cached);
    }

    // Fetch all country counters (prefix scan)
    const totalC = await env.SECURITY_HUB_KV.get(kvKey('counter', 'total_visitors'), 'json').catch(() => null);

    // Build top countries from KV prefix
    const topCountries = [];
    const countryKeys  = Object.keys(COUNTRY_FLAGS);
    const countryData  = await Promise.allSettled(
      countryKeys.map(c => env.SECURITY_HUB_KV.get(kvKey('country', c), 'json'))
    );
    for (let i = 0; i < countryData.length; i++) {
      const r = countryData[i];
      if (r.status === 'fulfilled' && r.value?.count) {
        topCountries.push({ country: countryKeys[i], ...r.value });
      }
    }
    topCountries.sort((a, b) => b.count - a.count);

    const stats = {
      total_visitors: totalC?.count || 0,
      top_countries:  topCountries.slice(0, 10),
      _ts:            Math.floor(Date.now() / 1000),
    };

    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(stats), {
      expirationTtl: STATS_CACHE_TTL + 10,
    }).catch(() => {});

    return jsonResponse(stats);
  } catch (err) {
    return jsonResponse({ error: 'unavailable' }, 500);
  }
}
