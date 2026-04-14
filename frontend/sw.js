/**
 * ══════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — PWA Service Worker v14.0
 * P0 FIX: HTML navigation now uses Network-First (NOT Cache-First).
 * Version bump to 14.0 forces ALL old caches (v8.1, v9, v10, v13)
 * to be deleted on next activation, resolving stale-page failures.
 *
 * Strategies:
 *   navigate / HTML → Network-First (always fresh from server)
 *   JS / CSS assets  → Network-First with cache fallback
 *   API /api/*       → Network-First with 8s timeout
 *   Images           → Cache-First (safe, immutable by nature)
 * ══════════════════════════════════════════════════════════════════
 */

const VERSION      = '14.0.0';
const CACHE_STATIC = `cdb-static-v${VERSION}`;
const CACHE_API    = `cdb-api-v${VERSION}`;
const CACHE_IMG    = `cdb-img-v${VERSION}`;
const API_TIMEOUT  = 8000;

// Only pre-cache the bare minimum — NO HTML files (they must always be fresh)
const PRECACHE = [
  '/manifest.json',
  '/robots.txt',
  '/version.json',
];

// ── Install: pre-cache minimal shell ─────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC)
      .then(cache => cache.addAll(PRECACHE).catch(e =>
        console.warn('[SW] Pre-cache partial failure:', e.message)
      ))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: delete ALL old caches from previous versions ───────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(key => {
        if (key !== CACHE_STATIC && key !== CACHE_API && key !== CACHE_IMG) {
          console.log('[SW] Deleting stale cache:', key);
          return caches.delete(key);
        }
      }))
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: route by request type ─────────────────────────────────
self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // Skip non-GET, chrome-extension, and cross-origin third-party requests
  if (req.method !== 'GET') return;
  if (url.protocol === 'chrome-extension:') return;
  // Only handle same-origin + our worker API
  const isSameOrigin = url.origin === self.location.origin;
  const isWorkerAPI  = url.hostname.endsWith('workers.dev');
  if (!isSameOrigin && !isWorkerAPI) return;

  // ① HTML navigation — ALWAYS network-first, never serve stale HTML
  if (req.mode === 'navigate' || url.pathname.endsWith('.html') || url.pathname === '/') {
    event.respondWith(networkFirstNav(req));
    return;
  }

  // ② API requests — network-first with timeout + cache fallback
  if (url.pathname.startsWith('/api/') || isWorkerAPI) {
    event.respondWith(networkFirstWithTimeout(req, CACHE_API, API_TIMEOUT));
    return;
  }

  // ③ Images — cache-first (stable assets, no stale risk)
  if (req.destination === 'image') {
    event.respondWith(cacheFirstWithFallback(req, CACHE_IMG));
    return;
  }

  // ④ JS / CSS — network-first so deployments are always live
  if (url.pathname.match(/\.(js|css|woff2?|ttf)$/)) {
    event.respondWith(networkFirstAsset(req, CACHE_STATIC));
    return;
  }

  // ⑤ Everything else — network with cache fallback
  event.respondWith(networkFirstAsset(req, CACHE_STATIC));
});


// ── Strategy: Network-First for HTML navigation ───────────────────
// Never caches HTML — always fetches fresh from server.
// Falls back to /index.html if network fails (offline mode).
async function networkFirstNav(request) {
  try {
    const response = await fetch(request);
    // Don't cache HTML — let the browser's Cache-Control headers handle it
    return response;
  } catch {
    // Offline: return cached index.html as fallback
    const cache = await caches.open(CACHE_STATIC);
    const cached = await cache.match('/index.html') || await cache.match('/');
    if (cached) return cached;
    return new Response(
      '<!DOCTYPE html><html><head><title>Offline — CYBERDUDEBIVASH</title></head>' +
      '<body style="background:#0d1117;color:#fff;font-family:sans-serif;text-align:center;padding:60px">' +
      '<h1 style="color:#00ffcc">You are offline</h1>' +
      '<p>Please check your internet connection and try again.</p>' +
      '<a href="/" style="color:#00ffcc">Retry</a></body></html>',
      { status: 503, headers: { 'Content-Type': 'text/html' } }
    );
  }
}

// ── Strategy: Network-First for JS/CSS assets ────────────────────
async function networkFirstAsset(request, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone()).catch(() => {});
    return response;
  } catch {
    const cached = await cache.match(request);
    if (cached) return cached;
    return new Response('/* offline */', { status: 503, headers: { 'Content-Type': 'text/plain' } });
  }
}


// ── Strategy: Network-First with timeout for API ─────────────────
async function networkFirstWithTimeout(request, cacheName, timeout) {
  const cache = await caches.open(cacheName);
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timer);
    if (response.ok) {
      const ct = response.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        const copy = response.clone();
        const hdrs = new Headers(copy.headers);
        hdrs.set('sw-cached-at', Date.now().toString());
        cache.put(request, new Response(await copy.text(), { status: copy.status, headers: hdrs })).catch(() => {});
      }
    }
    return response;
  } catch {
    const cached = await cache.match(request);
    if (cached) {
      const cachedAt = parseInt(cached.headers.get('sw-cached-at') || '0');
      if (Date.now() - cachedAt < 300_000) return cached;
    }
    return new Response(JSON.stringify({
      success: false, error: 'You are offline. Please check your connection.',
      code: 'ERR_OFFLINE', cached: false,
    }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }
}

// ── Strategy: Cache-First for images ─────────────────────────────
async function cacheFirstWithFallback(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone()).catch(() => {});
    return response;
  } catch {
    return new Response('', { status: 503 });
  }
}


// ── Push Notifications ────────────────────────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  try {
    const data = event.data.json();
    event.waitUntil(
      self.registration.showNotification(data.title || '🛡️ Sentinel APEX Alert', {
        body:    data.body    || 'New threat intelligence available.',
        icon:    data.icon    || '/og-image.png',
        badge:   data.badge   || '/og-image.png',
        tag:     data.tag     || 'sentinel-alert',
        data:    data.url     || '/',
        actions: [
          { action: 'view',    title: 'View Alert' },
          { action: 'dismiss', title: 'Dismiss'   },
        ],
      })
    );
  } catch (e) {
    console.warn('[SW] Push error:', e.message);
  }
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'view' || !event.action) {
    event.waitUntil(
      clients.matchAll({ type: 'window' }).then(wins => {
        const url = event.notification.data || '/';
        for (const w of wins) {
          if (w.url === url && 'focus' in w) return w.focus();
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
    );
  }
});

console.log(`[SW] CYBERDUDEBIVASH AI Security Hub SW v${VERSION} — Network-First HTML active`);
