/**
 * CYBERDUDEBIVASH AI Security Hub — PWA Service Worker v8.1
 *
 * Strategy:
 *   - Static assets (HTML, CSS, JS, fonts): Cache-first
 *   - API calls (/api/*):                  Network-first with timeout fallback
 *   - Fallback:                             Offline page when network fails
 *
 * Cache names:
 *   cdb-static-v8.1   — shell HTML, icons, fonts
 *   cdb-api-v8.1       — API response cache (5 min TTL)
 *   cdb-img-v8.1       — images (30 day TTL)
 */

const VERSION      = '8.1.0';
const CACHE_STATIC = `cdb-static-v${VERSION}`;
const CACHE_API    = `cdb-api-v${VERSION}`;
const CACHE_IMG    = `cdb-img-v${VERSION}`;
const API_TIMEOUT  = 8000; // ms

// ── Assets to pre-cache on install ──────────────────────────────────────────
const PRECACHE = [
  '/',
  '/index.html',
  '/manifest.json',
  '/robots.txt',
  '/version.json',
  '/user-dashboard.html',
  '/soc-dashboard.html',
];

// ── Install: pre-cache shell ─────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC).then(cache =>
      cache.addAll(PRECACHE).catch(e => {
        console.warn('[SW] Pre-cache failed for some assets:', e.message);
      })
    ).then(() => self.skipWaiting())
  );
});

// ── Activate: delete old caches ──────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(key => {
        if (key !== CACHE_STATIC && key !== CACHE_API && key !== CACHE_IMG) {
          console.log('[SW] Deleting old cache:', key);
          return caches.delete(key);
        }
      }))
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: route requests ────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Don't intercept non-GET, external third-party (AdSense etc), or chrome-extension
  if (event.request.method !== 'GET') return;
  if (url.protocol === 'chrome-extension:') return;

  // ── API requests: Network-first with 8s timeout, cache fallback ──────────
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstWithTimeout(event.request, CACHE_API, API_TIMEOUT));
    return;
  }

  // ── Images: Cache-first ──────────────────────────────────────────────────
  if (event.request.destination === 'image') {
    event.respondWith(cacheFirstWithFallback(event.request, CACHE_IMG));
    return;
  }

  // ── Static shell (HTML, JS, CSS, fonts): Cache-first ────────────────────
  event.respondWith(cacheFirstWithFallback(event.request, CACHE_STATIC));
});

// ── Strategy: Network-first with timeout ─────────────────────────────────────
async function networkFirstWithTimeout(request, cacheName, timeout) {
  const cache = await caches.open(cacheName);
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timer);
    if (response.ok) {
      // Cache successful API responses for 5 minutes
      const copy = response.clone();
      const headers = new Headers(copy.headers);
      headers.set('sw-cached-at', Date.now().toString());
      // Only cache simple JSON API responses (not streams)
      const ct = response.headers.get('Content-Type') || '';
      if (ct.includes('application/json')) {
        cache.put(request, new Response(await copy.text(), { status: copy.status, headers })).catch(() => {});
      }
    }
    return response;
  } catch {
    // Network failed — try cache
    const cached = await cache.match(request);
    if (cached) {
      // Check if cache is < 5 min old
      const cachedAt = parseInt(cached.headers.get('sw-cached-at') || '0');
      if (Date.now() - cachedAt < 300_000) return cached;
    }
    // Return offline JSON for API
    return new Response(JSON.stringify({
      success: false,
      error: 'You are offline. Please check your connection.',
      code: 'ERR_OFFLINE',
      cached: false,
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ── Strategy: Cache-first with network fallback ───────────────────────────────
async function cacheFirstWithFallback(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response.clone()).catch(() => {});
    }
    return response;
  } catch {
    // Return the offline page for navigation requests
    if (request.mode === 'navigate') {
      const offlinePage = await cache.match('/');
      if (offlinePage) return offlinePage;
    }
    return new Response('Offline — CYBERDUDEBIVASH AI Security Hub', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
}

// ── Push notifications (future use) ──────────────────────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  try {
    const data = event.data.json();
    event.waitUntil(
      self.registration.showNotification(
        data.title || '🛡 Sentinel APEX Alert',
        {
          body:    data.body    || 'New threat intelligence available.',
          icon:    data.icon    || '/icon-192.png',
          badge:   data.badge   || '/icon-192.png',
          tag:     data.tag     || 'sentinel-alert',
          data:    data.url     || '/',
          actions: [
            { action: 'view',    title: 'View Alert' },
            { action: 'dismiss', title: 'Dismiss'   },
          ],
        }
      )
    );
  } catch (e) {
    console.warn('[SW] Push notification error:', e.message);
  }
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'view' || !event.action) {
    event.waitUntil(
      clients.matchAll({ type: 'window' }).then(windowClients => {
        const url = event.notification.data || '/';
        for (const client of windowClients) {
          if (client.url === url && 'focus' in client) return client.focus();
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
    );
  }
});

console.log(`[SW] CYBERDUDEBIVASH AI Security Hub Service Worker v${VERSION} loaded`);
