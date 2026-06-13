/* ============================================================================
 * CYBERDUDEBIVASH AI Security Hub — Funnel Instrumentation (cdb-analytics.js)
 * Closes gap R5: revenue funnel was not instrumented → drop-off invisible.
 *
 * Self-contained, dependency-free, privacy-respecting. Emits device-segmented
 * conversion events to your existing /api/track endpoint (and to GA/GTM if the
 * page already loads gtag/dataLayer). No PII is collected. Safe to load on every
 * page; it is a no-op until an event is fired.
 *
 * INSTALL:  copy to frontend/assets/cdb-analytics.js
 *           add  <script src="/assets/cdb-analytics.js" defer></script>  to <head>
 *           call CDBAnalytics.track('scan_started', {...}) at funnel checkpoints.
 * ========================================================================== */
(function (global) {
  'use strict';

  // Canonical funnel taxonomy — the only events the board certifies as required.
  var FUNNEL = [
    'page_view', 'scan_started', 'scan_completed', 'report_viewed',
    'unlock_clicked', 'checkout_started', 'purchase_completed',
    'subscription_started', 'tier_limit_hit', 'consult_booked', 'lead_captured'
  ];

  function deviceClass() {
    var w = (global.innerWidth || 1024);
    if (w < 480) return 'small_phone';
    if (w < 768) return 'large_phone';
    if (w < 1024) return 'tablet';
    return 'desktop';
  }

  // Best-effort session id (in-memory only; no cookie, no localStorage requirement).
  var SID = (function () {
    try {
      var k = '__cdb_sid';
      if (global.sessionStorage && sessionStorage.getItem(k)) return sessionStorage.getItem(k);
      var id = 's_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      try { global.sessionStorage && sessionStorage.setItem(k, id); } catch (e) {}
      return id;
    } catch (e) { return 's_anon'; }
  })();

  function base() {
    return {
      session_id: SID,
      device_class: deviceClass(),
      viewport_w: global.innerWidth || null,
      path: (global.location && location.pathname) || '/',
      ts: new Date().toISOString(),
      platform: 'cyberdudebivash-ai-security-hub'
    };
  }

  // Transport: navigator.sendBeacon (survives navigation) → fetch keepalive fallback.
  function send(payload) {
    var url = '/api/track';
    try {
      var bodyStr = JSON.stringify(payload);
      if (global.navigator && navigator.sendBeacon) {
        var blob = new Blob([bodyStr], { type: 'application/json' });
        if (navigator.sendBeacon(url, blob)) return true;
      }
      if (global.fetch) {
        fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: bodyStr, keepalive: true, credentials: 'same-origin' }).catch(function () {});
        return true;
      }
    } catch (e) { /* never throw from analytics */ }
    return false;
  }

  function track(event, props) {
    if (FUNNEL.indexOf(event) === -1) {
      // Non-canonical events are allowed but flagged so the taxonomy stays clean.
      if (global.console && console.debug) console.debug('[CDBAnalytics] non-canonical event:', event);
    }
    var payload = base();
    payload.event = event;
    if (props && typeof props === 'object') {
      for (var k in props) if (Object.prototype.hasOwnProperty.call(props, k)) {
        // strip anything that looks like PII by key name (defensive)
        if (/email|phone|password|card|token|secret|name/i.test(k)) continue;
        payload[k] = props[k];
      }
    }
    send(payload);
    // Mirror to GA/GTM if present (no-op otherwise).
    try { if (global.gtag) global.gtag('event', event, { device_class: payload.device_class }); } catch (e) {}
    try { if (global.dataLayer) global.dataLayer.push(Object.assign({ event: 'cdb_' + event }, { device_class: payload.device_class })); } catch (e) {}
    return payload;
  }

  // Auto-fire a device-segmented page_view once per load.
  function init() {
    try { track('page_view', {}); } catch (e) {}
  }
  if (global.document) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
  }

  var api = { track: track, deviceClass: deviceClass, FUNNEL: FUNNEL, _sid: SID };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; // testable in Node
  global.CDBAnalytics = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
