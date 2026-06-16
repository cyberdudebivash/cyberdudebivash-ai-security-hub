/**
 * CYBERDUDEBIVASH® AI Security Hub
 * dashboard-live.js — Enterprise Real-Time Data Adapter v1.0
 *
 * Additive module — extends but never replaces existing index.html functionality.
 * Namespace: window.CDB_LIVE_*  (no collisions with existing code)
 *
 * Architecture:
 *   PlatformDataBus — multi-API aggregator with stale-while-revalidate cache
 *   CounterHydrator — wires all static IDs to live API values
 *   SSE Client       — /api/dashboard/stream with exponential backoff reconnect
 *   CommandCenters   — data loader for all 5 enterprise sections
 *
 * Poll intervals:
 *   Fast  (30s): /api/scan/stats, /api/threat-intel/stats
 *   Med   (60s): /api/vulns/stats, /api/global-threat-feed/stats
 *   Slow (120s): /api/trust/metrics, /api/platform/metrics
 */

(function CDB_LIVE_MODULE() {
  'use strict';

  const LOG = '[CDB-LIVE]';
  const VERSION = '1.0.0';
  const BASE = ''; // relative — same origin as the Workers API

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);
  const setText = (id, val) => { const el = $(id); if (el && val !== null && val !== undefined) el.textContent = val; };
  const fmt = (n) => (typeof n === 'number') ? n.toLocaleString() : (n || '—');
  // Honest CVE count — the real number of advisories tracked in threat_intel.
  // (Previously inflated by a hardcoded +3,841 "floor"; removed for metric integrity.)
  const fmtCve = (raw) => {
    const m = Number(raw);
    if (!isFinite(m) || m < 0) return '—';
    return m.toLocaleString('en-IN');
  };
  // Threat level + bar score derived from REAL critical/KEV counts (same thresholds
  // as the platform's ai_summary), not a missing threat_score field.
  const threatFrom = (crit, kev) => {
    crit = Number(crit) || 0; kev = Number(kev) || 0;
    if (kev > 50 || crit > 100) return { level: 'CRITICAL', score: 92 };
    if (kev > 20 || crit > 50)  return { level: 'HIGH',     score: 74 };
    if (kev > 5  || crit > 20)  return { level: 'MODERATE', score: 50 };
    if (crit > 0)               return { level: 'LOW',      score: 28 };
    return { level: 'MINIMAL', score: 10 };
  };
  const fmtK = (n) => {
    if (typeof n !== 'number') return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M+';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K+';
    return n.toString();
  };

  // ─────────────────────────────────────────────────────────────────────────
  // PlatformDataBus — fetches + cache
  // ─────────────────────────────────────────────────────────────────────────
  window.CDB_LIVE_BUS = window.CDB_LIVE_BUS || {
    cache: {},
    errors: 0,
    lastUpdate: null,

    async fetch(endpoint) {
      try {
        const resp = await fetch(BASE + endpoint, {
          signal: AbortSignal.timeout(8000),
          headers: { Accept: 'application/json' },
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        this.cache[endpoint] = { data, ts: Date.now() };
        return data;
      } catch (err) {
        this.errors++;
        console.info(LOG, `Fetch failed: ${endpoint}`, err.message);
        return this.cache[endpoint]?.data || null;
      }
    },

    get(endpoint) {
      return this.cache[endpoint]?.data || null;
    },
  };

  const Bus = window.CDB_LIVE_BUS;

  // ─────────────────────────────────────────────────────────────────────────
  // CounterHydrator — wires static IDs to live values
  // ─────────────────────────────────────────────────────────────────────────
  async function hydrateCounters() {
    // ── /api/platform/metrics — SINGLE SOURCE OF TRUTH ───────────────────────
    // Every headline counter is driven from this one endpoint so the hero, trust
    // center and all command centers always show identical, real values. The
    // metrics object already reconciles KV scan counters + D1 (see
    // metricsHydration.js) and agrees with /api/scan/stats and threat-intel/stats.
    const pm = await Bus.fetch('/api/platform/metrics');
    const m  = pm?.metrics || null;

    if (m) {
      const total    = m.total_scans ?? 0;
      const today    = m.scans_today ?? 0;
      const critical = m.critical_threats ?? 0;
      const cves     = m.total_cves_tracked ?? 0;
      const kev      = m.kev_count ?? m.active_exploitation ?? 0;
      // Threat level reflects RECENT exploitation activity (KEV added in last 30d),
      // not the full historical catalog — otherwise a large KEV count pins it to
      // CRITICAL forever. Falls back to total KEV if the field isn't present yet.
      const kevRecent = (typeof m.kev_recent === 'number') ? m.kev_recent : kev;
      const uptime   = m.uptime_pct ?? m.uptime_percent ?? m.uptime ?? null;

      // Scans
      setText('stat-scans',           fmtK(total));
      setText('tm-scans',             fmt(total));
      setText('p4-scan-count',        fmtK(total));
      setText('hero-live-scans',      fmt(today));
      setText('cdb-exec-total-scans', fmtK(total));
      setText('cdb-exec-scans-today', fmt(today));
      setText('cdb-soc-scan-count',   fmt(today));

      // Scan-based critical findings (risk_score>=80) — sits beside scan counts,
      // matches the SSE scan_count.critical so poll + stream never disagree.
      const scanCritical = m.high_risk_scans ?? 0;
      setText('stat-threats',      scanCritical > 0 ? `${fmt(scanCritical)} critical` : '—');
      setText('cdb-exec-critical', fmt(scanCritical));
      // CVE-critical (severity='CRITICAL') drives the threat-intel / Sentinel tiles.
      setText('ae-cve-count',      fmt(critical));

      // CVEs (honest counts — no fabricated floor)
      setText('stat-cves',          fmtCve(cves));
      setText('tm-cves',            fmtCve(cves));
      setText('cdb-exec-cves',      fmtCve(cves));
      setText('cdb-sentinel-total', fmtCve(cves));
      setText('cdb-sentinel-crit',  fmt(critical));
      setText('cdb-sentinel-kev',   fmt(kev));

      // Uptime
      if (uptime !== null) {
        setText('cdb-exec-uptime', typeof uptime === 'number' ? uptime.toFixed(2) + '%' : uptime);
      }

      // Threat level + bar — derived from REAL critical + recent-KEV counts
      const t = threatFrom(critical, kevRecent);
      const colors = { CRITICAL: '#ef4444', HIGH: '#f97316', MODERATE: '#eab308', LOW: '#22c55e', MINIMAL: '#22c55e' };
      setText('cdb-threat-level-label', t.level);
      setText('cdb-threat-score',       t.score);
      const tBar = $('cdb-threat-bar');
      if (tBar) {
        tBar.style.width      = Math.min(100, t.score) + '%';
        tBar.style.background = colors[t.level] || colors.MODERATE;
      }
    } else {
      // ── Fallback: SSOT unavailable — hydrate from scan/stats + threat-intel/stats
      // (correctly mapped this time) so the page still shows real data on outage.
      const scans = await Bus.fetch('/api/scan/stats');
      if (scans) {
        const total = scans.total_scans ?? 0;
        const today = scans.today ?? 0;
        const crit  = scans.critical_cves ?? scans.critical ?? 0;
        setText('stat-scans',           fmtK(total));
        setText('tm-scans',             fmt(total));
        setText('p4-scan-count',        fmtK(total));
        setText('hero-live-scans',      fmt(today));
        setText('cdb-exec-total-scans', fmtK(total));
        setText('cdb-exec-scans-today', fmt(today));
        setText('cdb-soc-scan-count',   fmt(today));
        setText('stat-threats',         crit > 0 ? `${fmt(crit)} critical` : '—');
        setText('cdb-exec-critical',    fmt(crit));
      }
      const intel = await Bus.fetch('/api/threat-intel/stats');
      // Payload is wrapped in .data.stats — read that first or total_advisories is undefined.
      const s = intel?.data?.stats || intel?.stats || intel || null;
      if (s) {
        const total = s.total_advisories ?? s.total_cves ?? s.total ?? 0;
        const crit  = s.critical ?? s.critical_cves ?? 0;
        const kev   = s.confirmed_exploited ?? s.kev_count ?? 0;
        setText('stat-cves',          fmtCve(total));
        setText('tm-cves',            fmtCve(total));
        setText('cdb-exec-cves',      fmtCve(total));
        setText('cdb-sentinel-total', fmtCve(total));
        setText('cdb-sentinel-crit',  fmt(crit));
        setText('cdb-sentinel-kev',   fmt(kev));
        const t = threatFrom(crit, kev);
        setText('cdb-threat-level-label', t.level);
        setText('cdb-threat-score',       t.score);
      }
    }

    // ── /api/health — platform status badge ──────────────────────────────────
    const health = await Bus.fetch('/api/health');
    if (health) {
      const status = health.status || 'operational';
      const badge  = $('cdb-platform-status');
      if (badge) {
        badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        badge.className   = badge.className.replace(/\bcdb-status-\w+/g, '');
        badge.classList.add(status === 'operational' ? 'cdb-status-green' : 'cdb-status-amber');
      }
    }

    Bus.lastUpdate = new Date();
    // Update last-updated timestamp in all command centers
    const ts = Bus.lastUpdate.toLocaleTimeString();
    document.querySelectorAll('.cdb-last-updated').forEach(el => { el.textContent = ts; });
    console.info(LOG, 'Counters hydrated at', ts);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Command Center Data Loaders
  // ─────────────────────────────────────────────────────────────────────────

  // SOC — threat feed
  async function loadSOCFeed() {
    const feed = await Bus.fetch('/api/threat-intel/live');
    const list = $('cdb-soc-alert-feed');
    if (!list || !feed) return;
    const items = Array.isArray(feed) ? feed : (feed.data || feed.items || feed.threats || []);
    if (!items.length) return;

    list.innerHTML = items.slice(0, 8).map(item => {
      const sev   = (item.severity || item.cvss_severity || 'MEDIUM').toUpperCase();
      const sevCls= sev === 'CRITICAL' ? 'cdb-sev-crit' : sev === 'HIGH' ? 'cdb-sev-high' : 'cdb-sev-med';
      const title = item.title || item.cve_id || item.id || 'Threat Event';
      const ts    = item.published_at || item.created_at || item.timestamp || '';
      const when  = ts ? new Date(ts).toLocaleTimeString() : '';
      return `<div class="cdb-feed-item">
        <span class="cdb-sev-badge ${sevCls}">${sev}</span>
        <span class="cdb-feed-title">${title}</span>
        <span class="cdb-feed-ts">${when}</span>
      </div>`;
    }).join('');
  }

  // Sentinel APEX — CVE intelligence cards
  async function loadSentinelIntel() {
    const feed = await Bus.fetch('/api/threat-intel/live');
    const grid = $('cdb-sentinel-cve-grid');
    if (!grid || !feed) return;
    const items = Array.isArray(feed) ? feed : (feed.data || feed.items || feed.threats || []);
    if (!items.length) return;

    grid.innerHTML = items.slice(0, 6).map(item => {
      const cveId   = item.cve_id || item.id || 'N/A';
      const cvss    = item.cvss_score ?? item.score ?? '—';
      const sev     = (item.severity || item.cvss_severity || 'MEDIUM').toUpperCase();
      const sevCls  = sev === 'CRITICAL' ? 'cdb-sev-crit' : sev === 'HIGH' ? 'cdb-sev-high' : 'cdb-sev-med';
      const title   = item.title || item.description || 'Vulnerability';
      const kev     = item.kev || item.in_kev ? '<span class="cdb-kev-badge">KEV</span>' : '';
      const desc    = (item.description || item.summary || '').substring(0, 90);
      return `<div class="cdb-cve-card">
        <div class="cdb-cve-header">
          <span class="cdb-cve-id">${cveId}</span>
          <span class="cdb-sev-badge ${sevCls}">${sev}</span>
          ${kev}
          <span class="cdb-cvss-score">CVSS ${cvss}</span>
        </div>
        <div class="cdb-cve-title">${title}</div>
        ${desc ? `<div class="cdb-cve-desc">${desc}…</div>` : ''}
      </div>`;
    }).join('');
  }

  // AI SecOps — AI asset registry
  async function loadAISecOps() {
    // Auth-gated — gracefully degrade if 401/403
    const assets = await Bus.fetch('/api/ai-security/dashboard');
    if (!assets) return;

    const totalAssets = assets.total_assets ?? assets.count ?? assets.assets?.length ?? 0;
    const riskScore   = assets.risk_score ?? assets.overall_risk ?? 0;
    const governance  = assets.governance_status ?? assets.governance ?? 'Assessed';

    setText('cdb-ai-total-assets',   fmt(totalAssets));
    setText('cdb-ai-risk-score',     typeof riskScore === 'number' ? riskScore + '/10' : riskScore);
    setText('cdb-ai-governance',     governance);

    const assetList = $('cdb-ai-asset-list');
    if (assetList && (assets.assets || assets.items)) {
      const items = assets.assets || assets.items || [];
      assetList.innerHTML = items.slice(0, 5).map(a => {
        const name = a.name || a.asset_name || a.id || 'AI Asset';
        const type = a.type || a.asset_type || 'LLM';
        const risk = a.risk_level || a.risk_score || '—';
        const rCls = risk === 'HIGH' || Number(risk) >= 7 ? 'cdb-sev-high' : 'cdb-sev-med';
        return `<div class="cdb-asset-row">
          <span class="cdb-asset-name">${name}</span>
          <span class="cdb-asset-type">${type}</span>
          <span class="cdb-sev-badge ${rCls}">${risk}</span>
        </div>`;
      }).join('');
    }
  }

  // MSSP — service health matrix
  async function loadMSSPCenter() {
    const scans = Bus.get('/api/scan/stats');
    const platform = Bus.get('/api/platform/metrics');
    const health   = Bus.get('/api/health');

    const services = [
      { name: 'Sentinel APEX',   status: 'OPERATIONAL',  metric: scans ? fmtK(scans.total_scans || 0) + ' scans'  : '—' },
      { name: 'MYTHOS Engine',   status: 'OPERATIONAL',  metric: 'Active' },
      { name: 'CVE Intelligence',status: 'OPERATIONAL',  metric: scans ? fmt(scans.cve_count || 0) + ' CVEs' : '—' },
      { name: 'Threat Feed',     status: 'OPERATIONAL',  metric: 'Live' },
      { name: 'API Gateway',     status: health?.status === 'operational' ? 'OPERATIONAL' : 'DEGRADED', metric: platform ? fmtK(platform.total_requests || 0) + ' reqs' : '—' },
      { name: 'AI Brain',        status: 'OPERATIONAL',  metric: 'Active' },
    ];

    const grid = $('cdb-mssp-service-grid');
    if (!grid) return;
    grid.innerHTML = services.map(svc => {
      const ok = svc.status === 'OPERATIONAL';
      return `<div class="cdb-service-tile ${ok ? 'cdb-svc-ok' : 'cdb-svc-warn'}">
        <div class="cdb-svc-indicator"></div>
        <div class="cdb-svc-name">${svc.name}</div>
        <div class="cdb-svc-status">${svc.status}</div>
        <div class="cdb-svc-metric">${svc.metric}</div>
      </div>`;
    }).join('');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SSE Client — /api/dashboard/stream
  // ─────────────────────────────────────────────────────────────────────────
  let sseRetryDelay = 1000;
  let sseActive     = false;

  function connectSSE() {
    if (sseActive) return;
    sseActive = true;

    try {
      const es = new EventSource(BASE + '/api/dashboard/stream');

      es.addEventListener('scan_count', (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.total)    { setText('stat-scans', fmtK(d.total)); setText('tm-scans', fmt(d.total)); setText('cdb-exec-total-scans', fmtK(d.total)); }
          if (d.today)    { setText('hero-live-scans', fmt(d.today)); setText('cdb-exec-scans-today', fmt(d.today)); setText('cdb-soc-scan-count', fmt(d.today)); }
          if (d.critical) { setText('stat-threats', `${fmt(d.critical)} critical`); setText('cdb-exec-critical', fmt(d.critical)); }
        } catch (_) {}
      });

      es.addEventListener('cve_stats', (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.total) { setText('stat-cves', fmtCve(d.total)); setText('tm-cves', fmtCve(d.total)); setText('cdb-exec-cves', fmtCve(d.total)); setText('cdb-sentinel-total', fmtCve(d.total)); }
          if (d.critical) setText('cdb-sentinel-crit', fmt(d.critical));
          if (d.kev_count) setText('cdb-sentinel-kev', fmt(d.kev_count));
        } catch (_) {}
      });

      es.addEventListener('threat_level', (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.level) setText('cdb-threat-level-label', d.level);
          if (d.score !== undefined) {
            setText('cdb-threat-score', d.score);
            const tBar = $('cdb-threat-bar');
            if (tBar) {
              const colors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' };
              tBar.style.width      = Math.min(100, d.score) + '%';
              tBar.style.background = colors[d.level] || colors.MEDIUM;
            }
          }
        } catch (_) {}
      });

      es.addEventListener('platform_health', (e) => {
        try {
          const d = JSON.parse(e.data);
          const badge = $('cdb-platform-status');
          if (badge && d.status) {
            badge.textContent = d.status.charAt(0).toUpperCase() + d.status.slice(1);
            badge.className   = badge.className.replace(/\bcdb-status-\w+/g, '');
            badge.classList.add(d.status === 'operational' ? 'cdb-status-green' : 'cdb-status-amber');
          }
        } catch (_) {}
      });

      es.onerror = () => {
        es.close();
        sseActive = false;
        console.info(LOG, `SSE error — reconnecting in ${sseRetryDelay}ms`);
        setTimeout(() => {
          sseRetryDelay = Math.min(sseRetryDelay * 2, 30_000);
          connectSSE();
        }, sseRetryDelay);
      };

      es.onopen = () => {
        sseRetryDelay = 1000;
        console.info(LOG, 'SSE connected to /api/dashboard/stream');
      };
    } catch (err) {
      sseActive = false;
      console.info(LOG, 'SSE unavailable:', err.message);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Command Center tab switcher
  // ─────────────────────────────────────────────────────────────────────────
  function initCommandCenterTabs() {
    document.querySelectorAll('.cdb-cc-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.target;
        document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        const panel = $(target);
        if (panel) panel.classList.add('active');

        // Lazy load data for newly activated center
        const loaders = {
          'cdb-panel-soc':      loadSOCFeed,
          'cdb-panel-sentinel': loadSentinelIntel,
          'cdb-panel-ai':       loadAISecOps,
          'cdb-panel-mssp':     loadMSSPCenter,
        };
        if (loaders[target]) loaders[target]();
      });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // IntersectionObserver — lazy load command centers on scroll
  // ─────────────────────────────────────────────────────────────────────────
  function initLazyLoader() {
    const section = $('cdb-command-centers');
    if (!section) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          loadSOCFeed();
          loadSentinelIntel();
          loadMSSPCenter();
          obs.disconnect();
        }
      });
    }, { threshold: 0.1 });
    obs.observe(section);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Polling loops
  // ─────────────────────────────────────────────────────────────────────────
  function startPolling() {
    // Fast 30s: scan + threat intel stats
    const fastPoll = async () => {
      await Promise.allSettled([
        Bus.fetch('/api/scan/stats'),
        Bus.fetch('/api/threat-intel/stats'),
      ]);
      hydrateCounters();
    };

    // Med 60s: vulns + global threat feed
    const medPoll = async () => {
      await Promise.allSettled([
        Bus.fetch('/api/vulns/stats'),
        Bus.fetch('/api/global-threat-feed/stats'),
      ]);
    };

    // Slow 120s: trust + platform + reload soc feed
    const slowPoll = async () => {
      await Promise.allSettled([
        Bus.fetch('/api/trust/metrics'),
        Bus.fetch('/api/platform/metrics'),
        Bus.fetch('/api/health'),
      ]);
      loadSOCFeed();
      loadMSSPCenter();
    };

    setInterval(fastPoll, 30_000);
    setInterval(medPoll,  60_000);
    setInterval(slowPoll, 120_000);

    // Offset med + slow polls to avoid thundering herd
    setTimeout(() => { setInterval(medPoll,  60_000); medPoll(); },  5_000);
    setTimeout(() => { setInterval(slowPoll, 120_000); slowPoll(); }, 10_000);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Boot
  // ─────────────────────────────────────────────────────────────────────────
  async function init() {
    console.info(LOG, `v${VERSION} booting — Enterprise Dashboard Adapter`);

    // Pre-fetch all data in parallel
    await Promise.allSettled([
      Bus.fetch('/api/scan/stats'),
      Bus.fetch('/api/vulns/stats'),
      Bus.fetch('/api/threat-intel/stats'),
      Bus.fetch('/api/trust/metrics'),
      Bus.fetch('/api/health'),
      Bus.fetch('/api/global-threat-feed/stats'),
      Bus.fetch('/api/platform/metrics'),
    ]);

    // Wire static counters
    await hydrateCounters();

    // Initialize command center UI
    initCommandCenterTabs();
    initLazyLoader();

    // Start SSE
    connectSSE();

    // Start polling loops
    startPolling();

    console.info(LOG, 'Ready. Errors so far:', Bus.errors);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
