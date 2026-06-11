/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * Platform Metrics Authority (PMA) — Frontend KPI Overlay Widget
 *
 * Self-injecting IIFE. Adds "Authority" tab to .cdb-cc-nav.
 * Displays unified KPIs from /api/authority/metrics — THE single source of truth.
 * All existing dashboard widgets remain untouched; this ADDS an authoritative overlay.
 */
(function () {
  'use strict';

  const MODULE_ID   = 'cdb-p4-platform-authority';
  const TAB_ID      = 'cdb-p4-pma-tab';
  const PANEL_ID    = 'cdb-p4-pma-panel';
  const REFRESH_MS  = 60000; // re-poll every 60s (matching KV TTL)

  let refreshTimer = null;

  // ── Inject ──────────────────────────────────────────────────────────────────
  function inject() {
    if (document.getElementById(MODULE_ID)) return;

    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }

    // Tab button
    const tab = document.createElement('button');
    tab.id          = TAB_ID;
    tab.className   = 'cdb-cc-nav-btn';
    tab.textContent = '⚡ Authority';
    tab.title       = 'Platform Metrics Authority — single source of truth';
    tab.addEventListener('click', () => activateTab());
    nav.appendChild(tab);

    // Panel
    const panel = document.createElement('div');
    panel.id        = PANEL_ID;
    panel.className = 'cdb-cc-panel';
    panel.style.display = 'none';
    panel.innerHTML = buildShell();
    body.appendChild(panel);

    // Mark sentinel
    const sentinel = document.createElement('div');
    sentinel.id    = MODULE_ID;
    sentinel.style.display = 'none';
    document.body.appendChild(sentinel);
  }

  // ── Tab activation ──────────────────────────────────────────────────────────
  function activateTab() {
    document.querySelectorAll('.cdb-cc-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.cdb-cc-panel').forEach(p => { p.style.display = 'none'; });
    document.getElementById(TAB_ID).classList.add('active');
    document.getElementById(PANEL_ID).style.display = 'block';
    loadMetrics();
    clearInterval(refreshTimer);
    refreshTimer = setInterval(loadMetrics, REFRESH_MS);
  }

  // ── Shell HTML ──────────────────────────────────────────────────────────────
  function buildShell() {
    return `
      <div style="padding:20px;font-family:system-ui,sans-serif;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div>
            <h2 style="margin:0;font-size:18px;font-weight:700;color:var(--cdb-text,#f1f5f9);">⚡ Platform Metrics Authority</h2>
            <p style="margin:4px 0 0;font-size:12px;color:var(--cdb-muted,#94a3b8);">Single source of truth · Auto-refreshes every 60s</p>
          </div>
          <div style="display:flex;gap:8px;align-items:center;">
            <span id="pma-status-badge" style="display:none;font-size:11px;padding:3px 8px;border-radius:999px;font-weight:600;"></span>
            <button onclick="window._pmaLoad()" style="background:#3b82f6;color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;">↻ Refresh</button>
          </div>
        </div>

        <!-- KPI Grid -->
        <div id="pma-kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:20px;">
          <div style="text-align:center;color:var(--cdb-muted,#94a3b8);padding:24px;font-size:13px;" colspan="4">Loading metrics…</div>
        </div>

        <!-- Status + Budget Alert -->
        <div id="pma-status-row" style="display:none;margin-bottom:20px;"></div>

        <!-- MRR Row -->
        <div id="pma-revenue-row" style="display:none;background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:16px;margin-bottom:20px;"></div>

        <!-- Cache info -->
        <div id="pma-meta" style="font-size:11px;color:var(--cdb-muted,#64748b);text-align:right;margin-top:8px;"></div>
      </div>`;
  }

  // ── Load Metrics ────────────────────────────────────────────────────────────
  async function loadMetrics() {
    const grid    = document.getElementById('pma-kpi-grid');
    const revRow  = document.getElementById('pma-revenue-row');
    const metaEl  = document.getElementById('pma-meta');
    const badge   = document.getElementById('pma-status-badge');
    const statRow = document.getElementById('pma-status-row');
    if (!grid) return;

    try {
      const res  = await fetch('/api/authority/metrics', {
        credentials: 'include',
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');

      const m = data.metrics;

      // KPI cards
      const kpis = [
        { label: 'Scans Today',     value: fmtNum(m.scans_today),    icon: '🔍', color: '#3b82f6' },
        { label: 'Scans (30d)',      value: fmtNum(m.scans_30d),      icon: '📊', color: '#6366f1' },
        { label: 'Critical CVEs',    value: fmtNum(m.critical_cves),  icon: '🔴', color: m.critical_cves > 0 ? '#ef4444' : '#22c55e' },
        { label: 'Open Cases',       value: fmtNum(m.open_cases),     icon: '📋', color: m.open_cases > 10 ? '#f59e0b' : '#22c55e' },
        { label: 'Critical Cases',   value: fmtNum(m.critical_cases), icon: '🚨', color: m.critical_cases > 5 ? '#ef4444' : '#22c55e' },
        { label: 'Active Threats',   value: fmtNum(m.active_threats), icon: '⚠️', color: '#f59e0b' },
        { label: 'Threat Actors',    value: fmtNum(m.threat_actors),  icon: '🎯', color: '#8b5cf6' },
        { label: 'Health Score',     value: `${m.health_score}%`,     icon: '❤️', color: m.health_score >= 80 ? '#22c55e' : m.health_score >= 60 ? '#f59e0b' : '#ef4444' },
      ];

      grid.innerHTML = kpis.map(k => `
        <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:14px;text-align:center;border:1px solid rgba(255,255,255,.08);">
          <div style="font-size:22px;margin-bottom:6px;">${k.icon}</div>
          <div style="font-size:22px;font-weight:700;color:${k.color};">${k.value}</div>
          <div style="font-size:11px;color:var(--cdb-muted,#94a3b8);margin-top:4px;">${k.label}</div>
        </div>`).join('');

      // Platform status badge
      const isOp = m.platform_status === 'operational';
      badge.style.display = 'inline-block';
      badge.textContent   = isOp ? '✓ Operational' : '⚠ Degraded';
      badge.style.background = isOp ? 'rgba(34,197,94,.2)' : 'rgba(239,68,68,.2)';
      badge.style.color      = isOp ? '#22c55e' : '#ef4444';

      // Budget alert
      if (m.budget_alert) {
        statRow.style.display = 'block';
        statRow.innerHTML = `<div style="background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:12px;color:#f59e0b;font-size:13px;">⚠ Error Budget Alert: <strong>${m.budget_alert}</strong> — ${m.critical_cases} critical cases open</div>`;
      } else {
        statRow.style.display = 'none';
      }

      // Revenue row
      if (m.mrr || m.arr) {
        revRow.style.display = 'block';
        revRow.innerHTML = `
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
            <div style="text-align:center;">
              <div style="font-size:20px;font-weight:700;color:#22c55e;">$${fmtNum(m.mrr)}</div>
              <div style="font-size:11px;color:var(--cdb-muted,#94a3b8);">MRR</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:20px;font-weight:700;color:#3b82f6;">$${fmtNum(m.arr)}</div>
              <div style="font-size:11px;color:var(--cdb-muted,#94a3b8);">ARR</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:20px;font-weight:700;color:#8b5cf6;">${fmtNum(m.customer_count)}</div>
              <div style="font-size:11px;color:var(--cdb-muted,#94a3b8);">Customers</div>
            </div>
          </div>`;
      }

      // Meta
      metaEl.textContent = `Source: ${data.source} · Computed: ${new Date(m.computed_at).toLocaleTimeString()} · Valid until: ${new Date(m.valid_until).toLocaleTimeString()}`;

    } catch (e) {
      grid.innerHTML = `<div style="color:#ef4444;padding:16px;font-size:13px;">Failed to load metrics: ${e.message}</div>`;
    }
  }

  function fmtNum(n) {
    if (n == null) return '—';
    n = Number(n);
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000)    return (n / 1000).toFixed(1) + 'k';
    return String(n);
  }

  window._pmaLoad = loadMetrics;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
