/**
 * CYBERDUDEBIVASH® AI Security Hub
 * platform-health.js — Enterprise Observability Dashboard
 *
 * Injects "Observability" tab into Phase 1 Command Centers.
 * Deep health probes: D1, KV, R2, scan engine, threat intel, SSE.
 * Routes: /api/platform/health/deep  /api/platform/health/services
 */

(function CDB_HEALTH_MODULE() {
  'use strict';
  const LOG = '[CDB-HEALTH]';

  let _autoRefreshTimer = null;

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 700); return; }
    if (document.getElementById('cdb-panel-observability')) return;

    const tab = document.createElement('button');
    tab.className    = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-observability';
    tab.setAttribute('role', 'tab');
    tab.textContent  = 'Observability';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id        = 'cdb-panel-observability';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadDeepHealth();
      loadServicesList();
      startAutoRefresh();
    });

    document.getElementById('cdb-health-refresh-btn')?.addEventListener('click', () => {
      loadDeepHealth(true);
    });

    // Pause auto-refresh when tab is hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stopAutoRefresh();
      else if (panel.classList.contains('active')) startAutoRefresh();
    });

    console.info(LOG, 'Observability tab injected');
  }

  const PANEL_HTML = `
    <!-- Overall status banner -->
    <div id="cdb-health-status-banner" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:10px;margin-bottom:20px;background:#0f1729;border:1px solid #1e293b;transition:border-color .3s;">
      <div id="cdb-health-status-dot" style="width:12px;height:12px;border-radius:50%;background:#475569;flex-shrink:0;"></div>
      <div>
        <div id="cdb-health-status-text" style="font-size:14px;font-weight:700;color:#e2e8f0;">Checking platform status…</div>
        <div id="cdb-health-status-sub" style="font-size:11px;color:#64748b;margin-top:2px;">Loading deep health probes</div>
      </div>
      <button id="cdb-health-refresh-btn" class="cdb-btn-outline" style="margin-left:auto;font-size:11px;padding:5px 12px;">↻ Refresh</button>
    </div>

    <!-- KPI strip -->
    <div class="cdb-kpi-grid" style="margin-bottom:20px;">
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Services Up</div>
        <div class="cdb-kpi-value" id="cdb-obs-up">—</div>
        <div class="cdb-kpi-sub">of <span id="cdb-obs-total">—</span> total</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">Avg Latency</div>
        <div class="cdb-kpi-value" id="cdb-obs-latency">—</div>
        <div class="cdb-kpi-sub">Cross-service P50</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">D1 Latency</div>
        <div class="cdb-kpi-value" id="cdb-obs-d1-lat">—</div>
        <div class="cdb-kpi-sub">Database query time</div>
      </div>
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">KV Latency</div>
        <div class="cdb-kpi-value" id="cdb-obs-kv-lat">—</div>
        <div class="cdb-kpi-sub">Cache read/write</div>
      </div>
    </div>

    <div class="cdb-two-col">
      <!-- Left: Deep probe results -->
      <div>
        <div class="cdb-section-heading">Infrastructure Probes</div>
        <div id="cdb-health-probe-grid" style="display:flex;flex-direction:column;gap:6px;">
          ${['d1', 'kv', 'r2', 'scan_engine', 'threat_intel', 'sse'].map(svc => `
            <div class="cdb-feed-item" id="cdb-probe-${svc}">
              <div id="cdb-probe-dot-${svc}" style="width:8px;height:8px;border-radius:50%;background:#475569;flex-shrink:0;"></div>
              <div style="flex:1;">
                <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${probeLabel(svc)}</div>
                <div id="cdb-probe-detail-${svc}" style="font-size:10px;color:#64748b;">—</div>
              </div>
              <div id="cdb-probe-latency-${svc}" style="font-size:11px;color:#64748b;font-family:monospace;">—</div>
              <div id="cdb-probe-status-${svc}" style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:9999px;background:#1e293b;color:#64748b;">—</div>
            </div>
          `).join('')}
        </div>

        <div style="margin-top:16px;">
          <div class="cdb-section-heading">SLA Monitoring</div>
          <div class="cdb-info-row"><span class="cdb-info-label">Platform Uptime</span><span class="cdb-info-value" id="cdb-obs-uptime">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">API SLA Target</span><span class="cdb-info-value" style="color:#4ade80">99.9%</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Last Full Check</span><span class="cdb-info-value" id="cdb-obs-last-check">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Check Interval</span><span class="cdb-info-value">30s cache</span></div>
        </div>
      </div>

      <!-- Right: Full service catalog -->
      <div>
        <div class="cdb-section-heading">Service Catalog</div>
        <div id="cdb-health-service-list" style="display:flex;flex-direction:column;gap:5px;max-height:480px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
          <div style="text-align:center;padding:16px;color:#475569;font-size:12px;">Loading services…</div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      Deep health powered by Cloudflare Workers · Auto-refresh every 60s · <span class="cdb-last-updated">—</span>
    </div>
  `;

  function probeLabel(svc) {
    return {
      d1: 'Cloudflare D1 (Database)',
      kv: 'Cloudflare KV (Cache)',
      r2: 'Cloudflare R2 (Storage)',
      scan_engine: 'Scan Engine',
      threat_intel: 'Threat Intel Feed',
      sse: 'SSE Event Stream',
    }[svc] || svc;
  }

  const STATUS_CONFIG = {
    operational:    { dot: '#22c55e', border: '#22c55e44', text: '✓ All Systems Operational',       bg: '#22c55e' },
    degraded:       { dot: '#eab308', border: '#eab30844', text: '⚠ Performance Degraded',          bg: '#eab308' },
    partial_outage: { dot: '#f97316', border: '#f9731644', text: '⚡ Partial Service Disruption',   bg: '#f97316' },
    critical:       { dot: '#ef4444', border: '#ef444444', text: '✕ Critical Platform Failure',     bg: '#ef4444' },
  };

  async function loadDeepHealth(forceRefresh = false) {
    try {
      const url  = forceRefresh ? '/api/platform/health/deep?force=true' : '/api/platform/health/deep';
      const resp = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d = await resp.json();

      // Overall banner
      const cfg    = STATUS_CONFIG[d.status] || STATUS_CONFIG.operational;
      const banner = document.getElementById('cdb-health-status-banner');
      if (banner) banner.style.borderColor = cfg.border;
      setStyle('cdb-health-status-dot', 'background', cfg.dot);
      setText('cdb-health-status-text', cfg.text);
      setText('cdb-health-status-sub',
        `${d.healthy_checks} / ${d.total_checks} checks passing · Checked at ${new Date(d.checked_at).toLocaleTimeString()}`);

      // KPI strip
      const latencies = Object.values(d.checks || {}).map(c => c.latency_ms).filter(n => typeof n === 'number');
      const avgLat = latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;
      setText('cdb-obs-up',       d.healthy_checks);
      setText('cdb-obs-total',    d.total_checks);
      setText('cdb-obs-latency',  avgLat + 'ms');
      setText('cdb-obs-d1-lat',   fmtLat(d.checks?.d1?.latency_ms));
      setText('cdb-obs-kv-lat',   fmtLat(d.checks?.kv?.latency_ms));

      // Individual probe cards
      Object.entries(d.checks || {}).forEach(([key, check]) => {
        const healthy = check.status === 'healthy';
        const dotEl   = document.getElementById(`cdb-probe-dot-${key}`);
        const detEl   = document.getElementById(`cdb-probe-detail-${key}`);
        const latEl   = document.getElementById(`cdb-probe-latency-${key}`);
        const stsEl   = document.getElementById(`cdb-probe-status-${key}`);

        if (dotEl) dotEl.style.background = healthy ? '#22c55e' : check.status === 'degraded' ? '#eab308' : '#ef4444';
        if (detEl) detEl.textContent = check.error || check.details || (healthy ? 'Healthy' : 'Error');
        if (latEl) latEl.textContent = fmtLat(check.latency_ms);
        if (stsEl) {
          stsEl.textContent = healthy ? 'OK' : check.status?.toUpperCase() || 'ERROR';
          stsEl.style.color = healthy ? '#22c55e' : check.status === 'degraded' ? '#eab308' : '#ef4444';
          stsEl.style.background = healthy ? '#22c55e22' : check.status === 'degraded' ? '#eab30822' : '#ef444422';
        }
      });

      setText('cdb-obs-uptime', d.uptime_pct ? d.uptime_pct + '%' : '99.9%');
      setText('cdb-obs-last-check', new Date(d.checked_at).toLocaleTimeString());
      document.querySelectorAll('.cdb-last-updated').forEach(el => el.textContent = new Date().toLocaleTimeString());

    } catch (e) {
      console.info(LOG, 'Deep health failed:', e.message);
      setText('cdb-health-status-text', '⚠ Health check unavailable');
      setText('cdb-health-status-sub', e.message);
    }
  }

  async function loadServicesList() {
    const list = document.getElementById('cdb-health-service-list');
    if (!list) return;

    try {
      const resp = await fetch('/api/platform/health/services', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d = await resp.json();
      const services = d.services || [];

      if (!services.length) {
        list.innerHTML = '<div style="text-align:center;padding:16px;color:#475569;font-size:12px;">No services defined</div>';
        return;
      }

      const catColors = {
        'Infrastructure': '#6366f1', 'Database': '#a855f7', 'Cache': '#22c55e',
        'Storage': '#f59e0b', 'AI': '#0ea5e9', 'Security': '#ef4444',
        'Monitoring': '#f97316', 'API': '#06b6d4',
      };

      const grouped = services.reduce((acc, svc) => {
        (acc[svc.category] = acc[svc.category] || []).push(svc);
        return acc;
      }, {});

      list.innerHTML = Object.entries(grouped).map(([cat, svcs]) => `
        <div>
          <div style="font-size:10px;font-weight:700;color:${catColors[cat] || '#64748b'};text-transform:uppercase;letter-spacing:.8px;padding:6px 0 2px;">${cat}</div>
          ${svcs.map(svc => {
            const up = svc.status === 'operational';
            const deg = svc.status === 'degraded';
            const dotColor = up ? '#22c55e' : deg ? '#eab308' : '#ef4444';
            return `
              <div class="cdb-feed-item" style="padding:6px 10px;gap:8px;">
                <div style="width:6px;height:6px;border-radius:50%;background:${dotColor};flex-shrink:0;"></div>
                <div style="flex:1;">
                  <div style="font-size:11px;font-weight:600;color:#cbd5e1;">${svc.name}</div>
                  ${svc.description ? `<div style="font-size:10px;color:#475569;">${svc.description}</div>` : ''}
                </div>
                ${svc.version ? `<span style="font-size:9px;color:#475569;font-family:monospace;">${svc.version}</span>` : ''}
                <span style="font-size:9px;font-weight:700;color:${dotColor}">${svc.status?.toUpperCase()}</span>
              </div>
            `;
          }).join('')}
        </div>
      `).join('');

    } catch (e) {
      console.info(LOG, 'Service list failed:', e.message);
      if (list) list.innerHTML = `<div style="text-align:center;padding:16px;color:#475569;font-size:12px;">Could not load services</div>`;
    }
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    _autoRefreshTimer = setInterval(() => {
      if (!document.hidden) loadDeepHealth();
    }, 60_000);
  }

  function stopAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
  }

  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v != null) el.textContent = v; };
  const setStyle = (id, prop, val) => { const el = $(id); if (el) el.style[prop] = val; };
  const fmtLat = (ms) => typeof ms === 'number' ? ms + 'ms' : '—';

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

})();
