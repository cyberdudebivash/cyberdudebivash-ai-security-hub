/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * growth-analytics.js — Growth Intelligence & Product Analytics Dashboard
 *
 * Injects "Growth" tab into Phase 1 Command Centers (admin only).
 * DAU/WAU/MAU, conversion funnel, feature adoption matrix, top countries.
 */

(function CDB_GROWTH_MODULE() {
  'use strict';
  const LOG = '[CDB-GROWTH]';

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }
    if (document.getElementById('cdb-panel-growth')) return;

    const tab = document.createElement('button');
    tab.className = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-growth';
    tab.setAttribute('role', 'tab');
    tab.textContent = 'Growth';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id = 'cdb-panel-growth';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadGrowthMetrics();
      loadFunnel();
      loadAdoption();
    });

    console.info(LOG, 'Growth tab injected');
  }

  const PANEL_HTML = `
    <!-- KPI Strip -->
    <div class="cdb-kpi-grid" style="grid-template-columns:repeat(6,1fr);">
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">DAU</div>
        <div class="cdb-kpi-value" id="cdb-g-dau">—</div>
        <div class="cdb-kpi-sub">Daily active users</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">WAU</div>
        <div class="cdb-kpi-value" id="cdb-g-wau">—</div>
        <div class="cdb-kpi-sub">Weekly active users</div>
      </div>
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">MAU</div>
        <div class="cdb-kpi-value" id="cdb-g-mau">—</div>
        <div class="cdb-kpi-sub">Monthly active users</div>
      </div>
      <div class="cdb-kpi-card">
        <div class="cdb-kpi-label">Activation Rate</div>
        <div class="cdb-kpi-value" id="cdb-g-activation">—</div>
        <div class="cdb-kpi-sub">First scan completed</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">Total Events</div>
        <div class="cdb-kpi-value" id="cdb-g-events">—</div>
        <div class="cdb-kpi-sub">30-day window</div>
      </div>
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Conversions</div>
        <div class="cdb-kpi-value" id="cdb-g-conv">—</div>
        <div class="cdb-kpi-sub">Free → Paid (30d)</div>
      </div>
    </div>

    <div class="cdb-two-col">
      <!-- Conversion Funnel -->
      <div>
        <div class="cdb-section-heading">Conversion Funnel</div>
        <div id="cdb-g-funnel" style="display:flex;flex-direction:column;gap:6px;min-height:160px;">
          <div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Loading…</div>
        </div>

        <!-- Top Event Types -->
        <div style="margin-top:16px;">
          <div class="cdb-section-heading">Top Event Types (30d)</div>
          <div id="cdb-g-event-types" style="display:flex;flex-direction:column;gap:4px;max-height:180px;overflow-y:auto;scrollbar-width:thin;">
            <div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Loading…</div>
          </div>
        </div>
      </div>

      <!-- Feature Adoption Matrix -->
      <div>
        <div class="cdb-section-heading">Feature Adoption Matrix</div>
        <div id="cdb-g-adoption" style="display:flex;flex-direction:column;gap:4px;max-height:230px;overflow-y:auto;scrollbar-width:thin;">
          <div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Loading…</div>
        </div>

        <!-- Top Countries -->
        <div style="margin-top:16px;">
          <div class="cdb-section-heading">Top Countries</div>
          <div id="cdb-g-countries" style="display:flex;flex-direction:column;gap:4px;max-height:160px;overflow-y:auto;scrollbar-width:thin;">
            <div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Loading…</div>
          </div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      Analytics data aggregated from platform events · Admin access required · Data pruned >90 days
    </div>
  `;

  async function loadGrowthMetrics() {
    try {
      const resp = await fetch('/api/analytics/p3/growth', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        if (resp.status === 401 || resp.status === 403) {
          setText('cdb-g-dau', 'Admin');
          setText('cdb-g-wau', 'only');
        }
        return;
      }
      const { metrics } = await resp.json();

      setText('cdb-g-dau',        fmtNum(metrics.dau));
      setText('cdb-g-wau',        fmtNum(metrics.wau));
      setText('cdb-g-mau',        fmtNum(metrics.mau));
      setText('cdb-g-activation', (metrics.activation_rate || 0) + '%');
      setText('cdb-g-events',     fmtNum(metrics.total_events_30d));
      setText('cdb-g-conv',       fmtNum(metrics.conversions_30d));

      // Render top event types breakdown
      const evEl = document.getElementById('cdb-g-event-types');
      if (evEl && metrics.event_breakdown?.length) {
        const maxCnt = metrics.event_breakdown[0]?.count || 1;
        evEl.innerHTML = metrics.event_breakdown.slice(0, 8).map(ev => `
          <div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #0f1729;">
            <div style="font-size:11px;color:#94a3b8;width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${ev.event_type}</div>
            <div style="flex:1;background:#0f1729;border-radius:4px;height:8px;overflow:hidden;">
              <div style="height:100%;background:#6366f1;width:${Math.round((ev.count / maxCnt) * 100)}%;border-radius:4px;"></div>
            </div>
            <div style="font-size:11px;color:#475569;text-align:right;min-width:36px;">${fmtNum(ev.count)}</div>
          </div>
        `).join('');
      } else if (evEl) {
        evEl.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">No events recorded yet</div>';
      }

      // Top countries
      const cntEl = document.getElementById('cdb-g-countries');
      if (cntEl && metrics.top_countries?.length) {
        const maxC = metrics.top_countries[0]?.count || 1;
        cntEl.innerHTML = metrics.top_countries.slice(0, 6).map(c => `
          <div style="display:flex;align-items:center;gap:8px;padding:3px 0;">
            <div style="font-size:11px;color:#94a3b8;width:60px;">${c.country || 'Unknown'}</div>
            <div style="flex:1;background:#0f1729;border-radius:4px;height:6px;overflow:hidden;">
              <div style="height:100%;background:#0ea5e9;width:${Math.round((c.count / maxC) * 100)}%;border-radius:4px;"></div>
            </div>
            <div style="font-size:11px;color:#475569;min-width:28px;text-align:right;">${fmtNum(c.count)}</div>
          </div>
        `).join('');
      } else if (cntEl) {
        cntEl.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">No country data</div>';
      }
    } catch (e) {
      console.info(LOG, 'Growth metrics failed:', e.message);
    }
  }

  async function loadFunnel() {
    const funnelEl = document.getElementById('cdb-g-funnel');
    if (!funnelEl) return;

    try {
      const resp = await fetch('/api/analytics/p3/funnel', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        funnelEl.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Admin access required</div>';
        return;
      }
      const { funnel } = await resp.json();

      if (!funnel?.stages?.length) {
        funnelEl.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">No funnel data yet</div>';
        return;
      }

      const maxUsers = funnel.stages[0]?.users || 1;
      const stageColors = ['#6366f1', '#0ea5e9', '#22c55e', '#f97316'];

      funnelEl.innerHTML = funnel.stages.map((stage, i) => {
        const pct = Math.round((stage.users / maxUsers) * 100);
        return `
          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
              <span style="font-size:11px;color:#94a3b8;">${stage.name}</span>
              <span style="font-size:11px;color:${stageColors[i] || '#64748b'};">${fmtNum(stage.users)} users (${stage.pct}%)</span>
            </div>
            <div style="background:#0f1729;border-radius:6px;height:22px;overflow:hidden;">
              <div style="height:100%;background:${stageColors[i] || '#334155'};width:${pct}%;border-radius:6px;display:flex;align-items:center;padding-left:8px;transition:width .4s ease;">
                ${pct > 15 ? `<span style="font-size:10px;color:rgba(255,255,255,.7);font-weight:600;">${stage.name}</span>` : ''}
              </div>
            </div>
            ${i < funnel.stages.length - 1 && stage.drop_off != null
              ? `<div style="font-size:10px;color:#475569;margin-top:1px;padding-left:2px;">▼ ${stage.drop_off}% drop-off</div>`
              : ''}
          </div>
        `;
      }).join('');
    } catch (e) {
      if (funnelEl) funnelEl.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">Funnel unavailable</div>';
    }
  }

  async function loadAdoption() {
    const adoptEl = document.getElementById('cdb-g-adoption');
    if (!adoptEl) return;

    try {
      const resp = await fetch('/api/analytics/p3/adoption', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        adoptEl.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Admin access required</div>';
        return;
      }
      const { adoption } = await resp.json();

      if (!adoption?.features?.length) {
        adoptEl.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">No adoption data yet</div>';
        return;
      }

      adoptEl.innerHTML = `
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:4px;padding:4px 6px;background:#0f1729;border-radius:6px;margin-bottom:4px;">
          <span style="font-size:10px;color:#475569;font-weight:700;">Feature</span>
          <span style="font-size:10px;color:#475569;font-weight:700;text-align:center;">Orgs</span>
          <span style="font-size:10px;color:#475569;font-weight:700;text-align:center;">Adoption</span>
          <span style="font-size:10px;color:#475569;font-weight:700;text-align:center;">Trend</span>
        </div>
        ${adoption.features.map(f => {
          const pct = f.adoption_pct || 0;
          const barColor = pct >= 70 ? '#22c55e' : pct >= 40 ? '#eab308' : '#ef4444';
          return `
            <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:4px;padding:5px 6px;border-bottom:1px solid #0f1729;align-items:center;">
              <span style="font-size:11px;color:#e2e8f0;">${f.feature}</span>
              <span style="font-size:11px;color:#94a3b8;text-align:center;">${f.org_count || 0}</span>
              <div style="display:flex;align-items:center;gap:4px;">
                <div style="flex:1;background:#0f1729;border-radius:4px;height:6px;overflow:hidden;">
                  <div style="height:100%;background:${barColor};width:${pct}%;border-radius:4px;"></div>
                </div>
                <span style="font-size:10px;color:${barColor};min-width:28px;">${pct}%</span>
              </div>
              <span style="font-size:12px;text-align:center;">${f.trend === 'up' ? '↑' : f.trend === 'down' ? '↓' : '→'}</span>
            </div>
          `;
        }).join('')}
      `;
    } catch (e) {
      if (adoptEl) adoptEl.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">Adoption data unavailable</div>';
    }
  }

  const $ = id => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v != null) el.textContent = v; };
  const fmtNum = n => (n == null ? '0' : n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n));

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
