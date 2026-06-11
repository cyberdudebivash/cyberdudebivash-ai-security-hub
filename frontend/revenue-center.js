/**
 * CYBERDUDEBIVASH® AI Security Hub
 * revenue-center.js — Executive Revenue Dashboard
 *
 * Injects "Revenue" tab into Phase 1 Command Centers.
 * Pulls /api/revenue/metrics. SVG sparklines (no library).
 * Namespace: window.CDB_REVENUE_*
 */

(function CDB_REVENUE_MODULE() {
  'use strict';
  const LOG = '[CDB-REVENUE]';

  // ── Inject tab + panel into Phase 1 Command Centers ───────────────────────
  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 500); return; }
    if (document.getElementById('cdb-panel-revenue')) return;

    // Tab
    const tab = document.createElement('button');
    tab.className    = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-revenue';
    tab.setAttribute('role', 'tab');
    tab.textContent  = 'Revenue';
    nav.appendChild(tab);

    // Panel
    const panel = document.createElement('div');
    panel.id        = 'cdb-panel-revenue';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    // Wire tab click (integrate with Phase 1 tab switcher)
    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadRevenue();
    });

    console.info(LOG, 'Revenue tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-kpi-grid" id="cdb-rev-kpi-grid">
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">MRR</div>
        <div class="cdb-kpi-value" id="cdb-rev-mrr">—</div>
        <div class="cdb-kpi-sub">Monthly Recurring Revenue</div>
      </div>
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">ARR</div>
        <div class="cdb-kpi-value" id="cdb-rev-arr">—</div>
        <div class="cdb-kpi-sub">Annual Run Rate</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">ARPU</div>
        <div class="cdb-kpi-value" id="cdb-rev-arpu">—</div>
        <div class="cdb-kpi-sub">Per paying user / mo</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">Paying Users</div>
        <div class="cdb-kpi-value" id="cdb-rev-paying">—</div>
        <div class="cdb-kpi-sub">Pro + Enterprise</div>
      </div>
      <div class="cdb-kpi-card accent-red">
        <div class="cdb-kpi-label">New MRR</div>
        <div class="cdb-kpi-value" id="cdb-rev-new">—</div>
        <div class="cdb-kpi-sub">New subs this month</div>
      </div>
      <div class="cdb-kpi-card">
        <div class="cdb-kpi-label">Pipeline</div>
        <div class="cdb-kpi-value" id="cdb-rev-pipeline">—</div>
        <div class="cdb-kpi-sub">Assessment pipeline</div>
      </div>
    </div>

    <div class="cdb-two-col">
      <div>
        <div class="cdb-section-heading">MRR Trend</div>
        <div id="cdb-rev-chart-wrap" style="background:#0f1729;border:1px solid #1e293b;border-radius:10px;padding:16px;">
          <svg id="cdb-mrr-chart" width="100%" height="80" viewBox="0 0 400 80" preserveAspectRatio="none"
               style="display:block;">
            <text x="50%" y="50%" text-anchor="middle" fill="#475569" font-size="12">Loading…</text>
          </svg>
          <div id="cdb-rev-chart-labels" style="display:flex;justify-content:space-between;margin-top:6px;font-size:10px;color:#475569;"></div>
        </div>
      </div>
      <div>
        <div class="cdb-section-heading">Plan Distribution</div>
        <div id="cdb-rev-plan-dist" style="display:flex;flex-direction:column;gap:8px;">
          <div class="cdb-info-row"><span class="cdb-info-label">Free Users</span><span class="cdb-info-value" id="cdb-rev-free">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Pro Users</span><span class="cdb-info-value" id="cdb-rev-pro" style="color:#6366f1">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Enterprise Users</span><span class="cdb-info-value" id="cdb-rev-ent" style="color:#a855f7">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Free→Paid Conv.</span><span class="cdb-info-value" id="cdb-rev-conv">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Pro→Enterprise</span><span class="cdb-info-value" id="cdb-rev-conv2">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">LTV Estimate</span><span class="cdb-info-value" id="cdb-rev-ltv" style="color:#4ade80">—</span></div>
        </div>
        <div style="margin-top:16px;">
          <div class="cdb-section-heading">Pipeline</div>
          <div class="cdb-info-row"><span class="cdb-info-label">Assessments Booked</span><span class="cdb-info-value" id="cdb-rev-asm-booked">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Assessments Done</span><span class="cdb-info-value" id="cdb-rev-asm-done">—</span></div>
        </div>
      </div>
    </div>

    <div style="margin-top:16px;font-size:11px;color:#475569;text-align:center;">
      Revenue data sourced from existing platform subscriptions · Updated every 5 minutes
      · Last refresh: <span class="cdb-last-updated">—</span>
    </div>
  `;

  // ── Data loader ────────────────────────────────────────────────────────────
  async function loadRevenue() {
    try {
      const resp = await fetch('/api/revenue/metrics', {
        signal: AbortSignal.timeout(8000),
        headers: { Accept: 'application/json' },
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d = await resp.json();

      setText('cdb-rev-mrr',      '$' + fmt(d.mrr));
      setText('cdb-rev-arr',      '$' + fmtK(d.arr));
      setText('cdb-rev-arpu',     '$' + fmt(d.arpu));
      setText('cdb-rev-paying',   fmt(d.paying_subscribers));
      setText('cdb-rev-new',      d.new_this_month > 0 ? '+' + fmt(d.new_this_month) : '0');
      setText('cdb-rev-pipeline', '$' + fmtK(d.pipeline_value));
      setText('cdb-rev-free',     fmt(d.free_users));
      setText('cdb-rev-pro',      fmt(d.pro_users));
      setText('cdb-rev-ent',      fmt(d.enterprise_users));
      setText('cdb-rev-conv',     d.conversion_rate_to_paid + '%');
      setText('cdb-rev-conv2',    d.conversion_rate_pro_to_ent + '%');
      setText('cdb-rev-ltv',      '$' + fmt(d.ltv_estimate));
      setText('cdb-rev-asm-booked', fmt(d.assessments_booked));
      setText('cdb-rev-asm-done',   fmt(d.assessments_completed));

      if (d.mrr_trend?.length > 1) renderMRRChart(d.mrr_trend);
      document.querySelectorAll('.cdb-last-updated').forEach(el => el.textContent = new Date().toLocaleTimeString());

    } catch (e) {
      console.info(LOG, 'Revenue load failed:', e.message);
      // Show auth message if 403
      if (e.message.includes('403')) {
        setText('cdb-rev-mrr', 'Enterprise+');
      }
    }
  }

  // ── SVG MRR Sparkline ──────────────────────────────────────────────────────
  function renderMRRChart(trend) {
    const svg    = document.getElementById('cdb-mrr-chart');
    const labels = document.getElementById('cdb-rev-chart-labels');
    if (!svg || !trend?.length) return;

    const W = 400, H = 80, PAD = 10;
    const values  = trend.map(t => t.mrr || 0);
    const maxVal  = Math.max(...values, 1);
    const minVal  = Math.min(...values, 0);
    const range   = maxVal - minVal || 1;
    const step    = (W - PAD * 2) / Math.max(values.length - 1, 1);

    const points  = values.map((v, i) => {
      const x = PAD + i * step;
      const y = H - PAD - ((v - minVal) / range) * (H - PAD * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');

    const firstPt = points.split(' ')[0];
    const lastPt  = points.split(' ').slice(-1)[0];

    svg.innerHTML = `
      <defs>
        <linearGradient id="mrr-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stop-color="#22c55e" stop-opacity=".3"/>
          <stop offset="100%" stop-color="#22c55e" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <polygon points="${points} ${lastPt.split(',')[0]},${H} ${PAD},${H}"
               fill="url(#mrr-grad)"/>
      <polyline points="${points}" fill="none" stroke="#22c55e" stroke-width="2" stroke-linejoin="round"/>
      ${values.map((v, i) => {
        const x = PAD + i * step;
        const y = H - PAD - ((v - minVal) / range) * (H - PAD * 2);
        return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="#22c55e"/>`;
      }).join('')}
      <text x="${lastPt.split(',')[0]}" y="${Number(lastPt.split(',')[1]) - 6}" text-anchor="middle" fill="#4ade80" font-size="10">$${fmtK(values[values.length - 1])}</text>
    `;

    if (labels) {
      labels.innerHTML = trend.map(t => `<span>${t.month?.slice(5) || ''}</span>`).join('');
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v !== null) el.textContent = v; };
  const fmt  = (n) => typeof n === 'number' ? n.toLocaleString() : (n || '—');
  const fmtK = (n) => {
    if (typeof n !== 'number') return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
    return n.toString();
  };

  // ── Boot ──────────────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

})();
