/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * customer-success.js — Customer Success Command Center
 *
 * Injects "Customer Success" tab into Phase 1 Command Centers.
 * Health scores, adoption metrics, churn risk, playbooks.
 */

(function CDB_CS_MODULE() {
  'use strict';
  const LOG = '[CDB-CS]';

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }
    if (document.getElementById('cdb-panel-cs')) return;

    const tab = document.createElement('button');
    tab.className = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-cs';
    tab.setAttribute('role', 'tab');
    tab.textContent = 'Customer Success';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id = 'cdb-panel-cs';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadHealth();
      loadPlaybooks();
    });

    console.info(LOG, 'Customer Success tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-kpi-grid">
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Health Score</div>
        <div class="cdb-kpi-value" id="cdb-cs-health">—</div>
        <div class="cdb-kpi-sub">Overall platform health</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">Adoption Score</div>
        <div class="cdb-kpi-value" id="cdb-cs-adoption">—</div>
        <div class="cdb-kpi-sub">Feature utilization</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">Churn Risk</div>
        <div class="cdb-kpi-value" id="cdb-cs-churn" style="font-size:18px;">—</div>
        <div class="cdb-kpi-sub">Early warning signal</div>
      </div>
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">Maturity</div>
        <div class="cdb-kpi-value" id="cdb-cs-maturity" style="font-size:16px;">—</div>
        <div class="cdb-kpi-sub">Platform maturity index</div>
      </div>
    </div>

    <div class="cdb-two-col">
      <div>
        <div class="cdb-section-heading">Health Breakdown</div>
        <div class="cdb-info-row"><span class="cdb-info-label">Days Since Last Scan</span><span class="cdb-info-value" id="cdb-cs-last-scan">—</span></div>
        <div class="cdb-info-row"><span class="cdb-info-label">Scans (Last 30d)</span><span class="cdb-info-value" id="cdb-cs-scans">—</span></div>
        <div class="cdb-info-row"><span class="cdb-info-label">Active Features</span><span class="cdb-info-value" id="cdb-cs-features">—</span></div>
        <div class="cdb-info-row"><span class="cdb-info-label">Case Resolution Rate</span><span class="cdb-info-value" id="cdb-cs-resolution">—</span></div>
        <div class="cdb-info-row"><span class="cdb-info-label">Subscription Tier</span><span class="cdb-info-value" id="cdb-cs-tier">—</span></div>
        <div class="cdb-info-row"><span class="cdb-info-label">Expansion Score</span><span class="cdb-info-value" id="cdb-cs-expansion">—</span></div>

        <div style="margin-top:16px;">
          <div class="cdb-section-heading">Risk Triggers</div>
          <div id="cdb-cs-triggers" style="font-size:12px;color:#94a3b8;">
            <span style="color:#475569;">Loading…</span>
          </div>
        </div>
      </div>
      <div>
        <div class="cdb-section-heading">Success Playbooks</div>
        <div id="cdb-cs-playbooks" style="display:flex;flex-direction:column;gap:6px;max-height:380px;overflow-y:auto;scrollbar-width:thin;">
          <div style="text-align:center;padding:16px;color:#475569;font-size:12px;">Loading playbooks…</div>
        </div>
      </div>
    </div>

    <div style="margin-top:16px;font-size:11px;color:#475569;text-align:center;">
      Health scores computed from scan history, case resolution, and feature adoption · <span class="cdb-last-updated">—</span>
    </div>
  `;

  async function loadHealth() {
    try {
      const resp = await fetch('/api/customer-success/health', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const { health } = await resp.json();

      const scoreColor = h => h >= 75 ? '#22c55e' : h >= 50 ? '#eab308' : '#ef4444';
      const churnColors = { NONE: '#22c55e', LOW: '#4ade80', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444' };

      setText('cdb-cs-health',      health.healthScore + '/100');
      setStyle('cdb-cs-health', 'color', scoreColor(health.healthScore));
      setText('cdb-cs-adoption',    health.adoptionScore + '/100');
      setText('cdb-cs-churn',       health.churnRisk);
      setStyle('cdb-cs-churn', 'color', churnColors[health.churnRisk] || '#94a3b8');
      setText('cdb-cs-maturity',    health.maturityIndex);
      setText('cdb-cs-last-scan',   health.lastScanDaysAgo >= 999 ? 'Never' : health.lastScanDaysAgo + 'd ago');
      setText('cdb-cs-scans',       health.scans30d);
      setText('cdb-cs-features',    health.activeFeatureCount + '/5');
      setText('cdb-cs-resolution',  health.resolutionRate + '%');
      setText('cdb-cs-tier',        (health.tier || 'FREE').toUpperCase());
      setText('cdb-cs-expansion',   health.expansionScore + '/100');

      // Risk triggers
      const triggersEl = document.getElementById('cdb-cs-triggers');
      if (triggersEl) {
        if (!health.riskTriggers?.length) {
          triggersEl.innerHTML = '<span style="color:#22c55e">✓ No risk triggers detected</span>';
        } else {
          triggersEl.innerHTML = health.riskTriggers.map(t =>
            `<div style="padding:4px 0;border-bottom:1px solid #1e293b;"><span style="color:#f97316">⚠</span> ${t}</div>`
          ).join('');
        }
      }

      document.querySelectorAll('.cdb-last-updated').forEach(el => el.textContent = new Date().toLocaleTimeString());
    } catch (e) {
      console.info(LOG, 'Health load failed:', e.message);
      if (e.message.includes('401') || e.message.includes('403')) {
        setText('cdb-cs-health', 'Login required');
      }
    }
  }

  async function loadPlaybooks() {
    const container = document.getElementById('cdb-cs-playbooks');
    if (!container) return;

    try {
      const resp = await fetch('/api/customer-success/playbooks', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const { playbooks, recommended_id } = await resp.json();

      container.innerHTML = playbooks.map(pb => `
        <div style="background:#0f1729;border:1px solid ${pb.is_recommended ? '#6366f1' : '#1e293b'};border-radius:8px;padding:12px;${pb.is_recommended ? 'box-shadow:0 0 0 1px #6366f133;' : ''}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            ${pb.is_recommended ? '<span style="font-size:10px;background:#6366f133;color:#a5b4fc;padding:1px 6px;border-radius:4px;font-weight:700;">RECOMMENDED</span>' : ''}
            <div style="font-size:12px;font-weight:700;color:#e2e8f0;">${pb.name}</div>
          </div>
          <div style="font-size:11px;color:#64748b;margin-bottom:8px;">${pb.description}</div>
          <div style="font-size:10px;color:#475569;">~${pb.estimated_days} days · ${pb.steps.length} steps</div>
        </div>
      `).join('');
    } catch (e) {
      if (container) container.innerHTML = '<div style="text-align:center;padding:16px;color:#475569;font-size:12px;">Could not load playbooks</div>';
    }
  }

  const $ = id => document.getElementById(id);
  const setText  = (id, v)   => { const el = $(id); if (el && v != null) el.textContent = v; };
  const setStyle = (id, p, v) => { const el = $(id); if (el) el.style[p] = v; };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
