/**
 * CYBERDUDEBIVASH® AI Security Hub
 * mssp-workspace.js — MSSP Customer Workspace
 *
 * Injects "Customers" tab into Phase 1 Command Centers.
 * Multi-tenant customer list, metrics, risk scores.
 * Degrades gracefully for non-MSSP users.
 */

(function CDB_MSSP_MODULE() {
  'use strict';
  const LOG = '[CDB-MSSP]';

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 600); return; }
    if (document.getElementById('cdb-panel-customers')) return;

    const tab = document.createElement('button');
    tab.className    = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-customers';
    tab.setAttribute('role', 'tab');
    tab.textContent  = 'Customers';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id        = 'cdb-panel-customers';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadMSSPOverview();
      loadCustomerList();
    });

    // Wire create customer form
    document.getElementById('cdb-mssp-create-btn')?.addEventListener('click', openCreateModal);

    console.info(LOG, 'MSSP tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-kpi-grid">
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">Total Customers</div>
        <div class="cdb-kpi-value" id="cdb-mssp-total">—</div>
        <div class="cdb-kpi-sub">Managed accounts</div>
      </div>
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Active</div>
        <div class="cdb-kpi-value" id="cdb-mssp-active">—</div>
        <div class="cdb-kpi-sub">Operational tenants</div>
      </div>
      <div class="cdb-kpi-card accent-red">
        <div class="cdb-kpi-label">High Risk</div>
        <div class="cdb-kpi-value" id="cdb-mssp-highrisk">—</div>
        <div class="cdb-kpi-sub">Risk score ≥ 75</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">Avg Risk Score</div>
        <div class="cdb-kpi-value" id="cdb-mssp-avgrisk">—</div>
        <div class="cdb-kpi-sub">Platform average</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">Platform MRR</div>
        <div class="cdb-kpi-value" id="cdb-mssp-mrr">—</div>
        <div class="cdb-kpi-sub">MSSP recurring rev</div>
      </div>
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Avg Compliance</div>
        <div class="cdb-kpi-value" id="cdb-mssp-compliance">—</div>
        <div class="cdb-kpi-sub">Platform average</div>
      </div>
    </div>

    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
      <div class="cdb-section-heading" style="margin-bottom:0">Customer Directory</div>
      <button id="cdb-mssp-create-btn" class="cdb-btn-primary" style="font-size:11px;padding:6px 14px;">
        + Add Customer
      </button>
    </div>

    <div id="cdb-mssp-customer-grid" style="display:flex;flex-direction:column;gap:6px;max-height:400px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
      <div style="text-align:center;padding:30px;color:#475569;font-size:13px;">
        Loading customer directory…<br>
        <span style="font-size:11px;margin-top:6px;display:block;">Requires MSSP Admin credentials.</span>
      </div>
    </div>

    <!-- Selected Customer Detail -->
    <div id="cdb-mssp-detail" style="display:none;margin-top:20px;">
      <div class="cdb-section-heading" id="cdb-mssp-detail-title">Customer Detail</div>
      <div class="cdb-two-col">
        <div id="cdb-mssp-detail-scan-block">
          <div class="cdb-info-row"><span class="cdb-info-label">Total Scans</span><span class="cdb-info-value" id="cdb-mssp-d-scans">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Critical Findings</span><span class="cdb-info-value" id="cdb-mssp-d-crit" style="color:#f87171">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Avg Risk Score</span><span class="cdb-info-value" id="cdb-mssp-d-risk">—</span></div>
        </div>
        <div id="cdb-mssp-detail-case-block">
          <div class="cdb-info-row"><span class="cdb-info-label">Open Cases</span><span class="cdb-info-value" id="cdb-mssp-d-open-cases">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">In Progress</span><span class="cdb-info-value" id="cdb-mssp-d-inprog">—</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Critical Open</span><span class="cdb-info-value" id="cdb-mssp-d-critcases" style="color:#f87171">—</span></div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      Last updated: <span class="cdb-last-updated">—</span>
    </div>
  `;

  async function loadMSSPOverview() {
    try {
      const resp = await fetch('/api/mssp/overview', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        if (resp.status === 403) showAccessDenied();
        return;
      }
      const d = await resp.json();
      setText('cdb-mssp-total',       fmt(d.total_customers));
      setText('cdb-mssp-active',      fmt(d.active_customers));
      setText('cdb-mssp-highrisk',    fmt(d.high_risk_count));
      setText('cdb-mssp-avgrisk',     d.avg_risk_score + '/100');
      setText('cdb-mssp-mrr',         '$' + fmt(d.total_mrr));
      setText('cdb-mssp-compliance',  d.avg_compliance + '%');
    } catch (e) { console.info(LOG, 'Overview failed:', e.message); }
  }

  async function loadCustomerList() {
    const grid = document.getElementById('cdb-mssp-customer-grid');
    if (!grid) return;

    try {
      const resp = await fetch('/api/mssp/customers?limit=20', { signal: AbortSignal.timeout(8000) });

      if (resp.status === 403) {
        grid.innerHTML = `
          <div style="text-align:center;padding:30px;color:#475569;font-size:13px;">
            <div style="font-size:24px;margin-bottom:8px;">🏢</div>
            MSSP Admin credentials required.<br>
            <span style="font-size:11px;margin-top:6px;display:block;">Contact your platform administrator to enable multi-tenant access.</span>
          </div>`;
        return;
      }

      const d = await resp.json();
      const customers = d.customers || [];

      if (!customers.length) {
        grid.innerHTML = `
          <div style="text-align:center;padding:30px;color:#475569;font-size:13px;">
            No customers yet. Add your first managed customer above.
          </div>`;
        return;
      }

      grid.innerHTML = customers.map(c => {
        const riskCls  = c.risk_score >= 75 ? 'cdb-sev-crit' : c.risk_score >= 50 ? 'cdb-sev-high' : 'cdb-sev-med';
        const tierCols = { starter: '#64748b', pro: '#6366f1', enterprise: '#a855f7', custom: '#f59e0b' };
        return `
          <div class="cdb-feed-item cdb-mssp-customer-row" data-cid="${c.id}" style="cursor:pointer;">
            <div style="width:8px;height:8px;border-radius:50%;background:${c.status === 'active' ? '#22c55e' : '#f97316'};flex-shrink:0;"></div>
            <div style="flex:1;">
              <div style="font-size:13px;font-weight:600;color:#e2e8f0;">${c.org_name}</div>
              <div style="font-size:11px;color:#64748b;">${c.contact_email || c.org_slug}</div>
            </div>
            <span style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:9999px;background:${tierCols[c.tier] || '#334155'}33;color:${tierCols[c.tier] || '#94a3b8'};">${c.tier.toUpperCase()}</span>
            <span class="cdb-sev-badge ${riskCls}">Risk ${c.risk_score}</span>
          </div>`;
      }).join('');

      // Customer row click → load detail
      grid.querySelectorAll('.cdb-mssp-customer-row').forEach(el => {
        el.addEventListener('click', () => loadCustomerDetail(el.dataset.cid, customers.find(c => c.id === el.dataset.cid)?.org_name));
      });

      document.querySelectorAll('.cdb-last-updated').forEach(el => el.textContent = new Date().toLocaleTimeString());

    } catch (e) {
      console.info(LOG, 'Customer list failed:', e.message);
      if (grid) grid.innerHTML = `<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Could not load customers: ${e.message}</div>`;
    }
  }

  async function loadCustomerDetail(customerId, orgName) {
    const detail = document.getElementById('cdb-mssp-detail');
    const title  = document.getElementById('cdb-mssp-detail-title');
    if (!detail) return;

    try {
      const resp = await fetch(`/api/mssp/customers/${customerId}/metrics`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const d = await resp.json();

      detail.style.display = 'block';
      if (title) title.textContent = `${orgName || d.customer?.org_name} — Detail`;

      setText('cdb-mssp-d-scans',     fmt(d.scans?.total_scans));
      setText('cdb-mssp-d-crit',      fmt(d.scans?.critical_findings));
      setText('cdb-mssp-d-risk',      (d.customer?.risk_score || 0) + '/100');
      setText('cdb-mssp-d-open-cases', fmt(d.cases?.open));
      setText('cdb-mssp-d-inprog',    fmt(d.cases?.in_progress));
      setText('cdb-mssp-d-critcases', fmt(d.cases?.critical_open));
    } catch (e) { console.info(LOG, 'Detail failed:', e.message); }
  }

  function openCreateModal() {
    const orgName = window.prompt('Customer organization name:');
    if (!orgName?.trim()) return;
    const email = window.prompt('Contact email (optional):') || '';
    const tier  = window.prompt('Tier (starter/pro/enterprise):', 'starter') || 'starter';

    fetch('/api/mssp/customers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ org_name: orgName.trim(), contact_email: email, tier }),
      signal: AbortSignal.timeout(8000),
    }).then(r => r.json()).then(d => {
      if (d.success) {
        window.CDB_UX_TOAST?.('success', 'Customer Added', orgName);
        loadCustomerList();
        loadMSSPOverview();
      } else {
        window.CDB_UX_TOAST?.('error', 'Failed to add customer', d.error || '');
      }
    }).catch(e => window.CDB_UX_TOAST?.('error', 'Request failed', e.message));
  }

  function showAccessDenied() {
    setText('cdb-mssp-total', 'MSSP+');
  }

  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v !== null) el.textContent = v; };
  const fmt = (n) => typeof n === 'number' ? n.toLocaleString() : (n ?? '—');

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

})();
