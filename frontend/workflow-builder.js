/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * workflow-builder.js — Security Workflow Automation Builder
 *
 * Injects "Workflows" tab into Phase 1 Command Centers.
 * Create, manage, and trigger security automation workflows.
 */

(function CDB_WF_MODULE() {
  'use strict';
  const LOG = '[CDB-WF]';

  const TRIGGER_LABELS = {
    SCAN_CRITICAL: 'Critical Scan Finding',
    CASE_CREATED: 'SOC Case Created',
    CASE_ESCALATED: 'Case Escalated',
    HEALTH_CHURN: 'Customer Churn Risk',
    IOC_MATCH: 'IOC Match',
    MANUAL: 'Manual Trigger',
    SCHEDULE: 'Scheduled',
  };

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }
    if (document.getElementById('cdb-panel-workflows')) return;

    const tab = document.createElement('button');
    tab.className = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-workflows';
    tab.setAttribute('role', 'tab');
    tab.textContent = 'Workflows';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id = 'cdb-panel-workflows';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadWorkflows();
      loadTemplates();
    });

    document.getElementById('cdb-wf-new-btn')?.addEventListener('click', openCreateForm);

    console.info(LOG, 'Workflows tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-kpi-grid" style="grid-template-columns:repeat(4,1fr);">
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">Total Workflows</div>
        <div class="cdb-kpi-value" id="cdb-wf-total">—</div>
        <div class="cdb-kpi-sub">Defined automations</div>
      </div>
      <div class="cdb-kpi-card accent-green">
        <div class="cdb-kpi-label">Active</div>
        <div class="cdb-kpi-value" id="cdb-wf-active">—</div>
        <div class="cdb-kpi-sub">Currently enabled</div>
      </div>
      <div class="cdb-kpi-card accent-blue">
        <div class="cdb-kpi-label">Templates</div>
        <div class="cdb-kpi-value" id="cdb-wf-tpl-count">4</div>
        <div class="cdb-kpi-sub">Built-in patterns</div>
      </div>
      <div class="cdb-kpi-card">
        <div class="cdb-kpi-label">Executions (All Time)</div>
        <div class="cdb-kpi-value" id="cdb-wf-runs">—</div>
        <div class="cdb-kpi-sub">Total workflow runs</div>
      </div>
    </div>

    <div class="cdb-two-col">
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <div class="cdb-section-heading" style="margin-bottom:0;">Your Workflows</div>
          <button id="cdb-wf-new-btn" class="cdb-btn-primary" style="font-size:11px;padding:5px 14px;">+ New Workflow</button>
        </div>
        <div id="cdb-wf-list" style="display:flex;flex-direction:column;gap:6px;max-height:400px;overflow-y:auto;scrollbar-width:thin;">
          <div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Log in to manage workflows.</div>
        </div>
      </div>

      <div>
        <div class="cdb-section-heading">Workflow Templates</div>
        <div id="cdb-wf-templates" style="display:flex;flex-direction:column;gap:6px;max-height:240px;overflow-y:auto;scrollbar-width:thin;">
          <div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Loading…</div>
        </div>

        <div id="cdb-wf-exec-log" style="margin-top:16px;display:none;">
          <div class="cdb-section-heading">Last Execution</div>
          <div id="cdb-wf-exec-body" style="font-size:12px;color:#94a3b8;background:#0f1729;border-radius:8px;padding:12px;"></div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      Workflows automate security actions · Triggers fire on platform events · Audit trail logged to SOC
    </div>
  `;

  async function loadWorkflows() {
    const list = document.getElementById('cdb-wf-list');
    if (!list) return;

    try {
      const resp = await fetch('/api/workflows', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        if (resp.status === 401) {
          list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">🔐 Log in to view workflows.</div>';
        }
        return;
      }
      const { workflows, total } = await resp.json();

      setText('cdb-wf-total', total || 0);
      setText('cdb-wf-active', workflows.filter(w => w.is_active).length);
      setText('cdb-wf-runs', workflows.reduce((a, w) => a + (w.run_count || 0), 0));

      if (!workflows?.length) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">No workflows yet. Use a template or create your own.</div>';
        return;
      }

      list.innerHTML = workflows.map(wf => `
        <div class="cdb-feed-item" style="flex-wrap:wrap;gap:6px;">
          <div style="width:8px;height:8px;border-radius:50%;background:${wf.is_active ? '#22c55e' : '#475569'};flex-shrink:0;margin-top:4px;"></div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${wf.name}</div>
            <div style="font-size:10px;color:#64748b;">${TRIGGER_LABELS[wf.trigger_type] || wf.trigger_type} · ${wf.run_count || 0} runs</div>
          </div>
          <div style="display:flex;gap:4px;flex-shrink:0;">
            <button onclick="executeWorkflow('${wf.id}','${wf.name}')" class="cdb-btn-primary" style="font-size:10px;padding:3px 8px;">▶ Run</button>
            <button onclick="toggleWorkflow('${wf.id}',${wf.is_active})" class="cdb-btn-outline" style="font-size:10px;padding:3px 8px;">${wf.is_active ? 'Pause' : 'Enable'}</button>
          </div>
        </div>
      `).join('');
    } catch (e) {
      console.info(LOG, 'Workflows load failed:', e.message);
    }
  }

  async function loadTemplates() {
    const el = document.getElementById('cdb-wf-templates');
    if (!el) return;

    try {
      const resp = await fetch('/api/workflows/templates', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const { templates } = await resp.json();

      el.innerHTML = templates.map(t => `
        <div class="cdb-feed-item" style="flex-wrap:wrap;gap:6px;">
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${t.name}</div>
            <div style="font-size:10px;color:#64748b;">${t.description}</div>
          </div>
          <div style="display:flex;gap:4px;flex-shrink:0;">
            <button onclick="executeWorkflow('${t.id}','${t.name}')" class="cdb-btn-outline" style="font-size:10px;padding:3px 8px;">▶ Run</button>
            <button onclick="deployTemplate('${t.id}')" class="cdb-btn-primary" style="font-size:10px;padding:3px 8px;">Deploy</button>
          </div>
        </div>
      `).join('');
    } catch (e) {
      if (el) el.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">Could not load templates</div>';
    }
  }

  window.executeWorkflow = async function(wfId, name) {
    window.CDB_UX_TOAST?.('info', 'Running workflow…', name);

    try {
      const resp = await fetch(`/api/workflows/${wfId}/execute`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        signal: AbortSignal.timeout(15000),
      });
      const d = await resp.json();

      if (d.success) {
        window.CDB_UX_TOAST?.('success', 'Workflow completed', `${d.steps_executed} steps executed`);
        const logEl = document.getElementById('cdb-wf-exec-log');
        const bodyEl = document.getElementById('cdb-wf-exec-body');
        if (logEl) logEl.style.display = 'block';
        if (bodyEl) {
          bodyEl.innerHTML = `
            <div><strong>Status:</strong> <span style="color:${d.status === 'COMPLETED' ? '#22c55e' : '#ef4444'}">${d.status}</span></div>
            <div style="margin-top:4px;"><strong>Steps:</strong> ${d.steps_executed}</div>
            <div style="margin-top:4px;font-size:10px;color:#475569;">${(d.steps || []).map(s => `${s.action}: <span style="color:${s.status === 'ok' ? '#22c55e' : '#ef4444'}">${s.status}</span>`).join(' · ')}</div>
          `;
        }
        loadWorkflows();
      } else {
        window.CDB_UX_TOAST?.('error', 'Workflow failed', d.error || '');
      }
    } catch (e) {
      window.CDB_UX_TOAST?.('error', 'Execution failed', e.message);
    }
  };

  window.toggleWorkflow = async function(wfId, isActive) {
    try {
      const resp = await fetch(`/api/workflows/${wfId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: !isActive }),
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        window.CDB_UX_TOAST?.('success', isActive ? 'Workflow paused' : 'Workflow enabled', '');
        loadWorkflows();
      }
    } catch (e) { window.CDB_UX_TOAST?.('error', 'Update failed', e.message); }
  };

  window.deployTemplate = async function(tplId) {
    // Execute the template to create a workflow from it
    window.CDB_UX_TOAST?.('info', 'Deploying template…', '');
    window.executeWorkflow(tplId, 'Template');
  };

  function openCreateForm() {
    const name    = window.prompt('Workflow name:');
    if (!name?.trim()) return;
    const trigger = window.prompt('Trigger type (SCAN_CRITICAL/CASE_CREATED/CASE_ESCALATED/HEALTH_CHURN/MANUAL):', 'MANUAL');
    if (!trigger) return;

    const steps = [{ action: 'SEND_NOTIFICATION', config: { event_type: 'workflow.executed', channels: ['INAPP'] } }];

    fetch('/api/workflows', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name.trim(), trigger_type: trigger.toUpperCase(), steps }),
      signal: AbortSignal.timeout(8000),
    }).then(r => r.json()).then(d => {
      if (d.success) {
        window.CDB_UX_TOAST?.('success', 'Workflow created', name);
        loadWorkflows();
      } else {
        window.CDB_UX_TOAST?.('error', 'Failed', d.error || '');
      }
    }).catch(e => window.CDB_UX_TOAST?.('error', 'Failed', e.message));
  }

  const $ = id => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v != null) el.textContent = v; };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
