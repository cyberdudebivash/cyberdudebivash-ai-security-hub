/**
 * CYBERDUDEBIVASH® AI Security Hub
 * soc-investigations.js — SOC Case Management & Investigation Workspace
 *
 * Injects "Cases" sub-section into existing SOC panel.
 * Full case lifecycle: create → investigate → resolve.
 */

(function CDB_SOC_INV_MODULE() {
  'use strict';
  const LOG = '[CDB-SOC-INV]';

  function inject() {
    const socPanel = document.getElementById('cdb-panel-soc');
    if (!socPanel) { setTimeout(inject, 700); return; }
    if (document.getElementById('cdb-soc-cases-section')) return;

    const section = document.createElement('div');
    section.id = 'cdb-soc-cases-section';
    section.innerHTML = CASES_HTML;
    socPanel.appendChild(section);

    // Wire buttons
    document.getElementById('cdb-soc-new-case-btn')?.addEventListener('click', openCreateCaseForm);
    document.getElementById('cdb-soc-refresh-cases')?.addEventListener('click', loadCases);

    // Load case metrics immediately (public endpoint)
    loadCaseMetrics();

    console.info(LOG, 'SOC investigations injected into SOC panel');
  }

  const CASES_HTML = `
    <div style="margin-top:24px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
        <div class="cdb-section-heading" style="margin-bottom:0;">Case Management</div>
        <div style="display:flex;gap:8px;">
          <button id="cdb-soc-refresh-cases" class="cdb-btn-outline" style="font-size:11px;padding:5px 12px;">↻ Refresh</button>
          <button id="cdb-soc-new-case-btn" class="cdb-btn-primary" style="font-size:11px;padding:6px 14px;">+ New Case</button>
        </div>
      </div>

      <!-- Case metrics strip -->
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;" id="cdb-case-metrics-strip">
        <div class="cdb-kpi-card" style="padding:10px;">
          <div class="cdb-kpi-label">Open</div>
          <div class="cdb-kpi-value" id="cdb-case-open" style="font-size:20px;">—</div>
        </div>
        <div class="cdb-kpi-card" style="padding:10px;">
          <div class="cdb-kpi-label">In Progress</div>
          <div class="cdb-kpi-value" id="cdb-case-inprog" style="font-size:20px;color:#6366f1">—</div>
        </div>
        <div class="cdb-kpi-card" style="padding:10px;">
          <div class="cdb-kpi-label">Critical Open</div>
          <div class="cdb-kpi-value" id="cdb-case-crit" style="font-size:20px;color:#f87171">—</div>
        </div>
        <div class="cdb-kpi-card" style="padding:10px;">
          <div class="cdb-kpi-label">Resolved</div>
          <div class="cdb-kpi-value" id="cdb-case-resolved" style="font-size:20px;color:#4ade80">—</div>
        </div>
      </div>

      <!-- Filter tabs -->
      <div style="display:flex;gap:4px;margin-bottom:12px;border-bottom:1px solid #1e293b;padding-bottom:8px;">
        <button class="cdb-case-filter-btn active" data-status="" style="font-size:11px;padding:4px 10px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#94a3b8;cursor:pointer;">All</button>
        <button class="cdb-case-filter-btn" data-status="OPEN" style="font-size:11px;padding:4px 10px;border:1px solid #334155;border-radius:6px;background:transparent;color:#94a3b8;cursor:pointer;">Open</button>
        <button class="cdb-case-filter-btn" data-status="IN_PROGRESS" style="font-size:11px;padding:4px 10px;border:1px solid #334155;border-radius:6px;background:transparent;color:#94a3b8;cursor:pointer;">In Progress</button>
        <button class="cdb-case-filter-btn" data-status="ESCALATED" style="font-size:11px;padding:4px 10px;border:1px solid #334155;border-radius:6px;background:transparent;color:#94a3b8;cursor:pointer;">Escalated</button>
        <button class="cdb-case-filter-btn" data-status="RESOLVED" style="font-size:11px;padding:4px 10px;border:1px solid #334155;border-radius:6px;background:transparent;color:#94a3b8;cursor:pointer;">Resolved</button>
      </div>

      <!-- Case list -->
      <div id="cdb-soc-case-list" style="display:flex;flex-direction:column;gap:6px;max-height:360px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
        <div style="text-align:center;padding:30px;color:#475569;font-size:13px;">
          Log in to view and manage SOC cases.
        </div>
      </div>

      <!-- Case detail panel (hidden by default) -->
      <div id="cdb-case-detail" style="display:none;margin-top:16px;background:#0f1729;border:1px solid #1e293b;border-radius:10px;padding:16px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <div id="cdb-case-detail-title" style="font-size:14px;font-weight:700;color:#e2e8f0;">Case Detail</div>
          <button onclick="document.getElementById('cdb-case-detail').style.display='none'" style="background:none;border:none;color:#64748b;cursor:pointer;font-size:16px;">✕</button>
        </div>
        <div id="cdb-case-detail-body"></div>
        <div id="cdb-case-timeline" style="margin-top:12px;max-height:200px;overflow-y:auto;"></div>
        <div style="display:flex;gap:8px;margin-top:12px;">
          <button id="cdb-case-resolve-btn" class="cdb-btn-primary" style="font-size:11px;padding:6px 14px;">Mark Resolved</button>
          <button id="cdb-case-escalate-btn" class="cdb-btn-outline" style="font-size:11px;padding:6px 14px;">Escalate</button>
        </div>
      </div>
    </div>
  `;

  let currentFilter = '';

  async function loadCaseMetrics() {
    try {
      const resp = await fetch('/api/soc/cases/metrics', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const d = await resp.json();
      setText('cdb-case-open',     fmt(d.open));
      setText('cdb-case-inprog',   fmt(d.in_progress));
      setText('cdb-case-crit',     fmt(d.critical_open));
      setText('cdb-case-resolved', fmt(d.resolved));
    } catch (_) {}
  }

  async function loadCases(statusFilter) {
    const status = statusFilter !== undefined ? statusFilter : currentFilter;
    const list   = document.getElementById('cdb-soc-case-list');
    if (!list) return;

    const url = `/api/soc/cases?limit=20${status ? '&status=' + status : ''}`;

    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });

      if (resp.status === 401) {
        list.innerHTML = `<div style="text-align:center;padding:24px;color:#475569;font-size:13px;">
          🔐 Authentication required to view SOC cases.<br>
          <span style="font-size:11px;margin-top:4px;display:block;">Log in to access the full SOC platform.</span>
        </div>`;
        return;
      }

      const d = await resp.json();
      const cases = d.cases || [];

      if (!cases.length) {
        list.innerHTML = `<div style="text-align:center;padding:24px;color:#475569;font-size:13px;">
          No ${status ? status.toLowerCase() : ''} cases found.
          ${!status ? 'Create your first case above.' : ''}
        </div>`;
        return;
      }

      const sevMap = { CRITICAL: 'cdb-sev-crit', HIGH: 'cdb-sev-high', MEDIUM: 'cdb-sev-med', LOW: 'cdb-sev-low', INFO: 'cdb-sev-low' };
      const statusColors = { OPEN: '#64748b', IN_PROGRESS: '#6366f1', ESCALATED: '#ef4444', RESOLVED: '#22c55e', CLOSED: '#22c55e' };

      list.innerHTML = cases.map(c => `
        <div class="cdb-feed-item cdb-case-row" data-case-id="${c.id}" style="cursor:pointer;flex-wrap:wrap;gap:6px;">
          <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:0;">
            <span class="cdb-sev-badge ${sevMap[c.severity] || 'cdb-sev-med'}">${c.severity}</span>
            <div style="min-width:0;">
              <div style="font-size:12px;font-weight:600;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.title}</div>
              <div style="font-size:10px;color:#64748b;font-family:monospace;">${c.case_number}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
            <span style="font-size:10px;font-weight:600;color:${statusColors[c.status] || '#64748b'};background:${statusColors[c.status] || '#64748b'}22;padding:2px 8px;border-radius:9999px;">${c.status}</span>
            <span style="font-size:10px;color:#475569;">${formatAge(c.created_at)}</span>
          </div>
        </div>
      `).join('');

      list.querySelectorAll('.cdb-case-row').forEach(el => {
        el.addEventListener('click', () => loadCaseDetail(el.dataset.caseId));
      });

    } catch (e) {
      console.info(LOG, 'Cases load failed:', e.message);
      if (list) list.innerHTML = `<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Could not load cases</div>`;
    }

    loadCaseMetrics();
  }

  async function loadCaseDetail(caseId) {
    try {
      const resp = await fetch(`/api/soc/cases/${caseId}`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const { case: c, timeline } = await resp.json();

      const detail = document.getElementById('cdb-case-detail');
      if (!detail) return;
      detail.style.display = 'block';

      setText('cdb-case-detail-title', `${c.case_number} — ${c.title}`);

      const body = document.getElementById('cdb-case-detail-body');
      if (body) body.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
          <div class="cdb-info-row"><span class="cdb-info-label">Severity</span><span class="cdb-info-value">${c.severity}</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Status</span><span class="cdb-info-value">${c.status}</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Source</span><span class="cdb-info-value">${c.source}</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">SLA Due</span><span class="cdb-info-value" style="color:${isSLABreached(c.sla_due_at) ? '#f87171' : '#4ade80'}">${c.sla_due_at ? new Date(c.sla_due_at).toLocaleString() : '—'}</span></div>
        </div>
        ${c.summary ? `<div style="margin-top:10px;font-size:12px;color:#94a3b8;background:#0a0e1a;padding:10px;border-radius:6px;">${c.summary}</div>` : ''}
      `;

      const timelineEl = document.getElementById('cdb-case-timeline');
      if (timelineEl && timeline?.length) {
        timelineEl.innerHTML = `
          <div class="cdb-section-heading">Timeline</div>
          ${timeline.map(t => `
            <div style="display:flex;gap:10px;padding:6px 0;border-bottom:1px solid #1e293b;font-size:11px;">
              <span style="color:#475569;flex-shrink:0;width:80px;">${new Date(t.ts).toLocaleTimeString()}</span>
              <span style="color:${t.type === 'created' ? '#6366f1' : t.type === 'resolved' ? '#22c55e' : '#94a3b8'};">
                ${t.author ? `<strong>${t.author}:</strong> ` : ''}${t.text}
              </span>
            </div>
          `).join('')}
        `;
      }

      // Wire action buttons
      const resolveBtn = document.getElementById('cdb-case-resolve-btn');
      const escalateBtn = document.getElementById('cdb-case-escalate-btn');
      if (resolveBtn) {
        resolveBtn.onclick = () => updateCase(c.id, 'RESOLVED');
        resolveBtn.style.display = ['RESOLVED','CLOSED'].includes(c.status) ? 'none' : 'block';
      }
      if (escalateBtn) {
        escalateBtn.onclick = () => updateCase(c.id, 'ESCALATED');
        escalateBtn.style.display = c.status === 'ESCALATED' ? 'none' : 'block';
      }

    } catch (e) { console.info(LOG, 'Case detail failed:', e.message); }
  }

  async function updateCase(caseId, status) {
    try {
      const resp = await fetch(`/api/soc/cases/${caseId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        window.CDB_UX_TOAST?.('success', `Case ${status.toLowerCase()}`, '');
        document.getElementById('cdb-case-detail').style.display = 'none';
        loadCases();
      }
    } catch (e) { window.CDB_UX_TOAST?.('error', 'Update failed', e.message); }
  }

  function openCreateCaseForm() {
    const title    = window.prompt('Case title:');
    if (!title?.trim()) return;
    const severity = window.prompt('Severity (CRITICAL/HIGH/MEDIUM/LOW):', 'HIGH') || 'HIGH';
    const summary  = window.prompt('Brief description (optional):') || '';

    fetch('/api/soc/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: title.trim(), severity: severity.toUpperCase(), summary }),
      signal: AbortSignal.timeout(8000),
    }).then(r => r.json()).then(d => {
      if (d.success) {
        window.CDB_UX_TOAST?.('success', `Case ${d.case.case_number} Created`, title);
        loadCases();
      } else if (d.error === 'Authentication required') {
        window.CDB_UX_TOAST?.('warning', 'Login Required', 'Please log in to create cases');
      } else {
        window.CDB_UX_TOAST?.('error', 'Failed to create case', d.error || '');
      }
    }).catch(e => window.CDB_UX_TOAST?.('error', 'Request failed', e.message));
  }

  // Wire filter buttons
  document.addEventListener('click', e => {
    const btn = e.target.closest('.cdb-case-filter-btn');
    if (!btn) return;
    document.querySelectorAll('.cdb-case-filter-btn').forEach(b => {
      b.style.background = 'transparent'; b.style.color = '#94a3b8'; b.classList.remove('active');
    });
    btn.style.background = '#1e293b'; btn.style.color = '#f1f5f9'; btn.classList.add('active');
    currentFilter = btn.dataset.status;
    loadCases(currentFilter);
  });

  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v !== null) el.textContent = v; };
  const fmt = (n) => typeof n === 'number' ? n.toLocaleString() : (n ?? '—');
  const formatAge = (ts) => {
    const diff = Date.now() - new Date(ts).getTime();
    const h = Math.floor(diff / 3_600_000);
    return h < 1 ? '<1h ago' : h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
  };
  const isSLABreached = (ts) => ts && new Date(ts) < new Date();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

})();
