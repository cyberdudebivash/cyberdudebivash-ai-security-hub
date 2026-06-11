/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * reporting-center.js — Enterprise Reporting Center
 *
 * Injects "Reports" tab into Phase 1 Command Centers.
 * Generate, download, and schedule enterprise reports.
 */

(function CDB_REPORTS_MODULE() {
  'use strict';
  const LOG = '[CDB-REPORTS]';

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }
    if (document.getElementById('cdb-panel-reports')) return;

    const tab = document.createElement('button');
    tab.className = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-reports';
    tab.setAttribute('role', 'tab');
    tab.textContent = 'Reports';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id = 'cdb-panel-reports';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadTemplates();
      loadRecentReports();
    });

    document.getElementById('cdb-report-gen-btn')?.addEventListener('click', generateReport);

    console.info(LOG, 'Reports tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-two-col">
      <div>
        <div class="cdb-section-heading">Generate Report</div>
        <div style="background:#0f1729;border:1px solid #1e293b;border-radius:10px;padding:16px;display:flex;flex-direction:column;gap:10px;">
          <div>
            <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Report Type</label>
            <select id="cdb-report-type" style="width:100%;margin-top:4px;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:8px 10px;color:#e2e8f0;font-size:12px;outline:none;">
              <option value="SECURITY_POSTURE">Security Posture Report</option>
              <option value="BOARD">Board Executive Report</option>
              <option value="MSSP">MSSP Customer Report</option>
              <option value="CTI">Threat Intelligence Report</option>
              <option value="COMPLIANCE">Compliance Report</option>
              <option value="AI_SECURITY">AI Security Report</option>
            </select>
          </div>
          <div>
            <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Format</label>
            <select id="cdb-report-format" style="width:100%;margin-top:4px;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:8px 10px;color:#e2e8f0;font-size:12px;outline:none;">
              <option value="HTML">HTML (View in Browser)</option>
              <option value="PDF">PDF (Print to PDF)</option>
            </select>
          </div>
          <button id="cdb-report-gen-btn" class="cdb-btn-primary" style="padding:10px;">Generate Report</button>
          <div id="cdb-report-status" style="font-size:11px;color:#475569;text-align:center;"></div>
        </div>

        <div style="margin-top:16px;">
          <div class="cdb-section-heading">Available Templates</div>
          <div id="cdb-report-templates" style="display:flex;flex-direction:column;gap:5px;max-height:280px;overflow-y:auto;scrollbar-width:thin;">
            <div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Loading templates…</div>
          </div>
        </div>
      </div>

      <div>
        <div class="cdb-section-heading">Recent Reports</div>
        <div id="cdb-report-list" style="display:flex;flex-direction:column;gap:6px;max-height:480px;overflow-y:auto;scrollbar-width:thin;">
          <div style="text-align:center;padding:20px;color:#475569;font-size:12px;">
            Log in to view your report history.
          </div>
        </div>
      </div>
    </div>

    <div style="margin-top:16px;font-size:11px;color:#475569;text-align:center;">
      Reports generated from live platform data · HTML reports open in new tab · PDF: use browser Print → Save as PDF
    </div>
  `;

  const TYPE_LABELS = {
    SECURITY_POSTURE: 'Security Posture', BOARD: 'Board Report',
    MSSP: 'MSSP Report', CTI: 'Threat Intel', COMPLIANCE: 'Compliance', AI_SECURITY: 'AI Security',
  };
  const STATUS_COLORS = { QUEUED: '#64748b', GENERATING: '#eab308', READY: '#22c55e', FAILED: '#ef4444', DELIVERED: '#6366f1' };

  async function loadTemplates() {
    const el = document.getElementById('cdb-report-templates');
    if (!el) return;

    try {
      const resp = await fetch('/api/reports/templates', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const { templates } = await resp.json();

      el.innerHTML = templates.map(t => `
        <div class="cdb-feed-item" style="flex-wrap:wrap;gap:6px;cursor:pointer;" onclick="document.getElementById('cdb-report-type').value='${t.type}'">
          <div style="flex:1;">
            <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${t.name}</div>
            <div style="font-size:10px;color:#64748b;">${t.audience} · ${t.pages} pages</div>
          </div>
          <span style="font-size:10px;color:#475569;">${t.sections.length} sections</span>
        </div>
      `).join('');
    } catch (e) {
      if (el) el.innerHTML = '<div style="text-align:center;padding:12px;color:#475569;font-size:11px;">Log in to see available templates</div>';
    }
  }

  async function loadRecentReports() {
    const list = document.getElementById('cdb-report-list');
    if (!list) return;

    try {
      const resp = await fetch('/api/reports', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        if (resp.status === 401) {
          list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">🔐 Log in to view reports</div>';
        }
        return;
      }
      const { reports } = await resp.json();

      if (!reports?.length) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">No reports generated yet. Create your first report above.</div>';
        return;
      }

      list.innerHTML = reports.map(r => `
        <div class="cdb-feed-item" style="flex-wrap:wrap;gap:6px;">
          <div style="flex:1;">
            <div style="font-size:12px;font-weight:600;color:#e2e8f0;">${TYPE_LABELS[r.report_type] || r.report_type}</div>
            <div style="font-size:10px;color:#64748b;">${new Date(r.created_at).toLocaleString()}</div>
          </div>
          <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:9999px;background:${STATUS_COLORS[r.status] || '#64748b'}22;color:${STATUS_COLORS[r.status] || '#64748b'}">
            ${r.status}
          </span>
          ${r.status === 'READY' ? `<button onclick="openReport('${r.id}')" class="cdb-btn-primary" style="font-size:10px;padding:3px 10px;">Open</button>` : ''}
        </div>
      `).join('');

      window._cdbReportTokens = {};
      reports.forEach(r => { if (r.download_token) window._cdbReportTokens[r.id] = r.download_token; });
    } catch (e) {
      console.info(LOG, 'Reports load failed:', e.message);
    }
  }

  window.openReport = async function(jobId) {
    // First get the report to get its download token
    try {
      const resp = await fetch(`/api/reports/${jobId}`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const { report } = await resp.json();
      if (report.download_token) {
        window.open(`/api/reports/${jobId}/download?token=${report.download_token}`, '_blank');
      }
    } catch (e) {
      window.CDB_UX_TOAST?.('error', 'Cannot open report', e.message);
    }
  };

  async function generateReport() {
    const type   = document.getElementById('cdb-report-type')?.value || 'SECURITY_POSTURE';
    const format = document.getElementById('cdb-report-format')?.value || 'HTML';
    const status = document.getElementById('cdb-report-status');
    const btn    = document.getElementById('cdb-report-gen-btn');

    if (btn) btn.disabled = true;
    if (status) status.textContent = 'Generating report…';

    try {
      const resp = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, format }),
        signal: AbortSignal.timeout(15000),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        if (status) status.textContent = 'Error: ' + (err.error || resp.statusText);
        return;
      }

      const d = await resp.json();
      if (status) status.textContent = '✓ Report ready!';

      window.CDB_UX_TOAST?.('success', 'Report generated', TYPE_LABELS[type]);

      if (d.status === 'READY' && d.download_token) {
        window.open(`/api/reports/${d.job_id}/download?token=${d.download_token}`, '_blank');
      }

      setTimeout(loadRecentReports, 1000);
    } catch (e) {
      if (status) status.textContent = 'Failed: ' + e.message;
      window.CDB_UX_TOAST?.('error', 'Report failed', e.message);
    } finally {
      if (btn) { btn.disabled = false; setTimeout(() => { if (status) status.textContent = ''; }, 4000); }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
