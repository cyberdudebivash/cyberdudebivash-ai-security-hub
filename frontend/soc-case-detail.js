/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * SOC Case Detail — Full Investigation Panel
 *
 * Self-injecting IIFE. Adds "Investigation" tab to .cdb-cc-nav.
 * Provides full case investigation UX: timeline, evidence vault, analyst notes,
 * escalation, and resolution — all backed by the Phase 4 /api/soc/inv/* endpoints.
 *
 * Never touches socCases.js or the existing SOC Cases tab.
 */
(function () {
  'use strict';

  const MODULE_ID = 'cdb-p4-soc-investigation';
  const TAB_ID    = 'cdb-p4-soc-inv-tab';
  const PANEL_ID  = 'cdb-p4-soc-inv-panel';

  let activeCaseId   = null;
  let activeSubView  = 'timeline';

  // ── Inject ──────────────────────────────────────────────────────────────────
  function inject() {
    if (document.getElementById(MODULE_ID)) return;

    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }

    const tab = document.createElement('button');
    tab.id          = TAB_ID;
    tab.className   = 'cdb-cc-nav-btn';
    tab.textContent = '🔬 Investigation';
    tab.addEventListener('click', activateTab);
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id        = PANEL_ID;
    panel.className = 'cdb-cc-panel';
    panel.style.display = 'none';
    panel.innerHTML = buildShell();
    body.appendChild(panel);

    const sentinel = document.createElement('div');
    sentinel.id    = MODULE_ID;
    sentinel.style.display = 'none';
    document.body.appendChild(sentinel);

    // Wire up global case-selection hook
    window._socInvOpen = openCase;
  }

  function activateTab() {
    document.querySelectorAll('.cdb-cc-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.cdb-cc-panel').forEach(p => { p.style.display = 'none'; });
    document.getElementById(TAB_ID).classList.add('active');
    document.getElementById(PANEL_ID).style.display = 'block';
    if (!activeCaseId) renderCaseSearch();
  }

  // ── Shell ───────────────────────────────────────────────────────────────────
  function buildShell() {
    return `
      <div style="padding:20px;font-family:system-ui,sans-serif;height:100%;display:flex;flex-direction:column;gap:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <h2 style="margin:0;font-size:18px;font-weight:700;color:var(--cdb-text,#f1f5f9);">🔬 SOC Investigation</h2>
            <p id="soc-inv-subtitle" style="margin:4px 0 0;font-size:12px;color:var(--cdb-muted,#94a3b8);">Select a case to investigate</p>
          </div>
          <button id="soc-inv-back" onclick="window._socInvBack()" style="display:none;background:rgba(255,255,255,.08);color:var(--cdb-text,#f1f5f9);border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;">← Back</button>
        </div>

        <!-- Case search -->
        <div id="soc-inv-search-area">
          <div style="display:flex;gap:8px;margin-bottom:12px;">
            <input id="soc-inv-case-input" placeholder="Enter Case ID (e.g. case_abc123)" style="flex:1;padding:8px 12px;background:var(--cdb-input,rgba(255,255,255,.08));border:1px solid rgba(255,255,255,.12);border-radius:6px;color:var(--cdb-text,#f1f5f9);font-size:13px;outline:none;" />
            <button onclick="window._socInvLoad()" style="background:#3b82f6;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:13px;">Load Case</button>
          </div>
          <div id="soc-inv-hint" style="font-size:12px;color:var(--cdb-muted,#64748b);">💡 Tip: Open a case from the SOC Cases tab, then click "Investigate" to populate this field automatically.</div>
        </div>

        <!-- Investigation content -->
        <div id="soc-inv-content" style="display:none;flex:1;overflow:auto;">
          <!-- Case header -->
          <div id="soc-inv-case-header" style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:14px;margin-bottom:14px;"></div>

          <!-- Sub-nav -->
          <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;">
            <button class="soc-inv-sub-btn active" data-view="timeline" onclick="window._socInvView('timeline')">📅 Timeline</button>
            <button class="soc-inv-sub-btn" data-view="evidence" onclick="window._socInvView('evidence')">🗂 Evidence</button>
            <button class="soc-inv-sub-btn" data-view="notes" onclick="window._socInvView('notes')">📝 Notes</button>
            <button class="soc-inv-sub-btn" data-view="actions" onclick="window._socInvView('actions')">⚡ Actions</button>
          </div>

          <!-- Sub-view content -->
          <div id="soc-inv-subview"></div>
        </div>
      </div>`;
  }

  // ── Sub-nav styling ─────────────────────────────────────────────────────────
  function styleSubBtns() {
    document.querySelectorAll('.soc-inv-sub-btn').forEach(b => {
      b.style.cssText = `background:${b.classList.contains('active') ? 'rgba(59,130,246,.2)' : 'rgba(255,255,255,.06)'};color:${b.classList.contains('active') ? '#3b82f6' : 'var(--cdb-text,#94a3b8)'};border:1px solid ${b.classList.contains('active') ? 'rgba(59,130,246,.4)' : 'rgba(255,255,255,.08)'};border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px;`;
    });
  }

  // ── Open / load a case ──────────────────────────────────────────────────────
  async function openCase(caseId) {
    activeCaseId = caseId;
    document.getElementById('soc-inv-case-input').value = caseId;
    await loadSummary(caseId);
  }

  async function loadSummary(caseId) {
    const content = document.getElementById('soc-inv-content');
    const search  = document.getElementById('soc-inv-search-area');
    const header  = document.getElementById('soc-inv-case-header');
    const subtitle = document.getElementById('soc-inv-subtitle');
    const backBtn = document.getElementById('soc-inv-back');

    content.style.display = 'none';
    header.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;">Loading…</div>';

    try {
      const res  = await fetch(`/api/soc/inv/${caseId}/summary`, { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');

      const c = data.case;
      const inv = data.investigation;

      subtitle.textContent = `Case: ${c.case_number || caseId}`;
      backBtn.style.display = 'block';

      const sevColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e' };
      const statColor = { OPEN: '#3b82f6', INVESTIGATING: '#f59e0b', ESCALATED: '#ef4444', RESOLVED: '#22c55e', CLOSED: '#6b7280' };

      header.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
          <div>
            <div style="font-size:15px;font-weight:700;color:var(--cdb-text,#f1f5f9);">${escHtml(c.title || caseId)}</div>
            <div style="font-size:12px;color:var(--cdb-muted,#94a3b8);margin-top:4px;">${escHtml(c.case_number || '')}</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <span style="font-size:11px;padding:3px 8px;border-radius:999px;background:rgba(239,68,68,.15);color:${sevColor[c.severity] || '#f59e0b'};">${c.severity || '?'}</span>
            <span style="font-size:11px;padding:3px 8px;border-radius:999px;background:rgba(59,130,246,.12);color:${statColor[c.status] || '#94a3b8'};">${c.status || '?'}</span>
            ${inv.sla_breached ? '<span style="font-size:11px;padding:3px 8px;border-radius:999px;background:rgba(239,68,68,.2);color:#ef4444;">⚠ SLA BREACHED</span>' : ''}
            ${inv.sla_hours_remaining != null && !inv.sla_breached ? `<span style="font-size:11px;padding:3px 8px;border-radius:999px;background:rgba(34,197,94,.12);color:#22c55e;">${inv.sla_hours_remaining}h SLA remaining</span>` : ''}
          </div>
        </div>
        <div style="display:flex;gap:16px;margin-top:12px;">
          ${stat('📅 Timeline', inv.timeline_events)}
          ${stat('🗂 Evidence',  inv.evidence_count)}
          ${stat('📝 Notes',     inv.notes_count)}
        </div>`;

      content.style.display = 'block';
      search.style.display  = 'none';
      switchSubView('timeline');

    } catch (e) {
      header.innerHTML = `<div style="color:#ef4444;font-size:13px;">Error: ${escHtml(e.message)}</div>`;
      content.style.display = 'block';
      search.style.display  = 'none';
    }
  }

  function stat(label, val) {
    return `<div style="text-align:center;min-width:70px;"><div style="font-size:18px;font-weight:700;color:var(--cdb-text,#f1f5f9);">${val}</div><div style="font-size:11px;color:var(--cdb-muted,#94a3b8);">${label}</div></div>`;
  }

  // ── Sub-view router ─────────────────────────────────────────────────────────
  function switchSubView(view) {
    activeSubView = view;
    document.querySelectorAll('.soc-inv-sub-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.view === view);
    });
    styleSubBtns();
    const el = document.getElementById('soc-inv-subview');
    el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:12px;">Loading…</div>';

    if (view === 'timeline') loadTimeline();
    else if (view === 'evidence') loadEvidence();
    else if (view === 'notes')    loadNotes();
    else if (view === 'actions')  renderActions();
  }

  // ── Timeline ────────────────────────────────────────────────────────────────
  async function loadTimeline() {
    const el = document.getElementById('soc-inv-subview');
    try {
      const res  = await fetch(`/api/soc/inv/${activeCaseId}/timeline`, { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();
      if (!data.timeline?.length) { el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:12px;">No timeline events yet.</div>'; return; }

      el.innerHTML = `<div style="position:relative;padding-left:20px;border-left:2px solid rgba(255,255,255,.1);">
        ${data.timeline.map(e => `
          <div style="position:relative;margin-bottom:16px;">
            <div style="position:absolute;left:-25px;top:4px;width:10px;height:10px;border-radius:50%;background:#3b82f6;border:2px solid #1e3a5f;"></div>
            <div style="font-size:12px;font-weight:600;color:var(--cdb-text,#f1f5f9);">${escHtml(e.event_type)}</div>
            <div style="font-size:12px;color:var(--cdb-muted,#94a3b8);margin-top:2px;">${escHtml(e.description)}</div>
            <div style="font-size:10px;color:var(--cdb-muted,#64748b);margin-top:3px;">${fmtTime(e.occurred_at)}${e.actor ? ' · ' + escHtml(e.actor) : ''}</div>
            ${e.old_value && e.new_value ? `<div style="font-size:10px;color:#f59e0b;margin-top:2px;">${escHtml(e.old_value)} → ${escHtml(e.new_value)}</div>` : ''}
          </div>`).join('')}
      </div>`;
    } catch (e) {
      el.innerHTML = `<div style="color:#ef4444;font-size:13px;">${escHtml(e.message)}</div>`;
    }
  }

  // ── Evidence ────────────────────────────────────────────────────────────────
  async function loadEvidence() {
    const el = document.getElementById('soc-inv-subview');
    try {
      const res  = await fetch(`/api/soc/inv/${activeCaseId}/evidence`, { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();

      el.innerHTML = `
        <div style="margin-bottom:12px;display:flex;justify-content:flex-end;">
          <button onclick="window._socInvAddEvidence()" style="background:#22c55e;color:#000;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;">+ Add Evidence</button>
        </div>
        <div id="soc-inv-add-ev-form" style="display:none;background:var(--cdb-card,rgba(255,255,255,.06));border-radius:8px;padding:14px;margin-bottom:12px;">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
            <input id="ev-title" placeholder="Title*" style="${inputStyle()}" />
            <select id="ev-type" style="${inputStyle()}">
              ${['ARTIFACT','FILE','LOG','SCREENSHOT','NETWORK_CAPTURE','MEMORY_DUMP','IOC','NOTE','PCAP','REGISTRY'].map(t => `<option>${t}</option>`).join('')}
            </select>
          </div>
          <textarea id="ev-desc" placeholder="Description" rows="2" style="${inputStyle()}width:100%;resize:vertical;"></textarea>
          <div style="display:flex;gap:8px;margin-top:8px;justify-content:flex-end;">
            <button onclick="document.getElementById('soc-inv-add-ev-form').style.display='none'" style="${cancelBtnStyle()}">Cancel</button>
            <button onclick="window._socInvSubmitEvidence()" style="${submitBtnStyle()}">Add</button>
          </div>
        </div>
        ${!data.evidence?.length
          ? '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:12px;">No evidence attached yet.</div>'
          : data.evidence.map(e => `
            <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:8px;padding:12px;margin-bottom:8px;border:1px solid rgba(255,255,255,.06);">
              <div style="display:flex;justify-content:space-between;">
                <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);">${escHtml(e.title)}</div>
                <span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(99,102,241,.15);color:#818cf8;">${e.evidence_type}</span>
              </div>
              ${e.description ? `<div style="font-size:12px;color:var(--cdb-muted,#94a3b8);margin-top:4px;">${escHtml(e.description)}</div>` : ''}
              <div style="font-size:10px;color:var(--cdb-muted,#64748b);margin-top:6px;">${fmtTime(e.created_at)} · ${escHtml(e.added_by || '?')} · ${escHtml(e.source_system || 'MANUAL')}</div>
            </div>`).join('')}`;
    } catch (e) {
      el.innerHTML = `<div style="color:#ef4444;font-size:13px;">${escHtml(e.message)}</div>`;
    }
  }

  // ── Notes ───────────────────────────────────────────────────────────────────
  async function loadNotes() {
    const el = document.getElementById('soc-inv-subview');
    try {
      const res  = await fetch(`/api/soc/inv/${activeCaseId}/notes`, { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();

      const noteTypeColor = { ANALYST: '#3b82f6', ESCALATION: '#ef4444', RESOLUTION: '#22c55e', INTEL_UPDATE: '#8b5cf6', PLAYBOOK: '#f59e0b', AUTOMATED: '#6b7280', CLOSURE: '#6b7280' };

      el.innerHTML = `
        <div style="margin-bottom:12px;display:flex;justify-content:flex-end;">
          <button onclick="window._socInvAddNote()" style="background:#3b82f6;color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;">+ Add Note</button>
        </div>
        <div id="soc-inv-add-note-form" style="display:none;background:var(--cdb-card,rgba(255,255,255,.06));border-radius:8px;padding:14px;margin-bottom:12px;">
          <select id="note-type" style="${inputStyle()}margin-bottom:8px;">
            ${['ANALYST','INTEL_UPDATE','PLAYBOOK','ESCALATION','RESOLUTION','CLOSURE'].map(t => `<option>${t}</option>`).join('')}
          </select>
          <textarea id="note-content" placeholder="Note content*" rows="3" style="${inputStyle()}width:100%;resize:vertical;"></textarea>
          <div style="display:flex;gap:8px;margin-top:8px;justify-content:flex-end;">
            <button onclick="document.getElementById('soc-inv-add-note-form').style.display='none'" style="${cancelBtnStyle()}">Cancel</button>
            <button onclick="window._socInvSubmitNote()" style="${submitBtnStyle()}">Save Note</button>
          </div>
        </div>
        ${!data.notes?.length
          ? '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:12px;">No notes yet.</div>'
          : data.notes.map(n => `
            <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:8px;padding:12px;margin-bottom:8px;border-left:3px solid ${noteTypeColor[n.note_type] || '#6b7280'};">
              <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                <span style="font-size:10px;font-weight:600;color:${noteTypeColor[n.note_type] || '#94a3b8'};">${n.note_type}${n.is_pinned ? ' 📌' : ''}</span>
                <span style="font-size:10px;color:var(--cdb-muted,#64748b);">${fmtTime(n.created_at)} · ${escHtml(n.author)}</span>
              </div>
              <div style="font-size:13px;color:var(--cdb-text,#e2e8f0);line-height:1.5;">${escHtml(n.content)}</div>
            </div>`).join('')}`;
    } catch (e) {
      el.innerHTML = `<div style="color:#ef4444;font-size:13px;">${escHtml(e.message)}</div>`;
    }
  }

  // ── Actions panel ───────────────────────────────────────────────────────────
  function renderActions() {
    const el = document.getElementById('soc-inv-subview');
    el.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:12px;">
        <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:14px;">
          <div style="font-size:13px;font-weight:600;color:#ef4444;margin-bottom:8px;">🚨 Escalate Case</div>
          <input id="escalate-reason" placeholder="Escalation reason (optional)" style="${inputStyle()}margin-bottom:8px;" />
          <button onclick="window._socInvEscalate()" style="background:#ef4444;color:#fff;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:13px;font-weight:600;">Escalate Now</button>
        </div>
        <div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:14px;">
          <div style="font-size:13px;font-weight:600;color:#22c55e;margin-bottom:8px;">✅ Resolve Case</div>
          <textarea id="resolve-resolution" placeholder="Resolution summary (optional)" rows="2" style="${inputStyle()}width:100%;resize:vertical;margin-bottom:8px;"></textarea>
          <div style="display:flex;gap:8px;">
            <button onclick="window._socInvResolve(false)" style="background:#22c55e;color:#000;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:13px;font-weight:600;">Mark Resolved</button>
            <button onclick="window._socInvResolve(true)" style="background:rgba(34,197,94,.2);color:#22c55e;border:1px solid rgba(34,197,94,.3);border-radius:6px;padding:7px 16px;cursor:pointer;font-size:13px;">Resolve & Close</button>
          </div>
        </div>
      </div>`;
  }

  // ── Mutations ────────────────────────────────────────────────────────────────
  async function postAction(url, body) {
    const res = await fetch(url, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed');
    return data;
  }

  window._socInvLoad = async function () {
    const id = document.getElementById('soc-inv-case-input').value.trim();
    if (!id) return;
    activeCaseId = id;
    await loadSummary(id);
  };
  window._socInvBack = function () {
    activeCaseId = null;
    document.getElementById('soc-inv-content').style.display = 'none';
    document.getElementById('soc-inv-search-area').style.display = 'block';
    document.getElementById('soc-inv-back').style.display = 'none';
    document.getElementById('soc-inv-subtitle').textContent = 'Select a case to investigate';
  };
  window._socInvView  = switchSubView;
  window._socInvOpen  = openCase;
  window._socInvAddEvidence = () => { document.getElementById('soc-inv-add-ev-form').style.display = 'block'; };
  window._socInvAddNote     = () => { document.getElementById('soc-inv-add-note-form').style.display = 'block'; };

  window._socInvSubmitEvidence = async function () {
    const title = document.getElementById('ev-title').value.trim();
    const type  = document.getElementById('ev-type').value;
    const desc  = document.getElementById('ev-desc').value.trim();
    if (!title) return toast('error', 'Title required');
    try {
      await postAction(`/api/soc/inv/${activeCaseId}/evidence`, { title, evidence_type: type, description: desc });
      toast('success', 'Evidence added');
      document.getElementById('soc-inv-add-ev-form').style.display = 'none';
      loadEvidence();
    } catch (e) { toast('error', e.message); }
  };
  window._socInvSubmitNote = async function () {
    const content = document.getElementById('note-content').value.trim();
    const type    = document.getElementById('note-type').value;
    if (!content) return toast('error', 'Content required');
    try {
      await postAction(`/api/soc/inv/${activeCaseId}/notes`, { content, note_type: type });
      toast('success', 'Note saved');
      document.getElementById('soc-inv-add-note-form').style.display = 'none';
      loadNotes();
    } catch (e) { toast('error', e.message); }
  };
  window._socInvEscalate = async function () {
    const reason = document.getElementById('escalate-reason').value.trim();
    if (!confirm('Escalate this case?')) return;
    try {
      await postAction(`/api/soc/inv/${activeCaseId}/escalate`, { reason });
      toast('success', 'Case escalated');
      loadSummary(activeCaseId);
    } catch (e) { toast('error', e.message); }
  };
  window._socInvResolve = async function (close) {
    const resolution = document.getElementById('resolve-resolution')?.value?.trim();
    if (!confirm(close ? 'Resolve and close case?' : 'Mark case as resolved?')) return;
    try {
      await postAction(`/api/soc/inv/${activeCaseId}/resolve`, { resolution, close_after: close });
      toast('success', close ? 'Case closed' : 'Case resolved');
      loadSummary(activeCaseId);
    } catch (e) { toast('error', e.message); }
  };

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function renderCaseSearch() { /* already shown by default */ }

  function escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function fmtTime(s) {
    if (!s) return '';
    try { return new Date(s).toLocaleString(); } catch { return s; }
  }

  function inputStyle() {
    return 'display:block;width:100%;padding:7px 10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:var(--cdb-text,#f1f5f9);font-size:12px;outline:none;box-sizing:border-box;';
  }
  function submitBtnStyle() { return 'background:#3b82f6;color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;'; }
  function cancelBtnStyle()  { return 'background:rgba(255,255,255,.06);color:var(--cdb-muted,#94a3b8);border:1px solid rgba(255,255,255,.1);border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px;'; }

  function toast(type, msg) {
    if (typeof window.CDB_UX_TOAST === 'function') {
      window.CDB_UX_TOAST(type, type === 'error' ? 'Error' : 'Success', msg);
    } else {
      console[type === 'error' ? 'error' : 'log']('[SOC Investigation]', msg);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
