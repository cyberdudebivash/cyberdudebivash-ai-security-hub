/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3 (revised for go-live)
 * global-search-v2.js — Enterprise Global Search Platform
 *
 * Command-palette-style search: hidden by default, opened via the nav search
 * trigger (#cdb-search-trigger) or Cmd/Ctrl+K, closed via Escape or backdrop
 * click. Searches: IOCs, actors, cases, customers, scans, workflows.
 *
 * Presented as a centered modal (matching this page's existing modal
 * pattern — see #ds-modal, #custom-solution-modal) rather than a permanently
 * docked bar: the top of this page is already occupied by the live ticker,
 * status rows, and main nav, so an always-visible fixed bar would overlap it.
 */

(function CDB_SEARCH_V2_MODULE() {
  'use strict';
  const LOG = '[CDB-SEARCH-V2]';

  let _debounceTimer = null;
  let _modal = null, _input = null, _popup = null;

  function inject() {
    if (document.getElementById('cdb-search-modal')) return;
    buildModal();
    wireTrigger();
    wireKeyboardShortcut();
    console.info(LOG, 'Global search v2 ready');
  }

  function buildModal() {
    const modal = document.createElement('div');
    modal.id = 'cdb-search-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', 'Global search');
    modal.style.cssText = 'display:none;position:fixed;inset:0;z-index:9995;background:rgba(0,0,0,.75);backdrop-filter:blur(4px);align-items:flex-start;justify-content:center;padding:12vh 20px 20px';
    modal.innerHTML = `
      <div style="width:100%;max-width:560px;background:var(--surface,#0f0f2e);border:1px solid var(--border,#1e1e4a);border-radius:var(--radius,12px);box-shadow:0 24px 64px rgba(0,0,0,.6);overflow:hidden">
        <div style="position:relative;border-bottom:1px solid var(--border,#1e1e4a)">
          <input id="cdb-search-input" type="text" placeholder="Search IOCs, actors, cases, scans, workflows…"
            style="width:100%;background:transparent;border:none;padding:16px 44px 16px 18px;color:var(--text,#e2e8f0);font-size:15px;outline:none;box-sizing:border-box"
            autocomplete="off" spellcheck="false">
          <span style="position:absolute;right:16px;top:50%;transform:translateY(-50%);font-size:10px;color:var(--text-dim,#64748b);pointer-events:none">ESC</span>
        </div>
        <div id="cdb-search-results-popup" style="max-height:min(60vh,420px);overflow-y:auto;padding:6px"></div>
      </div>
    `;
    document.body.appendChild(modal);

    _modal = modal;
    _input = modal.querySelector('#cdb-search-input');
    _popup = modal.querySelector('#cdb-search-results-popup');
    showPlaceholder();

    _input.addEventListener('input', () => {
      clearTimeout(_debounceTimer);
      const q = _input.value.trim();
      if (!q || q.length < 2) { showPlaceholder(); return; }
      _debounceTimer = setTimeout(() => runSearch(q, _popup), 300);
    });

    modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal.style.display !== 'none') closeModal();
    });
  }

  function showPlaceholder() {
    _popup.innerHTML = `<div style="text-align:center;padding:20px 12px;color:var(--text-dim,#64748b);font-size:12px">Type at least 2 characters…</div>`;
  }

  function openModal() {
    if (!_modal) return;
    _modal.style.display = 'flex';
    _input.value = '';
    showPlaceholder();
    _input.focus();
  }

  function closeModal() {
    if (!_modal) return;
    _modal.style.display = 'none';
  }

  // Exposed so the static nav trigger button (and any other future entry
  // point) can open the palette without needing to know its internals.
  window.CDB_SEARCH_V2_OPEN = openModal;

  function wireTrigger() {
    const trigger = document.getElementById('cdb-search-trigger');
    if (trigger) trigger.addEventListener('click', openModal);
  }

  function wireKeyboardShortcut() {
    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        openModal();
      }
    });
  }

  async function runSearch(q, popup) {
    popup.innerHTML = `<div style="text-align:center;padding:12px;color:var(--text-dim,#64748b);font-size:12px;">Searching…</div>`;

    try {
      const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}&limit=30`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const { results, total, facets } = await resp.json();

      if (!results?.length) {
        popup.innerHTML = `<div style="text-align:center;padding:16px;color:var(--text-dim,#64748b);font-size:12px;">No results for "${q}"</div>`;
        return;
      }

      const sevColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', INFO: '#64748b' };
      const typeColors = {
        ioc: '#ef4444', actor: '#f97316', case: '#6366f1',
        customer: '#22c55e', scan: '#0ea5e9', workflow: '#a855f7',
      };

      // Group by type
      const byType = {};
      results.forEach(r => { (byType[r.type] = byType[r.type] || []).push(r); });

      let html = `<div style="padding:6px 8px;font-size:10px;color:var(--text-dim,#64748b);display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border,#1e293b);margin-bottom:4px;">
        <span>${total} result${total !== 1 ? 's' : ''}</span>
        ${Object.entries(facets?.types || {}).filter(([,v]) => v > 0).map(([k,v]) =>
          `<span style="background:${typeColors[k] || '#334155'}22;color:${typeColors[k] || '#94a3b8'};padding:1px 6px;border-radius:4px;">${k}: ${v}</span>`
        ).join('')}
        <button onclick="saveCurrentSearch('${encodeURIComponent(q)}')" style="margin-left:auto;font-size:10px;background:none;border:1px solid var(--border,#334155);border-radius:4px;color:var(--text-dim,#64748b);padding:1px 6px;cursor:pointer;">Save Search</button>
      </div>`;

      Object.entries(byType).forEach(([type, items]) => {
        html += `<div style="font-size:10px;font-weight:700;color:${typeColors[type]};text-transform:uppercase;letter-spacing:.5px;padding:4px 8px;">${type}</div>`;
        html += items.map(r => `
          <div class="cdb-feed-item" style="padding:6px 8px;cursor:default;margin-bottom:2px;display:flex;align-items:center;gap:8px;">
            ${r.severity ? `<span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:${sevColors[r.severity] || '#334155'}22;color:${sevColors[r.severity] || '#94a3b8'}">${r.severity}</span>` : '<span style="width:10px;"></span>'}
            <div style="flex:1;min-width:0;">
              <div style="font-size:12px;font-weight:600;color:var(--text,#e2e8f0);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${r.title}</div>
              <div style="font-size:10px;color:var(--text-dim,#64748b);">${r.subtitle || ''}</div>
            </div>
            <span style="font-size:9px;color:var(--text-dim,#64748b);">${r.date ? new Date(r.date).toLocaleDateString() : ''}</span>
          </div>
        `).join('');
      });

      popup.innerHTML = html;
    } catch (e) {
      popup.innerHTML = `<div style="text-align:center;padding:12px;color:var(--text-dim,#64748b);font-size:12px;">
        ${e.message.includes('401') ? '🔐 Log in to search the platform' : 'Search unavailable: ' + e.message}
      </div>`;
    }
  }

  window.saveCurrentSearch = async function(encodedQ) {
    const q = decodeURIComponent(encodedQ);
    const name = window.prompt(`Save search as:`, q.slice(0, 40));
    if (!name?.trim()) return;

    try {
      const resp = await fetch('/api/search/saved', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), query: q }),
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        window.CDB_UX_TOAST?.('success', 'Search saved', name.trim());
      }
    } catch (e) {
      window.CDB_UX_TOAST?.('error', 'Save failed', e.message);
    }
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
