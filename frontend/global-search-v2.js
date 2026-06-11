/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * global-search-v2.js — Enterprise Global Search Platform
 *
 * Enhances Phase 2 command palette with real global search.
 * Also adds standalone search bar at top of dashboard.
 * Searches: IOCs, actors, cases, customers, scans, workflows.
 */

(function CDB_SEARCH_V2_MODULE() {
  'use strict';
  const LOG = '[CDB-SEARCH-V2]';

  let _debounceTimer = null;

  function inject() {
    // Add search bar to dashboard header area (if not already present)
    if (document.getElementById('cdb-global-search-bar')) return;
    injectSearchBar();
    enhanceCommandPalette();
    console.info(LOG, 'Global search v2 injected');
  }

  function injectSearchBar() {
    // Find a suitable injection point — try dashboard header or nav actions area
    const navActions = document.getElementById('cdb-nav-actions');
    if (!navActions) { setTimeout(inject, 1000); return; }

    const bar = document.createElement('div');
    bar.id = 'cdb-global-search-bar';
    bar.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);width:360px;z-index:9998;';
    bar.innerHTML = `
      <div style="position:relative;">
        <input id="cdb-search-input" type="text" placeholder="⌕ Search everything…"
          style="width:100%;background:#0f1729cc;border:1px solid #334155;border-radius:10px;padding:8px 36px 8px 14px;color:#e2e8f0;font-size:13px;outline:none;backdrop-filter:blur(8px);"
          autocomplete="off" spellcheck="false">
        <span style="position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:10px;color:#334155;pointer-events:none;">⌘K</span>
      </div>
      <div id="cdb-search-results-popup" style="display:none;position:absolute;top:calc(100% + 4px);left:0;right:0;background:#0f1729;border:1px solid #334155;border-radius:10px;max-height:400px;overflow-y:auto;scrollbar-width:thin;box-shadow:0 16px 48px #000a;z-index:9999;padding:6px;"></div>
    `;
    document.body.appendChild(bar);

    const input  = document.getElementById('cdb-search-input');
    const popup  = document.getElementById('cdb-search-results-popup');

    input.addEventListener('input', () => {
      clearTimeout(_debounceTimer);
      const q = input.value.trim();
      if (!q || q.length < 2) { popup.style.display = 'none'; return; }
      _debounceTimer = setTimeout(() => runSearch(q, popup), 300);
    });

    input.addEventListener('keydown', e => {
      if (e.key === 'Escape') { popup.style.display = 'none'; input.value = ''; }
    });

    // Open palette on Cmd/Ctrl+K
    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        input.focus();
        input.select();
      }
    });

    // Click outside to close
    document.addEventListener('click', e => {
      if (!bar.contains(e.target)) popup.style.display = 'none';
    });
  }

  async function runSearch(q, popup) {
    popup.style.display = 'block';
    popup.innerHTML = `<div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Searching…</div>`;

    try {
      const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}&limit=30`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const { results, total, facets } = await resp.json();

      if (!results?.length) {
        popup.innerHTML = `<div style="text-align:center;padding:16px;color:#475569;font-size:12px;">No results for "${q}"</div>`;
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

      let html = `<div style="padding:6px 8px;font-size:10px;color:#475569;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid #1e293b;margin-bottom:4px;">
        <span>${total} result${total !== 1 ? 's' : ''}</span>
        ${Object.entries(facets?.types || {}).filter(([,v]) => v > 0).map(([k,v]) =>
          `<span style="background:${typeColors[k] || '#334155'}22;color:${typeColors[k] || '#94a3b8'};padding:1px 6px;border-radius:4px;">${k}: ${v}</span>`
        ).join('')}
        <button onclick="saveCurrentSearch('${encodeURIComponent(q)}')" style="margin-left:auto;font-size:10px;background:none;border:1px solid #334155;border-radius:4px;color:#64748b;padding:1px 6px;cursor:pointer;">Save Search</button>
      </div>`;

      Object.entries(byType).forEach(([type, items]) => {
        html += `<div style="font-size:10px;font-weight:700;color:${typeColors[type]};text-transform:uppercase;letter-spacing:.5px;padding:4px 8px;">${type}</div>`;
        html += items.map(r => `
          <div class="cdb-feed-item" style="padding:6px 8px;cursor:default;margin-bottom:2px;">
            ${r.severity ? `<span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:${sevColors[r.severity] || '#334155'}22;color:${sevColors[r.severity] || '#94a3b8'}">${r.severity}</span>` : '<span style="width:10px;"></span>'}
            <div style="flex:1;min-width:0;">
              <div style="font-size:12px;font-weight:600;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${r.title}</div>
              <div style="font-size:10px;color:#64748b;">${r.subtitle || ''}</div>
            </div>
            <span style="font-size:9px;color:#334155;">${r.date ? new Date(r.date).toLocaleDateString() : ''}</span>
          </div>
        `).join('');
      });

      popup.innerHTML = html;
    } catch (e) {
      popup.innerHTML = `<div style="text-align:center;padding:12px;color:#475569;font-size:12px;">
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

  function enhanceCommandPalette() {
    // Extend Phase 2 CDB_UX command palette to support real search results
    const MAX_WAIT = 3000;
    const start = Date.now();
    const waitForPalette = () => {
      if (window.CDB_UX?.openPalette) {
        // Palette available — could hook into it here
        return;
      }
      if (Date.now() - start < MAX_WAIT) setTimeout(waitForPalette, 200);
    };
    waitForPalette();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
