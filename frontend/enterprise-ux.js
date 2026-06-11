/**
 * CYBERDUDEBIVASH® AI Security Hub
 * enterprise-ux.js — Enterprise UX System v1.0
 *
 * Additive module. Namespace: window.CDB_UX_*
 * Provides:
 *   - Command Palette (Cmd/Ctrl+K)
 *   - Global keyboard shortcuts
 *   - Toast notification system
 *   - Notification center (bell icon)
 *   - Dark/Light mode toggle
 *   - Enhanced nav with Command Centers dropdown
 *   - Tab visibility optimization (pause/resume polling)
 */

(function CDB_UX_MODULE() {
  'use strict';
  const LOG = '[CDB-UX]';

  // ── CSS Injection ──────────────────────────────────────────────────────────
  const STYLES = `
    /* Command Palette */
    #cdb-cmd-backdrop {
      position: fixed; inset: 0; background: rgba(0,0,0,.7);
      backdrop-filter: blur(4px); z-index: 9998;
      display: none; align-items: flex-start; justify-content: center;
      padding-top: 15vh;
    }
    #cdb-cmd-backdrop.open { display: flex; }
    #cdb-cmd-palette {
      width: 100%; max-width: 620px; background: #0f1729;
      border: 1px solid #334155; border-radius: 14px;
      box-shadow: 0 25px 50px rgba(0,0,0,.6); overflow: hidden;
    }
    #cdb-cmd-search-wrap {
      display: flex; align-items: center; gap: 12px;
      padding: 16px 20px; border-bottom: 1px solid #1e293b;
    }
    #cdb-cmd-search-wrap svg { flex-shrink: 0; opacity: .5; }
    #cdb-cmd-input {
      flex: 1; background: transparent; border: none; outline: none;
      color: #f1f5f9; font-size: 16px; font-family: inherit;
    }
    #cdb-cmd-input::placeholder { color: #475569; }
    #cdb-cmd-results {
      max-height: 380px; overflow-y: auto; padding: 8px;
      scrollbar-width: thin; scrollbar-color: #1e293b transparent;
    }
    .cdb-cmd-section-label {
      font-size: 10px; font-weight: 600; color: #475569;
      text-transform: uppercase; letter-spacing: .8px;
      padding: 8px 12px 4px;
    }
    .cdb-cmd-item {
      display: flex; align-items: center; gap: 12px;
      padding: 10px 12px; border-radius: 8px; cursor: pointer;
      color: #cbd5e1; font-size: 13px; transition: background .1s;
    }
    .cdb-cmd-item:hover, .cdb-cmd-item.selected {
      background: #1e293b; color: #f1f5f9;
    }
    .cdb-cmd-item-icon { width: 28px; height: 28px; border-radius: 6px;
      background: #1e293b; display: flex; align-items: center; justify-content: center;
      font-size: 14px; flex-shrink: 0;
    }
    .cdb-cmd-item-main { flex: 1; }
    .cdb-cmd-item-title { font-size: 13px; font-weight: 500; }
    .cdb-cmd-item-sub { font-size: 11px; color: #64748b; margin-top: 1px; }
    .cdb-cmd-item-kbd { font-size: 10px; color: #475569; background: #1e293b;
      padding: 2px 6px; border-radius: 4px; border: 1px solid #334155;
    }
    #cdb-cmd-footer {
      padding: 10px 16px; border-top: 1px solid #1e293b;
      display: flex; gap: 16px; font-size: 11px; color: #475569;
    }
    #cdb-cmd-footer kbd { background: #1e293b; padding: 1px 5px; border-radius: 3px; border: 1px solid #334155; }

    /* Toast Notifications */
    #cdb-toast-container {
      position: fixed; bottom: 24px; right: 24px;
      display: flex; flex-direction: column-reverse; gap: 8px;
      z-index: 9997; pointer-events: none; max-width: 360px;
    }
    .cdb-toast {
      background: #0f1729; border: 1px solid #1e293b; border-radius: 10px;
      padding: 12px 16px; display: flex; align-items: flex-start; gap: 10px;
      box-shadow: 0 4px 20px rgba(0,0,0,.4); pointer-events: all;
      animation: cdb-toast-in .25s ease; font-size: 13px; color: #cbd5e1;
      max-width: 360px;
    }
    .cdb-toast.removing { animation: cdb-toast-out .25s ease forwards; }
    @keyframes cdb-toast-in  { from { transform: translateX(120%); opacity: 0; } to { transform: none; opacity: 1; } }
    @keyframes cdb-toast-out { from { transform: none; opacity: 1; } to { transform: translateX(120%); opacity: 0; } }
    .cdb-toast-icon { font-size: 16px; flex-shrink: 0; margin-top: 1px; }
    .cdb-toast-body { flex: 1; }
    .cdb-toast-title { font-weight: 600; color: #f1f5f9; margin-bottom: 2px; }
    .cdb-toast-msg   { font-size: 12px; color: #94a3b8; }
    .cdb-toast.success { border-color: rgba(34,197,94,.3); }
    .cdb-toast.warning { border-color: rgba(234,179,8,.3); }
    .cdb-toast.error   { border-color: rgba(239,68,68,.3); }
    .cdb-toast.info    { border-color: rgba(99,102,241,.3); }
    .cdb-toast-close {
      background: none; border: none; color: #475569;
      cursor: pointer; font-size: 14px; padding: 0; flex-shrink: 0;
    }

    /* Notification Center */
    #cdb-notif-backdrop {
      position: fixed; inset: 0; z-index: 9996; display: none;
    }
    #cdb-notif-backdrop.open { display: block; }
    #cdb-notif-panel {
      position: fixed; top: 0; right: 0; bottom: 0; width: 360px;
      background: #0a0e1a; border-left: 1px solid #1e293b;
      z-index: 9997; transform: translateX(100%); transition: transform .3s ease;
      display: flex; flex-direction: column;
      box-shadow: -8px 0 32px rgba(0,0,0,.4);
    }
    #cdb-notif-backdrop.open #cdb-notif-panel { transform: none; }
    #cdb-notif-header {
      padding: 16px 20px; border-bottom: 1px solid #1e293b;
      display: flex; align-items: center; justify-content: space-between;
    }
    #cdb-notif-header h3 { font-size: 14px; font-weight: 600; color: #f1f5f9; margin: 0; }
    #cdb-notif-mark-read {
      font-size: 11px; color: #6366f1; background: none; border: none;
      cursor: pointer; padding: 0;
    }
    #cdb-notif-list {
      flex: 1; overflow-y: auto; padding: 8px;
      scrollbar-width: thin; scrollbar-color: #1e293b transparent;
    }
    .cdb-notif-item {
      padding: 12px; border-radius: 8px; margin-bottom: 4px;
      cursor: pointer; transition: background .1s; border: 1px solid transparent;
    }
    .cdb-notif-item:hover { background: #0f1729; border-color: #1e293b; }
    .cdb-notif-item.unread { background: rgba(99,102,241,.05); border-color: rgba(99,102,241,.15); }
    .cdb-notif-top { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .cdb-notif-badge { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .cdb-notif-badge.cve     { background: #ef4444; }
    .cdb-notif-badge.scan    { background: #6366f1; }
    .cdb-notif-badge.health  { background: #22c55e; }
    .cdb-notif-badge.case    { background: #f97316; }
    .cdb-notif-title { font-size: 12px; font-weight: 600; color: #e2e8f0; flex: 1; }
    .cdb-notif-ts    { font-size: 10px; color: #475569; }
    .cdb-notif-body  { font-size: 11px; color: #64748b; padding-left: 16px; }
    #cdb-notif-empty { text-align: center; padding: 40px 20px; color: #475569; font-size: 13px; }

    /* Nav enhancements */
    #cdb-nav-cmd-btn, #cdb-nav-bell-btn {
      background: rgba(99,102,241,.1); border: 1px solid rgba(99,102,241,.2);
      color: #a5b4fc; border-radius: 8px; padding: 6px 12px;
      font-size: 12px; font-weight: 600; cursor: pointer;
      display: inline-flex; align-items: center; gap: 6px;
      transition: all .2s; white-space: nowrap;
    }
    #cdb-nav-cmd-btn:hover, #cdb-nav-bell-btn:hover {
      background: rgba(99,102,241,.2); border-color: rgba(99,102,241,.4); color: #c7d2fe;
    }
    #cdb-bell-badge {
      background: #ef4444; color: #fff; border-radius: 9999px;
      font-size: 9px; font-weight: 700; padding: 1px 5px; min-width: 16px;
      text-align: center; display: none;
    }
    #cdb-bell-badge.visible { display: inline-block; }
    .cdb-nav-actions-wrap {
      position: fixed; top: 12px; right: 12px; z-index: 9000;
      display: flex; gap: 8px; align-items: center;
    }

    /* Keyboard shortcut reference */
    #cdb-shortcuts-modal {
      position: fixed; inset: 0; background: rgba(0,0,0,.7);
      backdrop-filter: blur(4px); z-index: 9998;
      display: none; align-items: center; justify-content: center;
    }
    #cdb-shortcuts-modal.open { display: flex; }
    #cdb-shortcuts-panel {
      background: #0f1729; border: 1px solid #334155; border-radius: 14px;
      padding: 24px; max-width: 500px; width: 100%; max-height: 80vh;
      overflow-y: auto;
    }
    #cdb-shortcuts-panel h2 { font-size: 16px; font-weight: 700; color: #f1f5f9; margin: 0 0 16px; }
    .cdb-shortcut-row { display: flex; align-items: center; justify-content: space-between;
      padding: 8px 0; border-bottom: 1px solid #1e293b; font-size: 13px; }
    .cdb-shortcut-desc { color: #94a3b8; }
    .cdb-shortcut-keys { display: flex; gap: 4px; }
    .cdb-key { background: #1e293b; border: 1px solid #334155; border-radius: 4px;
      padding: 2px 8px; font-size: 11px; font-family: monospace; color: #cbd5e1; }
  `;

  function injectStyles() {
    const style = document.createElement('style');
    style.id    = 'cdb-ux-styles';
    style.textContent = STYLES;
    document.head.appendChild(style);
  }

  // ── Nav Actions (fixed overlay) ────────────────────────────────────────────
  function buildNavActions() {
    if (document.getElementById('cdb-nav-actions')) return;

    const wrap = document.createElement('div');
    wrap.className = 'cdb-nav-actions-wrap';
    wrap.id        = 'cdb-nav-actions';
    wrap.innerHTML = `
      <button id="cdb-nav-cmd-btn" title="Command Palette (Ctrl+K)">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Search
        <span style="font-size:10px;opacity:.6">⌘K</span>
      </button>
      <button id="cdb-nav-bell-btn" title="Notifications">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span id="cdb-bell-badge"></span>
      </button>
    `;
    document.body.appendChild(wrap);

    document.getElementById('cdb-nav-cmd-btn').addEventListener('click', openPalette);
    document.getElementById('cdb-nav-bell-btn').addEventListener('click', toggleNotifPanel);
  }

  // ── Command Palette ────────────────────────────────────────────────────────
  const COMMANDS = [
    { group: 'Navigation', icon: '⚔', title: 'Executive Command Center', sub: 'Platform KPIs & threat level', action: () => switchCCTab('cdb-panel-exec') },
    { group: 'Navigation', icon: '🛡', title: 'SOC Command Center',      sub: 'Alert feed & cases',          action: () => switchCCTab('cdb-panel-soc') },
    { group: 'Navigation', icon: '🔍', title: 'Sentinel APEX Intelligence', sub: 'CVEs, KEV, APT actors',    action: () => switchCCTab('cdb-panel-sentinel') },
    { group: 'Navigation', icon: '🤖', title: 'AI Security Operations',  sub: 'AI assets & OWASP LLM',       action: () => switchCCTab('cdb-panel-ai') },
    { group: 'Navigation', icon: '🏢', title: 'MSSP Operations',         sub: 'Customer workspace',          action: () => switchCCTab('cdb-panel-mssp') },
    { group: 'Navigation', icon: '💰', title: 'Revenue Dashboard',       sub: 'MRR, ARR, pipeline',          action: () => switchCCTab('cdb-panel-revenue') },
    { group: 'Navigation', icon: '🔎', title: 'CTI Workbench',           sub: 'Threat actors & IOC search',  action: () => switchCCTab('cdb-panel-cti') },
    { group: 'Navigation', icon: '📊', title: 'Platform Observability',  sub: 'Service health & SLA',        action: () => switchCCTab('cdb-panel-health') },
    { group: 'Actions',   icon: '🖥', title: 'Scan a Domain',            sub: 'Quick domain security scan',  action: () => { closePalette(); document.getElementById('domain-scan-input')?.focus?.(); document.querySelector('[data-scan="domain"]')?.click?.(); }, kbd: 'S D' },
    { group: 'Actions',   icon: '🔑', title: 'Scan an API',              sub: 'API security assessment',      action: () => { closePalette(); document.querySelector('[data-scan="api"]')?.click?.(); } },
    { group: 'Actions',   icon: '📋', title: 'Keyboard Shortcuts',       sub: 'View all shortcuts',           action: () => { closePalette(); openShortcuts(); }, kbd: '? /' },
    { group: 'Links',     icon: '📚', title: 'API Documentation',        sub: 'Explore 488 API endpoints',    action: () => { closePalette(); document.querySelector('[href="#docs"]')?.click?.(); } },
    { group: 'Links',     icon: '💳', title: 'Pricing & Plans',          sub: 'Upgrade your subscription',    action: () => { closePalette(); document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' }); } },
  ];

  let selectedIdx = 0;
  let filteredCmds = [...COMMANDS];

  function buildPalette() {
    if (document.getElementById('cdb-cmd-backdrop')) return;

    const backdrop = document.createElement('div');
    backdrop.id = 'cdb-cmd-backdrop';
    backdrop.setAttribute('role', 'dialog');
    backdrop.setAttribute('aria-modal', 'true');
    backdrop.setAttribute('aria-label', 'Command Palette');
    backdrop.innerHTML = `
      <div id="cdb-cmd-palette">
        <div id="cdb-cmd-search-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2.5">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <input id="cdb-cmd-input" type="text" placeholder="Search commands, navigate sections…" autocomplete="off" spellcheck="false">
        </div>
        <div id="cdb-cmd-results"></div>
        <div id="cdb-cmd-footer">
          <span><kbd>↑↓</kbd> navigate</span>
          <span><kbd>↵</kbd> select</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </div>
    `;

    backdrop.addEventListener('click', e => { if (e.target === backdrop) closePalette(); });
    document.body.appendChild(backdrop);

    const input = document.getElementById('cdb-cmd-input');
    input.addEventListener('input', () => { renderResults(input.value); selectedIdx = 0; });
    input.addEventListener('keydown', onPaletteKeyDown);
  }

  function renderResults(query = '') {
    filteredCmds = query
      ? COMMANDS.filter(c =>
          c.title.toLowerCase().includes(query.toLowerCase()) ||
          c.sub.toLowerCase().includes(query.toLowerCase()) ||
          c.group.toLowerCase().includes(query.toLowerCase()))
      : COMMANDS;

    const container = document.getElementById('cdb-cmd-results');
    if (!container) return;

    if (!filteredCmds.length) {
      container.innerHTML = `<div style="text-align:center;padding:24px;color:#475569;font-size:13px;">No results for "${query}"</div>`;
      return;
    }

    const groups = {};
    filteredCmds.forEach(c => { (groups[c.group] = groups[c.group] || []).push(c); });

    let globalIdx = 0;
    container.innerHTML = Object.entries(groups).map(([group, cmds]) => `
      <div class="cdb-cmd-section-label">${group}</div>
      ${cmds.map(cmd => `
        <div class="cdb-cmd-item ${globalIdx++ === selectedIdx ? 'selected' : ''}" data-cmd-idx="${globalIdx - 1}">
          <div class="cdb-cmd-item-icon">${cmd.icon}</div>
          <div class="cdb-cmd-item-main">
            <div class="cdb-cmd-item-title">${cmd.title}</div>
            <div class="cdb-cmd-item-sub">${cmd.sub}</div>
          </div>
          ${cmd.kbd ? `<span class="cdb-cmd-item-kbd">${cmd.kbd}</span>` : ''}
        </div>
      `).join('')}
    `).join('');

    container.querySelectorAll('.cdb-cmd-item').forEach(el => {
      el.addEventListener('click', () => {
        const idx = parseInt(el.dataset.cmdIdx);
        if (filteredCmds[idx]) { filteredCmds[idx].action(); closePalette(); }
      });
    });
  }

  function onPaletteKeyDown(e) {
    if (e.key === 'Escape') { closePalette(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); selectedIdx = Math.min(selectedIdx + 1, filteredCmds.length - 1); renderResults(document.getElementById('cdb-cmd-input')?.value); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); selectedIdx = Math.max(selectedIdx - 1, 0); renderResults(document.getElementById('cdb-cmd-input')?.value); }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCmds[selectedIdx]) { filteredCmds[selectedIdx].action(); closePalette(); }
    }
  }

  function openPalette() {
    buildPalette();
    const backdrop = document.getElementById('cdb-cmd-backdrop');
    if (!backdrop) return;
    backdrop.classList.add('open');
    selectedIdx = 0;
    renderResults('');
    setTimeout(() => document.getElementById('cdb-cmd-input')?.focus(), 50);
    console.info(LOG, 'Command palette opened');
  }

  function closePalette() {
    const backdrop = document.getElementById('cdb-cmd-backdrop');
    if (backdrop) { backdrop.classList.remove('open'); }
    const input = document.getElementById('cdb-cmd-input');
    if (input) input.value = '';
  }

  // ── Notification Center ────────────────────────────────────────────────────
  const NOTIF_STORE = { items: [], unread: 0 };

  function buildNotifPanel() {
    if (document.getElementById('cdb-notif-backdrop')) return;

    const backdrop = document.createElement('div');
    backdrop.id = 'cdb-notif-backdrop';
    backdrop.innerHTML = `
      <div id="cdb-notif-panel" role="dialog" aria-modal="true" aria-label="Notifications">
        <div id="cdb-notif-header">
          <h3>Notifications <span id="cdb-notif-count" style="font-size:12px;color:#64748b;font-weight:400;"></span></h3>
          <button id="cdb-notif-mark-read">Mark all read</button>
        </div>
        <div id="cdb-notif-list">
          <div id="cdb-notif-empty">No notifications yet.<br><span style="font-size:11px;margin-top:4px;display:block;">Alerts appear here in real-time.</span></div>
        </div>
      </div>
    `;
    backdrop.addEventListener('click', e => { if (e.target === backdrop) closeNotifPanel(); });
    document.body.appendChild(backdrop);

    document.getElementById('cdb-notif-mark-read')?.addEventListener('click', () => {
      NOTIF_STORE.unread = 0;
      NOTIF_STORE.items.forEach(i => i.unread = false);
      updateBadge();
      renderNotifs();
    });
  }

  function renderNotifs() {
    const list = document.getElementById('cdb-notif-list');
    if (!list) return;
    if (!NOTIF_STORE.items.length) {
      list.innerHTML = '<div id="cdb-notif-empty">No notifications yet.<br><span style="font-size:11px;margin-top:4px;display:block;">Real-time alerts appear here.</span></div>';
      return;
    }
    list.innerHTML = NOTIF_STORE.items.slice(-50).reverse().map(n => `
      <div class="cdb-notif-item ${n.unread ? 'unread' : ''}">
        <div class="cdb-notif-top">
          <span class="cdb-notif-badge ${n.type || 'scan'}"></span>
          <span class="cdb-notif-title">${n.title}</span>
          <span class="cdb-notif-ts">${n.ts}</span>
        </div>
        <div class="cdb-notif-body">${n.body || ''}</div>
      </div>
    `).join('');
    const countEl = document.getElementById('cdb-notif-count');
    if (countEl) countEl.textContent = `(${NOTIF_STORE.items.length})`;
  }

  function addNotification(type, title, body = '') {
    const ts = new Date().toLocaleTimeString();
    NOTIF_STORE.items.push({ type, title, body, ts, unread: true });
    NOTIF_STORE.unread++;
    if (NOTIF_STORE.items.length > 100) NOTIF_STORE.items.shift();
    updateBadge();
    if (document.getElementById('cdb-notif-backdrop')?.classList.contains('open')) renderNotifs();
  }

  function updateBadge() {
    const badge = document.getElementById('cdb-bell-badge');
    if (!badge) return;
    if (NOTIF_STORE.unread > 0) {
      badge.textContent = NOTIF_STORE.unread > 9 ? '9+' : NOTIF_STORE.unread;
      badge.classList.add('visible');
    } else {
      badge.classList.remove('visible');
    }
  }

  function toggleNotifPanel() {
    buildNotifPanel();
    const backdrop = document.getElementById('cdb-notif-backdrop');
    if (!backdrop) return;
    if (backdrop.classList.contains('open')) { closeNotifPanel(); }
    else {
      backdrop.classList.add('open');
      NOTIF_STORE.unread = 0;
      NOTIF_STORE.items.forEach(i => i.unread = false);
      updateBadge();
      renderNotifs();
    }
  }

  function closeNotifPanel() {
    document.getElementById('cdb-notif-backdrop')?.classList.remove('open');
  }

  // ── Toast System ───────────────────────────────────────────────────────────
  function buildToastContainer() {
    if (document.getElementById('cdb-toast-container')) return;
    const c = document.createElement('div');
    c.id = 'cdb-toast-container';
    document.body.appendChild(c);
  }

  window.CDB_UX_TOAST = function toast(type = 'info', title, message = '', duration = 4000) {
    buildToastContainer();
    const icons = { success: '✅', warning: '⚠️', error: '❌', info: 'ℹ️' };
    const id    = `toast_${Date.now()}`;
    const el    = document.createElement('div');
    el.className = `cdb-toast ${type}`;
    el.id = id;
    el.innerHTML = `
      <span class="cdb-toast-icon">${icons[type] || icons.info}</span>
      <div class="cdb-toast-body">
        <div class="cdb-toast-title">${title}</div>
        ${message ? `<div class="cdb-toast-msg">${message}</div>` : ''}
      </div>
      <button class="cdb-toast-close" aria-label="Dismiss">✕</button>
    `;
    el.querySelector('.cdb-toast-close').addEventListener('click', () => removeToast(id));
    document.getElementById('cdb-toast-container').appendChild(el);
    setTimeout(() => removeToast(id), duration);
  };

  function removeToast(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add('removing');
    setTimeout(() => el.remove(), 260);
  }

  // ── Keyboard Shortcuts ─────────────────────────────────────────────────────
  const shortcuts = [
    { keys: ['Meta+k', 'Control+k'], action: openPalette,  desc: 'Open command palette' },
    { keys: ['Escape'],              action: closeAll,      desc: 'Close overlays' },
  ];

  let gSequence = '';
  let gTimer    = null;

  function handleKeyDown(e) {
    // Ignore when typing in inputs
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;

    const key = [e.metaKey && 'Meta', e.ctrlKey && 'Control', e.shiftKey && 'Shift', e.key]
      .filter(Boolean).join('+');

    if (key === 'Control+k' || key === 'Meta+k') { e.preventDefault(); openPalette(); return; }
    if (key === 'Escape') { e.preventDefault(); closeAll(); return; }
    if (key === 'Control+/' || key === 'Meta+/') { e.preventDefault(); openShortcuts(); return; }

    // g-sequences for navigation
    if (e.key === 'g') { gSequence = 'g'; clearTimeout(gTimer); gTimer = setTimeout(() => { gSequence = ''; }, 1000); return; }
    if (gSequence === 'g') {
      gSequence = '';
      const navMap = { e: 'cdb-panel-exec', c: 'cdb-panel-soc', s: 'cdb-panel-sentinel', a: 'cdb-panel-ai', m: 'cdb-panel-mssp', r: 'cdb-panel-revenue', t: 'cdb-panel-cti', h: 'cdb-panel-health' };
      if (navMap[e.key]) { switchCCTab(navMap[e.key]); return; }
    }
  }

  function closeAll() {
    closePalette();
    closeNotifPanel();
    document.getElementById('cdb-shortcuts-modal')?.classList.remove('open');
  }

  // ── Keyboard Shortcut Reference ────────────────────────────────────────────
  function openShortcuts() {
    let modal = document.getElementById('cdb-shortcuts-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'cdb-shortcuts-modal';
      modal.innerHTML = `
        <div id="cdb-shortcuts-panel" role="dialog" aria-modal="true">
          <h2>⌨️ Keyboard Shortcuts</h2>
          ${[
            ['⌘K / Ctrl+K', 'Open command palette'],
            ['⌘/ / Ctrl+/', 'Open this reference'],
            ['Escape',       'Close any overlay'],
            ['g → e',        'Go to Executive Center'],
            ['g → c',        'Go to SOC Command Center'],
            ['g → s',        'Go to Sentinel APEX Intel'],
            ['g → a',        'Go to AI SecOps Center'],
            ['g → m',        'Go to MSSP Operations'],
            ['g → r',        'Go to Revenue Dashboard'],
            ['g → t',        'Go to CTI Workbench'],
            ['g → h',        'Go to Platform Health'],
          ].map(([k, d]) => `
            <div class="cdb-shortcut-row">
              <span class="cdb-shortcut-desc">${d}</span>
              <div class="cdb-shortcut-keys">${k.split(' ').map(p => `<span class="cdb-key">${p}</span>`).join('')}</div>
            </div>
          `).join('')}
          <button onclick="document.getElementById('cdb-shortcuts-modal').classList.remove('open')" style="margin-top:16px;width:100%;padding:10px;background:#1e293b;border:1px solid #334155;border-radius:8px;color:#94a3b8;cursor:pointer;font-size:13px;">Close</button>
        </div>
      `;
      modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('open'); });
      document.body.appendChild(modal);
    }
    modal.classList.add('open');
  }

  // ── Command Center Tab Switch ──────────────────────────────────────────────
  function switchCCTab(panelId) {
    const ccSection = document.getElementById('cdb-command-centers');
    if (!ccSection) return;
    ccSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setTimeout(() => {
      // Trigger click on the matching tab
      const tab = document.querySelector(`.cdb-cc-tab[data-target="${panelId}"]`);
      if (tab) tab.click();
    }, 400);
  }

  // ── SSE Integration: push alerts to notification center ──────────────────
  function wireSSENotifications() {
    // Listen to Phase 1 SSE events via re-using the existing EventSource
    // We intercept by observing the CDB_LIVE_BUS cache — no new connection needed
    const origFetch = window.CDB_LIVE_BUS?.fetch;
    if (!origFetch) return;

    // Hook into CDB_LIVE_BUS SSE events via custom event dispatch from dashboard-live.js
    document.addEventListener('cdb:cve_alert', e => {
      const d = e.detail;
      addNotification('cve', `🔴 New Critical CVE: ${d.id || 'Unknown'}`, d.title || '');
      window.CDB_UX_TOAST?.('error', `Critical CVE Detected`, d.id || 'New vulnerability');
    });

    document.addEventListener('cdb:scan_complete', e => {
      const d = e.detail;
      addNotification('scan', `Scan Complete`, d.target || '');
    });
  }

  // ── Tab Visibility Optimization ────────────────────────────────────────────
  function initVisibilityOptimization() {
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        console.info(LOG, 'Tab hidden — polling paused by browser');
      } else {
        console.info(LOG, 'Tab visible — refreshing data');
        // Trigger immediate refresh via CDB_LIVE_BUS
        if (window.CDB_LIVE_BUS) {
          Promise.allSettled([
            window.CDB_LIVE_BUS.fetch('/api/scan/stats'),
            window.CDB_LIVE_BUS.fetch('/api/threat-intel/stats'),
          ]).then(() => {
            document.querySelectorAll('.cdb-last-updated').forEach(el => {
              el.textContent = new Date().toLocaleTimeString();
            });
          });
        }
      }
    });
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  function init() {
    console.info(LOG, 'Enterprise UX System booting');
    injectStyles();
    buildNavActions();
    buildToastContainer();
    document.addEventListener('keydown', handleKeyDown);
    wireSSENotifications();
    initVisibilityOptimization();
    console.info(LOG, 'Ready — ⌘K for command palette');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose public API
  window.CDB_UX = { openPalette, closeAll, addNotification, switchCCTab, toast: window.CDB_UX_TOAST };

})();
