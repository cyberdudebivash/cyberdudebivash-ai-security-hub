/**
 * CYBERDUDEBIVASH AI Security Hub — APEX Copilot Widget v1.0
 * Site-wide floating + fullscreen front door to the APEX AI Security Copilot
 * backend (POST /api/copilot/chat and friends — see workers/src/handlers/aiSecurityCopilot.js).
 *
 * Drop-in include, no build step, no dependencies:
 *   <script src="/assets/copilot-widget.js" defer></script>
 *
 * Keyboard: Ctrl/Cmd+K opens the command palette (search commands or ask APEX
 * directly) · Esc closes (or exits fullscreen first) · Enter sends
 */
(function CDB_COPILOT_WIDGET() {
'use strict';

if (window.__cdbCopilotWidgetLoaded) return;
window.__cdbCopilotWidgetLoaded = true;

// ─── Config ─────────────────────────────────────────────────────────────────
const API_BASE = (typeof window.API_BASE === 'string' ? window.API_BASE : null)
  ?? localStorage.getItem('cdb_api_base')
  ?? '';

const LS_ACTIVE_SESSION = 'cdb_copilot_active_session';
const LS_SESSIONS_INDEX = 'cdb_copilot_sessions_index';
const LS_MSGS_PREFIX    = 'cdb_copilot_msgs_';
const LS_CAPS_CACHE     = 'cdb_copilot_caps_cache';
const CAPS_CACHE_TTL_MS = 60 * 60 * 1000; // 1h
const MAX_CACHED_MSGS   = 40;
const MAX_SESSIONS      = 30;

const FALLBACK_PROMPTS = [
  'What are the top CRITICAL CVEs in the AI/LLM ecosystem right now?',
  'Show me all CISA KEV entries — which are most urgent to patch?',
  'Run a comprehensive EU AI Act and NIST AI RMF governance assessment',
  'Check our platform health and AI provider status',
];

const QUICK_ACTIONS = [
  { label: 'Platform health',  skill: 'get_platform_health'   },
  { label: 'Latest threats',   skill: 'get_threat_intel_feed'  },
  { label: 'CISA KEV feed',    skill: 'get_kev_feed'            },
];

function genId(prefix) {
  return prefix + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
}

// ─── Auth ───────────────────────────────────────────────────────────────────
// Every request below used to go out with no Authorization header at all, so
// the backend's auth resolver always fell through to its anonymous
// IP-fallback branch (tier: 'FREE') regardless of who was actually logged
// in — a paying customer using this widget on their own dashboard got the
// exact same 5 msgs/day, 24/58-tool experience as an anonymous visitor.
// god-mode.html's own inline chat already attaches this correctly; mirrored
// here for every fetch call site. (2026-07-06 revenue-mechanisms audit, P1-6.)
function authHeaders(extra) {
  let token = '';
  try { token = localStorage.getItem('cdb_token') || sessionStorage.getItem('cdb_token') || ''; } catch (e) {}
  const base = extra || {};
  return token ? Object.assign({}, base, { Authorization: 'Bearer ' + token }) : base;
}

// ─── localStorage helpers (fail-open — private browsing / quota errors) ────
function lsGet(key, fallback) {
  try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; }
  catch { return fallback; }
}
function lsSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* fail open */ }
}

function getSessionsIndex() { return lsGet(LS_SESSIONS_INDEX, []); }
function saveSessionsIndex(list) { lsSet(LS_SESSIONS_INDEX, list.slice(0, MAX_SESSIONS)); }

function upsertSessionMeta(sessionId, patch) {
  const list = getSessionsIndex();
  const idx = list.findIndex(s => s.id === sessionId);
  const now = Date.now();
  if (idx === -1) {
    list.unshift({ id: sessionId, title: 'New chat', pinned: false, updated_at: now, ...patch });
  } else {
    list[idx] = { ...list[idx], ...patch, updated_at: now };
    const [item] = list.splice(idx, 1);
    list.unshift(item);
  }
  // Pinned sessions float to top regardless of recency
  list.sort((a, b) => (b.pinned - a.pinned) || (b.updated_at - a.updated_at));
  saveSessionsIndex(list);
}

function getCachedMessages(sessionId) { return lsGet(LS_MSGS_PREFIX + sessionId, []); }
function saveCachedMessages(sessionId, msgs) {
  lsSet(LS_MSGS_PREFIX + sessionId, msgs.slice(-MAX_CACHED_MSGS));
}

// ─── Styles ─────────────────────────────────────────────────────────────────
function injectStyles() {
  if (document.getElementById('cdb-copilot-styles')) return;
  const s = document.createElement('style');
  s.id = 'cdb-copilot-styles';
  s.textContent = `
:root{
  --cdb-cp-bg: var(--surface, #0f0f2e);
  --cdb-cp-bg2: var(--surface2, #13132b);
  --cdb-cp-card: var(--card, #111130);
  --cdb-cp-border: var(--border, #1e1e4a);
  --cdb-cp-accent: var(--accent, #00d4ff);
  --cdb-cp-accent2: var(--accent2, #7c3aed);
  --cdb-cp-text: var(--text, #e2e8f0);
  --cdb-cp-text-muted: var(--text-muted, #94a3b8);
  --cdb-cp-text-dim: var(--text-dim, #64748b);
  --cdb-cp-danger: var(--danger, #ef4444);
  --cdb-cp-warn: var(--warn, #f59e0b);
  --cdb-cp-accent3: var(--accent3, #10b981);
}
#cdb-copilot-fab{
  /* Bottom-left, well clear of the ground floor: several pages already run their
     own bottom-right floating elements (WhatsApp CTA at z-index 99999, back-to-top)
     and a bottom-left social-proof ticker around bottom:80-130px — this avoids both. */
  position:fixed; left:24px; bottom:150px; z-index:99980;
  width:58px; height:58px; border-radius:50%; border:none; cursor:pointer;
  background:linear-gradient(135deg, var(--cdb-cp-accent), var(--cdb-cp-accent2));
  box-shadow:0 6px 28px rgba(0,212,255,.35), 0 0 0 rgba(0,212,255,.4);
  display:flex; align-items:center; justify-content:center;
  animation:cdb-cp-pulse 2.8s ease-in-out infinite;
  transition:transform .18s ease, box-shadow .18s ease;
}
#cdb-copilot-fab:hover{ transform:scale(1.07); }
#cdb-copilot-fab:focus-visible{ outline:2px solid #fff; outline-offset:3px; }
#cdb-copilot-fab svg{ width:26px; height:26px; fill:#04101a; }
#cdb-copilot-fab .cdb-cp-badge{
  position:absolute; top:-3px; right:-3px; width:14px; height:14px; border-radius:50%;
  background:var(--cdb-cp-accent3); border:2px solid var(--cdb-cp-bg);
}
@keyframes cdb-cp-pulse{
  0%,100%{ box-shadow:0 6px 28px rgba(0,212,255,.35), 0 0 0 0 rgba(0,212,255,.28); }
  50%{ box-shadow:0 6px 28px rgba(0,212,255,.45), 0 0 0 10px rgba(0,212,255,0); }
}
@media (prefers-reduced-motion: reduce){ #cdb-copilot-fab{ animation:none; } }

#cdb-copilot-panel{
  position:fixed; left:24px; bottom:220px; z-index:99981;
  width:min(400px, calc(100vw - 32px)); height:min(600px, calc(100vh - 200px));
  background:var(--cdb-cp-bg); border:1px solid var(--cdb-cp-border); border-radius:16px;
  box-shadow:0 20px 60px rgba(0,0,0,.5); display:flex; flex-direction:column; overflow:hidden;
  opacity:0; transform:translateY(16px) scale(.98); pointer-events:none;
  transition:opacity .18s ease, transform .18s ease;
}
#cdb-copilot-panel.cdb-cp-open{ opacity:1; transform:translateY(0) scale(1); pointer-events:auto; }
#cdb-copilot-panel.cdb-cp-fullscreen{
  right:16px; bottom:16px; left:16px; top:16px; width:auto; height:auto;
}
@media (max-width:520px){
  #cdb-copilot-panel{ left:12px; bottom:82px; width:calc(100vw - 24px); height:calc(100vh - 140px); }
  #cdb-copilot-fab{ left:16px; bottom:16px; width:50px; height:50px; }
}

.cdb-cp-header{
  display:flex; align-items:center; gap:10px; padding:14px 14px 12px; border-bottom:1px solid var(--cdb-cp-border);
  background:var(--cdb-cp-bg2); flex-shrink:0;
}
.cdb-cp-header-title{ font-size:13px; font-weight:800; color:var(--cdb-cp-text); display:flex; align-items:center; gap:7px; }
.cdb-cp-status-dot{ width:7px; height:7px; border-radius:50%; background:var(--cdb-cp-accent3); flex-shrink:0; }
.cdb-cp-status-dot.cdb-cp-offline{ background:var(--cdb-cp-danger); }
.cdb-cp-header-sub{ font-size:10px; color:var(--cdb-cp-text-muted); margin-top:1px; }
.cdb-cp-header-actions{ margin-left:auto; display:flex; gap:4px; }
.cdb-cp-icon-btn{
  background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.08); color:var(--cdb-cp-text-muted);
  width:28px; height:28px; border-radius:7px; cursor:pointer; display:flex; align-items:center; justify-content:center;
  transition:all .15s;
}
.cdb-cp-icon-btn:hover{ color:var(--cdb-cp-text); background:rgba(255,255,255,.1); }
.cdb-cp-icon-btn:focus-visible{ outline:2px solid var(--cdb-cp-accent); outline-offset:1px; }
.cdb-cp-icon-btn svg{ width:14px; height:14px; fill:currentColor; }

.cdb-cp-history{
  position:absolute; top:56px; right:14px; width:260px; max-height:340px; overflow-y:auto;
  background:var(--cdb-cp-bg2); border:1px solid var(--cdb-cp-border); border-radius:10px;
  box-shadow:0 12px 32px rgba(0,0,0,.4); z-index:5; display:none; padding:6px;
}
.cdb-cp-history.cdb-cp-open{ display:block; }
.cdb-cp-history-item{
  display:flex; align-items:center; gap:6px; padding:8px 9px; border-radius:7px; cursor:pointer; font-size:12px;
  color:var(--cdb-cp-text-muted);
}
.cdb-cp-history-item:hover{ background:rgba(255,255,255,.05); }
.cdb-cp-history-item.cdb-cp-active{ background:rgba(0,212,255,.08); color:var(--cdb-cp-text); }
.cdb-cp-history-title{ flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.cdb-cp-history-pin, .cdb-cp-history-del{ opacity:.55; flex-shrink:0; padding:2px; border-radius:4px; }
.cdb-cp-history-pin:hover, .cdb-cp-history-del:hover{ opacity:1; background:rgba(255,255,255,.08); }
.cdb-cp-history-empty{ padding:14px; text-align:center; font-size:11px; color:var(--cdb-cp-text-muted); }

.cdb-cp-messages{ flex:1; overflow-y:auto; padding:14px; display:flex; flex-direction:column; gap:12px; }
.cdb-cp-msg{ display:flex; flex-direction:column; gap:4px; max-width:88%; animation:cdb-cp-fadein .18s ease; }
@keyframes cdb-cp-fadein{ from{ opacity:0; transform:translateY(4px); } to{ opacity:1; transform:translateY(0); } }
.cdb-cp-msg.cdb-cp-user{ align-self:flex-end; align-items:flex-end; }
.cdb-cp-msg.cdb-cp-assistant, .cdb-cp-msg.cdb-cp-system{ align-self:flex-start; }
.cdb-cp-bubble{ padding:10px 13px; border-radius:12px; font-size:13px; line-height:1.55; white-space:pre-wrap; word-break:break-word; }
.cdb-cp-msg.cdb-cp-user .cdb-cp-bubble{ background:linear-gradient(135deg, var(--cdb-cp-accent2), #4f46e5); color:#fff; border-bottom-right-radius:3px; }
.cdb-cp-msg.cdb-cp-assistant .cdb-cp-bubble{ background:var(--cdb-cp-card); border:1px solid var(--cdb-cp-border); color:var(--cdb-cp-text); border-bottom-left-radius:3px; }
.cdb-cp-msg.cdb-cp-system .cdb-cp-bubble{ background:rgba(245,158,11,.08); border:1px solid rgba(245,158,11,.25); color:var(--cdb-cp-warn); font-size:12px; }
.cdb-cp-bubble code{ background:rgba(0,0,0,.3); padding:1px 5px; border-radius:4px; font-size:11.5px; }
.cdb-cp-bubble pre{ background:rgba(0,0,0,.3); padding:8px 10px; border-radius:8px; overflow-x:auto; font-size:11px; margin:4px 0; }
.cdb-cp-meta{ font-size:10px; color:var(--cdb-cp-text-muted); padding:0 3px; }

.cdb-cp-status-line{ font-size:12px; color:var(--cdb-cp-text-muted); font-style:italic; }

.cdb-cp-actions-row{ display:flex; flex-wrap:wrap; gap:8px; align-self:flex-start; max-width:88%; }
.cdb-cp-action-btn{
  background:linear-gradient(135deg, var(--cdb-cp-accent), var(--cdb-cp-accent2)); border:none; color:#04101a;
  padding:9px 16px; border-radius:9px; font-size:12px; font-weight:800; cursor:pointer; transition:opacity .15s;
}
.cdb-cp-action-btn:hover{ opacity:.9; }

.cdb-cp-typing{ display:flex; gap:4px; padding:12px 13px; }
.cdb-cp-typing span{ width:6px; height:6px; border-radius:50%; background:var(--cdb-cp-text-dim); animation:cdb-cp-bounce 1.1s infinite ease-in-out; }
.cdb-cp-typing span:nth-child(2){ animation-delay:.15s; }
.cdb-cp-typing span:nth-child(3){ animation-delay:.3s; }
@keyframes cdb-cp-bounce{ 0%,60%,100%{ transform:translateY(0); opacity:.5; } 30%{ transform:translateY(-4px); opacity:1; } }

.cdb-cp-empty{ margin:auto; text-align:center; padding:20px 10px; color:var(--cdb-cp-text-muted); }
.cdb-cp-empty-title{ font-size:14px; font-weight:800; color:var(--cdb-cp-text); margin-bottom:4px; }
.cdb-cp-empty-sub{ font-size:12px; margin-bottom:16px; }
.cdb-cp-chips{ display:flex; flex-direction:column; gap:6px; }
.cdb-cp-chip{
  text-align:left; background:rgba(255,255,255,.04); border:1px solid var(--cdb-cp-border); color:var(--cdb-cp-text-muted);
  padding:9px 12px; border-radius:9px; font-size:12px; cursor:pointer; transition:all .15s;
}
.cdb-cp-chip:hover{ border-color:var(--cdb-cp-accent); color:var(--cdb-cp-text); background:rgba(0,212,255,.06); }

.cdb-cp-quick-actions{ display:flex; gap:6px; padding:0 12px 10px; flex-wrap:wrap; flex-shrink:0; }
.cdb-cp-quick-btn{
  /* #a78bfa (not --accent2) — the theme purple only hits ~2.9:1 on this translucent
     fill and fails WCAG AA 4.5:1 for 11px bold text; this shade clears ~6:1. */
  background:rgba(124,58,237,.12); border:1px solid rgba(124,58,237,.3); color:#a78bfa;
  padding:6px 10px; border-radius:20px; font-size:11px; font-weight:700; cursor:pointer; transition:all .15s; white-space:nowrap;
}
.cdb-cp-quick-btn:hover{ background:rgba(124,58,237,.22); }
.cdb-cp-quick-btn:disabled{ opacity:.5; cursor:not-allowed; }

.cdb-cp-composer{ display:flex; gap:8px; padding:12px; border-top:1px solid var(--cdb-cp-border); flex-shrink:0; background:var(--cdb-cp-bg2); }
.cdb-cp-textarea{
  flex:1; resize:none; max-height:96px; background:rgba(255,255,255,.05); border:1px solid var(--cdb-cp-border);
  border-radius:10px; padding:10px 12px; color:var(--cdb-cp-text); font-size:13px; font-family:inherit; line-height:1.4;
}
.cdb-cp-textarea:focus{ outline:none; border-color:var(--cdb-cp-accent); }
.cdb-cp-textarea::placeholder{ color:var(--cdb-cp-text-dim); }
.cdb-cp-send{
  background:linear-gradient(135deg, var(--cdb-cp-accent), var(--cdb-cp-accent2)); border:none; color:#04101a;
  width:40px; border-radius:10px; cursor:pointer; display:flex; align-items:center; justify-content:center; flex-shrink:0;
  transition:opacity .15s;
}
.cdb-cp-send:disabled{ opacity:.45; cursor:not-allowed; }
.cdb-cp-send svg{ width:17px; height:17px; fill:currentColor; }

.cdb-cp-footer{ font-size:10px; color:var(--cdb-cp-text-muted); text-align:center; padding:0 0 10px; flex-shrink:0; }
.cdb-cp-upgrade-link{ color:var(--cdb-cp-accent); font-weight:700; }

.cdb-cp-sr-only{ position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }

/* ── Command palette (⌘K) — a real searchable command list, distinct from the
   chat widget itself. Linear/Raycast-style: centered overlay, fuzzy filter,
   arrow-key navigation, Enter executes, Esc closes. ── */
#cdb-cmdk-overlay{
  position:fixed; inset:0; z-index:99990; background:rgba(5,5,15,.65); backdrop-filter:blur(4px);
  display:none; align-items:flex-start; justify-content:center; padding-top:12vh;
}
#cdb-cmdk-overlay.cdb-cp-open{ display:flex; }
#cdb-cmdk-modal{
  width:min(560px, calc(100vw - 32px)); max-height:60vh; background:var(--cdb-cp-bg);
  border:1px solid var(--cdb-cp-border); border-radius:14px; box-shadow:0 24px 70px rgba(0,0,0,.6);
  display:flex; flex-direction:column; overflow:hidden;
}
#cdb-cmdk-input{
  width:100%; border:none; border-bottom:1px solid var(--cdb-cp-border); background:transparent; color:var(--cdb-cp-text);
  padding:16px 18px; font-size:15px; font-family:inherit;
}
#cdb-cmdk-input:focus{ outline:none; }
#cdb-cmdk-input::placeholder{ color:var(--cdb-cp-text-dim); }
#cdb-cmdk-list{ overflow-y:auto; padding:6px; }
.cdb-cmdk-item{
  display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:8px; cursor:pointer;
  font-size:13px; color:var(--cdb-cp-text-muted);
}
.cdb-cmdk-item.cdb-cmdk-active{ background:rgba(0,212,255,.09); color:var(--cdb-cp-text); }
.cdb-cmdk-item-icon{ opacity:.7; flex-shrink:0; width:16px; height:16px; }
.cdb-cmdk-item-icon svg{ width:16px; height:16px; fill:currentColor; }
.cdb-cmdk-item-hint{ margin-left:auto; font-size:10px; color:var(--cdb-cp-text-muted); }
.cdb-cmdk-empty{ padding:16px; text-align:center; font-size:12px; color:var(--cdb-cp-text-dim); }
.cdb-cmdk-footer{ padding:8px 14px; border-top:1px solid var(--cdb-cp-border); font-size:10px; color:var(--cdb-cp-text-muted); display:flex; gap:14px; }
`;
  document.head.appendChild(s);
}

// ─── Markup ─────────────────────────────────────────────────────────────────
const ICONS = {
  chat: '<svg viewBox="0 0 24 24"><path d="M4 4h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8l-4 4V6a2 2 0 0 1 2-2z"/></svg>',
  close: '<svg viewBox="0 0 24 24"><path d="M18.3 5.71 12 12l6.3 6.29-1.41 1.42L10.59 13.4 4.3 19.71 2.89 18.3 9.17 12 2.89 5.71 4.3 4.29l6.29 6.3 6.3-6.3z"/></svg>',
  expand: '<svg viewBox="0 0 24 24"><path d="M4 14h2v4h4v2H4v-6zm2-4V6h4V4H4v6h2zm12 4h-2v4h-4v2h6v-6zm-2-4h2V4h-6v2h4v4z"/></svg>',
  collapse: '<svg viewBox="0 0 24 24"><path d="M14 10V4h-2v4h-4v2h6zM4 14h4v4h2v-6H4v2zm12 6h2v-4h4v-2h-6v6zm4-16h-2v4h-4v-2h6v-2z"/></svg>',
  history: '<svg viewBox="0 0 24 24"><path d="M13 3a9 9 0 1 0 9 9h-2a7 7 0 1 1-7-7V3z"/><path d="M12 8v5l4 2 .9-1.6-3-1.5V8z"/></svg>',
  plus: '<svg viewBox="0 0 24 24"><path d="M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6z"/></svg>',
  send: '<svg viewBox="0 0 24 24"><path d="M2 21l21-9L2 3v7l15 2-15 2z"/></svg>',
  pin: '<svg viewBox="0 0 24 24"><path d="M14 4v5l2 3v2H4v-2l2-3V4h1V2h6v2h1zm-4 12v6h2v-6h-2z" transform="rotate(45 12 12)"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M6 7h12v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V7zm3-3h6l1 2H8l1-2zM4 7h16"/></svg>',
};

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Minimal markdown-lite: bold, inline code, code fences, line breaks (already via white-space:pre-wrap)
function renderMarkdownLite(text) {
  let html = escapeHtml(text);
  html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre>${code.trim()}</pre>`);
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  return html;
}

// ─── Command palette (⌘K) ───────────────────────────────────────────────────
const ICON_SEARCH  = '<svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27a6.5 6.5 0 1 0-.7.7l.27.28v.79l5 5L20.49 19zm-6 0a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z"/></svg>';
const ICON_ASK     = '<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm1 15h-2v-2h2zm0-3.5V14h-2v-1.25c0-.5.2-1 .6-1.4l1.13-1.14A1.5 1.5 0 1 0 9 9.5H7a3.5 3.5 0 1 1 6.7 1.4l-1.13 1.14a.5.5 0 0 0-.57.46z"/></svg>';
const ICON_LINK    = '<svg viewBox="0 0 24 24"><path d="M3.9 12a5 5 0 0 1 5-5H12v2H8.9a3 3 0 0 0 0 6H12v2H8.9a5 5 0 0 1-5-5zm7.1-1h4v2h-4zm2.1-4H16a5 5 0 0 1 0 10h-2.9v-2H16a3 3 0 0 0 0-6h-2.9z"/></svg>';

function buildCommandPaletteDom() {
  const overlay = document.createElement('div');
  overlay.id = 'cdb-cmdk-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('aria-label', 'Command palette');
  overlay.innerHTML = `
    <div id="cdb-cmdk-modal">
      <label for="cdb-cmdk-input" class="cdb-cp-sr-only">Search commands or ask APEX</label>
      <input id="cdb-cmdk-input" type="text" autocomplete="off" placeholder="Search commands, or type a question for APEX…">
      <div id="cdb-cmdk-list" role="listbox" aria-label="Commands"></div>
      <div class="cdb-cmdk-footer"><span>↑↓ navigate</span><span>↵ select</span><span>esc close</span></div>
    </div>
  `;
  document.body.appendChild(overlay);
  return overlay;
}

function buildDom() {
  const fab = document.createElement('button');
  fab.id = 'cdb-copilot-fab';
  fab.type = 'button';
  fab.setAttribute('aria-label', 'Open APEX AI Security Copilot');
  fab.innerHTML = ICONS.chat + '<span class="cdb-cp-badge" aria-hidden="true"></span>';

  const panel = document.createElement('div');
  panel.id = 'cdb-copilot-panel';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-label', 'APEX AI Security Copilot chat');
  panel.innerHTML = `
    <div class="cdb-cp-header">
      <div>
        <div class="cdb-cp-header-title"><span class="cdb-cp-status-dot" id="cdb-cp-status-dot"></span>APEX Security Copilot</div>
        <div class="cdb-cp-header-sub" id="cdb-cp-header-sub">AI Security Hub · God Mode</div>
      </div>
      <div class="cdb-cp-header-actions">
        <button class="cdb-cp-icon-btn" id="cdb-cp-new" type="button" aria-label="New chat" title="New chat">${ICONS.plus}</button>
        <button class="cdb-cp-icon-btn" id="cdb-cp-history-btn" type="button" aria-label="Chat history" title="Chat history" aria-expanded="false">${ICONS.history}</button>
        <button class="cdb-cp-icon-btn" id="cdb-cp-fullscreen" type="button" aria-label="Toggle fullscreen" title="Toggle fullscreen">${ICONS.expand}</button>
        <button class="cdb-cp-icon-btn" id="cdb-cp-close" type="button" aria-label="Close copilot" title="Close (Esc)">${ICONS.close}</button>
      </div>
      <div class="cdb-cp-history" id="cdb-cp-history" role="menu" aria-label="Chat history"></div>
    </div>
    <div class="cdb-cp-messages" id="cdb-cp-messages" role="log" aria-live="polite" aria-label="Conversation"></div>
    <div class="cdb-cp-quick-actions" id="cdb-cp-quick-actions"></div>
    <form class="cdb-cp-composer" id="cdb-cp-composer">
      <label for="cdb-cp-input" class="cdb-cp-sr-only">Message APEX</label>
      <textarea class="cdb-cp-textarea" id="cdb-cp-input" rows="1" maxlength="5000"
        placeholder="Ask about CVEs, threats, compliance, or book a demo…"></textarea>
      <button class="cdb-cp-send" id="cdb-cp-send" type="submit" aria-label="Send message">${ICONS.send}</button>
    </form>
    <div class="cdb-cp-footer" id="cdb-cp-footer">Powered by APEX — CyberDudeBivash AI Security Hub</div>
  `;

  document.body.appendChild(fab);
  document.body.appendChild(panel);
  return { fab, panel };
}

// ─── Widget controller ──────────────────────────────────────────────────────
function initWidget() {
  injectStyles();
  const { fab, panel } = buildDom();

  const els = {
    messages:       panel.querySelector('#cdb-cp-messages'),
    quickActions:   panel.querySelector('#cdb-cp-quick-actions'),
    composer:       panel.querySelector('#cdb-cp-composer'),
    input:          panel.querySelector('#cdb-cp-input'),
    send:           panel.querySelector('#cdb-cp-send'),
    close:          panel.querySelector('#cdb-cp-close'),
    fullscreen:     panel.querySelector('#cdb-cp-fullscreen'),
    historyBtn:     panel.querySelector('#cdb-cp-history-btn'),
    history:        panel.querySelector('#cdb-cp-history'),
    newChat:        panel.querySelector('#cdb-cp-new'),
    statusDot:      panel.querySelector('#cdb-cp-status-dot'),
    headerSub:      panel.querySelector('#cdb-cp-header-sub'),
    footer:         panel.querySelector('#cdb-cp-footer'),
  };

  let state = {
    open: false,
    fullscreen: false,
    busy: false,
    sessionId: lsGet(LS_ACTIVE_SESSION, null) || genId('sess'),
    messages: [],
    lastUserMessage: null,
  };
  lsSet(LS_ACTIVE_SESSION, state.sessionId);
  state.messages = getCachedMessages(state.sessionId);

  function scrollToBottom() { els.messages.scrollTop = els.messages.scrollHeight; }

  function renderEmptyState(prompts) {
    const wrap = document.createElement('div');
    wrap.className = 'cdb-cp-empty';
    wrap.innerHTML = `
      <div class="cdb-cp-empty-title">Ask APEX anything security</div>
      <div class="cdb-cp-empty-sub">Threat intel, CVEs, compliance, red team, or book a demo — one AI copilot for the whole platform.</div>
      <div class="cdb-cp-chips"></div>
    `;
    const chipsWrap = wrap.querySelector('.cdb-cp-chips');
    prompts.slice(0, 4).forEach(p => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'cdb-cp-chip';
      chip.textContent = p;
      chip.addEventListener('click', () => sendMessage(p));
      chipsWrap.appendChild(chip);
    });
    els.messages.appendChild(wrap);
  }

  function renderMessage(msg) {
    const row = document.createElement('div');
    row.className = 'cdb-cp-msg cdb-cp-' + msg.role;
    const bubble = document.createElement('div');
    bubble.className = 'cdb-cp-bubble';
    bubble.innerHTML = renderMarkdownLite(msg.content);
    row.appendChild(bubble);
    if (msg.meta) {
      const meta = document.createElement('div');
      meta.className = 'cdb-cp-meta';
      meta.textContent = msg.meta;
      row.appendChild(meta);
    }
    els.messages.appendChild(row);
  }

  function renderAll() {
    els.messages.innerHTML = '';
    if (!state.messages.length) {
      loadCapabilities().then(caps => renderEmptyState(caps.example_prompts || FALLBACK_PROMPTS));
    } else {
      state.messages.forEach(renderMessage);
    }
    scrollToBottom();
  }

  function showTyping() {
    const row = document.createElement('div');
    row.className = 'cdb-cp-msg cdb-cp-assistant';
    row.id = 'cdb-cp-typing-row';
    row.innerHTML = '<div class="cdb-cp-bubble cdb-cp-typing" aria-label="APEX is thinking"><span></span><span></span><span></span></div>';
    els.messages.appendChild(row);
    scrollToBottom();
  }
  function hideTyping() {
    const row = document.getElementById('cdb-cp-typing-row');
    if (row) row.remove();
  }

  let capsCache = null;
  async function loadCapabilities() {
    if (capsCache) return capsCache;
    const cached = lsGet(LS_CAPS_CACHE, null);
    if (cached && Date.now() - cached._cachedAt < CAPS_CACHE_TTL_MS) {
      capsCache = cached.data;
      updateStatus(true);
      return capsCache;
    }
    try {
      const res = await fetch(`${API_BASE}/api/copilot/capabilities`, { headers: authHeaders() });
      if (!res.ok) throw new Error('bad status');
      const data = await res.json();
      capsCache = data;
      lsSet(LS_CAPS_CACHE, { _cachedAt: Date.now(), data });
      updateStatus(true);
      return data;
    } catch {
      updateStatus(false);
      return { example_prompts: FALLBACK_PROMPTS };
    }
  }

  function updateStatus(online) {
    els.statusDot.classList.toggle('cdb-cp-offline', !online);
    els.headerSub.textContent = online ? 'AI Security Hub · God Mode' : 'Reconnecting…';
  }

  function renderQuickActions() {
    els.quickActions.innerHTML = '';
    QUICK_ACTIONS.forEach(qa => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cdb-cp-quick-btn';
      btn.textContent = qa.label;
      btn.addEventListener('click', () => runQuickAction(qa));
      els.quickActions.appendChild(btn);
    });
  }

  async function runQuickAction(qa) {
    if (state.busy) return;
    // First real message in a fresh session becomes its history title — same
    // rule sendMessage applies, so a session isn't silently left out of history
    // just because its first turn happened to be a quick action.
    if (!state.messages.length) {
      upsertSessionMeta(state.sessionId, { title: qa.label });
    }
    setBusy(true);
    pushMessage({ role: 'user', content: qa.label });
    showTyping();
    try {
      const res = await fetch(`${API_BASE}/api/copilot/quick-action`, {
        method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ skill: qa.skill }),
      });
      const data = await res.json();
      hideTyping();
      if (data.error) {
        pushMessage({ role: 'system', content: data.message || data.error });
      } else {
        const pretty = '```\n' + JSON.stringify(data.result, null, 2).slice(0, 3000) + '\n```';
        pushMessage({ role: 'assistant', content: pretty, meta: qa.skill });
        upsertSessionMeta(state.sessionId, {});
      }
    } catch {
      hideTyping();
      pushMessage({ role: 'system', content: 'Network error — could not reach APEX. Please try again.' });
    } finally {
      setBusy(false);
    }
  }

  function pushMessage(msg) {
    state.messages.push(msg);
    saveCachedMessages(state.sessionId, state.messages);
    renderMessage(msg);
    scrollToBottom();
  }

  function setBusy(busy) {
    state.busy = busy;
    els.send.disabled = busy;
    els.input.disabled = busy;
  }

  // ─── Suggested actions (structured side-channel — never triggers payment itself) ──
  // The backend only ever SUGGESTS an action here; creating a Razorpay order still
  // requires this explicit human click, which calls the platform's existing,
  // already-tested checkout flow directly (window.cdbBookAssessment / /booking.html).
  function renderSuggestedActions(actions) {
    if (!actions || !actions.length) return;
    const wrap = document.createElement('div');
    wrap.className = 'cdb-cp-actions-row';
    actions.forEach(a => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cdb-cp-action-btn';
      btn.textContent = a.label;
      btn.addEventListener('click', () => {
        if (a.type === 'book_assessment') {
          if (typeof window.cdbBookAssessment === 'function') {
            window.cdbBookAssessment();
          } else {
            window.open('/booking.html?service=assessment', '_blank', 'noopener');
          }
        }
      });
      wrap.appendChild(btn);
    });
    els.messages.appendChild(wrap);
    scrollToBottom();
  }

  // ─── Streaming chat (SSE) with graceful fallback to the JSON endpoint ──────
  async function parseSSEStream(response, handlers) {
    const reader  = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const blocks = buf.split('\n\n');
      buf = blocks.pop(); // keep incomplete trailing block
      for (const block of blocks) {
        const eventLine = block.split('\n').find(l => l.startsWith('event:'));
        const dataLine  = block.split('\n').find(l => l.startsWith('data:'));
        if (!eventLine || !dataLine) continue;
        const type = eventLine.slice(6).trim();
        let data;
        try { data = JSON.parse(dataLine.slice(5).trim()); } catch { continue; }
        handlers[type]?.(data);
      }
    }
  }

  async function sendMessageStreaming(trimmed) {
    let assistantText = '';
    let sawDelta = false;
    let statusRow = null;

    function ensureStatusRow(message) {
      if (!statusRow) {
        statusRow = document.createElement('div');
        statusRow.className = 'cdb-cp-msg cdb-cp-assistant';
        statusRow.innerHTML = '<div class="cdb-cp-bubble cdb-cp-status-line"></div>';
        els.messages.appendChild(statusRow);
      }
      statusRow.querySelector('.cdb-cp-status-line').textContent = message;
      scrollToBottom();
    }
    function ensureAssistantRow() {
      if (statusRow) { statusRow.remove(); statusRow = null; }
      let row = document.getElementById('cdb-cp-streaming-row');
      if (!row) {
        row = document.createElement('div');
        row.id = 'cdb-cp-streaming-row';
        row.className = 'cdb-cp-msg cdb-cp-assistant';
        row.innerHTML = '<div class="cdb-cp-bubble"></div>';
        els.messages.appendChild(row);
      }
      return row;
    }

    const res = await fetch(`${API_BASE}/api/copilot/chat/stream`, {
      method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ message: trimmed, session_id: state.sessionId }),
    });
    if (!res.ok || !res.body) throw new Error('stream_unavailable');

    let finalMeta = null, suggestedActions = [], softError = null;
    await parseSSEStream(res, {
      status: (d) => ensureStatusRow(d.message || 'Working…'),
      delta: (d) => {
        sawDelta = true;
        assistantText += d.text || '';
        const row = ensureAssistantRow();
        row.querySelector('.cdb-cp-bubble').innerHTML = renderMarkdownLite(assistantText);
        scrollToBottom();
      },
      done: (d) => { finalMeta = d; suggestedActions = d.suggested_actions || []; },
      error: (d) => { softError = d; },
    });

    if (statusRow) { statusRow.remove(); statusRow = null; }

    if (softError) {
      if (softError.error === 'daily_quota_exceeded') {
        pushMessage({ role: 'system', content: `${softError.message} <a class="cdb-cp-upgrade-link" href="${softError.upgrade_url || '/#pricing'}">Upgrade →</a>` });
      } else {
        pushMessage({ role: 'system', content: softError.message || 'APEX hit an error — please try again.' });
      }
      const row = document.getElementById('cdb-cp-streaming-row');
      if (row) row.remove();
      return;
    }

    if (!sawDelta || !assistantText) throw new Error('empty_stream');

    // Commit the streamed row into normal message state (so it persists/caches like any other message).
    const row = document.getElementById('cdb-cp-streaming-row');
    if (row) row.removeAttribute('id');
    const meta = finalMeta?.provider ? `${finalMeta.provider} · ${finalMeta.model}` : undefined;
    state.messages.push({ role: 'assistant', content: assistantText, meta });
    saveCachedMessages(state.sessionId, state.messages);
    if (meta && row) {
      const metaEl = document.createElement('div');
      metaEl.className = 'cdb-cp-meta';
      metaEl.textContent = meta;
      row.appendChild(metaEl);
    }
    renderSuggestedActions(suggestedActions);
    upsertSessionMeta(state.sessionId, {});
  }

  async function sendMessageJSON(trimmed) {
    showTyping();
    try {
      const res = await fetch(`${API_BASE}/api/copilot/chat`, {
        method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ message: trimmed, session_id: state.sessionId }),
      });
      const data = await res.json();
      hideTyping();

      if (data.error === 'daily_quota_exceeded') {
        pushMessage({ role: 'system', content: `${data.message} <a class="cdb-cp-upgrade-link" href="${data.upgrade_url || '/#pricing'}">Upgrade →</a>` });
      } else if (data.error === 'rate_limit_exceeded') {
        pushMessage({ role: 'system', content: data.message || 'Too many messages — please slow down.' });
      } else if (data.message) {
        pushMessage({ role: 'assistant', content: data.message, meta: data.provider ? `${data.provider} · ${data.model}` : undefined });
        renderSuggestedActions(data.suggested_actions);
        upsertSessionMeta(state.sessionId, {});
      } else {
        pushMessage({ role: 'system', content: 'APEX did not return a response. Please try again.' });
      }
    } catch {
      hideTyping();
      pushMessage({ role: 'system', content: 'Network error — could not reach APEX. Your message was not lost; press send to retry.' });
      els.input.value = trimmed; // let the user resend without retyping
    }
  }

  async function sendMessage(text) {
    const trimmed = (text || '').trim();
    if (!trimmed || state.busy) return;

    // First real message in a fresh session becomes its history title.
    if (!state.messages.length) {
      upsertSessionMeta(state.sessionId, { title: trimmed.slice(0, 60) });
    }

    els.input.value = '';
    autoGrow();
    state.lastUserMessage = trimmed;
    pushMessage({ role: 'user', content: trimmed });
    setBusy(true);

    try {
      if (window.ReadableStream) {
        await sendMessageStreaming(trimmed);
      } else {
        await sendMessageJSON(trimmed);
      }
    } catch {
      // Streaming failed (network hiccup, endpoint unavailable, empty stream) —
      // fall back to the plain JSON endpoint rather than leaving the user stuck.
      const leftover = document.getElementById('cdb-cp-streaming-row');
      if (leftover) leftover.remove();
      await sendMessageJSON(trimmed);
    } finally {
      setBusy(false);
      els.input.focus();
    }
  }

  // ─── History panel ─────────────────────────────────────────────────────
  function renderHistory() {
    const list = getSessionsIndex();
    els.history.innerHTML = '';
    if (!list.length) {
      els.history.innerHTML = '<div class="cdb-cp-history-empty">No saved conversations yet.</div>';
      return;
    }
    list.forEach(s => {
      const item = document.createElement('div');
      item.className = 'cdb-cp-history-item' + (s.id === state.sessionId ? ' cdb-cp-active' : '');
      item.setAttribute('role', 'menuitem');
      item.innerHTML = `
        <span class="cdb-cp-history-title">${escapeHtml(s.title || 'New chat')}</span>
        <span class="cdb-cp-history-pin" title="${s.pinned ? 'Unpin' : 'Pin'}" aria-label="${s.pinned ? 'Unpin conversation' : 'Pin conversation'}" role="button" tabindex="0">${ICONS.pin}</span>
        <span class="cdb-cp-history-del" title="Delete" aria-label="Delete conversation" role="button" tabindex="0">${ICONS.trash}</span>
      `;
      item.querySelector('.cdb-cp-history-title').addEventListener('click', () => switchSession(s.id));
      item.querySelector('.cdb-cp-history-pin').addEventListener('click', (e) => {
        e.stopPropagation();
        upsertSessionMeta(s.id, { pinned: !s.pinned });
        renderHistory();
      });
      item.querySelector('.cdb-cp-history-del').addEventListener('click', (e) => {
        e.stopPropagation();
        deleteSession(s.id);
      });
      els.history.appendChild(item);
    });
  }

  async function switchSession(sessionId) {
    if (sessionId === state.sessionId) { toggleHistory(false); return; }
    state.sessionId = sessionId;
    lsSet(LS_ACTIVE_SESSION, sessionId);
    state.messages = getCachedMessages(sessionId);
    renderAll();
    toggleHistory(false);
    // Reconcile with server session (covers cache misses / other-device history)
    try {
      const res = await fetch(`${API_BASE}/api/copilot/session?session_id=${encodeURIComponent(sessionId)}`, { headers: authHeaders() });
      const data = await res.json();
      if (Array.isArray(data.messages) && data.messages.length > state.messages.length) {
        state.messages = data.messages;
        saveCachedMessages(sessionId, state.messages);
        renderAll();
      }
    } catch { /* cached copy is good enough offline */ }
  }

  function deleteSession(sessionId) {
    const list = getSessionsIndex().filter(s => s.id !== sessionId);
    saveSessionsIndex(list);
    try { localStorage.removeItem(LS_MSGS_PREFIX + sessionId); } catch {}
    fetch(`${API_BASE}/api/copilot/session?session_id=${encodeURIComponent(sessionId)}`, { method: 'DELETE', headers: authHeaders() }).catch(() => {});
    if (sessionId === state.sessionId) startNewChat();
    else renderHistory();
  }

  function startNewChat() {
    state.sessionId = genId('sess');
    lsSet(LS_ACTIVE_SESSION, state.sessionId);
    state.messages = [];
    renderAll();
    toggleHistory(false);
    els.input.focus();
  }

  function toggleHistory(force) {
    const willOpen = force !== undefined ? force : !els.history.classList.contains('cdb-cp-open');
    els.history.classList.toggle('cdb-cp-open', willOpen);
    els.historyBtn.setAttribute('aria-expanded', String(willOpen));
    if (willOpen) renderHistory();
  }

  // ─── Open / close / fullscreen ──────────────────────────────────────────
  let lastFocused = null;
  function openPanel() {
    if (state.open) return;
    state.open = true;
    lastFocused = document.activeElement;
    panel.classList.add('cdb-cp-open');
    fab.setAttribute('aria-expanded', 'true');
    renderAll();
    renderQuickActions();
    setTimeout(() => els.input.focus(), 50);
    document.addEventListener('keydown', onKeydownTrap);
  }
  function closePanel() {
    if (!state.open) return;
    if (state.fullscreen) { toggleFullscreen(false); return; }
    state.open = false;
    panel.classList.remove('cdb-cp-open');
    fab.setAttribute('aria-expanded', 'false');
    toggleHistory(false);
    document.removeEventListener('keydown', onKeydownTrap);
    if (lastFocused && lastFocused.focus) lastFocused.focus();
  }
  function toggleFullscreen(force) {
    state.fullscreen = force !== undefined ? force : !state.fullscreen;
    panel.classList.toggle('cdb-cp-fullscreen', state.fullscreen);
    els.fullscreen.innerHTML = state.fullscreen ? ICONS.collapse : ICONS.expand;
    els.fullscreen.setAttribute('aria-label', state.fullscreen ? 'Exit fullscreen' : 'Toggle fullscreen');
  }

  function onKeydownTrap(e) {
    if (e.key === 'Escape') { e.preventDefault(); closePanel(); return; }
    if (e.key !== 'Tab') return;
    const focusables = panel.querySelectorAll('button, textarea, [tabindex]:not([tabindex="-1"])');
    if (!focusables.length) return;
    const first = focusables[0], last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  function autoGrow() {
    els.input.style.height = 'auto';
    els.input.style.height = Math.min(els.input.scrollHeight, 96) + 'px';
  }

  // ─── Wire events ────────────────────────────────────────────────────────
  fab.addEventListener('click', () => (state.open ? closePanel() : openPanel()));
  els.close.addEventListener('click', closePanel);
  els.fullscreen.addEventListener('click', () => toggleFullscreen());
  els.historyBtn.addEventListener('click', () => toggleHistory());
  els.newChat.addEventListener('click', startNewChat);
  els.input.addEventListener('input', autoGrow);
  els.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); els.composer.requestSubmit(); }
  });
  els.composer.addEventListener('submit', (e) => {
    e.preventDefault();
    sendMessage(els.input.value);
  });

  document.addEventListener('click', (e) => {
    if (!els.history.contains(e.target) && e.target !== els.historyBtn && !els.historyBtn.contains(e.target)) {
      toggleHistory(false);
    }
  });

  // ─── Command palette (⌘K) — a real searchable command list ────────────────
  const cmdkOverlay = buildCommandPaletteDom();
  const cmdkInput   = cmdkOverlay.querySelector('#cdb-cmdk-input');
  const cmdkList    = cmdkOverlay.querySelector('#cdb-cmdk-list');
  let cmdkActive = 0;

  function baseCommands() {
    const cmds = [
      { label: 'Open APEX Chat', hint: 'chat', icon: ICON_ASK, run: () => openPanel() },
      { label: 'New chat', hint: 'chat', icon: ICON_ASK, run: () => { openPanel(); startNewChat(); } },
    ];
    QUICK_ACTIONS.forEach(qa => cmds.push({
      label: qa.label, hint: 'quick action', icon: ICON_ASK,
      run: () => { openPanel(); runQuickAction(qa); },
    }));
    cmds.push({ label: 'Book a demo', hint: 'navigate', icon: ICON_LINK, run: () => { window.location.href = '/booking.html'; } });
    cmds.push({ label: 'View pricing', hint: 'navigate', icon: ICON_LINK, run: () => {
      if (document.getElementById('pricing')) document.getElementById('pricing').scrollIntoView({ behavior: 'smooth' });
      else window.location.href = '/#pricing';
    } });
    return cmds;
  }

  function filterCommands(query) {
    const q = query.trim();
    const base = baseCommands();
    const matches = q
      ? base.filter(c => c.label.toLowerCase().includes(q.toLowerCase()))
      : base;
    if (q) {
      matches.push({ label: `Ask APEX: "${q}"`, hint: 'send', icon: ICON_ASK, run: () => { openPanel(); sendMessage(q); } });
    }
    return matches;
  }

  function renderCmdk() {
    const cmds = filterCommands(cmdkInput.value);
    cmdkActive = Math.min(cmdkActive, Math.max(cmds.length - 1, 0));
    cmdkList.innerHTML = '';
    if (!cmds.length) {
      cmdkList.innerHTML = '<div class="cdb-cmdk-empty">No matching commands.</div>';
      return;
    }
    cmds.forEach((c, i) => {
      const item = document.createElement('div');
      item.className = 'cdb-cmdk-item' + (i === cmdkActive ? ' cdb-cmdk-active' : '');
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', String(i === cmdkActive));
      item.innerHTML = `<span class="cdb-cmdk-item-icon">${c.icon}</span><span>${escapeHtml(c.label)}</span><span class="cdb-cmdk-item-hint">${c.hint}</span>`;
      // Hover only toggles the active class on existing nodes — never rebuilds
      // the list here. A full renderCmdk() on mouseenter would replace the very
      // node under the cursor mid-hover, which can make a click land on a
      // stale/detached element (this actually broke automated clicks in testing).
      item.addEventListener('mouseenter', () => {
        if (cmdkActive === i) return;
        const prev = cmdkList.querySelector('.cdb-cmdk-item.cdb-cmdk-active');
        if (prev) { prev.classList.remove('cdb-cmdk-active'); prev.setAttribute('aria-selected', 'false'); }
        item.classList.add('cdb-cmdk-active');
        item.setAttribute('aria-selected', 'true');
        cmdkActive = i;
      });
      item.addEventListener('click', () => { closeCmdk(); c.run(); });
      cmdkList.appendChild(item);
    });
  }

  function openCmdk() {
    if (state.open) closePanel();
    cmdkOverlay.classList.add('cdb-cp-open');
    cmdkInput.value = '';
    cmdkActive = 0;
    renderCmdk();
    setTimeout(() => cmdkInput.focus(), 30);
  }
  function closeCmdk() {
    cmdkOverlay.classList.remove('cdb-cp-open');
  }

  cmdkInput.addEventListener('input', () => { cmdkActive = 0; renderCmdk(); });
  cmdkInput.addEventListener('keydown', (e) => {
    const cmds = filterCommands(cmdkInput.value);
    if (e.key === 'ArrowDown') { e.preventDefault(); cmdkActive = Math.min(cmdkActive + 1, cmds.length - 1); renderCmdk(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); cmdkActive = Math.max(cmdkActive - 1, 0); renderCmdk(); }
    else if (e.key === 'Enter') { e.preventDefault(); const c = cmds[cmdkActive]; if (c) { closeCmdk(); c.run(); } }
    else if (e.key === 'Escape') { e.preventDefault(); closeCmdk(); }
  });
  cmdkOverlay.addEventListener('click', (e) => { if (e.target === cmdkOverlay) closeCmdk(); });

  document.addEventListener('keydown', (e) => {
    const isK = e.key === 'k' || e.key === 'K';
    if (isK && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      cmdkOverlay.classList.contains('cdb-cp-open') ? closeCmdk() : openCmdk();
    }
  });

  // Register the current session in history the first time it produces a message.
  if (state.messages.length && !getSessionsIndex().some(s => s.id === state.sessionId)) {
    const firstUser = state.messages.find(m => m.role === 'user');
    upsertSessionMeta(state.sessionId, { title: (firstUser?.content || 'New chat').slice(0, 60) });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initWidget);
} else {
  initWidget();
}

})();
