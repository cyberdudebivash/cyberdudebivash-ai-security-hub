/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — MCP Control Client v18.0
 *
 * THE OPERATING SYSTEM layer for the frontend.
 * Wraps POST /mcp/control with:
 *   ✅ Triple failsafe (control → decision → static)
 *   ✅ UI Block dynamic renderer (Phase 5)
 *   ✅ Personalization bar integration (Phase 6)
 *   ✅ KV-aware deduplication (Phase 8)
 *   ✅ Zero regression — all existing UI continues to work if MCP fails
 *   ✅ v17: Self-learning feedback tracking (auto-tracks all recommendation interactions)
 *   ✅ v17: Buffered batch submission (max 20 events, 5s debounce)
 *   ✅ v17: A/B variant tracking in all rendered blocks
 *   ✅ v17: Pricing signal renderer (visual discounts on training cards)
 *   ✅ v18: Revenue Autopilot — Loss Prevention Engine (exit intent + inactivity)
 *   ✅ v18: Revenue Autopilot — Urgency Signal Renderer (real-signal based)
 *   ✅ v18: Revenue Autopilot — Return User Revenue Renderer (4 variants)
 *   ✅ v18: Revenue Event Tracker (fire-and-forget, keepalive, visual only)
 *
 * Usage:
 *   import { MCPControl } from './mcpControl.js';
 *
 *   const decision = await MCPControl.decide({ module, risk_score, findings, tier });
 *   MCPControl.renderUIBlocks(decision);
 *   MCPControl.showPersonalizationBar(decision);
 *
 * Or from inline HTML:
 *   window.MCPControl.decide({ ... }).then(d => window.MCPControl.renderUIBlocks(d))
 * ═══════════════════════════════════════════════════════════════════════════
 */

const MCP_CONTROL_ENDPOINT  = '/mcp/control';
const MCP_DECISION_ENDPOINT = '/mcp/decision';
const MCP_TIMEOUT_MS        = 5000;
const MCP_CACHE_MS          = 3 * 60 * 1000; // 3 min in-memory cache

// ── In-memory response cache (prevents duplicate calls on same page) ──────────
const _cache = new Map(); // key → { data, ts }

function _cacheKey(ctx) {
  return `${ctx.module}:${Math.round((ctx.risk_score||0)/10)*10}:${ctx.tier||'FREE'}:${ctx.locked_count > 0 ? 'locked' : 'open'}`;
}

// ── Static fallback — absolute last resort, never crashes ─────────────────────
function _staticFallback(ctx) {
  return {
    risk_level:           ctx.risk_score >= 70 ? 'HIGH' : ctx.risk_score >= 40 ? 'MEDIUM' : 'LOW',
    primary_action:       'review_findings',
    recommended_tools:    [],
    recommended_training: [],
    bundle_offer:         null,
    cta:                  'View your scan results below',
    urgency:              'medium',
    enterprise_flag:      false,
    enterprise_cta:       null,
    ui_blocks:            ['scan_summary'],
    personalization_bar:  null,
    return_user_offer:    null,
    upsell:               null,
    remediation_steps:    [],
    learning_path:        [],
    user_context:         { last_scan: null, purchases: [], scan_count: 0, behavior_tags: [], is_returning: false },
    source:               'static_fallback',
    version:              '16.0',
  };
}

// ── Core decide() — Phase 2 safe wrapper ──────────────────────────────────────
/**
 * The ONLY function frontend needs to call.
 * ctx = { module, risk_score, findings, tier, target, locked_count, user_email, page_context }
 */
async function decide(ctx = {}) {
  const key = _cacheKey(ctx);

  // 1. In-memory cache hit (deduplicates rapid calls)
  const cached = _cache.get(key);
  if (cached && (Date.now() - cached.ts) < MCP_CACHE_MS) {
    return { ...cached.data, cache_hit: true };
  }

  // 2. Try /mcp/control (unified engine)
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), MCP_TIMEOUT_MS);

    const res = await fetch(MCP_CONTROL_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        module:       ctx.module      || 'domain',
        risk_score:   ctx.risk_score  || 0,
        tier:         ctx.tier        || 'FREE',
        target:       ctx.target      || '',
        findings:     ctx.findings    || [],
        locked_count: ctx.locked_count || 0,
        user_email:   ctx.user_email  || '',
        page_context: ctx.page_context || 'scan_result',
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.ok) {
      const json = await res.json();
      const data = json?.data || json;
      if (data?.ui_blocks) {
        _cache.set(key, { data, ts: Date.now() });
        return data;
      }
    }
  } catch (e) {
    console.warn('[MCPControl] /mcp/control failed, trying /mcp/decision fallback:', e.message);
  }

  // 3. Fallback: try /mcp/decision (existing v15 endpoint)
  try {
    const controller2 = new AbortController();
    const timer2 = setTimeout(() => controller2.abort(), MCP_TIMEOUT_MS);

    const res2 = await fetch(MCP_DECISION_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        module:      ctx.module    || 'domain',
        risk_score:  ctx.risk_score || 0,
        tier:        ctx.tier      || 'FREE',
        target:      ctx.target    || '',
        findings:    ctx.findings  || [],
        locked_count: ctx.locked_count || 0,
      }),
      signal: controller2.signal,
    });
    clearTimeout(timer2);

    if (res2.ok) {
      const json2 = await res2.json();
      const data2 = json2?.data || json2;
      // Patch missing fields for backward compat
      const patched = {
        ...data2,
        ui_blocks:           data2.ui_blocks || ['scan_summary', 'training_banner', 'upsell_cta'],
        personalization_bar: data2.personalization_bar || null,
        return_user_offer:   data2.return_user_offer || null,
        user_context:        data2.user_context || { last_scan: null, purchases: [], scan_count: 0, behavior_tags: [], is_returning: false },
        source:              'decision_fallback',
      };
      _cache.set(key, { data: patched, ts: Date.now() });
      return patched;
    }
  } catch (e2) {
    console.warn('[MCPControl] /mcp/decision fallback also failed:', e2.message);
  }

  // 4. Absolute fallback — static response, NEVER crashes UI
  const fallback = _staticFallback(ctx);
  return fallback;
}

// ── UI Block Renderer (Phase 5) ───────────────────────────────────────────────
/**
 * Renders MCP-controlled UI blocks dynamically.
 * Maps block ids → DOM actions. Each renderer is self-contained.
 * SAFE: tries/catches each block individually — one broken block ≠ broken UI.
 */
const BLOCK_RENDERERS = {

  scan_summary: (decision, container) => {
    // Already rendered by existing scan result logic — nothing to do
    // MCP can enhance the risk badge if present
    try {
      const riskEl = document.querySelector('[data-mcp="risk_level"]');
      if (riskEl) {
        riskEl.textContent = decision.risk_level;
        riskEl.className = `risk-badge risk-${decision.risk_level.toLowerCase()}`;
      }
    } catch {}
  },

  risk_alert_banner: (decision, container) => {
    try {
      const existing = document.getElementById('mcp-risk-alert');
      if (existing) { existing.remove(); }

      const banner = document.createElement('div');
      banner.id = 'mcp-risk-alert';
      banner.style.cssText = `
        background: linear-gradient(135deg, rgba(239,68,68,.12), rgba(220,38,38,.08));
        border: 1px solid rgba(239,68,68,.4);
        border-radius: 10px; padding: 14px 18px; margin: 16px 0;
        display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
      `;
      banner.innerHTML = `
        <span style="font-size:20px">🚨</span>
        <div style="flex:1">
          <strong style="color:#ef4444;font-size:14px">${decision.risk_level} RISK DETECTED</strong>
          <div style="color:#aaa;font-size:12px;margin-top:2px">${decision.cta || 'Immediate action required'}</div>
        </div>
        ${decision.upsell?.show ? `<button onclick="${decision.upsell.cta_action}" style="
          background:#ef4444;color:#fff;border:none;border-radius:7px;
          padding:8px 16px;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap
        ">${decision.upsell.cta_text || 'Fix Now'}</button>` : ''}
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.prepend(banner);
    } catch (e) { console.warn('[MCPControl] risk_alert_banner render error:', e); }
  },

  remediation_steps: (decision, container) => {
    try {
      if (!decision.remediation_steps?.length) return;
      const existing = document.getElementById('mcp-remediation');
      if (existing) { existing.remove(); }

      const panel = document.createElement('div');
      panel.id = 'mcp-remediation';
      panel.style.cssText = `
        background: rgba(0,212,255,.04); border: 1px solid rgba(0,212,255,.12);
        border-radius: 10px; padding: 16px 20px; margin: 16px 0;
      `;
      panel.innerHTML = `
        <h4 style="color:#00d4ff;font-size:14px;font-weight:700;margin:0 0 10px">
          ⚡ AI Remediation Roadmap
        </h4>
        ${decision.remediation_steps.map((s, i) => `
          <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px">
            <span style="
              background:${s.priority==='CRITICAL'?'#ef4444':s.priority==='HIGH'?'#f59e0b':'#10b981'};
              color:#fff;font-size:10px;font-weight:800;padding:2px 7px;border-radius:4px;
              flex-shrink:0;margin-top:2px
            ">${s.priority}</span>
            <span style="color:#ccc;font-size:13px;line-height:1.4">${s.step}</span>
          </div>
        `).join('')}
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] remediation_steps render error:', e); }
  },

  training_banner: (decision, container) => {
    try {
      if (!decision.recommended_training?.length) return;
      const existing = document.getElementById('mcp-training-banner');
      if (existing) { existing.remove(); }

      const t = decision.recommended_training[0];
      const panel = document.createElement('div');
      panel.id = 'mcp-training-banner';
      panel.style.cssText = `
        background: linear-gradient(135deg, rgba(139,92,246,.1), rgba(99,102,241,.07));
        border: 1px solid rgba(139,92,246,.25); border-radius: 10px;
        padding: 14px 18px; margin: 16px 0;
        display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
      `;
      panel.innerHTML = `
        <span style="font-size:22px">🎓</span>
        <div style="flex:1">
          <div style="color:#a78bfa;font-size:11px;font-weight:700;letter-spacing:.05em;margin-bottom:3px">RECOMMENDED TRAINING</div>
          <div style="color:#e2e8f0;font-size:14px;font-weight:600">${t.name}</div>
          <div style="color:#94a3b8;font-size:12px;margin-top:2px">${t.relevance_reason || 'Based on your scan findings'}</div>
        </div>
        <a href="/academy.html" style="
          background:#8b5cf6;color:#fff;text-decoration:none;border-radius:7px;
          padding:8px 16px;font-size:13px;font-weight:700;white-space:nowrap
        ">View Course — ₹${t.price}</a>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] training_banner render error:', e); }
  },

  bundle_offer: (decision, container) => {
    try {
      if (!decision.bundle_offer) return;
      const existing = document.getElementById('mcp-bundle-offer');
      if (existing) { existing.remove(); }

      const b = decision.bundle_offer;
      const panel = document.createElement('div');
      panel.id = 'mcp-bundle-offer';
      panel.style.cssText = `
        background: linear-gradient(135deg, rgba(245,158,11,.1), rgba(239,68,68,.07));
        border: 1px solid rgba(245,158,11,.3); border-radius: 12px;
        padding: 18px 22px; margin: 16px 0;
      `;
      panel.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          <span style="font-size:20px">🔥</span>
          <div>
            <div style="color:#f59e0b;font-size:11px;font-weight:800;letter-spacing:.07em">LIMITED BUNDLE OFFER</div>
            <div style="color:#fff;font-size:15px;font-weight:700">${b.name}</div>
          </div>
          ${b.social_proof ? `<div style="margin-left:auto;text-align:right">
            <div style="color:#f59e0b;font-size:11px;font-weight:700">${b.social_proof.label}</div>
          </div>` : ''}
        </div>
        <div style="color:#94a3b8;font-size:13px;margin-bottom:12px">${b.description}</div>
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
          <div>
            <span style="color:#94a3b8;font-size:12px;text-decoration:line-through">₹${b.original_price}</span>
            <span style="color:#f59e0b;font-size:20px;font-weight:800;margin-left:8px">₹${b.bundle_price}</span>
            <span style="background:#ef4444;color:#fff;font-size:10px;font-weight:800;padding:2px 7px;border-radius:4px;margin-left:8px">SAVE ${b.discount_pct}%</span>
          </div>
          <button onclick="${b.cta_action}" style="
            background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;border:none;border-radius:8px;
            padding:10px 20px;font-size:14px;font-weight:800;cursor:pointer;white-space:nowrap
          ">${b.cta_text}</button>
        </div>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] bundle_offer render error:', e); }
  },

  upsell_cta: (decision, container) => {
    try {
      if (!decision.upsell?.show) return;
      // Only inject if not already rendered by existing upsell modal
      const existingModal = document.getElementById('upsell-modal-v11');
      if (existingModal?.style.display !== 'none') return; // existing upsell is showing — don't double

      const existing = document.getElementById('mcp-upsell-cta');
      if (existing) { existing.remove(); }

      const u = decision.upsell;
      const bar = document.createElement('div');
      bar.id = 'mcp-upsell-cta';
      bar.style.cssText = `
        background:linear-gradient(135deg,rgba(239,68,68,.09),rgba(245,158,11,.07));
        border:1px solid rgba(245,158,11,.28);border-radius:10px;
        padding:12px 18px;margin:14px 0;
        display:flex;align-items:center;gap:12px;flex-wrap:wrap;
      `;
      bar.innerHTML = `
        <span style="font-size:18px">${u.urgency==='critical'?'🚨':u.urgency==='high'?'⚡':'💡'}</span>
        <div style="flex:1">
          <div style="color:#f59e0b;font-size:12px;font-weight:700">${u.label}</div>
          <div style="color:#94a3b8;font-size:12px;margin-top:1px">${u.message}</div>
        </div>
        <button onclick="${u.cta_action}" style="
          background:#f59e0b;color:#000;border:none;border-radius:7px;
          padding:8px 16px;font-size:13px;font-weight:800;cursor:pointer;white-space:nowrap
        ">${u.cta_text}</button>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(bar);
    } catch (e) { console.warn('[MCPControl] upsell_cta render error:', e); }
  },

  enterprise_cta: (decision, container) => {
    try {
      if (!decision.enterprise_flag) return;
      const existing = document.getElementById('mcp-enterprise-cta');
      if (existing) { existing.remove(); }

      const panel = document.createElement('div');
      panel.id = 'mcp-enterprise-cta';
      panel.style.cssText = `
        background:linear-gradient(135deg,rgba(99,102,241,.12),rgba(139,92,246,.08));
        border:1px solid rgba(99,102,241,.3);border-radius:12px;
        padding:18px 22px;margin:16px 0;
        display:flex;align-items:center;gap:16px;flex-wrap:wrap;
      `;
      panel.innerHTML = `
        <span style="font-size:28px">🏢</span>
        <div style="flex:1">
          <div style="color:#818cf8;font-size:11px;font-weight:800;letter-spacing:.07em">ENTERPRISE SECURITY</div>
          <div style="color:#fff;font-size:15px;font-weight:700;margin:3px 0">
            Critical vulnerabilities detected — book an expert assessment
          </div>
          <div style="color:#94a3b8;font-size:12px">
            Free 30-min consultation with our security team. No commitment required.
          </div>
        </div>
        <a href="/booking.html" style="
          background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;text-decoration:none;
          border-radius:8px;padding:10px 20px;font-size:14px;font-weight:700;white-space:nowrap
        ">${decision.enterprise_cta || 'Book Free Assessment'}</a>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] enterprise_cta render error:', e); }
  },

  return_user_offer: (decision, container) => {
    try {
      if (!decision.return_user_offer?.show) return;
      const existing = document.getElementById('mcp-return-offer');
      if (existing) { existing.remove(); }

      const r = decision.return_user_offer;
      const panel = document.createElement('div');
      panel.id = 'mcp-return-offer';
      panel.style.cssText = `
        background:linear-gradient(135deg,rgba(16,185,129,.1),rgba(5,150,105,.07));
        border:1px solid rgba(16,185,129,.3);border-radius:10px;
        padding:14px 18px;margin:14px 0;
        display:flex;align-items:center;gap:12px;flex-wrap:wrap;
      `;
      panel.innerHTML = `
        <span style="font-size:20px">🎯</span>
        <div style="flex:1">
          <div style="color:#10b981;font-size:13px;font-weight:700">${r.headline}</div>
          <div style="color:#94a3b8;font-size:12px;margin-top:2px">${r.offer_text}</div>
        </div>
        <button onclick="${r.cta_action}" style="
          background:#10b981;color:#fff;border:none;border-radius:7px;
          padding:8px 16px;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap
        ">${r.cta_text}</button>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] return_user_offer render error:', e); }
  },

  loyalty_reward: (decision, container) => {
    try {
      const existing = document.getElementById('mcp-loyalty');
      if (existing) { existing.remove(); }
      const panel = document.createElement('div');
      panel.id = 'mcp-loyalty';
      panel.style.cssText = `
        background:linear-gradient(135deg,rgba(251,191,36,.08),rgba(245,158,11,.05));
        border:1px solid rgba(251,191,36,.25);border-radius:8px;
        padding:10px 16px;margin:10px 0;
        display:flex;align-items:center;gap:10px;
      `;
      panel.innerHTML = `
        <span style="font-size:18px">🏆</span>
        <div style="color:#fbbf24;font-size:13px;font-weight:600">
          You're a valued member! Enjoy priority support on all your reports.
        </div>
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] loyalty_reward render error:', e); }
  },

  advanced_tools_panel: (decision, container) => {
    try {
      if (!decision.recommended_tools?.length) return;
      const existing = document.getElementById('mcp-adv-tools');
      if (existing) { existing.remove(); }
      const panel = document.createElement('div');
      panel.id = 'mcp-adv-tools';
      panel.style.cssText = `
        background:rgba(0,212,255,.03);border:1px solid rgba(0,212,255,.1);
        border-radius:10px;padding:14px 18px;margin:14px 0;
      `;
      panel.innerHTML = `
        <div style="color:#00d4ff;font-size:12px;font-weight:700;margin-bottom:10px">🔧 RECOMMENDED TOOLS FOR YOUR SCAN</div>
        ${decision.recommended_tools.map(t => `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <div style="flex:1">
              <div style="color:#e2e8f0;font-size:13px;font-weight:600">${t.tool}</div>
              <div style="color:#94a3b8;font-size:11px">${t.desc}</div>
            </div>
            <a href="${t.url}" style="
              color:#00d4ff;font-size:11px;font-weight:700;text-decoration:none;
              border:1px solid rgba(0,212,255,.3);border-radius:5px;padding:4px 10px;white-space:nowrap
            ">Use Tool →</a>
          </div>
        `).join('')}
      `;
      const target = container || document.getElementById('mcp-blocks-root') || document.querySelector('.scan-results-area');
      if (target) target.appendChild(panel);
    } catch (e) { console.warn('[MCPControl] advanced_tools_panel render error:', e); }
  },
};

/**
 * Render all UI blocks returned by MCP
 * @param {object} decision - result from decide()
 * @param {HTMLElement|null} container - optional root container (uses smart defaults)
 */
function renderUIBlocks(decision, container = null) {
  if (!decision?.ui_blocks?.length) return;

  // Create a root mount point if not present
  let root = container || document.getElementById('mcp-blocks-root');
  if (!root) {
    root = document.createElement('div');
    root.id = 'mcp-blocks-root';
    // Inject after scan results section or at top of main content
    const scanResults = document.getElementById('scan-results')
      || document.querySelector('.scan-output')
      || document.querySelector('[data-mcp-mount]')
      || document.querySelector('main')
      || document.body;
    scanResults.prepend(root);
  }

  // Render each block — isolated try/catch per block
  for (const blockId of decision.ui_blocks) {
    const renderer = BLOCK_RENDERERS[blockId];
    if (renderer) {
      try { renderer(decision, root); }
      catch (e) { console.warn(`[MCPControl] Block "${blockId}" render failed:`, e); }
    }
  }
}

/**
 * Show / update personalization bar (Phase 6)
 * Looks for #personalize-bar (existing v16 bar)
 */
function showPersonalizationBar(decision) {
  try {
    const bar = document.getElementById('personalize-bar');
    if (!bar || !decision?.personalization_bar) return;

    const pb = decision.personalization_bar;
    const iconEl    = bar.querySelector('.pb-icon')  || bar.querySelector('[data-pb="icon"]');
    const titleEl   = bar.querySelector('.pb-title') || bar.querySelector('[data-pb="title"]');
    const subtitleEl = bar.querySelector('.pb-sub')  || bar.querySelector('[data-pb="subtitle"]')
      || bar.querySelector('.pb-text span');

    if (iconEl)     iconEl.textContent    = pb.icon    || '🛡️';
    if (titleEl)    titleEl.textContent   = pb.title   || '';
    if (subtitleEl) subtitleEl.textContent = pb.subtitle || '';

    bar.style.display = 'flex';
  } catch (e) {
    console.warn('[MCPControl] showPersonalizationBar error:', e);
  }
}

/**
 * Full integration: decide → render blocks → show personalization bar
 * Drop-in replacement for all existing scan result callback hooks.
 * Wraps everything in try/catch — existing UI continues to work if MCP fails.
 *
 * @param {object} ctx - same as decide()
 * @param {object} opts - { container, onDecision }
 */
async function integrate(ctx = {}, opts = {}) {
  try {
    const decision = await decide(ctx);

    // Callback for custom hooks
    if (typeof opts.onDecision === 'function') {
      try { opts.onDecision(decision); } catch {}
    }

    // Render UI blocks
    renderUIBlocks(decision, opts.container || null);

    // Show personalization bar
    showPersonalizationBar(decision);

    return decision;
  } catch (e) {
    console.warn('[MCPControl] integrate() error — falling back silently:', e);
    return _staticFallback(ctx);
  }
}

/**
 * Clears in-memory cache (useful on new scan)
 */
function clearCache() {
  _cache.clear();
}

// ═══════════════════════════════════════════════════════════════════════════════
// v17: SELF-LEARNING FEEDBACK TRACKER
// Auto-tracks all interactions with MCP recommendations.
// Uses buffered batch submission to minimize API calls.
// ═══════════════════════════════════════════════════════════════════════════════

const FEEDBACK_ENDPOINT       = '/api/mcp/feedback/batch';
const FEEDBACK_BUFFER_MAX     = 20;   // max events per batch
const FEEDBACK_DEBOUNCE_MS    = 4000; // wait 4s before sending batch
const _feedbackBuffer         = [];   // pending events
let   _feedbackTimer          = null; // debounce timer
let   _currentDecision        = null; // last MCP decision (for context)
let   _sessionId              = null; // stable per-page session

// Generate stable session id for this page load
function _getSessionId() {
  if (_sessionId) return _sessionId;
  _sessionId = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  return _sessionId;
}

/**
 * Flush feedback buffer to /api/mcp/feedback/batch.
 * Fire-and-forget — never throws or blocks UI.
 */
function _flushFeedback() {
  if (!_feedbackBuffer.length) return;
  const events = _feedbackBuffer.splice(0, FEEDBACK_BUFFER_MAX);

  fetch(FEEDBACK_ENDPOINT, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ events }),
  }).catch(() => {}); // completely silent — never affects UX
}

/**
 * Queue a feedback event. Debounced batch send.
 * NEVER throws. Completely invisible to user.
 *
 * @param {object} event - { action, recommendation_type, item_id, item_name, ... }
 */
function trackFeedback(event) {
  try {
    if (!event?.action || !event?.item_id) return;

    const d = _currentDecision;
    _feedbackBuffer.push({
      action:              event.action,
      recommendation_type: event.recommendation_type || 'tool',
      item_id:             String(event.item_id).slice(0, 80),
      item_name:           String(event.item_name || '').slice(0, 120),
      context:             event.context || d?.page_context || 'scan_result',
      module:              event.module  || d?.module       || '',
      risk_level:          event.risk_level || d?.risk_level || '',
      tier:                event.tier    || d?.tier         || 'FREE',
      ab_variant:          event.ab_variant || (d?.learning?.ab_variants ? Object.values(d.learning.ab_variants)[0] : null),
      experiment_id:       event.experiment_id || null,
      session_id:          _getSessionId(),
    });

    // Debounce: clear existing timer and reset
    if (_feedbackTimer) clearTimeout(_feedbackTimer);

    // Flush immediately on purchase (don't buffer purchases)
    if (event.action === 'purchase') {
      _flushFeedback();
    } else {
      _feedbackTimer = setTimeout(_flushFeedback, FEEDBACK_DEBOUNCE_MS);
      // Also flush if buffer is full
      if (_feedbackBuffer.length >= FEEDBACK_BUFFER_MAX) {
        clearTimeout(_feedbackTimer);
        _flushFeedback();
      }
    }
  } catch { /* completely silent */ }
}

/**
 * Track an "ignore" event for all visible recommendations.
 * Called when user dismisses a scan result without clicking any CTA.
 * Gives MCP signal that these items weren't compelling enough.
 */
function trackIgnore(decision) {
  try {
    if (!decision) return;

    if (decision.bundle_offer) {
      trackFeedback({ action: 'ignore', recommendation_type: 'bundle',
        item_id: decision.bundle_offer.id, item_name: decision.bundle_offer.name });
    }
    if (decision.upsell?.product) {
      trackFeedback({ action: 'ignore', recommendation_type: 'upsell',
        item_id: decision.upsell.product, item_name: decision.upsell.label });
    }
    if (decision.recommended_training?.[0]) {
      const t = decision.recommended_training[0];
      trackFeedback({ action: 'ignore', recommendation_type: 'training',
        item_id: t.id, item_name: t.name });
    }
  } catch { /* silent */ }
}

// ── Auto-track: Attach tracking to all rendered block buttons ─────────────────
/**
 * Intercepts all clicks on CDB_PAY and MCP block buttons.
 * Patches them with feedback tracking before the original onclick fires.
 */
function _attachFeedbackListeners(rootEl, decision) {
  if (!rootEl || !decision) return;

  try {
    // Attach to all buttons within MCP-rendered blocks
    const buttons = rootEl.querySelectorAll('button[onclick], a[href]');
    buttons.forEach(btn => {
      const originalOnclick = btn.onclick;
      const href = btn.getAttribute('href');

      btn.addEventListener('click', (e) => {
        try {
          // Determine what was clicked from parent block context
          const block = btn.closest('[id^="mcp-"]');
          const blockId = block?.id || '';

          let rec_type = 'tool';
          let item_id  = '';
          let item_name = '';

          if (blockId.includes('bundle'))   { rec_type = 'bundle';   item_id = decision.bundle_offer?.id || ''; item_name = decision.bundle_offer?.name || ''; }
          else if (blockId.includes('upsell')) { rec_type = 'upsell'; item_id = decision.upsell?.product || ''; item_name = decision.upsell?.label || ''; }
          else if (blockId.includes('training')) { rec_type = 'training'; item_id = decision.recommended_training?.[0]?.id || ''; item_name = decision.recommended_training?.[0]?.name || ''; }
          else if (blockId.includes('enterprise')) { rec_type = 'enterprise'; item_id = 'enterprise_demo'; item_name = 'Enterprise Demo'; }
          else if (blockId.includes('tools')) { rec_type = 'tool'; item_id = 'tool_click'; item_name = btn.textContent?.trim()?.slice(0,40) || ''; }

          if (item_id) {
            trackFeedback({ action: 'click', recommendation_type: rec_type, item_id, item_name,
              context: decision.page_context || 'scan_result' });
          }
        } catch { /* silent */ }
      }, { passive: true });
    });

    // Auto-track ignore after 60s if no interaction (user saw it but didn't click)
    setTimeout(() => {
      const hasMCPBlocks = rootEl.querySelector('[id^="mcp-"]');
      if (hasMCPBlocks) trackIgnore(decision);
    }, 60000);

  } catch { /* silent */ }
}

// ── Enhanced renderUIBlocks with tracking ─────────────────────────────────────
function renderUIBlocksWithTracking(decision, container = null) {
  _currentDecision = decision; // store for context in feedback events
  renderUIBlocks(decision, container);

  // Attach feedback listeners after a tick (blocks need to be in DOM first)
  const root = container || document.getElementById('mcp-blocks-root');
  if (root) {
    setTimeout(() => _attachFeedbackListeners(root, decision), 100);
  }
}

// ── Enhanced integrate with tracking ──────────────────────────────────────────
async function integrateWithTracking(ctx = {}, opts = {}) {
  try {
    const decision = await decide(ctx);
    _currentDecision = decision;

    if (typeof opts.onDecision === 'function') {
      try { opts.onDecision(decision); } catch {}
    }

    renderUIBlocksWithTracking(decision, opts.container || null);
    showPersonalizationBar(decision);

    // Phase 6 — pricing signal (visual only, never modifies payment)
    if (decision.training_pricing_note?.show) {
      applyPricingSignal(decision.training_pricing_note);
    }

    // ── v18 Revenue Autopilot ─────────────────────────────────────────────────
    if (decision.revenue?.autopilot_applied) {
      try {
        // Phase 8 — Urgency signal (standalone render if block not in ui_blocks)
        const urgency = decision.revenue?.urgency_signal;
        if (urgency?.active && !decision.ui_blocks?.includes('urgency_signal')) {
          renderUrgencySignal(urgency, opts.container || null);
        }

        // Phase 9 — Return user revenue (standalone render if block not in ui_blocks)
        const returnUser = decision.revenue?.return_user_revenue;
        if (returnUser?.show && !decision.ui_blocks?.includes('return_user_revenue')) {
          renderReturnUserRevenue(returnUser, opts.container || null, decision);
        }

        // Phase 7 — Loss prevention (standalone init if block not in ui_blocks)
        const lp = decision.revenue?.loss_prevention;
        if (lp?.eligible && !decision.ui_blocks?.includes('loss_prevention_trigger')) {
          _LossPrevention.init(lp, decision);
        }

        // Track offer impression for best_offer
        const offerMeta = decision.revenue?.offer_meta;
        if (offerMeta?.offer_id) {
          trackRevenueEvent({
            event_type:    'impression',
            offer_type:    offerMeta.selected_type || 'single',
            offer_id:      offerMeta.offer_id,
            offer_name:    offerMeta.offer_name || '',
            display_price: offerMeta.display_price || 0,
            discount_pct:  offerMeta.discount_pct  || 0,
            cta_variant:   decision.revenue?.signal?.cta_variant || 'standard',
            urgency_level: decision.revenue?.signal?.urgency_level || 'low',
            user_type:     decision.revenue?.signal?.user_type || 'new',
            module:        decision.module || '',
            risk_level:    decision.risk_level || '',
            context:       decision.page_context || 'scan_result',
          });
        }
      } catch (revErr) {
        // Revenue autopilot frontend error — never crash main flow
        console.warn('[MCPv18] Revenue frontend render error:', revErr?.message);
      }
    }
    // ── End v18 ───────────────────────────────────────────────────────────────

    return decision;
  } catch (e) {
    console.warn('[MCPControl v18] integrate() error — falling back silently:', e);
    return _staticFallback(ctx);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// GOD MODE v18 — REVENUE AUTOPILOT FRONTEND LAYER
//
// Phase 7 — Loss Prevention Engine (exit intent + inactivity + scroll)
// Phase 8 — Urgency Signal Renderer
// Phase 9 — Return User Revenue Renderer
// Phase 10 — Revenue Event Tracker (client → /api/mcp/revenue/event)
//
// STRICT RULES:
//   • DO NOT modify actual prices — all display_price is visual ONLY
//   • DO NOT block payment flow — all tracking is fire-and-forget
//   • All DOM writes are isolated try/catch — never crash page
// ═════════════════════════════════════════════════════════════════════════════

const MCP_REVENUE_EVENT_ENDPOINT = '/api/mcp/revenue/event';

/**
 * Phase 10 — Revenue event tracker
 * Fire-and-forget POST to revenue tracking API.
 * NEVER awaited in critical paths. NEVER throws.
 */
function trackRevenueEvent(payload = {}) {
  try {
    if (!payload.event_type || !payload.offer_type || !payload.offer_id) return;
    // revenue_inr is always 0 from client — server verifies from delivery_tokens
    const body = { ...payload, revenue_inr: 0, session_id: _getSessionId() };
    fetch(MCP_REVENUE_EVENT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      keepalive: true,  // survives page unload
    }).catch(() => {}); // never throw
  } catch { /* completely silent */ }
}

// ── Phase 7: Loss Prevention Engine ──────────────────────────────────────────
/**
 * Manages exit intent, inactivity timer, and scroll abandon detection.
 * Renders a loss prevention modal/banner when triggers fire.
 * Config comes from decision.revenue.loss_prevention (built by backend).
 */
const _LossPrevention = (() => {
  let _active         = false;
  let _shown          = false;
  let _inactivityTimer = null;
  let _config         = null;   // { offer_id, discount_pct, trigger_after_ms, exit_intent, offer_name, display_price }
  let _offer_type     = 'loss_prevention';
  let _user_type      = 'new';
  let _module         = '';
  let _risk_level     = '';

  function _show(trigger_type) {
    if (_shown || !_config) return;
    _shown = true;

    try {
      // Track loss_prevent_shown
      trackRevenueEvent({
        event_type: 'loss_prevent_shown',
        offer_type: _offer_type,
        offer_id:   _config.offer_id || 'lp_offer',
        offer_name: _config.offer_name || '',
        display_price: _config.display_price || 0,
        discount_pct:  _config.discount_pct || 0,
        user_type:     _user_type,
        module:        _module,
        risk_level:    _risk_level,
        context:       'loss_prevention',
      });

      // Remove existing panel if present
      const existing = document.getElementById('mcp-loss-prevention-panel');
      if (existing) existing.remove();

      const discountBadge = _config.discount_pct > 0
        ? `<span style="background:#ef4444;color:#fff;font-size:10px;font-weight:800;padding:2px 8px;border-radius:4px;margin-left:8px">SAVE ${_config.discount_pct}% TODAY ONLY</span>`
        : '';

      const panel = document.createElement('div');
      panel.id = 'mcp-loss-prevention-panel';
      panel.setAttribute('role', 'dialog');
      panel.setAttribute('aria-modal', 'true');
      panel.style.cssText = `
        position:fixed;bottom:0;left:0;right:0;z-index:99999;
        background:linear-gradient(135deg,rgba(15,23,42,.97),rgba(30,41,59,.98));
        border-top:2px solid rgba(239,68,68,.5);
        padding:20px 28px;
        display:flex;align-items:center;gap:20px;flex-wrap:wrap;
        box-shadow:0 -8px 40px rgba(0,0,0,.6);
        animation:mcp-lp-slide-up 0.35s ease-out;
      `;

      // Add slide-up animation
      if (!document.getElementById('mcp-lp-style')) {
        const style = document.createElement('style');
        style.id = 'mcp-lp-style';
        style.textContent = `
          @keyframes mcp-lp-slide-up {
            from { transform: translateY(100%); opacity: 0; }
            to   { transform: translateY(0);    opacity: 1; }
          }
        `;
        document.head.appendChild(style);
      }

      const displayPrice = _config.display_price
        ? `<span style="color:#94a3b8;font-size:12px;text-decoration:line-through;margin-right:5px">₹${Math.round(_config.display_price * (1 + _config.discount_pct/100))}</span><span style="color:#10b981;font-size:16px;font-weight:800">₹${_config.display_price}</span>`
        : '';

      panel.innerHTML = `
        <span style="font-size:32px">🚨</span>
        <div style="flex:1;min-width:200px">
          <div style="color:#ef4444;font-size:11px;font-weight:800;letter-spacing:.08em;margin-bottom:4px">
            WAIT — DON'T LEAVE YET ${discountBadge}
          </div>
          <div style="color:#f1f5f9;font-size:15px;font-weight:700;margin-bottom:2px">
            ${_config.offer_name || 'Your security gap is still open'}
          </div>
          <div style="color:#94a3b8;font-size:12px">
            ${trigger_type === 'exit_intent' ? 'Before you go — grab this offer at our best price today.' : 'You\'ve been researching this for a while. Lock in the deal now.'}
            ${displayPrice}
          </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <button id="mcp-lp-accept-btn" style="
            background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;border:none;
            border-radius:8px;padding:12px 24px;font-size:14px;font-weight:800;cursor:pointer;
            white-space:nowrap;min-width:140px;
          ">Claim Offer →</button>
          <button id="mcp-lp-dismiss-btn" style="
            background:transparent;color:#64748b;border:1px solid rgba(100,116,139,.3);
            border-radius:7px;padding:10px 16px;font-size:12px;cursor:pointer;white-space:nowrap;
          ">No thanks</button>
        </div>
      `;

      document.body.appendChild(panel);

      // Dismiss handler
      const dismissBtn = document.getElementById('mcp-lp-dismiss-btn');
      if (dismissBtn) {
        dismissBtn.addEventListener('click', () => {
          panel.style.animation = 'none';
          panel.style.transform = 'translateY(100%)';
          panel.style.transition = 'transform .25s ease-in';
          setTimeout(() => panel.remove(), 300);
          trackRevenueEvent({
            event_type: 'abandon',
            offer_type: _offer_type,
            offer_id:   _config.offer_id || 'lp_offer',
            user_type:  _user_type, module: _module,
            context:    'loss_prevention',
          });
        }, { once: true });
      }

      // Accept handler — track conversion, then redirect to offer
      const acceptBtn = document.getElementById('mcp-lp-accept-btn');
      if (acceptBtn) {
        acceptBtn.addEventListener('click', () => {
          trackRevenueEvent({
            event_type: 'loss_prevent_converted',
            offer_type: _offer_type,
            offer_id:   _config.offer_id || 'lp_offer',
            offer_name: _config.offer_name || '',
            display_price: _config.display_price || 0,
            discount_pct:  _config.discount_pct || 0,
            user_type:     _user_type, module: _module,
            context:       'loss_prevention',
          });
          // Navigate to offer — use config redirect or checkout
          const dest = _config.redirect_url || '/products.html';
          window.location.href = dest;
        }, { once: true });
      }
    } catch (e) { console.warn('[MCPv18] Loss prevention render error:', e); }
  }

  function _onExitIntent(e) {
    // mouseleave toward top of screen = exit intent
    if (!_active || _shown || e.clientY > 20) return;
    _clearInactivity();
    _show('exit_intent');
  }

  function _clearInactivity() {
    if (_inactivityTimer) { clearTimeout(_inactivityTimer); _inactivityTimer = null; }
  }

  function _startInactivity(ms) {
    _clearInactivity();
    _inactivityTimer = setTimeout(() => {
      if (!_shown) _show('inactivity');
    }, ms);
  }

  function _resetInactivity(ms) {
    _clearInactivity();
    _startInactivity(ms);
  }

  /** Initialize Loss Prevention for the current session. */
  function init(config, decision) {
    if (!config || _active) return;
    try {
      _config     = config;
      _offer_type = decision?.revenue?.offer_meta?.selected_type || 'loss_prevention';
      _user_type  = decision?.revenue?.signal?.user_type || 'new';
      _module     = decision?.module || '';
      _risk_level = decision?.risk_level || '';
      _active     = true;
      _shown      = false;

      const triggerMs = config.trigger_after_ms || 45000;

      // Exit intent: mouse leaves top of viewport
      if (config.exit_intent !== false) {
        document.addEventListener('mouseleave', _onExitIntent, { passive: true });
      }

      // Inactivity timer
      _startInactivity(triggerMs);

      // Reset inactivity on user activity
      const resetEvents = ['mousemove','keydown','scroll','click','touchstart'];
      const _resetHandler = () => _resetInactivity(triggerMs);
      resetEvents.forEach(evt => document.addEventListener(evt, _resetHandler, { passive: true }));

      // Track impression (fire-and-forget)
      trackRevenueEvent({
        event_type: 'impression',
        offer_type: 'loss_prevention',
        offer_id:   _config.offer_id || 'lp_offer',
        offer_name: _config.offer_name || '',
        display_price: _config.display_price || 0,
        discount_pct:  _config.discount_pct || 0,
        user_type:     _user_type, module: _module, risk_level: _risk_level,
        context:       'loss_prevention',
      });
    } catch (e) { console.warn('[MCPv18] LossPrevention init error:', e); }
  }

  function destroy() {
    _active = false;
    _clearInactivity();
    document.removeEventListener('mouseleave', _onExitIntent);
    const panel = document.getElementById('mcp-loss-prevention-panel');
    if (panel) panel.remove();
  }

  return { init, destroy };
})();

// ── Phase 8: Urgency Signal Renderer ─────────────────────────────────────────
/**
 * Renders a real-signal urgency bar above the main CTA.
 * Uses deterministic stats (teamsFixed, viewingNow) from backend.
 * NEVER fabricates numbers — all from revenue signal.
 */
function renderUrgencySignal(signal, container = null) {
  try {
    if (!signal?.active) return;

    const existing = document.getElementById('mcp-urgency-signal');
    if (existing) existing.remove();

    const bar = document.createElement('div');
    bar.id = 'mcp-urgency-signal';
    bar.style.cssText = `
      background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(245,158,11,.06));
      border:1px solid rgba(239,68,68,.22);border-radius:8px;
      padding:9px 14px;margin:10px 0;
      display:flex;align-items:center;gap:10px;flex-wrap:wrap;
    `;

    const levelIcon   = signal.level === 'critical' ? '🔴' : signal.level === 'high' ? '🟠' : '🟡';
    const teamsFixed  = signal.teams_fixed  || 0;
    const viewingNow  = signal.viewing_now  || 0;
    const timeLabel   = signal.time_label   || '';
    const expiresIn   = signal.expires_in_label || '';

    bar.innerHTML = `
      <span style="font-size:16px">${levelIcon}</span>
      <div style="flex:1;min-width:180px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${teamsFixed > 0  ? `<span style="color:#94a3b8;font-size:11px">✅ <strong style="color:#e2e8f0">${teamsFixed}</strong> teams secured this week</span>` : ''}
          ${viewingNow > 0  ? `<span style="color:#94a3b8;font-size:11px">👁 <strong style="color:#f59e0b">${viewingNow}</strong> viewing now</span>` : ''}
          ${timeLabel       ? `<span style="color:#94a3b8;font-size:11px">🕐 ${timeLabel}</span>` : ''}
        </div>
        ${expiresIn ? `<div style="color:#ef4444;font-size:10px;margin-top:3px;font-weight:700">⏰ ${expiresIn}</div>` : ''}
      </div>
    `;

    const target = container
      || document.getElementById('mcp-blocks-root')
      || document.querySelector('.scan-results-area');
    if (target) target.prepend(bar); // urgency goes ABOVE other blocks
  } catch (e) { console.warn('[MCPv18] Urgency signal render error:', e); }
}

// ── Phase 9: Return User Revenue Renderer ─────────────────────────────────────
/**
 * Renders a personalized return-user offer block.
 * 4 variants: vip_welcome, buyer_return, researcher_nudge, returning_offer.
 * Uses decision.revenue.return_user_revenue from backend.
 */
function renderReturnUserRevenue(returnData, container = null, decision = null) {
  try {
    if (!returnData?.show) return;

    const existing = document.getElementById('mcp-return-revenue');
    if (existing) existing.remove();

    const panel = document.createElement('div');
    panel.id = 'mcp-return-revenue';

    // Color scheme by variant type
    const colors = {
      vip_welcome:       { bg: 'rgba(99,102,241,.1)',   border: 'rgba(99,102,241,.3)',  accent: '#818cf8', icon: '👑' },
      buyer_return:      { bg: 'rgba(16,185,129,.1)',   border: 'rgba(16,185,129,.3)', accent: '#10b981', icon: '🏆' },
      researcher_nudge:  { bg: 'rgba(245,158,11,.08)',  border: 'rgba(245,158,11,.25)', accent: '#f59e0b', icon: '🔬' },
      returning_offer:   { bg: 'rgba(0,212,255,.07)',   border: 'rgba(0,212,255,.2)',  accent: '#00d4ff', icon: '🔄' },
    };
    const c = colors[returnData.type] || colors.returning_offer;

    panel.style.cssText = `
      background:linear-gradient(135deg,${c.bg},rgba(15,23,42,.02));
      border:1px solid ${c.border};border-radius:12px;
      padding:16px 20px;margin:14px 0;
      display:flex;align-items:center;gap:14px;flex-wrap:wrap;
    `;

    const discountStr = returnData.discount_pct > 0
      ? `<span style="background:${c.accent};color:#000;font-size:10px;font-weight:800;padding:2px 7px;border-radius:4px;margin-left:8px">-${returnData.discount_pct}%</span>`
      : '';

    panel.innerHTML = `
      <span style="font-size:26px">${c.icon}</span>
      <div style="flex:1;min-width:180px">
        <div style="color:${c.accent};font-size:12px;font-weight:800;letter-spacing:.06em">
          ${returnData.headline || 'Welcome back!'}${discountStr}
        </div>
        <div style="color:#f1f5f9;font-size:14px;font-weight:600;margin:4px 0">
          ${returnData.offer_text || ''}
        </div>
        ${returnData.sub_text ? `<div style="color:#94a3b8;font-size:11px">${returnData.sub_text}</div>` : ''}
      </div>
      <button id="mcp-return-rev-cta" style="
        background:${c.accent};color:${returnData.type === 'researcher_nudge' ? '#000' : '#fff'};
        border:none;border-radius:8px;padding:10px 20px;
        font-size:13px;font-weight:800;cursor:pointer;white-space:nowrap;
      ">${returnData.cta_text || 'View Offer'}</button>
    `;

    const target = container
      || document.getElementById('mcp-blocks-root')
      || document.querySelector('.scan-results-area');
    if (target) target.appendChild(panel);

    // Track impression
    const offerId = returnData.offer_id || 'return_user_offer';
    trackRevenueEvent({
      event_type:    'welcome_back_shown',
      offer_type:    'welcome_back',
      offer_id:      offerId,
      offer_name:    returnData.headline || '',
      display_price: returnData.display_price || 0,
      discount_pct:  returnData.discount_pct || 0,
      user_type:     returnData.type || 'returning',
      module:        decision?.module || '',
      context:       'return_user',
    });

    // CTA click → track + navigate
    const ctaBtn = document.getElementById('mcp-return-rev-cta');
    if (ctaBtn) {
      ctaBtn.addEventListener('click', () => {
        trackRevenueEvent({
          event_type:    'welcome_back_converted',
          offer_type:    'welcome_back',
          offer_id:      offerId,
          offer_name:    returnData.headline || '',
          display_price: returnData.display_price || 0,
          discount_pct:  returnData.discount_pct || 0,
          user_type:     returnData.type || 'returning',
          module:        decision?.module || '',
          context:       'return_user',
        });
        const dest = returnData.redirect_url || '/products.html';
        window.location.href = dest;
      }, { once: true });
    }

  } catch (e) { console.warn('[MCPv18] Return user revenue render error:', e); }
}

// ── Phase 8+9: Register new UI block renderers ─────────────────────────────────
// These extend BLOCK_RENDERERS after declaration (v18 blocks are revenue-specific)
// Called from renderUIBlocks() like any other block.
function _registerV18Blocks() {
  // urgency_signal: renders the urgency bar (Phase 8)
  BLOCK_RENDERERS['urgency_signal'] = (decision, container) => {
    const signal = decision?.revenue?.urgency_signal;
    if (signal) renderUrgencySignal(signal, container);
  };

  // loss_prevention_trigger: marks loss prevention as active (Phase 7)
  // Actual UI renders on trigger (exit/inactivity) not on block render
  BLOCK_RENDERERS['loss_prevention_trigger'] = (decision, _container) => {
    const lp = decision?.revenue?.loss_prevention;
    if (lp?.eligible) {
      _LossPrevention.init(lp, decision);
    }
  };

  // return_user_revenue: renders personalized return-user offer (Phase 9)
  BLOCK_RENDERERS['return_user_revenue'] = (decision, container) => {
    const rur = decision?.revenue?.return_user_revenue;
    if (rur) renderReturnUserRevenue(rur, container, decision);
  };
}

// ── Phase 6: Pricing signal renderer ──────────────────────────────────────────
/**
 * Applies a visual pricing note to the training banner.
 * ONLY modifies display text — never changes actual payment amounts.
 */
function applyPricingSignal(signal) {
  try {
    if (!signal?.show) return;
    const trainingBanner = document.getElementById('mcp-training-banner');
    if (!trainingBanner) return;

    const existing = trainingBanner.querySelector('.mcp-pricing-signal');
    if (existing) existing.remove();

    const ps = document.createElement('div');
    ps.className = 'mcp-pricing-signal';
    ps.style.cssText = `
      display:inline-flex;align-items:center;gap:8px;margin-top:6px;
    `;
    ps.innerHTML = `
      <span style="color:#94a3b8;font-size:12px;text-decoration:line-through">₹${signal.original_price}</span>
      <span style="color:#10b981;font-size:14px;font-weight:800">₹${signal.display_price}</span>
      <span style="background:#10b981;color:#fff;font-size:10px;font-weight:800;padding:2px 7px;border-radius:4px">${signal.label}</span>
    `;

    // Inject after the course name line
    const courseNameEl = trainingBanner.querySelector('div[style*="font-weight:600"]');
    if (courseNameEl) courseNameEl.after(ps);
    else trainingBanner.appendChild(ps);
  } catch { /* silent */ }
}

// ── Global purchase event hook (called by CDB_PAY after confirmed purchase) ───
/**
 * Call this AFTER a successful payment to record conversion signal.
 * This is the most valuable learning signal — don't miss it.
 *
 * Usage in payment handler:
 *   window.MCPControl.trackPurchase('SOC_PLAYBOOK_2026', 'SOC Analyst Survival Playbook 2026', 999, 'training');
 */
function trackPurchase(item_id, item_name, amount_inr, rec_type = 'training') {
  trackFeedback({
    action:              'purchase',
    recommendation_type: rec_type,
    item_id,
    item_name,
    revenue_inr:         0, // server-side verified — never trust client revenue
  });
  // Flush immediately on purchase
  _flushFeedback();
}

// ── v18: Register revenue block renderers into BLOCK_RENDERERS ────────────────
// Must be called after BLOCK_RENDERERS is defined (hoisted above this point)
_registerV18Blocks();

// ── Export as module + window global ──────────────────────────────────────────
const MCPControl = {
  // Core
  decide,
  renderUIBlocks,
  renderUIBlocksWithTracking,
  showPersonalizationBar,
  integrate:            integrateWithTracking,  // v18: full autopilot
  clearCache,
  // v17: self-learning feedback
  trackFeedback,
  trackIgnore,
  trackPurchase,
  applyPricingSignal,
  flushFeedback:        _flushFeedback,
  // v18: revenue autopilot
  trackRevenueEvent,
  renderUrgencySignal,
  renderReturnUserRevenue,
  lossPrevention:       _LossPrevention,        // { init, destroy }
};
export { MCPControl };

// Expose globally for inline HTML usage
if (typeof window !== 'undefined') {
  window.MCPControl = MCPControl;

  // Auto-flush feedback buffer on page unload (catch anything buffered)
  window.addEventListener('beforeunload', () => _flushFeedback(), { passive: true });
  window.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') _flushFeedback();
  }, { passive: true });

  // v18: cleanup loss prevention on page unload
  window.addEventListener('pagehide', () => {
    _LossPrevention.destroy();
  }, { passive: true });
}
