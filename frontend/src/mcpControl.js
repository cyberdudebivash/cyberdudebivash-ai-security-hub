/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — MCP Control Client v16.0
 *
 * THE OPERATING SYSTEM layer for the frontend.
 * Wraps POST /mcp/control with:
 *   ✅ Triple failsafe (control → decision → static)
 *   ✅ UI Block dynamic renderer (Phase 5)
 *   ✅ Personalization bar integration (Phase 6)
 *   ✅ KV-aware deduplication (Phase 8)
 *   ✅ Zero regression — all existing UI continues to work if MCP fails
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

// ── Export as module + window global ──────────────────────────────────────────
const MCPControl = { decide, renderUIBlocks, showPersonalizationBar, integrate, clearCache };
export { MCPControl };

// Expose globally for inline HTML usage
if (typeof window !== 'undefined') {
  window.MCPControl = MCPControl;
}
