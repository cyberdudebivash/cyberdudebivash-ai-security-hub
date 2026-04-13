/**
 * ═══════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI SECURITY HUB — OMNIGOD REVENUE ENGINE v14.0
 * ═══════════════════════════════════════════════════════════════════════
 * PHASE 1  → Hard Conversion Engine (Scan → Paywall → Unlock)
 * PHASE 2  → Auto Defense Sales Engine (CVE → Product mapping)
 * PHASE 3  → MYTHOS AI Selling (AI output CTAs)
 * PHASE 4  → Real-Time Activity Engine (Live counters / synthetic data)
 * PHASE 5  → Hero CTA Simplification
 * PHASE 6  → Marketplace Urgency & Trending Engine
 * PHASE 7  → Enterprise Lead Storage & Notification
 * PHASE 8  → Payment System Verification
 * PHASE 9  → Revenue Tracking Dashboard
 * PHASE 10 → Full System Integration
 * ═══════════════════════════════════════════════════════════════════════
 */
(function OMNIGOD_REVENUE_ENGINE() {
'use strict';

/* ══════════════════════════════════════════════════════════════════════
   INTERNAL CONSTANTS
══════════════════════════════════════════════════════════════════════ */
const REV = {
  version: '14.0.0',
  api: (window.CONFIG && window.CONFIG.API_BASE) || 'https://cyberdudebivash-security-hub.workers.dev',
  storageKey: 'cdb_rev_engine_v14',
  // Payment amounts (paise) per module
  moduleAmounts: { domain:19900, ai:49900, redteam:99900, identity:69900, compliance:49900 },
  modulePrices:  { domain:'₹199', ai:'₹499', redteam:'₹999', identity:'₹699', compliance:'₹499' },
  bundlePrice:   1999,
};

/* ── Revenue state (localStorage-backed) ─────────────────────────────── */
const REVENUE_STATE = (() => {
  const KEY = 'cdb_revenue_state_v14';
  const defaults = {
    todayRevenue:    0,
    monthRevenue:    0,
    totalPurchases:  0,
    conversions:     0,
    lastReset:       new Date().toDateString(),
  };
  function load() {
    try {
      const d = JSON.parse(localStorage.getItem(KEY) || '{}');
      // Reset daily if new day
      if (d.lastReset !== new Date().toDateString()) {
        d.todayRevenue = 0;
        d.conversions  = 0;
        d.lastReset    = new Date().toDateString();
        save(d);
      }
      return Object.assign({}, defaults, d);
    } catch { return { ...defaults }; }
  }
  function save(d) {
    try { localStorage.setItem(KEY, JSON.stringify(d)); } catch {}
  }
  function addRevenue(amount) {
    const d = load();
    d.todayRevenue   += amount;
    d.monthRevenue   += amount;
    d.totalPurchases += 1;
    d.conversions    += 1;
    save(d);
    updateRevenueDashboard();
  }
  return { load, save, addRevenue };
})();

/* ══════════════════════════════════════════════════════════════════════
   PHASE 1 — HARD CONVERSION ENGINE
   Hooks into renderResults to guarantee paywall is always shown
   for scans that haven't been paid for yet.
══════════════════════════════════════════════════════════════════════ */
function _initConversionEngine() {
  // Wrap renderResults to inject paywall enforcement
  const _originalRenderResults = window.renderResults;
  if (typeof _originalRenderResults !== 'function') return;

  window.renderResults = function(module, data) {
    // Call original render first
    _originalRenderResults(module, data);

    // After render: enforce strong paywall if not already unlocked
    try {
      const target = data.target || (window._currentScan && window._currentScan.target) || 'unknown';
      const isUnlocked = (typeof window.UNLOCK_STORE !== 'undefined')
        ? window.UNLOCK_STORE.get(module, target)
        : false;

      if (!isUnlocked) {
        const panel = document.getElementById(`results-${module}`);
        if (panel) {
          _injectStrongPaywall(panel, module, data, target);
          _injectAutoDefenseSales(panel, module, data); // Phase 2
        }
      }
    } catch(e) { /* non-blocking */ }
  };
}

function _injectStrongPaywall(panel, module, data, target) {
  // Only inject if there's already a paywall block OR there are locked findings
  const hasLocked = (data.locked_findings || []).length > 0;
  const hasCTA    = panel.querySelector('.unlock-cta');

  if (!hasLocked && !hasCTA) return; // no paywall needed — all findings unlocked

  // Remove any old weak paywall
  panel.querySelectorAll('.v14-strong-paywall').forEach(el => el.remove());

  const amount    = REV.moduleAmounts[module] || 19900;
  const price     = REV.modulePrices[module]  || '₹199';
  const score     = data.risk_score || 0;
  const level     = data.risk_level || 'MEDIUM';
  const lColor    = { CRITICAL:'#ef4444', HIGH:'#f59e0b', MEDIUM:'#a78bfa', LOW:'#10b981' }[level] || '#f59e0b';
  const lockedCnt = (data.locked_findings || []).length;

  // Urgency: how many people viewed similar reports today
  const viewCount = 3 + Math.floor(Math.random() * 12);
  const fixTime   = module === 'redteam' ? '72 hours' : module === 'compliance' ? '48 hours' : '24 hours';

  const paywall = document.createElement('div');
  paywall.className = 'v14-strong-paywall';
  paywall.style.cssText = `
    background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(124,58,237,.08));
    border:2px solid rgba(239,68,68,.35);border-radius:16px;padding:28px;
    margin:20px 0;position:relative;overflow:hidden;
  `;
  paywall.innerHTML = `
    <div style="position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#ef4444,#7c3aed,#f59e0b)"></div>

    <!-- Risk Alert Header -->
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <div style="width:48px;height:48px;border-radius:12px;background:${lColor}20;border:1px solid ${lColor}40;
                  display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0">🔒</div>
      <div>
        <div style="font-size:18px;font-weight:900;color:#fff;margin-bottom:2px">
          ${lockedCnt} Critical Findings Locked
        </div>
        <div style="font-size:13px;color:rgba(255,255,255,.55)">
          Risk Score: <span style="color:${lColor};font-weight:800">${score}/100 ${level}</span>
          · Attackers can exploit this within <strong style="color:#ef4444">${fixTime}</strong>
        </div>
      </div>
    </div>

    <!-- What's Locked -->
    <div style="background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:20px">
      <div style="font-size:11px;font-weight:800;color:rgba(255,255,255,.35);letter-spacing:.8px;text-transform:uppercase;margin-bottom:12px">
        🔒 LOCKED IN FULL REPORT
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        ${[
          ['💥','Full Attack Paths','How attackers would exploit each vulnerability'],
          ['🔧','Exploit Simulation','Step-by-step proof of concept for each CVE'],
          ['📋','Fix Scripts','Ready-to-deploy remediation code & configs'],
          ['📊','Compliance Gaps','ISO 27001, GDPR, PCI-DSS violations mapped'],
          ['🎯','CVSS Scores','Severity ratings for all findings'],
          ['📄','Executive PDF','Board-ready PDF report with risk timeline'],
        ].map(([icon, title, desc]) => `
          <div style="display:flex;gap:8px;padding:8px;background:rgba(255,255,255,.03);border-radius:8px">
            <div style="font-size:16px;flex-shrink:0">${icon}</div>
            <div>
              <div style="font-size:12px;font-weight:700;color:#e2e8f0">${title}</div>
              <div style="font-size:10px;color:rgba(255,255,255,.35);line-height:1.3">${desc}</div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Price + CTA -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
      <div>
        <div style="font-size:32px;font-weight:900;color:#f59e0b;line-height:1">${price}</div>
        <div style="font-size:11px;color:rgba(255,255,255,.45);margin-top:2px">one-time · full access · 30-day validity</div>
      </div>
      <div style="flex:1;min-width:220px">
        <button onclick="startPayment('${module}','${target.replace(/'/g,"&#39;")}',${amount},'${price}')"
          style="width:100%;padding:16px 24px;font-size:16px;font-weight:900;
                 background:linear-gradient(135deg,#f59e0b,#d97706);color:#000;
                 border:none;border-radius:12px;cursor:pointer;
                 box-shadow:0 4px 20px rgba(245,158,11,.4);
                 transition:transform .2s,box-shadow .2s;display:flex;align-items:center;justify-content:center;gap:8px"
          onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 8px 28px rgba(245,158,11,.5)'"
          onmouseout="this.style.transform='';this.style.boxShadow='0 4px 20px rgba(245,158,11,.4)'">
          🔓 Unlock Full Report — ${price}
        </button>
        <div style="text-align:center;margin-top:8px;font-size:11px;color:rgba(255,255,255,.35)">
          🔒 UPI · Bank · PayPal · Crypto &nbsp;|&nbsp; Access in 2–4 hrs
        </div>
      </div>
    </div>

    <!-- Social proof urgency -->
    <div style="display:flex;align-items:center;gap:8px;margin-top:16px;padding:10px 14px;
                background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.2);border-radius:8px">
      <div style="width:8px;height:8px;border-radius:50%;background:#ef4444;flex-shrink:0;
                  animation:urgencyPulse 1.5s ease infinite"></div>
      <div style="font-size:12px;color:rgba(255,255,255,.6)">
        <strong style="color:#ef4444">${viewCount} security teams</strong> scanned similar targets today ·
        <strong style="color:#f59e0b">${lockedCnt} critical risks</strong> require immediate patching
      </div>
    </div>
  `;

  // Insert before the existing unlock-cta (replace it) or after findings
  const existingCTA = panel.querySelector('.unlock-cta');
  if (existingCTA) {
    existingCTA.style.display = 'none'; // hide old one
    existingCTA.parentNode.insertBefore(paywall, existingCTA);
  } else {
    panel.appendChild(paywall);
  }
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 2 — AUTO DEFENSE SALES ENGINE
   Maps scan findings → marketplace products → injects upsell after results
══════════════════════════════════════════════════════════════════════ */
const CVE_TO_PRODUCT_MAP = {
  // By vulnerability type keywords
  'firewall':      { id:'fw-script',    name:'Enterprise Firewall Script',    price:799,  badge:'⚡ HOT' },
  'injection':     { id:'waf-rules',    name:'WAF + Input Validation Rules',  price:899,  badge:'🔥 TRENDING' },
  'ssl':           { id:'tls-hardening',name:'TLS Hardening Script',          price:599,  badge:'✅ QUICK FIX' },
  'tls':           { id:'tls-hardening',name:'TLS Hardening Script',          price:599,  badge:'✅ QUICK FIX' },
  'dns':           { id:'dns-sec',      name:'DNSSEC Configuration Pack',     price:499,  badge:'🛡 ESSENTIAL' },
  'sigma':         { id:'sigma-apt',    name:'Sigma Detection Rules (APT)',   price:1299, badge:'🔥 TRENDING' },
  'yara':          { id:'yara-pack',    name:'YARA Malware Detection Pack',   price:899,  badge:'🔥 TRENDING' },
  'ransomware':    { id:'ransomware-ir',name:'Ransomware IR Playbook',        price:1499, badge:'🚨 CRITICAL' },
  'phishing':      { id:'phishing-kit', name:'Anti-Phishing Detection Kit',   price:799,  badge:'🎯 TARGETED' },
  'mfa':           { id:'mfa-enforcer', name:'MFA Enforcement Script',        price:699,  badge:'🔐 IDENTITY' },
  'privilege':     { id:'priv-esc',     name:'Privilege Escalation Detector', price:999,  badge:'🚨 CRITICAL' },
  'compliance':    { id:'compliance-kit',name:'Compliance Automation Kit',    price:1299, badge:'📋 COMPLIANCE'},
  'owasp':         { id:'owasp-scanner',name:'OWASP Top 10 Scanner',          price:1099, badge:'🔍 APPSEC' },
  'default_domain':{ id:'domain-bundle',name:'Domain Security Bundle',        price:1299, badge:'🛡 BUNDLE' },
  'default_ai':    { id:'ai-sec-pack',  name:'AI/LLM Security Pack',          price:1499, badge:'🤖 AI SEC' },
  'default_redteam':{ id:'rt-toolkit',  name:'Red Team Defense Toolkit',      price:1999, badge:'🎯 RED TEAM' },
  'default_identity':{ id:'zt-bundle',  name:'Zero Trust Identity Bundle',    price:1299, badge:'🔐 ZT' },
};

function _autoMapCVEsToProducts(module, data) {
  const findings = [...(data.findings || []), ...(data.locked_findings || [])];
  const matched = new Map(); // deduplicate by product id

  findings.forEach(f => {
    const text = ((f.title || '') + ' ' + (f.description || '')).toLowerCase();
    for (const [keyword, product] of Object.entries(CVE_TO_PRODUCT_MAP)) {
      if (keyword.startsWith('default_')) continue;
      if (text.includes(keyword) && !matched.has(product.id)) {
        matched.set(product.id, product);
      }
    }
  });

  // Fallback: always recommend module-default product
  const defKey = `default_${module}`;
  if (CVE_TO_PRODUCT_MAP[defKey] && matched.size < 2) {
    const def = CVE_TO_PRODUCT_MAP[defKey];
    if (!matched.has(def.id)) matched.set(def.id, def);
  }

  return Array.from(matched.values()).slice(0, 4);
}

function _injectAutoDefenseSales(panel, module, data) {
  // Remove old if exists
  panel.querySelectorAll('.v14-defense-upsell').forEach(el => el.remove());

  const products = _autoMapCVEsToProducts(module, data);
  if (!products.length) return;

  const totalBundle = REV.bundlePrice;
  const saving = products.reduce((a, p) => a + p.price, 0) - totalBundle;

  const container = document.createElement('div');
  container.className = 'v14-defense-upsell';
  container.style.cssText = `
    background:linear-gradient(135deg,rgba(16,185,129,.06),rgba(0,212,255,.04));
    border:1px solid rgba(16,185,129,.25);border-radius:16px;padding:20px;margin-top:16px;
  `;

  const productCards = products.map(p => `
    <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px;
                display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
      <div style="flex:1;min-width:160px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
          <span style="font-size:10px;font-weight:800;padding:2px 6px;border-radius:4px;
                       background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)">
            ${p.badge}
          </span>
        </div>
        <div style="font-size:13px;font-weight:700;color:#e2e8f0">${p.name}</div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
        <div style="font-size:16px;font-weight:900;color:#00d4ff">₹${p.price.toLocaleString('en-IN')}</div>
        <button onclick="initiatePayment('${p.id}','${p.name}',${p.price})"
          style="background:rgba(0,212,255,.15);border:1px solid rgba(0,212,255,.35);color:#00d4ff;
                 padding:7px 14px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;
                 white-space:nowrap;transition:all .2s"
          onmouseover="this.style.background='rgba(0,212,255,.25)'"
          onmouseout="this.style.background='rgba(0,212,255,.15)'">
          Buy Fix
        </button>
      </div>
    </div>
  `).join('');

  container.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
      <div style="font-size:20px">🛡</div>
      <div>
        <div style="font-size:15px;font-weight:900;color:#fff">AI-Recommended Defense Fixes</div>
        <div style="font-size:12px;color:rgba(255,255,255,.45)">
          Based on your scan findings — deploy these to neutralize detected threats
        </div>
      </div>
    </div>

    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px">
      ${productCards}
    </div>

    <!-- Bundle offer -->
    <div style="background:linear-gradient(135deg,rgba(245,158,11,.12),rgba(239,68,68,.08));
                border:1px solid rgba(245,158,11,.35);border-radius:10px;padding:14px;
                display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
      <div>
        <div style="font-size:14px;font-weight:900;color:#f59e0b">
          🔥 Bundle Offer: Fix ALL Vulnerabilities
        </div>
        <div style="font-size:12px;color:rgba(255,255,255,.55);margin-top:2px">
          Complete defense package · Save ₹${saving > 0 ? saving.toLocaleString('en-IN') : '40%'} · Deploy in 24h
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <div>
          <div style="font-size:22px;font-weight:900;color:#f59e0b">₹${totalBundle.toLocaleString('en-IN')}</div>
          ${saving > 0 ? `<div style="font-size:10px;color:rgba(255,255,255,.35);text-decoration:line-through">₹${(totalBundle+saving).toLocaleString('en-IN')}</div>` : ''}
        </div>
        <button onclick="initiatePayment('defense-bundle-${module}','Complete Defense Bundle — ${module.toUpperCase()} Fix',${totalBundle * 100})"
          style="background:linear-gradient(135deg,#f59e0b,#d97706);color:#000;
                 padding:12px 20px;border-radius:10px;font-size:13px;font-weight:900;
                 border:none;cursor:pointer;white-space:nowrap;
                 box-shadow:0 4px 16px rgba(245,158,11,.4)"
          onmouseover="this.style.transform='translateY(-1px)'"
          onmouseout="this.style.transform=''">
          ⚡ Get Bundle — Save ${saving > 0 ? '₹'+saving.toLocaleString('en-IN') : '40%'}
        </button>
      </div>
    </div>
  `;

  panel.appendChild(container);
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 3 — MYTHOS AI SELLING ENGINE
   Injects CTAs into AI Brain content after it renders
══════════════════════════════════════════════════════════════════════ */
function _initMythosAISelling() {
  // Hook into fetchAIInsights if it exists
  const origFetch = window.fetchAIInsights;
  if (typeof origFetch !== 'function') return;

  window.fetchAIInsights = async function(module, data, tab) {
    await origFetch.apply(this, arguments);
    // After AI content renders, inject CTAs
    setTimeout(() => _injectAISellingCTAs(module, data), 600);
  };
}

function _injectAISellingCTAs(module, data) {
  const contentEl = document.getElementById(`aibrain-content-${module}`);
  if (!contentEl) return;
  if (contentEl.querySelector('.v14-ai-cta')) return; // already injected

  const score  = data.risk_score || 0;
  const target = (window._currentScan && window._currentScan.target) || data.target || 'your system';
  const price  = REV.modulePrices[module] || '₹199';
  const amount = REV.moduleAmounts[module] || 19900;
  const tgt    = target.replace(/'/g, "&#39;");

  const urgencyLevel = score >= 70 ? 'CRITICAL' : score >= 50 ? 'HIGH' : 'MODERATE';
  const urgencyMsg = {
    CRITICAL: `⚠️ <strong style="color:#ef4444">CRITICAL:</strong> Your system is vulnerable to active exploitation. Attackers can gain access within <strong>minutes</strong> using automated tools.`,
    HIGH:     `⚠️ <strong style="color:#f59e0b">HIGH RISK:</strong> Multiple vulnerabilities detected. Threat actors targeting this attack surface are active right now.`,
    MODERATE: `ℹ️ <strong style="color:#a78bfa">MODERATE RISK:</strong> Security gaps detected. Proactive patching prevents escalation to critical incidents.`,
  }[urgencyLevel];

  const ctaBanner = document.createElement('div');
  ctaBanner.className = 'v14-ai-cta';
  ctaBanner.style.cssText = `
    background:linear-gradient(135deg,rgba(124,58,237,.1),rgba(239,68,68,.08));
    border:1px solid rgba(124,58,237,.3);border-radius:12px;padding:16px;margin-top:16px;
  `;
  ctaBanner.innerHTML = `
    <div style="font-size:12px;color:rgba(255,255,255,.7);line-height:1.6;margin-bottom:14px">
      ${urgencyMsg}<br><br>
      <strong style="color:#a78bfa">Recommended actions:</strong>
      <ol style="margin:8px 0 0 16px;color:rgba(255,255,255,.6);font-size:12px;line-height:1.8">
        <li>Apply detected vulnerability patches immediately</li>
        <li>Deploy firewall rules to block exploitation vectors</li>
        <li>Run full compliance check for regulatory exposure</li>
      </ol>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button onclick="startPayment('${module}','${tgt}',${amount},'${price}')"
        style="flex:1;min-width:180px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;
               border:none;border-radius:10px;padding:12px 16px;font-size:13px;font-weight:800;
               cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px"
        onmouseover="this.style.transform='translateY(-1px)'"
        onmouseout="this.style.transform=''">
        🔓 Unlock Full Report — ${price}
      </button>
      <button onclick="document.getElementById('defense-marketplace')?.scrollIntoView({behavior:'smooth'})"
        style="flex:1;min-width:160px;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);
               color:#00d4ff;border-radius:10px;padding:12px 16px;font-size:13px;font-weight:700;cursor:pointer"
        onmouseover="this.style.background='rgba(0,212,255,.2)'"
        onmouseout="this.style.background='rgba(0,212,255,.1)'">
        🛡 Buy Defense Tools →
      </button>
    </div>
  `;

  contentEl.appendChild(ctaBanner);
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 4 — REAL-TIME ACTIVITY ENGINE
   Generates realistic synthetic counters and updates the UI
══════════════════════════════════════════════════════════════════════ */
const ACTIVITY_ENGINE = (() => {
  // Base state — realistic starting values
  let state = {
    scansRunning:    8 + Math.floor(Math.random() * 8),
    enterprisesActive: 3 + Math.floor(Math.random() * 5),
    revenueToday:    14200 + Math.floor(Math.random() * 12000),
    threatsBlocked:  247 + Math.floor(Math.random() * 80),
    scansTotal:      12847 + Math.floor(Math.random() * 500),
    usersOnline:     12 + Math.floor(Math.random() * 18),
  };

  function tick() {
    // Realistic increments — not too fast, not too slow
    if (Math.random() < 0.35) state.scansRunning = Math.max(3, state.scansRunning + (Math.random() < 0.5 ? 1 : -1));
    if (Math.random() < 0.15) state.enterprisesActive = Math.max(2, state.enterprisesActive + (Math.random() < 0.4 ? 1 : -1));
    if (Math.random() < 0.20) state.revenueToday += [199, 499, 699, 799, 999][Math.floor(Math.random() * 5)];
    if (Math.random() < 0.45) state.threatsBlocked += Math.floor(Math.random() * 3) + 1;
    if (Math.random() < 0.60) state.scansTotal += Math.floor(Math.random() * 3) + 1;
    if (Math.random() < 0.25) state.usersOnline = Math.max(5, state.usersOnline + (Math.random() < 0.5 ? 1 : -1));
    _applyToUI();
  }

  function _applyToUI() {
    // Activity bar counters
    _setText('v14-scans-running',    `${state.scansRunning} scans running now`);
    _setText('v14-enterprises-active',`${state.enterprisesActive} enterprises active`);
    _setText('v14-revenue-today',    `₹${state.revenueToday.toLocaleString('en-IN')} revenue today`);
    _setText('v14-threats-blocked',  `${state.threatsBlocked.toLocaleString('en-IN')} threats blocked`);
    _setText('v14-users-online',     `${state.usersOnline} users online now`);

    // Dashboard metric cards (existing IDs)
    _setTextSafe('mc-scans', state.scansTotal.toLocaleString('en-IN') + '+');

    // Hero attack counter
    _setTextSafe('hac-scans-today', state.scansTotal.toLocaleString('en-IN'));
    _setTextSafe('hero-live-scans',  state.scansTotal.toLocaleString('en-IN') + '+');

    // Marketplace live counters
    const purchasesToday = 47 + Math.floor(state.revenueToday / 400);
    _setTextSafe('ds-purchases-today', String(purchasesToday));
    _setTextSafe('ds-teams-active',    String(state.enterprisesActive + 7));
    _setTextSafe('ds-critical-count',  String(3 + Math.floor(Math.random() * 5)));

    // Revenue dashboard (Phase 9)
    updateRevenueDashboard();
  }

  function _setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function _setTextSafe(id, text) {
    const el = document.getElementById(id);
    if (el && !el.dataset.realData) el.textContent = text;
  }

  function start() {
    _applyToUI();
    setInterval(tick, 12000); // update every 12 seconds
    // Faster initial ticks
    setTimeout(tick, 3000);
    setTimeout(tick, 7000);
  }

  return { start, getState: () => state };
})();

/* ══════════════════════════════════════════════════════════════════════
   PHASE 5 — HERO LIVE ACTIVITY BAR
   Injects a real-time activity strip below the hero scan input
══════════════════════════════════════════════════════════════════════ */
function _injectHeroActivityBar() {
  const heroWrap = document.querySelector('.hero-scan-wrap');
  if (!heroWrap) return;
  if (document.getElementById('v14-hero-activity')) return;

  const bar = document.createElement('div');
  bar.id = 'v14-hero-activity';
  bar.style.cssText = `
    display:flex;align-items:center;justify-content:center;gap:20px;
    flex-wrap:wrap;margin-top:14px;padding:10px 16px;
    background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);
    border-radius:10px;font-size:11px;font-weight:700;
  `;
  bar.innerHTML = `
    <span style="display:flex;align-items:center;gap:5px;color:rgba(255,255,255,.55)">
      <span style="width:6px;height:6px;border-radius:50%;background:#ef4444;animation:urgencyPulse 1.5s ease infinite;flex-shrink:0"></span>
      <span id="v14-scans-running">12 scans running now</span>
    </span>
    <span style="display:flex;align-items:center;gap:5px;color:rgba(255,255,255,.55)">
      <span style="width:6px;height:6px;border-radius:50%;background:#10b981;animation:statLivePulse 2s ease infinite;flex-shrink:0"></span>
      <span id="v14-enterprises-active">5 enterprises active</span>
    </span>
    <span style="display:flex;align-items:center;gap:5px;color:rgba(255,255,255,.55)">
      <span style="width:6px;height:6px;border-radius:50%;background:#f59e0b;animation:statLivePulse 2.5s ease infinite;flex-shrink:0"></span>
      <span id="v14-revenue-today">₹18,400 revenue today</span>
    </span>
    <span style="display:flex;align-items:center;gap:5px;color:rgba(255,255,255,.55)">
      <span style="width:6px;height:6px;border-radius:50%;background:#7c3aed;animation:urgencyPulse 2s ease infinite;flex-shrink:0"></span>
      <span id="v14-threats-blocked">247 threats blocked</span>
    </span>
  `;

  heroWrap.appendChild(bar);
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 6 — MARKETPLACE URGENCY ENGINE
   Injects trending badges, sales counters, urgency signals into marketplace
══════════════════════════════════════════════════════════════════════ */
const MARKETPLACE_URGENCY = {
  badges: [
    { text:'🔥 Trending', color:'#ef4444', bg:'rgba(239,68,68,.12)' },
    { text:'⚡ Hot Pick', color:'#f59e0b', bg:'rgba(245,158,11,.12)' },
    { text:'🛡 Best Seller', color:'#10b981', bg:'rgba(16,185,129,.12)' },
    { text:'🎯 Recommended', color:'#a78bfa', bg:'rgba(124,58,237,.12)' },
    { text:'🚨 Active Exploit', color:'#ef4444', bg:'rgba(239,68,68,.12)' },
  ],
  salesTexts: [
    '🔥 9 teams bought this today',
    '⚡ 14 purchases this week',
    '🛡 Active exploit — patch now',
    '🎯 47 orgs deployed this week',
    '⏱ Patch within 24h',
    '🚨 23 CVEs mitigated',
    '📈 Most popular this month',
    '💼 Enterprise favorite',
  ],

  _getRandomBadge() {
    return this.badges[Math.floor(Math.random() * this.badges.length)];
  },
  _getRandomSales() {
    return this.salesTexts[Math.floor(Math.random() * this.salesTexts.length)];
  },

  injectIntoCards() {
    const cards = document.querySelectorAll('.ds-card');
    if (!cards.length) {
      // Retry after marketplace loads
      setTimeout(() => this.injectIntoCards(), 2000);
      return;
    }
    cards.forEach((card, i) => {
      if (card.dataset.v14Badge) return; // already done
      card.dataset.v14Badge = '1';

      // Urgency badge top-right
      const badge = this._getRandomBadge();
      const badgeEl = document.createElement('div');
      badgeEl.style.cssText = `
        position:absolute;top:12px;right:12px;
        background:${badge.bg};color:${badge.color};
        border:1px solid ${badge.color}40;border-radius:6px;
        padding:3px 8px;font-size:10px;font-weight:800;
        z-index:2;pointer-events:none;
      `;
      badgeEl.textContent = badge.text;
      if (getComputedStyle(card).position === 'static') card.style.position = 'relative';
      card.appendChild(badgeEl);

      // Sales proof text
      const salesText = this._getRandomSales();
      const proof = document.createElement('div');
      proof.style.cssText = `
        font-size:10px;color:rgba(255,255,255,.45);margin-top:6px;
        display:flex;align-items:center;gap:4px;
      `;
      proof.textContent = salesText;

      // Find the card's CTA button area and insert before it
      const btnArea = card.querySelector('button') || card.querySelector('.ds-btn');
      if (btnArea && btnArea.parentNode) {
        btnArea.parentNode.insertBefore(proof, btnArea);
      } else {
        card.appendChild(proof);
      }
    });
  },

  // Observe for new cards added dynamically
  watchForNewCards() {
    const obs = new MutationObserver(() => {
      const untagged = document.querySelectorAll('.ds-card:not([data-v14Badge])');
      if (untagged.length > 0) this.injectIntoCards();
    });
    const grid = document.getElementById('ds-grid') || document.getElementById('defense-marketplace');
    if (grid) obs.observe(grid, { childList: true, subtree: true });
  },
};

/* ══════════════════════════════════════════════════════════════════════
   PHASE 7 — ENTERPRISE LEAD STORAGE ENGINE
   Stores leads locally + fires notification + enriches pipeline
══════════════════════════════════════════════════════════════════════ */
function _initEnterpriseLeadEngine() {
  const origCreateLead = window.p4CreateLead;
  if (typeof origCreateLead !== 'function') return;

  window.p4CreateLead = async function() {
    // Call original
    await origCreateLead.apply(this, arguments);

    // Store lead locally for pipeline persistence
    try {
      const lead = {
        name:    document.getElementById('p4-lead-name')?.value?.trim()    || '',
        email:   document.getElementById('p4-lead-email')?.value?.trim()   || '',
        company: document.getElementById('p4-lead-company')?.value?.trim() || '',
        title:   document.getElementById('p4-lead-title')?.value?.trim()   || '',
        sector:  document.getElementById('p4-lead-sector')?.value          || '',
        size:    document.getElementById('p4-lead-size')?.value            || '',
        budget:  document.getElementById('p4-lead-budget')?.value          || '',
        urgency: document.getElementById('p4-lead-urgency')?.value         || '',
        phone:   document.getElementById('p4-lead-phone')?.value?.trim()   || '',
        notes:   document.getElementById('p4-lead-notes')?.value?.trim()   || '',
        ts:      new Date().toISOString(),
        stage:   'new',
        score:   _calcLeadScore({ budget: document.getElementById('p4-lead-budget')?.value, urgency: document.getElementById('p4-lead-urgency')?.value }),
      };

      if (lead.email) {
        const leads = _getLocalLeads();
        leads.unshift(lead);
        localStorage.setItem('cdb_enterprise_leads', JSON.stringify(leads.slice(0, 50)));
        _updatePipelineBoard();
        _showLeadToast(lead);
      }
    } catch(e) { /* non-blocking */ }
  };
}

function _calcLeadScore({ budget, urgency }) {
  let score = 50;
  if (budget === '>1CR')    score += 40;
  else if (budget === '25L-1CR') score += 25;
  else if (budget === '5L-25L')  score += 10;
  if (urgency === 'critical') score += 30;
  else if (urgency === 'high')   score += 15;
  return Math.min(score, 100);
}

function _getLocalLeads() {
  try { return JSON.parse(localStorage.getItem('cdb_enterprise_leads') || '[]'); } catch { return []; }
}

function _showLeadToast(lead) {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:99999;
    background:linear-gradient(135deg,rgba(16,185,129,.95),rgba(5,150,105,.95));
    border:1px solid rgba(16,185,129,.5);border-radius:12px;padding:16px 20px;
    box-shadow:0 8px 32px rgba(0,0,0,.4);max-width:320px;
    animation:alertFadeIn .3s ease;
  `;
  toast.innerHTML = `
    <div style="font-size:14px;font-weight:800;color:#fff;margin-bottom:4px">
      🎯 New Enterprise Lead Captured!
    </div>
    <div style="font-size:12px;color:rgba(255,255,255,.8)">
      ${lead.company || lead.name} · Score: ${lead.score}/100
    </div>
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function _updatePipelineBoard() {
  const leads = _getLocalLeads();
  const board = document.getElementById('p4-pipeline-board');
  if (!board) return;

  const stages = { new:'🆕 New', qualified:'✅ Qualified', proposal:'📄 Proposal', closed:'💰 Closed' };
  const grouped = {};
  Object.keys(stages).forEach(s => grouped[s] = []);
  leads.forEach(l => {
    const s = l.stage || 'new';
    if (grouped[s]) grouped[s].push(l);
  });

  const totalPipeline = leads.reduce((a, l) => {
    const budgetMap = { '<5L': 250000, '5L-25L': 1500000, '25L-1CR': 6250000, '>1CR': 15000000 };
    return a + (budgetMap[l.budget] || 0);
  }, 0);

  const pipelineEl = document.getElementById('p4-pipeline-revenue');
  if (pipelineEl) {
    pipelineEl.textContent = `₹${(totalPipeline / 100000).toFixed(1)}L pipeline`;
  }

  board.innerHTML = Object.entries(stages).map(([key, label]) => `
    <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px">
      <div style="font-size:12px;font-weight:700;color:rgba(255,255,255,.55);margin-bottom:8px">${label}</div>
      ${grouped[key].length === 0
        ? `<div style="font-size:11px;color:rgba(255,255,255,.25);padding:8px 0">No leads yet</div>`
        : grouped[key].map(l => `
          <div style="background:rgba(255,255,255,.04);border-radius:6px;padding:8px;margin-bottom:6px;font-size:11px">
            <div style="font-weight:700;color:#e2e8f0">${l.company || l.name || 'Lead'}</div>
            <div style="color:rgba(255,255,255,.45)">${l.sector || '—'} · Score: ${l.score}</div>
          </div>
        `).join('')
      }
    </div>
  `).join('');
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 8 — PAYMENT VERIFICATION
   Ensures all payment flows use correct config values
══════════════════════════════════════════════════════════════════════ */
function _verifyPaymentConfig() {
  // Verify the correct UPI IDs are shown in the payment modal
  const upiIdEl = document.querySelector('#cdb-pane-upi .cdb-pay-copy-val, [id*="upi-id"]');
  // The CDB_PAYMENT system already reads from the modal HTML which was
  // generated with correct values from paymentConfig.js — just verify
  const correctUPI = 'iambivash.bn-5@okaxis';
  if (upiIdEl && upiIdEl.textContent && !upiIdEl.textContent.includes(correctUPI)) {
    console.warn('[OMNIGOD] UPI ID mismatch detected — check payment modal HTML');
  }

  // Patch openManualPayment to also track revenue attempts
  const origOpen = window.openManualPayment;
  if (typeof origOpen === 'function') {
    window.openManualPayment = function(productId, amountInr, label) {
      // Track payment intent
      try {
        if (window.CDB_TRACK && typeof CDB_TRACK.event === 'function') {
          CDB_TRACK.event('payment_intent', { product: productId, amount: amountInr, label });
        }
        // Store intent for recovery
        sessionStorage.setItem('cdb_payment_intent', JSON.stringify({
          productId, amountInr, label, ts: Date.now()
        }));
      } catch {}
      return origOpen.apply(this, arguments);
    };
  }

  // Hook CDB_PAYMENT submit to track successful payments
  if (window.CDB_PAYMENT && typeof CDB_PAYMENT.submit === 'function') {
    const origSubmit = CDB_PAYMENT.submit.bind(CDB_PAYMENT);
    CDB_PAYMENT.submit = async function() {
      await origSubmit();
      // After submit: if successful, add to revenue
      const status = document.getElementById('cdb-pay-status');
      if (status && status.className === 'cdb-pay-ok') {
        const intent = (() => {
          try { return JSON.parse(sessionStorage.getItem('cdb_payment_intent') || '{}'); } catch { return {}; }
        })();
        if (intent.amountInr) REVENUE_STATE.addRevenue(parseInt(intent.amountInr));
      }
    };
  }
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 9 — REVENUE TRACKING DASHBOARD
   Injects a revenue widget into the dashboard metrics area
══════════════════════════════════════════════════════════════════════ */
function _injectRevenueDashboard() {
  // Look for a good injection point in the dashboard
  const targetEl = document.querySelector('.dashboard-grid, #dash-metrics, .dash-metrics-row, #p4-sales-metrics');
  if (!targetEl) {
    setTimeout(_injectRevenueDashboard, 2000);
    return;
  }
  if (document.getElementById('v14-revenue-dashboard')) return;

  const widget = document.createElement('div');
  widget.id = 'v14-revenue-dashboard';
  widget.style.cssText = `
    background:linear-gradient(135deg,rgba(16,185,129,.08),rgba(0,212,255,.05));
    border:1px solid rgba(16,185,129,.25);border-radius:16px;padding:20px;
    margin:16px 0;
  `;
  widget.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
      <div style="display:flex;align-items:center;gap:10px">
        <div style="font-size:20px">💰</div>
        <div>
          <div style="font-weight:800;font-size:15px;color:#fff">Revenue Engine</div>
          <div style="font-size:11px;color:rgba(255,255,255,.45)">Live tracking · updates every 12s</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:5px">
        <div style="width:6px;height:6px;border-radius:50%;background:#10b981;animation:statLivePulse 2s ease infinite"></div>
        <span style="font-size:11px;color:#10b981;font-weight:700">LIVE</span>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px">
      <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:900;color:#10b981" id="v14-rev-today">₹18,400</div>
        <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-top:3px">Today Revenue</div>
      </div>
      <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:900;color:#00d4ff" id="v14-rev-month">₹2.4L</div>
        <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-top:3px">Monthly Revenue</div>
      </div>
      <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:900;color:#f59e0b" id="v14-rev-purchases">47</div>
        <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-top:3px">Purchases</div>
      </div>
      <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px;text-align:center">
        <div style="font-size:22px;font-weight:900;color:#a78bfa" id="v14-rev-conversions">8.3%</div>
        <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-top:3px">Conv. Rate</div>
      </div>
    </div>
    <!-- Conversion funnel mini -->
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid rgba(255,255,255,.06)">
      <div style="font-size:11px;color:rgba(255,255,255,.35);font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">
        Conversion Funnel (Today)
      </div>
      <div style="display:flex;align-items:center;gap:4px">
        ${[
          { label:'Scans', value:100, color:'#00d4ff' },
          { label:'Views', value:42, color:'#7c3aed' },
          { label:'Intents', value:18, color:'#f59e0b' },
          { label:'Purchases', value:8, color:'#10b981' },
        ].map(s => `
          <div style="flex:${s.value};background:${s.color}20;border:1px solid ${s.color}30;border-radius:6px;padding:6px;text-align:center">
            <div style="font-size:13px;font-weight:800;color:${s.color}" id="v14-funnel-${s.label.toLowerCase()}">${s.value}</div>
            <div style="font-size:9px;color:rgba(255,255,255,.35)">${s.label}</div>
          </div>
        `).join('<div style="color:rgba(255,255,255,.2);font-size:12px">→</div>')}
      </div>
    </div>
  `;

  // Insert at beginning of target or after it
  if (targetEl.tagName === 'DIV' && targetEl.id === 'p4-sales-metrics') {
    targetEl.parentNode.insertBefore(widget, targetEl);
  } else {
    targetEl.insertBefore(widget, targetEl.firstChild);
  }
}

function updateRevenueDashboard() {
  const state = ACTIVITY_ENGINE.getState();
  const rev   = REVENUE_STATE.load();

  // Combine real + synthetic
  const todayTotal = rev.todayRevenue + state.revenueToday;
  const monthTotal = rev.monthRevenue + state.revenueToday * 4; // ~4x month multiplier

  _setRevEl('v14-rev-today',    `₹${todayTotal.toLocaleString('en-IN')}`);
  _setRevEl('v14-rev-month',    monthTotal >= 100000
    ? `₹${(monthTotal/100000).toFixed(1)}L`
    : `₹${monthTotal.toLocaleString('en-IN')}`);
  _setRevEl('v14-rev-purchases', String(47 + rev.totalPurchases));
  _setRevEl('v14-rev-conversions', '8.3%');
  _setRevEl('v14-revenue-today', `₹${todayTotal.toLocaleString('en-IN')} revenue today`);

  // Funnel
  const scansT = state.scansTotal % 100 + 50;
  _setRevEl('v14-funnel-scans',     String(scansT));
  _setRevEl('v14-funnel-views',     String(Math.floor(scansT * 0.42)));
  _setRevEl('v14-funnel-intents',   String(Math.floor(scansT * 0.18)));
  _setRevEl('v14-funnel-purchases', String(Math.floor(scansT * 0.08)));
}

function _setRevEl(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE 10 — FULL SYSTEM INTEGRATION
   Ties everything together, injects sticky CTA, and starts all engines
══════════════════════════════════════════════════════════════════════ */
function _injectStickyCTA() {
  if (document.getElementById('v14-sticky-cta')) return;

  const cta = document.createElement('div');
  cta.id = 'v14-sticky-cta';
  cta.style.cssText = `
    position:fixed;bottom:0;left:0;right:0;z-index:9990;
    background:linear-gradient(90deg,rgba(10,10,26,.97),rgba(15,15,46,.97));
    border-top:1px solid rgba(0,212,255,.2);
    padding:10px 20px;display:flex;align-items:center;justify-content:space-between;
    flex-wrap:wrap;gap:8px;backdrop-filter:blur(12px);
    transform:translateY(100%);transition:transform .4s ease;
  `;
  cta.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <div style="display:flex;align-items:center;gap:5px">
        <div style="width:7px;height:7px;border-radius:50%;background:#ef4444;animation:urgencyPulse 1.5s ease infinite"></div>
        <span style="font-size:12px;font-weight:700;color:rgba(255,255,255,.7)" id="v14-sticky-scans">12 scans running now</span>
      </div>
      <div style="font-size:12px;color:rgba(255,255,255,.5)">·</div>
      <div style="font-size:12px;color:rgba(255,255,255,.7)">
        Reports from <strong style="color:#f59e0b">₹199</strong> · Instant access
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px">
      <button onclick="document.getElementById('scanner')?.scrollIntoView({behavior:'smooth'});document.getElementById('v14-sticky-cta').style.transform='translateY(100%)'"
        style="background:linear-gradient(135deg,#00d4ff,#0284c7);color:#000;border:none;
               border-radius:8px;padding:9px 18px;font-size:13px;font-weight:800;cursor:pointer;
               white-space:nowrap"
        onmouseover="this.style.transform='translateY(-1px)'"
        onmouseout="this.style.transform=''">
        🚀 Scan Your Domain Free
      </button>
      <button onclick="document.getElementById('v14-sticky-cta').style.transform='translateY(100%)'"
        style="background:transparent;border:1px solid rgba(255,255,255,.15);color:rgba(255,255,255,.4);
               border-radius:6px;padding:8px 10px;font-size:12px;cursor:pointer">✕</button>
    </div>
  `;
  document.body.appendChild(cta);

  // Show after 8 seconds
  setTimeout(() => {
    cta.style.transform = 'translateY(0)';
  }, 8000);

  // Re-show every 2 minutes if dismissed
  setInterval(() => {
    if (cta.style.transform === 'translateY(100%)') {
      cta.style.transform = 'translateY(0)';
    }
  }, 120000);
}

function _injectUsersOnlineWidget() {
  if (document.getElementById('v14-users-online-widget')) return;
  const hero = document.querySelector('.hero-badge, .hero');
  if (!hero) return;

  const bar = document.createElement('div');
  bar.id = 'v14-users-online-widget';
  bar.style.cssText = `
    display:inline-flex;align-items:center;gap:5px;
    background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);
    border-radius:20px;padding:4px 12px;font-size:11px;
    font-weight:700;color:#10b981;margin:0 8px;
  `;
  bar.innerHTML = `
    <span style="width:6px;height:6px;border-radius:50%;background:#10b981;animation:statLivePulse 2s ease infinite"></span>
    <span id="v14-users-online">18 users online now</span>
  `;

  // Insert near hero badge
  const badge = document.querySelector('.hero-badge');
  if (badge && badge.parentNode) {
    badge.parentNode.insertBefore(bar, badge.nextSibling);
  }
}

/* ── Scan entry toast notification ──────────────────────────────────── */
function _injectScanStartToast() {
  const origRunScan = window.runScan;
  if (typeof origRunScan !== 'function') return;

  window.runScan = function(module) {
    // Show activity toast
    _showActivityToast(`🔍 Scan started · ${12 + Math.floor(Math.random() * 8)} teams scanning now`);
    return origRunScan.apply(this, arguments);
  };
}

function _showActivityToast(msg) {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;top:80px;right:20px;z-index:99999;
    background:rgba(10,10,26,.95);border:1px solid rgba(0,212,255,.3);
    border-radius:10px;padding:10px 16px;font-size:12px;font-weight:700;
    color:rgba(255,255,255,.8);backdrop-filter:blur(12px);
    box-shadow:0 4px 20px rgba(0,0,0,.4);
    animation:alertFadeIn .3s ease;max-width:280px;
  `;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity .3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

/* ── Enterprise demo slot generator ─────────────────────────────────── */
function _injectDemoSlots() {
  const container = document.getElementById('p4-demo-slots');
  if (!container) return;

  const now = new Date();
  const slots = [];
  // Generate 6 realistic slots in the next 3 days
  for (let i = 0; i < 3; i++) {
    const d = new Date(now);
    d.setDate(d.getDate() + i + 1);
    const dateStr = d.toLocaleDateString('en-IN', { weekday:'short', month:'short', day:'numeric' });
    ['10:00 AM IST', '3:00 PM IST'].forEach(time => {
      slots.push({ date: dateStr, time, available: Math.random() > 0.3 });
    });
  }

  container.innerHTML = slots.map(s => `
    <button onclick="${s.available ? `_selectDemoSlot(this,'${s.date} ${s.time}')` : 'void 0'}"
      style="display:inline-flex;align-items:center;gap:6px;margin:3px;padding:7px 12px;
             background:${s.available ? 'rgba(99,102,241,.1)' : 'rgba(255,255,255,.03)'};
             border:1px solid ${s.available ? 'rgba(99,102,241,.3)' : 'rgba(255,255,255,.07)'};
             color:${s.available ? '#e2e8f0' : 'rgba(255,255,255,.2)'};
             border-radius:8px;font-size:12px;cursor:${s.available ? 'pointer' : 'not-allowed'};
             transition:all .2s"
      ${s.available ? `onmouseover="this.style.background='rgba(99,102,241,.2)'" onmouseout="this.style.background='rgba(99,102,241,.1)'"` : ''}>
      ${s.available ? '📅' : '❌'} ${s.date} · ${s.time}
      ${!s.available ? `<span style="font-size:9px;color:rgba(255,255,255,.25)">Booked</span>` : ''}
    </button>
  `).join('');
}

window._selectDemoSlot = function(btn, slotStr) {
  // Clear other selections
  btn.closest('#p4-demo-slots').querySelectorAll('button').forEach(b => {
    b.style.background = 'rgba(99,102,241,.1)';
    b.style.borderColor = 'rgba(99,102,241,.3)';
  });
  btn.style.background = 'rgba(99,102,241,.3)';
  btn.style.borderColor = 'rgba(99,102,241,.6)';

  // Store selection
  window._selectedDemoSlot = slotStr;
  const nameEl = document.getElementById('p4-demo-name');
  if (nameEl) nameEl.focus();
};

/* ══════════════════════════════════════════════════════════════════════
   INIT — DOM ready
══════════════════════════════════════════════════════════════════════ */
function _init() {
  // Phase 1: Conversion engine
  _initConversionEngine();

  // Phase 3: MYTHOS AI selling
  _initMythosAISelling();

  // Phase 4: Real-time activity engine
  ACTIVITY_ENGINE.start();

  // Phase 5: Hero activity bar
  _injectHeroActivityBar();

  // Phase 7: Enterprise lead engine
  _initEnterpriseLeadEngine();

  // Phase 8: Payment verification
  _verifyPaymentConfig();

  // Phase 9: Revenue dashboard
  _injectRevenueDashboard();

  // Phase 10: Sticky CTA + integration
  _injectStickyCTA();
  _injectUsersOnlineWidget();
  _injectScanStartToast();

  // Marketplace urgency (Phase 6) — start watching
  setTimeout(() => {
    MARKETPLACE_URGENCY.injectIntoCards();
    MARKETPLACE_URGENCY.watchForNewCards();
  }, 2000);

  // Demo slots
  setTimeout(_injectDemoSlots, 1000);

  // Restore local pipeline board
  setTimeout(_updatePipelineBoard, 1500);

  // Update sticky scans counter from activity engine
  setInterval(() => {
    const state = ACTIVITY_ENGINE.getState();
    _setRevEl('v14-sticky-scans', `${state.scansRunning} scans running now`);
  }, 12000);

  console.log(`[OMNIGOD REVENUE ENGINE v${REV.version}] All systems online ⚡`);
}

// Boot when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _init);
} else {
  // DOM already loaded
  setTimeout(_init, 100);
}

})(); // END OMNIGOD_REVENUE_ENGINE
