/**
 * sentinel-apex-live-metrics.js — v31.1
 * Drop-in frontend client for CYBERDUDEBIVASH AI Security Hub
 *
 * READS FROM:
 *   GET /api/platform/metrics   → all platform counters (real D1 values)
 *   GET /api/trust/compliance   → framework alignment records (honest badges)
 *   GET /api/health             → status bar components
 *
 * WIRES:
 *   [data-live="cve-total"]          → total_cves_tracked
 *   [data-live="cve-critical"]       → critical_threats
 *   [data-live="cve-kev"]            → kev_count
 *   [data-live="scans-completed"]    → total_scans
 *   [data-live="scans-today"]        → scans_today
 *   [data-live="scans-active"]       → active_scans (from health endpoint)
 *   [data-live="paying-customers"]   → active_customers
 *   [data-live="soar-rules"]         → soar_rules_total
 *   [data-live="revenue-today"]      → revenue_today_inr (formatted ₹)
 *   [data-live="revenue-month"]      → revenue_month_inr (formatted ₹)
 *   [data-live="threat-level"]       → computed threat level string
 *   [data-live="last-updated"]       → timestamp of last successful refresh
 *
 *   [data-status="api"]              → ✓ / ✗ / ⚠ from /api/health components.database
 *   [data-status="db"]               → database probe
 *   [data-status="cache"]            → cache probe
 *   [data-status="sentinel-apex"]    → threat_intel probe
 *   [data-status="overall"]          → overall status
 *
 *   [data-compliance-section]        → replaced with live badge grid
 *
 * INSTALL:
 *   1. Copy this file to your frontend static assets folder
 *   2. Add to <head>:  <script src="/assets/sentinel-apex-live-metrics.js" defer></script>
 *   3. Add data-live="..." attributes to the elements listed above
 *   4. Optionally add data-compliance-section to the badge container div
 *
 * REFRESH: every 30 seconds (matches /api/platform/metrics KV TTL of 45s)
 */

(function SentinelApexLiveMetrics() {
  'use strict';

  const API_BASE = window.SENTINEL_API_BASE || '';
  const REFRESH_MS = 30_000;

  // ── Fetch helpers ──────────────────────────────────────────────────────────
  async function fetchJson(path) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    try {
      const r = await fetch(API_BASE + path, {
        signal: ctrl.signal,
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      clearTimeout(t);
      if (!r.ok) return null;
      return r.json();
    } catch { return null; }
  }

  // ── DOM helpers ────────────────────────────────────────────────────────────
  function setLive(key, value) {
    if (value === null || value === undefined) return;
    document.querySelectorAll(`[data-live="${key}"]`).forEach(el => {
      const s = String(value);
      if (el.textContent !== s) {
        el.textContent = s;
        el.classList.add('cdbb-updated');
        setTimeout(() => el.classList.remove('cdbb-updated'), 900);
      }
    });
  }

  function setStatus(key, status) {
    const icon = status === 'ok' ? '✓' : status === 'degraded' ? '⚠' : status === 'error' ? '✗' : '?';
    document.querySelectorAll(`[data-status="${key}"]`).forEach(el => {
      el.textContent = icon;
      el.dataset.statusValue = status || 'unknown';
      el.classList.remove('cdbb-status-ok','cdbb-status-degraded','cdbb-status-down','cdbb-status-unknown');
      el.classList.add('cdbb-status-' + (status === 'error' ? 'down' : status || 'unknown'));
      el.title = key + ': ' + (status || 'unknown');
    });
  }

  // ── Formatters ─────────────────────────────────────────────────────────────
  function fmtInr(paise) {
    if (paise === null || paise === undefined) return '₹—';
    const r = Math.round(paise / 100);
    return '₹' + r.toLocaleString('en-IN');
  }

  function fmtCount(n) {
    if (n === null || n === undefined) return '—';
    if (n === 0) return '0';
    return n.toLocaleString('en-IN') + '+';
  }

  function threatLevel(crit, kev) {
    crit = crit || 0; kev = kev || 0;
    if (kev > 50 || crit > 100) return 'CRITICAL';
    if (kev > 20 || crit > 50)  return 'HIGH';
    if (kev > 5  || crit > 20)  return 'MODERATE';
    if (crit > 0)                return 'LOW';
    return 'MINIMAL';
  }

  function fmtTime(isoStr) {
    if (!isoStr) return '—';
    try {
      return new Date(isoStr).toLocaleTimeString('en-IN', {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false, timeZone: 'Asia/Kolkata',
      }) + ' IST';
    } catch { return '—'; }
  }

  // ── Apply metrics to DOM ───────────────────────────────────────────────────
  function applyMetrics(m) {
    if (!m) return;
    setLive('cve-total',       fmtCount(m.total_cves_tracked));
    setLive('cve-critical',    String(m.critical_threats ?? '—'));
    setLive('cve-kev',         String(m.kev_count ?? '—'));
    setLive('scans-completed', fmtCount(m.total_scans));
    setLive('scans-today',     String(m.scans_today ?? '0'));
    setLive('paying-customers',String(m.active_customers ?? '—'));
    setLive('soar-rules',      fmtCount(m.soar_rules_total));
    setLive('revenue-today',   fmtInr(m.revenue_today_inr));
    setLive('revenue-month',   fmtInr(m.revenue_month_inr));
    setLive('threat-level',    threatLevel(m.critical_threats, m.kev_count));
    setLive('last-updated',    'Updated: ' + fmtTime(m.hydrated_at));
  }

  // ── Apply health probes to status bar ─────────────────────────────────────
  function applyHealth(h) {
    if (!h) return;
    const comp = h.components || {};
    setStatus('api',          comp.edge?.status === 'ok' ? 'ok' : h.status === 'ok' ? 'ok' : 'degraded');
    setStatus('db',           comp.database?.status);
    setStatus('cache',        comp.cache?.status);
    setStatus('sentinel-apex',comp.threat_intel?.status);
    setStatus('overall',      h.status === 'ok' ? 'ok' : h.status === 'degraded' ? 'degraded' : 'down');
    // active scans from stats
    if (h.stats?.total_scans !== undefined) {
      setLive('scans-active', String(h.stats?.scans_today ?? '—'));
    }
  }

  // ── Apply compliance badges ────────────────────────────────────────────────
  const FRAMEWORK_ICONS = {
    iso27001: '🛡️', soc2: '🔒', gdpr: '🇪🇺', pcidss: '💳',
    dpdp: '🇮🇳', hipaa: '🏥', owasp_llm: '⚡', mitre: '🎯', nist_ai: '📊',
  };
  const FRAMEWORK_NAMES = {
    iso27001: 'ISO 27001:2022', soc2: 'SOC 2 Type II', gdpr: 'GDPR 2016/679',
    pcidss: 'PCI-DSS v4.0', dpdp: 'DPDP Act 2023', hipaa: 'HIPAA/HITECH',
    owasp_llm: 'OWASP LLM Top 10', mitre: 'MITRE ATT&CK', nist_ai: 'NIST AI RMF',
  };

  function applyCompliance(data) {
    if (!data?.frameworks?.length) return;
    const section = document.querySelector('[data-compliance-section]');
    if (!section) return;

    const notice = document.createElement('p');
    notice.style.cssText = 'font-size:11px;color:#6b7280;margin:0 0 10px;font-style:italic';
    notice.textContent = 'ℹ Hover each badge for scope detail. Certified = formal audit completed.';

    const wrap = document.createElement('div');
    wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px';

    for (const fw of data.frameworks) {
      const badgeColor  = fw.alignment_level === 'certified' ? '#0a7c42'
                         : fw.alignment_level === 'aligned'  ? '#1a56db'
                         : '#b45309';
      const bgColor     = fw.alignment_level === 'certified' ? '#ecfdf5'
                         : fw.alignment_level === 'aligned'  ? '#eff6ff'
                         : '#fffbeb';
      const borderColor = fw.alignment_level === 'certified' ? '#a7f3d0'
                         : fw.alignment_level === 'aligned'  ? '#bfdbfe'
                         : '#fde68a';
      const sublabel    = fw.alignment_level === 'certified' ? '✓ Certified'
                         : fw.alignment_level === 'partial'  ? '△ Partial'
                         : '~ Aligned';

      const span = document.createElement('span');
      span.title = fw.scope_note || '';
      span.style.cssText = `
        display:inline-flex;align-items:center;gap:4px;
        background:${bgColor};border:1px solid ${borderColor};
        color:${badgeColor};border-radius:6px;padding:3px 8px;
        font-size:12px;cursor:help;line-height:1.4
      `;
      span.innerHTML = `
        ${FRAMEWORK_ICONS[fw.framework] || '📋'}
        <span style="font-weight:500">${FRAMEWORK_NAMES[fw.framework] || fw.framework}</span>
        <span style="font-size:10px;opacity:0.75">${sublabel}</span>
      `;
      wrap.appendChild(span);
    }

    section.innerHTML = '';
    section.appendChild(notice);
    section.appendChild(wrap);
  }

  // ── Main refresh loop ──────────────────────────────────────────────────────
  let running = false;

  async function refresh() {
    if (running) return;
    running = true;
    try {
      const [metricsRes, healthRes, complianceRes] = await Promise.allSettled([
        fetchJson('/api/platform/metrics'),
        fetchJson('/api/health'),
        fetchJson('/api/trust/compliance'),
      ]);

      if (metricsRes.status === 'fulfilled' && metricsRes.value?.success) {
        applyMetrics(metricsRes.value.metrics);
      }
      if (healthRes.status === 'fulfilled' && healthRes.value) {
        applyHealth(healthRes.value);
      }
      if (complianceRes.status === 'fulfilled' && complianceRes.value?.success) {
        applyCompliance(complianceRes.value);
      }
    } finally {
      running = false;
    }
  }

  // ── Boot ───────────────────────────────────────────────────────────────────
  function init() {
    refresh();
    setInterval(refresh, REFRESH_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ── CSS for update flash (inject once) ─────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    @keyframes cdbb-flash{0%{background:rgba(16,185,129,.18)}100%{background:transparent}}
    .cdbb-updated{animation:cdbb-flash .9s ease-out}
    [data-status].cdbb-status-ok{color:#10b981}
    [data-status].cdbb-status-degraded{color:#f59e0b}
    [data-status].cdbb-status-down{color:#ef4444}
    [data-status].cdbb-status-unknown{color:#9ca3af}
  `;
  document.head.appendChild(style);

  // Public API
  window.SentinelApexMetrics = { refresh };

})();
