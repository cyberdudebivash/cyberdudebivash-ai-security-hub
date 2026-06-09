/**
 * sentinel-apex-dashboard.js
 * Drop-in dashboard client — replaces ALL hardcoded metrics with live API data.
 *
 * Usage: <script src="/static/js/sentinel-apex-dashboard.js" defer></script>
 *
 * Automatically wires:
 *   - [data-live="cve-total"]            → live CVE count
 *   - [data-live="cve-critical"]         → critical CVE count
 *   - [data-live="cve-kev"]              → CISA KEV count
 *   - [data-live="cve-last-updated"]     → last ingest timestamp
 *   - [data-live="scans-completed"]      → total completed scans
 *   - [data-live="scans-active"]         → active scans right now
 *   - [data-live="scans-today"]          → scans completed today
 *   - [data-live="paying-customers"]     → verified paying customers
 *   - [data-live="soar-rules"]           → SOAR rules generated
 *   - [data-live="mrr"]                  → monthly recurring revenue
 *   - [data-live="arr"]                  → annual recurring revenue
 *   - [data-live="revenue-today"]        → today's revenue
 *   - [data-live="threat-level"]         → computed threat level
 *
 * Status bar:
 *   - [data-status="api"]                → ✓ / ✗ / ⚠
 *   - [data-status="db"]
 *   - [data-status="cache"]
 *   - [data-status="sentinel-apex"]
 *   - [data-status="overall"]
 *
 * Compliance badges:
 *   - [data-compliance-badge]            → replaced with honest alignment label
 *
 * Refresh: every 30 seconds (configurable via data-refresh-interval on <body>)
 */

(function SentinelApexDashboard() {
  'use strict';

  // ── Config ──────────────────────────────────────────────────
  const API_BASE = window.SENTINEL_API_BASE || 'https://cyberdudebivash.in';
  const REFRESH_INTERVAL = parseInt(
    document.body?.dataset?.refreshInterval || '30000', 10
  );

  const ENDPOINTS = {
    metrics:    `${API_BASE}/api/mythos/status`,
    cveCount:   `${API_BASE}/api/health/cve-count`,
    statusBar:  `${API_BASE}/api/health/status-bar`,
    compliance: `${API_BASE}/api/trust/compliance`,
    health:     `${API_BASE}/api/health`,
  };

  // ── State ───────────────────────────────────────────────────
  let lastMetrics = null;
  let refreshTimer = null;
  let isRefreshing = false;

  // ── Bootstrap ───────────────────────────────────────────────
  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', bootstrap);
    } else {
      bootstrap();
    }
  }

  function bootstrap() {
    refresh();
    refreshTimer = setInterval(refresh, REFRESH_INTERVAL);
  }

  // ── Main refresh cycle ───────────────────────────────────────
  async function refresh() {
    if (isRefreshing) return;
    isRefreshing = true;

    try {
      const [metricsRes, statusRes, complianceRes] = await Promise.allSettled([
        fetchJson(ENDPOINTS.metrics),
        fetchJson(ENDPOINTS.statusBar),
        fetchJson(ENDPOINTS.compliance),
      ]);

      if (metricsRes.status === 'fulfilled' && metricsRes.value?.ok) {
        applyMetrics(metricsRes.value.data);
        lastMetrics = metricsRes.value.data;
      }

      if (statusRes.status === 'fulfilled' && statusRes.value?.ok) {
        applyStatusBar(statusRes.value.data);
      }

      if (complianceRes.status === 'fulfilled' && complianceRes.value?.ok) {
        applyComplianceBadges(complianceRes.value.data.frameworks);
      }

      // Update marquee last-updated timestamp
      setTimestamp();

    } catch (e) {
      console.error('[SentinelApex] Refresh failed:', e);
    } finally {
      isRefreshing = false;
    }
  }

  // ── Apply metrics to DOM ─────────────────────────────────────
  function applyMetrics(data) {
    if (!data) return;
    const d = data.display || {};

    // CVE counters
    setLive('cve-total',       d.cve_total        || formatCount(data.cve?.total_tracked));
    setLive('cve-critical',    String(data.cve?.critical_count ?? '—'));
    setLive('cve-kev',         String(data.cve?.kev_count ?? '—'));
    setLive('cve-last-updated', formatTimestamp(data.cve?.last_ingestion_at));

    // Scan counters
    setLive('scans-completed', d.scans_completed   || formatCount(data.scans?.total_completed));
    setLive('scans-active',    d.active_scans       || String(data.scans?.active_now ?? '0'));
    setLive('scans-today',     String(data.scans?.completed_today ?? '0'));

    // Subscription / revenue
    setLive('paying-customers', d.paying_customers || String(data.subscriptions?.total_active ?? '0'));
    setLive('mrr',              d.mrr              || formatInr(data.subscriptions?.mrr_paise));
    setLive('arr',              d.arr              || formatInr(data.subscriptions?.arr_paise));
    setLive('revenue-today',    d.revenue_today    || formatInr(data.subscriptions?.revenue_today_paise));

    // SOAR
    setLive('soar-rules', d.soar_rules || formatCount(data.soar?.total_generated));

    // Threat level
    setLive('threat-level', data.health?.cve_ingester
      ? computeThreatDisplay(data.cve?.critical_count, data.cve?.kev_count)
      : 'MODERATE');

    // Update page title threat level if present
    const threatBadge = document.querySelector('[data-threat-level-badge]');
    if (threatBadge) {
      const level = computeThreatDisplay(data.cve?.critical_count, data.cve?.kev_count);
      threatBadge.textContent = `THREAT: ${level}`;
      threatBadge.className = threatBadge.className.replace(
        /\b(threat-critical|threat-high|threat-moderate|threat-low|threat-minimal)\b/g, ''
      );
      threatBadge.classList.add(`threat-${level.toLowerCase()}`);
    }
  }

  // ── Apply status bar ─────────────────────────────────────────
  function applyStatusBar(data) {
    if (!data) return;

    setStatus('api',           data.api?.status,           data.api?.icon);
    setStatus('db',            data.db?.status,            data.db?.icon);
    setStatus('cache',         data.cache?.status,         data.cache?.icon);
    setStatus('sentinel-apex', data.sentinel_apex?.status, data.sentinel_apex?.icon);
    setStatus('overall',       data.overall);

    // Update active scans counter in status bar
    const activeScanEl = document.querySelector('[data-status-bar="active-scans"]');
    if (activeScanEl) {
      activeScanEl.textContent = String(data.active_scans ?? '0');
    }

    // Update version
    const versionEl = document.querySelector('[data-status-bar="version"]');
    if (versionEl && data.version) {
      versionEl.textContent = `⬡ ${data.version}`;
    }

    // Update UTC timestamp in status bar
    const tsEl = document.querySelector('[data-status-bar="timestamp"]');
    if (tsEl && data.timestamp_utc) {
      tsEl.textContent = data.timestamp_utc.replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
    }
  }

  // ── Apply compliance badges ───────────────────────────────────
  function applyComplianceBadges(frameworks) {
    if (!frameworks?.length) return;

    const frameworkMap = {};
    for (const fw of frameworks) {
      frameworkMap[fw.framework] = fw;
    }

    // Replace all badge elements
    document.querySelectorAll('[data-compliance-badge]').forEach((el) => {
      const key = el.dataset.complianceBadge;
      const fw = frameworkMap[key];
      if (!fw) return;

      // Set title attribute with scope note
      el.title = fw.scope_note;

      // Add alignment indicator
      const indicator = el.querySelector('[data-alignment-level]');
      if (indicator) {
        indicator.textContent = fw.alignment_label;
      }

      // Add data attribute for CSS targeting
      el.dataset.alignmentLevel = fw.alignment_level;
      el.classList.remove('badge-certified', 'badge-aligned', 'badge-partial');
      el.classList.add(`badge-${fw.alignment_level}`);
    });

    // Replace entire compliance section if present
    const complianceSection = document.querySelector('[data-compliance-section]');
    if (complianceSection) {
      renderComplianceSection(complianceSection, frameworks);
    }
  }

  function renderComplianceSection(container, frameworks) {
    const ICONS = {
      iso27001:  '🛡️',
      soc2:      '🔒',
      gdpr:      '🇪🇺',
      pcidss:    '💳',
      dpdp:      '🇮🇳',
      hipaa:     '🏥',
      owasp_llm: '⚡',
      mitre:     '🎯',
      nist_ai:   '📊',
    };

    const NAMES = {
      iso27001:  'ISO 27001:2022',
      soc2:      'SOC 2 Type II',
      gdpr:      'GDPR 2016/679',
      pcidss:    'PCI-DSS v4.0',
      dpdp:      'DPDP Act 2023',
      hipaa:     'HIPAA/HITECH',
      owasp_llm: 'OWASP LLM Top 10',
      mitre:     'MITRE ATT&CK',
      nist_ai:   'NIST AI RMF',
    };

    const badgeColor = (level) => {
      switch (level) {
        case 'certified': return '#0a7c42';  // green — has actual cert
        case 'aligned':   return '#1a56db';  // blue — aligned but not certified
        case 'partial':   return '#b45309';  // amber — partial
        default:          return '#6b7280';
      }
    };

    container.innerHTML = `
      <p style="font-size:12px;color:#6b7280;margin:0 0 12px;font-style:italic;">
        ℹ️ Badges indicate control alignment. Hover each badge to see scope. Certified = formal audit completed.
      </p>
      <div style="display:flex;flex-wrap:wrap;gap:8px;">
        ${frameworks.map(fw => `
          <span
            title="${escHtml(fw.scope_note)}"
            style="
              display:inline-flex;align-items:center;gap:4px;
              background:#f0f4ff;border:1px solid #c7d7fd;
              color:${badgeColor(fw.alignment_level)};
              border-radius:6px;padding:4px 10px;font-size:12px;
              cursor:help;
            "
          >
            ${ICONS[fw.framework] || '📋'}
            <span>${NAMES[fw.framework] || fw.framework}</span>
            <span style="font-size:10px;opacity:0.7;">
              ${fw.alignment_level === 'certified' ? '✓ Certified' : '~ Aligned'}
            </span>
          </span>
        `).join('')}
      </div>
    `;
  }

  // ── DOM helpers ──────────────────────────────────────────────
  function setLive(key, value) {
    if (value === null || value === undefined) return;
    document.querySelectorAll(`[data-live="${key}"]`).forEach((el) => {
      const prev = el.textContent;
      if (prev !== String(value)) {
        el.textContent = String(value);
        // Brief flash to indicate update
        el.classList.add('live-updated');
        setTimeout(() => el.classList.remove('live-updated'), 800);
      }
    });
  }

  function setStatus(key, status, icon) {
    document.querySelectorAll(`[data-status="${key}"]`).forEach((el) => {
      if (icon) el.textContent = icon;
      el.dataset.statusValue = status || 'unknown';
      el.classList.remove('status-ok', 'status-degraded', 'status-down', 'status-unknown');
      el.classList.add(`status-${status || 'unknown'}`);
      el.title = `${key}: ${status || 'unknown'}`;
    });
  }

  function setTimestamp() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZone: 'Asia/Kolkata',
    });
    document.querySelectorAll('[data-live="last-updated"]').forEach((el) => {
      el.textContent = `Intel updated: ${timeStr} IST`;
    });
  }

  // ── Formatters ────────────────────────────────────────────────
  function formatCount(n) {
    if (n === null || n === undefined) return '—';
    if (n === 0) return '0';
    return `${n.toLocaleString('en-IN')}+`;
  }

  function formatInr(paise) {
    if (!paise && paise !== 0) return '₹0';
    const rupees = paise / 100;
    return `₹${rupees.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`;
  }

  function formatTimestamp(epoch) {
    if (!epoch) return 'Never';
    try {
      return new Date(epoch * 1000).toLocaleTimeString('en-IN', {
        hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Kolkata',
      }) + ' IST';
    } catch { return 'Unknown'; }
  }

  function computeThreatDisplay(critical, kev) {
    if ((kev ?? 0) > 50 || (critical ?? 0) > 100) return 'CRITICAL';
    if ((kev ?? 0) > 20 || (critical ?? 0) > 50)  return 'HIGH';
    if ((kev ?? 0) > 5  || (critical ?? 0) > 20)  return 'MODERATE';
    if ((critical ?? 0) > 0)                        return 'LOW';
    return 'MINIMAL';
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Fetch with timeout ────────────────────────────────────────
  async function fetchJson(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
        cache: 'no-store',
      });
      if (!res.ok) return null;
      return res.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  // ── Public API ───────────────────────────────────────────────
  window.SentinelApex = {
    refresh,
    getLastMetrics: () => lastMetrics,
    destroy: () => { if (refreshTimer) clearInterval(refreshTimer); },
  };

  init();

})();
