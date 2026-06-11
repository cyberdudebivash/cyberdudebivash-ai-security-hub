/**
 * CYBERDUDEBIVASH® AI Security Hub
 * cti-workbench.js — Cyber Threat Intelligence Workbench
 *
 * Injects "CTI" tab into Phase 1 Command Centers.
 * Threat actor profiles, IOC search, intel collections.
 */

(function CDB_CTI_MODULE() {
  'use strict';
  const LOG = '[CDB-CTI]';

  function inject() {
    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 700); return; }
    if (document.getElementById('cdb-panel-cti')) return;

    const tab = document.createElement('button');
    tab.className    = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-cti';
    tab.setAttribute('role', 'tab');
    tab.textContent  = 'CTI Workbench';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id        = 'cdb-panel-cti';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadActors();
      loadCTIStats();
    });

    // Wire IOC search
    document.getElementById('cdb-ioc-search-btn')?.addEventListener('click', runIOCSearch);
    document.getElementById('cdb-ioc-search-input')?.addEventListener('keydown', e => {
      if (e.key === 'Enter') runIOCSearch();
    });

    console.info(LOG, 'CTI Workbench tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-kpi-grid">
      <div class="cdb-kpi-card accent-red">
        <div class="cdb-kpi-label">Threat Actors</div>
        <div class="cdb-kpi-value" id="cdb-cti-actor-count">—</div>
        <div class="cdb-kpi-sub">Tracked APT groups</div>
      </div>
      <div class="cdb-kpi-card accent-orange">
        <div class="cdb-kpi-label">IOC Database</div>
        <div class="cdb-kpi-value" id="cdb-cti-ioc-count">—</div>
        <div class="cdb-kpi-sub">Active indicators</div>
      </div>
      <div class="cdb-kpi-card accent-red">
        <div class="cdb-kpi-label">Critical IOCs</div>
        <div class="cdb-kpi-value" id="cdb-cti-crit-count">—</div>
        <div class="cdb-kpi-sub">High-severity indicators</div>
      </div>
      <div class="cdb-kpi-card accent-purple">
        <div class="cdb-kpi-label">CVE Indicators</div>
        <div class="cdb-kpi-value" id="cdb-cti-cve-count">—</div>
        <div class="cdb-kpi-sub">Vulnerability IOCs</div>
      </div>
    </div>

    <!-- IOC Search Bar -->
    <div style="display:flex;gap:8px;margin-bottom:20px;">
      <input id="cdb-ioc-search-input" type="text" placeholder="Search IOCs — IP, domain, CVE, hash, URL…"
        style="flex:1;background:#0f1729;border:1px solid #334155;border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:13px;outline:none;"
        autocomplete="off" spellcheck="false">
      <select id="cdb-ioc-type-filter" style="background:#0f1729;border:1px solid #334155;border-radius:8px;padding:10px 12px;color:#94a3b8;font-size:12px;outline:none;">
        <option value="">All Types</option>
        <option value="IP">IP Address</option>
        <option value="DOMAIN">Domain</option>
        <option value="CVE">CVE</option>
        <option value="HASH_SHA256">SHA256 Hash</option>
        <option value="URL">URL</option>
        <option value="EMAIL">Email</option>
      </select>
      <button id="cdb-ioc-search-btn" class="cdb-btn-primary" style="padding:10px 20px;">Search</button>
    </div>
    <div id="cdb-ioc-results" style="display:none;margin-bottom:20px;max-height:200px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;"></div>

    <div class="cdb-two-col">
      <div>
        <div class="cdb-section-heading">Threat Actor Profiles</div>
        <div id="cdb-cti-actor-list" style="display:flex;flex-direction:column;gap:6px;max-height:400px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1e293b transparent;">
          <div style="text-align:center;padding:20px;color:#475569;font-size:13px;">Loading actors…</div>
        </div>
      </div>
      <div>
        <div id="cdb-actor-detail" style="display:none;">
          <div class="cdb-section-heading" id="cdb-actor-detail-name">Actor Profile</div>
          <div id="cdb-actor-detail-body"></div>
        </div>
        <div id="cdb-actor-placeholder" style="background:#0f1729;border:1px dashed #1e293b;border-radius:10px;padding:24px;text-align:center;color:#475569;font-size:13px;">
          <div style="font-size:24px;margin-bottom:8px;">🕵️</div>
          Click an actor to view their full profile, TTPs, and associated IOCs.
        </div>

        <div style="margin-top:20px;">
          <div class="cdb-section-heading">Intel Sources</div>
          <div class="cdb-info-row"><span class="cdb-info-label">MITRE ATT&CK</span><span class="cdb-info-value" style="color:#4ade80">v15.1</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">Sentinel APEX Feed</span><span class="cdb-info-value" style="color:#4ade80">Live</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">NVD / NIST</span><span class="cdb-info-value" style="color:#4ade80">Connected</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">CISA KEV</span><span class="cdb-info-value" style="color:#4ade80">Connected</span></div>
          <div class="cdb-info-row"><span class="cdb-info-label">STIX 2.1 Export</span><span class="cdb-info-value" style="color:#6366f1">Available</span></div>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      CTI data sourced from Sentinel APEX + MITRE ATT&CK · Last updated: <span class="cdb-last-updated">—</span>
    </div>
  `;

  async function loadCTIStats() {
    try {
      const resp = await fetch('/api/cti/stats', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) return;
      const d = await resp.json();
      setText('cdb-cti-actor-count', fmt(d.actors?.total));
      setText('cdb-cti-ioc-count',   fmt(d.iocs?.total));
      setText('cdb-cti-crit-count',  fmt(d.iocs?.critical));
      setText('cdb-cti-cve-count',   fmt(d.iocs?.cves));
    } catch (_) {}
  }

  async function loadActors() {
    const list = document.getElementById('cdb-cti-actor-list');
    if (!list) return;

    try {
      const resp = await fetch('/api/cti/actors?limit=15', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d = await resp.json();
      const actors = d.actors || [];

      if (!actors.length) {
        list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:13px;">No threat actors in database.</div>';
        return;
      }

      const threatColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' };
      const nationFlags = {
        'Russia': '🇷🇺', 'China': '🇨🇳', 'North Korea': '🇰🇵',
        'Iran': '🇮🇷', 'United States': '🇺🇸', 'Unknown': '🌐',
      };

      list.innerHTML = actors.map(a => `
        <div class="cdb-feed-item cdb-actor-row" data-actor-id="${a.id}" style="cursor:pointer;flex-wrap:wrap;">
          <span style="font-size:18px;flex-shrink:0;">${nationFlags[a.nation_state] || '🌐'}</span>
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:700;color:#e2e8f0;">${a.name}</div>
            <div style="font-size:10px;color:#64748b;">${a.nation_state || 'Unknown'} · ${a.motivation || '—'}</div>
          </div>
          <span class="cdb-sev-badge" style="background:${threatColors[a.threat_level] || threatColors.MEDIUM}22;color:${threatColors[a.threat_level] || threatColors.MEDIUM}">${a.threat_level}</span>
        </div>
      `).join('');

      list.querySelectorAll('.cdb-actor-row').forEach(el => {
        el.addEventListener('click', () => showActorDetail(el.dataset.actorId, actors));
      });

      document.querySelectorAll('.cdb-last-updated').forEach(el => el.textContent = new Date().toLocaleTimeString());

    } catch (e) {
      console.info(LOG, 'Actors load failed:', e.message);
      list.innerHTML = '<div style="text-align:center;padding:20px;color:#475569;font-size:12px;">Could not load threat actors</div>';
    }
  }

  function showActorDetail(actorId, actors) {
    const actor = actors.find(a => a.id === actorId);
    if (!actor) return;

    document.getElementById('cdb-actor-placeholder')?.style.setProperty('display', 'none');
    const detail = document.getElementById('cdb-actor-detail');
    if (!detail) return;
    detail.style.display = 'block';

    setText('cdb-actor-detail-name', actor.name);

    const body = document.getElementById('cdb-actor-detail-body');
    if (!body) return;

    const aliases  = Array.isArray(actor.aliases) ? actor.aliases : [];
    const sectors  = Array.isArray(actor.target_sectors) ? actor.target_sectors : [];
    const techs    = Array.isArray(actor.known_techniques) ? actor.known_techniques : [];
    const threatColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' };

    body.innerHTML = `
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">
        <span class="cdb-sev-badge" style="background:${threatColors[actor.threat_level]}22;color:${threatColors[actor.threat_level]}">${actor.threat_level}</span>
        <span class="cdb-sev-badge" style="background:#1e293b;color:#94a3b8">${actor.sophistication}</span>
        ${actor.mitre_group_id ? `<span class="cdb-sev-badge" style="background:#6366f133;color:#a5b4fc">${actor.mitre_group_id}</span>` : ''}
      </div>
      ${actor.description ? `<p style="font-size:12px;color:#94a3b8;margin:0 0 12px;line-height:1.5;">${actor.description}</p>` : ''}
      <div class="cdb-info-row"><span class="cdb-info-label">Nation State</span><span class="cdb-info-value">${actor.nation_state || '—'}</span></div>
      <div class="cdb-info-row"><span class="cdb-info-label">Motivation</span><span class="cdb-info-value">${actor.motivation || '—'}</span></div>
      <div class="cdb-info-row"><span class="cdb-info-label">Confidence</span><span class="cdb-info-value">${actor.confidence_score || 0}%</span></div>
      <div class="cdb-info-row"><span class="cdb-info-label">Last Active</span><span class="cdb-info-value">${actor.last_active || '—'}</span></div>
      ${aliases.length ? `<div class="cdb-info-row"><span class="cdb-info-label">Aliases</span><span class="cdb-info-value" style="font-size:11px;">${aliases.slice(0, 3).join(', ')}</span></div>` : ''}
      ${sectors.length ? `
        <div style="margin-top:8px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Target Sectors</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;">
          ${sectors.map(s => `<span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:9999px;font-size:10px;">${s}</span>`).join('')}
        </div>
      ` : ''}
      ${techs.length ? `
        <div style="margin-top:8px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Known MITRE Techniques</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;">
          ${techs.slice(0, 8).map(t => `<span style="background:#6366f120;color:#a5b4fc;padding:2px 8px;border-radius:4px;font-size:10px;font-family:monospace;">${t}</span>`).join('')}
        </div>
      ` : ''}
    `;
  }

  async function runIOCSearch() {
    const input = document.getElementById('cdb-ioc-search-input');
    const typeF = document.getElementById('cdb-ioc-type-filter');
    const results = document.getElementById('cdb-ioc-results');
    if (!input || !results) return;

    const q    = input.value.trim();
    const type = typeF?.value;
    if (!q) return;

    results.style.display = 'block';
    results.innerHTML     = `<div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Searching…</div>`;

    try {
      const url  = `/api/cti/ioc/search?q=${encodeURIComponent(q)}${type ? '&type=' + type : ''}`;
      const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
      const d    = await resp.json();
      const iocs = d.results || [];

      if (!iocs.length) {
        results.innerHTML = `<div style="text-align:center;padding:12px;color:#475569;font-size:12px;">No IOCs found for "${q}"</div>`;
        return;
      }

      const sevMap = { CRITICAL: 'cdb-sev-crit', HIGH: 'cdb-sev-high', MEDIUM: 'cdb-sev-med', LOW: 'cdb-sev-low', INFO: 'cdb-sev-low' };
      results.innerHTML = iocs.map(ioc => `
        <div class="cdb-feed-item" style="flex-wrap:wrap;gap:6px;">
          <span class="cdb-sev-badge ${sevMap[ioc.severity] || 'cdb-sev-med'}">${ioc.severity}</span>
          <span style="font-size:10px;background:#1e293b;color:#94a3b8;padding:2px 6px;border-radius:4px;">${ioc.ioc_type}</span>
          <code style="flex:1;font-size:11px;color:#e2e8f0;font-family:monospace;word-break:break-all;">${ioc.value}</code>
          <span style="font-size:10px;color:#475569;">${ioc.source}</span>
        </div>
      `).join('');

    } catch (e) {
      results.innerHTML = `<div style="text-align:center;padding:12px;color:#475569;font-size:12px;">Search failed: ${e.message}</div>`;
    }
  }

  const $ = (id) => document.getElementById(id);
  const setText = (id, v) => { const el = $(id); if (el && v !== null) el.textContent = v; };
  const fmt = (n) => typeof n === 'number' ? n.toLocaleString() : (n ?? '—');

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }

})();
