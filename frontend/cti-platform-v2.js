/**
 * CYBERDUDEBIVASH® AI Security Hub — v34.0 Phase 4 (God Mode)
 * CTI Platform V2 — Watchlists · IOC Enrichment · STIX 2.1 Export
 *
 * Self-injecting IIFE. Adds "CTI v2" tab to .cdb-cc-nav.
 * Extends existing CTI Workbench tab without touching it.
 * Backed by /api/cti/v2/* endpoints.
 */
(function () {
  'use strict';

  const MODULE_ID  = 'cdb-p4-cti-v2';
  const TAB_ID     = 'cdb-p4-cti-v2-tab';
  const PANEL_ID   = 'cdb-p4-cti-v2-panel';

  let activeView = 'watchlists';

  // ── Inject ──────────────────────────────────────────────────────────────────
  function inject() {
    if (document.getElementById(MODULE_ID)) return;

    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }

    const tab = document.createElement('button');
    tab.id          = TAB_ID;
    tab.className   = 'cdb-cc-nav-btn';
    tab.textContent = '🛡 CTI v2';
    tab.addEventListener('click', activateTab);
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id        = PANEL_ID;
    panel.className = 'cdb-cc-panel';
    panel.style.display = 'none';
    panel.innerHTML = buildShell();
    body.appendChild(panel);

    const sentinel = document.createElement('div');
    sentinel.id    = MODULE_ID;
    sentinel.style.display = 'none';
    document.body.appendChild(sentinel);
  }

  function activateTab() {
    document.querySelectorAll('.cdb-cc-nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.cdb-cc-panel').forEach(p => { p.style.display = 'none'; });
    document.getElementById(TAB_ID).classList.add('active');
    document.getElementById(PANEL_ID).style.display = 'block';
    switchView(activeView);
  }

  // ── Shell ───────────────────────────────────────────────────────────────────
  function buildShell() {
    return `
      <div style="padding:20px;font-family:system-ui,sans-serif;display:flex;flex-direction:column;gap:16px;">
        <div>
          <h2 style="margin:0;font-size:18px;font-weight:700;color:var(--cdb-text,#f1f5f9);">🛡 CTI Platform v2</h2>
          <p style="margin:4px 0 0;font-size:12px;color:var(--cdb-muted,#94a3b8);">Watchlists · IOC Enrichment · STIX 2.1 Export</p>
        </div>
        <!-- Sub-nav -->
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="cti2-sub-btn active" data-view="watchlists" onclick="window._cti2View('watchlists')">📋 Watchlists</button>
          <button class="cti2-sub-btn" data-view="enrich" onclick="window._cti2View('enrich')">🔍 IOC Enrichment</button>
          <button class="cti2-sub-btn" data-view="stix" onclick="window._cti2View('stix')">📦 STIX Export</button>
        </div>
        <!-- Content -->
        <div id="cti2-content"></div>
      </div>`;
  }

  function styleSubBtns() {
    document.querySelectorAll('.cti2-sub-btn').forEach(b => {
      const active = b.classList.contains('active');
      b.style.cssText = `background:${active ? 'rgba(139,92,246,.2)' : 'rgba(255,255,255,.06)'};color:${active ? '#8b5cf6' : 'var(--cdb-muted,#94a3b8)'};border:1px solid ${active ? 'rgba(139,92,246,.4)' : 'rgba(255,255,255,.08)'};border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px;`;
    });
  }

  function switchView(view) {
    activeView = view;
    document.querySelectorAll('.cti2-sub-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.view === view);
    });
    styleSubBtns();
    const el = document.getElementById('cti2-content');
    if (!el) return;
    el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:8px;">Loading…</div>';

    if (view === 'watchlists') renderWatchlists();
    else if (view === 'enrich') renderEnrich();
    else if (view === 'stix')   renderSTIX();
  }

  // ── WATCHLISTS VIEW ─────────────────────────────────────────────────────────
  async function renderWatchlists() {
    const el = document.getElementById('cti2-content');

    try {
      const res  = await fetch('/api/cti/v2/watchlists', { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();
      const lists = data.watchlists || [];

      el.innerHTML = `
        <!-- Create watchlist form -->
        <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:14px;margin-bottom:14px;">
          <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);margin-bottom:10px;">+ New Watchlist</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
            <input id="wl-name" placeholder="Watchlist name*" style="${inputStyle()}" />
            <input id="wl-desc" placeholder="Description (optional)" style="${inputStyle()}" />
          </div>
          <button onclick="window._cti2CreateWL()" style="${submitBtnStyle()}">Create Watchlist</button>
        </div>

        <!-- List -->
        <div id="wl-list">
          ${!lists.length ? '<div style="color:var(--cdb-muted,#94a3b8);font-size:13px;padding:8px;">No watchlists yet.</div>' :
            lists.map(w => `
              <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:14px;margin-bottom:10px;border:1px solid rgba(255,255,255,.06);">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
                  <div>
                    <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);">${escHtml(w.name)}</div>
                    ${w.description ? `<div style="font-size:11px;color:var(--cdb-muted,#94a3b8);margin-top:2px;">${escHtml(w.description)}</div>` : ''}
                    <div style="font-size:11px;color:var(--cdb-muted,#64748b);margin-top:4px;">${w.entry_count || 0} entries · Matches: ${w.match_count || 0}</div>
                  </div>
                  <div style="display:flex;gap:6px;">
                    <button onclick="window._cti2OpenWL('${escHtml(w.id)}','${escHtml(w.name)}')" style="background:rgba(139,92,246,.15);color:#8b5cf6;border:1px solid rgba(139,92,246,.3);border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;">View Entries</button>
                    <button onclick="window._cti2DeleteWL('${escHtml(w.id)}')" style="background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.25);border-radius:6px;padding:5px 10px;cursor:pointer;font-size:11px;">Delete</button>
                  </div>
                </div>
                <!-- Inline entries for this watchlist -->
                <div id="wl-entries-${escHtml(w.id)}" style="display:none;margin-top:12px;"></div>
              </div>`).join('')}
        </div>`;
    } catch (e) {
      el.innerHTML = `<div style="color:#ef4444;font-size:13px;">${escHtml(e.message)}</div>`;
    }
  }

  window._cti2CreateWL = async function () {
    const name = document.getElementById('wl-name').value.trim();
    const desc = document.getElementById('wl-desc').value.trim();
    if (!name) return toast('error', 'Name required');
    try {
      const res  = await fetch('/api/cti/v2/watchlists', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description: desc }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast('success', `Watchlist "${name}" created`);
      renderWatchlists();
    } catch (e) { toast('error', e.message); }
  };

  window._cti2DeleteWL = async function (id) {
    if (!confirm('Delete this watchlist and all its entries?')) return;
    try {
      const res  = await fetch(`/api/cti/v2/watchlists/${id}`, { method: 'DELETE', credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast('success', 'Watchlist deleted');
      renderWatchlists();
    } catch (e) { toast('error', e.message); }
  };

  window._cti2OpenWL = async function (id, name) {
    const entriesEl = document.getElementById(`wl-entries-${id}`);
    if (!entriesEl) return;

    if (entriesEl.style.display === 'block') { entriesEl.style.display = 'none'; return; }
    entriesEl.style.display = 'block';
    entriesEl.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:12px;">Loading…</div>';

    try {
      const res  = await fetch(`/api/cti/v2/watchlists/${id}/entries`, { credentials: 'include', signal: AbortSignal.timeout(8000) });
      const data = await res.json();
      const entries = data.entries || [];

      entriesEl.innerHTML = `
        <div style="border-top:1px solid rgba(255,255,255,.06);padding-top:10px;">
          <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;">
            <input id="entry-val-${id}" placeholder="IOC value*" style="${inputStyle()}flex:1;" />
            <select id="entry-type-${id}" style="${inputStyle()}width:auto;">
              ${['ip','domain','hash','url','email','cidr','asn','cve'].map(t => `<option>${t}</option>`).join('')}
            </select>
            <input id="entry-conf-${id}" placeholder="Confidence (0-100)" type="number" min="0" max="100" value="70" style="${inputStyle()}width:100px;" />
            <button onclick="window._cti2AddEntry('${id}')" style="${submitBtnStyle()}">Add IOC</button>
          </div>
          ${!entries.length ? '<div style="color:var(--cdb-muted,#94a3b8);font-size:12px;">No entries yet.</div>' :
            `<div style="max-height:200px;overflow-y:auto;">
              <table style="width:100%;font-size:11px;border-collapse:collapse;">
                <thead><tr style="color:var(--cdb-muted,#64748b);">
                  <th style="text-align:left;padding:4px 6px;">IOC Value</th>
                  <th style="text-align:left;padding:4px 6px;">Type</th>
                  <th style="text-align:center;padding:4px 6px;">Conf.</th>
                  <th style="text-align:left;padding:4px 6px;">Added</th>
                </tr></thead>
                <tbody>
                  ${entries.map(e => `<tr style="border-top:1px solid rgba(255,255,255,.04);">
                    <td style="padding:4px 6px;color:var(--cdb-text,#e2e8f0);font-family:monospace;">${escHtml(e.ioc_value)}</td>
                    <td style="padding:4px 6px;color:#8b5cf6;">${escHtml(e.ioc_type)}</td>
                    <td style="padding:4px 6px;text-align:center;color:${e.confidence >= 70 ? '#22c55e' : '#f59e0b'};">${e.confidence}%</td>
                    <td style="padding:4px 6px;color:var(--cdb-muted,#64748b);">${fmtTime(e.added_at)}</td>
                  </tr>`).join('')}
                </tbody>
              </table>
            </div>`}
        </div>`;
    } catch (e) {
      entriesEl.innerHTML = `<div style="color:#ef4444;font-size:12px;">${escHtml(e.message)}</div>`;
    }
  };

  window._cti2AddEntry = async function (watchlistId) {
    const val  = document.getElementById(`entry-val-${watchlistId}`)?.value?.trim();
    const type = document.getElementById(`entry-type-${watchlistId}`)?.value;
    const conf = parseInt(document.getElementById(`entry-conf-${watchlistId}`)?.value || '70');
    if (!val) return toast('error', 'IOC value required');
    try {
      const res = await fetch(`/api/cti/v2/watchlists/${watchlistId}/entries`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc_value: val, ioc_type: type, confidence: conf }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast('success', 'IOC added');
      window._cti2OpenWL(watchlistId, '');
      window._cti2OpenWL(watchlistId, ''); // toggle & reload
    } catch (e) { toast('error', e.message); }
  };

  // ── ENRICHMENT VIEW ─────────────────────────────────────────────────────────
  function renderEnrich() {
    const el = document.getElementById('cti2-content');
    el.innerHTML = `
      <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:16px;margin-bottom:14px;">
        <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);margin-bottom:10px;">🔍 IOC Enrichment</div>
        <div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
          <input id="enrich-val" placeholder="IOC value (IP, domain, hash, URL…)" style="${inputStyle()}flex:1;" />
          <select id="enrich-type" style="${inputStyle()}width:auto;">
            <option value="auto">Auto-detect</option>
            ${['ip','domain','hash','url','email','cidr','asn','cve'].map(t => `<option value="${t}">${t}</option>`).join('')}
          </select>
          <button onclick="window._cti2Enrich()" style="${submitBtnStyle()}">Enrich →</button>
        </div>
        <div id="enrich-result" style="display:none;margin-top:14px;"></div>
      </div>

      <!-- Batch match -->
      <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:16px;">
        <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);margin-bottom:10px;">🎯 Watchlist Match (Batch)</div>
        <textarea id="match-iocs" placeholder="Enter IOC values, one per line (max 100)" rows="4" style="${inputStyle()}width:100%;resize:vertical;margin-bottom:8px;"></textarea>
        <button onclick="window._cti2Match()" style="${submitBtnStyle()}">Check Watchlists</button>
        <div id="match-result" style="display:none;margin-top:14px;"></div>
      </div>`;
  }

  window._cti2Enrich = async function () {
    const val  = document.getElementById('enrich-val').value.trim();
    const type = document.getElementById('enrich-type').value;
    const res_el = document.getElementById('enrich-result');
    if (!val) return toast('error', 'IOC value required');

    res_el.style.display = 'block';
    res_el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:12px;">Enriching…</div>';

    try {
      const res  = await fetch(`/api/cti/v2/ioc/enrich?value=${encodeURIComponent(val)}&type=${type}`, {
        credentials: 'include', signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      const e = data.enrichment;
      const riskColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#22c55e' };

      res_el.innerHTML = `
        <div style="border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <div>
              <div style="font-family:monospace;font-size:14px;color:var(--cdb-text,#f1f5f9);">${escHtml(val)}</div>
              <div style="font-size:11px;color:var(--cdb-muted,#94a3b8);">Type: ${escHtml(data.type || type)}</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:28px;font-weight:700;color:${riskColors[e.risk_level] || '#94a3b8'};">${e.risk_score}</div>
              <div style="font-size:10px;color:${riskColors[e.risk_level] || '#94a3b8'};font-weight:700;">${e.risk_level}</div>
            </div>
          </div>
          ${e.risk_factors?.length ? `<div style="margin-bottom:10px;">${e.risk_factors.map(f => `<div style="font-size:11px;color:#f59e0b;margin-bottom:3px;">• ${escHtml(f)}</div>`).join('')}</div>` : ''}
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:8px;">
            <div style="text-align:center;background:rgba(255,255,255,.04);border-radius:6px;padding:8px;">
              <div style="font-size:16px;font-weight:700;color:${e.known_ioc ? '#ef4444' : '#22c55e'};">${e.known_ioc ? '⚠' : '✓'}</div>
              <div style="font-size:10px;color:var(--cdb-muted,#94a3b8);">Known IOC</div>
            </div>
            <div style="text-align:center;background:rgba(255,255,255,.04);border-radius:6px;padding:8px;">
              <div style="font-size:16px;font-weight:700;color:${e.associated_actors?.length ? '#ef4444' : '#22c55e'};">${e.associated_actors?.length || 0}</div>
              <div style="font-size:10px;color:var(--cdb-muted,#94a3b8);">Actor Links</div>
            </div>
            <div style="text-align:center;background:rgba(255,255,255,.04);border-radius:6px;padding:8px;">
              <div style="font-size:16px;font-weight:700;color:${e.watchlist_hits?.length ? '#f59e0b' : '#22c55e'};">${e.watchlist_hits?.length || 0}</div>
              <div style="font-size:10px;color:var(--cdb-muted,#94a3b8);">Watchlist Hits</div>
            </div>
          </div>
          ${e.known_ioc?.description ? `<div style="margin-top:10px;font-size:11px;color:var(--cdb-muted,#94a3b8);">${escHtml(e.known_ioc.description)}</div>` : ''}
        </div>`;
    } catch (e) {
      res_el.innerHTML = `<div style="color:#ef4444;font-size:12px;">${escHtml(e.message)}</div>`;
    }
  };

  window._cti2Match = async function () {
    const raw = document.getElementById('match-iocs').value.trim();
    const result_el = document.getElementById('match-result');
    if (!raw) return toast('error', 'Enter at least one IOC');

    const iocs = raw.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 100);
    result_el.style.display = 'block';
    result_el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:12px;">Checking…</div>';

    try {
      const res = await fetch('/api/cti/v2/watchlists/match', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iocs }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      const hits = data.matches || [];
      result_el.innerHTML = `
        <div style="font-size:12px;color:var(--cdb-muted,#94a3b8);margin-bottom:8px;">Checked ${data.total_checked} IOCs · <strong style="color:${hits.length ? '#ef4444' : '#22c55e'};">${hits.length} hit(s)</strong></div>
        ${!hits.length ? '<div style="color:#22c55e;font-size:12px;">✓ No watchlist matches</div>' :
          hits.map(h => `
            <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:6px;padding:8px;margin-bottom:6px;">
              <span style="font-family:monospace;color:#ef4444;font-size:12px;">${escHtml(h.ioc_value)}</span>
              <span style="color:var(--cdb-muted,#94a3b8);font-size:11px;"> matched </span>
              <strong style="color:var(--cdb-text,#f1f5f9);font-size:11px;">${escHtml(h.watchlist_name)}</strong>
              <span style="float:right;font-size:10px;color:#8b5cf6;">Conf: ${h.confidence}%</span>
            </div>`).join('')}`;
    } catch (e) {
      result_el.innerHTML = `<div style="color:#ef4444;font-size:12px;">${escHtml(e.message)}</div>`;
    }
  };

  // ── STIX EXPORT VIEW ────────────────────────────────────────────────────────
  function renderSTIX() {
    const el = document.getElementById('cti2-content');
    el.innerHTML = `
      <div style="background:var(--cdb-card,rgba(255,255,255,.06));border-radius:10px;padding:16px;">
        <div style="font-size:13px;font-weight:600;color:var(--cdb-text,#f1f5f9);margin-bottom:4px;">📦 STIX 2.1 Bundle Export</div>
        <div style="font-size:12px;color:var(--cdb-muted,#94a3b8);margin-bottom:14px;">Export your threat intelligence as a standards-compliant STIX 2.1 bundle.</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
          <div>
            <label style="font-size:11px;color:var(--cdb-muted,#94a3b8);display:block;margin-bottom:4px;">Include Types</label>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <label style="font-size:12px;color:var(--cdb-text,#f1f5f9);display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" id="stix-actors" checked /> Threat Actors</label>
              <label style="font-size:12px;color:var(--cdb-text,#f1f5f9);display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" id="stix-iocs" checked /> IOC Indicators</label>
            </div>
          </div>
          <div>
            <label style="font-size:11px;color:var(--cdb-muted,#94a3b8);display:block;margin-bottom:4px;">Max Objects</label>
            <input id="stix-limit" type="number" value="50" min="1" max="200" style="${inputStyle()}width:80px;" />
          </div>
        </div>

        <button onclick="window._cti2ExportSTIX()" style="${submitBtnStyle()}padding:8px 20px;font-size:13px;">Export STIX Bundle</button>

        <div id="stix-result" style="display:none;margin-top:14px;"></div>
      </div>`;
  }

  window._cti2ExportSTIX = async function () {
    const actors = document.getElementById('stix-actors')?.checked;
    const iocs   = document.getElementById('stix-iocs')?.checked;
    const limit  = document.getElementById('stix-limit')?.value || '50';
    const res_el = document.getElementById('stix-result');

    if (!actors && !iocs) return toast('error', 'Select at least one type');

    const types = [actors ? 'actor' : null, iocs ? 'ioc' : null].filter(Boolean).join(',');
    res_el.style.display = 'block';
    res_el.innerHTML = '<div style="color:var(--cdb-muted,#94a3b8);font-size:12px;">Building STIX bundle…</div>';

    try {
      const res  = await fetch(`/api/cti/v2/stix/export?types=${types}&limit=${limit}`, {
        credentials: 'include', signal: AbortSignal.timeout(15000),
      });
      const bundle = await res.json();
      if (!res.ok) throw new Error(bundle.error || 'Failed');

      const meta    = bundle._meta || {};
      const objCount = bundle.objects?.length || 0;
      const bundleStr = JSON.stringify(bundle, null, 2);

      // Trigger download
      const blob = new Blob([bundleStr], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `stix-bundle-${new Date().toISOString().slice(0,10)}.json`;
      a.click();
      URL.revokeObjectURL(url);

      res_el.innerHTML = `
        <div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:14px;">
          <div style="color:#22c55e;font-size:13px;font-weight:600;margin-bottom:8px;">✓ STIX Bundle Exported</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;color:var(--cdb-muted,#94a3b8);">
            <div>Objects: <strong style="color:var(--cdb-text,#f1f5f9);">${objCount}</strong></div>
            <div>Spec: <strong style="color:var(--cdb-text,#f1f5f9);">STIX 2.1</strong></div>
            <div>Generated: <strong style="color:var(--cdb-text,#f1f5f9);">${fmtTime(meta.generated_at)}</strong></div>
            <div>Bundle ID: <strong style="color:var(--cdb-text,#e2e8f0);font-family:monospace;font-size:10px;">${escHtml(bundle.id || '?')}</strong></div>
          </div>
          <div style="margin-top:10px;">
            <textarea rows="6" style="${inputStyle()}width:100%;resize:vertical;font-family:monospace;font-size:10px;">${escHtml(bundleStr.slice(0, 2000) + (bundleStr.length > 2000 ? '\n…' : ''))}</textarea>
          </div>
        </div>`;
    } catch (e) {
      res_el.innerHTML = `<div style="color:#ef4444;font-size:12px;">${escHtml(e.message)}</div>`;
    }
  };

  // ── Globals ──────────────────────────────────────────────────────────────────
  window._cti2View = switchView;

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function fmtTime(s) {
    if (!s) return '';
    try { return new Date(s).toLocaleString(); } catch { return s; }
  }
  function inputStyle() {
    return 'padding:7px 10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:var(--cdb-text,#f1f5f9);font-size:12px;outline:none;box-sizing:border-box;';
  }
  function submitBtnStyle() { return 'background:#8b5cf6;color:#fff;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:12px;font-weight:600;'; }
  function toast(type, msg) {
    if (typeof window.CDB_UX_TOAST === 'function') {
      window.CDB_UX_TOAST(type, type === 'error' ? 'Error' : 'Success', msg);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
