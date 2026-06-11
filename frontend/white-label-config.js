/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * white-label-config.js — White Label MSSP Branding Controls
 *
 * Injects "Branding" tab into Phase 1 Command Centers (MSSP Admin only).
 * Applies custom theme on page load for all users in the org.
 */

(function CDB_WL_MODULE() {
  'use strict';
  const LOG = '[CDB-WL]';

  function inject() {
    // Apply theme on load regardless of role
    applyTheme();

    const nav  = document.querySelector('.cdb-cc-nav');
    const body = document.querySelector('.cdb-cc-body');
    if (!nav || !body) { setTimeout(inject, 800); return; }
    if (document.getElementById('cdb-panel-branding')) return;

    const tab = document.createElement('button');
    tab.className = 'cdb-cc-tab';
    tab.dataset.target = 'cdb-panel-branding';
    tab.setAttribute('role', 'tab');
    tab.textContent = 'Branding';
    nav.appendChild(tab);

    const panel = document.createElement('div');
    panel.id = 'cdb-panel-branding';
    panel.className = 'cdb-cc-panel';
    panel.innerHTML = PANEL_HTML;
    body.appendChild(panel);

    tab.addEventListener('click', () => {
      document.querySelectorAll('.cdb-cc-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.cdb-cc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      panel.classList.add('active');
      loadCurrentTheme();
    });

    document.getElementById('cdb-wl-save-btn')?.addEventListener('click', saveTheme);
    document.getElementById('cdb-wl-reset-btn')?.addEventListener('click', resetTheme);

    // Live preview color changes
    ['cdb-wl-primary', 'cdb-wl-secondary', 'cdb-wl-accent'].forEach(id => {
      document.getElementById(id)?.addEventListener('input', updatePreview);
    });

    console.info(LOG, 'Branding tab injected');
  }

  const PANEL_HTML = `
    <div class="cdb-two-col">
      <div>
        <div class="cdb-section-heading">Brand Identity</div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          ${field('Brand Name', 'cdb-wl-brand', 'text', 'CYBERDUDEBIVASH®', 'Organization display name')}
          ${field('Logo URL', 'cdb-wl-logo', 'url', 'https://...', 'HTTPS URL to your logo (PNG/SVG)')}
          ${field('Favicon URL', 'cdb-wl-favicon', 'url', 'https://...', 'HTTPS URL to favicon')}
          ${field('Support Email', 'cdb-wl-email', 'email', 'support@yourcompany.com', '')}
          ${field('Support URL', 'cdb-wl-support', 'url', 'https://support.yourcompany.com', '')}
          ${field('Custom Domain', 'cdb-wl-domain', 'text', 'security.yourcompany.com', 'DNS CNAME required separately')}
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:#94a3b8;cursor:pointer;">
            <input type="checkbox" id="cdb-wl-hidepowered" style="width:14px;height:14px;">
            Hide "Powered by CYBERDUDEBIVASH®" footer
          </label>
        </div>
      </div>

      <div>
        <div class="cdb-section-heading">Theme Colors</div>
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div>
            <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Primary Color</label>
            <div style="display:flex;gap:8px;margin-top:4px;align-items:center;">
              <input type="color" id="cdb-wl-primary" value="#6366f1" style="width:40px;height:32px;border:none;border-radius:6px;cursor:pointer;background:none;">
              <input type="text" id="cdb-wl-primary-hex" value="#6366f1" style="flex:1;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:6px;color:#e2e8f0;font-size:12px;font-family:monospace;outline:none;">
            </div>
          </div>
          <div>
            <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Secondary Color</label>
            <div style="display:flex;gap:8px;margin-top:4px;align-items:center;">
              <input type="color" id="cdb-wl-secondary" value="#0ea5e9" style="width:40px;height:32px;border:none;border-radius:6px;cursor:pointer;background:none;">
              <input type="text" id="cdb-wl-secondary-hex" value="#0ea5e9" style="flex:1;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:6px;color:#e2e8f0;font-size:12px;font-family:monospace;outline:none;">
            </div>
          </div>
          <div>
            <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">Accent Color</label>
            <div style="display:flex;gap:8px;margin-top:4px;align-items:center;">
              <input type="color" id="cdb-wl-accent" value="#22c55e" style="width:40px;height:32px;border:none;border-radius:6px;cursor:pointer;background:none;">
              <input type="text" id="cdb-wl-accent-hex" value="#22c55e" style="flex:1;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:6px;color:#e2e8f0;font-size:12px;font-family:monospace;outline:none;">
            </div>
          </div>
        </div>

        <!-- Preview -->
        <div style="margin-top:16px;background:#0f1729;border:1px solid #1e293b;border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:#475569;margin-bottom:8px;">Live Preview</div>
          <div id="cdb-wl-preview-name" style="font-size:14px;font-weight:800;color:#6366f1;">CYBERDUDEBIVASH®</div>
          <div style="display:flex;gap:6px;margin-top:8px;">
            <div id="cdb-wl-preview-btn" style="padding:5px 12px;background:#6366f1;border-radius:6px;font-size:11px;color:white;font-weight:600;">Primary Button</div>
            <div id="cdb-wl-preview-acc" style="padding:5px 12px;background:#22c55e22;color:#22c55e;border-radius:6px;font-size:11px;font-weight:600;">Accent Badge</div>
          </div>
        </div>

        <div style="display:flex;gap:8px;margin-top:16px;">
          <button id="cdb-wl-save-btn" class="cdb-btn-primary" style="flex:1;padding:10px;">Save Branding</button>
          <button id="cdb-wl-reset-btn" class="cdb-btn-outline" style="padding:10px 14px;">Reset</button>
        </div>
        <div id="cdb-wl-status" style="margin-top:6px;font-size:11px;color:#475569;text-align:center;"></div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:11px;color:#475569;text-align:center;">
      Branding applies to all users in your organization · Requires MSSP Admin credentials
    </div>
  `;

  function field(label, id, type, placeholder, hint) {
    return `<div>
      <label style="font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">${label}</label>
      ${hint ? `<div style="font-size:10px;color:#475569;margin-top:1px;">${hint}</div>` : ''}
      <input type="${type}" id="${id}" placeholder="${placeholder}"
        style="width:100%;margin-top:3px;background:#0a0e1a;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#e2e8f0;font-size:12px;outline:none;">
    </div>`;
  }

  async function applyTheme() {
    try {
      const resp = await fetch('/api/white-label/theme', { signal: AbortSignal.timeout(5000) });
      if (!resp.ok) return;
      const { theme } = await resp.json();
      if (!theme) return;

      // Apply CSS variables to :root
      const root = document.documentElement;
      if (theme.primary_color)   { root.style.setProperty('--cdb-primary', theme.primary_color); root.style.setProperty('--color-accent', theme.primary_color); }
      if (theme.secondary_color) root.style.setProperty('--cdb-secondary', theme.secondary_color);
      if (theme.accent_color)    root.style.setProperty('--cdb-accent', theme.accent_color);

      // Apply custom CSS
      if (theme.custom_css) {
        let styleEl = document.getElementById('cdb-white-label-css');
        if (!styleEl) { styleEl = document.createElement('style'); styleEl.id = 'cdb-white-label-css'; document.head.appendChild(styleEl); }
        styleEl.textContent = theme.custom_css;
      }

      // Replace logo if set
      if (theme.logo_url) {
        const logos = document.querySelectorAll('.cdb-logo-img,[data-logo]');
        logos.forEach(el => { if (el.tagName === 'IMG') el.src = theme.logo_url; });
      }

      console.info(LOG, 'Theme applied:', theme.brand_name || 'custom');
    } catch (_) {}
  }

  async function loadCurrentTheme() {
    try {
      const resp = await fetch('/api/white-label/theme', { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        if (resp.status === 401) {
          document.getElementById('cdb-wl-status').textContent = 'Log in to manage branding';
        }
        return;
      }
      const { theme } = await resp.json();

      setVal('cdb-wl-brand',   theme.brand_name || '');
      setVal('cdb-wl-logo',    theme.logo_url || '');
      setVal('cdb-wl-favicon', theme.favicon_url || '');
      setVal('cdb-wl-email',   theme.support_email || '');
      setVal('cdb-wl-support', theme.support_url || '');
      setVal('cdb-wl-domain',  theme.custom_domain || '');
      setVal('cdb-wl-primary', theme.primary_color || '#6366f1');
      setVal('cdb-wl-secondary', theme.secondary_color || '#0ea5e9');
      setVal('cdb-wl-accent',  theme.accent_color || '#22c55e');
      setVal('cdb-wl-primary-hex', theme.primary_color || '#6366f1');
      setVal('cdb-wl-secondary-hex', theme.secondary_color || '#0ea5e9');
      setVal('cdb-wl-accent-hex', theme.accent_color || '#22c55e');
      const checkbox = document.getElementById('cdb-wl-hidepowered');
      if (checkbox) checkbox.checked = !!theme.hide_powered_by;

      updatePreview();
    } catch (e) { console.info(LOG, 'Theme load failed:', e.message); }
  }

  function updatePreview() {
    const primary   = getVal('cdb-wl-primary') || '#6366f1';
    const secondary = getVal('cdb-wl-secondary') || '#0ea5e9';
    const accent    = getVal('cdb-wl-accent') || '#22c55e';
    const brand     = getVal('cdb-wl-brand') || 'CYBERDUDEBIVASH®';

    // Sync hex inputs with color pickers
    setVal('cdb-wl-primary-hex', primary);
    setVal('cdb-wl-secondary-hex', secondary);
    setVal('cdb-wl-accent-hex', accent);

    const pName = document.getElementById('cdb-wl-preview-name');
    const pBtn  = document.getElementById('cdb-wl-preview-btn');
    const pAcc  = document.getElementById('cdb-wl-preview-acc');
    if (pName) { pName.textContent = brand; pName.style.color = primary; }
    if (pBtn)  pBtn.style.background = primary;
    if (pAcc)  { pAcc.style.color = accent; pAcc.style.background = accent + '22'; }
  }

  async function saveTheme() {
    const status = document.getElementById('cdb-wl-status');
    const btn    = document.getElementById('cdb-wl-save-btn');
    if (btn) btn.disabled = true;
    if (status) status.textContent = 'Saving…';

    const payload = {
      brand_name:       getVal('cdb-wl-brand') || undefined,
      logo_url:         getVal('cdb-wl-logo') || undefined,
      favicon_url:      getVal('cdb-wl-favicon') || undefined,
      primary_color:    getVal('cdb-wl-primary') || undefined,
      secondary_color:  getVal('cdb-wl-secondary') || undefined,
      accent_color:     getVal('cdb-wl-accent') || undefined,
      support_email:    getVal('cdb-wl-email') || undefined,
      support_url:      getVal('cdb-wl-support') || undefined,
      custom_domain:    getVal('cdb-wl-domain') || undefined,
      hide_powered_by:  document.getElementById('cdb-wl-hidepowered')?.checked,
    };
    // Remove undefined
    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

    try {
      const resp = await fetch('/api/white-label/theme', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000),
      });
      const d = await resp.json();
      if (d.success) {
        if (status) status.textContent = '✓ Branding saved';
        window.CDB_UX_TOAST?.('success', 'Branding saved', 'Applied to all org users');
        applyTheme();
      } else {
        if (status) status.textContent = 'Error: ' + (d.error || 'Unknown');
        window.CDB_UX_TOAST?.('error', 'Save failed', d.error || '');
      }
    } catch (e) {
      if (status) status.textContent = 'Failed: ' + e.message;
    } finally {
      if (btn) { btn.disabled = false; setTimeout(() => { if (status) status.textContent = ''; }, 4000); }
    }
  }

  async function resetTheme() {
    if (!window.confirm('Reset branding to platform defaults?')) return;
    try {
      const resp = await fetch('/api/white-label/theme', { method: 'DELETE', signal: AbortSignal.timeout(8000) });
      const d = await resp.json();
      if (d.success) {
        window.CDB_UX_TOAST?.('success', 'Branding reset', 'Platform defaults restored');
        loadCurrentTheme();
      }
    } catch (e) { window.CDB_UX_TOAST?.('error', 'Reset failed', e.message); }
  }

  const getVal = id => document.getElementById(id)?.value || '';
  const setVal = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', inject);
  else inject();
})();
