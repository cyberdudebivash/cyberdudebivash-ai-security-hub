/**
 * CYBERDUDEBIVASH AI Security Hub — shared platform-staff session gate.
 *
 * Replaces the hardcoded shared password that used to gate
 * mssp-command-center.html, revenue-command-center.html, and
 * proposal-generator.html — readable via view-source, or bypassable outright
 * with `localStorage.setItem('cdb_owner','true')` in devtools. Backed by a
 * real passwordless magic-link login (workers/src/handlers/staffAuth.js).
 *
 * IMPORTANT: this only controls what the PAGE renders. The actual data is
 * still protected server-side by each API route's own authorization check
 * (isOwner()/isPlatformAdmin() — see auth/rbac.js) — this gate exists so an
 * unauthorized visitor doesn't even see the dashboard shell, not as a
 * substitute for server-side enforcement.
 */
window.CDB_STAFF_AUTH = (function () {
  const SESSION_KEY = 'cdb_staff_session';

  function getSession() { return localStorage.getItem(SESSION_KEY); }
  function setSession(token) { localStorage.setItem(SESSION_KEY, token); }
  function clearSession() { localStorage.removeItem(SESSION_KEY); }

  async function authFetch(url, opts = {}) {
    const token = getSession();
    return fetch(url, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}), Authorization: `Bearer ${token}` },
    });
  }

  function renderLoginForm(container, onRetry) {
    container.innerHTML = `
      <div style="font-size:36px;margin-bottom:8px">🔒</div>
      <div style="font-size:18px;font-weight:800;margin-bottom:6px">Platform Staff — Restricted</div>
      <p style="color:#8892a6;font-size:13px;margin-bottom:16px;line-height:1.5">This is an internal-only dashboard. Enter your registered staff email — we'll send a secure one-time login link.</p>
      <input type="email" id="cdbStaffEmail" placeholder="you@cyberdudebivash.com"
        style="width:100%;padding:12px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.15);background:#1a1a2e;color:#fff;margin-bottom:10px;font-size:14px;box-sizing:border-box">
      <button id="cdbStaffLoginBtn" style="width:100%;padding:12px;border-radius:8px;border:none;background:#7c3aed;color:#fff;font-weight:700;cursor:pointer;font-size:14px">Send Login Link</button>
      <div id="cdbStaffLoginStatus" style="margin-top:12px;font-size:12px;color:#8892a6;min-height:16px"></div>`;

    const emailEl  = container.querySelector('#cdbStaffEmail');
    const statusEl = container.querySelector('#cdbStaffLoginStatus');
    const submit = async () => {
      const email = emailEl.value.trim();
      if (!email) { statusEl.textContent = 'Enter your email first.'; return; }
      statusEl.textContent = 'Sending…';
      try {
        const res = await fetch('/api/staff/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
        });
        const data = await res.json().catch(() => ({}));
        statusEl.textContent = data.message || 'If eligible, a login link has been sent to that email.';
      } catch (_) {
        statusEl.textContent = 'Something went wrong — try again.';
      }
    };
    container.querySelector('#cdbStaffLoginBtn').addEventListener('click', submit);
    emailEl.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  }

  // Server-verified gate: never trusts localStorage alone. A stored session
  // token is only treated as valid after GET /api/staff/me actually succeeds
  // — an expired/tampered/forged token still shows the login form, not the
  // dashboard, satisfying "authorization enforced server-side" even for the
  // page-render decision, not just the underlying data fetches.
  async function guard(overlayEl, gateContentEl, onUnlocked) {
    const params = new URLSearchParams(location.search);
    const magicToken = params.get('token');
    if (magicToken) {
      try {
        const res = await fetch('/api/staff/verify', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: magicToken }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.success) {
          setSession(data.session_token);
          history.replaceState({}, '', location.pathname);
        }
      } catch (_) { /* fall through to the stored-session check below */ }
    }

    if (getSession()) {
      try {
        const res = await authFetch('/api/staff/me');
        if (res.ok) {
          const data = await res.json();
          overlayEl.style.display = 'none';
          onUnlocked(data);
          return;
        }
      } catch (_) { /* treat as unauthenticated below */ }
      clearSession(); // stored token didn't verify — expired or invalid
    }

    overlayEl.style.display = 'flex';
    renderLoginForm(gateContentEl, () => guard(overlayEl, gateContentEl, onUnlocked));
  }

  async function logout() {
    try { await authFetch('/api/staff/logout', { method: 'POST' }); } catch (_) {}
    clearSession();
    location.reload();
  }

  return { getSession, setSession, clearSession, authFetch, guard, logout };
})();
