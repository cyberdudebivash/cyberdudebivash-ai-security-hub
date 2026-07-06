/**
 * ═══════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI SECURITY HUB
 * MULTI-RAIL CHECKOUT MODAL v2.0
 * ═══════════════════════════════════════════════════════════════════════
 * Rails:
 *   A. UPI Deep-Link + Dynamic QR (qrcode.js via CDN)
 *   B. Bank Wire (NEFT/IMPS/RTGS corporate details)
 *   C. Razorpay Gateway (webhook-verified)
 *   D. PayPal REST Link
 *   E. Web3 Crypto (ETH/BNB)
 *
 * Geo-aware: shows INR rails for IN, USD rails for non-IN.
 * Zero external dependencies at mount-time (qrcode loaded on demand).
 * ═══════════════════════════════════════════════════════════════════════
 */
(function CDB_CHECKOUT() {
  'use strict';

  /* ── CONSTANTS ────────────────────────────────────────────────────── */
  // UPI/bank/PayPal/crypto values are loaded at runtime from
  // /api/payment-config — never hardcode account/wallet details in source.
  // GSTIN is public business-registration info (same disclosure as on
  // terms-of-service.html / privacy-policy.html) and is fine to keep here.
  const MERCHANT = {
    UPI_ID:       '',
    UPI_ID_ALT:   '',
    PAYEE_NAME:   'CYBERDUDEBIVASH%20PVT%20LTD',
    PAYEE_DISPLAY:'CYBERDUDEBIVASH PRIVATE LIMITED',
    BANK_NAME:    '',
    BANK_ACCOUNT: '',
    IFSC:         '',
    GSTIN:        '21ARKPN8270G1ZP',
    PAYPAL_LINK:  '',
    CRYPTO: {
      ETH: '',
      BNB: '',
    },
    API_BASE: (window.CONFIG && window.CONFIG.API_BASE)
              || 'https://cyberdudebivash-security-hub.workers.dev',
  };

  let _merchantLoaded = false;
  let _merchantLoadingPromise = null;
  function loadMerchantConfig() {
    if (_merchantLoaded) return Promise.resolve();
    if (_merchantLoadingPromise) return _merchantLoadingPromise;
    _merchantLoadingPromise = fetch('/api/payment-config', { signal: AbortSignal.timeout(6000) })
      .then(r => r.ok ? r.json() : null)
      .then(cfg => {
        if (!cfg) return;
        MERCHANT.UPI_ID       = (cfg.upi && cfg.upi.primary) || '';
        MERCHANT.UPI_ID_ALT   = (cfg.upi && cfg.upi.secondary) || '';
        MERCHANT.PAYEE_DISPLAY= (cfg.bank && cfg.bank.account_name) || MERCHANT.PAYEE_DISPLAY;
        MERCHANT.BANK_NAME    = (cfg.bank && cfg.bank.bank_name) || '';
        MERCHANT.BANK_ACCOUNT = (cfg.bank && cfg.bank.account_number) || '';
        MERCHANT.IFSC         = (cfg.bank && cfg.bank.ifsc) || '';
        MERCHANT.GSTIN        = (cfg.business && cfg.business.gst) || MERCHANT.GSTIN;
        MERCHANT.PAYPAL_LINK  = (cfg.paypal && cfg.paypal.link) || '';
        MERCHANT.CRYPTO.ETH   = (cfg.crypto && cfg.crypto.bnb_smart_chain) || '';
        MERCHANT.CRYPTO.BNB   = (cfg.crypto && cfg.crypto.bnb_smart_chain) || '';
        _merchantLoaded = true;
      })
      .catch(e => console.warn('[CDB_CHECKOUT] Failed to load payment config:', e.message));
    return _merchantLoadingPromise;
  }

  /* ── GENERATE TRANSACTION ID ──────────────────────────────────────── */
  function genTxnId() {
    const ts  = Date.now().toString(36).toUpperCase();
    const rnd = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `CDB${ts}${rnd}`;
  }

  /* ── UPI DEEP LINK BUILDER ────────────────────────────────────────── */
  function buildUPILink(txnId, amount, tierName) {
    const tn = encodeURIComponent(`SENTINEL_APEX_${tierName.toUpperCase()}_SUBSCRIPTION`);
    return `upi://pay?pa=${MERCHANT.UPI_ID}&pn=${MERCHANT.PAYEE_NAME}&tr=${txnId}&am=${amount}&cu=INR&tn=${tn}`;
  }

  /* ── QR CODE LOADER ───────────────────────────────────────────────── */
  let _qrLoaded = false;
  function loadQRLib(cb) {
    if (_qrLoaded || window.QRCode) { cb(); return; }
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    s.onload = () => { _qrLoaded = true; cb(); };
    s.onerror = () => cb(new Error('QR lib load failed'));
    document.head.appendChild(s);
  }

  function renderQR(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = '';
    loadQRLib(err => {
      if (err || !window.QRCode) {
        el.innerHTML = `<p style="color:#ef4444;font-size:12px">QR unavailable — use UPI ID directly</p>`;
        return;
      }
      new window.QRCode(el, {
        text:           data,
        width:          200,
        height:         200,
        colorDark:      '#000000',
        colorLight:     '#ffffff',
        correctLevel:   window.QRCode.CorrectLevel.H,
      });
    });
  }

  /* ── COUNTRY/CURRENCY DETECTION ───────────────────────────────────── */
  function getGeo() {
    return window.__CDB_GEO || { countryCode: 'IN', matrix: { currency: 'INR', symbol: '₹' } };
  }

  /* ── MODAL HTML BUILDER ───────────────────────────────────────────── */
  function buildModalHTML(opts) {
    const geo        = getGeo();
    const isIndia    = geo.countryCode === 'IN';
    const symbol     = geo.matrix.symbol;
    const currency   = geo.matrix.currency;
    const txnId      = genTxnId();
    const amount     = opts.amount;
    const amountFmt  = `${symbol}${amount}`;
    const tierName   = opts.tierName || 'SUBSCRIPTION';
    const label      = opts.productLabel || 'CYBERDUDEBIVASH Security Report';
    const upiLink    = buildUPILink(txnId, amount, tierName);

    return `
<div id="cdb-checkout-overlay" style="
  position:fixed;inset:0;background:rgba(0,0,0,.85);backdrop-filter:blur(8px);
  z-index:99999;display:flex;align-items:center;justify-content:center;
  animation:cdbFadeIn .2s ease;padding:16px;overflow-y:auto
">
<div id="cdb-checkout-modal" style="
  background:linear-gradient(135deg,#0a0a1a,#0d1117);
  border:1px solid rgba(0,212,255,.25);border-radius:20px;
  width:100%;max-width:520px;max-height:90vh;overflow-y:auto;
  box-shadow:0 0 60px rgba(0,212,255,.15),0 25px 80px rgba(0,0,0,.6);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#fff;
  animation:cdbSlideUp .25s ease
">
  <!-- HEADER -->
  <div style="padding:24px 24px 0;display:flex;align-items:flex-start;justify-content:space-between">
    <div>
      <div style="font-size:11px;font-weight:700;letter-spacing:2px;color:#00d4ff;text-transform:uppercase;margin-bottom:6px">
        ⚔️ CYBERDUDEBIVASH CHECKOUT
      </div>
      <div style="font-size:18px;font-weight:900;color:#fff;line-height:1.2">${label}</div>
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span style="font-size:26px;font-weight:900;color:#00ff88">${amountFmt}</span>
        <span style="font-size:12px;color:rgba(255,255,255,.4)">Txn: ${txnId}</span>
      </div>
    </div>
    <button onclick="CDB_CHECKOUT_MODAL.close()" style="
      background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.1);
      color:rgba(255,255,255,.5);border-radius:8px;padding:8px 12px;
      cursor:pointer;font-size:14px;flex-shrink:0;margin-left:12px
    ">✕</button>
  </div>

  <!-- RAIL TABS -->
  <div style="padding:16px 24px 0;display:flex;gap:6px;flex-wrap:wrap">
    ${isIndia ? `
    <button class="cdb-rail-tab cdb-rail-active" onclick="CDB_CHECKOUT_MODAL.switchTab('upi',this)" style="font-size:12px;font-weight:700;padding:8px 14px;border-radius:8px;border:1px solid rgba(0,212,255,.4);background:rgba(0,212,255,.15);color:#00d4ff;cursor:pointer">📱 UPI</button>
    <button class="cdb-rail-tab" onclick="CDB_CHECKOUT_MODAL.switchTab('bank',this)" style="font-size:12px;font-weight:700;padding:8px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:rgba(255,255,255,.5);cursor:pointer">🏦 Bank Wire</button>
    ` : ''}
    ${!isIndia ? `
    <button class="cdb-rail-tab cdb-rail-active" onclick="CDB_CHECKOUT_MODAL.switchTab('paypal',this)" style="font-size:12px;font-weight:700;padding:8px 14px;border-radius:8px;border:1px solid rgba(0,212,255,.4);background:rgba(0,212,255,.15);color:#00d4ff;cursor:pointer">💳 PayPal</button>
    ` : ''}
    <button class="cdb-rail-tab" onclick="CDB_CHECKOUT_MODAL.switchTab('crypto',this)" style="font-size:12px;font-weight:700;padding:8px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:rgba(255,255,255,.5);cursor:pointer">⬡ Crypto</button>
    <button class="cdb-rail-tab" onclick="CDB_CHECKOUT_MODAL.switchTab('razorpay',this)" style="font-size:12px;font-weight:700;padding:8px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:rgba(255,255,255,.5);cursor:pointer">⚡ Card</button>
  </div>

  <!-- RAIL CONTENT -->
  <div style="padding:20px 24px 24px">

    <!-- ── UPI RAIL ─────────────────────────────────────────────────── -->
    <div id="cdb-rail-upi" class="cdb-rail-panel" style="${isIndia ? '' : 'display:none'}">
      <div style="background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.15);border-radius:14px;padding:20px">
        <div style="font-size:13px;font-weight:900;color:#00d4ff;margin-bottom:16px">📱 Pay via UPI</div>
        
        <!-- QR Code -->
        <div style="display:flex;justify-content:center;margin-bottom:16px">
          <div style="background:#fff;padding:12px;border-radius:12px;display:inline-block">
            <div id="cdb-upi-qr" style="width:200px;height:200px;display:flex;align-items:center;justify-content:center">
              <span style="color:#999;font-size:12px">Loading QR...</span>
            </div>
          </div>
        </div>

        <!-- UPI Deep Link Button (mobile) -->
        <a href="${upiLink}" style="
          display:block;text-align:center;background:linear-gradient(135deg,#00ff88,#00cc66);
          color:#000;border-radius:12px;padding:14px;font-size:14px;font-weight:900;
          text-decoration:none;margin-bottom:14px
        ">
          📱 Open UPI App — Pay ${amountFmt}
        </a>

        <!-- UPI IDs -->
        <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:8px">UPI ID (Primary):</div>
        <div style="
          background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
          border-radius:8px;padding:10px 14px;font-family:monospace;font-size:13px;
          color:#00ff88;cursor:pointer;margin-bottom:8px;word-break:break-all
        " onclick="navigator.clipboard?.writeText('${MERCHANT.UPI_ID}');this.style.borderColor='#00ff88';setTimeout(()=>this.style.borderColor='rgba(255,255,255,.1)',1500)">
          ${MERCHANT.UPI_ID} <span style="float:right;font-size:10px;color:rgba(255,255,255,.3)">📋 Copy</span>
        </div>
        <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:8px">UPI ID (Alternate):</div>
        <div style="
          background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
          border-radius:8px;padding:10px 14px;font-family:monospace;font-size:13px;
          color:#00ff88;cursor:pointer;margin-bottom:14px;word-break:break-all
        " onclick="navigator.clipboard?.writeText('${MERCHANT.UPI_ID_ALT}');this.style.borderColor='#00ff88';setTimeout(()=>this.style.borderColor='rgba(255,255,255,.1)',1500)">
          ${MERCHANT.UPI_ID_ALT} <span style="float:right;font-size:10px;color:rgba(255,255,255,.3)">📋 Copy</span>
        </div>

        <div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px;font-size:12px;color:rgba(255,255,255,.7)">
          ⚠️ After payment, email your UTR/Transaction ID to <strong style="color:#f59e0b">contact@cyberdudebivash.in</strong> for instant activation.
        </div>
      </div>
    </div>

    <!-- ── BANK WIRE RAIL ──────────────────────────────────────────── -->
    <div id="cdb-rail-bank" class="cdb-rail-panel" style="display:none">
      <div style="background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.2);border-radius:14px;padding:20px">
        <div style="font-size:13px;font-weight:900;color:#818cf8;margin-bottom:16px">🏦 NEFT / IMPS / RTGS Bank Transfer</div>
        
        ${[
          ['Beneficiary Name', MERCHANT.PAYEE_DISPLAY],
          ['Bank Name', MERCHANT.BANK_NAME],
          ['Account Number', MERCHANT.BANK_ACCOUNT],
          ['IFSC Code', MERCHANT.IFSC],
          ['GSTIN', MERCHANT.GSTIN],
          ['Amount', `₹${amount}`],
          ['Reference / Narration', txnId],
        ].map(([k,v]) => `
        <div style="display:flex;justify-content:space-between;align-items:flex-start;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06)">
          <span style="font-size:12px;color:rgba(255,255,255,.4);min-width:130px">${k}</span>
          <span style="font-size:13px;font-weight:700;color:#fff;text-align:right;cursor:pointer;font-family:${['Account Number','IFSC Code','Reference / Narration'].includes(k)?'monospace':'inherit'}"
                onclick="navigator.clipboard?.writeText('${v}');this.style.color='#00ff88';setTimeout(()=>this.style.color='#fff',1500)">
            ${v} <span style="font-size:10px;color:rgba(255,255,255,.2)">📋</span>
          </span>
        </div>`).join('')}

        <div style="margin-top:14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px;font-size:12px;color:rgba(255,255,255,.7)">
          ⚠️ Use <strong style="color:#f59e0b">${txnId}</strong> as payment narration. Email confirmation to <strong>contact@cyberdudebivash.in</strong> for same-day activation.
        </div>
      </div>
    </div>

    <!-- ── PAYPAL RAIL ─────────────────────────────────────────────── -->
    <div id="cdb-rail-paypal" class="cdb-rail-panel" style="display:none">
      <div style="background:rgba(0,148,255,.06);border:1px solid rgba(0,148,255,.2);border-radius:14px;padding:20px">
        <div style="font-size:13px;font-weight:900;color:#60a5fa;margin-bottom:16px">💳 PayPal Payment</div>
        <div style="font-size:28px;font-weight:900;color:#00ff88;margin-bottom:16px">\$${amount} USD</div>
        
        <a href="${MERCHANT.PAYPAL_LINK}/${amount}" target="_blank" style="
          display:block;text-align:center;background:linear-gradient(135deg,#003087,#009cde);
          color:#fff;border-radius:12px;padding:16px;font-size:15px;font-weight:900;
          text-decoration:none;margin-bottom:16px
        ">
          💙 Pay \$${amount} via PayPal →
        </a>

        <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:8px">PayPal.me link:</div>
        <div style="
          background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
          border-radius:8px;padding:10px 14px;font-family:monospace;font-size:13px;
          color:#60a5fa;cursor:pointer;word-break:break-all
        " onclick="navigator.clipboard?.writeText('${MERCHANT.PAYPAL_LINK}');this.style.borderColor='#60a5fa';setTimeout(()=>this.style.borderColor='rgba(255,255,255,.1)',1500)">
          ${MERCHANT.PAYPAL_LINK} <span style="float:right;font-size:10px;color:rgba(255,255,255,.3)">📋 Copy</span>
        </div>

        <div style="margin-top:14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px;font-size:12px;color:rgba(255,255,255,.7)">
          ⚠️ Include <strong style="color:#f59e0b">${txnId}</strong> in payment note. Email confirmation to <strong>contact@cyberdudebivash.in</strong>.
        </div>
      </div>
    </div>

    <!-- ── CRYPTO RAIL ─────────────────────────────────────────────── -->
    <div id="cdb-rail-crypto" class="cdb-rail-panel" style="display:none">
      <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:14px;padding:20px">
        <div style="font-size:13px;font-weight:900;color:#f59e0b;margin-bottom:16px">⬡ Web3 Crypto Payment</div>
        
        <div style="margin-bottom:16px;font-size:12px;color:rgba(255,255,255,.5)">
          Select network and send equivalent amount to the address below.
        </div>

        <!-- Network selector -->
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
          <button onclick="CDB_CHECKOUT_MODAL.selectChain('eth',this)" style="font-size:12px;padding:8px 14px;border-radius:8px;border:1px solid rgba(99,102,241,.5);background:rgba(99,102,241,.15);color:#818cf8;cursor:pointer;font-weight:700" id="cdb-chain-eth">Ξ ETH</button>
          <button onclick="CDB_CHECKOUT_MODAL.selectChain('bnb',this)" style="font-size:12px;padding:8px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.12);background:transparent;color:rgba(255,255,255,.4);cursor:pointer" id="cdb-chain-bnb">⬡ BNB</button>
        </div>

        <div id="cdb-crypto-addr-display">
          <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:8px">Ethereum (ERC-20) Address:</div>
          <div style="
            background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
            border-radius:8px;padding:12px 14px;font-family:monospace;font-size:11px;
            color:#818cf8;cursor:pointer;word-break:break-all
          " onclick="navigator.clipboard?.writeText('${MERCHANT.CRYPTO.ETH}');this.style.borderColor='#818cf8';setTimeout(()=>this.style.borderColor='rgba(255,255,255,.1)',1500)">
            ${MERCHANT.CRYPTO.ETH} <span style="float:right;font-size:10px;color:rgba(255,255,255,.3)">📋</span>
          </div>
        </div>

        <div style="margin-top:14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px;font-size:12px;color:rgba(255,255,255,.7)">
          ⚠️ After transfer, email TX hash + <strong style="color:#f59e0b">${txnId}</strong> to <strong>contact@cyberdudebivash.in</strong>. Activation within 2h of confirmation.
        </div>
      </div>
    </div>

    <!-- ── RAZORPAY / CARD RAIL ────────────────────────────────────── -->
    <div id="cdb-rail-razorpay" class="cdb-rail-panel" style="display:none">
      <div style="background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.15);border-radius:14px;padding:20px">
        <div style="font-size:13px;font-weight:900;color:#00ff88;margin-bottom:16px">⚡ Card / Net Banking / Wallet</div>
        <button onclick="CDB_CHECKOUT_MODAL.triggerRazorpay()" style="
          width:100%;background:linear-gradient(135deg,#00ff88,#00cc66);
          color:#000;border:none;border-radius:12px;padding:16px;
          font-size:15px;font-weight:900;cursor:pointer;margin-bottom:14px
        ">⚡ Pay ${amountFmt} via Card / Net Banking</button>
        <div style="font-size:11px;color:rgba(255,255,255,.35);text-align:center">
          Powered by Razorpay · 256-bit SSL · PCI-DSS Compliant
        </div>
      </div>
    </div>

    <!-- POST-PAYMENT INSTRUCTION -->
    <div style="margin-top:16px;background:rgba(0,255,136,.04);border:1px solid rgba(0,255,136,.1);border-radius:12px;padding:14px">
      <div style="font-size:11px;font-weight:700;color:#00ff88;margin-bottom:6px">✅ AFTER PAYMENT</div>
      <div style="font-size:12px;color:rgba(255,255,255,.6);line-height:1.7">
        Email your payment confirmation to <strong style="color:#fff">contact@cyberdudebivash.in</strong><br>
        Include your Transaction ID: <strong style="color:#00d4ff;font-family:monospace">${txnId}</strong><br>
        Account activation within <strong style="color:#fff">1–2 business hours</strong>.
      </div>
    </div>

  </div>
</div>
</div>

<style>
@keyframes cdbFadeIn { from{opacity:0} to{opacity:1} }
@keyframes cdbSlideUp { from{transform:translateY(20px);opacity:0} to{transform:translateY(0);opacity:1} }
.cdb-rail-tab { transition: all .15s ease; }
.cdb-rail-tab:hover { opacity: .85; }
</style>`;
  }

  /* ── MODAL CONTROLLER ─────────────────────────────────────────────── */
  window.CDB_CHECKOUT_MODAL = {
    _current: null,

    open(opts) {
      // opts: { amount, tierName, productLabel }
      this.close();
      loadMerchantConfig().then(() => this._mount(opts));
    },

    _mount(opts) {
      const geo       = getGeo();
      const isIndia   = geo.countryCode === 'IN';
      const container = document.createElement('div');
      container.id    = 'cdb-checkout-root';
      container.innerHTML = buildModalHTML({ ...opts });
      document.body.appendChild(container);
      this._current = opts;

      // Render QR for UPI
      if (isIndia) {
        setTimeout(() => {
          const txnId  = container.querySelector('[style*="Txn:"]')
            ? genTxnId() : genTxnId();
          renderQR('cdb-upi-qr', buildUPILink(txnId, opts.amount, opts.tierName || 'SUBSCRIPTION'));
        }, 100);
      }

      // Chain tab default = ETH
      this._activeChain = 'eth';

      // Close on overlay click
      document.getElementById('cdb-checkout-overlay')?.addEventListener('click', e => {
        if (e.target === document.getElementById('cdb-checkout-overlay')) this.close();
      });

      // Prevent body scroll
      document.body.style.overflow = 'hidden';
    },

    close() {
      const root = document.getElementById('cdb-checkout-root');
      if (root) root.remove();
      document.body.style.overflow = '';
      this._current = null;
    },

    switchTab(tabId, btn) {
      // Hide all panels
      document.querySelectorAll('.cdb-rail-panel').forEach(p => p.style.display = 'none');
      // Deactivate all tabs
      document.querySelectorAll('.cdb-rail-tab').forEach(t => {
        t.style.background = 'transparent';
        t.style.borderColor = 'rgba(255,255,255,.12)';
        t.style.color = 'rgba(255,255,255,.5)';
      });
      // Show selected
      const panel = document.getElementById(`cdb-rail-${tabId}`);
      if (panel) panel.style.display = 'block';
      // Activate tab
      if (btn) {
        btn.style.background = 'rgba(0,212,255,.15)';
        btn.style.borderColor = 'rgba(0,212,255,.4)';
        btn.style.color = '#00d4ff';
      }
    },

    selectChain(chain, btn) {
      this._activeChain = chain;
      // Reset all chain buttons
      ['eth','bnb'].forEach(c => {
        const b = document.getElementById(`cdb-chain-${c}`);
        if (b) {
          b.style.background = 'transparent';
          b.style.borderColor = 'rgba(255,255,255,.12)';
          b.style.color = 'rgba(255,255,255,.4)';
        }
      });
      if (btn) {
        btn.style.background = 'rgba(99,102,241,.15)';
        btn.style.borderColor = 'rgba(99,102,241,.5)';
        btn.style.color = '#818cf8';
      }
      const addrMap = {
        eth:  { label: 'Ethereum (ERC-20)', addr: MERCHANT.CRYPTO.ETH, color: '#818cf8' },
        bnb:  { label: 'BNB Smart Chain',   addr: MERCHANT.CRYPTO.BNB, color: '#f59e0b' },
      };
      const d = addrMap[chain];
      const el = document.getElementById('cdb-crypto-addr-display');
      if (el && d) {
        el.innerHTML = `
          <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:8px">${d.label} Address:</div>
          <div style="
            background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
            border-radius:8px;padding:12px 14px;font-family:monospace;font-size:11px;
            color:${d.color};cursor:pointer;word-break:break-all
          " onclick="navigator.clipboard?.writeText('${d.addr}');this.style.borderColor='${d.color}';setTimeout(()=>this.style.borderColor='rgba(255,255,255,.1)',1500)">
            ${d.addr} <span style="float:right;font-size:10px;color:rgba(255,255,255,.3)">📋</span>
          </div>`;
      }
    },

    triggerRazorpay() {
      const opts = this._current;
      if (!opts) return;
      // Call existing CDB_PAYMENT if present (backwards compat)
      if (window.CDB_PAYMENT && window.CDB_PAYMENT.open) {
        this.close();
        window.CDB_PAYMENT.open({
          product:      opts.product || 'checkout',
          productLabel: opts.productLabel || 'Security Report',
          amountLabel:  (getGeo().matrix.symbol) + opts.amount,
        });
        return;
      }
      // Real subscription plans (STARTER/PRO/ENTERPRISE/MSSP) go through the
      // canonical server-side create-order → Razorpay → verify flow, the same
      // path already used and verified live for marketplace/MSSP checkout.
      // Previously this constructed `new Razorpay({amount: opts.amount, ...})`
      // directly in the browser with NO order_id and NO server-side order —
      // even when it did fire, the real webhook handler (handleRazorpayWebhook)
      // looks up the payment by razorpay_order_id in the `payments` table and
      // would find nothing, so the subscription could never actually activate.
      // Found + fixed 2026-06-29.
      const SUBSCRIPTION_PLANS = new Set(['STARTER', 'PRO', 'ENTERPRISE', 'MSSP']);
      if (SUBSCRIPTION_PLANS.has(opts.tierName)) {
        this._startSubscriptionCheckout(opts);
        return;
      }
      // One-time report purchases (domain/ai/redteam/identity/compliance) go
      // through the same canonical create-order → Razorpay → verify flow as
      // subscriptions, for the same reason: the legacy `new Razorpay({amount})`
      // call below carried no order_id, so a captured payment had no `payments`
      // row to match against and no report was ever generated automatically.
      if (opts.module) {
        this._startReportCheckout(opts);
        return;
      }
      // Legacy path — only reachable if a caller sets neither opts.module nor a
      // subscription tierName. Kept as a last-resort so a stray/unknown product
      // still gets a payment ID a human can act on, rather than a hard failure.
      const key = (window.CONFIG && window.CONFIG.RAZORPAY_KEY_ID) || '';
      if (!key || !window.Razorpay) {
        alert('Card payment not configured. Please use UPI, Bank Wire, or PayPal.');
        return;
      }
      const geo = getGeo();
      new window.Razorpay({
        key,
        amount:      opts.amount * (geo.countryCode === 'IN' ? 100 : 1),
        currency:    geo.matrix.currency || 'INR',
        name:        'CYBERDUDEBIVASH PVT LTD',
        description: opts.productLabel || 'Security Report',
        handler:     r => this._onRazorpaySuccess(r),
        modal:       { ondismiss: () => {} },
      }).open();
    },

    _loadRazorpaySdk() {
      if (window.Razorpay) return Promise.resolve();
      return new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://checkout.razorpay.com/v1/checkout.js';
        s.onload  = () => resolve();
        s.onerror = () => reject(new Error('Razorpay SDK load failed'));
        document.head.appendChild(s);
      });
    },

    async _startSubscriptionCheckout(opts) {
      let email = '';
      try { email = localStorage.getItem('cdb_email') || ''; } catch (e) {}
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        email = (window.prompt('Enter your email to activate your subscription:') || '').trim();
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
          alert('A valid email address is required to activate a subscription.');
          return;
        }
        try { localStorage.setItem('cdb_email', email); } catch (e) {}
      }

      try {
        const oRes = await fetch('/api/payment/create-order', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ module: 'subscription', plan: opts.tierName, target: email }),
        });
        const order = await oRes.json().catch(() => ({}));
        if (!oRes.ok || !order.order_id || !order.key_id) {
          alert('Could not start checkout. Please use UPI, Bank Wire, or PayPal, or contact support@cyberdudebivash.com.');
          return;
        }

        await this._loadRazorpaySdk();
        this.close();

        new window.Razorpay({
          key:         order.key_id,
          amount:      order.amount,
          currency:    order.currency || 'INR',
          name:        'CYBERDUDEBIVASH PVT LTD',
          description: opts.productLabel || `${opts.tierName} Plan`,
          order_id:    order.order_id,
          prefill:     { email },
          handler:     async (rp) => {
            try {
              const vRes = await fetch('/api/payment/verify', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  razorpay_order_id:   rp.razorpay_order_id,
                  razorpay_payment_id: rp.razorpay_payment_id,
                  razorpay_signature:  rp.razorpay_signature,
                  module: 'subscription', plan: opts.tierName, target: email, email,
                }),
              });
              const vData = await vRes.json().catch(() => ({}));
              this._onRazorpaySuccess(rp, vRes.ok && vData.success, vData.message);
            } catch (e) {
              this._onRazorpaySuccess(rp, false);
            }
          },
          modal: { ondismiss: () => {} },
        }).open();
      } catch (e) {
        alert('Could not start checkout. Please use UPI, Bank Wire, or PayPal, or contact support@cyberdudebivash.com.');
      }
    },

    async _startReportCheckout(opts) {
      const target = (opts.target || '').trim();
      if (!target) {
        alert('Missing scan target for this report. Please contact support@cyberdudebivash.com.');
        return;
      }
      let email = '';
      try { email = localStorage.getItem('cdb_email') || ''; } catch (e) {}
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
        email = (window.prompt('Enter your email to receive your report:') || '').trim();
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
          alert('A valid email address is required to deliver your report.');
          return;
        }
        try { localStorage.setItem('cdb_email', email); } catch (e) {}
      }

      try {
        const oRes = await fetch('/api/payment/create-order', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ module: opts.module, target, email }),
        });
        const order = await oRes.json().catch(() => ({}));
        if (!oRes.ok || !order.order_id || !order.key_id) {
          alert('Could not start checkout. Please use UPI, Bank Wire, or PayPal, or contact support@cyberdudebivash.com.');
          return;
        }

        await this._loadRazorpaySdk();
        this.close();

        new window.Razorpay({
          key:         order.key_id,
          amount:      order.amount,
          currency:    order.currency || 'INR',
          name:        'CYBERDUDEBIVASH PVT LTD',
          description: opts.productLabel || order.report_name || 'Security Report',
          order_id:    order.order_id,
          prefill:     { email },
          handler:     async (rp) => {
            try {
              const vRes = await fetch('/api/payment/verify', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  razorpay_order_id:   rp.razorpay_order_id,
                  razorpay_payment_id: rp.razorpay_payment_id,
                  razorpay_signature:  rp.razorpay_signature,
                  module: opts.module, target, email,
                }),
              });
              const vData = await vRes.json().catch(() => ({}));
              this._onReportPaymentComplete(rp, vRes.ok && vData.success, vData);
            } catch (e) {
              this._onReportPaymentComplete(rp, false, {});
            }
          },
          modal: { ondismiss: () => {} },
        }).open();
      } catch (e) {
        alert('Could not start checkout. Please use UPI, Bank Wire, or PayPal, or contact support@cyberdudebivash.com.');
      }
    },

    _onReportPaymentComplete(resp, verified, data) {
      this.close();
      const toast = document.createElement('div');
      toast.style.cssText = 'position:fixed;top:20px;right:20px;max-width:360px;background:#00ff88;color:#000;padding:14px 22px;border-radius:12px;font-weight:900;font-size:14px;z-index:999999;box-shadow:0 8px 30px rgba(0,255,136,.3)';
      if (verified && data.download_url) {
        toast.innerHTML = `✅ Payment verified — your report is ready.<br><a href="${data.download_url}" style="color:#000;text-decoration:underline">Download it now</a>`;
      } else {
        toast.textContent = verified
          ? (data.message || '✅ Payment successful!')
          : `✅ Payment received (ID: ${resp.razorpay_payment_id}). If your report doesn't arrive within a few minutes, contact support@cyberdudebivash.com with this payment ID.`;
      }
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), verified ? 15000 : 20000);
    },

    _onRazorpaySuccess(resp, verified, message) {
      this.close();
      // Show success toast
      const toast = document.createElement('div');
      toast.style.cssText = 'position:fixed;top:20px;right:20px;background:#00ff88;color:#000;padding:14px 22px;border-radius:12px;font-weight:900;font-size:14px;z-index:999999;box-shadow:0 8px 30px rgba(0,255,136,.3)';
      toast.textContent = verified
        ? (message || '✅ Payment successful! Your account is now active.')
        : `✅ Payment received (ID: ${resp.razorpay_payment_id}). If your account isn't upgraded within a few minutes, contact support@cyberdudebivash.com with this payment ID.`;
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), verified ? 5000 : 12000);
    },
  };

  /* ── BACKWARDS COMPAT: pricing card CTA buttons ──────────────────── */
  // Pricing card "Get Plan" buttons call CDB_CHECKOUT_MODAL.openPlan(planId)
  window.CDB_CHECKOUT_MODAL.openPlan = function(planId) {
    const geo    = getGeo();
    const matrix = geo.matrix;
    const plan   = matrix.plans ? matrix.plans[planId] : null;
    if (!plan) { window.location.href = '/#pricing'; return; }
    this.open({
      amount:       plan.monthly,
      tierName:     planId,
      productLabel: `${plan.label} — Monthly Plan`,
    });
  };

  window.CDB_CHECKOUT_MODAL.openReport = function(reportType, target) {
    const geo    = getGeo();
    const module = (reportType || 'domain').toLowerCase();
    const amount = (geo.matrix.reports && geo.matrix.reports[module])
                   || (geo.countryCode === 'IN' ? 999 : 12);
    this.open({
      amount,
      module,
      target:       target || '',
      tierName:     'REPORT_' + module.toUpperCase(),
      productLabel: module.toUpperCase() + ' Security Report' + (target ? ` — ${target}` : ''),
    });
  };

})();
