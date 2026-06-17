/**
 * ═══════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI SECURITY HUB — GLOBAL ENGINE v1.0
 * Shared across ALL pages: Nav · Payment Modal · Sticky CTA
 * Exit Intent · Lead Capture · Toast · Animations
 * ═══════════════════════════════════════════════════════════════
 */
(function CDB_GLOBAL() {
'use strict';

/* ── Config ──────────────────────────────────────────────────── */
const CFG = {
  api:      'https://cyberdudebivash-security-hub.workers.dev',
  site:     'https://cyberdudebivash.in',
  tools:    'https://tools.cyberdudebivash.com',
  intel:    'https://intel.cyberdudebivash.com',
  email:    'bivash@cyberdudebivash.com',
  phone:    '+918179881447',
  upi1:     'iambivash.bn-5@okaxis',
  upi2:     '6302177246@axisbank',
  upiName:  'Bivash Kumar Nayak',
  bankAcc:  '915010024617260',
  bankIFSC: 'UTIB0000052',
  bankName: 'Axis Bank',
  bankAccName: 'BIVASHA KUMAR NAYAK',
  paypal:   'https://www.paypal.com/paypalme/iambivash',
  paypalEmail: 'iambivash.bn@gmail.com',
  crypto:   '0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796',
  cryptoNet:'BNB Smart Chain (BSC)',
};

window.CDB_CFG = CFG;

/* ══════════════════════════════════════════════════════════════
   PAYMENT MODAL
══════════════════════════════════════════════════════════════ */
function injectPaymentModal() {
  if (document.getElementById('cdb-global-pay-modal')) return;
  const m = document.createElement('div');
  m.id = 'cdb-global-pay-modal';
  m.style.cssText = `display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);
    backdrop-filter:blur(12px);z-index:99999;align-items:center;justify-content:center;padding:16px`;
  m.innerHTML = `
  <div style="background:#0d1117;border:1px solid rgba(0,255,204,.2);border-radius:20px;
              max-width:520px;width:100%;max-height:90vh;overflow-y:auto;
              box-shadow:0 0 60px rgba(0,255,204,.1)">
    <!-- Header -->
    <div style="padding:20px 24px 16px;border-bottom:1px solid rgba(255,255,255,.07);
                display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:18px;font-weight:900;color:#fff" id="cgpm-title">Complete Purchase</div>
        <div style="font-size:13px;color:rgba(255,255,255,.45)" id="cgpm-subtitle">Select payment method below</div>
      </div>
      <button onclick="CDB_PAY.close()" style="background:rgba(255,255,255,.07);border:1px solid
        rgba(255,255,255,.1);border-radius:8px;color:rgba(255,255,255,.5);padding:8px 12px;
        cursor:pointer;font-size:16px;line-height:1">✕</button>
    </div>

    <!-- Amount badge -->
    <div style="margin:16px 24px 0;background:rgba(0,255,204,.06);border:1px solid rgba(0,255,204,.2);
                border-radius:10px;padding:12px 16px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:11px;color:rgba(255,255,255,.4);font-weight:700;letter-spacing:.5px">AMOUNT DUE</div>
        <div style="font-size:28px;font-weight:900;color:#00ffcc" id="cgpm-amount">₹0</div>
      </div>
      <div style="font-size:11px;color:rgba(255,255,255,.35);text-align:right;line-height:1.6">
        One-time · GST incl.<br>Access in 2–4 hrs
      </div>
    </div>

    <!-- Tabs -->
    <div style="display:flex;gap:4px;padding:16px 24px 0">
      ${['upi','bank','paypal','crypto'].map(t=>`
      <button id="cgpm-tab-${t}" onclick="CDB_PAY.tab('${t}')"
        style="flex:1;padding:9px 4px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;
               border:1px solid rgba(255,255,255,.1);transition:all .2s;
               background:${t==='upi'?'rgba(0,255,204,.12)':'rgba(255,255,255,.04)'};
               color:${t==='upi'?'#00ffcc':'rgba(255,255,255,.5)'}">
        ${t==='upi'?'📱 UPI':t==='bank'?'🏦 Bank':t==='paypal'?'🌐 PayPal':'🔐 Crypto'}
      </button>`).join('')}
    </div>

    <div id="cgpm-body" style="padding:16px 24px 24px">

      <!-- UPI Pane — P0-2: UPI Deep-Link + Dynamic QR + NEFT wiring -->
      <div id="cgpm-pane-upi">
        <!-- Dynamic QR — generated from UPI deep-link for exact amount -->
        <div style="text-align:center;margin-bottom:14px">
          <div id="cgpm-upi-qr-wrap" style="display:inline-block;position:relative">
            <img id="cgpm-upi-qr-img"
              src="/assets/payment/upi-qr.png"
              alt="UPI QR — scan with any UPI app"
              style="width:180px;height:180px;border-radius:12px;border:2px solid rgba(0,255,204,.3);
                     object-fit:cover;background:rgba(255,255,255,.05)">
            <div id="cgpm-qr-loading" style="display:none;position:absolute;inset:0;background:rgba(0,0,0,.7);
                 border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:11px;color:#00ffcc">
              Generating QR...
            </div>
          </div>
          <div style="font-size:10px;color:rgba(255,255,255,.4);margin-top:6px">
            Scan with Google Pay · PhonePe · Paytm · BHIM · Any UPI App
          </div>
        </div>
        <!-- UPI Deep-Link Buttons — direct app launch -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px" id="cgpm-upi-apps">
          <a id="cgpm-gpay-link" href="#" target="_blank"
            style="display:flex;align-items:center;justify-content:center;gap:6px;
                   background:rgba(66,133,244,.15);border:1px solid rgba(66,133,244,.3);
                   border-radius:8px;padding:10px 8px;text-decoration:none;color:#74a7ff;font-size:12px;font-weight:700">
            <span style="font-size:16px">🟡</span> Google Pay
          </a>
          <a id="cgpm-phonepe-link" href="#" target="_blank"
            style="display:flex;align-items:center;justify-content:center;gap:6px;
                   background:rgba(98,0,238,.15);border:1px solid rgba(98,0,238,.3);
                   border-radius:8px;padding:10px 8px;text-decoration:none;color:#b39ddb;font-size:12px;font-weight:700">
            <span style="font-size:16px">💜</span> PhonePe
          </a>
          <a id="cgpm-paytm-link" href="#" target="_blank"
            style="display:flex;align-items:center;justify-content:center;gap:6px;
                   background:rgba(0,180,220,.15);border:1px solid rgba(0,180,220,.3);
                   border-radius:8px;padding:10px 8px;text-decoration:none;color:#4dd0e1;font-size:12px;font-weight:700">
            <span style="font-size:16px">💙</span> Paytm
          </a>
          <a id="cgpm-bhim-link" href="#" target="_blank"
            style="display:flex;align-items:center;justify-content:center;gap:6px;
                   background:rgba(255,153,0,.15);border:1px solid rgba(255,153,0,.3);
                   border-radius:8px;padding:10px 8px;text-decoration:none;color:#ffcc80;font-size:12px;font-weight:700">
            <span style="font-size:16px">🟠</span> BHIM
          </a>
        </div>
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
                    border-radius:10px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;letter-spacing:.5px;margin-bottom:4px">PRIMARY UPI ID</div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
            <code style="font-size:15px;font-weight:800;color:#00ffcc">${CFG.upi1}</code>
            <button onclick="CDB_PAY.copy('${CFG.upi1}','cgpm-copy-upi1')" id="cgpm-copy-upi1"
              style="background:rgba(0,255,204,.1);border:1px solid rgba(0,255,204,.3);color:#00ffcc;
                     border-radius:6px;padding:5px 12px;font-size:11px;cursor:pointer;white-space:nowrap">Copy</button>
          </div>
        </div>
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
                    border-radius:10px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;letter-spacing:.5px;margin-bottom:4px">ALTERNATE UPI ID</div>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
            <code style="font-size:14px;font-weight:700;color:rgba(255,255,255,.7)">${CFG.upi2}</code>
            <button onclick="CDB_PAY.copy('${CFG.upi2}','cgpm-copy-upi2')" id="cgpm-copy-upi2"
              style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.5);
                     border-radius:6px;padding:5px 12px;font-size:11px;cursor:pointer">Copy</button>
          </div>
        </div>
        <div style="font-size:11px;color:rgba(255,255,255,.4);margin-bottom:12px;text-align:center">
          Add your email in the payment remarks for faster activation
        </div>
      </div>

      <!-- Bank Pane -->
      <div id="cgpm-pane-bank" style="display:none">
        ${[['Account Name',CFG.bankAccName],['Account Number',CFG.bankAcc],['IFSC Code',CFG.bankIFSC],['Bank',CFG.bankName],['Account Type','Savings']].map(([k,v])=>`
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
                    border-radius:10px;padding:12px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between;gap:8px">
          <div>
            <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;letter-spacing:.5px">${k.toUpperCase()}</div>
            <div style="font-size:14px;font-weight:700;color:#fff;margin-top:2px">${v}</div>
          </div>
          <button onclick="CDB_PAY.copy('${v}','cgpm-copy-${k.replace(/ /g,'')}');this.textContent='✅'"
            style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.5);
                   border-radius:6px;padding:5px 12px;font-size:11px;cursor:pointer;white-space:nowrap;flex-shrink:0">Copy</button>
        </div>`).join('')}
        <div style="font-size:11px;color:rgba(255,255,255,.4);margin-top:6px;text-align:center">
          Add email in transfer remarks for faster activation
        </div>
      </div>

      <!-- PayPal Pane -->
      <div id="cgpm-pane-paypal" style="display:none;text-align:center">
        <div style="font-size:40px;margin-bottom:12px">🌐</div>
        <div style="font-size:16px;font-weight:800;color:#fff;margin-bottom:6px">Pay via PayPal</div>
        <div style="font-size:13px;color:rgba(255,255,255,.5);margin-bottom:16px">
          Email: <strong style="color:#fff">${CFG.paypalEmail}</strong><br>
          <em style="font-size:11px">Select "Friends &amp; Family" to avoid fees</em>
        </div>
        <a href="${CFG.paypal}" target="_blank"
          style="display:inline-block;background:linear-gradient(135deg,#003087,#009cde);color:#fff;
                 padding:14px 32px;border-radius:12px;font-weight:800;font-size:15px;text-decoration:none;
                 box-shadow:0 4px 20px rgba(0,156,222,.3)">
          Pay on PayPal →
        </a>
        <div style="font-size:11px;color:rgba(255,255,255,.35);margin-top:12px">
          Add product name in PayPal note for faster activation
        </div>
      </div>

      <!-- Crypto Pane -->
      <div id="cgpm-pane-crypto" style="display:none">
        <div style="background:rgba(255,165,0,.06);border:1px solid rgba(255,165,0,.2);
                    border-radius:10px;padding:12px;margin-bottom:12px;font-size:12px;color:rgba(255,200,0,.8)">
          ⚠️ Only send <strong>BNB or BEP-20 tokens</strong> on BNB Smart Chain. Other networks = permanent loss.
        </div>
        <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
                    border-radius:10px;padding:14px;margin-bottom:10px">
          <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;letter-spacing:.5px;margin-bottom:6px">WALLET ADDRESS (BNB SMART CHAIN)</div>
          <div style="font-size:12px;font-family:monospace;color:#00ffcc;word-break:break-all;margin-bottom:8px">${CFG.crypto}</div>
          <button onclick="CDB_PAY.copy('${CFG.crypto}','cgpm-copy-crypto')" id="cgpm-copy-crypto"
            style="width:100%;background:rgba(0,255,204,.1);border:1px solid rgba(0,255,204,.3);color:#00ffcc;
                   border-radius:8px;padding:8px;font-size:12px;font-weight:700;cursor:pointer">
            Copy Wallet Address
          </button>
        </div>
        <div style="font-size:11px;color:rgba(255,255,255,.35)">
          Network: <strong style="color:#fff">${CFG.cryptoNet}</strong> · Token: BNB / USDT (BEP-20)
        </div>
      </div>

      <!-- Proof submission (all methods) -->
      <div style="margin-top:16px;border-top:1px solid rgba(255,255,255,.07);padding-top:16px">
        <div style="font-size:12px;font-weight:800;color:rgba(255,255,255,.6);margin-bottom:10px;letter-spacing:.3px">
          SUBMIT PAYMENT PROOF
        </div>
        <input id="cgpm-email" type="email" placeholder="Your email *"
          style="width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);
                 border-radius:8px;padding:10px 14px;color:#fff;font-size:13px;margin-bottom:8px;box-sizing:border-box;outline:none">
        <input id="cgpm-txn" type="text" placeholder="Transaction ID / UTR / TxHash *"
          style="width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);
                 border-radius:8px;padding:10px 14px;color:#fff;font-size:13px;margin-bottom:12px;box-sizing:border-box;outline:none">
        <button onclick="CDB_PAY.submit()"
          style="width:100%;background:linear-gradient(135deg,#00ffcc,#00b894);color:#000;border:none;
                 border-radius:10px;padding:14px;font-size:15px;font-weight:900;cursor:pointer;
                 box-shadow:0 4px 20px rgba(0,255,204,.3)">
          ✅ I Have Paid — Submit Confirmation
        </button>
        <div id="cgpm-status" style="margin-top:10px;font-size:12px;text-align:center"></div>
        <div style="font-size:11px;color:rgba(255,255,255,.3);margin-top:10px;text-align:center;line-height:1.6">
          🔒 Access activated within 2–4 hours after verification<br>
          📧 Confirmation sent to your email · Support: ${CFG.email}
        </div>
      </div>
    </div>
  </div>`;
  document.body.appendChild(m);
  m.addEventListener('click', e => { if (e.target === m) CDB_PAY.close(); });
}

window.CDB_PAY = {
  _current: {},
  open(product, amountInr, label) {
    this._current = { product, amountInr, label };
    injectPaymentModal();
    const m = document.getElementById('cdb-global-pay-modal');
    document.getElementById('cgpm-title').textContent = label || product || 'Complete Purchase';
    document.getElementById('cgpm-amount').textContent = amountInr ? `₹${Number(amountInr).toLocaleString('en-IN')}` : '';
    document.getElementById('cgpm-status').textContent = '';
    document.getElementById('cgpm-txn').value = '';
    m.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    this.tab('upi');
    sessionStorage.setItem('cdb_pay_intent', JSON.stringify({ product, amountInr, label, ts: Date.now() }));
    // P0-2: Wire UPI deep-links with exact amount and generate dynamic QR
    if (amountInr) {
      try { this._setupUPIRails(label || product || 'Security Service', amountInr); }
      catch(e) { console.warn('[CDB_PAY] UPI setup failed:', e.message); }
    }
  },

  // ── P0-2: UPI Deep-Link + Dynamic QR Rail ─────────────────────────────────
  _buildUPIDeepLink(vpa, amountInr, note) {
    const params = new URLSearchParams({
      pa: vpa,
      pn: CFG.upiName || 'Bivash Kumar Nayak',
      am: String(Number(amountInr || 0).toFixed(2)),
      cu: 'INR',
      tn: (note || 'CYBERDUDEBIVASH').slice(0, 50),
    });
    return `upi://pay?${params.toString()}`;
  },

  _generateDynamicQR(upiUri, size) {
    // api.qrserver.com — free, no API key, supports custom colors
    return `https://api.qrserver.com/v1/create-qr-code/?size=${size||180}x${size||180}&data=${encodeURIComponent(upiUri)}&color=00ffcc&bgcolor=0d0d1a&margin=8`;
  },

  _setupUPIRails(productLabel, amountInr) {
    const note = `${(productLabel||'CDB').slice(0,30)} ${new Date().toISOString().slice(0,10)}`;
    const upiUri = this._buildUPIDeepLink(CFG.upi1, amountInr, note);

    // Standard UPI intent: works with any NPCI-registered app
    const set = (id, href) => { const el = document.getElementById(id); if (el) el.href = href; };

    // Build query string for each app's proprietary scheme
    const q = new URLSearchParams({ pa: CFG.upi1, pn: CFG.upiName||'Bivash Kumar Nayak',
      am: String(Number(amountInr||0).toFixed(2)), cu: 'INR', tn: note });

    set('cgpm-gpay-link',    `tez://upi/pay?${q}`);     // Google Pay (Tez)
    set('cgpm-phonepe-link', `phonepe://pay?${q}`);      // PhonePe
    set('cgpm-paytm-link',   `paytmmp://pay?${q}`);      // Paytm
    set('cgpm-bhim-link',    upiUri);                     // BHIM + generic UPI

    // Dynamic QR — regenerated for exact amount (not static /assets/payment/upi-qr.png)
    const qrImg = document.getElementById('cgpm-upi-qr-img');
    if (qrImg && amountInr > 0) {
      qrImg.style.opacity = '0.3';
      const tmp = new Image();
      tmp.onload  = () => { qrImg.src = tmp.src; qrImg.style.opacity = '1'; };
      tmp.onerror = () => { qrImg.style.opacity = '1'; }; // fallback to static
      tmp.src = this._generateDynamicQR(upiUri, 180);
    }
  },
  close() {
    const m = document.getElementById('cdb-global-pay-modal');
    if (m) { m.style.display = 'none'; document.body.style.overflow = ''; }
  },
  tab(t) {
    ['upi','bank','paypal','crypto'].forEach(x => {
      const btn  = document.getElementById(`cgpm-tab-${x}`);
      const pane = document.getElementById(`cgpm-pane-${x}`);
      const active = x === t;
      if (btn) {
        btn.style.background = active ? 'rgba(0,255,204,.12)' : 'rgba(255,255,255,.04)';
        btn.style.borderColor = active ? 'rgba(0,255,204,.4)' : 'rgba(255,255,255,.1)';
        btn.style.color = active ? '#00ffcc' : 'rgba(255,255,255,.5)';
      }
      if (pane) pane.style.display = active ? 'block' : 'none';
    });
  },
  copy(text, btnId) {
    navigator.clipboard?.writeText(text).catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    });
    const btn = document.getElementById(btnId);
    if (btn) { const orig = btn.textContent; btn.textContent = '✅ Copied!'; setTimeout(() => btn.textContent = orig, 2000); }
  },
  async submit() {
    const email = document.getElementById('cgpm-email')?.value?.trim();
    const txn   = document.getElementById('cgpm-txn')?.value?.trim();
    const statusEl = document.getElementById('cgpm-status');
    if (!email || !email.includes('@')) { statusEl.textContent = '⚠️ Valid email required'; statusEl.style.color = '#ef4444'; return; }
    if (!txn) { statusEl.textContent = '⚠️ Transaction ID required'; statusEl.style.color = '#ef4444'; return; }
    statusEl.textContent = '⏳ Submitting...'; statusEl.style.color = 'rgba(255,255,255,.6)';
    try {
      await fetch(`${CFG.api}/api/payment/confirm`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ txnId: txn, user: email, product: this._current.product,
          amount: this._current.amountInr, method: 'MANUAL', currency: 'INR',
          notes: `Global pay: ${this._current.label}` }),
      });
    } catch {}
    // Dispatch payment submitted event for academy delivery modal
    document.dispatchEvent(new CustomEvent('cdb:paymentSubmitted', { detail: { ...this._current, txnId: txn, email } }));

    // Determine if this was an academy purchase or a scan purchase
    const isAcademyPurchase = this._current.product && (
      this._current.product.includes('BUNDLE') ||
      this._current.product.includes('PLAYBOOK') ||
      this._current.product.includes('TRAINING') ||
      this._current.product.includes('COURSE') ||
      this._current.product.includes('OSINT') ||
      this._current.product.includes('PYTHON') ||
      this._current.product.includes('JAVA') ||
      this._current.product.includes('CYBER_MEGA') ||
      this._current.product.includes('ACADEMY') ||
      this._current.product.includes('AI_SECURITY')
    );

    const body = document.getElementById('cgpm-body');
    if (body) body.innerHTML = `
      <div style="padding:20px 16px">
        <div style="text-align:center;margin-bottom:20px">
          <div style="font-size:48px;margin-bottom:12px">✅</div>
          <div style="font-size:20px;font-weight:900;color:#00ffcc;margin-bottom:6px">Payment Submitted!</div>
          <div style="font-size:13px;color:rgba(255,255,255,.55);line-height:1.6">
            Txn ID: <code style="color:#00ffcc">${txn}</code><br>
            Access activated within <strong style="color:#fff">2–4 hours</strong>.<br>
            Confirmation to <strong style="color:#00ffcc">${email}</strong>
          </div>
        </div>
        ${isAcademyPurchase ? `
        <!-- ACADEMY DELIVERY INSTRUCTIONS -->
        <div style="background:rgba(0,255,136,.05);border:1px solid rgba(0,255,136,.15);border-radius:10px;padding:16px;margin-bottom:16px">
          <div style="font-size:11px;font-weight:900;letter-spacing:1.5px;text-transform:uppercase;color:#00ffcc;margin-bottom:10px">📥 GET YOUR TRAINING MATERIALS</div>
          <div style="font-size:12px;color:rgba(255,255,255,.6);line-height:1.9">
            <div>1️⃣ Screenshot your payment confirmation</div>
            <div>2️⃣ Email: <strong style="color:#00ffcc">bivash@cyberdudebivash.com</strong></div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;Subject: <strong style="color:#fff">Training — ${this._current.label||'Course'}</strong></div>
            <div>3️⃣ OR WhatsApp: <a href="https://wa.me/918179881447" target="_blank" style="color:#00ffcc">+91 8179881447</a></div>
            <div>4️⃣ Receive download link in <strong style="color:#00ff88">2–4 hours</strong></div>
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
            <a href="mailto:bivash@cyberdudebivash.com?subject=Training — ${encodeURIComponent(this._current.label||'Course')}" style="flex:1;display:flex;align-items:center;justify-content:center;gap:5px;background:linear-gradient(135deg,#00ff88,#00cc66);color:#000;font-size:12px;font-weight:900;padding:10px;border-radius:8px;text-decoration:none;min-width:100px">📧 Email Us</a>
            <a href="https://wa.me/918179881447?text=${encodeURIComponent('Hi! Purchased: '+(this._current.label||'Training')+'. Sending payment screenshot.')}" target="_blank" style="flex:1;display:flex;align-items:center;justify-content:center;gap:5px;background:rgba(37,211,102,.12);border:1px solid rgba(37,211,102,.3);color:#25d366;font-size:12px;font-weight:900;padding:10px;border-radius:8px;text-decoration:none;min-width:100px">💬 WhatsApp</a>
          </div>
        </div>` : `
        <!-- POST-SCAN PURCHASE: TRAINING UPSELL -->
        <div style="background:linear-gradient(135deg,rgba(0,0,0,.6),rgba(10,5,20,.8));border:1px solid rgba(124,58,237,.25);border-radius:10px;padding:16px;margin-bottom:16px">
          <div style="font-size:10px;font-weight:900;letter-spacing:1.5px;text-transform:uppercase;color:#a78bfa;margin-bottom:10px">🎓 LEVEL UP YOUR SKILLS</div>
          <div style="font-size:13px;font-weight:800;color:#fff;margin-bottom:6px">Learn How to Defend Against These Attacks</div>
          <div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:12px;line-height:1.5">The SOC Analyst Survival Playbook 2026 teaches you to detect, respond to, and prevent exactly the threats found in your scan.</div>
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <div>
              <span style="font-size:20px;font-weight:900;color:#00ff88">₹999</span>
              <span style="font-size:12px;color:rgba(255,255,255,.3);text-decoration:line-through;margin-left:6px">₹1,499</span>
            </div>
            <button onclick="CDB_PAY.open('SOC_PLAYBOOK_2026',999,'📘 SOC Analyst Survival Playbook 2026')" style="background:linear-gradient(135deg,#00ff88,#00cc66);color:#000;border:none;border-radius:8px;padding:9px 18px;font-size:12px;font-weight:900;cursor:pointer;transition:all .2s;flex:1">🔓 Get Training — ₹999</button>
            <a href="/academy.html" style="font-size:11px;color:#a78bfa;text-decoration:none;white-space:nowrap">View All →</a>
          </div>
        </div>`}
        <button onclick="CDB_PAY.close()" style="width:100%;background:rgba(0,255,204,.1);border:1px solid rgba(0,255,204,.3);color:#00ffcc;padding:11px 20px;border-radius:10px;font-weight:800;cursor:pointer;font-size:13px">Done ✓</button>
      </div>`;
  },
};

/* ══════════════════════════════════════════════════════════════
   STICKY CTA BAR
══════════════════════════════════════════════════════════════ */
function injectStickyCTA() {
  if (document.getElementById('cdb-sticky-cta')) return;
  const bar = document.createElement('div');
  bar.id = 'cdb-sticky-cta';
  bar.style.cssText = `position:fixed;bottom:0;left:0;right:0;z-index:9000;
    background:rgba(10,15,28,.96);border-top:1px solid rgba(0,255,204,.2);
    padding:10px 20px;display:flex;align-items:center;justify-content:center;gap:10px;
    flex-wrap:wrap;backdrop-filter:blur(16px);
    transform:translateY(100%);transition:transform .4s ease`;
  bar.innerHTML = `
    <span style="font-size:11px;color:rgba(255,255,255,.45);display:flex;align-items:center;gap:5px">
      <span style="width:6px;height:6px;border-radius:50%;background:#ef4444;animation:cdbPulse 1.5s infinite"></span>
      Live threat scan active
    </span>
    <a href="/#scanner" style="background:linear-gradient(135deg,#00ffcc,#00b894);color:#000;
       padding:9px 18px;border-radius:8px;font-size:13px;font-weight:900;text-decoration:none;white-space:nowrap">
      🔍 Scan Now
    </a>
    <a href="/booking.html" style="background:rgba(0,255,204,.1);border:1px solid rgba(0,255,204,.3);
       color:#00ffcc;padding:9px 18px;border-radius:8px;font-size:13px;font-weight:700;text-decoration:none;white-space:nowrap">
      📅 Book Demo
    </a>
    <a href="/services.html" style="background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.35);
       color:#a78bfa;padding:9px 18px;border-radius:8px;font-size:13px;font-weight:700;text-decoration:none;white-space:nowrap">
      💰 Security Report
    </a>
    <button onclick="document.getElementById('cdb-sticky-cta').style.transform='translateY(100%)'"
      style="background:transparent;border:1px solid rgba(255,255,255,.12);color:rgba(255,255,255,.35);
             border-radius:6px;padding:8px 10px;font-size:12px;cursor:pointer;flex-shrink:0">✕</button>
    <style>@keyframes cdbPulse{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,.5)}70%{box-shadow:0 0 0 6px rgba(239,68,68,0)}}</style>`;
  document.body.appendChild(bar);
  setTimeout(() => { bar.style.transform = 'translateY(0)'; }, 5000);
  setInterval(() => {
    if (bar.style.transform === 'translateY(100%)') bar.style.transform = 'translateY(0)';
  }, 90000);
}

/* ══════════════════════════════════════════════════════════════
   EXIT INTENT POPUP
══════════════════════════════════════════════════════════════ */
function injectExitIntent() {
  if (sessionStorage.getItem('cdb_exit_shown')) return;
  if (document.getElementById('cdb-exit-popup')) return;
  const pop = document.createElement('div');
  pop.id = 'cdb-exit-popup';
  pop.style.cssText = `display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);
    backdrop-filter:blur(12px);z-index:99998;align-items:center;justify-content:center;padding:20px`;
  pop.innerHTML = `
  <div style="background:#0d1117;border:1px solid rgba(0,255,204,.25);border-radius:20px;
              max-width:460px;width:100%;padding:32px;position:relative;
              box-shadow:0 0 60px rgba(0,255,204,.08)">
    <button onclick="CDB_EXIT.close()" style="position:absolute;top:16px;right:16px;
      background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:6px;
      color:rgba(255,255,255,.4);padding:6px 10px;cursor:pointer;font-size:14px">✕</button>
    <div style="text-align:center;margin-bottom:24px">
      <div style="font-size:40px;margin-bottom:12px">🔍</div>
      <h2 style="font-size:22px;font-weight:900;color:#fff;margin-bottom:8px">
        Wait — Is Your Domain Safe?
      </h2>
      <p style="font-size:14px;color:rgba(255,255,255,.55);line-height:1.6">
        Get a <strong style="color:#00ffcc">FREE security risk score</strong> for your domain.<br>
        Takes 30 seconds. No account needed.
      </p>
    </div>
    <div style="display:flex;flex-direction:column;gap:10px">
      <input id="cdb-exit-email" type="email" placeholder="Enter your work email *"
        style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:10px;
               padding:12px 16px;color:#fff;font-size:14px;outline:none;box-sizing:border-box">
      <input id="cdb-exit-domain" type="text" placeholder="Enter your domain (e.g. company.com)"
        style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:10px;
               padding:12px 16px;color:#fff;font-size:14px;outline:none;box-sizing:border-box">
      <button onclick="CDB_EXIT.submit()"
        style="background:linear-gradient(135deg,#00ffcc,#00b894);color:#000;border:none;
               border-radius:10px;padding:14px;font-size:15px;font-weight:900;cursor:pointer;
               box-shadow:0 4px 20px rgba(0,255,204,.3)">
        🚀 Get Free Security Scan
      </button>
      <button onclick="CDB_EXIT.close()"
        style="background:transparent;border:none;color:rgba(255,255,255,.3);
               font-size:12px;cursor:pointer;padding:4px">
        No thanks, I'll risk it
      </button>
    </div>
    <div id="cdb-exit-status" style="margin-top:10px;font-size:12px;text-align:center"></div>
  </div>`;
  document.body.appendChild(pop);
  pop.addEventListener('click', e => { if (e.target === pop) CDB_EXIT.close(); });
  document.addEventListener('mouseleave', function onLeave(e) {
    if (e.clientY <= 0 && !sessionStorage.getItem('cdb_exit_shown')) {
      pop.style.display = 'flex';
      document.removeEventListener('mouseleave', onLeave);
    }
  });
}

window.CDB_EXIT = {
  close() {
    sessionStorage.setItem('cdb_exit_shown', '1');
    const p = document.getElementById('cdb-exit-popup');
    if (p) p.style.display = 'none';
  },
  async submit() {
    const email  = document.getElementById('cdb-exit-email')?.value?.trim();
    const domain = document.getElementById('cdb-exit-domain')?.value?.trim();
    const s = document.getElementById('cdb-exit-status');
    if (!email || !email.includes('@')) { if(s){ s.textContent='⚠️ Valid email required'; s.style.color='#ef4444'; } return; }
    sessionStorage.setItem('cdb_exit_shown', '1');
    try {
      await fetch(`${CFG.api}/api/leads/capture`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, domain, source: 'exit_intent', page: location.pathname }),
      });
    } catch {}
    if (domain) {
      sessionStorage.setItem('cdb_hero_domain', domain);
      sessionStorage.setItem('cdb_lead_email', email);
      sessionStorage.setItem('cdb_lead_captured', '1');
      window.location.href = `/?scan=${encodeURIComponent(domain)}#scanner`;
    } else {
      if (s) { s.textContent = '✅ We\'ll send your scan report to ' + email; s.style.color = '#00ffcc'; }
      setTimeout(() => this.close(), 2500);
    }
  },
};

/* ══════════════════════════════════════════════════════════════
   LEAD CAPTURE ENGINE
══════════════════════════════════════════════════════════════ */
window.CDB_LEAD = {
  async submit(formData) {
    const payload = { ...formData, source: location.pathname, ts: new Date().toISOString() };
    try {
      const r = await fetch(`${CFG.api}/api/leads/capture`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return r.ok;
    } catch { return false; }
  },
  storeLocal(data) {
    try {
      const leads = JSON.parse(localStorage.getItem('cdb_leads') || '[]');
      leads.unshift({ ...data, ts: new Date().toISOString() });
      localStorage.setItem('cdb_leads', JSON.stringify(leads.slice(0, 100)));
    } catch {}
  },
};

/* ══════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
══════════════════════════════════════════════════════════════ */
window.CDB_TOAST = {
  show(msg, type = 'success', duration = 4000) {
    const t = document.createElement('div');
    const colors = { success: '#00ffcc', error: '#ef4444', warning: '#f59e0b', info: '#3b82f6' };
    const color = colors[type] || colors.success;
    t.style.cssText = `position:fixed;top:80px;right:20px;z-index:99999;
      background:#0d1117;border:1px solid ${color}40;border-radius:10px;
      padding:12px 18px;font-size:13px;font-weight:700;color:${color};
      backdrop-filter:blur(12px);box-shadow:0 4px 24px rgba(0,0,0,.4);
      max-width:300px;animation:cdbToastIn .3s ease;
      border-left:3px solid ${color}`;
    t.innerHTML = `<style>@keyframes cdbToastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}</style>${msg}`;
    document.body.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, duration);
  },
};

/* ══════════════════════════════════════════════════════════════
   NAV HAMBURGER (mobile)
══════════════════════════════════════════════════════════════ */
window.CDB_NAV = {
  toggle() {
    const m = document.getElementById('cdb-mobile-nav');
    if (m) m.style.display = m.style.display === 'flex' ? 'none' : 'flex';
  },
};

/* ══════════════════════════════════════════════════════════════
   SCROLL ANIMATIONS
══════════════════════════════════════════════════════════════ */
function initScrollAnimations() {
  const style = document.createElement('style');
  style.textContent = `
    .cdb-fade-up { opacity:0; transform:translateY(30px); transition:opacity .6s ease, transform .6s ease; }
    .cdb-fade-up.visible { opacity:1; transform:translateY(0); }
    .cdb-fade-in { opacity:0; transition:opacity .7s ease; }
    .cdb-fade-in.visible { opacity:1; }
  `;
  document.head.appendChild(style);
  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); obs.unobserve(e.target); } });
  }, { threshold: 0.1 });
  document.querySelectorAll('.cdb-fade-up, .cdb-fade-in').forEach(el => obs.observe(el));
}

/* ══════════════════════════════════════════════════════════════
   BOOT
══════════════════════════════════════════════════════════════ */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else { setTimeout(boot, 50); }

function boot() {
  injectStickyCTA();
  setTimeout(injectExitIntent, 3000);
  initScrollAnimations();
  // Pre-fill domain from session if redirected from exit popup
  const sd = sessionStorage.getItem('cdb_hero_domain');
  if (sd) {
    const inp = document.getElementById('heroScanInput') || document.getElementById('hero-domain-input');
    if (inp) { inp.value = sd; sessionStorage.removeItem('cdb_hero_domain'); }
  }
}

})();

/* ═══════════════════════════════════════════════════════════════
   LIVE INTELLIGENCE STATS — REAL DATA ONLY (no fabrication)
   Shared across all pages via global.js. Populates the risk-block /
   attention-bar stats from the public stats APIs. Metrics with no
   honest data source are HIDDEN, never faked.
   Targets IDs: ae-cve-count, ae-update-time, rb-scans-today,
                rb-cve-active, rb-threats-hour (+ hides ae-scan-live, rb-time-ago)
   ═══════════════════════════════════════════════════════════════ */
(function CDB_LIVE_STATS(){
  function fmt(n){ try { return Number(n).toLocaleString('en-IN'); } catch(_) { return String(n); } }
  function setText(id,val){ var e=document.getElementById(id); if(e&&val!=null) e.textContent=fmt(val); }
  function relabel(id,text){
    var e=document.getElementById(id); if(!e) return;
    var stat=e.closest('.risk-stat-v14'); var lbl=stat&&stat.querySelector('.risk-stat-lbl-v14');
    if(lbl) lbl.textContent=text;
  }
  function hideStat(id,sel){
    var e=document.getElementById(id); if(!e) return;
    var w=sel?e.closest(sel):e; if(w) w.style.display='none';
  }

  async function load(){
    var ti=null, sc=null;
    try { var r=await fetch('/api/threat-intel/stats'); if(r.ok){ var j=await r.json(); ti=(j.data&&j.data.stats)||j.stats||j; } } catch(_){}
    try { var r2=await fetch('/api/scan/stats'); if(r2.ok){ sc=await r2.json(); } } catch(_){}

    if(ti){
      if(ti.total_advisories!=null){ setText('rb-cve-active', ti.total_advisories); relabel('rb-cve-active','CVEs tracked'); }
      if(ti.critical!=null) setText('ae-cve-count', ti.critical);
      // Repurpose the (previously fabricated) "threats this hour" stat to a real,
      // meaningful number: confirmed actively-exploited CVEs in the catalog.
      if(ti.confirmed_exploited!=null){ setText('rb-threats-hour', ti.confirmed_exploited); relabel('rb-threats-hour','Confirmed exploited'); }
      else { hideStat('rb-threats-hour','.risk-stat-v14'); }
    }
    if(sc && sc.total_scans!=null){ setText('rb-scans-today', sc.total_scans); relabel('rb-scans-today','Scans run'); }

    var up=document.getElementById('ae-update-time'); if(up) up.textContent='live';

    // Drop widgets with no honest data source.
    hideStat('ae-scan-live','.attn-item-v14');        // no real concurrent-scan metric
    hideStat('rb-last-cve','.risk-ticker-txt-v14');   // fabricated "last detection … flagged N min ago" line
  }

  load();
  setInterval(load, 60000); // refresh from REAL API; no synthetic mutation
})();
