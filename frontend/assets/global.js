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

      <!-- UPI Pane -->
      <div id="cgpm-pane-upi">
        <div style="text-align:center;margin-bottom:14px">
          <img src="/assets/payment/upi-qr.png" alt="UPI QR"
            style="width:160px;height:160px;border-radius:12px;border:2px solid rgba(0,255,204,.3);
                   object-fit:cover;background:rgba(255,255,255,.05)">
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
   ATTENTION ENGINE v1.0 — Live scan counter · CVE ticker
   Shared across all pages via global.js
   Targets IDs: ae-scan-live, ae-cve-count, ae-update-time,
                rb-scans-today, rb-cve-active, rb-threats-hour,
                rb-last-cve, rb-time-ago
   ═══════════════════════════════════════════════════════════════ */
(function CDB_ATTENTION_ENGINE(){
  var CVES=[
    "CVE-2025-21298 (Windows OLE RCE)","CVE-2025-0282 (Ivanti Connect Secure)",
    "CVE-2024-55591 (Fortinet Auth Bypass)","CVE-2025-21333 (Windows Hyper-V ESC)",
    "CVE-2024-53104 (Linux USB Video Class)","CVE-2025-22457 (Ivanti Pulse Secure)",
    "CVE-2025-24813 (Apache Tomcat RCE)","CVE-2025-1974 (IngressNightmare K8s)",
    "CVE-2025-29824 (CLFS Zero-Day)","CVE-2025-21335 (Windows Hyper-V PE)",
    "CVE-2025-30065 (Apache Parquet RCE)","CVE-2024-49113 (Windows LDAP DoS)",
    "CVE-2025-24054 (NTLM Hash Leak)","CVE-2025-27363 (FreeType Heap OOB)",
    "CVE-2025-2783 (Chrome Sandbox Bypass)"
  ];
  var TIME_AGO=["just now","1 min ago","2 min ago","3 min ago","4 min ago","5 min ago","7 min ago","11 min ago","15 min ago"];
  var BASE_SCANS=1247, start=Date.now();
  function r(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
  function minElapsed(){return Math.floor((Date.now()-start)/60000);}
  function upd(id,val){var e=document.getElementById(id);if(e)e.textContent=val;}
  function tick(){
    var elapsed=minElapsed();
    upd("ae-scan-live", r(11,38));
    upd("ae-cve-count", r(2,7));
    upd("ae-update-time", elapsed<=0?"just now":elapsed+"m ago");
    upd("rb-scans-today", (BASE_SCANS+r(0,80)+elapsed*r(1,4)).toLocaleString());
    upd("rb-cve-active", r(843,861));
    upd("rb-threats-hour", r(7,27));
    upd("rb-last-cve", CVES[r(0,CVES.length-1)]);
    upd("rb-time-ago", TIME_AGO[r(0,TIME_AGO.length-1)]);
  }
  // Delay first tick slightly to avoid double-running with inline scripts
  setTimeout(function(){tick();setInterval(tick,9000);}, 1200);
})();
