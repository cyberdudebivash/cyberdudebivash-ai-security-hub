/**
 * CYBERDUDEBIVASH AI Security Hub
 * payment-modal.js — Global Manual Payment System v21.0
 *
 * Self-contained: injects CSS + HTML into any page.
 * Exposes: window.CDB_PAYMENT.open(opts)
 *
 * Payment methods: UPI · Bank Transfer (NEFT/IMPS/RTGS) · PayPal · Crypto (BEP20/ERC20)
 * Account: Bivash Kumar Nayak · iambivash.bn-5@okaxis · UTIB0000052
 *
 * Usage on any page:
 *   <script src="/assets/payment-modal.js"></script>
 *   <button onclick="CDB_PAYMENT.open({productLabel:'Pro Plan',amountLabel:'₹1,499'})">Buy</button>
 */
(function () {
  'use strict';

  // Guard — skip if already injected (e.g. index.html has it inline)
  if (window.__CDB_PAYMENT_LOADED__) return;
  window.__CDB_PAYMENT_LOADED__ = true;

  // ── Payment Details — live production ──────────────────────────────────────
  var PAY = {
    upi:    [
      { label: 'Axis (Primary)', id: 'iambivash.bn-5@okaxis' },
      { label: 'Axis Bank',      id: '6302177246@axisbank'   },
    ],
    bank: {
      name:   'Bivash Kumar Nayak',
      acc:    '915010024617260',
      ifsc:   'UTIB0000052',
      bank:   'Axis Bank',
      type:   'Savings Account',
    },
    paypal: {
      email: 'iambivash.bn@gmail.com',
      url:   'https://www.paypal.com/paypalme/iambivash',
    },
    crypto: {
      addr:  '0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796',
      nets:  'BNB Smart Chain (BEP20) / Ethereum (ERC20)',
    },
    email:    'bivash@cyberdudebivash.com',
    whatsapp: '+918179881447',
    tel:      'tel:+918179881447',
    submit_api: '/api/payments/submit',
  };

  // ── Inject CSS ─────────────────────────────────────────────────────────────
  var css = [
    '#cdbpm-overlay{position:fixed;inset:0;z-index:2147483640;background:rgba(0,0,0,.86);',
    'backdrop-filter:blur(7px);display:none;align-items:center;justify-content:center;padding:16px;',
    'box-sizing:border-box}',
    '#cdbpm-overlay.cdbpm-open{display:flex}',
    '#cdbpm-box{background:#0d0d1f;border:1px solid rgba(0,212,255,.28);border-radius:20px;',
    'max-width:530px;width:100%;max-height:93vh;overflow-y:auto;position:relative;',
    'box-shadow:0 28px 90px rgba(0,0,0,.75);font-family:-apple-system,BlinkMacSystemFont,',
    '"Segoe UI",Roboto,Arial,sans-serif;color:#fff}',
    '#cdbpm-box *{box-sizing:border-box}',
    '.cdbpm-header{background:linear-gradient(135deg,rgba(0,212,255,.12),rgba(124,58,237,.09));',
    'border-bottom:1px solid rgba(255,255,255,.07);padding:22px 24px 18px;border-radius:20px 20px 0 0;',
    'position:relative}',
    '.cdbpm-close{position:absolute;top:14px;right:16px;background:rgba(255,255,255,.08);',
    'border:none;color:rgba(255,255,255,.6);width:32px;height:32px;border-radius:50%;',
    'cursor:pointer;font-size:18px;line-height:1;transition:background .2s}',
    '.cdbpm-close:hover{background:rgba(255,255,255,.15)}',
    '.cdbpm-badge{font-size:10px;font-weight:800;color:#00d4ff;text-transform:uppercase;',
    'letter-spacing:.12em;margin-bottom:6px}',
    '.cdbpm-title{font-size:16px;font-weight:900;color:#fff;line-height:1.3;',
    'padding-right:36px;word-break:break-word}',
    '.cdbpm-amount{font-size:13px;color:rgba(255,255,255,.5);margin-top:5px}',
    '.cdbpm-body{padding:22px 24px 26px}',
    '.cdbpm-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}',
    '.cdbpm-tab{flex:1;min-width:76px;background:rgba(255,255,255,.04);',
    'border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.55);padding:9px 5px;',
    'border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;text-align:center;',
    'transition:all .2s;letter-spacing:.25px}',
    '.cdbpm-tab.active,.cdbpm-tab:hover{background:rgba(0,212,255,.12);',
    'border-color:rgba(0,212,255,.4);color:#00d4ff}',
    '.cdbpm-pane{display:none}.cdbpm-pane.active{display:block}',
    '.cdbpm-sec{font-size:10px;font-weight:800;color:rgba(255,255,255,.38);',
    'text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px}',
    '.cdbpm-field{display:flex;align-items:center;justify-content:space-between;gap:10px;',
    'background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);',
    'border-radius:8px;padding:10px 14px;margin-bottom:8px}',
    '.cdbpm-flabel{font-size:10px;color:rgba(255,255,255,.38);margin-bottom:2px;',
    'text-transform:uppercase;letter-spacing:.5px}',
    '.cdbpm-fval{font-family:monospace;font-size:12px;color:#e2e8f0;word-break:break-all}',
    '.cdbpm-copy{background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.25);',
    'color:#00d4ff;padding:5px 12px;border-radius:6px;font-size:11px;font-weight:700;',
    'cursor:pointer;white-space:nowrap;transition:all .2s;flex-shrink:0}',
    '.cdbpm-copy:hover{background:rgba(0,212,255,.22)}',
    '.cdbpm-btn{display:block;text-align:center;border-radius:8px;padding:10px 14px;',
    'font-size:13px;font-weight:700;text-decoration:none;margin-top:10px;',
    'transition:opacity .2s;cursor:pointer;border:none;width:100%}',
    '.cdbpm-btn-upi{background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.25);',
    'color:#00d4ff}',
    '.cdbpm-btn-pp{background:rgba(0,112,243,.12);border:1px solid rgba(0,112,243,.3);',
    'color:#60a5fa}',
    '.cdbpm-hint{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);',
    'border-radius:8px;padding:10px 14px;font-size:11px;color:rgba(255,255,255,.42);',
    'line-height:1.6;margin-top:8px}',
    '.cdbpm-divider{border-top:1px solid rgba(255,255,255,.07);margin:20px 0 16px}',
    '.cdbpm-subtitle{font-size:11px;font-weight:800;color:rgba(255,255,255,.5);',
    'text-align:center;letter-spacing:.5px;margin-bottom:14px}',
    '.cdbpm-input{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);',
    'border-radius:8px;padding:11px 14px;color:#fff;font-size:13px;outline:none;',
    'transition:border-color .2s;font-family:inherit}',
    '.cdbpm-input:focus{border-color:rgba(0,212,255,.5)}',
    '.cdbpm-submit{width:100%;background:linear-gradient(135deg,#00d4ff,#0099cc);border:none;',
    'color:#000;padding:14px;border-radius:10px;font-weight:900;font-size:15px;cursor:pointer;',
    'margin-top:6px;transition:opacity .2s;letter-spacing:.3px;font-family:inherit}',
    '.cdbpm-submit:hover:not(:disabled){opacity:.88}',
    '.cdbpm-submit:disabled{opacity:.55;cursor:not-allowed}',
    '.cdbpm-status{min-height:20px;font-size:12px;text-align:center;margin-top:10px}',
    '.cdbpm-err{color:#fca5a5;padding:8px 12px;background:rgba(239,68,68,.1);',
    'border-radius:6px;margin-top:8px}',
    '.cdbpm-ok{color:#86efac;background:rgba(34,197,94,.08);border-radius:6px;padding:8px 12px}',
    '.cdbpm-footer{text-align:center;margin-top:14px;font-size:11px;',
    'color:rgba(255,255,255,.22);line-height:1.8}',
    '.cdbpm-footer a{color:rgba(0,212,255,.5);text-decoration:none}',
    '.cdbpm-qr{display:block;max-width:150px;border-radius:10px;border:2px solid rgba(255,255,255,.1);',
    'margin:0 auto 6px}',
    '.cdbpm-warn{background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.18);',
    'border-radius:8px;padding:10px 14px;font-size:11px;color:rgba(255,255,255,.45);',
    'line-height:1.6;margin-top:8px}',
    '@media(max-width:480px){#cdbpm-box{border-radius:14px;max-height:97vh}',
    '.cdbpm-header,.cdbpm-body{padding:16px 16px 20px}}',
  ].join('');

  var styleEl = document.createElement('style');
  styleEl.id = 'cdbpm-styles';
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  // ── Inject HTML ─────────────────────────────────────────────────────────────
  var html = '<div id="cdbpm-overlay" role="dialog" aria-modal="true" aria-label="Secure Payment Checkout">' +
  '<div id="cdbpm-box">' +
  // Header
  '<div class="cdbpm-header">' +
    '<button class="cdbpm-close" onclick="CDB_PAYMENT.close()" aria-label="Close">&#x2715;</button>' +
    '<div class="cdbpm-badge">&#x1F512; SECURE MANUAL PAYMENT</div>' +
    '<div class="cdbpm-title" id="cdbpm-title">Selected Product</div>' +
    '<div class="cdbpm-amount" id="cdbpm-amount"></div>' +
  '</div>' +
  // Body
  '<div class="cdbpm-body">' +
    // How it works
    '<div class="cdbpm-hint" style="margin-bottom:18px;background:rgba(0,212,255,.04);border-color:rgba(0,212,255,.15)">' +
      '<strong style="color:#00d4ff">How it works:</strong> Pick a method &rarr; Transfer the exact amount &rarr; Click ' +
      '<strong style="color:#22c55e">&#x2705; I HAVE PAID</strong> &rarr; Enter your Transaction ID. Access activated within <strong style="color:#fff">2&ndash;4 hours</strong>.' +
    '</div>' +
    // Tabs
    '<div class="cdbpm-tabs">' +
      '<button class="cdbpm-tab active" id="cdbpm-tab-upi"    onclick="CDB_PAYMENT.switchTab(\'upi\')">&#x1F4F1; UPI</button>' +
      '<button class="cdbpm-tab"        id="cdbpm-tab-bank"   onclick="CDB_PAYMENT.switchTab(\'bank\')">&#x1F3E6; Bank</button>' +
      '<button class="cdbpm-tab"        id="cdbpm-tab-paypal" onclick="CDB_PAYMENT.switchTab(\'paypal\')">&#x1F30E; PayPal</button>' +
      '<button class="cdbpm-tab"        id="cdbpm-tab-crypto" onclick="CDB_PAYMENT.switchTab(\'crypto\')">&#x20BF; Crypto</button>' +
    '</div>' +

    // UPI Pane
    '<div class="cdbpm-pane active" id="cdbpm-pane-upi">' +
      '<div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">' +
        '<div style="flex:1;min-width:180px">' +
          '<div class="cdbpm-sec">UPI IDs &mdash; Send to any</div>' +
          '<div class="cdbpm-field">' +
            '<div><div class="cdbpm-flabel">Axis (Primary)</div><div class="cdbpm-fval">iambivash.bn-5@okaxis</div></div>' +
            '<button class="cdbpm-copy" id="cdbpm-cu1" onclick="CDB_PAYMENT.copy(\'iambivash.bn-5@okaxis\',\'cdbpm-cu1\')">Copy</button>' +
          '</div>' +
          '<div class="cdbpm-field">' +
            '<div><div class="cdbpm-flabel">Axis Bank</div><div class="cdbpm-fval">6302177246@axisbank</div></div>' +
            '<button class="cdbpm-copy" id="cdbpm-cu2" onclick="CDB_PAYMENT.copy(\'6302177246@axisbank\',\'cdbpm-cu2\')">Copy</button>' +
          '</div>' +
          '<a id="cdbpm-upi-link" href="upi://pay?pa=iambivash.bn-5@okaxis&pn=CYBERDUDEBIVASH&cu=INR" ' +
            'onclick="CDB_PAYMENT._patchUPILink(this)" class="cdbpm-btn cdbpm-btn-upi">&#x1F4F1; Open UPI App Directly &rarr;</a>' +
        '</div>' +
        '<div style="text-align:center;flex-shrink:0;min-width:130px">' +
          '<div class="cdbpm-sec" style="text-align:center">Scan QR Code</div>' +
          '<img src="/assets/payment/upi-qr.png" alt="UPI QR — Bivash Kumar Nayak" class="cdbpm-qr"' +
            ' onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'block\'">' +
          '<div style="display:none;font-size:11px;color:rgba(255,255,255,.35);padding:10px;' +
            'background:rgba(255,255,255,.03);border-radius:8px;border:1px dashed rgba(255,255,255,.08)">' +
            'UPI: iambivash.bn-5@okaxis' +
          '</div>' +
          '<div style="font-size:10px;color:rgba(255,255,255,.3);margin-top:6px">Bivash Kumar Nayak</div>' +
          '<div style="font-size:10px;color:rgba(255,255,255,.2);margin-top:2px">PhonePe &middot; GPay &middot; Paytm</div>' +
        '</div>' +
      '</div>' +
    '</div>' +

    // Bank Pane
    '<div class="cdbpm-pane" id="cdbpm-pane-bank">' +
      '<div class="cdbpm-sec">Bank Transfer &mdash; NEFT / IMPS / RTGS</div>' +
      '<div class="cdbpm-field">' +
        '<div><div class="cdbpm-flabel">Account Name</div><div class="cdbpm-fval">Bivash Kumar Nayak</div></div>' +
        '<button class="cdbpm-copy" id="cdbpm-cb1" onclick="CDB_PAYMENT.copy(\'Bivash Kumar Nayak\',\'cdbpm-cb1\')">Copy</button>' +
      '</div>' +
      '<div class="cdbpm-field">' +
        '<div><div class="cdbpm-flabel">Account Number</div><div class="cdbpm-fval" style="font-size:15px;font-weight:700;letter-spacing:1px">915010024617260</div></div>' +
        '<button class="cdbpm-copy" id="cdbpm-cb2" onclick="CDB_PAYMENT.copy(\'915010024617260\',\'cdbpm-cb2\')">Copy</button>' +
      '</div>' +
      '<div class="cdbpm-field">' +
        '<div><div class="cdbpm-flabel">IFSC Code</div><div class="cdbpm-fval" style="font-size:14px;font-weight:700">UTIB0000052</div></div>' +
        '<button class="cdbpm-copy" id="cdbpm-cb3" onclick="CDB_PAYMENT.copy(\'UTIB0000052\',\'cdbpm-cb3\')">Copy</button>' +
      '</div>' +
      '<div class="cdbpm-field" style="border:none;background:none;padding:4px 0">' +
        '<div><div class="cdbpm-flabel">Bank</div><div class="cdbpm-fval">Axis Bank &middot; Savings Account</div></div>' +
      '</div>' +
      '<div class="cdbpm-hint">&#x1F4A1; IMPS = instant 24&#x00D7;7 &middot; NEFT = 2&ndash;4 hrs on banking days &middot; Add your email in payment remarks for faster activation.</div>' +
    '</div>' +

    // PayPal Pane
    '<div class="cdbpm-pane" id="cdbpm-pane-paypal">' +
      '<div class="cdbpm-sec">PayPal Transfer</div>' +
      '<div class="cdbpm-field">' +
        '<div><div class="cdbpm-flabel">PayPal Email</div><div class="cdbpm-fval">iambivash.bn@gmail.com</div></div>' +
        '<button class="cdbpm-copy" id="cdbpm-cpp" onclick="CDB_PAYMENT.copy(\'iambivash.bn@gmail.com\',\'cdbpm-cpp\')">Copy</button>' +
      '</div>' +
      '<a href="https://www.paypal.com/paypalme/iambivash" target="_blank" rel="noopener" class="cdbpm-btn cdbpm-btn-pp">&#x1F30E; Open PayPal.me &rarr; Send Directly</a>' +
      '<div class="cdbpm-hint">&#x26A0;&#xFE0F; Select <strong style="color:rgba(255,255,255,.7)">"Friends &amp; Family"</strong> to avoid fees. Add product name + your email in the note for faster activation.</div>' +
    '</div>' +

    // Crypto Pane
    '<div class="cdbpm-pane" id="cdbpm-pane-crypto">' +
      '<div class="cdbpm-sec">Crypto Transfer &mdash; BEP20 / ERC20</div>' +
      '<div class="cdbpm-field">' +
        '<div><div class="cdbpm-flabel">BNB Smart Chain (BEP20) &middot; Ethereum (ERC20)</div>' +
          '<div class="cdbpm-fval" style="font-size:11px">0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796</div>' +
        '</div>' +
        '<button class="cdbpm-copy" id="cdbpm-ccr" onclick="CDB_PAYMENT.copy(\'0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796\',\'cdbpm-ccr\')">Copy</button>' +
      '</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px">' +
        '<div style="background:rgba(240,185,11,.07);border:1px solid rgba(240,185,11,.2);border-radius:8px;padding:10px;text-align:center;font-size:11px;color:rgba(255,255,255,.6)">&#x2705; BNB Smart Chain<br><span style="color:#f0b90b;font-weight:800;font-size:12px">BEP20</span></div>' +
        '<div style="background:rgba(98,126,234,.07);border:1px solid rgba(98,126,234,.2);border-radius:8px;padding:10px;text-align:center;font-size:11px;color:rgba(255,255,255,.6)">&#x2705; Ethereum Mainnet<br><span style="color:#627eea;font-weight:800;font-size:12px">ERC20</span></div>' +
      '</div>' +
      '<div class="cdbpm-warn">&#x26A0;&#xFE0F; Send <strong style="color:rgba(255,255,255,.75)">ONLY on BNB Smart Chain or Ethereum</strong>. Wrong network = permanently lost funds. After sending, your <strong style="color:rgba(255,255,255,.75)">TX Hash</strong> is the Transaction ID.</div>' +
    '</div>' +

    // Divider + confirmation form
    '<div class="cdbpm-divider"></div>' +
    '<div class="cdbpm-subtitle">&#x2193; AFTER PAYING &mdash; SUBMIT YOUR CONFIRMATION BELOW &#x2193;</div>' +
    '<div style="display:flex;flex-direction:column;gap:10px">' +
      '<select id="cdbpm-method" class="cdbpm-input" style="appearance:auto;cursor:pointer;color:rgba(255,255,255,.85)">' +
        '<option value="UPI">&#x1F4F1; UPI Transfer</option>' +
        '<option value="BANK">&#x1F3E6; Bank Transfer (NEFT / IMPS / RTGS)</option>' +
        '<option value="PAYPAL">&#x1F30E; PayPal</option>' +
        '<option value="CRYPTO_BNB">&#x20BF; Crypto &mdash; BNB (BEP20)</option>' +
        '<option value="CRYPTO_ETH">&#x20BF; Crypto &mdash; ETH (ERC20)</option>' +
      '</select>' +
      '<input id="cdbpm-txn"   class="cdbpm-input" type="text"  autocomplete="off" spellcheck="false" placeholder="Transaction ID / UTR Number / TX Hash *">' +
      '<input id="cdbpm-email" class="cdbpm-input" type="email" autocomplete="email" placeholder="Your email — for confirmation &amp; access activation *">' +
      '<input id="cdbpm-name"  class="cdbpm-input" type="text"  autocomplete="name"  placeholder="Your name (optional)">' +
    '</div>' +
    '<div class="cdbpm-status" id="cdbpm-status"></div>' +
    '<button class="cdbpm-submit" id="cdbpm-submit" onclick="CDB_PAYMENT.submit()">&#x2705; I HAVE PAID &mdash; Submit Confirmation</button>' +
    '<div class="cdbpm-footer">' +
      '&#x1F512; Verified manually by our team &middot; Access activated within 2&ndash;4 hours<br>' +
      'Questions? <a href="mailto:bivash@cyberdudebivash.com">bivash@cyberdudebivash.com</a>' +
      ' &nbsp;|&nbsp; <a href="tel:+918179881447">+91 8179881447</a>' +
    '</div>' +
  '</div>' + // .cdbpm-body
  '</div>' + // #cdbpm-box
  '</div>';  // #cdbpm-overlay

  var wrapper = document.createElement('div');
  wrapper.innerHTML = html;
  document.body.appendChild(wrapper.firstChild);

  // ── CDB_PAYMENT API ────────────────────────────────────────────────────────
  window.CDB_PAYMENT = {
    _cur: {},

    open: function (opts) {
      this._cur = opts || {};
      var overlay = document.getElementById('cdbpm-overlay');
      if (!overlay) return;

      var titleEl  = document.getElementById('cdbpm-title');
      var amountEl = document.getElementById('cdbpm-amount');
      if (titleEl)  titleEl.textContent  = opts.productLabel || opts.product || 'Selected Product';
      if (amountEl) amountEl.textContent = opts.amountLabel  ? 'Amount: ' + opts.amountLabel : (opts.amount ? 'Amount: ' + opts.amount : '');

      // Pre-fill email
      var emailEl = document.getElementById('cdbpm-email');
      if (emailEl && opts.email) emailEl.value = opts.email;

      // Reset form
      var txnEl = document.getElementById('cdbpm-txn');
      if (txnEl) txnEl.value = '';
      var statusEl = document.getElementById('cdbpm-status');
      if (statusEl) { statusEl.textContent = ''; statusEl.className = 'cdbpm-status'; }
      var btn = document.getElementById('cdbpm-submit');
      if (btn) { btn.disabled = false; btn.textContent = '✅ I HAVE PAID — Submit Confirmation'; }

      this.switchTab('upi');
      overlay.classList.add('cdbpm-open');
      document.body.style.overflow = 'hidden';
    },

    close: function () {
      var overlay = document.getElementById('cdbpm-overlay');
      if (overlay) overlay.classList.remove('cdbpm-open');
      document.body.style.overflow = '';
    },

    switchTab: function (tab) {
      ['upi', 'bank', 'paypal', 'crypto'].forEach(function (t) {
        var tabEl  = document.getElementById('cdbpm-tab-' + t);
        var paneEl = document.getElementById('cdbpm-pane-' + t);
        if (tabEl)  tabEl.classList.toggle('active',  t === tab);
        if (paneEl) paneEl.classList.toggle('active', t === tab);
      });
      // Sync payment method dropdown
      var methodEl = document.getElementById('cdbpm-method');
      if (methodEl) {
        var map = { upi: 'UPI', bank: 'BANK', paypal: 'PAYPAL', crypto: 'CRYPTO_BNB' };
        methodEl.value = map[tab] || 'UPI';
      }
    },

    copy: function (text, btnId) {
      var btn = document.getElementById(btnId);
      if (!btn) return;
      try {
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1800);
        });
      } catch (e) {
        // Fallback
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch (e2) {}
        document.body.removeChild(ta);
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = 'Copy'; }, 1800);
      }
    },

    _patchUPILink: function (el) {
      var cur = this._cur;
      var raw = cur.amount || (cur.amountLabel ? cur.amountLabel.replace(/[^0-9.]/g, '') : '');
      var base = 'upi://pay?pa=iambivash.bn-5@okaxis&pn=CYBERDUDEBIVASH&cu=INR';
      el.href = raw ? base + '&am=' + encodeURIComponent(raw) : base;
    },

    submit: function () {
      var txn    = (document.getElementById('cdbpm-txn')?.value    || '').trim();
      var email  = (document.getElementById('cdbpm-email')?.value  || '').trim();
      var name   = (document.getElementById('cdbpm-name')?.value   || '').trim();
      var method = (document.getElementById('cdbpm-method')?.value || 'UPI').trim();
      var statusEl = document.getElementById('cdbpm-status');
      var btn      = document.getElementById('cdbpm-submit');

      function setErr(msg) {
        if (statusEl) { statusEl.innerHTML = '<div class="cdbpm-err">' + msg + '</div>'; }
      }
      function setOk(msg) {
        if (statusEl) { statusEl.innerHTML = '<div class="cdbpm-ok">' + msg + '</div>'; }
      }

      if (!txn) { setErr('&#x26A0;&#xFE0F; Transaction ID / UTR Number is required'); return; }
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        setErr('&#x26A0;&#xFE0F; Valid email required — we send your access confirmation here');
        return;
      }

      if (btn) { btn.disabled = true; btn.textContent = '&#x23F3; Submitting...'; }

      var payload = {
        product_id:     this._cur.product || 'general',
        amount_inr:     this._cur.amount  ? this._cur.amount.replace(/[^0-9.]/g, '') : '0',
        payment_method: method.toLowerCase().replace('_bnb','').replace('_eth',''),
        transaction_id: txn,
        payer_email:    email,
        payer_name:     name,
        notes:          'Product: ' + (this._cur.productLabel || this._cur.product || 'general'),
      };

      var self = this;
      fetch('/api/payments/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.success) {
            var body = document.getElementById('cdbpm-box');
            if (body) {
              body.innerHTML =
                '<div style="padding:48px 28px;text-align:center">' +
                  '<div style="font-size:56px;margin-bottom:20px">&#x2705;</div>' +
                  '<div style="font-size:22px;font-weight:900;color:#22c55e;margin-bottom:12px">Payment Submitted!</div>' +
                  '<div style="font-size:14px;color:rgba(255,255,255,.55);line-height:1.8;max-width:340px;margin:0 auto">' +
                    'We received your confirmation.<br>Access will be activated within <strong style="color:#fff">2&ndash;4 hours</strong>.<br>' +
                    'Check your email <strong style="color:#00d4ff">' + email + '</strong> for the access details.' +
                  '</div>' +
                  '<div style="margin-top:12px;font-size:12px;color:rgba(255,255,255,.3)">Ref: ' + (d.data?.payment_id || txn) + '</div>' +
                  '<button onclick="CDB_PAYMENT.close()" style="margin-top:28px;background:rgba(0,212,255,.15);' +
                    'border:1px solid rgba(0,212,255,.35);color:#00d4ff;padding:12px 32px;border-radius:10px;' +
                    'font-weight:800;cursor:pointer;font-size:14px">Close</button>' +
                  '<div style="margin-top:16px;font-size:11px;color:rgba(255,255,255,.25)">' +
                    'Questions? <a href="mailto:bivash@cyberdudebivash.com" style="color:rgba(0,212,255,.5)">bivash@cyberdudebivash.com</a>' +
                  '</div>' +
                '</div>';
            }
            if (typeof self._cur.onSuccess === 'function') self._cur.onSuccess(d);
          } else {
            var msg = d.error || 'Submission failed. Please try again or contact support.';
            setErr('&#x26A0;&#xFE0F; ' + msg);
            if (btn) { btn.disabled = false; btn.textContent = '✅ I HAVE PAID — Submit Confirmation'; }
          }
        })
        .catch(function () {
          setErr('&#x26A0;&#xFE0F; Network error. Please WhatsApp <a href="tel:+918179881447" style="color:#00d4ff">+91 8179881447</a> with your Transaction ID and we\'ll activate manually.');
          if (btn) { btn.disabled = false; btn.textContent = '✅ I HAVE PAID — Submit Confirmation'; }
        });
    },
  };

  // ── Close on backdrop click ─────────────────────────────────────────────────
  var overlay = document.getElementById('cdbpm-overlay');
  if (overlay) {
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) CDB_PAYMENT.close();
    });
  }

  // ── Escape key to close ────────────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') CDB_PAYMENT.close();
  });

  // ── Global aliases for backward compat + other pages ──────────────────────
  window.openPaymentModal = function (module, target) {
    var prices = { domain: '₹199', ai: '₹499', redteam: '₹999', identity: '₹799', compliance: '₹499' };
    CDB_PAYMENT.open({
      product:      'scan-' + (module || 'report'),
      productLabel: (module ? module.toUpperCase() + ' Security Report' : 'Security Report') + (target ? ' — ' + target : ''),
      amountLabel:  prices[module] || '₹199',
    });
  };

  window.openPaymentCheckout = function (label, amount) {
    CDB_PAYMENT.open({ productLabel: label || 'Product', amountLabel: amount || '' });
  };

  // Razorpay compat shim — any stray Razorpay() call routes here
  if (!window.Razorpay) {
    window.Razorpay = function (opts) {
      return {
        open: function () {
          CDB_PAYMENT.open({
            productLabel: (opts && opts.name) || 'Purchase',
            amountLabel:  (opts && opts.amount) ? '₹' + Math.round(opts.amount / 100) : '',
          });
        },
      };
    };
  }

})();
