// ═══════════════════════════════════════════════════════════════
// PAYMENT CONFIG — IMMUTABLE SOURCE OF TRUTH
// CYBERDUDEBIVASH PRIVATE LIMITED | GST: 21ARKPN8270G1ZP
// DO NOT MODIFY — ALL SYSTEMS READ FROM THIS FILE ONLY
// ═══════════════════════════════════════════════════════════════
'use strict';

const PAYMENT_CONFIG = Object.freeze({

  upi: Object.freeze({
    primary:   'iambivash.bn-5@okaxis',
    secondary: '6302177246@axisbank',
    qr_path:   '/assets/payment/upi-qr.png',
    qr_static: true,
    name:      'Bivash Kumar Nayak',
  }),

  bank: Object.freeze({
    account_name:   'BIVASHA KUMAR NAYAK',
    account_number: '915010024617260',
    ifsc:           'UTIB0000052',
    bank_name:      'Axis Bank',
    account_type:   'Savings',
    note:           'Add your email in payment remarks for faster activation',
  }),

  crypto: Object.freeze({
    bnb_smart_chain: '0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796',
    network:         'BNB Smart Chain (BSC)',
    token:           'BNB / USDT (BEP-20)',
    warning:         'Only send BNB or BEP-20 tokens. Other networks will result in permanent loss.',
  }),

  paypal: Object.freeze({
    email: 'iambivash.bn@gmail.com',
    link:  'https://www.paypal.com/paypalme/iambivash',
    note:  'Select Friends & Family to avoid fees. Add product name in note.',
  }),

  business: Object.freeze({
    name:    'CYBERDUDEBIVASH PRIVATE LIMITED',
    gst:     '21ARKPN8270G1ZP',
    email:   'iambivash.bn@gmail.com',
    support: 'iambivash.bn@gmail.com',
    phone:   '+918179881447',
    address: '29, Korai - Sukinda - Ramchandrapur Rd, Ragadi, Odisha 755019, India',
  }),

  sla: Object.freeze({
    activation_hours: '2-4',
    support_hours:    'Mon-Sat 9AM-8PM IST',
    timezone:         'Asia/Kolkata',
  }),
});

export default PAYMENT_CONFIG;
export { PAYMENT_CONFIG };
