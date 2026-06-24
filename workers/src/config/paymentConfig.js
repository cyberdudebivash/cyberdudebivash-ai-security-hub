// ═══════════════════════════════════════════════════════════════
// PAYMENT CONFIG — IMMUTABLE SOURCE OF TRUTH
// All values are sourced from Cloudflare Worker secrets/vars at request
// time — never hardcode bank/UPI/crypto/personal details in this file.
// Set the required secrets with: npx wrangler secret put <NAME>
// (see wrangler.toml "PAYMENT DISPLAY DETAILS" section for the full list)
// ═══════════════════════════════════════════════════════════════
'use strict';

function getPaymentConfig(env) {
  return Object.freeze({

    upi: Object.freeze({
      primary:   env.UPI_PRIMARY_ID || '',
      secondary: env.UPI_SECONDARY_ID || '',
      qr_path:   '/assets/payment/upi-qr.png',
      qr_static: true,
      name:      env.PAYEE_NAME || '',
    }),

    bank: Object.freeze({
      account_name:   env.BANK_ACCOUNT_NAME || '',
      account_number: env.BANK_ACCOUNT_NUMBER || '',
      ifsc:           env.BANK_IFSC || '',
      bank_name:      env.BANK_NAME || '',
      account_type:   env.BANK_ACCOUNT_TYPE || 'Savings',
      note:           'Add your email in payment remarks for faster activation',
    }),

    crypto: Object.freeze({
      bnb_smart_chain: env.CRYPTO_BNB_ADDRESS || '',
      network:         'BNB Smart Chain (BSC)',
      token:           'BNB / USDT (BEP-20)',
      warning:         'Only send BNB or BEP-20 tokens. Other networks will result in permanent loss.',
    }),

    paypal: Object.freeze({
      email: env.PAYPAL_EMAIL || '',
      link:  env.PAYPAL_ME_LINK || '',
      note:  'Select Friends & Family to avoid fees. Add product name in note.',
    }),

    business: Object.freeze({
      name:    env.BUSINESS_NAME || 'CYBERDUDEBIVASH PRIVATE LIMITED',
      gst:     env.BUSINESS_GST || '',
      email:   env.BUSINESS_EMAIL || '',
      support: env.BUSINESS_SUPPORT_EMAIL || env.BUSINESS_EMAIL || '',
      phone:   env.BUSINESS_PHONE || '',
      address: env.BUSINESS_ADDRESS || '',
    }),

    sla: Object.freeze({
      activation_hours: '2-4',
      support_hours:    'Mon-Sat 9AM-8PM IST',
      timezone:         'Asia/Kolkata',
    }),
  });
}

export { getPaymentConfig };
