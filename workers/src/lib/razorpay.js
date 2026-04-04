/**
 * CYBERDUDEBIVASH AI Security Hub — Razorpay Integration v8.0
 * Handles order creation and payment signature verification
 * Uses only Cloudflare Workers Web Crypto API — no SDK required
 * Circuit breaker + retry via resilience.js
 */

import { resilientFetch } from './resilience.js';

// ─── Module pricing (amount in paise = INR × 100) ────────────────────────────
export const MODULE_PRICES = {
  domain:     { amount: 19900, label: '₹199', name: 'Domain Security Report'   },
  ai:         { amount: 49900, label: '₹499', name: 'AI Security Report'        },
  redteam:    { amount: 99900, label: '₹999', name: 'Red Team Report'           },
  identity:   { amount: 79900, label: '₹799', name: 'Identity Security Report'  },
  compliance: { amount: 49900, label: '₹499', name: 'Compliance Report'         },
};

// ─── Create Razorpay Order ────────────────────────────────────────────────────
export async function createRazorpayOrder(env, { amount, currency = 'INR', receipt, notes = {} }) {
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    throw new Error('Razorpay credentials not configured — set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET secrets');
  }
  const auth = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const resp = await resilientFetch('razorpay', env, 'https://api.razorpay.com/v1/orders', {
    method:  'POST',
    headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify({ amount, currency, receipt, notes }),
  }, 10000);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err?.error?.description || `Razorpay API error ${resp.status}`);
  }
  return resp.json(); // { id, entity, amount, currency, receipt, status, ... }
}

// ─── Verify Payment Signature (frontend-initiated) ────────────────────────────
// Signature = HMAC-SHA256( razorpay_order_id + "|" + razorpay_payment_id , key_secret )
export async function verifyPaymentSignature(env, orderId, paymentId, signature) {
  if (!env.RAZORPAY_KEY_SECRET) return false;
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(env.RAZORPAY_KEY_SECRET),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const computed = hexFromBuf(
      await crypto.subtle.sign('HMAC', key, enc.encode(`${orderId}|${paymentId}`))
    );
    return constantTimeEqual(computed, signature);
  } catch { return false; }
}

// ─── Verify Webhook Signature ─────────────────────────────────────────────────
// Signature = HMAC-SHA256( rawBody , webhook_secret )
export async function verifyWebhookSignature(env, rawBody, razorpaySignature) {
  if (!env.RAZORPAY_WEBHOOK_SECRET) return false;
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(env.RAZORPAY_WEBHOOK_SECRET),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const computed = hexFromBuf(
      await crypto.subtle.sign('HMAC', key, enc.encode(rawBody))
    );
    return constantTimeEqual(computed, razorpaySignature);
  } catch { return false; }
}

// ─── ID / Token Generators ────────────────────────────────────────────────────
export function generateReceiptId() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = hexFromBuf(crypto.getRandomValues(new Uint8Array(4))).toUpperCase();
  return `CBD-${ts}-${rand}`;
}

export function generateAccessToken() {
  // 64-char hex token (256 bits entropy)
  return hexFromBuf(crypto.getRandomValues(new Uint8Array(32)));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function hexFromBuf(buf) {
  return Array.from(new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer ?? buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
