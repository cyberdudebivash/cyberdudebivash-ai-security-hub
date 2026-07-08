-- ═══════════════════════════════════════════════════════════════════════════
-- CYBERDUDEBIVASH AI Security Hub — Enterprise Discount Coupon System v2.0
-- Migration: Append-only. DO NOT modify any existing tables.
--
-- Tracks the tables self-bootstrapped at runtime by workers/src/lib/coupons.js
-- (ensureCouponTables via CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN,
-- each independently idempotent). This file exists purely so
-- scripts/lab-bootstrap-d1.mjs's historical replay documents the same shape
-- in workers/schema_bootstrap.sql for the nightly D1 Schema Drift Check —
-- coupons.js remains the source of truth for the live schema.
--
-- New tables:
--   discount_coupons    — coupon definitions (admin-managed)
--   coupon_redemptions  — one row per order a coupon was applied to
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS discount_coupons (
  code                 TEXT PRIMARY KEY,
  discount_pct         INTEGER NOT NULL DEFAULT 0,
  applies_to           TEXT NOT NULL DEFAULT 'all',
  max_redemptions      INTEGER,
  redeemed_count       INTEGER NOT NULL DEFAULT 0,
  expires_at           TEXT,
  active               INTEGER NOT NULL DEFAULT 1,
  created_by           TEXT,
  created_at           TEXT DEFAULT (datetime('now')),
  description          TEXT,
  discount_type        TEXT NOT NULL DEFAULT 'percentage',
  discount_value       INTEGER,
  currency             TEXT NOT NULL DEFAULT 'INR',
  applicable_plans     TEXT,
  applicable_products  TEXT,
  applicable_apis      TEXT,
  enterprise_only      INTEGER NOT NULL DEFAULT 0,
  first_purchase_only  INTEGER NOT NULL DEFAULT 0,
  max_uses_per_user    INTEGER,
  start_date           TEXT,
  stackable            INTEGER NOT NULL DEFAULT 0,
  minimum_purchase     INTEGER,
  metadata             TEXT NOT NULL DEFAULT '{}',
  updated_at           TEXT
);

CREATE TABLE IF NOT EXISTS coupon_redemptions (
  razorpay_order_id  TEXT PRIMARY KEY,
  code               TEXT NOT NULL,
  module             TEXT,
  original_amount    INTEGER NOT NULL,
  discounted_amount  INTEGER NOT NULL,
  status             TEXT NOT NULL DEFAULT 'pending',
  created_at         TEXT DEFAULT (datetime('now')),
  email              TEXT,
  user_id            TEXT,
  revoked            INTEGER NOT NULL DEFAULT 0,
  revoked_at         TEXT,
  revoked_reason     TEXT
);
