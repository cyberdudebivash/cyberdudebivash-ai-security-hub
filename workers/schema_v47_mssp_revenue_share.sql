-- ============================================================================
-- v47 — MSSP Revenue Share (real implementation of the "Revenue Share 60/40"
-- claim advertised on mssp.html). Previously this was a marketing-only number
-- with zero backend support — no payout calculation, no ledger, no tracking.
-- This migration adds:
--   1. payments.partner_id — attributes a payment to the MSSP partner who
--      onboarded the paying customer (looked up via mssp_customers.contact_email
--      at order-creation time).
--   2. mssp_partners.partner_share_pct — real, per-partner configurable split
--      (defaults to 60.0, matching the marketed "60/40" claim; previously the
--      only split-like column was margin_pct, defaulting to 20.0, which
--      contradicted the marketed number and was never used in any calculation).
--   3. mssp_revenue_ledger — immutable, auditable ledger of every revenue
--      split, computed automatically when a payment is captured.
-- ============================================================================

ALTER TABLE payments ADD COLUMN partner_id TEXT;
CREATE INDEX IF NOT EXISTS idx_payments_partner ON payments(partner_id);

ALTER TABLE mssp_partners ADD COLUMN partner_share_pct REAL NOT NULL DEFAULT 60.0;

CREATE TABLE IF NOT EXISTS mssp_revenue_ledger (
  id                    TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  partner_id            TEXT NOT NULL,
  payment_id            TEXT NOT NULL UNIQUE,
  customer_email        TEXT,
  module                TEXT,
  gross_amount_paise    INTEGER NOT NULL,
  partner_share_pct     REAL NOT NULL,
  partner_share_paise   INTEGER NOT NULL,
  platform_share_paise  INTEGER NOT NULL,
  status                TEXT NOT NULL DEFAULT 'accrued' CHECK (status IN ('accrued','paid_out','reversed')),
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  paid_out_at           TEXT,
  FOREIGN KEY (partner_id) REFERENCES mssp_partners(id),
  FOREIGN KEY (payment_id) REFERENCES payments(id)
);
CREATE INDEX IF NOT EXISTS idx_mssp_revenue_ledger_partner ON mssp_revenue_ledger(partner_id);
CREATE INDEX IF NOT EXISTS idx_mssp_revenue_ledger_status  ON mssp_revenue_ledger(status);
