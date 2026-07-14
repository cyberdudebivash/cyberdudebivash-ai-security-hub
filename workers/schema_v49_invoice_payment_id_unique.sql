-- v49 — Enforce one invoice per payment at the database layer.
-- createInvoice() (services/v24/billingEngine.js) already checks for an
-- existing invoice by payment_id before inserting, but that check-then-insert
-- is not atomic: two concurrent calls for the same payment_id (a retried
-- Razorpay webhook, a double-submitted client confirmation) can each read
-- "none exists yet" and each successfully insert their own row with distinct,
-- individually-valid invoice_numbers — a real duplicate invoice, undetected
-- because neither insert violates invoice_number's own UNIQUE constraint.
--
-- This partial unique index closes that gap: a second insert for the same
-- non-empty payment_id now fails at the database layer, which createInvoice()
-- catches and resolves by returning the row that actually won the race.
-- Partial (WHERE payment_id != '') because invoices created without a
-- payment_id (e.g. POST /api/v24/billing/invoice/create with no payment_id)
-- all store '' and must not collide with one another.
CREATE UNIQUE INDEX IF NOT EXISTS idx_invoices_payment_id_unique
  ON invoices(payment_id) WHERE payment_id IS NOT NULL AND payment_id != '';
