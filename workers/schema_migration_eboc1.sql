-- EBOC-1: create tables referenced by live code that were never applied to production D1.
-- Both `refunds` and `support_tickets` INSERTs were wrapped in .catch(()=>{}) / try{}catch{},
-- silently swallowing every write because the tables did not exist. Customers saw
-- "submitted" / "Refund request submitted" confirmations that recorded nothing.

CREATE TABLE IF NOT EXISTS refunds (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  payment_id      TEXT NOT NULL,
  invoice_id      TEXT,
  user_id         TEXT,
  email           TEXT,
  amount_inr      INTEGER NOT NULL DEFAULT 0,
  reason          TEXT DEFAULT 'customer_request' CHECK(reason IN ('customer_request','duplicate','fraud','service_failure','other')),
  reason_detail   TEXT,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','failed','rejected')),
  razorpay_refund_id TEXT,
  stripe_refund_id TEXT,
  initiated_by    TEXT DEFAULT 'customer',
  processed_at    TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id          TEXT PRIMARY KEY,
  user_id     TEXT,
  tier        TEXT,
  subject     TEXT NOT NULL,
  description TEXT,
  category    TEXT DEFAULT 'general',
  priority    TEXT DEFAULT 'normal',
  status      TEXT NOT NULL DEFAULT 'open',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_refunds_status ON refunds(status);
CREATE INDEX IF NOT EXISTS idx_refunds_user ON refunds(user_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_user ON support_tickets(user_id);
