-- ============================================================
-- v45 — users.tier CHECK constraint only allowed FREE/PRO/ENTERPRISE.
-- A customer paying for STARTER (Rs.499/mo) or MSSP (Rs.9,999/mo) completed
-- a real Razorpay charge but the verify handler could never persist their
-- purchased tier — paid customers would be locked out of the feature they
-- just bought. Rebuild users with the full tier set; no data loss, no
-- column/index changes otherwise.
-- ============================================================

PRAGMA foreign_keys = OFF;

ALTER TABLE users RENAME TO users_v44_backup;

CREATE TABLE users (
  id              TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email           TEXT    NOT NULL UNIQUE,
  -- live data has 2 passwordless/magic-link accounts with NULL hash/salt —
  -- the original schema declared these NOT NULL but production drifted;
  -- match reality instead of forcing fabricated values into real accounts.
  password_hash   TEXT,
  password_salt   TEXT,
  tier            TEXT    NOT NULL DEFAULT 'FREE' CHECK (tier IN ('FREE','STARTER','PRO','ENTERPRISE','MSSP')),
  status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','unverified')),
  full_name       TEXT,
  company         TEXT,
  telegram_chat_id TEXT,
  alert_email     TEXT,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at   TEXT,
  login_count     INTEGER NOT NULL DEFAULT 0
);

-- Explicit column list: the live table had already drifted from
-- schema_master.sql (no updated_at column) — SELECT * caused a 15-vs-14
-- column mismatch and the whole migration safely rolled back. updated_at
-- gets its DEFAULT (datetime('now')) for every migrated row since it's
-- omitted here.
-- One live row had tier='pro' (lowercase) — drift that had bypassed even the
-- original CHECK constraint. Normalize case rather than reject the row.
INSERT INTO users (id, email, password_hash, password_salt, tier, status,
                    full_name, company, telegram_chat_id, alert_email,
                    email_verified, created_at, last_login_at, login_count)
SELECT id, email, password_hash, password_salt, UPPER(tier), status,
       full_name, company, telegram_chat_id, alert_email,
       email_verified, created_at, last_login_at, login_count
FROM users_v44_backup;

DROP TABLE users_v44_backup;

CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_tier   ON users(tier);

PRAGMA foreign_keys = ON;
