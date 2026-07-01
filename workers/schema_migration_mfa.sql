-- MFA (TOTP) — applied live to production D1.
CREATE TABLE IF NOT EXISTS mfa_secrets (
  user_id      TEXT PRIMARY KEY,
  secret       TEXT NOT NULL,
  backup_codes TEXT NOT NULL DEFAULT '[]',
  enabled      INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
