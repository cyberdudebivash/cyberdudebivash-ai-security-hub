-- Enterprise SSO (OIDC) — applied live to production D1.
CREATE TABLE IF NOT EXISTS sso_configs (
  id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  org_id          TEXT NOT NULL UNIQUE,
  provider_name   TEXT NOT NULL DEFAULT 'custom',
  issuer          TEXT NOT NULL,
  client_id       TEXT NOT NULL,
  client_secret   TEXT NOT NULL,
  allowed_domains TEXT NOT NULL DEFAULT '[]',
  enabled         INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sso_configs_org ON sso_configs(org_id);
