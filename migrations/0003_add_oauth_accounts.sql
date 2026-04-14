CREATE TABLE IF NOT EXISTS oauth_accounts (
    id            TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    email         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(provider, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_accounts(user_id);

-- Allow users without password (OAuth-only users)
-- Modify users table: password_hash can be NULL for OAuth users
-- SQLite doesn't support ALTER COLUMN, so we keep the constraint and use empty string for OAuth users
