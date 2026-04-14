CREATE TABLE IF NOT EXISTS passkeys (
    id              TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    counter         INTEGER NOT NULL DEFAULT 0,
    transports      TEXT,
    device_type     TEXT,
    backed_up       INTEGER NOT NULL DEFAULT 0,
    name            TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id);
