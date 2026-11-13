-- Sentinel DNS database schema (SQLite). All timestamps are UTC epoch seconds.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    must_change_password INTEGER NOT NULL DEFAULT 0
);

-- Server-side sessions: the cookie holds a random token, the database only its SHA-256.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    ip           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS login_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    success  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_events_ts ON login_events (ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT    NOT NULL,
    action   TEXT    NOT NULL,
    detail   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log (ts);

-- Key/value settings; values are JSON encoded.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zones (
    name           TEXT PRIMARY KEY,
    kind           TEXT    NOT NULL CHECK (kind IN ('forward', 'reverse')),
    serial         INTEGER NOT NULL,
    dnssec_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    zone       TEXT    NOT NULL REFERENCES zones (name) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    type       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    ttl        INTEGER NOT NULL,
    priority   INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (zone, name, type, value)
);
CREATE INDEX IF NOT EXISTS idx_records_zone_name ON records (zone, name);

-- Mutable state of blocklist categories (metadata lives in dnscore/catalog.py).
CREATE TABLE IF NOT EXISTS categories (
    key            TEXT PRIMARY KEY,
    enabled        INTEGER NOT NULL DEFAULT 1,
    domain_count   INTEGER NOT NULL DEFAULT 0,
    last_synced_at INTEGER
);

CREATE TABLE IF NOT EXISTS blocklist (
    domain   TEXT PRIMARY KEY,
    category TEXT NOT NULL REFERENCES categories (key)
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT    NOT NULL UNIQUE,
    action     TEXT    NOT NULL CHECK (action IN ('block', 'allow')),
    category   TEXT    NOT NULL DEFAULT 'other',
    note       TEXT    NOT NULL DEFAULT '',
    created_by TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

-- One row per DNS query (from BIND logs in production, simulated in demo mode).
CREATE TABLE IF NOT EXISTS query_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    client_ip   TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    action      TEXT    NOT NULL CHECK (action IN ('allowed', 'blocked')),
    rcode       TEXT    NOT NULL,
    cached      INTEGER NOT NULL DEFAULT 0,
    response_ms REAL    NOT NULL,
    category    TEXT,
    source      TEXT,
    severity    TEXT,
    confidence  REAL,
    measured    INTEGER NOT NULL DEFAULT 1  -- 0: from BIND logs, which carry no latency / cache data
);
CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log (ts);
CREATE INDEX IF NOT EXISTS idx_query_log_action_ts ON query_log (action, ts);
