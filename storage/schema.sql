-- HISN database schema (SQLite).
--
-- Privacy by design: only what the dashboard needs is stored (domain, time,
-- verdict, reason, device). No full URLs, no query types, no answers.
-- All timestamps are Unix seconds in UTC.

-- One row per decided query. Deleted after the retention period.
CREATE TABLE IF NOT EXISTS requests (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    domain  TEXT    NOT NULL,
    verdict TEXT    NOT NULL CHECK (verdict IN ('allow', 'block')),
    reason  TEXT    NOT NULL,
    device  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests (ts);
CREATE INDEX IF NOT EXISTS idx_requests_verdict_ts ON requests (verdict, ts);

-- One row per blocked domain, for the "top blocked" view. Deleted when the
-- domain was last seen before the retention cutoff.
CREATE TABLE IF NOT EXISTS blocked_domains (
    domain     TEXT    PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 1,
    reason     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocked_last_seen ON blocked_domains (last_seen);

-- Daily totals. Contains no domains or devices, so it is kept when old
-- requests are purged and removed only by "delete all logs".
CREATE TABLE IF NOT EXISTS stats (
    day     TEXT    PRIMARY KEY,  -- YYYY-MM-DD, UTC
    allowed INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
);

-- Sites the owner unblocked from the dashboard. This is a setting, not a log:
-- it is kept by the retention purge and by "delete all logs". The DNS server
-- allows these names (and their subdomains) before any other check except the
-- whitelist file.
CREATE TABLE IF NOT EXISTS allowed_domains (
    domain     TEXT    PRIMARY KEY,
    added_at   INTEGER NOT NULL,
    was_reason TEXT                 -- why it had been blocked, when known
);

-- Every unblock and re-block made from the dashboard, for the record.
-- Purged and deleted with the other logs.
CREATE TABLE IF NOT EXISTS owner_actions (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    action TEXT    NOT NULL CHECK (action IN ('unblock', 'reblock')),
    domain TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_owner_actions_ts ON owner_actions (ts);

-- Visual check queue and results (Phase 11, optional). The DNS server adds a
-- suspicious site as 'pending'; the visual worker (ml/visual/worker.py) sets
-- 'match' (looks like an official site: blocked), 'clear' or 'failed'. Holds
-- visited names, so it is purged and deleted with the other logs.
CREATE TABLE IF NOT EXISTS visual_checks (
    domain       TEXT    PRIMARY KEY,
    status       TEXT    NOT NULL CHECK (status IN ('pending', 'match', 'clear', 'failed')),
    brand        TEXT,              -- the official site it looks like ('match' only)
    distance     INTEGER,           -- pHash distance to the closest reference
    requested_at INTEGER NOT NULL,
    checked_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_visual_checks_status ON visual_checks (status, requested_at);

-- The one dashboard account (the admin), shared by everyone who manages the
-- home network. Only a salted scrypt hash of the password is stored. Not a
-- log: never purged or deleted with the logs.
CREATE TABLE IF NOT EXISTS admin_account (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
