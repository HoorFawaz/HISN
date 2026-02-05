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
