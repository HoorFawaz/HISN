"""SQLite access for HISN.

Rules enforced here:

* Every statement uses ``?`` placeholders. Values are never formatted into
  SQL text, because domains come from the network and are attacker-controlled.
* Only minimal data is stored (see ``schema.sql``) and it can be removed:
  :meth:`Database.purge_older_than` applies the retention period and
  :meth:`Database.delete_all_logs` wipes everything.

Command line (run from the project root)::

    python -m storage.db purge               # apply the retention period now
    python -m storage.db delete-all --yes    # delete every log entry
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 2  # 2: DoH lookups taken out of the threat counts of older logs
SECONDS_PER_DAY = 86_400
MAX_LIMIT = 100_000  # upper bound for any "give me N rows" call
# A DNS-over-HTTPS lookup answered NXDOMAIN (Phase 7) is logged, but it is not a
# threat: it stays out of the daily totals, the blocked-domain table and every
# threat count. The dashboard shows it with its own label ("DoH bypass attempt").
DOH_REASON = "doh"
CACHE_REASON = "cache"


@dataclass(frozen=True)
class RequestRow:
    ts: int
    domain: str
    verdict: str
    reason: str
    device: str


@dataclass(frozen=True)
class BlockedRow:
    domain: str
    hits: int
    first_seen: int
    last_seen: int
    reason: str


@dataclass(frozen=True)
class DeviceRow:
    device: str
    requests: int
    blocked: int  # threats only (DoH lookups not counted)
    last_seen: int


@dataclass(frozen=True)
class BlockEvent:
    id: int
    ts: int
    domain: str
    reason: str
    device: str


@dataclass(frozen=True)
class AdminAccount:
    username: str
    password_hash: str


@dataclass(frozen=True)
class AllowedRow:
    domain: str
    added_at: int
    was_reason: str | None


@dataclass(frozen=True)
class OwnerAction:
    ts: int
    action: str  # "unblock" or "reblock"
    domain: str


@dataclass(frozen=True)
class DayStats:
    day: str
    allowed: int
    blocked: int


def _day(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


class Database:
    """Thread-safe wrapper around one SQLite connection.

    The DNS server answers from several threads, so every access takes a lock.
    ``path`` may be ``":memory:"`` (used by the tests).
    """

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        # Overwrite deleted content, so purged logs do not linger in the file.
        self._conn.execute("PRAGMA secure_delete = ON")
        self._create_schema()
        if str(path) != ":memory:":
            try:
                os.chmod(path, 0o600)  # the log is private to the owner (no-op on Windows)
            except OSError:
                pass

    def _create_schema(self) -> None:
        with self._lock, self._conn:
            (version,) = self._conn.execute("PRAGMA user_version").fetchone()
            self._conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            if version < 2:
                self._remove_old_doh_counts()
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")  # constant, not input

    def _remove_old_doh_counts(self) -> None:
        """Logs written before Phase 9 counted DoH lookups as blocked threats; take them out.

        The blocked-domain table loses its DoH rows, and the daily totals of the
        days still in the request log are counted again from it.
        """
        self._conn.execute("DELETE FROM blocked_domains WHERE reason = ?", (DOH_REASON,))
        rows = self._conn.execute("SELECT ts, verdict, reason FROM requests").fetchall()
        if not rows:
            return
        first_day = min(_day(ts) for ts, _, _ in rows)
        # Days already in the totals start from zero: a day with only DoH lookups has no threats.
        days = {day: [0, 0] for (day,) in self._conn.execute("SELECT day FROM stats WHERE day >= ?", (first_day,))}
        for ts, verdict, reason in rows:
            if reason != DOH_REASON:
                days.setdefault(_day(ts), [0, 0])[0 if verdict == "allow" else 1] += 1
        for day, (allowed, blocked) in days.items():
            self._conn.execute(
                "INSERT INTO stats (day, allowed, blocked) VALUES (?, ?, ?) "
                "ON CONFLICT(day) DO UPDATE SET allowed = excluded.allowed, blocked = excluded.blocked",
                (day, allowed, blocked),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ----- writing -----

    def log_decision(
        self,
        domain: str,
        verdict: str,
        reason: str,
        device: str,
        ts: float | None = None,
    ) -> None:
        """Record one decision in the three tables, in a single transaction.

        A DoH lookup goes to ``requests`` only (see :data:`DOH_REASON`).
        """
        moment = int(time.time() if ts is None else ts)
        blocked = verdict == "block"
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO requests (ts, domain, verdict, reason, device) VALUES (?, ?, ?, ?, ?)",
                (moment, domain, verdict, reason, device),
            )
            if reason == DOH_REASON:
                return
            self._conn.execute(
                "INSERT INTO stats (day, allowed, blocked) VALUES (?, ?, ?) "
                "ON CONFLICT(day) DO UPDATE SET "
                "allowed = allowed + excluded.allowed, blocked = blocked + excluded.blocked",
                (_day(moment), 0 if blocked else 1, 1 if blocked else 0),
            )
            if blocked:
                self._conn.execute(
                    "INSERT INTO blocked_domains (domain, first_seen, last_seen, hits, reason) "
                    "VALUES (?, ?, ?, 1, ?) "
                    "ON CONFLICT(domain) DO UPDATE SET "
                    "last_seen = excluded.last_seen, hits = hits + 1, "
                    # A cache hit says nothing about why; keep the reason of the real decision.
                    "reason = CASE WHEN excluded.reason = 'cache' THEN reason ELSE excluded.reason END",
                    (domain, moment, moment, reason),
                )

    # ----- retention and deletion -----

    def purge_older_than(self, days: int, now: float | None = None) -> int:
        """Delete requests and blocked domains older than ``days`` days.

        Returns the number of deleted requests. Daily totals are kept (they
        hold no domain or device).
        """
        if days < 1:
            raise ValueError("days must be at least 1")
        cutoff = int(time.time() if now is None else now) - days * SECONDS_PER_DAY
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM requests WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM blocked_domains WHERE last_seen < ?", (cutoff,))
            self._conn.execute("DELETE FROM owner_actions WHERE ts < ?", (cutoff,))
            return cursor.rowcount

    def delete_all_logs(self) -> None:
        """Remove every log entry and shrink the file. The owner's allowed sites are kept."""
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM requests")
                self._conn.execute("DELETE FROM blocked_domains")
                self._conn.execute("DELETE FROM stats")
                self._conn.execute("DELETE FROM owner_actions")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")

    # ----- the dashboard account -----

    def admin_account(self) -> AdminAccount | None:
        with self._lock:
            row = self._conn.execute("SELECT username, password_hash FROM admin_account WHERE id = 1").fetchone()
        return AdminAccount(*row) if row else None

    def create_admin(self, username: str, password_hash: str, ts: float | None = None) -> bool:
        """Create the admin account. False if it already exists (only the first one wins)."""
        moment = int(time.time() if ts is None else ts)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO admin_account (id, username, password_hash, created_at, updated_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (username, password_hash, moment, moment),
            )
            return cursor.rowcount == 1

    def set_admin(self, username: str, password_hash: str, ts: float | None = None) -> None:
        """Create the admin account or replace its name and password (password reset)."""
        moment = int(time.time() if ts is None else ts)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO admin_account (id, username, password_hash, created_at, updated_at) "
                "VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "username = excluded.username, password_hash = excluded.password_hash, "
                "updated_at = excluded.updated_at",
                (username, password_hash, moment, moment),
            )

    # ----- sites the owner unblocked (dashboard) -----

    def allow_domain(self, domain: str, ts: float | None = None) -> bool:
        """Unblock an already-normalized ``domain``. False if it was already allowed."""
        moment = int(time.time() if ts is None else ts)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT reason FROM blocked_domains WHERE domain = ?", (domain,)
            ).fetchone()
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO allowed_domains (domain, added_at, was_reason) VALUES (?, ?, ?)",
                (domain, moment, row[0] if row else None),
            )
            if cursor.rowcount == 0:
                return False
            self._conn.execute(
                "INSERT INTO owner_actions (ts, action, domain) VALUES (?, 'unblock', ?)", (moment, domain)
            )
            return True

    def remove_allowed(self, domain: str, ts: float | None = None) -> bool:
        """Block ``domain`` again (normal checks apply). False if it was not allowed."""
        moment = int(time.time() if ts is None else ts)
        with self._lock, self._conn:
            cursor = self._conn.execute("DELETE FROM allowed_domains WHERE domain = ?", (domain,))
            if cursor.rowcount == 0:
                return False
            self._conn.execute(
                "INSERT INTO owner_actions (ts, action, domain) VALUES (?, 'reblock', ?)", (moment, domain)
            )
            return True

    def allowed_domains(self, limit: int = MAX_LIMIT) -> list[AllowedRow]:
        """The owner's allowed sites, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT domain, added_at, was_reason FROM allowed_domains ORDER BY added_at DESC, domain LIMIT ?",
                (_clamp(limit),),
            ).fetchall()
        return [AllowedRow(*row) for row in rows]

    def allowed_set(self) -> frozenset[str]:
        """All allowed names, for the DNS server."""
        with self._lock:
            rows = self._conn.execute("SELECT domain FROM allowed_domains").fetchall()
        return frozenset(row[0] for row in rows)

    def owner_actions(self, limit: int = 20) -> list[OwnerAction]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, action, domain FROM owner_actions ORDER BY id DESC LIMIT ?", (_clamp(limit),)
            ).fetchall()
        return [OwnerAction(*row) for row in rows]

    # ----- reading (block page and dashboard) -----

    def recent_requests(self, limit: int = 100) -> list[RequestRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, domain, verdict, reason, device FROM requests "
                "ORDER BY id DESC LIMIT ?",
                (_clamp(limit),),
            ).fetchall()
        return [RequestRow(*row) for row in rows]

    def top_blocked(self, limit: int = 10) -> list[BlockedRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT domain, hits, first_seen, last_seen, reason FROM blocked_domains "
                "ORDER BY hits DESC, last_seen DESC LIMIT ?",
                (_clamp(limit),),
            ).fetchall()
        return [BlockedRow(*row) for row in rows]

    def recent_blocks(self, after_id: int = 0, limit: int = 20) -> list[BlockEvent]:
        """Blocks newest first, DoH lookups included; only ids above ``after_id`` (for alerts).

        A cache hit carries the reason of the decision it repeats.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT r.id, r.ts, r.domain, "
                "CASE WHEN r.reason = ? THEN COALESCE(b.reason, r.reason) ELSE r.reason END, r.device "
                "FROM requests r LEFT JOIN blocked_domains b ON b.domain = r.domain "
                "WHERE r.verdict = 'block' AND r.id > ? ORDER BY r.id DESC LIMIT ?",
                (CACHE_REASON, int(after_id), _clamp(limit)),
            ).fetchall()
        return [BlockEvent(*row) for row in rows]

    def blocked_since(self, since: int) -> list[BlockedRow]:
        """Every domain blocked since ``since`` (DoH lookups included), with its hits in that period.

        The reason is the latest real one: a cache hit repeats an earlier decision,
        so it takes the reason of that decision.
        """
        with self._lock:
            events = self._conn.execute(
                "SELECT domain, ts, reason FROM requests WHERE verdict = 'block' AND ts >= ? ORDER BY id",
                (int(since),),
            ).fetchall()
            stored = dict(self._conn.execute("SELECT domain, reason FROM blocked_domains").fetchall())
        rows: dict[str, list] = {}
        for domain, ts, reason in events:
            row = rows.setdefault(domain, [domain, 0, ts, ts, None])
            row[1] += 1
            row[3] = ts
            if reason != CACHE_REASON:
                row[4] = reason
        return [
            BlockedRow(domain, hits, first, last, reason or stored.get(domain, CACHE_REASON))
            for domain, hits, first, last, reason in rows.values()
        ]

    def device_stats(self, limit: int = 20, since: int = 0) -> list[DeviceRow]:
        """Requests and blocked threats per device since ``since``, most targeted first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT device, COUNT(*), "
                "SUM(CASE WHEN verdict = 'block' AND reason != ? THEN 1 ELSE 0 END), MAX(ts) "
                "FROM requests WHERE ts >= ? GROUP BY device ORDER BY 3 DESC, 2 DESC LIMIT ?",
                (DOH_REASON, int(since), _clamp(limit)),
            ).fetchall()
        return [DeviceRow(*row) for row in rows]

    def device_count(self, since: int = 0) -> int:
        """Devices that sent at least one request since ``since``."""
        with self._lock:
            (count,) = self._conn.execute(
                "SELECT COUNT(DISTINCT device) FROM requests WHERE ts >= ?", (int(since),)
            ).fetchone()
        return int(count)

    def doh_count(self, since: int = 0) -> int:
        """DNS-over-HTTPS lookups answered NXDOMAIN since ``since``."""
        with self._lock:
            (count,) = self._conn.execute(
                "SELECT COUNT(*) FROM requests WHERE reason = ? AND ts >= ?", (DOH_REASON, int(since))
            ).fetchone()
        return int(count)

    def blocked_reason(self, domain: str) -> str | None:
        """Reason of the last block of ``domain`` (used by the block page), or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT reason FROM blocked_domains WHERE domain = ?", (domain,)
            ).fetchone()
        return row[0] if row else None

    def daily_stats(self, days: int = 7) -> list[DayStats]:
        """Totals for the most recent ``days`` days that have data, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT day, allowed, blocked FROM stats ORDER BY day DESC LIMIT ?",
                (_clamp(days),),
            ).fetchall()
        return [DayStats(*row) for row in rows]


def main(argv: Sequence[str] | None = None) -> int:
    from config import settings  # imported here so the module has no config side effects

    parser = argparse.ArgumentParser(prog="python -m storage.db", description="Manage HISN logs.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("purge", help="delete entries older than the retention period")
    wipe = sub.add_parser("delete-all", help="delete every log entry")
    wipe.add_argument("--yes", action="store_true", help="confirm the deletion")
    args = parser.parse_args(argv)

    database = Database(settings.db_path)
    try:
        if args.command == "purge":
            removed = database.purge_older_than(settings.log_retention_days)
            print(f"Deleted {removed} requests older than {settings.log_retention_days} days.")
        else:
            if not args.yes:
                print("This deletes ALL logs. Run again with --yes to confirm.")
                return 1
            database.delete_all_logs()
            print("All logs deleted.")
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
