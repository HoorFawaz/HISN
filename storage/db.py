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
SCHEMA_VERSION = 1
SECONDS_PER_DAY = 86_400
MAX_LIMIT = 1_000  # upper bound for any "give me N rows" call


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
            self._conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")  # constant, not input

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
        """Record one decision in the three tables, in a single transaction."""
        moment = int(time.time() if ts is None else ts)
        blocked = verdict == "block"
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO requests (ts, domain, verdict, reason, device) VALUES (?, ?, ?, ?, ?)",
                (moment, domain, verdict, reason, device),
            )
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
            return cursor.rowcount

    def delete_all_logs(self) -> None:
        """Remove every log entry and shrink the file."""
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM requests")
                self._conn.execute("DELETE FROM blocked_domains")
                self._conn.execute("DELETE FROM stats")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")

    # ----- reading (block page now, dashboard in a later phase) -----

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
