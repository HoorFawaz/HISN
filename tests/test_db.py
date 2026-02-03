"""Tests for the SQLite storage layer."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from storage.db import Database

DAY = 86_400
NOW = 1_800_000_000  # a fixed moment so day boundaries are predictable


@pytest.fixture
def db() -> Iterator[Database]:
    database = Database(":memory:")
    yield database
    database.close()


def test_logged_decision_can_be_read_back(db: Database) -> None:
    db.log_decision("example.com", "allow", "default", "192.168.1.20", ts=NOW)
    (row,) = db.recent_requests()
    assert (row.domain, row.verdict, row.reason, row.device, row.ts) == (
        "example.com",
        "allow",
        "default",
        "192.168.1.20",
        NOW,
    )


def test_recent_requests_are_newest_first_and_limited(db: Database) -> None:
    for index in range(5):
        db.log_decision(f"d{index}.example", "allow", "default", "dev", ts=NOW + index)
    rows = db.recent_requests(limit=2)
    assert [row.domain for row in rows] == ["d4.example", "d3.example"]


def test_blocked_domain_hits_are_counted(db: Database) -> None:
    for offset in range(3):
        db.log_decision("evil.example", "block", "blacklist", "dev", ts=NOW + offset)
    db.log_decision("fine.example", "allow", "default", "dev", ts=NOW)
    (blocked,) = db.top_blocked()
    assert blocked.domain == "evil.example"
    assert blocked.hits == 3
    assert blocked.first_seen == NOW
    assert blocked.last_seen == NOW + 2


def test_daily_stats_count_both_verdicts(db: Database) -> None:
    db.log_decision("a.example", "allow", "default", "dev", ts=NOW)
    db.log_decision("b.example", "allow", "default", "dev", ts=NOW)
    db.log_decision("c.example", "block", "blacklist", "dev", ts=NOW)
    db.log_decision("a.example", "allow", "default", "dev", ts=NOW + 2 * DAY)
    newest, oldest = db.daily_stats()
    assert (oldest.allowed, oldest.blocked) == (2, 1)
    assert (newest.allowed, newest.blocked) == (1, 0)
    assert newest.day > oldest.day


def test_invalid_verdict_is_rejected_by_the_schema(db: Database) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.log_decision("a.example", "maybe", "default", "dev", ts=NOW)
    assert db.recent_requests() == []  # the failed transaction left nothing behind


def test_hostile_strings_are_stored_as_plain_data(db: Database) -> None:
    # The domain validator rejects these long before this layer, but the layer
    # must be safe on its own: values are bound parameters, never SQL text.
    evil = "x'); DROP TABLE requests; --"
    db.log_decision(evil, "block", "blacklist", "dev", ts=NOW)
    db.log_decision("ok.example", "allow", "default", evil, ts=NOW)
    domains = {row.domain for row in db.recent_requests()}
    assert evil in domains
    assert db.top_blocked()[0].domain == evil


def test_purge_removes_only_entries_past_retention(db: Database) -> None:
    db.log_decision("old.example", "block", "blacklist", "dev", ts=NOW - 40 * DAY)
    db.log_decision("new.example", "block", "blacklist", "dev", ts=NOW - 5 * DAY)
    removed = db.purge_older_than(30, now=NOW)
    assert removed == 1
    assert [row.domain for row in db.recent_requests()] == ["new.example"]
    assert [row.domain for row in db.top_blocked()] == ["new.example"]


def test_purge_keeps_daily_totals(db: Database) -> None:
    db.log_decision("old.example", "allow", "default", "dev", ts=NOW - 40 * DAY)
    db.purge_older_than(30, now=NOW)
    assert db.recent_requests() == []
    assert db.daily_stats()[0].allowed == 1  # totals hold no domain or device


def test_delete_all_logs_empties_every_table(db: Database) -> None:
    db.log_decision("a.example", "block", "blacklist", "dev", ts=NOW)
    db.log_decision("b.example", "allow", "default", "dev", ts=NOW)
    db.delete_all_logs()
    assert db.recent_requests() == []
    assert db.top_blocked() == []
    assert db.daily_stats() == []


def test_purge_rejects_nonsense_retention(db: Database) -> None:
    with pytest.raises(ValueError):
        db.purge_older_than(0)


def test_data_survives_reopening_a_file_database(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "hisn.db"  # the parent folder is created on demand
    first = Database(path)
    first.log_decision("a.example", "allow", "default", "dev", ts=NOW)
    first.close()
    second = Database(path)
    assert [row.domain for row in second.recent_requests()] == ["a.example"]
    second.close()


def test_concurrent_writers_do_not_lose_rows(tmp_path: Path) -> None:
    database = Database(tmp_path / "hisn.db")

    def worker(name: str) -> None:
        for index in range(25):
            database.log_decision(f"{name}{index}.example", "allow", "default", "dev", ts=NOW)

    threads = [threading.Thread(target=worker, args=(f"t{n}",)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(database.recent_requests(limit=1000)) == 200
    assert database.daily_stats()[0].allowed == 200
    database.close()


def test_command_line_delete_all_requires_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import dataclasses

    import storage.db as storage_db
    from config import settings

    path = tmp_path / "cli.db"
    monkeypatch.setattr("config.settings", dataclasses.replace(settings, db_path=path))
    seed = Database(path)
    seed.log_decision("a.example", "allow", "default", "dev", ts=NOW)
    seed.close()

    assert storage_db.main(["delete-all"]) == 1  # no --yes: nothing is deleted
    check = Database(path)
    assert len(check.recent_requests()) == 1
    check.close()

    assert storage_db.main(["delete-all", "--yes"]) == 0
    check = Database(path)
    assert check.recent_requests() == []
    check.close()
    assert "All logs deleted" in capsys.readouterr().out
