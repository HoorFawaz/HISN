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


# ----- dashboard queries (Phase 9) -----


def test_doh_lookups_are_logged_but_not_counted_as_threats(db: Database) -> None:
    db.log_decision("dns.google", "block", "doh", "192.168.1.5", ts=NOW)
    db.log_decision("evil.example", "block", "blacklist", "192.168.1.5", ts=NOW)
    assert [r.domain for r in db.recent_requests()] == ["evil.example", "dns.google"]
    assert [r.domain for r in db.top_blocked()] == ["evil.example"]
    assert [r.domain for r in db.recent_blocks()] == ["evil.example", "dns.google"]  # listed, with its reason
    assert db.daily_stats()[0].blocked == 1
    assert db.doh_count() == 1
    (device,) = db.device_stats()
    assert (device.requests, device.blocked) == (2, 1)


def test_recent_blocks_after_an_id(db: Database) -> None:
    db.log_decision("a.example", "block", "model", "dev", ts=NOW)
    db.log_decision("ok.example", "allow", "default", "dev", ts=NOW)
    db.log_decision("b.example", "block", "lookalike", "dev", ts=NOW + 1)
    events = db.recent_blocks()
    assert [e.domain for e in events] == ["b.example", "a.example"]
    assert [e.domain for e in db.recent_blocks(after_id=events[1].id)] == ["b.example"]
    assert db.recent_blocks(after_id=events[0].id) == []
    assert len(db.recent_blocks(limit=1)) == 1


def test_device_stats_puts_the_most_targeted_device_first(db: Database) -> None:
    for _ in range(5):
        db.log_decision("ok.example", "allow", "default", "192.168.1.10", ts=NOW)
    db.log_decision("evil.example", "block", "blacklist", "192.168.1.20", ts=NOW + 5)
    rows = db.device_stats()
    assert [(r.device, r.requests, r.blocked) for r in rows] == [
        ("192.168.1.20", 1, 1),
        ("192.168.1.10", 5, 0),
    ]
    assert rows[0].last_seen == NOW + 5


def test_blocked_since_counts_hits_with_the_real_reason(db: Database) -> None:
    db.log_decision("old.example", "block", "model", "dev", ts=NOW - 100)
    db.log_decision("b.example", "block", "model", "dev", ts=NOW - 50)
    db.log_decision("a.example", "block", "lookalike", "dev", ts=NOW)
    db.log_decision("a.example", "block", "cache", "dev", ts=NOW + 1)
    db.log_decision("b.example", "block", "cache", "dev", ts=NOW + 2)  # its real decision is older
    db.log_decision("dns.google", "block", "doh", "dev", ts=NOW + 3)
    db.log_decision("ok.example", "allow", "default", "dev", ts=NOW + 4)
    rows = {r.domain: (r.hits, r.reason, r.first_seen, r.last_seen) for r in db.blocked_since(NOW)}
    assert rows == {
        "a.example": (2, "lookalike", NOW, NOW + 1),
        "b.example": (1, "model", NOW + 2, NOW + 2),
        "dns.google": (1, "doh", NOW + 3, NOW + 3),
    }


def test_recent_blocks_show_the_real_reason_of_a_cache_hit(db: Database) -> None:
    db.log_decision("a.example", "block", "lookalike", "dev", ts=NOW)
    db.log_decision("a.example", "block", "cache", "dev", ts=NOW + 1)
    assert [e.reason for e in db.recent_blocks()] == ["lookalike", "lookalike"]


def test_device_counts_cover_the_asked_period(db: Database) -> None:
    db.log_decision("evil.example", "block", "blacklist", "192.168.1.5", ts=NOW - 100)
    db.log_decision("ok.example", "allow", "default", "192.168.1.6", ts=NOW)
    assert db.device_count() == 2
    assert db.device_count(since=NOW) == 1
    assert [r.device for r in db.device_stats(since=NOW)] == ["192.168.1.6"]


def test_old_logs_lose_their_doh_threat_counts(tmp_path: Path) -> None:
    # Before Phase 9 a DoH lookup was counted as a blocked threat.
    path = tmp_path / "old.db"
    db = Database(path)
    db.log_decision("evil.example", "block", "blacklist", "dev", ts=NOW)
    db.log_decision("dns.google", "block", "doh", "dev", ts=NOW)
    db.log_decision("dns.google", "block", "doh", "dev", ts=NOW + 86_400)
    with db._conn:
        db._conn.execute("UPDATE stats SET blocked = blocked + 1")
        db._conn.execute("INSERT INTO stats (day, allowed, blocked) VALUES ('2027-01-16', 0, 1)")
        db._conn.execute("INSERT INTO blocked_domains VALUES ('dns.google', ?, ?, 2, 'doh')", (NOW, NOW))
        db._conn.execute("PRAGMA user_version = 1")
    db.close()

    fixed = Database(path)
    assert {(d.day, d.blocked) for d in fixed.daily_stats()} == {("2027-01-15", 1), ("2027-01-16", 0)}
    assert [r.domain for r in fixed.top_blocked()] == ["evil.example"]
    fixed.close()


# ----- sites the owner unblocked -----


def test_allow_and_reblock_a_domain(db: Database) -> None:
    db.log_decision("evil.example", "block", "blacklist", "dev", ts=NOW)
    assert db.allow_domain("evil.example", ts=NOW + 1)
    assert not db.allow_domain("evil.example", ts=NOW + 2)  # already allowed, not logged twice
    (row,) = db.allowed_domains()
    assert (row.domain, row.added_at, row.was_reason) == ("evil.example", NOW + 1, "blacklist")
    assert db.allowed_set() == frozenset({"evil.example"})
    assert db.allow_domain("never-blocked.example", ts=NOW + 3)
    assert db.allowed_domains()[0].was_reason is None

    assert db.remove_allowed("evil.example", ts=NOW + 4)
    assert not db.remove_allowed("evil.example", ts=NOW + 5)
    assert db.allowed_set() == frozenset({"never-blocked.example"})
    assert [(a.action, a.domain) for a in db.owner_actions()] == [
        ("reblock", "evil.example"),
        ("unblock", "never-blocked.example"),
        ("unblock", "evil.example"),
    ]


def test_allowed_sites_survive_log_deletion_but_actions_do_not(db: Database) -> None:
    db.allow_domain("ok.example", ts=NOW)
    db.purge_older_than(30, now=NOW + 31 * DAY)
    assert db.allowed_set() == frozenset({"ok.example"}) and db.owner_actions() == []
    db.allow_domain("two.example", ts=NOW)
    db.delete_all_logs()
    assert db.allowed_set() == frozenset({"ok.example", "two.example"}) and db.owner_actions() == []


def test_admin_account_is_created_once_and_survives_log_deletion(db: Database) -> None:
    assert db.admin_account() is None
    assert db.create_admin("hoor", "hash-1", ts=NOW)
    assert not db.create_admin("other", "hash-2", ts=NOW)
    db.delete_all_logs()
    db.purge_older_than(1, now=NOW + 10 * DAY)
    account = db.admin_account()
    assert account is not None and (account.username, account.password_hash) == ("hoor", "hash-1")
    db.set_admin("hoor", "hash-3")
    assert db.admin_account().password_hash == "hash-3"  # type: ignore[union-attr]
