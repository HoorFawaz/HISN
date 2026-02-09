"""Tests for the owner's allowed sites as the DNS server reads them."""

from __future__ import annotations

import sqlite3

from dns_server.owner_list import OwnerAllowList
from storage.db import Database


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_matches_the_site_and_its_subdomains_only() -> None:
    db = Database(":memory:")
    db.allow_domain("example.com")
    owner = OwnerAllowList(db)
    assert owner.match("example.com") == "example.com"
    assert owner.match("www.example.com") == "example.com"
    assert owner.match("badexample.com") is None and owner.match("example.com.evil.test") is None
    db.close()


def test_changes_from_the_dashboard_show_up_after_the_refresh() -> None:
    db = Database(":memory:")
    clock = Clock()
    owner = OwnerAllowList(db, refresh=2.0, clock=clock)
    assert owner.match("evil.test") is None
    db.allow_domain("evil.test")
    assert owner.match("evil.test") is None  # not re-read yet
    clock.now = 2.0
    assert owner.match("evil.test") == "evil.test"
    db.remove_allowed("evil.test")
    clock.now = 4.0
    assert owner.match("evil.test") is None
    db.close()


def test_keeps_the_last_copy_when_the_database_fails() -> None:
    class Flaky:
        def __init__(self) -> None:
            self.fail = False

        def allowed_set(self) -> frozenset[str]:
            if self.fail:
                raise sqlite3.OperationalError("database is locked")
            return frozenset({"ok.test"})

    source, clock = Flaky(), Clock()
    owner = OwnerAllowList(source, refresh=1.0, clock=clock)
    assert owner.match("ok.test") == "ok.test"
    source.fail, clock.now = True, 5.0
    assert owner.match("ok.test") == "ok.test"
