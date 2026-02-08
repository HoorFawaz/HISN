"""Tests for the DNS-over-HTTPS blocker (Phase 7)."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from config import settings
from dns_server.decision import ListFormatError
from dns_server.doh_blocker import FIREFOX_CANARY, DohBlocker
from dns_server.server import load_doh_blocker


def blocker() -> DohBlocker:
    return DohBlocker(frozenset({"dns.google", "cloudflare-dns.com"}))


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("dns.google", "dns.google"),
        ("dns64.dns.google", "dns.google"),
        ("mozilla.cloudflare-dns.com", "cloudflare-dns.com"),
        (FIREFOX_CANARY, FIREFOX_CANARY),
        ("x." + FIREFOX_CANARY, FIREFOX_CANARY),
    ],
)
def test_listed_hosts_and_subdomains_match(domain: str, expected: str) -> None:
    assert blocker().match(domain) == expected


@pytest.mark.parametrize(
    "domain",
    ["google.com", "dns.google.evil.com", "notcloudflare-dns.com", "cloudflare-dns.com.sa", "example.org"],
)
def test_other_names_do_not_match(domain: str) -> None:
    assert blocker().match(domain) is None


def test_canary_is_blocked_even_with_an_empty_list() -> None:
    assert DohBlocker(frozenset()).match(FIREFOX_CANARY) == FIREFOX_CANARY


def test_shipped_list_loads_and_covers_the_big_providers() -> None:
    shipped = DohBlocker.from_file(settings.doh_hosts_path)
    for name in ("dns.google", "cloudflare-dns.com", "dns.quad9.net", "mask.icloud.com"):
        assert shipped.match(name) == name


def test_missing_file_keeps_the_canary(tmp_path: Path) -> None:
    loaded = DohBlocker.from_file(tmp_path / "none.txt")
    assert loaded.match(FIREFOX_CANARY) == FIREFOX_CANARY
    assert loaded.match("dns.google") is None


def test_bad_entry_fails_loudly(tmp_path: Path) -> None:
    path = tmp_path / "doh.txt"
    path.write_text("dns.google\nnot a host!\n", encoding="utf-8")
    with pytest.raises(ListFormatError):
        DohBlocker.from_file(path)


def test_blocker_can_be_turned_off() -> None:
    assert load_doh_blocker(dataclasses.replace(settings, doh_block=False)) is None
    assert load_doh_blocker(dataclasses.replace(settings, doh_block=True)) is not None
