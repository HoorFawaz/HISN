"""Tests for the whitelist-then-blacklist decision engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from dns_server.decision import (
    DecisionEngine,
    ListFormatError,
    Reason,
    Verdict,
    load_domain_list,
)


@pytest.fixture
def engine() -> DecisionEngine:
    return DecisionEngine(
        whitelist=frozenset({"absher.gov.sa", "example.org"}),
        blacklist=frozenset({"absher-sa.com", "evil.example.org", "bad.test"}),
    )


def test_whitelisted_domain_is_allowed(engine: DecisionEngine) -> None:
    decision = engine.decide("absher.gov.sa")
    assert decision.verdict is Verdict.ALLOW
    assert decision.reason is Reason.WHITELIST
    assert decision.matched == "absher.gov.sa"


def test_subdomain_of_whitelisted_domain_is_allowed(engine: DecisionEngine) -> None:
    assert engine.decide("portal.absher.gov.sa").verdict is Verdict.ALLOW


def test_blacklisted_domain_is_blocked(engine: DecisionEngine) -> None:
    decision = engine.decide("absher-sa.com")
    assert decision.blocked
    assert decision.reason is Reason.BLACKLIST
    assert decision.matched == "absher-sa.com"


def test_subdomain_of_blacklisted_domain_is_blocked(engine: DecisionEngine) -> None:
    assert engine.decide("login.absher-sa.com").blocked


def test_unknown_domain_is_allowed_by_default(engine: DecisionEngine) -> None:
    decision = engine.decide("unknown-site.net")
    assert decision.verdict is Verdict.ALLOW
    assert decision.reason is Reason.DEFAULT
    assert decision.matched is None


def test_whitelist_wins_over_blacklist() -> None:
    engine = DecisionEngine(frozenset({"both.test"}), frozenset({"both.test"}))
    assert engine.decide("both.test").reason is Reason.WHITELIST


def test_whitelist_wins_over_blacklisted_subdomain(engine: DecisionEngine) -> None:
    # "evil.example.org" is blacklisted but its parent example.org is whitelisted.
    assert engine.decide("evil.example.org").verdict is Verdict.ALLOW


# --- Security: matching is by label boundary, never by substring -------------


def test_fake_domain_embedding_official_name_is_not_whitelisted(engine: DecisionEngine) -> None:
    """absher.gov.sa.fake-login.com must NOT pass the whitelist."""
    decision = engine.decide("absher.gov.sa.fake-login.com")
    assert decision.reason is not Reason.WHITELIST


def test_whitelist_does_not_match_a_suffix_without_dot(engine: DecisionEngine) -> None:
    # "notabsher.gov.sa" ends with "absher.gov.sa" as a string, but is not a subdomain.
    assert engine.decide("notabsher.gov.sa").reason is Reason.DEFAULT


def test_whitelist_does_not_match_a_prefix(engine: DecisionEngine) -> None:
    assert engine.decide("absher.gov.sa.evil.net").reason is Reason.DEFAULT


def test_blacklist_does_not_match_a_suffix_without_dot(engine: DecisionEngine) -> None:
    assert engine.decide("notabsher-sa.com").verdict is Verdict.ALLOW


def test_blacklist_does_not_match_a_substring(engine: DecisionEngine) -> None:
    assert engine.decide("bad.test.example.net").verdict is Verdict.ALLOW


# --- List loading ------------------------------------------------------------


def test_load_domain_list_ignores_comments_and_normalizes(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text(
        "# a comment\n\nExample.COM\n  spaced.test  # trailing comment\nTrailing.Dot.\n",
        encoding="utf-8",
    )
    assert load_domain_list(path) == frozenset({"example.com", "spaced.test", "trailing.dot"})


def test_load_domain_list_rejects_invalid_entry_with_line_number(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("good.com\nnot a domain\n", encoding="utf-8")
    with pytest.raises(ListFormatError, match=r"list\.txt:2"):
        load_domain_list(path)


def test_engine_loads_the_shipped_lists() -> None:
    from config import settings

    engine = DecisionEngine.from_files(settings.whitelist_path, settings.blacklist_path)
    assert engine.decide("absher.gov.sa").verdict is Verdict.ALLOW
    assert engine.decide("absher-sa.com").blocked
