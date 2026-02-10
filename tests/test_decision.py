"""Tests for the whitelist, blacklist and cache decision engine."""

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
from storage.cache import TTLCache


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
    assert engine.decide("absher.sa").verdict is Verdict.ALLOW
    assert engine.decide("absher.sa.fake-login.com").reason is not Reason.WHITELIST  # the brief's test case
    assert engine.decide("absher-sa.com").blocked
    assert engine.decide("www.abshergov.sa").reason is Reason.BLACKLIST
    assert engine.decide("lms.ksu.edu.sa").reason is Reason.WHITELIST
    assert engine.decide("edu.sa.fake-login.com").reason is not Reason.WHITELIST


def _engine_with_cache() -> tuple[DecisionEngine, TTLCache[Verdict]]:
    cache: TTLCache[Verdict] = TTLCache(60)
    engine = DecisionEngine(
        whitelist=frozenset({"absher.gov.sa"}),
        blacklist=frozenset({"evil.example"}),
        cache=cache,
    )
    return engine, cache


def test_cached_verdict_is_used_for_unknown_domains() -> None:
    engine, cache = _engine_with_cache()
    cache.put("suspicious.example", Verdict.BLOCK)
    decision = engine.decide("suspicious.example")
    assert decision.blocked
    assert decision.reason is Reason.CACHE


def test_cache_is_exact_match_only() -> None:
    engine, cache = _engine_with_cache()
    cache.put("suspicious.example", Verdict.BLOCK)
    assert not engine.decide("www.suspicious.example").blocked
    assert not engine.decide("other-suspicious.example").blocked


def test_lists_win_over_the_cache() -> None:
    engine, cache = _engine_with_cache()
    cache.put("absher.gov.sa", Verdict.BLOCK)  # a stale/wrong cached verdict
    cache.put("evil.example", Verdict.ALLOW)
    assert engine.decide("absher.gov.sa").reason is Reason.WHITELIST
    assert engine.decide("absher.gov.sa").verdict is Verdict.ALLOW
    assert engine.decide("evil.example").reason is Reason.BLACKLIST
    assert engine.decide("evil.example").blocked


def test_engine_works_without_a_cache() -> None:
    engine = DecisionEngine(frozenset(), frozenset())
    assert engine.decide("anything.example").reason is Reason.DEFAULT


# --- Phase 5: look-alike rule and model ---------------------------------------


class FixedScorer:
    def __init__(self, probability: float = 0.0, error: Exception | None = None) -> None:
        self.value = probability
        self.error = error
        self.calls = 0
        self.ages: list[float | None] = []

    def probability(self, host: str, age_days: float | None = None) -> float:
        self.calls += 1
        self.ages.append(age_days)
        if self.error is not None:
            raise self.error
        return self.value


def _full_engine(
    scorer: FixedScorer | None = None,
    techniques: frozenset[str] = frozenset({"brand_name", "hyphenation", "homoglyph", "typo"}),
    cache: TTLCache[Verdict] | None = None,
) -> DecisionEngine:
    from ml.lookalike import LookalikeChecker

    return DecisionEngine(
        whitelist=frozenset({"absher.sa", "alrajhibank.com.sa"}),
        blacklist=frozenset({"evil.example"}),
        cache=cache,
        lookalike=LookalikeChecker(frozenset({"absher", "alrajhi"}), frozenset({"absher.sa", "alrajhibank.com.sa"})),
        block_techniques=techniques,
        scorer=scorer,
        threshold=0.9,
    )


@pytest.mark.parametrize("host", ["abhser.com", "absher-sa.net", "ab-sher.com", "4bsher.com"])
def test_lookalike_rule_blocks_on_its_own(host: str) -> None:
    scorer = FixedScorer(0.0)
    decision = _full_engine(scorer).decide(host)
    assert decision.blocked
    assert decision.reason is Reason.LOOKALIKE
    assert decision.matched == "absher"
    assert scorer.calls == 0  # the model is not asked once the rule decided


def test_contains_is_left_to_the_model_by_default() -> None:
    scorer = FixedScorer(0.1)
    decision = _full_engine(scorer).decide("alrajhitakaful.com")
    assert decision.reason is Reason.MODEL
    assert decision.verdict is Verdict.ALLOW
    assert decision.matched == "0.10"


def test_lists_still_come_first() -> None:
    engine = _full_engine(FixedScorer(1.0))
    assert engine.decide("www.absher.sa").reason is Reason.WHITELIST
    assert engine.decide("evil.example").reason is Reason.BLACKLIST


@pytest.mark.parametrize(("probability", "blocked"), [(0.95, True), (0.90, True), (0.89, False)])
def test_model_blocks_at_or_above_the_threshold(probability: float, blocked: bool) -> None:
    decision = _full_engine(FixedScorer(probability)).decide("x7k2q9zv4m.xyz")
    assert decision.reason is Reason.MODEL
    assert decision.blocked is blocked


def test_rule_and_model_verdicts_are_cached() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    scorer = FixedScorer(0.95)
    engine = _full_engine(scorer, cache=cache)
    engine.decide("x7k2q9zv4m.xyz")
    engine.decide("abhser.com")
    assert cache.get("x7k2q9zv4m.xyz") is Verdict.BLOCK
    assert cache.get("abhser.com") is Verdict.BLOCK
    again = engine.decide("x7k2q9zv4m.xyz")
    assert again.reason is Reason.CACHE and again.blocked
    assert scorer.calls == 1


def test_list_and_default_verdicts_are_not_cached() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    engine = _full_engine(None, cache=cache)
    engine.decide("absher.sa")
    engine.decide("evil.example")
    engine.decide("x7k2q9zv4m.xyz")  # no model: default allow
    assert len(cache) == 0


def test_model_failure_fails_open_and_is_not_cached() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    engine = _full_engine(FixedScorer(error=RuntimeError("broken")), cache=cache)
    decision = engine.decide("x7k2q9zv4m.xyz")
    assert decision.verdict is Verdict.ALLOW
    assert decision.reason is Reason.DEFAULT
    assert len(cache) == 0


def test_rule_failure_fails_open() -> None:
    class BrokenRule:
        def check(self, host: str) -> None:
            raise RuntimeError("broken")

    engine = DecisionEngine(frozenset(), frozenset(), lookalike=BrokenRule(), block_techniques={"typo"})
    assert engine.decide("abhser.com").reason is Reason.DEFAULT


def test_empty_technique_set_turns_the_rule_off() -> None:
    assert _full_engine(None, techniques=frozenset()).decide("abhser.com").reason is Reason.DEFAULT


def test_threshold_must_be_a_probability() -> None:
    with pytest.raises(ValueError):
        DecisionEngine(frozenset(), frozenset(), threshold=1.5)


# ----- domain age (Phase 6) -----


class FakeAges:
    """Stands in for DomainAgeService: returns a fixed answer, or raises."""

    def __init__(self, days: float | None = None, final: bool = True, error: Exception | None = None) -> None:
        self.days = days
        self.final = final
        self.error = error
        self.calls = 0

    def lookup(self, host: str) -> FakeAges:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self


def _age_engine(ages: FakeAges, scorer: FixedScorer, cache: TTLCache[Verdict] | None = None) -> DecisionEngine:
    return DecisionEngine(frozenset({"absher.sa"}), frozenset({"evil.example"}), cache, scorer=scorer, ages=ages)


def test_known_age_is_passed_to_the_model() -> None:
    scorer = FixedScorer(0.2)
    _age_engine(FakeAges(days=5.0), scorer).decide("x7k2q9zv4m.xyz")
    assert scorer.ages == [5.0]


def test_pending_age_scores_the_name_alone_and_is_not_cached() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    scorer = FixedScorer(0.95)
    decision = _age_engine(FakeAges(final=False), scorer, cache).decide("x7k2q9zv4m.xyz")
    assert decision.reason is Reason.MODEL and decision.blocked  # the answer never waits for the lookup
    assert scorer.ages == [None]
    assert len(cache) == 0  # so the next query is scored with the age


def test_final_unknown_age_is_cached() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    _age_engine(FakeAges(days=None, final=True), FixedScorer(0.1), cache).decide("x7k2q9zv4m.xyz")
    assert cache.get("x7k2q9zv4m.xyz") is Verdict.ALLOW


def test_broken_age_source_fails_open() -> None:
    scorer = FixedScorer(0.1)
    decision = _age_engine(FakeAges(error=RuntimeError("broken")), scorer).decide("x7k2q9zv4m.xyz")
    assert decision.reason is Reason.MODEL
    assert decision.verdict is Verdict.ALLOW
    assert scorer.ages == [None]


def test_age_is_not_looked_up_for_list_or_rule_decisions() -> None:
    ages = FakeAges(days=1.0)
    engine = _age_engine(ages, FixedScorer(0.1))
    engine.decide("www.absher.sa")
    engine.decide("evil.example")
    assert ages.calls == 0


# ----- sites the owner unblocked from the dashboard -----


class OwnerList:
    def __init__(self, *domains: str) -> None:
        self.domains = set(domains)

    def match(self, domain: str) -> str | None:
        return domain if domain in self.domains else None


def test_owner_unblock_wins_over_the_blacklist_and_the_cache() -> None:
    cache: TTLCache[Verdict] = TTLCache(3600)
    cache.put("cached-block.test", Verdict.BLOCK)
    owner = OwnerList("bad.test", "cached-block.test")
    engine = DecisionEngine(frozenset({"example.org"}), frozenset({"bad.test"}), cache, owner_allowed=owner)
    for name in ("bad.test", "cached-block.test"):
        decision = engine.decide(name)
        assert (decision.verdict, decision.reason, decision.matched) == (Verdict.ALLOW, Reason.OWNER, name)
    owner.domains.clear()  # blocked again
    assert engine.decide("bad.test").reason is Reason.BLACKLIST
    assert engine.decide("cached-block.test").verdict is Verdict.BLOCK


def test_whitelist_is_still_checked_first() -> None:
    engine = DecisionEngine(frozenset({"example.org"}), frozenset(), owner_allowed=OwnerList("example.org"))
    assert engine.decide("example.org").reason is Reason.WHITELIST


def test_a_broken_owner_list_changes_nothing() -> None:
    class Broken:
        def match(self, domain: str) -> str | None:
            raise RuntimeError("boom")

    engine = DecisionEngine(frozenset(), frozenset({"bad.test"}), owner_allowed=Broken())
    assert engine.decide("bad.test").reason is Reason.BLACKLIST
