"""Tests for the synthetic look-alike generator and its leakage-free split."""

from __future__ import annotations

import pytest

from dns_server.domain import normalize_domain
from ml.lookalike import LookalikeChecker
from ml.typosquat import TECHNIQUES, generate, split_brands, split_synthetic

BRANDS = frozenset({"absher", "alrajhi", "tawakkalna", "snb"})
WHITELIST = frozenset({"absher.sa", "alrajhibank.com.sa"})


@pytest.fixture(scope="module")
def samples():  # type: ignore[no-untyped-def]
    return generate(BRANDS, WHITELIST)


def test_every_technique_is_used(samples) -> None:  # type: ignore[no-untyped-def]
    assert {s.technique for s in samples} == set(TECHNIQUES)


def test_names_are_valid_unique_and_deterministic(samples) -> None:  # type: ignore[no-untyped-def]
    hosts = [s.host for s in samples]
    assert len(hosts) == len(set(hosts))
    assert all(normalize_domain(h) == h for h in hosts)
    assert generate(BRANDS, WHITELIST) == samples
    assert generate(BRANDS, WHITELIST, seed=7) != samples


def test_official_domains_are_never_generated(samples) -> None:  # type: ignore[no-untyped-def]
    hosts = {s.host for s in samples}
    assert "absher.sa" not in hosts
    assert "absher.com" in hosts  # same name, wrong suffix
    assert not any(h.endswith(".absher.sa") for h in hosts)


def test_short_brands_get_no_typos(samples) -> None:  # type: ignore[no-untyped-def]
    snb = {s.technique for s in samples if s.brand == "snb"}
    assert snb.isdisjoint({"omission", "transposition", "hyphenation"})
    assert "combosquat" in snb


def test_homoglyphs_include_punycode(samples) -> None:  # type: ignore[no-untyped-def]
    assert any(s.host.startswith("xn--") for s in samples if s.technique == "homoglyph")


def test_rule_catches_every_generated_name(samples) -> None:  # type: ignore[no-untyped-def]
    checker = LookalikeChecker(BRANDS, WHITELIST)
    assert [s.host for s in samples if checker.check(s.host) is None] == []


def test_brand_split_has_no_overlap() -> None:
    train, test = split_brands(BRANDS, 0.3, seed=42)
    assert set(train).isdisjoint(test)
    assert set(train) | set(test) == BRANDS
    assert train and test


def test_brand_split_needs_two_brands() -> None:
    with pytest.raises(ValueError):
        split_brands({"absher"}, 0.3, seed=42)


def test_synthetic_split_keeps_held_out_brands_and_techniques_out_of_training(samples) -> None:  # type: ignore[no-untyped-def]
    train, test = split_synthetic(samples, ["absher"], ["transposition"])
    assert len(train) + len(test) == len(samples)
    assert all(s.brand != "absher" and s.technique != "transposition" for s in train)
    assert all(s.brand == "absher" or s.technique == "transposition" for s in test)


def test_unknown_technique_is_rejected(samples) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        split_synthetic(samples, [], ["teleport"])
