"""Tests for the rule-based brand look-alike check."""

from __future__ import annotations

import pytest

from config import settings
from dns_server.domain import InvalidDomainError
from ml.lookalike import LookalikeChecker, osa_distance, skeleton


@pytest.fixture(scope="module")
def checker() -> LookalikeChecker:
    return LookalikeChecker(
        brands=frozenset({"absher", "alrajhi", "tawakkalna", "snb"}),
        whitelist=frozenset({"absher.sa", "alrajhibank.com.sa"}),
    )


def technique(checker: LookalikeChecker, host: str) -> str | None:
    match = checker.check(host)
    return match.technique if match else None


def test_osa_distance_counts_a_swap_as_one_edit() -> None:
    assert osa_distance("absher", "absher") == 0
    assert osa_distance("abhser", "absher") == 1  # swap
    assert osa_distance("asher", "absher") == 1  # omission
    assert osa_distance("abshher", "absher") == 1  # insertion
    assert osa_distance("", "abc") == 3


def test_skeleton_maps_look_alike_characters() -> None:
    assert skeleton("4bsh3r") == skeleton("absher")
    assert skeleton("аbsher") == skeleton("absher")  # Cyrillic а
    assert skeleton("rnoi") == skeleton("mol")
    assert skeleton("vvave") == skeleton("wave")


@pytest.mark.parametrize("host", ["absher.sa", "www.absher.sa", "alrajhibank.com.sa", "online.alrajhibank.com.sa"])
def test_official_domains_are_exempt(checker: LookalikeChecker, host: str) -> None:
    assert checker.check(host) is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("absher.com", "brand_name"),  # another suffix
        ("absher-sa.com", "brand_name"),  # combosquat
        ("absher.sa.verify-id.com", "brand_name"),  # brand as a subdomain label
        ("ab-sher.net", "hyphenation"),
        ("4bsher.com", "homoglyph"),  # digit
        ("xn--bsher-3ve.com", "homoglyph"),  # Cyrillic а in punycode
        ("abhser.com", "typo"),  # swap
        ("abshr.co", "typo"),  # omission
        ("myabsherportal.com", "contains"),
        ("alrajhi-bank.net", "brand_name"),
        ("tawakalna.info", "typo"),
    ],
)
def test_look_alikes_are_caught(checker: LookalikeChecker, host: str, expected: str) -> None:
    assert technique(checker, host) == expected


@pytest.mark.parametrize("host", ["google.com", "riyadh.com", "abs.com", "sabbir.org"])
def test_unrelated_or_distant_names_are_not_flagged(checker: LookalikeChecker, host: str) -> None:
    assert checker.check(host) is None


def test_brand_on_an_unofficial_suffix_of_the_official_name_is_flagged(checker: LookalikeChecker) -> None:
    # alrajhibank.com.sa is official; alrajhibank.com is not.
    assert technique(checker, "alrajhibank.com") == "contains"


def test_short_brands_match_whole_words_only(checker: LookalikeChecker) -> None:
    assert technique(checker, "snb-login.com") == "brand_name"
    assert technique(checker, "5nb.com") == "homoglyph"
    assert checker.check("snbx.com") is None  # no fuzzy match on 3 letters
    assert checker.check("asnbc.com") is None  # no substring match on 3 letters


def test_matching_is_on_label_boundaries(checker: LookalikeChecker) -> None:
    # The suffix is never compared, and a whitelisted name only exempts itself
    # and its subdomains, not names that merely end with the same text.
    assert technique(checker, "fakeabsher.sa") == "contains"
    assert checker.check("absher.sa") is None


def test_invalid_names_raise(checker: LookalikeChecker) -> None:
    with pytest.raises(InvalidDomainError):
        checker.check("bad name.com")


def test_checker_loads_the_shipped_lists() -> None:
    checker = LookalikeChecker.from_files(settings.brands_path, settings.whitelist_path)
    assert checker.check("absher.sa") is None
    assert checker.check("absher-sa.com") is not None
    # Al Rajhi group sites are official, but look-alikes of them are not.
    for host in ("alrajhitakaful.com", "www.alrajhitadawul.com.sa", "alrajhi-capital.sa"):
        assert checker.check(host) is None
    assert checker.check("alrajhi-capital.com") is not None
    for host in ("iam.gov.sa", "www.iam.gov.sa", "my.gov.sa", "ta.sdaia.gov.sa"):
        assert checker.check(host) is None
    assert checker.check("nafath-iam.com") is not None
    assert checker.check("tawakkalna.sdaia-gov.com") is not None


def test_similarity_survives_swaps_and_hyphens(checker: LookalikeChecker) -> None:
    assert checker.similarity("abhser.com") == pytest.approx(1 - 1 / 6)
    assert checker.similarity("ab-sher.com") == 1.0
    assert checker.similarity("absher.com") == 1.0
    assert checker.similarity("google.com") < 0.5


def test_similarity_is_zero_on_official_domains(checker: LookalikeChecker) -> None:
    assert checker.similarity("absher.sa") == 0.0
    assert checker.similarity("www.absher.sa") == 0.0
