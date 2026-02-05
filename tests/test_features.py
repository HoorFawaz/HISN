"""Tests for domain-name features (brand, TLD and government cases included)."""

from __future__ import annotations

import math
import socket

import pytest

from config import settings
from dns_server.domain import InvalidDomainError
from ml.features import (
    FEATURE_NAMES,
    FeatureExtractor,
    edit_distance,
    shannon_entropy,
)


@pytest.fixture(scope="module")
def fx() -> FeatureExtractor:
    return FeatureExtractor(
        brands=frozenset({"absher", "paypal", "alrajhi", "tawakkalna", "snb"}),
        whitelist=frozenset({"absher.sa", "alrajhibank.com.sa"}),
    )


# ----- helper maths -----


def test_edit_distance_basics() -> None:
    assert edit_distance("absher", "absher") == 0
    assert edit_distance("paypal", "paypa1") == 1  # replace
    assert edit_distance("absher", "abshr") == 1  # delete
    assert edit_distance("absher", "abssher") == 1  # insert
    assert edit_distance("", "abc") == 3
    assert edit_distance("kitten", "sitting") == 3


def test_entropy_is_low_for_repeats_and_high_for_random_looking() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)
    assert shannon_entropy("x7k2q9zv4m") > shannon_entropy("google")


# ----- basic shape -----


def test_vector_matches_feature_names_and_is_finite(fx: FeatureExtractor) -> None:
    vector = fx.vector("www.example.com")
    assert len(vector) == len(FEATURE_NAMES)
    assert all(math.isfinite(value) for value in vector)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)  # no duplicate column names


def test_extract_is_deterministic(fx: FeatureExtractor) -> None:
    assert fx.extract("Login.Example.COM.") == fx.extract("login.example.com")


def test_invalid_names_are_rejected_not_scored(fx: FeatureExtractor) -> None:
    with pytest.raises(InvalidDomainError):
        fx.extract("-bad-.example")


def test_counts_for_a_plain_host(fx: FeatureExtractor) -> None:
    f = fx.extract("my-site-24.example.com")
    assert f["length"] == len("my-site-24.example.com")
    assert f["main_label_length"] == len("example")
    assert f["hyphen_count"] == 2
    assert f["digit_count"] == 2
    assert f["subdomain_levels"] == 0 + 1  # "my-site-24" is one subdomain level
    assert f["digit_ratio_main"] == 0.0


def test_subdomain_levels_and_keywords(fx: FeatureExtractor) -> None:
    f = fx.extract("bank.verify.account.example.com")
    assert f["subdomain_levels"] == 3
    assert f["keyword_count"] == 2  # verify, account
    assert f["main_label_length"] == len("example")


def test_punycode_flag(fx: FeatureExtractor) -> None:
    assert fx.extract("xn--80ak6aa92e.com")["has_punycode"] == 1.0
    assert fx.extract("example.com")["has_punycode"] == 0.0


# ----- TLD handling -----


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", "tld_com"),
        ("example.xyz", "tld_xyz"),
        ("example.top", "tld_top"),
        ("example.sa", "tld_sa"),
        ("example.com.sa", "tld_com_sa"),
        ("moh.gov.sa", "tld_gov_sa"),
        ("example.museum", "tld_other"),
    ],
)
def test_exactly_one_tld_feature_is_set(fx: FeatureExtractor, host: str, expected: str) -> None:
    f = fx.extract(host)
    set_tlds = {name for name in FEATURE_NAMES if name.startswith("tld_") and f[name] == 1.0}
    set_tlds -= {"tld_known"}
    assert set_tlds == {expected}


def test_gov_sa_is_one_suffix_not_sa(fx: FeatureExtractor) -> None:
    f = fx.extract("moh.gov.sa")
    assert f["tld_gov_sa"] == 1.0
    assert f["tld_sa"] == 0.0
    assert f["tld_length"] == len("gov.sa")
    assert f["main_label_length"] == len("moh")


def test_unknown_suffix_is_flagged_not_known(fx: FeatureExtractor) -> None:
    f = fx.extract("example.notarealtld")
    assert f["tld_known"] == 0.0
    assert f["tld_other"] == 1.0
    assert f["main_label_length"] == len("example")  # last label treated as the suffix


def test_free_hosting_platform_name_is_the_main_label(fx: FeatureExtractor) -> None:
    # The attacker-chosen part of x.github.io is "x", not "github".
    f = fx.extract("secure-login-absher.github.io")
    assert f["main_label_length"] == len("secure-login-absher")
    assert f["subdomain_levels"] == 0


# ----- brand and government impersonation -----


def test_official_domain_is_not_impersonation(fx: FeatureExtractor) -> None:
    f = fx.extract("absher.sa")
    assert f["brand_exact_token"] == 1.0
    assert f["brand_impersonation"] == 0.0


def test_official_subdomain_is_not_impersonation(fx: FeatureExtractor) -> None:
    assert fx.extract("www.absher.sa")["brand_impersonation"] == 0.0
    assert fx.extract("online.alrajhibank.com.sa")["brand_impersonation"] == 0.0


def test_brand_name_on_another_domain_is_impersonation(fx: FeatureExtractor) -> None:
    f = fx.extract("absher.com")
    assert f["brand_exact_token"] == 1.0
    assert f["brand_impersonation"] == 1.0


def test_hyphenated_brand_is_impersonation(fx: FeatureExtractor) -> None:
    f = fx.extract("absher-sa.com")
    assert f["brand_exact_token"] == 1.0
    assert f["brand_impersonation"] == 1.0


def test_brand_inside_a_longer_word_is_impersonation(fx: FeatureExtractor) -> None:
    f = fx.extract("alrajhibank-login.top")
    assert f["brand_contained"] == 1.0
    assert f["brand_impersonation"] == 1.0


def test_official_domain_containing_the_brand_is_not_impersonation(fx: FeatureExtractor) -> None:
    f = fx.extract("alrajhibank.com.sa")
    assert f["brand_contained"] == 1.0
    assert f["brand_impersonation"] == 0.0


def test_typosquat_is_caught_by_edit_distance(fx: FeatureExtractor) -> None:
    f = fx.extract("abshar.com")  # one letter off
    assert f["brand_exact_token"] == 0.0
    assert f["brand_fuzzy_match"] == 1.0
    assert f["brand_impersonation"] == 1.0
    assert f["brand_similarity"] > 0.8


@pytest.mark.parametrize("host", ["paypa1.com", "absh3r.xyz", "p4ypal.net"])
def test_look_alike_digits_are_caught(fx: FeatureExtractor, host: str) -> None:
    f = fx.extract(host)
    assert f["brand_fuzzy_match"] == 1.0
    assert f["brand_impersonation"] == 1.0


def test_unrelated_names_do_not_look_like_brands(fx: FeatureExtractor) -> None:
    for host in ("google.com", "weather.org", "university.edu.sa", "tabshare.net"):
        f = fx.extract(host)
        assert f["brand_impersonation"] == 0.0, host


def test_short_brands_match_whole_words_only(fx: FeatureExtractor) -> None:
    # "snb" has 3 letters: it matches the word "snb" but never inside other words.
    assert fx.extract("snb-login.com")["brand_exact_token"] == 1.0
    assert fx.extract("snbank.com")["brand_impersonation"] == 0.0
    assert fx.extract("sunbeam.com")["brand_impersonation"] == 0.0


def test_fake_government_subdomain_trick(fx: FeatureExtractor) -> None:
    # The brief's test case: must not look official.
    f = fx.extract("absher.gov.sa.fake-login.com")
    assert f["gov_label_misplaced"] == 1.0
    assert f["brand_impersonation"] == 1.0
    assert f["subdomain_levels"] == 3
    assert f["keyword_count"] == 1
    assert f["tld_com"] == 1.0


def test_real_government_domain_has_no_misplaced_gov(fx: FeatureExtractor) -> None:
    f = fx.extract("moh.gov.sa")
    assert f["gov_label_misplaced"] == 0.0
    assert f["tld_gov_sa"] == 1.0


def test_whitelist_is_matched_on_label_boundaries_only(fx: FeatureExtractor) -> None:
    assert fx.extract("absher.sa.evil.com")["brand_impersonation"] == 1.0
    assert fx.extract("notabsher.sa")["brand_impersonation"] == 1.0  # contains, but not official


# ----- shipped data -----


def test_extractor_loads_the_shipped_lists() -> None:
    fx = FeatureExtractor.from_files(settings.brands_path, settings.whitelist_path)
    assert fx.extract("absher.sa")["brand_impersonation"] == 0.0
    assert fx.extract("absher-sa.com")["brand_impersonation"] == 1.0
    assert fx.extract("alrajhibank.com.sa")["brand_impersonation"] == 0.0


# ----- privacy / speed guarantees -----


def test_feature_extraction_never_touches_the_network(
    fx: FeatureExtractor, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("feature extraction tried to use the network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    fx.vector("some-new-name.example.org")


@pytest.mark.parametrize(
    ("host", "feature", "min_similarity"),
    [
        ("abhser.com", "lookalike_typo", 0.8),  # swap: two edits for plain Levenshtein, one here
        ("al-rajhi.net", "lookalike_strong", 1.0),  # hyphen inside the brand
        ("absher-sa.com", "lookalike_strong", 0.7),
        ("myalrajhiportal.com", "lookalike_contains", 0.0),  # too long to compare whole
    ],
)
def test_lookalike_features(fx: FeatureExtractor, host: str, feature: str, min_similarity: float) -> None:
    values = fx.extract(host)
    assert values[feature] == 1.0
    assert values["brand_similarity_joined"] >= min_similarity


def test_lookalike_features_are_off_for_official_and_unrelated_names(fx: FeatureExtractor) -> None:
    for host in ("absher.sa", "www.alrajhibank.com.sa", "example.com"):
        values = fx.extract(host)
        assert values["lookalike_strong"] == values["lookalike_typo"] == values["lookalike_contains"] == 0.0
    assert fx.extract("absher.sa")["brand_similarity_joined"] == 0.0
