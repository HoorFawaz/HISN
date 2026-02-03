"""Tests for domain validation, normalization and label-boundary matching."""

from __future__ import annotations

import pytest

from dns_server.domain import (
    InvalidDomainError,
    name_from_labels,
    normalize_domain,
    parent_domains,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("ABSHER.gov.SA.", "absher.gov.sa"),
        ("a-b.example.com", "a-b.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("localhost", "localhost"),
    ],
)
def test_normalize_accepts_valid_names(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "..",
        "a..b.com",
        ".example.com",
        "-bad.example.com",
        "bad-.example.com",
        "exa mple.com",
        "exa/mple.com",
        "example.com/path",
        "user@example.com",
        "münchen.de",  # non-ASCII must arrive as punycode
        "xn--.com",  # not valid punycode
        "a" * 64 + ".com",  # label too long
        ".".join(["a" * 60] * 5),  # whole name too long
        "exa\x00mple.com",
        "exa\nmple.com",
    ],
)
def test_normalize_rejects_invalid_names(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


def test_normalize_accepts_maximum_lengths() -> None:
    label = "a" * 63
    assert normalize_domain(label + ".com") == label + ".com"
    # 253 characters in total is the legal maximum.
    name = ".".join(["a" * 61] * 4) + "." + "b" * 5
    assert len(name) == 253
    assert normalize_domain(name) == name


def test_normalize_rejects_non_string() -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(b"example.com")  # type: ignore[arg-type]


def test_name_from_labels_joins_labels() -> None:
    assert name_from_labels((b"www", b"Example", b"com")) == "www.Example.com"


def test_name_from_labels_rejects_dot_inside_label() -> None:
    # On the wire this is a different name than "x.absher.gov.sa".
    with pytest.raises(InvalidDomainError):
        name_from_labels((b"x.absher", b"gov", b"sa"))


def test_name_from_labels_rejects_non_ascii() -> None:
    with pytest.raises(InvalidDomainError):
        name_from_labels((b"\xc3\xa9", b"com"))


def test_parent_domains_walks_label_boundaries() -> None:
    assert list(parent_domains("a.b.example.com")) == [
        "a.b.example.com",
        "b.example.com",
        "example.com",
        "com",
    ]
    assert list(parent_domains("com")) == ["com"]
    assert list(parent_domains("")) == []
