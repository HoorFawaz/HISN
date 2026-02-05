"""Generate synthetic look-alike domains of the protected brands.

Why: the phishing feeds are mostly random-looking names, so they contain almost
no examples of names that imitate Saudi government or bank brands. Without
such examples the model never learns that ``abhser.com`` is dangerous. These
generated names are added to training as malicious examples, and a held-out
part of them measures how well the model catches look-alikes.

Techniques (one per generated name):

    omission       one letter left out          absher -> asher
    transposition  two neighbours swapped       absher -> abhser
    homoglyph      a letter that looks the same absher -> аbsher (Cyrillic а, punycode)
    digit          a digit that looks the same  absher -> 4bsher
    hyphenation    a hyphen inside the name     absher -> ab-sher
    combosquat     brand plus a common word     absher -> absher-sa, login-absher
    tld_swap       the brand on another suffix  absher.sa -> absher.com

Typos are only made for brands with at least ``MIN_FUZZY_BRAND_LEN`` letters,
matching the feature and rule thresholds: one typo of a 3-letter name is just
another short word. Generated names that fall under an official domain are
dropped. They are labels we invented, not observed attacks; see
``docs/limitations.md``.
"""

from __future__ import annotations

import math
import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from dns_server.domain import InvalidDomainError, normalize_domain, parent_domains
from ml.features import MIN_FUZZY_BRAND_LEN, split_host
from ml.lookalike import CONFUSABLES, DIGIT_LOOKALIKES

TECHNIQUES: tuple[str, ...] = (
    "omission",
    "transposition",
    "homoglyph",
    "digit",
    "hyphenation",
    "combosquat",
    "tld_swap",
)

DEFAULT_PER_TECHNIQUE = 16  # names per (brand, technique); see generate()

# Suffixes attackers commonly register look-alikes under.
SUFFIXES: tuple[str, ...] = ("com", "net", "org", "info", "online", "site", "xyz", "top", "co", "sa", "com.sa")

# Words glued to a brand in combosquats (absher-sa.com, absher-login.com).
COMBO_WORDS: tuple[str, ...] = ("sa", "ksa", "gov", "login", "online", "service", "portal", "verify", "update", "pay")

# ASCII letter groups that read as another letter (reverse of the skeleton map).
_ASCII_HOMOGLYPHS: dict[str, tuple[str, ...]] = {"m": ("rn",), "w": ("vv",), "l": ("i", "1"), "i": ("l",)}
_UNICODE_HOMOGLYPHS: dict[str, tuple[str, ...]] = {}
for _fake, _real in CONFUSABLES.items():
    _UNICODE_HOMOGLYPHS.setdefault(_real, ())
    _UNICODE_HOMOGLYPHS[_real] += (_fake,)
_DIGITS: dict[str, str] = {letter: digit for digit, letter in DIGIT_LOOKALIKES.items()}
_DIGITS["i"] = "1"


@dataclass(frozen=True)
class SyntheticDomain:
    host: str
    brand: str
    technique: str


def _omissions(brand: str) -> set[str]:
    return {brand[:i] + brand[i + 1 :] for i in range(len(brand))}


def _transpositions(brand: str) -> set[str]:
    return {
        brand[:i] + brand[i + 1] + brand[i] + brand[i + 2 :]
        for i in range(len(brand) - 1)
        if brand[i] != brand[i + 1]
    }


def _homoglyphs(brand: str) -> set[str]:
    labels: set[str] = set()
    for i, char in enumerate(brand):
        for fake in _ASCII_HOMOGLYPHS.get(char, ()):
            labels.add(brand[:i] + fake + brand[i + 1 :])
        for fake in _UNICODE_HOMOGLYPHS.get(char, ()):
            unicode_label = brand[:i] + fake + brand[i + 1 :]
            try:
                labels.add(unicode_label.encode("idna").decode("ascii"))
            except UnicodeError:
                continue
    return labels


def _digits(brand: str) -> set[str]:
    return {brand[:i] + _DIGITS[char] + brand[i + 1 :] for i, char in enumerate(brand) if char in _DIGITS}


def _hyphenations(brand: str) -> set[str]:
    return {brand[:i] + "-" + brand[i:] for i in range(2, len(brand) - 1)}


def _combosquats(brand: str) -> set[str]:
    return {f"{brand}-{word}" for word in COMBO_WORDS} | {f"{word}-{brand}" for word in COMBO_WORDS}


def generate(
    brands: Iterable[str],
    whitelist: frozenset[str],
    *,
    per_technique: int = DEFAULT_PER_TECHNIQUE,
    seed: int = 42,
) -> list[SyntheticDomain]:
    """Return look-alike hosts for every brand, sorted and without duplicates.

    Every (brand, technique) pair gets up to ``per_technique`` names, so each
    trick carries about the same weight in training. Without this, combosquats
    (20 word combinations) would outnumber swaps and hyphens (a handful each),
    and the model would learn the common tricks only. A technique with few
    labels pairs each one with more suffixes; one with many is sampled down.
    Hosts on an official domain (or a brand's own name in any technique but
    ``tld_swap``) are dropped.
    """
    if per_technique < 1:
        raise ValueError("per_technique must be at least 1")
    rng = random.Random(seed)
    found: dict[str, SyntheticDomain] = {}

    def valid(host: str, brand: str, technique: str) -> str | None:
        try:
            host = normalize_domain(host)
        except InvalidDomainError:
            return None
        if any(candidate in whitelist for candidate in parent_domains(host)):
            return None
        if split_host(host)[1] == brand and technique != "tld_swap":
            return None  # the generator changed nothing visible in the main label
        return host

    for brand in sorted(set(brands)):
        variants: list[tuple[str, set[str]]] = [
            ("homoglyph", _homoglyphs(brand)),
            ("digit", _digits(brand)),
            ("combosquat", _combosquats(brand)),
            ("tld_swap", {brand}),
        ]
        if len(brand) >= MIN_FUZZY_BRAND_LEN:
            variants += [
                ("omission", _omissions(brand)),
                ("transposition", _transpositions(brand)),
                ("hyphenation", _hyphenations(brand)),
            ]
        for technique, labels in variants:
            labels = sorted(labels) if technique == "tld_swap" else sorted(labels - {brand})
            if not labels:
                continue
            suffix_count = min(len(SUFFIXES), max(1, math.ceil(per_technique / len(labels))))
            hosts: list[str] = []
            for label in labels:
                for suffix in rng.sample(SUFFIXES, suffix_count):
                    host = valid(f"{label}.{suffix}", brand, technique)
                    if host is not None and host not in found and host not in hosts:
                        hosts.append(host)
            if len(hosts) > per_technique:
                hosts = rng.sample(hosts, per_technique)
            for host in hosts:
                found[host] = SyntheticDomain(host, brand, technique)
    return sorted(found.values(), key=lambda item: item.host)


def split_brands(brands: Iterable[str], test_fraction: float, seed: int) -> tuple[list[str], list[str]]:
    """Split brands into (train, test) at random. Both sides get at least one brand.

    Splitting by brand (not by name) is what stops leakage: a test look-alike of
    "absher" is scored by a model that never saw any look-alike of "absher".
    """
    names = sorted(set(brands))
    if len(names) < 2:
        raise ValueError("need at least two brands to hold some out for testing")
    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be between 0 and 1")
    random.Random(seed).shuffle(names)
    count = min(len(names) - 1, max(1, round(test_fraction * len(names))))
    return sorted(names[count:]), sorted(names[:count])


def split_synthetic(
    samples: Sequence[SyntheticDomain],
    test_brands: Iterable[str],
    holdout_techniques: Iterable[str] = (),
) -> tuple[list[SyntheticDomain], list[SyntheticDomain]]:
    """Return (train, test). A sample is test if its brand or its technique is held out.

    Holding a technique out too answers "does the model catch a kind of trick
    it never saw?", not only "does it catch a brand it never saw?".
    """
    test_brand_set = set(test_brands)
    held = set(holdout_techniques)
    unknown = held - set(TECHNIQUES)
    if unknown:
        raise ValueError(f"unknown technique(s): {', '.join(sorted(unknown))}")
    train: list[SyntheticDomain] = []
    test: list[SyntheticDomain] = []
    for sample in samples:
        (test if sample.brand in test_brand_set or sample.technique in held else train).append(sample)
    return train, test
