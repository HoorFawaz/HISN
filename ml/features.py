"""Turn a domain name into numeric features for the model.

Everything here is computed from the domain name alone: no network access and
no lookups, so one call takes well under a millisecond (the DNS decision has to
be fast). The same code runs when the dataset is built, when the model is
trained and when the DNS server asks for a verdict, so the three always agree.

Public parts of a name are split with the bundled Public Suffix List
(``tldextract``), configured so that it never downloads anything:

    bank.verify.account.example.com.sa
    |___________________| |_____| |____|
        subdomain        main     suffix  (the "TLD", may have two parts)

"Main label" below means the registrable name (``example`` here).
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

import tldextract

from dns_server.decision import load_domain_list
from dns_server.domain import normalize_domain, parent_domains

# Words that phishing hosts like to contain (checked as substrings of the host).
KEYWORDS: tuple[str, ...] = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "confirm",
    "password",
)

# Suffixes that get their own 0/1 feature. Everything else becomes "tld_other".
# The list is fixed in code (not learned) so training and serving always use
# exactly the same columns. It mixes the Saudi suffixes we care about with
# common generic ones, including cheap ones that are often abused.
TLD_VOCAB: tuple[str, ...] = (
    "com", "net", "org", "info", "io", "co", "me", "cc", "ru", "cn",
    "xyz", "top", "site", "online", "club", "icu", "tk", "ml", "ga", "cf", "gq",
    "sa", "com.sa", "gov.sa", "edu.sa", "org.sa", "net.sa", "med.sa",
)  # fmt: skip

# Brand matching knobs. Short brands only match as a whole word: a fuzzy or
# "contains" match on a 3-letter name would fire on thousands of innocent hosts.
MIN_FUZZY_BRAND_LEN = 6
MIN_TOKEN_LEN = 3
MAX_LENGTH_GAP = 3  # skip distance maths for tokens whose length differs a lot

# Look-alike digits: "paypa1" -> "paypal", "absh3r" -> "absher".
_LEET = str.maketrans("013457", "oleast")

# The offline extractor: no suffix-list download, no disk cache.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def _tld_feature_name(tld: str) -> str:
    return "tld_" + tld.replace(".", "_")


_BASE_FEATURES: tuple[str, ...] = (
    "length",
    "main_label_length",
    "hyphen_count",
    "digit_count",
    "digit_ratio_main",
    "subdomain_levels",
    "keyword_count",
    "entropy_main",
    "has_punycode",
    "tld_known",
    "tld_length",
)
_BRAND_FEATURES: tuple[str, ...] = (
    "brand_exact_token",
    "brand_contained",
    "brand_fuzzy_match",
    "brand_similarity",
    "brand_impersonation",
    "gov_label_misplaced",
)
FEATURE_NAMES: tuple[str, ...] = (
    _BASE_FEATURES
    + tuple(_tld_feature_name(tld) for tld in TLD_VOCAB)
    + ("tld_other",)
    + _BRAND_FEATURES
)


def shannon_entropy(text: str) -> float:
    """Entropy in bits per character. 0 for repeated letters, higher if random-looking."""
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values())


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (insert, delete or replace one character = 1)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,  # delete
                    current[j - 1] + 1,  # insert
                    previous[j - 1] + (char_a != char_b),  # replace
                )
            )
        previous = current
    return previous[-1]


def _fuzzy_allowance(brand: str) -> int:
    """How many edits still count as "the same brand" (longer names tolerate more)."""
    return 1 if len(brand) < 9 else 2


class FeatureExtractor:
    """Computes the feature dictionary or vector for a hostname.

    ``brands`` are lowercase brand names (``brands.txt``). ``whitelist`` holds
    the official domains: a brand-like name is only "impersonation" when the
    host is NOT one of them (matched on label boundaries, never by "contains").
    Instances are immutable, so one can be shared between threads.
    """

    def __init__(self, brands: frozenset[str], whitelist: frozenset[str]) -> None:
        self._brands = tuple(sorted(brands))
        self._whitelist = whitelist

    @classmethod
    def from_files(cls, brands_path: Path, whitelist_path: Path) -> FeatureExtractor:
        return cls(load_domain_list(brands_path), load_domain_list(whitelist_path))

    # ----- public API -----

    def extract(self, host: str) -> dict[str, float]:
        """Return ``{feature name: value}`` for ``host`` (validated and normalized first)."""
        host = normalize_domain(host)
        subdomain, main, suffix, suffix_known = split_host(host)
        labels = [*subdomain, main]
        tokens = [token for label in labels for token in label.split("-") if token]

        features: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)
        features["length"] = len(host)
        features["main_label_length"] = len(main)
        features["hyphen_count"] = host.count("-")
        features["digit_count"] = sum(char.isdigit() for char in host)
        features["digit_ratio_main"] = (
            sum(char.isdigit() for char in main) / len(main) if main else 0.0
        )
        features["subdomain_levels"] = len(subdomain)
        features["keyword_count"] = sum(host.count(word) for word in KEYWORDS)
        features["entropy_main"] = shannon_entropy(main)
        features["has_punycode"] = float(any(label.startswith("xn--") for label in host.split(".")))
        features["tld_known"] = float(suffix_known)
        features["tld_length"] = len(suffix)
        features[_tld_feature_name(suffix) if suffix in TLD_VOCAB else "tld_other"] = 1.0

        exact, contained, fuzzy, similarity = self._brand_signals(tokens)
        features["brand_exact_token"] = float(exact)
        features["brand_contained"] = float(contained)
        features["brand_fuzzy_match"] = float(fuzzy)
        features["brand_similarity"] = similarity
        brand_like = exact or contained or fuzzy
        features["brand_impersonation"] = float(brand_like and not self._is_official(host))
        # "gov" outside the real suffix, as in absher.gov.sa.fake-login.com
        features["gov_label_misplaced"] = float("gov" in tokens)
        return features

    def vector(self, host: str) -> list[float]:
        """Same values as :meth:`extract`, in the fixed ``FEATURE_NAMES`` order."""
        values = self.extract(host)
        return [values[name] for name in FEATURE_NAMES]

    # ----- internals -----

    def _is_official(self, host: str) -> bool:
        """True if ``host`` is a whitelisted domain or a subdomain of one."""
        return any(candidate in self._whitelist for candidate in parent_domains(host))

    def _brand_signals(self, tokens: list[str]) -> tuple[bool, bool, bool, float]:
        """Compare every word of the name with every brand.

        Returns (exact word match, brand inside a longer word, within a few
        edits of a brand, best similarity from 0 to 1).
        """
        exact = contained = fuzzy = False
        similarity = 0.0
        for token in tokens:
            if len(token) < MIN_TOKEN_LEN:
                continue
            # Compare the word as written and with look-alike digits fixed.
            for variant in {token, token.translate(_LEET)}:
                for brand in self._brands:
                    if variant == brand:
                        if variant == token:
                            exact = True
                            similarity = 1.0
                        else:  # only equal after fixing digits: "paypa1" -> "paypal"
                            fuzzy = True
                            similarity = max(similarity, 0.99)
                        continue
                    if len(brand) < MIN_FUZZY_BRAND_LEN:
                        continue
                    if brand in variant:
                        contained = True
                        similarity = max(similarity, len(brand) / len(variant))
                        continue
                    if abs(len(variant) - len(brand)) > MAX_LENGTH_GAP:
                        continue
                    distance = edit_distance(variant, brand)
                    similarity = max(similarity, 1 - distance / max(len(variant), len(brand)))
                    if distance <= _fuzzy_allowance(brand):
                        fuzzy = True
        return exact, contained, fuzzy, similarity


def split_host(host: str) -> tuple[list[str], str, str, bool]:
    """Split ``host`` into (subdomain labels, main label, suffix, suffix is known).

    An unknown suffix (a TLD missing from the bundled list) is not an error:
    the last label is used as the suffix and the flag is False.
    """
    parts = _EXTRACT(host)
    subdomain = [label for label in parts.subdomain.split(".") if label]
    if parts.suffix:
        return subdomain, parts.domain, parts.suffix, True
    labels = host.split(".")
    if len(labels) < 2:
        return [], host, "", False
    return labels[:-2], labels[-2], labels[-1], False


def registered_domain(host: str) -> str:
    """The name someone can register, e.g. ``example.com.sa`` for ``a.b.example.com.sa``.

    Used to group hosts that belong to the same owner (for the train/test split
    and for removing overlap between the benign and malicious sets).
    """
    _, main, suffix, _ = split_host(host)
    if not main:
        return suffix  # the host is itself a public suffix such as "co.uk"
    return f"{main}.{suffix}" if suffix else main
