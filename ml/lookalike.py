"""Deterministic look-alike check against the brand list.

The phishing feeds are mostly random-looking names (``4549djffj.xyz``), so a
model trained on them alone does not learn that ``absher-sa.com`` or
``abhser.com`` imitate Absher. This module catches those cases with plain
rules, independent of the model:

1. The official domains (``whitelist.txt``) and their subdomains are exempt.
2. Every label of the host except the public suffix is split into words on
   ``-``. The label with its hyphens removed is checked too (``ab-sher``).
3. Each word is reduced to a "skeleton": characters that look alike are
   mapped to one form (``0`` -> ``o``, ``rn`` -> ``m``, Cyrillic ``а`` -> ``a``,
   ``i``/``l``/``1`` -> ``l``). Punycode labels are decoded first.
4. A word matches a brand when it is the brand, has the same skeleton, contains
   the brand, or is within a small edit distance of it (an adjacent swap counts
   as one edit). Short brands (fewer than ``MIN_FUZZY_BRAND_LEN`` letters) only
   match as a whole word, because fuzzy matching on 3 letters fires on
   thousands of innocent names.

Matching is on label and word boundaries, never on raw substrings of the host,
so ``absher.sa.example.com`` matches (``absher`` is a whole label) while the
real ``absher.sa`` does not (it is whitelisted).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dns_server.decision import load_domain_list
from dns_server.domain import normalize_domain, parent_domains
from ml.features import MAX_LENGTH_GAP, MIN_FUZZY_BRAND_LEN, fuzzy_allowance, split_host

# Unicode letters that render like Latin ones (Cyrillic and Greek). Only the
# common cases: enough for IDN homograph tricks such as "аbsher" with a
# Cyrillic "а". Also used by the typosquat generator.
CONFUSABLES: dict[str, str] = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɑ": "a",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
}  # fmt: skip

# Digits that read as letters.
DIGIT_LOOKALIKES: dict[str, str] = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}

# Letter sequences that read as another letter. Applied after the maps above.
SEQUENCE_LOOKALIKES: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"), ("i", "l"))

_CHAR_MAP = str.maketrans({**CONFUSABLES, **DIGIT_LOOKALIKES})


def skeleton(text: str) -> str:
    """Map look-alike characters to one form so "abs4er", "аbsher" and "absher" compare equal."""
    result = text.lower().translate(_CHAR_MAP)
    for sequence, replacement in SEQUENCE_LOOKALIKES:
        result = result.replace(sequence, replacement)
    return result


def osa_distance(a: str, b: str) -> int:
    """Edit distance where swapping two neighbouring characters also costs 1.

    Plain Levenshtein counts "abhser" as two edits from "absher"; typing two
    letters in the wrong order is one mistake, so it should count as one.
    """
    rows, cols = len(a) + 1, len(b) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = a[i - 1] != b[j - 1]
            table[i][j] = min(
                table[i - 1][j] + 1,  # delete
                table[i][j - 1] + 1,  # insert
                table[i - 1][j - 1] + cost,  # replace
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                table[i][j] = min(table[i][j], table[i - 2][j - 2] + 1)  # swap
    return table[-1][-1]


def decode_label(label: str) -> str:
    """Return the Unicode form of a punycode label, or the label itself."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


@dataclass(frozen=True)
class LookalikeMatch:
    """Why a host looks like a brand.

    ``technique`` is one of: ``brand_name`` (the exact brand on a domain that is
    not official), ``hyphenation`` (the brand split by hyphens), ``homoglyph``
    (equal after mapping look-alike characters), ``contains`` (the brand inside
    a longer word) or ``typo`` (a few edits away).
    """

    brand: str
    technique: str
    word: str
    distance: int


# Lower rank = stronger evidence. Used to pick one match when several apply.
_RANK = {"brand_name": 0, "hyphenation": 1, "homoglyph": 2, "contains": 3, "typo": 4}


class LookalikeChecker:
    """Rule-based brand look-alike detector. Immutable and thread-safe."""

    def __init__(self, brands: frozenset[str], whitelist: frozenset[str]) -> None:
        self._brands = tuple(sorted((brand, skeleton(brand)) for brand in brands))
        self._whitelist = whitelist

    @classmethod
    def from_files(cls, brands_path: Path, whitelist_path: Path) -> LookalikeChecker:
        return cls(load_domain_list(brands_path), load_domain_list(whitelist_path))

    def is_official(self, host: str) -> bool:
        return any(candidate in self._whitelist for candidate in parent_domains(host))

    def check(self, host: str) -> LookalikeMatch | None:
        """Return the strongest brand match for ``host``, or None.

        ``host`` is validated first, so invalid input raises
        :class:`dns_server.domain.InvalidDomainError` instead of being scored.
        """
        host = normalize_domain(host)
        if self.is_official(host):
            return None
        subdomain, main, _, _ = split_host(host)
        best: LookalikeMatch | None = None
        for label in [*subdomain, main]:
            for word, joined in _words(decode_label(label)):
                match = self._match_word(word, joined)
                if match is not None and (best is None or _key(match) < _key(best)):
                    best = match
        return best

    def similarity(self, host: str) -> float:
        """Best similarity (0 to 1) between a label of ``host`` and a brand.

        Each label is compared without hyphens and as a skeleton, with a swap
        counting as one edit, so "al-inma", "ailnma" and "alinma" all score
        high. Official domains score 0: looking like a brand is only
        suspicious when the name is not the brand's own.
        """
        host = normalize_domain(host)
        if self.is_official(host):
            return 0.0
        subdomain, main, _, _ = split_host(host)
        best = 0.0
        for label in [*subdomain, main]:
            word = skeleton(decode_label(label).replace("-", ""))
            for _, brand_skeleton in self._brands:
                longest = max(len(word), len(brand_skeleton))
                if not longest or abs(len(word) - len(brand_skeleton)) > MAX_LENGTH_GAP:
                    continue
                best = max(best, 1 - osa_distance(word, brand_skeleton) / longest)
        return best

    def _match_word(self, word: str, joined: bool) -> LookalikeMatch | None:
        word_skeleton = skeleton(word)
        best: LookalikeMatch | None = None
        for brand, brand_skeleton in self._brands:
            match: LookalikeMatch | None = None
            if word == brand:
                match = LookalikeMatch(brand, "hyphenation" if joined else "brand_name", word, 0)
            elif word_skeleton == brand_skeleton:
                match = LookalikeMatch(brand, "homoglyph", word, 0)
            elif len(brand) >= MIN_FUZZY_BRAND_LEN:
                if brand_skeleton in word_skeleton:
                    match = LookalikeMatch(brand, "contains", word, len(word_skeleton) - len(brand_skeleton))
                elif abs(len(word_skeleton) - len(brand_skeleton)) <= fuzzy_allowance(brand):
                    distance = osa_distance(word_skeleton, brand_skeleton)
                    if distance <= fuzzy_allowance(brand):
                        match = LookalikeMatch(brand, "typo", word, distance)
            if match is not None and (best is None or _key(match) < _key(best)):
                best = match
        return best


def _key(match: LookalikeMatch) -> tuple[int, int, str]:
    return _RANK[match.technique], match.distance, match.brand


def _words(label: str) -> list[tuple[str, bool]]:
    """Words of a label: each hyphen-separated part, plus the whole label without hyphens.

    The flag is True for the joined form, so "ab-sher" is reported as hyphenation.
    """
    words = [(part, False) for part in label.split("-") if part]
    if "-" in label:
        words.append((label.replace("-", ""), True))
    return words
