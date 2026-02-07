"""Adjust the model's probability with the domain age.

Why not a model feature: only a small sample of the training names has an
age (one registry request each), and the DNS server often has none yet
either. A forest trained with a mostly empty age column either learns that
"age unknown" hints at the label, or, once that is prevented, barely sees the
age at all. Instead the forest judges the name alone, and this table moves
its probability up or down by how much more often each age range occurs in
malicious domains than in benign ones:

    odds(malicious | name, age) = odds(malicious | name) x ratio(age range)

The ratios come from the training rows that have an age. This assumes the
age says something the name does not (roughly true: the name features do not
look at dates), so the result is an approximation, not an exact probability.

Two limits keep it safe:

- An unknown age leaves the probability exactly as it was.
- Every ratio is capped at ``MAX_RATIO`` (and at least ``1 / MAX_RATIO``),
  so the age alone never blocks a name the model considers clean, and an old
  domain never fully clears a name the model considers dangerous.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# Upper bounds (in days) of the age ranges; the last range is "older than 10 years".
BUCKET_EDGES: tuple[int, ...] = (7, 30, 90, 365, 3 * 365, 10 * 365)
MAX_RATIO = 10.0
MIN_PER_CLASS = 30  # fewer known ages than this in a class: no table (age is ignored)
MIN_PER_BUCKET = 5  # an age range seen fewer times than this (both classes) stays neutral
_EPSILON = 1e-6


def bucket_of(days: float) -> int:
    """Index of the age range that ``days`` falls in."""
    for index, edge in enumerate(BUCKET_EDGES):
        if days < edge:
            return index
    return len(BUCKET_EDGES)


def bucket_labels() -> list[str]:
    """Readable names of the age ranges, for reports."""
    labels: list[str] = []
    lower = 0
    for edge in BUCKET_EDGES:
        labels.append(f"{_days_text(lower)}-{_days_text(edge)}")
        lower = edge
    labels.append(f"> {_days_text(lower)}")
    return labels


def _days_text(days: int) -> str:
    if days and days % 365 == 0:
        return f"{days // 365}y"
    return f"{days}d"


@dataclass(frozen=True)
class AgeTable:
    """How much more often each age range occurs in malicious than in benign domains."""

    ratios: tuple[float, ...]
    malicious_counts: tuple[int, ...]
    benign_counts: tuple[int, ...]

    @classmethod
    def fit(cls, malicious_days: Sequence[float], benign_days: Sequence[float]) -> AgeTable | None:
        """Learn the ratios, or return None when either class has too few ages.

        Each range gets one extra count per class (Laplace smoothing), so a
        range missing from one class gives a capped ratio instead of zero or
        infinity. A range with almost no data at all stays at 1 (no change).
        """
        if len(malicious_days) < MIN_PER_CLASS or len(benign_days) < MIN_PER_CLASS:
            return None
        size = len(BUCKET_EDGES) + 1
        malicious = [0] * size
        benign = [0] * size
        for days in malicious_days:
            malicious[bucket_of(days)] += 1
        for days in benign_days:
            benign[bucket_of(days)] += 1
        ratios = []
        for m, b in zip(malicious, benign):
            if m + b < MIN_PER_BUCKET:
                ratios.append(1.0)
                continue
            share_m = (m + 1) / (len(malicious_days) + size)
            share_b = (b + 1) / (len(benign_days) + size)
            ratios.append(min(MAX_RATIO, max(1 / MAX_RATIO, share_m / share_b)))
        return cls(tuple(ratios), tuple(malicious), tuple(benign))

    def ratio(self, days: float) -> float:
        return self.ratios[bucket_of(days)]

    def adjust(self, probability: float, days: float | None) -> float:
        """The probability after taking the age into account (unchanged when unknown)."""
        if days is None or not days >= 0:  # "not >=" also catches NaN
            return probability
        p = min(1 - _EPSILON, max(_EPSILON, probability))
        odds = p / (1 - p) * self.ratio(days)
        return odds / (1 + odds)

    def to_dict(self) -> dict[str, Any]:
        """Plain data for the model bundle (no custom classes in the pickle)."""
        return {
            "bucket_edges": list(BUCKET_EDGES),
            "ratios": list(self.ratios),
            "malicious_counts": list(self.malicious_counts),
            "benign_counts": list(self.benign_counts),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AgeTable | None:
        """Read the bundle's table. None if absent or made with other age ranges."""
        if not data or tuple(data.get("bucket_edges", ())) != BUCKET_EDGES:
            return None
        return cls(
            tuple(float(r) for r in data["ratios"]),
            tuple(int(c) for c in data["malicious_counts"]),
            tuple(int(c) for c in data["benign_counts"]),
        )
