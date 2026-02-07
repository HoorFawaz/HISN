"""Tests for the age table that adjusts the model's probability with the domain age."""

from __future__ import annotations

import pytest

from ml.age_table import BUCKET_EDGES, MAX_RATIO, MIN_PER_CLASS, AgeTable, bucket_labels, bucket_of


def table() -> AgeTable:
    young = [3.0] * 60 + [20.0] * 30 + [400.0] * 10  # most malicious domains are days old
    old = [5000.0] * 90 + [200.0] * 10  # most benign domains are years old
    fitted = AgeTable.fit(young, old)
    assert fitted is not None
    return fitted


def test_buckets() -> None:
    assert bucket_of(0) == 0
    assert bucket_of(6.9) == 0
    assert bucket_of(7) == 1
    assert bucket_of(100_000) == len(BUCKET_EDGES)
    assert len(bucket_labels()) == len(BUCKET_EDGES) + 1


def test_young_domains_raise_and_old_domains_lower_the_probability() -> None:
    t = table()
    assert t.adjust(0.5, 2) > 0.5
    assert t.adjust(0.5, 6000) < 0.5


def test_unknown_age_changes_nothing() -> None:
    t = table()
    for days in (None, float("nan"), -5.0):
        assert t.adjust(0.37, days) == 0.37


def test_ratios_are_capped_so_age_alone_never_blocks() -> None:
    t = table()
    assert all(1 / MAX_RATIO <= r <= MAX_RATIO for r in t.ratios)
    # a clean-looking name (5%) stays below the 0.90 blocking threshold even when brand new
    assert t.adjust(0.05, 1) < 0.90
    # extreme probabilities stay valid
    assert 0.0 < t.adjust(0.0, 1) < 1.0
    assert 0.0 < t.adjust(1.0, 6000) <= 1.0


def test_ranges_without_data_stay_neutral() -> None:
    t = table()
    assert t.ratio(60) == 1.0  # nobody in 30-90 days
    assert t.ratio(2000) == 1.0  # nobody in 3-10 years


def test_too_few_ages_gives_no_table() -> None:
    assert AgeTable.fit([1.0] * (MIN_PER_CLASS - 1), [5000.0] * 100) is None


def test_round_trip_through_plain_data() -> None:
    t = table()
    assert AgeTable.from_dict(t.to_dict()) == t
    assert AgeTable.from_dict(None) is None
    other = t.to_dict() | {"bucket_edges": [1, 2]}
    assert AgeTable.from_dict(other) is None  # made with other age ranges: ignored, never misread


@pytest.mark.parametrize("probability", [0.1, 0.5, 0.9])
def test_adjustment_is_monotonic_in_age(probability: float) -> None:
    t = table()
    values = [t.adjust(probability, days) for days in (1, 10, 50, 200, 700, 2000, 5000)]
    assert values[0] >= values[-1]
