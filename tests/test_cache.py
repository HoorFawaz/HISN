"""Tests for the TTL cache."""

from __future__ import annotations

import pytest

from storage.cache import TTLCache


class FakeClock:
    """Manual clock so tests never sleep."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_returns_stored_value() -> None:
    cache: TTLCache[str] = TTLCache(60, clock=FakeClock())
    cache.put("a.example", "block")
    assert cache.get("a.example") == "block"


def test_missing_key_returns_none() -> None:
    cache: TTLCache[str] = TTLCache(60, clock=FakeClock())
    assert cache.get("nope.example") is None


def test_entry_expires_after_ttl() -> None:
    clock = FakeClock()
    cache: TTLCache[str] = TTLCache(60, clock=clock)
    cache.put("a.example", "block")
    clock.now += 59.9
    assert cache.get("a.example") == "block"
    clock.now += 0.2
    assert cache.get("a.example") is None
    assert len(cache) == 0  # the expired entry was removed, not just hidden


def test_per_entry_ttl_overrides_default() -> None:
    clock = FakeClock()
    cache: TTLCache[str] = TTLCache(60, clock=clock)
    cache.put("short.example", "allow", ttl_seconds=5)
    clock.now += 6
    assert cache.get("short.example") is None


def test_put_again_refreshes_the_entry() -> None:
    clock = FakeClock()
    cache: TTLCache[str] = TTLCache(60, clock=clock)
    cache.put("a.example", "allow")
    clock.now += 50
    cache.put("a.example", "block")
    clock.now += 50
    assert cache.get("a.example") == "block"


def test_size_is_bounded_and_oldest_entry_is_evicted() -> None:
    cache: TTLCache[int] = TTLCache(60, max_entries=3, clock=FakeClock())
    for index in range(5):
        cache.put(f"d{index}.example", index)
    assert len(cache) == 3
    assert cache.get("d0.example") is None
    assert cache.get("d1.example") is None
    assert cache.get("d4.example") == 4


def test_clear_empties_the_cache() -> None:
    cache: TTLCache[str] = TTLCache(60, clock=FakeClock())
    cache.put("a.example", "block")
    cache.clear()
    assert len(cache) == 0


@pytest.mark.parametrize("ttl", [0, -1])
def test_invalid_ttl_is_rejected(ttl: float) -> None:
    with pytest.raises(ValueError):
        TTLCache(ttl)
    cache: TTLCache[str] = TTLCache(60)
    with pytest.raises(ValueError):
        cache.put("a.example", "x", ttl_seconds=ttl)


def test_invalid_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        TTLCache(60, max_entries=0)
