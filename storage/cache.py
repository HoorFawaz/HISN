"""Small in-memory cache with a time-to-live (TTL) and a size limit.

Used for verdicts now and for domain-age lookups later (see the project
brief). It lives in memory on purpose: a lookup must take microseconds, and a
restart simply starts with an empty cache.

Two properties matter because cache keys are attacker-controlled domain names:

* the size is bounded, so a flood of random names cannot exhaust memory;
* entries expire, so a stale verdict never lives longer than the TTL.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

V = TypeVar("V")

DEFAULT_MAX_ENTRIES = 10_000


class TTLCache(Generic[V]):
    """Thread-safe string-keyed cache. The oldest entries are evicted first."""

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._clock = clock  # injectable so tests do not have to sleep
        self._items: OrderedDict[str, tuple[float, V]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> V | None:
        """Return the cached value, or None if missing or expired."""
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock() >= expires_at:
                del self._items[key]
                return None
            return value

    def put(self, key: str, value: V, ttl_seconds: float | None = None) -> None:
        """Store ``value``; ``ttl_seconds`` overrides the default for this entry."""
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValueError("ttl_seconds must be positive")
        with self._lock:
            self._items[key] = (self._clock() + ttl, value)
            self._items.move_to_end(key)
            while len(self._items) > self._max_entries:
                self._items.popitem(last=False)  # drop the oldest entry

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
