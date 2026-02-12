"""Visual check results, as the DNS server sees them (Phase 11, optional).

The DNS server never opens a browser. It only:

- queues a suspicious name in the database (``visual_checks``), and
- reads the results the visual worker (``ml/visual/worker.py``, a separate
  program run as a normal user) wrote there.

Like the owner's allowed sites (``owner_list.py``), the results are re-read
at most every ``refresh`` seconds, so a new result applies within a couple of
seconds without a restart. If the database cannot be read, the last good copy
is kept and nothing new is queued: a storage problem must not block anything.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Protocol

from storage.db import VisualState

logger = logging.getLogger(__name__)

REFRESH_SECONDS = 2.0


class VisualStore(Protocol):
    """What this needs from ``storage.db.Database``."""

    def request_visual_check(self, domain: str, ttl: int, ts: float | None = None) -> bool: ...

    def visual_states(self, ttl: int, ts: float | None = None) -> dict[str, VisualState]: ...


class VisualChecks:
    def __init__(
        self,
        store: VisualStore,
        ttl: int,
        refresh: float = REFRESH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._ttl = ttl
        self._refresh = refresh
        self._clock = clock
        self._states: dict[str, VisualState] = {}
        self._loaded_at: float | None = None
        self._lock = threading.Lock()

    def _current(self) -> dict[str, VisualState]:
        with self._lock:
            now = self._clock()
            if self._loaded_at is None or now - self._loaded_at >= self._refresh:
                self._loaded_at = now
                try:
                    self._states = self._store.visual_states(self._ttl)
                except sqlite3.Error as exc:
                    logger.warning("could not read visual check results (keeping the last copy): %s", exc)
            return self._states

    def state(self, domain: str) -> VisualState | None:
        """The pending or recent result for ``domain``, or None if it was never queued."""
        return self._current().get(domain)

    def request(self, domain: str) -> None:
        """Queue ``domain`` for the worker. Never raises."""
        try:
            if self._store.request_visual_check(domain, self._ttl):
                logger.info("visual check queued for %s", domain)
        except sqlite3.Error as exc:
            logger.warning("could not queue a visual check for %s: %s", domain, exc)
            return
        with self._lock:
            # Seen as pending at once, so the next queries do not queue it again.
            self._states = {**self._states, domain: VisualState("pending", None)}
