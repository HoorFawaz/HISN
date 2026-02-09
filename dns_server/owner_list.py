"""Sites the owner unblocked from the dashboard, as the DNS server sees them.

The dashboard writes them to the database (``allowed_domains``); the DNS server
is another process, so it re-reads that small table at most every ``refresh``
seconds. An unblock therefore takes effect within a couple of seconds, without
restarting anything. Matching is on label boundaries, like the whitelist: an
entry ``example.com`` also allows ``www.example.com``.

If the database cannot be read, the last good copy is kept: a storage problem
must neither block the network nor silently drop the owner's choices.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Protocol

from dns_server.domain import parent_domains

logger = logging.getLogger(__name__)

REFRESH_SECONDS = 2.0


class AllowedSource(Protocol):
    def allowed_set(self) -> frozenset[str]: ...


class OwnerAllowList:
    def __init__(
        self,
        source: AllowedSource,
        refresh: float = REFRESH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._refresh = refresh
        self._clock = clock
        self._domains: frozenset[str] = frozenset()
        self._loaded_at: float | None = None
        self._lock = threading.Lock()

    def _current(self) -> frozenset[str]:
        with self._lock:
            now = self._clock()
            if self._loaded_at is None or now - self._loaded_at >= self._refresh:
                self._loaded_at = now
                try:
                    self._domains = self._source.allowed_set()
                except sqlite3.Error as exc:
                    logger.warning("could not read the owner's allowed sites (keeping the last copy): %s", exc)
            return self._domains

    def match(self, domain: str) -> str | None:
        """The allowed entry covering ``domain``, or None."""
        domains = self._current()
        if not domains:
            return None
        for candidate in parent_domains(domain):
            if candidate in domains:
                return candidate
        return None
