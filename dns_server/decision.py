"""Decide whether a domain is allowed or blocked.

Order of checks (the first match wins):

1. Whitelist: exact official domains, always allowed.
2. Blacklist: reported malicious domains, always blocked.
3. Verdict cache: a recent verdict for this exact domain, if any.
4. Default: allow.

The ML model (a later phase) goes between step 3 and step 4 and stores its
verdicts in the cache. The engine takes already-validated input, so callers
must run :func:`dns_server.domain.normalize_domain` first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from dns_server.domain import InvalidDomainError, normalize_domain, parent_domains
from storage.cache import TTLCache

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    """Final outcome for a domain."""

    ALLOW = "allow"
    BLOCK = "block"


class Reason(str, Enum):
    """Why a verdict was reached. Stored in logs from Phase 2 on."""

    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    CACHE = "cache"
    DEFAULT = "default"


@dataclass(frozen=True)
class Decision:
    """A verdict plus the reason and the list entry that caused it."""

    verdict: Verdict
    reason: Reason
    matched: str | None = None  # the list entry that matched, if any

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


class ListFormatError(ValueError):
    """Raised when a list file contains an invalid entry."""


def load_domain_list(path: Path) -> frozenset[str]:
    """Load one domain per line from ``path``.

    Blank lines and ``#`` comments are ignored. An invalid entry raises
    :class:`ListFormatError` instead of being skipped: a typo silently dropped
    from the whitelist or blacklist would change protection without notice.
    """
    domains: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                domains.add(normalize_domain(entry))
            except InvalidDomainError as exc:
                raise ListFormatError(f"{path.name}:{line_number}: {exc}") from exc
    return frozenset(domains)


class DecisionEngine:
    """Whitelist, blacklist, then cache. Thread-safe (the lists never change)."""

    def __init__(
        self,
        whitelist: frozenset[str],
        blacklist: frozenset[str],
        cache: TTLCache[Verdict] | None = None,
    ) -> None:
        self._whitelist = whitelist
        self._blacklist = blacklist
        self._cache = cache

    @classmethod
    def from_files(
        cls,
        whitelist_path: Path,
        blacklist_path: Path,
        cache: TTLCache[Verdict] | None = None,
    ) -> DecisionEngine:
        """Build an engine from the list files, failing loudly if one is bad."""
        whitelist = load_domain_list(whitelist_path)
        blacklist = load_domain_list(blacklist_path)
        logger.info("loaded %d whitelist and %d blacklist entries", len(whitelist), len(blacklist))
        return cls(whitelist, blacklist, cache)

    def decide(self, domain: str) -> Decision:
        """Return the decision for an already-normalized ``domain``."""
        # Matching is on label boundaries only: "fake-login.com" never matches
        # an entry "login.com", and "absher.gov.sa.fake-login.com" never
        # matches "absher.gov.sa" because no parent of it equals that entry.
        for candidate in parent_domains(domain):
            if candidate in self._whitelist:
                return Decision(Verdict.ALLOW, Reason.WHITELIST, candidate)

        for candidate in parent_domains(domain):
            if candidate in self._blacklist:
                return Decision(Verdict.BLOCK, Reason.BLACKLIST, candidate)

        # The cache comes after both lists, so editing a list always wins over
        # a verdict that was cached earlier.
        if self._cache is not None:
            cached = self._cache.get(domain)
            if cached is not None:
                return Decision(cached, Reason.CACHE)

        return Decision(Verdict.ALLOW, Reason.DEFAULT)
