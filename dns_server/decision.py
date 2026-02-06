"""Decide whether a domain is allowed or blocked.

Order of checks (the first match wins):

1. Whitelist: exact official domains, always allowed.
2. Blacklist: reported malicious domains, always blocked.
3. Verdict cache: a recent verdict for this exact domain, if any.
4. Look-alike rule: a name that imitates a protected brand is blocked on its
   own, for the techniques listed in ``block_techniques``.
5. Model: blocked when the probability reaches ``threshold``, else allowed.
6. Default: allow (also when the rule or the model is missing or fails).

Only steps 4 and 5 write to the cache, so a list edit always wins over a
cached verdict. A failing rule or model never blocks anything: it is logged
and the name is allowed ("fail open"), because a broken model must not take
the whole home network offline.

The engine takes already-validated input, so callers must run
:func:`dns_server.domain.normalize_domain` first.
"""

from __future__ import annotations

import logging
from collections.abc import Collection
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

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
    LOOKALIKE = "lookalike"
    MODEL = "model"
    DEFAULT = "default"


class LookalikeRule(Protocol):
    """What the engine needs from ``ml.lookalike.LookalikeChecker``."""

    def check(self, host: str) -> object | None:  # returns a match with .brand and .technique
        ...


class Scorer(Protocol):
    """What the engine needs from ``ml.predictor.Predictor``."""

    def probability(self, host: str) -> float: ...


@dataclass(frozen=True)
class Decision:
    """A verdict plus the reason and the list entry that caused it."""

    verdict: Verdict
    reason: Reason
    matched: str | None = None  # list entry, look-alike brand or model probability

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
    """Lists, cache, look-alike rule, model. Thread-safe (nothing here changes after start)."""

    def __init__(
        self,
        whitelist: frozenset[str],
        blacklist: frozenset[str],
        cache: TTLCache[Verdict] | None = None,
        *,
        lookalike: LookalikeRule | None = None,
        block_techniques: Collection[str] = (),
        scorer: Scorer | None = None,
        threshold: float = 0.9,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        self._whitelist = whitelist
        self._blacklist = blacklist
        self._cache = cache
        self._lookalike = lookalike
        self._block_techniques = frozenset(block_techniques)
        self._scorer = scorer
        self._threshold = threshold

    @classmethod
    def from_files(
        cls,
        whitelist_path: Path,
        blacklist_path: Path,
        cache: TTLCache[Verdict] | None = None,
        **kwargs: object,
    ) -> DecisionEngine:
        """Build an engine from the list files, failing loudly if one is bad."""
        whitelist = load_domain_list(whitelist_path)
        blacklist = load_domain_list(blacklist_path)
        logger.info("loaded %d whitelist and %d blacklist entries", len(whitelist), len(blacklist))
        return cls(whitelist, blacklist, cache, **kwargs)  # type: ignore[arg-type]

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

        decision = self._lookalike_decision(domain) or self._model_decision(domain)
        if decision is None:
            return Decision(Verdict.ALLOW, Reason.DEFAULT)
        if self._cache is not None:
            self._cache.put(domain, decision.verdict)
        return decision

    def _lookalike_decision(self, domain: str) -> Decision | None:
        if self._lookalike is None or not self._block_techniques:
            return None
        try:
            match = self._lookalike.check(domain)
        except Exception:  # fail open: a bug in the rule must not block the network
            logger.exception("look-alike rule failed for %s; allowing", domain)
            return None
        if match is None or getattr(match, "technique", None) not in self._block_techniques:
            return None
        return Decision(Verdict.BLOCK, Reason.LOOKALIKE, str(getattr(match, "brand", "")) or None)

    def _model_decision(self, domain: str) -> Decision | None:
        if self._scorer is None:
            return None
        try:
            probability = self._scorer.probability(domain)
        except Exception:  # fail open, see the module docstring
            logger.exception("model failed for %s; allowing", domain)
            return None
        verdict = Verdict.BLOCK if probability >= self._threshold else Verdict.ALLOW
        return Decision(verdict, Reason.MODEL, f"{probability:.2f}")
