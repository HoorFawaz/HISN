"""Domain age (registration date) from RDAP, looked up in the background.

New domains are riskier: most phishing domains are used within days of being
registered. The registration date comes from RDAP, the JSON successor of WHOIS
that registries serve over HTTPS. RDAP is used instead of port-43 WHOIS
because its answers are structured (no per-registry text parsing) and it runs
over HTTPS (no plain-text queries).

How it fits the DNS server (the decision must take milliseconds):

- :meth:`DomainAgeService.lookup` never waits for the network. It answers from
  the cache, or queues a background lookup and answers "pending".
- The model then scores the name without the age (it was trained to cope, see
  ``ml/train.py``), and the engine does not cache that verdict, so a query that
  comes after the lookup finished is scored with the age.
- Every failure (no RDAP server for the TLD, timeout, bad JSON, full queue)
  means "age unknown". An unknown age never blocks anything on its own.

Only the registered domain is looked up (``example.com`` for
``a.b.example.com``), so one lookup serves every host under it and the
registry never sees full host names. Hosts on shared platforms
(``x.netlify.app``, ``x.duckdns.org``) are not looked up at all: the registry
only knows the platform, and its age says nothing about the host.
"""

from __future__ import annotations

import json
import logging
import math
import queue
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ml.features import lookup_domain
from storage.cache import TTLCache

logger = logging.getLogger(__name__)

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_RESPONSE_BYTES = 512 * 1024  # RDAP answers are a few KB; never read an unbounded body
BOOTSTRAP_TTL = 24 * 3600  # seconds; IANA updates the file rarely
NOT_FOUND_TTL = 24 * 3600  # "no data" answers are retried after a day
FAILURE_TTL = 3600  # network errors are retried after an hour
DEFAULT_KNOWN_TTL = 7 * 24 * 3600
DEFAULT_WORKERS = 2
DEFAULT_QUEUE_SIZE = 256
SECONDS_PER_DAY = 86400.0


class AgeLookupError(Exception):
    """The lookup failed for a reason that may go away (network, server error)."""


class AgeStatus(str, Enum):
    KNOWN = "known"  # registration date found
    UNKNOWN = "unknown"  # final answer for now: no RDAP data, or the lookup failed
    PENDING = "pending"  # a background lookup is queued or running


@dataclass(frozen=True)
class AgeLookup:
    """Result of a non-blocking lookup. ``days`` is set only when the age is known."""

    status: AgeStatus
    days: float | None = None

    @property
    def final(self) -> bool:
        """True when waiting longer will not change the answer (so a verdict may be cached)."""
        return self.status is not AgeStatus.PENDING


PENDING = AgeLookup(AgeStatus.PENDING)
UNKNOWN = AgeLookup(AgeStatus.UNKNOWN)

# (url, timeout) -> parsed JSON. Replaced by a fake in the tests.
Fetcher = Callable[[str, float], Any]


def _tls_context() -> ssl.SSLContext:
    """Verified TLS that trusts the system store plus the certifi bundle.

    On Windows, Python only sees root certificates that Windows has already
    downloaded, so some registries fail with "unable to get local issuer
    certificate". Adding certifi's roots fixes that without ever turning
    certificate checks off.
    """
    context = ssl.create_default_context()
    try:
        import certifi
    except ImportError:  # optional: the system store alone still works for most registries
        return context
    context.load_verify_locations(cafile=certifi.where())
    return context


_TLS = _tls_context()


def fetch_json(url: str, timeout: float) -> Any:
    """GET ``url`` over HTTPS and parse the JSON body.

    Returns None for 404 (the registry has no such domain). Raises
    :class:`AgeLookupError` for anything else that went wrong.
    """
    if urllib.parse.urlsplit(url).scheme != "https":
        raise AgeLookupError(f"refusing non-HTTPS URL {url!r}")
    request = urllib.request.Request(
        url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "HISN/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_TLS) as response:  # noqa: S310 (scheme checked above)
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise AgeLookupError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AgeLookupError(str(exc)) from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise AgeLookupError("response too large")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgeLookupError("response is not JSON") from exc


def parse_bootstrap(data: Any) -> dict[str, str]:
    """Map each TLD to its RDAP base URL from IANA's ``dns.json`` (HTTPS URLs only)."""
    servers: dict[str, str] = {}
    if not isinstance(data, Mapping):
        raise AgeLookupError("bootstrap file is not a JSON object")
    for entry in data.get("services", []):
        if not (isinstance(entry, list) and len(entry) == 2):
            continue
        tlds, urls = entry
        https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
        if not https:
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for tld in tlds:
            if isinstance(tld, str):
                servers[tld.lower()] = base
    return servers


def parse_registration_date(data: Any) -> datetime | None:
    """The ``registration`` event date of an RDAP domain answer, or None."""
    if not isinstance(data, Mapping):
        return None
    for event in data.get("events", []):
        if not isinstance(event, Mapping) or event.get("eventAction") != "registration":
            continue
        raw = event.get("eventDate")
        if not isinstance(raw, str):
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


class RdapClient:
    """Blocking RDAP lookups. Used by the background workers and by ``ml.fetch_domain_age``."""

    def __init__(
        self,
        timeout: float = 3.0,
        fetcher: Fetcher = fetch_json,
        bootstrap_url: str = IANA_BOOTSTRAP_URL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._timeout = timeout
        self._fetch = fetcher
        self._bootstrap_url = bootstrap_url
        self._clock = clock
        self._servers: dict[str, str] | None = None
        self._servers_loaded_at = 0.0
        self._lock = threading.Lock()

    def _server_for(self, domain: str) -> str | None:
        with self._lock:
            if self._servers is None or self._clock() - self._servers_loaded_at > BOOTSTRAP_TTL:
                self._servers = parse_bootstrap(self._fetch(self._bootstrap_url, self._timeout))
                self._servers_loaded_at = self._clock()
            servers = self._servers
        tld = domain.rsplit(".", 1)[-1]
        return servers.get(tld)

    def registration_date(self, domain: str) -> datetime | None:
        """Registration date of a registered domain such as ``example.com``.

        Returns None when the TLD has no RDAP server or the registry has no
        date. Raises :class:`AgeLookupError` when the lookup itself failed.
        """
        base = self._server_for(domain)
        if base is None:
            return None
        url = base + "domain/" + urllib.parse.quote(domain, safe=".-")
        return parse_registration_date(self._fetch(url, self._timeout))


def age_in_days(created: datetime, now: datetime) -> float | None:
    """Whole-day age at ``now``. None if the date is in the future (bad data or re-registration)."""
    days = (now - created).total_seconds() / SECONDS_PER_DAY
    return None if days < 0 else math.floor(days)


class DomainAgeService:
    """Non-blocking, cached domain ages for the DNS server.

    ``lookup`` is safe to call from many DNS threads at once. Background
    workers are daemon threads, so they never keep the process alive.
    """

    def __init__(
        self,
        client: RdapClient,
        *,
        known_ttl: int = DEFAULT_KNOWN_TTL,
        workers: int = DEFAULT_WORKERS,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        start: bool = True,
    ) -> None:
        self._client = client
        self._now = now
        self._known: TTLCache[datetime] = TTLCache(known_ttl)
        self._unknown: TTLCache[bool] = TTLCache(NOT_FOUND_TTL)  # failures get a shorter TTL
        self._queue: queue.Queue[str | None] = queue.Queue(maxsize=queue_size)
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()
        self._threads = [
            threading.Thread(target=self._work, name=f"hisn-age-{i}", daemon=True) for i in range(workers)
        ]
        if start:
            for thread in self._threads:
                thread.start()

    def lookup(self, host: str) -> AgeLookup:
        """Age of ``host``'s registered domain from the cache; otherwise queue a lookup."""
        domain = lookup_domain(host)
        if domain is None:
            return UNKNOWN  # shared platform or bare suffix: nothing useful to look up
        created = self._known.get(domain)
        if created is not None:
            days = age_in_days(created, self._now())
            return AgeLookup(AgeStatus.KNOWN, days) if days is not None else UNKNOWN
        if self._unknown.get(domain):
            return UNKNOWN
        with self._lock:
            if domain in self._in_flight:
                return PENDING
            try:
                self._queue.put_nowait(domain)
            except queue.Full:
                # Too many lookups waiting. Answer "unknown" now and try again
                # on a later query; DNS answers never wait for this queue.
                return UNKNOWN
            self._in_flight.add(domain)
        return PENDING

    def run_pending(self) -> None:
        """Process queued lookups in the calling thread (for tests with ``start=False``)."""
        while True:
            try:
                domain = self._queue.get_nowait()
            except queue.Empty:
                return
            if domain is not None:
                self._resolve(domain)

    def close(self) -> None:
        """Ask the workers to stop (they finish the lookup they are on)."""
        for _ in self._threads:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                break  # daemon threads end with the process anyway

    def _work(self) -> None:
        while True:
            domain = self._queue.get()
            if domain is None:
                return
            self._resolve(domain)

    def _resolve(self, domain: str) -> None:
        try:
            created = self._client.registration_date(domain)
        except AgeLookupError as exc:
            logger.info("domain age lookup failed for %s: %s", domain, exc)
            self._unknown.put(domain, True, FAILURE_TTL)
        except Exception:  # a bug here must never kill the worker thread
            logger.exception("domain age lookup crashed for %s", domain)
            self._unknown.put(domain, True, FAILURE_TTL)
        else:
            if created is None:
                self._unknown.put(domain, True)
            else:
                self._known.put(domain, created)
        finally:
            with self._lock:
                self._in_flight.discard(domain)
