"""Make sure the visual check only ever reaches public internet addresses.

The browser runs on the HISN computer, inside the home network, and the names
it opens come from DNS queries, which any device or web page can trigger. A
name that resolves to ``192.168.1.1`` would make it load the router's admin
page (server-side request forgery, SSRF). So the browser never connects to
anything itself: ``capture.py`` hands every request to :class:`GuardedFetcher`,
which for every host, including each redirect:

1. validates the name like every other name (``normalize_domain``);
2. resolves it through the upstream DNS server (never through HISN itself,
   which would answer a blocked name with the block page address);
3. requires every address to be public (:func:`is_public_address`). One
   private address among public ones rejects the whole name: a mix is a
   classic way to slip a private address past a check;
4. connects to exactly the address it checked, so a second lookup cannot
   return something else (DNS rebinding).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from dnslib import QTYPE, RCODE, DNSRecord

from dns_server.domain import InvalidDomainError, normalize_domain
from dns_server.resolver import UpstreamError, UpstreamResolver

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Lookup = Callable[[str], Sequence[str]]
AddressCheck = Callable[[IPAddress], bool]

MAX_REDIRECTS = 5
MAX_BYTES = 5_000_000  # per file; a page needs far less, a bomb is cut short
FORWARDED_HEADERS = ("user-agent", "accept", "accept-language")
RETURNED_HEADERS = ("content-type", "access-control-allow-origin")


class GuardError(Exception):
    """The name must not be opened (invalid, unresolvable or not public)."""


class FetchError(Exception):
    """A request failed (connection, timeout, too large, too many redirects)."""


def is_public_address(address: IPAddress) -> bool:
    """True only for globally routable unicast addresses.

    ``is_global`` already excludes private, loopback, link-local, shared
    (100.64.0.0/10), reserved and documentation ranges. IPv6 addresses that
    carry an IPv4 address inside (mapped, 6to4, Teredo) are judged by that
    IPv4 address too, so ``::ffff:192.168.1.1`` is not public.
    """
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        inner = [address.ipv4_mapped, address.sixtofour]
        if address.teredo is not None:
            inner.extend(address.teredo)
        return all(ip is None or is_public_address(ip) for ip in inner)
    return True


class UpstreamLookup:
    """A and AAAA records of a name, asked from the upstream DNS server."""

    def __init__(self, resolver: UpstreamResolver) -> None:
        self._resolver = resolver

    def __call__(self, host: str) -> list[str]:
        addresses: list[str] = []
        for qtype in ("A", "AAAA"):
            try:
                reply = self._resolver.forward(DNSRecord.question(host, qtype))
            except UpstreamError as exc:
                raise GuardError(f"lookup of {host} failed: {exc}") from exc
            if reply.header.rcode == RCODE.NXDOMAIN:
                raise GuardError(f"{host} does not exist")
            # CNAME records are followed by the upstream server; only the
            # final A/AAAA records carry addresses.
            addresses.extend(
                str(record.rdata) for record in reply.rr if record.rtype in (QTYPE.A, QTYPE.AAAA)
            )
        return addresses


def resolve_public(host: str, lookup: Lookup, allowed: AddressCheck = is_public_address) -> str:
    """Return the address to connect ``host`` to, or raise :class:`GuardError`.

    IPv4 is preferred when both families are present, since a home network
    is more likely to have working IPv4. ``allowed`` is replaced only in tests.
    """
    try:
        name = normalize_domain(host)
    except InvalidDomainError as exc:
        raise GuardError(f"invalid name: {exc}") from exc
    raw = list(lookup(name))
    if not raw:
        raise GuardError(f"{name} has no address")
    addresses: list[IPAddress] = []
    for value in raw:
        try:
            addresses.append(ipaddress.ip_address(value))
        except ValueError as exc:
            raise GuardError(f"{name} resolved to an invalid address {value!r}") from exc
    rejected = [str(ip) for ip in addresses if not allowed(ip)]
    if rejected:
        raise GuardError(f"{name} resolves to a non-public address ({', '.join(rejected)})")
    addresses.sort(key=lambda ip: ip.version)
    return str(addresses[0])


@dataclass(frozen=True)
class FetchResult:
    url: str  # after redirects
    status: int
    headers: dict[str, str]  # only RETURNED_HEADERS
    body: bytes


class _PinnedHTTP(http.client.HTTPConnection):
    """An HTTP connection to a fixed address; the Host header keeps the name."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """An HTTPS connection to a fixed address; SNI keeps the name."""

    def __init__(self, host: str, port: int, address: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._tls = context

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)


def _unsafe_tls() -> ssl.SSLContext:
    # Phishing sites often have odd certificates. Nothing is sent to them
    # (GET only, no cookies, no form data), so the page is shown regardless,
    # as the browser does with ignore_https_errors.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class GuardedFetcher:
    """GET requests for the browser, to public addresses only.

    Thread-safe: ``capture.py`` fetches a page's files in parallel. Each
    host is checked once per page and the answer is reused.
    """

    def __init__(
        self,
        lookup: Lookup,
        *,
        timeout: float = 8.0,
        max_bytes: int = MAX_BYTES,
        allowed: AddressCheck = is_public_address,
    ) -> None:
        self._lookup = lookup
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._allowed = allowed
        self._addresses: dict[str, str | GuardError] = {}
        self._lock = threading.Lock()
        self._tls = _unsafe_tls()

    def address(self, host: str) -> str:
        """The checked address of ``host`` (cached), or :class:`GuardError`."""
        with self._lock:
            known = self._addresses.get(host)
        if known is None:
            try:
                known = resolve_public(host, self._lookup, self._allowed)
            except GuardError as exc:
                known = exc
            with self._lock:
                self._addresses[host] = known
        if isinstance(known, GuardError):
            raise known
        return known

    def fetch(self, url: str, headers: Mapping[str, str] | None = None) -> FetchResult:
        """GET ``url``, following redirects; every hop goes through the guard."""
        sent = {k: v for k, v in (headers or {}).items() if k.lower() in FORWARDED_HEADERS}
        sent["Accept-Encoding"] = "gzip, deflate"
        for _ in range(MAX_REDIRECTS + 1):
            status, location, kept, body = self._get(url, sent)
            if status in (301, 302, 303, 307, 308) and location:
                url = urljoin(url, location)
                continue
            return FetchResult(url, status, kept, body)
        raise FetchError(f"more than {MAX_REDIRECTS} redirects")

    def _get(self, url: str, headers: dict[str, str]) -> tuple[int, str | None, dict[str, str], bytes]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise FetchError(f"bad URL {url!r}") from exc
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FetchError(f"only http(s) is fetched, not {url!r}")
        host = parts.hostname.lower()
        address = self.address(host)
        secure = parts.scheme == "https"
        port = port or (443 if secure else 80)
        connection: http.client.HTTPConnection = (
            _PinnedHTTPS(host, port, address, self._timeout, self._tls)
            if secure
            else _PinnedHTTP(host, port, address, self._timeout)
        )
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            connection.request("GET", target, headers=headers)
            response = connection.getresponse()
            body = response.read(self._max_bytes + 1)
            if len(body) > self._max_bytes:
                raise FetchError(f"{url} is larger than {self._max_bytes} bytes")
            body = _decode(body, response.getheader("content-encoding", ""), self._max_bytes)
            kept = {name: value for name in RETURNED_HEADERS if (value := response.getheader(name))}
            return response.status, response.getheader("location"), kept, body
        except (OSError, http.client.HTTPException, zlib.error) as exc:
            raise FetchError(f"{url}: {exc}") from exc
        finally:
            connection.close()


def _decode(body: bytes, encoding: str, max_bytes: int) -> bytes:
    """Undo gzip/deflate, refusing anything that unpacks to more than ``max_bytes``."""
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding in ("gzip", "x-gzip"):
        unpacker = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        unpacker = zlib.decompressobj()
    else:
        raise FetchError(f"unsupported content encoding {encoding!r}")
    data = unpacker.decompress(body, max_bytes + 1)
    if len(data) > max_bytes or unpacker.unconsumed_tail:
        raise FetchError(f"unpacks to more than {max_bytes} bytes")
    return data
