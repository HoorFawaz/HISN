"""Answer NXDOMAIN for DNS-over-HTTPS servers, so browsers fall back to our DNS.

A browser using DNS-over-HTTPS (DoH) sends its lookups straight to a public
resolver over HTTPS, and HISN never sees them. Browsers first look up the
DoH server's own name through the normal DNS, though. When that name does not
exist (NXDOMAIN), most browsers give up on DoH and use the network's DNS,
which is HISN.

Two kinds of names are answered NXDOMAIN:

- the DoH servers in ``data/lists/doh_hosts.txt`` (and every subdomain of
  them, matched on label boundaries like the other lists);
- the canary domain ``use-application-dns.net``: Firefox checks it before
  turning DoH on by itself, and an NXDOMAIN answer tells it this network
  filters DNS on purpose. This is a documented Firefox signal, so it is
  always on while the blocker is on.

This does not stop a client that has a DoH server's IP address configured
directly, or one using DNS-over-TLS (port 853). See ``docs/limitations.md``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from dns_server.decision import load_domain_list
from dns_server.domain import parent_domains

logger = logging.getLogger(__name__)

# Firefox's canary domain: NXDOMAIN here disables Firefox's automatic DoH.
FIREFOX_CANARY = "use-application-dns.net"


class DohBlocker:
    """Decides whether a name belongs to a DoH server. Immutable, so thread-safe."""

    def __init__(self, hosts: frozenset[str]) -> None:
        self._hosts = hosts | {FIREFOX_CANARY}

    @classmethod
    def from_file(cls, path: Path) -> DohBlocker:
        """Load ``doh_hosts.txt``. A missing file leaves only the Firefox canary."""
        if not path.exists():
            logger.warning("%s not found; only the Firefox canary domain is blocked", path)
            return cls(frozenset())
        hosts = load_domain_list(path)
        logger.info("loaded %d DoH hostnames", len(hosts))
        return cls(hosts)

    def match(self, domain: str) -> str | None:
        """The listed name that ``domain`` falls under, or None.

        ``domain`` must already be normalized. ``dns.google`` matches
        ``dns.google`` and ``x.dns.google``, never ``dns.google.example.com``.
        """
        for candidate in parent_domains(domain):
            if candidate in self._hosts:
                return candidate
        return None
