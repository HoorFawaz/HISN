"""Domain validation, normalization and label-boundary matching.

Every name that reaches the decision logic is attacker-controlled (any device
or web page can make the network ask for any name), so it is validated here
first. Nothing downstream should ever see an unvalidated string.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

MAX_DOMAIN_LENGTH = 253  # RFC 1035: 255 octets on the wire, minus length bytes
MAX_LABEL_LENGTH = 63

# Letters, digits, hyphen. Underscore is allowed too because real DNS traffic
# uses it (SRV and TXT records such as _sip._tcp or _dmarc). Refusing it would
# break legitimate applications on the network.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]+(?<!-)$")


class InvalidDomainError(ValueError):
    """Raised when a name is not a syntactically valid domain name."""


def normalize_domain(name: str) -> str:
    """Return the canonical form of ``name`` or raise :class:`InvalidDomainError`.

    Canonical form: ASCII, lowercase, no trailing dot, valid labels.

    - Non-ASCII input is rejected. Internationalised names must arrive as
      punycode (``xn--...``), which is what DNS carries on the wire.
    - ``xn--`` labels must decode as valid punycode, so a malformed one cannot
      slip through looking legitimate.
    """
    if not isinstance(name, str):
        raise InvalidDomainError("domain must be a string")

    try:
        name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidDomainError("domain must be ASCII (use punycode)") from exc

    host = name.lower()
    if host.endswith("."):
        host = host[:-1]

    if not host:
        raise InvalidDomainError("domain is empty")
    if len(host) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError("domain is too long")

    for label in host.split("."):
        if not label:
            raise InvalidDomainError("domain has an empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidDomainError("domain label is too long")
        if not _LABEL_RE.match(label):
            raise InvalidDomainError("domain label has invalid characters")
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except UnicodeError as exc:
                raise InvalidDomainError("invalid punycode label") from exc

    return host


def name_from_labels(labels: tuple[bytes, ...]) -> str:
    """Join raw DNS labels into a dotted name, rejecting ambiguous input.

    A DNS label may legally contain a ``.`` byte. If we joined such labels
    naively, ``[b"x.absher", b"gov", b"sa"]`` would look like the name
    ``x.absher.gov.sa`` although it is a different name on the wire. That
    ambiguity could be abused to confuse list matching, so it is refused.
    """
    for label in labels:
        if b"." in label:
            raise InvalidDomainError("label contains a dot")
    try:
        return b".".join(labels).decode("ascii")
    except UnicodeDecodeError as exc:
        raise InvalidDomainError("label is not ASCII") from exc


def parent_domains(host: str) -> Iterator[str]:
    """Yield ``host`` and each of its parent domains, most specific first.

    ``a.b.example.com`` yields ``a.b.example.com``, ``b.example.com``,
    ``example.com``, ``com``. Looking each one up in a set is equivalent to
    testing ``host == d or host.endswith("." + d)`` for every listed ``d``,
    but costs one lookup per label instead of a scan of the whole list.
    Matching only ever happens on label boundaries, never on substrings.
    """
    while host:
        yield host
        _, dot, host = host.partition(".")
        if not dot:
            return
