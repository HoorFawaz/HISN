"""Central configuration for HISN.

All tunable values live here. Nothing secret is hardcoded: values come from
environment variables (optionally loaded from a local ``.env`` file that is
never committed) and fall back to safe development defaults.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Union
from urllib.parse import urlsplit

from dotenv import load_dotenv

BASE_DIR: Path = Path(__file__).resolve().parent

# Load .env if present. Real environment variables take precedence over it.
load_dotenv(BASE_DIR / ".env", override=False)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_DEFAULT_ALLOWED_NETWORKS = "127.0.0.0/8,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

# Look-alike techniques (see ml/lookalike.py). "contains" (the brand inside a
# longer word, such as a bank's own sister company) is left to the model by
# default because it has the most false positives.
LOOKALIKE_TECHNIQUES = ("brand_name", "hyphenation", "homoglyph", "typo", "contains")
_DEFAULT_LOOKALIKE_BLOCK = "brand_name,hyphenation,homoglyph,typo"


class ConfigError(ValueError):
    """Raised when a configuration value is missing or invalid."""


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _env_str(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = _env_str(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_str(name, "true" if default else "false").lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _env_ip(name: str, default: str) -> IPAddress:
    raw = _env_str(name, default)
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an IP address, got {raw!r}") from exc


def _env_https_url(name: str, default: str) -> str:
    """An absolute https:// URL (it is put in a link on the block page)."""
    raw = _env_str(name, default)
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.netloc or any(c in raw for c in " \"'<>"):
        raise ConfigError(f"{name} must be an https:// URL, got {raw!r}")
    return raw


def _env_networks(name: str, default: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated list of CIDR networks."""
    raw = _env_str(name, default)
    networks: list[IPNetwork] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ConfigError(f"{name} has an invalid network {part!r}") from exc
    if not networks:
        # An empty allow-list would silently turn the server into a brick (or,
        # if misread elsewhere, an open resolver). Fail loudly instead.
        raise ConfigError(f"{name} must contain at least one network")
    return tuple(networks)


def _env_choices(name: str, default: str, choices: tuple[str, ...]) -> frozenset[str]:
    """Parse a comma-separated subset of ``choices``. Empty means none."""
    raw = _env_str(name, default)
    values = frozenset(part.strip().lower() for part in raw.split(",") if part.strip())
    unknown = values - set(choices)
    if unknown:
        raise ConfigError(f"{name} has unknown value(s) {', '.join(sorted(unknown))}; use {', '.join(choices)}")
    return values


def _env_path(name: str, default: str) -> Path:
    """Resolve a path relative to the project root unless it is absolute."""
    path = Path(_env_str(name, default))
    return path if path.is_absolute() else BASE_DIR / path


@dataclass(frozen=True)
class Settings:
    """Immutable, validated runtime settings."""

    # DNS server. Port 5353 is unprivileged; port 53 needs admin rights.
    dns_host: str
    dns_port: int
    upstream_dns: IPAddress
    upstream_port: int
    upstream_timeout: float  # seconds; every upstream call must time out
    allowed_networks: tuple[IPNetwork, ...]  # only these clients get answers
    block_page_ip: IPAddress  # returned instead of the real IP for blocked domains
    block_page_port: int  # HTTP port of the block page (browsers use 80)
    block_page_safe_url: str  # where the "Back to safety" button goes

    # Model decision threshold: probability above which a domain is blocked.
    model_threshold: float
    model_path: Path  # trained model bundle written by ml/train.py
    lookalike_block: frozenset[str]  # look-alike techniques that block on their own

    # Domain age (RDAP). Looked up in the background; an unknown age never blocks.
    domain_age_lookup: bool  # False: never contact RDAP servers, the model scores names only
    domain_age_timeout: float  # seconds per RDAP request
    domain_age_cache_ttl: int  # seconds a known registration date is kept

    # DNS-over-HTTPS servers get NXDOMAIN so browsers fall back to HISN
    doh_block: bool

    # Visual check (Phase 11, optional): a separate worker screenshots sites the
    # model finds suspicious but not dangerous enough to block, and compares
    # them with screenshots of the official sites.
    visual_check: bool  # False: the DNS server never queues a check
    visual_min_score: float  # model probability from which a site is checked
    visual_max_distance: int  # largest pHash distance (of 64 bits) that counts as "looks the same"
    visual_ttl: int  # seconds a visual result is trusted before the site is checked again
    visual_timeout: float  # seconds the browser may spend loading one page
    visual_browser_path: str  # Chromium to use; empty = the one "playwright install" downloaded
    references_dir: Path  # data/references: official screenshots and their hashes

    # Storage
    db_path: Path
    log_retention_days: int
    verdict_cache_ttl: int  # seconds

    # Dashboard / API
    api_host: str
    api_port: int

    # Static lists
    whitelist_path: Path
    blacklist_path: Path
    brands_path: Path
    doh_hosts_path: Path

    def is_client_allowed(self, client_ip: str) -> bool:
        """Return True if ``client_ip`` belongs to an allowed network.

        Anything unparsable is rejected, so malformed input can never be
        treated as a trusted client.
        """
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        return any(address in network for network in self.allowed_networks)


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment, validating every value."""
    lists_dir = BASE_DIR / "data" / "lists"
    return Settings(
        dns_host=str(_env_ip("HISN_DNS_HOST", "127.0.0.1")),
        dns_port=_env_int("HISN_DNS_PORT", 5353, minimum=1, maximum=65535),
        upstream_dns=_env_ip("HISN_UPSTREAM_DNS", "1.1.1.1"),
        upstream_port=_env_int("HISN_UPSTREAM_PORT", 53, minimum=1, maximum=65535),
        upstream_timeout=_env_float("HISN_UPSTREAM_TIMEOUT", 2.0, minimum=0.1, maximum=10.0),
        allowed_networks=_env_networks("HISN_ALLOWED_NETWORKS", _DEFAULT_ALLOWED_NETWORKS),
        block_page_ip=_env_ip("HISN_BLOCK_PAGE_IP", "127.0.0.1"),
        block_page_port=_env_int("HISN_BLOCK_PAGE_PORT", 80, minimum=1, maximum=65535),
        block_page_safe_url=_env_https_url("HISN_BLOCK_PAGE_SAFE_URL", "https://www.google.com/"),
        model_threshold=_env_float("HISN_MODEL_THRESHOLD", 0.90, minimum=0.0, maximum=1.0),
        model_path=_env_path("HISN_MODEL_PATH", "ml/models/hisn_rf.joblib"),
        lookalike_block=_env_choices("HISN_LOOKALIKE_BLOCK", _DEFAULT_LOOKALIKE_BLOCK, LOOKALIKE_TECHNIQUES),
        domain_age_lookup=_env_bool("HISN_DOMAIN_AGE_LOOKUP", True),
        domain_age_timeout=_env_float("HISN_DOMAIN_AGE_TIMEOUT", 3.0, minimum=0.5, maximum=15.0),
        domain_age_cache_ttl=_env_int("HISN_DOMAIN_AGE_CACHE_TTL", 604800, minimum=3600, maximum=2592000),
        doh_block=_env_bool("HISN_DOH_BLOCK", True),
        visual_check=_env_bool("HISN_VISUAL_CHECK", False),
        visual_min_score=_env_float("HISN_VISUAL_MIN_SCORE", 0.50, minimum=0.0, maximum=1.0),
        visual_max_distance=_env_int("HISN_VISUAL_MAX_DISTANCE", 10, minimum=0, maximum=32),
        visual_ttl=_env_int("HISN_VISUAL_TTL", 604800, minimum=3600, maximum=2592000),
        visual_timeout=_env_float("HISN_VISUAL_TIMEOUT", 30.0, minimum=5.0, maximum=120.0),
        visual_browser_path=_env_str("HISN_VISUAL_BROWSER_PATH", ""),
        references_dir=_env_path("HISN_REFERENCES_DIR", "data/references"),
        db_path=_env_path("HISN_DB_PATH", "data/hisn.db"),
        log_retention_days=_env_int("HISN_LOG_RETENTION_DAYS", 30, minimum=1, maximum=365),
        verdict_cache_ttl=_env_int("HISN_VERDICT_CACHE_TTL", 3600, minimum=1, maximum=86400),
        # Default to localhost: the dashboard must never be exposed by accident.
        api_host=str(_env_ip("HISN_API_HOST", "127.0.0.1")),
        api_port=_env_int("HISN_API_PORT", 8080, minimum=1, maximum=65535),
        whitelist_path=lists_dir / "whitelist.txt",
        blacklist_path=lists_dir / "blacklist.txt",
        brands_path=lists_dir / "brands.txt",
        doh_hosts_path=lists_dir / "doh_hosts.txt",
    )


settings: Settings = load_settings()
