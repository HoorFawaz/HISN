"""Access control for the dashboard API: the admin password, sessions and rate limits.

There is one account, the admin, shared by the people who manage the home
network. It is created once, from the HISN computer itself, on the dashboard's
first start (or with ``python -m api.set_password``, which also resets the
password). The password is never stored: the database keeps a salted scrypt
hash of it. Logging in with the password returns a random session token that the page keeps in the browser tab and sends as
``Authorization: Bearer <token>``. No cookies are used, so a malicious web
page cannot make the browser send authenticated requests for it (no CSRF).
Sessions live in memory only: they expire on their own and end when the
dashboard restarts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32
SESSION_SECONDS = 8 * 3600
MAX_SESSIONS = 32

# scrypt cost: 16 MiB of memory per check, well inside hashlib's default limit.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_LEN = 32
_SCHEME = "scrypt"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def username_problem(username: str) -> str | None:
    """Why ``username`` cannot be used, or None. Letters of any language, digits, ``.``, ``_``, ``-``."""
    if not MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH:
        return f"the username must be {MIN_USERNAME_LENGTH} to {MAX_USERNAME_LENGTH} characters"
    if not all(ch.isalnum() or ch in "._-" for ch in username):
        return "the username may contain only letters, digits, '.', '_' and '-'"
    return None


def password_problem(password: str) -> str | None:
    """Why ``password`` is not good enough for the admin, or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"the password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"the password must be at most {MAX_PASSWORD_LENGTH} characters"
    if password.strip() != password:
        return "the password must not start or end with a space"
    return None


def hash_password(password: str, salt: bytes | None = None) -> str:
    """``scrypt:N:r:p:<salt>:<hash>``, safe to keep in ``.env`` (no ``$``, quotes or spaces)."""
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LEN
    )
    return f"{_SCHEME}:{_SCRYPT_N}:{_SCRYPT_R}:{_SCRYPT_P}:{_b64(salt)}:{_b64(digest)}"


def _parse_hash(stored: str) -> tuple[int, int, int, bytes, bytes] | None:
    parts = stored.split(":")
    if len(parts) != 6 or parts[0] != _SCHEME:
        return None
    try:
        n, r, p = (int(x) for x in parts[1:4])
        salt, digest = _unb64(parts[4]), _unb64(parts[5])
    except ValueError:
        return None
    if n < 2**14 or n > 2**20 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
        return None
    if len(salt) < 16 or len(digest) != _SCRYPT_LEN:
        return None
    return n, r, p, salt, digest


def password_hash_problem(stored: str) -> str | None:
    """Why a stored hash cannot be used, or None if it is fine."""
    if not stored:
        return "no password hash"
    if _parse_hash(stored) is None:
        return "not a valid password hash"
    return None


def verify_password(password: str | None, stored: str) -> bool:
    """True if ``password`` matches ``stored``; compared in constant time."""
    parsed = _parse_hash(stored)
    if parsed is None or not password or len(password) > MAX_PASSWORD_LENGTH:
        return False
    n, r, p, salt, digest = parsed
    given = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(digest), maxmem=256 * 1024 * 1024
    )
    return hmac.compare_digest(given, digest)


def bearer_token(header: str | None) -> str | None:
    """The token from an ``Authorization: Bearer <token>`` header."""
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


class SessionStore:
    """Random session tokens that expire ``lifetime`` seconds after login.

    Only a SHA-256 of each token is kept. At most ``max_sessions`` live at once;
    a new login past that ends the oldest session. Thread-safe.
    """

    def __init__(
        self,
        lifetime: float = SESSION_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        max_sessions: int = MAX_SESSIONS,
    ) -> None:
        self._lifetime = lifetime
        self._clock = clock
        self._max = max_sessions
        self._expires: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @property
    def lifetime(self) -> float:
        return self._lifetime

    def create(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._drop_expired(self._clock())
            while len(self._expires) >= self._max:
                self._expires.popitem(last=False)
            self._expires[self._key(token)] = self._clock() + self._lifetime
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            expires = self._expires.get(self._key(token))
            if expires is None:
                return False
            if self._clock() >= expires:
                del self._expires[self._key(token)]
                return False
            return True

    def end(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._expires.pop(self._key(token), None)

    def _drop_expired(self, now: float) -> None:
        for key in [k for k, t in self._expires.items() if now >= t]:
            del self._expires[key]


class RateLimiter:
    """At most ``limit`` events per ``window`` seconds for each key (a client address).

    Thread-safe. Keys whose events have all expired are dropped once there are
    many of them, so memory stays bounded by the number of active clients.
    """

    MAX_KEYS = 4096

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic) -> None:
        if limit < 1 or window <= 0:
            raise ValueError("limit must be at least 1 and window positive")
        self._limit = limit
        self._window = window
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            events = self._events[key] = deque()
        while events and now - events[0] >= self._window:
            events.popleft()
        return events

    def blocked(self, key: str) -> bool:
        """True if ``key`` has used up its allowance (without counting a new event)."""
        with self._lock:
            now = self._clock()
            events = self._recent(key, now)
            if not events:
                del self._events[key]
                return False
            return len(events) >= self._limit

    def hit(self, key: str) -> bool:
        """Count one event. Returns False (and does not count it) when over the limit."""
        with self._lock:
            now = self._clock()
            if len(self._events) > self.MAX_KEYS:
                self._prune(now)
            events = self._recent(key, now)
            if len(events) >= self._limit:
                return False
            events.append(now)
            return True

    def _prune(self, now: float) -> None:
        for key in list(self._events):
            if not self._recent(key, now):
                del self._events[key]
