"""The block page: what a browser shows when HISN blocked a domain.

The DNS server answers a blocked name with ``HISN_BLOCK_PAGE_IP``, so the
browser connects here instead of to the real site. Whatever path or host it
asks for, it gets the same page: a clear message, a simple reason, advice and
a "Back to safety" button.

Run from the project root (next to ``python -m dns_server.server``)::

    python -m web.block_page.app

Plain HTTP only. A link that starts with ``https://`` cannot show this page
without a certificate warning; see ``docs/https_block_page.md``.

Security notes:

- The ``Host`` header is attacker-controlled. It is validated with
  :func:`dns_server.domain.normalize_domain` and is only ever put in the page
  through Jinja's HTML escaping. An invalid host is not shown at all.
- The page runs no script (``script-src 'none'``), is never framed and is
  never cached, so unblocking a domain takes effect at once.
- Nothing the browser sends is stored or read beyond the ``Host`` header. A
  phishing form that posts credentials here gets the page back; the body is
  never parsed.
"""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
from dataclasses import dataclass
from typing import Protocol

from flask import Flask, Response, render_template, request

from config import Settings
from dns_server.domain import InvalidDomainError, normalize_domain

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 16 * 1024  # upper bound if a body is ever read (the page never reads one)
STATIC_PATH = "/_hisn/static"  # unlikely to clash with a path of the blocked site
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ReasonSource(Protocol):
    """What the page needs from ``storage.db.Database``."""

    def blocked_reason(self, domain: str) -> str | None: ...


@dataclass(frozen=True)
class ReasonText:
    arabic: str
    english: str


# Keys are the reason values the DNS server logs (dns_server.decision.Reason).
REASONS = {
    "blacklist": ReasonText(
        "هذا الموقع مدرج في قوائم مواقع الاحتيال المبلَّغ عنها.",
        "This site is listed among reported fraud sites.",
    ),
    "lookalike": ReasonText(
        "اسم هذا الموقع ينتحل اسم جهة معروفة.",
        "This site's name impersonates a known organization.",
    ),
    "model": ReasonText(
        "اسم هذا الموقع يشبه أنماط أسماء مواقع الاحتيال المعروفة.",
        "This site's name resembles patterns commonly used by known fraud sites.",
    ),
    "visual": ReasonText(
        "صفحة هذا الموقع تشبه صفحة جهة معروفة، لكنه ليس موقعها الرسمي.",
        "This site's page looks like a known organization's page, but it is not their official site.",
    ),
}
# The site was blocked by one of the above, but the log no longer says which.
GENERIC_REASON = ReasonText(
    "نظام حصن صنّف هذا الموقع على أنه غير آمن.",
    "The HISN system has classified this site as unsafe.",
)


def host_from_header(raw: str) -> str | None:
    """The validated domain from a ``Host`` header, or None (IP address, invalid, missing)."""
    host = raw.strip()
    if host.startswith("["):  # IPv6 literal such as [::1]:80
        return None
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    try:
        ipaddress.ip_address(host)
        return None  # someone opened the page by its address: no domain to show
    except ValueError:
        pass
    try:
        return normalize_domain(host)
    except InvalidDomainError:
        return None


def reason_for(domain: str | None, reasons: ReasonSource | None) -> ReasonText:
    """The reason to show. Falls back to the generic text when the log cannot tell."""
    if domain is None or reasons is None:
        return GENERIC_REASON
    try:
        key = reasons.blocked_reason(domain)
    except sqlite3.Error as exc:  # the page must still show if the log is busy or broken
        logger.warning("could not read the block reason for %s: %s", domain, exc)
        return GENERIC_REASON
    return REASONS.get(key or "", GENERIC_REASON)


def create_app(config: Settings, reasons: ReasonSource | None = None) -> Flask:
    """Build the block page app. ``reasons`` is usually the HISN database."""
    app = Flask(__name__, static_url_path=STATIC_PATH)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

    @app.route("/", defaults={"path": ""}, methods=METHODS)
    @app.route("/<path:path>", methods=METHODS)
    def block_page(path: str) -> tuple[str, int]:
        domain = host_from_header(request.headers.get("Host", ""))
        return (
            render_template(
                "block.html",
                domain=domain,
                reason=reason_for(domain, reasons),
                safe_url=config.block_page_safe_url,
            ),
            403,
        )

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers.update(SECURITY_HEADERS)
        return response

    return app


def main() -> int:
    from werkzeug.serving import make_server

    from config import settings
    from storage.db import Database

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    database = Database(settings.db_path)
    app = create_app(settings, database)
    host = str(settings.block_page_ip)
    try:
        server = make_server(host, settings.block_page_port, app, threaded=True)
    except OSError as exc:
        logger.error(
            "cannot listen on %s:%d (%s). Is another program using the port? Set HISN_BLOCK_PAGE_PORT.",
            host,
            settings.block_page_port,
            exc,
        )
        database.close()
        return 1
    logger.info("HISN block page on http://%s:%d/", host, settings.block_page_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
