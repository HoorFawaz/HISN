"""The dashboard: a Flask app serving the dashboard page and its JSON API.

Run from the project root, next to the DNS server::

    python -m api.app

It listens on ``HISN_API_HOST:HISN_API_PORT`` (default ``127.0.0.1:8080``)
and refuses to start on an address that is not loopback or private (the
dashboard must never be reachable from the internet).

Security:

- Only clients in ``HISN_ALLOWED_NETWORKS`` get an answer (403 otherwise).
- One account, the admin, shared by the people who manage the network. It is
  created on the first start (``POST /api/setup``), and only from the HISN
  computer itself (a loopback client), so nobody else on the network can
  claim it first; after that, creating another one is refused.
  ``POST /api/login`` with the username and password returns a session token (8 hours,
  memory only); each device signs in and out on its own. Every other ``/api/`` route needs
  ``Authorization: Bearer <session token>``. The page itself holds no data; it
  keeps the session token in the browser tab only (sessionStorage), never in
  a cookie, so there is no CSRF.
- Rate limits per client: requests per minute, and wrong passwords per ten
  minutes (then 429 until the window passes).
- Security headers on every answer: a strict CSP (scripts and styles from this
  server only, no inline code), no framing, no caching, no referrer.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import time
from collections.abc import Callable

from flask import Flask, Response, jsonify, request, send_from_directory

from api.auth import (
    RateLimiter,
    SessionStore,
    bearer_token,
    hash_password,
    password_problem,
    username_problem,
    verify_password,
)
from api.routes import build_blueprint
from config import BASE_DIR, Settings
from storage.db import Database

logger = logging.getLogger(__name__)

DASHBOARD_DIR = BASE_DIR / "web" / "dashboard"
FONTS_DIR = BASE_DIR / "web" / "block_page" / "static" / "fonts"  # shared with the block page
REQUESTS_PER_MINUTE = 240
FAILED_LOGINS = 10  # wrong passwords per client per FAILED_LOGIN_WINDOW
FAILED_LOGIN_WINDOW = 600.0  # seconds
MAX_BODY_BYTES = 4 * 1024
OPEN_API_PATHS = frozenset({"/api/login", "/api/setup"})  # these check their own input

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(
    config: Settings,
    database: Database,
    *,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> Flask:
    """Build the dashboard app. Tests pass their own clocks."""
    app = Flask(__name__, static_folder=str(DASHBOARD_DIR), static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.json.sort_keys = False  # type: ignore[attr-defined]
    requests_limit = RateLimiter(REQUESTS_PER_MINUTE, 60.0, monotonic)
    login_failures = RateLimiter(FAILED_LOGINS, FAILED_LOGIN_WINDOW, monotonic)
    sessions = SessionStore(clock=monotonic)

    @app.before_request
    def guard() -> tuple[Response, int] | None:
        client = request.remote_addr or ""
        if not config.is_client_allowed(client):
            return jsonify(error="forbidden"), 403
        if not requests_limit.hit(client):
            return jsonify(error="too many requests"), 429
        if not request.path.startswith("/api/"):
            return None  # the page and its files hold no data
        if login_failures.blocked(client):
            return jsonify(error="too many failed logins, try again later"), 429
        if request.path in OPEN_API_PATHS:
            return None
        # A wrong session token is not counted as a failed login: it cannot be
        # guessed (256 random bits), and it is what a tab sends after a restart.
        if not sessions.valid(bearer_token(request.headers.get("Authorization"))):
            return jsonify(error="signed out"), 401
        return None

    def error(code: str, message: str, status: int) -> tuple[Response, int]:
        # ``code`` is for the page, which shows its own Arabic or English text.
        return jsonify(error=message, code=code), status

    def signed_in() -> Response:
        return jsonify(token=sessions.create(), expires_in=int(sessions.lifetime))

    @app.get("/api/setup")
    def setup_state() -> Response:
        exists = database.admin_account() is not None
        return jsonify(account_exists=exists, can_create=not exists and is_local(request.remote_addr))

    @app.post("/api/setup")
    def setup() -> tuple[Response, int] | Response:
        if database.admin_account() is not None:
            return error("account_exists", "the admin account already exists", 409)
        if not is_local(request.remote_addr):
            return error("not_local", "create the account on the HISN computer itself (http://127.0.0.1)", 403)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        username, password, confirm = (body.get(k) for k in ("username", "password", "confirm"))
        if not all(isinstance(v, str) for v in (username, password, confirm)):
            return error("missing", "send username, password and confirm", 400)
        username = username.strip()
        if problem := username_problem(username):
            return error("bad_username", problem, 400)
        if problem := password_problem(password):
            return error("bad_password", problem, 400)
        if password != confirm:
            return error("password_mismatch", "the two passwords are different", 400)
        if not database.create_admin(username, hash_password(password), ts=clock()):
            return error("account_exists", "the admin account already exists", 409)
        logger.info("admin account %r created", username)
        return signed_in()

    @app.post("/api/login")
    def login() -> tuple[Response, int] | Response:
        account = database.admin_account()
        if account is None:
            return error("no_account", "no admin account yet", 409)
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        username, password = body.get("username"), body.get("password")
        # The password is always checked, so a wrong name answers as slowly as a
        # wrong password, and the answer never says which of the two was wrong.
        password_ok = isinstance(password, str) and verify_password(password, account.password_hash)
        name_ok = isinstance(username, str) and same_username(username, account.username)
        if not (password_ok and name_ok):
            login_failures.hit(request.remote_addr or "")
            return error("wrong_login", "wrong username or password", 401)
        return signed_in()

    @app.get("/api/me")
    def me() -> Response:
        account = database.admin_account()
        return jsonify(username=account.username if account else "")

    @app.post("/api/logout")
    def logout() -> Response:
        sessions.end(bearer_token(request.headers.get("Authorization")))
        return jsonify(ok=True)

    @app.get("/")
    def index() -> Response:
        return send_from_directory(DASHBOARD_DIR, "index.html")

    @app.get("/fonts/<path:name>")
    def fonts(name: str) -> Response:
        return send_from_directory(FONTS_DIR, name)

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers.update(SECURITY_HEADERS)
        return response

    app.register_blueprint(build_blueprint(database, config.log_retention_days, clock))
    return app


def same_username(given: str, stored: str) -> bool:
    """Usernames match ignoring case and surrounding spaces ("Hoor" is "hoor")."""
    return hmac.compare_digest(given.strip().casefold().encode("utf-8"), stored.casefold().encode("utf-8"))


def is_local(address: str | None) -> bool:
    """True for a client on the HISN computer itself."""
    try:
        return address is not None and ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def host_problem(host: str) -> str | None:
    """Why the dashboard must not listen on ``host``, or None."""
    address = ipaddress.ip_address(host)
    if address.is_unspecified:
        return f"HISN_API_HOST={host} listens on every network; use 127.0.0.1 or the LAN address"
    if not (address.is_loopback or address.is_private):
        return f"HISN_API_HOST={host} is a public address; use 127.0.0.1 or the LAN address"
    return None


def main() -> int:
    from werkzeug.serving import make_server

    from config import settings

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    problem = host_problem(settings.api_host)
    if problem:
        logger.error("%s. The dashboard will not start.", problem)
        return 1

    database = Database(settings.db_path)
    app = create_app(settings, database)
    try:
        server = make_server(settings.api_host, settings.api_port, app, threaded=True)
    except OSError as exc:
        logger.error("cannot listen on %s:%d (%s). Set HISN_API_PORT.", settings.api_host, settings.api_port, exc)
        database.close()
        return 1
    logger.info("HISN dashboard on http://%s:%d/", settings.api_host, settings.api_port)
    if database.admin_account() is None:
        logger.info(
            "No admin account yet: open http://127.0.0.1:%d/ on this computer to create it.", settings.api_port
        )
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
