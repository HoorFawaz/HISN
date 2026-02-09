"""Tests for the dashboard API (api/)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flask.testing import FlaskClient

from api.app import FAILED_LOGINS, REQUESTS_PER_MINUTE, create_app, host_problem
from api.auth import (
    SESSION_SECONDS,
    RateLimiter,
    SessionStore,
    bearer_token,
    hash_password,
    password_hash_problem,
    password_problem,
    verify_password,
)
from config import settings
from storage.db import Database

PASSWORD = "correct horse battery"
PASSWORD_HASH = hash_password(PASSWORD)
NOW = 1_800_000_000  # 2027-01-15 08:00 UTC
LAN = {"REMOTE_ADDR": "192.168.1.50"}


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def db() -> Iterator[Database]:
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def monotonic() -> Clock:
    return Clock()


@pytest.fixture
def client(db: Database, monotonic: Clock) -> FlaskClient:
    db.create_admin("hoor", PASSWORD_HASH)
    test_client = make_client(db, monotonic)
    test_client.auth = login_headers(test_client)  # type: ignore[attr-defined]
    return test_client


def make_client(db: Database, monotonic: Clock) -> FlaskClient:
    return create_app(settings, db, clock=lambda: NOW, monotonic=monotonic).test_client()


def login(client: FlaskClient, password: str, remote: str = "192.168.1.50", username: str = "hoor"):
    body = {"username": username, "password": password}
    return client.post("/api/login", json=body, environ_base={"REMOTE_ADDR": remote})


def login_headers(client: FlaskClient) -> dict[str, str]:
    response = login(client, PASSWORD)
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def get(client: FlaskClient, path: str, headers: dict[str, str] | None = None, remote: str = "192.168.1.50"):
    auth = client.auth if headers is None else headers  # type: ignore[attr-defined]
    return client.get(path, headers=auth, environ_base={"REMOTE_ADDR": remote})


# ----- access control -----


@pytest.mark.parametrize("path", ["/api/stats", "/api/blocked", "/api/devices", "/api/recent", "/api/allowed"])
def test_every_api_route_needs_a_session(client: FlaskClient, path: str) -> None:
    token = client.auth["Authorization"].split()[1]  # type: ignore[attr-defined]
    assert get(client, path, headers={}).status_code == 401
    assert get(client, path, headers={"Authorization": "Bearer wrong-token-0123456789"}).status_code == 401
    assert get(client, path, headers={"Authorization": token}).status_code == 401  # no "Bearer"
    assert get(client, path, headers={"Authorization": f"Bearer {PASSWORD}"}).status_code == 401  # not a session
    assert get(client, path).status_code == 200


def test_login_gives_a_new_random_session_each_time(client: FlaskClient) -> None:
    first, second = login(client, PASSWORD).get_json(), login(client, PASSWORD).get_json()
    assert first["token"] != second["token"] and len(first["token"]) >= 40
    assert first["expires_in"] == SESSION_SECONDS
    for bad in (
        {"username": "hoor", "password": "wrong password!!"},
        {"username": "hoor", "password": ""},
        {"username": "hoor", "password": 123},
        {"password": PASSWORD},  # the username is required
        {"username": "someone", "password": PASSWORD},
        {},
        [],
    ):
        assert client.post("/api/login", json=bad, environ_base=LAN).status_code == 401
    assert client.post("/api/login", data="password", environ_base=LAN).status_code == 401


def test_sessions_expire_and_log_out(client: FlaskClient, monotonic: Clock) -> None:
    other = login_headers(client)
    assert client.post("/api/logout", headers=other, environ_base=LAN).status_code == 200
    assert get(client, "/api/stats", headers=other).status_code == 401
    assert get(client, "/api/stats").status_code == 200  # other sessions are untouched
    monotonic.now += SESSION_SECONDS
    assert get(client, "/api/stats").status_code == 401


def test_delete_needs_the_token(client: FlaskClient, db: Database) -> None:
    db.log_decision("evil.example", "block", "blacklist", "dev", ts=NOW)
    response = client.post("/api/logs/delete", json={"confirm": "delete"}, environ_base=LAN)  # no session
    assert response.status_code == 401
    assert db.top_blocked()


def test_the_page_loads_without_the_token_but_holds_no_data(client: FlaskClient, db: Database) -> None:
    db.log_decision("evil.example", "block", "blacklist", "dev", ts=NOW)
    response = get(client, "/", headers={})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "HISN Dashboard" in html and "evil.example" not in html
    assert get(client, "/static/dashboard.js", headers={}).status_code == 200
    assert get(client, "/static/vendor/chart.umd.js", headers={}).status_code == 200
    font = get(client, "/fonts/ibm-plex-sans-arabic-arabic-400-normal.woff2", headers={})
    assert font.status_code == 200 and font.data[:4] == b"wOF2"
    logo_font = get(client, "/static/fonts/aref-ruqaa-arabic-700-normal.woff2", headers={})
    assert logo_font.status_code == 200 and logo_font.data[:4] == b"wOF2"
    assert get(client, "/static/banner.svg", headers={}).status_code == 200
    assert get(client, "/static/i18n.js", headers={}).status_code == 200


def test_clients_outside_the_allowed_networks_are_refused(client: FlaskClient) -> None:
    assert get(client, "/api/stats", remote="8.8.8.8").status_code == 403
    assert get(client, "/", remote="8.8.8.8").status_code == 403
    assert get(client, "/api/stats", remote="127.0.0.1").status_code == 200


def test_wrong_passwords_are_rate_limited(client: FlaskClient, monotonic: Clock) -> None:
    for _ in range(FAILED_LOGINS):
        assert login(client, "wrong password!!").status_code == 401
    # Locked out, even with the right password, until the window passes.
    assert login(client, PASSWORD).status_code == 429
    assert get(client, "/api/stats").status_code == 429
    assert login(client, PASSWORD, remote="192.168.1.51").status_code == 200  # other clients are fine
    monotonic.now += 601
    assert login(client, PASSWORD).status_code == 200


def test_wrong_session_tokens_do_not_lock_the_owner_out(client: FlaskClient) -> None:
    # An old tab after a restart sends a dead token; that is not a password guess.
    for _ in range(FAILED_LOGINS * 2):
        assert get(client, "/api/stats", headers={"Authorization": "Bearer old-token"}).status_code == 401
    assert login(client, PASSWORD).status_code == 200


def test_requests_are_rate_limited(client: FlaskClient, monotonic: Clock) -> None:
    for _ in range(REQUESTS_PER_MINUTE):
        get(client, "/api/recent")
    assert get(client, "/api/recent").status_code == 429
    monotonic.now += 61
    assert get(client, "/api/recent").status_code == 200


def test_security_headers(client: FlaskClient) -> None:
    for response in (get(client, "/", headers={}), get(client, "/api/stats")):
        csp = response.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Frame-Options"] == "DENY"


def test_dashboard_has_no_inline_script_or_style(client: FlaskClient) -> None:
    html = get(client, "/", headers={}).get_data(as_text=True)
    assert "<script>" not in html and "style=" not in html and "onclick" not in html


def test_dashboard_script_never_uses_innerhtml(client: FlaskClient) -> None:
    for name in ("dashboard.js", "i18n.js"):
        script = get(client, f"/static/{name}", headers={}).get_data(as_text=True)
        assert "innerHTML" not in script and "insertAdjacentHTML" not in script


def test_every_text_key_exists_in_both_languages() -> None:
    import re

    from api.app import DASHBOARD_DIR

    texts = (DASHBOARD_DIR / "i18n.js").read_text(encoding="utf-8")
    ar, en = texts.split("\n  en: {")
    ar_keys = set(re.findall(r"^    (\w+):", ar, re.MULTILINE))
    en_keys = set(re.findall(r"^    (\w+):", en, re.MULTILINE))
    assert ar_keys == en_keys and len(ar_keys) > 50
    used = set(re.findall(r'data-i18n(?:-placeholder)?="(\w+)"', (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")))
    used |= set(re.findall(r'\bt\("(\w+)"', (DASHBOARD_DIR / "dashboard.js").read_text(encoding="utf-8")))
    assert used <= ar_keys, used - ar_keys


# ----- data -----


def fill(db: Database) -> None:
    db.log_decision("evil.example", "block", "blacklist", "192.168.1.21", ts=NOW - 86_400)
    db.log_decision("abhser.com", "block", "lookalike", "192.168.1.20", ts=NOW - 60)
    db.log_decision("abhser.com", "block", "cache", "192.168.1.20", ts=NOW - 30)
    db.log_decision("google.com", "allow", "model", "192.168.1.20", ts=NOW - 10)
    db.log_decision("dns.google", "block", "doh", "192.168.1.21", ts=NOW - 5)


def test_stats(client: FlaskClient, db: Database) -> None:
    fill(db)
    body = get(client, "/api/stats?days=3").get_json()
    assert [d["day"] for d in body["daily"]] == ["2027-01-13", "2027-01-14", "2027-01-15"]
    assert body["today"] == {"day": "2027-01-15", "allowed": 1, "blocked": 2}
    assert body["totals"] == {"allowed": 1, "blocked": 3}  # the DoH lookup is not a threat
    assert body["by_reason"] == {"lookalike": 1, "blacklist": 1}
    assert body["doh_blocked"] == 1
    assert body["devices"] == 2
    assert body["retention_days"] == settings.log_retention_days


def test_blocked_devices_and_recent(client: FlaskClient, db: Database) -> None:
    fill(db)
    blocked = get(client, "/api/blocked").get_json()
    assert [(b["domain"], b["hits"], b["reason"]) for b in blocked] == [
        ("abhser.com", 2, "lookalike"),
        ("evil.example", 1, "blacklist"),
    ]
    devices = get(client, "/api/devices").get_json()
    assert [(d["device"], d["blocked"], d["requests"]) for d in devices] == [
        ("192.168.1.20", 2, 3),
        ("192.168.1.21", 1, 2),
    ]
    recent = get(client, "/api/recent").get_json()
    assert [e["domain"] for e in recent] == ["abhser.com", "abhser.com", "evil.example"]
    newer = get(client, f"/api/recent?after={recent[1]['id']}").get_json()
    assert [e["id"] for e in newer] == [recent[0]["id"]]


@pytest.mark.parametrize("query", ["days=0", "days=91", "days=abc", "limit=0", "limit=101"])
def test_bad_parameters_are_refused(client: FlaskClient, query: str) -> None:
    path = "/api/stats" if query.startswith("days") else "/api/blocked"
    response = get(client, f"{path}?{query}")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_domains_come_back_as_plain_json_strings(client: FlaskClient, db: Database) -> None:
    # Names are validated before they are logged, but the API must not trust that.
    db.log_decision("<img src=x onerror=alert(1)>", "block", "model", "dev", ts=NOW)
    response = get(client, "/api/blocked")
    assert response.mimetype == "application/json"
    assert response.get_json()[0]["domain"] == "<img src=x onerror=alert(1)>"


def test_delete_logs(client: FlaskClient, db: Database) -> None:
    fill(db)
    auth = client.auth  # type: ignore[attr-defined]
    refused = client.post("/api/logs/delete", json={}, headers=auth, environ_base=LAN)
    assert refused.status_code == 400 and db.top_blocked()
    done = client.post("/api/logs/delete", json={"confirm": "delete"}, headers=auth, environ_base=LAN)
    assert done.status_code == 200
    assert db.top_blocked() == [] and db.recent_requests() == []


def post(client: FlaskClient, path: str, body: object, auth: bool = True):
    headers = client.auth if auth else {}  # type: ignore[attr-defined]
    return client.post(path, json=body, headers=headers, environ_base=LAN)


def test_unblock_and_block_again(client: FlaskClient, db: Database) -> None:
    fill(db)
    assert post(client, "/api/allowed", {"domain": "Evil.Example."}, auth=False).status_code == 401
    assert db.allowed_set() == frozenset()

    done = post(client, "/api/allowed", {"domain": "Evil.Example."})
    assert done.status_code == 200 and done.get_json() == {"domain": "evil.example", "added": True}
    assert post(client, "/api/allowed", {"domain": "evil.example"}).get_json()["added"] is False
    body = get(client, "/api/allowed").get_json()
    assert body["allowed"] == [{"domain": "evil.example", "added_at": NOW, "was_reason": "blacklist"}]
    assert body["actions"] == [{"ts": NOW, "action": "unblock", "domain": "evil.example"}]

    assert post(client, "/api/allowed/delete", {"domain": "evil.example"}).status_code == 200
    assert post(client, "/api/allowed/delete", {"domain": "evil.example"}).status_code == 404
    assert get(client, "/api/allowed").get_json()["allowed"] == []


@pytest.mark.parametrize("body", [{}, {"domain": ""}, {"domain": 5}, {"domain": "not a domain"}, {"domain": "a" * 300}, []])
def test_unblock_refuses_bad_names(client: FlaskClient, db: Database, body: object) -> None:
    response = post(client, "/api/allowed", body)
    assert response.status_code == 400 and "error" in response.get_json()
    assert db.allowed_set() == frozenset()


# ----- helpers -----


def test_password_hash() -> None:
    assert PASSWORD_HASH.startswith("scrypt:16384:8:1:") and PASSWORD not in PASSWORD_HASH
    assert "$" not in PASSWORD_HASH and " " not in PASSWORD_HASH  # safe as a .env value
    assert hash_password(PASSWORD) != PASSWORD_HASH  # a new salt every time
    assert verify_password(PASSWORD, PASSWORD_HASH)
    assert not verify_password("correct horse batterY", PASSWORD_HASH)
    assert not verify_password("", PASSWORD_HASH) and not verify_password(None, PASSWORD_HASH)
    assert not verify_password(PASSWORD, "") and not verify_password(PASSWORD, "scrypt:1:2:3")
    assert password_hash_problem(PASSWORD_HASH) is None
    for bad in ("", PASSWORD, "scrypt:16384:8:1:abc:def", "scrypt:1024:8:1:" + PASSWORD_HASH.split(":", 4)[4]):
        assert password_hash_problem(bad)


def test_password_rules() -> None:
    assert password_problem("short") and password_problem(" " + PASSWORD) and password_problem("x" * 257)
    assert password_problem(PASSWORD) is None


def test_bearer_header() -> None:
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("bearer  abc ") == "abc"
    assert bearer_token("Basic abc") is None and bearer_token("Bearer ") is None and bearer_token(None) is None


def test_session_store_keeps_a_bounded_number_of_sessions() -> None:
    clock = Clock()
    store = SessionStore(lifetime=100.0, clock=clock, max_sessions=2)
    a, b = store.create(), store.create()
    c = store.create()  # ends the oldest
    assert not store.valid(a) and store.valid(b) and store.valid(c)
    assert not store.valid(None) and not store.valid("")
    clock.now = 100.0
    assert not store.valid(b) and not store.valid(c)


@pytest.mark.parametrize(
    ("host", "ok"),
    [("127.0.0.1", True), ("192.168.1.10", True), ("10.0.0.5", True), ("0.0.0.0", False), ("8.8.8.8", False)],
)
def test_dashboard_only_listens_on_local_addresses(host: str, ok: bool) -> None:
    assert (host_problem(host) is None) is ok


def test_rate_limiter_forgets_old_events() -> None:
    clock = Clock()
    limiter = RateLimiter(2, 10.0, clock)
    assert limiter.hit("a") and limiter.hit("a") and not limiter.hit("a")
    assert limiter.blocked("a") and not limiter.blocked("b")
    clock.now = 10.0
    assert not limiter.blocked("a") and limiter.hit("a")


def test_set_password_creates_or_resets_the_account(
    db: Database, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from api import set_password

    def answer(username: str, *passwords: str) -> None:
        monkeypatch.setattr("builtins.input", lambda prompt: username)
        it = iter(passwords)
        monkeypatch.setattr(set_password.getpass, "getpass", lambda prompt: next(it))

    answer("hoor", PASSWORD, PASSWORD)
    assert set_password.main(db) == 0
    account = db.admin_account()
    assert account is not None and account.username == "hoor" and verify_password(PASSWORD, account.password_hash)
    assert PASSWORD not in capsys.readouterr().out

    answer("", "a new password 2", "a new password 2")  # Enter keeps the name
    assert set_password.main(db) == 0
    account = db.admin_account()
    assert account is not None and account.username == "hoor" and verify_password("a new password 2", account.password_hash)

    answer("hoor", PASSWORD, PASSWORD + "x")
    assert set_password.main(db) == 1  # the two do not match
    answer("hoor", "short", "short")
    assert set_password.main(db) == 1
    answer("no spaces allowed", PASSWORD, PASSWORD)
    assert set_password.main(db) == 1
    assert verify_password("a new password 2", db.admin_account().password_hash)  # type: ignore[union-attr]


def test_login_needs_the_right_username_and_never_says_which_part_was_wrong(client: FlaskClient) -> None:
    wrong_name = login(client, PASSWORD, username="someone")
    wrong_password = login(client, "wrong password!!")
    assert wrong_name.status_code == wrong_password.status_code == 401
    assert wrong_name.get_json() == wrong_password.get_json() == {"error": "wrong username or password", "code": "wrong_login"}
    assert login(client, PASSWORD, username=" Hoor ").status_code == 200  # case and spaces do not matter


# ----- first start: creating the account -----


def setup(client: FlaskClient, body: object, remote: str = "127.0.0.1"):
    return client.post("/api/setup", json=body, environ_base={"REMOTE_ADDR": remote})


GOOD = {"username": "hoor", "password": PASSWORD, "confirm": PASSWORD}


def test_the_account_can_be_created_once_from_the_hisn_computer(db: Database, monotonic: Clock) -> None:
    client = make_client(db, monotonic)
    state = client.get("/api/setup", environ_base={"REMOTE_ADDR": "127.0.0.1"}).get_json()
    assert state == {"account_exists": False, "can_create": True}
    assert client.get("/api/setup", environ_base=LAN).get_json()["can_create"] is False
    assert login(client, PASSWORD).get_json()["code"] == "no_account"

    refused = setup(client, GOOD, remote="192.168.1.50")
    assert refused.status_code == 403 and refused.get_json()["code"] == "not_local"
    assert db.admin_account() is None

    created = setup(client, GOOD)
    assert created.status_code == 200 and created.get_json()["token"]  # signed in straight away
    headers = {"Authorization": f"Bearer {created.get_json()['token']}"}
    assert client.get("/api/me", headers=headers, environ_base=LAN).get_json() == {"username": "hoor"}

    again = setup(client, {**GOOD, "username": "intruder"})
    assert again.status_code == 409 and again.get_json()["code"] == "account_exists"
    assert db.admin_account().username == "hoor"  # type: ignore[union-attr]
    assert client.get("/api/setup", environ_base=LAN).get_json() == {"account_exists": True, "can_create": False}


def test_several_devices_share_the_account_with_their_own_sessions(client: FlaskClient) -> None:
    phone = login_headers(client)
    laptop = client.auth  # type: ignore[attr-defined]
    assert client.post("/api/logout", headers=phone, environ_base=LAN).status_code == 200
    assert get(client, "/api/stats", headers=phone).status_code == 401
    assert get(client, "/api/stats", headers=laptop).status_code == 200


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({}, "missing"),
        ({**GOOD, "username": "ab"}, "bad_username"),
        ({**GOOD, "username": "has space"}, "bad_username"),
        ({**GOOD, "username": "<script>"}, "bad_username"),
        ({**GOOD, "password": "short", "confirm": "short"}, "bad_password"),
        ({**GOOD, "confirm": PASSWORD + "x"}, "password_mismatch"),
    ],
)
def test_setup_checks_its_input(db: Database, monotonic: Clock, body: dict[str, str], code: str) -> None:
    response = setup(make_client(db, monotonic), body)
    assert response.status_code == 400 and response.get_json()["code"] == code
    assert db.admin_account() is None


def test_arabic_usernames_are_fine(db: Database, monotonic: Clock) -> None:
    assert setup(make_client(db, monotonic), {**GOOD, "username": "حور_1"}).status_code == 200
