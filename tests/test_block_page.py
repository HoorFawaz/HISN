"""Tests for the block page (web/block_page/app.py)."""

from __future__ import annotations

import dataclasses
import sqlite3
from collections.abc import Iterator

import pytest
from flask.testing import FlaskClient
from markupsafe import escape

from config import ConfigError, _env_https_url, settings
from storage.db import Database
from web.block_page.app import GENERIC_REASON, REASONS, create_app, host_from_header


@pytest.fixture
def db() -> Iterator[Database]:
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def client(db: Database) -> FlaskClient:
    return create_app(settings, db).test_client()


def page(client: FlaskClient, host: str, path: str = "/", method: str = "GET") -> tuple[int, str]:
    response = client.open(path, method=method, headers={"Host": host})
    return response.status_code, response.get_data(as_text=True)


def test_page_shows_the_message_domain_advice_and_button(client: FlaskClient) -> None:
    status, html = page(client, "absher-sa.com")
    assert status == 403
    assert "This site was blocked as suspected fraud" in html
    assert "تم حجب هذا الموقع للاشتباه بالاحتيال" in html
    assert "absher-sa.com" in html
    assert "Back to safety" in html
    assert 'href="https://www.google.com/"' in html
    assert "verification code" in html
    assert "contact your bank to block the card" in html


@pytest.mark.parametrize("path", ["/", "/login.php", "/a/b/c?x=1", "/static/app.js"])
def test_every_path_gets_the_page(client: FlaskClient, path: str) -> None:
    status, html = page(client, "absher-sa.com", path)
    assert status == 403 and "Back to safety" in html


def test_a_posted_form_gets_the_page_and_is_not_kept(client: FlaskClient) -> None:
    response = client.post("/login", data={"password": "secret123"}, headers={"Host": "absher-sa.com"})
    assert response.status_code == 403
    assert "secret123" not in response.get_data(as_text=True)


def test_a_large_body_is_ignored(client: FlaskClient) -> None:
    response = client.post("/", data="x" * 200_000, headers={"Host": "absher-sa.com"})
    assert response.status_code == 403  # the body is never read, the page is still shown


@pytest.mark.parametrize(
    ("reason", "text"),
    [(key, REASONS[key]) for key in ("blacklist", "lookalike", "model", "visual")],
)
def test_reason_comes_from_the_log(client: FlaskClient, db: Database, reason: str, text: object) -> None:
    db.log_decision("bad.example.com", "block", reason, "192.168.1.5")
    _, html = page(client, "bad.example.com")
    assert escape(text.english) in html  # type: ignore[attr-defined]
    assert text.arabic in html  # type: ignore[attr-defined]


def test_unknown_domain_gets_the_generic_reason(client: FlaskClient) -> None:
    _, html = page(client, "never-logged.com")
    assert GENERIC_REASON.english in html


def test_a_cache_hit_keeps_the_real_reason(client: FlaskClient, db: Database) -> None:
    db.log_decision("abhser.com", "block", "lookalike", "dev")
    db.log_decision("abhser.com", "block", "cache", "dev")
    assert db.blocked_reason("abhser.com") == "lookalike"
    _, html = page(client, "abhser.com")
    assert escape(REASONS["lookalike"].english) in html


def test_a_broken_log_still_shows_the_page() -> None:
    class Broken:
        def blocked_reason(self, domain: str) -> str | None:
            raise sqlite3.OperationalError("database is locked")

    status, html = page(create_app(settings, Broken()).test_client(), "bad.com")
    assert status == 403 and GENERIC_REASON.english in html


def test_page_works_without_a_database() -> None:
    status, html = page(create_app(settings).test_client(), "bad.com")
    assert status == 403 and GENERIC_REASON.english in html


def test_hostile_host_header_is_not_reflected(client: FlaskClient) -> None:
    status, html = page(client, "<script>alert(1)</script>")
    assert status == 403
    assert "<script>" not in html and "alert(1)" not in html


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Absher-SA.com", "absher-sa.com"),
        ("absher-sa.com.", "absher-sa.com"),
        ("absher-sa.com:80", "absher-sa.com"),
        ("127.0.0.1", None),
        ("127.0.0.1:8081", None),
        ("[::1]:80", None),
        ("::1", None),
        ("", None),
        ("bad host.com", None),
        ("xn--ls8h.com:80", "xn--ls8h.com"),
    ],
)
def test_host_from_header(raw: str, expected: str | None) -> None:
    assert host_from_header(raw) == expected


def test_page_opened_by_ip_shows_no_domain(client: FlaskClient) -> None:
    status, html = page(client, "127.0.0.1")
    assert status == 403
    assert 'class="domain"' not in html


def test_security_headers(client: FlaskClient) -> None:
    response = client.get("/", headers={"Host": "bad.com"})
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "script" not in csp  # no script source at all, so no script runs
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_stylesheet_is_served_from_its_own_path(client: FlaskClient) -> None:
    response = client.get("/_hisn/static/block.css", headers={"Host": "bad.com"})
    assert response.status_code == 200
    assert "text/css" in response.headers["Content-Type"]
    assert response.headers["Content-Security-Policy"]


def test_safe_url_comes_from_the_settings() -> None:
    config = dataclasses.replace(settings, block_page_safe_url="https://www.my.gov.sa/")
    _, html = page(create_app(config).test_client(), "bad.com")
    assert 'href="https://www.my.gov.sa/"' in html


@pytest.mark.parametrize(
    "value",
    ["http://example.com/", "javascript:alert(1)", "https://", 'https://a.com/"onmouseover=x', "example.com"],
)
def test_safe_url_must_be_https(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("HISN_TEST_URL", value)
    with pytest.raises(ConfigError):
        _env_https_url("HISN_TEST_URL", "https://www.google.com/")



def test_bundled_font_is_served(client: FlaskClient) -> None:
    css = client.get("/_hisn/static/block.css").get_data(as_text=True)
    font = css.split('url("', 1)[1].split('"', 1)[0]  # first @font-face file, relative to the stylesheet
    response = client.get(f"/_hisn/static/{font}")
    assert response.status_code == 200
    assert response.data[:4] == b"wOF2"
    assert "font-src 'self'" in response.headers["Content-Security-Policy"]
