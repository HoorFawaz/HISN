"""Tests for the PhishStats downloader, using a tiny fake API on localhost."""

from __future__ import annotations

import csv
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import ml.fetch_phishstats as module
from ml.fetch_phishstats import (
    FetchError,
    build_url,
    fetch_page,
    parse_report,
    read_archive,
    run,
)

TOTAL = 250  # the fake API holds report ids 250 .. 1


class FakeApi:
    """Records requests and answers like PhishStats: newest first, 100 per page."""

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.rate_limit_after: int | None = None
        self.minute_limit_at: set[int] = set()  # request numbers answered with a per-minute 429
        self.ignore_filter = False
        self.garbage = False

    def answer(self, query: dict[str, list[str]], headers: dict[str, str]) -> tuple[int, bytes]:
        self.requests.append({"query": query, "headers": headers})
        if len(self.requests) in self.minute_limit_at:
            return 429, b'{"message":"API rate limit exceeded (20/min). Spread requests across time"}'
        if self.rate_limit_after is not None and len(self.requests) > self.rate_limit_after:
            return 429, b"Too many requests"
        if self.garbage:
            return 200, b"<html>not json</html>"
        upper = TOTAL + 1
        where = query.get("_where", [""])[0]
        if where.startswith("(id,lt,") and not self.ignore_filter:
            upper = int(where[len("(id,lt,") : -1])
        size = int(query["_size"][0])
        ids = list(range(upper - 1, max(upper - 1 - size, 0), -1))
        items = [
            {
                "id": i,
                "url": f"http://host{i}.example.xyz/login",
                "date": f"2026-10-{(i % 28) + 1:02d}T12:00:00.000Z",
                "score": 7.5 if i % 2 else None,
                "ip": "203.0.113.9",  # must never reach the archive
            }
            for i in ids
        ]
        return 200, json.dumps(items).encode()


@pytest.fixture
def api() -> Iterator[tuple[FakeApi, str]]:
    fake = FakeApi()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (name required by http.server)
            status, body = fake.answer(
                parse_qs(urlsplit(self.path).query), {k.lower(): v for k, v in self.headers.items()}
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # keep test output quiet
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield fake, f"http://127.0.0.1:{server.server_address[1]}/api/phishing"
    server.shutdown()
    server.server_close()


def _no_sleep(_: float) -> None:
    pass


def _fetch(out: Path, url: str, max_requests: int = 10) -> str:
    return run(out, max_requests, api_url=url, sleep=_no_sleep)


# ----- URL and parsing -----


def test_build_url_without_and_with_cursor() -> None:
    assert build_url("https://x.test/api", None) == "https://x.test/api?_sort=-id&_size=100"
    assert build_url("https://x.test/api", 500) == "https://x.test/api?_sort=-id&_size=100&_where=(id,lt,500)"


def test_parse_report_accepts_good_items_and_rejects_bad_ones() -> None:
    good = parse_report({"id": 5, "url": "http://a.test/", "date": "2026-10-16T04:25:25.000Z", "score": 6.7})
    assert good is not None
    assert (good.id, good.url, good.score) == (5, "http://a.test/", 6.7)
    assert good.first_seen.year == 2026 and good.first_seen.tzinfo is not None

    unscored = parse_report({"id": 6, "url": "http://a.test/", "date": "2026-10-16T04:25:25.000Z", "score": None})
    assert unscored is not None and unscored.score is None

    for bad in (
        {"id": "5", "url": "http://a.test/", "date": "2026-10-16T04:25:25.000Z"},
        {"id": True, "url": "http://a.test/", "date": "2026-10-16T04:25:25.000Z"},
        {"id": 5, "url": None, "date": "2026-10-16T04:25:25.000Z"},
        {"id": 5, "url": "http://a.test/", "date": "yesterday"},
        {"id": 5, "url": "http://a.test/"},
    ):
        assert parse_report(bad) is None


def test_plain_http_to_a_remote_host_is_refused() -> None:
    with pytest.raises(FetchError, match="https"):
        fetch_page("http://api.phishstats.info/api/phishing")


# ----- running -----


def test_run_downloads_everything_and_stores_only_minimal_fields(
    api: tuple[FakeApi, str], tmp_path: Path
) -> None:
    fake, url = api
    out = tmp_path / "raw" / "phishstats.csv"
    summary = _fetch(out, url)
    assert f"{TOTAL} new reports" in summary
    assert "no older reports" in summary
    with out.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == ["id", "url", "first_seen", "score"]  # no ip, no location
    assert sorted(int(r["id"]) for r in rows) == list(range(1, TOTAL + 1))
    assert len(fake.requests) == 4  # 100 + 100 + 50 + one empty page


def test_run_stops_at_the_request_budget_and_resumes_later(
    api: tuple[FakeApi, str], tmp_path: Path
) -> None:
    fake, url = api
    out = tmp_path / "phishstats.csv"
    assert "request budget used" in _fetch(out, url, max_requests=1)
    ids, smallest = read_archive(out)
    assert len(ids) == 100 and smallest == TOTAL - 99

    _fetch(out, url, max_requests=1)  # continues from the cursor
    ids, smallest = read_archive(out)
    assert len(ids) == 200 and smallest == TOTAL - 199
    second_query = fake.requests[1]["query"]
    assert second_query["_where"] == [f"(id,lt,{TOTAL - 99})"]  # type: ignore[index]

    _fetch(out, url)  # finishes the rest
    ids, _ = read_archive(out)
    assert ids == set(range(1, TOTAL + 1))


def test_running_twice_never_duplicates_rows(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    _, url = api
    out = tmp_path / "phishstats.csv"
    _fetch(out, url)
    _fetch(out, url)
    with out.open(encoding="utf-8", newline="") as handle:
        ids = [row["id"] for row in csv.DictReader(handle)]
    assert len(ids) == len(set(ids)) == TOTAL


def test_rate_limit_keeps_what_was_saved(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    fake, url = api
    fake.rate_limit_after = 2
    out = tmp_path / "phishstats.csv"
    summary = _fetch(out, url)
    assert "rate limit" in summary
    ids, _ = read_archive(out)
    assert len(ids) == 200  # two good pages were kept


def test_an_api_that_ignores_the_cursor_is_detected(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    fake, url = api
    fake.ignore_filter = True
    out = tmp_path / "phishstats.csv"
    with pytest.raises(FetchError, match="ignored the id filter"):
        _fetch(out, url)
    assert len(fake.requests) == 2  # stopped immediately instead of spending the whole quota


def test_garbage_answer_is_a_clear_error(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    fake, url = api
    fake.garbage = True
    with pytest.raises(FetchError, match="not valid JSON"):
        _fetch(tmp_path / "phishstats.csv", url)


def test_api_key_is_sent_as_a_header_only_when_given(api: tuple[FakeApi, str]) -> None:
    fake, url = api
    fetch_page(build_url(url, None))
    fetch_page(build_url(url, None), api_key="secret-key")
    assert "x-api-key" not in fake.requests[0]["headers"]  # type: ignore[operator]
    assert fake.requests[1]["headers"]["x-api-key"] == "secret-key"  # type: ignore[index]


# ----- command line -----


def test_main_reports_errors_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> str:
        raise FetchError("network problem: test")

    monkeypatch.setattr(module, "run", boom)
    assert module.main(["--out", str(tmp_path / "x.csv")]) == 1
    assert "network problem: test" in capsys.readouterr().err


def test_main_rejects_a_zero_request_budget(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        module.main(["--out", str(tmp_path / "x.csv"), "--max-requests", "0"])


def test_main_passes_the_key_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, object] = {}

    def fake_run(out: Path, max_requests: int, **kwargs: object) -> str:
        seen.update(kwargs)
        return "ok"

    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setenv("PHISHSTATS_API_KEY", "abc")
    assert module.main(["--out", str(tmp_path / "x.csv")]) == 0
    assert seen["api_key"] == "abc"




def test_per_minute_limit_waits_and_continues(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    fake, url = api
    fake.minute_limit_at = {2}  # the second request is refused once
    waits: list[float] = []
    out = tmp_path / "phishstats.csv"
    summary = run(out, 10, api_url=url, pause=0.0, sleep=waits.append)
    assert module.MINUTE_WAIT_SECONDS in waits
    assert f"{TOTAL} new reports" in summary  # nothing was lost


def test_repeated_per_minute_limits_give_up_politely(api: tuple[FakeApi, str], tmp_path: Path) -> None:
    fake, url = api
    fake.minute_limit_at = set(range(2, 50))  # the limit never clears
    summary = run(tmp_path / "phishstats.csv", 10, api_url=url, pause=0.0, sleep=lambda _: None)
    assert "rate limit reached" in summary
    ids, _ = read_archive(tmp_path / "phishstats.csv")
    assert len(ids) == 100  # the first page was kept


def test_pause_between_requests_respects_the_documented_limit() -> None:
    assert 60 / module.PAUSE_SECONDS < 20  # fewer than 20 requests a minute
