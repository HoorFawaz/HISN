"""Tests for domain-age lookups: RDAP parsing, the non-blocking service and the training helpers.

No test touches the network: every RDAP answer comes from a fake fetcher.
"""

from __future__ import annotations

import csv
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from ml import fetch_domain_age
from ml.domain_age import (
    _TLS,
    AgeLookupError,
    AgeStatus,
    DomainAgeService,
    RdapClient,
    age_in_days,
    fetch_json,
    parse_bootstrap,
    parse_registration_date,
)
from ml.features import lookup_domain
from ml.train import AgeRecord, load_ages, row_age_days

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)
BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.example-registry.test/v1/"]],
        [["xyz"], ["http://insecure.test/", "https://rdap.xyz.test"]],  # the HTTPS one is used, "/" added
        [["org"], ["http://only-http.test/"]],  # no HTTPS server: treated as unsupported
    ]
}


def rdap_answer(created: str) -> dict[str, Any]:
    return {
        "objectClassName": "domain",
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": created},
        ],
    }


class FakeFetcher:
    """Answers RDAP URLs from a dict; records every URL asked."""

    def __init__(self, answers: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.answers = answers or {}
        self.error = error
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> Any:
        self.urls.append(url)
        if url.endswith("dns.json"):
            return BOOTSTRAP
        if self.error is not None:
            raise self.error
        return self.answers.get(url)


def service(fetcher: FakeFetcher, **kwargs: Any) -> DomainAgeService:
    return DomainAgeService(RdapClient(fetcher=fetcher), now=lambda: NOW, start=False, **kwargs)


# ----- parsing -----


def test_bootstrap_maps_tlds_to_https_servers_only() -> None:
    servers = parse_bootstrap(BOOTSTRAP)
    assert servers["com"] == servers["net"] == "https://rdap.example-registry.test/v1/"
    assert servers["xyz"] == "https://rdap.xyz.test/"
    assert "org" not in servers


def test_bad_bootstrap_is_an_error() -> None:
    with pytest.raises(AgeLookupError):
        parse_bootstrap(None)


def test_registration_date_is_read_from_the_events() -> None:
    assert parse_registration_date(rdap_answer("2026-10-10T08:30:00Z")) == datetime(
        2026, 10, 10, 8, 30, tzinfo=timezone.utc
    )


@pytest.mark.parametrize(
    "answer",
    [None, {}, {"events": "nope"}, {"events": [{"eventAction": "registration", "eventDate": "yesterday"}]}],
)
def test_missing_or_bad_registration_date_is_none(answer: Any) -> None:
    assert parse_registration_date(answer) is None


def test_age_in_days() -> None:
    assert age_in_days(NOW - timedelta(days=3, hours=5), NOW) == 3
    assert age_in_days(NOW + timedelta(days=1), NOW) is None  # registered after the date we ask about


def test_plain_http_is_refused() -> None:
    with pytest.raises(AgeLookupError, match="non-HTTPS"):
        fetch_json("http://rdap.example.test/domain/x.com", 1.0)


# ----- RdapClient -----


def test_client_asks_the_right_server_and_caches_the_bootstrap() -> None:
    url = "https://rdap.example-registry.test/v1/domain/example.com"
    fetcher = FakeFetcher({url: rdap_answer("2020-01-01T00:00:00Z")})
    client = RdapClient(fetcher=fetcher)
    assert client.registration_date("example.com") == datetime(2020, 1, 1, tzinfo=timezone.utc)
    client.registration_date("example.net")
    assert sum(u.endswith("dns.json") for u in fetcher.urls) == 1
    assert url in fetcher.urls


def test_client_returns_none_for_tlds_without_rdap() -> None:
    fetcher = FakeFetcher()
    assert RdapClient(fetcher=fetcher).registration_date("example.sa") is None
    assert fetcher.urls == ["https://data.iana.org/rdap/dns.json"]  # nothing else was contacted


# ----- DomainAgeService -----


def test_first_lookup_is_pending_then_known() -> None:
    url = "https://rdap.example-registry.test/v1/domain/new-shop.com"
    fetcher = FakeFetcher({url: rdap_answer("2026-10-12T00:00:00Z")})
    ages = service(fetcher)
    first = ages.lookup("login.new-shop.com")
    assert first.status is AgeStatus.PENDING and not first.final and first.days is None
    assert ages.lookup("www.new-shop.com").status is AgeStatus.PENDING  # same domain, not queued twice
    ages.run_pending()
    result = ages.lookup("pay.new-shop.com")
    assert result.status is AgeStatus.KNOWN and result.final
    assert result.days == 5
    assert sum(u == url for u in fetcher.urls) == 1  # one lookup served every host


def test_not_found_and_failures_are_unknown_and_final() -> None:
    ages = service(FakeFetcher())  # every domain answer is 404 (None)
    ages.lookup("gone.com")
    ages.run_pending()
    assert ages.lookup("gone.com").status is AgeStatus.UNKNOWN

    broken = service(FakeFetcher(error=AgeLookupError("timeout")))
    broken.lookup("slow.com")
    broken.run_pending()
    result = broken.lookup("slow.com")
    assert result.status is AgeStatus.UNKNOWN and result.final


def test_a_bug_in_the_client_does_not_escape() -> None:
    ages = service(FakeFetcher(error=RuntimeError("bug")))
    ages.lookup("example.com")
    ages.run_pending()
    assert ages.lookup("example.com").status is AgeStatus.UNKNOWN


def test_full_queue_answers_unknown_without_waiting() -> None:
    ages = service(FakeFetcher(), queue_size=1)
    assert ages.lookup("one.com").status is AgeStatus.PENDING
    assert ages.lookup("two.com").status is AgeStatus.UNKNOWN
    assert ages.lookup("two.com").status is AgeStatus.UNKNOWN  # still full, still not blocking


@pytest.mark.parametrize("host", ["com", "co.uk", "lugigo.duckdns.org", "pub-b379c3.r2.dev", "x.netlify.app"])
def test_suffixes_and_shared_platforms_are_never_looked_up(host: str) -> None:
    fetcher = FakeFetcher()
    ages = service(fetcher)
    assert ages.lookup(host).status is AgeStatus.UNKNOWN
    ages.run_pending()
    assert fetcher.urls == []


def test_lookup_domain() -> None:
    assert lookup_domain("a.b.example.com.sa") == "example.com.sa"
    assert lookup_domain("x.duckdns.org") is None
    assert lookup_domain("duckdns.org") == "duckdns.org"  # the platform's own site is a normal domain


def test_tls_context_still_verifies_certificates() -> None:
    assert _TLS.verify_mode is ssl.CERT_REQUIRED
    assert _TLS.check_hostname


def test_lookup_never_waits_for_the_network() -> None:
    release = threading.Event()

    def slow_fetcher(url: str, timeout: float) -> Any:
        if url.endswith("dns.json"):
            return BOOTSTRAP
        release.wait(5)
        return rdap_answer("2000-01-01T00:00:00Z")

    ages = DomainAgeService(RdapClient(fetcher=slow_fetcher), now=lambda: NOW, workers=1)
    try:
        started = time.perf_counter()
        assert ages.lookup("example.com").status is AgeStatus.PENDING
        assert time.perf_counter() - started < 0.1
        release.set()
        deadline = time.time() + 5
        while ages.lookup("example.com").status is AgeStatus.PENDING and time.time() < deadline:
            time.sleep(0.01)
        assert ages.lookup("example.com").status is AgeStatus.KNOWN
    finally:
        release.set()
        ages.close()


# ----- training helpers -----


def test_row_age_uses_the_report_date_for_malicious_rows() -> None:
    ages = {"bad.com": AgeRecord(datetime(2026, 1, 1, tzinfo=timezone.utc), NOW)}
    assert row_age_days("login.bad.com", "2026-01-11T00:00:00+00:00", ages) == 10
    assert row_age_days("bad.com", "", ages) == (NOW - datetime(2026, 1, 1, tzinfo=timezone.utc)).days
    assert row_age_days("bad.com", "2025-12-01T00:00:00+00:00", ages) is None  # re-registered after the report
    assert row_age_days("other.com", "", ages) is None


def test_load_ages_reads_the_fetch_output(tmp_path: Path) -> None:
    path = tmp_path / "ages.csv"
    path.write_text(
        "domain,created,status,checked_at\n"
        "old.com,2001-05-01T00:00:00+00:00,found,2026-10-17T00:00:00+00:00\n"
        "gone.com,,not_found,2026-10-17T00:00:00+00:00\n"
        "broken.com,2001-05-01,found,not-a-date\n",
        encoding="utf-8",
    )
    ages = load_ages(path)
    assert ages["old.com"].created == datetime(2001, 5, 1, tzinfo=timezone.utc)
    assert ages["gone.com"].created is None
    assert "broken.com" not in ages
    assert load_ages(tmp_path / "missing.csv") == {}


# ----- ml.fetch_domain_age -----


def test_pick_splits_between_classes_and_skips_done() -> None:
    groups = {0: {f"b{i}.com" for i in range(50)}, 1: {f"m{i}.com" for i in range(3)}}
    chosen = fetch_domain_age.pick(groups, done={"m0.com"}, max_lookups=10, seed=1)
    assert len(chosen) == 10
    assert sum(d.startswith("m") for d in chosen) == 2  # all that are left; benign fills the rest
    assert "m0.com" not in chosen


def test_fetch_writes_answers_and_skips_failures(tmp_path: Path) -> None:
    class Client:
        def registration_date(self, domain: str) -> datetime | None:
            if domain == "fail.com":
                raise AgeLookupError("timeout")
            return datetime(2020, 1, 1, tzinfo=timezone.utc) if domain == "old.com" else None

    out = tmp_path / "ages.csv"
    counts = fetch_domain_age.fetch(["old.com", "gone.com", "fail.com"], out, Client(), 0, sleep=lambda _: None)  # type: ignore[arg-type]
    assert counts == {"found": 1, "not_found": 1, "failed": 1}
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert [(r["domain"], r["status"]) for r in rows] == [
        ("old.com", "found"),
        ("gone.com", "not_found"),
        ("fail.com", "failed"),
    ]
    assert fetch_domain_age.read_done(out) == {"old.com", "gone.com", "fail.com"}
    assert fetch_domain_age.read_done(out, retry_failed=True) == {"old.com", "gone.com"}
    assert load_ages(out)["fail.com"].created is None  # a failure is an unknown age, not an error


def test_shared_platforms_are_not_picked(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset.csv"
    dataset.write_text(
        "host,label,split\nlugigo.duckdns.org,1,train\nlogin.bad-shop.com,1,train\nwww.example.org,0,train\n",
        encoding="utf-8",
    )
    assert fetch_domain_age.read_domains(dataset) == {0: {"example.org"}, 1: {"bad-shop.com"}}
