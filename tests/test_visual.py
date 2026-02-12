"""Tests for the visual impersonation check (Phase 11).

Nothing here opens a real website. The one browser test serves its pages from
localhost and only runs when HISN_TEST_BROWSER=1 (it needs Chromium).
"""

from __future__ import annotations

import http.server
import io
import ipaddress
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from PIL import Image, ImageDraw

from dns_server.decision import DecisionEngine, Reason, Verdict
from dns_server.visual_checks import VisualChecks
from ml.visual import capture as capture_module
from ml.visual.capture import BROWSER_ARGS, CaptureError, desktop_user_agent, with_base
from ml.visual.compare import (
    Reference,
    closest,
    distance,
    empty_share,
    from_hex,
    header_hash,
    is_nearly_empty,
    looks_like,
    phash,
    to_hex,
)
from ml.visual.evaluate import Sample, score, synthetic_clones
from ml.visual.reference_hashes import (
    OfficialPage,
    ReferenceError,
    build_hashes,
    capture_pages,
    load_references,
    parse_pages,
)
from ml.visual.ssrf_guard import (
    FetchError,
    GuardedFetcher,
    GuardError,
    UpstreamLookup,
    is_public_address,
    resolve_public,
)
from ml.visual.worker import ReferenceWatcher, VisualResult, check_host, work_once
from storage.cache import TTLCache
from storage.db import Database, VisualState

WHITELIST = frozenset({"alrajhibank.com.sa", "absher.sa"})


def login_page(color: tuple[int, int, int] = (0, 90, 160), shift: int = 0) -> Image.Image:
    """A fake official login page: header bar, logo, a form box."""
    image = Image.new("RGB", (1280, 800), (245, 245, 245))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0 + shift, 1280, 90 + shift), fill=color)
    draw.ellipse((60, 15 + shift, 130, 75 + shift), fill=(255, 255, 255))
    draw.rectangle((440, 200 + shift, 840, 620 + shift), fill=(255, 255, 255), outline=(200, 200, 200))
    draw.rectangle((480, 520 + shift, 800, 580 + shift), fill=color)
    return image


def other_page() -> Image.Image:
    """An unrelated page: dark, with a big picture on the left."""
    image = Image.new("RGB", (1280, 800), (20, 20, 30))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 700, 800), fill=(200, 120, 40))
    draw.rectangle((760, 100, 1240, 160), fill=(240, 240, 240))
    return image


def png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


# ----- SSRF guard -----


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("192.168.1.1", False),
        ("10.0.0.5", False),
        ("172.16.3.4", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("100.64.0.1", False),  # carrier-grade NAT
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fe80::1", False),
        ("fc00::1", False),
        ("::ffff:192.168.1.1", False),  # IPv4-mapped
        ("2002:c0a8:0101::1", False),  # 6to4 carrying 192.168.1.1
    ],
)
def test_only_public_addresses_pass(address: str, public: bool) -> None:
    assert is_public_address(ipaddress.ip_address(address)) is public


def test_resolve_public_prefers_ipv4() -> None:
    assert resolve_public("Shop.Example.COM.", lambda name: ["2606:4700::1", "93.184.216.34"]) == "93.184.216.34"


@pytest.mark.parametrize(
    "addresses",
    [[], ["93.184.216.34", "192.168.1.1"], ["10.0.0.1"], ["not-an-ip"]],
)
def test_resolve_public_refuses(addresses: list[str]) -> None:
    with pytest.raises(GuardError):
        resolve_public("shop.example.com", lambda name: addresses)


def test_resolve_public_refuses_invalid_names() -> None:
    with pytest.raises(GuardError):
        resolve_public("bad name!.com", lambda name: ["93.184.216.34"])


class FakeResolver:
    def __init__(self, rcode: int = RCODE.NOERROR, address: str = "93.184.216.34") -> None:
        self.rcode = rcode
        self.address = address

    def forward(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        reply.header.rcode = self.rcode
        if self.rcode == RCODE.NOERROR and request.q.qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.address), ttl=60))
        return reply


def test_upstream_lookup_collects_addresses() -> None:
    assert UpstreamLookup(FakeResolver()).__call__("shop.example.com") == ["93.184.216.34"]  # type: ignore[arg-type]


def test_upstream_lookup_nxdomain() -> None:
    with pytest.raises(GuardError):
        UpstreamLookup(FakeResolver(RCODE.NXDOMAIN))("gone.example.com")  # type: ignore[arg-type]


# ----- guarded fetcher (local servers; the guard is told 127.0.0.1 is "public") -----


class _Server(http.server.ThreadingHTTPServer):
    hits: list[str]


Routes = dict[str, tuple[int, dict[str, str], bytes]]


def _serve(routes: Routes) -> _Server:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            self.server.hits.append(self.path)  # type: ignore[attr-defined]
            status, headers, body = routes.get(self.path, (404, {}, b"not found"))
            self.send_response(status)
            for name, value in {"Content-Type": "text/html", **headers}.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = _Server(("127.0.0.1", 0), Handler)
    server.hits = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def make_server() -> Iterator[Callable[[Routes], _Server]]:
    started: list[_Server] = []

    def make(routes: Routes) -> _Server:
        started.append(_serve(routes))
        return started[-1]

    yield make
    for server in started:
        server.shutdown()


NAMES = {"site.example": ["127.0.0.1"], "cdn.example": ["127.0.0.1"], "router.example": ["10.0.0.1"]}


def local_fetcher(**kwargs: object) -> GuardedFetcher:
    loopback = ipaddress.ip_address("127.0.0.1")
    return GuardedFetcher(lambda name: NAMES.get(name, []), allowed=lambda ip: ip == loopback, **kwargs)  # type: ignore[arg-type]


def test_fetch_follows_redirects_through_the_guard(make_server: Callable[[Routes], _Server]) -> None:
    server = make_server({"/": (302, {"Location": "/home"}, b""), "/home": (200, {}, b"<html>hi</html>")})
    port = server.server_address[1]
    result = local_fetcher().fetch(f"http://site.example:{port}/", {"User-Agent": "x", "Cookie": "secret"})
    assert result.status == 200 and result.body == b"<html>hi</html>"
    assert result.url == f"http://site.example:{port}/home"
    assert result.headers == {"content-type": "text/html"}


def test_redirect_to_the_home_network_is_refused(make_server: Callable[[Routes], _Server]) -> None:
    server = make_server({"/": (302, {"Location": "http://router.example/admin"}, b"")})
    with pytest.raises(GuardError):
        local_fetcher().fetch(f"http://site.example:{server.server_address[1]}/")


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://unknown.example/", "file:///etc/passwd", "ftp://site.example/"])
def test_fetch_refuses(url: str) -> None:
    with pytest.raises((GuardError, FetchError)):
        local_fetcher().fetch(url)


def test_the_real_guard_refuses_loopback(make_server: Callable[[Routes], _Server]) -> None:
    server = make_server({"/": (200, {}, b"secret")})
    with pytest.raises(GuardError):
        GuardedFetcher(lambda name: ["127.0.0.1"]).fetch(f"http://site.example:{server.server_address[1]}/")
    assert server.hits == []


def test_fetch_limits_size_and_compression_bombs(make_server: Callable[[Routes], _Server]) -> None:
    import gzip

    bomb = gzip.compress(b"0" * 2_000_000)
    server = make_server({"/big": (200, {}, b"x" * 2000), "/bomb": (200, {"Content-Encoding": "gzip"}, bomb)})
    port = server.server_address[1]
    fetcher = local_fetcher(max_bytes=1000)
    for path in ("/big", "/bomb"):
        with pytest.raises(FetchError):
            fetcher.fetch(f"http://site.example:{port}{path}")
    small = make_server({"/": (200, {"Content-Encoding": "gzip"}, gzip.compress(b"hello"))})
    assert local_fetcher().fetch(f"http://site.example:{small.server_address[1]}/").body == b"hello"


def test_redirect_loops_stop(make_server: Callable[[Routes], _Server]) -> None:
    server = make_server({"/": (302, {"Location": "/"}, b"")})
    with pytest.raises(FetchError):
        local_fetcher().fetch(f"http://site.example:{server.server_address[1]}/")


def test_browser_resolves_nothing_itself() -> None:
    assert "--host-resolver-rules=MAP * ~NOTFOUND" in BROWSER_ARGS
    assert "--no-proxy-server" in BROWSER_ARGS


def test_with_base_and_user_agent() -> None:
    assert with_base(b"<html><HEAD lang=en><title>x</title>", "https://www.x.example/") == (
        b'<html><HEAD lang=en><base href="https://www.x.example/"><title>x</title>'
    )
    assert with_base(b"<p>no head</p>", "https://a.example/").startswith(b"<base ")
    agent = desktop_user_agent("140.0.7339.16")
    assert "Chrome/140.0.0.0" in agent and "Headless" not in agent


def test_capture_rejects_relative_paths() -> None:
    with pytest.raises(ValueError):
        capture_module.capture("absher.sa", local_fetcher(), timeout=5, path="evil")


# ----- pHash -----


def test_same_page_has_the_same_hash() -> None:
    assert distance(phash(png_bytes(login_page())), phash(login_page())) == 0


def test_a_slightly_changed_copy_stays_close_and_another_page_is_far() -> None:
    original = phash(login_page())
    copy = phash(login_page(shift=8))
    unrelated = phash(other_page())
    assert distance(original, copy) <= 10
    assert distance(original, unrelated) > 20


def error_page() -> Image.Image:
    """What bot protection shows: black text on white ("The requested URL was rejected")."""
    image = Image.new("RGB", (1900, 900), (255, 255, 255))
    ImageDraw.Draw(image).rectangle((8, 8, 480, 24), fill=(0, 0, 0))
    ImageDraw.Draw(image).rectangle((8, 40, 300, 56), fill=(0, 0, 0))
    return image


def test_empty_pages_are_recognised() -> None:
    assert is_nearly_empty(png_bytes(error_page()))
    assert is_nearly_empty(Image.new("RGB", (1900, 900), (0, 0, 0)))
    assert empty_share(error_page()) > 0.98
    # Real pages stay well under the limit, light or dark.
    assert not is_nearly_empty(png_bytes(login_page()))
    assert not is_nearly_empty(png_bytes(other_page()))
    dark = Image.new("RGB", (1900, 900), (18, 20, 28))
    ImageDraw.Draw(dark).rectangle((600, 150, 1300, 700), fill=(40, 46, 60))
    ImageDraw.Draw(dark).rectangle((0, 0, 1900, 120), fill=(30, 35, 45))
    assert not is_nearly_empty(dark)


def test_hex_round_trip() -> None:
    value = phash(login_page())
    assert from_hex(to_hex(value)) == value
    with pytest.raises(ValueError):
        from_hex("1" * 17)


def test_closest_and_looks_like() -> None:
    references = [Reference("alrajhi", "a.png", 0b1111), Reference("absher", "b.png", 0)]
    assert closest(0b0111, references).brand == "alrajhi"  # type: ignore[union-attr]
    assert looks_like(0b0111, references, 1).distance == 1  # type: ignore[union-attr]
    assert looks_like(0b0111, references, 0) is None
    assert closest(1, []) is None


def with_other_banner(image: Image.Image) -> Image.Image:
    """The same page under the header, with a different hero banner below it."""
    image = image.copy()
    ImageDraw.Draw(image).rectangle((0, 170, 1280, 800), fill=(15, 15, 40))
    return image


def test_a_changed_banner_still_matches_by_the_header() -> None:
    official, banner = login_page(), with_other_banner(login_page())
    assert distance(phash(official), phash(banner)) > 10  # the whole page no longer looks alike
    references = [Reference("alrajhi", "a.png", phash(official), header_hash(official))]
    match = looks_like(phash(banner), references, 10, header_hash(banner))
    assert match is not None
    assert (match.part, match.distance) == ("header", 0)
    assert looks_like(phash(banner), references, 10) is None  # without the header hash it is missed


def test_unrelated_header_does_not_match() -> None:
    references = [Reference("alrajhi", "a.png", phash(login_page()), header_hash(login_page()))]
    unrelated = other_page()
    assert looks_like(phash(unrelated), references, 10, header_hash(unrelated)) is None


def test_blank_header_is_never_compared() -> None:
    blank = Image.new("RGB", (1280, 800), (255, 255, 255))
    assert header_hash(blank) is None
    assert header_hash(png_bytes(login_page())) is not None
    # a reference without a header hash (an old hashes.json) falls back to the whole page
    old = [Reference("alrajhi", "a.png", phash(login_page()))]
    match = closest(phash(login_page()), old, header_hash(login_page()))
    assert match is not None and match.part == "page"


# ----- references -----


def test_parse_pages(tmp_path: Path) -> None:
    pages = tmp_path / "references.txt"
    pages.write_text("# comment\nalrajhi https://www.alrajhibank.com.sa/login  # login\nabsher https://absher.sa\n")
    assert parse_pages(pages, WHITELIST) == [
        OfficialPage("alrajhi", "https://www.alrajhibank.com.sa/login", "www.alrajhibank.com.sa", "/login"),
        OfficialPage("absher", "https://absher.sa", "absher.sa", "/"),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "alrajhi https://alrajhi-bank.com/",  # not official
        "alrajhi http://www.alrajhibank.com.sa/",  # not https
        "alrajhi https://www.alrajhibank.com.sa:8443/",
        "alrajhi https://www.alrajhibank.com.sa/?q=1",
        "Al Rajhi https://www.alrajhibank.com.sa/",
        "alrajhi",
    ],
)
def test_parse_pages_refuses(tmp_path: Path, line: str) -> None:
    pages = tmp_path / "references.txt"
    pages.write_text(line + "\n")
    with pytest.raises(ReferenceError):
        parse_pages(pages, WHITELIST)


def test_build_and_load_hashes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    login_page().save(tmp_path / "alrajhi--login.png")
    other_page().save(tmp_path / "no-brand.png")
    built = build_hashes(tmp_path)
    assert [r.brand for r in built] == ["alrajhi"]
    assert "ignored no-brand.png" in capsys.readouterr().out
    assert load_references(tmp_path) == built
    assert load_references(tmp_path / "missing") == []


def test_hashes_file_keeps_the_header_hash_and_reads_old_files(tmp_path: Path) -> None:
    (tmp_path / "alrajhi--login.png").write_bytes(png_bytes(login_page()))
    (built,) = build_hashes(tmp_path)
    assert built.header == header_hash(login_page())
    assert load_references(tmp_path) == [built]
    # a hashes.json written before the header hash existed still loads
    (tmp_path / "hashes.json").write_text(
        json.dumps({"references": [{"brand": "alrajhi", "source": "a.png", "hash": to_hex(built.hash)}]})
    )
    assert load_references(tmp_path) == [Reference("alrajhi", "a.png", built.hash, None)]


def test_check_host_matches_a_changed_banner_by_the_header() -> None:
    references = [Reference("alrajhi", "alrajhi--login.png", phash(login_page()), header_hash(login_page()))]
    result = check_host(
        "clone.example", references, lookup=PUBLIC, capture=lambda host: png_bytes(with_other_banner(login_page())), max_distance=10
    )
    assert (result.status, result.brand, result.distance) == ("match", "alrajhi", 0)
    assert "page header" in result.detail


def test_error_pages_never_become_references(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    error_page().save(tmp_path / "alinma--www-alinma-com-1.png")
    login_page().save(tmp_path / "alrajhi--login.png")
    assert [r.brand for r in build_hashes(tmp_path)] == ["alrajhi"]
    assert "nearly empty" in capsys.readouterr().out


def test_damaged_hashes_file(tmp_path: Path) -> None:
    (tmp_path / "hashes.json").write_text(json.dumps({"references": [{"brand": "x", "source": "a", "hash": "zz"}]}))
    with pytest.raises(ReferenceError):
        load_references(tmp_path)


def test_capture_pages_skips_failures(tmp_path: Path) -> None:
    pages = [
        OfficialPage("alrajhi", "https://www.alrajhibank.com.sa/", "www.alrajhibank.com.sa", "/"),
        OfficialPage("absher", "https://absher.sa/", "absher.sa", "/"),
    ]

    def fake(page: OfficialPage) -> list[bytes]:
        if page.brand == "absher":
            raise RuntimeError("timeout")
        return [png_bytes(login_page()), png_bytes(login_page(shift=4))]

    (tmp_path / "alrajhi--www-alrajhibank-com-sa.png").write_bytes(b"old shot")
    assert capture_pages(pages, tmp_path, fake) == 2
    assert capture_pages(pages[:1], tmp_path, lambda page: [png_bytes(error_page())] * 3) == 0  # bot check page
    assert len(list(tmp_path.glob("alrajhi*.png"))) == 2  # the good shots were kept
    assert sorted(p.name for p in tmp_path.glob("*.png")) == [
        "alrajhi--www-alrajhibank-com-sa-1.png",
        "alrajhi--www-alrajhibank-com-sa-2.png",
    ]


# ----- worker -----

REFERENCES = [Reference("alrajhi", "alrajhi--login.png", phash(login_page()))]
PUBLIC = lambda name: ["93.184.216.34"]  # noqa: E731


def test_check_host_match_and_clear() -> None:
    clone = check_host("alrajhi-online.top", REFERENCES, lookup=PUBLIC, capture=lambda h: png_bytes(login_page(shift=6)), max_distance=10)
    assert clone.status == "match" and clone.brand == "alrajhi"
    other = check_host("recipes.example", REFERENCES, lookup=PUBLIC, capture=lambda h: png_bytes(other_page()), max_distance=10)
    assert other.status == "clear" and other.distance is not None and other.distance > 10


def test_check_host_never_opens_private_addresses() -> None:
    opened: list[str] = []

    def capture(host: str) -> bytes:
        opened.append(host)
        return png_bytes(login_page())

    result = check_host("router.example", REFERENCES, lookup=lambda n: ["192.168.1.1"], capture=capture, max_distance=10)
    assert result.status == "failed" and opened == []


def test_a_bot_check_page_is_never_compared() -> None:
    result = check_host(
        "alinma-online.top", REFERENCES, lookup=PUBLIC, capture=lambda h: png_bytes(error_page()), max_distance=64
    )
    assert result.status == "failed" and "bot check" in result.detail


def test_check_host_capture_problems_fail_quietly() -> None:
    def broken(host: str) -> bytes:
        raise CaptureError("did not load")

    assert check_host("x.example", REFERENCES, lookup=PUBLIC, capture=broken, max_distance=10).status == "failed"
    garbage = check_host("x.example", REFERENCES, lookup=PUBLIC, capture=lambda h: b"not a png", max_distance=10)
    assert garbage.status == "failed"
    assert check_host("bad name", REFERENCES, lookup=PUBLIC, capture=broken, max_distance=10).status == "failed"


def test_work_once_with_the_database(tmp_path: Path) -> None:
    db = Database(":memory:")
    login_page().save(tmp_path / "alrajhi--login.png")
    build_hashes(tmp_path)
    watcher = ReferenceWatcher(tmp_path)
    db.request_visual_check("alrajhi-online.top", ttl=3600, ts=100)

    def check(host: str, refs: object) -> VisualResult:
        return VisualResult("match", "alrajhi", 3, "looks like alrajhi--login.png")

    assert work_once(db, watcher, check) is True
    assert db.visual_states(3600, ts=200) == {"alrajhi-online.top": VisualState("match", "alrajhi")}
    assert work_once(db, watcher, check) is False  # queue empty


def test_reference_watcher_reloads(tmp_path: Path) -> None:
    watcher = ReferenceWatcher(tmp_path)
    assert watcher.current() == []
    login_page().save(tmp_path / "alrajhi--login.png")
    build_hashes(tmp_path)
    assert [r.brand for r in watcher.current()] == ["alrajhi"]


# ----- database queue -----


def test_queue_semantics() -> None:
    db = Database(":memory:")
    assert db.request_visual_check("a.example", ttl=100, ts=1000) is True
    assert db.request_visual_check("a.example", ttl=100, ts=1001) is False  # already pending
    assert db.pending_visual_checks() == ["a.example"]
    db.save_visual_result("a.example", "clear", distance=30, ts=1010)
    assert db.pending_visual_checks() == []
    assert db.request_visual_check("a.example", ttl=100, ts=1050) is False  # fresh result
    assert db.visual_states(100, ts=1050) == {"a.example": VisualState("clear", None)}
    assert db.visual_states(100, ts=1200) == {}  # result too old to trust
    assert db.request_visual_check("a.example", ttl=100, ts=1200) is True  # checked again
    with pytest.raises(ValueError):
        db.save_visual_result("a.example", "pending")


def test_results_for_deleted_names_are_not_written_back() -> None:
    db = Database(":memory:")
    db.request_visual_check("a.example", ttl=100, ts=1000)
    db.delete_all_logs()
    db.save_visual_result("a.example", "match", "alrajhi", 2, ts=1001)
    assert db.visual_states(100, ts=1001) == {}


def test_visual_checks_are_purged_with_the_logs() -> None:
    db = Database(":memory:")
    db.request_visual_check("old.example", ttl=100, ts=0)
    db.request_visual_check("new.example", ttl=100, ts=40 * 86400)
    db.purge_older_than(30, now=40 * 86400)
    assert db.pending_visual_checks(10) == ["new.example"]


# ----- DNS side -----


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_visual_checks_refresh_and_request() -> None:
    db = Database(":memory:")
    clock = Clock()
    checks = VisualChecks(db, ttl=3600, refresh=2.0, clock=clock)
    assert checks.state("a.example") is None
    checks.request("a.example")
    assert checks.state("a.example") == VisualState("pending", None)
    db.save_visual_result("a.example", "match", "absher", 4)
    assert checks.state("a.example").status == "pending"  # type: ignore[union-attr]
    clock.now = 2.0
    assert checks.state("a.example") == VisualState("match", "absher")


class BrokenStore:
    def request_visual_check(self, domain: str, ttl: int, ts: float | None = None) -> bool:
        raise sqlite3.OperationalError("locked")

    def visual_states(self, ttl: int, ts: float | None = None) -> dict[str, VisualState]:
        raise sqlite3.OperationalError("locked")


def test_visual_checks_survive_database_errors() -> None:
    checks = VisualChecks(BrokenStore(), ttl=3600)
    assert checks.state("a.example") is None
    checks.request("a.example")  # logged, not raised


class FixedScorer:
    def __init__(self, probability: float) -> None:
        self.value = probability

    def probability(self, host: str, age_days: float | None = None) -> float:
        return self.value


class FakeVisual:
    def __init__(self, state: VisualState | None = None) -> None:
        self.current = state
        self.requested: list[str] = []

    def state(self, domain: str) -> VisualState | None:
        return self.current

    def request(self, domain: str) -> None:
        self.requested.append(domain)


def make_engine(probability: float, visual: object) -> tuple[DecisionEngine, TTLCache[Verdict]]:
    cache: TTLCache[Verdict] = TTLCache(3600)
    engine = DecisionEngine(
        WHITELIST,
        frozenset(),
        cache,
        scorer=FixedScorer(probability),
        threshold=0.9,
        visual=visual,  # type: ignore[arg-type]
        visual_min_score=0.5,
    )
    return engine, cache


def test_low_scores_are_never_checked() -> None:
    visual = FakeVisual()
    engine, _ = make_engine(0.3, visual)
    assert engine.decide("recipes.example").verdict is Verdict.ALLOW
    assert visual.requested == []


def test_high_scores_are_blocked_by_the_model_without_a_check() -> None:
    visual = FakeVisual()
    engine, _ = make_engine(0.95, visual)
    assert engine.decide("x.example").reason is Reason.MODEL
    assert visual.requested == []


def test_suspicious_names_are_queued_and_not_cached() -> None:
    visual = FakeVisual()
    engine, cache = make_engine(0.7, visual)
    decision = engine.decide("alrajhi-online.top")
    assert decision.verdict is Verdict.ALLOW and decision.reason is Reason.MODEL
    assert visual.requested == ["alrajhi-online.top"]
    assert cache.get("alrajhi-online.top") is None
    visual.current = VisualState("pending", None)
    engine.decide("alrajhi-online.top")
    assert visual.requested == ["alrajhi-online.top"]  # queued once
    assert cache.get("alrajhi-online.top") is None


def test_a_visual_match_blocks_and_is_cached() -> None:
    engine, cache = make_engine(0.7, FakeVisual(VisualState("match", "alrajhi")))
    decision = engine.decide("alrajhi-online.top")
    assert decision.blocked and decision.reason is Reason.VISUAL and decision.matched == "alrajhi"
    assert cache.get("alrajhi-online.top") is Verdict.BLOCK


@pytest.mark.parametrize("status", ["clear", "failed"])
def test_no_match_keeps_the_model_verdict(status: str) -> None:
    engine, cache = make_engine(0.7, FakeVisual(VisualState(status, None)))
    assert engine.decide("recipes.example").verdict is Verdict.ALLOW
    assert cache.get("recipes.example") is Verdict.ALLOW


def test_lists_win_over_a_visual_match() -> None:
    engine, _ = make_engine(0.7, FakeVisual(VisualState("match", "alrajhi")))
    assert engine.decide("www.alrajhibank.com.sa").reason is Reason.WHITELIST


def test_a_broken_visual_check_fails_open() -> None:
    class Broken(FakeVisual):
        def state(self, domain: str) -> VisualState | None:
            raise RuntimeError("bug")

    engine, _ = make_engine(0.7, Broken())
    assert engine.decide("x.example").verdict is Verdict.ALLOW


def test_server_keeps_the_check_off_by_default() -> None:
    from config import settings
    from dns_server.server import load_visual_checks

    assert settings.visual_check is False
    assert load_visual_checks(settings, Database(":memory:"), has_model=True) is None


def test_server_turns_it_on_only_with_the_model() -> None:
    import dataclasses

    from config import settings
    from dns_server.server import load_visual_checks

    on = dataclasses.replace(settings, visual_check=True)
    assert load_visual_checks(on, Database(":memory:"), has_model=False) is None
    assert isinstance(load_visual_checks(on, Database(":memory:"), has_model=True), VisualChecks)


# ----- evaluation -----


def test_evaluation_counts(tmp_path: Path) -> None:
    login_page().save(tmp_path / "alrajhi--login.png")
    references = build_hashes(tmp_path)
    clones = synthetic_clones(tmp_path, references)
    assert len(clones) == 7 and all(c.positive for c in clones)
    negatives = [Sample("other.png", phash(other_page()), False)]
    scores = score(clones + negatives, references, max_distance=12)
    assert scores.false_positives == 0
    assert scores.recall >= 0.7
    assert scores.precision == 1.0
    assert score(clones + negatives, references, max_distance=64).false_positives == 1


# ----- the real browser (opt-in) -----


@pytest.mark.skipif(os.environ.get("HISN_TEST_BROWSER") != "1", reason="set HISN_TEST_BROWSER=1 to run the browser")
def test_browser_reaches_only_guarded_addresses(make_server: Callable[[Routes], _Server]) -> None:
    other = make_server({"/logo.png": (200, {"Content-Type": "image/png"}, png_bytes(login_page()))})
    other_port = other.server_address[1]
    page = (
        "<html><head><link rel=stylesheet href='style.css'></head><body><h1>Bank login</h1>"
        f"<img src='http://cdn.example:{other_port}/logo.png'>"  # third-party file: fetched through the guard
        f"<img src='http://127.0.0.1:{other_port}/ip.png'>"  # IP address: refused
        f"<img src='http://router.example:{other_port}/admin.png'>"  # private address: refused
        f"<script>fetch('http://127.0.0.1:{other_port}/xhr').catch(() => {{}});"
        f"new WebSocket('ws://127.0.0.1:{other_port}/ws');"
        f"window.open('http://127.0.0.1:{other_port}/popup')</script></body></html>"
    ).encode()
    site = make_server(
        {
            "/": (302, {"Location": "/home"}, b""),
            "/home": (200, {}, page),
            "/style.css": (200, {"Content-Type": "text/css"}, b"body { background: #06c }"),
        }
    )
    port = site.server_address[1]

    class TestFetcher(GuardedFetcher):
        def fetch(self, url: str, headers: object = None):  # type: ignore[override]
            # The site listens on a random port; the real worker uses 80/443.
            return super().fetch(url.replace("://site.example/", f"://site.example:{port}/", 1), headers)  # type: ignore[arg-type]

    loopback = ipaddress.ip_address("127.0.0.1")
    fetcher = TestFetcher(lambda name: NAMES.get(name, []), allowed=lambda ip: ip == loopback)
    (png,) = capture_module.capture(
        "site.example",
        fetcher,
        timeout=20,
        browser_path=os.environ.get("HISN_VISUAL_BROWSER_PATH", ""),
        sandbox=os.environ.get("HISN_TEST_SANDBOX", "1") == "1",
    )
    assert Image.open(io.BytesIO(png)).size == (1900, 900)
    assert site.hits == ["/", "/home", "/style.css"]  # the base tag made style.css resolve after the redirect
    assert other.hits == ["/logo.png"]  # only the guarded third-party file
    assert Image.open(io.BytesIO(png)).convert("RGB").getpixel((5, 890)) == (0, 102, 204)  # the stylesheet applied
