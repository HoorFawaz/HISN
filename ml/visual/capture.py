"""Take screenshots of a site in a locked-down headless browser.

The pages opened here are suspected phishing pages, so the browser is treated
as hostile ground:

- **The browser never connects to anything itself.** Every request it makes
  (the page, its images, styles, scripts, on any host) is handed to
  :class:`ssrf_guard.GuardedFetcher`, which checks every host and every
  redirect against the public-address rule and connects to exactly the
  address it checked. Only GET over http(s) is fetched; anything else is
  aborted. As a second wall, ``--host-resolver-rules`` makes every name and
  IP address "not found" inside the browser, so a WebSocket, a pop-up or
  anything the routing misses cannot connect either.
- **No other way out.** No proxy, WebRTC limited to proxied UDP (so, with no
  proxy, none), no DNS prefetch, no background networking, service workers
  blocked, pop-ups closed, downloads refused, no cookies kept between files.
- **Nothing kept.** A fresh, empty browser profile for every page. The
  screenshot stays in memory; only its hash is kept (``compare.py``).
- **Sandboxed, not privileged.** Chromium's own sandbox is on. The worker
  refuses to start as root or as a Windows administrator
  (:func:`privilege_problem`): a browser exploit would get the rights of the
  user that runs it.

The official reference pages (``reference_hashes.py``) are photographed the
same way, so a reference and a check of the same page see exactly the same
thing. CSS animations are frozen for the screenshot.

Command line, to collect screenshots for ``evaluate.py`` (run from the
project root, in a normal window, not as administrator)::

    python -m ml.visual.capture --out data/visual_eval/negatives google.com wikipedia.org
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import logging
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from ml.visual.ssrf_guard import FetchError, GuardedFetcher, GuardError

logger = logging.getLogger(__name__)

# A maximised browser on a normal screen (about 1900 x 900 of page). Reference screenshots taken by
# hand have this size, and a page lays itself out by the width, so the check must match it.
VIEWPORT = {"width": 1900, "height": 900}
SETTLE_MS = 1500  # after the page is quiet, for late styles and images
IDLE_MS = 10_000  # longest wait for the page to stop loading (sliders, lazy images)
SHOT_INTERVAL_MS = 2500  # between screenshots of one page (rotating banners)
MAX_REQUESTS = 300  # per page; the rest is aborted
_HEAD_RE = re.compile(rb"<head[^>]*>", re.IGNORECASE)


class CaptureError(Exception):
    """The page could not be opened or photographed."""


def privilege_problem() -> str | None:
    """Why the browser must not run as the current user, or None if it may."""
    if hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            return "running as root; start the visual check as a normal user"
        return None
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
            return "running as administrator; start the visual check in a normal (not administrator) window"
    except (AttributeError, OSError):
        pass
    return None


BROWSER_ARGS = [
    # Inside the browser nothing resolves: every request goes through the
    # guarded fetcher instead.
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--no-proxy-server",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--no-first-run",
    "--no-default-browser-check",
]


def desktop_user_agent(version: str) -> str:
    """The user agent of a normal Chrome on Windows, for ``version``."""
    major = version.split(".", 1)[0] if version[:1].isdigit() else "140"
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


def with_base(html: bytes, url: str) -> bytes:
    """Add ``<base href=url>`` so relative links resolve against the page's final address.

    The browser still believes it is on the first address when the fetcher
    followed a redirect (``google.com`` -> ``www.google.com``).
    """
    tag = b'<base href="' + url.replace('"', "%22").encode("ascii", "replace") + b'">'
    match = _HEAD_RE.search(html)
    if match:
        return html[: match.end()] + tag + html[match.end() :]
    return tag + html


def capture(
    host: str,
    fetcher: GuardedFetcher,
    *,
    timeout: float,
    path: str = "/",
    shots: int = 1,
    browser_path: str = "",
    sandbox: bool = True,
) -> list[bytes]:
    """PNG screenshots of ``host`` (its home page, or ``path``).

    https is tried first, then http. ``shots`` screenshots are taken
    ``SHOT_INTERVAL_MS`` apart. ``sandbox=False`` exists only for tests in
    containers that run as root.
    """
    if not path.startswith("/"):
        raise ValueError("path must start with /")
    try:
        import playwright.async_api  # noqa: F401
    except ImportError as exc:
        raise CaptureError("Playwright is not installed (pip install -r requirements.txt)") from exc
    return asyncio.run(_capture(host, fetcher, timeout, path, shots, browser_path, sandbox))


async def _capture(
    host: str,
    fetcher: GuardedFetcher,
    timeout: float,
    path: str,
    shots: int,
    browser_path: str,
    sandbox: bool,
) -> list[bytes]:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import Route, async_playwright

    requests = 0

    async def route(route: Route) -> None:
        nonlocal requests
        request = route.request
        requests += 1
        if request.method != "GET" or requests > MAX_REQUESTS or not request.url.startswith(("http://", "https://")):
            await route.abort()
            return
        try:
            # In a thread, so the files of a page download in parallel.
            result = await asyncio.to_thread(fetcher.fetch, request.url, request.headers)
        except (GuardError, FetchError) as exc:
            logger.debug("refused %s: %s", request.url, exc)
            await route.abort()
            return
        body = result.body
        html = "html" in result.headers.get("content-type", "")
        if request.is_navigation_request() and html and result.url != request.url:
            body = with_base(body, result.url)
        await route.fulfill(status=result.status, headers=result.headers, body=body)

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                chromium_sandbox=sandbox,
                executable_path=browser_path or None,
                args=BROWSER_ARGS,
            )
            try:
                context = await browser.new_context(
                    viewport=VIEWPORT,
                    accept_downloads=False,
                    service_workers="block",
                    # Arabic first: Saudi sites choose their language from this, and the references are Arabic pages.
                    locale="ar-SA",
                    timezone_id="Asia/Riyadh",
                    # A normal desktop browser: many kits show "HeadlessChrome" a harmless page.
                    user_agent=desktop_user_agent(browser.version),
                )
                await context.route("**/*", route)
                errors: list[str] = []
                for scheme in ("https", "http"):
                    # A fresh tab per attempt: the error page of a failed
                    # attempt would otherwise interrupt the next navigation.
                    page = await context.new_page()
                    page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))
                    page.on("popup", lambda popup: asyncio.ensure_future(popup.close()))
                    try:
                        await page.goto(f"{scheme}://{host}{path}", wait_until="load", timeout=timeout * 1000)
                        break
                    except PlaywrightError as exc:
                        errors.append(f"{scheme}: {str(exc).splitlines()[0]}")
                        await page.close()
                else:
                    raise CaptureError(f"{host} did not load ({'; '.join(errors)})")
                try:
                    # Pages that build themselves with scripts keep loading after
                    # "load"; a screenshot of a half-built page would not match.
                    await page.wait_for_load_state("networkidle", timeout=min(IDLE_MS, timeout * 1000))
                except PlaywrightError:
                    pass  # some pages never go quiet; take the screenshot anyway
                images: list[bytes] = []
                for index in range(max(1, shots)):
                    await page.wait_for_timeout(SETTLE_MS if index == 0 else SHOT_INTERVAL_MS)
                    images.append(
                        await page.screenshot(type="png", full_page=False, animations="disabled", timeout=timeout * 1000)
                    )
                return images
            finally:
                await browser.close()
    except PlaywrightError as exc:
        raise CaptureError(f"browser failed on {host}: {str(exc).splitlines()[0]}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    from config import settings
    from dns_server.domain import InvalidDomainError, normalize_domain
    from dns_server.resolver import UpstreamResolver
    from ml.visual.ssrf_guard import UpstreamLookup

    parser = argparse.ArgumentParser(prog="python -m ml.visual.capture", description=__doc__.split("\n")[0])
    parser.add_argument("names", nargs="*", help="domain names to photograph")
    parser.add_argument("--names-file", type=Path, help="one domain name per line")
    parser.add_argument("--out", type=Path, required=True, help="folder for the PNG files")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    problem = privilege_problem()
    if problem:
        print(f"Not started: {problem}.", file=sys.stderr)
        return 1
    names = list(args.names)
    if args.names_file:
        names += [line.split("#", 1)[0].strip() for line in args.names_file.read_text(encoding="utf-8").splitlines()]
    names = [name for name in names if name]
    if not names:
        parser.error("give at least one name")
    lookup = UpstreamLookup(
        UpstreamResolver(str(settings.upstream_dns), settings.upstream_port, settings.upstream_timeout)
    )
    args.out.mkdir(parents=True, exist_ok=True)
    saved = 0
    for raw in names:
        try:
            name = normalize_domain(raw)  # also makes it safe as a file name
            fetcher = GuardedFetcher(lookup)
            fetcher.address(name)  # refuse private names before starting the browser
            (png,) = capture(name, fetcher, timeout=settings.visual_timeout, browser_path=settings.visual_browser_path)
        except (InvalidDomainError, GuardError, CaptureError) as exc:
            print(f"  skipped {raw}: {exc}")
            continue
        (args.out / f"{name}.png").write_bytes(png)
        saved += 1
        print(f"  saved {name}.png")
    print(f"{saved} of {len(names)} screenshots saved in {args.out}")
    return 0 if saved else 1


if __name__ == "__main__":
    raise SystemExit(main())
