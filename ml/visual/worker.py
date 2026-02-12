"""The visual check worker: works through the names the DNS server queued.

Run it in its own window, as a normal user (not as administrator), next to
the DNS server, after building the references::

    python -m ml.visual.reference_hashes
    python -m ml.visual.worker

For each queued name it:

1. resolves the name through the upstream DNS server and refuses anything
   that is not a public address (``ssrf_guard.py``);
2. opens the home page in the sandboxed browser, whose every request goes
   through the same guard, and takes one screenshot (``capture.py``), kept in
   memory only;
3. compares its pHash with the official references (``compare.py``);
4. writes the result: ``match`` (looks like an official site, so the DNS
   server blocks it from then on, reason "visual"), ``clear`` or ``failed``.

One page at a time, with a pause between pages, so a burst of suspicious
names cannot keep the browser running nonstop. If the worker is not running,
names simply stay queued and the model's verdict stands.

To test one name without saving anything::

    python -m ml.visual.worker --check example.com
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from dns_server.domain import InvalidDomainError, normalize_domain
from ml.visual.capture import CaptureError
from ml.visual.compare import Reference, closest, empty_share, header_hash, is_nearly_empty, phash
from ml.visual.reference_hashes import HASHES_FILE, ReferenceError, load_references
from ml.visual.ssrf_guard import GuardError, Lookup, resolve_public

logger = logging.getLogger(__name__)

IDLE_SECONDS = 2.0  # how often an empty queue is looked at again
PAUSE_SECONDS = 3.0  # between two pages


@dataclass(frozen=True)
class VisualResult:
    status: str  # "match", "clear" or "failed"
    brand: str | None = None
    distance: int | None = None
    detail: str = ""


CaptureFn = Callable[[str], bytes]  # host -> PNG


def check_host(
    host: str,
    references: Sequence[Reference],
    *,
    lookup: Lookup,
    capture: CaptureFn,
    max_distance: int,
) -> VisualResult:
    """Guard, photograph and compare one name. Never raises for a bad site."""
    try:
        host = normalize_domain(host)
        resolve_public(host, lookup)  # refuse private names before starting the browser
    except InvalidDomainError as exc:
        return VisualResult("failed", detail=f"invalid name: {exc}")
    except GuardError as exc:
        return VisualResult("failed", detail=str(exc))
    try:
        png = capture(host)
        if is_nearly_empty(png):
            # A blank page, an error or a bot check looks the same on every site: never compare it.
            return VisualResult("failed", detail=f"nothing to compare: the page is almost one colour (blank, an error, a bot check, or a very plain page like google.com) ({empty_share(png):.2f})")
        value, header = phash(png), header_hash(png)
    except CaptureError as exc:
        return VisualResult("failed", detail=str(exc))
    except (OSError, ValueError) as exc:  # not a readable image
        return VisualResult("failed", detail=f"bad screenshot: {exc}")
    best = closest(value, references, header)
    if best is None:
        return VisualResult("failed", detail="no references")
    part = " (page header)" if best.part == "header" else ""
    if best.distance <= max_distance:
        return VisualResult("match", best.brand, best.distance, f"looks like {best.source}{part}")
    return VisualResult("clear", None, best.distance, f"closest {best.source}{part}")


class ReferenceWatcher:
    """The current references, reloaded when ``hashes.json`` changes."""

    def __init__(self, directory: Path) -> None:
        self._path = directory / HASHES_FILE
        self._directory = directory
        self._mtime: float | None = None
        self._references: list[Reference] = []

    def current(self) -> list[Reference]:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return self._references
        if mtime != self._mtime:
            try:
                self._references = load_references(self._directory)
                self._mtime = mtime
                logger.info("loaded %d visual references", len(self._references))
            except ReferenceError as exc:
                logger.warning("%s (keeping the previous references)", exc)
        return self._references


class Queue(Protocol):
    """What the worker needs from ``storage.db.Database``."""

    def pending_visual_checks(self, limit: int = 1) -> list[str]: ...

    def save_visual_result(
        self, domain: str, status: str, brand: str | None = None, distance: int | None = None, ts: float | None = None
    ) -> None: ...


def work_once(queue: Queue, references: ReferenceWatcher, check: Callable[[str, Sequence[Reference]], VisualResult]) -> bool:
    """Check the oldest queued name. False if the queue was empty."""
    names = queue.pending_visual_checks(limit=1)
    if not names:
        return False
    host = names[0]
    result = check(host, references.current())
    queue.save_visual_result(host, result.status, result.brand, result.distance)
    logger.info("%s -> %s%s (%s)", host, result.status, f" {result.brand}" if result.brand else "", result.detail)
    return True


def main(argv: Sequence[str] | None = None) -> int:
    from config import settings
    from dns_server.resolver import UpstreamResolver
    from ml.visual.capture import capture, privilege_problem
    from ml.visual.ssrf_guard import GuardedFetcher, UpstreamLookup
    from storage.db import Database

    parser = argparse.ArgumentParser(prog="python -m ml.visual.worker", description=__doc__.split("\n")[0])
    parser.add_argument("--check", metavar="NAME", help="check one name and print the result (nothing goes to the database)")
    parser.add_argument("--save", type=Path, metavar="PNG", help="with --check: also save the screenshot to this file")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    problem = privilege_problem()
    if problem:
        print(f"Not started: {problem}.", file=sys.stderr)
        return 1
    references = ReferenceWatcher(settings.references_dir)
    if not references.current():
        print("No references yet. Build them first: python -m ml.visual.reference_hashes", file=sys.stderr)
        return 1

    lookup = UpstreamLookup(
        UpstreamResolver(str(settings.upstream_dns), settings.upstream_port, settings.upstream_timeout)
    )

    def photograph(host: str) -> bytes:
        # A new fetcher per page: no address or cookie survives from one site to the next.
        (png,) = capture(
            host,
            GuardedFetcher(lookup),
            timeout=settings.visual_timeout,
            browser_path=settings.visual_browser_path,
        )
        if args.save:
            args.save.write_bytes(png)
        return png

    def check(host: str, refs: Sequence[Reference]) -> VisualResult:
        return check_host(host, refs, lookup=lookup, capture=photograph, max_distance=settings.visual_max_distance)

    if args.check:
        result = check(args.check, references.current())
        print(f"{args.check}: {result.status}", end="")
        if result.distance is not None:
            print(f", distance {result.distance} (match at {settings.visual_max_distance} or less)", end="")
        print(f"{', brand ' + result.brand if result.brand else ''}. {result.detail}")
        if args.save and args.save.exists():
            shot = args.save.read_bytes()
            value, header = phash(shot), header_hash(shot)
            print(f"Screenshot saved to {args.save}. Closest reference of each brand:")
            for brand in sorted({r.brand for r in references.current()}):
                best = closest(value, [r for r in references.current() if r.brand == brand], header)
                if best is not None:
                    print(f"  {brand:12} {best.distance:>2}  {best.source} ({best.part})")
        return 0

    if not settings.visual_check:
        logger.warning("HISN_VISUAL_CHECK is false: the DNS server queues nothing for this worker")
    database = Database(settings.db_path)
    logger.info("visual worker started; waiting for names queued by the DNS server")
    try:
        while True:
            try:
                busy = work_once(database, references, check)
            except sqlite3.Error as exc:
                logger.warning("database problem: %s", exc)
                busy = False
            time.sleep(PAUSE_SECONDS if busy else IDLE_SECONDS)
    except KeyboardInterrupt:
        logger.info("visual worker stopped")
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
