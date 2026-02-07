"""Download dated phishing reports from the free PhishStats API.

Why PhishStats: it gives every report a timestamp, which the time-based
train/test split needs, and read access needs no account. Be aware that the
labels are automatic (each report has a ``score``, there is no human review),
so ``ml.prepare_data`` keeps only reports with a high enough score.

Run from the project root::

    python -m ml.fetch_phishstats                # newest reports first
    python -m ml.fetch_phishstats                # run again later: continues further back in time

How it stays inside the free limit (50 requests per day per IP without a key):

* one request returns at most 100 reports, so a default run (45 requests)
  gives about 4,500 reports;
* each run continues where the last one stopped, using the smallest report id
  already in ``data/raw/phishstats.csv`` as a cursor (the API refuses deep
  page numbers, so ids are used instead);
* it waits 3.5 seconds between requests (the API also allows only 20 per minute);
  if the per-minute limit is hit anyway it waits a minute and carries on;
* it stops on a daily rate-limit answer and keeps what it already saved.

A free key raises the limit; if you have one, put it in the environment
variable ``PHISHSTATS_API_KEY`` (never in a file inside the project).

Only ``id, url, first_seen, score`` are stored: no IP address, no location.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from config import BASE_DIR
from ml.prepare_data import parse_time

API_URL = "https://api.phishstats.info/api/phishing"
DEFAULT_OUT = BASE_DIR / "data" / "raw" / "phishstats.csv"
PAGE_SIZE = 100  # the API's maximum
DEFAULT_MAX_REQUESTS = 45  # the anonymous limit is 50 per day per IP
PAUSE_SECONDS = 3.5  # the API allows 20 requests per minute, so stay under 17
MINUTE_WAIT_SECONDS = 65  # wait this long when the per-minute limit is hit
MAX_MINUTE_WAITS = 3
TIMEOUT_SECONDS = 30
MAX_BODY_BYTES = 8_000_000
USER_AGENT = "hisn-research/0.1 (student project; read-only)"
KEY_VARIABLE = "PHISHSTATS_API_KEY"

HEADER = ["id", "url", "first_seen", "score"]


class FetchError(RuntimeError):
    """Raised for a problem the user should read about (bad answer, network)."""


class RateLimited(FetchError):
    """Raised when the API says the daily limit is used up."""


@dataclass(frozen=True)
class Report:
    id: int
    url: str
    first_seen: datetime
    score: float | None


def build_url(api_url: str, before_id: int | None) -> str:
    """URL for one page of the newest reports, optionally only those below ``before_id``."""
    params = {"_sort": "-id", "_size": str(PAGE_SIZE)}
    if before_id is not None:
        params["_where"] = f"(id,lt,{before_id})"
    return f"{api_url}?{urllib.parse.urlencode(params, safe='(),')}"


def _check_scheme(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    local = parts.hostname in {"127.0.0.1", "localhost"}
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise FetchError("the API address must use https")


def fetch_page(url: str, api_key: str | None = None) -> list[dict[str, Any]]:
    """Fetch one page and return the decoded JSON list."""
    _check_scheme(url)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 (scheme checked above)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            body = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(200).decode("utf-8", errors="replace").strip()
        if exc.code in (403, 429):
            raise RateLimited(f"HTTP {exc.code}: {detail or 'limit reached'}") from exc
        raise FetchError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"network problem: {exc}") from exc
    if len(body) > MAX_BODY_BYTES:
        raise FetchError("the answer was unexpectedly large; stopping")
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FetchError("the answer was not valid JSON") from exc
    if not isinstance(data, list):
        raise FetchError("the answer was not a list of reports")
    return [item for item in data if isinstance(item, dict)]


def parse_report(item: dict[str, Any]) -> Report | None:
    """Turn one API item into a :class:`Report`, or None if it is unusable."""
    identifier, url, stamp = item.get("id"), item.get("url"), item.get("date")
    if not isinstance(identifier, int) or isinstance(identifier, bool):
        return None
    if not isinstance(url, str) or not isinstance(stamp, str):
        return None
    moment = parse_time(stamp)
    if moment is None:
        return None
    score = item.get("score")
    return Report(
        identifier,
        url,
        moment,
        float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
    )


def read_archive(path: Path) -> tuple[set[int], int | None]:
    """Return (ids already saved, smallest id) from the CSV archive."""
    if not path.exists():
        return set(), None
    ids: set[int] = set()
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                ids.add(int(row["id"]))
            except (KeyError, ValueError):
                continue
    return ids, (min(ids) if ids else None)


def append_reports(path: Path, reports: Sequence[Report]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if is_new:
            writer.writerow(HEADER)
        for report in reports:
            writer.writerow(
                [
                    report.id,
                    report.url,
                    report.first_seen.isoformat(),
                    "" if report.score is None else report.score,
                ]
            )


def run(
    out_path: Path,
    max_requests: int,
    *,
    api_url: str = API_URL,
    api_key: str | None = None,
    pause: float = PAUSE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Fetch pages until the request budget, the data or the rate limit runs out.

    Returns a one-line summary. Reports are saved after every page, so an
    error or a rate limit never loses what was already downloaded.
    """
    seen_ids, cursor = read_archive(out_path)
    added = requests = minute_waits = 0
    stop_reason = "request budget used"
    while requests < max_requests:
        if requests:
            sleep(pause)
        try:
            page = fetch_page(build_url(api_url, cursor), api_key)
        except RateLimited as exc:
            if "/min" in str(exc) and minute_waits < MAX_MINUTE_WAITS:
                minute_waits += 1  # a per-minute limit clears quickly: wait and retry
                print(f"  per-minute limit reached, waiting {MINUTE_WAIT_SECONDS} seconds...", flush=True)
                sleep(MINUTE_WAIT_SECONDS)
                continue
            stop_reason = f"rate limit reached ({' '.join(str(exc).split())})"
            break
        requests += 1
        reports = [r for r in map(parse_report, page) if r is not None]
        if not page:
            stop_reason = "no older reports"
            break
        if cursor is not None and any(r.id >= cursor for r in reports):
            # Never burn the daily quota on an answer that ignores the cursor.
            raise FetchError("the API ignored the id filter; stopping to protect your daily limit")
        fresh = [r for r in reports if r.id not in seen_ids]
        append_reports(out_path, fresh)
        seen_ids.update(r.id for r in fresh)
        added += len(fresh)
        ids = [r.id for r in reports]
        if not ids:
            raise FetchError("no usable reports in the answer; stopping")
        cursor = min(ids)
        oldest = min(r.first_seen for r in reports)
        print(f"  request {requests}: {len(fresh)} new reports, oldest {oldest:%Y-%m-%d}", flush=True)
    return f"{added} new reports saved in {requests} requests ({stop_reason})"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.fetch_phishstats", description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    args = parser.parse_args(argv)
    if args.max_requests < 1:
        parser.error("--max-requests must be at least 1")

    try:
        summary = run(args.out, args.max_requests, api_key=os.environ.get(KEY_VARIABLE))
    except FetchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(summary)
    print(f"Archive: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
