"""Look up domain ages (RDAP) for the training dataset.

Run from the project root after ``python -m ml.prepare_data``::

    python -m ml.fetch_domain_age --max-lookups 300

It picks registered domains from ``data/processed/dataset.csv`` at random,
half malicious and half benign (so both classes get ages), skips the ones
already in ``data/processed/domain_age.csv``, and appends one row per answer.
Run it again to add more; an interrupted run keeps every row written so far.
Hosts on shared platforms (``x.netlify.app``, ``x.duckdns.org``) are never
looked up: their registry only knows the platform.

Lookups go to the public RDAP servers of each registry, one at a time with a
pause in between (``--delay``), so the registries are not flooded. Failed
lookups (network errors, rate limits, a registry whose certificate cannot be
verified) are written with status ``failed`` and skipped next time; pass
``--retry-failed`` to try them again. No API key is needed.

Ages of old phishing domains are only partly recoverable: many were deleted
after being reported (the registry then has no record) or registered again by
someone else (the date is after the report, and ``ml.train`` ignores it).
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from config import BASE_DIR, settings
from ml.domain_age import AgeLookupError, RdapClient
from ml.features import lookup_domain

DEFAULT_DATASET = BASE_DIR / "data" / "processed" / "dataset.csv"
DEFAULT_OUT = BASE_DIR / "data" / "processed" / "domain_age.csv"
DEFAULT_MAX_LOOKUPS = 300
DEFAULT_DELAY = 1.0  # seconds between requests
COLUMNS = ("domain", "created", "status", "checked_at")
FOUND, NOT_FOUND, FAILED = "found", "not_found", "failed"


def read_domains(dataset_path: Path) -> dict[int, set[str]]:
    """Domains to look up, grouped by label (0 benign, 1 malicious). Shared platforms are left out."""
    groups: dict[int, set[str]] = {0: set(), 1: set()}
    with dataset_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            label = int(row["label"])
            domain = lookup_domain(row["host"])
            if label in groups and domain is not None:
                groups[label].add(domain)
    return groups


def read_done(out_path: Path, retry_failed: bool = False) -> set[str]:
    """Domains already answered (failed ones too, unless ``retry_failed``)."""
    if not out_path.exists():
        return set()
    with out_path.open(encoding="utf-8", newline="") as handle:
        return {
            row["domain"]
            for row in csv.DictReader(handle)
            if not (retry_failed and row.get("status") == FAILED)
        }


def pick(groups: dict[int, set[str]], done: set[str], max_lookups: int, seed: int) -> list[str]:
    """Up to ``max_lookups`` new domains, split evenly between the classes."""
    rng = random.Random(seed)
    pools = {label: sorted(domains - done) for label, domains in groups.items()}
    for pool in pools.values():
        rng.shuffle(pool)
    half = max_lookups // 2
    malicious = pools[1][:half]
    benign = pools[0][: max_lookups - len(malicious)]  # the benign side fills any gap
    chosen = malicious + benign
    rng.shuffle(chosen)
    return chosen


def fetch(
    domains: Sequence[str],
    out_path: Path,
    client: RdapClient,
    delay: float,
    sleep: Callable[[float], None] = time.sleep,
) -> Counter[str]:
    """Look up ``domains`` and append the answers to ``out_path``."""
    counts: Counter[str] = Counter()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not out_path.exists()
    with out_path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if new_file:
            writer.writerow(COLUMNS)
        for index, domain in enumerate(domains):
            if index:
                sleep(delay)
            checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                created = client.registration_date(domain)
            except AgeLookupError as exc:
                print(f"  {domain}: failed ({exc})", file=sys.stderr)
                created, status = None, FAILED
            else:
                status = FOUND if created is not None else NOT_FOUND
            writer.writerow([domain, created.isoformat() if created else "", status, checked_at])
            handle.flush()  # keep every answer if the run is interrupted
            counts[status] += 1
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.fetch_domain_age", description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--max-lookups", type=int, default=DEFAULT_MAX_LOOKUPS)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="seconds between requests (min 0.2)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--retry-failed", action="store_true", help="look up domains that failed before again")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"{args.dataset} not found. Run python -m ml.prepare_data first.", file=sys.stderr)
        return 1
    if args.max_lookups < 1:
        print("--max-lookups must be at least 1", file=sys.stderr)
        return 1

    domains = pick(read_domains(args.dataset), read_done(args.out, args.retry_failed), args.max_lookups, args.seed)
    if not domains:
        print("Every domain in the dataset already has an answer.")
        return 0
    print(f"Looking up {len(domains)} domains (about {len(domains) * max(args.delay, 0.2):.0f} s)...")
    counts = fetch(domains, args.out, RdapClient(settings.domain_age_timeout), max(args.delay, 0.2))
    for key, value in sorted(counts.items()):
        print(f"  {key}: {value}")
    print(f"Saved to {args.out}")
    print("Next: python -m ml.train, then python -m ml.evaluate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
