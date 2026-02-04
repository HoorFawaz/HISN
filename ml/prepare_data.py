"""Build the training dataset from raw feed files.

Run from the project root after saving the feeds in ``data/raw/``::

    python -m ml.prepare_data

or name the files yourself::

    python -m ml.prepare_data --benign data/raw/tranco.csv.zip \\
        --malicious data/raw/phishtank.csv --malicious data/raw/urlhaus.csv

Inputs
    benign     a Tranco list (``rank,domain`` per line; .csv, .zip, .gz or .bz2)
    malicious  CSV files from ``ml.fetch_phishstats`` (``phishstats*``), PhishTank
               or URLhaus (any of the same extensions). A header with a ``url``
               column and a date column is required: ``first_seen``,
               ``submission_time`` (PhishTank) or ``dateadded`` (URLhaus). If the
               file has a ``score`` column, rows below ``--min-score`` are skipped, and so are
               rows with an empty score unless ``--keep-unscored`` is given.
               Only ``phishstats*``, ``phishtank*`` and ``online-valid*`` files are
               picked up automatically; name others with ``--malicious``.

What it does, and why (the project brief's "data pitfalls"):

1. Reduces every URL to a validated hostname. IP-address hosts are dropped
   because DNS never sees them as names.
2. Removes duplicates (a host keeps its earliest sighting).
3. Removes overlap between the sets: a host in both is dropped from both, and
   a malicious host that belongs to the same registered domain as a benign host
   is dropped (a compromised legitimate site cannot be told apart by its name).
4. Limits how many hosts one owner or platform can contribute (default 50):
   without it a single free-hosting service could be most of the malicious set
   and the model would learn that service instead of phishing traits.
5. Samples the benign list at random (not the top ranks), so the benign side is
   not just short, famous names.
6. Splits by time: the newest malicious domains become the test set, so the
   evaluation asks "can the model catch phishing that appeared after it was
   trained?". Hosts of one registered domain always stay on the same side.
   Benign domains carry no date, so they are split at random with the same ratio.

Output: ``data/processed/dataset.csv`` (never committed, see ``.gitignore``).
"""

from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import io
import ipaddress
import random
import sys
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from config import BASE_DIR
from dns_server.domain import InvalidDomainError, normalize_domain
from ml.features import concentration_key, registered_domain, split_host

RAW_DIR = BASE_DIR / "data" / "raw"
DEFAULT_OUT = BASE_DIR / "data" / "processed" / "dataset.csv"
DEFAULT_BENIGN_LIMIT = 200_000
DEFAULT_MIN_SCORE = 5.0  # PhishStats reports below this score are too uncertain
DEFAULT_MAX_PER_KEY = 50  # hosts kept per owner or platform (0 = no limit)

BENIGN, MALICIOUS = 0, 1
TRAIN, TEST = "train", "test"

# Column names the feeds use for "when was this reported", in order of preference.
TIME_COLUMNS = ("submission_time", "dateadded", "first_seen", "first_seen_utc", "verification_time")


@dataclass(frozen=True)
class Sample:
    host: str
    label: int
    source: str
    first_seen: datetime | None  # None for benign hosts


@dataclass
class Report:
    """Counters that explain what happened to the input, shown at the end."""

    counts: Counter[str] = field(default_factory=Counter)

    def add(self, key: str, amount: int = 1) -> None:
        self.counts[key] += amount


# ---------------------------------------------------------------- reading


@contextmanager
def _open_text(path: Path) -> Iterator[io.TextIOBase]:
    """Open a plain, .gz, .bz2 or .zip (first file inside) feed as text."""
    suffix = path.suffix.lower()
    if suffix == ".zip":
        archive = zipfile.ZipFile(path)
        try:
            names = [n for n in archive.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError(f"{path.name}: the zip file is empty")
            with archive.open(names[0]) as raw:
                yield io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        finally:
            archive.close()
    elif suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield handle
    elif suffix == ".bz2":
        with bz2.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield handle
    else:
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            yield handle


def url_to_host(value: str) -> str | None:
    """Return a validated, lowercase ASCII hostname from a URL or bare host.

    Returns None for anything unusable (empty, IP literal, invalid name), so
    the caller can count it instead of crashing on messy third-party data.
    """
    text = value.strip()
    if not text:
        return None
    if "://" not in text:
        text = "//" + text
    try:
        host = urlsplit(text).hostname
    except ValueError:  # e.g. a malformed IPv6 literal
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # a bare IP address is not a domain name
    except ValueError:
        pass
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    try:
        return normalize_domain(host)
    except InvalidDomainError:
        return None


def parse_time(value: str) -> datetime | None:
    """Parse the ISO-like timestamps used by the feeds into UTC."""
    text = value.strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def read_benign(path: Path, report: Report) -> Iterator[str]:
    """Yield hostnames from a Tranco-style ``rank,domain`` file."""
    with _open_text(path) as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            report.add("benign rows read")
            field_value = text.split(",", 1)[1] if "," in text else text
            host = url_to_host(field_value)
            if host is None:
                report.add("benign rows invalid")
                continue
            yield host


def _row(text: str) -> list[str]:
    return next(csv.reader([text]), [])


def read_malicious(
    path: Path, report: Report, min_score: float | None = None, keep_unscored: bool = False
) -> Iterator[tuple[str, datetime, str]]:
    """Yield (host, first_seen, source) from a PhishTank or URLhaus CSV file.

    With ``min_score`` set, reports scored below it are skipped. Reports with
    no score at all (PhishStats leaves it empty for most reports) are skipped
    too, unless ``keep_unscored`` is True: they are then kept and counted, but
    their label has never been checked by anyone.
    """
    source = path.name.split(".")[0].lower()
    header: list[str] | None = None
    url_col = time_col = verified_col = score_col = -1

    def set_header(cells: list[str]) -> bool:
        nonlocal header, url_col, time_col, verified_col, score_col
        names = [cell.strip().lower() for cell in cells]
        if "url" not in names:
            return False
        header = names
        url_col = names.index("url")
        time_col = next((names.index(c) for c in TIME_COLUMNS if c in names), -1)
        verified_col = names.index("verified") if "verified" in names else -1
        score_col = names.index("score") if "score" in names else -1
        return True

    with _open_text(path) as handle:
        for line in handle:
            text = line.rstrip("\r\n")
            if not text.strip():
                continue
            if text.startswith("#"):
                if header is None:  # URLhaus writes its header as a "# ..." comment
                    set_header(_row(text.lstrip("#").strip()))
                continue
            cells = _row(text)
            if header is None:
                if set_header(cells):
                    continue
                raise ValueError(f"{path.name}: no header with a 'url' column was found")
            report.add(f"{source}: rows read")
            if len(cells) <= max(url_col, time_col):
                report.add(f"{source}: rows malformed")
                continue
            if verified_col >= 0 and cells[verified_col].strip().lower() != "yes":
                report.add(f"{source}: rows not verified")
                continue
            if min_score is not None and score_col >= 0:
                try:
                    score = float(cells[score_col])
                except (ValueError, IndexError):
                    score = None
                if score is None and keep_unscored:
                    report.add(f"{source}: unscored rows kept")
                elif score is None or score < min_score:
                    report.add(f"{source}: rows below the score threshold")
                    continue
            host = url_to_host(cells[url_col])
            if host is None:
                report.add(f"{source}: rows with unusable host")
                continue
            moment = parse_time(cells[time_col]) if time_col >= 0 else None
            if moment is None:
                report.add(f"{source}: rows without a usable date")
                continue
            yield host, moment, source


# --------------------------------------------------------------- building


def split_by_time(
    malicious: Sequence[Sample],
    benign: Sequence[Sample],
    test_fraction: float,
    seed: int,
) -> dict[str, str]:
    """Return ``{host: "train" | "test"}``.

    Malicious: whole registered-domain groups, newest first, go to the test set
    until it holds ``test_fraction`` of the hosts. Benign: groups are shuffled
    with ``seed`` and filled the same way. The oldest malicious group always
    stays in training so neither side can end up empty.
    """
    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be between 0 and 1")

    assignment: dict[str, str] = {}

    groups: dict[str, list[Sample]] = defaultdict(list)
    for sample in malicious:
        groups[registered_domain(sample.host)].append(sample)
    ordered = sorted(
        groups.items(),
        key=lambda item: (min(s.first_seen for s in item[1] if s.first_seen), item[0]),
    )
    target = test_fraction * len(malicious)
    taken = 0
    for index in range(len(ordered) - 1, 0, -1):  # newest first; index 0 (oldest) is never taken
        if taken >= target:
            break
        for sample in ordered[index][1]:
            assignment[sample.host] = TEST
        taken += len(ordered[index][1])
    for _, members in ordered:
        for sample in members:
            assignment.setdefault(sample.host, TRAIN)

    benign_groups: dict[str, list[Sample]] = defaultdict(list)
    for sample in benign:
        benign_groups[registered_domain(sample.host)].append(sample)
    names = sorted(benign_groups)
    random.Random(seed).shuffle(names)
    target = test_fraction * len(benign)
    taken = 0
    for name in names:
        side = TEST if taken < target else TRAIN
        for sample in benign_groups[name]:
            assignment[sample.host] = side
        if side == TEST:
            taken += len(benign_groups[name])
    return assignment


def cap_per_key(hosts: Iterable[str], limit: int, seed: int) -> tuple[list[str], int]:
    """Keep at most ``limit`` random hosts per owner/platform. Returns (kept, dropped count)."""
    groups: dict[str, list[str]] = defaultdict(list)
    for host in sorted(hosts):
        groups[concentration_key(host)].append(host)
    rng = random.Random(seed)
    kept: list[str] = []
    dropped = 0
    for key in sorted(groups):
        members = groups[key]
        if len(members) > limit:
            dropped += len(members) - limit
            members = sorted(rng.sample(members, limit))
        kept.extend(members)
    return kept, dropped


def build_dataset(
    benign_paths: Sequence[Path],
    malicious_paths: Sequence[Path],
    *,
    benign_limit: int = DEFAULT_BENIGN_LIMIT,
    test_fraction: float = 0.2,
    seed: int = 42,
    min_score: float | None = None,
    keep_unscored: bool = False,
    max_per_key: int = 0,
) -> tuple[list[tuple[Sample, str]], Report]:
    """Read, clean and split the feeds. Returns ``[(sample, split), ...]`` and a report."""
    report = Report()

    # 1-2. malicious hosts, deduplicated; the earliest sighting wins
    earliest: dict[str, tuple[datetime, str]] = {}
    for path in malicious_paths:
        for host, moment, source in read_malicious(path, report, min_score, keep_unscored):
            known = earliest.get(host)
            if known is not None:
                report.add("malicious duplicates removed")
            if known is None or moment < known[0]:
                earliest[host] = (moment, source)

    # benign hosts, deduplicated
    benign_hosts: set[str] = set()
    for path in benign_paths:
        for host in read_benign(path, report):
            if host in benign_hosts:
                report.add("benign duplicates removed")
            benign_hosts.add(host)

    # 3. overlap: exact hosts leave both sets
    both = benign_hosts.intersection(earliest)
    for host in both:
        del earliest[host]
    benign_hosts -= both
    report.add("hosts in both sets (dropped from both)", len(both))

    # 3b. malicious hosts that share a registered domain with a benign host
    benign_registered = {registered_domain(host) for host in benign_hosts}
    for host in [h for h in earliest if registered_domain(h) in benign_registered]:
        del earliest[host]
        report.add("malicious hosts on a benign registered domain (dropped)")

    # 4. no single owner or platform may dominate either class
    if max_per_key > 0:
        kept, dropped = cap_per_key(earliest, max_per_key, seed)
        report.add("malicious hosts over the per-owner limit (dropped)", dropped)
        earliest = {host: earliest[host] for host in kept}
        kept_benign, dropped = cap_per_key(benign_hosts, max_per_key, seed)
        report.add("benign hosts over the per-owner limit (dropped)", dropped)
        benign_hosts = set(kept_benign)

    # 5. random benign sample (taken after the overlap check, from the full list)
    chosen = sorted(benign_hosts)
    if len(chosen) > benign_limit:
        chosen = random.Random(seed).sample(chosen, benign_limit)
        report.add("benign hosts left out by --benign-limit", len(benign_hosts) - benign_limit)

    malicious = [
        Sample(host, MALICIOUS, source, moment) for host, (moment, source) in sorted(earliest.items())
    ]
    benign = [Sample(host, BENIGN, "tranco", None) for host in sorted(chosen)]
    if not malicious or not benign:
        raise ValueError("need at least one benign and one malicious host after cleaning")

    # 6. time-based, group-aware split
    assignment = split_by_time(malicious, benign, test_fraction, seed)
    rows = [(sample, assignment[sample.host]) for sample in [*malicious, *benign]]
    return rows, report


# ---------------------------------------------------------------- output


def write_dataset(rows: Iterable[tuple[Sample, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "label", "source", "first_seen", "registered_domain", "split"])
        for sample, split in rows:
            writer.writerow(
                [
                    sample.host,
                    sample.label,
                    sample.source,
                    sample.first_seen.isoformat() if sample.first_seen else "",
                    registered_domain(sample.host),
                    split,
                ]
            )


def describe(rows: Sequence[tuple[Sample, str]]) -> list[str]:
    """Plain-text summary, including simple checks for source artifacts.

    If the two classes differ a lot on something that is not about phishing
    (for example "benign names never have subdomains"), the model could learn
    the data source instead of phishing traits. These lines make that visible.
    """
    lines: list[str] = []
    for label, name in ((MALICIOUS, "malicious"), (BENIGN, "benign")):
        for split in (TRAIN, TEST):
            hosts = [s.host for s, sp in rows if s.label == label and sp == split]
            if hosts:
                lines.append(f"{name:9} {split:5} {len(hosts):>8} hosts")
    for label, name in ((MALICIOUS, "malicious"), (BENIGN, "benign")):
        hosts = [s.host for s, _ in rows if s.label == label]
        if not hosts:
            continue
        splits = [split_host(h) for h in hosts]
        with_sub = sum(1 for sub, *_ in splits if sub) / len(hosts)
        with_digit = sum(any(c.isdigit() for c in h) for h in hosts) / len(hosts)
        avg_len = sum(len(h) for h in hosts) / len(hosts)
        top = Counter(suffix for _, _, suffix, _ in splits).most_common(5)
        lines.append(
            f"{name:9} avg length {avg_len:.1f} | with subdomain {with_sub:.0%} | "
            f"with digit {with_digit:.0%} | top suffixes "
            + ", ".join(f"{s} {n / len(hosts):.0%}" for s, n in top)
        )
    test_dates = [s.first_seen for s, sp in rows if s.label == MALICIOUS and sp == TEST and s.first_seen]
    train_dates = [s.first_seen for s, sp in rows if s.label == MALICIOUS and sp == TRAIN and s.first_seen]
    if test_dates and train_dates:
        lines.append(
            f"malicious train: {min(train_dates):%Y-%m-%d} to {max(train_dates):%Y-%m-%d} | "
            f"test: {min(test_dates):%Y-%m-%d} to {max(test_dates):%Y-%m-%d}"
        )
    return lines


# -------------------------------------------------------------------- CLI


def discover(raw_dir: Path) -> tuple[list[Path], list[Path]]:
    """Find feed files in ``raw_dir`` by their usual names."""
    def pick(*patterns: str) -> list[Path]:
        found: set[Path] = set()
        for pattern in patterns:
            found.update(raw_dir.glob(pattern))
        return sorted(found)

    benign = pick("tranco*", "top-1m*")
    malicious = pick("phishstats*", "phishtank*", "online-valid*", "verified_online*")
    return benign, malicious


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.prepare_data", description=__doc__.split("\n")[0])
    parser.add_argument("--benign", action="append", type=Path, help="Tranco file (repeatable)")
    parser.add_argument("--malicious", action="append", type=Path, help="PhishTank/URLhaus file (repeatable)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--benign-limit", type=int, default=DEFAULT_BENIGN_LIMIT)
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-score", type=float, default=DEFAULT_MIN_SCORE, help="skip scored reports below this")
    parser.add_argument(
        "--keep-unscored",
        action="store_true",
        help="also keep reports that have no score (their labels are unchecked; see docs/limitations.md)",
    )
    parser.add_argument(
        "--max-per-key", type=int, default=DEFAULT_MAX_PER_KEY, help="hosts kept per owner/platform, 0 = no limit"
    )
    args = parser.parse_args(argv)

    found_benign, found_malicious = discover(RAW_DIR)
    benign_paths = args.benign or found_benign
    malicious_paths = args.malicious or found_malicious
    if not benign_paths or not malicious_paths:
        print(
            f"Missing input. Put a Tranco file (name starts with 'tranco') and a phishing file "
            f"(from ml.fetch_phishstats, or named 'phishtank...') in {RAW_DIR}, "
            f"or pass --benign and --malicious.",
            file=sys.stderr,
        )
        return 1

    rows, report = build_dataset(
        benign_paths,
        malicious_paths,
        benign_limit=args.benign_limit,
        test_fraction=args.test_fraction,
        seed=args.seed,
        min_score=args.min_score,
        keep_unscored=args.keep_unscored,
        max_per_key=args.max_per_key,
    )
    write_dataset(rows, args.out)

    print("Cleaning report:")
    for key, value in sorted(report.counts.items()):
        print(f"  {key}: {value}")
    print("Dataset:")
    for line in describe(rows):
        print(f"  {line}")
    print(f"Written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
