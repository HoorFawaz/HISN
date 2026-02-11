"""Pick domain names that show the model at work in a live demo.

Run from the project root after ``python -m ml.train``::

    python -m ml.demo_names

It scores names from the temporal test split of ``dataset.csv`` (never used in
training) on the name alone, as the DNS server does before a domain's age is
known, and prints:

- the newest phishing names the model blocks that no list and no look-alike
  rule covers, so only the model can be the reason for the block;
- a few benign names the model allows.

The phishing names come from unreviewed feeds and may still be live: query
them only through HISN (``docs/demo.md``), never open them without it.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections.abc import Sequence
from pathlib import Path

from config import settings
from dns_server.decision import load_domain_list
from ml.features import FeatureExtractor
from ml.lookalike import LookalikeChecker
from ml.prepare_data import BENIGN, MALICIOUS, TEST
from ml.train import DEFAULT_DATASET, feature_matrix, load_bundle, load_dataset

MAX_CANDIDATES = 3000  # newest malicious test names scored; enough to find a handful
BENIGN_SAMPLE = 500


def pick(
    dataset_path: Path,
    model_path: Path,
    brands_path: Path,
    whitelist_path: Path,
    blacklist_path: Path,
    threshold: float,
    count: int,
    seed: int = 7,
) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
    """Return ``(blocked phishing names, allowed benign names)`` with their probabilities."""
    bundle = load_bundle(model_path)
    model = bundle["model"]
    column = list(model.classes_).index(MALICIOUS)
    brands = load_domain_list(brands_path)
    whitelist = load_domain_list(whitelist_path)
    blacklist = load_domain_list(blacklist_path)
    extractor = FeatureExtractor(brands, whitelist)
    checker = LookalikeChecker(brands, whitelist)

    test = load_dataset(dataset_path)
    test = test[test["split"] == TEST]
    malicious = test[test["label"] == MALICIOUS].sort_values("first_seen", ascending=False)
    candidates = [
        host
        for host in malicious["host"]
        if host not in blacklist and not checker.is_official(host) and checker.check(host) is None
    ][:MAX_CANDIDATES]
    benign_hosts = list(test[test["label"] == BENIGN]["host"])
    benign_hosts = random.Random(seed).sample(benign_hosts, min(BENIGN_SAMPLE, len(benign_hosts)))

    def score(hosts: list[str]) -> list[tuple[str, float]]:
        if not hosts:
            return []
        rows, kept = feature_matrix(extractor, hosts)
        if not kept:
            return []
        probabilities = model.predict_proba(rows)[:, column]
        return [(hosts[i], float(p)) for i, p in zip(kept, probabilities)]

    blocked = [(host, p) for host, p in score(candidates) if p >= threshold][:count]
    allowed = [(host, p) for host, p in score(benign_hosts) if p < threshold][:count]
    return blocked, allowed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.demo_names", description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", type=Path, default=settings.model_path)
    parser.add_argument("--threshold", type=float, default=settings.model_threshold)
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args(argv)

    for path, hint in ((args.dataset, "python -m ml.prepare_data"), (args.model, "python -m ml.train")):
        if not path.exists():
            print(f"{path} not found. Run {hint} first.", file=sys.stderr)
            return 1
    blocked, allowed = pick(
        args.dataset,
        args.model,
        settings.brands_path,
        settings.whitelist_path,
        settings.blacklist_path,
        args.threshold,
        args.count,
    )
    print(f"Phishing names only the model blocks (probability >= {args.threshold:.2f}, name alone):")
    for host, probability in blocked:
        print(f"  {host:50} {probability:.2f}")
    if not blocked:
        print("  none found; lower --threshold to see the closest ones")
    print("Benign names the model allows:")
    for host, probability in allowed:
        print(f"  {host:50} {probability:.2f}")
    print()
    print("Query these only through HISN. Once a domain's age is known, the age table can change the verdict.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
