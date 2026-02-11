"""Train the phishing-domain model (Random Forest on domain-name features).

Run from the project root after ``python -m ml.prepare_data``::

    python -m ml.train

What goes in:

- ``data/processed/dataset.csv`` rows with ``split == "train"`` (the test rows
  are never touched here; ``ml.evaluate`` uses them).
- Synthetic look-alikes of the brands in ``brands.txt`` (``ml.typosquat``),
  labelled malicious. Only the *training brands* are used: some brands are
  held out entirely, so ``ml.evaluate`` can measure look-alikes of brands the
  model never saw. ``--holdout-technique`` holds out a whole technique too.
- Domain ages from ``data/processed/domain_age.csv`` (``ml.fetch_domain_age``),
  if the file exists. A malicious name's age is taken on the day it was
  reported (``first_seen``), a benign name's age on the day it was checked.
  They are not forest features: the train rows with an age build the age
  table (``ml/age_table.py``) that adjusts the forest's probability.

The classes are very unbalanced (about 1 malicious to 23 benign), so the forest
uses ``class_weight="balanced_subsample"``: each tree weighs the rare class up
instead of learning "always say benign".

Output: one ``.joblib`` bundle (model, feature names and the synthetic split)
at ``HISN_MODEL_PATH`` (default ``ml/models/hisn_rf.joblib``). ``ml.predictor``
loads it. Model files are pickles: only ever load a file you trained yourself.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

from config import BASE_DIR, settings
from dns_server.decision import load_domain_list
from dns_server.domain import InvalidDomainError
from ml.age_table import MIN_PER_CLASS, AgeTable, bucket_labels
from ml.domain_age import age_in_days
from ml.features import FEATURE_NAMES, FeatureExtractor, lookup_domain
from ml.predictor import BUNDLE_VERSION, load_bundle  # noqa: F401  (load_bundle is re-exported)
from ml.prepare_data import BENIGN, MALICIOUS, TEST, TRAIN
from ml.typosquat import DEFAULT_PER_TECHNIQUE, TECHNIQUES, SyntheticDomain, generate, split_brands, split_synthetic

DEFAULT_DATASET = BASE_DIR / "data" / "processed" / "dataset.csv"
DEFAULT_AGES = BASE_DIR / "data" / "processed" / "domain_age.csv"
AGE_COLUMNS = ("domain", "created", "status", "checked_at")
DEFAULT_TREES = 300
DEFAULT_SYNTHETIC_TEST_FRACTION = 0.3
REQUIRED_COLUMNS = ("host", "label", "split")


@dataclass(frozen=True)
class SyntheticConfig:
    """How the synthetic look-alikes were made and split. Stored in the bundle."""

    seed: int
    per_technique: int
    train_brands: tuple[str, ...]
    test_brands: tuple[str, ...]
    holdout_techniques: tuple[str, ...]

    def generate_split(self, whitelist: frozenset[str]) -> tuple[list[SyntheticDomain], list[SyntheticDomain]]:
        """Rebuild exactly the same (train, test) look-alikes that training used."""
        samples = generate(
            [*self.train_brands, *self.test_brands],
            whitelist,
            per_technique=self.per_technique,
            seed=self.seed,
        )
        return split_synthetic(samples, self.test_brands, self.holdout_techniques)


def load_dataset(path: Path) -> pd.DataFrame:
    """Read ``dataset.csv`` and check the columns this phase relies on."""
    frame = pd.read_csv(path, dtype={"host": str, "split": str, "source": str}, keep_default_na=False)
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"{path.name}: missing column(s): {', '.join(missing)}")
    frame["label"] = pd.to_numeric(frame["label"], errors="raise").astype(int)
    if not set(frame["label"]).issubset({BENIGN, MALICIOUS}):
        raise ValueError(f"{path.name}: label must be 0 (benign) or 1 (malicious)")
    if not set(frame["split"]).issubset({TRAIN, TEST}):
        raise ValueError(f"{path.name}: split must be '{TRAIN}' or '{TEST}'")
    return frame


@dataclass(frozen=True)
class AgeRecord:
    """One row of ``domain_age.csv``: when a registered domain was created, and when we asked."""

    created: datetime | None  # None: the registry had no date
    checked_at: datetime


def _parse_utc(value: str) -> datetime | None:
    text = value.strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def load_ages(path: Path) -> dict[str, AgeRecord]:
    """Read ``domain_age.csv`` (missing file = no ages). Bad rows are skipped."""
    if not path.exists():
        return {}
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = [column for column in AGE_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"{path.name}: missing column(s): {', '.join(missing)}")
    ages: dict[str, AgeRecord] = {}
    for domain, created, checked_at in zip(frame["domain"], frame["created"], frame["checked_at"]):
        checked = _parse_utc(checked_at)
        if checked is None:
            continue
        ages[domain.strip().lower()] = AgeRecord(_parse_utc(created), checked)
    return ages


def row_age_days(host: str, first_seen: str, ages: dict[str, AgeRecord]) -> float | None:
    """Age of ``host``'s registered domain when it was seen, or None if unknown.

    Malicious rows carry the report date (``first_seen``); benign rows have
    none, so the day of the lookup is used. A creation date after that day
    means the domain was registered again later: the age then is unknown.
    """
    domain = lookup_domain(host)
    record = ages.get(domain) if domain is not None else None
    if record is None or record.created is None:
        return None
    seen = _parse_utc(first_seen) if first_seen else None
    return age_in_days(record.created, seen or record.checked_at)


def fit_age_table(frame: pd.DataFrame, ages: dict[str, AgeRecord]) -> tuple[AgeTable | None, Counter[str]]:
    """The age table from the train rows that have an age (test rows are never used)."""
    train = frame[frame["split"] == TRAIN]
    first_seen = train["first_seen"] if "first_seen" in train.columns else [""] * len(train)
    by_label: dict[int, list[float]] = {BENIGN: [], MALICIOUS: []}
    for host, seen, label in zip(train["host"], first_seen, train["label"]):
        days = row_age_days(host, seen, ages)
        if days is not None:
            by_label[int(label)].append(days)
    counts: Counter[str] = Counter()
    counts["train rows with a known age (benign)"] = len(by_label[BENIGN])
    counts["train rows with a known age (malicious)"] = len(by_label[MALICIOUS])
    return AgeTable.fit(by_label[MALICIOUS], by_label[BENIGN]), counts


def feature_matrix(extractor: FeatureExtractor, hosts: Sequence[str]) -> tuple[np.ndarray, list[int]]:
    """Feature rows for ``hosts`` and the indexes of hosts that were valid.

    Invalid names are skipped (``prepare_data`` already validated them, so this
    only matters for hand-edited files).
    """
    rows: list[list[float]] = []
    kept: list[int] = []
    for index, host in enumerate(hosts):
        try:
            rows.append(extractor.vector(host))
        except InvalidDomainError:
            continue
        kept.append(index)
    return np.asarray(rows, dtype=np.float64).reshape(len(rows), len(FEATURE_NAMES)), kept


def build_training_set(
    frame: pd.DataFrame,
    synthetic_train: Sequence[SyntheticDomain],
    extractor: FeatureExtractor,
) -> tuple[np.ndarray, np.ndarray, Counter[str]]:
    """Train rows of the dataset plus the synthetic look-alikes. Returns (X, y, counts)."""
    train = frame[frame["split"] == TRAIN]
    counts: Counter[str] = Counter()
    # A generated name that is in the real data keeps its real label instead.
    known = set(frame["host"])
    extra = [sample for sample in synthetic_train if sample.host not in known]
    counts["synthetic names already in the dataset (skipped)"] = len(synthetic_train) - len(extra)

    hosts = [*train["host"], *(sample.host for sample in extra)]
    labels = [*train["label"], *([MALICIOUS] * len(extra))]
    features, kept = feature_matrix(extractor, hosts)
    target = np.asarray([labels[i] for i in kept], dtype=np.int64)
    counts["invalid hosts (skipped)"] = len(hosts) - len(kept)
    counts["benign"] = int((target == BENIGN).sum())
    counts["malicious from feeds"] = int((train["label"] == MALICIOUS).sum())
    counts["malicious synthetic look-alikes"] = len(extra)
    if counts["benign"] == 0 or int((target == MALICIOUS).sum()) == 0:
        raise ValueError("the training split needs both benign and malicious hosts")
    return features, target, counts


def make_model(trees: int, seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=trees,
        class_weight="balanced_subsample",
        min_samples_leaf=2,  # a leaf of one name is memorising, not learning
        n_jobs=-1,
        random_state=seed,
    )


def train(
    dataset_path: Path,
    out_path: Path,
    brands_path: Path,
    whitelist_path: Path,
    *,
    trees: int = DEFAULT_TREES,
    seed: int = 42,
    synthetic: bool = True,
    synthetic_test_fraction: float = DEFAULT_SYNTHETIC_TEST_FRACTION,
    holdout_techniques: Sequence[str] = (),
    per_technique: int = DEFAULT_PER_TECHNIQUE,
    ages_path: Path | None = None,
) -> dict[str, Any]:
    """Train, save and return the bundle. ``ages_path`` is an optional ``domain_age.csv``."""
    brands = load_domain_list(brands_path)
    whitelist = load_domain_list(whitelist_path)
    extractor = FeatureExtractor(brands, whitelist)
    frame = load_dataset(dataset_path)

    config: SyntheticConfig | None = None
    synthetic_train: list[SyntheticDomain] = []
    if synthetic:
        train_brands, test_brands = split_brands(brands, synthetic_test_fraction, seed)
        config = SyntheticConfig(
            seed=seed,
            per_technique=per_technique,
            train_brands=tuple(train_brands),
            test_brands=tuple(test_brands),
            holdout_techniques=tuple(sorted(set(holdout_techniques))),
        )
        synthetic_train, _ = config.generate_split(whitelist)

    features, target, counts = build_training_set(frame, synthetic_train, extractor)
    age_table, age_counts = fit_age_table(frame, load_ages(ages_path) if ages_path is not None else {})
    counts.update(age_counts)
    model = make_model(trees, seed)
    model.fit(features, target)

    bundle: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "model": model,
        "feature_names": FEATURE_NAMES,
        # Plain data, not the dataclass: "python -m ml.train" runs as __main__,
        # and a pickled __main__ class could not be loaded by ml.evaluate.
        "synthetic": asdict(config) if config is not None else None,
        "brands": tuple(sorted(brands)),
        "age_table": age_table.to_dict() if age_table is not None else None,
        "train_counts": dict(counts),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path, compress=3)
    return bundle


def print_age_table(table: AgeTable | None) -> None:
    """Show how each age range moves the model's probability (shared with ml.evaluate)."""
    if table is None:
        print(
            f"   Age table: not built (needs at least {MIN_PER_CLASS} train rows with a known age in each class; "
            "run python -m ml.fetch_domain_age). The model scores names only."
        )
        return
    print("   Age table (how much more often each age range is malicious; unknown age = no change):")
    print("   age range   malicious  benign   ratio")
    for label, m, b, ratio in zip(bucket_labels(), table.malicious_counts, table.benign_counts, table.ratios):
        print(f"   {label:10}  {m:>9}  {b:>6}  {ratio:>6.2f}x")


def synthetic_config(bundle: dict[str, Any]) -> SyntheticConfig | None:
    """The look-alike split stored in a bundle, or None if trained with --no-synthetic."""
    data = bundle.get("synthetic")
    if data is None:
        return None
    return SyntheticConfig(**{key: tuple(value) if isinstance(value, list) else value for key, value in data.items()})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.train", description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--ages", type=Path, default=DEFAULT_AGES, help="domain ages from python -m ml.fetch_domain_age (optional)"
    )
    parser.add_argument("--out", type=Path, default=settings.model_path)
    parser.add_argument("--trees", type=int, default=DEFAULT_TREES)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-synthetic", action="store_true", help="train on the feeds only (for comparison)")
    parser.add_argument(
        "--synthetic-test-fraction",
        type=float,
        default=DEFAULT_SYNTHETIC_TEST_FRACTION,
        help="share of brands whose look-alikes are kept out of training",
    )
    parser.add_argument(
        "--holdout-technique",
        action="append",
        default=[],
        choices=TECHNIQUES,
        help="also keep this look-alike technique out of training (repeatable)",
    )
    parser.add_argument(
        "--per-technique", type=int, default=DEFAULT_PER_TECHNIQUE, help="look-alikes per brand and technique"
    )
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"{args.dataset} not found. Run python -m ml.prepare_data first.", file=sys.stderr)
        return 1

    bundle = train(
        args.dataset,
        args.out,
        settings.brands_path,
        settings.whitelist_path,
        trees=args.trees,
        seed=args.seed,
        synthetic=not args.no_synthetic,
        synthetic_test_fraction=args.synthetic_test_fraction,
        holdout_techniques=args.holdout_technique,
        per_technique=args.per_technique,
        ages_path=args.ages,
    )
    print("Training rows:")
    for key, value in bundle["train_counts"].items():
        print(f"  {key}: {value}")
    print_age_table(AgeTable.from_dict(bundle["age_table"]))
    config = synthetic_config(bundle)
    if config is not None:
        print(f"Look-alike brands used in training: {', '.join(config.train_brands)}")
        print(f"Look-alike brands held out for evaluation: {', '.join(config.test_brands)}")
        if config.holdout_techniques:
            print(f"Techniques held out for evaluation: {', '.join(config.holdout_techniques)}")
    print(f"Model saved to {args.out}")
    print("Next: python -m ml.evaluate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
