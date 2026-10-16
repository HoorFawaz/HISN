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

The classes are very unbalanced (about 1 malicious to 43 benign), so the forest
uses ``class_weight="balanced_subsample"``: each tree weighs the rare class up
instead of learning "always say benign".

Output: one ``.joblib`` bundle (model, feature names and the synthetic split)
at ``HISN_MODEL_PATH`` (default ``ml/models/hisn_rf.joblib``). Model files are
pickles: only ever load a file you trained yourself.
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
from ml.features import FEATURE_NAMES, FeatureExtractor
from ml.prepare_data import BENIGN, MALICIOUS, TEST, TRAIN
from ml.typosquat import TECHNIQUES, SyntheticDomain, generate, split_brands, split_synthetic

DEFAULT_DATASET = BASE_DIR / "data" / "processed" / "dataset.csv"
DEFAULT_TREES = 300
DEFAULT_SYNTHETIC_TEST_FRACTION = 0.3
REQUIRED_COLUMNS = ("host", "label", "split")
BUNDLE_VERSION = 1


@dataclass(frozen=True)
class SyntheticConfig:
    """How the synthetic look-alikes were made and split. Stored in the bundle."""

    seed: int
    suffixes_per_label: int
    train_brands: tuple[str, ...]
    test_brands: tuple[str, ...]
    holdout_techniques: tuple[str, ...]

    def generate_split(self, whitelist: frozenset[str]) -> tuple[list[SyntheticDomain], list[SyntheticDomain]]:
        """Rebuild exactly the same (train, test) look-alikes that training used."""
        samples = generate(
            [*self.train_brands, *self.test_brands],
            whitelist,
            suffixes_per_label=self.suffixes_per_label,
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
    suffixes_per_label: int = 2,
) -> dict[str, Any]:
    """Train, save and return the bundle."""
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
            suffixes_per_label=suffixes_per_label,
            train_brands=tuple(train_brands),
            test_brands=tuple(test_brands),
            holdout_techniques=tuple(sorted(set(holdout_techniques))),
        )
        synthetic_train, _ = config.generate_split(whitelist)

    features, target, counts = build_training_set(frame, synthetic_train, extractor)
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
        "train_counts": dict(counts),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path, compress=3)
    return bundle


def load_bundle(path: Path) -> dict[str, Any]:
    """Load a bundle written by :func:`train` and check it matches this code.

    Only load files you trained yourself: joblib files can run code when loaded.
    """
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or bundle.get("bundle_version") != BUNDLE_VERSION:
        raise ValueError(f"{path.name}: not a HISN model bundle (retrain with python -m ml.train)")
    if tuple(bundle["feature_names"]) != FEATURE_NAMES:
        raise ValueError(f"{path.name}: trained with different features (retrain with python -m ml.train)")
    return bundle


def synthetic_config(bundle: dict[str, Any]) -> SyntheticConfig | None:
    """The look-alike split stored in a bundle, or None if trained with --no-synthetic."""
    data = bundle.get("synthetic")
    if data is None:
        return None
    return SyntheticConfig(**{key: tuple(value) if isinstance(value, list) else value for key, value in data.items()})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.train", description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
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
    parser.add_argument("--suffixes-per-label", type=int, default=2)
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
        suffixes_per_label=args.suffixes_per_label,
    )
    print("Training rows:")
    for key, value in bundle["train_counts"].items():
        print(f"  {key}: {value}")
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
