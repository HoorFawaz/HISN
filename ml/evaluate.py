"""Evaluate the trained model and the look-alike rule.

Run from the project root after ``python -m ml.train``::

    python -m ml.evaluate

Three separate results, because they answer different questions:

1. **Temporal test split** (``split == "test"`` in ``dataset.csv``): the newest
   phishing names, which the model never saw. Precision, recall and the
   confusion matrix at the blocking threshold, plus a small threshold table.
   Accuracy is not reported: with about 1 malicious name per 43 benign ones,
   "allow everything" already scores over 97%.
2. **Held-out look-alikes**: synthetic look-alikes of brands (and techniques)
   kept out of training, split by brand and by technique. Every name here is
   malicious, so only recall means anything; precision comes from part 1 and 3.
3. **Look-alike rule** (``ml.lookalike``): the same look-alikes, plus how many
   benign test names the rule would wrongly flag. The rule learns nothing, so
   it is scored on all brands.

Every figure depends on labels nobody reviewed (see ``docs/limitations.md``).
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support

from config import settings
from dns_server.decision import load_domain_list
from ml.features import FeatureExtractor
from ml.lookalike import LookalikeChecker
from ml.prepare_data import BENIGN, MALICIOUS, TEST
from ml.train import DEFAULT_DATASET, feature_matrix, load_bundle, load_dataset, synthetic_config
from ml.typosquat import SyntheticDomain, generate

THRESHOLDS: tuple[float, ...] = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)

LIMITATIONS_NOTE = (
    "Limitations: most malicious labels come from automatic feed reports that nobody reviewed, "
    "benign names have no dates (split at random), and the look-alikes are generated, not observed "
    "attacks. Read these numbers as estimates. See docs/limitations.md."
)


@dataclass(frozen=True)
class BinaryScores:
    threshold: float
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int
    precision: float
    recall: float
    f1: float


def binary_scores(target: np.ndarray, probability: np.ndarray, threshold: float) -> BinaryScores:
    predicted = (probability >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(target, predicted, labels=[BENIGN, MALICIOUS]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        target, predicted, labels=[MALICIOUS], average=None, zero_division=0
    )
    return BinaryScores(threshold, int(tn), int(fp), int(fn), int(tp), float(precision[0]), float(recall[0]), float(f1[0]))


@dataclass
class RecallTable:
    """Caught / total, overall and per group (brand or technique)."""

    caught: int = 0
    total: int = 0
    by_brand: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    by_technique: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    missed: list[str] = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.caught / self.total if self.total else 0.0


def recall_table(samples: Iterable[SyntheticDomain], is_caught: Callable[[SyntheticDomain], bool]) -> RecallTable:
    table = RecallTable()
    for sample in samples:
        hit = is_caught(sample)
        table.total += 1
        table.caught += hit
        for group in (table.by_brand[sample.brand], table.by_technique[sample.technique]):
            group[0] += hit
            group[1] += 1
        if not hit:
            table.missed.append(sample.host)
    return table


def evaluate(
    dataset_path: Path,
    model_path: Path,
    brands_path: Path,
    whitelist_path: Path,
    threshold: float,
) -> dict[str, Any]:
    """Compute every result. Returns plain data so tests and the CLI share it."""
    bundle = load_bundle(model_path)
    model = bundle["model"]
    brands = load_domain_list(brands_path)
    whitelist = load_domain_list(whitelist_path)
    extractor = FeatureExtractor(brands, whitelist)
    checker = LookalikeChecker(brands, whitelist)

    def probabilities(hosts: Sequence[str]) -> tuple[np.ndarray, list[int]]:
        features, kept = feature_matrix(extractor, hosts)
        if not kept:
            return np.zeros(0), kept
        return model.predict_proba(features)[:, list(model.classes_).index(MALICIOUS)], kept

    # 1. temporal test split
    frame = load_dataset(dataset_path)
    test = frame[frame["split"] == TEST]
    if test.empty:
        raise ValueError("the dataset has no test rows")
    test_hosts = list(test["host"])
    test_probability, kept = probabilities(test_hosts)
    test_target = test["label"].to_numpy()[kept]
    has_both = len(set(test_target)) == 2
    result: dict[str, Any] = {
        "test_counts": {"benign": int((test_target == BENIGN).sum()), "malicious": int((test_target == MALICIOUS).sum())},
        "at_threshold": binary_scores(test_target, test_probability, threshold),
        "thresholds": [binary_scores(test_target, test_probability, t) for t in THRESHOLDS],
        "average_precision": float(average_precision_score(test_target, test_probability)) if has_both else None,
    }

    # 2. held-out look-alikes, scored by the model
    config = synthetic_config(bundle)
    if config is not None:
        _, synthetic_test = config.generate_split(whitelist)
        known = set(frame["host"])
        synthetic_test = [sample for sample in synthetic_test if sample.host not in known]
        synthetic_probability, kept = probabilities([s.host for s in synthetic_test])
        caught = {synthetic_test[i].host for i, p in zip(kept, synthetic_probability) if p >= threshold}
        result["model_lookalikes"] = recall_table(synthetic_test, lambda s: s.host in caught)
        result["held_out_brands"] = config.test_brands
        result["held_out_techniques"] = config.holdout_techniques
    else:
        result["model_lookalikes"] = None

    # 3. the rule, on look-alikes of every brand and on benign test names
    all_lookalikes = (
        generate(brands, whitelist, per_technique=config.per_technique, seed=config.seed)
        if config
        else generate(brands, whitelist)
    )
    result["rule_lookalikes"] = recall_table(all_lookalikes, lambda s: checker.check(s.host) is not None)
    benign_hosts = [h for h, label in zip(test_hosts, test["label"]) if label == BENIGN]
    flagged = []
    for host in benign_hosts:
        match = checker.check(host)
        if match is not None:
            flagged.append((host, match.brand, match.technique))
    result["rule_false_positives"] = flagged
    result["rule_benign_total"] = len(benign_hosts)
    return result


# ---------------------------------------------------------------- output


def _percent(part: int, whole: int) -> str:
    return f"{part}/{whole} ({part / whole:.1%})" if whole else "0/0"


def _print_recall(title: str, table: RecallTable) -> None:
    print(f"{title}: recall {_percent(table.caught, table.total)}")
    for name, groups in (("by brand", table.by_brand), ("by technique", table.by_technique)):
        print(f"  {name}:")
        for key in sorted(groups):
            caught, total = groups[key]
            print(f"    {key:15} {_percent(caught, total)}")
    if table.missed:
        print(f"  missed (first 10): {', '.join(table.missed[:10])}")


def report(result: dict[str, Any], threshold: float) -> None:
    counts = result["test_counts"]
    scores: BinaryScores = result["at_threshold"]
    print(f"1. Temporal test split: {counts['malicious']} malicious, {counts['benign']} benign")
    print(f"   Threshold {threshold:.2f}: precision {scores.precision:.3f} | recall {scores.recall:.3f} | F1 {scores.f1:.3f}")
    print("   Confusion matrix (rows = real, columns = predicted):")
    print("                  benign  malicious")
    print(f"     benign     {scores.true_negative:>8} {scores.false_positive:>10}")
    print(f"     malicious  {scores.false_negative:>8} {scores.true_positive:>10}")
    if result["average_precision"] is not None:
        print(f"   Average precision (area under the precision-recall curve): {result['average_precision']:.3f}")
    print("   threshold  precision  recall  false positives  missed")
    for row in result["thresholds"]:
        print(f"   {row.threshold:9.2f}  {row.precision:9.3f}  {row.recall:6.3f}  {row.false_positive:15}  {row.false_negative:6}")
    print()

    lookalikes: RecallTable | None = result["model_lookalikes"]
    if lookalikes is None:
        print("2. Held-out look-alikes: skipped (model trained with --no-synthetic)")
    else:
        held = ", ".join(result["held_out_brands"])
        techniques = ", ".join(result["held_out_techniques"]) or "none"
        _print_recall(f"2. Model on held-out look-alikes (brands: {held}; techniques: {techniques})", lookalikes)
    print()

    _print_recall("3. Look-alike rule on generated look-alikes of every brand", result["rule_lookalikes"])
    flagged = result["rule_false_positives"]
    print(f"   Benign test names flagged by the rule: {_percent(len(flagged), result['rule_benign_total'])}")
    for host, brand, technique in flagged[:10]:
        print(f"     {host} (looks like {brand}, {technique})")
    print()
    print(LIMITATIONS_NOTE)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ml.evaluate", description=__doc__.split("\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", type=Path, default=settings.model_path)
    parser.add_argument("--threshold", type=float, default=settings.model_threshold)
    args = parser.parse_args(argv)

    for path, hint in ((args.dataset, "python -m ml.prepare_data"), (args.model, "python -m ml.train")):
        if not path.exists():
            print(f"{path} not found. Run {hint} first.", file=sys.stderr)
            return 1
    result = evaluate(args.dataset, args.model, settings.brands_path, settings.whitelist_path, args.threshold)
    report(result, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
