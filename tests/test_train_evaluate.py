"""End-to-end tests for training and evaluation on a small generated dataset.

The real dataset lives only on the developer's machine (it is never
committed), so these tests build a tiny one that looks like ``dataset.csv``.
"""

from __future__ import annotations

import csv
import random
from dataclasses import replace
from pathlib import Path

import joblib
import pytest

from ml import evaluate as evaluate_module
from ml import train as train_module
from ml.evaluate import binary_scores, evaluate
from ml.features import FEATURE_NAMES
from ml.train import load_bundle, load_dataset, synthetic_config, train

BRANDS = ["absher", "alrajhi", "tawakkalna", "alinma", "riyadbank", "nafath"]
WHITELIST = ["absher.sa", "alrajhibank.com.sa", "alinma.com", "riyadbank.com"]
WORDS = ["green", "market", "travel", "studio", "coffee", "school", "garden", "music", "health", "sports"]


def write_list(path: Path, entries: list[str]) -> Path:
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return path


def make_dataset(path: Path, seed: int = 1) -> Path:
    rng = random.Random(seed)
    rows = []
    for i in range(300):
        host = f"{rng.choice(WORDS)}{rng.choice(WORDS)}{i}.{rng.choice(['com', 'org', 'net', 'sa'])}"
        rows.append((host, 0, "tranco", "", "test" if i % 5 == 0 else "train"))
    for i in range(80):
        noise = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14))
        rows.append((f"{noise}.{rng.choice(['xyz', 'top', 'icu'])}", 1, "phishstats", "2026-01-01", "test" if i >= 64 else "train"))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "label", "source", "first_seen", "split"])
        writer.writerows(rows)
    return path


@pytest.fixture()
def files(tmp_path: Path) -> dict[str, Path]:
    return {
        "dataset": make_dataset(tmp_path / "dataset.csv"),
        "brands": write_list(tmp_path / "brands.txt", BRANDS),
        "whitelist": write_list(tmp_path / "whitelist.txt", WHITELIST),
        "model": tmp_path / "models" / "model.joblib",
    }


def run_train(files: dict[str, Path], **kwargs) -> dict:  # type: ignore[no-untyped-def]
    return train(files["dataset"], files["model"], files["brands"], files["whitelist"], trees=25, **kwargs)


def test_train_saves_a_loadable_bundle(files: dict[str, Path]) -> None:
    bundle = run_train(files)
    assert files["model"].exists()
    loaded = load_bundle(files["model"])
    assert tuple(loaded["feature_names"]) == FEATURE_NAMES
    assert loaded["model"].n_features_in_ == len(FEATURE_NAMES)
    assert loaded["model"].class_weight == "balanced_subsample"
    assert bundle["train_counts"]["malicious synthetic look-alikes"] > 0


def test_training_never_sees_held_out_brands_or_test_rows(files: dict[str, Path]) -> None:
    bundle = run_train(files, holdout_techniques=["transposition"])
    config = synthetic_config(bundle)
    assert config is not None
    assert set(config.train_brands).isdisjoint(config.test_brands)
    synthetic_train, synthetic_test = config.generate_split(frozenset(WHITELIST))
    assert all(s.brand in config.train_brands and s.technique != "transposition" for s in synthetic_train)
    assert {s.brand for s in synthetic_test} >= set(config.test_brands)
    frame = load_dataset(files["dataset"])
    benign_train = int(((frame["split"] == "train") & (frame["label"] == 0)).sum())
    assert bundle["train_counts"]["benign"] == benign_train  # no test rows were used


def test_no_synthetic_option(files: dict[str, Path]) -> None:
    bundle = run_train(files, synthetic=False)
    assert bundle["synthetic"] is None
    assert bundle["train_counts"]["malicious synthetic look-alikes"] == 0
    result = evaluate(files["dataset"], files["model"], files["brands"], files["whitelist"], 0.5)
    assert result["model_lookalikes"] is None


def test_evaluate_reports_precision_recall_and_confusion_matrix(files: dict[str, Path]) -> None:
    run_train(files)
    result = evaluate(files["dataset"], files["model"], files["brands"], files["whitelist"], 0.5)
    scores = result["at_threshold"]
    counts = result["test_counts"]
    assert scores.true_negative + scores.false_positive == counts["benign"]
    assert scores.true_positive + scores.false_negative == counts["malicious"]
    # random-looking names against dictionary words is an easy toy problem
    assert scores.recall > 0.8 and scores.precision > 0.8
    assert result["average_precision"] is not None
    lookalikes = result["model_lookalikes"]
    assert lookalikes.total > 0
    assert set(lookalikes.by_brand) == set(result["held_out_brands"]) or result["held_out_techniques"]
    assert result["rule_lookalikes"].caught == result["rule_lookalikes"].total
    assert result["rule_benign_total"] == counts["benign"]


def test_binary_scores_on_a_known_case() -> None:
    import numpy as np

    target = np.array([0, 0, 0, 1, 1])
    probability = np.array([0.1, 0.9, 0.2, 0.8, 0.3])
    scores = binary_scores(target, probability, 0.5)
    assert (scores.true_negative, scores.false_positive, scores.false_negative, scores.true_positive) == (2, 1, 1, 1)
    assert scores.precision == pytest.approx(0.5)
    assert scores.recall == pytest.approx(0.5)


def test_bundle_with_other_features_is_refused(files: dict[str, Path]) -> None:
    run_train(files)
    bundle = joblib.load(files["model"])
    bundle["feature_names"] = ("length",)
    joblib.dump(bundle, files["model"])
    with pytest.raises(ValueError, match="different features"):
        load_bundle(files["model"])


def test_dataset_with_bad_labels_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("host,label,split\nexample.com,2,train\n", encoding="utf-8")
    with pytest.raises(ValueError, match="label"):
        load_dataset(path)


def test_command_lines_run_end_to_end(
    files: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Settings is frozen, so swap the whole object for one with the test lists.
    patched = replace(train_module.settings, brands_path=files["brands"], whitelist_path=files["whitelist"])
    monkeypatch.setattr(train_module, "settings", patched)
    monkeypatch.setattr(evaluate_module, "settings", patched)

    assert train_module.main(["--dataset", str(files["dataset"]), "--out", str(files["model"]), "--trees", "20"]) == 0
    assert evaluate_module.main(["--dataset", str(files["dataset"]), "--model", str(files["model"])]) == 0
    output = capsys.readouterr().out
    assert "Confusion matrix" in output
    assert "precision" in output and "recall" in output
    assert "accuracy" not in output.lower()
    assert "nobody reviewed" in output


def test_command_lines_explain_missing_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert train_module.main(["--dataset", str(tmp_path / "none.csv")]) == 1
    assert evaluate_module.main(["--dataset", str(tmp_path / "none.csv"), "--model", str(tmp_path / "m")]) == 1
    assert "prepare_data" in capsys.readouterr().err


def write_ages(files: dict[str, Path]) -> Path:
    """Ages for every other domain: benign ones are years old, malicious ones a week old."""
    frame = load_dataset(files["dataset"])
    path = files["dataset"].parent / "domain_age.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "created", "status", "checked_at"])
        for index, (host, label) in enumerate(zip(frame["host"], frame["label"])):
            if index % 2:
                continue
            created = "2025-12-25T00:00:00+00:00" if label == 1 else "2010-03-01T00:00:00+00:00"
            writer.writerow([host, created, "found", "2026-10-17T00:00:00+00:00"])
    return path


def test_training_and_evaluation_with_domain_ages(files: dict[str, Path]) -> None:
    ages_path = write_ages(files)
    bundle = run_train(files, ages_path=ages_path)
    counts = bundle["train_counts"]
    assert counts["train rows with a known age (benign)"] >= 30
    assert counts["train rows with a known age (malicious)"] >= 30
    assert bundle["age_table"] is not None
    result = evaluate(files["dataset"], files["model"], files["brands"], files["whitelist"], 0.5, ages_path)
    age = result["age"]
    assert age is not None
    assert age["counts"]["benign"] > 0 and age["counts"]["malicious"] > 0
    assert age["with_age"].true_positive + age["with_age"].false_negative == age["counts"]["malicious"]
    profile = result["age_profile"]
    assert profile[1]["under_30_days"] == 1.0  # every malicious age in write_ages is 7 days at report time
    assert profile[0]["under_30_days"] == 0.0 and profile[0]["median_days"] > 5000


def test_training_without_ages_reports_none(files: dict[str, Path]) -> None:
    bundle = run_train(files)
    assert bundle["train_counts"]["train rows with a known age (malicious)"] == 0
    assert bundle["age_table"] is None
    result = evaluate(files["dataset"], files["model"], files["brands"], files["whitelist"], 0.5)
    assert result["age"] is None


def test_demo_names_are_blocked_only_by_the_model(files: dict[str, Path], tmp_path: Path) -> None:
    from ml.demo_names import pick
    from ml.lookalike import LookalikeChecker

    run_train(files)
    blacklist = write_list(tmp_path / "blacklist.txt", ["listed-example.com"])
    blocked, allowed = pick(
        files["dataset"], files["model"], files["brands"], files["whitelist"], blacklist, 0.5, 3
    )
    test_rows = load_dataset(files["dataset"])
    test_rows = test_rows[test_rows["split"] == "test"]
    malicious = set(test_rows[test_rows["label"] == 1]["host"])
    benign = set(test_rows[test_rows["label"] == 0]["host"])
    checker = LookalikeChecker(frozenset(BRANDS), frozenset(WHITELIST))
    assert blocked and allowed
    assert len(blocked) <= 3 and len(allowed) <= 3
    assert all(host in malicious and p >= 0.5 and checker.check(host) is None for host, p in blocked)
    assert all(host in benign and p < 0.5 for host, p in allowed)


def test_demo_names_command(
    files: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ml import demo_names

    run_train(files)
    patched = replace(demo_names.settings, brands_path=files["brands"], whitelist_path=files["whitelist"])
    monkeypatch.setattr(demo_names, "settings", patched)
    args = ["--dataset", str(files["dataset"]), "--model", str(files["model"]), "--threshold", "0.5"]
    assert demo_names.main(args) == 0
    output = capsys.readouterr().out
    assert "only the model blocks" in output and "only through HISN" in output
    assert demo_names.main(["--dataset", str(files["dataset"]), "--model", str(files["dataset"].parent / "none")]) == 1
