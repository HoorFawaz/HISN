"""Tests for loading the model in the server: real predictions and fail-open startup."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from config import settings
from dns_server.decision import Reason
from dns_server.server import build_engine, load_age_service, load_lookalike, load_predictor
from ml.domain_age import AgeLookup, AgeStatus
from ml.predictor import Predictor
from storage.cache import TTLCache
from tests.test_train_evaluate import files, run_train  # noqa: F401  (fixture)


def _config(files: dict[str, Path], **overrides: object):  # type: ignore[no-untyped-def]
    values: dict[str, object] = {
        "model_path": files["model"],
        "brands_path": files["brands"],
        "whitelist_path": files["whitelist"],
    }
    values.update(overrides)
    return dataclasses.replace(settings, **values)  # type: ignore[arg-type]


def test_predictor_scores_names(files: dict[str, Path]) -> None:  # noqa: F811
    run_train(files)
    predictor = Predictor.from_files(files["model"], files["brands"], files["whitelist"])
    risky = predictor.probability("x7k2q9zv4m0pq1.xyz")
    safe = predictor.probability("greenmarket.com")
    assert 0.0 <= safe < risky <= 1.0


def test_missing_model_runs_without_it(files: dict[str, Path], caplog: pytest.LogCaptureFixture) -> None:  # noqa: F811
    assert load_predictor(_config(files)) is None
    assert "no model" in caplog.text


def test_broken_model_file_runs_without_it(files: dict[str, Path]) -> None:  # noqa: F811
    files["model"].parent.mkdir(parents=True, exist_ok=True)
    files["model"].write_bytes(b"not a model")
    assert load_predictor(_config(files)) is None


def test_rule_can_be_turned_off(files: dict[str, Path]) -> None:  # noqa: F811
    assert load_lookalike(_config(files, lookalike_block=frozenset())) is None


def test_engine_with_trained_model_and_rule(files: dict[str, Path]) -> None:  # noqa: F811
    run_train(files)
    config = _config(files, blacklist_path=settings.blacklist_path, model_threshold=0.5)
    engine = build_engine(config, TTLCache(3600))
    assert engine.decide("absher.sa").reason is Reason.WHITELIST
    assert engine.decide("abhser.com").reason is Reason.LOOKALIKE
    assert engine.decide("x7k2q9zv4m0pq1.xyz").reason is Reason.MODEL
    assert engine.decide("x7k2q9zv4m0pq1.xyz").reason is Reason.CACHE


def test_age_lookups_can_be_turned_off(files: dict[str, Path]) -> None:  # noqa: F811
    assert load_age_service(_config(files, domain_age_lookup=False)) is None


def test_engine_uses_ages_only_with_a_model(files: dict[str, Path]) -> None:  # noqa: F811
    class Ages:
        calls = 0

        def lookup(self, host: str) -> object:
            Ages.calls += 1
            return AgeLookup(AgeStatus.KNOWN, 3.0)

    config = _config(files, blacklist_path=settings.blacklist_path, model_threshold=0.5)
    build_engine(config, TTLCache(3600), Ages()).decide("x7k2q9zv4m0pq1.xyz")  # type: ignore[arg-type]
    assert Ages.calls == 0  # no model file yet: nothing would use the age
    run_train(files)
    decision = build_engine(config, TTLCache(3600), Ages()).decide("x7k2q9zv4m0pq1.xyz")  # type: ignore[arg-type]
    assert decision.reason is Reason.MODEL
    assert Ages.calls == 1


def test_predictor_accepts_an_age(files: dict[str, Path]) -> None:  # noqa: F811
    run_train(files)
    predictor = Predictor.from_files(files["model"], files["brands"], files["whitelist"])
    for age in (None, 2.0, 5000.0):
        assert 0.0 <= predictor.probability("greenmarket.com", age_days=age) <= 1.0
