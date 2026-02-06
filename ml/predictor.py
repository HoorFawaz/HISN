"""Load a trained model bundle and score single domain names.

Used by the DNS server, so this module stays light: no pandas, no training
code. ``ml.train`` writes the bundle; this module only reads it.

Model files are pickles (joblib). Loading one can run code, so only ever load
a file you trained yourself, from a folder only you can write to.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib

from dns_server.decision import load_domain_list
from ml.features import FEATURE_NAMES, FeatureExtractor

logger = logging.getLogger(__name__)

BUNDLE_VERSION = 2  # 2: look-alike features and per-technique balancing
MALICIOUS = 1


def load_bundle(path: Path) -> dict[str, Any]:
    """Load a bundle written by ``ml.train`` and check it matches this code.

    Only load files you trained yourself: joblib files can run code when loaded.
    """
    bundle = joblib.load(path)
    if not isinstance(bundle, dict) or bundle.get("bundle_version") != BUNDLE_VERSION:
        raise ValueError(f"{path.name}: not a HISN model bundle (retrain with python -m ml.train)")
    if tuple(bundle["feature_names"]) != FEATURE_NAMES:
        raise ValueError(f"{path.name}: trained with different features (retrain with python -m ml.train)")
    return bundle


class Predictor:
    """Probability that a domain name is malicious, from the trained forest."""

    def __init__(self, model: Any, extractor: FeatureExtractor) -> None:
        classes = list(model.classes_)
        if MALICIOUS not in classes:
            raise ValueError("the model was trained without malicious examples")
        self._model = model
        self._column = classes.index(MALICIOUS)
        self._extractor = extractor

    @classmethod
    def from_files(cls, model_path: Path, brands_path: Path, whitelist_path: Path) -> Predictor:
        bundle = load_bundle(model_path)
        model = bundle["model"]
        # One name at a time: worker threads cost more than they save, and the
        # DNS server already answers queries from several threads.
        if hasattr(model, "n_jobs"):
            model.n_jobs = 1
        brands = load_domain_list(brands_path)
        if tuple(sorted(brands)) != tuple(bundle.get("brands", ())):
            logger.warning("brands.txt changed since the model was trained; retrain for best results")
        return cls(model, FeatureExtractor(brands, load_domain_list(whitelist_path)))

    def probability(self, host: str) -> float:
        """Probability from 0 to 1. Raises InvalidDomainError for invalid names."""
        row = [self._extractor.vector(host)]
        return float(self._model.predict_proba(row)[0][self._column])
