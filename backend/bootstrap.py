"""
Startup tasks: curated testbed samples and the traffic classifier.

Both run in a background thread so the API is reachable immediately; /api/health
reports progress.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from backend.config import SAMPLE_DIR, TRAINING_FLOWS_PER_CLASS
from backend.ml.model import classifier
from backend.storage import sample_manifest
from backend.testbed.scenarios import generate_samples

logger = logging.getLogger(__name__)

SAMPLES_VERSION = 2
state: dict[str, Any] = {"samples_ready": False, "model_training": False, "model_error": None}
_train_lock = threading.Lock()


class TrainingInProgress(RuntimeError):
    pass


def ensure_samples(force: bool = False) -> dict[str, Any]:
    manifest = sample_manifest()
    current = (manifest.get("version") == SAMPLES_VERSION and
               all((SAMPLE_DIR / t["file"]).exists() for t in manifest.get("samples", {}).values()))
    if current and not force:
        state["samples_ready"] = True
        return manifest
    logger.info("Generating testbed sample captures…")
    truths = generate_samples(SAMPLE_DIR)
    manifest = {"version": SAMPLES_VERSION,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "samples": {t["name"]: t for t in truths}}
    (SAMPLE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    state["samples_ready"] = True
    return manifest


def train_model(flows_per_class: int = TRAINING_FLOWS_PER_CLASS) -> dict[str, Any]:
    if not _train_lock.acquire(blocking=False):
        raise TrainingInProgress("Model training already in progress")
    state["model_training"] = True
    state["model_error"] = None
    try:
        return classifier.train(flows_per_class)
    except Exception as exc:
        state["model_error"] = str(exc)
        raise
    finally:
        state["model_training"] = False
        _train_lock.release()


def seed_from_bundle() -> bool:
    """Copy a pre-built model and small sample set from SECURIQ_SEED_DIR into the data directory when missing.

    For hosts with an ephemeral disk and little RAM (e.g. a free tier): the container starts in seconds instead of
    generating captures and training the classifier on every cold start. Never overwrites existing files."""
    seed = os.environ.get("SECURIQ_SEED_DIR")
    if not seed or not Path(seed).is_dir():
        return False
    from backend.config import MODEL_DIR
    copied = False
    for source_dir, target_dir in ((Path(seed) / "models", MODEL_DIR), (Path(seed) / "samples", SAMPLE_DIR)):
        for f in source_dir.glob("*") if source_dir.is_dir() else []:
            if not (target_dir / f.name).exists():
                shutil.copyfile(f, target_dir / f.name)
                copied = True
    if copied:
        logger.info("Seeded model and samples from %s", seed)
    return copied


def _bootstrap() -> None:
    try:
        seed_from_bundle()
    except Exception:
        logger.exception("Seeding from bundle failed")
    try:
        ensure_samples()
    except Exception:
        logger.exception("Sample generation failed")
    try:
        if not classifier.load():
            logger.info("Training traffic classifier (first start)…")
            train_model()
    except Exception:
        logger.exception("Model training failed")


def start_background_bootstrap() -> threading.Thread:
    thread = threading.Thread(target=_bootstrap, name="securiq-bootstrap", daemon=True)
    thread.start()
    return thread
