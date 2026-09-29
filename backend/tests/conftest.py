"""
Shared fixtures. All generated data (samples, model, analyses) goes to a
temporary directory so tests never touch backend/data.
"""
import os
import tempfile

os.environ.setdefault("SECURIQ_DATA_DIR", tempfile.mkdtemp(prefix="securiq-test-"))

import pytest  # noqa: E402

from backend.testbed.scenarios import SAMPLE_SCENARIOS, write_scenario  # noqa: E402

SCENARIOS = {sc.name: sc for sc in SAMPLE_SCENARIOS}


@pytest.fixture(scope="session")
def capture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("captures")


@pytest.fixture(scope="session")
def scenario_capture(capture_dir):
    """Build a curated scenario PCAP once per session: scenario_capture(name) -> (path, truth)."""
    cache = {}

    def build(name):
        if name not in cache:
            cache[name] = write_scenario(SCENARIOS[name], capture_dir)
        return cache[name]
    return build


@pytest.fixture(scope="session")
def trained_classifier():
    """A small but real classifier, trained once per session."""
    from backend.ml.model import classifier
    if not classifier.is_trained:
        classifier.train(flows_per_class=10, seed=3)
    return classifier
