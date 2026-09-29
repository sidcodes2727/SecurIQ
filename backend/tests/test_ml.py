"""Traffic classifier: train/inference parity, training quality and output contract."""
import random

from backend.analyzers.flow_extractor import FEATURE_NAMES, build_tunnels, extract_flow_features, extract_from_esp_packets
from backend.analyzers.pcap_parser import parse_pcap
from backend.ml.dataset import esp_records, generate_training_windows
from backend.testbed.esp_model import ESP_SUITES
from backend.testbed import pcap_writer as pw
from backend.testbed.scenarios import SAMPLE_SCENARIOS, CaptureBuilder
from backend.testbed.traffic_models import TRAFFIC_CLASSES, generate_traffic

SCENARIOS = {sc.name: sc for sc in SAMPLE_SCENARIOS}


def test_features_identical_from_records_and_pcap(tmp_path):
    """Training data and uploaded captures must go through identical feature computation."""
    builder = CaptureBuilder(SCENARIOS["moderate_ikev2_cbc_sha1_nopfs"])
    frames, _ = builder.build()
    path = tmp_path / "parity.pcap"
    pw.write_pcap(path, frames)
    direct = extract_from_esp_packets(builder.esp_records)
    parsed = extract_flow_features(parse_pcap(str(path)))
    assert len(direct) == len(parsed) > 0
    for a, b in zip(direct, parsed):
        for f in FEATURE_NAMES:
            assert abs(a[f] - b[f]) < 1e-9, f


def test_tunnels_pair_opposite_direction_sas():
    rng = random.Random(1)
    records = esp_records(generate_traffic("voip", 12, rng), ESP_SUITES["aes128gcm16"], "tunnel", 4, rng, 0.0)
    tunnels = build_tunnels(records)
    assert len(tunnels) == 1 and tunnels[0]["bidirectional"]
    windows = extract_from_esp_packets(records)
    assert all(0.4 < w["down_pkt_frac"] < 0.6 for w in windows)  # symmetric RTP, not the old fwd_ratio = 1.0


def test_every_class_produces_windows():
    rows = generate_training_windows(flows_per_class=2, seed=11)
    assert {r["label"] for r in rows} == set(TRAFFIC_CLASSES)
    assert all(set(FEATURE_NAMES) <= set(r) for r in rows)


def test_training_quality_and_group_split(trained_classifier):
    metrics = trained_classifier.metrics
    assert metrics["accuracy"] > 0.8
    assert "GroupShuffleSplit" in metrics["split"]
    assert len(metrics["confusion_matrix"]) == len(TRAFFIC_CLASSES)


def test_prediction_contract(trained_classifier, scenario_capture):
    path, _ = scenario_capture("mixed_all_traffic_ikev2")
    windows = extract_flow_features(parse_pcap(str(path)))
    predictions = trained_classifier.predict(windows)
    assert len(predictions) == len(windows)
    for p in predictions:
        assert p["predicted_class"] in TRAFFIC_CLASSES
        assert abs(sum(p["all_probabilities"].values()) - 1) < 1e-3
        assert p["uncertain"] == (p["confidence"] < 0.5)
        assert len(p["explanation"]) > 0
    summary = trained_classifier.summarize(predictions)
    assert abs(sum(summary["mix"].values()) - 1) < 1e-3
    assert 0 < summary["mean_confidence"] <= 1


def test_model_reload_roundtrip(trained_classifier):
    from backend.ml.model import TrafficClassifier
    fresh = TrafficClassifier()
    assert fresh.load() and fresh.metrics["accuracy"] == trained_classifier.metrics["accuracy"]
