"""
Tests for ML model and synthetic data generation.
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.ml.synthetic_data import generate_dataset, TRAFFIC_PROFILES
from backend.ml.model import TrafficClassifier
from backend.analyzers.flow_extractor import FEATURE_NAMES
from backend.config import TRAFFIC_CLASSES


class TestSyntheticData:
    def test_generate_dataset(self, tmp_path):
        result = generate_dataset(samples_per_class=20, output_dir=str(tmp_path), seed=42)
        assert result["total_samples"] == 20 * len(TRAFFIC_CLASSES)
        assert os.path.exists(result["output_file"])

    def test_dataset_has_all_classes(self, tmp_path):
        result = generate_dataset(samples_per_class=10, output_dir=str(tmp_path))
        with open(result["output_file"]) as f:
            data = json.load(f)
        labels = set(s["label"] for s in data["samples"])
        for cls in TRAFFIC_CLASSES:
            assert cls in labels, f"Missing class: {cls}"

    def test_sample_has_all_features(self, tmp_path):
        result = generate_dataset(samples_per_class=5, output_dir=str(tmp_path))
        with open(result["output_file"]) as f:
            data = json.load(f)
        sample = data["samples"][0]
        for name in FEATURE_NAMES:
            assert name in sample, f"Missing feature: {name}"

    def test_profiles_cover_all_classes(self):
        for cls in TRAFFIC_CLASSES:
            assert cls in TRAFFIC_PROFILES, f"Missing profile for class: {cls}"


class TestTrafficClassifier:
    @pytest.fixture(scope="class")
    def trained_classifier(self, tmp_path_factory):
        tmpdir = str(tmp_path_factory.mktemp("ml"))
        dataset_result = generate_dataset(samples_per_class=50, output_dir=tmpdir, seed=42)
        
        clf = TrafficClassifier()
        # Override paths
        from pathlib import Path
        from backend import config
        orig_model = config.ML_MODEL_PATH
        orig_scaler = config.ML_SCALER_PATH
        config.ML_MODEL_PATH = Path(tmpdir) / "model.joblib"
        config.ML_SCALER_PATH = Path(tmpdir) / "scaler.joblib"
        
        metrics = clf.train(dataset_path=dataset_result["output_file"])
        
        yield clf, metrics
        
        # Restore
        config.ML_MODEL_PATH = orig_model
        config.ML_SCALER_PATH = orig_scaler

    def test_training_succeeds(self, trained_classifier):
        clf, metrics = trained_classifier
        assert clf.is_trained
        assert metrics["accuracy"] > 0.5  # Should be well above 0.5 with synthetic data

    def test_accuracy_reasonable(self, trained_classifier):
        _, metrics = trained_classifier
        assert metrics["accuracy"] > 0.7, f"Accuracy too low: {metrics['accuracy']}"

    def test_f1_score_reasonable(self, trained_classifier):
        _, metrics = trained_classifier
        assert metrics["f1_score"] > 0.7, f"F1 too low: {metrics['f1_score']}"

    def test_prediction_output(self, trained_classifier):
        clf, _ = trained_classifier
        test_features = [{name: 100.0 for name in FEATURE_NAMES}]
        predictions = clf.predict(test_features)
        assert len(predictions) == 1
        assert "predicted_class" in predictions[0]
        assert "confidence" in predictions[0]
        assert predictions[0]["predicted_class"] in TRAFFIC_CLASSES

    def test_confidence_bounded(self, trained_classifier):
        clf, _ = trained_classifier
        test_features = [{name: 100.0 for name in FEATURE_NAMES}]
        predictions = clf.predict(test_features)
        assert 0 <= predictions[0]["confidence"] <= 1

    def test_feature_importance_computed(self, trained_classifier):
        clf, _ = trained_classifier
        assert len(clf.feature_importance) > 0
        assert all("feature" in fi and "importance" in fi for fi in clf.feature_importance)

    def test_model_info(self, trained_classifier):
        clf, _ = trained_classifier
        info = clf.get_model_info()
        assert info["is_trained"]
        assert info["model_type"] == "RandomForestClassifier"
        assert len(info["feature_importance"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
