"""
ML model for encrypted traffic classification.
Uses RandomForest to predict traffic type from flow metadata features.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, f1_score
)

from backend.config import (
    ML_MODEL_PATH, ML_SCALER_PATH, TRAFFIC_CLASSES,
    DATASET_DIR, TEST_SPLIT_RATIO
)
from backend.analyzers.flow_extractor import FEATURE_NAMES, features_to_vector

logger = logging.getLogger(__name__)


class TrafficClassifier:
    """Encrypted traffic type classifier using RandomForest."""
    
    def __init__(self):
        self.model: RandomForestClassifier | None = None
        self.scaler: StandardScaler | None = None
        self.classes = TRAFFIC_CLASSES
        self.is_trained = False
        self.metrics: dict[str, Any] = {}
        self.feature_importance: list[dict] = []
    
    def load(self) -> bool:
        """Load a pre-trained model from disk."""
        try:
            if ML_MODEL_PATH.exists() and ML_SCALER_PATH.exists():
                self.model = joblib.load(ML_MODEL_PATH)
                self.scaler = joblib.load(ML_SCALER_PATH)
                self.is_trained = True
                self._compute_feature_importance()
                logger.info("Model loaded successfully")
                return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
        return False
    
    def train(self, dataset_path: str | None = None) -> dict[str, Any]:
        """
        Train the classifier on the synthetic dataset.
        
        Returns training metrics.
        """
        # Load dataset
        if dataset_path is None:
            dataset_path = str(DATASET_DIR / "synthetic_dataset.json")
        
        if not Path(dataset_path).exists():
            raise FileNotFoundError(
                f"Dataset not found at {dataset_path}. "
                "Run dataset generation first."
            )
        
        with open(dataset_path) as f:
            dataset = json.load(f)
        
        samples = dataset["samples"]
        
        # Extract features and labels
        X = []
        y = []
        for sample in samples:
            feature_vec = [float(sample.get(name, 0)) for name in FEATURE_NAMES]
            X.append(feature_vec)
            y.append(sample["label"])
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SPLIT_RATIO, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train RandomForest
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        
        # Cross-validation
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, cv=5, scoring="accuracy"
        )
        
        # Classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred, labels=self.classes)
        
        self.metrics = {
            "accuracy": round(accuracy, 4),
            "f1_score": round(f1, 4),
            "cv_mean_accuracy": round(cv_scores.mean(), 4),
            "cv_std_accuracy": round(cv_scores.std(), 4),
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "n_features": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "classes": self.classes,
        }
        
        # Feature importance
        self._compute_feature_importance()
        
        # Save model
        joblib.dump(self.model, ML_MODEL_PATH)
        joblib.dump(self.scaler, ML_SCALER_PATH)
        
        self.is_trained = True
        logger.info(f"Model trained. Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        
        return self.metrics
    
    def predict(self, flow_features: list[dict]) -> list[dict[str, Any]]:
        """
        Predict traffic type for a list of flow feature dicts.
        
        Returns predictions with confidence scores.
        """
        if not self.is_trained:
            if not self.load():
                raise RuntimeError("Model not trained. Train the model first.")
        
        if not flow_features:
            return []
        
        # Convert to feature vectors
        X = np.array([features_to_vector(f) for f in flow_features])
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        results = []
        for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
            # Get top-3 predictions
            sorted_indices = np.argsort(proba)[::-1]
            top_predictions = []
            for idx in sorted_indices[:3]:
                top_predictions.append({
                    "class": self.model.classes_[idx],
                    "confidence": round(float(proba[idx]), 4),
                })
            
            result = {
                "spi": flow_features[i].get("spi", f"flow_{i}"),
                "predicted_class": pred,
                "confidence": round(float(max(proba)), 4),
                "top_predictions": top_predictions,
                "all_probabilities": {
                    cls: round(float(p), 4)
                    for cls, p in zip(self.model.classes_, proba)
                },
            }
            results.append(result)
        
        return results
    
    def _compute_feature_importance(self):
        """Compute and store feature importance rankings."""
        if self.model is None:
            return
        
        importances = self.model.feature_importances_
        self.feature_importance = sorted(
            [
                {"feature": name, "importance": round(float(imp), 4)}
                for name, imp in zip(FEATURE_NAMES, importances)
            ],
            key=lambda x: x["importance"],
            reverse=True,
        )
    
    def get_model_info(self) -> dict[str, Any]:
        """Get model information and performance metrics."""
        return {
            "is_trained": self.is_trained,
            "model_type": "RandomForestClassifier",
            "n_estimators": 200,
            "n_features": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "classes": self.classes,
            "metrics": self.metrics,
            "feature_importance": self.feature_importance[:15],  # Top 15
            "model_path": str(ML_MODEL_PATH) if ML_MODEL_PATH.exists() else None,
        }


# Singleton instance
classifier = TrafficClassifier()
