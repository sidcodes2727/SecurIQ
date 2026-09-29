"""
Encrypted traffic classifier (PS §c: "predict type of traffic inside ESP").

- Model: soft-voting ensemble of ExtraTrees and HistGradientBoosting over
  direction-agnostic size/timing features of 10-second tunnel windows.
- Training data is augmented with network impairments (jitter, loss with TCP
  retransmissions, multiplexed background flows); a separate *heavy*-impairment
  stress set with an unseen seed measures robustness.
- Probabilities are calibrated with a power (temperature-like) transform fitted
  on held-out flows, so "confidence" means what it says.
- Consecutive windows of one tunnel are smoothed with a sticky HMM
  (forward-backward offline, forward-only in the live engine).
- All evaluation uses group-aware splits (every window of a flow on one side).
- A k-nearest-neighbour novelty detector (log-scaled, standardised features) flags windows
  unlike anything in the training distribution; it is evaluated leave-one-class-out.
  (Chosen over IsolationForest: 49% vs 25% unseen-class detection at < 1% false alarms, same data.)
- Each prediction carries plain-language evidence (which traffic properties support it)
  and uncertainty notes drawn from the held-out confusion matrix.
"""
from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.neighbors import NearestNeighbors

from backend.analyzers.flow_extractor import FEATURE_NAMES, WINDOW_SECONDS, features_to_vector
from backend.config import DATASET_DIR, ML_MODEL_PATH, TRAFFIC_CLASSES, TRAFFIC_CLASS_LABELS
from backend.ml.dataset import generate_training_windows, save_rows

logger = logging.getLogger(__name__)

MODEL_VERSION = 5
UNCERTAIN_THRESHOLD = 0.5
EXPLAIN_FEATURES = 6
HMM_STAY = 0.8            # probability that the next 10 s window carries the same application
ENSEMBLE_WEIGHTS = (0.6, 0.4)
NOVELTY_PERCENTILE = 97.5  # kNN distance above the 97.5th percentile of training windows = novel
NOVELTY_K = 5


class EnsembleModel:
    """Soft vote of ExtraTrees (variance-robust) and gradient boosting (bias-robust)."""

    def __init__(self, n_trees: int = 400, iterations: int = 300) -> None:
        self.members = [
            ExtraTreesClassifier(n_estimators=n_trees, class_weight="balanced", n_jobs=-1, random_state=42),
            HistGradientBoostingClassifier(max_iter=iterations, learning_rate=0.08, class_weight="balanced",
                                           random_state=42),
        ]
        self.classes_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "EnsembleModel":
        for member in self.members:
            member.fit(X, y)
        self.classes_ = self.members[0].classes_
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return sum(w * m.predict_proba(X) for w, m in zip(ENSEMBLE_WEIGHTS, self.members))

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.classes_[self.predict_proba(X).argmax(axis=1)]

    def score(self, X: np.ndarray, y: np.ndarray) -> float:  # used by permutation_importance
        return accuracy_score(y, self.predict(X))


class TrafficClassifier:
    def __init__(self) -> None:
        self.model: EnsembleModel | None = None
        self.temperature_power = 1.0
        self.is_trained = False
        self.metrics: dict[str, Any] = {}
        self.feature_importance: list[dict[str, Any]] = []
        self.class_profiles: dict[str, dict[str, float]] = {}
        self.dataset_info: dict[str, Any] = {}
        self.trained_at: str | None = None
        self.novelty: dict[str, Any] | None = None
        self.feature_quantiles: dict[str, list[float]] = {}

    # ------------------------------------------------------------ persistence

    def load(self) -> bool:
        try:
            if not ML_MODEL_PATH.exists():
                return False
            bundle = joblib.load(ML_MODEL_PATH)
            if bundle.get("version") != MODEL_VERSION or bundle.get("feature_names") != FEATURE_NAMES:
                logger.info("Stored model is from an older version or feature set; retraining required")
                return False
            for key in ("model", "temperature_power", "metrics", "feature_importance", "class_profiles",
                        "dataset_info", "trained_at", "novelty", "feature_quantiles"):
                setattr(self, key, bundle[key])
            self.is_trained = True
            return True
        except Exception as exc:  # corrupt or incompatible file → retrain
            logger.warning("Could not load model: %s", exc)
            return False

    def _save(self) -> None:
        joblib.dump({
            "version": MODEL_VERSION, "feature_names": FEATURE_NAMES, "model": self.model,
            "temperature_power": self.temperature_power, "metrics": self.metrics,
            "feature_importance": self.feature_importance, "class_profiles": self.class_profiles,
            "dataset_info": self.dataset_info, "trained_at": self.trained_at,
            "novelty": self.novelty, "feature_quantiles": self.feature_quantiles,
        }, ML_MODEL_PATH)

    # ------------------------------------------------------------ training

    def train(self, flows_per_class: int = 60, seed: int = 7) -> dict[str, Any]:
        started = time.time()
        rows = generate_training_windows(flows_per_class, seed, impairment="augment")
        stress = generate_training_windows(max(12, flows_per_class // 3), seed + 1000, impairment="heavy")
        save_rows(rows, DATASET_DIR / "training_windows.csv")

        X, y, groups = _matrix(rows)
        Xs, ys, _ = _matrix(stress)
        train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
                                   .split(X, y, groups))
        model = EnsembleModel().fit(X[train_idx], y[train_idx])
        classes = list(model.classes_)

        test_proba = model.predict_proba(X[test_idx])
        y_pred = model.classes_[test_proba.argmax(axis=1)]
        self.temperature_power = _fit_power(test_proba, y[test_idx], classes)
        stress_proba = model.predict_proba(Xs)
        stress_pred = model.classes_[stress_proba.argmax(axis=1)]

        cv_scores = []
        for tr, te in GroupKFold(n_splits=3).split(X, y, groups):
            fold = EnsembleModel(n_trees=150, iterations=150).fit(X[tr], y[tr])
            cv_scores.append(accuracy_score(y[te], fold.predict(X[te])))

        importance = permutation_importance(model, X[test_idx], y[test_idx], n_repeats=3, random_state=0,
                                            n_jobs=1).importances_mean
        importance = np.clip(importance, 0, None)
        importance = importance / importance.sum() if importance.sum() > 0 else importance

        test_rows = [rows[i] for i in test_idx]
        novelty_eval = _novelty_evaluation(X[train_idx], y[train_idx], X[test_idx], y[test_idx])
        self.metrics = {
            "roc_auc_ovr": _auc(y[test_idx], _calibrate(test_proba, self.temperature_power), classes),
            "stress_roc_auc_ovr": _auc(ys, _calibrate(stress_proba, self.temperature_power), classes),
            "novelty": novelty_eval,
            "accuracy": _r(accuracy_score(y[test_idx], y_pred)),
            "f1_macro": _r(f1_score(y[test_idx], y_pred, average="macro")),
            "f1_score": _r(f1_score(y[test_idx], y_pred, average="weighted")),
            "cv_mean_accuracy": _r(np.mean(cv_scores)),
            "cv_std_accuracy": _r(np.std(cv_scores)),
            "stress_accuracy": _r(accuracy_score(ys, stress_pred)),
            "stress_f1_macro": _r(f1_score(ys, stress_pred, average="macro")),
            "stress_windows": int(len(ys)),
            "calibration": {
                "power": round(self.temperature_power, 3),
                "ece_before": _r(_ece(stress_proba, ys, classes)),
                "ece_after": _r(_ece(_calibrate(stress_proba, self.temperature_power), ys, classes)),
                "evaluated_on": "heavy-impairment stress set",
            },
            "classification_report": classification_report(y[test_idx], y_pred, output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(y[test_idx], y_pred, labels=TRAFFIC_CLASSES).tolist(),
            "stress_confusion_matrix": confusion_matrix(ys, stress_pred, labels=TRAFFIC_CLASSES).tolist(),
            "accuracy_by_suite_family": _grouped_accuracy(test_rows, y_pred, "suite_family"),
            "accuracy_by_mode": _grouped_accuracy(test_rows, y_pred, "mode"),
            "accuracy_by_ip_version": _grouped_accuracy(test_rows, y_pred, "ip_version"),
            "accuracy_by_impairment": _grouped_accuracy(test_rows, y_pred, "impairment"),
            "training_samples": int(len(train_idx)),
            "test_samples": int(len(test_idx)),
            "split": "GroupShuffleSplit by flow (25% test) + 3-fold GroupKFold CV + unseen heavy-impairment stress set",
            "n_features": len(FEATURE_NAMES),
            "classes": TRAFFIC_CLASSES,
        }

        # Final model: every training window (the stress set stays unseen).
        self.model = EnsembleModel().fit(X, y)
        self.novelty = _fit_novelty(X)
        self.feature_quantiles = {f: [round(float(q), 4) for q in np.percentile(X[:, i], [10, 25, 50, 75, 90])]
                                  for i, f in enumerate(FEATURE_NAMES)}
        self.feature_importance = sorted(
            ({"feature": name, "importance": round(float(imp), 4)} for name, imp in zip(FEATURE_NAMES, importance)),
            key=lambda item: item["importance"], reverse=True)
        top = [item["feature"] for item in self.feature_importance[:EXPLAIN_FEATURES]]
        self.class_profiles = {
            cls: {f: round(float(np.median(X[y == cls, FEATURE_NAMES.index(f)])), 4) for f in top}
            for cls in TRAFFIC_CLASSES
        }
        self.dataset_info = {
            "windows": len(rows),
            "flows": len(set(groups)),
            "flows_per_class": flows_per_class,
            "windows_per_class": dict(Counter(y.tolist())),
            "impairment_mix": dict(Counter(r["impairment"] for r in rows)),
            "stress_windows": len(stress),
            "seed": seed,
            "window_seconds": WINDOW_SECONDS,
            "suites": sorted({row["suite"] for row in rows}),
            "file": "training_windows.csv",
        }
        self.trained_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.metrics["training_seconds"] = round(time.time() - started, 1)
        self.is_trained = True
        self._save()
        logger.info("Classifier trained: accuracy %.3f, stress %.3f", self.metrics["accuracy"],
                    self.metrics["stress_accuracy"])
        return self.metrics

    # ------------------------------------------------------------ inference

    def predict(self, windows: list[dict[str, Any]], smooth: bool = True) -> list[dict[str, Any]]:
        if not self.is_trained and not self.load():
            raise RuntimeError("Model not trained")
        if not windows:
            return []
        X = np.array([features_to_vector(w) for w in windows])
        probabilities = _calibrate(self.model.predict_proba(X), self.temperature_power)
        classes = list(self.model.classes_)
        results = [self._result(window, proba, classes) for window, proba in zip(windows, probabilities)]
        novelty = self.novelty_scores(X)
        results = smooth_predictions(results, classes) if smooth else results
        for window, result, novelty_score in zip(windows, results, novelty):
            if novelty_score is not None:
                result["novelty_score"] = round(float(novelty_score), 3)   # 1.0 = the novelty threshold
                result["novel"] = bool(novelty_score > 1.0)
            result["reasoning"] = self.reasoning(window, result)
        return results

    def novelty_scores(self, X: np.ndarray) -> list[float | None]:
        """Mean distance to the k nearest training windows, as a multiple of the novelty threshold."""
        if not self.novelty:
            return [None] * len(X)
        return list(_novelty_distance(self.novelty, X) / self.novelty["threshold"])

    def reasoning(self, window: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        """Plain-language support for a window's prediction, and what makes it uncertain."""
        cls = result["predicted_class"]
        supports: list[str] = []
        for feature in [f["feature"] for f in self.feature_importance[:16]]:
            phrase = _phrase(feature, float(window.get(feature, 0.0)), self.feature_quantiles.get(feature),
                             (self.class_profiles.get(cls) or {}).get(feature))
            if phrase and phrase not in supports:
                supports.append(phrase)
            if len(supports) == 4:
                break
        caveats = []
        top = result["top_predictions"]
        if len(top) > 1 and top[0]["confidence"] - top[1]["confidence"] < 0.25:
            caveats.append(f"Runner-up {TRAFFIC_CLASS_LABELS.get(top[1]['class'], top[1]['class'])} at "
                           f"{top[1]['confidence']:.0%}: the two patterns overlap in this window")
        confused = _confusable(self.metrics, cls)
        if confused:
            caveats.append(confused)
        if result.get("novel"):
            caveats.append("This window is unlike the training data (novelty detector): treat the label with caution")
        if (window.get("packet_count") or 0) < 20:
            caveats.append(f"Only {window.get('packet_count')} packets in the window")
        if not caveats:
            caveats.append("Other applications with similar size and timing can look alike once encrypted")
        return {"supports": supports, "caveats": caveats}

    def _result(self, window: dict[str, Any], proba: np.ndarray, classes: list[str]) -> dict[str, Any]:
        top = [item["feature"] for item in self.feature_importance[:EXPLAIN_FEATURES]]
        result = {
            "flow_id": window.get("flow_id"),
            "spi": window.get("flow_id"),
            "window_start": window.get("window_start"),
            "window_end": window.get("window_end"),
            "packet_count": window.get("packet_count"),
            "explanation": [{"feature": f, "value": round(float(window.get(f, 0.0)), 4),
                             "class_median": None} for f in top],
        }
        _apply_distribution(result, proba, classes)
        result["raw_class"] = result["predicted_class"]
        result["raw_confidence"] = result["confidence"]
        for e in result["explanation"]:
            e["class_median"] = self.class_profiles.get(result["predicted_class"], {}).get(e["feature"])
        return result

    def summarize(self, predictions: list[dict[str, Any]]) -> dict[str, Any]:
        """Per-tunnel and capture-wide traffic mix as share of time (windows); confidence weighted by packets."""
        if not predictions:
            return {"flows": [], "mix": {}, "mean_confidence": None, "windows": 0}
        by_flow: dict[str, list[dict]] = defaultdict(list)
        for p in predictions:
            by_flow[p["flow_id"]].append(p)

        def mix(preds: list[dict]) -> dict[str, float]:
            # Time share, not packet share: a 20 Mbit/s transfer must not drown out a VoIP call of equal length.
            weights = Counter(p["predicted_class"] for p in preds)
            total = sum(weights.values())
            return {c: round(w / total, 4) for c, w in weights.most_common()}

        flows = []
        for flow_id, preds in by_flow.items():
            preds = sorted(preds, key=lambda p: p["window_start"])
            flow_mix = mix(preds)
            dominant = next(iter(flow_mix))
            flows.append({
                "flow_id": flow_id,
                "dominant_class": dominant,
                "dominant_label": TRAFFIC_CLASS_LABELS.get(dominant, dominant),
                "mix": flow_mix,
                "windows": len(preds),
                "mean_confidence": round(float(np.mean([p["confidence"] for p in preds])), 4),
                "timeline": [{"start": p["window_start"], "end": p["window_end"], "class": p["predicted_class"],
                              "confidence": p["confidence"], "uncertain": p["uncertain"]} for p in preds],
            })
        packets = sum(p["packet_count"] or 1 for p in predictions)
        weighted = sum(p["confidence"] * (p["packet_count"] or 1) for p in predictions) / packets
        return {
            "flows": flows,
            "mix": mix(predictions),
            "mean_confidence": round(float(weighted), 4),
            "windows": len(predictions),
            "uncertain_windows": sum(1 for p in predictions if p["uncertain"]),
            "novel_windows": sum(1 for p in predictions if p.get("novel")),
            "smoothed_changes": sum(1 for p in predictions if p.get("raw_class") != p["predicted_class"]),
        }

    def get_model_info(self) -> dict[str, Any]:
        return {
            "is_trained": self.is_trained,
            "model_type": "Ensemble: ExtraTrees + HistGradientBoosting (soft vote 0.6 / 0.4)",
            "model_version": MODEL_VERSION,
            "n_estimators": 400,
            "n_features": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "classes": TRAFFIC_CLASSES,
            "class_labels": TRAFFIC_CLASS_LABELS,
            "window_seconds": WINDOW_SECONDS,
            "uncertain_threshold": UNCERTAIN_THRESHOLD,
            "smoothing": f"sticky HMM, stay probability {HMM_STAY}",
            "metrics": self.metrics,
            "feature_importance": self.feature_importance[:15],
            "importance_method": "permutation importance on held-out flows",
            "dataset": self.dataset_info,
            "trained_at": self.trained_at,
            "novelty_detector": (f"{NOVELTY_K}-nearest-neighbour distance on log-scaled, standardised features; "
                                 f"windows farther than the {NOVELTY_PERCENTILE:g}th percentile of training windows "
                                 "are flagged novel"),
        }


# ---------------------------------------------------------------- novelty detection

def _log_scale(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


def _fit_novelty(X: np.ndarray) -> dict[str, Any]:
    L = _log_scale(X)
    mean, scale = L.mean(axis=0), L.std(axis=0) + 1e-9
    Z = (L - mean) / scale
    nn = NearestNeighbors(n_neighbors=NOVELTY_K + 1).fit(Z)
    dist, _ = nn.kneighbors(Z)
    threshold = float(np.percentile(dist[:, 1:].mean(axis=1), NOVELTY_PERCENTILE))  # leave-one-out distances
    return {"model": nn, "mean": mean, "scale": scale, "threshold": threshold}


def _novelty_distance(detector: dict[str, Any], X: np.ndarray) -> np.ndarray:
    Z = (_log_scale(X) - detector["mean"]) / detector["scale"]
    dist, _ = detector["model"].kneighbors(Z, n_neighbors=NOVELTY_K)
    return dist.mean(axis=1)


def _novelty_evaluation(X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray,
                        y_test: np.ndarray) -> dict[str, Any]:
    """Leave-one-class-out: fit without class k, then measure how many class-k windows are flagged novel."""
    detector = _fit_novelty(X_train)
    false_alarm = float(np.mean(_novelty_distance(detector, X_test) > detector["threshold"]))
    unseen = {}
    for cls in TRAFFIC_CLASSES:
        held = _fit_novelty(X_train[y_train != cls])
        target = X_test[y_test == cls]
        if len(target):
            unseen[cls] = _r(np.mean(_novelty_distance(held, target) > held["threshold"]))
    return {"false_alarm_rate": _r(false_alarm), "unseen_class_detection": unseen,
            "mean_unseen_detection": _r(np.mean(list(unseen.values()))) if unseen else None,
            "method": (f"leave-one-class-out on held-out flows; {NOVELTY_K}-NN distance, threshold = "
                       f"{NOVELTY_PERCENTILE:g}th percentile of training windows")}


def _auc(y: np.ndarray, proba: np.ndarray, classes: list[str]) -> float | None:
    try:
        return _r(roc_auc_score(y, proba, multi_class="ovr", labels=classes, average="macro"))
    except ValueError:
        return None


# ---------------------------------------------------------------- plain-language evidence

PHRASES = {
    "size_median": ("Large packets (median {v:.0f} B)", "Small packets (median {v:.0f} B)"),
    "size_mean": ("Large packets (mean {v:.0f} B)", "Small packets (mean {v:.0f} B)"),
    "size_q90": ("Full-size packets at the top end ({v:.0f} B)", "Even the largest packets are small ({v:.0f} B)"),
    "size_q75": ("Most packets are large ({v:.0f} B at the 75th percentile)", "Most packets are small ({v:.0f} B)"),
    "pkt_rate": ("High packet rate ({v:.0f} pkt/s)", "Low packet rate ({v:.1f} pkt/s)"),
    "byte_rate": ("High throughput ({kb:.0f} KB/s)", "Low throughput ({kb:.1f} KB/s)"),
    "iat_cv": ("Irregular, bursty timing (CV {v:.2f})", "Very regular timing (CV {v:.2f})"),
    "iat_regularity": ("Metronome-like packet clock", "No regular packet clock"),
    "mode_iat_cv": ("Irregular spacing of the dominant packet size", "Dominant packet size sent on a steady clock"),
    "mode_iat_median": ("Slow cadence of the dominant packet size ({ms:.0f} ms)",
                        "Fast cadence of the dominant packet size ({ms:.0f} ms)"),
    "iat_median": ("Long gaps between packets (median {ms:.0f} ms)", "Tight packet spacing (median {ms:.1f} ms)"),
    "idle_frac": ("Mostly idle ({pct:.0f}% of the window)", "Continuously active"),
    "size_mode_share": ("One packet size dominates ({pct:.0f}% of packets)", "Many different packet sizes"),
    "distinct_size_ratio": ("Highly varied packet sizes", "Few distinct packet sizes"),
    "size_entropy": ("High size variety (entropy {v:.2f})", "Low size variety (entropy {v:.2f})"),
    "down_byte_frac": ("Asymmetric: {pct:.0f}% of bytes flow one way", "Balanced bytes in both directions"),
    "down_pkt_frac": ("Most packets flow one way ({pct:.0f}%)", "Symmetric bidirectional packet exchange"),
    "frac_small": ("Mostly small packets ({pct:.0f}%)", "Few small packets ({pct:.0f}%)"),
    "frac_large": ("Mostly large packets ({pct:.0f}%)", "Few large packets ({pct:.0f}%)"),
    "byte_frac_large": ("Bytes carried by large packets ({pct:.0f}%)", "Bytes carried by small packets"),
    "burst_rate": ("Frequent bursts ({v:.1f}/s)", "Few bursts"),
    "burst_len_mean": ("Long bursts ({v:.0f} packets)", "Short bursts"),
    "burst_bytes_max": ("Large bursts (up to {kb:.0f} KB)", "Small bursts (up to {kb:.1f} KB)"),
    "frac_iat_under_2ms": ("Back-to-back packet trains ({pct:.0f}% under 2 ms apart)", "Few back-to-back packets"),
    "large_iat_median": ("Large packets spaced out ({ms:.0f} ms)", "Large packets arrive back-to-back"),
    "mid_frac": ("Many mid-sized packets ({pct:.0f}%)", "Few mid-sized packets"),
}


def _phrase(feature: str, value: float, quantiles: list[float] | None, class_median: float | None) -> str | None:
    """Describe a feature only when this window is clearly low/high overall and the predicted class agrees."""
    if not quantiles or feature not in PHRASES:
        return None
    _, q25, median, q75, _ = quantiles
    high, low = value >= q75 and q75 > median, value <= q25 and q25 < median
    if not (high or low):
        return None
    if class_median is not None and ((high and class_median < median) or (low and class_median > median)):
        return None
    return PHRASES[feature][0 if high else 1].format(v=value, kb=value / 1024, ms=value * 1000, pct=value * 100)


def _confusable(metrics: dict[str, Any], cls: str) -> str | None:
    matrix, classes = metrics.get("confusion_matrix"), metrics.get("classes")
    if not matrix or cls not in (classes or []):
        return None
    j = classes.index(cls)
    column = [row[j] for row in matrix]
    total = sum(column)
    others = [(column[i], classes[i]) for i in range(len(classes)) if i != j and column[i]]
    if not total or not others:
        return None
    count, other = max(others)
    share = count / total
    if share < 0.01:
        return None
    return (f"In held-out tests {share:.0%} of windows predicted as {TRAFFIC_CLASS_LABELS.get(cls, cls)} were "
            f"actually {TRAFFIC_CLASS_LABELS.get(other, other)}")


# ---------------------------------------------------------------- temporal smoothing

def _transition(n: int, stay: float = HMM_STAY) -> np.ndarray:
    matrix = np.full((n, n), (1 - stay) / (n - 1))
    np.fill_diagonal(matrix, stay)
    return matrix


def forward_step(prior: np.ndarray | None, proba: np.ndarray, stay: float = HMM_STAY) -> np.ndarray:
    """One causal HMM step (live engine): belief after this window given the previous belief."""
    if prior is None:
        return proba / proba.sum()
    belief = (prior @ _transition(len(proba), stay)) * proba
    return belief / belief.sum()


def smooth_predictions(predictions: list[dict[str, Any]], classes: list[str],
                       stay: float = HMM_STAY) -> list[dict[str, Any]]:
    """Forward-backward over runs of consecutive windows of the same tunnel."""
    by_flow: dict[str, list[dict]] = defaultdict(list)
    for p in predictions:
        by_flow[p["flow_id"]].append(p)
    T = _transition(len(classes), stay)
    for preds in by_flow.values():
        preds.sort(key=lambda p: p["window_start"])
        chains, chain = [], [preds[0]]
        for prev, cur in zip(preds, preds[1:]):
            if abs(cur["window_start"] - prev["window_end"]) < 1e-6:
                chain.append(cur)
            else:
                chains.append(chain)
                chain = [cur]
        chains.append(chain)
        for chain in chains:
            if len(chain) < 2:
                continue
            emissions = np.array([[p["all_probabilities"][c] for c in classes] for p in chain]) + 1e-9
            alpha = np.zeros_like(emissions)
            alpha[0] = emissions[0] / emissions[0].sum()
            for t in range(1, len(chain)):
                alpha[t] = (alpha[t - 1] @ T) * emissions[t]
                alpha[t] /= alpha[t].sum()
            beta = np.ones_like(emissions)
            for t in range(len(chain) - 2, -1, -1):
                beta[t] = T @ (emissions[t + 1] * beta[t + 1])
                beta[t] /= beta[t].sum()
            posterior = alpha * beta
            posterior /= posterior.sum(axis=1, keepdims=True)
            for p, dist in zip(chain, posterior):
                _apply_distribution(p, dist, classes)
    return predictions


def _apply_distribution(result: dict[str, Any], proba: np.ndarray, classes: list[str]) -> None:
    order = np.argsort(proba)[::-1]
    best = classes[order[0]]
    confidence = float(proba[order[0]])
    result.update({
        "predicted_class": best,
        "predicted_label": TRAFFIC_CLASS_LABELS.get(best, best),
        "confidence": round(confidence, 4),
        "uncertain": confidence < UNCERTAIN_THRESHOLD,
        "top_predictions": [{"class": classes[i], "confidence": round(float(proba[i]), 4)} for i in order[:3]],
        "all_probabilities": {c: round(float(p), 4) for c, p in zip(classes, proba)},
    })


# ---------------------------------------------------------------- calibration & helpers

def _calibrate(proba: np.ndarray, power: float) -> np.ndarray:
    scaled = np.clip(proba, 1e-9, 1.0) ** power
    return scaled / scaled.sum(axis=1, keepdims=True)


def _fit_power(proba: np.ndarray, y: np.ndarray, classes: list[str]) -> float:
    """Power a minimising held-out negative log-likelihood of p^a / Σ p^a (a<1 softens, a>1 sharpens)."""
    idx = np.array([classes.index(label) for label in y])
    best, best_nll = 1.0, np.inf
    for power in np.linspace(0.3, 3.0, 28):
        calibrated = _calibrate(proba, power)
        nll = -np.mean(np.log(calibrated[np.arange(len(idx)), idx] + 1e-12))
        if nll < best_nll:
            best, best_nll = float(power), nll
    return best


def _ece(proba: np.ndarray, y: np.ndarray, classes: list[str], bins: int = 10) -> float:
    """Expected calibration error: |accuracy − confidence| averaged over confidence bins."""
    confidence = proba.max(axis=1)
    correct = np.array(classes)[proba.argmax(axis=1)] == y
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (confidence > lo) & (confidence <= hi)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return float(ece)


def _matrix(rows: list[dict]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    X = np.array([[row[f] for f in FEATURE_NAMES] for row in rows], dtype=float)
    return X, np.array([row["label"] for row in rows]), np.array([row["group"] for row in rows])


def _r(value: float) -> float:
    return round(float(value), 4)


def _grouped_accuracy(rows: list[dict], y_pred: np.ndarray, key: str) -> dict[str, float]:
    buckets: dict[str, list[bool]] = defaultdict(list)
    for row, pred in zip(rows, y_pred):
        buckets[str(row[key])].append(row["label"] == pred)
    return {k: round(sum(v) / len(v), 4) for k, v in sorted(buckets.items())}


classifier = TrafficClassifier()
