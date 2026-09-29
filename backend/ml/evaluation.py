"""
End-to-end evaluation of the AI identification engine against testbed ground truth.

Random points of the configuration matrix are rendered to PCAP, analysed by the
full pipeline, and every identified property is compared with the scenario that
produced it. "Abstained" (not observable) is reported separately from "wrong", so
coverage and accuracy are both visible.

    python -m backend.ml.evaluation --scenarios 30 --seed 2024
"""
from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from backend.config import EVALUATION_DIR
from backend.pipeline import run_pipeline
from backend.testbed.scenarios import random_scenario, write_scenario

RESULT_FILE = EVALUATION_DIR / "latest.json"


def evaluate_end_to_end(n_scenarios: int = 24, seed: int = 2024, impairment: str = "none") -> dict[str, Any]:
    rng = random.Random(seed)
    started = time.time()
    per_field: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "wrong": 0, "abstained": 0})
    scenarios = []
    window_hits = window_total = raw_hits = pure_hits = pure_total = 0

    with tempfile.TemporaryDirectory() as tmp:
        for i in range(n_scenarios):
            scenario = random_scenario(rng, i, duration=(15, 22), impairment=impairment)
            path, truth = write_scenario(scenario, tmp)
            result = run_pipeline(str(path), truth)
            comparison = result["ground_truth"]
            for row in comparison["rows"]:
                if row["observable"]:
                    per_field[row["field"]][row["status"]] += 1
            window_hits += comparison["window_hits"]
            raw_hits += comparison["window_hits_raw"]
            pure_hits += comparison["pure_window_hits"]
            pure_total += comparison["pure_window_total"]
            window_total += comparison["window_total"]
            scenarios.append({
                "name": scenario.name,
                "config": {k: truth["config"][k] for k in ("ike_version", "aggressive", "ike_suite", "esp_suite",
                                                           "pfs", "mode", "ip_version", "nat_t", "auth")},
                "traffic": [s["class"] for s in truth["traffic_segments"]],
                "accuracy": comparison["accuracy"],
                "wrong": [r["field"] for r in comparison["rows"] if r["status"] == "wrong"],
                "abstained": [r["field"] for r in comparison["rows"] if r["status"] == "abstained" and r["observable"]],
            })

    fields = []
    for field, counts in per_field.items():
        decided = counts["correct"] + counts["wrong"]
        total = decided + counts["abstained"]
        fields.append({
            "field": field, **counts,
            "accuracy": round(counts["correct"] / decided, 3) if decided else None,
            "coverage": round(decided / total, 3) if total else None,
        })
    decided_all = sum(f["correct"] + f["wrong"] for f in fields)
    correct_all = sum(f["correct"] for f in fields)
    result = {
        "scenarios_evaluated": n_scenarios,
        "seed": seed,
        "overall_accuracy": round(correct_all / decided_all, 3) if decided_all else None,
        "traffic_window_accuracy": round(window_hits / window_total, 3) if window_total else None,
        "traffic_window_accuracy_unsmoothed": round(raw_hits / window_total, 3) if window_total else None,
        "traffic_pure_window_accuracy": round(pure_hits / pure_total, 3) if pure_total else None,
        "pure_windows": pure_total,
        "impairment": impairment,
        "traffic_windows": window_total,
        "fields": fields,
        "scenarios": scenarios,
        "seconds": round(time.time() - started, 1),
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": ("Held-out captures from the synthetic testbed (unseen seeds). Validate on strongSwan captures "
                 "from backend/testbed/strongswan before quoting real-world accuracy."),
    }
    RESULT_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def latest() -> dict[str, Any] | None:
    if not RESULT_FILE.exists():
        return None
    return json.loads(RESULT_FILE.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", type=int, default=24)
    parser.add_argument("--seed", type=int, default=2024)
    parser.add_argument("--impairment", default="none", choices=["none", "light", "moderate", "heavy"])
    args = parser.parse_args()
    from backend.ml.model import classifier
    if not classifier.load():
        print("Training classifier first…")
        classifier.train()
    result = evaluate_end_to_end(args.scenarios, args.seed, args.impairment)
    print(f"Overall identification accuracy: {result['overall_accuracy']}  "
          f"traffic windows: {result['traffic_window_accuracy']} (unsmoothed {result['traffic_window_accuracy_unsmoothed']}, "
          f"single-application windows {result['traffic_pure_window_accuracy']}) "
          f"[{args.impairment}] ({result['seconds']} s)")
    for f in sorted(result["fields"], key=lambda x: x["field"]):
        print(f"  {f['field']:28s} acc={f['accuracy']}  coverage={f['coverage']}  "
              f"({f['correct']}✓ {f['wrong']}✗ {f['abstained']} abstained)")
    print(f"Saved to {Path(RESULT_FILE)}")


if __name__ == "__main__":
    main()
