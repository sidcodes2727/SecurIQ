"""
Build a labelled IPsec capture dataset from the configuration matrix.

Output directory layout:
    pcaps/<scenario>.pcap     one capture per scenario
    manifest.jsonl            ground truth per capture (configuration + traffic segments)
    windows.csv               per-window features extracted *from the PCAPs*, labelled from ground truth

    python -m backend.testbed.build_dataset --count 50 --seed 1 --out backend/data/datasets/testbed
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import time
from pathlib import Path
from typing import Any

from backend.analyzers.flow_extractor import FEATURE_NAMES, extract_flow_features
from backend.analyzers.pcap_parser import parse_pcap
from backend.testbed.scenarios import random_scenario, write_scenario


def build_dataset(out_dir: str | Path, count: int = 50, seed: int = 1) -> dict[str, Any]:
    started = time.time()
    out = Path(out_dir)
    pcaps = out / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    windows_written = 0
    label_counts: dict[str, int] = {}

    with open(out / "manifest.jsonl", "w", encoding="utf-8") as manifest, \
            open(out / "windows.csv", "w", newline="", encoding="utf-8") as table:
        writer = csv.DictWriter(table, fieldnames=["scenario", "flow_id", "window_start", "label", *FEATURE_NAMES])
        writer.writeheader()
        for i in range(count):
            scenario = random_scenario(rng, i)
            path, truth = write_scenario(scenario, pcaps)
            manifest.write(json.dumps(truth) + "\n")
            for window in extract_flow_features(parse_pcap(str(path))):
                mid = (window["window_start"] + window["window_end"]) / 2
                segment = next((s for s in truth["traffic_segments"] if s["start"] <= mid <= s["end"]), None)
                if segment is None:
                    continue  # window straddles two applications — no single label
                label = segment["class"]
                label_counts[label] = label_counts.get(label, 0) + 1
                writer.writerow({"scenario": scenario.name, "flow_id": window["flow_id"],
                                 "window_start": window["window_start"], "label": label,
                                 **{f: round(window[f], 6) for f in FEATURE_NAMES}})
                windows_written += 1

    summary = {
        "directory": str(out),
        "captures": count,
        "windows": windows_written,
        "windows_per_class": dict(sorted(label_counts.items())),
        "seed": seed,
        "seconds": round(time.time() - started, 1),
        "files": ["pcaps/", "manifest.jsonl", "windows.csv"],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "data" / "datasets" / "testbed"))
    args = parser.parse_args()
    summary = build_dataset(args.out, args.count, args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
