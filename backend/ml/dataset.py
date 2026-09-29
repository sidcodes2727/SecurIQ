"""
Training data for the encrypted-traffic classifier.

Each training flow is an application conversation from the testbed traffic
models, framed with a randomly chosen ESP cipher suite, mode and IP version,
and then passed through the *same* SA pairing, windowing and feature code that
analyses uploaded captures (backend.analyzers.flow_extractor). Training and
inference therefore see identically computed features.
"""
from __future__ import annotations

import csv
import random
from pathlib import Path
from typing import Any

from backend.analyzers.flow_extractor import FEATURE_NAMES, extract_from_esp_packets
from backend.testbed.esp_model import ESP_SUITES, TRAINING_SUITES, EspSuite, esp_payload_len, inner_packet_len
from backend.testbed.impairments import impair
from backend.testbed.scenarios import GATEWAYS
from backend.testbed.traffic_models import TRAFFIC_CLASSES, generate_traffic

# Flow duration ranges (seconds): long enough for 2–5 windows, bounded for high-rate classes.
TRAINING_DURATION = {
    "icmp": (25, 40), "web": (25, 45), "voip": (20, 35), "video": (18, 30),
    "email": (25, 45), "chat": (35, 60), "file_transfer": (12, 20),
}


def esp_records(events: list[tuple], suite: EspSuite, mode: str, ip_version: int,
                rng: random.Random, t0: float) -> list[dict[str, Any]]:
    """Frame an inner packet sequence as ESP packet records (the parser's output schema)."""
    gw_a, gw_b = GATEWAYS[ip_version]
    spis = (hex(rng.randint(0x1000_0000, 0xFFFF_FFFF)), hex(rng.randint(0x1000_0000, 0xFFFF_FFFF)))
    records = []
    for ts, direction, l4, _ in events:
        records.append({
            "timestamp": round(t0 + ts, 6),
            "spi": spis[direction],
            "src_ip": gw_a if direction == 0 else gw_b,
            "dst_ip": gw_b if direction == 0 else gw_a,
            "esp_payload_len": esp_payload_len(inner_packet_len(l4, mode, ip_version), suite),
            "protocol_type": "esp",
        })
    return records


AUGMENT_LEVELS = ["none", "light", "light", "moderate", "moderate"]  # mixture used for training


def generate_training_windows(flows_per_class: int = 60, seed: int = 7,
                              impairment: str = "augment") -> list[dict[str, Any]]:
    """
    impairment: "augment" draws a per-flow level from AUGMENT_LEVELS; any key of
    backend.testbed.impairments.PROFILES applies that level to every flow (e.g. "heavy" for a stress set).
    """
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    for cls in TRAFFIC_CLASSES:
        for i in range(flows_per_class):
            suite = ESP_SUITES[rng.choice(TRAINING_SUITES)]
            mode = "transport" if rng.random() < 0.3 else "tunnel"
            ip_version = 6 if rng.random() < 0.3 else 4
            duration = rng.uniform(*TRAINING_DURATION[cls])
            level = rng.choice(AUGMENT_LEVELS) if impairment == "augment" else impairment
            events = impair(generate_traffic(cls, duration, rng), duration, rng, level)
            # random grid phase: flows do not start on a window boundary in real captures
            records = esp_records(events, suite, mode, ip_version, rng, t0=1_000.0 * (i + 1) + rng.uniform(0, 10))
            for window in extract_from_esp_packets(records):
                row = {name: window[name] for name in FEATURE_NAMES}
                row.update(label=cls, group=f"{cls}-{i:04d}", suite=suite.key, suite_family=suite.family,
                           mode=mode, ip_version=ip_version, packets=window["packet_count"], impairment=level)
                rows.append(row)
    return rows


def save_rows(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
