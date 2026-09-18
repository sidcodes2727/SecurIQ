"""
Synthetic dataset generator for encrypted traffic classification.
Generates realistic flow features that mimic different traffic types
inside an IPsec ESP tunnel.

Each traffic type has characteristic packet size distributions,
timing patterns, and burst behaviors.
"""
from __future__ import annotations

import random
import math
import json
from pathlib import Path
from typing import Any

from backend.config import TRAFFIC_CLASSES, SYNTHETIC_SAMPLES_PER_CLASS, DATASET_DIR


# Traffic type profiles based on known traffic characteristics
# These model what the metadata (sizes, timing) would look like
# when different application traffic is encapsulated in ESP
TRAFFIC_PROFILES = {
    "icmp": {
        "description": "ICMP echo (ping) traffic - small, regular, symmetric",
        "packet_count": (10, 50),
        "size_mean": (98, 130),
        "size_std": (2, 10),
        "duration": (1, 10),
        "iat_mean": (0.5, 2.0),
        "iat_cv": (0.01, 0.1),
        "fwd_ratio": (0.45, 0.55),
        "burst_rate": (0.0, 0.2),
        "payload_mean": (60, 100),
    },
    "web": {
        "description": "HTTP/HTTPS traffic - variable sizes, bursty, asymmetric",
        "packet_count": (50, 500),
        "size_mean": (300, 800),
        "size_std": (200, 500),
        "duration": (0.5, 30),
        "iat_mean": (0.001, 0.05),
        "iat_cv": (0.5, 3.0),
        "fwd_ratio": (0.25, 0.45),
        "burst_rate": (1.0, 10.0),
        "payload_mean": (250, 700),
    },
    "voip": {
        "description": "VoIP/SIP traffic - small fixed-size, very regular (~20ms IAT)",
        "packet_count": (200, 3000),
        "size_mean": (160, 220),
        "size_std": (5, 20),
        "duration": (10, 120),
        "iat_mean": (0.018, 0.025),
        "iat_cv": (0.02, 0.15),
        "fwd_ratio": (0.45, 0.55),
        "burst_rate": (0.0, 0.5),
        "payload_mean": (120, 180),
    },
    "video": {
        "description": "Video streaming - large packets, sustained, slightly variable",
        "packet_count": (500, 5000),
        "size_mean": (900, 1400),
        "size_std": (100, 400),
        "duration": (10, 120),
        "iat_mean": (0.001, 0.01),
        "iat_cv": (0.2, 1.0),
        "fwd_ratio": (0.15, 0.35),
        "burst_rate": (2.0, 15.0),
        "payload_mean": (800, 1300),
    },
    "email": {
        "description": "Email (SMTP/IMAP) - medium packets, sparse, bursty transfers",
        "packet_count": (20, 200),
        "size_mean": (200, 600),
        "size_std": (100, 400),
        "duration": (1, 30),
        "iat_mean": (0.01, 0.5),
        "iat_cv": (0.5, 3.0),
        "fwd_ratio": (0.3, 0.6),
        "burst_rate": (0.5, 5.0),
        "payload_mean": (150, 500),
    },
    "chat": {
        "description": "Chat/IM traffic - very small packets, irregular timing",
        "packet_count": (20, 300),
        "size_mean": (80, 200),
        "size_std": (30, 100),
        "duration": (5, 120),
        "iat_mean": (0.5, 10.0),
        "iat_cv": (0.5, 2.5),
        "fwd_ratio": (0.4, 0.6),
        "burst_rate": (0.1, 2.0),
        "payload_mean": (40, 150),
    },
    "file_transfer": {
        "description": "FTP/SCP file transfer - large packets, sustained throughput",
        "packet_count": (100, 5000),
        "size_mean": (1200, 1500),
        "size_std": (50, 200),
        "duration": (2, 60),
        "iat_mean": (0.0001, 0.005),
        "iat_cv": (0.1, 0.5),
        "fwd_ratio": (0.1, 0.3),
        "burst_rate": (3.0, 20.0),
        "payload_mean": (1100, 1400),
    },
}


def _uniform(low: float, high: float) -> float:
    return random.uniform(low, high)


def _generate_sample(traffic_type: str) -> dict[str, Any]:
    """Generate a single synthetic flow feature sample for a given traffic type."""
    profile = TRAFFIC_PROFILES[traffic_type]
    
    # Core parameters from profile
    packet_count = int(_uniform(*profile["packet_count"]))
    size_mean = _uniform(*profile["size_mean"])
    size_std = _uniform(*profile["size_std"])
    duration = _uniform(*profile["duration"])
    iat_mean = _uniform(*profile["iat_mean"])
    iat_cv = _uniform(*profile["iat_cv"])
    fwd_ratio = _uniform(*profile["fwd_ratio"])
    burst_rate = _uniform(*profile["burst_rate"])
    payload_mean = _uniform(*profile["payload_mean"])
    
    # Derived features
    iat_std = iat_mean * iat_cv
    iat_min = max(0.00001, iat_mean - 2 * iat_std)
    iat_max = iat_mean + 2 * iat_std + random.uniform(0, iat_std)
    iat_median = iat_mean + random.gauss(0, iat_std * 0.1)
    
    size_min = max(40, size_mean - 2.5 * size_std + random.gauss(0, 5))
    size_max = size_mean + 2.5 * size_std + random.gauss(0, 10)
    size_median = size_mean + random.gauss(0, size_std * 0.2)
    size_q1 = size_mean - 0.675 * size_std + random.gauss(0, size_std * 0.1)
    size_q3 = size_mean + 0.675 * size_std + random.gauss(0, size_std * 0.1)
    size_iqr = size_q3 - size_q1
    
    payload_std = size_std * 0.9 + random.gauss(0, 5)
    
    packet_rate = packet_count / max(duration, 0.001)
    byte_rate = (packet_count * size_mean) / max(duration, 0.001)
    bits_per_second = byte_rate * 8
    
    bwd_ratio = 1.0 - fwd_ratio
    fwd_packet_count = int(packet_count * fwd_ratio)
    bwd_packet_count = packet_count - fwd_packet_count
    
    burst_count = max(0, int(burst_rate * duration + random.gauss(0, 1)))
    avg_burst_size = random.uniform(2, 10) if burst_count > 0 else 0
    
    # Size entropy - more variable traffic has higher entropy
    size_entropy = min(3.32, max(0, math.log2(max(1, len(set(range(int(size_std))))))))
    size_entropy = random.uniform(0.5, 3.0) if size_std > 50 else random.uniform(0, 1.5)
    
    # IAT regularity - inverse of CV
    iat_regularity = 1.0 / (1.0 + iat_cv)
    
    # Add noise to all features
    noise = lambda v, pct=0.05: v * (1 + random.gauss(0, pct))  # noqa: E731
    
    return {
        "packet_count": packet_count,
        "size_mean": noise(size_mean),
        "size_std": noise(max(1, size_std)),
        "size_min": noise(max(40, size_min)),
        "size_max": noise(size_max),
        "size_median": noise(size_median),
        "size_q1": noise(size_q1),
        "size_q3": noise(size_q3),
        "size_iqr": noise(max(0, size_iqr)),
        "payload_mean": noise(payload_mean),
        "payload_std": noise(max(1, payload_std)),
        "duration": noise(max(0.001, duration)),
        "iat_mean": noise(max(0.00001, iat_mean)),
        "iat_std": noise(max(0, iat_std)),
        "iat_min": noise(max(0, iat_min)),
        "iat_max": noise(max(0, iat_max)),
        "iat_median": noise(max(0, iat_median)),
        "iat_cv": noise(max(0, iat_cv)),
        "packet_rate": noise(max(0.1, packet_rate)),
        "byte_rate": noise(max(1, byte_rate)),
        "bits_per_second": noise(max(8, bits_per_second)),
        "fwd_ratio": max(0, min(1, noise(fwd_ratio, 0.02))),
        "bwd_ratio": max(0, min(1, noise(bwd_ratio, 0.02))),
        "fwd_packet_count": fwd_packet_count,
        "bwd_packet_count": bwd_packet_count,
        "burst_count": burst_count,
        "avg_burst_size": noise(avg_burst_size) if avg_burst_size > 0 else 0,
        "burst_rate": noise(max(0, burst_rate)),
        "size_entropy": noise(max(0, size_entropy)),
        "iat_regularity": max(0, min(1, noise(iat_regularity, 0.02))),
        "label": traffic_type,
    }


def generate_dataset(
    samples_per_class: int = SYNTHETIC_SAMPLES_PER_CLASS,
    output_dir: str | None = None,
    seed: int = 42,
) -> dict[str, Any]:
    """
    Generate a complete synthetic dataset for traffic classification.
    
    Returns dataset statistics and saves to disk.
    """
    random.seed(seed)
    
    if output_dir is None:
        output_dir = str(DATASET_DIR)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    all_samples = []
    class_counts = {}
    
    for traffic_type in TRAFFIC_CLASSES:
        class_samples = []
        for _ in range(samples_per_class):
            sample = _generate_sample(traffic_type)
            class_samples.append(sample)
        
        all_samples.extend(class_samples)
        class_counts[traffic_type] = len(class_samples)
    
    # Shuffle
    random.shuffle(all_samples)
    
    # Save dataset
    dataset_file = output_path / "synthetic_dataset.json"
    with open(dataset_file, "w") as f:
        json.dump({
            "metadata": {
                "total_samples": len(all_samples),
                "classes": TRAFFIC_CLASSES,
                "samples_per_class": samples_per_class,
                "seed": seed,
                "profiles": {k: v["description"] for k, v in TRAFFIC_PROFILES.items()},
            },
            "samples": all_samples,
        }, f, indent=2)
    
    return {
        "total_samples": len(all_samples),
        "classes": TRAFFIC_CLASSES,
        "samples_per_class": samples_per_class,
        "class_counts": class_counts,
        "output_file": str(dataset_file),
    }
