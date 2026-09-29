"""
Flow feature extraction for encrypted-traffic classification.

ESP Security Associations are unidirectional, so a single SPI only ever sees one
direction of a conversation. We therefore:

1. group ESP packets by SPI into SAs,
2. pair each SA with the reverse-direction SA between the same peers that overlaps
   it most in time (one *tunnel*),
3. cut each tunnel into fixed time windows, and
4. compute direction-agnostic size/timing features per window.

Direction is canonicalised to "down" = the direction carrying more bytes in the window,
so features do not depend on which peer initiated the tunnel.

The exact same code path is used for training data (see backend/ml/dataset.py) and for
inference on uploaded captures, which removes train/inference skew.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np

WINDOW_SECONDS = 10.0
MIN_WINDOW_PACKETS = 8
BURST_GAP = 0.01          # packets closer than 10 ms belong to the same burst
IDLE_GAP = 1.0
PAIRING_TOLERANCE = 5.0   # reverse SA may start up to 5 s after the forward SA ends
SIZE_BINS = np.arange(0, 1601, 100)

FEATURE_NAMES = [
    # volume
    "pkt_rate", "byte_rate",
    # size (ESP payload length)
    "size_mean", "size_std", "size_min", "size_max", "size_q10", "size_q25",
    "size_median", "size_q75", "size_q90",
    "frac_small", "frac_large", "size_entropy", "distinct_size_ratio",
    # timing
    "iat_mean", "iat_std", "iat_cv", "iat_median", "iat_q90",
    "frac_iat_under_2ms", "iat_regularity", "idle_frac",
    # direction (canonical: down = heavier direction)
    "down_pkt_frac", "down_byte_frac", "down_size_mean", "up_size_mean",
    "down_iat_cv", "up_iat_cv",
    # bursts
    "burst_rate", "burst_len_mean", "burst_bytes_max",
    # noise-robust structure (stable when other small flows share the SA)
    "size_mode_share", "mode_iat_cv", "mode_iat_median", "byte_frac_large", "mid_frac", "large_iat_median",
]


# ---------------------------------------------------------------- SA pairing

def group_security_associations(esp_packets: list[dict]) -> dict[str, dict[str, Any]]:
    """Group ESP packets by SPI (+ direction, since SPIs are chosen per receiver)."""
    sas: dict[str, dict[str, Any]] = {}
    for p in esp_packets:
        spi = p.get("spi")
        if spi is None:
            continue
        key = f"{spi}|{p.get('src_ip')}>{p.get('dst_ip')}"
        sa = sas.get(key)
        if sa is None:
            sa = sas[key] = {
                "key": key, "spi": spi, "src": p.get("src_ip"), "dst": p.get("dst_ip"),
                "packets": [], "first_seen": p["timestamp"], "last_seen": p["timestamp"],
            }
        sa["packets"].append(p)
        sa["first_seen"] = min(sa["first_seen"], p["timestamp"])
        sa["last_seen"] = max(sa["last_seen"], p["timestamp"])
    return sas


def build_tunnels(esp_packets: list[dict]) -> list[dict[str, Any]]:
    """Pair unidirectional SAs into bidirectional tunnels (greedy by time overlap)."""
    sas = group_security_associations(esp_packets)
    unpaired = sorted(sas.values(), key=lambda s: s["first_seen"])
    used: set[str] = set()
    tunnels = []

    for sa in unpaired:
        if sa["key"] in used:
            continue
        used.add(sa["key"])
        best, best_overlap = None, -PAIRING_TOLERANCE
        for other in unpaired:
            if other["key"] in used or other["src"] != sa["dst"] or other["dst"] != sa["src"]:
                continue
            overlap = min(sa["last_seen"], other["last_seen"]) - max(sa["first_seen"], other["first_seen"])
            if overlap > best_overlap:
                best, best_overlap = other, overlap
        if best is not None:
            used.add(best["key"])

        entries = [(p, 0) for p in sa["packets"]]
        if best is not None:
            entries.extend((p, 1) for p in best["packets"])
        entries.sort(key=lambda e: e[0]["timestamp"])

        tunnels.append({
            # canonical id: independent of which direction happened to be seen first (live slices vs batch)
            "id": "/".join(sorted((sa["spi"], best["spi"]))) if best else sa["spi"],
            "spi_a": sa["spi"],
            "spi_b": best["spi"] if best else None,
            "peer_a": sa["src"],
            "peer_b": sa["dst"],
            "bidirectional": best is not None,
            "packets": [p for p, _ in entries],
            "dirs": [d for _, d in entries],
            "first_seen": entries[0][0]["timestamp"],
            "last_seen": entries[-1][0]["timestamp"],
        })
    return tunnels


# ---------------------------------------------------------------- windows + features

def extract_flow_features(parsed_data: dict[str, Any],
                          window_seconds: float = WINDOW_SECONDS) -> list[dict[str, Any]]:
    """Return one feature dict per (tunnel, time window) with ≥ MIN_WINDOW_PACKETS packets."""
    esp_packets = [p for p in parsed_data.get("packets", [])
                   if p.get("protocol_type") == "esp" and p.get("esp_payload_len")]
    return extract_from_esp_packets(esp_packets, window_seconds)


def extract_from_esp_packets(esp_packets: list[dict],
                             window_seconds: float = WINDOW_SECONDS) -> list[dict[str, Any]]:
    windows = []
    for tunnel in build_tunnels(esp_packets):
        packets, dirs = tunnel["packets"], tunnel["dirs"]
        # Windows sit on an absolute time grid, so a live stream that only holds the last few
        # seconds cuts exactly the same windows as the batch analysis of the whole capture.
        buckets: dict[int, list[int]] = defaultdict(list)
        for i, p in enumerate(packets):
            buckets[int(p["timestamp"] // window_seconds)].append(i)
        for idx in sorted(buckets):
            chunk = buckets[idx]
            if len(chunk) < MIN_WINDOW_PACKETS:
                continue
            feats = compute_window_features(
                np.array([packets[i]["timestamp"] for i in chunk], dtype=float),
                np.array([packets[i]["esp_payload_len"] for i in chunk], dtype=float),
                np.array([dirs[i] for i in chunk], dtype=int),
                window_seconds,
            )
            feats.update({
                "flow_id": tunnel["id"],
                "spi": tunnel["id"],
                "peer_a": tunnel["peer_a"],
                "peer_b": tunnel["peer_b"],
                "window_index": idx,
                "window_start": round(idx * window_seconds, 6),
                "window_end": round((idx + 1) * window_seconds, 6),
                "packet_count": len(chunk),
            })
            windows.append(feats)
    return windows


def compute_window_features(ts: np.ndarray, sizes: np.ndarray, dirs: np.ndarray,
                            window_seconds: float = WINDOW_SECONDS) -> dict[str, float]:
    """Direction-agnostic statistics over one window. Inputs must be time-sorted."""
    n = len(ts)
    span = max(float(ts[-1] - ts[0]), 1e-3)
    duration = min(window_seconds, max(span, 1e-3))

    iats = np.diff(ts) if n > 1 else np.array([0.0])
    iat_mean = float(iats.mean())
    iat_median = float(np.median(iats))

    # canonical direction: the one carrying more bytes is "down"
    bytes0 = float(sizes[dirs == 0].sum())
    bytes1 = float(sizes[dirs == 1].sum())
    down = 0 if bytes0 >= bytes1 else 1
    down_mask = dirs == down
    up_mask = ~down_mask

    bursts = _bursts(iats, sizes)
    hist, _ = np.histogram(np.clip(sizes, 0, 1599), bins=SIZE_BINS)
    modal = _modal_structure(ts, sizes, dirs)
    large = sizes > 1000
    large_iats = np.diff(ts[large]) if large.sum() > 2 else np.array([])

    return {
        "size_mode_share": modal["share"],
        "mode_iat_cv": modal["iat_cv"],
        "mode_iat_median": modal["iat_median"],
        "byte_frac_large": float(sizes[large].sum() / max(sizes.sum(), 1.0)),
        "mid_frac": float(((sizes >= 150) & (sizes <= 1000)).mean()),
        "large_iat_median": float(np.median(large_iats)) if len(large_iats) else 0.0,
        "pkt_rate": n / duration,
        "byte_rate": float(sizes.sum()) / duration,
        "size_mean": float(sizes.mean()),
        "size_std": float(sizes.std()),
        "size_min": float(sizes.min()),
        "size_max": float(sizes.max()),
        "size_q10": float(np.percentile(sizes, 10)),
        "size_q25": float(np.percentile(sizes, 25)),
        "size_median": float(np.median(sizes)),
        "size_q75": float(np.percentile(sizes, 75)),
        "size_q90": float(np.percentile(sizes, 90)),
        "frac_small": float((sizes < 150).mean()),
        "frac_large": float((sizes > 1000).mean()),
        "size_entropy": _entropy(hist),
        "distinct_size_ratio": len(np.unique(sizes)) / n,
        "iat_mean": iat_mean,
        "iat_std": float(iats.std()),
        "iat_cv": float(iats.std() / iat_mean) if iat_mean > 0 else 0.0,
        "iat_median": iat_median,
        "iat_q90": float(np.percentile(iats, 90)),
        "frac_iat_under_2ms": float((iats < 0.002).mean()),
        "iat_regularity": float((np.abs(iats - iat_median) <= 0.2 * iat_median).mean()) if iat_median > 0 else 0.0,
        "idle_frac": float(iats[iats > IDLE_GAP].sum() / duration),
        "down_pkt_frac": float(down_mask.mean()),
        "down_byte_frac": max(bytes0, bytes1) / max(bytes0 + bytes1, 1.0),
        "down_size_mean": float(sizes[down_mask].mean()) if down_mask.any() else 0.0,
        "up_size_mean": float(sizes[up_mask].mean()) if up_mask.any() else 0.0,
        "down_iat_cv": _cv(np.diff(ts[down_mask])),
        "up_iat_cv": _cv(np.diff(ts[up_mask])),
        "burst_rate": bursts["count"] / duration,
        "burst_len_mean": bursts["len_mean"],
        "burst_bytes_max": bursts["bytes_max"],
    }


def features_to_vector(features: dict) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


# ---------------------------------------------------------------- helpers

def _bursts(iats: np.ndarray, sizes: np.ndarray) -> dict[str, float]:
    """A burst is a run of ≥3 packets separated by < BURST_GAP."""
    lengths, byte_totals = [], []
    run_len, run_bytes = 1, float(sizes[0])
    for gap, size in zip(iats, sizes[1:]):
        if gap < BURST_GAP:
            run_len += 1
            run_bytes += float(size)
        else:
            if run_len >= 3:
                lengths.append(run_len)
                byte_totals.append(run_bytes)
            run_len, run_bytes = 1, float(size)
    if run_len >= 3:
        lengths.append(run_len)
        byte_totals.append(run_bytes)
    return {
        "count": len(lengths),
        "len_mean": float(np.mean(lengths)) if lengths else 0.0,
        "bytes_max": float(max(byte_totals)) if byte_totals else 0.0,
    }


def _modal_structure(ts: np.ndarray, sizes: np.ndarray, dirs: np.ndarray) -> dict[str, float]:
    """Share and timing regularity of the most common packet size (16-byte bins), in its busiest direction.

    Constant-size media (RTP, ping) keeps a regular cadence here even when unrelated small flows
    are multiplexed into the same SA and disturb the overall IAT statistics.
    """
    bins = (sizes // 16).astype(int)
    values, counts = np.unique(bins, return_counts=True)
    mode_bin = values[np.argmax(counts)]
    in_mode = bins == mode_bin
    share = float(in_mode.mean())
    direction = 0 if (in_mode & (dirs == 0)).sum() >= (in_mode & (dirs == 1)).sum() else 1
    mode_ts = ts[in_mode & (dirs == direction)]
    if len(mode_ts) < 3:
        return {"share": share, "iat_cv": 0.0, "iat_median": 0.0}
    iats = np.diff(mode_ts)
    return {"share": share, "iat_cv": _cv(iats), "iat_median": float(np.median(iats))}


def _cv(values: np.ndarray) -> float:
    if len(values) < 2:
        return 0.0
    mean = float(values.mean())
    return float(values.std() / mean) if mean > 0 else 0.0


def _entropy(hist: np.ndarray) -> float:
    total = hist.sum()
    if total == 0:
        return 0.0
    p = hist[hist > 0] / total
    return float(-(p * np.log2(p)).sum())
