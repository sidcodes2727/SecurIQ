"""
Flow feature extractor for ML traffic classification.
Extracts statistical features from ESP packet flows grouped by SPI.
"""
import math
from typing import Any
from collections import defaultdict


def extract_flow_features(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract ML-ready features from ESP packet flows.
    
    Groups packets by SPI and computes statistical features per flow.
    Returns a list of feature dictionaries, one per flow.
    """
    packets = parsed_data.get("packets", [])
    esp_packets = [p for p in packets if p.get("protocol_type") == "esp"]
    
    if not esp_packets:
        return []
    
    # Group packets by SPI
    spi_flows = defaultdict(list)
    for p in esp_packets:
        spi = p.get("spi", "unknown")
        spi_flows[spi].append(p)
    
    features_list = []
    for spi, flow_packets in spi_flows.items():
        if len(flow_packets) < 3:
            continue  # Need minimum packets for meaningful features
        
        features = _compute_flow_features(flow_packets, spi)
        features_list.append(features)
    
    return features_list


def _compute_flow_features(packets: list[dict], spi: str) -> dict[str, Any]:
    """Compute comprehensive feature vector for a single flow."""
    # Sort by timestamp
    packets = sorted(packets, key=lambda p: p.get("timestamp", 0))
    
    # Basic packet size statistics
    sizes = [p.get("length", 0) for p in packets]
    payload_sizes = [p.get("esp_payload_len", 0) for p in packets if p.get("esp_payload_len", 0) > 0]
    if not payload_sizes:
        payload_sizes = sizes
    
    # Timestamps
    timestamps = [p.get("timestamp", 0) for p in packets]
    
    # Inter-arrival times (IAT)
    iats = []
    for i in range(1, len(timestamps)):
        iat = timestamps[i] - timestamps[i-1]
        if iat >= 0:
            iats.append(iat)
    
    # Flow duration
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.001
    if duration <= 0:
        duration = 0.001
    
    # Direction analysis (heuristic: based on IP pair)
    directions = _analyze_directions(packets)
    
    # Burst detection
    bursts = _detect_bursts(iats, threshold_factor=3.0)
    
    features = {
        "spi": spi,
        # Packet count
        "packet_count": len(packets),
        # Size statistics
        "size_mean": _mean(sizes),
        "size_std": _std(sizes),
        "size_min": min(sizes) if sizes else 0,
        "size_max": max(sizes) if sizes else 0,
        "size_median": _median(sizes),
        "size_q1": _percentile(sizes, 25),
        "size_q3": _percentile(sizes, 75),
        "size_iqr": _percentile(sizes, 75) - _percentile(sizes, 25),
        "payload_mean": _mean(payload_sizes),
        "payload_std": _std(payload_sizes),
        # Timing statistics
        "duration": duration,
        "iat_mean": _mean(iats) if iats else 0,
        "iat_std": _std(iats) if iats else 0,
        "iat_min": min(iats) if iats else 0,
        "iat_max": max(iats) if iats else 0,
        "iat_median": _median(iats) if iats else 0,
        "iat_cv": (_std(iats) / _mean(iats)) if iats and _mean(iats) > 0 else 0,
        # Rate statistics
        "packet_rate": len(packets) / duration,
        "byte_rate": sum(sizes) / duration,
        "bits_per_second": (sum(sizes) * 8) / duration,
        # Direction
        "fwd_ratio": directions["fwd_ratio"],
        "bwd_ratio": directions["bwd_ratio"],
        "fwd_packet_count": directions["fwd_count"],
        "bwd_packet_count": directions["bwd_count"],
        # Burst features
        "burst_count": bursts["count"],
        "avg_burst_size": bursts["avg_size"],
        "burst_rate": bursts["count"] / duration if duration > 0 else 0,
        # Entropy-like features
        "size_entropy": _entropy(sizes),
        "iat_regularity": 1.0 / (1.0 + (_std(iats) / _mean(iats) if iats and _mean(iats) > 0 else 1.0)),
    }
    
    return features


def _analyze_directions(packets: list[dict]) -> dict[str, Any]:
    """Analyze packet directions based on IP pairs."""
    if not packets:
        return {"fwd_ratio": 0.5, "bwd_ratio": 0.5, "fwd_count": 0, "bwd_count": 0}
    
    # Use first packet's source as "forward" direction
    first_src = packets[0].get("src_ip", "")
    fwd = sum(1 for p in packets if p.get("src_ip") == first_src)
    bwd = len(packets) - fwd
    total = len(packets)
    
    return {
        "fwd_ratio": fwd / total if total > 0 else 0.5,
        "bwd_ratio": bwd / total if total > 0 else 0.5,
        "fwd_count": fwd,
        "bwd_count": bwd,
    }


def _detect_bursts(iats: list[float], threshold_factor: float = 3.0) -> dict[str, Any]:
    """
    Detect bursts in traffic based on inter-arrival time patterns.
    A burst is a sequence of packets with IAT significantly below average.
    """
    if not iats or len(iats) < 2:
        return {"count": 0, "avg_size": 0, "sizes": []}
    
    avg_iat = _mean(iats)
    threshold = avg_iat / threshold_factor if avg_iat > 0 else 0.001
    
    bursts = []
    current_burst = 0
    
    for iat in iats:
        if iat < threshold:
            current_burst += 1
        else:
            if current_burst > 1:
                bursts.append(current_burst)
            current_burst = 0
    
    if current_burst > 1:
        bursts.append(current_burst)
    
    return {
        "count": len(bursts),
        "avg_size": _mean(bursts) if bursts else 0,
        "sizes": bursts,
    }


# --- Statistical helpers ---

def _mean(values: list) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def _median(values: list) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 0:
        return (s[n//2 - 1] + s[n//2]) / 2
    return s[n//2]


def _percentile(values: list, p: int) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = f + 1
    if c >= len(s):
        return s[f]
    return s[f] + (k - f) * (s[c] - s[f])


def _entropy(values: list) -> float:
    """Shannon entropy of value distribution (binned)."""
    if not values or len(values) < 2:
        return 0.0
    
    # Bin into 10 bins
    min_v = min(values)
    max_v = max(values)
    if min_v == max_v:
        return 0.0
    
    n_bins = min(10, len(set(values)))
    bin_width = (max_v - min_v) / n_bins
    
    bins = [0] * n_bins
    for v in values:
        idx = min(int((v - min_v) / bin_width), n_bins - 1)
        bins[idx] += 1
    
    total = sum(bins)
    entropy = 0.0
    for count in bins:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return round(entropy, 4)


# Feature names used by the ML model (order matters)
FEATURE_NAMES = [
    "packet_count", "size_mean", "size_std", "size_min", "size_max",
    "size_median", "size_q1", "size_q3", "size_iqr",
    "payload_mean", "payload_std",
    "duration", "iat_mean", "iat_std", "iat_min", "iat_max",
    "iat_median", "iat_cv",
    "packet_rate", "byte_rate", "bits_per_second",
    "fwd_ratio", "bwd_ratio", "fwd_packet_count", "bwd_packet_count",
    "burst_count", "avg_burst_size", "burst_rate",
    "size_entropy", "iat_regularity",
]


def features_to_vector(features: dict) -> list[float]:
    """Convert a feature dict to a numeric vector in the correct order."""
    return [float(features.get(name, 0)) for name in FEATURE_NAMES]
