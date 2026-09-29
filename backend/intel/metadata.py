"""
Metadata leakage: encryption hides the payload, not the conversation.

Scores two things separately:
  confidentiality   — can an observer read the payload? (cipher present and strong)
  metadata privacy  — what can an observer still learn? (who, when, how much, what kind of activity)
Each exposure dimension is shown with the evidence behind it, so "50% metadata privacy" is explainable.
"""
from __future__ import annotations

from typing import Any

from backend.config import TRAFFIC_CLASS_LABELS

# weight of each dimension in the metadata-privacy score (sums to 100)
WEIGHTS = {
    "endpoints": 10, "inner_addressing": 14, "packet_sizes": 14, "timing": 10, "activity": 20,
    "volume": 6, "identity": 14, "implementation": 6, "topology": 3, "trust": 3,
}


def _dim(key: str, label: str, exposed: float | None, detail: str, source: str = "observed") -> dict[str, Any]:
    return {"key": key, "label": label, "exposed": exposed, "weight": WEIGHTS[key], "detail": detail, "source": source}


def metadata_leakage(analysis: dict[str, Any], traffic: dict[str, Any], security: dict[str, Any]) -> dict[str, Any]:
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    ah = analysis.get("ah_analysis") or {}
    profile = analysis.get("profile") or {}
    mode = (profile.get("mode") or {}).get("value")
    null = bool((esp.get("null_encryption") or {}).get("suspected"))
    ah_only = bool(ah.get("detected")) and not esp.get("detected")
    cleartext_payload = null or ah_only

    tunnels = esp.get("tunnels") or []
    peers = sorted({ip for t in tunnels for ip in (t["peer_a"], t["peer_b"])}) or \
        sorted({ip for s in ike.get("sessions") or [] for ip in (s["initiator_ip"], s["responder_ip"])})
    dims = [_dim("endpoints", "Tunnel endpoints", 1.0,
                 f"Outer headers name the gateways: {', '.join(peers[:4]) or 'n/a'}")]

    if cleartext_payload:
        dims.append(_dim("inner_addressing", "Inner addresses & ports", 1.0,
                         "Inner IP/transport headers travel unencrypted (ESP-NULL / AH)"))
    elif mode == "Transport":
        dims.append(_dim("inner_addressing", "True communicating hosts", 1.0,
                         "Transport mode: the outer addresses are the hosts themselves", (profile.get("mode") or {}).get("source", "inferred")))
    elif mode == "Tunnel":
        dims.append(_dim("inner_addressing", "Inner addresses & ports", 0.0,
                         "Tunnel mode encrypts the inner IP header: internal hosts and ports are hidden", (profile.get("mode") or {}).get("source", "inferred")))
    else:
        dims.append(_dim("inner_addressing", "Inner addresses & ports", None,
                         "Mode not observable, so exposure of inner addressing is unknown", "not_observable"))

    lengths_spread = [sa["max_payload_size"] - sa["min_payload_size"] for sa in esp.get("sa_info") or []
                      if sa["packet_count"] >= 30]
    padded = bool(lengths_spread) and max(lengths_spread) <= 16
    if esp.get("detected"):
        dims.append(_dim("packet_sizes", "Packet sizes", 0.2 if padded else 1.0,
                         "ESP lengths are near-constant (TFC padding or constant-size traffic)" if padded else
                         f"ESP lengths track the inner packets ({(esp.get('fingerprint') or {}).get('distinct_lengths', '?')} distinct sizes); "
                         "no TFC padding observed"))
        dims.append(_dim("timing", "Packet timing", 1.0, "Inter-arrival times pass through the tunnel unchanged"))
    conf = traffic.get("mean_confidence")
    if traffic.get("windows"):
        mix = ", ".join(f"{TRAFFIC_CLASS_LABELS.get(c, c)} {v:.0%}" for c, v in list((traffic.get("mix") or {}).items())[:3])
        dims.append(_dim("activity", "Application activity", round(min(1.0, max(0.0, (conf - 0.3) / 0.6)), 2),
                         f"The classifier recognises the traffic with {conf:.0%} mean confidence ({mix})", "inferred"))
    total_bytes = sum(t.get("bytes", 0) for t in tunnels)
    duration = analysis.get("capture_duration") or 0
    dims.append(_dim("volume", "Volume & session duration", 1.0,
                     f"{total_bytes / 1e6:.1f} MB over {duration:.0f} s in {len(tunnels)} tunnel(s); rekeys mark session boundaries"))
    identities = ike.get("identities") or []
    if ike.get("detected"):
        dims.append(_dim("identity", "Peer identities", 1.0 if identities else 0.0,
                         f"Cleartext ID payloads: {', '.join(i['value'] for i in identities[:3])}" if identities
                         else "Identities are exchanged inside encrypted messages"))
        products = [v["name"] for v in ike.get("vendor_ids") or [] if v.get("reveals_implementation")]
        dims.append(_dim("implementation", "VPN product", 1.0 if products else 0.0,
                         f"Vendor IDs reveal {', '.join(products)}" if products else "No product-identifying Vendor IDs"))
        dims.append(_dim("trust", "Trusted CA", 1.0 if ike.get("certreq_seen") else 0.0,
                         "CERTREQ carries CA key hashes in cleartext" if ike.get("certreq_seen") else "No CERTREQ sent"))
    nat = (profile.get("nat_traversal") or {}).get("value")
    dims.append(_dim("topology", "Network topology", 1.0 if nat else 0.0,
                     "UDP 4500 encapsulation reveals a NAT between the peers" if nat else "No NAT signal"))

    known = [d for d in dims if d["exposed"] is not None]
    weight = sum(d["weight"] for d in known)
    leaked = sum(d["weight"] * d["exposed"] for d in known)
    privacy = round(100 * (1 - leaked / weight), 1) if weight else None

    crypto = (security.get("categories") or {}).get("cryptographic_strength") or {}
    confidentiality = 0.0 if cleartext_payload else crypto.get("score")

    statements = []
    if cleartext_payload:
        statements.append("An observer can read the payload: this SA provides integrity only.")
    for flow in (traffic.get("flows") or [])[:4]:
        statements.append(f"An observer cannot read tunnel {flow['flow_id'][:21]}, but can infer that it resembles "
                          f"{flow['dominant_label']} ({flow['mean_confidence']:.0%} confidence) over {flow['windows'] * 10} s.")
    if identities:
        statements.append(f"The peer identity {identities[0]['value']} is visible to anyone on the path.")
    if not statements:
        statements.append("An observer sees the gateways and traffic volume, but no application pattern was recognisable.")

    return {
        "confidentiality": confidentiality,
        "metadata_privacy": privacy,
        "dimensions": dims,
        "statements": statements,
        "observer_sees": [d["label"] for d in dims if d["exposed"] and d["exposed"] >= 0.5],
        "observer_cannot_see": (["Payload content"] if not cleartext_payload else []) +
                               [d["label"] for d in dims if d["exposed"] is not None and d["exposed"] < 0.5],
        "method": "Weighted exposure of 10 metadata dimensions; activity exposure scales with classifier confidence",
    }
