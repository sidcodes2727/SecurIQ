"""
Configuration fingerprint and drift detection.

The fingerprint is a hash over the *configuration* the analyzer identified (not over traffic), so two
captures of the same VPN produce the same fingerprint and any change in algorithms, DH group, PFS,
mode or authentication changes it. Drift compares two captures component by component and says
whether each change strengthened or weakened the deployment.
"""
from __future__ import annotations

import hashlib
from typing import Any

from backend.security.strength import dh_bits, encryption_bits, hash_bits

COMPONENTS = [
    ("ike_version", "IKE version"), ("exchange_mode", "Exchange mode"), ("ike_encryption", "IKE encryption"),
    ("ike_integrity", "IKE integrity"), ("ike_prf", "PRF"), ("dh_group", "DH group"),
    ("esp_encryption", "ESP encryption"), ("esp_integrity", "ESP integrity"), ("pfs", "PFS"),
    ("mode", "Mode"), ("ip_version", "IP version"), ("nat_traversal", "NAT-T"), ("auth", "Authentication"),
]


def _auth_class(value: str | None) -> str | None:
    if not value:
        return None
    if "Pre-Shared" in value:
        return "PSK"
    if "EAP" in value:
        return "EAP"
    if "Certificate" in value or "Signature" in value or "RSA" in value or "ECDSA" in value:
        return "Certificate"
    return value


def config_components(analysis: dict[str, Any]) -> dict[str, Any]:
    profile = analysis.get("profile") or {}
    chosen = (analysis.get("ike_analysis") or {}).get("chosen_suite") or {}

    def v(key: str):
        return (profile.get(key) or {}).get("value")

    return {
        "ike_version": v("ike_version"),
        "exchange_mode": v("exchange_mode"),
        "ike_encryption": v("ike_encryption"),
        "ike_integrity": v("ike_integrity") or ("AEAD" if v("ike_encryption") and "GCM" in v("ike_encryption") else None),
        "ike_prf": v("ike_prf"),
        "dh_group": chosen.get("dh_group"),
        "esp_encryption": v("esp_encryption"),
        "esp_integrity": v("esp_integrity"),
        "pfs": v("pfs"),
        "mode": v("mode"),
        "ip_version": v("ip_version"),
        "nat_traversal": v("nat_traversal"),
        "auth": _auth_class(v("authentication_method")),
    }


def _short(value: Any) -> str:
    if value is None:
        return "?"
    if value is True:
        return "ON"
    if value is False:
        return "OFF"
    return str(value)


def _integrity_short(name: str | None) -> str:
    """HMAC-SHA2-256-128 → SHA2-256, HMAC-SHA1-96 → SHA1."""
    if not name:
        return "?"
    for token in ("SHA2-512", "SHA2-384", "SHA2-256", "SHA1", "MD5", "AEAD", "XCBC", "CMAC"):
        if token in name.upper():
            return token
    return name


def config_fingerprint(analysis: dict[str, Any]) -> dict[str, Any]:
    comps = config_components(analysis)
    canonical = "|".join(f"{k}={_short(comps[k])}" for k, _ in COMPONENTS)
    digest = hashlib.sha256(canonical.encode()).hexdigest().upper()
    observed = sum(1 for k, _ in COMPONENTS if comps[k] is not None)
    ike = analysis.get("ike_analysis") or {}
    tunnels = (analysis.get("esp_analysis") or {}).get("tunnels") or []
    endpoints = sorted({ip for s in ike.get("sessions") or [] for ip in (s["initiator_ip"], s["responder_ip"])}) or \
        sorted({ip for t in tunnels for ip in (t["peer_a"], t["peer_b"])})
    label = " / ".join(x for x in [
        comps["ike_version"] or "IKE?",
        comps["ike_encryption"] or "?",
        _integrity_short(comps["ike_integrity"]),
        f"DH{comps['dh_group']}" if comps["dh_group"] else "DH?",
        f"PFS-{_short(comps['pfs'])}",
        comps["mode"] or "mode?",
        comps["ip_version"] or "IP?",
    ])
    return {
        "id": f"{digest[:4]}-{digest[4:8]}-{digest[8:12]}",
        "sha256": digest.lower(),
        "label": label,
        "canonical": canonical,
        "components": [{"key": k, "label": lbl, "value": comps[k]} for k, lbl in COMPONENTS],
        "observed_components": observed,
        "total_components": len(COMPONENTS),
        "endpoints": endpoints[:4],
    }


# ---------------------------------------------------------------- drift

def _cipher_rank(name: str | None) -> float | None:
    bits, _ = encryption_bits(name)
    if bits is None:
        return None
    aead = any(t in (name or "").upper() for t in ("GCM", "CCM", "CHACHA", "AEAD"))
    return bits + (8 if aead else 0)


def _integrity_rank(name: str | None) -> float | None:
    if not name:
        return None
    if "AEAD" in name.upper() or "INTEGRATED" in name.upper():
        return 130
    return hash_bits(name)


RANKERS = {
    "ike_version": lambda v: {"IKEv2": 2, "IKEv1": 1}.get(v),
    "exchange_mode": lambda v: {"IKEv2": 3, "Main Mode": 2, "Aggressive Mode": 1}.get(v),
    "ike_encryption": _cipher_rank,
    "esp_encryption": _cipher_rank,
    "ike_integrity": _integrity_rank,
    "esp_integrity": _integrity_rank,
    "ike_prf": hash_bits,
    "dh_group": dh_bits,
    "pfs": lambda v: None if v is None else int(bool(v)),
    "auth": lambda v: {"Certificate": 3, "EAP": 3, "PSK": 1}.get(v),
}


def drift(base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Compare two stored analysis records (base = earlier / reference)."""
    fb = base.get("intel", {}).get("fingerprint") or config_fingerprint(base["ipsec_analysis"])
    ft = target.get("intel", {}).get("fingerprint") or config_fingerprint(target["ipsec_analysis"])
    vb = {c["key"]: c["value"] for c in fb["components"]}
    vt = {c["key"]: c["value"] for c in ft["components"]}
    changes = []
    for key, label in COMPONENTS:
        a, b = vb.get(key), vt.get(key)
        if a == b:
            continue
        if a is None or b is None:
            direction = "visibility"
        else:
            rank = RANKERS.get(key)
            ra, rb = (rank(a), rank(b)) if rank else (None, None)
            direction = "changed" if ra is None or rb is None or ra == rb else "improved" if rb > ra else "degraded"
        changes.append({"key": key, "label": label, "from": a, "to": b, "direction": direction})

    sb, st = base["security"], target["security"]
    categories = []
    for key, cat in st["categories"].items():
        before = (sb["categories"].get(key) or {}).get("score")
        after = cat.get("score")
        categories.append({"key": key, "label": cat.get("label", key), "before": before, "after": after,
                           "delta": None if before is None or after is None else round(after - before, 1)})
    ids_b = {f["id"] for f in sb["findings"] if f["severity"] != "Informational"}
    ids_t = {f["id"] for f in st["findings"] if f["severity"] != "Informational"}
    real = [c for c in changes if c["direction"] != "visibility"]
    degraded = [c for c in real if c["direction"] == "degraded"]
    status = "no_drift" if not real else "degraded" if degraded else "improved" if all(
        c["direction"] == "improved" for c in real) else "changed"
    return {
        "status": status,
        "same_fingerprint": fb["id"] == ft["id"],
        "base": {"analysis_id": base.get("analysis_id"), "filename": base["parsed_metadata"]["filename"],
                 "created": base.get("created"), "fingerprint": fb, "score": sb.get("overall_score"),
                 "risk_level": sb.get("risk_level")},
        "target": {"analysis_id": target.get("analysis_id"), "filename": target["parsed_metadata"]["filename"],
                   "created": target.get("created"), "fingerprint": ft, "score": st.get("overall_score"),
                   "risk_level": st.get("risk_level")},
        "changes": changes,
        "score_delta": None if sb.get("overall_score") is None or st.get("overall_score") is None
        else round(st["overall_score"] - sb["overall_score"], 1),
        "categories": categories,
        "new_findings": sorted(ids_t - ids_b),
        "resolved_findings": sorted(ids_b - ids_t),
        "same_endpoints": bool(set(fb.get("endpoints") or []) & set(ft.get("endpoints") or [])),
    }
