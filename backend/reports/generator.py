"""
Executive and technical report builders (PS §e).

Both reports are plain dicts (served as JSON and rendered to printable HTML by
backend.reports.html). The executive report answers "how exposed are we and what
do we do first"; the technical report carries every piece of evidence behind it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.config import TRAFFIC_CLASS_LABELS

PROFILE_LABELS = {
    "ipsec_protocols": "IPsec protocol",
    "ike_version": "IKE version",
    "exchange_mode": "Exchange mode",
    "mode": "Tunnel / transport mode",
    "ike_encryption": "IKE SA encryption",
    "ike_integrity": "IKE SA integrity",
    "ike_prf": "IKE SA PRF",
    "key_exchange": "Key exchange",
    "esp_encryption": "ESP (Child SA) encryption",
    "esp_integrity": "ESP (Child SA) integrity",
    "authentication_method": "Authentication",
    "pfs": "Perfect Forward Secrecy",
    "ike_lifetime": "IKE SA lifetime",
    "child_sa_lifetime": "Child SA lifetime",
    "replay_protection": "Replay protection",
    "nat_traversal": "NAT traversal",
    "ip_version": "IP version",
    "implementation": "Implementation",
    "traffic_types": "Traffic inside the tunnel",
}

EXECUTIVE_FIELDS = ["ike_version", "exchange_mode", "mode", "ike_encryption", "key_exchange", "esp_encryption",
                    "authentication_method", "pfs", "traffic_types"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _display(record: dict[str, Any]) -> str:
    value = record.get("display") or record.get("value")
    if value is None:
        return "Not observable"
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return str(value)


def profile_rows(profile: dict[str, Any], fields: list[str] | None = None) -> list[dict[str, Any]]:
    keys = fields or [k for k in PROFILE_LABELS if k in profile]
    return [{
        "key": key,
        "label": PROFILE_LABELS.get(key, key),
        "value": _display(profile[key]),
        "source": profile[key].get("source"),
        "confidence": profile[key].get("confidence"),
        "evidence": profile[key].get("evidence"),
        "method": profile[key].get("method"),
    } for key in keys if key in profile]


def _bottom_line(result: dict[str, Any]) -> str:
    security = result["security"]
    profile = result["ipsec_analysis"]["profile"]
    rows = {r["key"]: r["value"] for r in profile_rows(profile)}
    ike = rows.get("ike_version", "Not observable")
    ike_text = f"an {ike}" if ike != "Not observable" else "an IPsec"
    mode = rows.get("exchange_mode")
    if mode not in (None, "IKEv2", "Not observable"):
        ike_text += f" ({mode})"
    esp = rows.get("esp_encryption", "Not observable")
    if esp.startswith("None"):
        data = "no data-channel encryption (AH only)"
    elif esp.startswith("NULL"):
        data = "NULL encryption on the data channel (no confidentiality)"
    elif esp == "Not observable":
        data = "a data-channel cipher that could not be inferred"
    else:
        data = f"{esp} on the data channel"
    key_exchange = rows.get("key_exchange", "Not observable")
    kx = f"{key_exchange} key exchange" if key_exchange != "Not observable" else "an unobserved key exchange"
    description = f"The capture shows {ike_text} VPN using {data} and {kx}."
    counts = security["severity_counts"]
    serious = counts.get("Critical", 0) + counts.get("High", 0)
    score = security["overall_score"]
    if score is None:
        verdict = "There was not enough evidence in the capture to score the deployment."
    elif serious:
        top = [f["title"] for f in security["findings"] if f["severity"] in ("Critical", "High")][:3]
        verdict = (f"{serious} critical/high issue{'s' if serious > 1 else ''} — {'; '.join(top)} — "
                   f"place the deployment at {security['risk_level'].lower()} (score {score}/100).")
    else:
        verdict = f"No critical or high issues were found; overall posture is {security['risk_level'].lower()} (score {score}/100)."
    return f"{description} {verdict}"


def generate_executive_report(result: dict[str, Any]) -> dict[str, Any]:
    security = result["security"]
    threats = result["threat_matrix"]
    traffic = result.get("traffic") or {}
    meta = result["parsed_metadata"]
    analysis = result["ipsec_analysis"]
    return {
        "title": "IPsec VPN Security Assessment — Executive Summary",
        "generated_at": _now(),
        "capture": {
            "filename": meta.get("filename"),
            "packets": meta.get("total_packets"),
            "duration_seconds": analysis.get("capture_duration"),
            "file_hash": meta.get("file_hash"),
        },
        "bottom_line": _bottom_line(result),
        "overall_security_score": security["overall_score"],
        "risk_score": security["risk_score"],
        "risk_level": security["risk_level"],
        "score_cap": security.get("score_cap"),
        "coverage": security["coverage"],
        "provisional": security["provisional"],
        "ai_confidence": result["ai_confidence"],
        "key_findings": security["severity_counts"],
        "vpn_summary": profile_rows(analysis["profile"], EXECUTIVE_FIELDS),
        "category_scores": {k: {"label": c["label"], "score": c["score"], "rating": c["rating"],
                                "confidence": c["confidence"]} for k, c in security["categories"].items()},
        "top_recommendations": security["recommendations"][:6],
        "top_threats": [{"name": t["name"], "risk_score": t["risk_score"], "risk_level": t["risk_level"],
                         "likelihood": t["likelihood"], "impact": t["impact"]} for t in threats["threats"][:4]],
        "compliance": {k: {"name": p["name"], "status": p["status"], "score": p["score"], "coverage": p["coverage"]}
                       for k, p in security["compliance"].items()},
        "effective_strength": security["effective_strength"],
        "traffic_mix": [{"class": c, "label": TRAFFIC_CLASS_LABELS.get(c, c), "share": v}
                        for c, v in (traffic.get("mix") or {}).items()],
        "posture": (result.get("intel") or {}).get("posture"),
        "metadata": {k: (result.get("intel") or {}).get("metadata", {}).get(k)
                     for k in ("confidentiality", "metadata_privacy", "statements")},
        "fingerprint": (result.get("intel") or {}).get("fingerprint", {}).get("id"),
        "policy": {k: (result.get("intel") or {}).get("policy", {}).get(k) for k in ("status", "counts", "score")},
    }


def generate_technical_report(result: dict[str, Any], model_info: dict[str, Any] | None = None) -> dict[str, Any]:
    analysis = result["ipsec_analysis"]
    ike = analysis.get("ike_analysis", {})
    esp = analysis.get("esp_analysis", {})
    security = result["security"]
    return {
        "title": "IPsec VPN Security Assessment — Technical Report",
        "generated_at": _now(),
        "capture_info": result["parsed_metadata"],
        "packet_statistics": result["parsed_summary"],
        "capture_duration_seconds": analysis.get("capture_duration"),
        "identification": profile_rows(analysis["profile"]),
        "ike": {
            "detected": ike.get("detected"),
            "version": ike.get("version"),
            "exchange_mode": ike.get("exchange_mode"),
            "exchange_types": ike.get("exchange_types", []),
            "sessions": ike.get("sessions", []),
            "offered_proposals": ike.get("offered_proposals", []),
            "chosen_suite": ike.get("chosen_suite"),
            "downgrade_surface": ike.get("downgrade_surface", []),
            "vendor_ids": ike.get("vendor_ids", []),
            "identities": ike.get("identities", []),
            "notifies": ike.get("notifies", []),
            "signature_hashes": ike.get("signature_hashes", []),
            "pfs_decisions": (ike.get("pfs") or {}).get("exchanges", []),
        },
        "esp": {
            "detected": esp.get("detected"),
            "packet_count": esp.get("packet_count"),
            "fingerprint": esp.get("fingerprint"),
            "mode_inference": esp.get("mode_inference"),
            "null_encryption": esp.get("null_encryption"),
            "replay_summary": esp.get("replay_summary"),
            "security_associations": esp.get("sa_info", []),
            "tunnels": esp.get("tunnels", []),
        },
        "ah": analysis.get("ah_analysis", {}),
        "nat_t": analysis.get("nat_t_analysis", {}),
        "ip": analysis.get("ip_analysis", {}),
        "security_assessment": {
            "overall_score": security["overall_score"],
            "uncapped_score": security["uncapped_score"],
            "score_cap": security["score_cap"],
            "risk_level": security["risk_level"],
            "coverage": security["coverage"],
            "method": security["method"],
            "categories": security["categories"],
            "scoring_weights": security["scoring_weights"],
            "effective_strength": security["effective_strength"],
        },
        "findings": security["findings"],
        "recommendations": security["recommendations"],
        "compliance": security["compliance"],
        "threat_matrix": result["threat_matrix"],
        "traffic_classification": {"summary": result.get("traffic"), "windows": result.get("classification", [])},
        "ai_confidence": result["ai_confidence"],
        "ground_truth": result.get("ground_truth"),
        "model_info": model_info,
        "timeline": analysis.get("timeline", [])[:100],
        "methodology": METHODOLOGY,
    }


METHODOLOGY = [
    "IKE_SA_INIT (IKEv2) and Main/Aggressive Mode messages 1–4 (IKEv1) are cleartext: their proposals, "
    "key-exchange groups, notifications and vendor IDs are reported as observed.",
    "Child SA (ESP) algorithms, mode, and PFS are negotiated inside encrypted messages and are inferred: "
    "ESP ciphertext length residues reveal the block size and ICV length; the smallest inner packet bounds "
    "tunnel vs transport mode; the size of encrypted CREATE_CHILD_SA / Quick Mode messages reveals whether "
    "a Key Exchange payload (PFS) is present.",
    "Traffic inside ESP is classified per 10-second window of each bidirectional tunnel with a RandomForest "
    "trained on testbed traffic framed by the same ESP model and feature code used here.",
    "Scores are confidence-weighted across assessable categories only; categories without evidence reduce "
    "coverage rather than defaulting to a neutral value. Critical (High) findings cap the score at 40 (70).",
    "Limitations: AES key length on ESP is not observable; several applications multiplexed in one SA are "
    "classified by their dominant pattern; size heuristics assume standard IKE implementations.",
]
