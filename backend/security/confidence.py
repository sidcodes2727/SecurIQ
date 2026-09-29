"""
AI confidence score (PS §e).

Combines three separately reported parts:
  identification  mean confidence of protocol properties that could be determined
  classification  packet-weighted confidence of the traffic classifier
  coverage        share of the weighted security assessment backed by evidence
"""
from __future__ import annotations

from typing import Any

IDENTIFICATION_FIELDS = [
    "ipsec_protocols", "ike_version", "exchange_mode", "mode", "ike_encryption", "ike_integrity",
    "key_exchange", "esp_encryption", "esp_integrity", "authentication_method", "pfs",
    "ike_lifetime", "child_sa_lifetime", "replay_protection", "nat_traversal", "ip_version",
]


def compute_ai_confidence(analysis: dict[str, Any], classification: dict[str, Any] | None,
                          security: dict[str, Any]) -> dict[str, Any]:
    profile = analysis.get("profile", {})
    determined = [profile[f] for f in IDENTIFICATION_FIELDS
                  if f in profile and profile[f].get("source") != "not_observable"]
    observed = sum(1 for e in determined if e["source"] == "observed")
    inferred = sum(1 for e in determined if e["source"] == "inferred")
    identification = sum(e["confidence"] for e in determined) / len(determined) if determined else 0.0

    parts = [(0.4, identification)]
    classification_conf = None
    if classification and classification.get("mean_confidence") is not None:
        classification_conf = classification["mean_confidence"]
        parts.append((0.4, classification_conf))
    coverage = security.get("coverage") or 0.0
    parts.append((0.2, coverage))

    total = sum(w for w, _ in parts)
    overall = sum(w * v for w, v in parts) / total
    return {
        "overall": round(overall, 3),
        "identification": round(identification, 3),
        "classification": round(classification_conf, 3) if classification_conf is not None else None,
        "assessment_coverage": round(coverage, 3),
        "fields_total": len(IDENTIFICATION_FIELDS),
        "fields_observed": observed,
        "fields_inferred": inferred,
        "fields_not_observable": len(IDENTIFICATION_FIELDS) - observed - inferred,
        "formula": "0.4 × identification + 0.4 × classification + 0.2 × coverage (renormalised if a part is absent)",
    }
