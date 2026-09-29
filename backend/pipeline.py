"""
End-to-end analysis pipeline: capture → parse → IPsec analysis → traffic
classification → security assessment → threat matrix → AI confidence → reports.
"""
from __future__ import annotations

import time
from typing import Any

from backend.analyzers.flow_extractor import extract_flow_features
from backend.analyzers.ipsec_analyzer import INFERRED, analyze_ipsec, evidence, not_observable
from backend.analyzers.pcap_parser import parse_pcap
from backend.config import TRAFFIC_CLASS_LABELS
from backend.intel import build_intel
from backend.ml.model import classifier
from backend.reports.generator import generate_executive_report, generate_technical_report
from backend.security.confidence import compute_ai_confidence
from backend.security.scoring_engine import assess_security
from backend.security.threat_matrix import generate_threat_matrix


def run_pipeline(file_path: str, ground_truth: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.time()
    parsed = parse_pcap(file_path)
    analysis = analyze_ipsec(parsed)
    if analysis.get("error"):
        raise ValueError(analysis["error"])

    windows = extract_flow_features(parsed)
    predictions: list[dict[str, Any]] = []
    classification_note = None
    if not windows:
        classification_note = "No ESP tunnel window had enough packets (≥ 8 per 10 s) to classify"
    elif classifier.is_trained or classifier.load():
        predictions = classifier.predict(windows)
    else:
        classification_note = "Traffic classifier is still training — re-run the analysis in a moment"
    traffic = classifier.summarize(predictions)
    traffic["note"] = classification_note
    analysis["profile"]["traffic_types"] = traffic_evidence(traffic, classification_note)

    security = assess_security(analysis, traffic)
    threats = generate_threat_matrix(security["findings"])
    confidence = compute_ai_confidence(analysis, traffic, security)
    comparison = compare_with_truth(analysis, traffic, predictions, ground_truth) if ground_truth else None

    result = {
        "parsed_metadata": parsed["metadata"],
        "parsed_summary": parsed["summary"],
        "ipsec_analysis": analysis,
        "classification": predictions,
        "traffic": traffic,
        "security": security,
        "threat_matrix": threats,
        "ai_confidence": confidence,
        "ground_truth": comparison,
        "pipeline_seconds": round(time.time() - started, 2),
    }
    result["intel"] = build_intel(result)
    result["executive_report"] = generate_executive_report(result)
    result["technical_report"] = generate_technical_report(result, classifier.get_model_info())
    result["_packets"] = parsed["packets"]
    return result


def traffic_evidence(traffic: dict[str, Any], note: str | None) -> dict[str, Any]:
    if not traffic.get("windows"):
        return not_observable(note or "No classifiable ESP traffic", "Traffic classifier")
    mix = traffic["mix"]
    value = ", ".join(f"{TRAFFIC_CLASS_LABELS.get(c, c)} {max(1, int(round(v * 100)))}%" for c, v in mix.items())
    uncertain = traffic.get("uncertain_windows", 0)
    return evidence(value, INFERRED, traffic["mean_confidence"],
                    f"{traffic['windows']} ten-second windows across {len(traffic['flows'])} tunnel(s)"
                    + (f"; {uncertain} window(s) below the 50% confidence threshold" if uncertain else ""),
                    "Ensemble classifier on ESP size/timing features")


# ---------------------------------------------------------------- ground truth

def _auth_category(label: str | None) -> str | None:
    if not label:
        return None
    if "Pre-Shared" in label:
        return "psk"
    if "EAP" in label:
        return "eap"
    if "Certificate" in label or "Signature" in label:
        return "certificate"
    return label


def compare_with_truth(analysis: dict, traffic: dict, predictions: list[dict],
                       truth: dict[str, Any]) -> dict[str, Any]:
    """Field-by-field comparison of the AI result with the testbed's ground truth."""
    profile = analysis["profile"]
    fp = (analysis.get("esp_analysis") or {}).get("fingerprint") or {}

    def val(key):
        return (profile.get(key) or {}).get("value")

    rows = []

    def add(field, expected, predicted, correct, observable=True):
        rows.append({"field": field, "expected": expected, "predicted": predicted,
                     "status": "abstained" if predicted is None else ("correct" if correct else "wrong"),
                     "observable": observable})

    add("IKE version", truth["ike_version"], val("ike_version"), val("ike_version") == truth["ike_version"])
    add("Exchange mode", truth["exchange_mode"], val("exchange_mode"), val("exchange_mode") == truth["exchange_mode"])
    add("IPsec protocol", truth["ipsec_protocols"], val("ipsec_protocols"),
        val("ipsec_protocols") == truth["ipsec_protocols"])
    add("Tunnel / transport mode", truth["mode"], val("mode"), val("mode") == truth["mode"])
    add("IKE encryption", truth["ike_encryption"], val("ike_encryption"),
        val("ike_encryption") == truth["ike_encryption"])
    add("Key exchange (DH group)", truth["dh_group_name"], val("key_exchange"),
        (profile.get("key_exchange") or {}).get("group") == truth["dh_group"])
    if truth.get("esp_family"):
        expected_family = "NULL (no encryption)" if truth["esp_family"] == "NULL" else truth["esp_family"]
        add("ESP cipher family", expected_family, val("esp_encryption"), val("esp_encryption") == expected_family)
        if truth["esp_family"] != "NULL":
            icvs = fp.get("icv_len_candidates") or []
            add("ESP ICV length", f"{truth['esp_icv']} B",
                f"{'/'.join(map(str, icvs))} B" if icvs else None, truth["esp_icv"] in icvs)
    add("Authentication", truth["auth_method"], val("authentication_method"),
        _auth_category(val("authentication_method")) == _auth_category(truth["auth_method"]))
    add("Perfect Forward Secrecy", truth["pfs"] if truth["pfs_observable"] else "not observable", val("pfs"),
        val("pfs") == truth["pfs"], truth["pfs_observable"])
    add("NAT traversal", truth["nat_t"], val("nat_traversal"), val("nat_traversal") == truth["nat_t"])
    add("IP version", truth["ip_version"], val("ip_version"), val("ip_version") == truth["ip_version"])

    segments = truth.get("traffic_segments", [])
    window_hits = window_total = raw_hits = pure_hits = pure_total = 0
    for p in predictions:
        mid = (p["window_start"] + p["window_end"]) / 2
        seg = next((s for s in segments if s["start"] <= mid <= s["end"]), None)
        if seg:
            window_total += 1
            window_hits += seg["class"] == p["predicted_class"]
            raw_hits += seg["class"] == p.get("raw_class", p["predicted_class"])
            # 'pure' windows lie ≥ 80% inside one application; the rest straddle a switch and have no single label
            inside = min(p["window_end"], seg["end"]) - max(p["window_start"], seg["start"])
            if inside >= 0.8 * (p["window_end"] - p["window_start"]):
                pure_total += 1
                pure_hits += seg["class"] == p["predicted_class"]
    if window_total:
        add("Traffic type (per window)", ", ".join(s["class"] for s in segments),
            f"{window_hits}/{window_total} windows", window_hits / window_total >= 0.5)

    scored = [r for r in rows if r["observable"]]
    decided = [r for r in scored if r["status"] != "abstained"]
    correct = sum(1 for r in decided if r["status"] == "correct")
    return {
        "scenario": truth["name"],
        "description": truth.get("description"),
        "rows": rows,
        "correct": correct,
        "decided": len(decided),
        "total": len(scored),
        "accuracy": round(correct / len(decided), 3) if decided else None,
        "window_hits": window_hits,
        "window_hits_raw": raw_hits,
        "pure_window_hits": pure_hits,
        "pure_window_total": pure_total,
        "window_total": window_total,
        "window_accuracy": round(window_hits / window_total, 3) if window_total else None,
    }
