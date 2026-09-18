"""
Report generation engine.
Generates executive and technical reports from analysis results.
"""
from __future__ import annotations
from typing import Any
from datetime import datetime


def generate_executive_report(
    analysis: dict,
    security: dict,
    classification: list[dict] | None = None,
    threat_matrix: dict | None = None,
) -> dict[str, Any]:
    """Generate an executive-level summary report."""
    vpn_profile = analysis.get("vpn_profile", {})
    
    # Severity counts
    findings = security.get("findings", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.get("severity", "Informational")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # AI confidence
    ai_confidence = None
    if classification:
        confidences = [c.get("confidence", 0) for c in classification]
        ai_confidence = round(sum(confidences) / len(confidences), 4) if confidences else None
    
    report = {
        "title": "IPsec VPN Security Assessment - Executive Summary",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "overall_security_score": security.get("overall_score", 0),
        "risk_level": security.get("risk_level", "Unknown"),
        "key_findings": {
            "total_findings": len(findings),
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
            "informational": severity_counts["Informational"],
        },
        "vpn_summary": {
            "protocol": ", ".join(vpn_profile.get("ipsec_protocol", ["Unknown"])),
            "ike_version": vpn_profile.get("ike_version", "Unknown"),
            "encryption": vpn_profile.get("encryption", "Unknown"),
            "mode": vpn_profile.get("mode", "Unknown"),
            "pfs": vpn_profile.get("pfs", "Unknown"),
        },
        "category_scores": {
            cat: {
                "score": data["score"],
                "rating": data["rating"],
            }
            for cat, data in security.get("categories", {}).items()
        },
        "top_recommendations": security.get("recommendations", [])[:5],
        "ai_confidence": ai_confidence,
        "threat_summary": None,
    }
    
    if threat_matrix:
        report["threat_summary"] = {
            "total_threats": threat_matrix.get("threat_count", 0),
            "max_risk": threat_matrix.get("max_risk_score", 0),
            "top_threats": [
                {"name": t["name"], "risk_score": t["risk_score"], "risk_level": t["risk_level"]}
                for t in threat_matrix.get("threats", [])[:3]
            ],
        }
    
    return report


def generate_technical_report(
    parsed_data: dict,
    analysis: dict,
    security: dict,
    classification: list[dict] | None = None,
    threat_matrix: dict | None = None,
    model_info: dict | None = None,
) -> dict[str, Any]:
    """Generate a detailed technical report."""
    vpn_profile = analysis.get("vpn_profile", {})
    ike = analysis.get("ike_analysis", {})
    esp = analysis.get("esp_analysis", {})
    
    report = {
        "title": "IPsec VPN Security Assessment - Technical Report",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        
        # Capture metadata
        "capture_info": parsed_data.get("metadata", {}),
        "packet_statistics": parsed_data.get("summary", {}),
        
        # Protocol analysis
        "vpn_profile": vpn_profile,
        "ike_details": {
            "version": ike.get("version", "Not Observable"),
            "detected": ike.get("detected", False),
            "packet_count": ike.get("packet_count", 0),
            "exchange_types": ike.get("exchange_types", []),
            "chosen_algorithms": ike.get("chosen_algorithms", {}),
            "pfs": ike.get("pfs_detected", {}),
            "mode": ike.get("mode", "Not Observable"),
            "spis": ike.get("ike_spis", []),
            "notifies": ike.get("notifies", []),
        },
        "esp_details": {
            "detected": esp.get("detected", False),
            "packet_count": esp.get("packet_count", 0),
            "sa_info": esp.get("sa_info", []),
        },
        "ah_details": analysis.get("ah_analysis", {}),
        "nat_t_details": analysis.get("nat_t_analysis", {}),
        "ip_details": analysis.get("ip_analysis", {}),
        
        # Security assessment
        "security_assessment": {
            "overall_score": security.get("overall_score", 0),
            "risk_level": security.get("risk_level", "Unknown"),
            "categories": security.get("categories", {}),
            "scoring_weights": security.get("scoring_weights", {}),
            "assessment_basis": security.get("assessment_basis", {}),
        },
        
        # Findings
        "findings": security.get("findings", []),
        "recommendations": security.get("recommendations", []),
        
        # Threat matrix
        "threat_matrix": threat_matrix,
        
        # Traffic classification
        "traffic_classification": classification,
        
        # Model info
        "model_info": model_info,
        
        # Flow analysis
        "flow_analysis": analysis.get("flow_analysis", {}),
        
        # Timeline
        "timeline": analysis.get("timeline", [])[:50],
    }
    
    return report
