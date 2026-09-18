"""
Threat matrix generator.
Maps security findings to threat categories with likelihood and impact scores.
"""
from typing import Any


# Threat categories mapped to MITRE ATT&CK-style tactics
THREAT_CATEGORIES = {
    "credential_access": {
        "name": "Credential Access",
        "description": "Attacks targeting VPN credentials or key material",
        "mitre_tactic": "TA0006",
    },
    "cryptanalysis": {
        "name": "Cryptanalysis",
        "description": "Attacks exploiting weak cryptographic algorithms",
        "mitre_tactic": "T1600",
    },
    "traffic_analysis": {
        "name": "Traffic Analysis",
        "description": "Attacks using metadata to infer VPN tunnel contents",
        "mitre_tactic": "T1040",
    },
    "replay_attack": {
        "name": "Replay Attack",
        "description": "Replaying captured packets to disrupt or exploit the VPN",
        "mitre_tactic": "T1557",
    },
    "downgrade_attack": {
        "name": "Protocol Downgrade",
        "description": "Forcing weaker protocol versions or algorithms",
        "mitre_tactic": "T1562",
    },
    "key_compromise": {
        "name": "Key Compromise",
        "description": "Attacks targeting key exchange or lacking forward secrecy",
        "mitre_tactic": "T1552",
    },
    "dos": {
        "name": "Denial of Service",
        "description": "Attacks disrupting VPN availability",
        "mitre_tactic": "T1499",
    },
    "mitm": {
        "name": "Man-in-the-Middle",
        "description": "Interception and modification of VPN traffic",
        "mitre_tactic": "T1557",
    },
}

# Mapping: finding ID prefix -> threat categories + likelihood/impact
FINDING_THREAT_MAP = {
    "CRYPTO-002": [("cryptanalysis", 0.9, 1.0), ("mitm", 0.7, 0.9)],
    "CRYPTO-003": [("cryptanalysis", 0.6, 0.8), ("key_compromise", 0.4, 0.7)],
    "CRYPTO-004": [("cryptanalysis", 0.3, 0.6)],
    "KE-002": [("key_compromise", 0.5, 0.8)],
    "KE-003": [("key_compromise", 0.8, 0.9), ("cryptanalysis", 0.7, 0.9)],
    "KE-004": [("key_compromise", 0.4, 0.6)],
    "INT-003": [("replay_attack", 0.5, 0.7), ("mitm", 0.4, 0.6)],
    "REPLAY-001": [("replay_attack", 0.7, 0.8)],
    "CFG-001": [("downgrade_attack", 0.4, 0.5)],
    "CFG-004": [("credential_access", 0.7, 0.8), ("downgrade_attack", 0.6, 0.7)],
    "CFG-005": [("traffic_analysis", 0.9, 0.9), ("cryptanalysis", 0.8, 1.0)],
    "META-001": [("traffic_analysis", 0.6, 0.5)],
    "SA-004": [("key_compromise", 0.3, 0.5)],
}


def generate_threat_matrix(findings: list[dict]) -> dict[str, Any]:
    """
    Generate a threat matrix from security findings.
    
    Returns threat categories with aggregated likelihood and impact scores.
    """
    threat_scores = {}
    
    for finding in findings:
        fid = finding.get("id", "")
        
        if fid in FINDING_THREAT_MAP:
            for category, likelihood, impact in FINDING_THREAT_MAP[fid]:
                if category not in threat_scores:
                    threat_scores[category] = {
                        **THREAT_CATEGORIES[category],
                        "likelihood": 0,
                        "impact": 0,
                        "risk_score": 0,
                        "contributing_findings": [],
                    }
                
                # Take max likelihood and impact
                threat_scores[category]["likelihood"] = max(
                    threat_scores[category]["likelihood"], likelihood
                )
                threat_scores[category]["impact"] = max(
                    threat_scores[category]["impact"], impact
                )
                threat_scores[category]["contributing_findings"].append(fid)
    
    # Calculate risk scores
    for cat in threat_scores.values():
        cat["risk_score"] = round(cat["likelihood"] * cat["impact"] * 100, 1)
        cat["risk_level"] = (
            "Critical" if cat["risk_score"] >= 70 else
            "High" if cat["risk_score"] >= 50 else
            "Medium" if cat["risk_score"] >= 30 else
            "Low" if cat["risk_score"] >= 10 else
            "Negligible"
        )
    
    # Sort by risk score
    sorted_threats = sorted(
        threat_scores.values(),
        key=lambda t: t["risk_score"],
        reverse=True,
    )
    
    # Calculate overall threat score
    if sorted_threats:
        max_risk = max(t["risk_score"] for t in sorted_threats)
        avg_risk = sum(t["risk_score"] for t in sorted_threats) / len(sorted_threats)
    else:
        max_risk = 0
        avg_risk = 0
    
    return {
        "threats": sorted_threats,
        "max_risk_score": max_risk,
        "average_risk_score": round(avg_risk, 1),
        "threat_count": len(sorted_threats),
        "categories_defined": len(THREAT_CATEGORIES),
    }
