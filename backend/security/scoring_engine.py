"""
Rule-based security assessment engine.
Evaluates IPsec VPN configuration security using transparent, documented rules.
Every score has a clear rationale.
"""
from typing import Any

from backend.config import (
    ENCRYPTION_SCORES, INTEGRITY_SCORES, DH_GROUP_SCORES,
    SCORING_WEIGHTS, SEVERITY_CRITICAL, SEVERITY_HIGH,
    SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
)


def assess_security(analysis: dict[str, Any]) -> dict[str, Any]:
    """
    Perform comprehensive security assessment on IPsec analysis results.
    
    Returns:
    - Overall risk score (0-100, higher = more secure)
    - Category scores with rationale
    - Security findings with severity
    - Recommendations
    """
    vpn_profile = analysis.get("vpn_profile", {})
    ike_analysis = analysis.get("ike_analysis", {})
    esp_analysis = analysis.get("esp_analysis", {})
    ah_analysis = analysis.get("ah_analysis", {})
    nat_analysis = analysis.get("nat_t_analysis", {})
    
    # Evaluate each category
    categories = {
        "cryptographic_strength": _assess_crypto(vpn_profile, ike_analysis),
        "key_exchange": _assess_key_exchange(vpn_profile, ike_analysis),
        "authentication_integrity": _assess_integrity(vpn_profile, ike_analysis),
        "sa_parameters": _assess_sa(esp_analysis, ike_analysis),
        "replay_protection": _assess_replay(esp_analysis),
        "configuration": _assess_config(vpn_profile, ike_analysis, analysis),
        "metadata_exposure": _assess_metadata(vpn_profile, nat_analysis, analysis),
    }
    
    # Calculate weighted overall score
    overall_score = sum(
        categories[cat]["score"] * SCORING_WEIGHTS[cat]
        for cat in categories
    )
    overall_score = round(overall_score, 1)
    
    # Determine risk level
    if overall_score >= 85:
        risk_level = "Low Risk"
        risk_color = "green"
    elif overall_score >= 70:
        risk_level = "Moderate Risk"
        risk_color = "yellow"
    elif overall_score >= 50:
        risk_level = "Elevated Risk"
        risk_color = "orange"
    elif overall_score >= 30:
        risk_level = "High Risk"
        risk_color = "red"
    else:
        risk_level = "Critical Risk"
        risk_color = "darkred"
    
    # Collect all findings
    all_findings = []
    for cat_data in categories.values():
        all_findings.extend(cat_data.get("findings", []))
    
    # Sort findings by severity
    severity_order = {
        SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2,
        SEVERITY_LOW: 3, SEVERITY_INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    
    # Generate recommendations
    recommendations = _generate_recommendations(categories, vpn_profile)
    
    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "categories": categories,
        "findings": all_findings,
        "recommendations": recommendations,
        "scoring_weights": SCORING_WEIGHTS,
        "assessment_basis": _get_assessment_basis(vpn_profile),
    }


def _assess_crypto(profile: dict, ike: dict) -> dict[str, Any]:
    """Assess cryptographic strength of encryption algorithms."""
    findings = []
    enc = profile.get("encryption", "Not Observable")
    
    if enc == "Not Observable":
        return {
            "score": 50,
            "rating": "Unknown",
            "rationale": "Encryption algorithm could not be determined from the capture. "
                         "IKE negotiation may not be present.",
            "details": {"algorithm": enc},
            "findings": [{
                "id": "CRYPTO-001",
                "title": "Encryption Algorithm Not Observable",
                "severity": SEVERITY_INFO,
                "description": "The encryption algorithm could not be determined from the capture.",
                "evidence": "No IKE SA negotiation found",
                "recommendation": "Capture the full IKE negotiation to assess encryption strength.",
            }],
        }
    
    # Look up score
    score = 50  # default for unknown
    enc_upper = enc.upper()
    for key, val in ENCRYPTION_SCORES.items():
        if key.upper() in enc_upper or enc_upper in key.upper():
            score = val
            break
    
    # Generate findings based on score
    if score <= 10:
        findings.append({
            "id": "CRYPTO-002",
            "title": f"Critically Weak Encryption: {enc}",
            "severity": SEVERITY_CRITICAL,
            "description": f"The encryption algorithm {enc} is considered broken and "
                           "provides no meaningful confidentiality.",
            "evidence": f"IKE negotiation selected {enc}",
            "recommendation": "Immediately upgrade to AES-256-GCM or AES-256-CBC.",
        })
    elif score <= 30:
        findings.append({
            "id": "CRYPTO-003",
            "title": f"Weak Encryption: {enc}",
            "severity": SEVERITY_HIGH,
            "description": f"The encryption algorithm {enc} is deprecated and "
                           "vulnerable to modern attacks.",
            "evidence": f"IKE negotiation selected {enc}",
            "recommendation": "Upgrade to AES-256-GCM for authenticated encryption.",
        })
    elif score <= 60:
        findings.append({
            "id": "CRYPTO-004",
            "title": f"Moderate Encryption: {enc}",
            "severity": SEVERITY_MEDIUM,
            "description": f"The encryption algorithm {enc} provides adequate security "
                           "but stronger alternatives exist.",
            "evidence": f"IKE negotiation selected {enc}",
            "recommendation": "Consider upgrading to AES-256-GCM for better security and performance.",
        })
    elif score <= 85:
        findings.append({
            "id": "CRYPTO-005",
            "title": f"Good Encryption: {enc}",
            "severity": SEVERITY_LOW,
            "description": f"The encryption algorithm {enc} provides good security.",
            "evidence": f"IKE negotiation selected {enc}",
            "recommendation": "Consider AES-GCM mode for authenticated encryption with better performance.",
        })
    else:
        findings.append({
            "id": "CRYPTO-006",
            "title": f"Strong Encryption: {enc}",
            "severity": SEVERITY_INFO,
            "description": f"The encryption algorithm {enc} provides strong, "
                           "state-of-the-art security.",
            "evidence": f"IKE negotiation selected {enc}",
            "recommendation": "No changes needed. Continue monitoring for future deprecations.",
        })
    
    rating = (
        "Critical" if score <= 10 else
        "Weak" if score <= 30 else
        "Moderate" if score <= 60 else
        "Good" if score <= 85 else
        "Excellent"
    )
    
    return {
        "score": score,
        "rating": rating,
        "rationale": f"Based on algorithm {enc} with score {score}/100. "
                     f"AES-256-GCM=100, AES-128-CBC=70, 3DES=30, DES=5.",
        "details": {"algorithm": enc, "key_length": profile.get("key_length")},
        "findings": findings,
    }


def _assess_key_exchange(profile: dict, ike: dict) -> dict[str, Any]:
    """Assess key exchange and PFS."""
    findings = []
    dh_group = profile.get("dh_group", "Not Observable")
    dh_num = profile.get("dh_group_number")
    pfs = profile.get("pfs", "Not Observable")
    
    # DH group score
    dh_score = 50  # default
    if dh_num and dh_num in DH_GROUP_SCORES:
        dh_score = DH_GROUP_SCORES[dh_num]
    elif dh_group == "Not Observable":
        dh_score = 50
    
    # PFS bonus/penalty
    pfs_bonus = 0
    if pfs is True:
        pfs_bonus = 10
        findings.append({
            "id": "KE-001",
            "title": "Perfect Forward Secrecy Enabled",
            "severity": SEVERITY_INFO,
            "description": "PFS is enabled, providing forward secrecy for child SAs.",
            "evidence": "Key Exchange payload found in CREATE_CHILD_SA exchange",
            "recommendation": "Good practice. Maintain PFS configuration.",
        })
    elif pfs is False:
        pfs_bonus = -15
        findings.append({
            "id": "KE-002",
            "title": "Perfect Forward Secrecy Not Enabled",
            "severity": SEVERITY_MEDIUM,
            "description": "PFS is not enabled. If the IKE SA key is compromised, "
                           "all child SA keys can be derived.",
            "evidence": "CREATE_CHILD_SA without Key Exchange payload",
            "recommendation": "Enable PFS by configuring a DH group for child SA negotiations.",
        })
    
    # DH group findings
    if dh_num and dh_num <= 2:
        findings.append({
            "id": "KE-003",
            "title": f"Weak Diffie-Hellman Group: {dh_group}",
            "severity": SEVERITY_CRITICAL,
            "description": f"DH Group {dh_num} ({dh_group}) uses insufficient key length "
                           "and is vulnerable to precomputation attacks.",
            "evidence": f"IKE negotiation uses DH Group {dh_num}",
            "recommendation": "Use DH Group 14 (2048-bit) minimum, preferably Group 19/20 (ECP) or 31 (Curve25519).",
        })
    elif dh_num and dh_num <= 5:
        findings.append({
            "id": "KE-004",
            "title": f"Moderate Diffie-Hellman Group: {dh_group}",
            "severity": SEVERITY_MEDIUM,
            "description": f"DH Group {dh_num} ({dh_group}) provides moderate security "
                           "but is below current best practices.",
            "evidence": f"IKE negotiation uses DH Group {dh_num}",
            "recommendation": "Upgrade to DH Group 14+ (MODP 2048) or elliptic curve groups.",
        })
    elif dh_group != "Not Observable":
        findings.append({
            "id": "KE-005",
            "title": f"Strong Key Exchange: {dh_group}",
            "severity": SEVERITY_INFO,
            "description": f"DH Group {dh_group} provides strong key exchange security.",
            "evidence": f"IKE negotiation uses {dh_group}",
            "recommendation": "No changes needed.",
        })
    
    score = min(100, max(0, dh_score + pfs_bonus))
    
    return {
        "score": score,
        "rating": (
            "Critical" if score <= 20 else
            "Weak" if score <= 40 else
            "Moderate" if score <= 60 else
            "Good" if score <= 80 else
            "Excellent"
        ),
        "rationale": f"DH Group {dh_group} (score {dh_score}), PFS adjustment: {pfs_bonus:+d}",
        "details": {
            "dh_group": dh_group,
            "dh_group_number": dh_num,
            "pfs": pfs,
        },
        "findings": findings,
    }


def _assess_integrity(profile: dict, ike: dict) -> dict[str, Any]:
    """Assess authentication and integrity algorithms."""
    findings = []
    integrity = profile.get("integrity", "Not Observable")
    enc = profile.get("encryption", "Not Observable")
    
    # Check if AEAD mode (handles integrity itself)
    is_aead = any(aead in enc.upper() for aead in ["GCM", "CCM", "CHACHA", "POLY"])
    
    if is_aead:
        score = 100
        findings.append({
            "id": "INT-001",
            "title": "AEAD Encryption Mode",
            "severity": SEVERITY_INFO,
            "description": f"Using AEAD mode ({enc}) which provides both encryption "
                           "and authentication in a single operation.",
            "evidence": f"Encryption algorithm: {enc}",
            "recommendation": "Excellent choice. AEAD modes prevent padding oracle and similar attacks.",
        })
    elif integrity == "Not Observable":
        score = 50
        findings.append({
            "id": "INT-002",
            "title": "Integrity Algorithm Not Observable",
            "severity": SEVERITY_INFO,
            "description": "The integrity algorithm could not be determined.",
            "evidence": "No IKE SA negotiation found",
            "recommendation": "Capture the full IKE negotiation.",
        })
    else:
        score = 50
        int_upper = integrity.upper()
        for key, val in INTEGRITY_SCORES.items():
            if key.upper() in int_upper or int_upper in key.upper():
                score = val
                break
        
        if score <= 30:
            findings.append({
                "id": "INT-003",
                "title": f"Weak Integrity Algorithm: {integrity}",
                "severity": SEVERITY_HIGH,
                "description": f"The integrity algorithm {integrity} is deprecated.",
                "evidence": f"IKE negotiation selected {integrity}",
                "recommendation": "Use HMAC-SHA2-256 or upgrade to AEAD encryption.",
            })
        elif score <= 65:
            findings.append({
                "id": "INT-004",
                "title": f"Moderate Integrity Algorithm: {integrity}",
                "severity": SEVERITY_MEDIUM,
                "description": f"{integrity} is acceptable but SHA-1 based algorithms "
                               "are being phased out.",
                "evidence": f"IKE negotiation selected {integrity}",
                "recommendation": "Upgrade to HMAC-SHA2-256 or use AEAD mode.",
            })
        else:
            findings.append({
                "id": "INT-005",
                "title": f"Strong Integrity: {integrity}",
                "severity": SEVERITY_INFO,
                "description": f"{integrity} provides strong integrity protection.",
                "evidence": f"IKE negotiation selected {integrity}",
                "recommendation": "No changes needed.",
            })
    
    return {
        "score": score,
        "rating": (
            "Critical" if score <= 25 else
            "Weak" if score <= 50 else
            "Moderate" if score <= 70 else
            "Good" if score <= 90 else
            "Excellent"
        ),
        "rationale": f"Integrity: {integrity}, AEAD: {is_aead}",
        "details": {"integrity": integrity, "is_aead": is_aead},
        "findings": findings,
    }


def _assess_sa(esp: dict, ike: dict) -> dict[str, Any]:
    """Assess Security Association parameters."""
    findings = []
    score = 70  # Base score when SA exists
    
    if not esp.get("detected"):
        return {
            "score": 50,
            "rating": "Unknown",
            "rationale": "No ESP SAs detected",
            "details": {},
            "findings": [{
                "id": "SA-001",
                "title": "No ESP Security Associations Detected",
                "severity": SEVERITY_INFO,
                "description": "No ESP packets found in the capture.",
                "evidence": "No ESP protocol packets",
                "recommendation": "Ensure ESP traffic is included in the capture.",
            }],
        }
    
    sa_info = esp.get("sa_info", [])
    unique_spis = esp.get("unique_spis", 0)
    
    # Multiple SPIs indicate SA rekeying (good practice)
    if unique_spis >= 4:
        score += 15
        findings.append({
            "id": "SA-002",
            "title": "SA Rekeying Detected",
            "severity": SEVERITY_INFO,
            "description": f"Multiple SPIs ({unique_spis}) detected, indicating SA rekeying.",
            "evidence": f"{unique_spis} unique SPIs observed",
            "recommendation": "Good practice. Regular rekeying limits exposure.",
        })
    elif unique_spis == 2:
        score += 5
        findings.append({
            "id": "SA-003",
            "title": "Bidirectional SA Pair",
            "severity": SEVERITY_INFO,
            "description": "Two SPIs detected, consistent with a single bidirectional SA.",
            "evidence": f"{unique_spis} unique SPIs observed",
            "recommendation": "Consider if the capture duration is sufficient to observe rekeying.",
        })
    
    # Check for long-lived SAs
    for sa in sa_info:
        duration = sa.get("duration", 0)
        if duration > 86400:  # > 24 hours
            score -= 10
            findings.append({
                "id": "SA-004",
                "title": "Long-Lived Security Association",
                "severity": SEVERITY_MEDIUM,
                "description": f"SA with SPI {sa['spi']} has been active for "
                               f"{duration/3600:.1f} hours without rekeying.",
                "evidence": f"SA duration: {duration:.0f}s",
                "recommendation": "Configure SA lifetime to 1-8 hours maximum.",
            })
    
    return {
        "score": min(100, max(0, score)),
        "rating": (
            "Weak" if score <= 40 else
            "Moderate" if score <= 60 else
            "Good" if score <= 80 else
            "Excellent"
        ),
        "rationale": f"{unique_spis} unique SPIs, {len(sa_info)} SAs analyzed",
        "details": {"unique_spis": unique_spis, "sa_count": len(sa_info)},
        "findings": findings,
    }


def _assess_replay(esp: dict) -> dict[str, Any]:
    """Assess replay protection based on sequence number analysis."""
    findings = []
    score = 75  # Base score
    
    if not esp.get("detected"):
        return {
            "score": 50,
            "rating": "Unknown",
            "rationale": "No ESP traffic to analyze",
            "details": {},
            "findings": [],
        }
    
    sa_info = esp.get("sa_info", [])
    total_gaps = 0
    total_duplicates = 0
    
    for sa in sa_info:
        gaps = sa.get("seq_gaps", [])
        for gap in gaps:
            if gap.get("type") == "duplicate":
                total_duplicates += 1
            else:
                total_gaps += 1
    
    if total_duplicates > 0:
        score -= min(30, total_duplicates * 10)
        findings.append({
            "id": "REPLAY-001",
            "title": "Duplicate Sequence Numbers Detected",
            "severity": SEVERITY_HIGH,
            "description": f"{total_duplicates} duplicate sequence numbers found. "
                           "This may indicate replay attacks or retransmissions.",
            "evidence": f"{total_duplicates} duplicate sequence numbers",
            "recommendation": "Verify anti-replay window is properly configured. "
                              "Investigate if duplicates are from legitimate retransmissions.",
        })
    
    if total_gaps > 5:
        score -= 5
        findings.append({
            "id": "REPLAY-002",
            "title": "Sequence Number Gaps Detected",
            "severity": SEVERITY_LOW,
            "description": f"{total_gaps} gaps in sequence numbers detected. "
                           "This may indicate packet loss.",
            "evidence": f"{total_gaps} sequence number gaps",
            "recommendation": "Monitor for persistent packet loss which may indicate network issues.",
        })
    
    if total_duplicates == 0 and total_gaps <= 5:
        score = 90
        findings.append({
            "id": "REPLAY-003",
            "title": "Sequence Numbers Consistent",
            "severity": SEVERITY_INFO,
            "description": "Sequence numbers appear consistent with no replay indicators.",
            "evidence": "Sequential sequence numbers with minimal gaps",
            "recommendation": "No issues detected.",
        })
    
    return {
        "score": max(0, min(100, score)),
        "rating": (
            "Critical" if score <= 30 else
            "Weak" if score <= 50 else
            "Good" if score <= 80 else
            "Excellent"
        ),
        "rationale": f"Duplicates: {total_duplicates}, Gaps: {total_gaps}",
        "details": {"duplicates": total_duplicates, "gaps": total_gaps},
        "findings": findings,
    }


def _assess_config(profile: dict, ike: dict, analysis: dict) -> dict[str, Any]:
    """Assess overall VPN configuration."""
    findings = []
    score = 70
    
    ike_version = profile.get("ike_version", "Not Observable")
    mode = profile.get("mode", "Not Observable")
    
    # IKEv1 vs IKEv2
    if ike_version == "IKEv1":
        score -= 15
        findings.append({
            "id": "CFG-001",
            "title": "IKEv1 Protocol Detected",
            "severity": SEVERITY_MEDIUM,
            "description": "IKEv1 has known weaknesses and lacks features present in IKEv2.",
            "evidence": f"IKE version: {ike_version}",
            "recommendation": "Migrate to IKEv2 for improved security and performance.",
        })
    elif ike_version == "IKEv2":
        score += 10
        findings.append({
            "id": "CFG-002",
            "title": "IKEv2 Protocol In Use",
            "severity": SEVERITY_INFO,
            "description": "IKEv2 is the current standard with improved security.",
            "evidence": f"IKE version: {ike_version}",
            "recommendation": "Good choice. Maintain IKEv2 configuration.",
        })
    
    # Tunnel vs Transport mode
    if mode == "Transport":
        findings.append({
            "id": "CFG-003",
            "title": "Transport Mode Detected",
            "severity": SEVERITY_LOW,
            "description": "Transport mode exposes original IP headers. "
                           "This is appropriate for host-to-host but not site-to-site.",
            "evidence": "USE_TRANSPORT_MODE notify detected",
            "recommendation": "Use Tunnel mode for site-to-site VPN to hide internal addressing.",
        })
    
    # Check for aggressive mode (IKEv1)
    if ike.get("detected"):
        exchange_types = ike.get("exchange_types", [])
        if "AGGRESSIVE" in exchange_types:
            score -= 20
            findings.append({
                "id": "CFG-004",
                "title": "IKEv1 Aggressive Mode Detected",
                "severity": SEVERITY_HIGH,
                "description": "Aggressive Mode transmits the identity in cleartext "
                               "and is vulnerable to offline dictionary attacks.",
                "evidence": "AGGRESSIVE exchange type in IKE packets",
                "recommendation": "Use Main Mode (Identity Protection) or migrate to IKEv2.",
            })
    
    # Check protocol types
    protocols = profile.get("ipsec_protocol", [])
    if "AH" in protocols and "ESP" not in protocols:
        score -= 10
        findings.append({
            "id": "CFG-005",
            "title": "AH Only - No Encryption",
            "severity": SEVERITY_HIGH,
            "description": "Only AH protocol detected. AH provides authentication "
                           "but no encryption.",
            "evidence": "Only AH protocol packets found",
            "recommendation": "Use ESP for both encryption and authentication.",
        })
    
    return {
        "score": max(0, min(100, score)),
        "rating": (
            "Weak" if score <= 40 else
            "Moderate" if score <= 60 else
            "Good" if score <= 80 else
            "Excellent"
        ),
        "rationale": f"IKE: {ike_version}, Mode: {mode}, Protocols: {protocols}",
        "details": {"ike_version": ike_version, "mode": mode, "protocols": protocols},
        "findings": findings,
    }


def _assess_metadata(profile: dict, nat: dict, analysis: dict) -> dict[str, Any]:
    """Assess metadata exposure and privacy."""
    findings = []
    score = 75
    
    mode = profile.get("mode", "Not Observable")
    nat_t = nat.get("detected", False)
    ip_analysis = analysis.get("ip_analysis", {})
    
    # Tunnel mode hides internal addresses
    if mode == "Transport":
        score -= 15
        findings.append({
            "id": "META-001",
            "title": "Internal IP Headers Exposed",
            "severity": SEVERITY_MEDIUM,
            "description": "Transport mode exposes original IP headers, "
                           "revealing internal network topology.",
            "evidence": "Transport mode detected",
            "recommendation": "Use Tunnel mode to encapsulate and hide internal addresses.",
        })
    elif mode == "Tunnel":
        score += 10
        findings.append({
            "id": "META-002",
            "title": "Internal Addressing Hidden",
            "severity": SEVERITY_INFO,
            "description": "Tunnel mode hides internal IP addresses from observers.",
            "evidence": "Tunnel mode detected",
            "recommendation": "Good practice.",
        })
    
    # NAT-T considerations
    if nat_t:
        findings.append({
            "id": "META-003",
            "title": "NAT Traversal Active",
            "severity": SEVERITY_LOW,
            "description": "NAT-T encapsulation detected. While functional, "
                           "this adds overhead and may reveal NAT topology.",
            "evidence": "UDP port 4500 encapsulation detected",
            "recommendation": "NAT-T is often necessary. Ensure IKE keepalives are configured.",
        })
    
    # IP pairs visible
    ip_pairs = ip_analysis.get("unique_ip_pairs", [])
    if len(ip_pairs) > 2:
        findings.append({
            "id": "META-004",
            "title": "Multiple Endpoint Pairs Visible",
            "severity": SEVERITY_LOW,
            "description": f"{len(ip_pairs)} unique IP pairs visible in the capture.",
            "evidence": f"{len(ip_pairs)} IP pairs observed",
            "recommendation": "External IP addresses are always visible. "
                              "Consider VPN concentrators to reduce exposed endpoints.",
        })
    
    return {
        "score": max(0, min(100, score)),
        "rating": (
            "Weak" if score <= 40 else
            "Moderate" if score <= 60 else
            "Good" if score <= 80 else
            "Excellent"
        ),
        "rationale": f"Mode: {mode}, NAT-T: {nat_t}",
        "details": {"mode": mode, "nat_t": nat_t, "ip_pairs": len(ip_pairs)},
        "findings": findings,
    }


def _generate_recommendations(categories: dict, profile: dict) -> list[dict]:
    """Generate prioritized recommendations based on assessment."""
    recommendations = []
    
    # Sort categories by score (worst first)
    sorted_cats = sorted(categories.items(), key=lambda x: x[1]["score"])
    
    for cat_name, cat_data in sorted_cats:
        score = cat_data["score"]
        if score < 70:
            priority = "High" if score < 50 else "Medium"
            for finding in cat_data.get("findings", []):
                if finding["severity"] in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
                    recommendations.append({
                        "priority": priority,
                        "category": cat_name.replace("_", " ").title(),
                        "finding_id": finding["id"],
                        "action": finding["recommendation"],
                        "impact": f"Improves {cat_name.replace('_', ' ')} score from {score}/100",
                    })
    
    return recommendations


def _get_assessment_basis(profile: dict) -> dict[str, str]:
    """Document what the assessment is based on."""
    basis = {}
    for key, value in profile.items():
        if isinstance(value, str) and "Not Observable" in value:
            basis[key] = "Score based on default assumption (50/100) due to missing data"
        elif isinstance(value, str) and value != "Not Observable":
            basis[key] = f"Score based on observed value: {value}"
        elif isinstance(value, bool):
            basis[key] = f"Observed: {'Yes' if value else 'No'}"
        elif isinstance(value, list):
            basis[key] = f"Observed: {', '.join(str(v) for v in value)}"
    return basis
