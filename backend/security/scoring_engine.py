"""
Rule-based security assessment (PS §d).

Eight categories, each returning a score (0–100, or None when the capture holds
no evidence for it), a confidence, a rationale and findings. The overall score is
the confidence-weighted mean of the assessable categories; *coverage* reports how
much of the assessment rests on evidence. A single Critical (High) finding caps
the overall score at 40 (70): one broken control dominates the posture.
"""
from __future__ import annotations

from typing import Any

from backend.config import (
    SCORE_CAP_CRITICAL, SCORE_CAP_HIGH, SCORING_WEIGHTS, SEVERITY_CRITICAL, SEVERITY_HIGH,
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_ORDER,
)
from backend.security.compliance import evaluate_compliance
from backend.security.strength import dh_bits, effective_strength, encryption_bits, hash_bits

CATEGORY_LABELS = {
    "cryptographic_strength": "Cryptographic strength",
    "key_exchange": "Key exchange",
    "forward_secrecy": "Forward secrecy",
    "authentication_integrity": "Authentication & integrity",
    "sa_lifetime": "SA parameters & key lifetime",
    "replay_protection": "Replay protection",
    "configuration_compliance": "Configuration compliance",
    "metadata_exposure": "Metadata exposure",
}


def finding(fid: str, title: str, severity: str, description: str, evidence: str,
            recommendation: str, source: str = "observed", confidence: float = 1.0) -> dict[str, Any]:
    return {"id": fid, "title": title, "severity": severity, "description": description,
            "evidence": evidence, "recommendation": recommendation,
            "evidence_source": source, "confidence": round(confidence, 3)}


def _category(score: float | None, confidence: float, rationale: str, findings: list[dict],
              details: dict | None = None) -> dict[str, Any]:
    score = None if score is None else round(max(0.0, min(100.0, score)), 1)
    return {
        "score": score,
        "confidence": round(confidence if score is not None else 0.0, 3),
        "rating": _rating(score),
        "rationale": rationale,
        "findings": findings,
        "details": details or {},
    }


def _rating(score: float | None) -> str:
    if score is None:
        return "Not assessable"
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Moderate"
    if score >= 35:
        return "Weak"
    return "Critical"


def _ev(analysis: dict, key: str) -> dict[str, Any]:
    return (analysis.get("profile") or {}).get(key) or {"value": None, "source": "not_observable", "confidence": 0.0}


# ================================================================ entry point

def assess_security(analysis: dict[str, Any], classification: dict[str, Any] | None = None) -> dict[str, Any]:
    compliance = evaluate_compliance(analysis)
    categories = {
        "cryptographic_strength": _crypto(analysis),
        "key_exchange": _key_exchange(analysis),
        "forward_secrecy": _forward_secrecy(analysis),
        "authentication_integrity": _authentication(analysis),
        "sa_lifetime": _lifetime(analysis),
        "replay_protection": _replay(analysis),
        "configuration_compliance": _configuration(analysis, compliance),
        "metadata_exposure": _metadata(analysis, classification),
    }
    for key, cat in categories.items():
        cat["label"] = CATEGORY_LABELS[key]
        cat["weight"] = SCORING_WEIGHTS[key]

    weighted = [(SCORING_WEIGHTS[k] * c["confidence"], c["score"]) for k, c in categories.items()
                if c["score"] is not None and c["confidence"] > 0]
    total_weight = sum(w for w, _ in weighted)
    raw_score = sum(w * s for w, s in weighted) / total_weight if total_weight else None
    coverage = round(total_weight, 3)

    findings = [f for c in categories.values() for f in c["findings"]]
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    severities = {f["severity"] for f in findings}

    overall, cap_reason = raw_score, None
    if overall is not None:
        if SEVERITY_CRITICAL in severities and overall > SCORE_CAP_CRITICAL:
            overall, cap_reason = SCORE_CAP_CRITICAL, f"capped at {SCORE_CAP_CRITICAL}: Critical finding present"
        elif SEVERITY_HIGH in severities and overall > SCORE_CAP_HIGH:
            overall, cap_reason = SCORE_CAP_HIGH, f"capped at {SCORE_CAP_HIGH}: High finding present"
        overall = round(overall, 1)

    risk_level, risk_color = _risk_level(overall)
    return {
        "overall_score": overall,
        "uncapped_score": round(raw_score, 1) if raw_score is not None else None,
        "score_cap": cap_reason,
        "risk_score": round(100 - overall, 1) if overall is not None else None,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "coverage": coverage,
        "provisional": coverage < 0.5,
        "categories": categories,
        "findings": findings,
        "severity_counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER},
        "recommendations": _recommendations(findings),
        "compliance": compliance["profiles"],
        "effective_strength": _suite_strength(analysis),
        "scoring_weights": SCORING_WEIGHTS,
        "method": ("Confidence-weighted mean of assessable categories; categories without evidence are "
                   "excluded and reduce coverage instead of defaulting to a neutral score."),
    }


def _risk_level(score: float | None) -> tuple[str, str]:
    if score is None:
        return "Unknown", "grey"
    if score >= 85:
        return "Low Risk", "green"
    if score >= 70:
        return "Moderate Risk", "yellow"
    if score >= 50:
        return "Elevated Risk", "orange"
    if score >= 30:
        return "High Risk", "red"
    return "Critical Risk", "darkred"


# ================================================================ categories

def _cipher_assessment(name: str | None) -> tuple[float, str] | None:
    """(score, class) where class ∈ none / broken / legacy / cbc / aead."""
    bits, _ = encryption_bits(name)
    if bits is None:
        return None
    if bits == 0:
        return 0, "none"
    if bits < 80:
        return 5, "broken"
    if bits < 128:
        return 30, "legacy"
    aead = any(t in name.upper() for t in ("GCM", "CCM", "CHACHA", "AEAD"))
    if aead:
        return (100 if bits >= 256 else 97 if bits >= 192 else 93), "aead"
    return (90 if bits >= 256 else 88 if bits >= 192 else 85), "cbc"


CIPHER_FINDINGS = {
    "none": ("CRYPTO-001", "No confidentiality", SEVERITY_CRITICAL,
             "Tunnel payloads travel in cleartext and can be read by any on-path observer.",
             "Configure ESP with AES-GCM (e.g. aes256gcm16)."),
    "broken": ("CRYPTO-002", "Broken cipher", SEVERITY_CRITICAL,
               "Single DES and similar ciphers can be brute-forced.", "Replace with AES-256-GCM."),
    "legacy": ("CRYPTO-003", "Deprecated 64-bit block cipher", SEVERITY_HIGH,
               "3DES/Blowfish use 64-bit blocks (Sweet32 birthday attack) and TDEA encryption is disallowed "
               "by NIST SP 800-131A Rev. 2 after 2023.", "Migrate IKE and ESP to AES-GCM (aes256gcm16)."),
    "cbc": ("CRYPTO-004", "CBC-mode cipher with separate HMAC", SEVERITY_LOW,
            "AES-CBC + HMAC is secure but slower and more error-prone than authenticated encryption.",
            "Prefer AES-GCM or ChaCha20-Poly1305."),
    "aead": ("CRYPTO-005", "Authenticated encryption (AEAD)", SEVERITY_INFO,
             "Modern authenticated encryption.", "No change needed."),
}


def _merged(fid: str, title: str, severity: str, description: str, recommendation: str,
            subjects: list[tuple[str, dict]]) -> dict[str, Any]:
    """One finding covering every subject (IKE SA, ESP, …) that shares the same weakness."""
    names = "; ".join(f"{label} {ev['value']}" for label, ev in subjects)
    evidence = " | ".join(f"{label}: {ev.get('evidence', ev['value'])}" for label, ev in subjects)
    inferred = [ev for _, ev in subjects if ev["source"] != "observed"]
    source = "inferred" if len(inferred) == len(subjects) else "observed"
    confidence = min(ev["confidence"] for _, ev in subjects)
    return finding(fid, f"{title}: {names}", severity, description, evidence, recommendation, source, confidence)


def _crypto(analysis: dict) -> dict[str, Any]:
    parts = []
    for label, key in (("IKE SA", "ike_encryption"), ("ESP", "esp_encryption")):
        ev = _ev(analysis, key)
        assessed = _cipher_assessment(ev["value"]) if ev["value"] else None
        if assessed is not None:
            parts.append((label, ev, *assessed))

    if not parts:
        return _category(None, 0, "No encryption algorithm could be observed or inferred", [finding(
            "CRYPTO-007", "Encryption not observable", SEVERITY_INFO,
            "Neither the IKE SA suite nor the ESP framing revealed the cipher.",
            "No IKE_SA_INIT in capture and ESP fingerprint inconclusive",
            "Capture from before the tunnel comes up, and include varied traffic.", "not_observable", 0)])

    findings = []
    for cls in ("none", "broken", "legacy", "cbc", "aead"):
        subjects = [(label, ev) for label, ev, _, c in parts if c == cls]
        if subjects:
            fid, title, severity, description, recommendation = CIPHER_FINDINGS[cls]
            findings.append(_merged(fid, title, severity, description, recommendation, subjects))

    worst = min(parts, key=lambda p: p[2])
    confidence = sum(p[1]["confidence"] for p in parts) / len(parts)
    rationale = "; ".join(f"{label}: {ev['value']} → {score}" for label, ev, score, _ in parts)
    return _category(worst[2], confidence, f"Weakest cipher governs. {rationale}", findings)


def _key_exchange(analysis: dict) -> dict[str, Any]:
    ke = _ev(analysis, "key_exchange")
    group = ke.get("group")
    if not group:
        return _category(None, 0, "DH group not observable", [])
    bits = dh_bits(group) or 0
    findings = []
    name = ke["value"]
    if bits < 80:
        score = 5
        findings.append(finding("KE-001", f"Broken Diffie-Hellman group: {name}", SEVERITY_CRITICAL,
                                "Groups 1/2 are within reach of precomputation attacks (Logjam class).", ke["evidence"],
                                "Use ECP-384 (group 20) or Curve25519 (group 31).", ke["source"], ke["confidence"]))
    elif bits < 112:
        score = 25 if bits <= 80 else 40
        severity = SEVERITY_CRITICAL if bits <= 80 else SEVERITY_HIGH
        findings.append(finding("KE-002" if bits > 80 else "KE-001", f"Weak Diffie-Hellman group: {name}", severity,
                                f"≈{bits}-bit security, below the 112-bit minimum (NIST SP 800-57).", ke["evidence"],
                                "Use group 19/20/31 or MODP ≥ 3072.", ke["source"], ke["confidence"]))
    elif bits < 128:
        score = 72
        findings.append(finding("KE-003", f"112-bit key exchange: {name}", SEVERITY_LOW,
                                "MODP-2048 is acceptable until 2030 but not beyond.", ke["evidence"],
                                "Plan migration to ECP-384 / Curve25519.", ke["source"], ke["confidence"]))
    else:
        score = 100 if bits >= 192 else 90
        findings.append(finding("KE-004", f"Strong key exchange: {name}", SEVERITY_INFO,
                                f"≈{bits}-bit security.", ke["evidence"], "No change needed.", ke["source"]))

    findings.append(finding("KE-005", "Classical key exchange only (quantum harvest-now-decrypt-later)", SEVERITY_LOW,
                            "All negotiated groups are classical; recorded traffic could be decrypted by a future "
                            "cryptographically relevant quantum computer.", f"DH group {group}",
                            "Plan hybrid post-quantum key exchange (RFC 9370 with ML-KEM) for long-lived secrets.",
                            ke["source"], ke["confidence"]))

    ike = analysis.get("ike_analysis", {})
    surface = ike.get("downgrade_surface") or []
    if surface:
        score -= 10
        findings.append(finding("KE-006", "Weak fallback algorithms offered (downgrade surface)", SEVERITY_MEDIUM,
                                "The initiator's cleartext proposal includes algorithms weaker than the one selected; "
                                "a responder that is misconfigured or compromised can force them.",
                                ", ".join(surface), "Remove legacy proposals from the initiator configuration."))
    if any(n["type"] == 17 for n in ike.get("negotiation_errors", [])):
        findings.append(finding("KE-007", "DH group renegotiated (INVALID_KE_PAYLOAD)", SEVERITY_INFO,
                                "The responder rejected the initiator's first key-exchange group.",
                                "INVALID_KE_PAYLOAD notify", "Align DH group preferences on both peers."))
    return _category(score, ke["confidence"], f"{name}: ≈{bits}-bit security"
                     + (f"; downgrade surface {surface}" if surface else ""), findings, {"bits": bits})


def _forward_secrecy(analysis: dict) -> dict[str, Any]:
    pfs = _ev(analysis, "pfs")
    if pfs["value"] is None:
        return _category(None, 0, pfs.get("evidence", "PFS not observable"), [finding(
            "PFS-003", "PFS not observable in this capture", SEVERITY_INFO, pfs.get("evidence", ""),
            "No Child SA rekey / Quick Mode captured",
            "Capture at least one rekey interval (or shorten rekey_time in the lab) to assess PFS.",
            "not_observable", 0)])
    if pfs["value"]:
        return _category(100, pfs["confidence"], pfs["evidence"], [finding(
            "PFS-002", "Perfect Forward Secrecy enabled", SEVERITY_INFO,
            "Each Child SA rekey runs a fresh Diffie-Hellman exchange.", pfs["evidence"],
            "No change needed.", pfs["source"], pfs["confidence"])])
    return _category(35, pfs["confidence"], pfs["evidence"], [finding(
        "PFS-001", "Perfect Forward Secrecy disabled", SEVERITY_MEDIUM,
        "Child SA keys derive from the IKE SA key material: compromising one IKE SA exposes every "
        "Child SA it created.", pfs["evidence"],
        "Add a DH group to the ESP proposal (e.g. esp_proposals = aes256gcm16-ecp384).",
        pfs["source"], pfs["confidence"])])


def _authentication(analysis: dict) -> dict[str, Any]:
    findings, parts = [], []
    auth = _ev(analysis, "authentication_method")
    aggressive = _ev(analysis, "exchange_mode")["value"] == "Aggressive Mode"
    if auth["value"]:
        value = auth["value"]
        psk = auth.get("psk") or "Pre-Shared" in value
        if psk and aggressive:
            score = 15
            findings.append(finding("AUTH-001", "Aggressive Mode with Pre-Shared Key", SEVERITY_HIGH,
                                    "The responder's HASH_R is sent in cleartext; an eavesdropper can crack the PSK "
                                    "offline (ike-scan / psk-crack) and then impersonate either gateway.",
                                    auth["evidence"], "Disable Aggressive Mode; move to IKEv2 with certificates.",
                                    auth["source"], auth["confidence"]))
        elif psk:
            score = 65
            findings.append(finding("AUTH-002", "Pre-Shared Key authentication", SEVERITY_LOW,
                                    "PSK security depends entirely on key entropy and distribution hygiene.",
                                    auth["evidence"], "Use certificates, or PSKs of ≥ 32 random characters.",
                                    auth["source"], auth["confidence"]))
        else:
            score = 95 if "Certificate" in value or "Signature" in value else 88
            findings.append(finding("AUTH-003", f"{value} authentication", SEVERITY_INFO,
                                    "Public-key or EAP based peer authentication.", auth["evidence"],
                                    "Keep certificate lifetimes short and revocation checking enabled.",
                                    auth["source"], auth["confidence"]))
        parts.append((score, auth["confidence"]))

    integ_scores, md5, sha1 = [], [], []
    for label, key in (("IKE SA", "ike_integrity"), ("ESP", "esp_integrity")):
        ev = _ev(analysis, key)
        if not ev["value"]:
            continue
        upper = ev["value"].upper()
        if "MD5" in upper:
            md5.append((label, ev))
            integ_scores.append((25, ev["confidence"]))
        elif "SHA1" in upper:
            sha1.append((label, ev))
            integ_scores.append((70, ev["confidence"]))
        else:
            integ_scores.append((100, ev["confidence"]))
    if md5:
        findings.append(_merged("AUTH-004", "MD5-based integrity", SEVERITY_HIGH,
                                "HMAC-MD5 is prohibited by RFC 8221 / RFC 8247.",
                                "Use HMAC-SHA2-256-128 or an AEAD cipher.", md5))
    if sha1:
        findings.append(_merged("AUTH-005", "SHA-1 based integrity", SEVERITY_LOW,
                                "HMAC-SHA1 remains unbroken but is being phased out (MUST- in RFC 8221 / 8247).",
                                "Move to HMAC-SHA2-256-128 or AEAD.", sha1))
    if integ_scores:
        parts.append(min(integ_scores))

    if not parts:
        return _category(None, 0, "Authentication and integrity not observable", findings)
    score = min(p[0] for p in parts)
    confidence = sum(p[1] for p in parts) / len(parts)
    return _category(score, confidence, f"Weakest of authentication ({auth['value']}) and integrity", findings)


def _lifetime(analysis: dict) -> dict[str, Any]:
    findings, scores = [], []
    ike_life = _ev(analysis, "ike_lifetime")
    child = _ev(analysis, "child_sa_lifetime")
    if ike_life["value"]:
        seconds = ike_life["value"]
        if seconds > 7 * 86400:
            score, severity = 25, SEVERITY_HIGH
        elif seconds > 86400:
            score, severity = 50, SEVERITY_MEDIUM
        else:
            score, severity = 95, SEVERITY_INFO
        if severity != SEVERITY_INFO:
            findings.append(finding("LIFE-001", f"Long IKE SA lifetime: {seconds / 3600:.0f} h", severity,
                                    "Long-lived keying material widens the window for key compromise and cryptanalysis.",
                                    ike_life["evidence"], "Set the IKE SA lifetime to ≤ 24 h (NIST SP 800-77r1).",
                                    ike_life["source"], ike_life["confidence"]))
        else:
            findings.append(finding("LIFE-003", "IKE SA lifetime within guidance", SEVERITY_INFO,
                                    f"{seconds} s ≤ 24 h.", ike_life["evidence"], "No change needed.",
                                    ike_life["source"], ike_life["confidence"]))
        scores.append((score, ike_life["confidence"]))
    if child["value"]:
        score = 95 if child["value"] <= 28800 else 60
        scores.append((score, child["confidence"]))
    elif child.get("lower_bound_seconds", 0) and child["lower_bound_seconds"] > 28800:
        findings.append(finding("LIFE-002", "Child SA not rekeyed within 8 h", SEVERITY_LOW,
                                "ESP keys were used longer than the recommended lifetime.", child["evidence"],
                                "Set Child SA rekey_time ≤ 8 h.", "inferred", 0.7))
        scores.append((60, 0.7))

    replay = (analysis.get("esp_analysis") or {}).get("replay_summary") or {}
    if replay.get("near_exhaustion"):
        findings.append(finding("LIFE-004", "Sequence number near 2^32 exhaustion", SEVERITY_MEDIUM,
                                "Without ESN the SA must be rekeyed before the 32-bit counter wraps.",
                                "Sequence numbers ≥ 0xF0000000", "Enable ESN or lower the Child SA byte lifetime.",
                                "observed", 1.0))
        scores.append((40, 1.0))
    if not scores:
        return _category(None, 0, "No lifetime or rekey evidence in capture", [finding(
            "LIFE-005", "Key lifetimes not observable", SEVERITY_INFO,
            "IKEv2 lifetimes are local policy and no rekey occurred during the capture.",
            f"IKE: {ike_life.get('evidence')}; Child: {child.get('evidence')}",
            "Capture for longer than the rekey interval.", "not_observable", 0)] + findings)
    score = min(s for s, _ in scores)
    confidence = sum(c for _, c in scores) / len(scores)
    rationale = (f"IKE lifetime: {ike_life.get('display') or ike_life.get('value') or 'n/a'}; "
                 f"Child SA: {child.get('display') or child.get('value') or 'n/a'}")
    return _category(score, confidence, rationale, findings)


def _replay(analysis: dict) -> dict[str, Any]:
    ev = _ev(analysis, "replay_protection")
    if ev["value"] is None:
        return _category(None, 0, "No ESP/AH traffic", [])
    summary = ev.get("summary") or {}
    findings, score = [], 92
    if summary.get("duplicates"):
        score = min(score, 40)
        findings.append(finding("REPLAY-001", "Duplicate ESP sequence numbers", SEVERITY_HIGH,
                                "The same (SPI, sequence) pair appeared more than once — a replayed or duplicated "
                                "packet. A receiver with anti-replay enabled must drop it.",
                                f"{summary['duplicates']} duplicates", "Verify anti-replay is enabled "
                                "(replay_window) and investigate the source of the duplicates.", "observed", 0.9))
    if summary.get("counter_resets"):
        score = min(score, 35)
        findings.append(finding("REPLAY-002", "Sequence counter reset without rekey", SEVERITY_HIGH,
                                "RFC 4303 forbids the counter from cycling within an SA when anti-replay is on; "
                                "this suggests anti-replay is disabled or manual keying.",
                                f"{summary['counter_resets']} reset(s)", "Use IKE-negotiated SAs with anti-replay "
                                "enabled.", "inferred", 0.8))
    if summary.get("beyond_default_window"):
        score = min(score, 80)
        findings.append(finding("REPLAY-003", "Reordering beyond a 64-packet replay window", SEVERITY_LOW,
                                "Legitimate packets this late are dropped by a default-sized window.",
                                f"max reorder depth {summary.get('max_reorder_depth')}",
                                "Increase replay_window (e.g. 128–1024) on high-throughput links.", "observed", 0.9))
    if not findings:
        findings.append(finding("REPLAY-004", "Sequence numbers consistent", SEVERITY_INFO,
                                "Monotonic per-SA counters with no duplicates or resets.", ev["evidence"],
                                "No change needed.", "inferred", ev["confidence"]))
    return _category(score, ev["confidence"], ev["evidence"], findings, summary)


def _configuration(analysis: dict, compliance: dict) -> dict[str, Any]:
    findings = []
    profile = analysis.get("profile", {})
    version = (profile.get("ike_version") or {}).get("value")
    if version == "IKEv1":
        findings.append(finding("CFG-001", "IKEv1 in use", SEVERITY_MEDIUM,
                                "IKEv1 is deprecated (RFC 9395) and lacks IKEv2's DoS protection and robustness.",
                                "IKE major version 1", "Migrate to IKEv2."))
    elif version == "IKEv2":
        findings.append(finding("CFG-002", "IKEv2 in use", SEVERITY_INFO, "Current IKE version.",
                                "IKE major version 2", "No change needed."))
    mode = profile.get("mode") or {}
    if mode.get("value") == "Transport":
        findings.append(finding("CFG-003", "Transport mode", SEVERITY_LOW,
                                "Suitable for host-to-host; site-to-site gateways should use tunnel mode.",
                                mode.get("evidence", ""), "Use tunnel mode between gateways.",
                                mode.get("source", "observed"), mode.get("confidence", 1.0)))
    ike = analysis.get("ike_analysis", {})
    errors = [n["name"] for n in ike.get("negotiation_errors", []) if n["type"] != 17]
    if errors:
        findings.append(finding("CFG-004", "IKE negotiation errors observed", SEVERITY_LOW,
                                "Failed negotiations indicate mismatched or probing peers.", ", ".join(errors),
                                "Align proposals; investigate unexpected peers."))
    if ike.get("cookie_challenge"):
        findings.append(finding("CFG-006", "IKEv2 cookie challenge observed", SEVERITY_INFO,
                                "The responder is using stateless cookies (DoS protection).", "COOKIE notify",
                                "No change needed."))

    scored = [p for key, p in compliance["profiles"].items() if key in ("ietf", "nist") and p["score"] is not None]
    if not scored:
        return _category(None, 0, "Not enough evidence for compliance checks", findings)
    score = sum(p["score"] for p in scored) / len(scored)
    coverage = sum(p["coverage"] for p in scored) / len(scored)
    failed = [c for p in scored for c in p["checks"] if c["status"] == "fail"]
    if failed:
        findings.append(finding("CFG-005", f"{len(failed)} compliance check(s) failed", SEVERITY_MEDIUM,
                                "The configuration violates published IETF / NIST guidance.",
                                "; ".join(f"{c['id']}: {c['evidence']}" for c in failed[:6]),
                                "See the compliance section for each failed control."))
    rationale = ", ".join(f"{p['name']}: {p['score']}% ({p['status']})" for p in scored)
    return _category(score, coverage, rationale, findings)


def _metadata(analysis: dict, classification: dict | None) -> dict[str, Any]:
    findings, score = [], 100.0
    ike = analysis.get("ike_analysis", {})
    profile = analysis.get("profile", {})

    exposed = [i for i in ike.get("identities", [])]
    if exposed:
        score -= 40
        values = ", ".join(f"{i['id_type']} {i['value']}" for i in exposed[:4])
        findings.append(finding("META-001", "Peer identities disclosed in cleartext", SEVERITY_HIGH,
                                "Identity payloads were sent unencrypted (IKEv1 Aggressive Mode), revealing "
                                "user or gateway names to any observer.", values,
                                "Use Main Mode / IKEv2, where identities are encrypted."))
    products = [v["name"] for v in ike.get("vendor_ids", []) if v.get("reveals_implementation")]
    if products:
        score -= 8
        findings.append(finding("META-002", "VPN implementation fingerprinted via Vendor ID", SEVERITY_LOW,
                                "Cleartext Vendor ID payloads reveal the product, helping attackers pick exploits.",
                                ", ".join(products), "Disable sending vendor IDs where the product allows it."))
    if classification and classification.get("mean_confidence") is not None and classification.get("windows"):
        conf = classification["mean_confidence"]
        mix = ", ".join(f"{c} {int(v * 100)}%" for c, v in list(classification.get("mix", {}).items())[:3])
        if conf >= 0.8:
            score -= 20
            severity = SEVERITY_MEDIUM
        elif conf >= 0.6:
            score -= 10
            severity = SEVERITY_LOW
        else:
            severity = None
        if severity:
            findings.append(finding("META-003", "Tunnel traffic type inferable from sizes and timing", severity,
                                    f"The AI classifier identified the traffic inside ESP with {conf:.0%} mean "
                                    "confidence, so encryption hides content but not activity.", mix,
                                    "Enable TFC padding / traffic shaping for sensitive tunnels (RFC 4303 §2.7).",
                                    "inferred", conf))
    mode = profile.get("mode") or {}
    if mode.get("value") == "Transport":
        score -= 10
        findings.append(finding("META-005", "Transport mode exposes true endpoints", SEVERITY_LOW,
                                "Outer headers are the communicating hosts themselves, revealing who talks to whom.",
                                mode.get("evidence", ""), "Tunnel mode between gateways hides inner addressing.",
                                mode.get("source", "observed"), mode.get("confidence", 1.0)))
    nat = profile.get("nat_traversal") or {}
    if nat.get("value"):
        score -= 3
        findings.append(finding("META-004", "NAT traversal in use", SEVERITY_INFO,
                                "UDP 4500 encapsulation reveals that a peer sits behind NAT.", nat.get("evidence", ""),
                                "Expected for remote-access clients."))
    if ike.get("certreq_seen"):
        findings.append(finding("META-006", "Certificate request reveals trusted CA", SEVERITY_INFO,
                                "CERTREQ in IKE_SA_INIT carries CA key hashes in cleartext.", "CERTREQ payload",
                                "Accept as inherent to IKEv2 certificate auth."))
    return _category(score, 0.85, "Deductions for disclosed identities, fingerprints, inferable traffic and "
                     "addressing", findings)


# ================================================================ helpers

def _suite_strength(analysis: dict) -> dict[str, Any]:
    chosen = (analysis.get("ike_analysis") or {}).get("chosen_suite") or {}
    esp_enc = _ev(analysis, "esp_encryption")["value"]
    esp_bits, esp_note = encryption_bits(esp_enc)
    if "assumed" in esp_note:
        esp_bits = None  # an assumed key length must not become the weakest link
    components = {
        "IKE encryption": (chosen.get("encryption"), encryption_bits(chosen.get("encryption"))[0]),
        "Key exchange": (chosen.get("dh_group_name"), dh_bits(chosen.get("dh_group"))),
        "PRF": (chosen.get("prf"), hash_bits(chosen.get("prf"))),
        "ESP encryption": (esp_enc, esp_bits),
    }
    result = effective_strength(components)
    if "assumed" in esp_note:
        result["note"] = "ESP key length is not observable on the wire; ESP excluded from the weakest-link bound"
    return result


def _recommendations(findings: list[dict]) -> list[dict[str, Any]]:
    priority = {SEVERITY_CRITICAL: "Immediate", SEVERITY_HIGH: "High", SEVERITY_MEDIUM: "Medium", SEVERITY_LOW: "Low"}
    seen, recs = set(), []
    for f in findings:
        if f["severity"] not in priority or f["recommendation"] in seen:
            continue
        seen.add(f["recommendation"])
        recs.append({"priority": priority[f["severity"]], "finding_id": f["id"], "title": f["title"],
                     "action": f["recommendation"], "severity": f["severity"]})
    return recs
