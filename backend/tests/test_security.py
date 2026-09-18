"""
Tests for the security assessment engine.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.security.scoring_engine import assess_security
from backend.security.threat_matrix import generate_threat_matrix


def _make_analysis(
    encryption="AES-GCM-256",
    integrity="NONE (AEAD)",
    dh_group="ECP-384",
    dh_group_number=20,
    ike_version="IKEv2",
    mode="Tunnel",
    pfs=True,
    nat_t=False,
    esp_detected=True,
    ike_detected=True,
):
    """Build a mock analysis result for testing."""
    return {
        "vpn_profile": {
            "ipsec_protocol": ["ESP"],
            "ike_version": ike_version,
            "mode": mode,
            "encryption": encryption,
            "integrity": integrity,
            "dh_group": dh_group,
            "dh_group_number": dh_group_number,
            "pfs": pfs,
            "nat_t": nat_t,
            "ip_version": "IPv4",
        },
        "ike_analysis": {
            "detected": ike_detected,
            "version": ike_version,
            "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"],
            "pfs_detected": {"detected": pfs, "reason": "test"},
        },
        "esp_analysis": {
            "detected": esp_detected,
            "packet_count": 100,
            "unique_spis": 2,
            "sa_info": [
                {"spi": "0x1234", "packet_count": 50, "duration": 30, "seq_gaps": []},
                {"spi": "0x5678", "packet_count": 50, "duration": 30, "seq_gaps": []},
            ],
        },
        "ah_analysis": {"detected": False},
        "nat_t_analysis": {"detected": nat_t},
        "ip_analysis": {"unique_ip_pairs": [{"src": "10.0.1.1", "dst": "10.0.2.1"}]},
    }


class TestSecurityScoring:
    def test_strong_config_high_score(self):
        analysis = _make_analysis()
        result = assess_security(analysis)
        assert result["overall_score"] >= 80, f"Strong config should score high, got {result['overall_score']}"

    def test_weak_crypto_low_score(self):
        analysis = _make_analysis(
            encryption="3DES-CBC", 
            integrity="HMAC-MD5-96", 
            ike_version="IKEv1", 
            dh_group="MODP-768", 
            dh_group_number=1, 
            pfs=False
        )
        result = assess_security(analysis)
        assert result["overall_score"] < 60, f"Weak crypto should score low, got {result['overall_score']}"

    def test_weak_dh_group(self):
        analysis = _make_analysis(dh_group="MODP-1024", dh_group_number=2)
        result = assess_security(analysis)
        ke_score = result["categories"]["key_exchange"]["score"]
        assert ke_score < 40, f"DH Group 2 should score low, got {ke_score}"

    def test_no_pfs_penalty(self):
        with_pfs = assess_security(_make_analysis(pfs=True))
        without_pfs = assess_security(_make_analysis(pfs=False))
        assert with_pfs["overall_score"] > without_pfs["overall_score"]

    def test_ikev1_penalty(self):
        v2 = assess_security(_make_analysis(ike_version="IKEv2"))
        v1 = assess_security(_make_analysis(ike_version="IKEv1"))
        assert v2["overall_score"] > v1["overall_score"]

    def test_not_observable_gets_default(self):
        analysis = _make_analysis(encryption="Not Observable", ike_detected=False)
        result = assess_security(analysis)
        assert result["categories"]["cryptographic_strength"]["score"] == 50

    def test_findings_generated(self):
        result = assess_security(_make_analysis())
        assert len(result["findings"]) > 0

    def test_findings_have_required_fields(self):
        result = assess_security(_make_analysis())
        for finding in result["findings"]:
            assert "id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert "description" in finding
            assert "recommendation" in finding

    def test_recommendations_generated(self):
        # Weak config should generate recommendations
        result = assess_security(_make_analysis(encryption="3DES-CBC", dh_group="MODP-1024", dh_group_number=2))
        assert len(result["recommendations"]) > 0

    def test_risk_level_assigned(self):
        result = assess_security(_make_analysis())
        assert result["risk_level"] in ["Low Risk", "Moderate Risk", "Elevated Risk", "High Risk", "Critical Risk"]

    def test_category_scores_bounded(self):
        result = assess_security(_make_analysis())
        for cat, data in result["categories"].items():
            assert 0 <= data["score"] <= 100, f"{cat} score out of bounds: {data['score']}"

    def test_replay_duplicate_detection(self):
        analysis = _make_analysis()
        analysis["esp_analysis"]["sa_info"][0]["seq_gaps"] = [
            {"seq": 5, "type": "duplicate", "note": "test"}
        ]
        result = assess_security(analysis)
        replay_score = result["categories"]["replay_protection"]["score"]
        assert replay_score < 75  # Should be penalized


class TestThreatMatrix:
    def test_threat_matrix_from_findings(self):
        findings = [
            {"id": "CRYPTO-002", "severity": "Critical", "title": "Weak encryption"},
            {"id": "KE-003", "severity": "Critical", "title": "Weak DH"},
        ]
        result = generate_threat_matrix(findings)
        assert result["threat_count"] > 0

    def test_threat_risk_scores_bounded(self):
        findings = [{"id": "CRYPTO-003", "severity": "High"}]
        result = generate_threat_matrix(findings)
        for threat in result["threats"]:
            assert 0 <= threat["risk_score"] <= 100
            assert 0 <= threat["likelihood"] <= 1
            assert 0 <= threat["impact"] <= 1

    def test_empty_findings_no_threats(self):
        result = generate_threat_matrix([])
        assert result["threat_count"] == 0

    def test_threat_has_mitre(self):
        findings = [{"id": "CFG-004", "severity": "High"}]
        result = generate_threat_matrix(findings)
        for threat in result["threats"]:
            assert "mitre_tactic" in threat


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
