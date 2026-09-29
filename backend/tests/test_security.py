"""Security scoring, compliance, threat matrix and AI confidence."""
import pytest

from backend.analyzers.ipsec_analyzer import analyze_ipsec
from backend.analyzers.pcap_parser import parse_pcap
from backend.security.compliance import evaluate_compliance
from backend.security.confidence import compute_ai_confidence
from backend.security.scoring_engine import assess_security
from backend.security.strength import dh_bits, effective_strength, encryption_bits
from backend.security.threat_matrix import generate_threat_matrix


@pytest.fixture(scope="module")
def assessed(scenario_capture):
    cache = {}

    def run(name):
        if name not in cache:
            path, _ = scenario_capture(name)
            analysis = analyze_ipsec(parse_pcap(str(path)))
            cache[name] = (analysis, assess_security(analysis))
        return cache[name]
    return run


def test_strong_config_scores_higher_than_weak(assessed):
    strong = assessed("strong_ikev2_gcm_ecp384_pfs")[1]["overall_score"]
    moderate = assessed("moderate_ikev2_cbc_sha1_nopfs")[1]["overall_score"]
    weak = assessed("weak_ikev1_main_3des_md5")[1]["overall_score"]
    assert strong > moderate > weak
    assert strong >= 85 and weak < 50


def test_critical_finding_caps_score(assessed):
    security = assessed("misconfig_esp_null")[1]
    assert any(f["id"] == "CRYPTO-001" and f["severity"] == "Critical" for f in security["findings"])
    assert security["overall_score"] <= 40
    assert security["score_cap"] and security["uncapped_score"] > security["overall_score"]


def test_unobservable_categories_reduce_coverage_not_score(assessed):
    security = assessed("natt_ikev2_chacha_eap")[1]
    assert security["categories"]["forward_secrecy"]["score"] is None
    assert security["categories"]["forward_secrecy"]["rating"] == "Not assessable"
    assert security["coverage"] < assessed("strong_ikev2_gcm_ecp384_pfs")[1]["coverage"]


def test_findings_have_unique_ids(assessed):
    for name in ("weak_ikev1_main_3des_md5", "moderate_ikev2_cbc_sha1_nopfs"):
        ids = [f["id"] for f in assessed(name)[1]["findings"]]
        assert len(ids) == len(set(ids)), ids


def test_aggressive_mode_findings(assessed):
    ids = {f["id"] for f in assessed("ikev1_aggressive_psk_identity")[1]["findings"]}
    assert {"AUTH-001", "META-001", "CFG-001"} <= ids


def test_compliance_profiles(assessed):
    strong = evaluate_compliance(assessed("strong_ikev2_gcm_ecp384_pfs")[0])["profiles"]
    weak = evaluate_compliance(assessed("weak_ikev1_main_3des_md5")[0])["profiles"]
    assert strong["ietf"]["status"] == "Compliant"
    assert weak["ietf"]["status"] == "Non-compliant" and weak["nist"]["status"] == "Non-compliant"
    failed = {c["id"] for c in weak["nist"]["checks"] if c["status"] == "fail"}
    assert {"NIST-1", "NIST-3", "NIST-5"} <= failed


def test_threat_matrix_grid(assessed):
    tm = generate_threat_matrix(assessed("ikev1_aggressive_psk_identity")[1]["findings"])
    psk = next(t for t in tm["threats"] if t["id"] == "psk_cracking")
    assert psk["risk_score"] == psk["likelihood"] * psk["impact"] >= 16
    assert "psk_cracking" in tm["grid"][psk["likelihood"] - 1][psk["impact"] - 1]
    assert tm["threats"] == sorted(tm["threats"], key=lambda t: t["risk_score"], reverse=True)


def test_ai_confidence_parts(assessed):
    analysis, security = assessed("strong_ikev2_gcm_ecp384_pfs")
    confidence = compute_ai_confidence(analysis, {"mean_confidence": 0.9, "windows": 5}, security)
    assert 0 < confidence["overall"] <= 1
    assert confidence["fields_observed"] + confidence["fields_inferred"] + confidence["fields_not_observable"] == \
        confidence["fields_total"]
    without = compute_ai_confidence(analysis, None, security)
    assert without["classification"] is None


@pytest.mark.parametrize("name,bits", [("AES-256-GCM-16", 256), ("AES-128-CBC", 128), ("3DES-CBC", 112),
                                       ("DES-CBC", 56), ("NULL (no encryption)", 0), ("ChaCha20-Poly1305", 256)])
def test_encryption_bits(name, bits):
    assert encryption_bits(name)[0] == bits


def test_inferred_family_does_not_overclaim_key_length():
    bits, note = encryption_bits("AES-GCM / ChaCha20-Poly1305 (AEAD)")
    assert bits == 128 and "assumed" in note


def test_effective_strength_weakest_link():
    result = effective_strength({"enc": ("AES-256-CBC", 256), "kx": ("MODP-1024", dh_bits(2))})
    assert result["bits"] == 80 and "MODP-1024" in result["limited_by"]
