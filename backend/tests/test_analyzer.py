"""IPsec analyzer against testbed ground truth."""
import pytest

from backend.analyzers.ipsec_analyzer import analyze_ipsec
from backend.analyzers.pcap_parser import parse_pcap
from backend.pipeline import compare_with_truth
from backend.testbed.scenarios import SAMPLE_SCENARIOS


def _analyze(scenario_capture, name):
    path, truth = scenario_capture(name)
    return analyze_ipsec(parse_pcap(str(path))), truth


# Mode may legitimately abstain: with AES-CBC padding a transport ACK (TCP timestamps) and a tunnelled
# ACK are the same size, and constant-size traffic (VoIP, ping) has no ACK clock to measure.
MAY_ABSTAIN = {"Tunnel / transport mode"}


@pytest.mark.parametrize("name", [sc.name for sc in SAMPLE_SCENARIOS])
def test_identification_matches_ground_truth(scenario_capture, name):
    analysis, truth = _analyze(scenario_capture, name)
    comparison = compare_with_truth(analysis, {}, [], truth)
    wrong = [row for row in comparison["rows"] if row["status"] == "wrong"]
    assert not wrong, wrong
    abstained = [row["field"] for row in comparison["rows"]
                 if row["status"] == "abstained" and row["observable"] and row["field"] not in MAY_ABSTAIN]
    assert not abstained, f"observable fields left undetermined: {abstained}"


@pytest.mark.parametrize("name,mode", [
    ("strong_ikev2_gcm_ecp384_pfs", "Tunnel"),
    ("transport_ipv6_voip", "Transport"),
    ("weak_ikev1_main_3des_md5", "Tunnel"),   # decided thanks to the IKE SA integrity ICV hint
    ("ah_transport_integrity_only", "Transport"),
])
def test_mode_decided_where_the_capture_allows(scenario_capture, name, mode):
    analysis, _ = _analyze(scenario_capture, name)
    assert analysis["profile"]["mode"]["value"] == mode


def test_mode_abstains_instead_of_guessing(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "ikev1_aggressive_psk_identity")  # VoIP only: no ACK clock
    mode = analysis["profile"]["mode"]
    assert mode["value"] is None and mode["source"] == "not_observable"
    assert "no ACK-like small packets" in mode["evidence"]


def test_every_profile_field_is_an_evidence_record(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "strong_ikev2_gcm_ecp384_pfs")
    for key, record in analysis["profile"].items():
        assert {"value", "source", "confidence", "evidence"} <= set(record), key
        assert record["source"] in ("observed", "inferred", "not_observable")
        assert 0.0 <= record["confidence"] <= 1.0


def test_ike_sa_suite_is_observed_but_esp_suite_inferred(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "strong_ikev2_gcm_ecp384_pfs")
    assert analysis["profile"]["ike_encryption"]["source"] == "observed"
    assert analysis["profile"]["esp_encryption"]["source"] == "inferred"
    assert "Key length is not observable" in analysis["profile"]["esp_encryption"]["evidence"]


def test_aggressive_mode_exposes_identity(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "ikev1_aggressive_psk_identity")
    values = [i["value"] for i in analysis["ike_analysis"]["identities"]]
    assert "vpnuser@corp.example" in values
    assert analysis["profile"]["authentication_method"]["source"] == "observed"


def test_downgrade_surface_excludes_selected_suite(scenario_capture):
    moderate, _ = _analyze(scenario_capture, "moderate_ikev2_cbc_sha1_nopfs")
    assert set(moderate["ike_analysis"]["downgrade_surface"]) >= {"3DES-CBC", "MODP-1024"}
    weak, _ = _analyze(scenario_capture, "weak_ikev1_main_3des_md5")
    assert weak["ike_analysis"]["downgrade_surface"] == []


@pytest.mark.parametrize("name,expected", [
    ("strong_ikev2_gcm_ecp384_pfs", True),
    ("moderate_ikev2_cbc_sha1_nopfs", False),
    ("weak_ikev1_main_3des_md5", False),
    ("natt_ikev2_chacha_eap", None),  # no rekey captured → not observable
])
def test_pfs_inference(scenario_capture, name, expected):
    analysis, _ = _analyze(scenario_capture, name)
    pfs = analysis["profile"]["pfs"]
    assert pfs["value"] is expected
    if expected is None:
        assert pfs["source"] == "not_observable"


def test_lifetimes(scenario_capture):
    weak, _ = _analyze(scenario_capture, "weak_ikev1_main_3des_md5")
    assert weak["profile"]["ike_lifetime"]["value"] == 604800
    strong, _ = _analyze(scenario_capture, "strong_ikev2_gcm_ecp384_pfs")
    assert strong["profile"]["child_sa_lifetime"]["source"] == "inferred"
    assert 15 <= strong["profile"]["child_sa_lifetime"]["value"] <= 25


def test_ah_mode_and_integrity_observed(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "ah_transport_integrity_only")
    mode = analysis["profile"]["mode"]
    assert mode["value"] == "Transport" and mode["source"] == "observed"
    assert analysis["ah_analysis"]["icv_len"] == 16


def test_nat_traversal(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "natt_ikev2_chacha_eap")
    nat = analysis["nat_t_analysis"]
    assert nat["detected"] and nat["nat_t_ike_packets"] > 0 and nat["keepalives"] > 0


def test_replay_anomalies(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "replay_anomaly")
    summary = analysis["esp_analysis"]["replay_summary"]
    assert summary["duplicates"] > 0 and summary["counter_resets"] == 1


def test_esp_null_detected(scenario_capture):
    analysis, _ = _analyze(scenario_capture, "misconfig_esp_null")
    assert analysis["profile"]["esp_encryption"]["value"] == "NULL (no encryption)"


def test_analysis_is_json_serialisable(scenario_capture):
    import json
    analysis, _ = _analyze(scenario_capture, "mixed_all_traffic_ikev2")
    json.dumps(analysis)
