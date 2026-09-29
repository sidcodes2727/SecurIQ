"""Decision-support layer: evidence chains, simulator, policy, fingerprint/drift, lab builds, replay evidence."""
import pytest
from fastapi.testclient import TestClient

from backend.analyzers.ipsec_analyzer import _replay_analysis
from backend.bootstrap import ensure_samples
from backend.intel.policy import DEFAULT_POLICY, evaluate_policy
from backend.main import app


@pytest.fixture(scope="module")
def client(trained_classifier):
    ensure_samples()
    return TestClient(app)


@pytest.fixture(scope="module")
def ids(client):
    out = {}
    for name in ("weak_ikev1_main_3des_md5", "strong_ikev2_gcm_ecp384_pfs", "moderate_ikev2_cbc_sha1_nopfs",
                 "replay_anomaly"):
        response = client.post(f"/api/analyze/{name}")
        assert response.status_code == 200, response.text
        out[name] = response.json()["analysis_id"]
    return out


def test_every_finding_has_a_complete_chain(client, ids):
    record = client.get(f"/api/analysis/{ids['weak_ikev1_main_3des_md5']}").json()
    chains = client.get(f"/api/intel/{ids['weak_ikev1_main_3des_md5']}").json()["chains"]
    for finding in record["security"]["findings"]:
        chain = chains[finding["id"]]
        assert chain["rule"]["statement"] and chain["rule"]["reference"]
        assert chain["risk"]["severity"] == finding["severity"] and chain["risk"]["impact"]
        assert chain["recommendation"] == finding["recommendation"]
    ke = chains["KE-001"]
    assert ke["parameters"][0]["value"] == "MODP-1024 (group 2)"
    assert ke["packets"][0]["frames"] and min(ke["packets"][0]["frames"]) >= 1  # Wireshark numbering


def test_posture_explanation_names_the_weaknesses(client, ids):
    posture = client.get(f"/api/intel/{ids['weak_ikev1_main_3des_md5']}").json()["posture"]
    assert posture["headline"] == "HIGH"
    texts = " ".join(e["text"] for e in posture["evidence"])
    assert "MODP-1024" in texts and "3DES" in texts
    assert posture["recommendations"]


def test_simulator_reproduces_current_and_improves_with_fixes(client, ids):
    aid = ids["weak_ikev1_main_3des_md5"]
    stored = client.get(f"/api/analysis/{aid}").json()["security"]["overall_score"]
    base = client.get(f"/api/simulator/{aid}/baseline").json()
    assert base["recommended"]["dh_group"] == 20 and base["recommended"]["pfs"] is True
    result = client.post(f"/api/simulator/{aid}", json={"changes": base["recommended"]}).json()
    assert result["valid"] and result["current"]["overall_score"] == stored
    assert result["proposed"]["overall_score"] > 90 > stored
    assert "KE-001" in result["resolved"] and not result["introduced"]
    dh = next(f for f in result["factors"] if f["key"] == "dh_group")
    assert dh["resolves"] == ["KE-001"] and dh["delta_if_removed"] > 0
    assert result["policy_before"]["counts"]["fail"] > result["policy_after"]["counts"]["fail"]


def test_simulator_rejects_impossible_configuration(client, ids):
    aid = ids["weak_ikev1_main_3des_md5"]
    result = client.post(f"/api/simulator/{aid}", json={"changes": {"ike_encryption": "AES-256-GCM-16"}}).json()
    assert not result["valid"] and "IKEv1" in result["problems"][0]


def test_verify_measures_the_fix(client, ids):
    aid = ids["weak_ikev1_main_3des_md5"]
    changes = client.get(f"/api/simulator/{aid}/baseline").json()["recommended"]
    response = client.post(f"/api/simulator/{aid}/verify", json={"changes": changes})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["after"]["score"] > body["before"]["score"] + 30
    assert body["after"]["identification_accuracy"] == 1.0
    assert "IKE_PROPOSALS=aes256gcm16-prfsha384-ecp384" in body["strongswan_profile"]


def test_policy_distinguishes_strong_from_weak(client, ids):
    strong = client.get(f"/api/policy/evaluate/{ids['strong_ikev2_gcm_ecp384_pfs']}").json()
    weak = client.get(f"/api/policy/evaluate/{ids['weak_ikev1_main_3des_md5']}").json()
    assert strong["counts"]["fail"] == 0 and weak["counts"]["fail"] >= 6
    esp_bits = next(r for r in strong["rows"] if r["key"] == "esp_bits")
    assert esp_bits["status"] == "unknown"  # ESP key length is never observable: not a pass


def test_policy_update_validation(client):
    assert client.post("/api/policy", json={"policy": {"bogus": 1}}).status_code == 422
    assert client.post("/api/policy", json={"policy": {"require_pfs": "yes"}}).status_code == 422
    saved = client.post("/api/policy", json={"policy": {"allowed_dh_groups": [19, 20]}}).json()["policy"]
    assert saved["allowed_dh_groups"] == [19, 20]
    assert client.post("/api/policy/reset").json()["policy"] == DEFAULT_POLICY


def test_fingerprint_is_stable_and_drift_is_directional(client, ids):
    again = client.post("/api/analyze/strong_ikev2_gcm_ecp384_pfs").json()["analysis_id"]
    fp1 = client.get(f"/api/intel/{ids['strong_ikev2_gcm_ecp384_pfs']}").json()["fingerprint"]
    fp2 = client.get(f"/api/intel/{again}").json()["fingerprint"]
    assert fp1["id"] == fp2["id"]
    drift = client.get(f"/api/drift/{ids['moderate_ikev2_cbc_sha1_nopfs']}?baseline={again}").json()
    assert drift["status"] == "degraded"
    changed = {c["key"]: c["direction"] for c in drift["changes"]}
    assert changed["dh_group"] == "degraded" and changed["pfs"] == "degraded"
    same = client.get(f"/api/drift/{again}?baseline={ids['strong_ikev2_gcm_ecp384_pfs']}").json()
    assert same["status"] == "no_drift"


def test_lab_build_round_trip(client):
    response = client.post("/api/lab/build", json={
        "config": {"ike_encryption": "AES-128-CBC", "ike_integrity": "HMAC-SHA1-96", "dh_group": 2,
                   "esp_suite": "aes128-sha1", "pfs": False},
        "traffic": [{"class": "voip", "seconds": 20}, {"class": "web", "seconds": 20}], "label": "test build"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["identification_accuracy"] == 1.0 and body["score"] <= 40
    ids_found = {f["id"] for f in client.get(f"/api/analysis/{body['analysis_id']}").json()["security"]["findings"]}
    assert {"KE-001", "PFS-001", "AUTH-005"} <= ids_found
    assert any(b["id"] == body["file_id"] for b in client.get("/api/lab/builds").json()["builds"])
    bad = client.post("/api/lab/build", json={"config": {"ike_version": "IKEv1", "ike_encryption": "AES-256-GCM-16"}})
    assert bad.status_code == 422


def test_metadata_and_surface(client, ids):
    intel = client.get(f"/api/intel/{ids['moderate_ikev2_cbc_sha1_nopfs']}").json()
    meta = intel["metadata"]
    assert 0 <= meta["metadata_privacy"] <= 100 and meta["statements"]
    kinds = {n["kind"] for n in intel["surface"]["nodes"]}
    assert {"gateway", "ike", "child"} <= kinds
    assert any(n["risks"] for n in intel["surface"]["nodes"])


def test_replay_events_carry_frames(client, ids):
    sas = client.get(f"/api/analysis/{ids['replay_anomaly']}").json()["ipsec_analysis"]["esp_analysis"]["sa_info"]
    events = [e for sa in sas for e in sa["replay"]["events"]]
    assert any(e["kind"] == "duplicate" for e in events) and any(e["kind"] == "reset" for e in events)
    assert all(e["frame"] >= 1 and e["seq"] in e["context"] for e in events)


def test_short_counter_reset_is_not_mistaken_for_replay():
    seqs = list(range(1, 60)) + list(range(1, 40))       # restart after only 59 packets, no new SPI
    result = _replay_analysis(seqs)
    assert result["counter_resets"] == 1 and result["duplicates"] == 0
    replayed = list(range(1, 60)) + [12] + list(range(60, 80))  # one injected old packet
    result = _replay_analysis(replayed)
    assert result["duplicates"] == 1 and result["counter_resets"] == 0


def test_window_reasoning_and_novelty(client, ids):
    windows = client.get(f"/api/analysis/{ids['moderate_ikev2_cbc_sha1_nopfs']}").json()["classification"]
    assert windows and all("reasoning" in w and w["reasoning"]["caveats"] for w in windows)
    assert all("novel" in w for w in windows)


def test_policy_on_empty_analysis_is_unknown_not_pass():
    result = evaluate_policy(DEFAULT_POLICY, {"profile": {}, "ike_analysis": {}, "esp_analysis": {}, "ah_analysis": {}})
    assert result["counts"]["pass"] == 0 and result["counts"]["fail"] == 0


# ---------------------------------------------------------------- fleet: explorer rows, link graph, triage

def test_fleet_objects_describe_each_capture(client, ids):
    rows = {r["analysis_id"]: r for r in client.get("/api/fleet/objects").json()["rows"]}
    weak = rows[ids["weak_ikev1_main_3des_md5"]]
    assert weak["ike_version"] == "IKEv1" and weak["dh_group"] == 2 and weak["pfs"] == "off"
    assert weak["policy_status"] == "Non-compliant" and weak["source"] == "testbed"
    assert any(f["id"] == "KE-001" for f in weak["findings"])
    strong = rows[ids["strong_ikev2_gcm_ecp384_pfs"]]
    assert strong["pfs"] == "on" and not any(f["severity"] in ("Critical", "High") for f in strong["findings"])


def test_link_graph_connects_shared_objects(client, ids):
    graph = client.get("/api/fleet/graph").json()
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert f"capture:{ids['weak_ikev1_main_3des_md5']}" in nodes
    ke = nodes["finding:KE-001"]
    assert ke["severity"] == "Critical" and ids["weak_ikev1_main_3des_md5"] in ke["captures"]
    gateways = [n for n in graph["nodes"] if n["type"] == "gateway"]
    assert gateways and all(len(g["captures"]) >= 1 for g in gateways)
    assert all(e["source"] in nodes and e["target"] in nodes for e in graph["edges"])


def test_triage_status_and_notes_persist(client, ids):
    items = client.get("/api/triage").json()["items"]
    key = next(i["key"] for i in items if i["analysis_id"] == ids["weak_ikev1_main_3des_md5"] and i["finding_id"] == "KE-001")
    assert client.post("/api/triage", json={"keys": [key], "status": "investigating", "note": "owner: netops"}).status_code == 200
    item = next(i for i in client.get("/api/triage").json()["items"] if i["key"] == key)
    assert item["status"] == "investigating" and item["note"] == "owner: netops"
    assert item["history"][-1]["from"] == "new" and item["history"][-1]["to"] == "investigating"
    assert client.post("/api/triage", json={"keys": [key], "status": "bogus"}).status_code == 422
    assert client.post("/api/triage", json={"keys": ["../../etc:KE-001"], "status": "resolved"}).status_code == 422
