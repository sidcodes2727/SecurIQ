"""HTTP API: upload hardening, analysis flow, reports and input validation."""
import io

import pytest
from fastapi.testclient import TestClient

from backend.bootstrap import ensure_samples
from backend.config import UPLOAD_DIR
from backend.main import app


@pytest.fixture(scope="module")
def client(trained_classifier):
    ensure_samples()
    return TestClient(app)  # no context manager: skip the background bootstrap thread


@pytest.fixture(scope="module")
def analysis_id(client):
    response = client.post("/api/analyze/ikev1_aggressive_psk_identity")
    assert response.status_code == 200, response.text
    return response.json()["analysis_id"]


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "healthy" and body["sample_files"] == 10


def test_sample_listing(client):
    samples = client.get("/api/upload/list").json()["samples"]
    assert {s["id"] for s in samples} >= {"strong_ikev2_gcm_ecp384_pfs", "misconfig_esp_null"}
    assert all("description" in s for s in samples)


class TestUploadHardening:
    def test_rejects_wrong_extension(self, client):
        r = client.post("/api/upload", files={"file": ("x.exe", b"MZ", "application/octet-stream")})
        assert r.status_code == 400

    def test_rejects_non_pcap_content(self, client):
        r = client.post("/api/upload", files={"file": ("x.pcap", b"not a capture at all", "application/octet-stream")})
        assert r.status_code == 400
        assert not any(p.name.endswith("x.pcap") for p in UPLOAD_DIR.iterdir())

    def test_path_traversal_name_is_neutralised(self, client, scenario_capture):
        path, _ = scenario_capture("misconfig_esp_null")
        r = client.post("/api/upload", files={"file": ("..\\..\\..\\evil.pcap", path.read_bytes(), "application/octet-stream")})
        assert r.status_code == 200
        stored = [p for p in UPLOAD_DIR.iterdir() if p.name.startswith(r.json()["file_id"])]
        assert len(stored) == 1 and stored[0].parent == UPLOAD_DIR
        assert ".." not in stored[0].name and "\\" not in stored[0].name

    def test_upload_then_analyze(self, client, scenario_capture):
        path, _ = scenario_capture("transport_ipv6_voip")
        upload = client.post("/api/upload", files={"file": ("voip.pcap", io.BytesIO(path.read_bytes()), "application/octet-stream")})
        file_id = upload.json()["file_id"]
        result = client.post(f"/api/analyze/{file_id}")
        assert result.status_code == 200
        record = client.get(f"/api/analysis/{result.json()['analysis_id']}").json()
        assert record["ground_truth"] is None  # uploads carry no ground truth
        assert record["ipsec_analysis"]["profile"]["mode"]["value"] == "Transport"


class TestAnalysisFlow:
    def test_analysis_record(self, client, analysis_id):
        record = client.get(f"/api/analysis/{analysis_id}").json()
        assert record["ground_truth"]["accuracy"] == 1.0
        assert "executive_report" not in record
        assert record["ai_confidence"]["overall"] > 0

    def test_security_endpoints(self, client, analysis_id):
        security = client.get(f"/api/security/{analysis_id}").json()
        assert security["risk_level"] and security["categories"]
        findings = client.get(f"/api/security/{analysis_id}/findings").json()
        assert findings["count"] == len(security["findings"])
        matrix = client.get(f"/api/security/{analysis_id}/threat-matrix").json()
        assert len(matrix["grid"]) == 5
        compliance = client.get(f"/api/security/{analysis_id}/compliance").json()
        assert set(compliance) == {"ietf", "nist", "cnsa"}

    def test_packets_pagination(self, client, analysis_id):
        page = client.get(f"/api/analysis/{analysis_id}/packets?limit=10000&offset=5").json()
        assert page["limit"] == 500 and page["offset"] == 5 and len(page["packets"]) <= 500

    def test_reports(self, client, analysis_id):
        executive = client.get(f"/api/reports/{analysis_id}/executive").json()
        assert executive["bottom_line"] and executive["top_recommendations"]
        html = client.get(f"/api/reports/{analysis_id}/executive.html")
        assert html.status_code == 200 and "Executive Summary" in html.text
        assert "vpnuser@corp.example" in client.get(f"/api/reports/{analysis_id}/technical.html").text
        export = client.get(f"/api/reports/{analysis_id}/export.json")
        assert "attachment" in export.headers["content-disposition"]

    def test_listing(self, client, analysis_id):
        analyses = client.get("/api/analyses").json()["analyses"]
        assert any(a["analysis_id"] == analysis_id and a["findings_count"] > 0 for a in analyses)

    def test_classification_endpoint(self, client, analysis_id):
        body = client.get(f"/api/ml/classify/{analysis_id}").json()
        assert body["traffic"]["windows"] == len(body["classification"])
        assert body["model_info"]["is_trained"]


class TestValidation:
    @pytest.mark.parametrize("url", ["/api/analysis/doesnotexist", "/api/security/..%2F..%2Fetc",
                                     "/api/reports/nope/executive.html"])
    def test_unknown_or_malformed_ids(self, client, url):
        assert client.get(url).status_code == 404

    def test_analyze_unknown_file(self, client):
        assert client.post("/api/analyze/..%2Fsecret").status_code == 404

    def test_capture_rejects_hostile_filter(self, client):
        r = client.post("/api/capture/start", json={"filter": "esp; rm -rf /", "duration": 1})
        assert r.status_code == 400

    def test_dataset_request_bounds(self, client):
        assert client.post("/api/dataset/generate", json={"count": 100000}).status_code == 422

    def test_matrix_describes_configuration_space(self, client):
        matrix = client.get("/api/testbed/matrix").json()
        assert len(matrix["esp_suites"]) >= 10 and "Transport" in matrix["modes"]
