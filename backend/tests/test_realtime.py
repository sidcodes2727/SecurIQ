"""Real-time engine: parity with the batch pipeline, event stream, sources and API."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from backend.analyzers.flow_extractor import extract_flow_features
from backend.analyzers.pcap_parser import parse_pcap
from backend.bootstrap import ensure_samples
from backend.main import app
from backend.realtime.engine import LiveSession
from backend.realtime.sources import ReplaySource, open_interface_source


def _run(session: LiveSession, timeout: float = 60) -> LiveSession:
    session.start()
    deadline = time.monotonic() + timeout
    while session.status in ("starting", "running", "finalizing") and time.monotonic() < deadline:
        time.sleep(0.1)
    return session


@pytest.fixture(scope="module")
def replayed(trained_classifier, scenario_capture):
    path, _ = scenario_capture("weak_ikev1_main_3des_md5")
    return path, _run(LiveSession(ReplaySource(path, speed=0), "test"))


def test_live_windows_match_batch_windows(replayed, trained_classifier):
    path, session = replayed
    assert session.status == "finished"
    batch = trained_classifier.predict(extract_flow_features(parse_pcap(str(path))), smooth=False)
    assert {(p["flow_id"], p["window_start"]) for p in session.predictions} == \
           {(p["flow_id"], p["window_start"]) for p in batch}


def test_live_emits_protocol_events_and_alerts(replayed):
    _, session = replayed
    kinds = [e["type"] for e in session.events_since(0)]
    assert {"ike", "sa", "window", "snapshot", "alert"} <= set(kinds)
    alerts = {e["data"]["id"] for e in session.events_since(0) if e["type"] == "alert"}
    assert {"KE-001", "CRYPTO-003"} <= alerts            # MODP-1024 and 3DES raised while streaming
    assert kinds[-1] == "status" and session.events_since(0)[-1]["data"]["status"] == "finished"


def test_snapshot_profile_is_evidence_backed(replayed):
    _, session = replayed
    profile = session.snapshot["profile"]
    assert profile["ike_version"]["value"] == "IKEv1" and profile["ike_version"]["source"] == "observed"
    assert session.snapshot["security"]["overall_score"] is not None


def test_events_since_is_incremental(replayed):
    _, session = replayed
    events = session.events_since(0)
    assert session.events_since(events[-1]["seq"]) == []
    assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)


def test_paced_replay_reports_realtime_lag(trained_classifier, scenario_capture):
    path, _ = scenario_capture("misconfig_esp_null")
    session = _run(LiveSession(ReplaySource(path, speed=25), "paced"))
    assert session.status == "finished" and session.predictions
    alerts = {e["data"]["id"] for e in session.events_since(0) if e["type"] == "alert"}
    assert "CRYPTO-001" in alerts                          # ESP-NULL flagged during the stream


def test_interface_source_validation():
    with pytest.raises(ValueError):
        open_interface_source("eth0; rm -rf /", "esp")
    with pytest.raises(ValueError):
        open_interface_source("eth0", "esp`reboot`")


@pytest.fixture(scope="module")
def client(trained_classifier):
    ensure_samples()
    return TestClient(app)


class TestLiveApi:
    def test_capabilities(self, client):
        caps = client.get("/api/live/capabilities").json()
        assert caps["replay"] is True and "default_filter" in caps

    def test_replay_session_streams_events_and_saves_analysis(self, client):
        started = client.post("/api/live/start", json={"source": "replay", "file_id": "misconfig_esp_null", "speed": 0})
        assert started.status_code == 200, started.text
        sid = started.json()["id"]
        types = []
        with client.stream("GET", f"/api/live/{sid}/events") as response:
            assert response.headers["content-type"].startswith("text/event-stream")
            for line in response.iter_lines():
                if line.startswith("data: ") and line != "data: {}":
                    types.append(json.loads(line[6:])["type"])
                if line.startswith("event: end"):
                    break
        assert {"ike", "window", "alert", "analysis"} <= set(types)
        status = client.get(f"/api/live/{sid}").json()
        assert status["status"] == "finished" and status["analysis_id"]
        assert client.get(f"/api/analysis/{status['analysis_id']}").status_code == 200

    def test_start_validation(self, client):
        assert client.post("/api/live/start", json={"source": "replay"}).status_code == 400
        assert client.post("/api/live/start", json={"source": "replay", "file_id": "nope"}).status_code == 404
        assert client.post("/api/live/start", json={"source": "replay", "file_id": "x", "speed": 999}).status_code == 422
        assert client.get("/api/live/../../etc/events").status_code == 404
        assert client.get("/api/live/0123456789").status_code == 404


def test_scapy_frames_get_the_right_link_type():
    """The parser skips a different number of header bytes per link type, so the label must match the frame."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import CookedLinux, Ether, Loopback
    from backend.realtime.sources import scapy_linktype
    ip = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500)
    assert scapy_linktype(Ether() / ip) == 1
    assert scapy_linktype(Loopback() / ip) == 0      # Npcap loopback / BSD: 4-byte family header
    assert scapy_linktype(CookedLinux() / ip) == 113
    assert scapy_linktype(ip) == 101                  # headerless


def test_windows_loopback_frame_is_decoded_as_ike():
    """A frame as the Npcap loopback adapter delivers it (02 00 00 00 + IP) must decode to IKE, not 'other'."""
    import struct
    from backend.analyzers.pcap_parser import PacketDecoder
    from backend.testbed import pcap_writer as pw
    from backend.testbed.esp_model import IKE_SUITES
    from tests.test_parser import _ikev2_init
    ike = _ikev2_init([IKE_SUITES["aes128-sha256-ecp256"]])
    ip = pw.ip_packet(4, "127.0.0.1", "127.0.0.1", 17, pw.udp(4, "127.0.0.1", "127.0.0.1", 500, 500, ike))
    for header in (struct.pack("<I", 2), struct.pack(">I", 2)):
        packet = PacketDecoder().decode(header + ip, 0, 1.0, 1)
        assert packet["protocol_type"] == "ike" and packet["src_ip"] == "127.0.0.1"
