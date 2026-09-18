"""
Tests for the PCAP parser and IPsec analyzer.
"""
import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.sample_data.generate_sample_pcap import generate_sample_pcap
from backend.analyzers.pcap_parser import parse_pcap
from backend.analyzers.ipsec_analyzer import analyze_ipsec
from backend.analyzers.flow_extractor import extract_flow_features, FEATURE_NAMES


@pytest.fixture(scope="module")
def strong_pcap(tmp_path_factory):
    """Generate a strong config sample PCAP."""
    tmpdir = str(tmp_path_factory.mktemp("pcap"))
    return generate_sample_pcap("ikev2_aes256gcm", output_dir=tmpdir)


@pytest.fixture(scope="module")
def weak_pcap(tmp_path_factory):
    """Generate a weak config sample PCAP."""
    tmpdir = str(tmp_path_factory.mktemp("pcap"))
    return generate_sample_pcap("ikev1_3des", output_dir=tmpdir)


@pytest.fixture(scope="module")
def natt_pcap(tmp_path_factory):
    """Generate a NAT-T sample PCAP."""
    tmpdir = str(tmp_path_factory.mktemp("pcap"))
    return generate_sample_pcap("natt_tunnel", output_dir=tmpdir)


class TestPcapParser:
    def test_parse_strong_pcap(self, strong_pcap):
        result = parse_pcap(strong_pcap)
        assert result["metadata"]["total_packets"] > 0
        assert result["metadata"]["filename"].endswith(".pcap")
        assert "packets" in result
        assert "summary" in result

    def test_parse_has_ike_packets(self, strong_pcap):
        result = parse_pcap(strong_pcap)
        ike_count = result["summary"]["ike"]
        assert ike_count > 0, "Should detect IKE packets"

    def test_parse_has_esp_packets(self, strong_pcap):
        result = parse_pcap(strong_pcap)
        esp_count = result["summary"]["esp"]
        assert esp_count > 0, "Should detect ESP packets"

    def test_ike_version_detected(self, strong_pcap):
        result = parse_pcap(strong_pcap)
        ike_packets = [p for p in result["packets"] if p["protocol_type"] == "ike"]
        assert any(p.get("ike_major_version") == 2 for p in ike_packets)

    def test_esp_spi_extracted(self, strong_pcap):
        result = parse_pcap(strong_pcap)
        esp_packets = [p for p in result["packets"] if p["protocol_type"] == "esp"]
        assert all("spi" in p for p in esp_packets)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_pcap("/nonexistent/file.pcap")


class TestIpsecAnalyzer:
    def test_analyze_strong(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        
        assert analysis["packets_analyzed"] > 0
        assert analysis["ike_analysis"]["detected"]
        assert analysis["esp_analysis"]["detected"]

    def test_vpn_profile_generated(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        profile = analysis["vpn_profile"]
        
        assert "ipsec_protocol" in profile
        assert "ike_version" in profile
        assert "encryption" in profile
        assert "mode" in profile

    def test_ikev2_detected(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        assert analysis["ike_analysis"]["version"] == "IKEv2"

    def test_ikev1_detected(self, weak_pcap):
        parsed = parse_pcap(weak_pcap)
        analysis = analyze_ipsec(parsed)
        assert analysis["ike_analysis"]["version"] == "IKEv1"

    def test_esp_sa_info(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        sa_info = analysis["esp_analysis"]["sa_info"]
        assert len(sa_info) > 0
        for sa in sa_info:
            assert "spi" in sa
            assert "packet_count" in sa

    def test_natt_detection(self, natt_pcap):
        parsed = parse_pcap(natt_pcap)
        analysis = analyze_ipsec(parsed)
        assert analysis["nat_t_analysis"]["detected"]

    def test_timeline_generated(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        assert len(analysis["timeline"]) > 0

    def test_not_observable_fields(self, strong_pcap):
        """ESP encryption should be 'Not Observable' from ESP packets alone."""
        parsed = parse_pcap(strong_pcap)
        analysis = analyze_ipsec(parsed)
        for sa in analysis["esp_analysis"].get("sa_info", []):
            assert "Not Observable" in sa.get("encryption", "")


class TestFlowExtractor:
    def test_extract_features(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        features = extract_flow_features(parsed)
        assert len(features) > 0

    def test_feature_names_complete(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        features = extract_flow_features(parsed)
        for f in features:
            for name in FEATURE_NAMES:
                assert name in f, f"Missing feature: {name}"

    def test_feature_values_numeric(self, strong_pcap):
        parsed = parse_pcap(strong_pcap)
        features = extract_flow_features(parsed)
        for f in features:
            for name in FEATURE_NAMES:
                val = f[name]
                assert isinstance(val, (int, float)), f"{name} should be numeric, got {type(val)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
