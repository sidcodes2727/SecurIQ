"""ESP fingerprinting, mode inference, ESP-NULL detection and replay analysis."""
import random

import pytest

from backend.analyzers.esp_fingerprint import (
    FAMILY_AEAD, FAMILY_CBC64, FAMILY_CBC128, detect_null_encryption, fingerprint_esp, infer_mode,
)
from backend.analyzers.ipsec_analyzer import _replay_analysis
from backend.testbed.esp_model import ESP_SUITES, esp_payload_len, inner_packet_len


def _lengths(suite_key, n=60, seed=1, mode="tunnel"):
    rng = random.Random(seed)
    suite = ESP_SUITES[suite_key]
    return [esp_payload_len(inner_packet_len(rng.randint(20, 1300), mode, 4), suite) for _ in range(n)]


class TestEspFingerprint:
    @pytest.mark.parametrize("suite_key,family,icv", [
        ("aes128-sha1", FAMILY_CBC128, 12),
        ("aes256-sha256", FAMILY_CBC128, 16),
        ("aes256-sha384", FAMILY_CBC128, 24),
        ("3des-sha1", FAMILY_CBC64, 12),
        ("3des-md5", FAMILY_CBC64, 12),
        ("aes256gcm16", FAMILY_AEAD, 16),
        ("chacha20poly1305", FAMILY_AEAD, 16),
    ])
    def test_identifies_family_and_icv(self, suite_key, family, icv):
        fp = fingerprint_esp(_lengths(suite_key))
        assert fp["status"] == "identified"
        assert fp["family"] == family
        assert icv in fp["icv_len_candidates"]
        assert fp["confidence"] > 0.8

    def test_constant_size_traffic_is_inconclusive(self):
        fp = fingerprint_esp([188] * 200)
        assert fp["status"] == "insufficient_data" and fp["confidence"] == 0

    def test_non_aligned_lengths_flagged(self):
        assert fingerprint_esp([101, 203, 305, 407, 509, 611, 713, 815])["status"] == "irregular"

    def test_confidence_grows_with_distinct_lengths(self):
        few = fingerprint_esp([28 + 16 * k for k in (2, 3, 4)] * 5)
        many = fingerprint_esp([28 + 16 * k for k in range(2, 12)] * 2)
        assert many["confidence"] > few["confidence"]


class TestModeInference:
    def test_transport_from_small_packets(self):
        suite = ESP_SUITES["aes128gcm16"]
        lengths = [esp_payload_len(inner_packet_len(l4, "transport", 4), suite) for l4 in [20, 32, 500, 1200] * 20]
        fp = fingerprint_esp(lengths)
        assert infer_mode(lengths, fp)["value"] == "Transport"

    def test_tunnel_when_ack_clock_carries_inner_headers(self):
        suite = ESP_SUITES["aes128gcm16"]
        lengths = [esp_payload_len(inner_packet_len(l4, "tunnel", 4), suite) for l4 in [32, 500, 1200] * 30]
        result = infer_mode(lengths, fingerprint_esp(lengths))
        assert result["value"] == "Tunnel" and result["confidence"] >= 0.6  # 0.7 × fingerprint confidence

    def test_cbc_padding_ambiguity_abstains(self):
        """AES-CBC: transport ACK with timestamps (32 B) and tunnelled ACK (40 B) encrypt to the same length."""
        suite = ESP_SUITES["aes128-sha1"]
        for mode, ack in (("transport", 32), ("tunnel", 20)):
            lengths = [esp_payload_len(inner_packet_len(l4, mode, 4), suite) for l4 in [ack, 700, 1300] * 30]
            assert infer_mode(lengths, fingerprint_esp(lengths))["value"] is None

    def test_constant_size_traffic_abstains(self):
        suite = ESP_SUITES["aes256gcm16"]
        lengths = [esp_payload_len(inner_packet_len(l4, "transport", 4), suite) for l4 in [180, 184, 176] * 50]
        assert infer_mode(lengths, fingerprint_esp(lengths))["value"] is None

    def test_icv_hint_resolves_candidate_ambiguity(self):
        suite = ESP_SUITES["3des-md5"]
        lengths = [esp_payload_len(inner_packet_len(l4, "tunnel", 4), suite)
                   for l4 in [20, 20, 150, 333, 600, 777, 999, 1300] * 20]
        fp = fingerprint_esp(lengths)
        assert infer_mode(lengths, fp)["value"] is None            # ICV 12 or 20 → range too wide
        hinted = infer_mode(lengths, fp, icv_hint=12)
        assert hinted["value"] == "Tunnel" and "narrowed" in hinted["evidence"]


class TestNullEncryption:
    def test_detects_cleartext_inner_ipv4(self):
        samples = []
        for size in (60, 120, 300, 700, 1000, 1300):
            inner = bytes([0x45, 0, size >> 8, size & 0xFF, 0, 0, 0x40, 0, 64, 6, 0, 0]) + bytes(4) + bytes(4)
            samples.append((size + 2 + 16, inner.hex()))
        assert detect_null_encryption(samples)["suspected"] is True

    def test_random_iv_is_not_flagged(self):
        rng = random.Random(3)
        samples = [(rng.randint(60, 1400), rng.randbytes(16).hex()) for _ in range(50)]
        assert detect_null_encryption(samples)["suspected"] is False


class TestReplayAnalysis:
    def test_clean_sequence(self):
        assert _replay_analysis(list(range(1, 500)))["duplicates"] == 0

    def test_duplicate(self):
        assert _replay_analysis(list(range(1, 100)) + [50] + list(range(100, 120)))["duplicates"] == 1

    def test_counter_reset_is_not_a_duplicate(self):
        result = _replay_analysis(list(range(1, 2000)) + list(range(1, 40)))
        assert result["counter_resets"] == 1 and result["duplicates"] == 0

    def test_reordering_beyond_window(self):
        result = _replay_analysis([1, 2, 3, 200, 100, 201])
        assert result["beyond_default_window"] == 1 and result["max_reorder_depth"] == 100
