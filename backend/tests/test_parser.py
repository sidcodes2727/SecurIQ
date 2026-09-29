"""IKE message parser and capture-file reader."""
import random
import struct

import pytest

from backend.analyzers.ike_parser import parse_ike_message
from backend.analyzers.pcap_parser import CaptureFormatError, is_capture_file, parse_pcap
from backend.testbed import ike_builder as ib
from backend.testbed import pcap_writer as pw
from backend.testbed.esp_model import IKE_SUITES

RNG = random.Random(5)


def _ikev2_init(suites, response=False, notifies=(16388, 16389), vendor="strongswan"):
    payloads = [(ib.V2_SA, ib.v2_sa(suites)), (ib.V2_KE, ib.v2_ke(suites[0].dh_group, RNG)),
                (ib.V2_NONCE, RNG.randbytes(32))]
    payloads += [(ib.V2_NOTIFY, ib.v2_notify(n, RNG.randbytes(20))) for n in notifies]
    if vendor:
        payloads.append((ib.V2_VID, bytes.fromhex(ib.VENDOR_IDS[vendor])))
    first, body = ib.chain(payloads)
    return ib.header(b"\x11" * 8, b"\x22" * 8 if response else b"\x00" * 8, first, 2, 34,
                     0x20 if response else 0x08, 0, body)


class TestIkeParser:
    def test_ikev2_sa_init_fields(self):
        msg = parse_ike_message(_ikev2_init([IKE_SUITES["aes256-sha256-modp2048"]]))
        assert msg["major_version"] == 2 and msg["exchange_type"] == "IKE_SA_INIT"
        offer = msg["proposals"][0]
        assert offer["encryption"] == ["AES-256-CBC"]
        assert offer["integrity"] == ["HMAC-SHA2-256-128"]
        assert offer["prf"] == ["PRF-HMAC-SHA2-256"]
        assert offer["dh_groups"] == [14]
        assert msg["ke_dh_group"] == 14 and msg["ke_data_len"] == 256

    def test_ikev2_notify_codes_follow_rfc7296(self):
        msg = parse_ike_message(_ikev2_init([IKE_SUITES["aes128-sha256-ecp256"]], notifies=(16388, 16391, 16430)))
        names = [n["name"] for n in msg["notifies"]]
        assert names == ["NAT_DETECTION_SOURCE_IP", "USE_TRANSPORT_MODE", "IKEV2_FRAGMENTATION_SUPPORTED"]
        assert msg["nat_detection"] is True

    def test_vendor_id_identifies_implementation(self):
        msg = parse_ike_message(_ikev2_init([IKE_SUITES["aes128-sha256-ecp256"]]))
        assert msg["vendor_ids"][0]["name"] == "strongSwan"
        assert msg["vendor_ids"][0]["reveals_implementation"] is True

    def test_ikev2_multiple_proposals(self):
        suites = [IKE_SUITES["aes256gcm16-prfsha384-ecp384"], IKE_SUITES["3des-md5-modp1024"]]
        msg = parse_ike_message(_ikev2_init(suites))
        assert [p["encryption"][0] for p in msg["proposals"]] == ["AES-256-GCM-16", "3DES-CBC"]
        assert msg["proposals"][0]["integrity"] == []  # AEAD: no integrity transform

    def test_ikev1_phase1_attributes(self):
        transform = ib.v1_transform_for(IKE_SUITES["3des-md5-modp1024"], 1, 604800)
        first, body = ib.chain([(ib.V1_SA, ib.v1_sa([transform]))])
        msg = parse_ike_message(ib.header(b"\x01" * 8, b"\x00" * 8, first, 1, 2, 0, 0, body))
        offer = msg["proposals"][0]
        assert msg["exchange_type"] == "MAIN_MODE"
        assert offer["encryption"] == ["3DES-CBC"]
        assert offer["integrity"] == ["HMAC-MD5"]
        assert offer["auth_method"] == "Pre-Shared Key"
        assert offer["dh_groups"] == [2]
        assert offer["life_seconds"] == 604800

    def test_ikev1_aggressive_identity_is_decoded(self):
        first, body = ib.chain([(ib.V1_ID, ib.v1_id("vpnuser@corp.example"))])
        msg = parse_ike_message(ib.header(b"\x01" * 8, b"\x00" * 8, first, 1, 4, 0, 0, body))
        assert msg["identities"][0] == {"payload": "ID", "id_type": "USER_FQDN", "value": "vpnuser@corp.example"}

    def test_ikev1_encrypted_body_is_not_parsed(self):
        msg = parse_ike_message(ib.header(b"\x01" * 8, b"\x02" * 8, 8, 1, 32, 0x01, 7, RNG.randbytes(150)))
        assert msg["encrypted_flag"] is True
        assert msg["encrypted_len"] == 150 and msg["proposals"] == []

    def test_ikev2_sk_payload_size(self):
        first, body = ib.chain([(ib.V2_SK, ib.v2_sk_payload(400, RNG), ib.V2_IDI)])
        msg = parse_ike_message(ib.header(b"\x01" * 8, b"\x02" * 8, first, 2, 35, 0x08, 1, body))
        assert msg["length"] == 400
        assert msg["sk_inner_first_payload"] == "IDi"

    @pytest.mark.parametrize("data", [b"", b"\x00" * 10, b"\x00" * 17 + b"\x55" + b"\x00" * 10,
                                      b"\x11" * 16 + bytes([33, 0x20, 34, 8]) + b"\x00" * 4 + b"\xff\xff\xff\xff" + b"\x21\x00\xff\xff"])
    def test_malformed_input_never_raises(self, data):
        parse_ike_message(data)


def _frame_esp(ip_version=4, payload_len=100):
    src, dst = ("10.0.0.1", "10.0.0.2") if ip_version == 4 else ("2001:db8::1", "2001:db8::2")
    esp = struct.pack("!II", 0x1234, 7) + b"\xaa" * payload_len
    return pw.ip_packet(ip_version, src, dst, 50, esp)


class TestCaptureReader:
    def test_pcap_esp_ike_and_natt(self, tmp_path):
        ike = _ikev2_init([IKE_SUITES["aes128-sha256-ecp256"]])
        frames = [
            (1.0, pw.ethernet(pw.ip_packet(4, "10.0.0.1", "10.0.0.2", 17,
                                           pw.udp(4, "10.0.0.1", "10.0.0.2", 500, 500, ike)), 4)),
            (1.1, pw.ethernet(pw.ip_packet(4, "10.0.0.1", "10.0.0.2", 17,
                                           pw.udp(4, "10.0.0.1", "10.0.0.2", 4500, 4500, b"\x00" * 4 + ike)), 4)),
            (1.2, pw.ethernet(pw.ip_packet(4, "10.0.0.1", "10.0.0.2", 17,
                                           pw.udp(4, "10.0.0.1", "10.0.0.2", 4500, 4500, b"\xff")), 4)),
            (1.3, pw.ethernet(_frame_esp(4, 100), 4)),
            (1.4, pw.ethernet(_frame_esp(6, 64), 6)),
        ]
        path = tmp_path / "mixed.pcap"
        pw.write_pcap(path, frames)
        result = parse_pcap(str(path))
        types = [p["protocol_type"] for p in result["packets"]]
        assert types == ["ike", "ike_natt", "natt_keepalive", "esp", "esp"]
        assert result["packets"][3]["esp_payload_len"] == 100
        assert result["packets"][4]["ip_version"] == 6
        assert result["summary"]["ipv6"] == 1

    def test_pcapng_is_supported(self, tmp_path):
        frame = pw.ethernet(_frame_esp(4, 80), 4)
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
        ts = 1_700_000_000_500_000
        pad = (4 - len(frame) % 4) % 4
        epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame + b"\x00" * pad
        epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
        path = tmp_path / "one.pcapng"
        path.write_bytes(shb + idb + epb)
        result = parse_pcap(str(path))
        assert result["packets"][0]["protocol_type"] == "esp"
        assert result["packets"][0]["timestamp"] == pytest.approx(1_700_000_000.5)

    def _write_raw(self, path, linktype, frames):
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
            for ts, frame, orig in frames:
                fh.write(struct.pack("<IIII", int(ts), 0, len(frame), orig) + frame)

    def test_linux_sll_and_vlan(self, tmp_path):
        ip = _frame_esp(4, 60)
        sll = struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800) + ip
        self._write_raw(tmp_path / "sll.pcap", 113, [(1, sll, len(sll))])
        assert parse_pcap(str(tmp_path / "sll.pcap"))["packets"][0]["protocol_type"] == "esp"

        vlan = pw.MAC_B + pw.MAC_A + struct.pack("!HHH", 0x8100, 42, 0x0800) + ip
        self._write_raw(tmp_path / "vlan.pcap", 1, [(1, vlan, len(vlan))])
        assert parse_pcap(str(tmp_path / "vlan.pcap"))["packets"][0]["esp_payload_len"] == 60

    def test_truncated_snaplen_uses_ip_length(self, tmp_path):
        full = pw.ethernet(_frame_esp(4, 1200), 4)
        self._write_raw(tmp_path / "snap.pcap", 1, [(1, full[:96], len(full))])
        packet = parse_pcap(str(tmp_path / "snap.pcap"))["packets"][0]
        assert packet["esp_payload_len"] == 1200

    def test_rejects_non_capture(self, tmp_path):
        path = tmp_path / "fake.pcap"
        path.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
        assert not is_capture_file(path.read_bytes()[:4])
        with pytest.raises(CaptureFormatError):
            parse_pcap(str(path))

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_pcap("/nonexistent/file.pcap")
