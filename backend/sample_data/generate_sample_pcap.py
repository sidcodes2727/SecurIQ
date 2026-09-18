"""
Sample PCAP generator using Scapy.
Creates realistic IKE/ESP packets for demonstration purposes.
"""
from __future__ import annotations

import struct
import random
import time
from pathlib import Path
from scapy.all import (
    Ether, IP, IPv6, UDP, ESP, Raw,
    wrpcap, conf
)

conf.verb = 0

from backend.config import SAMPLE_DIR


def generate_sample_pcap(
    scenario: str = "ikev2_aes256gcm",
    output_dir: str | None = None,
) -> str:
    """
    Generate a sample PCAP file with IKE and ESP packets.
    
    Scenarios:
    - ikev2_aes256gcm: IKEv2 with AES-256-GCM (strong config)
    - ikev2_aes128cbc: IKEv2 with AES-128-CBC (moderate config)
    - ikev1_3des: IKEv1 with 3DES (weak config)
    - natt_tunnel: NAT-T encapsulated traffic
    - mixed_traffic: Various traffic patterns
    """
    if output_dir is None:
        output_dir = str(SAMPLE_DIR)
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    scenarios = {
        "ikev2_aes256gcm": _generate_ikev2_strong,
        "ikev2_aes128cbc": _generate_ikev2_moderate,
        "ikev1_3des": _generate_ikev1_weak,
        "natt_tunnel": _generate_natt,
        "mixed_traffic": _generate_mixed,
    }
    
    generator = scenarios.get(scenario, _generate_ikev2_strong)
    packets = generator()
    
    filename = f"sample_{scenario}.pcap"
    filepath = str(Path(output_dir) / filename)
    wrpcap(filepath, packets)
    
    return filepath


def _build_ike_header(
    init_spi: bytes,
    resp_spi: bytes,
    next_payload: int,
    major_version: int,
    minor_version: int,
    exchange_type: int,
    flags: int,
    message_id: int,
    payload: bytes = b"",
) -> bytes:
    """Build an IKE header (28 bytes) + optional payload."""
    version_byte = (major_version << 4) | minor_version
    total_length = 28 + len(payload)
    
    header = (
        init_spi +
        resp_spi +
        struct.pack("!BBBBII", next_payload, version_byte, exchange_type, flags, message_id, total_length)
    )
    return header + payload


def _build_sa_payload_ikev2(
    encryption_id: int,
    key_length: int,
    integrity_id: int,
    dh_group: int,
    prf_id: int,
    protocol_id: int = 1,  # 1=IKE, 3=ESP
) -> bytes:
    """Build an IKEv2 SA payload with one proposal."""
    # Build transforms
    transforms = b""
    
    # Encryption transform (with key length attribute)
    key_attr = struct.pack("!HH", 0x800E, key_length)  # TV format, type 14
    enc_transform = struct.pack("!BBHBBH", 3, 0, 8 + len(key_attr), 1, 0, encryption_id) + key_attr
    
    # PRF transform
    prf_transform = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, prf_id)
    
    # Integrity transform
    integ_transform = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integrity_id)
    
    # DH transform
    dh_transform = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_group)  # 0 = last
    
    transforms = enc_transform + prf_transform + integ_transform + dh_transform
    
    # Proposal
    proposal = struct.pack(
        "!BBHBBBB",
        0,  # last proposal
        0,  # reserved
        8 + len(transforms),  # proposal length
        1,  # proposal number
        protocol_id,
        0,  # SPI size
        4,  # num transforms
    ) + transforms
    
    # SA payload header (next_payload=0, reserved=0)
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    
    return sa_payload


def _build_notify_payload(notify_type: int, next_payload: int = 0) -> bytes:
    """Build an IKEv2 Notify payload."""
    # Protocol ID = 0, SPI size = 0
    data = struct.pack("!BBHBBH", next_payload, 0, 8, 0, 0, notify_type)
    return data


def _generate_ikev2_strong() -> list:
    """Generate IKEv2 with AES-256-GCM, DH Group 20, PFS."""
    packets = []
    base_time = time.time()
    
    gw1 = "10.0.1.1"
    gw2 = "10.0.2.1"
    
    init_spi = random.randbytes(8)
    resp_spi = b"\x00" * 8
    
    # IKE_SA_INIT Request (exchange type 34)
    sa_payload = _build_sa_payload_ikev2(
        encryption_id=20,   # AES-GCM-16
        key_length=256,
        integrity_id=0,     # NONE (AEAD)
        dh_group=20,        # ECP-384
        prf_id=5,           # PRF-HMAC-SHA2-256
    )
    
    ike_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=b"\x00" * 8,
        next_payload=33,  # SA
        major_version=2,
        minor_version=0,
        exchange_type=34,  # IKE_SA_INIT
        flags=0x08,  # Initiator
        message_id=0,
        payload=sa_payload,
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=ike_data)
    pkt.time = base_time
    packets.append(pkt)
    
    # IKE_SA_INIT Response
    resp_spi = random.randbytes(8)
    sa_resp = _build_sa_payload_ikev2(
        encryption_id=20,
        key_length=256,
        integrity_id=0,
        dh_group=20,
        prf_id=5,
    )
    
    ike_resp = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=33,
        major_version=2,
        minor_version=0,
        exchange_type=34,
        flags=0x20,  # Response
        message_id=0,
        payload=sa_resp,
    )
    
    pkt = IP(src=gw2, dst=gw1) / UDP(sport=500, dport=500) / Raw(load=ike_resp)
    pkt.time = base_time + 0.05
    packets.append(pkt)
    
    # IKE_AUTH Request (exchange type 35) - encrypted, just header
    auth_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=46,  # Encrypted
        major_version=2,
        minor_version=0,
        exchange_type=35,
        flags=0x08,
        message_id=1,
        payload=random.randbytes(200),
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=auth_data)
    pkt.time = base_time + 0.1
    packets.append(pkt)
    
    # IKE_AUTH Response
    auth_resp = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=46,
        major_version=2,
        minor_version=0,
        exchange_type=35,
        flags=0x20,
        message_id=1,
        payload=random.randbytes(200),
    )
    
    pkt = IP(src=gw2, dst=gw1) / UDP(sport=500, dport=500) / Raw(load=auth_resp)
    pkt.time = base_time + 0.15
    packets.append(pkt)
    
    # ESP traffic (simulated encrypted data)
    esp_spi1 = random.randint(0x10000, 0xFFFFFF)
    esp_spi2 = random.randint(0x10000, 0xFFFFFF)
    
    for i in range(100):
        # Forward direction
        spi = esp_spi1
        pkt = IP(src=gw1, dst=gw2) / ESP(spi=spi, seq=i+1, data=random.randbytes(random.randint(64, 1400)))
        pkt.time = base_time + 0.5 + i * 0.02
        packets.append(pkt)
        
        # Reverse direction
        spi = esp_spi2
        pkt = IP(src=gw2, dst=gw1) / ESP(spi=spi, seq=i+1, data=random.randbytes(random.randint(64, 1400)))
        pkt.time = base_time + 0.51 + i * 0.02
        packets.append(pkt)
    
    # CREATE_CHILD_SA with PFS (exchange type 36)
    # Include Key Exchange payload (type 34)
    ke_payload = struct.pack("!BBH", 0, 0, 4 + 4 + 48)  # next=0, reserved=0
    ke_payload += struct.pack("!HH", 20, 0)  # DH Group 20, reserved
    ke_payload += random.randbytes(48)  # KE data
    
    child_sa = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=34,  # KE payload
        major_version=2,
        minor_version=0,
        exchange_type=36,
        flags=0x08,
        message_id=2,
        payload=ke_payload,
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=child_sa)
    pkt.time = base_time + 3.0
    packets.append(pkt)
    
    return packets


def _generate_ikev2_moderate() -> list:
    """Generate IKEv2 with AES-128-CBC, HMAC-SHA1, DH14."""
    packets = []
    base_time = time.time()
    
    gw1 = "192.168.1.1"
    gw2 = "192.168.2.1"
    
    init_spi = random.randbytes(8)
    resp_spi = random.randbytes(8)
    
    # IKE_SA_INIT Request
    sa_payload = _build_sa_payload_ikev2(
        encryption_id=12,   # AES-CBC
        key_length=128,
        integrity_id=2,     # HMAC-SHA1-96
        dh_group=14,        # MODP-2048
        prf_id=2,           # PRF-HMAC-SHA1
    )
    
    ike_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=b"\x00" * 8,
        next_payload=33,
        major_version=2,
        minor_version=0,
        exchange_type=34,
        flags=0x08,
        message_id=0,
        payload=sa_payload,
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=ike_data)
    pkt.time = base_time
    packets.append(pkt)
    
    # IKE_SA_INIT Response
    sa_resp = _build_sa_payload_ikev2(
        encryption_id=12,
        key_length=128,
        integrity_id=2,
        dh_group=14,
        prf_id=2,
    )
    
    ike_resp = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=33,
        major_version=2,
        minor_version=0,
        exchange_type=34,
        flags=0x20,
        message_id=0,
        payload=sa_resp,
    )
    
    pkt = IP(src=gw2, dst=gw1) / UDP(sport=500, dport=500) / Raw(load=ike_resp)
    pkt.time = base_time + 0.05
    packets.append(pkt)
    
    # ESP traffic
    esp_spi = random.randint(0x10000, 0xFFFFFF)
    for i in range(80):
        src, dst = (gw1, gw2) if i % 2 == 0 else (gw2, gw1)
        pkt = IP(src=src, dst=dst) / ESP(spi=esp_spi, seq=i+1, data=random.randbytes(random.randint(100, 800)))
        pkt.time = base_time + 0.3 + i * 0.05
        packets.append(pkt)
    
    return packets


def _generate_ikev1_weak() -> list:
    """Generate IKEv1 with 3DES-CBC (weak config)."""
    packets = []
    base_time = time.time()
    
    gw1 = "172.16.0.1"
    gw2 = "172.16.0.2"
    
    init_spi = random.randbytes(8)
    
    # IKEv1 Main Mode (exchange type 2)
    # Simplified - just the header to indicate IKEv1
    ike_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=b"\x00" * 8,
        next_payload=1,   # SA payload
        major_version=1,
        minor_version=0,
        exchange_type=2,  # IDENTITY_PROTECTION (Main Mode)
        flags=0x00,
        message_id=0,
        payload=random.randbytes(100),
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=ike_data)
    pkt.time = base_time
    packets.append(pkt)
    
    # Response
    resp_spi = random.randbytes(8)
    ike_resp = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=1,
        major_version=1,
        minor_version=0,
        exchange_type=2,
        flags=0x00,
        message_id=0,
        payload=random.randbytes(100),
    )
    
    pkt = IP(src=gw2, dst=gw1) / UDP(sport=500, dport=500) / Raw(load=ike_resp)
    pkt.time = base_time + 0.1
    packets.append(pkt)
    
    # IKEv1 Quick Mode
    qm_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=1,
        major_version=1,
        minor_version=0,
        exchange_type=32,  # QUICK_MODE
        flags=0x01,  # Encrypted
        message_id=random.randint(1, 0xFFFFFFFF),
        payload=random.randbytes(150),
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=500, dport=500) / Raw(load=qm_data)
    pkt.time = base_time + 0.5
    packets.append(pkt)
    
    # ESP traffic
    esp_spi = random.randint(0x10000, 0xFFFFFF)
    for i in range(50):
        src, dst = (gw1, gw2) if i % 2 == 0 else (gw2, gw1)
        pkt = IP(src=src, dst=dst) / ESP(spi=esp_spi, seq=i+1, data=random.randbytes(random.randint(64, 500)))
        pkt.time = base_time + 1.0 + i * 0.1
        packets.append(pkt)
    
    return packets


def _generate_natt() -> list:
    """Generate NAT-T encapsulated traffic."""
    packets = []
    base_time = time.time()
    
    gw1 = "203.0.113.1"
    gw2 = "198.51.100.1"
    
    init_spi = random.randbytes(8)
    resp_spi = random.randbytes(8)
    
    # NAT-T IKE (port 4500, with non-ESP marker)
    non_esp_marker = b"\x00\x00\x00\x00"
    
    # NAT detection notify
    nat_notify = _build_notify_payload(16394)  # NAT_DETECTION_SOURCE_IP
    
    ike_data = _build_ike_header(
        init_spi=init_spi,
        resp_spi=b"\x00" * 8,
        next_payload=41,  # Notify
        major_version=2,
        minor_version=0,
        exchange_type=34,
        flags=0x08,
        message_id=0,
        payload=nat_notify + random.randbytes(50),
    )
    
    pkt = IP(src=gw1, dst=gw2) / UDP(sport=4500, dport=4500) / Raw(load=non_esp_marker + ike_data)
    pkt.time = base_time
    packets.append(pkt)
    
    # Response with NAT detection
    nat_notify_dst = _build_notify_payload(16395)  # NAT_DETECTION_DESTINATION_IP
    
    ike_resp = _build_ike_header(
        init_spi=init_spi,
        resp_spi=resp_spi,
        next_payload=41,
        major_version=2,
        minor_version=0,
        exchange_type=34,
        flags=0x20,
        message_id=0,
        payload=nat_notify_dst + random.randbytes(50),
    )
    
    pkt = IP(src=gw2, dst=gw1) / UDP(sport=4500, dport=4500) / Raw(load=non_esp_marker + ike_resp)
    pkt.time = base_time + 0.05
    packets.append(pkt)
    
    # NAT-T ESP (UDP 4500 without non-ESP marker)
    esp_spi = random.randint(0x10000, 0xFFFFFF)
    for i in range(60):
        src, dst = (gw1, gw2) if i % 2 == 0 else (gw2, gw1)
        esp_data = struct.pack("!II", esp_spi, i + 1) + random.randbytes(random.randint(64, 1000))
        pkt = IP(src=src, dst=dst) / UDP(sport=4500, dport=4500) / Raw(load=esp_data)
        pkt.time = base_time + 0.3 + i * 0.03
        packets.append(pkt)
    
    return packets


def _generate_mixed() -> list:
    """Generate mixed traffic with multiple traffic patterns."""
    packets = []
    
    # Combine all scenarios
    packets.extend(_generate_ikev2_strong())
    
    # Add some VoIP-like ESP (small, regular)
    base_time = time.time() + 10
    voip_spi = random.randint(0x100000, 0xFFFFFF)
    for i in range(200):
        src, dst = ("10.0.1.1", "10.0.2.1") if i % 2 == 0 else ("10.0.2.1", "10.0.1.1")
        pkt = IP(src=src, dst=dst) / ESP(spi=voip_spi, seq=i+1, data=random.randbytes(random.randint(160, 220)))
        pkt.time = base_time + i * 0.020  # 20ms intervals (VoIP-like)
        packets.append(pkt)
    
    # Add some file transfer-like ESP (large, sustained)
    base_time2 = time.time() + 20
    ft_spi = random.randint(0x200000, 0xFFFFFF)
    for i in range(150):
        pkt = IP(src="10.0.1.1", dst="10.0.2.1") / ESP(spi=ft_spi, seq=i+1, data=random.randbytes(random.randint(1200, 1400)))
        pkt.time = base_time2 + i * 0.001
        packets.append(pkt)
    
    # Sort all by timestamp
    packets.sort(key=lambda p: float(p.time))
    
    return packets


def generate_all_samples() -> list[str]:
    """Generate all sample PCAP scenarios."""
    files = []
    for scenario in ["ikev2_aes256gcm", "ikev2_aes128cbc", "ikev1_3des", "natt_tunnel", "mixed_traffic"]:
        filepath = generate_sample_pcap(scenario)
        files.append(filepath)
    return files
