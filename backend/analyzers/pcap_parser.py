"""
PCAP/PCAPNG parser using Scapy.
Extracts raw packet data and identifies IPsec-related traffic.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any
from scapy.all import (
    rdpcap, IP, IPv6, UDP, TCP, ESP, Raw,
    Packet, conf
)

# Suppress Scapy warnings
conf.verb = 0

# IKE constants
IKE_PORT = 500
IKE_NATT_PORT = 4500
ESP_PROTO = 50
AH_PROTO = 51


def parse_pcap(file_path: str) -> dict[str, Any]:
    """
    Parse a PCAP/PCAPNG file and extract packet information.
    
    Returns a dict with:
    - metadata: file info
    - packets: list of parsed packet dicts
    - summary: traffic summary statistics
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    start_time = time.time()
    packets = rdpcap(str(path))
    parse_duration = time.time() - start_time

    parsed_packets = []
    stats = {
        "total": 0,
        "ike": 0,
        "esp": 0,
        "ah": 0,
        "ike_natt": 0,
        "ipv4": 0,
        "ipv6": 0,
        "other": 0,
    }

    for i, pkt in enumerate(packets):
        parsed = _parse_packet(pkt, i)
        if parsed:
            parsed_packets.append(parsed)
            stats["total"] += 1
            ptype = parsed.get("protocol_type", "other")
            if ptype in stats:
                stats[ptype] += 1
            else:
                stats["other"] += 1
            if parsed.get("ip_version") == 4:
                stats["ipv4"] += 1
            elif parsed.get("ip_version") == 6:
                stats["ipv6"] += 1

    # Calculate file hash for identification
    file_hash = hashlib.sha256(path.read_bytes()).hexdigest()[:16]

    return {
        "metadata": {
            "filename": path.name,
            "file_size": path.stat().st_size,
            "file_hash": file_hash,
            "total_packets": len(packets),
            "parsed_packets": len(parsed_packets),
            "parse_duration_ms": round(parse_duration * 1000, 2),
        },
        "packets": parsed_packets,
        "summary": stats,
    }


def _parse_packet(pkt: Packet, index: int) -> dict[str, Any] | None:
    """Parse a single packet and extract relevant fields."""
    result = {
        "index": index,
        "timestamp": float(pkt.time) if hasattr(pkt, 'time') else 0.0,
        "length": len(pkt),
        "ip_version": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol_type": "other",
        "src_port": None,
        "dst_port": None,
    }

    # Extract IP layer
    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["ip_version"] = 4
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ip_proto"] = ip.proto
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        result["ip_version"] = 6
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ip_proto"] = ip.nh
    else:
        return result  # Non-IP packet

    proto = result.get("ip_proto", 0)

    # Check for ESP (protocol 50)
    if proto == ESP_PROTO or pkt.haslayer(ESP):
        result["protocol_type"] = "esp"
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport == IKE_NATT_PORT or udp.dport == IKE_NATT_PORT:
                result["nat_t"] = True
                result["src_port"] = udp.sport
                result["dst_port"] = udp.dport
        if pkt.haslayer(ESP):
            esp = pkt[ESP]
            result["spi"] = hex(esp.spi)
            result["seq_num"] = esp.seq
            result["esp_payload_len"] = len(esp.data) if hasattr(esp, 'data') and esp.data else len(bytes(esp)) - 8
        return result

    # Check for AH (protocol 51)
    if proto == AH_PROTO:
        result["protocol_type"] = "ah"
        # Scapy may not fully parse AH, extract manually
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            if len(raw) >= 12:
                result["ah_next_header"] = raw[0]
                result["ah_payload_len"] = raw[1]
                spi_bytes = raw[4:8]
                result["spi"] = hex(int.from_bytes(spi_bytes, 'big'))
                seq_bytes = raw[8:12]
                result["seq_num"] = int.from_bytes(seq_bytes, 'big')
        return result

    # Check for IKE (UDP port 500 or 4500)
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport

        if udp.dport == IKE_PORT or udp.sport == IKE_PORT:
            result["protocol_type"] = "ike"
            result["nat_t"] = False
            _parse_ike_header(pkt, result)
            return result

        if udp.dport == IKE_NATT_PORT or udp.sport == IKE_NATT_PORT:
            # Could be NAT-T IKE or NAT-T ESP
            payload = bytes(udp.payload) if udp.payload else b""
            if len(payload) >= 4:
                # Non-ESP marker: 4 bytes of zeros before IKE header
                if payload[:4] == b'\x00\x00\x00\x00':
                    result["protocol_type"] = "ike_natt"
                    result["nat_t"] = True
                    _parse_ike_header_from_bytes(payload[4:], result)
                else:
                    # NAT-T ESP encapsulation
                    result["protocol_type"] = "esp"
                    result["nat_t"] = True
                    if len(payload) >= 8:
                        result["spi"] = hex(int.from_bytes(payload[:4], 'big'))
                        result["seq_num"] = int.from_bytes(payload[4:8], 'big')
                        result["esp_payload_len"] = len(payload) - 8
            return result

    # Check for TCP (rare but possible IKE over TCP)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport

    return result


def _parse_ike_header(pkt: Packet, result: dict) -> None:
    """Parse IKE header from a packet with UDP layer."""
    if pkt.haslayer(UDP):
        payload = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
        _parse_ike_header_from_bytes(payload, result)


def _parse_ike_header_from_bytes(data: bytes, result: dict) -> None:
    """
    Parse IKE header from raw bytes.
    
    IKE Header format (28 bytes):
    - Initiator SPI (8 bytes)
    - Responder SPI (8 bytes)
    - Next Payload (1 byte)
    - Major Version (4 bits) | Minor Version (4 bits)
    - Exchange Type (1 byte)
    - Flags (1 byte)
    - Message ID (4 bytes)
    - Length (4 bytes)
    """
    if len(data) < 28:
        return

    init_spi = data[0:8].hex()
    resp_spi = data[8:16].hex()
    next_payload = data[16]
    version_byte = data[17]
    major_version = (version_byte >> 4) & 0x0F
    minor_version = version_byte & 0x0F
    exchange_type = data[18]
    flags = data[19]
    message_id = int.from_bytes(data[20:24], 'big')
    length = int.from_bytes(data[24:28], 'big')

    result["ike_init_spi"] = init_spi
    result["ike_resp_spi"] = resp_spi
    result["ike_version"] = f"{major_version}.{minor_version}"
    result["ike_major_version"] = major_version
    result["ike_exchange_type"] = _get_exchange_type_name(exchange_type, major_version)
    result["ike_exchange_type_num"] = exchange_type
    result["ike_flags"] = flags
    result["ike_message_id"] = message_id
    result["ike_length"] = length
    result["ike_next_payload"] = next_payload
    result["ike_initiator"] = bool(flags & 0x08)
    result["ike_response"] = bool(flags & 0x20)

    # Parse IKE payloads for transform information
    if len(data) > 28:
        _parse_ike_payloads(data[28:], next_payload, result, major_version)


def _get_exchange_type_name(et: int, major_version: int) -> str:
    """Map exchange type number to human-readable name."""
    if major_version == 2:
        # IKEv2 exchange types
        ike2_types = {
            34: "IKE_SA_INIT",
            35: "IKE_AUTH",
            36: "CREATE_CHILD_SA",
            37: "INFORMATIONAL",
        }
        return ike2_types.get(et, f"UNKNOWN({et})")
    else:
        # IKEv1 exchange types
        ike1_types = {
            1: "BASE",
            2: "IDENTITY_PROTECTION",  # Main Mode
            4: "AGGRESSIVE",
            5: "INFORMATIONAL",
            32: "QUICK_MODE",
            33: "NEW_GROUP_MODE",
        }
        return ike1_types.get(et, f"UNKNOWN({et})")


# IKEv2 Transform Type constants
TRANSFORM_TYPE_ENCR = 1
TRANSFORM_TYPE_PRF = 2
TRANSFORM_TYPE_INTEG = 3
TRANSFORM_TYPE_DH = 4
TRANSFORM_TYPE_ESN = 5

# Transform ID mappings
ENCR_NAMES = {
    1: "DES-IV64", 2: "DES-CBC", 3: "3DES-CBC", 4: "RC5-CBC",
    5: "IDEA-CBC", 6: "CAST-CBC", 7: "Blowfish-CBC", 8: "3IDEA",
    9: "DES-IV32", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR",
    14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16",
    18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
    23: "Camellia-CBC", 24: "Camellia-CTR",
    25: "Camellia-CCM-8", 26: "Camellia-CCM-12", 27: "Camellia-CCM-16",
    28: "ChaCha20-Poly1305",
}

PRF_NAMES = {
    1: "PRF-HMAC-MD5", 2: "PRF-HMAC-SHA1", 3: "PRF-HMAC-TIGER",
    4: "PRF-AES128-XCBC", 5: "PRF-HMAC-SHA2-256",
    6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512",
    8: "PRF-AES128-CMAC",
}

INTEG_NAMES = {
    0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96",
    3: "DES-MAC", 4: "KPDK-MD5",
    5: "AES-XCBC-96", 6: "HMAC-MD5-128", 7: "HMAC-SHA1-160",
    8: "AES-CMAC-96", 9: "AES-128-GMAC", 10: "AES-192-GMAC",
    11: "AES-256-GMAC", 12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
}

DH_NAMES = {
    0: "NONE", 1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536",
    14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
    17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521",
    22: "MODP-1024-160", 23: "MODP-2048-224", 24: "MODP-2048-256",
    25: "ECP-192", 26: "ECP-224",
    27: "Brainpool-224", 28: "Brainpool-256",
    29: "Brainpool-384", 30: "Brainpool-512",
    31: "Curve25519", 32: "Curve448",
}


def _parse_ike_payloads(data: bytes, next_payload_type: int, result: dict, major_version: int) -> None:
    """
    Parse IKE payload chain to extract transform proposals.
    """
    offset = 0
    current_payload_type = next_payload_type
    proposals = []
    
    while offset < len(data) - 4 and current_payload_type != 0:
        if offset + 4 > len(data):
            break
            
        next_pl = data[offset]
        reserved = data[offset + 1]  # noqa: F841
        payload_length = int.from_bytes(data[offset + 2:offset + 4], 'big')
        
        if payload_length < 4 or offset + payload_length > len(data):
            break
        
        payload_data = data[offset + 4:offset + payload_length]
        
        # SA payload (type 33 in IKEv2, type 1 in IKEv1)
        if (major_version == 2 and current_payload_type == 33) or \
           (major_version == 1 and current_payload_type == 1):
            sa_proposals = _parse_sa_payload(payload_data, major_version)
            proposals.extend(sa_proposals)
        
        # Notify payload (type 41 in IKEv2)
        if major_version == 2 and current_payload_type == 41:
            _parse_notify_payload(payload_data, result)
        
        # Key Exchange payload (type 34 in IKEv2) - indicates PFS in CREATE_CHILD_SA
        if major_version == 2 and current_payload_type == 34:
            if len(payload_data) >= 4:
                dh_group = int.from_bytes(payload_data[0:2], 'big')
                result.setdefault("ike_ke_dh_groups", []).append(dh_group)
        
        current_payload_type = next_pl
        offset += payload_length
    
    if proposals:
        result["ike_proposals"] = proposals


def _parse_sa_payload(data: bytes, major_version: int) -> list[dict]:
    """Parse SA payload to extract proposals and transforms."""
    proposals = []
    offset = 0
    
    while offset < len(data) - 8:
        if offset + 8 > len(data):
            break
            
        # Proposal header
        next_prop = data[offset]  # 0 = last, 2 = more
        reserved = data[offset + 1]  # noqa: F841
        proposal_length = int.from_bytes(data[offset + 2:offset + 4], 'big')
        proposal_num = data[offset + 4]
        protocol_id = data[offset + 5]
        spi_size = data[offset + 6]
        num_transforms = data[offset + 7]
        
        if proposal_length < 8 or offset + proposal_length > len(data):
            break
        
        proposal = {
            "number": proposal_num,
            "protocol_id": protocol_id,
            "protocol_name": {1: "IKE", 2: "AH", 3: "ESP"}.get(protocol_id, f"UNKNOWN({protocol_id})"),
            "transforms": [],
        }
        
        # Skip SPI
        transform_offset = offset + 8 + spi_size
        
        if spi_size > 0 and transform_offset <= offset + proposal_length:
            spi_data = data[offset + 8:transform_offset]
            proposal["spi"] = spi_data.hex()
        
        # Parse transforms
        for _ in range(num_transforms):
            if transform_offset + 8 > offset + proposal_length:
                break
                
            t_next = data[transform_offset]  # noqa: F841
            t_reserved = data[transform_offset + 1]  # noqa: F841
            t_length = int.from_bytes(data[transform_offset + 2:transform_offset + 4], 'big')
            t_type = data[transform_offset + 4]
            t_reserved2 = data[transform_offset + 5]  # noqa: F841
            t_id = int.from_bytes(data[transform_offset + 6:transform_offset + 8], 'big')
            
            if t_length < 8:
                break
            
            transform = {
                "type": t_type,
                "id": t_id,
            }
            
            # Map transform type and ID to names
            if t_type == TRANSFORM_TYPE_ENCR:
                transform["type_name"] = "Encryption"
                name = ENCR_NAMES.get(t_id, f"UNKNOWN({t_id})")
                # Check for key length attribute
                if t_length > 8:
                    attr_data = data[transform_offset + 8:transform_offset + t_length]
                    key_len = _parse_transform_attributes(attr_data)
                    if key_len:
                        transform["key_length"] = key_len
                        name = f"{name}-{key_len}"
                transform["name"] = name
            elif t_type == TRANSFORM_TYPE_PRF:
                transform["type_name"] = "PRF"
                transform["name"] = PRF_NAMES.get(t_id, f"UNKNOWN({t_id})")
            elif t_type == TRANSFORM_TYPE_INTEG:
                transform["type_name"] = "Integrity"
                transform["name"] = INTEG_NAMES.get(t_id, f"UNKNOWN({t_id})")
            elif t_type == TRANSFORM_TYPE_DH:
                transform["type_name"] = "DH Group"
                transform["name"] = DH_NAMES.get(t_id, f"UNKNOWN({t_id})")
                transform["group_number"] = t_id
            elif t_type == TRANSFORM_TYPE_ESN:
                transform["type_name"] = "ESN"
                transform["name"] = "ESN" if t_id == 1 else "No ESN"
            else:
                transform["type_name"] = f"Type-{t_type}"
                transform["name"] = f"ID-{t_id}"
            
            proposal["transforms"].append(transform)
            transform_offset += t_length
        
        proposals.append(proposal)
        
        if next_prop == 0:
            break
        offset += proposal_length
    
    return proposals


def _parse_transform_attributes(data: bytes) -> int | None:
    """Parse transform attributes to extract key length."""
    offset = 0
    while offset + 4 <= len(data):
        attr_format = (data[offset] >> 7) & 1
        attr_type = int.from_bytes(data[offset:offset + 2], 'big') & 0x7FFF
        
        if attr_format == 1:  # TV format (Type/Value)
            attr_value = int.from_bytes(data[offset + 2:offset + 4], 'big')
            if attr_type == 14:  # Key Length
                return attr_value
            offset += 4
        else:  # TLV format
            if offset + 4 > len(data):
                break
            attr_length = int.from_bytes(data[offset + 2:offset + 4], 'big')
            offset += 4 + attr_length
    
    return None


def _parse_notify_payload(data: bytes, result: dict) -> None:
    """Parse IKEv2 Notify payload for useful information."""
    if len(data) < 4:
        return
    
    protocol_id = data[0]  # noqa: F841
    spi_size = data[1]
    notify_type = int.from_bytes(data[2:4], 'big')
    
    notify_names = {
        16384: "INITIAL_CONTACT",
        16388: "SET_WINDOW_SIZE",
        16389: "ADDITIONAL_TS_POSSIBLE",
        16394: "NAT_DETECTION_SOURCE_IP",
        16395: "NAT_DETECTION_DESTINATION_IP",
        16396: "COOKIE",
        16397: "USE_TRANSPORT_MODE",
        16400: "HTTP_CERT_LOOKUP_SUPPORTED",
        16401: "REKEY_SA",
        16402: "ESP_TFC_PADDING_NOT_SUPPORTED",
        16403: "NON_FIRST_FRAGMENTS_ALSO",
        16404: "MOBIKE_SUPPORTED",
        16405: "ADDITIONAL_IP4_ADDRESS",
        16406: "ADDITIONAL_IP6_ADDRESS",
        16407: "NO_ADDITIONAL_ADDRESSES",
        16408: "UPDATE_SA_ADDRESSES",
        16409: "COOKIE2",
        16410: "NO_NATS_ALLOWED",
        16411: "AUTH_LIFETIME",
        16416: "MULTIPLE_AUTH_SUPPORTED",
        16417: "ANOTHER_AUTH_FOLLOWS",
        16418: "REDIRECT_SUPPORTED",
        16419: "REDIRECT",
        16420: "REDIRECTED_FROM",
        16430: "SIGNATURE_HASH_ALGORITHMS",
    }
    
    name = notify_names.get(notify_type, f"NOTIFY_{notify_type}")
    result.setdefault("ike_notifies", []).append({
        "type": notify_type,
        "name": name,
    })
    
    # Detect NAT-T
    if notify_type in (16394, 16395):
        result["nat_detection"] = True
    
    # Detect transport mode request
    if notify_type == 16397:
        result["transport_mode_requested"] = True
