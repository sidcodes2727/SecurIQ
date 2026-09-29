"""
PCAP / PCAPNG parser for IPsec traffic.

A struct-based reader (no per-packet object model) that decodes the link layer
(Ethernet + VLAN, Linux SLL/SLL2, raw IP, BSD loopback), IPv4 and IPv6 (with
extension headers), and classifies:

  ike             IKE on UDP 500
  ike_natt        IKE on UDP 4500 behind the non-ESP marker (RFC 3948)
  esp             native ESP (IP proto 50) or ESP-in-UDP on 4500
  ah              AH (IP proto 51)
  natt_keepalive  single 0xFF byte on UDP 4500
  other           everything else

Lengths come from IP headers, never from the capture frame, so link-layer
framing and Ethernet padding cannot distort the ESP length fingerprint.
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct
import time
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from backend.analyzers.ike_constants import AH_PROTO, ESP_PROTO, IKE_NATT_PORT, IKE_PORT
from backend.analyzers.ike_parser import parse_ike_message

DEFAULT_MAX_PACKETS = 2_000_000
PROTOCOL_TYPES = ("ike", "ike_natt", "esp", "ah", "natt_keepalive", "other")

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW = 0, 1, 101
LINKTYPE_SLL, LINKTYPE_SLL2, LINKTYPE_IPV4, LINKTYPE_IPV6 = 113, 276, 228, 229
RAW_LINKTYPES = {LINKTYPE_RAW, 12, 14, LINKTYPE_IPV4, LINKTYPE_IPV6}
IPV6_EXTENSION_HEADERS = {0, 43, 60}


class CaptureFormatError(ValueError):
    """The file is not a readable pcap/pcapng capture."""


def is_capture_file(head: bytes) -> bool:
    return head[:4] in PCAP_MAGICS or head[:4] == PCAPNG_MAGIC


def parse_pcap(file_path: str, max_packets: int = DEFAULT_MAX_PACKETS) -> dict[str, Any]:
    """Parse a capture. Returns {"metadata": ..., "packets": [...], "summary": {...}}."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    start = time.time()
    packets: list[dict[str, Any]] = []
    stats = {key: 0 for key in PROTOCOL_TYPES}
    stats.update({"total": 0, "ipv4": 0, "ipv6": 0, "ip_fragment": 0, "non_ip": 0})
    truncated = False
    decoder = _Decoder()

    with open(path, "rb") as fh:
        for index, (ts, linktype, frame) in enumerate(read_frames(fh), start=1):  # Wireshark frame numbers
            if index >= max_packets:
                truncated = True
                break
            parsed = decoder.decode(frame, linktype, ts, index)
            packets.append(parsed)
            stats["total"] += 1
            stats[parsed["protocol_type"]] += 1
            version = parsed["ip_version"]
            if version == 4:
                stats["ipv4"] += 1
            elif version == 6:
                stats["ipv6"] += 1
            else:
                stats["non_ip"] += 1
            if parsed.get("ip_fragment"):
                stats["ip_fragment"] += 1

    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)

    return {
        "metadata": {
            "filename": path.name,
            "file_size": path.stat().st_size,
            "file_hash": sha.hexdigest()[:16],
            "total_packets": len(packets),
            "parsed_packets": len(packets),
            "truncated": truncated,
            "parse_duration_ms": round((time.time() - start) * 1000, 2),
        },
        "packets": packets,
        "summary": stats,
    }


# ================================================================ file formats

def read_frames(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame bytes) from a pcap or pcapng stream."""
    magic = fh.read(4)
    if magic in PCAP_MAGICS:
        yield from _read_pcap(fh, magic)
    elif magic == PCAPNG_MAGIC:
        yield from _read_pcapng(fh)
    else:
        raise CaptureFormatError("Not a pcap or pcapng file (unknown magic number)")


def _read_pcap(fh: BinaryIO, magic: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian, resolution = PCAP_MAGICS[magic]
    header = fh.read(20)
    if len(header) < 20:
        raise CaptureFormatError("Truncated pcap global header")
    linktype = struct.unpack(endian + "HHiIII", header)[5] & 0x0FFFFFFF
    record = struct.Struct(endian + "IIII")
    while True:
        rh = fh.read(16)
        if len(rh) < 16:
            return
        sec, frac, caplen, _ = record.unpack(rh)
        data = fh.read(caplen)
        if len(data) < caplen:
            return
        yield sec + frac * resolution, linktype, data


def _read_pcapng(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    first = True
    while True:
        head = PCAPNG_MAGIC if first else fh.read(4)
        if len(head) < 4:
            return
        length_raw = fh.read(4)
        if len(length_raw) < 4:
            return
        if first or head == PCAPNG_MAGIC:
            body_start = fh.read(4)
            endian = "<" if body_start == b"\x4d\x3c\x2b\x1a" else ">"
            total = struct.unpack(endian + "I", length_raw)[0]
            fh.read(total - 12)
            interfaces = []
            first = False
            continue
        block_type = struct.unpack(endian + "I", head)[0]
        total = struct.unpack(endian + "I", length_raw)[0]
        if total < 12:
            raise CaptureFormatError("Corrupt pcapng block length")
        body = fh.read(total - 12)
        fh.read(4)
        if block_type == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _pcapng_tsresol(body[8:], endian)))
        elif block_type == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_high, ts_low, caplen, _ = struct.unpack(endian + "IIIII", body[:20])
            if iface < len(interfaces):
                linktype, resolution = interfaces[iface]
                yield ((ts_high << 32) | ts_low) * resolution, linktype, body[20:20 + caplen]
        elif block_type == 3 and len(body) >= 4 and interfaces:  # Simple Packet Block
            yield 0.0, interfaces[0][0], body[4:]
        elif block_type == 2 and len(body) >= 20:  # obsolete Packet Block
            iface, _, ts_high, ts_low, caplen, _ = struct.unpack(endian + "HHIIII", body[:20])
            if iface < len(interfaces):
                linktype, resolution = interfaces[iface]
                yield ((ts_high << 32) | ts_low) * resolution, linktype, body[20:20 + caplen]


def _pcapng_tsresol(options: bytes, endian: str) -> float:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[offset + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        offset += 4 + ((length + 3) & ~3)
    return 1e-6


# ================================================================ packet decoding

class _Decoder:
    def __init__(self) -> None:
        self._v6_names: dict[bytes, str] = {}

    def _v6(self, raw: bytes) -> str:
        name = self._v6_names.get(raw)
        if name is None:
            name = self._v6_names[raw] = str(ipaddress.IPv6Address(raw))
        return name

    def decode(self, frame: bytes, linktype: int, ts: float, index: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "index": index, "timestamp": ts, "length": len(frame), "ip_version": None,
            "src_ip": None, "dst_ip": None, "protocol_type": "other",
            "src_port": None, "dst_port": None, "nat_t": False,
        }
        ip = _strip_link_layer(frame, linktype)
        if ip is None or len(ip) < 20:
            return result
        version = ip[0] >> 4
        if version == 4:
            self._ipv4(ip, result)
        elif version == 6 and len(ip) >= 40:
            self._ipv6(ip, result)
        return result

    def _ipv4(self, ip: bytes, result: dict) -> None:
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        frag = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
        proto = ip[9]
        result.update(ip_version=4, src_ip=socket.inet_ntoa(ip[12:16]), dst_ip=socket.inet_ntoa(ip[16:20]),
                      ip_proto=proto, length=total)
        if frag:
            result["ip_fragment"] = True
            return
        payload = ip[ihl:total] if total >= ihl else ip[ihl:]
        _transport(proto, payload, max(0, total - ihl), result)

    def _ipv6(self, ip: bytes, result: dict) -> None:
        payload_len = struct.unpack("!H", ip[4:6])[0]
        next_header = ip[6]
        result.update(ip_version=6, src_ip=self._v6(ip[8:24]), dst_ip=self._v6(ip[24:40]),
                      ip_proto=next_header, length=40 + payload_len)
        payload = ip[40:40 + payload_len]
        declared = payload_len
        while next_header in IPV6_EXTENSION_HEADERS or next_header == 44:
            if len(payload) < 8:
                return
            if next_header == 44:  # fragment header
                if struct.unpack("!H", payload[2:4])[0] >> 3:
                    result["ip_fragment"] = True
                    return
                next_header, payload, declared = payload[0], payload[8:], declared - 8
            else:
                ext_len = (payload[1] + 1) * 8
                next_header, payload, declared = payload[0], payload[ext_len:], declared - ext_len
        result["ip_proto"] = next_header
        _transport(next_header, payload, max(0, declared), result)


PacketDecoder = _Decoder  # public name for the streaming engine


def _strip_link_layer(frame: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_ETHERNET:
        offset, ethertype = 14, struct.unpack("!H", frame[12:14])[0] if len(frame) >= 14 else 0
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(frame) >= offset + 4:
            ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        return frame[offset:] if ethertype in (0x0800, 0x86DD) else None
    if linktype in RAW_LINKTYPES:
        return frame
    if linktype == LINKTYPE_SLL and len(frame) >= 16:
        return frame[16:] if frame[14:16] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == LINKTYPE_SLL2 and len(frame) >= 20:
        return frame[20:] if frame[0:2] in (b"\x08\x00", b"\x86\xdd") else None
    if linktype == LINKTYPE_NULL and len(frame) >= 4:
        family = max(struct.unpack("<I", frame[:4])[0], struct.unpack(">I", frame[:4])[0]) & 0xFF
        return frame[4:] if family in (2, 24, 28, 30) else None
    return None


def _transport(proto: int, payload: bytes, declared: int, result: dict) -> None:
    """declared = L4 length from the IP header (correct even when a small snaplen truncated the frame)."""
    if proto == 17 and len(payload) >= 8:
        sport, dport, length = struct.unpack("!HHH", payload[:6])
        result["src_port"], result["dst_port"] = sport, dport
        data = payload[8:length] if length >= 8 else payload[8:]
        if IKE_PORT in (sport, dport):
            _ike(data, result, "ike")
        elif IKE_NATT_PORT in (sport, dport):
            _udp_4500(data, max(0, (length or declared) - 8), result)
    elif proto == ESP_PROTO:
        _esp(payload, declared, result)
    elif proto == AH_PROTO:
        _ah(payload, result)


def _ike(data: bytes, result: dict, protocol_type: str) -> None:
    msg = parse_ike_message(data)
    if msg is None:
        result["note"] = "UDP 500/4500 payload is not a valid IKE header"
        return
    result["protocol_type"] = protocol_type
    result["ike"] = msg


def _udp_4500(data: bytes, declared: int, result: dict) -> None:
    result["nat_t"] = True
    if data == b"\xff":
        result["protocol_type"] = "natt_keepalive"
    elif data[:4] == b"\x00\x00\x00\x00":
        _ike(data[4:], result, "ike_natt")
    elif len(data) >= 8:
        _esp(data, declared, result)


def _esp(data: bytes, declared: int, result: dict) -> None:
    """ESP: SPI(4) | Sequence(4) | IV + ciphertext + ICV."""
    result["protocol_type"] = "esp"
    if len(data) < 8:
        return
    spi, seq = struct.unpack("!II", data[:8])
    result["spi"] = hex(spi)
    result["seq_num"] = seq
    result["esp_payload_len"] = max(declared, len(data)) - 8
    # IV for real ciphers; an inner IP/UDP header when encryption is NULL
    result["esp_head"] = data[8:24].hex()


def _ah(data: bytes, result: dict) -> None:
    """AH authenticates but does not encrypt; its Next Header is cleartext, exposing the mode."""
    result["protocol_type"] = "ah"
    if len(data) < 12:
        return
    next_header, payload_len = data[0], data[1]
    spi, seq = struct.unpack("!II", data[4:12])
    result.update(spi=hex(spi), seq_num=seq, ah_next_header=next_header,
                  ah_icv_len=max(0, (payload_len + 2) * 4 - 12))
