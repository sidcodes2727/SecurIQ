"""
Minimal, fast PCAP writer (libpcap format, Ethernet link type).

Building packets with struct is ~50x faster than Scapy objects, which matters
when a scenario contains tens of thousands of ESP packets.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path
from typing import Iterable

MAC_A = bytes.fromhex("020000000a01")
MAC_B = bytes.fromhex("020000000b01")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    hdr = hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), next_header, 64,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + payload


def ip_packet(ip_version: int, src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    return ipv4(src, dst, proto, payload, ident) if ip_version == 4 else ipv6(src, dst, proto, payload)


def udp(ip_version: int, src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", sport, dport, length, 0) + payload
    if ip_version == 6:  # UDP checksum is mandatory over IPv6
        pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed +
                  struct.pack("!IxxxB", length, 17))
        csum = _checksum(pseudo + segment) or 0xFFFF
        segment = segment[:6] + struct.pack("!H", csum) + segment[8:]
    return segment


def ethernet(ip_bytes: bytes, ip_version: int, forward: bool = True) -> bytes:
    src, dst = (MAC_A, MAC_B) if forward else (MAC_B, MAC_A)
    return dst + src + struct.pack("!H", 0x0800 if ip_version == 4 else 0x86DD) + ip_bytes


def write_pcap(path: str | Path, frames: Iterable[tuple[float, bytes]]) -> int:
    """frames: (timestamp, ethernet frame). Returns the number of packets written."""
    count = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
            count += 1
    return count
