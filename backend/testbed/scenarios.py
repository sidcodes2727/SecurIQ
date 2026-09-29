"""
Scenario matrix and capture builder for the VPN testbed.

A Scenario describes one IPsec deployment (PS §a): IKE version and exchange,
IKE/ESP cipher suites, DH group, PFS, tunnel/transport, IPv4/IPv6, NAT-T,
authentication, lifetimes, application traffic, and optional anomalies.
build_capture() turns it into a PCAP-ready frame list plus ground truth.

Cleartext IKE payloads are byte-accurate. Encrypted IKE content is random data
whose size follows the RFC payload layout, which is precisely what a passive
analyzer (and a real adversary) observes.
"""
from __future__ import annotations

import math
import random
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from backend.analyzers.ike_constants import DH_KE_LENGTH, DH_NAMES, V1_AUTH_METHOD
from backend.testbed import ike_builder as ib
from backend.testbed import pcap_writer as pw
from backend.testbed.esp_model import (
    ESP_SUITES, IKE_SUITES, WEAK_FALLBACK, V1_ENCRYPTION_NAMES, V1_HASH_NAMES,
    esp_payload_len, inner_packet_len,
)
from backend.testbed.impairments import impair
from backend.testbed.traffic_models import TRAFFIC_CLASSES, generate_traffic

BASE_TIME = 1_760_000_000.0
GATEWAYS = {4: ("198.51.100.10", "203.0.113.20"), 6: ("2001:db8:a::10", "2001:db8:b::20")}
AUTH_V1_IDS = {"psk": 1, "rsa": 3, "ecdsa": 9, "xauth-psk": 65001}
AUTH_LABELS = {"psk": "Pre-Shared Key", "rsa": "Certificate (RSA)", "ecdsa": "Certificate (ECDSA)",
               "eap": "EAP", "xauth-psk": "XAUTH + Pre-Shared Key"}

# (request size range, response size range) per IKE_AUTH round trip
IKEV2_AUTH_ROUNDS = {
    "psk": [((300, 380), (250, 320))],
    "rsa": [((1250, 1750), (1150, 1650))],
    "ecdsa": [((600, 800), (580, 760))],
    "eap": [((300, 360), (1300, 1700)), ((110, 180), (110, 200)),
            ((110, 180), (110, 200)), ((120, 170), (200, 260))],
}


@dataclass
class Scenario:
    name: str
    description: str = ""
    ike_version: int = 2
    aggressive: bool = False
    ike_suite: str = "aes256-sha256-modp2048"
    esp_suite: str = "aes256gcm16"
    protocol: str = "esp"            # "esp" or "ah"
    ah_icv: int = 16
    pfs: bool = True
    mode: str = "tunnel"             # "tunnel" or "transport"
    ip_version: int = 4
    nat_t: bool = False
    auth: str = "psk"
    lifetime: int = 28800            # IKEv1 Phase 1 life duration (seconds)
    rekey_after: float | None = None
    traffic: list[tuple[str, float]] = field(default_factory=lambda: [("web", 30.0)])
    vendor: str | None = "strongswan"
    offer_weak: bool = False
    identity: str = "gw-a.example.org"
    replay_duplicates: int = 0
    counter_reset: bool = False
    impairment: str = "none"        # network impairment level (testbed/impairments.py)
    seed: int = 1


# ================================================================ curated demo scenarios

SAMPLE_SCENARIOS: list[Scenario] = [
    Scenario("strong_ikev2_gcm_ecp384_pfs",
             "IKEv2, AES-256-GCM, ECP-384, PFS, certificate auth — hardened site-to-site tunnel",
             ike_suite="aes256gcm16-prfsha384-ecp384", esp_suite="aes256gcm16", pfs=True, rekey_after=20,
             auth="rsa", traffic=[("web", 25), ("video", 30)], seed=11),
    Scenario("moderate_ikev2_cbc_sha1_nopfs",
             "IKEv2, AES-128-CBC + HMAC-SHA1, MODP-2048, no PFS, legacy fallback proposal offered",
             ike_suite="aes128-sha1-modp2048", esp_suite="aes128-sha1", pfs=False, rekey_after=25,
             offer_weak=True, traffic=[("email", 30), ("chat", 30)], seed=12),
    Scenario("weak_ikev1_main_3des_md5",
             "IKEv1 Main Mode, 3DES + MD5, MODP-1024, 7-day lifetime — legacy configuration",
             ike_version=1, ike_suite="3des-md5-modp1024", esp_suite="3des-md5", pfs=False,
             lifetime=604800, vendor="cisco", traffic=[("icmp", 30), ("file_transfer", 20)], seed=13),
    Scenario("ikev1_aggressive_psk_identity",
             "IKEv1 Aggressive Mode with PSK — identity in cleartext, PSK hash crackable offline",
             ike_version=1, aggressive=True, ike_suite="aes128-sha1-modp1536", esp_suite="aes128-sha1",
             pfs=False, lifetime=86400, vendor="cisco", identity="vpnuser@corp.example",
             traffic=[("voip", 30)], seed=14),
    Scenario("transport_ipv6_voip",
             "IKEv2 transport mode over IPv6, AES-128-GCM, Curve25519 — host-to-host",
             ike_suite="aes128gcm16-prfsha256-curve25519", esp_suite="aes128gcm16", mode="transport",
             ip_version=6, pfs=True, rekey_after=25, traffic=[("voip", 25), ("web", 20)], seed=15),
    Scenario("natt_ikev2_chacha_eap",
             "IKEv2 behind NAT (UDP 4500), ChaCha20-Poly1305, EAP remote-access",
             ike_suite="aes128gcm16-prfsha256-curve25519", esp_suite="chacha20poly1305", nat_t=True,
             auth="eap", vendor="windows", pfs=False, traffic=[("chat", 30), ("web", 20)], seed=16),
    Scenario("mixed_all_traffic_ikev2",
             "IKEv2 tunnel carrying all seven traffic classes in sequence, with PFS rekeys",
             ike_suite="aes256-sha256-modp2048", esp_suite="aes256-sha256", pfs=True, rekey_after=45,
             auth="rsa", traffic=[(c, 15.0) for c in TRAFFIC_CLASSES], seed=17),
    Scenario("misconfig_esp_null",
             "ESP with NULL encryption — integrity only, traffic readable on the wire",
             esp_suite="null-sha256", pfs=False, traffic=[("web", 20), ("icmp", 10)], seed=18),
    Scenario("replay_anomaly",
             "Duplicate ESP sequence numbers and a counter reset without rekey",
             ike_suite="aes128-sha256-ecp256", esp_suite="aes128-sha256", pfs=False,
             replay_duplicates=12, counter_reset=True, traffic=[("file_transfer", 15), ("icmp", 15)], seed=19),
    Scenario("ah_transport_integrity_only",
             "AH transport mode — authenticated but unencrypted traffic",
             protocol="ah", mode="transport", pfs=False, traffic=[("icmp", 20), ("email", 20)], seed=20),
]


def random_scenario(rng: random.Random, index: int, duration: tuple[float, float] = (20, 30),
                    impairment: str = "none") -> Scenario:
    """Sample one point of the configuration matrix."""
    ike_version = 2 if rng.random() < 0.7 else 1
    aggressive = ike_version == 1 and rng.random() < 0.3
    auth_choices = ["psk", "psk", "rsa", "ecdsa"] + (["eap"] if ike_version == 2 else [])
    rekey = rng.uniform(8, 18) if rng.random() < 0.5 else None
    classes = rng.sample(TRAFFIC_CLASSES, k=rng.choice([1, 2]))
    return Scenario(
        name=f"matrix_{index:04d}",
        description="Random configuration-matrix scenario",
        ike_version=ike_version,
        aggressive=aggressive,
        ike_suite=rng.choice(list(IKE_SUITES)),
        esp_suite=rng.choice([k for k in ESP_SUITES if k != "null-sha256"]),
        pfs=rng.random() < 0.5,
        mode="transport" if rng.random() < 0.3 else "tunnel",
        ip_version=6 if rng.random() < 0.3 else 4,
        nat_t=rng.random() < 0.25,
        auth=rng.choice(auth_choices),
        lifetime=rng.choice([3600, 28800, 86400, 604800]),
        rekey_after=rekey,
        traffic=[(c, rng.uniform(*duration)) for c in classes],
        vendor=rng.choice(["strongswan", "cisco", "windows", None]),
        offer_weak=rng.random() < 0.25,
        identity=rng.choice(["gw-a.example.org", "vpnuser@corp.example", "198.51.100.10"]),
        impairment=impairment,
        seed=rng.randint(1, 10**9),
    )


# ================================================================ builder

class CaptureBuilder:
    def __init__(self, scenario: Scenario):
        self.sc = scenario
        self.rng = random.Random(scenario.seed)
        self.frames: list[tuple[float, bytes]] = []
        self.gw_a, self.gw_b = GATEWAYS[scenario.ip_version]
        self.ident = self.rng.randint(0, 0xFFFF)
        self.natt_active = False
        self.ike_spis = (b"", b"")
        self.message_id = 0
        self.esp_records: list[dict[str, Any]] = []
        self.rekey_times: list[float] = []
        self.suite = IKE_SUITES[scenario.ike_suite]

    # ------------------------------------------------------------ emit helpers

    def _emit_ip(self, ts: float, forward: bool, proto: int, payload: bytes) -> None:
        src, dst = (self.gw_a, self.gw_b) if forward else (self.gw_b, self.gw_a)
        self.ident += 1
        packet = pw.ip_packet(self.sc.ip_version, src, dst, proto, payload, self.ident)
        self.frames.append((round(ts, 6), pw.ethernet(packet, self.sc.ip_version, forward)))

    def _emit_udp(self, ts: float, forward: bool, port: int, payload: bytes) -> None:
        src, dst = (self.gw_a, self.gw_b) if forward else (self.gw_b, self.gw_a)
        self._emit_ip(ts, forward, 17, pw.udp(self.sc.ip_version, src, dst, port, port, payload))

    def _emit_ike(self, ts: float, forward: bool, message: bytes) -> None:
        if self.natt_active:
            self._emit_udp(ts, forward, 4500, b"\x00\x00\x00\x00" + message)
        else:
            self._emit_udp(ts, forward, 500, message)

    def _emit_v2_encrypted(self, ts: float, forward: bool, exchange: int, total: int, inner: int,
                           response: bool, fragment: bool = False) -> None:
        ispi, rspi = self.ike_spis
        flags = (0x20 if response else 0) | (0x08 if forward else 0)
        if fragment and total > 1200:
            count = math.ceil(total / 1100)
            for n in range(1, count + 1):
                size = total // count
                body = struct.pack("!HH", n, count) + self.rng.randbytes(max(16, size - 36))
                first, payloads = ib.chain([(53, body, inner if n == 1 else 0)])
                self._emit_ike(ts + n * 0.0005, forward,
                               ib.header(ispi, rspi, first, 2, exchange, flags, self.message_id, payloads))
            return
        first, payloads = ib.chain([(ib.V2_SK, ib.v2_sk_payload(total, self.rng), inner)])
        self._emit_ike(ts, forward, ib.header(ispi, rspi, first, 2, exchange, flags, self.message_id, payloads))

    def _emit_v1_encrypted(self, ts: float, forward: bool, exchange: int, message_id: int, size: int) -> None:
        ispi, rspi = self.ike_spis
        body = self.rng.randbytes(max(8, size - 28))
        self._emit_ike(ts, forward, ib.header(ispi, rspi, 8, 1, exchange, 0x01, message_id, body))

    # ------------------------------------------------------------ IKEv2

    def _ikev2(self, t: float) -> float:
        sc, rng, suite = self.sc, self.rng, self.suite
        offers = [suite] + ([WEAK_FALLBACK] if sc.offer_weak and WEAK_FALLBACK is not suite else [])
        ispi, rspi = rng.randbytes(8), rng.randbytes(8)
        nat_d = [(ib.V2_NOTIFY, ib.v2_notify(16388, rng.randbytes(20))),
                 (ib.V2_NOTIFY, ib.v2_notify(16389, rng.randbytes(20)))]
        caps = [(ib.V2_NOTIFY, ib.v2_notify(16430)),
                (ib.V2_NOTIFY, ib.v2_notify(16431, struct.pack("!HHH", 2, 3, 4)))]
        vid = [(ib.V2_VID, bytes.fromhex(ib.VENDOR_IDS[sc.vendor]))] if sc.vendor else []

        first, body = ib.chain([(ib.V2_SA, ib.v2_sa(offers)), (ib.V2_KE, ib.v2_ke(suite.dh_group, rng)),
                                (ib.V2_NONCE, rng.randbytes(32))] + nat_d + caps + vid)
        self._emit_ike(t, True, ib.header(ispi, b"\x00" * 8, first, 2, 34, 0x08, 0, body))

        certreq = [(ib.V2_CERTREQ, bytes([4]) + rng.randbytes(20))] if sc.auth in ("rsa", "ecdsa", "eap") else []
        first, body = ib.chain([(ib.V2_SA, ib.v2_sa([suite])), (ib.V2_KE, ib.v2_ke(suite.dh_group, rng)),
                                (ib.V2_NONCE, rng.randbytes(32))] + nat_d + certreq + caps + vid)
        self._emit_ike(t + 0.03, False, ib.header(ispi, rspi, first, 2, 34, 0x20, 0, body))

        self.ike_spis = (ispi, rspi)
        self.natt_active = sc.nat_t
        t += 0.06
        for i, (req, resp) in enumerate(IKEV2_AUTH_ROUNDS[sc.auth]):
            self.message_id = i + 1
            fragment = sc.auth == "rsa"
            self._emit_v2_encrypted(t, True, 35, rng.randint(*req), ib.V2_IDI if i == 0 else 48, False, fragment)
            self._emit_v2_encrypted(t + 0.02, False, 35, rng.randint(*resp), ib.V2_IDR if i == 0 else 48, True,
                                    fragment)
            t += 0.05
        return t

    def _ikev2_child_rekey(self, t: float) -> None:
        rng = self.rng
        ke = DH_KE_LENGTH[self.suite.dh_group] + 8 if self.sc.pfs else 0
        selectors = 48 if self.sc.ip_version == 6 else 0
        resp = rng.randint(196, 236) + selectors + ke
        req = resp + rng.randint(0, 40)
        self.message_id += 1
        self._emit_v2_encrypted(t, True, 36, req, 33, False)
        self._emit_v2_encrypted(t + 0.02, False, 36, resp, 33, True)
        self.message_id += 1  # delete the old Child SA
        self._emit_v2_encrypted(t + 0.2, True, 37, rng.randint(76, 92), 42, False)
        self._emit_v2_encrypted(t + 0.22, False, 37, rng.randint(76, 92), 42, True)

    # ------------------------------------------------------------ IKEv1

    def _ikev1(self, t: float) -> float:
        sc, rng, suite = self.sc, self.rng, self.suite
        auth_id = AUTH_V1_IDS.get(sc.auth, 1)
        transforms = [ib.v1_transform_for(suite, auth_id, sc.lifetime)]
        if sc.offer_weak and WEAK_FALLBACK is not suite:
            transforms.append(ib.v1_transform_for(WEAK_FALLBACK, auth_id, sc.lifetime))
        ispi, rspi = rng.randbytes(8), rng.randbytes(8)
        vids = [(ib.V1_VID, bytes.fromhex(ib.VENDOR_IDS[v])) for v in ("dpd", "natt")]
        if sc.vendor:
            vids.append((ib.V1_VID, bytes.fromhex(ib.VENDOR_IDS[sc.vendor])))
        natd = [(ib.V1_NATD, rng.randbytes(20)), (ib.V1_NATD, rng.randbytes(20))]
        group = suite.dh_group

        if sc.aggressive:
            first, body = ib.chain([(ib.V1_SA, ib.v1_sa(transforms)), (ib.V1_KE, ib.v1_ke(group, rng)),
                                    (ib.V1_NONCE, rng.randbytes(20)), (ib.V1_ID, ib.v1_id(sc.identity))] + vids)
            self._emit_ike(t, True, ib.header(ispi, b"\x00" * 8, first, 1, 4, 0, 0, body))
            first, body = ib.chain([(ib.V1_SA, ib.v1_sa(transforms[:1])), (ib.V1_KE, ib.v1_ke(group, rng)),
                                    (ib.V1_NONCE, rng.randbytes(20)), (ib.V1_ID, ib.v1_id(self.gw_b)),
                                    (ib.V1_HASH, rng.randbytes(20))] + vids + natd)
            self._emit_ike(t + 0.03, False, ib.header(ispi, rspi, first, 1, 4, 0, 0, body))
            self.ike_spis = (ispi, rspi)
            self.natt_active = sc.nat_t
            self._emit_v1_encrypted(t + 0.06, True, 4, 0, rng.randint(60, 92))
            t += 0.1
        else:
            first, body = ib.chain([(ib.V1_SA, ib.v1_sa(transforms))] + vids)
            self._emit_ike(t, True, ib.header(ispi, b"\x00" * 8, first, 1, 2, 0, 0, body))
            first, body = ib.chain([(ib.V1_SA, ib.v1_sa(transforms[:1]))] + vids)
            self._emit_ike(t + 0.02, False, ib.header(ispi, rspi, first, 1, 2, 0, 0, body))
            first, body = ib.chain([(ib.V1_KE, ib.v1_ke(group, rng)), (ib.V1_NONCE, rng.randbytes(20))] + natd)
            self._emit_ike(t + 0.04, True, ib.header(ispi, rspi, first, 1, 2, 0, 0, body))
            certreq = [(ib.V1_CERTREQ, bytes([4]))] if sc.auth in ("rsa", "ecdsa") else []
            first, body = ib.chain([(ib.V1_KE, ib.v1_ke(group, rng)), (ib.V1_NONCE, rng.randbytes(20))]
                                   + certreq + natd)
            self._emit_ike(t + 0.07, False, ib.header(ispi, rspi, first, 1, 2, 0, 0, body))
            self.ike_spis = (ispi, rspi)
            self.natt_active = sc.nat_t
            size = (rng.randint(68, 108) if sc.auth.endswith("psk")
                    else rng.randint(1100, 1500) if sc.auth == "rsa" else rng.randint(500, 700))
            self._emit_v1_encrypted(t + 0.09, True, 2, 0, size)
            self._emit_v1_encrypted(t + 0.11, False, 2, 0, size + rng.randint(-20, 20))
            t += 0.13
        self._ikev1_quick_mode(t)
        return t + 0.1

    def _ikev1_quick_mode(self, t: float) -> None:
        rng = self.rng
        ke = DH_KE_LENGTH[self.suite.dh_group] + 4 if self.sc.pfs else 0
        mid = rng.randint(1, 0xFFFFFFFF)
        resp = rng.randint(170, 200) + ke
        self._emit_v1_encrypted(t, True, 32, mid, resp + rng.randint(0, 16))
        self._emit_v1_encrypted(t + 0.02, False, 32, mid, resp)
        self._emit_v1_encrypted(t + 0.04, True, 32, mid, rng.randint(52, 68))

    # ------------------------------------------------------------ traffic

    def _traffic_events(self, t: float) -> tuple[list[tuple], list[dict]]:
        events, segments = [], []
        for cls, duration in self.sc.traffic:
            for et, direction, l4, proto in impair(generate_traffic(cls, duration, self.rng), duration, self.rng,
                                                   self.sc.impairment):
                events.append((t + et, direction, l4, proto))
            segments.append({"class": cls, "start": round(t, 6), "end": round(t + duration, 6)})
            t += duration + self.rng.uniform(0.5, 2.0)
        events.sort(key=lambda e: e[0])
        return events, segments

    def _new_spis(self) -> list[int]:
        return [self.rng.randint(0x1000_0000, 0xFFFF_FFFF), self.rng.randint(0x1000_0000, 0xFFFF_FFFF)]

    def _esp_payload(self, esp_len: int, inner_len: int, proto: int) -> bytes:
        suite = ESP_SUITES[self.sc.esp_suite]
        if suite.family != "NULL":
            return self.rng.randbytes(esp_len)
        ipv = self.sc.ip_version
        if self.sc.mode == "tunnel":
            src, dst = ("10.1.0.5", "10.2.0.9") if ipv == 4 else ("fd00:1::5", "fd00:2::9")
            header = pw.ip_packet(ipv, src, dst, proto, b"")
            if ipv == 4:
                header = header[:2] + struct.pack("!H", inner_len) + header[4:]
            else:
                header = header[:4] + struct.pack("!H", inner_len - 40) + header[6:]
        else:
            header = struct.pack("!HHHH", 40000, 5060, inner_len, 0) if proto == 17 else self.rng.randbytes(8)
        body = header + self.rng.randbytes(max(0, inner_len - len(header)))
        pad = esp_len - suite.icv - inner_len - 2
        next_header = (4 if ipv == 4 else 41) if self.sc.mode == "tunnel" else proto
        return body + bytes(range(1, pad + 1)) + bytes([pad, next_header]) + self.rng.randbytes(suite.icv)

    def _emit_protected(self, events: list[tuple]) -> None:
        sc, rng = self.sc, self.rng
        suite = ESP_SUITES.get(sc.esp_suite)
        spis = self._new_spis()
        seqs = [0, 0]
        rekeys = list(self.rekey_times)
        duplicates, reset_done = [], False
        halfway = events[len(events) // 2][0] if events else 0

        for ts, direction, l4, proto in events:
            while rekeys and ts >= rekeys[0] + 0.05:
                rekeys.pop(0)
                spis, seqs = self._new_spis(), [0, 0]
            if sc.counter_reset and not reset_done and direction == 0 and ts >= halfway:
                seqs[0], reset_done = 0, True
            seqs[direction] += 1
            spi, seq = spis[direction], seqs[direction]
            forward = direction == 0

            if sc.protocol == "ah":
                inner = self._ah_inner(l4, proto)
                icv = rng.randbytes(sc.ah_icv)
                nh = (4 if sc.ip_version == 4 else 41) if sc.mode == "tunnel" else proto
                ah = struct.pack("!BBHII", nh, (12 + sc.ah_icv) // 4 - 2, 0, spi, seq) + icv
                self._emit_ip(ts, forward, 51, ah + inner)
                continue

            inner_len = inner_packet_len(l4, sc.mode, sc.ip_version)
            length = esp_payload_len(inner_len, suite)
            esp = struct.pack("!II", spi, seq) + self._esp_payload(length, inner_len, proto)
            if sc.nat_t:
                self._emit_udp(ts, forward, 4500, esp)
            else:
                self._emit_ip(ts, forward, 50, esp)
            src, dst = (self.gw_a, self.gw_b) if forward else (self.gw_b, self.gw_a)
            self.esp_records.append({"timestamp": round(ts, 6), "spi": hex(spi), "src_ip": src, "dst_ip": dst,
                                     "esp_payload_len": length, "protocol_type": "esp", "seq_num": seq})
            if len(duplicates) < sc.replay_duplicates and seq > 5 and rng.random() < 0.05:
                duplicates.append((ts + rng.uniform(0.5, 2.0), self.frames[-1][1]))
        self.frames.extend((round(ts, 6), frame) for ts, frame in duplicates)

    def _ah_inner(self, l4: int, proto: int) -> bytes:
        rng = self.rng
        if proto == 17:
            header = struct.pack("!HHHH", 40000, 53, l4, 0)
        elif proto == 6:
            header = struct.pack("!HHIIBBHHH", 51000, 443, rng.getrandbits(32), rng.getrandbits(32),
                                 0x50, 0x18, 502, 0, 0)
        else:
            header = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
        inner = header + rng.randbytes(max(0, l4 - len(header)))
        if self.sc.mode == "tunnel":
            inner = pw.ip_packet(self.sc.ip_version, "10.1.0.5", "10.2.0.9", proto, inner)
        return inner

    # ------------------------------------------------------------ assemble

    def build(self) -> tuple[list[tuple[float, bytes]], dict[str, Any]]:
        sc = self.sc
        t = BASE_TIME + sc.seed % 100_000
        t = self._ikev2(t) if sc.ike_version == 2 else self._ikev1(t)
        events, segments = self._traffic_events(t + 0.3)
        if events:
            start, end = events[0][0], events[-1][0]
            if sc.rekey_after:
                r = start + sc.rekey_after
                while r < end - 1:
                    self.rekey_times.append(r)
                    r += sc.rekey_after
            for r in self.rekey_times:
                if sc.ike_version == 2:
                    self._ikev2_child_rekey(r)
                else:
                    self._ikev1_quick_mode(r)
            if sc.nat_t:
                k = start + 5
                while k < end:
                    self._emit_udp(k, True, 4500, b"\xff")
                    k += 20
        self._emit_protected(events)
        self.frames.sort(key=lambda f: f[0])
        return self.frames, self._truth(segments)

    def _truth(self, segments: list[dict]) -> dict[str, Any]:
        sc, suite = self.sc, self.suite
        esp = ESP_SUITES.get(sc.esp_suite)
        if sc.ike_version == 2:
            ike_enc, ike_integ = suite.encryption_name, suite.integrity_name or "None (AEAD)"
            auth = AUTH_LABELS[sc.auth]
            mode_label = "IKEv2"
        else:
            enc = V1_ENCRYPTION_NAMES[suite.v1_encryption]
            ike_enc = f"AES-{suite.key_length}-CBC" if enc == "AES-CBC" and suite.key_length else enc
            ike_integ = f"HMAC-{V1_HASH_NAMES[suite.v1_hash]}"
            auth = V1_AUTH_METHOD[AUTH_V1_IDS.get(sc.auth, 1)]
            mode_label = "Aggressive Mode" if sc.aggressive else "Main Mode"
        return {
            "name": sc.name,
            "description": sc.description,
            "config": asdict(sc),
            "ike_version": f"IKEv{sc.ike_version}",
            "exchange_mode": mode_label,
            "mode": sc.mode.capitalize(),
            "ipsec_protocols": "AH" if sc.protocol == "ah" else "ESP",
            "ike_encryption": ike_enc,
            "ike_integrity": ike_integ,
            "dh_group": suite.dh_group,
            "dh_group_name": DH_NAMES[suite.dh_group],
            "esp_suite": esp.label if sc.protocol == "esp" else None,
            "esp_family": esp.family if sc.protocol == "esp" else None,
            "esp_icv": esp.icv if sc.protocol == "esp" else sc.ah_icv,
            "pfs": sc.pfs,
            "pfs_observable": bool(self.rekey_times) or sc.ike_version == 1,
            "rekey_times": [round(r, 3) for r in self.rekey_times],
            "ip_version": f"IPv{sc.ip_version}",
            "nat_t": sc.nat_t,
            "auth_method": auth,
            "ike_lifetime": sc.lifetime if sc.ike_version == 1 else None,
            "traffic_segments": segments,
            "anomalies": {"replay_duplicates": sc.replay_duplicates, "counter_reset": sc.counter_reset},
        }


def build_capture(scenario: Scenario) -> tuple[list[tuple[float, bytes]], dict[str, Any]]:
    return CaptureBuilder(scenario).build()


def write_scenario(scenario: Scenario, directory: str | Path) -> tuple[Path, dict[str, Any]]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    frames, truth = build_capture(scenario)
    path = directory / f"{scenario.name}.pcap"
    truth["packets"] = pw.write_pcap(path, frames)
    truth["file"] = path.name
    return path, truth


def generate_samples(directory: str | Path) -> list[dict[str, Any]]:
    """Write every curated demo scenario and return their ground truth."""
    return [write_scenario(sc, directory)[1] for sc in SAMPLE_SCENARIOS]
