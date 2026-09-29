"""
Wire-format construction of IKEv1 (RFC 2408/2409) and IKEv2 (RFC 7296) messages.

Cleartext payloads are built field by field; encrypted content (IKEv2 SK,
IKEv1 encrypted bodies) is random bytes of a realistic size, because that is
exactly what a passive observer sees.
"""
from __future__ import annotations

import random
import struct

from backend.analyzers.ike_constants import DH_KE_LENGTH
from backend.testbed.esp_model import IkeSuite

# payload type numbers
V2_SA, V2_KE, V2_CERTREQ, V2_NONCE, V2_NOTIFY, V2_VID, V2_SK = 33, 34, 38, 40, 41, 43, 46
V2_IDI, V2_IDR = 35, 36
V1_SA, V1_KE, V1_ID, V1_CERTREQ, V1_HASH, V1_NONCE, V1_VID, V1_NATD = 1, 4, 5, 7, 8, 10, 13, 20

VENDOR_IDS = {
    "strongswan": "882fe56d6fd20dbc2251613b2ebe5beb",
    "cisco": "12f5f28c457168a9702d9fe274cc0100",
    "windows": "1e2b516905991c7d7c96fcbfb587e46100000009",
    "dpd": "afcad71368a1f1c96b8696fc77570100",
    "natt": "4a131c81070358455c5728f20e95452f",
    "xauth": "09002689dfd6b712",
    "frag": "4048b7d56ebce88525e7de7f00d6c2d3c0000000",
}


def header(init_spi: bytes, resp_spi: bytes, next_payload: int, major: int, exchange: int,
           flags: int, message_id: int, body: bytes) -> bytes:
    version = (major << 4) | 0
    return init_spi + resp_spi + struct.pack("!BBBBII", next_payload, version, exchange, flags,
                                             message_id, 28 + len(body)) + body


def chain(payloads: list[tuple]) -> tuple[int, bytes]:
    """payloads: (type, body) or (type, body, next_override). Returns (first type, encoded chain)."""
    out = b""
    for i, item in enumerate(payloads):
        ptype, body = item[0], item[1]
        next_type = item[2] if len(item) > 2 else (payloads[i + 1][0] if i + 1 < len(payloads) else 0)
        out += struct.pack("!BBH", next_type, 0, 4 + len(body)) + body
    return (payloads[0][0] if payloads else 0), out


# ---------------------------------------------------------------- IKEv2 payload bodies

def v2_transform(t_type: int, t_id: int, key_length: int | None, last: bool) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_length) if key_length else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), t_type, 0, t_id) + attrs


def v2_proposal(number: int, suite: IkeSuite, last: bool, protocol_id: int = 1) -> bytes:
    transforms = [(1, suite.encryption_id, suite.key_length), (2, suite.prf_id, None)]
    if suite.integrity_id:
        transforms.append((3, suite.integrity_id, None))
    transforms.append((4, suite.dh_group, None))
    body = b"".join(v2_transform(t, i, k, idx == len(transforms) - 1)
                    for idx, (t, i, k) in enumerate(transforms))
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(body), number, protocol_id, 0,
                       len(transforms)) + body


def v2_sa(suites: list[IkeSuite]) -> bytes:
    return b"".join(v2_proposal(i + 1, s, i == len(suites) - 1) for i, s in enumerate(suites))


def v2_ke(group: int, rng: random.Random) -> bytes:
    return struct.pack("!HH", group, 0) + rng.randbytes(DH_KE_LENGTH[group])


def v2_notify(notify_type: int, data: bytes = b"") -> bytes:
    return struct.pack("!BBH", 0, 0, notify_type) + data


def v2_sk_payload(total_message_len: int, rng: random.Random) -> bytes:
    """Random SK body so that header (28) + SK payload header (4) + body == total_message_len."""
    return rng.randbytes(max(16, total_message_len - 32))


# ---------------------------------------------------------------- IKEv1 payload bodies

def v1_sa(transforms: list[dict]) -> bytes:
    """DOI=IPsec, Situation=identity-only, one ISAKMP proposal with Phase 1 transforms."""
    encoded = b""
    for i, t in enumerate(transforms):
        attrs = struct.pack("!HH", 0x8001, t["encryption"]) + struct.pack("!HH", 0x8002, t["hash"])
        attrs += struct.pack("!HH", 0x8003, t["auth"]) + struct.pack("!HH", 0x8004, t["group"])
        if t.get("key_length"):
            attrs += struct.pack("!HH", 0x800E, t["key_length"])
        attrs += struct.pack("!HH", 0x800B, 1)                      # life type: seconds
        attrs += struct.pack("!HHI", 0x000C, 4, t["life_seconds"])  # life duration (TLV)
        body = struct.pack("!BBH", i + 1, 1, 0) + attrs              # transform #, KEY_IKE
        encoded += struct.pack("!BBH", 3 if i < len(transforms) - 1 else 0, 0, 4 + len(body)) + body
    proposal = struct.pack("!BBBB", 1, 1, 0, len(transforms)) + encoded  # proposal #1, PROTO_ISAKMP
    proposal_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    return struct.pack("!II", 1, 1) + proposal_payload


def v1_transform_for(suite: IkeSuite, auth: int, life_seconds: int) -> dict:
    return {"encryption": suite.v1_encryption, "hash": suite.v1_hash, "auth": auth,
            "group": suite.dh_group, "key_length": suite.key_length, "life_seconds": life_seconds}


def v1_id(identity: str) -> bytes:
    if all(part.isdigit() for part in identity.split(".")) and identity.count(".") == 3:
        return struct.pack("!BBH", 1, 17, 500) + bytes(int(x) for x in identity.split("."))
    id_type = 3 if "@" in identity else 2  # USER_FQDN or FQDN
    return struct.pack("!BBH", id_type, 17, 500) + identity.encode()


def v1_ke(group: int, rng: random.Random) -> bytes:
    return rng.randbytes(DH_KE_LENGTH[group])
