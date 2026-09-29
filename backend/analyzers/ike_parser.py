"""
IKEv1 / IKEv2 message parser.

Walks the generic payload chain of an ISAKMP/IKE message and extracts everything
that is visible on the wire without keys:

- SA proposals (IKEv2 transforms and IKEv1 attribute-encoded transforms)
- Key Exchange group, Nonce size, Notify, Vendor ID, CERTREQ
- Identity payloads (cleartext in IKEv1 Aggressive Mode)
- Size of encrypted content (IKEv2 SK / SKF, IKEv1 encrypted body), which later
  drives the size-based inference of PFS and authentication method.

Every accessor is bounds-checked: malformed input yields partial results, never exceptions.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from backend.analyzers.ike_constants import (
    IKEV1_EXCHANGE_TYPES, IKEV2_EXCHANGE_TYPES,
    IKEV1_PAYLOAD_TYPES, IKEV2_PAYLOAD_TYPES,
    TRANSFORM_ENCR, TRANSFORM_PRF, TRANSFORM_INTEG, TRANSFORM_DH, TRANSFORM_ESN,
    ENCR_NAMES, PRF_NAMES, INTEG_NAMES, DH_NAMES,
    IKEV2_NOTIFY_TYPES, SIGNATURE_HASH_NAMES,
    V1_ATTR_ENCRYPTION, V1_ATTR_HASH, V1_ATTR_AUTH, V1_ATTR_GROUP,
    V1_ATTR_LIFE_TYPE, V1_ATTR_LIFE_DURATION, V1_ATTR_KEY_LENGTH,
    V1_ENCRYPTION, V1_HASH, V1_AUTH_METHOD, V1_ID_TYPES, IKEV2_ID_TYPES,
    lookup_vendor_id,
)

IKE_HEADER_LEN = 28
PROTOCOL_NAMES = {1: "IKE", 2: "AH", 3: "ESP", 4: "IPCOMP"}

IKEV1_NOTIFY_TYPES = {
    14: "NO-PROPOSAL-CHOSEN", 24: "AUTHENTICATION-FAILED",
    24576: "RESPONDER-LIFETIME", 24578: "INITIAL-CONTACT",
    36136: "R-U-THERE", 36137: "R-U-THERE-ACK",
}


def format_encryption(base: str, key_length: int | None) -> str:
    """Human-readable cipher name, e.g. AES-CBC + 256 -> AES-256-CBC."""
    if key_length and base.startswith("AES-"):
        return f"AES-{key_length}-{base[4:]}"
    if key_length and base.startswith("Camellia-"):
        return f"Camellia-{key_length}-{base[9:]}"
    if key_length and base not in ("3DES-CBC", "DES-CBC", "NULL", "ChaCha20-Poly1305"):
        return f"{base}-{key_length}"
    return base


def parse_ike_message(data: bytes) -> dict[str, Any] | None:
    """Parse one IKE message (without UDP header / non-ESP marker)."""
    if len(data) < IKE_HEADER_LEN:
        return None

    version_byte = data[17]
    major = (version_byte >> 4) & 0x0F
    minor = version_byte & 0x0F
    if major not in (1, 2):
        return None

    exchange_num = data[18]
    flags = data[19]
    exchange_table = IKEV2_EXCHANGE_TYPES if major == 2 else IKEV1_EXCHANGE_TYPES

    msg: dict[str, Any] = {
        "init_spi": data[0:8].hex(),
        "resp_spi": data[8:16].hex(),
        "next_payload": data[16],
        "major_version": major,
        "minor_version": minor,
        "version": f"{major}.{minor}",
        "exchange_type_num": exchange_num,
        "exchange_type": exchange_table.get(exchange_num, f"UNKNOWN({exchange_num})"),
        "flags": flags,
        "message_id": int.from_bytes(data[20:24], "big"),
        "length": int.from_bytes(data[24:28], "big"),
        "initiator_flag": bool(flags & 0x08) if major == 2 else None,
        "response_flag": bool(flags & 0x20) if major == 2 else None,
        "encrypted_flag": bool(flags & 0x01) if major == 1 else None,
        "payload_types": [],
        "proposals": [],
        "notifies": [],
        "vendor_ids": [],
        "identities": [],
        "certreq": [],
        "ke_dh_group": None,
        "ke_data_len": None,
        "nonce_len": None,
        "encrypted_len": 0,
        "nat_detection": False,
    }

    body = data[IKE_HEADER_LEN:]
    if major == 1 and msg["encrypted_flag"]:
        # IKEv1 encrypts everything after the header once keys exist.
        msg["encrypted_len"] = len(body)
        msg["payload_types"].append("Encrypted")
        return msg

    try:
        _walk_payloads(body, msg["next_payload"], major, msg)
    except Exception as exc:  # defensive: never let a malformed packet break analysis
        msg["parse_error"] = str(exc)
    return msg


# ---------------------------------------------------------------- payload chain

def _walk_payloads(body: bytes, first_type: int, major: int, msg: dict) -> None:
    names = IKEV2_PAYLOAD_TYPES if major == 2 else IKEV1_PAYLOAD_TYPES
    offset = 0
    ptype = first_type
    guard = 0
    while ptype != 0 and offset + 4 <= len(body) and guard < 64:
        guard += 1
        next_type = body[offset]
        plen = int.from_bytes(body[offset + 2:offset + 4], "big")
        if plen < 4 or offset + plen > len(body):
            msg["parse_error"] = f"payload length {plen} out of bounds at offset {offset}"
            break
        pdata = body[offset + 4:offset + plen]
        msg["payload_types"].append(names.get(ptype, f"Type-{ptype}"))

        if major == 2:
            if ptype in (46, 53):  # SK / SKF: always last, next_type names the first inner payload
                msg["encrypted_len"] += plen
                msg["sk_inner_first_payload"] = names.get(next_type, next_type)
                if ptype == 53 and len(pdata) >= 4:
                    msg["fragment"] = {
                        "number": int.from_bytes(pdata[0:2], "big"),
                        "total": int.from_bytes(pdata[2:4], "big"),
                    }
                break
            _parse_v2_payload(ptype, pdata, msg)
        else:
            _parse_v1_payload(ptype, pdata, msg)

        ptype = next_type
        offset += plen


def _parse_v2_payload(ptype: int, pdata: bytes, msg: dict) -> None:
    if ptype == 33:
        msg["proposals"].extend(_parse_v2_sa(pdata))
    elif ptype == 34 and len(pdata) >= 4:
        msg["ke_dh_group"] = int.from_bytes(pdata[0:2], "big")
        msg["ke_data_len"] = len(pdata) - 4
    elif ptype in (35, 36) and len(pdata) >= 4:
        msg["identities"].append(_decode_identity(pdata[0], pdata[4:], IKEV2_ID_TYPES,
                                                  "IDi" if ptype == 35 else "IDr"))
    elif ptype == 38 and len(pdata) >= 1:
        msg["certreq"].append({"encoding": pdata[0], "ca_count": (len(pdata) - 1) // 20})
    elif ptype == 40:
        msg["nonce_len"] = len(pdata)
    elif ptype == 41 and len(pdata) >= 4:
        msg["notifies"].append(_parse_v2_notify(pdata, msg))
    elif ptype == 43:
        _add_vendor_id(pdata, msg)


def _parse_v1_payload(ptype: int, pdata: bytes, msg: dict) -> None:
    if ptype == 1:
        msg["proposals"].extend(_parse_v1_sa(pdata))
    elif ptype == 4:
        msg["ke_data_len"] = len(pdata)
    elif ptype == 5 and len(pdata) >= 4:
        msg["identities"].append(_decode_identity(pdata[0], pdata[4:], V1_ID_TYPES, "ID"))
    elif ptype == 7 and len(pdata) >= 1:
        msg["certreq"].append({"encoding": pdata[0], "ca_count": 1 if len(pdata) > 1 else 0})
    elif ptype == 10:
        msg["nonce_len"] = len(pdata)
    elif ptype == 11 and len(pdata) >= 8:
        ntype = int.from_bytes(pdata[6:8], "big")
        msg["notifies"].append({"type": ntype, "name": IKEV1_NOTIFY_TYPES.get(ntype, f"NOTIFY_{ntype}")})
    elif ptype == 13:
        _add_vendor_id(pdata, msg)
    elif ptype in (20, 130):
        msg["nat_detection"] = True


# ---------------------------------------------------------------- SA payloads

def _parse_attributes(data: bytes) -> dict[int, int | bytes]:
    """Parse TV/TLV data attributes (same encoding in IKEv1 and IKEv2)."""
    attrs: dict[int, int | bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        attr_type = word & 0x7FFF
        if word & 0x8000:  # TV
            attrs[attr_type] = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
        else:  # TLV
            alen = int.from_bytes(data[offset + 2:offset + 4], "big")
            value = data[offset + 4:offset + 4 + alen]
            attrs[attr_type] = int.from_bytes(value, "big") if 0 < alen <= 8 else value
            offset += 4 + alen
    return attrs


def _empty_offer(number: int, protocol_id: int, spi: str | None) -> dict[str, Any]:
    return {
        "number": number,
        "protocol_id": protocol_id,
        "protocol": PROTOCOL_NAMES.get(protocol_id, f"UNKNOWN({protocol_id})"),
        "spi": spi,
        "encryption": [],
        "integrity": [],
        "prf": [],
        "dh_groups": [],
        "esn": [],
        "auth_method": None,
        "auth_method_id": None,
        "life_seconds": None,
        "life_kilobytes": None,
    }


def _parse_v2_sa(data: bytes) -> list[dict]:
    offers = []
    offset = 0
    while offset + 8 <= len(data):
        more = data[offset]
        plen = int.from_bytes(data[offset + 2:offset + 4], "big")
        if plen < 8 or offset + plen > len(data):
            break
        number, protocol_id, spi_size, n_transforms = data[offset + 4:offset + 8]
        spi = data[offset + 8:offset + 8 + spi_size].hex() if spi_size else None
        offer = _empty_offer(number, protocol_id, spi)

        t_off = offset + 8 + spi_size
        end = offset + plen
        for _ in range(n_transforms):
            if t_off + 8 > end:
                break
            t_len = int.from_bytes(data[t_off + 2:t_off + 4], "big")
            if t_len < 8 or t_off + t_len > end:
                break
            t_type = data[t_off + 4]
            t_id = int.from_bytes(data[t_off + 6:t_off + 8], "big")
            attrs = _parse_attributes(data[t_off + 8:t_off + t_len])
            key_len = attrs.get(14) if isinstance(attrs.get(14), int) else None

            if t_type == TRANSFORM_ENCR:
                offer["encryption"].append(
                    format_encryption(ENCR_NAMES.get(t_id, f"ENCR-{t_id}"), key_len))
                offer.setdefault("encryption_ids", []).append(t_id)
            elif t_type == TRANSFORM_PRF:
                offer["prf"].append(PRF_NAMES.get(t_id, f"PRF-{t_id}"))
            elif t_type == TRANSFORM_INTEG:
                offer["integrity"].append(INTEG_NAMES.get(t_id, f"INTEG-{t_id}"))
            elif t_type == TRANSFORM_DH:
                offer["dh_groups"].append(t_id)
            elif t_type == TRANSFORM_ESN:
                offer["esn"].append("ESN" if t_id == 1 else "No ESN")
            t_off += t_len

        offers.append(offer)
        if more == 0:
            break
        offset += plen
    return offers


def _parse_v1_sa(data: bytes) -> list[dict]:
    """IKEv1 SA: DOI(4) + Situation(4) + Proposal payloads, each holding Transform payloads."""
    offers = []
    if len(data) < 8:
        return offers
    offset = 8
    while offset + 8 <= len(data):
        p_next = data[offset]
        p_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        if p_len < 8 or offset + p_len > len(data):
            break
        number, protocol_id, spi_size, n_transforms = data[offset + 4:offset + 8]
        spi = data[offset + 8:offset + 8 + spi_size].hex() if spi_size else None

        t_off = offset + 8 + spi_size
        end = offset + p_len
        for _ in range(n_transforms):
            if t_off + 8 > end:
                break
            t_len = int.from_bytes(data[t_off + 2:t_off + 4], "big")
            if t_len < 8 or t_off + t_len > end:
                break
            t_number = data[t_off + 4]
            attrs = _parse_attributes(data[t_off + 8:t_off + t_len])
            offer = _empty_offer(number, protocol_id, spi)
            offer["transform_number"] = t_number
            if protocol_id == 1:
                _apply_v1_phase1_attributes(offer, attrs)
            offers.append(offer)
            t_off += t_len

        if p_next == 0:
            break
        offset += p_len
    return offers


def _apply_v1_phase1_attributes(offer: dict, attrs: dict) -> None:
    key_len = attrs.get(V1_ATTR_KEY_LENGTH) if isinstance(attrs.get(V1_ATTR_KEY_LENGTH), int) else None
    enc = attrs.get(V1_ATTR_ENCRYPTION)
    if isinstance(enc, int):
        offer["encryption"].append(format_encryption(V1_ENCRYPTION.get(enc, f"ENCR-{enc}"), key_len))
    hash_alg = attrs.get(V1_ATTR_HASH)
    if isinstance(hash_alg, int):
        name = V1_HASH.get(hash_alg, f"HASH-{hash_alg}")
        # In IKEv1 the negotiated hash drives both the PRF (HMAC) and integrity of IKE messages.
        offer["integrity"].append(f"HMAC-{name}")
        offer["prf"].append(f"PRF-HMAC-{name}")
    auth = attrs.get(V1_ATTR_AUTH)
    if isinstance(auth, int):
        offer["auth_method_id"] = auth
        offer["auth_method"] = V1_AUTH_METHOD.get(auth, f"AUTH-{auth}")
    group = attrs.get(V1_ATTR_GROUP)
    if isinstance(group, int):
        offer["dh_groups"].append(group)
    life_type = attrs.get(V1_ATTR_LIFE_TYPE)
    life_value = attrs.get(V1_ATTR_LIFE_DURATION)
    if isinstance(life_type, int) and isinstance(life_value, int):
        if life_type == 1:
            offer["life_seconds"] = life_value
        elif life_type == 2:
            offer["life_kilobytes"] = life_value


# ---------------------------------------------------------------- other payloads

def _parse_v2_notify(pdata: bytes, msg: dict) -> dict:
    spi_size = pdata[1]
    ntype = int.from_bytes(pdata[2:4], "big")
    ndata = pdata[4 + spi_size:]
    notify: dict[str, Any] = {"type": ntype, "name": IKEV2_NOTIFY_TYPES.get(ntype, f"NOTIFY_{ntype}")}
    if ntype in (16388, 16389):
        msg["nat_detection"] = True
    elif ntype == 16431:
        notify["hashes"] = [
            SIGNATURE_HASH_NAMES.get(int.from_bytes(ndata[i:i + 2], "big"), "?")
            for i in range(0, len(ndata) - 1, 2)
        ]
    elif ntype == 17 and len(ndata) >= 2:
        group = int.from_bytes(ndata[0:2], "big")
        notify["accepted_group"] = group
        notify["accepted_group_name"] = DH_NAMES.get(group, str(group))
    return notify


def _add_vendor_id(pdata: bytes, msg: dict) -> None:
    vid_hex = pdata.hex()
    name, reveals = lookup_vendor_id(vid_hex)
    msg["vendor_ids"].append({"hex": vid_hex, "name": name, "reveals_implementation": reveals})


def _decode_identity(id_type: int, value: bytes, table: dict, payload: str) -> dict:
    type_name = table.get(id_type, f"ID-{id_type}")
    try:
        if id_type in (1,) and len(value) == 4:
            text = str(ipaddress.IPv4Address(value))
        elif id_type in (5,) and len(value) == 16:
            text = str(ipaddress.IPv6Address(value))
        elif id_type in (2, 3, 11):
            text = value.decode("utf-8", errors="replace")
        elif id_type == 9:
            text = f"<X.509 DN, {len(value)} bytes>"
        else:
            text = value.hex()
    except ValueError:
        text = value.hex()
    return {"payload": payload, "id_type": type_name, "value": text}
