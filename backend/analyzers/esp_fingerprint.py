"""
Passive inference of ESP (Child SA) properties from packet lengths.

An ESP payload after SPI + sequence number is  IV || ciphertext || ICV.

* CBC ciphers pad the ciphertext to the block size (16 bytes for AES, 8 for 3DES),
  so every length L satisfies  L ≡ (IV + ICV) (mod block)  — one constant residue.
* AEAD / counter-mode suites (AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CTR) only
  align to 4 bytes, so residues mod 8 and mod 16 vary with the plaintext.

The residue therefore reveals the block size and the ICV length (i.e. the HMAC
truncation), and the chance of a false match shrinks with every distinct length
observed. Key length (AES-128 vs AES-256) does not change the framing and is
reported as not observable.
"""
from __future__ import annotations

from typing import Any

MIN_PACKETS = 8
MIN_DISTINCT_LENGTHS = 3
# Below this, a shared residue is too likely to be coincidence to name a cipher (e.g. 3 lengths: 25%).
MIN_IDENTIFY_CONFIDENCE = 0.85

# ICV residue (mod block) -> candidate ICV lengths, most common first
_ICV_BY_RESIDUE_16 = {12: [12], 0: [16, 32], 8: [24], 4: [20]}
_ICV_BY_RESIDUE_8 = {4: [12, 20], 0: [16, 24, 32]}

INTEGRITY_BY_ICV = {
    12: "HMAC-SHA1-96",
    16: "HMAC-SHA2-256-128",
    20: "HMAC-SHA1-160",
    24: "HMAC-SHA2-384-192",
    32: "HMAC-SHA2-512-256",
}
ALTERNATIVES_BY_ICV = {
    12: ["HMAC-MD5-96", "AES-XCBC-96"],
    16: ["HMAC-SHA2-512-256 (if ICV is 32 bytes)"],
}

FAMILY_CBC128 = "AES-CBC"
FAMILY_CBC64 = "3DES-CBC"
FAMILY_AEAD = "AES-GCM / ChaCha20-Poly1305 (AEAD)"


def fingerprint_esp(lengths: list[int]) -> dict[str, Any]:
    """Infer cipher family, IV and ICV length for one SA from its ESP payload lengths."""
    n = len(lengths)
    distinct = sorted(set(lengths))
    d = len(distinct)
    base: dict[str, Any] = {
        "packets": n,
        "distinct_lengths": d,
        "status": "insufficient_data",
        "family": None,
        "integrity": None,
        "suite": None,
        "block_size": None,
        "iv_len": None,
        "icv_len_candidates": [],
        "confidence": 0.0,
    }
    if n < MIN_PACKETS or d < MIN_DISTINCT_LENGTHS:
        base["evidence"] = (f"{n} packets with {d} distinct lengths — need ≥{MIN_PACKETS} packets and "
                            f"≥{MIN_DISTINCT_LENGTHS} distinct lengths (constant-size traffic hides the cipher)")
        return base

    if any(length % 4 for length in distinct):
        base["status"] = "irregular"
        base["evidence"] = "Lengths are not 4-byte aligned — not standard ESP framing (RFC 4303 §2.4)"
        return base

    r16 = sorted({length % 16 for length in distinct})
    r8 = sorted({length % 8 for length in distinct})
    chance_alignment = 0.5 ** (d - 1)  # probability a 4-aligned suite shows one residue by chance

    if len(r16) == 1:
        icvs = _ICV_BY_RESIDUE_16.get(r16[0], [])
        min_ok = not icvs or min(distinct) >= 16 + 16 + icvs[0]
        result = _block_result(base, FAMILY_CBC128, 16, 16, icvs, min(0.97, 1 - chance_alignment))
        result["evidence"] = (f"{n} packets, {d} distinct lengths, all ≡ {r16[0]} (mod 16): 128-bit block "
                              f"cipher with 16-byte IV; residue implies a {_icv_text(icvs)} ICV")
        if not min_ok:
            result["confidence"] = round(result["confidence"] * 0.6, 3)
            result["evidence"] += "; smallest packet is shorter than this suite allows (confidence reduced)"
        return _require_confidence(result, base, d)

    if len(r8) == 1:
        icvs = _ICV_BY_RESIDUE_8.get(r8[0], [])
        result = _block_result(base, FAMILY_CBC64, 8, 8, icvs, min(0.95, 1 - chance_alignment))
        result["evidence"] = (f"{n} packets, {d} distinct lengths, all ≡ {r8[0]} (mod 8) but varying mod 16: "
                              f"64-bit block cipher (3DES/Blowfish/CAST); residue implies a {_icv_text(icvs)} ICV")
        return _require_confidence(result, base, d)

    base.update(
        status="identified",
        family=FAMILY_AEAD,
        integrity="Integrated AEAD tag (ICV typically 16 bytes)",
        suite=FAMILY_AEAD,
        block_size=4,
        iv_len=8,
        icv_len_candidates=[16],
        confidence=0.9,
        evidence=(f"{n} packets, {d} distinct lengths with residues {r8} (mod 8): only 4-byte alignment, "
                  "which rules out CBC block ciphers — AEAD (AES-GCM/CCM, ChaCha20-Poly1305) or AES-CTR"),
    )
    return base


def _require_confidence(result: dict, base: dict, d: int) -> dict:
    if result["confidence"] >= MIN_IDENTIFY_CONFIDENCE:
        return result
    base["evidence"] = (f"{result['evidence']} — but with only {d} distinct lengths this pattern arises by chance "
                        f"{1 - result['confidence']:.0%} of the time, so no cipher is claimed")
    return base


def _block_result(base: dict, family: str, block: int, iv: int, icvs: list[int], confidence: float) -> dict:
    integrity = INTEGRITY_BY_ICV.get(icvs[0], f"{icvs[0]}-byte ICV") if icvs else "Unknown ICV"
    result = dict(base)
    result.update(
        status="identified",
        family=family,
        integrity=integrity,
        integrity_alternatives=ALTERNATIVES_BY_ICV.get(icvs[0], []) if icvs else [],
        suite=f"{family} + {integrity}",
        block_size=block,
        iv_len=iv,
        icv_len_candidates=icvs,
        confidence=round(confidence, 3),
    )
    return result


def _icv_text(icvs: list[int]) -> str:
    return " or ".join(f"{c}-byte" for c in icvs) if icvs else "non-standard"


# ---------------------------------------------------------------- mode

MIN_TUNNEL_INNER = 28      # inner IPv4 header (20) + smallest transport header (8)
MIN_TUNNEL_TCP = 40        # inner IPv4 (20) + TCP (20): the smallest tunnelled TCP ACK
MAX_TRANSPORT_ACK = 32     # TCP header with timestamps: the largest common transport-mode pure ACK


def icv_from_integrity(name: str | None) -> int | None:
    """ESP ICV length implied by an IKE integrity algorithm name (RFC 2404 / 4868 truncations)."""
    if not name:
        return None
    upper = name.upper()
    for token, icv in (("SHA2-512", 32), ("SHA2-384", 24), ("SHA2-256", 16), ("SHA1", 12), ("MD5", 12), ("XCBC", 12)):
        if token in upper:
            return icv
    return None


def infer_mode(lengths: list[int], fingerprint: dict[str, Any], icv_hint: int | None = None) -> dict[str, Any]:
    """
    Tunnel mode wraps a whole IP packet, so every inner packet carries ≥ 20 extra bytes.

    The smallest ESP packets bound the smallest inner packets (range = unknown padding and ICV):
      * inner < 40 B cannot be a tunnelled TCP segment (IP 20 + TCP 20)  → Transport
      * frequent small packets in a bimodal flow are a TCP ACK clock; if even the lower bound
        exceeds a transport-mode ACK (≤ 32 B)                          → Tunnel
      * otherwise the capture does not decide it, and we say so instead of guessing.
    """
    if not lengths:
        return {"value": None, "confidence": 0.0, "evidence": "No ESP packets"}

    identified = fingerprint.get("status") == "identified"
    hinted = False
    if identified:
        icvs = fingerprint.get("icv_len_candidates") or [16]
        if icv_hint in icvs and len(icvs) > 1:
            icvs, hinted = [icv_hint], True
        iv, block, icv_min, icv_max = fingerprint["iv_len"], fingerprint["block_size"], min(icvs), max(icvs)
        upper_overhead, lower_overhead = iv + icv_min + 2, iv + icv_max + 2 + block - 1
    else:  # unknown suite: widest plausible overhead range
        upper_overhead, lower_overhead = 8 + 12 + 2, 16 + 32 + 2 + 15

    counts: dict[int, int] = {}
    for length in lengths:
        counts[length] = counts.get(length, 0) + 1
    # ignore one-off outliers: the smallest length seen at least twice
    smallest = min((length for length, c in counts.items() if c >= 2), default=min(lengths))
    p_upper = smallest - upper_overhead
    p_lower = max(0, smallest - lower_overhead)
    bound = f"smallest recurring ESP payload {smallest} B → inner packet {p_lower}–{p_upper} B"
    if not identified:
        bound += " (cipher unknown; widest overhead range assumed)"
    if hinted:
        bound += f" (ICV narrowed to {icv_hint} B by the IKE SA integrity algorithm)"
    # the bound is only as reliable as the cipher identification it rests on
    fingerprint_confidence = (fingerprint.get("confidence") or 1.0) if identified else 1.0
    discount = (0.9 if hinted else 1.0) * fingerprint_confidence

    if p_upper < MIN_TUNNEL_INNER:
        return {"value": "Transport", "confidence": round(0.9 * discount, 3),
                "evidence": f"{bound}: too small for an inner IP header + transport header (≥ 28 B)"}
    if p_upper < MIN_TUNNEL_TCP:
        return {"value": "Transport", "confidence": round(0.75 * discount, 3),
                "evidence": f"{bound}: cannot hold a tunnelled TCP segment (≥ 40 B), fits a transport-mode ACK"}

    small = sum(c for length, c in counts.items() if length <= smallest + (fingerprint.get("block_size") or 16))
    small_share = small / len(lengths)
    bimodal = max(lengths) >= 3 * smallest and 0.05 <= small_share <= 0.8
    if p_lower > MAX_TRANSPORT_ACK and bimodal:
        return {"value": "Tunnel", "confidence": round((0.8 if len(lengths) >= 200 else 0.7) * discount, 3),
                "evidence": f"{bound}: {small_share:.0%} of packets are small ACK-like packets, yet all exceed a "
                            f"transport-mode TCP ACK (≤ 32 B) — they carry an inner IP header"}
    if p_lower > MAX_TRANSPORT_ACK:
        why = "no ACK-like small packets to test against (constant-size traffic such as VoIP or ping)"
    else:
        why = "this cipher's padding makes a transport ACK with timestamps and a tunnelled ACK the same size"
    return {"value": None, "confidence": 0.0, "evidence": f"{bound}: undetermined — {why}"}


# ---------------------------------------------------------------- ESP-NULL

_INNER_PROTOCOLS = {1, 6, 17, 47, 50, 58}


def detect_null_encryption(samples: list[tuple[int, str]]) -> dict[str, Any]:
    """
    ESP with NULL encryption (RFC 2410) carries the inner packet in cleartext right after the header.
    A real cipher puts an IV there. Look for structurally valid inner IPv4/IPv6/UDP headers whose
    length fields agree with the ESP length — a match on random bytes is ~1 in 10^7.

    samples: (esp_payload_len, hex of first 16 payload bytes)
    """
    usable = [(length, bytes.fromhex(head)) for length, head in samples if head and len(head) >= 32]
    if len(usable) < 5:
        return {"suspected": False, "confidence": 0.0, "evidence": "Too few ESP packets to test"}

    matches = sum(1 for length, head in usable if _looks_like_cleartext(length, head))
    ratio = matches / len(usable)
    if ratio >= 0.5:
        return {"suspected": True, "confidence": round(min(0.98, 0.7 + ratio * 0.28), 3),
                "evidence": f"{matches}/{len(usable)} ESP payloads begin with a valid inner IP/UDP header "
                            f"whose length matches the packet — payload is not encrypted"}
    return {"suspected": False, "confidence": round(1 - ratio, 3),
            "evidence": f"{matches}/{len(usable)} payloads resemble cleartext headers — consistent with encryption"}


def _looks_like_cleartext(esp_len: int, head: bytes) -> bool:
    low, high = esp_len - 50, esp_len - 14   # trailer (2) + pad (0-3) + ICV (12-32)
    if head[0] == 0x45:
        total = int.from_bytes(head[2:4], "big")
        return low <= total <= high and head[9] in _INNER_PROTOCOLS
    if head[0] >> 4 == 6:
        total = int.from_bytes(head[4:6], "big") + 40
        return low <= total <= high and head[6] in _INNER_PROTOCOLS
    udp_len = int.from_bytes(head[4:6], "big")
    return low <= udp_len <= high and udp_len >= 8
