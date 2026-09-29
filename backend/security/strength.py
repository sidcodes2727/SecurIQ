"""
Security strength in bits (NIST SP 800-57 Part 1 Rev. 5, Table 2) and the
weakest-link effective strength of a negotiated suite.
"""
from __future__ import annotations

import re
from typing import Any

# Finite-field DH: 1024→80, 2048→112, 3072→128, 7680→192, 15360→256 (interpolated between table rows).
# Elliptic curves: half the field size.
DH_BITS = {
    1: 60, 2: 80, 5: 96, 14: 112, 15: 128, 16: 150, 17: 175, 18: 200,
    19: 128, 20: 192, 21: 256, 22: 80, 23: 112, 24: 112, 25: 96, 26: 112,
    27: 112, 28: 128, 29: 192, 30: 256, 31: 128, 32: 224,
}


def encryption_bits(name: str | None) -> tuple[int | None, str]:
    """(bits, note). AES without an observable key length is assumed to be the 128-bit minimum."""
    if not name:
        return None, "not observable"
    upper = name.upper()
    if "NULL" in upper or upper.startswith("NONE"):
        return 0, "no encryption"
    if "3DES" in upper:
        return 112, "3DES (64-bit block, Sweet32-exposed)"
    if "DES" in upper:
        return 56, "single DES"
    if "/" in upper:  # inferred family label such as "AES-GCM / ChaCha20-Poly1305 (AEAD)"
        return 128, "cipher family inferred; key length not observable — 128-bit minimum assumed"
    if "CHACHA20" in upper:
        return 256, "ChaCha20 (256-bit key)"
    if any(weak in upper for weak in ("BLOWFISH", "CAST", "IDEA", "RC5")):
        return 64, "legacy 64-bit block cipher"
    match = re.search(r"(AES|CAMELLIA)-(\d{3})", upper)
    if match:
        return int(match.group(2)), f"{match.group(1)} {match.group(2)}-bit"
    if "AES" in upper or "CAMELLIA" in upper:
        return 128, "key length not observable — 128-bit minimum assumed"
    return None, "unknown cipher"


def hash_bits(name: str | None) -> int | None:
    """Security strength of an HMAC/PRF construction (NIST SP 800-57 Table 3)."""
    if not name:
        return None
    upper = name.upper()
    if "MD5" in upper:
        return 64
    if "SHA2-512" in upper or "SHA2-384" in upper:
        return 256
    if "SHA2-256" in upper or "SHA1" in upper or "XCBC" in upper or "CMAC" in upper or "AEAD" in upper:
        return 128
    return None


def dh_bits(group: int | None) -> int | None:
    return DH_BITS.get(group) if group else None


def effective_strength(components: dict[str, tuple[str | None, int | None]]) -> dict[str, Any]:
    """components: role -> (algorithm name, bits). Weakest known component bounds the suite."""
    known = {role: (name, bits) for role, (name, bits) in components.items() if bits is not None}
    if not known:
        return {"bits": None, "limited_by": None, "components": [], "rating": "Unknown"}
    role, (name, bits) = min(known.items(), key=lambda item: item[1][1])
    return {
        "bits": bits,
        "limited_by": f"{name} ({role})",
        "components": [{"role": r, "algorithm": n, "bits": b} for r, (n, b) in components.items()],
        "rating": strength_rating(bits),
    }


def strength_rating(bits: int) -> str:
    if bits >= 192:
        return "Excellent (≥192-bit)"
    if bits >= 128:
        return "Strong (128-bit)"
    if bits >= 112:
        return "Acceptable until 2030 (112-bit)"
    if bits >= 80:
        return "Weak (<112-bit)"
    return "Broken (<80-bit)"
