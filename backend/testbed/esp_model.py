"""
Cipher-suite framing for ESP (RFC 4303) and IKE SA suites.

The ESP length model here is the single source of truth for both the capture
generator and the ML training data, so generated PCAPs and training windows are
framed identically.
"""
from __future__ import annotations

from dataclasses import dataclass

from backend.analyzers.esp_fingerprint import FAMILY_AEAD, FAMILY_CBC64, FAMILY_CBC128
from backend.analyzers.ike_parser import format_encryption
from backend.analyzers.ike_constants import ENCR_NAMES, INTEG_NAMES, PRF_NAMES


@dataclass(frozen=True)
class EspSuite:
    key: str
    label: str
    encryption_id: int
    key_length: int | None
    integrity_id: int
    iv: int
    block: int
    icv: int
    family: str

    @property
    def integrity_label(self) -> str:
        return "Integrated (AEAD)" if self.block == 4 and self.integrity_id == 0 else INTEG_NAMES[self.integrity_id]


ESP_SUITES: dict[str, EspSuite] = {s.key: s for s in [
    EspSuite("aes128gcm16", "AES-128-GCM-16", 20, 128, 0, 8, 4, 16, FAMILY_AEAD),
    EspSuite("aes256gcm16", "AES-256-GCM-16", 20, 256, 0, 8, 4, 16, FAMILY_AEAD),
    EspSuite("chacha20poly1305", "ChaCha20-Poly1305", 28, None, 0, 8, 4, 16, FAMILY_AEAD),
    EspSuite("aes128-sha1", "AES-128-CBC + HMAC-SHA1-96", 12, 128, 2, 16, 16, 12, FAMILY_CBC128),
    EspSuite("aes128-sha256", "AES-128-CBC + HMAC-SHA2-256-128", 12, 128, 12, 16, 16, 16, FAMILY_CBC128),
    EspSuite("aes256-sha256", "AES-256-CBC + HMAC-SHA2-256-128", 12, 256, 12, 16, 16, 16, FAMILY_CBC128),
    EspSuite("aes256-sha384", "AES-256-CBC + HMAC-SHA2-384-192", 12, 256, 13, 16, 16, 24, FAMILY_CBC128),
    EspSuite("aes256-sha512", "AES-256-CBC + HMAC-SHA2-512-256", 12, 256, 14, 16, 16, 32, FAMILY_CBC128),
    EspSuite("3des-sha1", "3DES-CBC + HMAC-SHA1-96", 3, None, 2, 8, 8, 12, FAMILY_CBC64),
    EspSuite("3des-md5", "3DES-CBC + HMAC-MD5-96", 3, None, 1, 8, 8, 12, FAMILY_CBC64),
    EspSuite("null-sha256", "NULL + HMAC-SHA2-256-128", 11, None, 12, 0, 4, 16, "NULL"),
]}

TRAINING_SUITES = [k for k in ESP_SUITES if k != "null-sha256"]


def align(n: int, block: int) -> int:
    return -(-n // block) * block


def esp_payload_len(inner_len: int, suite: EspSuite) -> int:
    """IV + ciphertext(inner + pad + pad_len + next_header, block-aligned) + ICV."""
    return suite.iv + align(inner_len + 2, suite.block) + suite.icv


def inner_packet_len(l4_len: int, mode: str, ip_version: int) -> int:
    """Tunnel mode carries the whole inner IP packet; transport mode only the L4 segment."""
    if mode == "tunnel":
        return l4_len + (20 if ip_version == 4 else 40)
    return l4_len


# ---------------------------------------------------------------- IKE SA suites

@dataclass(frozen=True)
class IkeSuite:
    key: str
    encryption_id: int          # IKEv2 ENCR transform ID
    key_length: int | None
    integrity_id: int           # IKEv2 INTEG transform ID (0 = none, AEAD)
    prf_id: int
    dh_group: int
    v1_encryption: int          # IKEv1 attribute values
    v1_hash: int

    @property
    def encryption_name(self) -> str:
        return format_encryption(ENCR_NAMES[self.encryption_id], self.key_length)

    @property
    def integrity_name(self) -> str | None:
        return INTEG_NAMES[self.integrity_id] if self.integrity_id else None

    @property
    def prf_name(self) -> str:
        return PRF_NAMES[self.prf_id]


IKE_SUITES: dict[str, IkeSuite] = {s.key: s for s in [
    IkeSuite("aes256gcm16-prfsha384-ecp384", 20, 256, 0, 6, 20, 7, 5),
    IkeSuite("aes128gcm16-prfsha256-curve25519", 20, 128, 0, 5, 31, 7, 4),
    IkeSuite("aes256-sha384-ecp384", 12, 256, 13, 6, 20, 7, 5),
    IkeSuite("aes256-sha256-modp2048", 12, 256, 12, 5, 14, 7, 4),
    IkeSuite("aes128-sha256-ecp256", 12, 128, 12, 5, 19, 7, 4),
    IkeSuite("aes128-sha1-modp2048", 12, 128, 2, 2, 14, 7, 2),
    IkeSuite("aes128-sha1-modp1536", 12, 128, 2, 2, 5, 7, 2),
    IkeSuite("3des-sha1-modp1024", 3, None, 2, 2, 2, 5, 2),
    IkeSuite("3des-md5-modp1024", 3, None, 1, 1, 2, 5, 1),
]}

# A legacy fallback proposal some initiators still offer (downgrade surface).
WEAK_FALLBACK = IKE_SUITES["3des-md5-modp1024"]

# IKEv1 has no AEAD in Phase 1; map AEAD IKE suites to their CBC equivalent for v1 scenarios.
V1_HASH_NAMES = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
V1_ENCRYPTION_NAMES = {5: "3DES-CBC", 7: "AES-CBC"}
