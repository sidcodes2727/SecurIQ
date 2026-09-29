"""
IANA registries for IKEv1 (RFC 2408/2409) and IKEv2 (RFC 7296), plus
well-known Vendor ID fingerprints and Key Exchange payload sizes.

Values were cross-checked against Scapy's ISAKMP/IKEv2 registries.
"""

IKE_PORT = 500
IKE_NATT_PORT = 4500
ESP_PROTO = 50
AH_PROTO = 51

# ---------------------------------------------------------------- exchanges

IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    43: "IKE_INTERMEDIATE",
}

IKEV1_EXCHANGE_TYPES = {
    1: "BASE",
    2: "MAIN_MODE",          # Identity Protection
    3: "AUTHENTICATION_ONLY",
    4: "AGGRESSIVE",
    5: "INFORMATIONAL",
    32: "QUICK_MODE",
    33: "NEW_GROUP_MODE",
}

# ---------------------------------------------------------------- payloads

IKEV2_PAYLOAD_TYPES = {
    33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "VendorID",
    44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF",
}

IKEV1_PAYLOAD_TYPES = {
    1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT",
    7: "CERTREQ", 8: "HASH", 9: "SIG", 10: "Nonce", 11: "Notify",
    12: "Delete", 13: "VendorID", 20: "NAT-D", 130: "NAT-D (draft)",
}

# ---------------------------------------------------------------- IKEv2 transforms

TRANSFORM_ENCR = 1
TRANSFORM_PRF = 2
TRANSFORM_INTEG = 3
TRANSFORM_DH = 4
TRANSFORM_ESN = 5

ENCR_NAMES = {
    1: "DES-IV64", 2: "DES-CBC", 3: "3DES-CBC", 4: "RC5-CBC",
    5: "IDEA-CBC", 6: "CAST-CBC", 7: "Blowfish-CBC", 8: "3IDEA",
    9: "DES-IV32", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR",
    14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16",
    18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
    21: "NULL-AUTH-AES-GMAC",
    23: "Camellia-CBC", 24: "Camellia-CTR",
    25: "Camellia-CCM-8", 26: "Camellia-CCM-12", 27: "Camellia-CCM-16",
    28: "ChaCha20-Poly1305",
}

AEAD_ENCR_IDS = {14, 15, 16, 18, 19, 20, 25, 26, 27, 28}

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

# Size in bytes of the Key Exchange data for each group (RFC 7296 / RFC 5903 / RFC 8031).
DH_KE_LENGTH = {
    1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
    19: 64, 20: 96, 21: 132, 22: 128, 23: 256, 24: 256, 25: 48, 26: 56,
    27: 56, 28: 64, 29: 96, 30: 128, 31: 32, 32: 56,
}

# ---------------------------------------------------------------- IKEv2 notify

IKEV2_NOTIFY_TYPES = {
    # Error types
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS",
    43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
    # Status types
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE", 16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE", 16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED", 16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED", 16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS", 16399: "NO_ADDITIONAL_ADDRESSES",
    16400: "UPDATE_SA_ADDRESSES", 16401: "COOKIE2", 16402: "NO_NATS_ALLOWED",
    16403: "AUTH_LIFETIME", 16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS", 16406: "REDIRECT_SUPPORTED",
    16407: "REDIRECT", 16408: "REDIRECTED_FROM",
    16417: "EAP_ONLY_AUTHENTICATION", 16418: "CHILDLESS_IKEV2_SUPPORTED",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
    16435: "USE_PPK", 16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
}

NOTIFY_NAT_DETECTION = {16388, 16389}
NOTIFY_USE_TRANSPORT_MODE = 16391
NOTIFY_COOKIE = 16390
NOTIFY_SIGNATURE_HASH_ALGORITHMS = 16431
NOTIFY_TFC_PADDING_NOT_SUPPORTED = 16394

SIGNATURE_HASH_NAMES = {
    1: "SHA1", 2: "SHA2-256", 3: "SHA2-384", 4: "SHA2-512", 5: "Identity",
}

# ---------------------------------------------------------------- IKEv1 attributes

V1_ATTR_ENCRYPTION = 1
V1_ATTR_HASH = 2
V1_ATTR_AUTH = 3
V1_ATTR_GROUP = 4
V1_ATTR_LIFE_TYPE = 11
V1_ATTR_LIFE_DURATION = 12
V1_ATTR_KEY_LENGTH = 14

V1_ENCRYPTION = {
    1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 4: "RC5-CBC",
    5: "3DES-CBC", 6: "CAST-CBC", 7: "AES-CBC", 8: "Camellia-CBC",
}

V1_HASH = {
    1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512",
}

V1_AUTH_METHOD = {
    1: "Pre-Shared Key", 2: "DSS Signature", 3: "RSA Signature",
    4: "RSA Encryption", 5: "RSA Revised Encryption", 8: "ECDSA Signature",
    9: "ECDSA-256 Signature", 10: "ECDSA-384 Signature", 11: "ECDSA-521 Signature",
    64221: "Hybrid RSA (initiator)", 64222: "Hybrid RSA (responder)",
    65001: "XAUTH + Pre-Shared Key", 65002: "XAUTH + Pre-Shared Key",
    65003: "XAUTH + DSS", 65004: "XAUTH + DSS",
    65005: "XAUTH + RSA Signature", 65006: "XAUTH + RSA Signature",
}

V1_PSK_AUTH_METHODS = {1, 65001, 65002}

V1_LIFE_TYPE = {1: "seconds", 2: "kilobytes"}

V1_ID_TYPES = {
    1: "IPV4_ADDR", 2: "FQDN", 3: "USER_FQDN", 4: "IPV4_ADDR_SUBNET",
    5: "IPV6_ADDR", 6: "IPV6_ADDR_SUBNET", 9: "DER_ASN1_DN", 11: "KEY_ID",
}

# IKEv2 uses the same numbering for ID types 1, 2, 3, 5, 9, 11.
IKEV2_ID_TYPES = {1: "ID_IPV4_ADDR", 2: "ID_FQDN", 3: "ID_RFC822_ADDR",
                  5: "ID_IPV6_ADDR", 9: "ID_DER_ASN1_DN", 11: "ID_KEY_ID"}

# ---------------------------------------------------------------- vendor IDs

# Hex prefix -> description. Only fingerprints with well-established values are listed.
KNOWN_VENDOR_IDS = {
    "afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection v1.0 (RFC 3706)",
    "4a131c81070358455c5728f20e95452f": "NAT-Traversal (RFC 3947)",
    "90cb80913ebb696e086381b5ec427b1f": "NAT-Traversal (draft-ietf-ipsec-nat-t-ike-02)",
    "09002689dfd6b712": "XAUTH",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco Unity",
    "4048b7d56ebce88525e7de7f00d6c2d3": "IKE Fragmentation (Cisco/Microsoft)",
    "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
    "1e2b516905991c7d7c96fcbfb587e461": "Microsoft Windows (MS NT5 ISAKMPOAKLEY)",
}

# Vendor IDs that reveal the product (as opposed to feature flags).
IMPLEMENTATION_VENDOR_IDS = {
    "882fe56d6fd20dbc2251613b2ebe5beb",
    "12f5f28c457168a9702d9fe274cc0100",
    "1e2b516905991c7d7c96fcbfb587e461",
}


def lookup_vendor_id(vid_hex: str) -> tuple[str, bool]:
    """Return (description, reveals_implementation) for a Vendor ID payload."""
    vid_hex = vid_hex.lower()
    for prefix, name in KNOWN_VENDOR_IDS.items():
        if vid_hex.startswith(prefix):
            return name, prefix in IMPLEMENTATION_VENDOR_IDS
    return f"Unknown vendor ID ({vid_hex[:16]}…)", False
