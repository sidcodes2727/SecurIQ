"""
Configuration compliance against published IPsec guidance (PS §d "configuration compliance").

Profiles:
  IETF   RFC 8247 (IKEv2 algorithms), RFC 8221 (ESP algorithms), RFC 9395 (IKEv1 deprecation)
  NIST   SP 800-77 Rev. 1 (Guide to IPsec VPNs), SP 800-131A Rev. 2 (algorithm transitions)
  CNSA   NSA Commercial National Security Algorithm Suite 1.0 (CNSSP-15)

Each check returns pass / warn / fail / unknown with the evidence it used, so a
"not observable" field lowers coverage instead of silently passing or failing.
"""
from __future__ import annotations

from typing import Any, Callable

PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"


def extract_facts(analysis: dict[str, Any]) -> dict[str, Any]:
    """Flatten the evidence profile into the values compliance checks need."""
    profile = analysis.get("profile", {})
    ike = analysis.get("ike_analysis", {})
    esp = analysis.get("esp_analysis", {})
    ah = analysis.get("ah_analysis", {})
    chosen = ike.get("chosen_suite") or {}

    def value(key: str):
        return (profile.get(key) or {}).get("value")

    child = profile.get("child_sa_lifetime") or {}
    ike_life = profile.get("ike_lifetime") or {}
    auth = profile.get("authentication_method") or {}
    return {
        "ike_version": value("ike_version"),
        "aggressive": value("exchange_mode") == "Aggressive Mode",
        "ike_encryption": chosen.get("encryption"),
        "ike_key_length": chosen.get("key_length"),
        "ike_integrity": chosen.get("integrity"),
        "ike_prf": chosen.get("prf"),
        "dh_group": chosen.get("dh_group"),
        "esp_encryption": value("esp_encryption"),
        "esp_integrity": value("esp_integrity"),
        "esp_detected": bool(esp.get("detected")),
        "ah_only": bool(ah.get("detected")) and not esp.get("detected"),
        "pfs": value("pfs"),
        "ike_lifetime": ike_life.get("value"),
        "child_lifetime": child.get("value"),
        "child_lifetime_lower_bound": child.get("lower_bound_seconds"),
        "auth_method": auth.get("value"),
        "psk": auth.get("psk") or ("Pre-Shared" in (auth.get("value") or "")),
        "downgrade_surface": ike.get("downgrade_surface") or [],
    }


# ---------------------------------------------------------------- helpers

def _has(name: str | None, *tokens: str) -> bool:
    return bool(name) and any(t in name.upper() for t in tokens)


def _result(status: str, evidence: str) -> tuple[str, str]:
    return status, evidence


def _ike_version(f):
    if f["ike_version"] is None:
        return _result(UNKNOWN, "IKE not captured")
    if f["ike_version"] == "IKEv2":
        return _result(PASS, "IKEv2 in use")
    return _result(FAIL, "IKEv1 negotiated (RFC 9395 moves IKEv1 to Historic)")


def _ike_encryption_ietf(f):
    enc = f["ike_encryption"]
    if not enc:
        return _result(UNKNOWN, "IKE SA encryption not observable")
    if _has(enc, "NULL") or (_has(enc, "DES") and not _has(enc, "3DES")):
        return _result(FAIL, f"{enc} is MUST NOT")
    if _has(enc, "3DES", "BLOWFISH", "CAST", "IDEA"):
        return _result(WARN, f"{enc} is legacy (MAY at best)")
    return _result(PASS, f"{enc}")


def _prf_ietf(f):
    prf = f["ike_prf"]
    if not prf:
        return _result(UNKNOWN, "PRF not observable")
    if _has(prf, "MD5"):
        return _result(FAIL, f"{prf} is MUST NOT")
    if _has(prf, "SHA1"):
        return _result(WARN, f"{prf} is MUST- (being phased out)")
    return _result(PASS, prf)


def _ike_integrity_ietf(f):
    integ = f["ike_integrity"]
    if not integ:
        return _result(UNKNOWN, "IKE integrity not observable")
    if "AEAD" in integ:
        return _result(PASS, "AEAD cipher provides integrity")
    if _has(integ, "MD5"):
        return _result(FAIL, f"{integ} is MUST NOT")
    if _has(integ, "SHA1"):
        return _result(WARN, f"{integ} is MUST-")
    return _result(PASS, integ)


def _dh_ietf(f):
    group = f["dh_group"]
    if not group:
        return _result(UNKNOWN, "DH group not observable")
    if group in (1, 2):
        return _result(FAIL, f"Group {group} is MUST NOT")
    if group in (5, 22, 23, 24):
        return _result(WARN, f"Group {group} is SHOULD NOT")
    return _result(PASS, f"Group {group}")


def _esp_encryption_ietf(f):
    if f["ah_only"]:
        return _result(FAIL, "AH only — no confidentiality")
    enc = f["esp_encryption"]
    if not enc:
        return _result(UNKNOWN, "ESP encryption not inferable")
    if _has(enc, "NULL"):
        return _result(FAIL, "ESP with NULL encryption provides no confidentiality")
    if _has(enc, "3DES"):
        return _result(WARN, f"{enc} (RFC 8221: MAY, legacy)")
    return _result(PASS, enc)


def _esp_integrity_ietf(f):
    integ = f["esp_integrity"]
    if not integ:
        return _result(UNKNOWN, "ESP integrity not inferable")
    if _has(integ, "MD5"):
        return _result(FAIL, f"{integ} is MUST NOT (RFC 8221)")
    if _has(integ, "SHA1"):
        return _result(WARN, f"{integ} is MUST- (RFC 8221)")
    return _result(PASS, integ)


def _no_aggressive(f):
    if f["ike_version"] is None:
        return _result(UNKNOWN, "IKE not captured")
    if f["aggressive"]:
        return _result(FAIL, "IKEv1 Aggressive Mode exposes identities and PSK hashes")
    return _result(PASS, "No Aggressive Mode")


def _no_downgrade(f):
    if f["ike_version"] is None:
        return _result(UNKNOWN, "IKE not captured")
    if f["downgrade_surface"]:
        return _result(WARN, f"Initiator also offers {', '.join(f['downgrade_surface'])}")
    return _result(PASS, "No weaker fallback algorithms offered")


def _aes_nist(f):
    issues = []
    for label, enc in (("IKE", f["ike_encryption"]), ("ESP", f["esp_encryption"])):
        if enc and (_has(enc, "3DES", "NULL", "BLOWFISH", "CAST") or (_has(enc, "DES") and not _has(enc, "3DES"))):
            issues.append(f"{label}: {enc}")
    if f["ah_only"]:
        issues.append("AH only")
    if issues:
        return _result(FAIL, "; ".join(issues) + " (SP 800-131A Rev. 2 disallows TDEA encryption after 2023)")
    if not f["ike_encryption"] and not f["esp_encryption"]:
        return _result(UNKNOWN, "Encryption not observable")
    return _result(PASS, "AES / ChaCha20 family")


def _sha2_nist(f):
    algs = [a for a in (f["ike_prf"], f["ike_integrity"], f["esp_integrity"]) if a]
    if not algs:
        return _result(UNKNOWN, "Integrity/PRF not observable")
    if any(_has(a, "MD5") for a in algs):
        return _result(FAIL, "MD5 in use")
    if any(_has(a, "SHA1") for a in algs):
        return _result(WARN, "SHA-1 based HMAC in use")
    return _result(PASS, ", ".join(algs))


def _dh_nist(f):
    group = f["dh_group"]
    if not group:
        return _result(UNKNOWN, "DH group not observable")
    if group in (1, 2, 5, 22, 25):
        return _result(FAIL, f"Group {group} below 112-bit strength")
    return _result(PASS, f"Group {group}")


def _pfs(f):
    if f["pfs"] is None:
        return _result(UNKNOWN, "PFS not observable in this capture")
    return _result(PASS, "PFS enabled") if f["pfs"] else _result(FAIL, "PFS disabled")


def _ike_lifetime(f):
    life = f["ike_lifetime"]
    if not life:
        return _result(UNKNOWN, "IKE SA lifetime not observable")
    if life > 86400:
        return _result(FAIL, f"{life} s exceeds 24 h")
    return _result(PASS, f"{life} s")


def _child_lifetime(f):
    life, bound = f["child_lifetime"], f["child_lifetime_lower_bound"]
    if life:
        return _result(PASS, f"≈{life} s") if life <= 28800 else _result(FAIL, f"≈{life} s exceeds 8 h")
    if bound and bound > 28800:
        return _result(FAIL, f"SA active ≥ {bound:.0f} s without rekey")
    return _result(UNKNOWN, "No Child SA rekey observed")


def _confidentiality(f):
    if f["ah_only"]:
        return _result(FAIL, "AH only")
    if _has(f["esp_encryption"], "NULL"):
        return _result(FAIL, "ESP-NULL")
    if not f["esp_detected"]:
        return _result(UNKNOWN, "No ESP traffic")
    return _result(PASS, "ESP encryption in use")


def _auth_nist(f):
    auth = f["auth_method"]
    if not auth:
        return _result(UNKNOWN, "Authentication method not observable")
    if f["aggressive"] and f["psk"]:
        return _result(FAIL, "Aggressive Mode with PSK")
    if f["psk"]:
        return _result(WARN, "PSK — acceptable only with long random keys")
    return _result(PASS, auth)


def _cnsa_aes256(f):
    if not f["ike_encryption"]:
        return _result(UNKNOWN, "IKE encryption not observable")
    if f["ike_key_length"] == 256 and _has(f["ike_encryption"], "AES"):
        return _result(PASS, f["ike_encryption"])
    return _result(FAIL, f"{f['ike_encryption']} is not AES-256")


def _cnsa_esp(f):
    enc = f["esp_encryption"]
    if not enc:
        return _result(UNKNOWN, "ESP encryption not inferable")
    if not _has(enc, "AES"):
        return _result(FAIL, f"{enc} is not AES")
    return _result(UNKNOWN, "AES family inferred; key length (256 required) not observable on ESP")


def _cnsa_dh(f):
    group = f["dh_group"]
    if not group:
        return _result(UNKNOWN, "DH group not observable")
    if group in (20, 21) or group in (15, 16, 17, 18):
        return _result(PASS, f"Group {group}")
    return _result(FAIL, f"Group {group} (CNSA requires ECP-384 or MODP ≥ 3072)")


def _cnsa_hash(f):
    prf = f["ike_prf"]
    if not prf:
        return _result(UNKNOWN, "PRF not observable")
    return _result(PASS, prf) if _has(prf, "SHA2-384", "SHA2-512") else _result(FAIL, f"{prf} (SHA-384 required)")


def _cnsa_auth(f):
    if not f["auth_method"]:
        return _result(UNKNOWN, "Authentication not observable")
    if f["psk"]:
        return _result(FAIL, "CNSA requires certificate (ECDSA P-384 / RSA ≥ 3072) authentication")
    return _result(UNKNOWN, "Certificate in use; key type/size not observable")


Check = tuple[str, str, str, Callable[[dict], tuple[str, str]]]

PROFILES: dict[str, dict[str, Any]] = {
    "ietf": {
        "name": "IETF RFC 8247 / 8221 / 9395",
        "description": "Current IETF algorithm requirements for IKEv2 and ESP, and IKEv1 deprecation",
        "checks": [
            ("IETF-1", "IKEv2 is used", "RFC 9395", _ike_version),
            ("IETF-2", "IKE encryption is MUST/SHOULD level", "RFC 8247 §2.1", _ike_encryption_ietf),
            ("IETF-3", "IKE PRF is not MD5 / SHA-1", "RFC 8247 §2.2", _prf_ietf),
            ("IETF-4", "IKE integrity is not MD5 / SHA-1", "RFC 8247 §2.3", _ike_integrity_ietf),
            ("IETF-5", "DH group is not deprecated", "RFC 8247 §2.4", _dh_ietf),
            ("IETF-6", "ESP encryption provides confidentiality with a current cipher", "RFC 8221 §5", _esp_encryption_ietf),
            ("IETF-7", "ESP integrity is not MD5 / SHA-1", "RFC 8221 §6", _esp_integrity_ietf),
            ("IETF-8", "Aggressive Mode is not used", "RFC 9395", _no_aggressive),
            ("IETF-9", "No weak fallback algorithms offered", "RFC 8247 §1.3", _no_downgrade),
        ],
    },
    "nist": {
        "name": "NIST SP 800-77r1",
        "description": "NIST Guide to IPsec VPNs with SP 800-131A algorithm transitions",
        "checks": [
            ("NIST-1", "Encryption is AES (or ChaCha20); no TDEA/DES/NULL", "SP 800-77r1 §4.2, SP 800-131A", _aes_nist),
            ("NIST-2", "Integrity and PRF use SHA-2", "SP 800-77r1 §4.2", _sha2_nist),
            ("NIST-3", "DH group ≥ 112-bit strength (MODP-2048 / ECP-256)", "SP 800-77r1 §4.2", _dh_nist),
            ("NIST-4", "Perfect Forward Secrecy enabled", "SP 800-77r1 §4.2", _pfs),
            ("NIST-5", "IKE SA lifetime ≤ 24 h", "SP 800-77r1 §4.2", _ike_lifetime),
            ("NIST-6", "Child SA lifetime ≤ 8 h", "SP 800-77r1 §4.2", _child_lifetime),
            ("NIST-7", "Traffic is encrypted (not AH-only / ESP-NULL)", "SP 800-77r1 §3", _confidentiality),
            ("NIST-8", "Strong peer authentication", "SP 800-77r1 §4.3", _auth_nist),
        ],
    },
    "cnsa": {
        "name": "CNSA 1.0 (high assurance)",
        "description": "NSA CNSSP-15 suite for national-security systems",
        "checks": [
            ("CNSA-1", "IKE encryption AES-256", "CNSSP-15", _cnsa_aes256),
            ("CNSA-2", "ESP encryption AES-256", "CNSSP-15", _cnsa_esp),
            ("CNSA-3", "Key exchange ECDH P-384 or DH ≥ 3072", "CNSSP-15", _cnsa_dh),
            ("CNSA-4", "Hash SHA-384 or better", "CNSSP-15", _cnsa_hash),
            ("CNSA-5", "IKEv2", "CNSSP-15 / RFC 9206", _ike_version),
            ("CNSA-6", "Certificate authentication (ECDSA P-384 / RSA ≥ 3072)", "CNSSP-15", _cnsa_auth),
        ],
    },
}


def evaluate_compliance(analysis: dict[str, Any]) -> dict[str, Any]:
    facts = extract_facts(analysis)
    profiles = {}
    for key, profile in PROFILES.items():
        checks = []
        for check_id, title, reference, fn in profile["checks"]:
            status, evidence = fn(facts)
            checks.append({"id": check_id, "title": title, "reference": reference,
                           "status": status, "evidence": evidence})
        profiles[key] = {"name": profile["name"], "description": profile["description"],
                         "checks": checks, **_summarize(checks)}
    return {"profiles": profiles, "facts": facts}


def _summarize(checks: list[dict]) -> dict[str, Any]:
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in (PASS, WARN, FAIL, UNKNOWN)}
    assessable = counts[PASS] + counts[WARN] + counts[FAIL]
    coverage = assessable / len(checks) if checks else 0.0
    score = round(100 * (counts[PASS] + 0.5 * counts[WARN]) / assessable, 1) if assessable else None
    if counts[FAIL]:
        status = "Non-compliant"
    elif coverage < 0.4:
        status = "Indeterminate"
    elif counts[WARN]:
        status = "Compliant with warnings"
    else:
        status = "Compliant" if counts[UNKNOWN] == 0 else "Compliant (partial evidence)"
    return {"counts": counts, "score": score, "coverage": round(coverage, 3), "status": status}
