"""
"Golden configuration" compliance: the administrator states the policy, SecurIQ checks each capture.

A requirement the capture cannot show (e.g. an IKEv2 lifetime without a rekey, or the ESP key length)
is reported as *unknown*, never as a pass.
"""
from __future__ import annotations

import json
from typing import Any

from backend.analyzers.ike_constants import DH_NAMES
from backend.config import DATA_DIR
from backend.security.compliance import extract_facts
from backend.security.strength import encryption_bits

POLICY_PATH = DATA_DIR / "policy.json"

DEFAULT_POLICY: dict[str, Any] = {
    "name": "Golden configuration",
    "allowed_ike_versions": ["IKEv2"],
    "allow_aggressive_mode": False,
    "min_ike_encryption_bits": 256,
    "require_aead_esp": True,
    "min_esp_encryption_bits": 256,
    "forbidden_integrity": ["MD5", "SHA1"],
    "allowed_dh_groups": [14, 19, 20, 21, 31],
    "require_pfs": True,
    "allowed_modes": ["Tunnel"],
    "max_ike_lifetime_s": 86400,
    "max_child_lifetime_s": 3600,
    "allowed_auth": ["certificate", "eap"],
    "require_replay_integrity": True,
    "forbid_weak_proposals": True,
    "forbid_vendor_ids": False,
    "allow_nat_t": True,
}


def load_policy() -> dict[str, Any]:
    try:
        if POLICY_PATH.exists():
            return {**DEFAULT_POLICY, **json.loads(POLICY_PATH.read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        pass
    return dict(DEFAULT_POLICY)


def save_policy(policy: dict[str, Any]) -> dict[str, Any]:
    merged = {**DEFAULT_POLICY, **policy}
    POLICY_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def reset_policy() -> dict[str, Any]:
    if POLICY_PATH.exists():
        POLICY_PATH.unlink()
    return dict(DEFAULT_POLICY)


def _auth_class(value: str | None) -> str | None:
    if not value:
        return None
    if "Pre-Shared" in value:
        return "psk"
    if "EAP" in value:
        return "eap"
    return "certificate"


def _fmt_seconds(s: float) -> str:
    return f"{s / 3600:g} h" if s >= 3600 else f"{s:g} s"


def evaluate_policy(policy: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    f = extract_facts(analysis)
    profile = analysis.get("profile") or {}
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    rows: list[dict[str, Any]] = []

    def row(requirement: str, observed: Any, status: str, source: str | None = None, key: str = "") -> None:
        rows.append({"key": key, "requirement": requirement, "observed": "not observable" if observed is None else observed,
                     "status": status, "source": source})

    def src(field: str) -> str | None:
        return (profile.get(field) or {}).get("source")

    allowed = policy["allowed_ike_versions"]
    row(f"IKE version ∈ {{{', '.join(allowed)}}}", f["ike_version"],
        "unknown" if f["ike_version"] is None else "pass" if f["ike_version"] in allowed else "fail", src("ike_version"),
        "ike_version")
    if not policy["allow_aggressive_mode"]:
        mode = (profile.get("exchange_mode") or {}).get("value")
        row("No IKEv1 Aggressive Mode", mode, "unknown" if mode is None else "fail" if f["aggressive"] else "pass",
            src("exchange_mode"), "aggressive")

    bits, _ = encryption_bits(f["ike_encryption"])
    row(f"IKE SA encryption ≥ {policy['min_ike_encryption_bits']}-bit",
        f"{f['ike_encryption']} ({bits}-bit)" if f["ike_encryption"] else None,
        "unknown" if bits is None else "pass" if bits >= policy["min_ike_encryption_bits"] else "fail",
        src("ike_encryption"), "ike_encryption")

    esp_enc = f["esp_encryption"]
    if f["ah_only"]:
        row("ESP encryption present", "AH only (no encryption)", "fail", "observed", "esp_present")
    if policy["require_aead_esp"]:
        aead = esp_enc and any(t in esp_enc.upper() for t in ("GCM", "CCM", "CHACHA", "AEAD"))
        row("ESP uses AEAD (AES-GCM / ChaCha20-Poly1305)", esp_enc,
            "unknown" if not esp_enc else "pass" if aead else "fail", src("esp_encryption"), "esp_aead")
    esp_bits, note = encryption_bits(esp_enc)
    esp_unknown = esp_bits is None or "assumed" in note or "not observable" in note
    row(f"ESP encryption ≥ {policy['min_esp_encryption_bits']}-bit",
        esp_enc if not esp_unknown else (f"{esp_enc} — key length not observable" if esp_enc else None),
        "fail" if esp_bits == 0 else "unknown" if esp_unknown else
        "pass" if esp_bits >= policy["min_esp_encryption_bits"] else "fail", src("esp_encryption"), "esp_bits")

    forbidden = [t.upper() for t in policy["forbidden_integrity"]]
    integ = [x for x in (f["ike_integrity"], f["esp_integrity"]) if x]
    bad = [x for x in integ if any(t in x.upper().replace("SHA2", "") for t in forbidden)]
    row(f"No {'/'.join(policy['forbidden_integrity'])} integrity", ", ".join(integ) or None,
        "unknown" if not integ else "fail" if bad else "pass", src("ike_integrity"), "integrity")

    groups = policy["allowed_dh_groups"]
    row(f"DH group ∈ {{{', '.join(str(g) for g in groups)}}}",
        f"{DH_NAMES.get(f['dh_group'], '?')} (group {f['dh_group']})" if f["dh_group"] else None,
        "unknown" if not f["dh_group"] else "pass" if f["dh_group"] in groups else "fail", src("key_exchange"), "dh")

    if policy["require_pfs"]:
        row("PFS enabled on Child SAs", None if f["pfs"] is None else ("enabled" if f["pfs"] else "disabled"),
            "unknown" if f["pfs"] is None else "pass" if f["pfs"] else "fail", src("pfs"), "pfs")

    mode = (profile.get("mode") or {}).get("value")
    row(f"Mode ∈ {{{', '.join(policy['allowed_modes'])}}}", mode,
        "unknown" if mode is None else "pass" if mode in policy["allowed_modes"] else "fail", src("mode"), "mode")

    life = f["ike_lifetime"]
    row(f"IKE SA lifetime ≤ {_fmt_seconds(policy['max_ike_lifetime_s'])}", _fmt_seconds(life) if life else None,
        "unknown" if not life else "pass" if life <= policy["max_ike_lifetime_s"] else "fail", src("ike_lifetime"),
        "ike_lifetime")
    child, lower = f["child_lifetime"], f["child_lifetime_lower_bound"]
    if child:
        status, observed = ("pass" if child <= policy["max_child_lifetime_s"] else "fail"), _fmt_seconds(child)
    elif lower and lower > policy["max_child_lifetime_s"]:
        status, observed = "fail", f"> {_fmt_seconds(lower)} (no rekey seen)"
    else:
        status, observed = "unknown", None
    row(f"Child SA lifetime ≤ {_fmt_seconds(policy['max_child_lifetime_s'])}", observed, status,
        src("child_sa_lifetime"), "child_lifetime")

    auth = _auth_class(f["auth_method"])
    row(f"Authentication ∈ {{{', '.join(policy['allowed_auth'])}}}", f["auth_method"],
        "unknown" if auth is None else "pass" if auth in policy["allowed_auth"] else "fail",
        src("authentication_method"), "auth")

    if policy["require_replay_integrity"]:
        summary = esp.get("replay_summary") or {}
        issues = (summary.get("duplicates") or 0) + (summary.get("counter_resets") or 0)
        row("No replayed or reset sequence numbers", f"{summary.get('duplicates', 0)} duplicates, "
            f"{summary.get('counter_resets', 0)} resets" if esp.get("detected") else None,
            "unknown" if not esp.get("detected") else "fail" if issues else "pass", "inferred", "replay")
    if policy["forbid_weak_proposals"] and ike.get("detected"):
        surface = f["downgrade_surface"]
        row("No weak fallback proposals offered", ", ".join(surface) or "none",
            "fail" if surface else "pass", "observed", "weak_proposals")
    if policy["forbid_vendor_ids"] and ike.get("detected"):
        products = [v["name"] for v in ike.get("vendor_ids") or [] if v.get("reveals_implementation")]
        row("No product-identifying Vendor IDs", ", ".join(products) or "none", "fail" if products else "pass",
            "observed", "vendor_ids")
    if not policy["allow_nat_t"]:
        nat = (profile.get("nat_traversal") or {}).get("value")
        row("No NAT traversal", "UDP 4500" if nat else "none", "fail" if nat else "pass", "observed", "nat")

    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("pass", "fail", "unknown")}
    decided = counts["pass"] + counts["fail"]
    return {
        "policy_name": policy.get("name", "Policy"),
        "rows": rows,
        "counts": counts,
        "compliant": counts["fail"] == 0,
        "status": "Non-compliant" if counts["fail"] else "Compliant" if not counts["unknown"] else
        "Compliant on observable requirements",
        "score": round(100 * counts["pass"] / decided) if decided else None,
    }
