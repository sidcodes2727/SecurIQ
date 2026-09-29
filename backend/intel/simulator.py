"""
What-if configuration simulator.

The analyst changes configuration knobs; SecurIQ re-scores the *same analysis* with those profile fields
replaced, using the unchanged rule engine. Fields the analyst does not touch keep their observed or
inferred evidence, so the "current" column reproduces the real assessment exactly.

Each change is also scored on its own (marginal attribution), so the result explains which change moved
which category. `verify` in routes renders the proposed configuration as a testbed capture and runs the
full pipeline, turning the modelled estimate into a measured one.
"""
from __future__ import annotations

import copy
from typing import Any

from backend.analyzers.ike_constants import DH_NAMES
from backend.intel.fingerprint import config_fingerprint
from backend.intel.policy import evaluate_policy, load_policy
from backend.security.scoring_engine import assess_security
from backend.security.strength import dh_bits
from backend.testbed.esp_model import ESP_SUITES

IKE_ENCRYPTIONS = ["AES-256-GCM-16", "AES-128-GCM-16", "ChaCha20-Poly1305", "AES-256-CBC", "AES-128-CBC", "3DES-CBC"]
IKE_INTEGRITIES = ["None (AEAD)", "HMAC-SHA2-512-256", "HMAC-SHA2-384-192", "HMAC-SHA2-256-128", "HMAC-SHA1-96",
                   "HMAC-MD5-96"]
DH_CHOICES = [31, 21, 20, 19, 16, 15, 14, 5, 2]
AUTH_CHOICES = {"rsa": "Certificate (RSA)", "ecdsa": "Certificate (ECDSA)", "eap": "EAP", "psk": "Pre-Shared Key"}
LIFETIMES = [3600, 14400, 28800, 86400, 604800]
CHILD_LIFETIMES = [1800, 3600, 14400, 28800, 86400]

KNOBS: list[dict[str, Any]] = [
    {"key": "ike_version", "label": "IKE version", "group": "IKE SA", "options": ["IKEv2", "IKEv1"]},
    {"key": "exchange_mode", "label": "IKEv1 exchange", "group": "IKE SA", "options": ["Main Mode", "Aggressive Mode"]},
    {"key": "ike_encryption", "label": "IKE encryption", "group": "IKE SA", "options": IKE_ENCRYPTIONS},
    {"key": "ike_integrity", "label": "IKE integrity", "group": "IKE SA", "options": IKE_INTEGRITIES},
    {"key": "dh_group", "label": "DH group", "group": "IKE SA",
     "options": [{"value": g, "label": f"{DH_NAMES[g]} (group {g})"} for g in DH_CHOICES]},
    {"key": "auth", "label": "Authentication", "group": "IKE SA",
     "options": [{"value": k, "label": v} for k, v in AUTH_CHOICES.items()]},
    {"key": "ike_lifetime", "label": "IKE SA lifetime", "group": "IKE SA",
     "options": [{"value": s, "label": f"{s / 3600:g} h"} for s in LIFETIMES]},
    {"key": "esp_suite", "label": "ESP suite", "group": "Child SA",
     "options": [{"value": s.key, "label": s.label} for s in ESP_SUITES.values()]},
    {"key": "pfs", "label": "Perfect Forward Secrecy", "group": "Child SA", "options": [True, False]},
    {"key": "mode", "label": "Encapsulation", "group": "Child SA", "options": ["Tunnel", "Transport"]},
    {"key": "child_lifetime", "label": "Child SA lifetime", "group": "Child SA",
     "options": [{"value": s, "label": f"{s / 3600:g} h"} for s in CHILD_LIFETIMES]},
    {"key": "anti_replay", "label": "Replay anomalies resolved", "group": "Hardening", "options": [True, False]},
    {"key": "weak_proposals", "label": "Offer legacy fallback proposals", "group": "Hardening", "options": [True, False]},
    {"key": "vendor_id", "label": "Send Vendor IDs", "group": "Hardening", "options": [True, False]},
]
KNOB_KEYS = {k["key"] for k in KNOBS}

SIM = "simulated"


def _ev(value: Any, text: str = "Proposed configuration (simulated)", **extra: Any) -> dict[str, Any]:
    return {"value": value, "source": SIM, "confidence": 1.0, "evidence": text, "method": "What-if simulator", **extra}


def _aead(name: str | None) -> bool:
    return bool(name) and any(t in name.upper() for t in ("GCM", "CCM", "CHACHA", "AEAD"))


def esp_values(suite_key: str) -> tuple[str, str]:
    suite = ESP_SUITES[suite_key]
    if suite.family == "NULL":
        return "NULL (no encryption)", suite.integrity_label
    return suite.label.split(" + ")[0], suite.integrity_label


def _prf_for(encryption: str, integrity: str | None) -> str:
    if _aead(encryption) or not integrity:
        return "PRF-HMAC-SHA2-384" if "256" in encryption or "CHACHA" in encryption.upper() else "PRF-HMAC-SHA2-256"
    for token in ("SHA2-512", "SHA2-384", "SHA2-256", "SHA1", "MD5"):
        if token in integrity:
            return f"PRF-HMAC-{token}"
    return "PRF-HMAC-SHA2-256"


# ---------------------------------------------------------------- current configuration

def current_config(analysis: dict[str, Any]) -> dict[str, Any]:
    profile = analysis.get("profile") or {}
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    chosen = ike.get("chosen_suite") or {}

    def v(key: str):
        return (profile.get(key) or {}).get("value")

    auth = v("authentication_method")
    auth_key = None
    if auth:
        auth_key = "psk" if "Pre-Shared" in auth else "eap" if "EAP" in auth else "ecdsa" if "ECDSA" in auth else "rsa"
    replay = (esp.get("replay_summary") or {}) if esp.get("detected") else {}
    return {
        "ike_version": v("ike_version"),
        "exchange_mode": v("exchange_mode") if v("ike_version") == "IKEv1" else None,
        "ike_encryption": chosen.get("encryption"),
        "ike_integrity": chosen.get("integrity") or ("None (AEAD)" if _aead(chosen.get("encryption")) else None),
        "dh_group": chosen.get("dh_group"),
        "auth": auth_key,
        "ike_lifetime": v("ike_lifetime"),
        "esp_suite": None,  # key length is not observable, so no exact suite; the label below says what was seen
        "esp_observed": " + ".join(x for x in (v("esp_encryption"), v("esp_integrity")) if x) or None,
        "pfs": v("pfs"),
        "mode": v("mode"),
        "child_lifetime": v("child_sa_lifetime"),
        "anti_replay": None if not replay else not (replay.get("duplicates") or replay.get("counter_resets")),
        "weak_proposals": bool(ike.get("downgrade_surface")) if ike.get("detected") else None,
        "vendor_id": any(x.get("reveals_implementation") for x in ike.get("vendor_ids") or []) if ike.get("detected") else None,
    }


def recommended_changes(analysis: dict[str, Any]) -> dict[str, Any]:
    """The smallest set of changes that resolves every non-informational weakness the knobs can fix."""
    cur = current_config(analysis)
    changes: dict[str, Any] = {}
    if cur["ike_version"] == "IKEv1":
        changes["ike_version"] = "IKEv2"
    enc = cur["ike_encryption"]
    if enc and (not _aead(enc) or "128" in enc):
        changes["ike_encryption"] = "AES-256-GCM-16"
        changes["ike_integrity"] = "None (AEAD)"
    elif cur["ike_integrity"] and any(t in cur["ike_integrity"] for t in ("MD5", "SHA1")):
        changes["ike_integrity"] = "HMAC-SHA2-256-128"
    if cur["dh_group"] and (dh_bits(cur["dh_group"]) or 0) < 128:
        changes["dh_group"] = 20
    if cur["auth"] == "psk":
        changes["auth"] = "rsa"
    if cur["ike_lifetime"] and cur["ike_lifetime"] > 86400:
        changes["ike_lifetime"] = 14400
    esp = cur["esp_observed"] or ""
    if esp and not ("AEAD" in esp or "GCM" in esp or "ChaCha" in esp):
        changes["esp_suite"] = "aes256gcm16"
    if cur["pfs"] is False:
        changes["pfs"] = True
    if cur["mode"] == "Transport":
        changes["mode"] = "Tunnel"
    if cur["child_lifetime"] and cur["child_lifetime"] > 28800:
        changes["child_lifetime"] = 3600
    if cur["anti_replay"] is False:
        changes["anti_replay"] = True
    if cur["weak_proposals"]:
        changes["weak_proposals"] = False
    if cur["vendor_id"]:
        changes["vendor_id"] = False
    return changes


# ---------------------------------------------------------------- applying changes

def validate(changes: dict[str, Any], analysis: dict[str, Any]) -> list[str]:
    cur = {**current_config(analysis), **changes}
    problems = [f"Unknown setting: {k}" for k in changes if k not in KNOB_KEYS]
    if cur.get("ike_version") == "IKEv1" and _aead(cur.get("ike_encryption")):
        problems.append("IKEv1 Phase 1 has no AEAD ciphers: choose a CBC cipher or IKEv2")
    if cur.get("ike_version") == "IKEv1" and cur.get("auth") == "eap":
        problems.append("EAP authentication requires IKEv2")
    if not _aead(cur.get("ike_encryption")) and cur.get("ike_integrity") == "None (AEAD)":
        problems.append("A CBC IKE cipher needs an integrity algorithm")
    return problems


def apply_changes(analysis: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    a = copy.deepcopy(analysis)
    profile = a.setdefault("profile", {})
    ike = a.setdefault("ike_analysis", {})
    if not ike.get("chosen_suite"):
        ike["chosen_suite"] = {}
    chosen = ike["chosen_suite"]
    esp = a.setdefault("esp_analysis", {})
    changes = dict(changes)

    if changes.get("ike_encryption") and _aead(changes["ike_encryption"]) and "ike_integrity" not in changes:
        changes["ike_integrity"] = "None (AEAD)"

    if "ike_version" in changes:
        version = changes["ike_version"]
        profile["ike_version"] = _ev(version)
        if version == "IKEv2":
            profile["exchange_mode"] = _ev("IKEv2")
            ike["identities"] = []  # IKEv2 identities travel inside encrypted IKE_AUTH
        elif "exchange_mode" not in changes and (profile.get("exchange_mode") or {}).get("value") == "IKEv2":
            profile["exchange_mode"] = _ev("Main Mode")
    if "exchange_mode" in changes and (changes.get("ike_version") or (profile.get("ike_version") or {}).get("value")) == "IKEv1":
        profile["exchange_mode"] = _ev(changes["exchange_mode"])
        if changes["exchange_mode"] == "Aggressive Mode":
            ike["identities"] = ike.get("identities") or [{"id_type": "FQDN", "value": "gw-a.example.org"}]
        else:
            ike["identities"] = []
    if "ike_encryption" in changes:
        name = changes["ike_encryption"]
        profile["ike_encryption"] = _ev(name)
        chosen["encryption"] = name
        chosen["key_length"] = 256 if "256" in name or "ChaCha" in name else 128 if "128" in name else None
    if "ike_integrity" in changes:
        name = changes["ike_integrity"]
        value = None if name == "None (AEAD)" else name
        profile["ike_integrity"] = _ev(value) if value else {"value": None, "source": SIM, "confidence": 1.0,
                                                               "evidence": "AEAD suite: no separate integrity"}
        chosen["integrity"] = value
    if "ike_encryption" in changes or "ike_integrity" in changes:
        prf = _prf_for(chosen.get("encryption") or "", chosen.get("integrity"))
        chosen["prf"] = prf
        profile["ike_prf"] = _ev(prf)
    if "dh_group" in changes:
        g = int(changes["dh_group"])
        chosen["dh_group"], chosen["dh_group_name"] = g, DH_NAMES.get(g, str(g))
        profile["key_exchange"] = _ev(f"{DH_NAMES.get(g, g)} (group {g})", group=g)
    if "auth" in changes:
        key = changes["auth"]
        profile["authentication_method"] = _ev(AUTH_CHOICES[key], psk=key == "psk")
    if "ike_lifetime" in changes:
        s = int(changes["ike_lifetime"])
        profile["ike_lifetime"] = _ev(s, display=f"{s / 3600:g} h")
    if "esp_suite" in changes:
        enc, integ = esp_values(changes["esp_suite"])
        profile["esp_encryption"] = _ev(enc)
        profile["esp_integrity"] = _ev(integ)
        if ESP_SUITES[changes["esp_suite"]].family == "NULL":
            esp["null_encryption"] = {"suspected": True, "confidence": 1.0, "evidence": "simulated ESP-NULL"}
        else:
            esp["null_encryption"] = {"suspected": False, "confidence": 1.0, "evidence": "simulated"}
    if "pfs" in changes:
        profile["pfs"] = _ev(bool(changes["pfs"]))
    if "mode" in changes:
        profile["mode"] = _ev(changes["mode"])
    if "child_lifetime" in changes:
        s = int(changes["child_lifetime"])
        profile["child_sa_lifetime"] = _ev(s, display=f"{s / 3600:g} h")
    if "anti_replay" in changes and esp.get("detected"):
        summary = dict(esp.get("replay_summary") or {})
        if changes["anti_replay"]:
            summary.update(duplicates=0, counter_resets=0, beyond_default_window=0)
            profile["replay_protection"] = _ev("Consistent", summary=summary)
        else:
            summary.update(duplicates=max(1, summary.get("duplicates") or 0), counter_resets=max(1, summary.get("counter_resets") or 0))
            profile["replay_protection"] = _ev("Anomalies detected", summary=summary)
        esp["replay_summary"] = summary
    if "weak_proposals" in changes:
        ike["downgrade_surface"] = ["3DES-CBC", "HMAC-MD5-96", "MODP-1024 (group 2)"] if changes["weak_proposals"] else []
    if "vendor_id" in changes:
        if changes["vendor_id"]:
            ike["vendor_ids"] = ike.get("vendor_ids") or [{"name": "strongSwan", "hex": "sim", "reveals_implementation": True}]
        else:
            ike["vendor_ids"] = [v for v in ike.get("vendor_ids") or [] if not v.get("reveals_implementation")]
            profile["implementation"] = {"value": None, "source": "not_observable", "confidence": 0.0,
                                         "evidence": "Vendor IDs disabled (simulated)"}
    return a


# ---------------------------------------------------------------- simulation

def _diff(a: float | None, b: float | None) -> float | None:
    return None if a is None or b is None else round(a - b, 1)


def _summary(security: dict[str, Any]) -> dict[str, Any]:
    return {
        "overall_score": security["overall_score"],
        "uncapped_score": security["uncapped_score"],
        "score_cap": security["score_cap"],
        "risk_level": security["risk_level"],
        "coverage": security["coverage"],
        "strength_bits": (security.get("effective_strength") or {}).get("bits"),
        "categories": {k: {"label": c["label"], "score": c["score"], "rating": c["rating"]}
                       for k, c in security["categories"].items()},
        "findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in security["findings"]
                     if f["severity"] != "Informational"],
    }


def simulate(record: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    analysis, traffic = record["ipsec_analysis"], record.get("traffic") or {}
    changes = {k: v for k, v in changes.items() if v is not None and v != ""}
    problems = validate(changes, analysis)
    if problems:
        return {"valid": False, "problems": problems}

    before = assess_security(analysis, traffic)
    proposed = apply_changes(analysis, changes)
    after = assess_security(proposed, traffic)

    labels = {k["key"]: k["label"] for k in KNOBS}
    cur = current_config(analysis)
    factors = []
    for key, value in changes.items():
        alone = assess_security(apply_changes(analysis, {key: value}), traffic)
        cats = []
        for cat_key, cat in alone["categories"].items():
            b, a = before["categories"][cat_key]["score"], cat["score"]
            if b != a:
                cats.append({"key": cat_key, "label": cat["label"], "before": b, "after": a,
                             "delta": None if b is None or a is None else round(a - b, 1)})
        without = assess_security(apply_changes(analysis, {k: v for k, v in changes.items() if k != key}), traffic)
        factors.append({
            "key": key, "label": labels.get(key, key),
            "from": cur.get("esp_observed") if key == "esp_suite" else cur.get(key), "to": value,
            "score_alone": alone["overall_score"],
            "delta_alone": _diff(alone["overall_score"], before["overall_score"]),
            # the weakest-link cap hides single changes while another Critical/High finding remains,
            # so also report the uncapped effect and how much is lost if this change is left out
            "delta_uncapped": _diff(alone["uncapped_score"], before["uncapped_score"]),
            "delta_if_removed": _diff(after["overall_score"], without["overall_score"]),
            "capped_alone": bool(alone["score_cap"]),
            "categories": cats,
            "resolves": sorted({f["id"] for f in before["findings"] if f["severity"] != "Informational"}
                               - {f["id"] for f in alone["findings"]}),
        })
    factors.sort(key=lambda f: (-(f["delta_if_removed"] or 0), -(f["delta_uncapped"] or 0)))

    ids_before = {f["id"] for f in before["findings"] if f["severity"] != "Informational"}
    ids_after = {f["id"] for f in after["findings"] if f["severity"] != "Informational"}
    policy = load_policy()
    delta = None if before["overall_score"] is None or after["overall_score"] is None \
        else round(after["overall_score"] - before["overall_score"], 1)
    return {
        "valid": True,
        "changes": changes,
        "current": _summary(before),
        "proposed": _summary(after),
        "delta": delta,
        "verdict": "No change" if not delta else "Security posture improved" if delta > 0 else "Security posture weakened",
        "factors": factors,
        "resolved": sorted(ids_before - ids_after),
        "introduced": sorted(ids_after - ids_before),
        "policy_before": evaluate_policy(policy, analysis),
        "policy_after": evaluate_policy(policy, proposed),
        "fingerprint_before": config_fingerprint(analysis),
        "fingerprint_after": config_fingerprint(proposed),
        "note": ("Modelled: the unchanged rule engine re-scores the analysis with the chosen settings replaced. "
                 "Untouched settings keep their observed or inferred evidence. Use Verify to render the proposed "
                 "configuration as a capture and measure it with the full pipeline."),
    }
