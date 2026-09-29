"""
Evidence chains: Packet → Extracted parameter → Security rule → Risk → Recommendation.

Every finding is traced back to the capture frames it rests on and the profile fields the rule read,
so an analyst (or an evaluator) can verify each claim step by step.
"""
from __future__ import annotations

from typing import Any

from backend.intel.rules import rule_for

FIELD_LABELS = {
    "ipsec_protocols": "IPsec protocol", "ike_version": "IKE version", "exchange_mode": "Exchange mode",
    "mode": "Encapsulation mode", "ike_encryption": "IKE SA encryption", "ike_integrity": "IKE SA integrity",
    "ike_prf": "IKE SA PRF", "key_exchange": "Key exchange", "esp_encryption": "ESP encryption",
    "esp_integrity": "ESP integrity", "authentication_method": "Authentication", "pfs": "Perfect Forward Secrecy",
    "ike_lifetime": "IKE SA lifetime", "child_sa_lifetime": "Child SA lifetime",
    "replay_protection": "Replay protection", "nat_traversal": "NAT traversal", "ip_version": "IP version",
    "implementation": "Implementation", "traffic_types": "Traffic inside the tunnel",
}

# finding id (or prefix) → the profile fields / pseudo-fields the rule reads
FINDING_FIELDS: dict[str, list[str]] = {
    "CRYPTO": ["ike_encryption", "esp_encryption"],
    "KE-006": ["offered"], "KE-007": ["notify"], "KE": ["key_exchange"],
    "PFS": ["pfs"],
    "AUTH-004": ["ike_integrity", "esp_integrity"], "AUTH-005": ["ike_integrity", "esp_integrity"],
    "AUTH-001": ["authentication_method", "exchange_mode"], "AUTH": ["authentication_method"],
    "LIFE-001": ["ike_lifetime"], "LIFE-003": ["ike_lifetime"], "LIFE-002": ["child_sa_lifetime"],
    "LIFE-004": ["replay_protection"], "LIFE-005": ["ike_lifetime", "child_sa_lifetime"],
    "REPLAY": ["replay_protection"],
    "CFG-001": ["ike_version"], "CFG-002": ["ike_version"], "CFG-003": ["mode"], "CFG-004": ["notify"],
    "CFG-005": ["compliance"], "CFG-006": ["notify"],
    "META-001": ["identities"], "META-002": ["implementation"], "META-003": ["traffic_types"],
    "META-004": ["nat_traversal"], "META-005": ["mode"], "META-006": ["certreq"],
}

SA_EXCHANGES = ("IKE_SA_INIT", "MAIN_MODE", "AGGRESSIVE")
REKEY_EXCHANGES = ("CREATE_CHILD_SA", "QUICK_MODE")


def _fields_for(finding_id: str) -> list[str]:
    if finding_id in FINDING_FIELDS:
        return FINDING_FIELDS[finding_id]
    return FINDING_FIELDS.get(finding_id.split("-")[0], [])


# ---------------------------------------------------------------- packet references

def primary_session(analysis: dict[str, Any]) -> dict[str, Any] | None:
    ike = analysis.get("ike_analysis") or {}
    sessions = ike.get("sessions") or []
    return next((s for s in sessions if s.get("init_spi") == ike.get("primary_session")), sessions[0] if sessions else None)


def _frames(messages: list[dict]) -> list[int]:
    out: list[int] = []
    for m in messages:
        out.extend(m.get("frames") or [])
    return sorted(set(out))[:10]


def _message_ref(analysis: dict, exchanges: tuple[str, ...], what: str) -> dict[str, Any] | None:
    session = primary_session(analysis)
    if not session:
        return None
    msgs = [m for m in session.get("message_sizes") or [] if m["exchange"] in exchanges]
    if not msgs:
        return None
    names = sorted({m["exchange"] for m in msgs})
    encrypted = any(m.get("encrypted") for m in msgs)
    sizes = ", ".join(f"{m['length']} B" for m in msgs[:4])
    frames = _frames(msgs)
    return {"label": f"{' / '.join(names)} · {sum(max(1, len(m.get('frames') or [])) for m in msgs)} packet(s)",
            "detail": f"{what}; {'encrypted' if encrypted else 'cleartext'} message(s) of {sizes}",
            "frames": frames, "encrypted": encrypted}


def _esp_ref(analysis: dict) -> dict[str, Any] | None:
    esp = analysis.get("esp_analysis") or {}
    if not esp.get("detected"):
        ah = analysis.get("ah_analysis") or {}
        if ah.get("detected"):
            return {"label": f"AH × {ah.get('packet_count', 0)}", "detail": "IP protocol 51 headers", "frames": []}
        return None
    sas = sorted(esp.get("sa_info") or [], key=lambda sa: -sa["packet_count"])
    frames = [sa["first_frame"] for sa in sas[:6] if sa.get("first_frame") is not None]
    fp = esp.get("fingerprint") or {}
    return {"label": f"ESP × {esp['packet_count']:,} on {esp.get('sa_count', 0)} SA(s)",
            "detail": f"payload lengths of {fp.get('packets', esp['packet_count']):,} packets, "
                      f"{fp.get('distinct_lengths', '?')} distinct",
            "frames": sorted(frames), "encrypted": True}


def packet_ref(analysis: dict[str, Any], field: str, traffic: dict | None = None) -> dict[str, Any] | None:
    ike = analysis.get("ike_analysis") or {}
    v1 = ike.get("version") == "IKEv1"
    if field in ("ike_version", "exchange_mode", "ike_encryption", "ike_integrity", "ike_prf", "key_exchange",
                 "offered", "implementation", "certreq", "identities"):
        what = {"offered": "initiator's cleartext proposal list", "implementation": "Vendor ID payloads",
                "certreq": "CERTREQ payload", "identities": "ID payloads (Aggressive Mode)"}.get(
            field, "IKE header and SA / KE payloads")
        return _message_ref(analysis, SA_EXCHANGES, what)
    if field == "authentication_method":
        return _message_ref(analysis, SA_EXCHANGES if v1 else ("IKE_AUTH",),
                            "authentication attribute" if v1 else "IKE_AUTH sizes and round trips")
    if field == "pfs":
        return _message_ref(analysis, REKEY_EXCHANGES, "Child SA negotiation sizes")
    if field == "ike_lifetime":
        return _message_ref(analysis, SA_EXCHANGES if v1 else ("CREATE_CHILD_SA",), "lifetime attribute / rekey timing")
    if field == "child_sa_lifetime":
        return _message_ref(analysis, REKEY_EXCHANGES, "rekey timing") or _esp_ref(analysis)
    if field == "notify":
        return _message_ref(analysis, SA_EXCHANGES + ("IKE_AUTH", "INFORMATIONAL"), "Notify payloads")
    if field in ("esp_encryption", "esp_integrity", "mode", "ipsec_protocols"):
        return _esp_ref(analysis)
    if field == "replay_protection":
        esp = analysis.get("esp_analysis") or {}
        events = [e for sa in esp.get("sa_info") or [] for e in (sa.get("replay") or {}).get("events", [])]
        if events:
            return {"label": f"{len(events)} sequence anomalies",
                    "detail": "; ".join(f"{e['kind']} seq {e['seq']}" for e in events[:3]),
                    "frames": sorted(e["frame"] for e in events if e.get("frame") is not None)[:10]}
        return _esp_ref(analysis)
    if field == "traffic_types":
        traffic = traffic or {}
        return {"label": f"{traffic.get('windows', 0)} × 10 s windows",
                "detail": f"ESP sizes and timing across {len(traffic.get('flows') or [])} tunnel(s)", "frames": []}
    if field == "nat_traversal":
        nat = analysis.get("nat_t_analysis") or {}
        return {"label": "UDP 4500", "detail": f"{nat.get('nat_t_esp_packets', 0)} ESP-in-UDP, "
                f"{nat.get('nat_t_ike_packets', 0)} IKE on 4500, {nat.get('keepalives', 0)} keepalives", "frames": []}
    if field == "ip_version":
        return {"label": "Outer IP headers", "detail": "version field of every IPsec packet", "frames": []}
    return None


# ---------------------------------------------------------------- parameters

def _parameter(analysis: dict, field: str, security: dict) -> dict[str, Any] | None:
    profile = analysis.get("profile") or {}
    ike = analysis.get("ike_analysis") or {}
    if field in profile:
        ev = profile[field]
        value = ev.get("display") or ev.get("value")
        if value is None:
            value = "not observable"
        elif value is True:
            value = "Yes"
        elif value is False:
            value = "No"
        return {"label": FIELD_LABELS.get(field, field), "value": str(value), "source": ev.get("source"),
                "confidence": ev.get("confidence"), "evidence": ev.get("evidence"), "method": ev.get("method")}
    if field == "offered":
        return {"label": "Weak algorithms offered", "value": ", ".join(ike.get("downgrade_surface") or []) or "none",
                "source": "observed", "confidence": 1.0, "evidence": "Initiator's cleartext SA payload"}
    if field == "notify":
        names = [n["name"] for n in ike.get("notifies") or []][:6]
        return {"label": "Notify types", "value": ", ".join(names) or "none", "source": "observed",
                "confidence": 1.0, "evidence": "Notify payloads"}
    if field == "identities":
        ids = ike.get("identities") or []
        return {"label": "Identity payloads", "value": ", ".join(f"{i['id_type']} {i['value']}" for i in ids[:3]) or "none",
                "source": "observed", "confidence": 1.0, "evidence": "ID payloads in cleartext"}
    if field == "certreq":
        return {"label": "CERTREQ", "value": "present" if ike.get("certreq_seen") else "absent",
                "source": "observed", "confidence": 1.0, "evidence": "IKE_SA_INIT payload list"}
    if field == "compliance":
        failed = [f"{c['id']}" for p in (security.get("compliance") or {}).values() for c in p["checks"]
                  if c["status"] == "fail"]
        return {"label": "Failed controls", "value": ", ".join(failed[:8]) or "none", "source": "observed",
                "confidence": 1.0, "evidence": "Compliance profiles"}
    return None


# ---------------------------------------------------------------- chains

def build_chains(analysis: dict[str, Any], security: dict[str, Any], traffic: dict[str, Any]) -> dict[str, Any]:
    chains = {}
    for f in security.get("findings") or []:
        fields = _fields_for(f["id"])
        params = [p for p in (_parameter(analysis, field, security) for field in fields) if p]
        if f["id"].startswith(("CRYPTO", "AUTH-004", "AUTH-005")):
            # merged findings name the subjects they cover: keep only the parameters they mention
            mentioned = [p for p in params if p["value"] in f["title"]]
            params = mentioned or params
        refs = []
        for field in fields:
            ref = packet_ref(analysis, field, traffic)
            if ref and ref not in refs:
                refs.append(ref)
        rule, reference, impact = rule_for(f["id"])
        chains[f["id"]] = {
            "finding_id": f["id"],
            "packets": refs,
            "parameters": params,
            "rule": {"statement": rule, "reference": reference, "id": f["id"]},
            "risk": {"severity": f["severity"], "impact": impact, "confidence": f.get("confidence"),
                     "source": f.get("evidence_source")},
            "recommendation": f["recommendation"],
        }
    return chains


SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def posture_explanation(security: dict[str, Any], chains: dict[str, Any]) -> dict[str, Any]:
    """The overall verdict as Risk → Evidence → Impact → Recommendation, built from the top findings."""
    findings = [f for f in security.get("findings") or [] if f["severity"] != "Informational"]
    findings.sort(key=lambda f: SEVERITY_RANK[f["severity"]])
    evidence, impacts, actions, seen = [], [], [], set()
    for f in findings:
        chain = chains.get(f["id"]) or {}
        for p in chain.get("parameters") or []:
            if p["label"] == "Failed controls":
                continue
            item = f"{p['label']}: {p['value']}"
            if p["value"] not in ("not observable", "none") and item not in seen:
                seen.add(item)
                evidence.append({"text": item, "finding": f["id"], "severity": f["severity"],
                                 "source": p.get("source"), "confidence": p.get("confidence")})
        impact = (chain.get("risk") or {}).get("impact")
        if impact and impact not in impacts and len(impacts) < 3 and f["severity"] in ("Critical", "High", "Medium"):
            impacts.append(impact)
        if f["recommendation"] not in actions and len(actions) < 3:
            actions.append(f["recommendation"])
    if not impacts and findings:
        impacts.append((chains.get(findings[0]["id"]) or {}).get("risk", {}).get("impact", ""))
    level = security.get("risk_level") or "Unknown"
    return {
        "risk_level": level,
        "headline": level.replace(" Risk", "").upper(),
        "score": security.get("overall_score"),
        "evidence": evidence[:6],
        "impact": " ".join(i for i in impacts if i) or "No material weakness found in the observable configuration.",
        "recommendations": actions or ["No change needed."],
        "cap": security.get("score_cap"),
        "coverage": security.get("coverage"),
        "method": "Deterministic: top findings by severity → the parameters they read → rule impact → actions",
    }
