"""
IPsec deep analysis.

Turns parsed packets into an evidence-backed VPN profile. Every property is an
evidence record  {value, source, confidence, evidence, method}  where source is:

  observed        read directly from cleartext protocol fields
  inferred        derived from side channels (lengths, timing, message sizes)
  not_observable  cannot be determined passively from this capture

What is observable (RFC 7296 / RFC 2409):
  * IKEv2 IKE_SA_INIT and IKEv1 Main/Aggressive Mode messages 1–2 are cleartext:
    IKE SA algorithms, DH group, Vendor IDs, NAT detection, and in IKEv1 the
    authentication method and lifetime.
  * The Child SA (ESP) proposal, traffic selectors, USE_TRANSPORT_MODE and any PFS
    key exchange travel inside encrypted IKE_AUTH / CREATE_CHILD_SA / Quick Mode
    messages — so ESP algorithms, mode and PFS must be inferred.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from backend.analyzers.esp_fingerprint import detect_null_encryption, fingerprint_esp, icv_from_integrity, infer_mode
from backend.analyzers.flow_extractor import build_tunnels, group_security_associations
from backend.analyzers.ike_constants import (
    AEAD_ENCR_IDS, DH_KE_LENGTH, DH_NAMES, NOTIFY_COOKIE, NOTIFY_USE_TRANSPORT_MODE,
)

OBSERVED, INFERRED, NOT_OBSERVABLE = "observed", "inferred", "not_observable"

WEAK_ENCRYPTION_MARKERS = ("DES", "NULL", "Blowfish", "CAST", "IDEA", "RC5")
WEAK_HASH_MARKERS = ("MD5",)
WEAK_DH_GROUPS = {1, 2, 5, 22}

REPLAY_WINDOW = 64
SEQ_EXHAUSTION = 0xF0000000

# Expected total size (bytes) of a Child SA negotiation *without* a KE payload. The response carries a
# single selected proposal, so it is the most predictable message; requests may carry extra proposals.
# IKEv2 CREATE_CHILD_SA (RFC 7296): HDR(28) + SK hdr/IV/ICV(~36) + SA(~52) + Nonce(36) + TSi/TSr(48) [+ N]
# IKEv1 Quick Mode (RFC 2409):      HDR(28) + HASH(24) + SA(~56) + Nonce(~36) + IDci/IDcr(32), padded
REKEY_BASELINE = {2: {"response": 216, "request": 246}, 1: {"response": 185, "request": 193}}
IPV6_SELECTOR_EXTRA = 48   # two IPv6 traffic selectors instead of IPv4
# IKE_AUTH size thresholds: an X.509 RSA certificate alone is ~800–1500 bytes.
AUTH_SIZE_CERT_RSA = 900
AUTH_SIZE_CERT_ECDSA = 550

AH_INTEGRITY_BY_ICV = {
    12: "HMAC-SHA1-96 (or HMAC-MD5-96 / AES-XCBC-96)",
    16: "HMAC-SHA2-256-128",
    24: "HMAC-SHA2-384-192",
    32: "HMAC-SHA2-512-256",
}
IP_PROTOCOL_NAMES = {1: "ICMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


def evidence(value: Any, source: str, confidence: float, text: str,
             method: str | None = None, **extra: Any) -> dict[str, Any]:
    record = {
        "value": value,
        "source": source,
        "confidence": round(float(confidence), 3),
        "evidence": text,
        "method": method,
    }
    record.update(extra)
    return record


def not_observable(text: str, method: str | None = None) -> dict[str, Any]:
    return evidence(None, NOT_OBSERVABLE, 0.0, text, method)


# ================================================================ entry point

def analyze_ipsec(parsed_data: dict[str, Any]) -> dict[str, Any]:
    packets = parsed_data.get("packets", [])
    if not packets:
        return {"error": "No packets to analyze", "packets_analyzed": 0}

    ike_packets = [p for p in packets if p.get("protocol_type") in ("ike", "ike_natt") and p.get("ike")]
    esp_packets = [p for p in packets if p.get("protocol_type") == "esp" and p.get("spi")]
    ah_packets = [p for p in packets if p.get("protocol_type") == "ah" and p.get("spi")]

    ike = _analyze_ike(ike_packets)
    esp = _analyze_esp(esp_packets, (ike.get("chosen_suite") or {}).get("integrity"))
    ah = _analyze_ah(ah_packets)
    ip = _analyze_ip_versions(packets)
    ike["pfs"] = _infer_pfs(ike, esp, ip["primary_version"])
    lifetimes = _infer_lifetimes(ike, esp)
    nat = _analyze_nat_t(packets, ike_packets)

    timestamps = [p["timestamp"] for p in packets]
    profile = _build_profile(ike, esp, ah, nat, ip, lifetimes)
    timeline = _build_timeline(ike, esp, ah)
    ike.pop("_sessions", None)  # holds packet references; not serialisable

    return {
        "packets_analyzed": len(packets),
        "capture_start": min(timestamps),
        "capture_duration": round(max(timestamps) - min(timestamps), 3),
        "ike_analysis": ike,
        "esp_analysis": esp,
        "ah_analysis": ah,
        "nat_t_analysis": nat,
        "ip_analysis": ip,
        "lifetimes": lifetimes,
        "flow_analysis": {"flow_count": len(esp.get("tunnels", [])), "flows": esp.get("tunnels", [])},
        "timeline": timeline,
        "profile": profile,
        "vpn_profile": _flat_profile(profile, ike, esp, ah),
    }


# ================================================================ IKE

def _analyze_ike(ike_packets: list[dict]) -> dict[str, Any]:
    if not ike_packets:
        return {
            "detected": False,
            "version": None,
            "sessions": [],
            "message": "No IKE messages in the capture. The tunnel may have been negotiated before the "
                       "capture started; algorithms can then only be inferred from ESP.",
        }

    sessions: dict[str, dict[str, Any]] = {}
    for p in sorted(ike_packets, key=lambda x: x["timestamp"]):
        m = p["ike"]
        session = sessions.get(m["init_spi"])
        if session is None:
            if m["major_version"] == 2:
                initiator = p["src_ip"] if m["initiator_flag"] else p["dst_ip"]
            else:
                initiator = p["src_ip"]
            session = sessions[m["init_spi"]] = {
                "init_spi": m["init_spi"],
                "version": m["major_version"],
                "initiator_ip": initiator,
                "responder_ip": p["dst_ip"] if initiator == p["src_ip"] else p["src_ip"],
                "first_seen": p["timestamp"],
                "last_seen": p["timestamp"],
                "messages": [],
            }
        from_initiator = p["src_ip"] == session["initiator_ip"]
        is_response = m["response_flag"] if m["major_version"] == 2 else not from_initiator
        session["last_seen"] = p["timestamp"]
        session["messages"].append({"packet": p, "msg": m, "from_initiator": from_initiator,
                                    "is_response": bool(is_response)})

    summaries = [_summarize_session(s) for s in sessions.values()]
    summaries.sort(key=lambda s: s["first_seen"])
    primary = next((s for s in summaries if s["chosen"]), None) or \
        next((s for s in summaries if s["offered"]), None) or summaries[0]

    versions = sorted({s["version"] for s in summaries})
    all_notifies = _unique_by(n for s in summaries for n in s["notifies"])
    vendor_ids = _unique_by((v for s in summaries for v in s["vendor_ids"]), key="hex")

    return {
        "detected": True,
        "version": f"IKEv{primary['version']}",
        "versions_seen": [f"IKEv{v}" for v in versions],
        "packet_count": len(ike_packets),
        "session_count": len(summaries),
        "exchange_types": sorted({e for s in summaries for e in s["exchanges"]}),
        "exchange_mode": primary["exchange_mode"],
        "primary_session": primary["init_spi"],
        "sessions": [{k: v for k, v in s.items() if k != "_messages"} for s in summaries],
        "offered_proposals": primary["offered"],
        "chosen_suite": primary["chosen"],
        "weak_offers": primary["weak_offers"],
        "downgrade_surface": primary["downgrade_surface"],
        "notifies": all_notifies,
        "negotiation_errors": [n for n in all_notifies if n["type"] < 16384],
        "vendor_ids": vendor_ids,
        "identities": [i for s in summaries for i in s["identities"]],
        "certreq_seen": any(s["certreq"] for s in summaries),
        "cookie_challenge": any(n["type"] == NOTIFY_COOKIE for n in all_notifies),
        "transport_mode_notify": any(n["type"] == NOTIFY_USE_TRANSPORT_MODE for n in all_notifies),
        "signature_hashes": sorted({h for n in all_notifies for h in n.get("hashes", [])}),
        "authentication": _infer_authentication(primary),
        "_sessions": summaries,
    }


def _summarize_session(s: dict[str, Any]) -> dict[str, Any]:
    msgs = s["messages"]
    exchanges = []
    for rec in msgs:
        if rec["msg"]["exchange_type"] not in exchanges:
            exchanges.append(rec["msg"]["exchange_type"])

    if s["version"] == 2:
        mode = "IKEv2"
        sa_exchange = "IKE_SA_INIT"
    else:
        mode = "Aggressive Mode" if "AGGRESSIVE" in exchanges else "Main Mode" if "MAIN_MODE" in exchanges else "IKEv1"
        sa_exchange = "AGGRESSIVE" if "AGGRESSIVE" in exchanges else "MAIN_MODE"

    offered, chosen_offer, ke_group = [], None, None
    for rec in msgs:
        m = rec["msg"]
        if m["exchange_type"] != sa_exchange:
            continue
        if m["proposals"] and not rec["is_response"] and not offered:
            offered = m["proposals"]
        if m["proposals"] and rec["is_response"] and chosen_offer is None:
            chosen_offer = m["proposals"][0]
        if m["ke_dh_group"] and (rec["is_response"] or ke_group is None):
            ke_group = m["ke_dh_group"]

    chosen_source = "responder"
    if chosen_offer is None and len(offered) == 1 and _is_single_choice(offered[0]):
        chosen_offer, chosen_source = offered[0], "single_offer"

    chosen = _normalize_suite(chosen_offer, ke_group, chosen_source) if chosen_offer else None
    if chosen is None and ke_group:
        chosen = {"dh_group": ke_group, "dh_group_name": DH_NAMES.get(ke_group, str(ke_group)),
                  "source": "ke_payload"}

    notifies, vendor_ids, identities, certreq = [], [], [], False
    for rec in msgs:
        m = rec["msg"]
        notifies.extend(m["notifies"])
        vendor_ids.extend(m["vendor_ids"])
        certreq = certreq or bool(m["certreq"])
        for ident in m["identities"]:
            identities.append({**ident, "sender": rec["packet"]["src_ip"], "exchange": m["exchange_type"]})

    return {
        "init_spi": s["init_spi"],
        "version": s["version"],
        "initiator_ip": s["initiator_ip"],
        "responder_ip": s["responder_ip"],
        "first_seen": s["first_seen"],
        "last_seen": s["last_seen"],
        "message_count": len(msgs),
        "exchanges": exchanges,
        "exchange_mode": mode,
        "starts_with_negotiation": msgs[0]["msg"]["exchange_type"] in ("IKE_SA_INIT", "MAIN_MODE", "AGGRESSIVE"),
        "offered": offered,
        "chosen": chosen,
        "weak_offers": _weak_offers(offered, chosen),
        "downgrade_surface": _downgrade_surface(_weak_offers(offered, chosen), chosen),
        "notifies": _unique_by(notifies),
        "vendor_ids": _unique_by(vendor_ids, key="hex"),
        "identities": identities,
        "certreq": certreq,
        "message_sizes": _message_sizes(msgs),
        "_messages": msgs,
    }


def _is_single_choice(offer: dict) -> bool:
    return all(len(offer[k]) <= 1 for k in ("encryption", "integrity", "prf", "dh_groups"))


def _normalize_suite(offer: dict, ke_group: int | None, source: str) -> dict[str, Any]:
    enc_ids = offer.get("encryption_ids") or []
    aead = bool(enc_ids) and enc_ids[0] in AEAD_ENCR_IDS
    integrity = next((i for i in offer["integrity"] if i != "NONE"), None)
    group = ke_group or (offer["dh_groups"][0] if offer["dh_groups"] else None)
    encryption = offer["encryption"][0] if offer["encryption"] else None
    return {
        "encryption": encryption,
        "key_length": _key_length(encryption),
        "aead": aead,
        "integrity": integrity or ("None (AEAD)" if aead else None),
        "prf": offer["prf"][0] if offer["prf"] else None,
        "dh_group": group,
        "dh_group_name": DH_NAMES.get(group, str(group)) if group else None,
        "auth_method": offer.get("auth_method"),
        "auth_method_id": offer.get("auth_method_id"),
        "life_seconds": offer.get("life_seconds"),
        "life_kilobytes": offer.get("life_kilobytes"),
        "source": source,
    }


def _key_length(encryption: str | None) -> int | None:
    if not encryption:
        return None
    if encryption.startswith("ChaCha20"):
        return 256
    if encryption.startswith("3DES"):
        return 168
    if encryption.startswith("DES"):
        return 56
    for part in encryption.split("-"):
        if part in ("128", "192", "256"):
            return int(part)
    return None


def _weak_offers(offered: list[dict], chosen: dict | None) -> list[str]:
    weak = []
    for offer in offered:
        for enc in offer["encryption"]:
            if any(marker in enc for marker in WEAK_ENCRYPTION_MARKERS):
                weak.append(enc)
        for alg in offer["integrity"] + offer["prf"]:
            if any(marker in alg for marker in WEAK_HASH_MARKERS):
                weak.append(alg)
        for group in offer["dh_groups"]:
            if group in WEAK_DH_GROUPS:
                weak.append(DH_NAMES.get(group, f"group {group}"))
    return sorted(set(weak))


def _downgrade_surface(weak: list[str], chosen: dict | None) -> list[str]:
    """Weak algorithms the initiator offered that were *not* selected — what an active attacker could force."""
    chosen = chosen or {}
    selected = {chosen.get("encryption"), chosen.get("integrity"), chosen.get("prf"), chosen.get("dh_group_name")}
    return [w for w in weak if w not in selected]


def _message_sizes(msgs: list[dict]) -> list[dict[str, Any]]:
    """Total size per logical message: IKEv2 fragments (SKF) with the same Message ID are summed."""
    sizes: dict[tuple, dict[str, Any]] = {}
    for rec in msgs:
        m = rec["msg"]
        key = (m["exchange_type"], m["message_id"], rec["is_response"])
        entry = sizes.setdefault(key, {
            "exchange": m["exchange_type"], "message_id": m["message_id"],
            "is_response": rec["is_response"], "from_initiator": rec["from_initiator"],
            "timestamp": rec["packet"]["timestamp"], "length": 0, "fragments": set(),
            "cleartext_ke": "KE" in m["payload_types"], "encrypted": m["encrypted_len"] > 0,
            "payloads": list(m["payload_types"]), "frames": [],
        })
        if len(entry["frames"]) < 8:
            entry["frames"].append(rec["packet"]["index"])
        frag = m.get("fragment")
        if frag:
            if frag["number"] not in entry["fragments"]:
                entry["fragments"].add(frag["number"])
                entry["length"] += m["length"]
        else:
            entry["length"] = max(entry["length"], m["length"])  # retransmissions repeat the same size
    result = []
    for entry in sorted(sizes.values(), key=lambda e: e["timestamp"]):
        entry["fragments"] = len(entry["fragments"])
        result.append(entry)
    return result


def _infer_authentication(session: dict[str, Any]) -> dict[str, Any]:
    chosen = session.get("chosen") or {}
    if session["version"] == 1:
        if chosen.get("auth_method"):
            return evidence(chosen["auth_method"], OBSERVED, 1.0,
                            "IKEv1 Authentication Method attribute in the cleartext SA payload",
                            "IKEv1 SA attribute", psk=chosen.get("auth_method_id") in (1, 65001, 65002))
        return not_observable("IKEv1 SA payload with the authentication attribute was not captured")

    auth = [m for m in session["message_sizes"] if m["exchange"] == "IKE_AUTH"]
    requests = [m for m in auth if not m["is_response"]]
    if not requests:
        return not_observable("No IKE_AUTH exchange in capture — authentication happens inside it (encrypted)")

    rounds = len(requests)
    largest = max(m["length"] for m in auth[:2])
    certreq = session["certreq"]
    detail = (f"{rounds} IKE_AUTH round trip(s); first exchange up to {largest} B"
              f"{'; CERTREQ sent in IKE_SA_INIT' if certreq else ''}")
    method = "IKE_AUTH size / round-trip analysis"
    if rounds >= 3:
        return evidence("EAP (with server certificate)", INFERRED, 0.75,
                        f"{detail} — EAP needs several IKE_AUTH round trips", method)
    if largest >= AUTH_SIZE_CERT_RSA:
        return evidence("Certificate (RSA)", INFERRED, 0.85 if certreq else 0.8,
                        f"{detail} — large enough to carry an X.509 RSA certificate", method)
    if largest >= AUTH_SIZE_CERT_ECDSA:
        return evidence("Certificate (likely ECDSA)", INFERRED, 0.65 if certreq else 0.55,
                        f"{detail} — fits a compact ECDSA certificate", method)
    return evidence("Pre-Shared Key", INFERRED, 0.6 if certreq else 0.7,
                    f"{detail} — too small for a certificate chain", method, psk=True)


# ================================================================ ESP / AH

def _analyze_esp(esp_packets: list[dict], ike_integrity: str | None = None) -> dict[str, Any]:
    if not esp_packets:
        return {"detected": False, "packet_count": 0, "sa_info": [], "tunnels": []}

    sas = sorted(group_security_associations(esp_packets).values(), key=lambda s: s["first_seen"])
    sa_info, lengths_by_sa = [], {}
    for sa in sas:
        pk = sa["packets"]
        lengths = [p["esp_payload_len"] for p in pk if p.get("esp_payload_len")]
        lengths_by_sa[sa["key"]] = lengths
        seqs = [p.get("seq_num", 0) for p in pk]
        replay = _replay_analysis(seqs, [p.get("index") for p in pk], [p["timestamp"] for p in pk])
        sa_info.append({
            "spi": sa["spi"],
            "src": sa["src"],
            "dst": sa["dst"],
            "packet_count": len(pk),
            "bytes": sum(lengths),
            "first_seen": sa["first_seen"],
            "last_seen": sa["last_seen"],
            "duration": round(sa["last_seen"] - sa["first_seen"], 3),
            "nat_t": any(p.get("nat_t") for p in pk),
            "min_seq": min(seqs),
            "max_seq": max(seqs),
            "avg_payload_size": round(sum(lengths) / len(lengths), 1) if lengths else 0,
            "min_payload_size": min(lengths) if lengths else 0,
            "max_payload_size": max(lengths) if lengths else 0,
            "fingerprint": fingerprint_esp(lengths),
            "first_frame": pk[0].get("index"),
            "replay": replay,
            "null_encryption": detect_null_encryption(
                [(p.get("esp_payload_len", 0), p.get("esp_head", "")) for p in pk[:60]]),
            "_key": sa["key"],
        })

    fingerprint = _pooled_fingerprint(sa_info, lengths_by_sa)
    all_lengths = [length for lengths in lengths_by_sa.values() for length in lengths]
    tunnels = [{
        "id": t["id"], "peer_a": t["peer_a"], "peer_b": t["peer_b"],
        "spi_a": t["spi_a"], "spi_b": t["spi_b"], "bidirectional": t["bidirectional"],
        "packet_count": len(t["packets"]),
        "bytes": sum(p.get("esp_payload_len", 0) for p in t["packets"]),
        "first_seen": t["first_seen"], "last_seen": t["last_seen"],
        "duration_seconds": round(t["last_seen"] - t["first_seen"], 3),
    } for t in build_tunnels(esp_packets)]

    null_hits = [sa for sa in sa_info if sa["null_encryption"]["suspected"]]
    for sa in sa_info:
        sa.pop("_key")

    return {
        "detected": True,
        "packet_count": len(esp_packets),
        "unique_spis": len({sa["spi"] for sa in sa_info}),
        "sa_count": len(sa_info),
        "sa_info": sa_info,
        "fingerprint": fingerprint,
        "mode_inference": infer_mode(all_lengths, fingerprint, icv_from_integrity(ike_integrity)),
        "null_encryption": null_hits[0]["null_encryption"] if null_hits else
        {"suspected": False, "confidence": 0.0, "evidence": "No SA carries cleartext inner headers"},
        "replay_summary": _replay_summary(sa_info),
        "tunnels": tunnels,
    }


def _pooled_fingerprint(sa_info: list[dict], lengths_by_sa: dict[str, list[int]]) -> dict[str, Any]:
    """Pool lengths across SAs that agree on the cipher family (more distinct lengths → more confidence)."""
    identified = [sa for sa in sa_info if sa["fingerprint"]["status"] == "identified"]
    if identified:
        weight = Counter()
        for sa in identified:
            weight[sa["fingerprint"]["suite"]] += sa["packet_count"]
        suite = weight.most_common(1)[0][0]
        members = [sa for sa in identified if sa["fingerprint"]["suite"] == suite]
        pooled = fingerprint_esp([x for sa in members for x in lengths_by_sa[sa["_key"]]])
        if pooled["suite"] != suite:  # pooling must not change the answer; fall back to the best single SA
            pooled = max(members, key=lambda sa: sa["fingerprint"]["confidence"])["fingerprint"]
        pooled["sa_agreement"] = f"{len(members)}/{len(sa_info)} SAs"
        if len(weight) > 1:
            pooled["mixed_suites"] = sorted(weight)
        return pooled
    return fingerprint_esp([x for lengths in lengths_by_sa.values() for x in lengths])


def _replay_analysis(seqs: list[int], frames: list | None = None, times: list | None = None) -> dict[str, Any]:
    """Sender-side anti-replay indicators, in capture order (RFC 4303 §3.4.3).

    Each anomaly is recorded with its frame number, time and the sequence numbers around it, so the
    analyst can see the evidence (e.g. 101 → 102 → 103 → 102 ← replay)."""
    frames = frames or [None] * len(seqs)
    times = times or [None] * len(seqs)
    seen: set[int] = set()
    duplicates = resets = late = beyond_window = 0
    max_depth = 0
    max_seen: int | None = None
    events: list[dict[str, Any]] = []

    def note(i: int, kind: str) -> None:
        if len(events) < 40:
            events.append({"i": i, "kind": kind, "seq": seqs[i], "frame": frames[i], "time": times[i],
                           "expected_above": max_seen, "context": seqs[max(0, i - 4):i + 3],
                           "context_start": max(0, i - 4)})

    for i, seq in enumerate(seqs):
        # a reset restarts the counter and counts up again; an injected replay is an isolated old number.
        # With a short-lived counter the restart re-uses already-seen numbers, so require a whole run of them.
        restart = max_seen is not None and seq <= 16 and _counts_up(seqs, i) and (
            max_seen - seq > REPLAY_WINDOW * 4 or (max_seen - seq > 8 and all(x in seen for x in seqs[i:i + 6])))
        if restart:
            resets += 1              # counter restarted without a new SPI
            note(i, "reset")
            seen = {seq}
            max_seen = seq
            continue
        if seq in seen:
            duplicates += 1
            note(i, "duplicate")
            continue
        if max_seen is not None and seq < max_seen:
            depth = max_seen - seq
            late += 1
            max_depth = max(max_depth, depth)
            if depth >= REPLAY_WINDOW:
                beyond_window += 1
                note(i, "beyond_window")
        seen.add(seq)
        max_seen = seq if max_seen is None else max(max_seen, seq)

    unique = len(set(seqs))
    span = (max(seqs) - min(seqs) + 1) if seqs else 0
    step = max(1, len(seqs) // 240)
    marked = {e["i"] for e in events}
    trace_idx = sorted(set(range(0, len(seqs), step)) | marked | ({len(seqs) - 1} if seqs else set()))
    return {
        "duplicates": duplicates,
        "counter_resets": resets,
        "reordered": late,
        "max_reorder_depth": max_depth,
        "beyond_default_window": beyond_window,
        "missing": max(0, span - unique) if resets == 0 else None,
        "near_exhaustion": bool(seqs) and max(seqs) >= SEQ_EXHAUSTION,
        "events": events,
        "trace": [[i, seqs[i], times[i]] for i in trace_idx],
    }


def _counts_up(seqs: list[int], i: int, lookahead: int = 3) -> bool:
    """A reset is followed by a new ascending run (a replayed old packet is not)."""
    following = seqs[i + 1:i + 1 + lookahead]
    return len(following) == lookahead and all(0 < b - a <= 4 for a, b in zip([seqs[i]] + following, following))


def _replay_summary(sa_info: list[dict]) -> dict[str, Any]:
    keys = ("duplicates", "counter_resets", "reordered", "beyond_default_window")
    total = {k: sum(sa["replay"][k] for sa in sa_info) for k in keys}
    total["missing"] = sum(sa["replay"]["missing"] or 0 for sa in sa_info)
    total["max_reorder_depth"] = max((sa["replay"]["max_reorder_depth"] for sa in sa_info), default=0)
    total["near_exhaustion"] = any(sa["replay"]["near_exhaustion"] for sa in sa_info)
    return total


def _analyze_ah(ah_packets: list[dict]) -> dict[str, Any]:
    if not ah_packets:
        return {"detected": False, "packet_count": 0}

    groups: dict[str, list[dict]] = defaultdict(list)
    for p in ah_packets:
        groups[f"{p['spi']}|{p['src_ip']}>{p['dst_ip']}"].append(p)

    sa_info = []
    for pk in groups.values():
        icv = Counter(p.get("ah_icv_len", 0) for p in pk).most_common(1)[0][0]
        next_headers = Counter(p.get("ah_next_header") for p in pk)
        tunnel = any(nh in (4, 41) for nh in next_headers)
        sa_info.append({
            "spi": pk[0]["spi"], "src": pk[0]["src_ip"], "dst": pk[0]["dst_ip"],
            "first_seen": pk[0]["timestamp"], "packet_count": len(pk), "icv_len": icv,
            "integrity": AH_INTEGRITY_BY_ICV.get(icv, f"{icv}-byte ICV"),
            "mode": "Tunnel" if tunnel else "Transport",
            "inner_protocols": sorted(IP_PROTOCOL_NAMES.get(nh, str(nh)) for nh in next_headers),
            "replay": _replay_analysis([p.get("seq_num", 0) for p in pk]),
        })

    main = max(sa_info, key=lambda s: s["packet_count"])
    return {
        "detected": True,
        "packet_count": len(ah_packets),
        "unique_spis": len({s["spi"] for s in sa_info}),
        "sa_info": sa_info,
        "mode": main["mode"],
        "icv_len": main["icv_len"],
        "integrity": main["integrity"],
        "inner_protocols": main["inner_protocols"],
        "note": "AH authenticates but does not encrypt; its Next Header field is cleartext",
    }


# ================================================================ PFS / lifetime

def _infer_pfs(ike: dict[str, Any], esp: dict[str, Any], ip_version: str = "IPv4") -> dict[str, Any]:
    """
    PFS means each Child SA negotiation runs a fresh Diffie-Hellman exchange. In IKEv2 that KE payload
    sits inside the encrypted CREATE_CHILD_SA (IKEv1: inside Quick Mode), so we compare each
    message's size with the size it would have without a KE payload for the negotiated group.
    """
    if not ike.get("detected"):
        return not_observable("No IKE traffic in capture")
    sessions = ike["_sessions"]
    primary = next(s for s in sessions if s["init_spi"] == ike["primary_session"])
    group = (primary.get("chosen") or {}).get("dh_group")
    ke_len = DH_KE_LENGTH.get(group) if group else None
    version = primary["version"]
    exchange = "CREATE_CHILD_SA" if version == 2 else "QUICK_MODE"
    ke_overhead = (ke_len or 32) + (8 if version == 2 else 4)
    selectors = IPV6_SELECTOR_EXTRA if (version == 2 and ip_version == "IPv6") else 0

    new_esp_times = sorted(sa["first_seen"] for sa in esp.get("sa_info", []))
    decisions = []
    for session in sessions:
        if session["version"] != version:
            continue
        for request, response in _negotiations(session, exchange, version):
            msg = response or request
            role = "response" if response else "request"
            if request["cleartext_ke"] or not request["encrypted"]:
                decisions.append({"timestamp": request["timestamp"], "message_id": request["message_id"],
                                  "length": msg["length"], "pfs": request["cleartext_ke"],
                                  "source": OBSERVED, "confidence": 1.0, "kind": "child_sa"})
                continue
            if version == 2 and _is_ike_rekey(request["timestamp"], session, sessions):
                decisions.append({"timestamp": request["timestamp"], "message_id": request["message_id"],
                                  "length": msg["length"], "kind": "ike_rekey", "pfs": None})
                continue
            baseline = REKEY_BASELINE[version][role] + selectors
            threshold = baseline + ke_overhead / 2
            confirmed = any(0 <= t - request["timestamp"] <= 10 for t in new_esp_times)
            separation = 0.8 if ke_overhead >= 72 else 0.6 if ke_overhead >= 40 else 0.5
            if ke_len is None:
                separation = min(separation, 0.5)
            if role == "request":
                separation *= 0.85
            decisions.append({
                "timestamp": request["timestamp"], "message_id": request["message_id"],
                "length": msg["length"], "measured": role, "baseline": baseline, "threshold": round(threshold),
                "pfs": msg["length"] >= threshold, "source": INFERRED, "kind": "child_sa",
                "confidence": round(separation * (1.0 if confirmed else 0.9), 3),
                "new_esp_sa_followed": confirmed,
            })

    child = [d for d in decisions if d["kind"] == "child_sa"]
    if not child:
        why = ("no CREATE_CHILD_SA (Child SA rekey) in capture — the first Child SA of an IKEv2 SA never "
               "runs its own DH exchange, so capture at least one rekey interval" if version == 2 else
               "no Quick Mode exchange in capture")
        result = not_observable(f"PFS not observable: {why}", "Encrypted rekey size analysis")
        result["exchanges"] = decisions
        return result

    votes = Counter(d["pfs"] for d in child)
    value = votes.most_common(1)[0][0]
    agreeing = [d for d in child if d["pfs"] == value]
    source = OBSERVED if all(d["source"] == OBSERVED for d in agreeing) else INFERRED
    confidence = statistics.mean(d["confidence"] for d in agreeing) * (len(agreeing) / len(child))
    if source == OBSERVED:
        text = f"{len(child)} {exchange} message(s) with cleartext payloads: KE payload {'present' if value else 'absent'}"
    else:
        group_text = f"{DH_NAMES.get(group, group)} KE = {ke_len} B" if ke_len else "DH group unknown (assumed 32 B KE)"
        sizes = ", ".join(f"{d['length']} B ({d['measured']})" for d in child[:4])
        first = child[0]
        text = (f"{len(child)} {exchange} negotiation(s): {sizes}; without a KE payload ≈{first['baseline']} B "
                f"expected, with {group_text} ≈{first['baseline'] + ke_overhead} B (threshold {first['threshold']} B)")
    return evidence(value, source, confidence, text, "Encrypted rekey size analysis", exchanges=decisions)


def _negotiations(session: dict, exchange: str, version: int) -> list[tuple[dict, dict | None]]:
    """(request, response) pairs per Message ID. IKEv1 Quick Mode may be started by either peer."""
    by_id: dict[int, list[dict]] = defaultdict(list)
    for m in session["message_sizes"]:
        if m["exchange"] == exchange:
            by_id[m["message_id"]].append(m)
    pairs = []
    for msgs in by_id.values():
        msgs.sort(key=lambda m: m["timestamp"])
        if version == 2:
            request = next((m for m in msgs if not m["is_response"]), None)
            response = next((m for m in msgs if m["is_response"]), None)
        else:
            request, response = msgs[0], (msgs[1] if len(msgs) > 1 else None)
        if request:
            pairs.append((request, response))
    return sorted(pairs, key=lambda p: p[0]["timestamp"])


def _is_ike_rekey(ts: float, session: dict, sessions: list[dict]) -> bool:
    """An IKEv2 IKE SA rekey is followed by traffic on a new IKE SPI pair without a new IKE_SA_INIT."""
    peers = {session["initiator_ip"], session["responder_ip"]}
    return any(
        other is not session and not other["starts_with_negotiation"]
        and {other["initiator_ip"], other["responder_ip"]} == peers
        and 0 <= other["first_seen"] - ts <= 10
        for other in sessions
    )


def _infer_lifetimes(ike: dict[str, Any], esp: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    chosen = ike.get("chosen_suite") or {}
    if chosen.get("life_seconds"):
        secs = chosen["life_seconds"]
        result["ike"] = evidence(secs, OBSERVED, 1.0,
                                 f"IKEv1 Life Duration attribute = {secs} s ({_hours(secs)})",
                                 "IKEv1 SA attribute", display=f"{secs} s ({_hours(secs)})")
    elif ike.get("detected"):
        rekeys = sorted(s["first_seen"] for s in ike["_sessions"] if not s["starts_with_negotiation"])
        starts = sorted(s["first_seen"] for s in ike["_sessions"] if s["starts_with_negotiation"])
        if rekeys and starts:
            interval = rekeys[0] - starts[0]
            result["ike"] = evidence(round(interval), INFERRED, 0.7,
                                     f"First IKE SA rekey observed {interval:.0f} s after negotiation",
                                     "IKE SPI succession", display=f"≈{interval:.0f} s ({_hours(interval)})")
        else:
            span = max((s["last_seen"] for s in ike["_sessions"]), default=0) - min(
                (s["first_seen"] for s in ike["_sessions"]), default=0)
            result["ike"] = not_observable(
                f"IKEv2 lifetimes are local policy (not negotiated); no IKE rekey within the {span:.0f} s of IKE "
                "traffic captured", "IKE SPI succession")
    else:
        result["ike"] = not_observable("No IKE traffic")

    by_direction: dict[tuple, list[dict]] = defaultdict(list)
    for sa in esp.get("sa_info", []):
        by_direction[(sa["src"], sa["dst"])].append(sa)
    intervals = []
    for sas in by_direction.values():
        starts = sorted(sa["first_seen"] for sa in sas)
        intervals.extend(b - a for a, b in zip(starts, starts[1:]) if b - a > 1)
    if intervals:
        median = statistics.median(intervals)
        result["child"] = evidence(round(median), INFERRED, 0.75 if len(intervals) > 1 else 0.6,
                                   f"{len(intervals)} ESP SPI rollover(s); median interval {median:.0f} s",
                                   "ESP SPI succession", display=f"≈{median:.0f} s ({_hours(median)})",
                                   seconds=median)
    elif esp.get("detected"):
        longest = max(sa["duration"] for sa in esp["sa_info"])
        result["child"] = not_observable(
            f"No ESP SPI rollover within capture; SAs lived ≥ {longest:.0f} s", "ESP SPI succession")
        result["child"]["lower_bound_seconds"] = longest
    else:
        result["child"] = not_observable("No ESP traffic")
    return result


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:.1f} h" if seconds >= 3600 else f"{seconds / 60:.0f} min"


# ================================================================ NAT-T / IP

def _analyze_nat_t(packets: list[dict], ike_packets: list[dict]) -> dict[str, Any]:
    nat_t_ike = sum(1 for p in packets if p.get("protocol_type") == "ike_natt")
    nat_t_esp = sum(1 for p in packets if p.get("protocol_type") == "esp" and p.get("nat_t"))
    keepalives = sum(1 for p in packets if p.get("protocol_type") == "natt_keepalive")
    nat_detection = any(p["ike"].get("nat_detection") for p in ike_packets)
    detected = bool(nat_t_ike or nat_t_esp or keepalives)
    return {
        "detected": detected,
        "nat_t_ike_packets": nat_t_ike,
        "nat_t_esp_packets": nat_t_esp,
        "keepalives": keepalives,
        "nat_detection_payloads": nat_detection,
        "encapsulation": "UDP 4500 (RFC 3948)" if detected else "None observed",
    }


def _analyze_ip_versions(packets: list[dict]) -> dict[str, Any]:
    ipsec = [p for p in packets if p.get("protocol_type") in ("ike", "ike_natt", "esp", "ah")]
    v4 = sum(1 for p in ipsec if p.get("ip_version") == 4)
    v6 = sum(1 for p in ipsec if p.get("ip_version") == 6)
    pairs = sorted({(p["src_ip"], p["dst_ip"]) for p in ipsec if p.get("src_ip")})
    primary = "Dual-stack" if v4 and v6 else "IPv6" if v6 else "IPv4" if v4 else "Unknown"
    return {
        "ipv4_packets": sum(1 for p in packets if p.get("ip_version") == 4),
        "ipv6_packets": sum(1 for p in packets if p.get("ip_version") == 6),
        "ipsec_ipv4_packets": v4,
        "ipsec_ipv6_packets": v6,
        "primary_version": primary,
        "dual_stack": bool(v4 and v6),
        "unique_ip_pairs": [{"src": s, "dst": d} for s, d in pairs[:50]],
        "unique_ip_pair_count": len(pairs),
    }


# ================================================================ profile

def _build_profile(ike, esp, ah, nat, ip, lifetimes) -> dict[str, dict[str, Any]]:
    profile: dict[str, dict[str, Any]] = {}
    chosen = ike.get("chosen_suite") or {}
    fp = esp.get("fingerprint") or {}

    protocols = [name for name, present in (("ESP", esp.get("detected")), ("AH", ah.get("detected"))) if present]
    profile["ipsec_protocols"] = evidence(" + ".join(protocols), OBSERVED, 1.0,
                                          f"ESP packets: {esp.get('packet_count', 0)}, AH packets: {ah.get('packet_count', 0)}",
                                          "IP protocol 50/51, ESP-in-UDP") if protocols else \
        not_observable("No ESP or AH packets in capture")

    if ike.get("detected"):
        profile["ike_version"] = evidence(ike["version"], OBSERVED, 1.0,
                                          f"{ike['packet_count']} IKE messages in {ike['session_count']} IKE SA(s)",
                                          "IKE header major version")
        profile["exchange_mode"] = evidence(ike["exchange_mode"], OBSERVED, 1.0,
                                            f"Exchanges: {', '.join(ike['exchange_types'])}", "IKE exchange type")
    else:
        profile["ike_version"] = not_observable(ike.get("message", "No IKE traffic"))
        profile["exchange_mode"] = not_observable("No IKE traffic")

    profile["mode"] = _mode_evidence(ike, esp, ah)

    suite_source = OBSERVED
    suite_conf = 1.0 if chosen.get("source") == "responder" else 0.9
    suite_text = ("Responder's selected proposal in cleartext " +
                  ("IKE_SA_INIT" if ike.get("version") == "IKEv2" else "Main/Aggressive Mode SA payload"))
    if chosen.get("source") == "single_offer":
        suite_text = "Initiator offered a single suite (responder reply not captured)"
    for field, key, label in (("ike_encryption", "encryption", "encryption"),
                              ("ike_integrity", "integrity", "integrity"),
                              ("ike_prf", "prf", "PRF")):
        if chosen.get(key):
            profile[field] = evidence(chosen[key], suite_source, suite_conf, suite_text, "IKE SA proposal")
        else:
            profile[field] = not_observable(f"IKE SA {label} not visible (no SA payload captured)")

    if chosen.get("dh_group"):
        group = chosen["dh_group"]
        how = "KE payload group" if chosen.get("source") == "ke_payload" else "IKE SA proposal + KE payload"
        profile["key_exchange"] = evidence(f"{chosen['dh_group_name']} (group {group})", OBSERVED, suite_conf,
                                           f"Diffie-Hellman group {group} in cleartext {how}", how,
                                           group=group)
    else:
        profile["key_exchange"] = not_observable("No IKE SA negotiation captured")

    profile["esp_encryption"], profile["esp_integrity"] = _esp_crypto_evidence(esp, ah, fp, chosen)
    profile["authentication_method"] = ike.get("authentication") or not_observable("No IKE traffic")
    profile["pfs"] = ike.get("pfs") or not_observable("No IKE traffic")
    profile["ike_lifetime"] = lifetimes["ike"]
    profile["child_sa_lifetime"] = lifetimes["child"]
    profile["replay_protection"] = _replay_evidence(esp, ah)
    profile["nat_traversal"] = evidence(nat["detected"], OBSERVED, 1.0,
                                        f"IKE on 4500: {nat['nat_t_ike_packets']}, ESP-in-UDP: {nat['nat_t_esp_packets']}, "
                                        f"keepalives: {nat['keepalives']}", "UDP 4500 encapsulation")
    profile["ip_version"] = evidence(ip["primary_version"], OBSERVED, 1.0,
                                     f"IPsec packets over IPv4: {ip['ipsec_ipv4_packets']}, IPv6: {ip['ipsec_ipv6_packets']}",
                                     "Outer IP header") if ip["primary_version"] != "Unknown" else \
        not_observable("No IPsec packets")

    products = [v["name"] for v in ike.get("vendor_ids", []) if v.get("reveals_implementation")]
    if products:
        profile["implementation"] = evidence(", ".join(products), OBSERVED, 0.95,
                                             "Vendor ID payload(s) in cleartext IKE messages", "Vendor ID")
    else:
        profile["implementation"] = not_observable("No product-identifying Vendor ID payloads")
    return profile


def _mode_evidence(ike, esp, ah) -> dict[str, Any]:
    if ah.get("detected"):
        return evidence(ah["mode"], OBSERVED, 1.0,
                        f"AH Next Header carries {', '.join(ah['inner_protocols'])} in cleartext",
                        "AH Next Header")
    if ike.get("transport_mode_notify"):
        return evidence("Transport", OBSERVED, 1.0, "USE_TRANSPORT_MODE notify seen in cleartext", "IKE Notify")
    inference = esp.get("mode_inference")
    if inference and inference.get("value"):
        return evidence(inference["value"], INFERRED, inference["confidence"], inference["evidence"],
                        "Smallest inner packet bound")
    if inference:
        return not_observable(f"Mode is negotiated inside encrypted IKE_AUTH; {inference['evidence']}",
                              "Smallest inner packet bound")
    return not_observable("Mode is negotiated inside encrypted IKE_AUTH and no ESP traffic to infer from")


def _esp_crypto_evidence(esp, ah, fp, chosen) -> tuple[dict, dict]:
    method = "ESP length fingerprint"
    if not esp.get("detected"):
        if ah.get("detected"):
            enc = evidence("None (AH provides no encryption)", OBSERVED, 1.0, "Only AH is used", "IP protocol 51")
            integ = evidence(ah["integrity"], INFERRED, 0.85,
                             f"AH ICV length {ah['icv_len']} B", "AH ICV length")
            return enc, integ
        return not_observable("No ESP traffic"), not_observable("No ESP traffic")

    null = esp.get("null_encryption") or {}
    if null.get("suspected"):
        enc = evidence("NULL (no encryption)", INFERRED, null["confidence"], null["evidence"], "Cleartext header detection")
        return enc, not_observable("Integrity algorithm not determinable for ESP-NULL from lengths")

    if fp.get("status") != "identified":
        text = fp.get("evidence", "ESP length fingerprint inconclusive")
        return not_observable(text, method), not_observable(text, method)

    hint = ""
    ike_enc = chosen.get("encryption") or ""
    family = fp["family"]
    consistent = (family.startswith("AES-GCM") and "GCM" in ike_enc) or \
                 (family == "AES-CBC" and "AES" in ike_enc and "CBC" in ike_enc) or \
                 (family == "3DES-CBC" and "3DES" in ike_enc)
    if ike_enc:
        hint = (f"; consistent with the IKE SA suite ({ike_enc})" if consistent
                else f"; differs from the IKE SA suite ({ike_enc})")
    enc = evidence(family, INFERRED, fp["confidence"],
                   f"{fp['evidence']}. Key length is not observable from ESP framing{hint}", method,
                   ike_suite_consistent=consistent if ike_enc else None)

    if fp["block_size"] == 4:
        integ = evidence("Integrated (AEAD)", INFERRED, fp["confidence"],
                         "AEAD suites authenticate with their own tag; no separate HMAC", method)
    else:
        integ_value = fp["integrity"]
        ike_integ = chosen.get("integrity") or ""
        alternatives = fp.get("integrity_alternatives") or []
        match = next((a for a in [integ_value] + alternatives
                      if ike_integ and _hash_family(a) == _hash_family(ike_integ)), None)
        if match and match != integ_value:
            integ_value = match
        integ = evidence(integ_value, INFERRED, fp["confidence"] * (0.9 if alternatives else 1.0),
                         f"ICV length {fp['icv_len_candidates']} B from length residue"
                         + (f"; alternatives: {', '.join(alternatives)}" if alternatives else ""),
                         method, alternatives=alternatives)
    return enc, integ


def _hash_family(name: str) -> str:
    for token in ("SHA2-512", "SHA2-384", "SHA2-256", "SHA1", "MD5", "XCBC", "CMAC"):
        if token in name:
            return token
    return name


def _replay_evidence(esp, ah) -> dict[str, Any]:
    if not esp.get("detected") and not ah.get("detected"):
        return not_observable("No ESP/AH traffic")
    summary = esp.get("replay_summary") if esp.get("detected") else {
        "duplicates": sum(s["replay"]["duplicates"] for s in ah["sa_info"]),
        "counter_resets": sum(s["replay"]["counter_resets"] for s in ah["sa_info"]),
        "beyond_default_window": 0, "near_exhaustion": False,
    }
    issues = []
    if summary["duplicates"]:
        issues.append(f"{summary['duplicates']} duplicate sequence numbers")
    if summary["counter_resets"]:
        issues.append(f"{summary['counter_resets']} counter reset(s) without rekey")
    if summary.get("beyond_default_window"):
        issues.append(f"{summary['beyond_default_window']} packets reordered beyond a 64-packet window")
    if summary.get("near_exhaustion"):
        issues.append("sequence number near 2^32 exhaustion")
    method = "Sequence number analysis"
    if issues:
        return evidence("Anomalies detected", INFERRED, 0.8, "; ".join(issues), method, summary=summary)
    return evidence("Consistent", INFERRED, 0.7,
                    "Monotonic per-SA sequence numbers, no duplicates or counter resets "
                    "(receiver-side window enforcement is not observable)", method, summary=summary)


def _flat_profile(profile, ike, esp, ah) -> dict[str, Any]:
    flat = {key: record["value"] for key, record in profile.items()}
    chosen = ike.get("chosen_suite") or {}
    flat.update({
        "dh_group_number": chosen.get("dh_group"),
        "ike_key_length": chosen.get("key_length"),
        "total_sas": esp.get("sa_count", 0) + len(ah.get("sa_info", [])),
        "tunnel_count": len(esp.get("tunnels", [])),
    })
    return flat


# ================================================================ timeline

def _build_timeline(ike, esp, ah) -> list[dict[str, Any]]:
    events = []
    for session in ike.get("_sessions", []):
        for rec in session["_messages"]:
            p, m = rec["packet"], rec["msg"]
            label = m["exchange_type"] + (" response" if rec["is_response"] else " request")
            if m["encrypted_len"]:
                label += f" [encrypted {m['length']} B]"
            events.append({"timestamp": p["timestamp"], "type": "IKE", "description": label,
                           "src": p["src_ip"], "dst": p["dst_ip"]})
    for sa in esp.get("sa_info", []):
        events.append({"timestamp": sa["first_seen"], "type": "ESP",
                       "description": f"New ESP SA {sa['spi']} ({sa['packet_count']} packets)",
                       "src": sa["src"], "dst": sa["dst"]})
    for sa in ah.get("sa_info", []):
        events.append({"timestamp": sa["first_seen"], "type": "AH", "description": f"AH SA {sa['spi']} ({sa['mode']} mode)",
                       "src": sa["src"], "dst": sa["dst"]})
    events.sort(key=lambda e: e["timestamp"])
    return events[:200]


def _unique_by(items, key: str = "type") -> list[dict]:
    seen, out = set(), []
    for item in items:
        if item[key] not in seen:
            seen.add(item[key])
            out.append(item)
    return out
