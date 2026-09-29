"""
Evidence checklists and configuration novelty.

evidence_checks: for each identified property, the individual observations that support it (✓), the ones
that argue against it (✗) and what limits certainty (⚠), so a confidence number is never shown alone.

configuration_novelty: signals that a configuration is unusual or unlike anything in the testbed
catalogue the analyzer was built and evaluated on.
"""
from __future__ import annotations

from typing import Any

from backend.analyzers.ike_constants import DH_NAMES
from backend.intel.chains import primary_session
from backend.testbed.esp_model import ESP_SUITES, IKE_SUITES


def _c(ok: bool | None, text: str) -> dict[str, Any]:
    return {"ok": ok, "text": text}


def _frames(msgs: list[dict]) -> str:
    frames = sorted({f for m in msgs for f in (m.get("frames") or [])})[:6]
    return f" (frames {', '.join(f'#{f}' for f in frames)})" if frames else ""


def evidence_checks(analysis: dict[str, Any], traffic: dict[str, Any], predictions: list[dict]) -> dict[str, Any]:
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    profile = analysis.get("profile") or {}
    session = primary_session(analysis) or {}
    msgs = session.get("message_sizes") or []
    by_ex: dict[str, list[dict]] = {}
    for m in msgs:
        by_ex.setdefault(m["exchange"], []).append(m)
    out: dict[str, dict[str, list]] = {}

    def put(field: str, checks: list, caveats: list | None = None) -> None:
        out[field] = {"checks": checks, "caveats": caveats or []}

    # ---- IKE version / exchange
    if ike.get("detected"):
        versions = ike.get("versions_seen") or []
        checks = [_c(len(versions) == 1, f"IKE header major version {ike['version'][-1]} in all "
                                         f"{ike.get('packet_count', 0)} IKE messages"
                  if len(versions) == 1 else f"Several IKE versions seen: {', '.join(versions)}")]
        if ike["version"] == "IKEv2":
            checks.append(_c("IKE_SA_INIT" in by_ex, "IKE_SA_INIT exchange (type 34) detected" + _frames(by_ex.get("IKE_SA_INIT", []))))
            checks.append(_c("IKE_AUTH" in by_ex, "IKE_AUTH exchange (type 35) detected" + _frames(by_ex.get("IKE_AUTH", []))))
            order = session.get("exchanges") or []
            if "IKE_SA_INIT" in order and "IKE_AUTH" in order:
                checks.append(_c(order.index("IKE_SA_INIT") < order.index("IKE_AUTH"),
                                 "Exchange sequence IKE_SA_INIT → IKE_AUTH matches RFC 7296"))
            if "CREATE_CHILD_SA" in by_ex:
                checks.append(_c(True, f"{len(by_ex['CREATE_CHILD_SA'])} CREATE_CHILD_SA message(s) (rekeys)"))
        else:
            mode = "AGGRESSIVE" if "AGGRESSIVE" in by_ex else "MAIN_MODE"
            checks.append(_c(mode in by_ex, f"{mode} exchange detected ({len(by_ex.get(mode, []))} messages)"
                             + _frames(by_ex.get(mode, []))))
            checks.append(_c("QUICK_MODE" in by_ex, "Quick Mode (Phase 2) follows Phase 1"))
        put("ike_version", checks)
        put("exchange_mode", [_c(True, f"Exchange types seen: {', '.join(ike.get('exchange_types') or [])}")])

        chosen = ike.get("chosen_suite") or {}
        suite_checks = []
        if chosen.get("source") == "responder":
            suite_checks.append(_c(True, "Responder's reply carries exactly one selected proposal (cleartext SA payload)"))
        elif chosen.get("source") == "single_offer":
            suite_checks.append(_c(None, "Only the initiator's single-suite offer was captured"))
        offered = ike.get("offered_proposals") or []
        if offered:
            suite_checks.append(_c(True, f"Initiator offered {len(offered)} proposal(s)"))
        if chosen.get("dh_group"):
            suite_checks.append(_c(True, f"KE payload carries DH group {chosen['dh_group']} "
                                         f"({DH_NAMES.get(chosen['dh_group'], '?')})"))
        for field in ("ike_encryption", "ike_integrity", "ike_prf", "key_exchange"):
            if (profile.get(field) or {}).get("value"):
                put(field, suite_checks)
    else:
        put("ike_version", [_c(False, "No IKE messages in the capture")],
            ["The tunnel was negotiated before the capture started; IKE properties cannot be observed"])

    # ---- ESP cipher
    fp = esp.get("fingerprint") or {}
    if esp.get("detected"):
        checks = [_c(fp.get("packets", 0) >= 30, f"{fp.get('packets', esp.get('packet_count', 0)):,} ESP packets, "
                                                  f"{fp.get('distinct_lengths', '?')} distinct payload lengths analysed")]
        caveats = []
        if fp.get("status") == "identified":
            if fp.get("block_size") == 4:
                checks.append(_c(True, "Lengths are 4-byte aligned but vary mod 8 and mod 16 — rules out CBC block ciphers"))
            else:
                checks.append(_c(True, f"Every length has the same residue mod {fp['block_size']} — "
                                       f"{fp['block_size'] * 8}-bit block cipher with {fp['iv_len']}-byte IV"))
                checks.append(_c(True, f"Residue implies a {'/'.join(map(str, fp.get('icv_len_candidates') or []))}-byte ICV"))
            if fp.get("sa_agreement"):
                checks.append(_c(True, f"{fp['sa_agreement']} agree on the cipher family"))
            enc = profile.get("esp_encryption") or {}
            if enc.get("ike_suite_consistent") is True:
                checks.append(_c(True, "Consistent with the cleartext IKE SA suite"))
            elif enc.get("ike_suite_consistent") is False:
                checks.append(_c(None, "Differs from the IKE SA suite (legal, but check the Child SA proposal)"))
            caveats.append("ESP key length (128 vs 256 bit) never shows in the framing")
            if fp.get("mixed_suites"):
                caveats.append(f"SAs disagree: {', '.join(fp['mixed_suites'])}")
        else:
            checks.append(_c(False, fp.get("evidence", "Fingerprint inconclusive")))
        null = esp.get("null_encryption") or {}
        checks.append(_c(not null.get("suspected"), null.get("evidence", "")))
        put("esp_encryption", checks, caveats)
        put("esp_integrity", checks[:3], caveats[1:] + ["ICV length is shared by several HMAC truncations"]
            if fp.get("block_size") != 4 else caveats[1:])

        mode = profile.get("mode") or {}
        inference = esp.get("mode_inference") or {}
        put("mode", [_c(mode.get("value") is not None, inference.get("evidence") or mode.get("evidence", ""))],
            ["Tunnel/transport is negotiated inside encrypted IKE_AUTH; only a size bound is observable",
             "Constant-size traffic (VoIP, ping) has no small ACK packets to measure"] if mode.get("source") != "observed" else [])

        summary = esp.get("replay_summary") or {}
        put("replay_protection", [
            _c(not summary.get("duplicates"), f"{summary.get('duplicates', 0)} duplicate (SPI, sequence) pairs"),
            _c(not summary.get("counter_resets"), f"{summary.get('counter_resets', 0)} counter resets without a new SPI"),
            _c(not summary.get("beyond_default_window"), f"{summary.get('beyond_default_window', 0)} packets reordered "
                                                          f"beyond a 64-packet window (max depth {summary.get('max_reorder_depth', 0)})"),
        ], ["The receiver's window enforcement is not observable; only the sender's counters are"])

    # ---- PFS
    pfs = profile.get("pfs") or {}
    exchanges = pfs.get("exchanges") or []
    child = [d for d in exchanges if d.get("kind") == "child_sa"]
    if child:
        checks = []
        for d in child[:4]:
            if d.get("threshold"):
                checks.append(_c(True, f"Rekey {d.get('measured', 'message')} {d['length']} B "
                                       f"{'≥' if d['pfs'] else '<'} threshold {d['threshold']} B → KE payload "
                                       f"{'present' if d['pfs'] else 'absent'}"))
            else:
                checks.append(_c(True, f"Rekey carries a cleartext KE payload: {'yes' if d['pfs'] else 'no'}"))
            if d.get("new_esp_sa_followed"):
                checks.append(_c(True, "A new ESP SA appears within 10 s of the rekey"))
        agree = sum(1 for d in child if d["pfs"] == pfs.get("value"))
        checks.append(_c(agree == len(child), f"{agree}/{len(child)} rekeys agree"))
        put("pfs", checks, ["Assumes standard payload sizes (no vendor extensions inside the encrypted message)"])
    elif pfs:
        put("pfs", [_c(False, pfs.get("evidence", "No rekey"))])

    # ---- authentication
    auth = profile.get("authentication_method") or {}
    if auth.get("value") and ike.get("version") == "IKEv2":
        rounds = len([m for m in by_ex.get("IKE_AUTH", []) if not m["is_response"]])
        largest = max((m["length"] for m in by_ex.get("IKE_AUTH", [])[:2]), default=0)
        put("authentication_method", [
            _c(True, f"{rounds} IKE_AUTH round trip(s)" + (" — EAP needs ≥ 3" if rounds >= 3 else "")),
            _c(True, f"Largest first IKE_AUTH message {largest} B (an RSA certificate needs ≳ 900 B)"),
            _c(bool(ike.get("certreq_seen")) if "Certificate" in auth["value"] or "EAP" in auth["value"] else None,
               "CERTREQ sent in IKE_SA_INIT" if ike.get("certreq_seen") else "No CERTREQ in IKE_SA_INIT"),
        ], ["Size-based: an unusually large PSK exchange (e.g. many notifies) could look like a certificate"])
    elif auth.get("value"):
        put("authentication_method", [_c(True, "IKEv1 authentication attribute in the cleartext SA payload")])

    # ---- traffic
    if traffic.get("windows"):
        novel = sum(1 for p in predictions if p.get("novel"))
        put("traffic_types", [
            _c(True, f"{traffic['windows']} ten-second windows classified across {len(traffic.get('flows') or [])} tunnel(s)"),
            _c((traffic.get("mean_confidence") or 0) >= 0.6, f"Packet-weighted mean confidence {traffic['mean_confidence']:.0%}"),
            _c(not traffic.get("uncertain_windows"), f"{traffic.get('uncertain_windows', 0)} window(s) below 50% confidence"),
            _c(not novel, f"{novel} window(s) flagged novel (unlike the training data)"),
        ], ["Classified from sizes and timing only; similar applications can look alike once encrypted"])

    if profile.get("nat_traversal"):
        put("nat_traversal", [_c(True, profile["nat_traversal"].get("evidence", ""))])
    if profile.get("ip_version") and profile["ip_version"].get("value"):
        put("ip_version", [_c(True, profile["ip_version"].get("evidence", ""))])
    return out


# ---------------------------------------------------------------- novelty

RARE_DH = {22, 23, 24, 25, 26, 27, 28, 29, 30, 32}


def _enc_family(name: str | None) -> str:
    upper = (name or "").upper()
    for token in ("3DES", "CHACHA", "GCM", "CCM", "CBC", "CTR", "NULL"):
        if token in upper:
            bits = "256" if "256" in upper else "128" if "128" in upper else ""
            return token + bits
    return upper


def _hash_family(name: str | None) -> str:
    upper = (name or "").upper()
    if not upper or upper in ("NONE", "NONE (AEAD)"):
        return "AEAD"
    for token in ("SHA2-512", "SHA2-384", "SHA2-256", "SHA1", "MD5", "XCBC", "CMAC"):
        if token in upper:
            return token
    return upper


def configuration_novelty(analysis: dict[str, Any], traffic: dict[str, Any]) -> dict[str, Any]:
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    chosen = ike.get("chosen_suite") or {}
    profile = analysis.get("profile") or {}
    signals: list[dict[str, Any]] = []

    def add(level: str, text: str) -> None:
        signals.append({"level": level, "text": text})

    if len(ike.get("versions_seen") or []) > 1:
        add("unusual", f"Several IKE versions in one capture: {', '.join(ike['versions_seen'])}")
    for key in ("encryption", "integrity", "prf"):
        name = chosen.get(key) or ""
        if "UNKNOWN" in name.upper() or name.upper().startswith("ENCR-") or "PRIVATE" in name.upper():
            add("novel", f"Unregistered IKE {key} transform: {name}")
    if chosen.get("dh_group") in RARE_DH:
        add("unusual", f"Rarely deployed DH group {chosen['dh_group']} ({DH_NAMES.get(chosen['dh_group'], '?')})")
    if chosen.get("dh_group") and chosen["dh_group"] not in DH_NAMES:
        add("novel", f"Unregistered DH group {chosen['dh_group']}")
    private = [n for n in ike.get("notifies") or [] if n.get("type", 0) >= 40960]
    if private:
        add("unusual", f"Private-use notify types: {', '.join(str(n['type']) for n in private[:4])}")
    unknown_vids = [v for v in ike.get("vendor_ids") or [] if not v.get("name") or "Unknown" in v.get("name", "")]
    if unknown_vids:
        add("unusual", f"{len(unknown_vids)} unrecognised Vendor ID payload(s)")
    enc = profile.get("esp_encryption") or {}
    if enc.get("ike_suite_consistent") is False:
        add("unusual", "Child SA cipher family differs from the IKE SA suite")
    fp = esp.get("fingerprint") or {}
    if fp.get("mixed_suites"):
        add("unusual", f"SAs in one capture use different cipher families: {', '.join(fp['mixed_suites'])}")
    if fp.get("status") == "irregular":
        add("novel", "ESP lengths are not 4-byte aligned — non-standard framing or a different protocol on port 50/4500")
    if traffic.get("novel_windows"):
        add("novel", f"{traffic['novel_windows']} traffic window(s) unlike anything in the training data (k-NN novelty detector)")

    nearest = None
    if chosen.get("encryption"):
        best = None
        for suite in IKE_SUITES.values():
            if suite.key.startswith("lab-"):
                continue
            score = sum([_enc_family(suite.encryption_name) == _enc_family(chosen.get("encryption")),
                         _hash_family(suite.integrity_name) == _hash_family(chosen.get("integrity")),
                         suite.dh_group == chosen.get("dh_group")])
            if best is None or score > best[0]:
                best = (score, suite)
        nearest = {"suite": best[1].key, "matching_components": best[0], "of": 3}
        if best[0] < 3:
            add("info", f"IKE suite is outside the testbed catalogue (nearest: {best[1].key}, {best[0]}/3 components) — "
                        "identification still works, but accuracy figures were measured on catalogue suites")
    if esp.get("detected") and fp.get("status") == "identified":
        families = {s.family for s in ESP_SUITES.values()}
        if fp.get("family") not in families:
            add("info", f"ESP family {fp.get('family')} is outside the testbed catalogue")

    level = "novel" if any(s["level"] == "novel" for s in signals) else \
        "unusual" if any(s["level"] == "unusual" for s in signals) else "known"
    return {"status": level, "signals": signals, "nearest_known": nearest,
            "method": "Rule-based configuration checks + k-NN novelty detector on traffic windows"}
