"""
IPsec-specific deep analysis module.
Aggregates parsed packet data into high-level VPN analysis results.
"""
from typing import Any
from collections import defaultdict


def analyze_ipsec(parsed_data: dict[str, Any]) -> dict[str, Any]:
    """
    Perform deep IPsec/IKE analysis on parsed PCAP data.
    
    Returns comprehensive analysis including:
    - IKE version and exchange info
    - Negotiated algorithms
    - SA information
    - Tunnel/transport mode detection
    - NAT-T detection
    - Replay analysis
    - PFS detection
    """
    packets = parsed_data.get("packets", [])
    
    if not packets:
        return {"error": "No packets to analyze", "packets_analyzed": 0}
    
    analysis = {
        "packets_analyzed": len(packets),
        "ike_analysis": _analyze_ike(packets),
        "esp_analysis": _analyze_esp(packets),
        "ah_analysis": _analyze_ah(packets),
        "nat_t_analysis": _analyze_nat_t(packets),
        "ip_analysis": _analyze_ip_versions(packets),
        "flow_analysis": _analyze_flows(packets),
        "timeline": _build_timeline(packets),
    }
    
    # Determine overall VPN profile
    analysis["vpn_profile"] = _build_vpn_profile(analysis)
    
    return analysis


def _analyze_ike(packets: list[dict]) -> dict[str, Any]:
    """Analyze IKE packets to extract negotiation details."""
    ike_packets = [p for p in packets if p.get("protocol_type") in ("ike", "ike_natt")]
    
    if not ike_packets:
        return {
            "detected": False,
            "version": "Not Observable",
            "exchange_types": [],
            "proposals": [],
            "message": "No IKE packets found in capture. Algorithm details cannot be determined from ESP traffic alone.",
        }
    
    # Determine IKE version
    versions = set()
    for p in ike_packets:
        v = p.get("ike_major_version")
        if v:
            versions.add(v)
    
    if 2 in versions:
        ike_version = "IKEv2"
    elif 1 in versions:
        ike_version = "IKEv1"
    else:
        ike_version = "Unknown"
    
    # Collect exchange types
    exchange_types = set()
    for p in ike_packets:
        et = p.get("ike_exchange_type")
        if et:
            exchange_types.add(et)
    
    # Collect all proposals
    all_proposals = []
    for p in ike_packets:
        proposals = p.get("ike_proposals", [])
        for prop in proposals:
            all_proposals.append(prop)
    
    # Extract chosen algorithms (from response packets)
    chosen_algorithms = _extract_chosen_algorithms(ike_packets)
    
    # Detect PFS
    pfs_detected = _detect_pfs(ike_packets)
    
    # Collect SPIs
    ike_spis = set()
    for p in ike_packets:
        init_spi = p.get("ike_init_spi")
        resp_spi = p.get("ike_resp_spi")
        if init_spi and init_spi != "0" * 16:
            ike_spis.add(init_spi)
        if resp_spi and resp_spi != "0" * 16:
            ike_spis.add(resp_spi)
    
    # Detect transport mode
    transport_mode = any(p.get("transport_mode_requested") for p in ike_packets)
    
    # Collect notify types
    all_notifies = []
    for p in ike_packets:
        notifies = p.get("ike_notifies", [])
        for n in notifies:
            if n not in all_notifies:
                all_notifies.append(n)
    
    return {
        "detected": True,
        "version": ike_version,
        "packet_count": len(ike_packets),
        "exchange_types": sorted(exchange_types),
        "proposals": all_proposals,
        "chosen_algorithms": chosen_algorithms,
        "pfs_detected": pfs_detected,
        "ike_spis": sorted(ike_spis),
        "transport_mode_requested": transport_mode,
        "tunnel_mode": not transport_mode,
        "mode": "Transport" if transport_mode else "Tunnel",
        "notifies": all_notifies,
    }


def _extract_chosen_algorithms(ike_packets: list[dict]) -> dict[str, Any]:
    """
    Extract the chosen (negotiated) algorithms from IKE responses.
    In IKEv2, the responder echoes the chosen proposal with exactly one transform per type.
    """
    chosen = {
        "encryption": "Not Observable",
        "integrity": "Not Observable",
        "prf": "Not Observable",
        "dh_group": "Not Observable",
        "dh_group_number": None,
        "esn": "Not Observable",
    }
    
    # Look for response packets with single-transform proposals
    for p in ike_packets:
        if not p.get("ike_response"):
            continue
        proposals = p.get("ike_proposals", [])
        for prop in proposals:
            transforms = prop.get("transforms", [])
            for t in transforms:
                t_type = t.get("type_name", "")
                t_name = t.get("name", "")
                
                if t_type == "Encryption" and t_name:
                    chosen["encryption"] = t_name
                    key_len = t.get("key_length")
                    if key_len:
                        chosen["key_length"] = key_len
                elif t_type == "Integrity" and t_name:
                    chosen["integrity"] = t_name
                elif t_type == "PRF" and t_name:
                    chosen["prf"] = t_name
                elif t_type == "DH Group" and t_name:
                    chosen["dh_group"] = t_name
                    chosen["dh_group_number"] = t.get("group_number")
                elif t_type == "ESN":
                    chosen["esn"] = t_name
    
    return chosen


def _detect_pfs(ike_packets: list[dict]) -> dict[str, Any]:
    """
    Detect Perfect Forward Secrecy.
    PFS is indicated by a Key Exchange payload in CREATE_CHILD_SA exchange.
    """
    create_child_packets = [
        p for p in ike_packets
        if p.get("ike_exchange_type") == "CREATE_CHILD_SA"
    ]
    
    if not create_child_packets:
        return {
            "detected": "Not Observable",
            "reason": "No CREATE_CHILD_SA exchanges found in capture",
        }
    
    ke_in_child = any(p.get("ike_ke_dh_groups") for p in create_child_packets)
    
    if ke_in_child:
        dh_groups = []
        for p in create_child_packets:
            dh_groups.extend(p.get("ike_ke_dh_groups", []))
        return {
            "detected": True,
            "dh_groups_used": dh_groups,
            "reason": "Key Exchange payload found in CREATE_CHILD_SA",
        }
    
    return {
        "detected": False,
        "reason": "CREATE_CHILD_SA without Key Exchange payload (no PFS)",
    }


def _analyze_esp(packets: list[dict]) -> dict[str, Any]:
    """Analyze ESP packets."""
    esp_packets = [p for p in packets if p.get("protocol_type") == "esp"]
    
    if not esp_packets:
        return {"detected": False, "packet_count": 0}
    
    # Group by SPI
    spi_groups = defaultdict(list)
    for p in esp_packets:
        spi = p.get("spi", "unknown")
        spi_groups[spi].append(p)
    
    # Analyze each SPI group
    sa_info = []
    for spi, pkts in spi_groups.items():
        seq_nums = [p.get("seq_num", 0) for p in pkts]
        payload_sizes = [p.get("esp_payload_len", 0) for p in pkts if p.get("esp_payload_len")]
        timestamps = [p.get("timestamp", 0) for p in pkts]
        
        sa = {
            "spi": spi,
            "packet_count": len(pkts),
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen": max(timestamps) if timestamps else None,
            "duration": (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0,
        }
        
        if seq_nums:
            sa["min_seq"] = min(seq_nums)
            sa["max_seq"] = max(seq_nums)
            sa["seq_gaps"] = _detect_sequence_gaps(sorted(seq_nums))
        
        if payload_sizes:
            sa["avg_payload_size"] = round(sum(payload_sizes) / len(payload_sizes), 1)
            sa["min_payload_size"] = min(payload_sizes)
            sa["max_payload_size"] = max(payload_sizes)
        
        # Note: encryption algorithm cannot be determined from ESP alone
        sa["encryption"] = "Not Observable (encrypted)"
        sa["note"] = "Encryption algorithm cannot be determined from ESP ciphertext. See IKE negotiation if available."
        
        sa_info.append(sa)
    
    return {
        "detected": True,
        "packet_count": len(esp_packets),
        "unique_spis": len(spi_groups),
        "sa_info": sa_info,
    }


def _detect_sequence_gaps(sorted_seqs: list[int]) -> list[dict]:
    """Detect gaps in sequence numbers that might indicate packet loss or replay."""
    gaps = []
    for i in range(1, len(sorted_seqs)):
        diff = sorted_seqs[i] - sorted_seqs[i - 1]
        if diff > 1:
            gaps.append({
                "after_seq": sorted_seqs[i - 1],
                "before_seq": sorted_seqs[i],
                "gap_size": diff - 1,
            })
        elif diff == 0:
            gaps.append({
                "seq": sorted_seqs[i],
                "type": "duplicate",
                "note": "Possible replay or retransmission",
            })
    return gaps


def _analyze_ah(packets: list[dict]) -> dict[str, Any]:
    """Analyze AH packets."""
    ah_packets = [p for p in packets if p.get("protocol_type") == "ah"]
    
    if not ah_packets:
        return {"detected": False, "packet_count": 0}
    
    spi_groups = defaultdict(int)
    for p in ah_packets:
        spi = p.get("spi", "unknown")
        spi_groups[spi] += 1
    
    return {
        "detected": True,
        "packet_count": len(ah_packets),
        "unique_spis": len(spi_groups),
        "spis": dict(spi_groups),
        "note": "AH provides authentication/integrity only, no encryption",
    }


def _analyze_nat_t(packets: list[dict]) -> dict[str, Any]:
    """Analyze NAT Traversal indicators."""
    nat_t_ike = [p for p in packets if p.get("protocol_type") == "ike_natt"]
    nat_detection = any(p.get("nat_detection") for p in packets)
    nat_t_esp = [p for p in packets if p.get("protocol_type") == "esp" and p.get("nat_t")]
    
    detected = bool(nat_t_ike or nat_detection or nat_t_esp)
    
    return {
        "detected": detected,
        "nat_t_ike_packets": len(nat_t_ike),
        "nat_t_esp_packets": len(nat_t_esp),
        "nat_detection_payloads": nat_detection,
        "encapsulation": "UDP 4500" if detected else "None observed",
    }


def _analyze_ip_versions(packets: list[dict]) -> dict[str, Any]:
    """Analyze IP version usage."""
    v4_count = sum(1 for p in packets if p.get("ip_version") == 4)
    v6_count = sum(1 for p in packets if p.get("ip_version") == 6)
    
    # Unique IP pairs
    ip_pairs = set()
    for p in packets:
        src = p.get("src_ip")
        dst = p.get("dst_ip")
        if src and dst:
            ip_pairs.add((src, dst))
    
    return {
        "ipv4_packets": v4_count,
        "ipv6_packets": v6_count,
        "primary_version": "IPv6" if v6_count > v4_count else "IPv4" if v4_count > 0 else "Unknown",
        "dual_stack": v4_count > 0 and v6_count > 0,
        "unique_ip_pairs": [{"src": s, "dst": d} for s, d in sorted(ip_pairs)],
    }


def _analyze_flows(packets: list[dict]) -> dict[str, Any]:
    """Analyze packet flows grouped by SPI."""
    esp_packets = [p for p in packets if p.get("protocol_type") == "esp"]
    
    if not esp_packets:
        return {"flow_count": 0, "flows": []}
    
    # Group by SPI
    flows = defaultdict(list)
    for p in esp_packets:
        spi = p.get("spi", "unknown")
        flows[spi].append(p)
    
    flow_info = []
    for spi, pkts in flows.items():
        timestamps = sorted([p.get("timestamp", 0) for p in pkts])
        sizes = [p.get("length", 0) for p in pkts]
        
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        
        flow = {
            "spi": spi,
            "packet_count": len(pkts),
            "duration_seconds": round(duration, 3),
            "avg_packet_size": round(sum(sizes) / len(sizes), 1) if sizes else 0,
            "total_bytes": sum(sizes),
            "packets_per_second": round(len(pkts) / duration, 1) if duration > 0 else len(pkts),
        }
        
        # Calculate inter-arrival times
        if len(timestamps) > 1:
            iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            flow["avg_iat_ms"] = round(sum(iats) / len(iats) * 1000, 2) if iats else 0
            flow["min_iat_ms"] = round(min(iats) * 1000, 2) if iats else 0
            flow["max_iat_ms"] = round(max(iats) * 1000, 2) if iats else 0
        
        flow_info.append(flow)
    
    return {
        "flow_count": len(flow_info),
        "flows": flow_info,
    }


def _build_timeline(packets: list[dict]) -> list[dict]:
    """Build a timeline of significant events."""
    events = []
    
    for p in packets:
        ptype = p.get("protocol_type")
        
        if ptype in ("ike", "ike_natt"):
            et = p.get("ike_exchange_type", "Unknown")
            direction = "→" if p.get("ike_initiator") else "←"
            resp = " (Response)" if p.get("ike_response") else " (Request)"
            events.append({
                "timestamp": p.get("timestamp", 0),
                "type": "IKE",
                "description": f"{et}{resp}",
                "direction": direction,
                "src": p.get("src_ip", "?"),
                "dst": p.get("dst_ip", "?"),
            })
        elif ptype == "esp" and p.get("seq_num", 0) <= 3:
            events.append({
                "timestamp": p.get("timestamp", 0),
                "type": "ESP",
                "description": f"ESP SPI={p.get('spi', '?')} Seq={p.get('seq_num', '?')}",
                "src": p.get("src_ip", "?"),
                "dst": p.get("dst_ip", "?"),
            })
    
    # Sort by timestamp and limit
    events.sort(key=lambda e: e["timestamp"])
    return events[:100]


def _build_vpn_profile(analysis: dict) -> dict[str, Any]:
    """Build an overall VPN profile summary."""
    ike = analysis.get("ike_analysis", {})
    esp = analysis.get("esp_analysis", {})
    ah = analysis.get("ah_analysis", {})
    nat = analysis.get("nat_t_analysis", {})
    ip = analysis.get("ip_analysis", {})
    
    chosen = ike.get("chosen_algorithms", {})
    
    profile = {
        "ipsec_protocol": [],
        "ike_version": ike.get("version", "Not Observable"),
        "mode": ike.get("mode", "Not Observable") if ike.get("detected") else "Not Observable",
        "encryption": chosen.get("encryption", "Not Observable"),
        "integrity": chosen.get("integrity", "Not Observable"),
        "prf": chosen.get("prf", "Not Observable"),
        "dh_group": chosen.get("dh_group", "Not Observable"),
        "dh_group_number": chosen.get("dh_group_number"),
        "pfs": ike.get("pfs_detected", {}).get("detected", "Not Observable"),
        "nat_t": nat.get("detected", False),
        "ip_version": ip.get("primary_version", "Unknown"),
        "dual_stack": ip.get("dual_stack", False),
        "esn": chosen.get("esn", "Not Observable"),
    }
    
    if esp.get("detected"):
        profile["ipsec_protocol"].append("ESP")
    if ah.get("detected"):
        profile["ipsec_protocol"].append("AH")
    if not profile["ipsec_protocol"]:
        profile["ipsec_protocol"].append("Not Observable")
    
    # Key length
    if chosen.get("key_length"):
        profile["key_length"] = chosen["key_length"]
    
    # Total SPI count
    esp_spis = esp.get("unique_spis", 0)
    ah_spis = ah.get("unique_spis", 0)
    profile["total_sas"] = esp_spis + ah_spis
    
    return profile
