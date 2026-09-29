"""
Attack-surface map: the deployment as a layered graph with risks overlaid.

  gateways ── IKE SA ── Child SA tunnels ── traffic inside each tunnel

Each node carries the findings that concern it and a status (worst severity), plus the strengths that
hold, so the analyst sees where the weak links sit.
"""
from __future__ import annotations

from typing import Any

from backend.config import TRAFFIC_CLASS_LABELS

STATUS = {"Critical": "critical", "High": "serious", "Medium": "warning", "Low": "low", "Informational": "good"}
ORDER = ["critical", "serious", "warning", "low", "good", "unknown"]

# which findings attach to which layer
LAYER_OF = {
    "gateway": ("META-002", "META-004", "META-005", "CFG-003", "CFG-004", "META-006"),
    "ike": ("KE-", "AUTH-001", "AUTH-002", "AUTH-003", "CFG-001", "CFG-002", "CFG-005", "CFG-006",
            "META-001", "LIFE-001", "LIFE-003", "LIFE-005"),
    "child": ("PFS-", "REPLAY-", "LIFE-002", "LIFE-004"),
    "traffic": ("META-003",),
}


def _layer(fid: str) -> list[str]:
    layers = [layer for layer, prefixes in LAYER_OF.items() if fid.startswith(prefixes)]
    if fid.startswith(("CRYPTO", "AUTH-004", "AUTH-005")):
        layers = ["ike", "child"]  # merged findings name their subject (IKE SA / ESP)
    return layers


def _status(findings: list[dict]) -> str:
    if not findings:
        return "unknown"
    return min((STATUS[f["severity"]] for f in findings), key=ORDER.index)


def _mentions(finding: dict, subject: str) -> bool:
    title = finding["title"]
    if subject == "ike":
        return "IKE SA" in title or not ("ESP" in title)
    return "ESP" in title or "IKE SA" not in title


def attack_surface(analysis: dict[str, Any], security: dict[str, Any], traffic: dict[str, Any]) -> dict[str, Any]:
    profile = analysis.get("profile") or {}
    ike = analysis.get("ike_analysis") or {}
    esp = analysis.get("esp_analysis") or {}
    findings = security.get("findings") or []

    def v(key: str):
        ev = profile.get(key) or {}
        return ev.get("display") or ev.get("value")

    by_layer: dict[str, list[dict]] = {k: [] for k in LAYER_OF}
    for f in findings:
        for layer in _layer(f["id"]):
            if f["id"].startswith(("CRYPTO", "AUTH-004", "AUTH-005")) and not _mentions(f, layer):
                continue
            by_layer[layer].append({"id": f["id"], "title": f["title"], "severity": f["severity"]})

    def risks(layer: str) -> list[dict]:
        return [f for f in by_layer[layer] if f["severity"] != "Informational"]

    def strengths(layer: str) -> list[str]:
        return [f["title"] for f in by_layer[layer] if f["severity"] == "Informational"
                and not f["title"].lower().startswith(("pfs not", "key lifetimes not", "encryption not"))][:4]

    nodes, edges = [], []
    sessions = ike.get("sessions") or []
    initiator = sessions[0]["initiator_ip"] if sessions else None
    responder = sessions[0]["responder_ip"] if sessions else None
    tunnels = esp.get("tunnels") or []
    if not initiator and tunnels:
        initiator, responder = tunnels[0]["peer_a"], tunnels[0]["peer_b"]
    implementation = v("implementation")
    for role, ip in (("Initiator", initiator), ("Responder", responder)):
        if not ip:
            continue
        nodes.append({"id": f"gw-{role.lower()}", "layer": 0, "kind": "gateway", "title": f"{role} gateway",
                      "subtitle": ip, "facts": [x for x in [implementation and f"Product: {implementation}",
                                                            v("ip_version"), "NAT-T" if v("nat_traversal") is True else None] if x],
                      "risks": risks("gateway"), "strengths": [], "status": _status(risks("gateway")) if risks("gateway") else "good"})

    if ike.get("detected"):
        facts = [x for x in [v("ike_version"), v("exchange_mode") if v("exchange_mode") != v("ike_version") else None,
                             v("ike_encryption"), v("ike_integrity"), v("key_exchange"), v("authentication_method")] if x]
        nodes.append({"id": "ike", "layer": 1, "kind": "ike", "title": "IKE SA", "subtitle": "control channel · UDP 500/4500",
                      "facts": facts, "risks": risks("ike"), "strengths": strengths("ike"),
                      "status": _status(risks("ike")) if risks("ike") else "good"})
        for gw in ("gw-initiator", "gw-responder"):
            if any(n["id"] == gw for n in nodes):
                edges.append({"from": gw, "to": "ike", "label": "IKE negotiation"})

    flows = {f["flow_id"]: f for f in traffic.get("flows") or []}
    pfs = v("pfs")
    child_facts = [x for x in [v("esp_encryption"), v("esp_integrity"), v("mode"),
                               None if pfs is None else f"PFS {'on' if pfs is True or pfs == 'Yes' else 'off'}"] if x]
    shown = sorted(tunnels, key=lambda t: -t["packet_count"])[:6]
    for i, t in enumerate(shown):
        node_id = f"child-{i}"
        nodes.append({"id": node_id, "layer": 2, "kind": "child", "title": f"Child SA pair {i + 1}",
                      "subtitle": f"{t['spi_a']} / {t['spi_b'] or '—'}",
                      "facts": child_facts + [f"{t['packet_count']:,} packets · {t['duration_seconds']:.0f} s"],
                      "risks": risks("child"), "strengths": strengths("child"),
                      "status": _status(risks("child")) if risks("child") else "good"})
        edges.append({"from": "ike" if ike.get("detected") else "gw-initiator", "to": node_id, "label": "ESP tunnel"})
        flow = flows.get(t["id"])
        if flow:
            for cls, share in list(flow["mix"].items())[:3]:
                leaf = f"{node_id}-{cls}"
                meta = risks("traffic")
                nodes.append({"id": leaf, "layer": 3, "kind": "traffic", "title": TRAFFIC_CLASS_LABELS.get(cls, cls),
                              "subtitle": f"{share:.0%} of this tunnel's windows", "class": cls,
                              "facts": [f"{flow['mean_confidence']:.0%} mean confidence"], "risks": meta,
                              "strengths": [], "status": _status(meta) if meta else "good"})
                edges.append({"from": node_id, "to": leaf, "label": ""})
    hidden = len(tunnels) - len(shown)
    legend = [
        {"status": "critical", "label": "Critical"}, {"status": "serious", "label": "High"},
        {"status": "warning", "label": "Medium"}, {"status": "low", "label": "Low"}, {"status": "good", "label": "No weakness"},
    ]
    return {"nodes": nodes, "edges": edges, "hidden_tunnels": max(0, hidden), "legend": legend,
            "layers": ["Gateways", "IKE SA (control)", "Child SAs (ESP data)", "Traffic inside"]}
