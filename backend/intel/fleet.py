"""
Fleet-wide views across every stored analysis.

  object_rows   one flat, filterable row per capture (the object explorer and the command palette)
  link_graph    captures, gateways, configurations, findings and traffic as a link-analysis graph
  inbox         every non-informational finding occurrence, with a persisted triage status

Analysis records never change after they are saved, so each capture's row is memoised by id.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from backend.config import DATA_DIR, TRAFFIC_CLASS_LABELS
from backend.intel.rules import rule_for
from backend.storage import list_analyses, load_analysis

MAX_CAPTURES = 80
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
TRIAGE_PATH = DATA_DIR / "triage.json"
TRIAGE_STATUSES = ["new", "investigating", "accepted", "resolved", "false_positive"]
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,80}:[A-Z]+-\d{3}$")

_rows: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------- object rows

def _source(record: dict[str, Any]) -> str:
    source = record.get("source") or {}
    if source.get("live"):
        return "live"
    if source.get("lab"):
        return "lab"
    if source.get("is_sample"):
        return "testbed"
    return "upload"


def _auth_class(value: str | None) -> str | None:
    if not value:
        return None
    if "Pre-Shared" in value:
        return "PSK"
    if "EAP" in value:
        return "EAP"
    return "Certificate"


def build_row(record: dict[str, Any]) -> dict[str, Any]:
    from backend.intel import build_intel

    intel = record.get("intel") if (record.get("intel") or {}).get("version") == 1 else build_intel(record)
    analysis = record["ipsec_analysis"]
    profile = analysis.get("profile") or {}
    security = record["security"]
    chosen = (analysis.get("ike_analysis") or {}).get("chosen_suite") or {}
    esp = analysis.get("esp_analysis") or {}

    def v(key: str):
        return (profile.get(key) or {}).get("value")

    pfs = v("pfs")
    mix = (record.get("traffic") or {}).get("mix") or {}
    findings = [{"id": f["id"], "title": f["title"], "severity": f["severity"], "source": f.get("evidence_source"),
                 "confidence": f.get("confidence")}
                for f in security["findings"] if f["severity"] != "Informational"]
    fp = intel["fingerprint"]
    return {
        "analysis_id": record["analysis_id"],
        "filename": record["parsed_metadata"]["filename"],
        "created": record.get("created"),
        "packets": record["parsed_metadata"].get("total_packets"),
        "duration": analysis.get("capture_duration"),
        "source": _source(record),
        "score": security.get("overall_score"),
        "risk_level": security.get("risk_level"),
        "coverage": security.get("coverage"),
        "strength_bits": (security.get("effective_strength") or {}).get("bits"),
        "ike_version": v("ike_version"),
        "exchange_mode": v("exchange_mode"),
        "ike_encryption": chosen.get("encryption"),
        "ike_integrity": chosen.get("integrity") or ("AEAD" if chosen.get("encryption") and "GCM" in chosen["encryption"] else None),
        "dh_group": chosen.get("dh_group"),
        "dh_name": chosen.get("dh_group_name"),
        "esp_encryption": v("esp_encryption"),
        "esp_integrity": v("esp_integrity"),
        "pfs": None if pfs is None else ("on" if pfs else "off"),
        "mode": v("mode"),
        "auth": _auth_class(v("authentication_method")),
        "nat_t": bool(v("nat_traversal")),
        "ip_version": v("ip_version"),
        "implementation": v("implementation"),
        "gateways": fp.get("endpoints") or [],
        "fingerprint": fp["id"],
        "fingerprint_label": fp["label"],
        "policy_status": intel["policy"]["status"],
        "policy_fail": intel["policy"]["counts"]["fail"],
        "novelty": intel["novelty"]["status"],
        "confidentiality": intel["metadata"]["confidentiality"],
        "metadata_privacy": intel["metadata"]["metadata_privacy"],
        "traffic": [c for c, share in mix.items() if share >= 0.05],
        "traffic_confidence": (record.get("traffic") or {}).get("mean_confidence"),
        "findings": findings,
        "severity_counts": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER[:4]},
        "tunnels": len(esp.get("tunnels") or []),
        "sas": esp.get("sa_count", 0),
        "replay_anomalies": sum((esp.get("replay_summary") or {}).get(k) or 0 for k in ("duplicates", "counter_resets")),
    }


def object_rows(limit: int = MAX_CAPTURES) -> list[dict[str, Any]]:
    rows = []
    for summary in list_analyses()[:limit]:
        aid = summary["analysis_id"]
        with _lock:
            row = _rows.get(aid)
        if row is None:
            record = load_analysis(aid)
            if record is None:
                continue
            try:
                row = build_row(record)
            except (KeyError, TypeError, ValueError):
                continue  # records from much older versions are skipped, not fatal
            with _lock:
                _rows[aid] = row
        rows.append(row)
    return rows


# ---------------------------------------------------------------- link graph

def _worst(severities: list[str]) -> str | None:
    return min(severities, key=SEVERITY_ORDER.index) if severities else None


def link_graph(rows: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def node(nid: str, kind: str, label: str, **extra: Any) -> dict[str, Any]:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": kind, "label": label, "captures": [], "severities": [], **extra}
        return nodes[nid]

    def link(capture: dict, target: dict, kind: str, row: dict) -> None:
        edges.append({"source": capture["id"], "target": target["id"], "kind": kind})
        target["captures"].append(row["analysis_id"])

    for row in rows:
        worst = _worst([f["severity"] for f in row["findings"]])
        cap = node(f"capture:{row['analysis_id']}", "capture", row["filename"], analysis_id=row["analysis_id"],
                   sub=f"{row['risk_level']} · {row['score']}", severity=worst, score=row["score"],
                   props={"Score": row["score"], "Risk": row["risk_level"], "IKE": row["ike_version"],
                          "Fingerprint": row["fingerprint"], "Packets": row["packets"], "Source": row["source"],
                          "Policy": row["policy_status"]})
        for ip in row["gateways"]:
            link(cap, node(f"gateway:{ip}", "gateway", ip, sub="VPN gateway",
                           props={"Address": ip, "Implementation": row.get("implementation") or "not disclosed"}),
                 "between", row)
        link(cap, node(f"fingerprint:{row['fingerprint']}", "fingerprint", row["fingerprint"],
                       sub=row["fingerprint_label"], props={"Configuration": row["fingerprint_label"]}), "has config", row)
        for f in row["findings"]:
            short = f["title"].split(":")[0]
            n = node(f"finding:{f['id']}", "finding", f"{f['id']} {short}", sub=rule_for(f["id"])[0],
                     finding_id=f["id"], props={"Rule": rule_for(f["id"])[0], "Reference": rule_for(f["id"])[1]})
            n["severities"].append(f["severity"])
            link(cap, n, "raised", row)
        for cls in row["traffic"]:
            link(cap, node(f"traffic:{cls}", "traffic", TRAFFIC_CLASS_LABELS.get(cls, cls), sub="Application class",
                           traffic_class=cls, props={"Class": TRAFFIC_CLASS_LABELS.get(cls, cls)}), "carries", row)
        configs = [
            ("ike", row["ike_version"] and (f"{row['ike_version']}" + (f" {row['exchange_mode']}" if row["ike_version"] == "IKEv1" else ""))),
            ("enc", row["ike_encryption"]),
            ("dh", row["dh_group"] and f"DH {row['dh_group']} · {row['dh_name']}"),
            ("esp", row["esp_encryption"] and f"ESP {row['esp_encryption']}"),
            ("pfs", row["pfs"] and f"PFS {row['pfs']}"),
            ("auth", row["auth"] and f"Auth {row['auth']}"),
        ]
        for kind, label in configs:
            if label:
                link(cap, node(f"config:{kind}:{label}", "config", label, sub="Configuration value",
                               props={"Setting": kind.upper(), "Value": label}), "uses", row)

    for n in nodes.values():
        n["captures"] = sorted(set(n["captures"]))
        n["degree"] = len(n["captures"]) if n["type"] != "capture" else sum(
            1 for e in edges if e["source"] == n["id"])
        if n["type"] == "finding":
            n["severity"] = _worst(n["severities"])
            n["props"]["Captures"] = len(n["captures"])
        elif n["type"] != "capture":
            n["props"]["Captures"] = len(n["captures"])
        n.pop("severities", None)
    counts: dict[str, int] = {}
    for n in nodes.values():
        counts[n["type"]] = counts.get(n["type"], 0) + 1
    return {"nodes": list(nodes.values()), "edges": edges, "counts": counts, "captures": len(rows)}


# ---------------------------------------------------------------- triage inbox

def _read_triage() -> dict[str, Any]:
    try:
        return json.loads(TRIAGE_PATH.read_text(encoding="utf-8")) if TRIAGE_PATH.exists() else {}
    except (OSError, ValueError):
        return {}


def inbox(rows: list[dict[str, Any]]) -> dict[str, Any]:
    store = _read_triage()
    items = []
    for row in rows:
        for f in row["findings"]:
            key = f"{row['analysis_id']}:{f['id']}"
            state = store.get(key) or {}
            items.append({
                "key": key, "analysis_id": row["analysis_id"], "filename": row["filename"], "created": row["created"],
                "fingerprint": row["fingerprint"], "gateways": row["gateways"], "finding_id": f["id"],
                "title": f["title"], "severity": f["severity"], "source": f.get("source"), "confidence": f.get("confidence"),
                "status": state.get("status", "new"), "note": state.get("note", ""), "updated": state.get("updated"),
                "history": state.get("history", [])[-6:],
            })
    items.sort(key=lambda i: (SEVERITY_ORDER.index(i["severity"]), -(i["created"] or 0)))
    counts = {s: sum(1 for i in items if i["status"] == s) for s in TRIAGE_STATUSES}
    return {"items": items, "counts": counts, "statuses": TRIAGE_STATUSES}


def update_triage(keys: list[str], status: str | None, note: str | None) -> dict[str, Any]:
    bad = [k for k in keys if not KEY_PATTERN.match(k)]
    if bad:
        raise ValueError(f"Invalid finding key(s): {', '.join(bad[:3])}")
    if status is not None and status not in TRIAGE_STATUSES:
        raise ValueError(f"Status must be one of {', '.join(TRIAGE_STATUSES)}")
    now = time.time()
    with _lock:
        store = _read_triage()
        for key in keys:
            state = store.setdefault(key, {"status": "new", "note": "", "history": []})
            if status is not None and status != state["status"]:
                state["history"].append({"at": now, "from": state["status"], "to": status})
                state["status"] = status
            if note is not None:
                state["note"] = note[:2000]
            state["updated"] = now
        TRIAGE_PATH.write_text(json.dumps(store), encoding="utf-8")
    return {"updated": len(keys)}
