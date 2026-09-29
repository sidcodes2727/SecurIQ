"""
Decision-support routes: explanations, what-if simulation (with testbed verification), golden-policy
compliance, configuration fingerprints and drift, digital-twin lab builds, and the misconfiguration
benchmark.
"""
import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.intel import build_intel
from backend.intel import fleet, lab, simulator
from backend.intel.fingerprint import drift
from backend.intel.policy import DEFAULT_POLICY, evaluate_policy, load_policy, reset_policy, save_policy
from backend.ml import benchmark
from backend.ml.model import classifier
from backend.pipeline import run_pipeline
from backend.storage import list_analyses, load_analysis, new_id, save_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["intelligence"])


def _record(analysis_id: str) -> dict:
    record = load_analysis(analysis_id)
    if record is None:
        raise HTTPException(404, "Analysis not found")
    if not record.get("intel") or record["intel"].get("version") != 1:
        record["intel"] = build_intel(record)  # analyses stored before this layer existed
    return record


def _run_and_save(file_id: str, path, truth, source: dict[str, Any]) -> tuple[str, dict]:
    if not (classifier.is_trained or classifier.load()):
        raise HTTPException(409, "The traffic classifier is still training")
    result = run_pipeline(str(path), truth)
    analysis_id = new_id()
    result["created"] = time.time()
    result["source"] = {"file_id": file_id, "is_sample": True, **source}
    save_analysis(analysis_id, file_id, result)
    return analysis_id, load_analysis(analysis_id)


# ---------------------------------------------------------------- explanations

@router.get("/intel/{analysis_id}")
def get_intel(analysis_id: str):
    return _record(analysis_id)["intel"]


# ---------------------------------------------------------------- what-if simulator

class Changes(BaseModel):
    changes: dict[str, Any] = Field(default_factory=dict)


@router.get("/simulator/options")
def simulator_options():
    return {"knobs": simulator.KNOBS}


@router.get("/simulator/{analysis_id}/baseline")
def simulator_baseline(analysis_id: str):
    record = _record(analysis_id)
    analysis = record["ipsec_analysis"]
    return {"current": simulator.current_config(analysis), "recommended": simulator.recommended_changes(analysis),
            "knobs": simulator.KNOBS, "filename": record["parsed_metadata"]["filename"]}


@router.post("/simulator/{analysis_id}")
def simulate(analysis_id: str, body: Changes):
    return simulator.simulate(_record(analysis_id), body.changes)


@router.post("/simulator/{analysis_id}/verify")
def verify(analysis_id: str, body: Changes):
    """Render the proposed configuration as a capture (same traffic) and measure it with the full pipeline."""
    record = _record(analysis_id)
    problems = simulator.validate(body.changes, record["ipsec_analysis"])
    if problems:
        raise HTTPException(422, "; ".join(problems))
    config = lab.config_for_verify(record, body.changes)
    traffic = lab.traffic_from_record(record)
    file_id, path, truth = lab.build(config, traffic, f"Verification of {record['parsed_metadata']['filename']}",
                                     derived_from=analysis_id)
    new_analysis_id, after = _run_and_save(file_id, path, truth, {"lab": True, "derived_from": analysis_id})
    before, measured = record["security"], after["security"]
    categories = [{"key": k, "label": c["label"], "before": c["score"],
                   "after": measured["categories"][k]["score"],
                   "delta": None if c["score"] is None or measured["categories"][k]["score"] is None
                   else round(measured["categories"][k]["score"] - c["score"], 1)}
                  for k, c in before["categories"].items()]
    return {
        "analysis_id": new_analysis_id,
        "file_id": file_id,
        "config": config,
        "before": {"score": before["overall_score"], "risk_level": before["risk_level"]},
        "after": {"score": measured["overall_score"], "risk_level": measured["risk_level"],
                  "identification_accuracy": (after.get("ground_truth") or {}).get("accuracy")},
        "delta": None if before["overall_score"] is None or measured["overall_score"] is None
        else round(measured["overall_score"] - before["overall_score"], 1),
        "categories": categories,
        "resolved": sorted({f["id"] for f in before["findings"] if f["severity"] != "Informational"}
                           - {f["id"] for f in measured["findings"]}),
        "remaining": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in measured["findings"]
                      if f["severity"] != "Informational"],
        "strongswan_profile": lab.strongswan_profile(config, traffic, file_id),
        "note": ("Measured: the proposed configuration was rendered by the testbed generator with this capture's "
                 "traffic and analysed from the PCAP alone. Lifetimes are compressed in the lab, so lifetime "
                 "categories may be not assessable."),
    }


# ---------------------------------------------------------------- golden policy

class PolicyBody(BaseModel):
    policy: dict[str, Any]


@router.get("/policy")
def get_policy():
    return {"policy": load_policy(), "default": DEFAULT_POLICY}


@router.post("/policy")
def set_policy(body: PolicyBody):
    unknown = [k for k in body.policy if k not in DEFAULT_POLICY]
    if unknown:
        raise HTTPException(422, f"Unknown policy keys: {', '.join(unknown)}")
    for key, value in body.policy.items():
        if type(value) is not type(DEFAULT_POLICY[key]) and not (isinstance(value, int) and isinstance(DEFAULT_POLICY[key], int)):
            raise HTTPException(422, f"{key} must be a {type(DEFAULT_POLICY[key]).__name__}")
    return {"policy": save_policy(body.policy)}


@router.post("/policy/reset")
def policy_reset():
    return {"policy": reset_policy()}


@router.get("/policy/evaluate/{analysis_id}")
def policy_evaluate(analysis_id: str):
    return evaluate_policy(load_policy(), _record(analysis_id)["ipsec_analysis"])


@router.get("/policy/fleet")
def policy_fleet():
    """Every stored analysis against the current policy."""
    policy, rows = load_policy(), []
    for summary in list_analyses()[:40]:
        record = load_analysis(summary["analysis_id"])
        if record:
            result = evaluate_policy(policy, record["ipsec_analysis"])
            rows.append({"analysis_id": summary["analysis_id"], "filename": summary["filename"],
                         "created": summary.get("created"), "status": result["status"], "counts": result["counts"],
                         "score": result["score"]})
    return {"analyses": rows}


# ---------------------------------------------------------------- fingerprints & drift

@router.get("/fingerprints")
def fingerprints():
    out = []
    for summary in list_analyses()[:60]:
        fp_id = summary.get("fingerprint")
        if not fp_id:
            record = load_analysis(summary["analysis_id"])
            if not record:
                continue
            fp = (record.get("intel") or {}).get("fingerprint") or build_intel(record)["fingerprint"]
            fp_id, label, endpoints = fp["id"], fp["label"], fp["endpoints"]
        else:
            label, endpoints = summary.get("fingerprint_label"), summary.get("endpoints")
        out.append({"analysis_id": summary["analysis_id"], "filename": summary["filename"],
                    "created": summary.get("created"), "fingerprint": fp_id, "label": label,
                    "endpoints": endpoints, "score": summary.get("security_score"),
                    "risk_level": summary.get("risk_level")})
    return {"analyses": out}


@router.get("/drift/{target_id}")
def get_drift(target_id: str, baseline: str | None = None):
    target = _record(target_id)
    if baseline is None:
        endpoints = set(target["intel"]["fingerprint"].get("endpoints") or [])
        earlier = [a for a in list_analyses() if a["analysis_id"] != target_id
                   and (a.get("created") or 0) < (target.get("created") or 0)]
        match = next((a for a in earlier if endpoints & set(a.get("endpoints") or [])), None)
        if match is None:
            return {"status": "no_baseline", "note": "No earlier capture of these endpoints to compare with"}
        baseline = match["analysis_id"]
    return drift(_record(baseline), target)


# ---------------------------------------------------------------- lab builds

class BuildRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)
    traffic: list[dict[str, Any]] = Field(default_factory=list)
    label: str = Field("", max_length=80)
    impairment: str = Field("none", pattern="^(none|light|moderate|heavy)$")


@router.post("/lab/build")
def lab_build(req: BuildRequest):
    config = {k: v for k, v in req.config.items() if k in lab.DEFAULT_CONFIG}
    probe = {"ipsec_analysis": {"profile": {}, "ike_analysis": {}, "esp_analysis": {}}}
    problems = simulator.validate({k: v for k, v in config.items() if k in simulator.KNOB_KEYS}, probe["ipsec_analysis"])
    merged = {**lab.DEFAULT_CONFIG, **config}
    if merged["ike_version"] == "IKEv1" and any(t in merged["ike_encryption"] for t in ("GCM", "ChaCha")):
        problems.append("IKEv1 Phase 1 has no AEAD ciphers: choose a CBC cipher or IKEv2")
    if merged["ike_integrity"] == "None (AEAD)" and not any(t in merged["ike_encryption"] for t in ("GCM", "ChaCha")):
        problems.append("A CBC IKE cipher needs an integrity algorithm")
    if problems:
        raise HTTPException(422, "; ".join(sorted(set(problems))))
    traffic = lab.normalise_traffic(req.traffic)
    file_id, path, truth = lab.build(config, traffic, req.label or "Lab build", impairment=req.impairment)
    analysis_id, record = _run_and_save(file_id, path, truth, {"lab": True})
    return {"analysis_id": analysis_id, "file_id": file_id, "packets": truth.get("packets"),
            "score": record["security"]["overall_score"], "risk_level": record["security"]["risk_level"],
            "identification_accuracy": (record.get("ground_truth") or {}).get("accuracy"),
            "strongswan_profile": lab.strongswan_profile(config, traffic, file_id)}


@router.get("/lab/builds")
def lab_builds():
    return {"builds": lab.list_builds(), "defaults": lab.DEFAULT_CONFIG}


# ---------------------------------------------------------------- misconfiguration benchmark

class BenchmarkRequest(BaseModel):
    count: int = Field(40, ge=8, le=120)
    seed: int = Field(99, ge=0, le=2**31)


@router.get("/benchmark/latest")
def benchmark_latest():
    return benchmark.latest() or {"available": False}


@router.post("/benchmark/run")
def benchmark_run(req: BenchmarkRequest):
    if not (classifier.is_trained or classifier.load()):
        raise HTTPException(409, "The traffic classifier is still training")
    return benchmark.run_benchmark(req.count, req.seed)


# ---------------------------------------------------------------- fleet: explorer, link graph, triage

@router.get("/fleet/objects")
def fleet_objects():
    return {"rows": fleet.object_rows()}


@router.get("/fleet/graph")
def fleet_graph():
    return fleet.link_graph(fleet.object_rows())


class TriageUpdate(BaseModel):
    keys: list[str] = Field(..., min_length=1, max_length=500)
    status: str | None = None
    note: str | None = Field(None, max_length=2000)


@router.get("/triage")
def triage_inbox():
    return fleet.inbox(fleet.object_rows())


@router.post("/triage")
def triage_update(body: TriageUpdate):
    try:
        return fleet.update_triage(body.keys, body.status, body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
