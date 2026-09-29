"""
Analysis API routes: run the pipeline, and serve results, security assessment,
classification, and reports (JSON + printable HTML).

Endpoints doing CPU-bound work are plain `def`, so FastAPI runs them in its
thread pool instead of blocking the event loop.
"""
import json
import logging
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from backend.analyzers.pcap_parser import CaptureFormatError
from backend.bootstrap import TrainingInProgress, state, train_model
from backend.config import DATASET_DIR
from backend.ml.model import classifier
from backend.pipeline import run_pipeline
from backend.reports.html import render_executive, render_technical
from backend.storage import list_analyses, load_analysis, load_packets, new_id, resolve_capture, save_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analysis"])

HEAVY_KEYS = ("executive_report", "technical_report")


def _require(analysis_id: str) -> dict:
    record = load_analysis(analysis_id)
    if record is None:
        raise HTTPException(404, "Analysis not found")
    return record


@router.post("/analyze/{file_id}")
def run_analysis(file_id: str):
    """Run the complete pipeline on an uploaded capture or a testbed sample."""
    resolved = resolve_capture(file_id)
    if resolved is None:
        raise HTTPException(404, f"File not found: {file_id}")
    path, truth = resolved
    try:
        result = run_pipeline(str(path), truth)
    except CaptureFormatError as exc:
        raise HTTPException(400, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except Exception:
        logger.exception("Analysis failed for %s", file_id)
        raise HTTPException(500, "Analysis failed — see server log for details")

    analysis_id = new_id()
    result["created"] = time.time()
    result["source"] = {"file_id": file_id, "is_sample": truth is not None}
    save_analysis(analysis_id, file_id, result)
    security = result["security"]
    return {
        "analysis_id": analysis_id,
        "status": "complete",
        "summary": {
            "total_packets": result["parsed_metadata"]["total_packets"],
            "ike_detected": result["ipsec_analysis"]["ike_analysis"].get("detected", False),
            "esp_detected": result["ipsec_analysis"]["esp_analysis"].get("detected", False),
            "security_score": security["overall_score"],
            "risk_level": security["risk_level"],
            "classified_windows": len(result["classification"]),
            "findings_count": len(security["findings"]),
            "ai_confidence": result["ai_confidence"]["overall"],
            "seconds": result["pipeline_seconds"],
        },
    }


@router.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    record = _require(analysis_id)
    return {k: v for k, v in record.items() if k not in HEAVY_KEYS}


@router.get("/analysis/{analysis_id}/packets")
def get_packets(analysis_id: str, limit: int = 100, offset: int = 0):
    data = load_packets(analysis_id)
    if data is None:
        raise HTTPException(404, "Analysis not found")
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    stored = data["packets"]
    return {"total": data["total"], "stored": len(stored), "offset": offset, "limit": limit,
            "packets": stored[offset:offset + limit]}


@router.get("/analyses")
def get_analyses():
    analyses = list_analyses()
    return {"analyses": analyses, "count": len(analyses)}


# ---------------------------------------------------------------- security

@router.get("/security/{analysis_id}")
def get_security(analysis_id: str):
    return _require(analysis_id)["security"]


@router.get("/security/{analysis_id}/findings")
def get_findings(analysis_id: str):
    findings = _require(analysis_id)["security"]["findings"]
    return {"findings": findings, "count": len(findings)}


@router.get("/security/{analysis_id}/threat-matrix")
def get_threat_matrix(analysis_id: str):
    return _require(analysis_id)["threat_matrix"]


@router.get("/security/{analysis_id}/compliance")
def get_compliance(analysis_id: str):
    return _require(analysis_id)["security"]["compliance"]


# ---------------------------------------------------------------- ML

@router.get("/ml/classify/{analysis_id}")
def classify_traffic(analysis_id: str):
    record = _require(analysis_id)
    return {"classification": record["classification"], "traffic": record["traffic"],
            "model_info": classifier.get_model_info()}


@router.get("/ml/model-info")
def get_model_info():
    info = classifier.get_model_info()
    info["training_in_progress"] = state["model_training"]
    info["training_error"] = state["model_error"]
    return info


@router.post("/ml/train")
def retrain_model():
    try:
        metrics = train_model()
    except TrainingInProgress as exc:
        raise HTTPException(409, str(exc))
    return {"status": "success", "metrics": metrics}


@router.get("/dataset/info")
def get_dataset_info():
    info = dict(classifier.dataset_info or {})
    info["exists"] = (DATASET_DIR / "training_windows.csv").exists()
    testbed = DATASET_DIR / "testbed" / "summary.json"
    info["testbed"] = json.loads(testbed.read_text(encoding="utf-8")) if testbed.exists() else None
    return info


# ---------------------------------------------------------------- reports

@router.get("/reports/{analysis_id}/executive")
def get_executive_report(analysis_id: str):
    return _require(analysis_id)["executive_report"]


@router.get("/reports/{analysis_id}/technical")
def get_technical_report(analysis_id: str):
    return _require(analysis_id)["technical_report"]


@router.get("/reports/{analysis_id}/executive.html", response_class=HTMLResponse)
def get_executive_html(analysis_id: str):
    record = _require(analysis_id)
    return HTMLResponse(render_executive(record["executive_report"], record["threat_matrix"]))


@router.get("/reports/{analysis_id}/technical.html", response_class=HTMLResponse)
def get_technical_html(analysis_id: str):
    return HTMLResponse(render_technical(_require(analysis_id)["technical_report"]))


@router.get("/reports/{analysis_id}/export.json")
def export_json(analysis_id: str):
    record = _require(analysis_id)
    return Response(json.dumps(record, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="securiq-{analysis_id}.json"'})
