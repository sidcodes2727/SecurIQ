"""
Testbed, dataset and evaluation routes (PS §a, deliverable "dataset used for training/testing").
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.analyzers.ike_constants import DH_NAMES
from backend.bootstrap import ensure_samples
from backend.config import DATASET_DIR
from backend.ml import evaluation
from backend.ml.model import classifier
from backend.testbed.build_dataset import build_dataset
from backend.testbed.esp_model import ESP_SUITES, IKE_SUITES
from backend.testbed.scenarios import AUTH_LABELS
from backend.testbed.traffic_models import TRAFFIC_LABELS

router = APIRouter(prefix="/api", tags=["testbed"])

DOWNLOADS = {
    "training_windows.csv": DATASET_DIR / "training_windows.csv",
    "testbed_windows.csv": DATASET_DIR / "testbed" / "windows.csv",
    "testbed_manifest.jsonl": DATASET_DIR / "testbed" / "manifest.jsonl",
}


class DatasetRequest(BaseModel):
    count: int = Field(30, ge=1, le=200)
    seed: int = Field(1, ge=0, le=2**31)


class EvaluationRequest(BaseModel):
    scenarios: int = Field(24, ge=4, le=60)
    seed: int = Field(2024, ge=0, le=2**31)


@router.get("/testbed/scenarios")
def list_scenarios():
    manifest = ensure_samples()
    return {"scenarios": list(manifest.get("samples", {}).values()), "generated_at": manifest.get("generated_at")}


@router.get("/testbed/matrix")
def configuration_matrix():
    """Dimensions of the configuration matrix the testbed can generate."""
    return {
        "ike_versions": ["IKEv2", "IKEv1 Main Mode", "IKEv1 Aggressive Mode"],
        "ike_suites": [{"key": s.key, "encryption": s.encryption_name, "integrity": s.integrity_name or "AEAD",
                        "prf": s.prf_name, "dh_group": f"{DH_NAMES[s.dh_group]} (group {s.dh_group})"}
                       for s in IKE_SUITES.values()],
        "esp_suites": [{"key": s.key, "label": s.label, "iv": s.iv, "block": s.block, "icv": s.icv,
                        "family": s.family} for s in ESP_SUITES.values()],
        "modes": ["Tunnel", "Transport"],
        "ip_versions": ["IPv4", "IPv6"],
        "pfs": ["enabled", "disabled"],
        "nat_traversal": ["off", "on (UDP 4500)"],
        "authentication": list(AUTH_LABELS.values()),
        "traffic": TRAFFIC_LABELS,
        "anomalies": ["duplicate sequence numbers", "counter reset", "ESP-NULL", "AH-only", "weak fallback proposals"],
    }


@router.post("/samples/generate")
def regenerate_samples():
    manifest = ensure_samples(force=True)
    return {"status": "success", "count": len(manifest["samples"]), "files": list(manifest["samples"])}


@router.post("/dataset/generate")
def generate_dataset(req: DatasetRequest):
    """Render N random configuration-matrix scenarios to a labelled PCAP dataset."""
    return {"status": "success", **build_dataset(DATASET_DIR / "testbed", req.count, req.seed)}


@router.get("/dataset/download/{name}")
def download(name: str):
    path = DOWNLOADS.get(name)
    if path is None or not path.exists():
        raise HTTPException(404, "Dataset file not available — generate it first")
    return FileResponse(path, filename=name)


@router.get("/evaluation/latest")
def latest_evaluation():
    return evaluation.latest() or {"available": False}


@router.post("/evaluation/run")
def run_evaluation(req: EvaluationRequest):
    if not (classifier.is_trained or classifier.load()):
        raise HTTPException(409, "The traffic classifier is still training")
    return evaluation.evaluate_end_to_end(req.scenarios, req.seed)
