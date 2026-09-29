"""
On-disk persistence for uploads and analyses (JSON files under backend/data).

Uploads are stored as  <id>__<sanitised name>  so the index can be rebuilt from
the directory listing alone; analyses as  <id>.json  plus a capped packet list.
"""
from __future__ import annotations

import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any

import numpy as np

from backend.config import ANALYSIS_DIR, SAMPLE_DIR, STORED_PACKETS_LIMIT, UPLOAD_DIR

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] = {}
_CACHE_LIMIT = 8


def valid_id(value: str) -> bool:
    return bool(ID_PATTERN.match(value or ""))


def new_id() -> str:
    return uuid.uuid4().hex[:10]


def safe_filename(name: str) -> str:
    base = Path(name or "capture.pcap").name
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "capture.pcap"
    return cleaned[-100:]


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f"Not JSON serialisable: {type(obj)}")


# ---------------------------------------------------------------- uploads

def upload_path(file_id: str, original_name: str) -> Path:
    return UPLOAD_DIR / f"{file_id}__{safe_filename(original_name)}"


def list_uploads() -> list[dict[str, Any]]:
    uploads = []
    for path in sorted(UPLOAD_DIR.glob("*__*"), key=lambda p: p.stat().st_mtime, reverse=True):
        file_id, _, name = path.name.partition("__")
        uploads.append({"id": file_id, "original_name": name, "size": path.stat().st_size,
                        "status": "uploaded", "path": str(path)})
    return uploads


def sample_manifest() -> dict[str, Any]:
    manifest = SAMPLE_DIR / "manifest.json"
    if not manifest.exists():
        return {}
    try:
        return json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def resolve_capture(file_id: str) -> tuple[Path, dict[str, Any] | None] | None:
    """Return (path, ground truth or None) for an upload id or a sample name."""
    if not valid_id(file_id):
        return None
    for path in UPLOAD_DIR.glob(f"{file_id}__*"):
        return path, None
    if file_id.startswith("lab_"):
        from backend.intel.lab import resolve
        return resolve(file_id)
    manifest = sample_manifest()
    truth = manifest.get("samples", {}).get(file_id)
    if truth:
        path = SAMPLE_DIR / truth["file"]
        if path.exists():
            return path, truth
    return None


# ---------------------------------------------------------------- analyses

def save_analysis(analysis_id: str, file_id: str, result: dict[str, Any]) -> None:
    packets = result.pop("_packets", [])
    record = {"analysis_id": analysis_id, "file_id": file_id, **result}
    with _lock:
        (ANALYSIS_DIR / f"{analysis_id}.json").write_text(
            json.dumps(record, default=_json_default), encoding="utf-8")
        (ANALYSIS_DIR / f"{analysis_id}.packets.json").write_text(
            json.dumps({"total": len(packets), "packets": packets[:STORED_PACKETS_LIMIT]}, default=_json_default),
            encoding="utf-8")
        index = _read_index()
        index[analysis_id] = _summary(record)
        (ANALYSIS_DIR / "index.json").write_text(json.dumps(index), encoding="utf-8")
        _remember(analysis_id, json.loads(json.dumps(record, default=_json_default)))


def load_analysis(analysis_id: str) -> dict[str, Any] | None:
    if not valid_id(analysis_id):
        return None
    with _lock:
        if analysis_id in _cache:
            return _cache[analysis_id]
        path = ANALYSIS_DIR / f"{analysis_id}.json"
        if not path.exists():
            return None
        record = json.loads(path.read_text(encoding="utf-8"))
        _remember(analysis_id, record)
        return record


def load_packets(analysis_id: str) -> dict[str, Any] | None:
    if not valid_id(analysis_id):
        return None
    path = ANALYSIS_DIR / f"{analysis_id}.packets.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def list_analyses() -> list[dict[str, Any]]:
    with _lock:
        index = _read_index()
    return sorted(index.values(), key=lambda a: a.get("created", 0), reverse=True)


def _read_index() -> dict[str, Any]:
    path = ANALYSIS_DIR / "index.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}


def _remember(analysis_id: str, record: dict[str, Any]) -> None:
    _cache[analysis_id] = record
    while len(_cache) > _CACHE_LIMIT:
        _cache.pop(next(iter(_cache)))


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    security = record.get("security", {})
    profile = record.get("ipsec_analysis", {}).get("vpn_profile", {})
    return {
        "analysis_id": record["analysis_id"],
        "file_id": record["file_id"],
        "filename": record.get("parsed_metadata", {}).get("filename"),
        "created": record.get("created"),
        "total_packets": record.get("parsed_metadata", {}).get("total_packets"),
        "security_score": security.get("overall_score"),
        "risk_level": security.get("risk_level"),
        "findings_count": len(security.get("findings", [])),
        "critical_high": sum(1 for f in security.get("findings", []) if f["severity"] in ("Critical", "High")),
        "ike_version": profile.get("ike_version"),
        "ai_confidence": (record.get("ai_confidence") or {}).get("overall"),
        "fingerprint": ((record.get("intel") or {}).get("fingerprint") or {}).get("id"),
        "fingerprint_label": ((record.get("intel") or {}).get("fingerprint") or {}).get("label"),
        "endpoints": ((record.get("intel") or {}).get("fingerprint") or {}).get("endpoints"),
        "source": record.get("source"),
    }
