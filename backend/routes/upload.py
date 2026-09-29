"""
Upload API routes.

Hardening (OWASP file-upload guidance): extension allow-list, magic-number check,
streamed size limit, server-generated storage names (no client path components).
"""
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.analyzers.pcap_parser import is_capture_file
from backend.config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_MB
from backend.storage import list_uploads, new_id, safe_filename, sample_manifest, upload_path

router = APIRouter(prefix="/api/upload", tags=["upload"])

CHUNK_SIZE = 1 << 20


@router.post("")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload a PCAP/PCAPNG capture for analysis."""
    name = file.filename or "capture.pcap"
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Invalid file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    file_id = new_id()
    dest = upload_path(file_id, name)
    limit = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    size, head = 0, b""
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(CHUNK_SIZE):
                if len(head) < 4:
                    head += chunk[:4 - len(head)]
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"File too large. Maximum size: {MAX_UPLOAD_SIZE_MB} MB")
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise

    if not is_capture_file(head):
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "File is not a pcap or pcapng capture (unrecognised magic number)")

    return {
        "file_id": file_id,
        "filename": safe_filename(name),
        "size": size,
        "status": "uploaded",
        "message": "File uploaded successfully. Ready for analysis.",
    }


@router.get("/list")
def list_all():
    """Uploaded captures and the curated testbed samples."""
    uploads = [{k: v for k, v in u.items() if k != "path"} for u in list_uploads()]
    samples = []
    for sample_id, truth in sample_manifest().get("samples", {}).items():
        samples.append({
            "id": sample_id,
            "original_name": truth["file"],
            "description": truth.get("description"),
            "packets": truth.get("packets"),
            "status": "sample",
            "is_sample": True,
            "highlights": {
                "ike": f"{truth['ike_version']} {truth['exchange_mode'] if truth['ike_version'] == 'IKEv1' else ''}".strip(),
                "esp": truth.get("esp_suite") or "AH",
                "mode": truth["mode"],
                "ip": truth["ip_version"],
                "traffic": [s["class"] for s in truth["traffic_segments"]],
            },
        })
    from backend.intel.lab import list_builds
    lab = [{"id": b["id"], "label": b["label"], "created": b["created"], "packets": b.get("packets"),
            "config": b.get("config"), "derived_from": b.get("derived_from")} for b in list_builds()[:30]]
    return {"uploads": uploads, "samples": samples, "lab": lab, "total": len(uploads) + len(samples) + len(lab)}
