"""
Upload API routes.
Handles PCAP/PCAPNG file uploads.
"""
import uuid
import shutil
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException

from backend.config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_MB

router = APIRouter(prefix="/api/upload", tags=["upload"])

# In-memory storage for uploaded files metadata
uploaded_files: dict[str, dict] = {}


@router.post("")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload a PCAP/PCAPNG file for analysis."""
    # Validate file extension
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{suffix}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )
    
    # Read file
    content = await file.read()
    
    # Validate size
    if len(content) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size: {MAX_UPLOAD_SIZE_MB}MB",
        )
    
    # Save file
    file_id = str(uuid.uuid4())[:8]
    filename = f"{file_id}_{file.filename}"
    filepath = UPLOAD_DIR / filename
    
    with open(filepath, "wb") as f:
        f.write(content)
    
    # Store metadata
    uploaded_files[file_id] = {
        "id": file_id,
        "original_name": file.filename,
        "stored_name": filename,
        "path": str(filepath),
        "size": len(content),
        "status": "uploaded",
    }
    
    return {
        "file_id": file_id,
        "filename": file.filename,
        "size": len(content),
        "status": "uploaded",
        "message": "File uploaded successfully. Ready for analysis.",
    }


@router.get("/list")
async def list_uploads():
    """List all uploaded files."""
    # Also check for sample files
    sample_files = []
    from backend.config import SAMPLE_DIR
    if SAMPLE_DIR.exists():
        for f in SAMPLE_DIR.glob("*.pcap"):
            sample_files.append({
                "id": f.stem,
                "original_name": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "status": "sample",
                "is_sample": True,
            })
    
    uploads = list(uploaded_files.values())
    return {
        "uploads": uploads,
        "samples": sample_files,
        "total": len(uploads) + len(sample_files),
    }
