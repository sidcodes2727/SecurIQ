"""
Bounded live capture (PS §b "live network streams").

Sniffs IPsec traffic for a fixed duration with a BPF filter, saves it as an
upload, and hands it to the normal analysis pipeline. Requires libpcap/Npcap and
capture privileges (root / Administrator); without them the endpoint returns 503
with instructions instead of failing obscurely.
"""
import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.config import DEFAULT_CAPTURE_FILTER, MAX_CAPTURE_DURATION, MAX_CAPTURE_PACKETS
from backend.storage import new_id, upload_path

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/capture", tags=["capture"])

BPF_ALLOWED = re.compile(r"^[A-Za-z0-9 .:/()!&|<>=\-\[\]]{1,200}$")
IFACE_ALLOWED = re.compile(r"^[A-Za-z0-9 _.:{}\\\-()]{1,120}$")


class CaptureRequest(BaseModel):
    interface: str | None = None
    duration: int = Field(30, ge=1, le=MAX_CAPTURE_DURATION)
    filter: str = DEFAULT_CAPTURE_FILTER
    max_packets: int = Field(50_000, ge=1, le=MAX_CAPTURE_PACKETS)


def _scapy():
    from scapy.all import conf, get_if_list, sniff, wrpcap
    return conf, get_if_list, sniff, wrpcap


@router.get("/interfaces")
def interfaces():
    try:
        conf, get_if_list, _, _ = _scapy()
        names = [str(i) for i in get_if_list()]
        return {"available": bool(conf.use_pcap), "libpcap": bool(conf.use_pcap),
                "interfaces": names, "default_filter": DEFAULT_CAPTURE_FILTER,
                "note": None if conf.use_pcap else
                "libpcap/Npcap not detected — install Npcap (Windows) or run with capture privileges."}
    except Exception as exc:
        return {"available": False, "interfaces": [], "note": f"Capture backend unavailable: {exc}"}


@router.post("/start")
def start_capture(req: CaptureRequest):
    if not BPF_ALLOWED.match(req.filter):
        raise HTTPException(400, "Capture filter contains unsupported characters")
    if req.interface and not IFACE_ALLOWED.match(req.interface):
        raise HTTPException(400, "Invalid interface name")
    try:
        conf, _, sniff, wrpcap = _scapy()
        if not conf.use_pcap:
            raise PermissionError("libpcap/Npcap not available")
        packets = sniff(iface=req.interface or None, filter=req.filter, timeout=req.duration,
                        count=req.max_packets, store=True)
    except (PermissionError, OSError, RuntimeError) as exc:
        raise HTTPException(503, f"Live capture unavailable: {exc}. Install Npcap (Windows) / run as root "
                                 "(Linux), or capture with tcpdump/Wireshark and upload the file.")
    file_id = new_id()
    path = upload_path(file_id, f"live-capture-{file_id}.pcap")
    wrpcap(str(path), packets)
    return {"file_id": file_id, "filename": path.name.split("__", 1)[1], "packets": len(packets),
            "duration": req.duration, "status": "captured"}
