"""
Real-time analysis API.

  GET  /api/live/capabilities        capture backends, interfaces, replay availability
  POST /api/live/start               start a replay or interface session
  GET  /api/live/sessions            recent sessions
  GET  /api/live/{id}                session status + latest snapshot
  POST /api/live/{id}/stop           stop (the capture is then analysed in full)
  GET  /api/live/{id}/events         Server-Sent Events stream (resumable via Last-Event-ID)
"""
import asyncio
import json
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.realtime.manager import SessionLimit, manager
from backend.realtime.sources import DEFAULT_FILTER, capture_tools, list_interfaces, scapy_available

router = APIRouter(prefix="/api/live", tags=["live"])
SESSION_ID = re.compile(r"^[a-f0-9]{10}$")


class LiveRequest(BaseModel):
    source: Literal["replay", "interface"] = "replay"
    file_id: str | None = None
    speed: float = Field(10, ge=0, le=200)      # replay pace; 0 = as fast as possible (benchmark)
    interface: str | None = None
    filter: str | None = None
    tool: Literal["tcpdump", "dumpcap"] | None = None


def _session(session_id: str):
    session = manager.get(session_id) if SESSION_ID.match(session_id) else None
    if session is None:
        raise HTTPException(404, "Live session not found")
    return session


@router.get("/capabilities")
def capabilities():
    tools = capture_tools()
    live = bool(tools) or scapy_available()
    return {
        "replay": True,
        "live_capture": live,
        "tools": sorted(tools),
        "scapy": scapy_available(),
        "interfaces": list_interfaces() if live else [],
        "default_filter": DEFAULT_FILTER,
        "note": None if live else "No capture backend found — install tcpdump (Linux) or Wireshark/dumpcap / "
                                  "Npcap (Windows). Replay of stored captures always works.",
    }


@router.post("/start")
def start(req: LiveRequest):
    try:
        if req.source == "replay":
            if not req.file_id:
                raise HTTPException(400, "file_id is required for a replay session")
            session = manager.start_replay(req.file_id, req.speed)
        else:
            if not req.interface:
                raise HTTPException(400, "interface is required for a live session")
            session = manager.start_interface(req.interface, req.filter, req.tool)
    except SessionLimit as exc:
        raise HTTPException(429, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    return session.summary()


@router.get("/sessions")
def sessions():
    return {"sessions": manager.list()}


@router.get("/{session_id}")
def status(session_id: str):
    session = _session(session_id)
    return {**session.summary(), "snapshot": session.snapshot, "metrics": session.metrics}


@router.post("/{session_id}/stop")
def stop(session_id: str):
    session = _session(session_id)
    session.stop()
    return session.summary()


@router.get("/{session_id}/events")
async def events(session_id: str, request: Request, since: int = 0):
    session = _session(session_id)
    last = int(request.headers.get("last-event-id") or since or 0)

    async def stream():
        nonlocal last
        idle = 0
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                return
            batch = session.events_since(last)
            for event in batch:
                last = event["seq"]
                yield f"id: {event['seq']}\nevent: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"
            if not batch:
                if not session.running and session.status != "finalizing":
                    yield "event: end\ndata: {}\n\n"
                    return
                idle += 1
                if idle % 30 == 0:
                    yield ": keep-alive\n\n"
            else:
                idle = 0
            await asyncio.sleep(0.3)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
