"""Registry of live sessions: creation, limits, and hand-off to the batch pipeline when a stream ends."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from backend.realtime.engine import LiveSession
from backend.realtime.sources import DEFAULT_FILTER, ReplaySource, open_interface_source
from backend.storage import new_id, resolve_capture, save_analysis, upload_path

MAX_ACTIVE = 3
KEEP_FINISHED = 12


class SessionLimit(RuntimeError):
    pass


def _full_analysis(path: Path, file_id: str, truth: dict[str, Any] | None) -> str:
    from backend.pipeline import run_pipeline  # imported lazily: pipeline pulls in the whole analysis stack
    result = run_pipeline(str(path), truth)
    analysis_id = new_id()
    result["created"] = time.time()
    result["source"] = {"file_id": file_id, "is_sample": truth is not None, "live": True}
    save_analysis(analysis_id, file_id, result)
    return analysis_id


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, LiveSession] = {}
        self._lock = threading.Lock()

    def _register(self, session: LiveSession) -> LiveSession:
        with self._lock:
            if sum(1 for s in self._sessions.values() if s.running) >= MAX_ACTIVE:
                raise SessionLimit(f"At most {MAX_ACTIVE} live sessions can run at once")
            finished = [sid for sid, s in self._sessions.items() if not s.running]
            for sid in finished[:-KEEP_FINISHED] if len(finished) > KEEP_FINISHED else []:
                del self._sessions[sid]
            self._sessions[session.id] = session
        session.start()
        return session

    def start_replay(self, file_id: str, speed: float) -> LiveSession:
        resolved = resolve_capture(file_id)
        if resolved is None:
            raise FileNotFoundError(f"Capture not found: {file_id}")
        path, truth = resolved
        source = ReplaySource(path, speed)
        return self._register(LiveSession(source, label=path.name.split("__", 1)[-1],
                                          finalize=lambda s: _full_analysis(path, file_id, truth)))

    def start_interface(self, interface: str, bpf: str | None = None, tool: str | None = None) -> LiveSession:
        source = open_interface_source(interface, bpf or DEFAULT_FILTER, tool)
        file_id = new_id()
        record = upload_path(file_id, f"live-{time.strftime('%Y%m%d-%H%M%S')}.pcap")
        return self._register(LiveSession(source, label=f"Live: {interface}", record_path=record,
                                          finalize=lambda s: _full_analysis(record, file_id, None)))

    def get(self, session_id: str) -> LiveSession | None:
        return self._sessions.get(session_id)

    def list(self) -> list[dict[str, Any]]:
        return [s.summary() for s in sorted(self._sessions.values(), key=lambda s: s.created, reverse=True)]


manager = SessionManager()
