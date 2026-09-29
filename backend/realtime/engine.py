"""
Live (streaming) analysis sessions.

A session pulls frames from a Source on a reader thread and decodes each packet
immediately with the batch decoder. An analyzer thread then, once per second:

  * publishes throughput,
  * closes every 10-second window that has fully elapsed (windows sit on an absolute
    time grid, so they match the batch analysis exactly), classifies it, and applies
    causal HMM smoothing per tunnel,
  * every few seconds re-runs the batch analyzer and scorer on the retained state and
    raises an alert the moment a new finding appears.

Consumers read an append-only event log (Server-Sent Events in routes/live.py).
When the source ends or the session is stopped, the capture is analysed by the full
batch pipeline and saved as a normal analysis, so the live view and the final report
come from the same code.
"""
from __future__ import annotations

import logging
import struct
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

import numpy as np

from backend.analyzers.flow_extractor import WINDOW_SECONDS, extract_from_esp_packets
from backend.analyzers.ipsec_analyzer import analyze_ipsec
from backend.analyzers.pcap_parser import PacketDecoder
from backend.ml.model import _apply_distribution, classifier, forward_step
from backend.realtime.sources import Source
from backend.security.confidence import compute_ai_confidence
from backend.security.scoring_engine import assess_security
from backend.security.threat_matrix import generate_threat_matrix

logger = logging.getLogger(__name__)

HORIZON_SECONDS = 120          # ESP state retained for fingerprinting / replay / mode
MAX_ESP_RETAINED = 200_000
MAX_IKE_RETAINED = 20_000
SNAPSHOT_SECONDS = 3.0         # wall-clock interval between security re-assessments
WINDOW_GRACE = 1.0             # wait for late packets before closing a window
MAX_EVENTS = 5000
ALERT_SEVERITIES = {"Critical", "High", "Medium"}
KEY_FIELDS = ["ipsec_protocols", "ike_version", "exchange_mode", "mode", "ike_encryption", "key_exchange",
              "esp_encryption", "esp_integrity", "authentication_method", "pfs", "nat_traversal", "ip_version",
              "replay_protection", "traffic_types"]


class PcapStreamWriter:
    """Append frames to a pcap as they arrive (recording of a live session)."""

    def __init__(self, path: Path, linktype: int) -> None:
        self.path, self.linktype = path, linktype
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        self.fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)) + frame)

    def close(self) -> None:
        self.fh.close()


class LiveSession:
    def __init__(self, source: Source, label: str, finalize=None, record_path: Path | None = None) -> None:
        self.id = uuid.uuid4().hex[:10]
        self.source, self.label = source, label
        self.finalize = finalize            # callable(session) -> analysis_id, run after the stream ends
        self.record_path = record_path
        self.writer: PcapStreamWriter | None = None
        self.created = time.time()
        self.status = "starting"
        self.error: str | None = None
        self.analysis_id: str | None = None

        self._stop = threading.Event()
        self._lock = threading.Lock()          # guards packet state and the event log
        self._work = threading.Lock()          # serialises window closing and assessment
        self._decoder = PacketDecoder()
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._seq = 0

        self.packet_index = 0
        self.first_ts: float | None = None
        self.last_ts = 0.0
        self.counts = {"total": 0, "ike": 0, "ike_natt": 0, "esp": 0, "ah": 0, "natt_keepalive": 0, "other": 0}
        self.bytes = 0
        self._ike: list[dict] = []
        self._ah: deque[dict] = deque(maxlen=50_000)
        self._esp: deque[dict] = deque()
        self._sa_keys: set[str] = set()
        self._per_second: dict[int, list[int]] = {}
        self._closed_upto: int | None = None          # grid index of the first window not yet closed
        self._beliefs: dict[str, tuple[float, np.ndarray]] = {}
        self.predictions: list[dict[str, Any]] = []
        self._known_findings: set[str] = set()
        self.snapshot: dict[str, Any] | None = None
        self.metrics = {"analysis_ms": 0.0, "ingest_pps": 0.0, "max_lag_s": 0.0}

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self.status = "running"
        self._emit("status", {"status": "running", "source": self.source.description})
        threading.Thread(target=self._reader, name=f"live-read-{self.id}", daemon=True).start()
        threading.Thread(target=self._analyzer, name=f"live-analyze-{self.id}", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self.source.close()

    @property
    def running(self) -> bool:
        return self.status in ("starting", "running")

    # ------------------------------------------------------------ events

    def _emit(self, kind: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            self._events.append({"seq": self._seq, "type": kind, "t": self.last_ts, "data": data})

    def events_since(self, seq: int) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if e["seq"] > seq]

    @property
    def last_seq(self) -> int:
        return self._seq

    # ------------------------------------------------------------ ingest

    def _reader(self) -> None:
        started = time.monotonic()
        try:
            for ts, linktype, frame in self.source.frames(self._stop):
                self._ingest(ts, linktype, frame)
                # event-driven: close a window as soon as capture time passes its end (+ grace)
                if self._closed_upto is not None and ts - WINDOW_GRACE >= (self._closed_upto + 1) * WINDOW_SECONDS:
                    with self._work:
                        self._close_windows(ts)
                if self._stop.is_set():
                    break
            self.metrics["ingest_pps"] = round(self.packet_index / max(time.monotonic() - started, 1e-3))
        except Exception as exc:  # a broken source must end the session visibly, not silently
            logger.exception("Live source failed")
            self.error = str(exc)
        finally:
            if self.writer:
                self.writer.close()
            self._finish()

    def _ingest(self, ts: float, linktype: int, frame: bytes) -> None:
        if self.record_path is not None:
            if self.writer is None:
                self.writer = PcapStreamWriter(self.record_path, linktype)
            if linktype == self.writer.linktype:
                self.writer.write(ts, frame)
        self.packet_index += 1   # 1-based, like Wireshark frame numbers
        packet = self._decoder.decode(frame, linktype, ts, self.packet_index)
        kind = packet["protocol_type"]
        with self._lock:
            if self.first_ts is None:
                self.first_ts = ts
                self._closed_upto = int(ts // WINDOW_SECONDS)
            self.last_ts = max(self.last_ts, ts)
            self.counts["total"] += 1
            self.counts[kind] += 1
            self.bytes += packet["length"] or 0
            bucket = self._per_second.setdefault(int(ts), [0, 0, 0, 0])
            bucket[0] += 1
            bucket[1] += packet["length"] or 0
            bucket[2] += kind == "esp"
            bucket[3] += kind in ("ike", "ike_natt")
            if kind == "esp" and packet.get("spi"):
                self._esp.append(packet)
                while len(self._esp) > MAX_ESP_RETAINED or (self._esp and self._esp[0]["timestamp"] < ts - HORIZON_SECONDS):
                    self._esp.popleft()
            elif kind in ("ike", "ike_natt") and len(self._ike) < MAX_IKE_RETAINED:
                self._ike.append(packet)
            elif kind == "ah":
                self._ah.append(packet)

        if kind in ("ike", "ike_natt") and packet.get("ike"):
            m = packet["ike"]
            self._emit("ike", {"exchange": m["exchange_type"], "version": m["major_version"],
                               "response": bool(m["response_flag"]), "encrypted": m["encrypted_len"] > 0,
                               "length": m["length"], "src": packet["src_ip"], "dst": packet["dst_ip"],
                               "nat_t": kind == "ike_natt"})
        if kind in ("esp", "ah") and packet.get("spi"):
            key = f"{packet['spi']}|{packet['src_ip']}>{packet['dst_ip']}"
            if key not in self._sa_keys:
                self._sa_keys.add(key)
                self._emit("sa", {"protocol": kind.upper(), "spi": packet["spi"], "src": packet["src_ip"],
                                  "dst": packet["dst_ip"], "nat_t": packet.get("nat_t", False)})

    # ------------------------------------------------------------ analysis loop

    def _analyzer(self) -> None:
        last_snapshot = 0.0
        while not self._stop.is_set() and self.status == "running":
            self._stop.wait(1.0)
            if self.status != "running":
                break
            try:
                self._publish_rate()
                with self._work:
                    self._close_windows(self.source.clock())
                    if time.monotonic() - last_snapshot >= SNAPSHOT_SECONDS:
                        self._assess()
                        last_snapshot = time.monotonic()
            except Exception:
                logger.exception("Live analysis step failed")

    def _publish_rate(self) -> None:
        now = int(self.source.clock())
        with self._lock:
            recent = {s: v for s, v in self._per_second.items() if s > now - 120}
            self._per_second = recent
        series = [{"t": s, "packets": v[0], "bytes": v[1], "esp": v[2], "ike": v[3]} for s, v in sorted(recent.items())
                  if s <= now]
        self._emit("rate", {"series": series[-5:], "total_packets": self.counts["total"], "total_bytes": self.bytes})

    def _close_windows(self, now: float, final: bool = False) -> None:
        if self.first_ts is None:
            return
        closable = int(now // WINDOW_SECONDS) + (1 if final else 0)
        if not final:
            closable = int((now - WINDOW_GRACE) // WINDOW_SECONDS)
        if self._closed_upto is None:
            self._closed_upto = int(self.first_ts // WINDOW_SECONDS)
        if closable <= self._closed_upto:
            return
        lo, hi = self._closed_upto * WINDOW_SECONDS, closable * WINDOW_SECONDS
        with self._lock:
            subset = [p for p in self._esp if lo <= p["timestamp"] < hi and p.get("esp_payload_len")]
        self._closed_upto = closable
        if not subset or not (classifier.is_trained or classifier.load()):
            return
        windows = extract_from_esp_packets(subset)
        if not windows:
            return
        started = time.monotonic()
        preds = classifier.predict(windows, smooth=False)
        classes = list(classifier.model.classes_)
        for window, pred in sorted(zip(windows, preds), key=lambda wp: wp[0]["window_start"]):
            proba = np.array([pred["all_probabilities"][c] for c in classes])
            previous = self._beliefs.get(pred["flow_id"])
            prior = previous[1] if previous and abs(previous[0] - pred["window_start"]) < 1e-6 else None
            belief = forward_step(prior, proba)
            self._beliefs[pred["flow_id"]] = (pred["window_end"], belief)
            _apply_distribution(pred, belief, classes)
            # capture-time delay between the end of the window and its classification being published
            pred["latency_s"] = round(max(0.0, self.source.clock() - pred["window_end"]) + (time.monotonic() - started), 3)
            if self.source.realtime or getattr(self.source, "speed", 0) == 1:
                self.metrics["max_lag_s"] = max(self.metrics["max_lag_s"], pred["latency_s"])
            self.predictions.append(pred)
            self._emit("window", {k: pred[k] for k in ("flow_id", "window_start", "window_end", "packet_count",
                                                        "predicted_class", "predicted_label", "confidence",
                                                        "uncertain", "raw_class", "top_predictions")})
        if len(self.predictions) > 5000:
            self.predictions = self.predictions[-5000:]

    def _assess(self) -> None:
        with self._lock:
            packets = self._ike + list(self._esp) + list(self._ah)
        if not packets:
            return
        started = time.monotonic()
        packets.sort(key=lambda p: p["index"])
        analysis = analyze_ipsec({"packets": packets})
        if analysis.get("error"):
            return
        from backend.pipeline import traffic_evidence  # local import: pipeline imports the ML module too
        traffic = classifier.summarize(self.predictions)
        analysis["profile"]["traffic_types"] = traffic_evidence(traffic, None)
        security = assess_security(analysis, traffic)
        threats = generate_threat_matrix(security["findings"])
        confidence = compute_ai_confidence(analysis, traffic, security)
        self.metrics["analysis_ms"] = round((time.monotonic() - started) * 1000, 1)

        for finding in security["findings"]:
            if finding["id"] not in self._known_findings:
                self._known_findings.add(finding["id"])
                if finding["severity"] in ALERT_SEVERITIES:
                    self._emit("alert", {k: finding[k] for k in ("id", "title", "severity", "description",
                                                                  "evidence", "recommendation", "evidence_source")})

        profile = analysis["profile"]
        self.snapshot = {
            "capture_time": self.last_ts,
            "capture_elapsed": round(self.last_ts - (self.first_ts or self.last_ts), 1),
            "counts": dict(self.counts),
            "bytes": self.bytes,
            "security_associations": len(self._sa_keys),
            "profile": {k: {x: profile[k].get(x) for x in ("value", "source", "confidence", "evidence", "display")}
                        for k in KEY_FIELDS if k in profile},
            "security": {
                "overall_score": security["overall_score"], "risk_level": security["risk_level"],
                "risk_score": security["risk_score"], "coverage": security["coverage"],
                "severity_counts": security["severity_counts"],
                "categories": {k: {"label": c["label"], "score": c["score"], "rating": c["rating"]}
                               for k, c in security["categories"].items()},
            },
            "threats": [{k: t[k] for k in ("name", "risk_score", "risk_level", "likelihood", "impact")}
                        for t in threats["threats"][:5]],
            "ai_confidence": confidence,
            "traffic": {"mix": traffic.get("mix", {}), "windows": traffic.get("windows", 0),
                        "mean_confidence": traffic.get("mean_confidence"), "flows": traffic.get("flows", [])},
            "metrics": dict(self.metrics),
        }
        self._emit("snapshot", self.snapshot)

    # ------------------------------------------------------------ end of stream

    def _finish(self) -> None:
        stopped = self._stop.is_set()
        self.status = "finalizing"
        try:
            with self._work:
                self._close_windows(self.last_ts, final=True)
                self._assess()
        except Exception:
            logger.exception("Final live assessment failed")
        self._emit("status", {"status": "finalizing", "packets": self.packet_index, "error": self.error})
        if self.finalize and self.packet_index:
            try:
                self.analysis_id = self.finalize(self)
                if self.analysis_id:
                    self._emit("analysis", {"analysis_id": self.analysis_id})
            except Exception as exc:
                logger.exception("Finalizing live session failed")
                self.error = self.error or f"Full analysis failed: {exc}"
        self.status = "error" if self.error else ("stopped" if stopped else "finished")
        self._emit("status", {"status": self.status, "packets": self.packet_index, "error": self.error,
                              "analysis_id": self.analysis_id, "metrics": self.metrics})

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "label": self.label, "source": self.source.description, "status": self.status,
            "created": self.created, "packets": self.packet_index, "error": self.error,
            "analysis_id": self.analysis_id, "last_seq": self._seq,
            "capture_elapsed": round(self.last_ts - self.first_ts, 1) if self.first_ts else 0.0,
        }
