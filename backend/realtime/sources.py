"""
Packet sources for live sessions. Each yields (timestamp, linktype, frame bytes).

  ReplaySource  a stored capture paced by its own timestamps at N× speed (0 = as fast as possible)
  PipeSource    tcpdump / dumpcap writing pcap to stdout, read by the streaming pcap reader
  ScapySource   Scapy AsyncSniffer (fallback when no capture binary is installed)

Nothing is passed through a shell: capture tools get an argument list built from
validated interface names and BPF filters.
"""
from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterator

from backend.analyzers.pcap_parser import read_frames

Frame = tuple[float, int, bytes]

BPF_ALLOWED = re.compile(r"^[A-Za-z0-9 .:/()!&|<>=\-\[\]]{1,200}$")
IFACE_ALLOWED = re.compile(r"^[A-Za-z0-9 _.:{}\\\-()]{1,120}$")
DEFAULT_FILTER = "esp or ah or udp port 500 or udp port 4500"
WINDOWS_DUMPCAP = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe"


class Source:
    realtime = False
    description = ""

    def frames(self, stop: threading.Event) -> Iterator[Frame]:
        raise NotImplementedError

    def clock(self) -> float:
        """Current capture-time 'now' used to decide which windows are complete."""
        return time.time()

    def close(self) -> None:
        pass


class ReplaySource(Source):
    def __init__(self, path: Path, speed: float) -> None:
        self.path, self.speed = path, speed
        self.description = f"Replay of {path.name} at {'max' if speed == 0 else f'{speed:g}×'} speed"
        self._first_ts: float | None = None
        self._last_ts = 0.0
        self._next_ts = 0.0      # timestamp of the packet the reader is holding until it is due
        self._start = time.monotonic()
        self._done = False

    def frames(self, stop: threading.Event) -> Iterator[Frame]:
        with open(self.path, "rb") as fh:
            for ts, linktype, frame in read_frames(fh):
                if stop.is_set():
                    return
                if self._first_ts is None:
                    self._first_ts, self._start = ts, time.monotonic()
                self._next_ts = ts
                if self.speed > 0:
                    due = self._start + (ts - self._first_ts) / self.speed
                    while not stop.is_set() and (wait := due - time.monotonic()) > 0:
                        stop.wait(min(wait, 0.25))
                self._last_ts = max(self._last_ts, ts)
                yield ts, linktype, frame
        self._done = True

    def clock(self) -> float:
        """Capture time already fully delivered: never ahead of the packet still waiting to be released,
        so quiet gaps advance the clock (windows close on time) without skipping unread packets."""
        if self._first_ts is None:
            return 0.0
        if self.speed == 0 or self._done:
            return self._last_ts
        virtual = self._first_ts + (time.monotonic() - self._start) * self.speed
        return min(virtual, max(self._next_ts, self._last_ts))


class PipeSource(Source):
    realtime = True

    def __init__(self, tool: str, interface: str, bpf: str) -> None:
        binary = capture_tools().get(tool)
        if not binary:
            raise RuntimeError(f"{tool} is not installed")
        if tool == "tcpdump":
            self.args = [binary, "-i", interface, "-U", "-s", "0", "-w", "-", bpf]
        else:
            self.args = [binary, "-i", interface, "-q", "-P", "-w", "-", "-f", bpf]
        self.description = f"Live capture on {interface} via {tool}"
        self.proc: subprocess.Popen | None = None

    def frames(self, stop: threading.Event) -> Iterator[Frame]:
        self.proc = subprocess.Popen(self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            yield from read_frames(self.proc.stdout)
        finally:
            self.close()
        if self.proc.returncode not in (0, None, -15, 1) and not stop.is_set():
            err = self.proc.stderr.read().decode(errors="replace")[-300:] if self.proc.stderr else ""
            raise RuntimeError(f"capture tool exited: {err.strip()}")

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def scapy_linktype(pkt) -> int:
    """pcap link-layer type of a frame Scapy captured, judged by the layer it decoded first.

    Getting this wrong makes the parser skip the wrong number of header bytes: the Npcap loopback adapter frames start
    with a 4-byte BSD header (type 0), Linux 'any' captures with a cooked header (113 / 276), and only truly headerless
    frames are raw IP (101)."""
    from scapy.all import Ether
    from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Loopback
    if isinstance(pkt, Ether):
        return 1
    if isinstance(pkt, Loopback):
        return 0
    if isinstance(pkt, CookedLinux):
        return 113
    if isinstance(pkt, CookedLinuxV2):
        return 276
    return 101


class ScapySource(Source):
    realtime = True

    def __init__(self, interface: str | None, bpf: str) -> None:
        from scapy.all import conf
        if not conf.use_pcap:
            raise RuntimeError("libpcap/Npcap not available for Scapy")
        self.interface, self.bpf = interface, bpf
        self.description = f"Live capture on {interface or 'default interface'} via Scapy"
        self._queue: queue.Queue = queue.Queue(maxsize=100_000)
        self._sniffer = None

    def frames(self, stop: threading.Event) -> Iterator[Frame]:
        from scapy.all import AsyncSniffer

        def enqueue(pkt) -> None:
            linktype = scapy_linktype(pkt)
            try:
                self._queue.put_nowait((float(pkt.time), linktype, bytes(pkt)))
            except queue.Full:
                pass  # shed load rather than block the capture thread

        self._sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf, prn=enqueue, store=False)
        self._sniffer.start()
        try:
            while not stop.is_set():
                try:
                    yield self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
        finally:
            self.close()

    def close(self) -> None:
        if self._sniffer and getattr(self._sniffer, "running", False):
            self._sniffer.stop()


# ---------------------------------------------------------------- capabilities

def capture_tools() -> dict[str, str]:
    tools = {}
    for name in ("tcpdump", "dumpcap"):
        found = shutil.which(name)
        if found:
            tools[name] = found
    if "dumpcap" not in tools and WINDOWS_DUMPCAP.exists():
        tools["dumpcap"] = str(WINDOWS_DUMPCAP)
    return tools


def scapy_available() -> bool:
    try:
        from scapy.all import conf
        return bool(conf.use_pcap)
    except Exception:
        return False


def list_interfaces() -> list[str]:
    tools = capture_tools()
    for tool in ("dumpcap", "tcpdump"):
        if tool in tools:
            try:
                out = subprocess.run([tools[tool], "-D"], capture_output=True, text=True, timeout=10).stdout
                names = [line.split(". ", 1)[1].split(" ")[0] for line in out.splitlines() if ". " in line]
                if names:
                    return names
            except (OSError, subprocess.SubprocessError):
                pass
    try:
        from scapy.all import get_if_list
        return [str(i) for i in get_if_list()]
    except Exception:
        return []


def open_interface_source(interface: str, bpf: str, tool: str | None = None) -> Source:
    if not IFACE_ALLOWED.match(interface):
        raise ValueError("Invalid interface name")
    if not BPF_ALLOWED.match(bpf):
        raise ValueError("Capture filter contains unsupported characters")
    tools = capture_tools()
    chosen = tool or next((t for t in ("tcpdump", "dumpcap") if t in tools), None)
    if chosen:
        if chosen not in tools:
            raise RuntimeError(f"{chosen} is not installed")
        return PipeSource(chosen, interface, bpf)
    if scapy_available():
        return ScapySource(interface, bpf)
    raise RuntimeError("No capture backend: install tcpdump (Linux), Wireshark/dumpcap or Npcap (Windows)")
