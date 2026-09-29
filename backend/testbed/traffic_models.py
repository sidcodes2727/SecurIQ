"""
Application traffic models for the VPN testbed.

Each generator returns the *inner* packet sequence of one conversation as
(time, direction, l4_length, ip_protocol) tuples, where direction 0 is
client → server (the tunnel initiator's site) and l4_length includes the
TCP/UDP/ICMP header. The ESP model then wraps these into ESP payload lengths.

The models encode well-documented protocol behaviour (RTP packetisation
intervals, DASH segment fetching, TCP delayed ACKs, messaging keepalives)
rather than arbitrary distributions, so size and timing structure resembles
real encrypted captures.
"""
from __future__ import annotations

import math
import random

TCP, UDP, ICMP = 6, 17, 1
Event = tuple[float, int, int, int]

TRAFFIC_CLASSES = ["icmp", "web", "voip", "video", "email", "chat", "file_transfer"]
TRAFFIC_LABELS = {
    "icmp": "ICMP (ping)",
    "web": "Web browsing",
    "voip": "VoIP call",
    "video": "Video streaming",
    "email": "E-mail",
    "chat": "Chat / WhatsApp-like messaging",
    "file_transfer": "File transfer",
}


def generate_traffic(traffic_class: str, duration: float, rng: random.Random) -> list[Event]:
    events = _GENERATORS[traffic_class](duration, rng)
    events = [e for e in events if 0.0 <= e[0] < duration]
    events.sort(key=lambda e: e[0])
    return events


# ---------------------------------------------------------------- helpers

def _tcp_params(rng: random.Random) -> tuple[int, int]:
    """TCP header (32 B with timestamps as on Linux, else 20 B) and an MSS that fits inside a tunnel."""
    return (32 if rng.random() < 0.7 else 20), rng.randint(1340, 1400)


def _tcp_transfer(events: list[Event], t: float, direction: int, nbytes: int, rate_bps: float,
                  hdr: int, mss: int, rng: random.Random, ack_every: int = 2) -> float:
    n = max(1, math.ceil(nbytes / mss))
    gap = (mss + hdr + 40) * 8 / rate_bps
    for i in range(n):
        size = mss if i < n - 1 else max(1, nbytes - mss * (n - 1))
        events.append((t, direction, hdr + size, TCP))
        if i % ack_every == ack_every - 1 or i == n - 1:
            events.append((t + rng.uniform(0.0002, 0.003), 1 - direction, hdr, TCP))
        t += gap * rng.uniform(0.85, 1.15)
    return t


def _exchange(events: list[Event], t: float, rng: random.Random, hdr: int, rtt: float,
              turns: int, req: tuple[int, int], resp: tuple[int, int]) -> float:
    """Request/response turns (protocol handshakes, commands)."""
    for _ in range(turns):
        events.append((t, 0, hdr + rng.randint(*req), TCP))
        t += rtt * rng.uniform(0.9, 1.2) + rng.uniform(0.001, 0.05)
        events.append((t, 1, hdr + rng.randint(*resp), TCP))
        events.append((t + rng.uniform(0.0005, 0.01), 0, hdr, TCP))
        t += rng.uniform(0.005, 0.15)
    return t


# ---------------------------------------------------------------- generators

def _icmp(duration: float, rng: random.Random) -> list[Event]:
    interval = rng.choice([1.0, 1.0, 1.0, 0.5, 0.2])
    data = rng.choice([56, 56, 56, 32, 48, 64])
    rtt = rng.uniform(0.004, 0.08)
    events: list[Event] = []
    t = rng.uniform(0, interval)
    while t < duration:
        events.append((t, 0, 8 + data, ICMP))
        if rng.random() > 0.01:
            events.append((t + rtt * rng.uniform(0.9, 1.15), 1, 8 + data, ICMP))
        t += interval + rng.gauss(0, 0.003)
    return events


def _voip(duration: float, rng: random.Random) -> list[Event]:
    codec, payload, ptime = rng.choice([
        ("G.711", 160, 0.02), ("G.711", 240, 0.03), ("G.729", 20, 0.02),
        ("G.722", 160, 0.02), ("Opus", None, 0.02), ("Opus", None, 0.02),
    ])
    dtx = codec in ("Opus", "G.729") and rng.random() < 0.4
    events: list[Event] = []
    for direction in (0, 1):
        t = rng.uniform(0, ptime)
        talking, state_end = True, rng.expovariate(1 / 2.5)
        while t < duration:
            if dtx and t >= state_end:
                talking = not talking
                state_end = t + rng.expovariate(1 / (2.5 if talking else 1.5))
            if talking:
                size = payload if payload else rng.randint(60, 120)
                events.append((t, direction, 8 + 12 + size, UDP))
                t += max(0.001, ptime + rng.gauss(0, 0.0015))
            else:
                events.append((t, direction, 8 + 12 + rng.randint(10, 20), UDP))  # comfort noise
                t += 0.4
        t = rng.uniform(1, 5)
        while t < duration:  # RTCP reports
            events.append((t, direction, 8 + rng.randint(52, 100), UDP))
            t += rng.uniform(4.5, 5.5)
    return events


def _video(duration: float, rng: random.Random) -> list[Event]:
    quic = rng.random() < 0.3
    bitrate = rng.uniform(1.5e6, 8e6)
    segment = rng.choice([2.0, 4.0, 5.0, 6.0])
    link = rng.uniform(20e6, 100e6)
    rtt = rng.uniform(0.01, 0.06)
    hdr, mss = _tcp_params(rng)
    events: list[Event] = []

    t = rng.uniform(0, 0.5)
    startup = 3
    while t < duration:
        if quic:
            events.append((t, 0, 8 + rng.randint(80, 300), UDP))
        else:
            events.append((t, 0, hdr + rng.randint(350, 750), TCP))
        seg_bytes = int(bitrate * segment / 8 * rng.uniform(0.7, 1.3))
        start = t + rtt
        if quic:
            n = max(1, math.ceil(seg_bytes / 1300))
            gap = 1350 * 8 / link
            ack_every = rng.randint(2, 10)
            tt = start
            for i in range(n):
                events.append((tt, 1, 8 + rng.randint(1250, 1350), UDP))
                if i % ack_every == 0:
                    events.append((tt + rng.uniform(0.0003, 0.004), 0, 8 + rng.randint(35, 60), UDP))
                tt += gap * rng.uniform(0.85, 1.15)
            end = tt
        else:
            end = _tcp_transfer(events, start, 1, seg_bytes, link, hdr, mss, rng)
        if startup > 0:
            startup -= 1
            t = end + rng.uniform(0.01, 0.05)
        else:
            t = max(end, t + segment * rng.uniform(0.9, 1.1))
    return events


def _web(duration: float, rng: random.Random) -> list[Event]:
    events: list[Event] = []
    hdr, mss = _tcp_params(rng)
    t = rng.uniform(0, 1)
    while t < duration:
        rtt = rng.uniform(0.015, 0.09)
        link = rng.uniform(8e6, 60e6)
        parallel = rng.randint(2, 6)
        # TLS handshakes for each connection
        for c in range(parallel):
            tc = t + c * rng.uniform(0.001, 0.01)
            events.append((tc, 0, hdr + rng.randint(517, 600), TCP))
            _tcp_transfer(events, tc + rtt, 1, rng.randint(2500, 5000), link, hdr, mss, rng)
            events.append((tc + 2 * rtt, 0, hdr + rng.randint(60, 130), TCP))
        page_end = t + 2 * rtt
        n_objects = rng.randint(4, 35)
        for k in range(n_objects):
            start = t + 2 * rtt + rtt * (k // parallel) + rng.uniform(0, 0.02)
            events.append((start, 0, hdr + rng.randint(250, 900), TCP))
            size = min(int(rng.lognormvariate(math.log(15000), 1.4)), 800_000)
            page_end = max(page_end, _tcp_transfer(events, start + rtt, 1, size, link, hdr, mss, rng))
        t = page_end + min(20.0, 0.5 + rng.expovariate(1 / 6))
    return events


def _email(duration: float, rng: random.Random) -> list[Event]:
    events: list[Event] = []
    hdr, mss = _tcp_params(rng)
    t = rng.uniform(0, 2)
    while t < duration:
        rtt = rng.uniform(0.02, 0.12)
        t = _exchange(events, t, rng, hdr, rtt, rng.randint(6, 14), (10, 120), (20, 260))
        size = min(int(rng.lognormvariate(math.log(25000), 1.3)), 4_000_000)
        direction = rng.randint(0, 1)  # 0: SMTP submission, 1: IMAP fetch
        t = _tcp_transfer(events, t, direction, size, rng.uniform(4e6, 30e6), hdr, mss, rng)
        t = _exchange(events, t + rtt, rng, hdr, rtt, rng.randint(1, 3), (10, 60), (20, 120))
        t += 1 + rng.expovariate(1 / 8)
    return events


def _chat(duration: float, rng: random.Random) -> list[Event]:
    events: list[Event] = []
    hdr, mss = _tcp_params(rng)
    rtt = rng.uniform(0.03, 0.15)
    rate = rng.uniform(0.15, 0.8)
    keepalive = rng.uniform(15, 45)

    t = rng.uniform(0, keepalive)
    while t < duration:
        for direction in (0, 1):
            events.append((t + direction * rtt, direction, hdr + rng.randint(1, 20), TCP))
        t += keepalive

    t = 0.0
    while True:
        t += rng.expovariate(rate)
        if t >= duration:
            break
        sender = rng.randint(0, 1)
        if rng.random() < 0.4:
            events.append((max(0.0, t - rng.uniform(0.5, 3)), sender, hdr + rng.randint(25, 60), TCP))
        events.append((t, sender, hdr + rng.randint(80, 450), TCP))
        events.append((t + rtt, 1 - sender, hdr + rng.randint(30, 70), TCP))      # server ack
        events.append((t + rng.uniform(0.1, 1.0), 1 - sender, hdr + rng.randint(40, 90), TCP))  # receipt
        events.append((t + rtt + 0.001, sender, hdr, TCP))
        if rng.random() < 0.06:  # photo / voice note
            _tcp_transfer(events, t + rtt, sender, rng.randint(30_000, 300_000),
                          rng.uniform(5e6, 25e6), hdr, mss, rng)
    return events


def _file_transfer(duration: float, rng: random.Random) -> list[Event]:
    events: list[Event] = []
    hdr, mss = _tcp_params(rng)
    direction = rng.randint(0, 1)
    rate = rng.uniform(3e6, 20e6)
    rtt = rng.uniform(0.01, 0.08)
    t = _exchange(events, rng.uniform(0, 0.5), rng, hdr, rtt, rng.randint(4, 9), (30, 200), (30, 300))
    while t < duration:
        chunk_rate = rate * rng.uniform(0.8, 1.2)
        chunk = int(chunk_rate / 8 * 1.0)
        t = _tcp_transfer(events, t, direction, chunk, chunk_rate, hdr, mss, rng)
        events.append((t, 1 - direction, hdr + rng.randint(40, 100), TCP))  # SFTP/SMB status
    return events


_GENERATORS = {
    "icmp": _icmp,
    "web": _web,
    "voip": _voip,
    "video": _video,
    "email": _email,
    "chat": _chat,
    "file_transfer": _file_transfer,
}
