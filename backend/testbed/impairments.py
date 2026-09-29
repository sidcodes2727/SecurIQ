"""
Network impairments applied to an inner packet sequence before ESP framing.

Real tunnels are not clean lab links. These perturbations are used to
(a) augment classifier training so it does not overfit perfectly regular synthetic
    timing, and
(b) build a held-out *stress* set that measures robustness honestly.

- jitter:      Gaussian delay per packet (packets may reorder, as on real paths)
- loss:        dropped packets; lost TCP data segments are retransmitted after an RTO
- background:  other small flows multiplexed into the same SA (DNS, NTP, keepalives,
               telemetry) — site-to-site tunnels rarely carry one application alone
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from backend.testbed.traffic_models import TCP, UDP, Event


@dataclass(frozen=True)
class ImpairmentProfile:
    jitter_ms: tuple[float, float]
    loss: tuple[float, float]
    background_share: tuple[float, float]


PROFILES = {
    "none": ImpairmentProfile((0, 0), (0, 0), (0, 0)),
    "light": ImpairmentProfile((0, 3), (0, 0.01), (0, 0.05)),
    "moderate": ImpairmentProfile((1, 8), (0.005, 0.03), (0.03, 0.12)),
    "heavy": ImpairmentProfile((3, 15), (0.02, 0.06), (0.10, 0.25)),
}


def impair(events: list[Event], duration: float, rng: random.Random, level: str = "moderate") -> list[Event]:
    profile = PROFILES[level]
    if level == "none" or not events:
        return events
    jitter = rng.uniform(*profile.jitter_ms) / 1000
    loss = rng.uniform(*profile.loss)
    share = rng.uniform(*profile.background_share)

    out: list[Event] = []
    for t, direction, l4, proto in events:
        if rng.random() < loss:
            if proto == TCP and l4 > 100:  # retransmission after an RTO
                out.append((t + rng.uniform(0.2, 0.6), direction, l4, proto))
            continue
        out.append((max(0.0, t + abs(rng.gauss(0, jitter))), direction, l4, proto))

    if share > 0:
        out.extend(_background(len(events) * share / max(1 - share, 1e-6), duration, rng))
    out = [e for e in out if e[0] < duration]
    out.sort(key=lambda e: e[0])
    return out


def _background(count: float, duration: float, rng: random.Random) -> list[Event]:
    """Small multiplexed flows: DNS query/response pairs, NTP, TLS keepalives, telemetry."""
    events: list[Event] = []
    for _ in range(int(count / 2)):
        t = rng.uniform(0, duration)
        kind = rng.random()
        if kind < 0.5:    # DNS
            events += [(t, 0, 8 + rng.randint(28, 60), UDP), (t + rng.uniform(0.005, 0.05), 1, 8 + rng.randint(60, 220), UDP)]
        elif kind < 0.7:  # NTP
            events += [(t, 0, 56, UDP), (t + rng.uniform(0.005, 0.05), 1, 56, UDP)]
        else:             # keepalive / telemetry over TCP
            events += [(t, rng.randint(0, 1), 32 + rng.randint(0, 120), TCP), (t + rng.uniform(0.01, 0.1), rng.randint(0, 1), 32, TCP)]
    return events
