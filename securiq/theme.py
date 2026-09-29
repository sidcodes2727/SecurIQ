"""Palette and small style helpers (Blueprint-dark / Gotham inspired: near-black canvas, muted chrome, saturated intents)."""
from __future__ import annotations

from rich.text import Text

BG = "#111418"
PANEL = "#1C2127"
PANEL_HI = "#252A31"
BORDER = "#383E47"
TEXT = "#F6F7F9"
MUTED = "#ABB3BF"
DIM = "#738091"

BLUE = "#4C90F0"
CYAN = "#3FA6DA"
TEAL = "#2AB6B0"
GREEN = "#3DCC91"
GOLD = "#FBD065"
ORANGE = "#EC9A3C"
RED = "#F0686C"
VIOLET = "#AD7BE9"

SEVERITY_COLOR = {"Critical": RED, "High": ORANGE, "Medium": GOLD, "Low": BLUE, "Informational": DIM}
SEVERITY_GLYPH = {"Critical": "◆", "High": "▲", "Medium": "●", "Low": "○", "Informational": "·"}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

SOURCE_COLOR = {"observed": GREEN, "inferred": GOLD, "not_observable": DIM, "simulated": VIOLET}
SOURCE_GLYPH = {"observed": "●", "inferred": "◐", "not_observable": "○", "simulated": "◇"}

STATUS_COLOR = {"pass": GREEN, "warn": GOLD, "fail": RED, "unknown": DIM, "good": GREEN, "info": BLUE,
                "critical": RED, "high": ORANGE, "medium": GOLD, "low": BLUE}

RISK_COLOR = {"Low Risk": GREEN, "Medium Risk": GOLD, "High Risk": ORANGE, "Critical Risk": RED, "Critical": RED}

NODE_COLOR = {"capture": BLUE, "gateway": TEAL, "fingerprint": VIOLET, "finding": RED, "traffic": GOLD, "config": DIM}
NODE_GLYPH = {"capture": "■", "gateway": "◉", "fingerprint": "◈", "finding": "▲", "traffic": "◆", "config": "●"}


def score_color(score: float | None) -> str:
    if score is None:
        return DIM
    if score >= 80:
        return GREEN
    if score >= 60:
        return GOLD
    if score >= 40:
        return ORANGE
    return RED


def risk_color(level: str | None) -> str:
    if not level:
        return DIM
    for key, colour in RISK_COLOR.items():
        if level.startswith(key.split()[0]):
            return colour
    return MUTED


def chip(label: str, colour: str, *, solid: bool = True) -> Text:
    """A tag: solid = dark text on colour, otherwise coloured text in brackets."""
    if solid:
        return Text(f" {label} ", style=f"bold {BG} on {colour}")
    return Text(f"[{label}]", style=f"bold {colour}")


def severity_chip(severity: str) -> Text:
    return chip(severity.upper() if severity != "Informational" else "INFO", SEVERITY_COLOR.get(severity, DIM))


def source_tag(source: str | None) -> Text:
    s = source or "not_observable"
    return Text(f"{SOURCE_GLYPH.get(s, '?')} {s.replace('_', ' ')}", style=SOURCE_COLOR.get(s, DIM))


def label(text: str) -> Text:
    """Gotham-style small-caps section label."""
    return Text(text.upper(), style=f"bold {DIM}")
