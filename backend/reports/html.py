"""Render executive / technical reports as self-contained, printable HTML (print → PDF from the browser)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _pct(value: Any, digits: int = 0) -> str:
    if value is None:
        return "—"
    return f"{float(value) * 100:.{digits}f}%"


def _score_class(score: Any) -> str:
    if score is None:
        return "na"
    score = float(score)
    return "good" if score >= 85 else "ok" if score >= 70 else "warn" if score >= 50 else "bad"


def _level_class(level: str | None) -> str:
    return {"Critical": "bad", "High": "warn", "Medium": "mid", "Low": "ok"}.get(level or "", "na")


_env.filters.update(pct=_pct, score_class=_score_class, level_class=_level_class)


def render_executive(report: dict[str, Any], threat_matrix: dict[str, Any]) -> str:
    return _env.get_template("executive.html").render(r=report, tm=threat_matrix)


def render_technical(report: dict[str, Any]) -> str:
    return _env.get_template("technical.html").render(r=report)
