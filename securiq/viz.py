"""Terminal visualisations built from block, braille and box-drawing characters.

Everything returns rich `Text` / renderables so it composes into panels, tables, the TUI and plain CLI output.
"""
from __future__ import annotations

import math
from typing import Iterable, Sequence

from rich.console import Group
from rich.table import Table
from rich.text import Text

from securiq import theme as T

PARTIAL = " ▏▎▍▌▋▊▉█"
SPARK = "▁▂▃▄▅▆▇█"

# 3x5 block digits for the hero score
_DIGITS = {
    "0": ["███", "█ █", "█ █", "█ █", "███"], "1": [" █ ", "██ ", " █ ", " █ ", "███"],
    "2": ["███", "  █", "███", "█  ", "███"], "3": ["███", "  █", "███", "  █", "███"],
    "4": ["█ █", "█ █", "███", "  █", "  █"], "5": ["███", "█  ", "███", "  █", "███"],
    "6": ["███", "█  ", "███", "█ █", "███"], "7": ["███", "  █", "  █", "  █", "  █"],
    "8": ["███", "█ █", "███", "█ █", "███"], "9": ["███", "█ █", "███", "  █", "███"],
    "-": ["   ", "   ", "███", "   ", "   "], ".": ["   ", "   ", "   ", "   ", " █ "],
    "?": ["███", "  █", " ██", "   ", " █ "], "+": ["   ", " █ ", "███", " █ ", "   "], " ": ["   "] * 5,
}


def bar(value: float, maximum: float = 100.0, width: int = 20, colour: str | None = None,
        track: str = T.PANEL_HI) -> Text:
    """Horizontal bar with 1/8-cell resolution."""
    colour = colour or T.BLUE
    frac = 0.0 if maximum <= 0 or value is None else max(0.0, min(1.0, value / maximum))
    eighths = round(frac * width * 8)
    full, part = divmod(eighths, 8)
    text = Text("█" * full, style=colour)
    if part and full < width:
        text.append(PARTIAL[part], style=f"{colour} on {track}")
        full += 1
    text.append("█" * (width - full), style=track)
    return text


def score_bar(score: float | None, width: int = 20) -> Text:
    if score is None:
        return Text("n/a".ljust(width), style=T.DIM)
    return bar(score, 100, width, T.score_color(score))


def spark(values: Sequence[float], colour: str = T.BLUE, lo: float | None = None, hi: float | None = None) -> Text:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return Text("")
    lo = min(vals) if lo is None else lo
    hi = max(vals) if hi is None else hi
    span = (hi - lo) or 1.0
    return Text("".join(SPARK[min(7, max(0, int((v - lo) / span * 7.999)))] for v in vals), style=colour)


def big_number(value: float | int | str | None, colour: str) -> Text:
    s = "?" if value is None else (f"{value:.0f}" if isinstance(value, (int, float)) else str(value))
    rows = ["", "", "", "", ""]
    for ch in s[:4]:
        glyph = _DIGITS.get(ch, _DIGITS["?"])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return Text("\n".join(rows), style=f"bold {colour}")


def segmented(parts: Iterable[tuple[str, float, str]], width: int = 40) -> Text:
    """Stacked proportional bar: [(label, value, colour), …]."""
    parts = [p for p in parts if p[1] > 0]
    total = sum(p[1] for p in parts) or 1
    text = Text()
    used = 0
    for i, (_, v, colour) in enumerate(parts):
        n = width - used if i == len(parts) - 1 else max(1, round(v / total * width))
        n = min(n, width - used)
        text.append("█" * n, style=colour)
        used += n
    return text


def legend(parts: Iterable[tuple[str, float, str]], pct: bool = True) -> Text:
    parts = [p for p in parts if p[1] > 0]
    total = sum(p[1] for p in parts) or 1
    text = Text()
    for label, v, colour in parts:
        text.append("■ ", style=colour)
        text.append(f"{label} ", style=T.MUTED)
        text.append(f"{v / total * 100:.0f}%  " if pct else f"{v:g}  ", style=T.DIM)
    return text


def histogram(values: Sequence[float], lo: float = 0, hi: float = 100, bins: int = 10, height: int = 5,
              colour_fn=T.score_color) -> Text:
    """Vertical histogram, bin colour follows the bin centre."""
    counts = [0] * bins
    for v in values:
        if v is None:
            continue
        counts[min(bins - 1, max(0, int((v - lo) / (hi - lo) * bins)))] += 1
    peak = max(counts) or 1
    lines = []
    for level in range(height, 0, -1):
        row = Text()
        for i, c in enumerate(counts):
            colour = colour_fn(lo + (i + 0.5) * (hi - lo) / bins)
            cells = c / peak * height
            if cells >= level:
                ch = "██"
            elif cells > level - 1:
                ch = SPARK[min(7, int((cells - (level - 1)) * 8))] * 2
            else:
                ch = "  "
            row.append(ch + " ", style=colour)
        lines.append(row)
    axis = Text("".join(f"{int(lo + i * (hi - lo) / bins):<3d}"[:3] for i in range(bins)), style=T.DIM)
    return Text("\n").join([*lines, axis])


def gauge_ring(score: float | None, width: int = 30) -> Text:
    """Half-block scale with a marker: 0 ─── 40 ─── 70 ─── 100."""
    if score is None:
        return Text("no score", style=T.DIM)
    marks = Text()
    pos = round(score / 100 * (width - 1))
    for i in range(width):
        colour = T.score_color(i / (width - 1) * 100)
        marks.append("◆" if i == pos else "▬", style=f"bold {T.TEXT}" if i == pos else colour)
    return marks


def heat_matrix(grid: list[list[list[str]]], names: dict[str, str]) -> Group:
    """5×5 likelihood × impact matrix; cell colour = risk band, cell text = threat ordinals."""
    order: list[str] = []
    for row in grid:
        for cell in row:
            for t in cell:
                if t not in order:
                    order.append(t)
    index = {t: i + 1 for i, t in enumerate(order)}
    table = Table(box=None, show_header=False, padding=0, collapse_padding=True)
    table.add_column(justify="right", width=6)
    for _ in range(5):
        table.add_column(width=7, justify="center")
    for likelihood in range(5, 0, -1):
        cells = [Text(f"L{likelihood} ", style=T.DIM)]
        for impact in range(1, 6):
            risk = likelihood * impact
            colour = T.RED if risk >= 20 else T.ORANGE if risk >= 12 else T.GOLD if risk >= 6 else T.GREEN if risk >= 3 else T.BLUE
            ids = grid[likelihood - 1][impact - 1]
            label = " ".join(str(index[t]) for t in ids) if ids else "·"
            style = f"bold {T.BG} on {colour}" if ids else f"{colour} on {T.PANEL_HI}"
            cells.append(Text(f" {label:^5} ", style=style))
        table.add_row(*cells)
        table.add_row(*[""] * 6)
    axis = Table(box=None, show_header=False, padding=0)
    axis.add_column(width=6)
    for _ in range(5):
        axis.add_column(width=7, justify="center")
    axis.add_row("", *[Text(f"I{i}", style=T.DIM) for i in range(1, 6)])
    key = Table(box=None, show_header=False, padding=(0, 1))
    for t in order:
        key.add_row(Text(f"{index[t]}", style=f"bold {T.TEXT}"), Text(names.get(t, t), style=T.MUTED))
    return Group(table, axis, Text(""), key)


def timeline_strip(spans: list[dict], t0: float, t1: float, width: int = 60) -> list[Text]:
    """Gantt rows: [{label, start, end, colour}, …] → one row of blocks per span."""
    total = max(t1 - t0, 1e-6)
    rows = []
    for s in spans:
        a = int((s["start"] - t0) / total * width)
        b = max(a + 1, int((s["end"] - t0) / total * width))
        row = Text(f"{s['label'][:18]:<18} ", style=T.MUTED)
        row.append("·" * a, style=T.PANEL_HI)
        row.append("█" * (b - a), style=s.get("colour", T.BLUE))
        row.append("·" * max(0, width - b), style=T.PANEL_HI)
        rows.append(row)
    return rows


def time_axis(t0: float, t1: float, width: int = 60, prefix: int = 19) -> Text:
    total = t1 - t0
    text = Text(" " * prefix, style=T.DIM)
    ticks = 5
    cursor = 0
    for i in range(ticks + 1):
        label = f"{total * i / ticks:.0f}s"
        target = int(i * (width - len(label)) / ticks)
        text.append(" " * max(0, target - cursor) + label, style=T.DIM)
        cursor = target + len(label)
    return text


# ---------------------------------------------------------------- character canvas (link graph, ladders)

class Canvas:
    """A grid of styled cells: draw text, lines and boxes, then convert to Text."""

    def __init__(self, width: int, height: int) -> None:
        self.w, self.h = width, height
        self.cells = [[(" ", "") for _ in range(width)] for _ in range(height)]

    def put(self, x: int, y: int, ch: str, style: str = "") -> None:
        if 0 <= x < self.w and 0 <= y < self.h:
            self.cells[y][x] = (ch, style)

    def text(self, x: int, y: int, s: str, style: str = "") -> None:
        for i, ch in enumerate(s):
            self.put(x + i, y, ch, style)

    def line(self, x0: int, y0: int, x1: int, y1: int, ch: str = "·", style: str = "") -> None:
        dx, dy = abs(x1 - x0), abs(y1 - y0)
        sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
        err = dx - dy
        while True:
            if self.cells[y0][x0][0] == " " if 0 <= x0 < self.w and 0 <= y0 < self.h else False:
                self.put(x0, y0, ch, style)
            if x0 == x1 and y0 == y1:
                break
            e2 = 2 * err
            if e2 > -dy:
                err -= dy
                x0 += sx
            if e2 < dx:
                err += dx
                y0 += sy

    def to_text(self) -> Text:
        out = Text()
        for y, row in enumerate(self.cells):
            run, style = "", None
            for ch, st in row:
                if st != style and run:
                    out.append(run, style=style or "")
                    run = ""
                style = st
                run += ch
            if run:
                out.append(run, style=style or "")
            if y < self.h - 1:
                out.append("\n")
        return out


_LAYOUTS: dict[tuple, dict[str, tuple[float, float]]] = {}


def force_layout(nodes: list[str], edges: list[tuple[str, str]], width: int, height: int,
                 iterations: int = 260, seed: int = 7) -> dict[str, tuple[float, float]]:
    """Deterministic spring embedder, cached: animation frames reuse the same layout."""
    key = (tuple(nodes), tuple(edges), width, height, iterations, seed)
    if key not in _LAYOUTS:
        if len(_LAYOUTS) > 16:
            _LAYOUTS.clear()
        _LAYOUTS[key] = _force_layout(nodes, edges, width, height, iterations, seed)
    return _LAYOUTS[key]


def settle(pos: dict[str, tuple[float, float]], width: int, height: int, progress: float) -> dict[str, tuple[float, float]]:
    """Interpolate from a burst at the centre to the final layout (ease-out cubic), for the settling animation."""
    if progress >= 1:
        return pos
    t = 1 - (1 - max(0.0, progress)) ** 3
    cx, cy = width / 2, height / 2
    return {k: (cx + (x - cx) * t, cy + (y - cy) * t) for k, (x, y) in pos.items()}


def _force_layout(nodes: list[str], edges: list[tuple[str, str]], width: int, height: int,
                  iterations: int, seed: int) -> dict[str, tuple[float, float]]:
    """Small deterministic spring embedder (Fruchterman–Reingold) into a width × height box."""
    import random
    rng = random.Random(seed)
    n = len(nodes)
    if n == 0:
        return {}
    pos = {k: [rng.uniform(0.1, 0.9), rng.uniform(0.1, 0.9)] for k in nodes}
    k_const = math.sqrt(1.0 / n) * 0.9
    temp = 0.12
    neighbours = [(a, b) for a, b in edges if a in pos and b in pos]
    for it in range(iterations):
        disp = {k: [0.0, 0.0] for k in nodes}
        keys = list(nodes)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = keys[i], keys[j]
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy) or 1e-3
                f = k_const * k_const / d
                disp[a][0] += dx / d * f
                disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f
                disp[b][1] -= dy / d * f
        for a, b in neighbours:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 1e-3
            f = d * d / k_const
            disp[a][0] -= dx / d * f
            disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f
            disp[b][1] += dy / d * f
        for k in keys:
            dx, dy = disp[k]
            d = math.hypot(dx, dy) or 1e-3
            step = min(d, temp)
            pos[k][0] = min(0.98, max(0.02, pos[k][0] + dx / d * step))
            pos[k][1] = min(0.98, max(0.02, pos[k][1] + dy / d * step))
        temp = max(0.002, temp * 0.985)
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    return {k: (2 + (p[0] - x0) / ((x1 - x0) or 1) * (width - 6),
                1 + (p[1] - y0) / ((y1 - y0) or 1) * (height - 3)) for k, p in pos.items()}
