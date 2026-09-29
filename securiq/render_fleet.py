"""Renderables for fleet-wide views: operations dashboard, explorer, link graph, triage, testbed, live, model."""
from __future__ import annotations

import time
from collections import Counter
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from securiq import theme as T
from securiq import viz
from securiq.render import CLASS_COLOR, _trunc, kv_table, panel

SEV = ["Critical", "High", "Medium", "Low"]


# ---------------------------------------------------------------- KPI tiles

def tile(label: str, value: Any, colour: str = T.TEXT, sub: str = "") -> RenderableType:
    return Group(Text(label.upper(), style=f"bold {T.DIM}"), Text(str(value), style=f"bold {colour}"),
                 Text(sub or " ", style=T.DIM))


def kpis(rows: list[dict]) -> RenderableType:
    n = len(rows)
    scores = [r["score"] for r in rows if r["score"] is not None]
    avg = sum(scores) / len(scores) if scores else None
    crit = sum(1 for r in rows if any(f["severity"] == "Critical" for f in r["findings"]))
    noncomp = sum(1 for r in rows if r["policy_status"] != "Compliant")
    novel = sum(1 for r in rows if r["novelty"] == "novel")
    fps = len({r["fingerprint"] for r in rows})
    gws = len({g for r in rows for g in r["gateways"]})
    grid = Table.grid(expand=True, padding=(0, 2))
    for _ in range(6):
        grid.add_column(ratio=1)
    grid.add_row(tile("Captures", n, T.TEXT, f"{gws} gateways"),
                 tile("Mean score", "—" if avg is None else f"{avg:.0f}", T.score_color(avg), f"min {min(scores):.0f}" if scores else ""),
                 tile("With critical", crit, T.RED if crit else T.GREEN, "capture(s)"),
                 tile("Policy breaches", noncomp, T.ORANGE if noncomp else T.GREEN, f"of {n}"),
                 tile("Novel configs", novel, T.VIOLET, "unlike training"),
                 tile("Fingerprints", fps, T.VIOLET, "distinct configs"))
    return grid


def dashboard(rows: list[dict]) -> RenderableType:
    if not rows:
        return panel(Text("No analyses yet. Press  o  to open a capture, or run  securiq analyze <capture>.", style=T.DIM), "Operations")
    scores = [r["score"] for r in rows if r["score"] is not None]
    risk = Counter((r["risk_level"] or "n/a").split()[0] for r in rows)
    risk_parts = [(k, risk.get(k, 0), c) for k, c in (("Critical", T.RED), ("High", T.ORANGE), ("Medium", T.GOLD), ("Low", T.GREEN))]
    recurring = Counter(f["id"] for r in rows for f in r["findings"])
    titles = {f["id"]: (f["title"], f["severity"]) for r in rows for f in r["findings"]}
    rec_lines = []
    for fid, n in recurring.most_common(7):
        title, sev = titles[fid]
        rec_lines.append(Text.assemble((f"{T.SEVERITY_GLYPH[sev]} ", T.SEVERITY_COLOR[sev]), (f"{fid:<11}", T.DIM),
                                       (_trunc(title.split(':')[0], 34).ljust(35), T.TEXT),
                                       viz.bar(n, len(rows), 10, T.SEVERITY_COLOR[sev]), (f" {n}", T.MUTED)))

    def dist(title: str, values: list) -> RenderableType:
        c = Counter(str(v) for v in values if v is not None)
        top = c.most_common(6)
        peak = max([n for _, n in top], default=1)
        lines = [Text.assemble((f"{k[:16]:<17}", T.MUTED), viz.bar(n, peak, 8, T.BLUE), (f" {n}", T.DIM)) for k, n in top]
        return panel(Group(*lines), title)

    recent = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("CAPTURE", "SCORE", "", "RISK", "CONFIGURATION"):
        recent.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis")
    for r in rows[:9]:
        recent.add_row(_trunc(r["filename"].split("__", 1)[-1], 30), Text(f"{r['score']}", style=f"bold {T.score_color(r['score'])}"),
                       viz.score_bar(r["score"], 10), Text((r["risk_level"] or "").split()[0], style=T.risk_color(r["risk_level"])),
                       _trunc(r["fingerprint_label"], 56))
    grid_a = Table.grid(expand=True, padding=(0, 1))
    grid_a.add_column(ratio=1)
    grid_a.add_column(ratio=1)
    grid_a.add_row(panel(Group(viz.histogram(scores, 0, 100, 10, 6), Text("security score →", style=T.DIM)), "Score distribution"),
                   panel(Group(viz.segmented(risk_parts, 34), viz.legend(risk_parts, pct=False), Text(""), *rec_lines[:0]), "Risk posture"))
    grid_b = Table.grid(expand=True, padding=(0, 1))
    for _ in range(4):
        grid_b.add_column(ratio=1)
    grid_b.add_row(dist("IKE version", [r["ike_version"] for r in rows]),
                   dist("DH group", [f"{r['dh_group']} {r['dh_name']}" if r["dh_group"] else None for r in rows]),
                   dist("Authentication", [r["auth"] for r in rows]),
                   dist("PFS", [r["pfs"] for r in rows]))
    sev_total = Counter(f["severity"] for r in rows for f in r["findings"])
    sev_parts = [(s, sev_total.get(s, 0), T.SEVERITY_COLOR[s]) for s in SEV]
    return Group(panel(kpis(rows), "Fleet operations"), grid_a,
                 panel(Group(viz.segmented(sev_parts, 60), viz.legend(sev_parts, pct=False), Text(""), *rec_lines),
                       "Recurring findings across the fleet", f"{sum(sev_total.values())} occurrences"),
                 grid_b, panel(recent, "Recent captures"))


# ---------------------------------------------------------------- animated topology and ticker

def tunnels(rows: list[dict], limit: int = 7) -> list[dict]:
    """One entry per gateway pair (newest capture wins), with the packet rate that drives the animation."""
    seen: dict[frozenset, dict] = {}
    for r in rows:
        if len(r["gateways"]) == 2 and frozenset(r["gateways"]) not in seen:
            pps = (r["packets"] or 0) / max(r["duration"] or 1, 1)
            seen[frozenset(r["gateways"])] = {
                "a": r["gateways"][0], "b": r["gateways"][1], "score": r["score"], "pps": pps,
                "label": r["fingerprint_label"].split(" / ")[:3], "traffic": r["traffic"], "risk": r["risk_level"],
                "worst": next((f for f in r["findings"] if f["severity"] in ("Critical", "High")), None),
            }
    return list(seen.values())[:limit]


def topology(tuns: list[dict], frame: int, width: int = 120) -> RenderableType:
    """Animated tunnels: ciphertext packets flow in both directions at a density set by the real packet rate;
    the pipe colour is the tunnel's security score; periodic IKE rekey pulses travel along the pipe."""
    if not tuns:
        return panel(Text("No tunnels between two identified gateways yet — analyse a capture (o).", style=T.DIM), "Live tunnel topology")
    pipe_w = max(24, width - 70)
    lines: list[RenderableType] = []
    for i, t in enumerate(tuns):
        colour = T.score_color(t["score"])
        # 1 packet glyph per ~(8 - log rate) cells; faster tunnels are denser and move quicker
        import math
        density = max(3, 9 - int(math.log10(max(t["pps"], 1)) * 2))
        speed = 1 + int(math.log10(max(t["pps"], 1)))
        cells = [("━", colour)] * pipe_w
        cells = list(cells)
        for k in range(0, pipe_w, density):
            fwd = (frame * speed + k + i * 3) % pipe_w
            bwd = (pipe_w - 1) - ((frame * speed + k + density // 2 + i * 5) % pipe_w)
            cells[fwd] = ("▸", f"bold {T.TEXT}")
            cells[bwd] = ("◂", T.CYAN)
        pulse = (frame * 2 + i * 17) % (pipe_w * 4)
        if pulse < pipe_w:  # IKE rekey pulse, one pass every few seconds
            cells[pulse] = ("◆", f"bold {T.GOLD}")
        pipe = Text()
        for ch, st in cells:
            pipe.append(ch, style=st)
        blink = "◉" if (frame // 4 + i) % 2 else "◎"
        row = Text.assemble((f"{t['a'][:15]:>15} ", T.MUTED), (blink, f"bold {T.TEAL}"), pipe, (blink, f"bold {T.TEAL}"),
                            (f" {t['b'][:15]:<15}", T.MUTED), (f" {t['score']:>5}", f"bold {colour}"),
                            (f"  {' / '.join(t['label'])[:26]:<26}", T.DIM))
        lines.append(row)
        detail = Text(" " * 17)
        detail.append(f"{t['pps']:,.0f} pkt/s", style=T.DIM)
        if t["traffic"]:
            detail.append("  carrying " + ", ".join(t["traffic"][:3]), style=T.DIM)
        if t["worst"]:
            detail.append(f"   {T.SEVERITY_GLYPH[t['worst']['severity']]} {t['worst']['id']} {t['worst']['title'][:40]}",
                          style=T.SEVERITY_COLOR[t["worst"]["severity"]])
        lines.append(detail)
    sweep = "▁▂▃▄▅▆▇█▇▆▅▄▃▂"
    radar = "".join(sweep[(frame + j) % len(sweep)] for j in range(18))
    return panel(Group(*lines), "Live tunnel topology",
                 f"▸ outbound  ◂ inbound  ◆ IKE rekey   {radar}")


def ticker(rows: list[dict], frame: int, width: int = 140) -> Text:
    """Scrolling marquee of findings across the fleet."""
    items = []
    for r in rows[:30]:
        for f in r["findings"][:3]:
            items.append((f"{T.SEVERITY_GLYPH[f['severity']]} {f['id']} {r['filename'].split('__', 1)[-1][:24]} · {f['title'][:44]}",
                          T.SEVERITY_COLOR[f["severity"]]))
    if not items:
        return Text(" ● all quiet — no findings in the fleet", style=T.GREEN)
    segs: list[tuple[str, str]] = []
    for s, c in items:
        segs += [(s, c), ("     ", "")]
    total = sum(len(s) for s, _ in segs)
    off = (frame * 2) % total
    out = Text(" LIVE ▌ ", style=f"bold {T.BG} on {T.RED}" if frame // 5 % 2 else f"bold {T.BG} on {T.ORANGE}")
    stream = segs * 3
    pos = 0
    shown = 0
    for s, c in stream:
        if pos + len(s) <= off:
            pos += len(s)
            continue
        start = max(0, off - pos)
        chunk = s[start: start + (width - shown)]
        out.append(chunk, style=c)
        shown += len(chunk)
        pos += len(s)
        if shown >= width:
            break
    return out


# ---------------------------------------------------------------- explorer

def explorer_table(rows: list[dict], limit: int = 200) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c, kw in (("ID", {}), ("CAPTURE", {}), ("SRC", {}), ("SCORE", {"justify": "right"}), ("RISK", {}), ("IKE", {}),
                  ("ENCRYPTION", {}), ("DH", {}), ("PFS", {}), ("AUTH", {}), ("POLICY", {}), ("FINDINGS", {})):
        t.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis", **kw)
    for r in rows[:limit]:
        sev = "".join(Text(f"{r['severity_counts'].get(s, 0)}", style=T.SEVERITY_COLOR[s]).plain.ljust(3) for s in SEV[:3])
        t.add_row(r["analysis_id"], _trunc(r["filename"].split("__", 1)[-1], 28), r["source"],
                  Text(str(r["score"]), style=f"bold {T.score_color(r['score'])}"),
                  Text((r["risk_level"] or "").split()[0], style=T.risk_color(r["risk_level"])),
                  r["ike_version"] or "—", _trunc(r["ike_encryption"] or "—", 16), str(r["dh_group"] or "—"),
                  Text(r["pfs"] or "—", style=T.GREEN if r["pfs"] == "on" else T.ORANGE if r["pfs"] == "off" else T.DIM),
                  r["auth"] or "—", Text(_trunc(r["policy_status"], 10), style=T.GREEN if r["policy_status"] == "Compliant" else T.ORANGE),
                  Text.assemble(*[(f"{r['severity_counts'].get(s, 0)} ", T.SEVERITY_COLOR[s]) for s in SEV[:3]]))
    return t


def facets(facet_counts: dict[str, dict[str, int]]) -> RenderableType:
    lines: list[RenderableType] = []
    for field, counts in facet_counts.items():
        lines.append(Text(field.upper(), style=f"bold {T.DIM}"))
        for value, n in list(counts.items())[:6]:
            lines.append(Text.assemble(("  ", ""), (f"{field}:{value.split()[0]}", T.BLUE), (f"  {n}", T.MUTED)))
    return Group(*lines)


def row_detail(r: dict) -> RenderableType:
    fl = [Text.assemble(T.severity_chip(f["severity"]), " ", (f["id"], T.DIM), " ", (_trunc(f["title"], 56), T.TEXT)) for f in r["findings"][:8]]
    return Group(
        Text(r["filename"].split("__", 1)[-1], style=f"bold {T.TEXT}"),
        Text.assemble((f"{r['score']} ", f"bold {T.score_color(r['score'])}"), viz.score_bar(r["score"], 20), (f"  {r['risk_level']}", T.MUTED)),
        Text(""),
        kv_table([("Configuration", Text(r["fingerprint_label"], style=T.VIOLET)), ("Fingerprint", r["fingerprint"]),
                  ("Gateways", ", ".join(r["gateways"]) or "—"), ("Encryption", f"{r['ike_encryption']} / {r['ike_integrity']}"),
                  ("Key exchange", f"{r['dh_name']} (group {r['dh_group']})"), ("Traffic", ", ".join(r["traffic"]) or "—"),
                  ("Policy", f"{r['policy_status']} ({r['policy_fail']} fail)"), ("Novelty", r["novelty"]),
                  ("Privacy", f"confidentiality {r['confidentiality']} · metadata {r['metadata_privacy']}"),
                  ("Effective strength", f"{r['strength_bits']} bit" if r["strength_bits"] else "—")], 18),
        Text(""), *fl)


# ---------------------------------------------------------------- link graph

def graph_canvas(graph: dict, width: int, height: int, selected: str | None = None, visible_types: set[str] | None = None,
                 focus: set[str] | None = None, progress: float = 1.0) -> tuple[Text, dict[str, tuple[int, int]], list[str]]:
    """Force-directed layout drawn on a character canvas. Returns (text, node positions, drawn node ids).
    `progress` < 1 draws an intermediate frame of the settling animation."""
    types = visible_types or set(T.NODE_COLOR)
    nodes = [n for n in graph["nodes"] if n["type"] in types and (focus is None or n["id"] in focus)]
    ids = {n["id"] for n in nodes}
    edges = [(e["source"], e["target"]) for e in graph["edges"] if e["source"] in ids and e["target"] in ids]
    pos = viz.settle(viz.force_layout([n["id"] for n in nodes], edges, width, height), width, height, progress)
    canvas = viz.Canvas(width, height)
    neighbours = {selected} | {b for a, b in edges if a == selected} | {a for a, b in edges if b == selected} if selected else set()
    for a, b in edges:
        hot = selected in (a, b)
        (x0, y0), (x1, y1) = pos[a], pos[b]
        canvas.line(int(x0), int(y0), int(x1), int(y1), "·" if not hot else "•", T.BLUE if hot else T.BORDER)
    cells: dict[str, tuple[int, int]] = {}
    taken: set[tuple[int, int]] = set()
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        x, y = int(pos[n["id"]][0]), int(pos[n["id"]][1])
        cells[n["id"]] = (x, y)
        taken.add((x, y))
        colour = T.NODE_COLOR[n["type"]]
        if n["type"] in ("capture", "finding") and n.get("severity"):
            colour = T.SEVERITY_COLOR.get(n["severity"], colour)
        dim = selected is not None and n["id"] not in neighbours
        canvas.put(x, y, T.NODE_GLYPH[n["type"]],
                   f"bold {T.BG} on {T.TEXT}" if n["id"] == selected else (T.DIM if dim else f"bold {colour}"))

    rank = {"gateway": 0, "fingerprint": 1, "capture": 2, "finding": 3, "traffic": 4, "config": 5}

    def priority(n: dict) -> tuple:
        sev = T.SEVERITY_RANK.get(n.get("severity") or "Informational", 4)
        return (0 if n["id"] == selected else 1 if n["id"] in neighbours else 2, rank[n["type"]], sev, -n.get("degree", 0))

    budget = 60 if selected else 26
    for n in sorted(nodes, key=priority):
        if budget <= 0:
            break
        chosen = n["id"] == selected
        if selected and n["id"] not in neighbours:
            continue
        if not selected and n["type"] in ("traffic", "config"):
            continue
        label = _trunc(n["label"].split("__", 1)[-1], 26)
        x, y = cells[n["id"]]
        lx = x + 2
        if lx + len(label) >= width:
            lx = max(0, x - len(label) - 1)
        if any((xx, y) in taken for xx in range(lx - 1, lx + len(label) + 1) if (xx, y) != (x, y)) and not chosen:
            continue
        canvas.text(lx, y, label, f"bold {T.TEXT}" if chosen else T.MUTED)
        for xx in range(lx - 1, lx + len(label) + 1):
            taken.add((xx, y))
        budget -= 1
    return canvas.to_text(), cells, [n["id"] for n in nodes]


def node_detail(graph: dict, node_id: str) -> RenderableType:
    node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
    if node is None:
        return Text("Select a node", style=T.DIM)
    linked = []
    for e in graph["edges"]:
        other = e["target"] if e["source"] == node_id else e["source"] if e["target"] == node_id else None
        if other:
            o = next((n for n in graph["nodes"] if n["id"] == other), None)
            if o:
                linked.append(Text.assemble((f"{T.NODE_GLYPH[o['type']]} ", T.NODE_COLOR[o["type"]]), (_trunc(o["label"].split("__", 1)[-1], 40), T.TEXT),
                                            (f"  {e['kind']}", T.DIM)))
    return Group(Text.assemble((f"{T.NODE_GLYPH[node['type']]} ", f"bold {T.NODE_COLOR[node['type']]}"), (node["label"].split("__", 1)[-1], f"bold {T.TEXT}")),
                 Text(f"{node['type'].upper()} · {node.get('sub', '')}", style=T.DIM), Text(""),
                 kv_table([(k, v) for k, v in (node.get("props") or {}).items()], 16), Text(""),
                 Text(f"LINKED ({len(linked)})", style=f"bold {T.DIM}"), *linked[:12])


def graph_insights(graph: dict, rows: list[dict]) -> RenderableType:
    nodes = graph["nodes"]
    recurring = sorted((n for n in nodes if n["type"] == "finding" and len(n["captures"]) > 1), key=lambda n: -len(n["captures"]))[:5]
    shared = sorted((n for n in nodes if n["type"] == "fingerprint" and len(n["captures"]) > 1), key=lambda n: -len(n["captures"]))[:4]
    by_gw: dict[str, set[str]] = {}
    for r in rows:
        for g in r["gateways"]:
            by_gw.setdefault(g, set()).add(r["fingerprint"])
    drifted = [g for g, fps in by_gw.items() if len(fps) > 1]
    lines: list[RenderableType] = [Text("RECURRING FINDINGS", style=f"bold {T.DIM}")]
    lines += [Text.assemble((f"▲ {n['label'][:34]:<36}", T.TEXT), (f"{len(n['captures'])} captures", T.MUTED)) for n in recurring] or [Text("none", style=T.DIM)]
    lines += [Text(""), Text("SHARED CONFIGURATIONS", style=f"bold {T.DIM}")]
    lines += [Text.assemble((f"◈ {n['label']:<16}", T.VIOLET), (f"{len(n['captures'])} captures", T.MUTED)) for n in shared] or [Text("none", style=T.DIM)]
    lines += [Text(""), Text("GATEWAYS WITH CONFIGURATION DRIFT", style=f"bold {T.DIM}")]
    lines += [Text.assemble(("◉ ", T.TEAL), (g, T.TEXT), (f"  {len(by_gw[g])} configurations", T.ORANGE)) for g in drifted] or [Text("none", style=T.DIM)]
    counts = "  ".join(f"{T.NODE_GLYPH[k]} {k} {v}" for k, v in graph["counts"].items())
    return Group(*lines, Text(""), Text(counts, style=T.DIM))


# ---------------------------------------------------------------- triage

STATUS_STYLE = {"new": T.BLUE, "investigating": T.GOLD, "accepted": T.VIOLET, "resolved": T.GREEN, "false_positive": T.DIM}


def inbox_table(items: list[dict], selected_keys: set[str] | None = None) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("", "SEV", "FINDING", "CAPTURE", "STATUS", "NOTE"):
        t.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis")
    for i in items:
        t.add_row("■" if selected_keys and i["key"] in selected_keys else "", T.severity_chip(i["severity"]),
                  Text.assemble((f"{i['finding_id']} ", T.DIM), (_trunc(i["title"], 44), T.TEXT)),
                  _trunc(i["filename"].split("__", 1)[-1], 22),
                  Text(i["status"].replace("_", " "), style=STATUS_STYLE.get(i["status"], T.MUTED)), _trunc(i["note"], 24))
    return t


def inbox_counts(inbox: dict) -> RenderableType:
    parts = [(s.replace("_", " "), n, STATUS_STYLE[s]) for s, n in inbox["counts"].items()]
    return Group(viz.segmented(parts, 50), viz.legend(parts, pct=False))


# ---------------------------------------------------------------- captures & samples

def capture_lists(caps: dict) -> RenderableType:
    st = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("SAMPLE", "IKE", "ESP SUITE", "MODE", "IP", "TRAFFIC", "PACKETS"):
        st.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis")
    for s in caps["samples"]:
        st.add_row(Text(s["id"], style=T.TEXT), s["ike"], s["esp"], s["mode"], s["ip"], ",".join(s["traffic"]), str(s["packets"]))
    parts: list[RenderableType] = [panel(st, "Testbed samples (ground truth included)", "securiq analyze <name>")]
    if caps["uploads"]:
        ut = Table(box=None, show_header=False, padding=(0, 2))
        for u in caps["uploads"][:20]:
            ut.add_row(Text(u["id"], style=T.BLUE), u["file"], f"{u['size'] / 1024:.1f} kB")
        parts.append(panel(ut, "Uploads"))
    if caps["lab"]:
        lt = Table(box=None, show_header=False, padding=(0, 2))
        for b in caps["lab"][:20]:
            lt.add_row(Text(b["id"], style=T.VIOLET), b["label"], str(b.get("packets") or ""))
        parts.append(panel(lt, "Digital-twin lab builds"))
    return Group(*parts)


def analyses_table(items: list[dict]) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("#", "ID", "CAPTURE", "WHEN", "SCORE", "RISK", "FINDINGS", "AI CONF", "CONFIGURATION"):
        t.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis")
    for i, a in enumerate(items, 1):
        t.add_row(f"@{i}", Text(a["analysis_id"], style=T.BLUE), _trunc((a.get("filename") or "").split("__", 1)[-1], 30),
                  time.strftime("%m-%d %H:%M", time.localtime(a.get("created") or 0)),
                  Text(str(a.get("security_score")), style=f"bold {T.score_color(a.get('security_score'))}"),
                  Text(a.get("risk_level") or "", style=T.risk_color(a.get("risk_level"))),
                  f"{a.get('findings_count')} ({a.get('critical_high')} crit/high)",
                  f"{(a.get('ai_confidence') or 0) * 100:.0f}%", _trunc(a.get("fingerprint_label") or "", 50))
    return t


# ---------------------------------------------------------------- testbed, model, evaluation

def matrix(m: dict) -> RenderableType:
    ike = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("IKE SUITE", "ENCRYPTION", "INTEGRITY", "PRF", "DH"):
        ike.add_column(c, style=T.MUTED)
    for s in m["ike_suites"]:
        ike.add_row(s["key"], s["encryption"], s["integrity"], s["prf"], s["dh"])
    esp = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("ESP SUITE", "LABEL", "FAMILY", "IV", "BLOCK", "ICV"):
        esp.add_column(c, style=T.MUTED)
    for s in m["esp_suites"]:
        esp.add_row(s["key"], s["label"], s["family"], str(s["iv"]), str(s["block"]), str(s["icv"]))
    dims = kv_table([("IKE versions", ", ".join(m["ike_versions"])), ("Modes", ", ".join(m["modes"])),
                     ("IP versions", ", ".join(m["ip_versions"])), ("PFS", ", ".join(m["pfs"])),
                     ("NAT traversal", ", ".join(m["nat_traversal"])), ("Authentication", ", ".join(m["authentication"])),
                     ("Traffic classes", ", ".join(m["traffic"].values())), ("Anomalies", ", ".join(m["anomalies"]))], 18)
    return Group(panel(dims, "Configuration matrix"), panel(ike, f"{len(m['ike_suites'])} IKE suites"), panel(esp, f"{len(m['esp_suites'])} ESP suites"))


def model(info: dict) -> RenderableType:
    mt = info["metrics"]
    head = kv_table([("Model", f"{info['model_type']}  v{info['model_version']}"), ("Estimators", info["n_estimators"]),
                     ("Features", info["n_features"]), ("Window", f"{info['window_seconds']:.0f} s"),
                     ("Smoothing", info["smoothing"]), ("Uncertain below", f"{info['uncertain_threshold'] * 100:.0f}% confidence"),
                     ("Trained", info.get("trained_at"))], 18)
    perf = Table.grid(expand=True, padding=(0, 3))
    for _ in range(4):
        perf.add_column(ratio=1)
    perf.add_row(tile("Accuracy", f"{mt['accuracy'] * 100:.1f}%", T.GREEN, "held-out"), tile("Macro F1", f"{mt['f1_macro'] * 100:.1f}%", T.GREEN, ""),
                 tile("Stress accuracy", f"{mt['stress_accuracy'] * 100:.1f}%", T.GOLD, "heavy impairment"),
                 tile("ROC AUC", f"{mt['roc_auc_ovr']:.3f}", T.BLUE, f"CV {mt['cv_mean_accuracy'] * 100:.1f}% ± {mt['cv_std_accuracy'] * 100:.1f}"))
    rep = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("CLASS", "PRECISION", "RECALL", "F1", "SUPPORT"):
        rep.add_column(c, style=T.MUTED)
    for cls, r in mt["classification_report"].items():
        if isinstance(r, dict) and cls in info["classes"]:
            rep.add_row(Text(info["class_labels"].get(cls, cls), style=CLASS_COLOR.get(cls, T.TEXT)),
                        viz.bar(r["precision"], 1, 10, T.BLUE) + Text(f" {r['precision']:.2f}"),
                        viz.bar(r["recall"], 1, 10, T.TEAL) + Text(f" {r['recall']:.2f}"), f"{r['f1-score']:.2f}", str(int(r["support"])))
    fi = info.get("feature_importance") or []
    peak = max((f["importance"] for f in fi), default=1)
    fil = [Text.assemble((f"{f['feature']:<22}", T.MUTED), viz.bar(f["importance"], peak, 24, T.VIOLET), (f" {f['importance']:.3f}", T.DIM)) for f in fi[:10]]
    nov = mt["novelty"]
    return Group(panel(head, "Traffic classifier"), panel(perf, "Held-out performance"), panel(rep, "Per-class report"),
                 panel(Group(*fil), "Feature importance", info.get("importance_method", "")),
                 panel(Text(f"False-alarm rate {nov['false_alarm_rate'] * 100:.1f}% · mean unseen-class detection {nov['mean_unseen_detection'] * 100:.0f}%\n{nov['method']}", style=T.MUTED), "Novelty detector"))


def evaluation(ev: dict) -> RenderableType:
    head = Table.grid(expand=True, padding=(0, 3))
    for _ in range(4):
        head.add_column(ratio=1)
    head.add_row(tile("Scenarios", ev["scenarios_evaluated"], T.TEXT, f"impairment {ev.get('impairment', 'none')}"),
                 tile("Field accuracy", f"{ev['overall_accuracy'] * 100:.1f}%", T.GREEN, "over decided fields"),
                 tile("Traffic windows", f"{ev['traffic_window_accuracy'] * 100:.1f}%", T.GREEN, f"{ev['traffic_windows']} windows"),
                 tile("Pure windows", f"{ev['traffic_pure_window_accuracy'] * 100:.1f}%", T.GREEN, f"{ev['pure_windows']} windows"))
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("FIELD", "CORRECT", "WRONG", "ABSTAINED", "ACCURACY", "COVERAGE"):
        t.add_column(c, style=T.MUTED)
    for f in ev["fields"]:
        t.add_row(f["field"], Text(str(f["correct"]), style=T.GREEN), Text(str(f["wrong"]), style=T.RED if f["wrong"] else T.DIM),
                  Text(str(f["abstained"]), style=T.GOLD if f["abstained"] else T.DIM),
                  viz.score_bar(f["accuracy"] * 100, 10) + Text(f" {f['accuracy'] * 100:.0f}%"), f"{f['coverage'] * 100:.0f}%")
    return Group(panel(head, "End-to-end evaluation on unseen testbed scenarios"), panel(t, "Per-field accuracy — abstaining is not an error"))


def benchmark(b: dict) -> RenderableType:
    head = Table.grid(expand=True, padding=(0, 3))
    for _ in range(5):
        head.add_column(ratio=1)
    head.add_row(tile("Captures", b["captures"], T.TEXT, f"{b['clean_captures']} clean controls"),
                 tile("Defects injected", b["injected_total"], T.TEXT, f"seed {b['seed']}"),
                 tile("Detection rate", f"{b['detection_rate'] * 100:.1f}%", T.GREEN, f"{b['detected']} found · {b['missed']} missed"),
                 tile("Precision", f"{b['precision'] * 100:.1f}%", T.GREEN, f"{b['false_positives']} false positives"),
                 tile("Clean false alarms", f"{b['clean_false_alarm_rate'] * 100:.1f}%", T.GREEN, f"{b.get('seconds', 0):.0f}s run"))
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("DEFECT CLASS", "TP", "FN", "FP", "PRECISION", "RECALL", "F1"):
        t.add_column(c, style=T.MUTED)
    for r in b["per_type"]:
        t.add_row(r["label"], Text(str(r["tp"]), style=T.GREEN), Text(str(r["fn"]), style=T.RED if r["fn"] else T.DIM),
                  Text(str(r["fp"]), style=T.RED if r["fp"] else T.DIM), f"{r['precision']:.2f}", f"{r['recall']:.2f}",
                  viz.bar(r["f1"], 1, 10, T.GREEN) + Text(f" {r['f1']:.2f}"))
    ct = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("CASE", "INJECTED", "DETECTED", "MISSED", "SCORE"):
        ct.add_column(c, style=T.MUTED, overflow="ellipsis")
    for c in b["cases"][:24]:
        ct.add_row(c["name"], _trunc(", ".join(c["injected"]) or "—", 40), _trunc(", ".join(c["detected"]) or "—", 40),
                   Text(", ".join(c["missed"]) or "—", style=T.RED if c["missed"] else T.DIM), f"{c['score']}")
    return Group(panel(head, "Misconfiguration benchmark: known defects injected, then detected from the PCAP"),
                 panel(t, "Per defect class"), panel(ct, "Cases"))


# ---------------------------------------------------------------- live

def live(summary: dict, snap: dict | None, alerts: list[dict], pps: list[float]) -> RenderableType:
    status_colour = {"running": T.GREEN, "starting": T.GOLD, "finalizing": T.GOLD, "finished": T.BLUE, "stopped": T.DIM, "error": T.RED}.get(summary["status"], T.MUTED)
    head = Text.assemble(T.chip(summary["status"].upper(), status_colour), "  ", (summary["label"], f"bold {T.TEXT}"), (f"   {summary['source']}", T.DIM),
                         (f"   {summary['packets']} packets · {summary['capture_elapsed']}s of capture", T.MUTED))
    if summary.get("error"):
        head.append(f"\n{summary['error']}", style=T.RED)
    parts: list[RenderableType] = [panel(Group(head, Text.assemble(("throughput ", T.DIM), viz.spark(pps[-60:], T.TEAL), (f"  {pps[-1]:.0f} pps" if pps else "", T.MUTED))), "Session")]
    if not snap:
        parts.append(panel(Text("Waiting for the first snapshot…", style=T.DIM), "Live assessment"))
        return Group(*parts)
    sec = snap["security"]
    counts = snap["counts"]
    tiles = Table.grid(expand=True, padding=(0, 2))
    for _ in range(5):
        tiles.add_column(ratio=1)
    tiles.add_row(tile("Score", sec["overall_score"] if sec["overall_score"] is not None else "—", T.score_color(sec["overall_score"]), sec["risk_level"]),
                  tile("IKE / ESP / AH", f"{counts.get('ike', 0)} / {counts.get('esp', 0)} / {counts.get('ah', 0)}", T.TEXT, "packets"),
                  tile("SAs", snap["security_associations"], T.TEXT, f"{snap['bytes']} bytes"),
                  tile("AI confidence", f"{(snap['ai_confidence']['overall'] or 0) * 100:.0f}%", T.BLUE, f"coverage {sec['coverage'] * 100:.0f}%"),
                  tile("Analysis", f"{snap['metrics']['analysis_ms']:.0f} ms", T.MUTED, f"lag ≤ {snap['metrics']['max_lag_s']}s"))
    parts.append(panel(tiles, "Live assessment", f"capture t+{snap['capture_elapsed']}s"))
    prof = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    prof.add_column(style=T.DIM, width=22)
    prof.add_column(style=T.TEXT, ratio=1)
    prof.add_column(width=14)
    for k, v in snap["profile"].items():
        val = v.get("display") or v.get("value")
        prof.add_row(k.replace("_", " "), Text("not yet observable" if val is None else str(val), style=T.DIM if val is None else T.TEXT), T.source_tag(v.get("source")))
    cats = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    cats.add_column(width=28, style=T.MUTED)
    cats.add_column()
    cats.add_column(width=5, justify="right")
    for c in sec["categories"].values():
        cats.add_row(c["label"], viz.score_bar(c["score"], 18), Text("—" if c["score"] is None else f"{c['score']:.0f}", style=T.score_color(c["score"])))
    two = Table.grid(expand=True, padding=(0, 1))
    two.add_column(ratio=1)
    two.add_column(ratio=1)
    two.add_row(panel(prof, "What the VPN is (so far)"), panel(cats, "Category scores"))
    parts.append(two)
    mix = snap["traffic"]["mix"]
    from backend.config import TRAFFIC_CLASS_LABELS as L
    mixparts = [(L.get(c, c), v, CLASS_COLOR.get(c, T.MUTED)) for c, v in mix.items()]
    if mixparts:
        parts.append(panel(Group(viz.segmented(mixparts, 60), viz.legend(mixparts)), "Traffic inside the tunnel", f"{snap['traffic']['windows']} windows"))
    thr = [Text.assemble((f"{t['risk_score']:>3} ", f"bold {T.RED if t['risk_score'] >= 20 else T.ORANGE if t['risk_score'] >= 12 else T.GOLD}"),
                         viz.bar(t["risk_score"], 25, 10, T.ORANGE), (f" {t['name']}", T.TEXT)) for t in snap["threats"]]
    parts.append(panel(Group(*thr), "Top threats"))
    al = [Text.assemble(T.severity_chip(a["severity"]), " ", (a["id"], T.DIM), " ", (a["title"], T.TEXT)) for a in alerts[-8:]]
    parts.append(panel(Group(*al) if al else Text("No alerts raised", style=T.DIM), "Alert feed", f"{len(alerts)} raised"))
    return Group(*parts)
