"""Renderables for a single capture's analysis. Used by both the CLI commands and the TUI workspace."""
from __future__ import annotations

import time
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from securiq import theme as T
from securiq import viz

VIEWS = ["overview", "protocol", "findings", "threats", "compliance", "traffic", "timeline", "surface",
         "privacy", "policy", "fingerprint", "esp", "packets", "executive", "technical"]


# ---------------------------------------------------------------- building blocks

def panel(body: RenderableType, title: str = "", subtitle: str = "", accent: str = T.BORDER,
          padding=(0, 1)) -> Panel:
    return Panel(body, title=Text(f" {title.upper()} ", style=f"bold {T.MUTED}") if title else None,
                 title_align="left", subtitle=Text(subtitle, style=T.DIM) if subtitle else None,
                 subtitle_align="right", box=box.SQUARE, border_style=accent, padding=padding,
                 style=f"on {T.PANEL}")


def kv_table(rows: list[tuple[str, Any]], key_width: int = 22) -> Table:
    t = Table(box=None, show_header=False, padding=(0, 1), collapse_padding=True, expand=True)
    t.add_column(style=T.DIM, width=key_width, no_wrap=True)
    t.add_column(style=T.TEXT, ratio=1)
    for k, v in rows:
        t.add_row(k, v if isinstance(v, (Text, Table, Group)) else Text("—" if v in (None, "") else str(v)))
    return t


def _fmt_ts(ts: float | None, rel: float | None = None) -> str:
    if ts is None:
        return "—"
    return f"+{ts - rel:7.3f}s" if rel is not None else time.strftime("%H:%M:%S", time.gmtime(ts))


def _trunc(s: Any, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------- overview

def hero(rec: dict) -> RenderableType:
    sec, ai = rec["security"], rec["ai_confidence"]
    score = sec["overall_score"]
    colour = T.score_color(score)
    left = Group(Text("SECURITY SCORE", style=f"bold {T.DIM}"), viz.big_number(score, colour),
                 viz.gauge_ring(score, 22), Text("0        40     70      100", style=T.DIM))
    posture = rec["intel"]["posture"]
    mid = Group(
        Text("RISK POSTURE", style=f"bold {T.DIM}"),
        Text(posture["headline"], style=f"bold {T.risk_color(sec['risk_level'])}", no_wrap=True),
        Text(sec["risk_level"], style=T.MUTED),
        Text(""),
        Text("Risk score  ", style=T.DIM) + Text(f"{sec['risk_score']}/100", style=T.TEXT),
        Text("Coverage    ", style=T.DIM) + Text(f"{sec['coverage'] * 100:.0f}%", style=T.TEXT)
        + Text("  provisional" if sec.get("provisional") else "", style=T.GOLD),
        Text(sec.get("score_cap") or "no score cap applied", style=T.GOLD if sec.get("score_cap") else T.DIM),
    )
    sev = sec["severity_counts"]
    right_rows = [Text("FINDINGS", style=f"bold {T.DIM}")]
    for s in ("Critical", "High", "Medium", "Low"):
        n = sev.get(s, 0)
        right_rows.append(Text(f"{T.SEVERITY_GLYPH[s]} {s:<9}", style=T.SEVERITY_COLOR[s])
                          + viz.bar(n, max(max(sev.values(), default=1), 1), 14, T.SEVERITY_COLOR[s])
                          + Text(f" {n}", style=T.TEXT))
    right = Group(*right_rows)
    ai_block = Group(
        Text("AI CONFIDENCE", style=f"bold {T.DIM}"),
        Text(f"{ai['overall'] * 100:.0f}%", style=f"bold {T.BLUE}"),
        viz.bar(ai["overall"], 1, 16, T.BLUE),
        Text(f"{ai['fields_observed']} observed · {ai['fields_inferred']} inferred · "
             f"{ai['fields_not_observable']} unseen", style=T.DIM),
    )
    grid = Table.grid(expand=True, padding=(0, 3))
    for _ in range(4):
        grid.add_column(ratio=1)
    grid.add_row(left, mid, right, ai_block)
    return grid


def categories(rec: dict) -> RenderableType:
    rows = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    rows.add_column(width=40, no_wrap=True, overflow="ellipsis")
    rows.add_column(ratio=1, min_width=12)
    rows.add_column(width=6, justify="right")
    rows.add_column(width=10)
    weights = rec["security"].get("scoring_weights", {})
    for key, c in rec["security"]["categories"].items():
        rows.add_row(Text(c["label"], style=T.MUTED) + Text(f"  {weights.get(key, 0) * 100:.0f}%", style=T.DIM),
                     viz.score_bar(c["score"], 26),
                     Text("n/a" if c["score"] is None else f"{c['score']:.0f}", style=T.score_color(c["score"])),
                     Text(c["rating"], style=T.score_color(c["score"])))
    return rows


def overview(rec: dict) -> RenderableType:
    meta = rec["parsed_metadata"]
    posture = rec["intel"]["posture"]
    eff = rec["security"].get("effective_strength") or {}
    header = Text.assemble((meta["filename"].split("__", 1)[-1], f"bold {T.TEXT}"),
                           (f"   {meta['total_packets']} packets · {rec['ipsec_analysis']['capture_duration']:.1f}s · "
                            f"sha {meta['file_hash'][:10]} · analysed in {rec['pipeline_seconds']}s", T.DIM))
    top = []
    for f in rec["security"]["findings"][:6]:
        if f["severity"] == "Informational":
            continue
        top.append(Text.assemble(T.severity_chip(f["severity"]), " ", (f["id"], T.DIM), " ", (f["title"], T.TEXT)))
    actions = [Text.assemble(("▸ ", T.BLUE), (a, T.MUTED)) for a in posture.get("recommendations", [])[:4]]
    evidence = [Text.assemble(T.source_tag(e.get("source")), "  ", (e["text"], T.TEXT),
                              (f"  → {e['finding']}", T.DIM)) for e in posture.get("evidence", [])[:5]]
    strength = Text.assemble((f"{eff.get('bits', '?')}-bit", f"bold {T.score_color((eff.get('bits') or 0) / 1.28)}"),
                             (f"  {eff.get('rating', '')}", T.MUTED), (f"  limited by {eff.get('limited_by')}", T.DIM))
    body = [
        header, Text(""),
        panel(hero(rec), "Assessment"),
        panel(Group(Text(rec["executive_report"]["bottom_line"], style=T.TEXT), Text(""),
                    Text("Effective strength: ", style=T.DIM) + strength), "Bottom line"),
        panel(categories(rec), "Category scores (weakest link caps the total)"),
        panel(Group(*top) if top else Text("No findings above informational.", style=T.GREEN), "Top findings"),
        panel(Group(*evidence, Text(""), Text("RISK → EVIDENCE → IMPACT → RECOMMENDATION", style=f"bold {T.DIM}"),
                    Text(posture.get("impact", ""), style=T.MUTED), Text(""), *actions), "Explanation"),
    ]
    return Group(*body)


# ---------------------------------------------------------------- protocol identification

PROFILE_ORDER = ["ipsec_protocols", "ike_version", "exchange_mode", "mode", "ike_encryption", "ike_integrity",
                 "ike_prf", "key_exchange", "esp_encryption", "esp_integrity", "authentication_method", "pfs",
                 "ike_lifetime", "child_sa_lifetime", "replay_protection", "nat_traversal", "ip_version",
                 "implementation", "traffic_types"]
PROFILE_LABELS = {"ipsec_protocols": "IPsec protocol", "ike_version": "IKE version", "exchange_mode": "Exchange mode",
                  "mode": "Tunnel / transport", "ike_encryption": "IKE encryption", "ike_integrity": "IKE integrity",
                  "ike_prf": "IKE PRF", "key_exchange": "Key exchange", "esp_encryption": "ESP encryption",
                  "esp_integrity": "ESP integrity", "authentication_method": "Authentication", "pfs": "PFS",
                  "ike_lifetime": "IKE SA lifetime", "child_sa_lifetime": "Child SA lifetime",
                  "replay_protection": "Replay behaviour", "nat_traversal": "NAT traversal", "ip_version": "IP version",
                  "implementation": "Implementation", "traffic_types": "Traffic inside tunnel"}


def _value_text(ev: dict) -> str:
    if ev.get("display"):
        return str(ev["display"])
    v = ev.get("value")
    if v is None:
        return "not observable"
    if isinstance(v, bool):
        return "Yes" if v else "No"
    return str(v)


def protocol(rec: dict) -> RenderableType:
    profile = rec["ipsec_analysis"]["profile"]
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", border_style=T.BORDER, expand=True, padding=(0, 1))
    t.add_column("PROPERTY", style=T.MUTED, no_wrap=True)
    t.add_column("VALUE", style=f"bold {T.TEXT}", ratio=2)
    t.add_column("HOW KNOWN", no_wrap=True)
    t.add_column("CONF", width=14)
    t.add_column("EVIDENCE", style=T.DIM, ratio=3)
    for key in PROFILE_ORDER:
        ev = profile.get(key)
        if not ev:
            continue
        val = _value_text(ev)
        style = T.DIM if ev.get("value") is None else f"bold {T.TEXT}"
        t.add_row(PROFILE_LABELS.get(key, key), Text(_trunc(val, 46), style=style), T.source_tag(ev.get("source")),
                  viz.bar(ev.get("confidence") or 0, 1, 8, T.SOURCE_COLOR.get(ev.get("source"), T.DIM))
                  + Text(f" {(ev.get('confidence') or 0) * 100:3.0f}%", style=T.MUTED),
                  _trunc(ev.get("evidence", ""), 110))
    ike = rec["ipsec_analysis"]["ike_analysis"]
    checks = rec["intel"]["checks"]
    lines: list[RenderableType] = []
    for key in ("ike_version", "key_exchange", "ike_encryption", "pfs", "mode", "esp_encryption"):
        block = checks.get(key)
        if not block or not (block["checks"] or block["caveats"]):
            continue
        lines.append(Text(PROFILE_LABELS.get(key, key).upper(), style=f"bold {T.DIM}"))
        for c in block["checks"]:
            lines.append(Text.assemble(("  ✓ " if c["ok"] else "  ✕ ", T.GREEN if c["ok"] else T.RED), (c["text"], T.MUTED)))
        for c in block["caveats"]:
            lines.append(Text.assemble(("  ! ", T.GOLD), (c if isinstance(c, str) else c.get("text", str(c)), T.MUTED)))
    parts = [panel(t, "Identified configuration", "observed ● · inferred ◐ · not observable ○"),
             panel(ike_ladder(rec), "IKE message ladder")]
    if lines:
        parts.append(panel(Group(*lines), "Evidence checklist  ✓ supports · ✕ contradicts · ! limit"))
    offered = ike.get("offered_proposals") or []
    if offered:
        ot = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True)
        for c in ("#", "PROTO", "ENCRYPTION", "INTEGRITY", "PRF", "DH", "AUTH", "LIFETIME"):
            ot.add_column(c, style=T.MUTED)
        for p in offered[:14]:
            ot.add_row(str(p.get("number", "")), p.get("protocol", ""), ", ".join(p.get("encryption") or []),
                       ", ".join(p.get("integrity") or []), ", ".join(p.get("prf") or []),
                       ", ".join(str(g) for g in p.get("dh_groups") or []), p.get("auth_method") or "—",
                       f"{p['life_seconds']}s" if p.get("life_seconds") else "—")
        weak = ike.get("weak_offers") or []
        chosen = ike.get("chosen_suite") or {}
        foot = Text.assemble(("Chosen: ", T.DIM),
                             (f"{chosen.get('encryption')} / {chosen.get('integrity') or 'AEAD'} / {chosen.get('prf')} / "
                              f"{chosen.get('dh_group_name')}", f"bold {T.TEXT}"),
                             (f"   ({chosen.get('source', '?')} selection)", T.DIM),
                             (f"   {len(weak)} weak proposal(s) offered" if weak else "", T.ORANGE))
        parts.append(panel(Group(ot, foot), "Negotiated proposals"))
    return Group(*parts)


def ike_ladder(rec: dict) -> RenderableType:
    """Sequence diagram of IKE messages between the two gateways: cleartext vs encrypted."""
    events = [e for e in rec["ipsec_analysis"]["timeline"] if e["type"] in ("IKE", "IKE-NAT-T", "ESP", "AH")]
    ike = [e for e in events if e["type"].startswith("IKE")][:22]
    if not ike:
        return Text("No IKE messages in this capture", style=T.DIM)
    a = ike[0]["src"]
    b = ike[0]["dst"]
    t0 = ike[0]["timestamp"]
    width = 46
    lines = [Text.assemble((f"{a:^22}", f"bold {T.BLUE}"), (" " * 24, ""), (f"{b:<22}", f"bold {T.TEAL}"))]
    lines.append(Text(" " * 11 + "│" + " " * width + "│", style=T.BORDER))
    for e in ike:
        forward = e["src"] == a
        desc = _trunc(e["description"], width - 4)
        enc = "encrypted" in e["description"].lower()
        arrow = ("─" * (width - 1) + "▶") if forward else ("◀" + "─" * (width - 1))
        colour = T.DIM if enc else (T.BLUE if forward else T.TEAL)
        lines.append(Text(f"{_fmt_ts(e['timestamp'], t0)[-9:]:>10} ", style=T.DIM)
                     + Text("│", style=T.BORDER) + Text(arrow, style=colour) + Text("│", style=T.BORDER)
                     + Text(f" {desc}", style=T.MUTED))
    return Group(*lines)


# ---------------------------------------------------------------- findings and evidence chains

def findings(rec: dict, detail: str | None = None) -> RenderableType:
    fl = rec["security"]["findings"]
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    t.add_column("SEV", no_wrap=True)
    t.add_column("ID", style=T.DIM, no_wrap=True)
    t.add_column("FINDING", ratio=3)
    t.add_column("BASIS", no_wrap=True)
    t.add_column("CONF", justify="right", style=T.MUTED)
    for f in fl:
        t.add_row(T.severity_chip(f["severity"]), f["id"], Text(f["title"], style=T.TEXT),
                  T.source_tag(f.get("evidence_source")), f"{(f.get('confidence') or 0) * 100:.0f}%")
    body: list[RenderableType] = [panel(t, "Findings", f"{len(fl)} total")]
    chains = rec["intel"]["chains"]
    for f in fl:
        if detail and detail.upper() != f["id"]:
            continue
        if not detail and f["severity"] not in ("Critical", "High"):
            continue
        if f["id"] in chains:
            body.append(chain(rec, f["id"]))
    return Group(*body)


def chain(rec: dict, finding_id: str) -> RenderableType:
    """packet frames → extracted parameter → rule (with reference) → risk and impact → fix."""
    c = rec["intel"]["chains"].get(finding_id)
    f = next((x for x in rec["security"]["findings"] if x["id"] == finding_id), None)
    if c is None or f is None:
        return Text(f"No evidence chain for {finding_id}", style=T.DIM)
    colour = T.SEVERITY_COLOR[f["severity"]]
    steps: list[tuple[str, RenderableType]] = []
    pk = []
    for p in c["packets"]:
        frames = ", ".join(f"#{n}" for n in p["frames"][:8]) + (" …" if len(p["frames"]) > 8 else "")
        pk.append(Text.assemble((("🔒 " if p.get("encrypted") else "◉ "), T.DIM), (p["label"], T.TEXT),
                                (f"  frames {frames}", T.BLUE), (f"\n   {p['detail']}", T.DIM)))
    steps.append(("1  PACKETS", Group(*pk) if pk else Text("no single frame carries this evidence", style=T.DIM)))
    prm = [Text.assemble(T.source_tag(x.get("source")), "  ", (f"{x['label']}: ", T.MUTED), (str(x["value"]), f"bold {T.TEXT}"),
                         (f"  {(x.get('confidence') or 0) * 100:.0f}%", T.DIM)) for x in c["parameters"]]
    steps.append(("2  PARAMETER", Group(*prm)))
    r = c["rule"]
    steps.append(("3  RULE", Group(Text(r["statement"], style=T.TEXT), Text(r["reference"], style=T.BLUE))))
    steps.append(("4  RISK", Group(Text.assemble(T.severity_chip(c["risk"]["severity"]), "  ",
                                                 (c["risk"]["impact"], T.MUTED)))))
    steps.append(("5  FIX", Text(c["recommendation"], style=T.GREEN)))
    rows: list[RenderableType] = [Text.assemble((f"{f['id']}  ", T.DIM), (f["title"], f"bold {T.TEXT}"))]
    for i, (h, body) in enumerate(steps):
        rows.append(Text(("│" if i else "┌") + f" {h}", style=f"bold {colour}"))
        rows.append(Padding(body, (0, 0, 0, 3)))
    return panel(Group(*rows), "Evidence chain", accent=colour)


# ---------------------------------------------------------------- threats & compliance

def threats(rec: dict) -> RenderableType:
    tm = rec["threat_matrix"]
    names = {t["id"]: t["name"] for t in tm["threats"]}
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c, kw in (("#", {}), ("THREAT", {"ratio": 2}), ("ATT&CK", {}), ("L", {"justify": "right"}),
                  ("I", {"justify": "right"}), ("RISK", {}), ("DRIVEN BY", {"ratio": 1})):
        t.add_column(c, style=T.MUTED, **kw)
    order = []
    for row in tm["grid"]:
        for cell in row:
            for x in cell:
                if x not in order:
                    order.append(x)
    for th in sorted(tm["threats"], key=lambda x: -x["risk_score"]):
        colour = T.RED if th["risk_score"] >= 20 else T.ORANGE if th["risk_score"] >= 12 else T.GOLD if th["risk_score"] >= 6 else T.GREEN
        t.add_row(str(order.index(th["id"]) + 1) if th["id"] in order else "", Text(th["name"], style=T.TEXT),
                  th["attack"], str(th["likelihood"]), str(th["impact"]),
                  viz.bar(th["risk_score"], 25, 8, colour) + Text(f" {th['risk_score']:>2} {th['risk_level']}", style=colour),
                  ", ".join(th["contributing_findings"][:4]))
    ordered = {t_id: names[t_id] for t_id in order}
    return Group(panel(Columns([viz.heat_matrix(tm["grid"], ordered)], padding=(0, 4)), "5 × 5 threat matrix",
                       "likelihood ↑ · impact →"),
                 panel(t, "Threats", f"{tm['critical_count']} critical · {tm['high_count']} high"))


def compliance(rec: dict) -> RenderableType:
    parts: list[RenderableType] = []
    for key, fw in rec["security"]["compliance"].items():
        t = Table(box=None, show_header=False, expand=True, padding=(0, 1))
        t.add_column(width=6)
        t.add_column(ratio=2)
        t.add_column(style=T.BLUE, no_wrap=True)
        t.add_column(style=T.DIM, ratio=3)
        for c in fw["checks"]:
            glyph = {"pass": "✓ PASS", "fail": "✕ FAIL", "warn": "! WARN", "unknown": "? N/A"}[c["status"]]
            t.add_row(Text(glyph, style=f"bold {T.STATUS_COLOR[c['status']]}"), Text(c["title"], style=T.TEXT),
                      c["reference"], _trunc(c["evidence"], 90))
        counts = fw["counts"]
        sub = f"{counts.get('pass', 0)} pass · {counts.get('warn', 0)} warn · {counts.get('fail', 0)} fail · {counts.get('unknown', 0)} unknown"
        head = Text.assemble((f"{fw['name']}  ", f"bold {T.TEXT}"), (fw["description"], T.DIM))
        score = fw.get("score")
        bar = Text.assemble(("  compliance ", T.DIM)) + viz.score_bar(score, 20) + Text(
            f" {score if score is not None else 'n/a'}", style=T.score_color(score))
        parts.append(panel(Group(head, bar, t), key.upper(), sub))
    return Group(*parts)


# ---------------------------------------------------------------- traffic, timeline, ESP

CLASS_COLOR = {"web": T.BLUE, "video": T.VIOLET, "voip": T.GREEN, "file_transfer": T.ORANGE, "email": T.GOLD,
               "chat": T.TEAL, "icmp": T.RED}


def traffic(rec: dict) -> RenderableType:
    from backend.config import TRAFFIC_CLASS_LABELS as LABELS
    tr = rec["traffic"]
    if not tr.get("windows"):
        return panel(Text(tr.get("note") or "No classifiable ESP traffic", style=T.DIM), "Traffic inside the tunnel")
    mix = [(LABELS.get(c, c), v, CLASS_COLOR.get(c, T.MUTED)) for c, v in tr["mix"].items()]
    parts: list[RenderableType] = [
        panel(Group(viz.segmented(mix, 64), viz.legend(mix),
                    Text(f"\n{tr['windows']} windows · mean confidence {tr['mean_confidence'] * 100:.0f}% · "
                         f"{tr['uncertain_windows']} uncertain · {tr['novel_windows']} novel · "
                         f"{tr['smoothed_changes']} HMM-smoothed", style=T.DIM)), "Application mix")]
    for flow in tr["flows"]:
        line = Text.assemble(*[("███ ", CLASS_COLOR.get(w["class"], T.MUTED)) for w in flow["timeline"]])
        parts.append(panel(Group(Text.assemble(("dominant ", T.DIM), (flow["dominant_label"], f"bold {T.TEXT}"),
                                               (f"  {flow['mean_confidence'] * 100:.0f}% mean confidence", T.DIM)),
                                 line), f"Tunnel {flow['flow_id']}"))
    ct = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("WINDOW", "PKTS", "CLASS", "CONFIDENCE", "TOP-3", "FLAGS"):
        ct.add_column(c, style=T.MUTED)
    t0 = min(p["window_start"] for p in rec["classification"])
    for p in rec["classification"][:40]:
        top3 = "  ".join(f"{x['class']} {x['confidence'] * 100:.0f}%" for x in p["top_predictions"])
        flags = Text()
        if p["uncertain"]:
            flags.append("uncertain ", style=T.GOLD)
        if p["novel"]:
            flags.append("novel ", style=T.VIOLET)
        if p.get("raw_class") != p["predicted_class"]:
            flags.append(f"smoothed from {p['raw_class']}", style=T.DIM)
        ct.add_row(f"{p['window_start'] - t0:5.0f}–{p['window_end'] - t0:<5.0f}s", str(p["packet_count"]),
                   Text(p["predicted_label"], style=CLASS_COLOR.get(p["predicted_class"], T.TEXT)),
                   viz.bar(p["confidence"], 1, 10, CLASS_COLOR.get(p["predicted_class"], T.BLUE))
                   + Text(f" {p['confidence'] * 100:.0f}%", style=T.MUTED), top3, flags)
    parts.append(panel(ct, "Per-window classification"))
    first = rec["classification"][0]
    reason = first.get("reasoning", {})
    expl = [Text("WHY THE FIRST WINDOW WAS CLASSIFIED " + first["predicted_class"].upper(), style=f"bold {T.DIM}")]
    expl += [Text.assemble(("  ✓ ", T.GREEN), (s, T.MUTED)) for s in reason.get("supports", [])]
    expl += [Text.assemble(("  ! ", T.GOLD), (s, T.MUTED)) for s in reason.get("caveats", [])]
    ft = Table(box=None, show_header=True, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("FEATURE", "THIS WINDOW", "CLASS MEDIAN"):
        ft.add_column(c, style=T.MUTED)
    for e in first["explanation"]:
        ft.add_row(e["feature"], f"{e['value']:.4g}", f"{e['class_median']:.4g}")
    parts.append(panel(Group(*expl, Text(""), ft), "Explainability"))
    return Group(*parts)


def timeline(rec: dict) -> RenderableType:
    a = rec["ipsec_analysis"]
    events = a["timeline"]
    if not events:
        return Text("No events", style=T.DIM)
    t0 = min(e["timestamp"] for e in events)
    t1 = max(e["timestamp"] for e in events)
    spans, colours = [], {"IKE": T.BLUE, "IKE-NAT-T": T.CYAN, "ESP": T.GREEN, "AH": T.ORANGE}
    for kind in ("IKE", "IKE-NAT-T", "AH"):
        ts = [e["timestamp"] for e in events if e["type"] == kind]
        if ts:
            spans.append({"label": kind, "start": min(ts), "end": max(ts) + 0.05 * (t1 - t0 or 1), "colour": colours[kind]})
    for fl in a["flow_analysis"]["flows"]:
        spans.append({"label": f"ESP {fl['id'][:12]}", "start": fl["first_seen"], "end": fl["last_seen"], "colour": T.GREEN})
    for p in rec["classification"]:
        spans.append({"label": f"▸ {p['predicted_class']}", "start": p["window_start"], "end": p["window_end"],
                      "colour": CLASS_COLOR.get(p["predicted_class"], T.MUTED)})
    t1 = max(t1, max(s["end"] for s in spans))
    t0 = min(t0, min(s["start"] for s in spans))
    rows = viz.timeline_strip(spans[:24], t0, t1, 64)
    esp = rec["ipsec_analysis"]["esp_analysis"]
    notes = []
    rs = esp.get("replay_summary") or {}
    if esp.get("detected"):
        notes.append(Text.assemble(("Replay: ", T.DIM), (f"{rs.get('duplicates', 0)} duplicate sequence numbers, "
                                                          f"{rs.get('counter_resets', 0)} counter resets, "
                                                          f"{rs.get('reordered', 0)} reordered", T.ORANGE if (rs.get('duplicates') or rs.get('counter_resets')) else T.GREEN)))
    lt = rec["ipsec_analysis"]["lifetimes"]
    for name in ("ike", "child"):
        ev = lt.get(name)
        if ev:
            notes.append(Text.assemble((f"{name.upper()} SA lifetime: ", T.DIM),
                                       (ev.get("display") or ("not observable — " + str(ev.get("evidence", ""))), T.TEXT)))
    et = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("T+", "TYPE", "EVENT", "FROM → TO"):
        et.add_column(c, style=T.MUTED)
    for e in [x for x in events if x["type"] != "ESP"][:30]:
        et.add_row(f"{e['timestamp'] - t0:7.3f}s", Text(e["type"], style=colours.get(e["type"], T.MUTED)),
                   e["description"], f"{e['src']} → {e['dst']}")
    return Group(panel(Group(*rows, viz.time_axis(t0, t1, 64), Text(""), *notes), "Investigation timeline"),
                 panel(et, "Key events"))


def esp(rec: dict) -> RenderableType:
    e = rec["ipsec_analysis"]["esp_analysis"]
    if not e.get("detected"):
        return panel(Text("No ESP traffic in this capture", style=T.DIM), "ESP")
    fp = e["fingerprint"]
    parts: list[RenderableType] = []
    parts.append(panel(kv_table([
        ("Packets / SAs", f"{e['packet_count']} packets · {e['sa_count']} SAs · {e['unique_spis']} SPIs"),
        ("Cipher family", fp.get("family") or "not claimed"), ("Integrity", fp.get("integrity") or "not claimed"),
        ("Suite", fp.get("suite") or "not claimed"),
        ("Block / IV / ICV", f"{fp.get('block_size')} / {fp.get('iv_len')} / {fp.get('icv_len_candidates')}"),
        ("Distinct lengths", fp.get("distinct_lengths")), ("Confidence", f"{(fp.get('confidence') or 0) * 100:.0f}%"),
        ("Reasoning", Text(fp.get("evidence", ""), style=T.MUTED)),
        ("Mode inference", Text(f"{e['mode_inference']['value']} ({e['mode_inference']['confidence'] * 100:.0f}%) — "
                                f"{_trunc(e['mode_inference']['evidence'], 200)}", style=T.MUTED)),
    ]), "ESP fingerprint (from lengths alone, no keys)"))
    st = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("SPI", "DIRECTION", "PKTS", "BYTES", "DURATION", "SEQ RANGE", "PAYLOAD MIN/AVG/MAX", "NAT-T"):
        st.add_column(c, style=T.MUTED)
    for sa in e["sa_info"]:
        st.add_row(sa["spi"], f"{sa['src']} → {sa['dst']}", str(sa["packet_count"]), str(sa["bytes"]),
                   f"{sa['duration']:.1f}s", f"{sa['min_seq']}–{sa['max_seq']}",
                   f"{sa['min_payload_size']} / {sa['avg_payload_size']:.0f} / {sa['max_payload_size']}", "yes" if sa["nat_t"] else "no")
    parts.append(panel(st, "Security associations"))
    return Group(*parts)


def esp_sequences(pkts: list[dict]) -> RenderableType:
    """Per-SPI sequence-number trace; replays show as backward steps."""
    by_spi: dict[str, list[int]] = {}
    for p in pkts:
        if p.get("protocol_type") == "esp" and p.get("seq_num") is not None:
            by_spi.setdefault(p["spi"], []).append(p["seq_num"])
    if not by_spi:
        return Text("No ESP sequence numbers stored", style=T.DIM)
    rows = []
    for spi, seq in by_spi.items():
        resets = sum(1 for a, b in zip(seq, seq[1:]) if b < a)
        dups = len(seq) - len(set(seq))
        line = viz.spark(seq[:80], T.GREEN if not (resets or dups) else T.ORANGE)
        rows.append(Text.assemble((f"{spi:<12}", T.MUTED), line, (f"  {len(seq)} pkts", T.DIM),
                                  (f"  {dups} dup" if dups else "", T.ORANGE), (f"  {resets} backward" if resets else "", T.RED)))
    return Group(*rows)


def packets(rec_or_packets: dict, limit: int = 60, kind: str | None = None) -> RenderableType:
    pkts = rec_or_packets["packets"]
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("#", "T+", "PROTO", "SOURCE", "DEST", "LEN", "INFO"):
        t.add_column(c, style=T.MUTED, no_wrap=True)
    t0 = pkts[0]["timestamp"] if pkts else 0
    colours = {"ike": T.BLUE, "esp": T.GREEN, "ah": T.ORANGE, "other": T.DIM}
    shown = [p for p in pkts if not kind or p["protocol_type"] == kind][:limit]
    for p in shown:
        info = ""
        if p.get("ike"):
            info = f"{p['ike']['exchange_type']} {'ENC ' if p['ike']['encrypted_flag'] else ''}" + ",".join(p["ike"]["payload_types"][:5])
        elif p["protocol_type"] == "esp":
            info = f"SPI {p['spi']} seq {p['seq_num']} payload {p['esp_payload_len']}B"
        t.add_row(str(p["index"]), f"{p['timestamp'] - t0:.3f}", Text(p["protocol_type"].upper(), style=colours.get(p["protocol_type"], T.MUTED)),
                  p["src_ip"] + (f":{p['src_port']}" if p.get("src_port") else ""),
                  p["dst_ip"] + (f":{p['dst_port']}" if p.get("dst_port") else ""), str(p["length"]), _trunc(info, 70))
    return panel(Group(t, esp_sequences(pkts)), "Packets", f"{len(shown)} of {rec_or_packets['total']}")


# ---------------------------------------------------------------- attack surface, privacy

def surface(rec: dict) -> RenderableType:
    s = rec["intel"]["surface"]
    layers: dict[int, list[dict]] = {}
    for n in s["nodes"]:
        layers.setdefault(n["layer"], []).append(n)
    parts: list[RenderableType] = []
    for i, layer in enumerate(sorted(layers)):
        cards = []
        for n in layers[layer]:
            colour = T.STATUS_COLOR.get(n["status"], T.MUTED)
            body = [Text(n["subtitle"], style=T.MUTED)]
            body += [Text.assemble(("✕ ", T.SEVERITY_COLOR.get(r["severity"], T.RED)), (_trunc(r["title"], 34), T.TEXT))
                     for r in n["risks"][:4]]
            if len(n["risks"]) > 4:
                body.append(Text(f"+{len(n['risks']) - 4} more weaknesses", style=T.DIM))
            body += [Text.assemble(("✓ ", T.GREEN), (g, T.MUTED)) for g in n["strengths"][:3]]
            body += [Text(f, style=T.DIM) for f in n["facts"][:3]]
            cards.append(Panel(Group(*body), title=Text(f" {n['title']} ", style=f"bold {colour}"), border_style=colour,
                               box=box.HEAVY if n["status"] in ("critical", "high") else box.ROUNDED, width=40,
                               style=f"on {T.PANEL}"))
        label = s["layers"][layer] if layer < len(s["layers"]) else f"Layer {layer}"
        parts.append(Text(f"LAYER {layer + 1} · {label.upper()}", style=f"bold {T.DIM}"))
        parts.append(Columns(cards, padding=(0, 1)))
        if i < len(layers) - 1:
            parts.append(Text("                     │\n                     ▼", style=T.BORDER))
    parts.append(Text("\n" + "  ".join(f"■ {x['label']}" for x in s["legend"]), style=T.DIM))
    return panel(Group(*parts), "Attack surface: gateways → IKE SA → child SAs → traffic")


def privacy(rec: dict) -> RenderableType:
    m = rec["intel"]["metadata"]
    dims = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    dims.add_column(width=26, style=T.MUTED, no_wrap=True)
    dims.add_column(width=22)
    dims.add_column(style=T.DIM, ratio=1)
    for d in m["dimensions"]:
        colour = T.RED if d["exposed"] >= 0.75 else T.ORANGE if d["exposed"] >= 0.4 else T.GOLD if d["exposed"] > 0 else T.GREEN
        dims.add_row(d["label"], viz.bar(d["exposed"], 1, 12, colour) + Text(f" {d['exposed'] * 100:3.0f}% exposed", style=colour),
                     _trunc(d["detail"], 90))
    head = Table.grid(expand=True, padding=(0, 4))
    head.add_column()
    head.add_column()
    head.add_row(Group(Text("CONFIDENTIALITY", style=f"bold {T.DIM}"), viz.big_number(m["confidentiality"], T.score_color(m["confidentiality"]))),
                 Group(Text("METADATA PRIVACY", style=f"bold {T.DIM}"), viz.big_number(m["metadata_privacy"], T.score_color(m["metadata_privacy"]))))
    sees = Text.assemble(("An observer CAN see  ", f"bold {T.RED}"), (" · ".join(m["observer_sees"]), T.MUTED))
    hides = Text.assemble(("An observer CANNOT see  ", f"bold {T.GREEN}"), (" · ".join(m["observer_cannot_see"]), T.MUTED))
    stmts = [Text(f"▸ {s}", style=T.TEXT) for s in m["statements"]]
    return Group(panel(head, "Confidentiality vs metadata privacy"),
                 panel(Group(*stmts, Text(""), sees, hides), "What a passive observer learns"),
                 panel(dims, "Exposure by dimension"))


# ---------------------------------------------------------------- policy, fingerprint, novelty, drift

def policy(rec: dict, result: dict | None = None, policy_doc: dict | None = None) -> RenderableType:
    p = result or rec["intel"]["policy"]
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("", "REQUIREMENT", "OBSERVED", "BASIS"):
        t.add_column(c, style=T.MUTED)
    for r in p["rows"]:
        st = r["status"]
        t.add_row(Text({"pass": "✓", "fail": "✕", "unknown": "?"}.get(st, "·"), style=f"bold {T.STATUS_COLOR.get(st, T.MUTED)}"),
                  Text(r["requirement"], style=T.TEXT), Text(_trunc(r["observed"], 40), style=T.STATUS_COLOR.get(st, T.MUTED)),
                  T.source_tag(r.get("source")))
    c = p["counts"]
    colour = T.GREEN if p["status"] == "Compliant" else T.RED
    head = Text.assemble(T.chip(p["status"].upper(), colour), "  ",
                         (f"{c['pass']} pass · {c['fail']} fail · {c['unknown']} unknown", T.MUTED),
                         ("   unknown is never counted as a pass", T.DIM))
    parts = [panel(Group(head, t), f"Golden policy — {p['policy_name']}")]
    if policy_doc is not None:
        lines = [Text(f"{k}: {v}", style=T.MUTED) for k, v in policy_doc.items()]
        parts.append(panel(Group(*lines), "Policy document"))
    return Group(*parts)


def fingerprint(rec: dict) -> RenderableType:
    fp = rec["intel"]["fingerprint"]
    nov = rec["intel"]["novelty"]
    comps = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    comps.add_column(style=T.DIM, width=18)
    comps.add_column(style=T.TEXT)
    for c in fp["components"]:
        comps.add_row(c["label"], Text(str(c["value"]) if c["value"] is not None else "unknown",
                                       style=T.TEXT if c["value"] is not None else T.DIM))
    nearest = nov.get("nearest_known")
    novelty_lines = [Text.assemble(T.chip(nov["status"].upper(), T.VIOLET if nov["status"] == "novel" else T.GREEN if nov["status"] == "known" else T.GOLD))]
    for s in nov["signals"]:
        novelty_lines.append(Text.assemble(("▸ ", T.VIOLET), (s["text"], T.MUTED)))
    if nearest:
        novelty_lines.append(Text(f"nearest known suite: {nearest['suite']} ({nearest['matching_components']}/{nearest['of']} components)", style=T.DIM))
    head = Group(Text(fp["id"], style=f"bold {T.VIOLET}"), Text(fp["label"], style=T.TEXT),
                 Text(f"observed {fp['observed_components']}/{fp['total_components']} components · sha256 {fp['sha256'][:24]}…", style=T.DIM))
    return Group(panel(head, "Configuration fingerprint"), panel(comps, "Components"), panel(Group(*novelty_lines), "Novelty"))


def drift(d: dict) -> RenderableType:
    if d.get("status") == "no_baseline":
        return panel(Text(d["note"], style=T.DIM), "Configuration drift")
    head = Table.grid(expand=True, padding=(0, 2))
    head.add_column(ratio=1)
    head.add_column(width=5)
    head.add_column(ratio=1)
    head.add_row(Group(Text("BASELINE", style=f"bold {T.DIM}"), Text(d["base"]["filename"].split("__", 1)[-1], style=T.TEXT),
                       Text(d["base"]["fingerprint"]["id"], style=T.VIOLET), Text(f"score {d['base']['score']}", style=T.score_color(d['base']['score']))),
                 Text("  ──▶", style=T.BLUE),
                 Group(Text("TARGET", style=f"bold {T.DIM}"), Text(d["target"]["filename"].split("__", 1)[-1], style=T.TEXT),
                       Text(d["target"]["fingerprint"]["id"], style=T.VIOLET), Text(f"score {d['target']['score']}", style=T.score_color(d['target']['score']))))
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("COMPONENT", "FROM", "TO", "VERDICT"):
        t.add_column(c, style=T.MUTED)
    verdict = {"strengthened": (T.GREEN, "▲ strengthened"), "degraded": (T.RED, "▼ weakened"),
               "weakened": (T.RED, "▼ weakened"), "visibility": (T.DIM, "◌ visibility only"), "changed": (T.GOLD, "≠ changed")}
    for c in d["changes"]:
        colour, text = verdict.get(c["direction"], (T.GOLD, c["direction"]))
        t.add_row(c["label"], str(c["from"]), str(c["to"]), Text(text, style=colour))
    delta = d["score_delta"]
    summary = Text.assemble((f"{d['status'].replace('_', ' ').upper()}  ", f"bold {T.TEXT}"),
                            (f"score {delta:+.1f}", f"bold {T.GREEN if delta > 0 else T.RED if delta < 0 else T.MUTED}"),
                            (f"   {len(d['new_findings'])} new finding(s), {len(d['resolved_findings'])} resolved", T.DIM))
    parts = [panel(Group(head, Text(""), summary), "Configuration drift"), panel(t, "Changes")]
    if d["new_findings"] or d["resolved_findings"]:
        lines = [Text.assemble(("+ new       ", T.RED), (str(f), T.TEXT)) for f in d["new_findings"]]
        lines += [Text.assemble(("− resolved  ", T.GREEN), (str(f), T.MUTED)) for f in d["resolved_findings"]]
        parts.append(panel(Group(*lines), "Findings"))
    return Group(*parts)


# ---------------------------------------------------------------- what-if and verification

def simulation(sim: dict) -> RenderableType:
    cur, new = sim["current"], sim["proposed"]
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c, kw in (("CATEGORY", {}), ("BEFORE", {"justify": "right"}), ("", {"no_wrap": True}), ("AFTER", {"justify": "right"}), ("Δ", {"justify": "right"})):
        t.add_column(c, style=T.MUTED, **kw)
    for k, c in cur["categories"].items():
        a, b = c["score"], new["categories"][k]["score"]
        d = None if a is None or b is None else b - a
        t.add_row(c["label"], "n/a" if a is None else f"{a:.0f}", viz.score_bar(a, 9) + Text(" → ", style=T.DIM) + viz.score_bar(b, 9),
                  "n/a" if b is None else f"{b:.0f}",
                  Text("" if d is None else f"{d:+.0f}", style=T.GREEN if d and d > 0 else T.RED if d and d < 0 else T.DIM))
    delta = sim["delta"]
    head = Table.grid(expand=True, padding=(0, 3))
    for _ in range(3):
        head.add_column(ratio=1)
    head.add_row(Group(Text("BEFORE", style=f"bold {T.DIM}"), viz.big_number(cur["overall_score"], T.score_color(cur["overall_score"])), Text(cur["risk_level"], style=T.MUTED)),
                 Group(Text("MODELLED", style=f"bold {T.DIM}"), viz.big_number(new["overall_score"], T.score_color(new["overall_score"])), Text(new["risk_level"], style=T.MUTED)),
                 Group(Text("CHANGE", style=f"bold {T.DIM}"), viz.big_number(f"{delta:+.0f}", T.GREEN if delta > 0 else T.RED if delta < 0 else T.MUTED)))
    ch = [Text.assemble((f"{k} ", T.DIM), (f"→ {v}", f"bold {T.VIOLET}")) for k, v in sim["changes"].items()]
    factors = Table(box=None, show_header=True, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("CHANGE", "ALONE", "IF REMOVED"):
        factors.add_column(c, style=T.MUTED)
    for f in sim.get("factors", []):
        factors.add_row(f"{f['label']}: {f['from']} → {f['to']}", _signed(f.get("delta_alone")),
                        _signed(f.get("delta_if_removed")))
    parts = [panel(Group(head, Text(""), Text(sim["verdict"], style=T.TEXT)), "What-if simulation (unchanged rule engine)"),
             panel(Group(*ch), "Proposed changes"), panel(t, "Category effect")]
    if sim.get("factors"):
        parts.append(panel(factors, "Attribution: what actually moves the posture"))
    res = [Text.assemble(("− ", T.GREEN), (f, T.MUTED)) for f in sim["resolved"]]
    res += [Text.assemble(("+ ", T.RED), (f if isinstance(f, str) else f.get("id", str(f)), T.TEXT)) for f in sim["introduced"]]
    if res:
        parts.append(panel(Group(*res), "Findings resolved / introduced"))
    pb, pa = sim["policy_before"], sim["policy_after"]
    parts.append(panel(Text.assemble(("Golden policy: ", T.DIM), (f"{pb['status']} ({pb['counts']['fail']} fail)", T.RED), ("  →  ", T.DIM),
                                     (f"{pa['status']} ({pa['counts']['fail']} fail)", T.GREEN if pa["status"] == "Compliant" else T.ORANGE),
                                     ("\nFingerprint:    ", T.DIM), (sim["fingerprint_before"]["id"], T.VIOLET), ("  →  ", T.DIM),
                                     (sim["fingerprint_after"]["id"], T.VIOLET)), "Policy & fingerprint effect"))
    parts.append(Text(sim["note"], style=T.DIM))
    return Group(*parts)


def _signed(v: Any) -> Text:
    if v is None:
        return Text("—", style=T.DIM)
    return Text(f"{v:+.1f}", style=T.GREEN if v > 0 else T.RED if v < 0 else T.DIM)


def verification(v: dict) -> RenderableType:
    delta = v["delta"]
    head = Text.assemble(("measured  ", T.DIM), (f"{v['before']['score']}", f"bold {T.score_color(v['before']['score'])}"), ("  →  ", T.DIM),
                         (f"{v['after']['score']}", f"bold {T.score_color(v['after']['score'])}"),
                         (f"   ({delta:+.1f})" if delta is not None else "", f"bold {T.GREEN if (delta or 0) > 0 else T.RED}"),
                         (f"   {v['after']['risk_level']}", T.MUTED),
                         (f"   identification accuracy {v['after']['identification_accuracy'] * 100:.0f}%" if v["after"].get("identification_accuracy") is not None else "", T.DIM))
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", padding=(0, 2))
    for c in ("CATEGORY", "BEFORE", "AFTER"):
        t.add_column(c, style=T.MUTED)
    for c in v["categories"]:
        t.add_row(c["label"], "n/a" if c["before"] is None else f"{c['before']:.0f}", "n/a" if c["after"] is None else f"{c['after']:.0f}")
    from rich.syntax import Syntax
    return Group(panel(head, "Verified by the digital twin (same traffic, full pipeline)"),
                 panel(t, "Categories"),
                 panel(Group(*[Text.assemble(("− ", T.GREEN), (f, T.MUTED)) for f in v["resolved"]],
                             *[Text.assemble(("! ", T.ORANGE), (f"{r['id']} {r['title']}", T.TEXT)) for r in v["remaining"]]), "Resolved / remaining"),
                 panel(Syntax(v["strongswan_profile"], "ini", theme="ansi_dark", background_color=T.PANEL), "strongSwan profile for the Docker lab"))


# ---------------------------------------------------------------- reports as terminal text

def executive(rec: dict) -> RenderableType:
    r = rec["executive_report"]
    colour = T.risk_color(r["risk_level"])
    top = [Text.assemble(T.chip(x.get("priority", "•") if isinstance(x, dict) else "•", T.BLUE), " ",
                         (x.get("action") if isinstance(x, dict) else str(x), T.TEXT)) for x in r["top_recommendations"]]
    thr = [Text.assemble(("▸ ", colour), (x["name"] if isinstance(x, dict) else str(x), T.TEXT),
                         (f"  risk {x.get('risk_score')}" if isinstance(x, dict) else "", T.DIM)) for x in r["top_threats"]]
    vp = Table(box=None, show_header=False, expand=True, padding=(0, 1))
    vp.add_column(style=T.DIM, width=22)
    vp.add_column(style=T.TEXT)
    vp.add_column()
    for x in r["vpn_summary"]:
        vp.add_row(x["label"], _trunc(x["value"] if x["value"] is not None else "not observable", 48), T.source_tag(x["source"]))
    return Group(Text(r["title"], style=f"bold {T.TEXT}"), Text(f"{r['generated_at']} · {r['capture']['filename']}", style=T.DIM), Text(""),
                 panel(Text.assemble((f"{r['overall_security_score']}/100  ", f"bold {colour}"), (r["risk_level"], colour),
                                     ("\n\n" + r["bottom_line"], T.TEXT)), "Bottom line", accent=colour),
                 panel(vp, "What the VPN is"), panel(Group(*top), "Do this first"), panel(Group(*thr), "Top threats"))


def technical(rec: dict) -> RenderableType:
    r = rec["technical_report"]
    rec_t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("PRIORITY", "FINDING", "ACTION"):
        rec_t.add_column(c, style=T.MUTED)
    for x in r["recommendations"]:
        rec_t.add_row(Text(x["priority"], style=T.SEVERITY_COLOR.get(x["severity"], T.MUTED)), f"{x['finding_id']}  {_trunc(x['title'], 50)}", x["action"])
    stats = r["packet_statistics"]
    st = Text("  ".join(f"{k}={v}" for k, v in stats.items()), style=T.MUTED)
    return Group(Text(r["title"], style=f"bold {T.TEXT}"), Text(r["generated_at"], style=T.DIM), Text(""),
                 panel(st, "Capture statistics"), panel(rec_t, "Remediation plan"),
                 panel(Group(*[Text.assemble(("▸ ", T.BLUE), (m, T.MUTED)) for m in r["methodology"]]), "Methodology"),
                 protocol(rec), findings(rec), compliance(rec))


def ground_truth(rec: dict) -> RenderableType | None:
    gt = rec.get("ground_truth")
    if not gt:
        return None
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
    for c in ("FIELD", "TESTBED TRUTH", "SECURIQ SAID", ""):
        t.add_column(c, style=T.MUTED)
    for r in gt["rows"]:
        colour = {"correct": T.GREEN, "wrong": T.RED, "abstained": T.GOLD}[r["status"]]
        t.add_row(r["field"], _trunc(r["expected"], 34), _trunc(r["predicted"], 34), Text({"correct": "✓ correct", "wrong": "✕ wrong", "abstained": "○ abstained"}[r["status"]], style=colour))
    acc = gt["accuracy"]
    head = Text.assemble((f"{gt['correct']}/{gt['decided']} correct", f"bold {T.GREEN}"), (f"   {acc * 100:.0f}% of decided fields" if acc is not None else "", T.MUTED),
                         (f"   window accuracy {gt['window_accuracy'] * 100:.0f}%" if gt.get("window_accuracy") is not None else "", T.DIM))
    return panel(Group(head, t), f"Ground truth — {gt['scenario']}")


def view(rec: dict, name: str, pkts: dict | None = None) -> RenderableType:
    """Render one named view of an analysis (CLI `show`)."""
    if name == "overview":
        gt = ground_truth(rec)
        return Group(overview(rec), gt) if gt else overview(rec)
    table = {"protocol": protocol, "findings": findings, "threats": threats, "compliance": compliance,
             "traffic": traffic, "timeline": timeline, "surface": surface, "privacy": privacy, "policy": policy,
             "fingerprint": fingerprint, "esp": esp, "executive": executive, "technical": technical}
    if name == "packets":
        return packets(pkts or {"packets": [], "total": 0})
    return table[name](rec)
