"""The nine views of the console. Each is a container that knows how to (re)load and render its own data."""
from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.syntax import Syntax
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Click
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, OptionList, Select, Static, TabbedContent, TabPane
from textual.widgets.option_list import Option

from securiq import core, render, render_fleet as F, theme as T, viz
from securiq.render import panel
from securiq.tui.widgets import KnobForm, TextPrompt

if TYPE_CHECKING:  # pragma: no cover
    from securiq.tui.app import SecurIQApp


class View(Vertical):
    """Base: `app_` gives typed access; `refresh_data` is called when the view is shown or data changes."""

    @property
    def app_(self) -> "SecurIQApp":
        return self.app  # type: ignore[return-value]

    def refresh_data(self) -> None:
        pass

    def on_show(self) -> None:
        self.refresh_data()


def _cell(text: Any, style: str = "") -> Text:
    return Text(str(text), style=style)


# ================================================================ 1 · operations

class DashboardView(View):
    """Fleet dashboard with a live, animated tunnel topology and a scrolling finding ticker."""

    def compose(self) -> ComposeResult:
        yield Static(id="dash-ticker")
        with VerticalScroll():
            yield Static(id="dash-topology")
            yield Static(id="dash")

    def on_mount(self) -> None:
        self.frame = 0
        self.tuns: list[dict] = []
        self.anim = self.set_interval(0.12, self._frame)

    def refresh_data(self) -> None:
        self.tuns = F.tunnels(self.app_.rows)
        self.query_one("#dash", Static).update(F.dashboard(self.app_.rows))
        self._frame()

    def _frame(self) -> None:
        # only animate while this view is on screen (not behind a dialog, the boot screen or another view)
        if getattr(self.parent, "current", None) != self.id or self.app.screen is not self.screen:
            return
        self.frame += 1
        width = max(80, self.size.width - 4)
        self.query_one("#dash-topology", Static).update(F.topology(self.tuns, self.frame, width))
        self.query_one("#dash-ticker", Static).update(F.ticker(self.app_.rows, self.frame, width))


# ================================================================ 2 · explorer

class ExplorerView(View):
    BINDINGS = [Binding("slash", "focus_query", "Query"), Binding("e", "export", "Export CSV")]

    def compose(self) -> ComposeResult:
        yield Input(placeholder="dh:2 dh:5 pfs:off risk:high score<70 -src:testbed finding:KE-001 traffic:voip", id="ex-query")
        yield Static(id="ex-status")
        with Horizontal(id="ex-body"):
            yield DataTable(id="ex-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="ex-side"):
                yield Label("FACETS", classes="side-title")
                yield OptionList(id="ex-facets")
                yield Label("SELECTED", classes="side-title")
                with VerticalScroll():
                    yield Static(id="ex-detail")

    def on_mount(self) -> None:
        t = self.query_one("#ex-table", DataTable)
        for name, width in (("ID", 11), ("CAPTURE", 30), ("SRC", 8), ("SCORE", 6), ("RISK", 9), ("IKE", 6), ("ENCRYPTION", 16),
                            ("DH", 4), ("PFS", 4), ("AUTH", 6), ("POLICY", 11), ("C/H/M", 8)):
            t.add_column(name, width=width)
        self.filtered: list[dict] = []

    def refresh_data(self) -> None:
        self._apply(self.query_one("#ex-query", Input).value)

    def action_focus_query(self) -> None:
        self.query_one("#ex-query", Input).focus()

    @on(Input.Changed, "#ex-query")
    def _q(self, event: Input.Changed) -> None:
        self._apply(event.value)

    @on(Input.Submitted, "#ex-query")
    def _q_done(self) -> None:
        self.query_one("#ex-table", DataTable).focus()

    def _apply(self, query: str) -> None:
        rows = self.app_.rows
        self.filtered = core.filter_rows(rows, query)
        t = self.query_one("#ex-table", DataTable)
        t.clear()
        for r in self.filtered:
            sc = r["severity_counts"]
            t.add_row(_cell(r["analysis_id"], T.BLUE), _cell(r["filename"].split("__", 1)[-1][:30]), _cell(r["source"], T.DIM),
                      _cell(r["score"], f"bold {T.score_color(r['score'])}"), _cell((r["risk_level"] or "").split()[0], T.risk_color(r["risk_level"])),
                      _cell(r["ike_version"] or "—"), _cell((r["ike_encryption"] or "—")[:16]), _cell(r["dh_group"] or "—"),
                      _cell(r["pfs"] or "—", T.GREEN if r["pfs"] == "on" else T.ORANGE if r["pfs"] == "off" else T.DIM),
                      _cell(r["auth"] or "—"), _cell(r["policy_status"][:11], T.GREEN if r["policy_status"] == "Compliant" else T.ORANGE),
                      Text.assemble((f"{sc.get('Critical', 0)}", T.RED), ("/", T.DIM), (f"{sc.get('High', 0)}", T.ORANGE),
                                    ("/", T.DIM), (f"{sc.get('Medium', 0)}", T.GOLD)),
                      key=r["analysis_id"])
        self.query_one("#ex-status", Static).update(Text.assemble(
            (f" {len(self.filtered)}", f"bold {T.TEXT}"), (f" of {len(rows)} captures match", T.DIM),
            ("   " + core.query_help()[:0], T.DIM)))
        fl = self.query_one("#ex-facets", OptionList)
        fl.clear_options()
        for field, counts in core.facet_counts(self.filtered).items():
            for value, n in list(counts.items())[:5]:
                fl.add_option(Option(Text.assemble((f"{field}:{value.split()[0]:<10}", T.BLUE), (f" {n}", T.MUTED)), id=f"{field}:{value.split()[0]}"))
        if self.filtered:
            self._detail(self.filtered[0])
        else:
            self.query_one("#ex-detail", Static).update(Text("No captures match", style=T.DIM))

    def _detail(self, row: dict) -> None:
        self.query_one("#ex-detail", Static).update(F.row_detail(row))

    @on(DataTable.RowHighlighted, "#ex-table")
    def _hl(self, event: DataTable.RowHighlighted) -> None:
        row = next((r for r in self.filtered if r["analysis_id"] == (event.row_key.value if event.row_key else None)), None)
        if row:
            self._detail(row)

    @on(DataTable.RowSelected, "#ex-table")
    def _open(self, event: DataTable.RowSelected) -> None:
        if event.row_key and event.row_key.value:
            self.app_.open_analysis(event.row_key.value)

    @on(OptionList.OptionSelected, "#ex-facets")
    def _facet(self, event: OptionList.OptionSelected) -> None:
        q = self.query_one("#ex-query", Input)
        term = event.option.id or ""
        parts = q.value.split()
        q.value = " ".join(p for p in parts if p != term) if term in parts else " ".join([*parts, term])

    def action_export(self) -> None:
        path = Path.cwd() / "securiq-fleet.csv"
        path.write_text(core.rows_to_csv(self.filtered), encoding="utf-8")
        self.app_.notify(f"{len(self.filtered)} rows → {path.name}", title="Exported")


# ================================================================ 3 · link graph

class GraphCanvas(Static, can_focus=True):
    def on_click(self, event: Click) -> None:
        self.post_message(GraphView.Clicked(event.x, event.y))


class GraphView(View):
    class Clicked(Message):
        def __init__(self, x: int, y: int) -> None:
            super().__init__()
            self.x, self.y = x, y

    BINDINGS = [
        Binding("left", "move('left')", "Prev", show=False), Binding("right", "move('right')", "Next", show=False),
        Binding("up", "move('up')", show=False), Binding("down", "move('down')", show=False),
        Binding("n", "cycle(1)", "Next node"), Binding("p", "cycle(-1)", "Prev node"),
        Binding("enter", "isolate", "Isolate"), Binding("escape", "release", "Release"),
        Binding("i", "toggle('finding')", "Findings"), Binding("c", "toggle('config')", "Configs"),
        Binding("y", "toggle('traffic')", "Traffic"), Binding("g", "toggle('gateway')", "Gateways"),
        Binding("h", "toggle('fingerprint')", "Fingerprints"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="g-main"):
                yield Static(id="g-legend")
                yield GraphCanvas(id="g-canvas")
            with Vertical(id="g-side"):
                yield Label("SELECTED", classes="side-title")
                with VerticalScroll(id="g-detail-scroll"):
                    yield Static(id="g-detail")
                yield Label("INSIGHTS", classes="side-title")
                with VerticalScroll():
                    yield Static(id="g-insights")

    def on_mount(self) -> None:
        self.g: dict = {"nodes": [], "edges": [], "counts": {}}
        self.sel: str | None = None
        self.show_types = set(T.NODE_COLOR)
        self.isolated: set[str] | None = None
        self.cells: dict[str, tuple[int, int]] = {}
        self.order: list[str] = []
        self.progress = 1.0
        self.settler = self.set_interval(0.04, self._settle_step, pause=True)

    def refresh_data(self) -> None:
        self.g = self.app_.graph
        if self.sel not in {n["id"] for n in self.g["nodes"]}:
            self.sel = None
        self._animate_in()
        self.query_one("#g-insights", Static).update(F.graph_insights(self.g, self.app_.rows))
        self.query_one("#g-canvas", GraphCanvas).focus()

    def on_resize(self) -> None:
        self._draw()

    def _animate_in(self) -> None:
        """Nodes burst from the centre and settle into the force-directed layout."""
        self.progress = 0.0
        self.settler.resume()
        self._draw()

    def _settle_step(self) -> None:
        self.progress = min(1.0, self.progress + 0.07)
        self._draw()
        if self.progress >= 1.0:
            self.settler.pause()

    def _draw(self) -> None:
        canvas = self.query_one("#g-canvas", GraphCanvas)
        w, h = max(40, canvas.size.width), max(12, canvas.size.height)
        text, self.cells, self.order = F.graph_canvas(self.g, w, h, self.sel, self.show_types, self.isolated, self.progress)
        canvas.update(text)
        legend = Text()
        for kind in T.NODE_COLOR:
            on_ = kind in self.show_types
            legend.append(f" {T.NODE_GLYPH[kind]} {kind} ", style=T.NODE_COLOR[kind] if on_ else f"strike {T.DIM}")
            legend.append(f"{self.g['counts'].get(kind, 0)}  ", style=T.DIM)
        if self.isolated:
            legend.append("  ISOLATED · esc releases", style=f"bold {T.GOLD}")
        self.query_one("#g-legend", Static).update(legend)
        detail = self.query_one("#g-detail", Static)
        detail.update(F.node_detail(self.g, self.sel) if self.sel else Text("Use the arrow keys or click a node.\nn / p cycles.", style=T.DIM))

    def _select(self, node_id: str | None) -> None:
        self.sel = node_id
        self._draw()

    def action_move(self, direction: str) -> None:
        if not self.cells:
            return
        if self.sel not in self.cells:
            self._select(self.order[0])
            return
        x0, y0 = self.cells[self.sel]
        best, best_d = None, 1e9
        for nid, (x, y) in self.cells.items():
            if nid == self.sel:
                continue
            dx, dy = x - x0, (y - y0) * 2.2
            ok = {"left": dx < 0 and abs(dx) >= abs(dy) * 0.4, "right": dx > 0 and abs(dx) >= abs(dy) * 0.4,
                  "up": dy < 0 and abs(dy) >= abs(dx) * 0.4, "down": dy > 0 and abs(dy) >= abs(dx) * 0.4}[direction]
            if ok and (d := dx * dx + dy * dy) < best_d:
                best, best_d = nid, d
        if best:
            self._select(best)

    def action_cycle(self, step: int) -> None:
        if not self.order:
            return
        i = self.order.index(self.sel) if self.sel in self.order else -1
        self._select(self.order[(i + step) % len(self.order)])

    def action_toggle(self, kind: str) -> None:
        self.show_types ^= {kind}
        if not self.show_types:
            self.show_types = set(T.NODE_COLOR)
        self._animate_in()

    def action_isolate(self) -> None:
        if not self.sel:
            return
        near = {self.sel} | {e["target"] for e in self.g["edges"] if e["source"] == self.sel} | {e["source"] for e in self.g["edges"] if e["target"] == self.sel}
        second = {x for e in self.g["edges"] for x in (e["source"], e["target"]) if e["source"] in near or e["target"] in near}
        self.isolated = near | (second if any(n["id"] == self.sel and n["type"] in ("gateway", "fingerprint", "finding", "traffic", "config") for n in self.g["nodes"]) else set())
        self.show_types = set(T.NODE_COLOR)
        self._animate_in()

    def action_release(self) -> None:
        self.isolated = None
        self._animate_in()

    @on(Clicked)
    def _clicked(self, event: "GraphView.Clicked") -> None:
        best, best_d = None, 9.0
        for nid, (x, y) in self.cells.items():
            d = (x - event.x) ** 2 + ((y - event.y) * 2) ** 2
            if d < best_d:
                best, best_d = nid, d
        if best:
            self._select(best)

    def selected_capture(self) -> str | None:
        node = next((n for n in self.g["nodes"] if n["id"] == self.sel), None)
        return node.get("analysis_id") if node and node["type"] == "capture" else None


# ================================================================ 4 · triage inbox

class InboxView(View):
    BINDINGS = [Binding("j", "cursor(1)", show=False), Binding("k", "cursor(-1)", show=False),
                Binding("i", "status('investigating')", "Investigating"), Binding("a", "status('accepted')", "Accept"),
                Binding("r", "status('resolved')", "Resolve"), Binding("f", "status('false_positive')", "False +"),
                Binding("w", "status('new')", "Reset"), Binding("n", "note", "Note"), Binding("x", "mark", "Select"),
                Binding("s", "cycle_status", "Status filter"), Binding("v", "cycle_sev", "Severity filter")]

    STATUSES = [None, "new", "investigating", "accepted", "resolved", "false_positive"]
    SEVS = [None, "Critical", "High", "Medium", "Low"]

    def compose(self) -> ComposeResult:
        yield Static(id="in-counts")
        with Horizontal(id="in-body"):
            yield DataTable(id="in-table", cursor_type="row", zebra_stripes=True)
            with VerticalScroll(id="in-side"):
                yield Static(id="in-detail")

    def on_mount(self) -> None:
        t = self.query_one("#in-table", DataTable)
        for name, width in (("", 2), ("SEV", 10), ("FINDING", 50), ("CAPTURE", 24), ("STATUS", 14), ("NOTE", 22)):
            t.add_column(name, width=width)
        self.inbox: dict = {"items": [], "counts": {}}
        self.items: list[dict] = []
        self.marked: set[str] = set()
        self.f_status = 0
        self.f_sev = 0

    def refresh_data(self) -> None:
        self.inbox = core.triage_inbox()
        self._fill()

    def _fill(self, keep: str | None = None) -> None:
        st, sv = self.STATUSES[self.f_status], self.SEVS[self.f_sev]
        self.items = [i for i in self.inbox["items"] if (not st or i["status"] == st) and (not sv or i["severity"] == sv)]
        t = self.query_one("#in-table", DataTable)
        t.clear()
        for i in self.items:
            t.add_row(_cell("■" if i["key"] in self.marked else "", T.GOLD), T.severity_chip(i["severity"]),
                      Text.assemble((f"{i['finding_id']} ", T.DIM), (i["title"][:44], T.TEXT)),
                      _cell(i["filename"].split("__", 1)[-1][:24], T.MUTED),
                      _cell(i["status"].replace("_", " "), F.STATUS_STYLE.get(i["status"], T.MUTED)), _cell(i["note"][:22], T.DIM), key=i["key"])
        if keep and any(i["key"] == keep for i in self.items):
            t.move_cursor(row=[i["key"] for i in self.items].index(keep))
        head = Group(F.inbox_counts(self.inbox),
                     Text(f"filter  status={st or 'any'}  severity={sv or 'any'}   ·   {len(self.items)} shown · {len(self.marked)} selected", style=T.DIM))
        self.query_one("#in-counts", Static).update(head)
        self._detail()

    def _current(self) -> dict | None:
        t = self.query_one("#in-table", DataTable)
        if not self.items or t.cursor_row is None or t.cursor_row >= len(self.items):
            return None
        return self.items[t.cursor_row]

    def _detail(self) -> None:
        item = self._current()
        out = self.query_one("#in-detail", Static)
        if not item:
            out.update(Text("Inbox is empty", style=T.DIM))
            return
        try:
            rec = core.record(item["analysis_id"])
            body: Any = render.chain(rec, item["finding_id"])
        except core.CoreError as exc:
            body = Text(str(exc), style=T.RED)
        hist = [Text.assemble((time.strftime("%m-%d %H:%M ", time.localtime(h["at"])), T.DIM), (f"{h['from']} → {h['to']}", T.MUTED)) for h in item.get("history", [])]
        out.update(Group(body, panel(Group(*hist), "Status history") if hist else Text("")))

    @on(DataTable.RowHighlighted, "#in-table")
    def _hl(self) -> None:
        self._detail()

    @on(DataTable.RowSelected, "#in-table")
    def _open(self) -> None:
        item = self._current()
        if item:
            self.app_.open_analysis(item["analysis_id"])

    def action_cursor(self, step: int) -> None:
        t = self.query_one("#in-table", DataTable)
        t.action_cursor_down() if step > 0 else t.action_cursor_up()

    def _targets(self) -> list[str]:
        if self.marked:
            return list(self.marked)
        item = self._current()
        return [item["key"]] if item else []

    def action_status(self, status: str) -> None:
        keys = self._targets()
        if keys:
            keep = keys[0] if len(keys) == 1 else None
            core.triage_update(keys, status=status)
            self.marked.clear()
            self.refresh_data()
            if keep:
                self._fill(keep)
            self.app_.notify(f"{len(keys)} → {status.replace('_', ' ')}", title="Triage")

    def action_mark(self) -> None:
        item = self._current()
        if item:
            self.marked ^= {item["key"]}
            self._fill(item["key"])
            self.action_cursor(1)

    def action_cycle_status(self) -> None:
        self.f_status = (self.f_status + 1) % len(self.STATUSES)
        self._fill()

    def action_cycle_sev(self) -> None:
        self.f_sev = (self.f_sev + 1) % len(self.SEVS)
        self._fill()

    def action_note(self) -> None:
        keys = self._targets()
        item = self._current()
        if not keys:
            return

        def done(value: str | None) -> None:
            if value is not None:
                core.triage_update(keys, note=value)
                self.refresh_data()
                if len(keys) == 1:
                    self._fill(keys[0])
        self.app.push_screen(TextPrompt("Analyst note", item["note"] if item and len(keys) == 1 else "", "why is this accepted / what did you find?"), done)


# ================================================================ 5 · workspace

TABS = [("overview", "Overview"), ("protocol", "Protocol"), ("findings", "Findings"), ("threats", "Threats"),
        ("compliance", "Compliance"), ("traffic", "Traffic"), ("timeline", "Timeline"), ("surface", "Surface"),
        ("privacy", "Privacy"), ("policy", "Policy"), ("fingerprint", "Fingerprint"), ("simulator", "What-if"),
        ("packets", "Packets"), ("report", "Report")]


class WorkspaceView(View):
    BINDINGS = [Binding("left_square_bracket", "tab(-1)", "Prev tab", show=False), Binding("right_square_bracket", "tab(1)", "Next tab", show=False),
                Binding("x", "export('html')", "Export HTML"), Binding("j", "export('json')", "Export JSON"),
                Binding("d", "baseline", "Drift baseline")]

    def compose(self) -> ComposeResult:
        yield Static(id="ws-head")
        with TabbedContent(id="ws-tabs"):
            for key, title in TABS:
                with TabPane(title, id=f"tab-{key}"):
                    if key == "findings":
                        with Horizontal():
                            yield DataTable(id="fd-table", cursor_type="row", zebra_stripes=True)
                            with VerticalScroll(id="fd-side"):
                                yield Static(id="fd-chain")
                    elif key == "simulator":
                        with Horizontal():
                            yield KnobForm(id="sim-form")
                            with Vertical(id="sim-main"):
                                with Horizontal(id="sim-buttons"):
                                    yield Button("Apply recommended", id="sim-rec", variant="primary")
                                    yield Button("Reset", id="sim-reset")
                                    yield Button("Verify in digital twin", id="sim-verify", variant="warning")
                                with VerticalScroll():
                                    yield Static(id="sim-out")
                    elif key == "report":
                        with Horizontal(id="rp-buttons"):
                            yield Button("Executive", id="rp-exec", variant="primary")
                            yield Button("Technical", id="rp-tech")
                            yield Button("Export HTML (x)", id="rp-html")
                            yield Button("Export JSON (j)", id="rp-json")
                        with VerticalScroll():
                            yield Static(id="out-report")
                    else:
                        with VerticalScroll():
                            yield Static(id=f"out-{key}")

    def on_mount(self) -> None:
        t = self.query_one("#fd-table", DataTable)
        for name, width in (("SEV", 10), ("ID", 11), ("FINDING", 44), ("BASIS", 12)):
            t.add_column(name, width=width)
        self.rec: dict | None = None
        self.rendered: set[str] = set()
        self.baseline: str | None = None
        self.sim_base: dict | None = None
        self.report_kind = "executive"

    # ---- data
    def load(self, rec: dict) -> None:
        self.rec = rec
        self.rendered.clear()
        self.baseline = None
        self.sim_base = None
        sec = rec["security"]
        name = rec["parsed_metadata"]["filename"].split("__", 1)[-1]
        self.query_one("#ws-head", Static).update(Text.assemble(
            (" ◆ ", T.BLUE), (name, f"bold {T.TEXT}"), (f"   {rec['analysis_id']}", T.DIM), ("   ", ""),
            T.chip(f"{sec['overall_score']}", T.score_color(sec["overall_score"])), (f" {sec['risk_level']}", T.risk_color(sec["risk_level"])),
            (f"   {rec['intel']['fingerprint']['id']}", T.VIOLET), (f"   {rec['parsed_metadata']['total_packets']} pkts", T.DIM)))
        self.render_tab(self.query_one("#ws-tabs", TabbedContent).active)

    def refresh_data(self) -> None:
        if self.rec is None and self.app_.current_id:
            self.load(core.record(self.app_.current_id))
        elif self.rec is None:
            self.query_one("#out-overview", Static).update(panel(Text("No capture open.\n\nPress  o  to open or analyse a capture, or pick one from the Explorer.", style=T.DIM), "Workspace"))

    @on(TabbedContent.TabActivated)
    def _tab(self, event: TabbedContent.TabActivated) -> None:
        if event.pane.id:
            self.render_tab(event.pane.id)

    def action_tab(self, step: int) -> None:
        tabs = self.query_one("#ws-tabs", TabbedContent)
        ids = [f"tab-{k}" for k, _ in TABS]
        i = ids.index(tabs.active) if tabs.active in ids else 0
        tabs.active = ids[(i + step) % len(ids)]

    def render_tab(self, tab_id: str) -> None:
        rec = self.rec
        if rec is None or tab_id in self.rendered:
            return
        key = tab_id.removeprefix("tab-")
        self.rendered.add(tab_id)
        aid = rec["analysis_id"]
        if key == "findings":
            t = self.query_one("#fd-table", DataTable)
            t.clear()
            for f in rec["security"]["findings"]:
                t.add_row(T.severity_chip(f["severity"]), _cell(f["id"], T.DIM), _cell(f["title"][:44]), T.source_tag(f.get("evidence_source")), key=f["id"])
            if rec["security"]["findings"]:
                self.query_one("#fd-chain", Static).update(render.chain(rec, rec["security"]["findings"][0]["id"]))
        elif key == "simulator":
            self._sim_load()
        elif key == "report":
            self._report()
        elif key == "overview":
            self.query_one("#out-overview", Static).update(render.view(rec, "overview"))
        elif key == "packets":
            self.query_one("#out-packets", Static).update(render.packets(core.packets(aid), 200))
        elif key == "policy":
            self.query_one("#out-policy", Static).update(render.policy(rec, core.policy_evaluate(rec)))
        elif key == "fingerprint":
            self._fingerprint()
        else:
            self.query_one(f"#out-{key}", Static).update(render.view(rec, key))

    # ---- findings
    @on(DataTable.RowHighlighted, "#fd-table")
    def _finding(self, event: DataTable.RowHighlighted) -> None:
        if self.rec and event.row_key and event.row_key.value:
            self.query_one("#fd-chain", Static).update(render.chain(self.rec, event.row_key.value))

    # ---- fingerprint + drift
    def _fingerprint(self) -> None:
        assert self.rec
        parts: list[Any] = [render.fingerprint(self.rec)]
        try:
            parts.append(render.drift(core.drift(self.rec["analysis_id"], self.baseline)))
        except core.CoreError as exc:
            parts.append(Text(str(exc), style=T.RED))
        parts.append(Text("press d to choose a baseline (an @N reference or an analysis id)", style=T.DIM))
        self.query_one("#out-fingerprint", Static).update(Group(*parts))

    def action_baseline(self) -> None:
        def done(value: str | None) -> None:
            if value:
                self.baseline = value.strip()
                self.rendered.discard("tab-fingerprint")
                self.query_one("#ws-tabs", TabbedContent).active = "tab-fingerprint"
                self.render_tab("tab-fingerprint")
        self.app.push_screen(TextPrompt("Drift baseline", "", "@2 or an analysis id"), done)

    # ---- simulator
    def _sim_load(self) -> None:
        assert self.rec
        self.sim_base = core.simulator_baseline(self.rec)
        self.query_one("#sim-form", KnobForm).load(self.sim_base["current"])
        rec_changes = self.sim_base["recommended"]
        self.query_one("#sim-out", Static).update(panel(Group(
            Text("Change any setting on the left — the unchanged rule engine re-scores this capture.", style=T.MUTED), Text(""),
            Text("Recommended changes for this capture:", style=T.DIM),
            *[Text.assemble(("  ▸ ", T.BLUE), (f"{k} → {v}", T.TEXT)) for k, v in rec_changes.items()] or [Text("  none: nothing fixable here", style=T.GREEN)]),
            "What-if simulator"))

    def _sim_changes(self) -> dict[str, Any]:
        cur = (self.sim_base or {}).get("current", {})
        return {k: v for k, v in self.query_one("#sim-form", KnobForm).values().items() if v != cur.get(k) and k in cur}

    @on(KnobForm.Changed, "#sim-form")
    def _sim_changed(self) -> None:
        self._simulate(self._sim_changes())

    def _simulate(self, changes: dict[str, Any]) -> None:
        if not self.rec or not changes:
            return
        rec = self.rec

        def work(progress):
            return core.simulate(rec, changes)

        def done(sim):
            self.query_one("#sim-out", Static).update(render.simulation(sim))
        self.app_.background("Simulating…", work, done, quiet=True)

    @on(Button.Pressed, "#sim-rec")
    def _sim_rec(self) -> None:
        if self.sim_base:
            merged = {**self.sim_base["current"], **self.sim_base["recommended"]}
            self.query_one("#sim-form", KnobForm).load(merged)
            self._simulate(self.sim_base["recommended"])

    @on(Button.Pressed, "#sim-reset")
    def _sim_reset(self) -> None:
        if self.sim_base:
            self.query_one("#sim-form", KnobForm).load(self.sim_base["current"])
            self._sim_load()

    @on(Button.Pressed, "#sim-verify")
    def _sim_verify(self) -> None:
        changes = self._sim_changes() or (self.sim_base or {}).get("recommended") or {}
        if not self.rec or not changes:
            self.app_.notify("Change a setting first", severity="warning")
            return
        rec = self.rec
        self.app_.background("Verifying in the digital twin…", lambda progress: core.verify(rec, changes, progress),
                             lambda v: self.query_one("#sim-out", Static).update(render.verification(v)))

    # ---- report
    def _report(self) -> None:
        if self.rec:
            self.query_one("#out-report", Static).update(render.view(self.rec, self.report_kind))

    @on(Button.Pressed, "#rp-exec")
    def _rp_exec(self) -> None:
        self.report_kind = "executive"
        self._report()

    @on(Button.Pressed, "#rp-tech")
    def _rp_tech(self) -> None:
        self.report_kind = "technical"
        self._report()

    @on(Button.Pressed, "#rp-html")
    def _rp_html(self) -> None:
        self.action_export("html")

    @on(Button.Pressed, "#rp-json")
    def _rp_json(self) -> None:
        self.action_export("json")

    def action_export(self, fmt: str) -> None:
        if not self.rec:
            return
        path = Path.cwd() / f"securiq-{self.rec['analysis_id']}-{self.report_kind}.{fmt}"
        try:
            path.write_text(core.render_report(self.rec, self.report_kind, fmt), encoding="utf-8")
        except core.CoreError as exc:
            self.app_.notify(str(exc), severity="error")
            return
        self.app_.notify(str(path), title=f"{self.report_kind.title()} report exported")


# ================================================================ 6 · live ops

class LiveView(View):
    BINDINGS = [Binding("s", "replay", "Replay"), Binding("c", "capture", "Capture"), Binding("k", "stop", "Stop"),
                Binding("enter", "open_result", "Open result")]

    def compose(self) -> ComposeResult:
        with Horizontal(id="live-controls"):
            yield Select([], id="live-src", prompt="capture to replay", compact=True)
            yield Select([("1×", 1.0), ("5×", 5.0), ("10×", 10.0), ("25×", 25.0), ("50×", 50.0), ("max", 0.0)], id="live-speed", value=10.0,
                         allow_blank=False, compact=True)
            yield Button("▶ Replay", id="live-replay", variant="primary")
            yield Select([], id="live-iface", prompt="interface", compact=True)
            yield Button("◉ Capture", id="live-capture", variant="warning")
            yield Button("■ Stop", id="live-stop", variant="error")
        with VerticalScroll():
            yield Static(id="live-out")

    def on_mount(self) -> None:
        self.session = None
        self.alerts: list[dict] = []
        self.pps: list[float] = []
        self.seq = 0
        self.timer = self.set_interval(0.5, self._tick, pause=True)
        self.query_one("#live-out", Static).update(panel(Text(
            "Real-time analysis: pick a stored capture and replay it paced, or capture a live interface.\n"
            "The engine grows the profile, the score and the alerts as packets arrive; when the stream ends\n"
            "it runs the full pipeline and stores the analysis.", style=T.MUTED), "Live ops"))

    def refresh_data(self) -> None:
        src = self.query_one("#live-src", Select)
        caps = core.list_captures()
        opts = [(f"◇ {s['id']}", s["id"]) for s in caps["samples"]] + [(f"◈ {b['label'][:30]}", b["id"]) for b in caps["lab"]] \
            + [(f"▪ {u['file'][:30]}", u["id"]) for u in caps["uploads"]]
        src.set_options(opts)
        iface = self.query_one("#live-iface", Select)
        try:
            live = core.live_capabilities()
            iface.set_options([(i[-32:], i) for i in live["interfaces"]])
        except Exception:
            iface.set_options([])

    def _start(self, starter) -> None:
        if self.session is not None and self.session.running:
            self.app_.notify("A session is already running — stop it first", severity="warning")
            return
        self.alerts, self.pps, self.seq = [], [], 0
        try:
            self.session = starter()
        except core.CoreError as exc:
            self.app_.notify(str(exc), severity="error", title="Cannot start")
            return
        self.timer.resume()

    @on(Button.Pressed, "#live-replay")
    def action_replay(self) -> None:
        src = self.query_one("#live-src", Select).value
        if src is Select.NULL or src is None:
            self.app_.notify("Choose a capture to replay", severity="warning")
            return
        speed = self.query_one("#live-speed", Select).value
        self._start(lambda: core.live_start_replay(str(src), float(speed)))

    @on(Button.Pressed, "#live-capture")
    def action_capture(self) -> None:
        iface = self.query_one("#live-iface", Select).value
        if iface is Select.NULL or iface is None:
            self.app_.notify("Choose an interface (needs Npcap/tcpdump and privileges)", severity="warning")
            return
        self._start(lambda: core.live_start_interface(str(iface)))

    @on(Button.Pressed, "#live-stop")
    def action_stop(self) -> None:
        if self.session is not None and self.session.running:
            self.session.stop()

    def _tick(self) -> None:
        s = self.session
        if s is None:
            return
        for ev in s.events_since(self.seq):
            self.seq = ev["seq"]
            if ev["type"] == "alert":
                self.alerts.append(ev["data"])
        self.pps.append(s.metrics.get("ingest_pps", 0.0))
        self.query_one("#live-out", Static).update(F.live(s.summary(), s.snapshot, self.alerts, self.pps))
        if not s.running and s.status != "finalizing":
            self.timer.pause()
            if s.analysis_id:
                self.app_.notify(f"Full analysis {s.analysis_id} saved — press enter to open", title="Live session finished")
                self.app_.refresh_fleet()

    def action_open_result(self) -> None:
        if self.session is not None and self.session.analysis_id:
            self.app_.open_analysis(self.session.analysis_id)


# ================================================================ 7 · digital twin

class LabView(View):
    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="lab-side"):
                yield Label("CONFIGURATION", classes="side-title")
                yield KnobForm(extras=True, id="lab-form")
            with Vertical(id="lab-main"):
                with Horizontal(id="lab-controls"):
                    yield Input(value="Lab build", id="lab-label", placeholder="label")
                    yield Input(value="web:25,voip:25", id="lab-traffic", placeholder="class:seconds,…")
                    yield Select([("no impairment", "none"), ("light", "light"), ("moderate", "moderate"), ("heavy", "heavy")], id="lab-imp",
                                 value="none", allow_blank=False, compact=True)
                with Horizontal(id="lab-buttons"):
                    yield Button("Build & analyse", id="lab-build", variant="primary")
                    yield Button("Open in workspace", id="lab-open")
                    yield Button("Reset to secure defaults", id="lab-reset")
                with VerticalScroll():
                    yield Static(id="lab-out")

    def on_mount(self) -> None:
        self.result: dict | None = None
        self.query_one("#lab-form", KnobForm).load({**core.lab_defaults()})
        self.query_one("#lab-out", Static).update(panel(Group(
            Text("Digital twin: choose an IKE version, ciphers, DH group, PFS, mode, lifetimes and the applications in the tunnel.", style=T.MUTED),
            Text("SecurIQ generates the negotiation and the encrypted traffic, captures it as a PCAP, and analyses it from the packets alone.", style=T.MUTED),
            Text(""), Text("The matching strongSwan profile is emitted so the same scenario can run on the Docker lab.", style=T.DIM),
            Text("traffic classes: web video voip file_transfer email chat icmp   (10–60 s each)", style=T.DIM)), "Lab"))

    @on(Button.Pressed, "#lab-reset")
    def _reset(self) -> None:
        self.query_one("#lab-form", KnobForm).load({**core.lab_defaults()})

    @on(Button.Pressed, "#lab-build")
    def _build(self) -> None:
        cfg = self.query_one("#lab-form", KnobForm).values()
        traffic = []
        for item in self.query_one("#lab-traffic", Input).value.split(","):
            if item.strip():
                cls, _, secs = item.strip().partition(":")
                try:
                    traffic.append({"class": cls.strip(), "seconds": float(secs or 25)})
                except ValueError:
                    self.app_.notify(f"Bad traffic entry '{item}'", severity="error")
                    return
        label = self.query_one("#lab-label", Input).value
        imp = str(self.query_one("#lab-imp", Select).value)

        def done(out: dict) -> None:
            self.result = out
            rec = out["record"]
            self.query_one("#lab-out", Static).update(Group(
                Text(f" built {out['file_id']} · {out['packets']} packets · analysis {rec['analysis_id']}", style=f"bold {T.GREEN}"),
                render.overview(rec), render.ground_truth(rec) or Text(""),
                panel(Syntax(out["strongswan_profile"], "ini", theme="ansi_dark", background_color=T.PANEL), "strongSwan profile for the Docker lab")))
            self.app_.refresh_fleet()
        self.app_.background("Building in the digital twin…", lambda progress: core.lab_build(cfg, traffic, label, imp, progress), done)

    @on(Button.Pressed, "#lab-open")
    def _open(self) -> None:
        if self.result:
            self.app_.open_analysis(self.result["record"]["analysis_id"])


# ================================================================ 8 · testbed & model

class TestbedView(View):
    ACTIONS = [("matrix", "Configuration matrix"), ("samples", "Curated samples"), ("model", "Classifier & metrics"),
               ("eval-latest", "Evaluation — last result"), ("eval-run", "Evaluation — run (24 scenarios)"),
               ("bench-latest", "Misconfig benchmark — last result"), ("bench-run", "Misconfig benchmark — run (24)"),
               ("dataset", "Build labelled dataset (30)"), ("regen", "Regenerate samples"), ("train", "Retrain classifier")]

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="tb-side"):
                yield Label("TESTBED & MODEL", classes="side-title")
                yield OptionList(*[Option(title, id=key) for key, title in self.ACTIONS], id="tb-actions")
            with VerticalScroll(id="tb-main"):
                yield Static(id="tb-out")

    @on(OptionList.OptionSelected, "#tb-actions")
    def _run(self, event: OptionList.OptionSelected) -> None:
        key = event.option.id or ""
        out = self.query_one("#tb-out", Static)
        bg = self.app_.background
        if key == "matrix":
            out.update(F.matrix(core.testbed_matrix()))
        elif key == "samples":
            out.update(F.capture_lists({**core.list_captures(), "uploads": [], "lab": []}))
        elif key == "model":
            out.update(F.model(core.model_info()))
        elif key == "eval-latest":
            ev = core.evaluation_latest()
            out.update(F.evaluation(ev) if ev else panel(Text("No stored evaluation yet — choose “run”.", style=T.DIM), "Evaluation"))
        elif key == "bench-latest":
            b = core.benchmark_latest()
            out.update(F.benchmark(b) if b else panel(Text("No stored benchmark yet — choose “run”.", style=T.DIM), "Benchmark"))
        elif key == "eval-run":
            bg("Evaluating on unseen scenarios…", lambda p: core.evaluate(24, 2024, p), lambda r: out.update(F.evaluation(r)))
        elif key == "bench-run":
            bg("Running the misconfiguration benchmark…", lambda p: core.benchmark(24, 99, p), lambda r: out.update(F.benchmark(r)))
        elif key == "dataset":
            def done(r: dict) -> None:
                out.update(panel(Group(*[Text.assemble((f"{k}: ", T.DIM), (str(v), T.TEXT)) for k, v in r.items() if isinstance(v, (str, int, float))]), "Dataset written"))
            bg("Rendering labelled scenarios…", lambda p: core.build_dataset(30, 1, p), done)
        elif key == "regen":
            bg("Regenerating samples…", lambda p: core.regenerate_samples(p), lambda n: (out.update(Text(f"{n} samples regenerated", style=T.GREEN)), self.app_.refresh_fleet()))
        elif key == "train":
            bg("Retraining the classifier…", lambda p: core.train(p), lambda r: out.update(F.model(core.model_info())))


# ================================================================ 9 · policy

class PolicyView(View):
    BINDINGS = [Binding("r", "reset", "Reset policy")]

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="pol-side"):
                yield Label("GOLDEN POLICY  ·  enter edits a value", classes="side-title")
                yield DataTable(id="pol-table", cursor_type="row", zebra_stripes=True)
            with VerticalScroll():
                yield Static(id="pol-fleet")

    def on_mount(self) -> None:
        t = self.query_one("#pol-table", DataTable)
        t.add_column("KEY", width=28)
        t.add_column("VALUE", width=36)

    def refresh_data(self) -> None:
        cur, default = core.policy_get()
        t = self.query_one("#pol-table", DataTable)
        t.clear()
        for k, v in cur.items():
            t.add_row(_cell(k, T.MUTED), _cell(v if not isinstance(v, list) else ", ".join(map(str, v)), T.TEXT if v == default.get(k) else f"bold {T.VIOLET}"), key=k)
        self._fleet()

    def _fleet(self) -> None:
        def work(progress):
            out = []
            for a in core.analyses()[:40]:
                rec = core.record(a["analysis_id"])
                out.append((rec, core.policy_evaluate(rec)))
            return out

        def done(results):
            from rich.table import Table
            from rich import box
            tb = Table(box=box.SIMPLE_HEAD, header_style=f"bold {T.DIM}", expand=True, padding=(0, 1))
            for c in ("CAPTURE", "STATUS", "PASS", "FAIL", "UNKNOWN", "COMPLIANCE"):
                tb.add_column(c, style=T.MUTED, no_wrap=True, overflow="ellipsis")
            for rec, res in results:
                c = res["counts"]
                tb.add_row(rec["parsed_metadata"]["filename"].split("__", 1)[-1][:34],
                           Text(res["status"], style=T.GREEN if res["status"] == "Compliant" else T.ORANGE),
                           Text(str(c["pass"]), style=T.GREEN), Text(str(c["fail"]), style=T.RED if c["fail"] else T.DIM), str(c["unknown"]),
                           viz.score_bar(res.get("score"), 12))
            ok = sum(1 for _, r in results if r["status"] == "Compliant")
            self.query_one("#pol-fleet", Static).update(panel(tb, "Every capture against the active policy", f"{ok}/{len(results)} compliant · unknown is never a pass"))
        self.app_.background("Evaluating fleet…", work, done, quiet=True)

    @on(DataTable.RowSelected, "#pol-table")
    def _edit(self, event: DataTable.RowSelected) -> None:
        key = event.row_key.value if event.row_key else None
        if not key:
            return
        cur, _ = core.policy_get()
        shown = cur[key] if not isinstance(cur[key], list) else ",".join(map(str, cur[key]))

        def done(value: str | None) -> None:
            if value is None:
                return
            try:
                core.policy_set({key: core.parse_policy_value(key, value)})
            except core.CoreError as exc:
                self.app_.notify(str(exc), severity="error")
                return
            self.refresh_data()
            self.app_.refresh_fleet()
        self.app.push_screen(TextPrompt(f"policy · {key}", str(shown), "true / false / number / comma-separated list"), done)

    def action_reset(self) -> None:
        core.policy_reset()
        self.refresh_data()
        self.app_.refresh_fleet()
