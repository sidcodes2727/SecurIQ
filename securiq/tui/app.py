"""SecurIQ operations console: a Gotham-style multi-view terminal application."""
from __future__ import annotations

import time
from functools import partial
from typing import Any, Callable

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import ContentSwitcher, Footer, OptionList, Static
from textual.widgets.option_list import Option

from securiq import __version__, core, theme as T
from securiq.tui import views as V
from securiq.tui.widgets import BootScreen, Help, OpenCapture

# id, nav title, view class, hotkey
VIEWS: list[tuple[str, str, type, str]] = [
    ("v-dash", "Operations", V.DashboardView, "1"),
    ("v-explorer", "Object explorer", V.ExplorerView, "2"),
    ("v-graph", "Link graph", V.GraphView, "3"),
    ("v-inbox", "Triage inbox", V.InboxView, "4"),
    ("v-workspace", "Analysis workspace", V.WorkspaceView, "5"),
    ("v-live", "Live ops", V.LiveView, "6"),
    ("v-lab", "Digital twin", V.LabView, "7"),
    ("v-testbed", "Testbed & model", V.TestbedView, "8"),
    ("v-policy", "Policy & compliance", V.PolicyView, "9"),
]
NAV_GROUPS = {"v-dash": "OPERATE", "v-explorer": "INVESTIGATE", "v-workspace": "ANALYSE", "v-lab": "BUILD & VALIDATE", "v-policy": "GOVERN"}
WORKSPACE_TABS = V.TABS


class Commands(Provider):
    """Command palette: pages, captures, findings, actions."""

    def _entries(self) -> list[tuple[str, str, Callable[[], Any]]]:
        app: SecurIQApp = self.app  # type: ignore[assignment]
        out: list[tuple[str, str, Callable[[], Any]]] = []
        for vid, title, _, key in VIEWS:
            out.append((f"Go to {title}", f"view {key}", partial(app.show_view, vid)))
        for key, title in WORKSPACE_TABS:
            out.append((f"Workspace ▸ {title}", "current capture", partial(app.workspace_tab, key)))
        out.append(("Open / analyse a capture…", "o", app.action_open))
        out.append(("Refresh all data", "ctrl+r", app.refresh_fleet))
        out.append(("Show keyboard help", "?", app.action_help))
        for r in app.rows:
            name = r["filename"].split("__", 1)[-1]
            out.append((f"Open capture: {name}", f"{r['analysis_id']} · score {r['score']} · {r['risk_level']}", partial(app.open_analysis, r["analysis_id"])))
        seen: set[str] = set()
        for r in app.rows:
            for f in r["findings"]:
                if f["id"] not in seen:
                    seen.add(f["id"])
                    out.append((f"Finding {f['id']}: {f['title'][:60]}", f["severity"], partial(app.explorer_query, f"finding:{f['id']}")))
            out.append((f"Fingerprint {r['fingerprint']}", r["fingerprint_label"][:60], partial(app.explorer_query, f"fp:{r['fingerprint']}")))
        for gw in sorted({g for r in app.rows for g in r["gateways"]}):
            out.append((f"Gateway {gw}", "explorer", partial(app.explorer_query, f"gw:{gw}")))
        for q, help_ in (("risk:high", "high-risk captures"), ("pfs:off", "no forward secrecy"), ("dh:2", "1024-bit DH"), ("ike:ikev1", "IKEv1 deployments"),
                         ("policy:Non-compliant", "policy breaches"), ("novelty:novel", "novel configurations"), ("score<50", "score under 50")):
            out.append((f"Query: {q}", help_, partial(app.explorer_query, q)))
        for s in core.list_captures()["samples"]:
            out.append((f"Analyse sample: {s['id']}", f"{s['ike']} · {s['esp']}", partial(app.open_target, s["id"])))
        out.append(("Run misconfiguration benchmark", "testbed", partial(app.testbed_run, "bench-run")))
        out.append(("Run end-to-end evaluation", "testbed", partial(app.testbed_run, "eval-run")))
        out.append(("Show classifier metrics", "testbed", partial(app.testbed_run, "model")))
        return out

    async def discover(self) -> Hits:
        for title, help_, cb in self._entries()[: len(VIEWS) + 1]:
            yield DiscoveryHit(title, cb, help=help_)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, help_, cb in self._entries():
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, matcher.highlight(title), cb, help=help_)


class SecurIQApp(App):
    CSS_PATH = "securiq.tcss"
    TITLE = "SecurIQ"
    COMMANDS = App.COMMANDS | {Commands}
    BINDINGS = [Binding(key, f"view('{vid}')", title, show=False) for vid, title, _, key in VIEWS] + [
        Binding("o", "open", "Open capture"), Binding("ctrl+r", "refresh", "Refresh"), Binding("question_mark", "help", "Help"),
        Binding("ctrl+b", "toggle_nav", "Nav", show=False), Binding("q", "quit", "Quit"),
    ]

    def __init__(self, capture: str | None = None) -> None:
        super().__init__()
        self.start_capture = capture
        self.rows: list[dict] = []
        self.graph: dict = {"nodes": [], "edges": [], "counts": {}}
        self.current_id: str | None = None
        self.busy: str | None = None
        self.ready_note = "starting…"
        self.jobs = 0

    # ------------------------------------------------------------ layout
    def compose(self) -> ComposeResult:
        yield Static(id="classification")
        yield Static(id="topbar")
        with Horizontal(id="shell"):
            with Vertical(id="nav"):
                yield OptionList(id="nav-list")
                yield Static(id="nav-foot")
            with ContentSwitcher(id="views", initial="v-dash"):
                for vid, _, cls, _ in VIEWS:
                    yield cls(id=vid)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#classification", Static).update(Text(
            "  SIH 26160 · NTRO  //  PASSIVE KEYLESS IPSEC ANALYSIS  //  SYNTHETIC TESTBED DATA — NOT FOR OPERATIONAL DECISIONS  ", style=f"bold {T.BG} on {T.TEAL}", justify="center"))
        nav = self.query_one("#nav-list", OptionList)
        for vid, title, _, key in VIEWS:
            if vid in NAV_GROUPS:
                nav.add_option(Option(Text(f"\n {NAV_GROUPS[vid]}", style=f"bold {T.DIM}"), disabled=True))
            nav.add_option(Option(Text.assemble((f" {key} ", f"bold {T.BLUE}"), (title, T.TEXT)), id=vid))
        nav.highlighted = 1
        self.set_interval(1.0, self._tick)
        self._tick()
        self.boot = BootScreen()
        self.push_screen(self.boot)
        self.background("Preparing testbed and classifier…", self._boot_sequence, self._after_ready)

    def _boot_sequence(self, progress: Callable[[str], None]) -> None:
        """Real start-up steps, narrated on the boot screen."""
        started = time.monotonic()

        def log(text: str, detail: str = "") -> None:
            self.call_from_thread(self.boot.log, text, detail)
            time.sleep(0.18)  # paced so each step is readable; the work itself is not delayed

        log("Loading analysis engine", "IKE/ESP parser · rule engine · threat model")
        import backend.pipeline  # noqa: F401  (the heavy import)
        st = core.ready_state()
        log("Testbed sample captures", f"{st['samples']} available" if st["samples"] else "generating 10 labelled captures…")
        log("Traffic classifier", "loaded" if st["model_trained"] else "training ensemble (first run, ~30 s)…")
        core.ensure_ready(progress)
        info = core.model_info()
        log("Classifier online", f"{info['model_type'].split(':')[0]} v{info['model_version']} · {info['n_features']} features · "
                                 f"acc {info['metrics']['accuracy'] * 100:.1f}%")
        log("Indexing analyses", f"{len(core.analyses())} stored")
        caps = core.live_capabilities()
        log("Capture backends", ", ".join(caps["tools"]) or ("scapy" if caps["scapy"] else "replay only"))
        self.call_from_thread(self.boot.finish)
        time.sleep(max(0.0, 1.2 - (time.monotonic() - started)))

    def _after_ready(self, _: Any) -> None:
        if self.screen is self.boot:
            self.boot.dismiss(None)
        self.ready_note = "ready"
        self.refresh_fleet(then=lambda: self.open_target(self.start_capture) if self.start_capture else None)

    # ------------------------------------------------------------ status bar
    def _tick(self) -> None:
        state = core.ready_state() if self.ready_note != "starting…" else {"model_trained": False, "model_training": True, "samples": 0}
        model = Text.assemble(("● ", T.GREEN if state["model_trained"] else T.GOLD), ("model ready" if state["model_trained"] else "model training…", T.MUTED))
        busy = Text.assemble(("  ⟳ ", f"bold {T.GOLD}"), (self.busy, T.GOLD)) if self.busy else Text("")
        current = Text.assemble(("   ◆ ", T.BLUE), (self.current_id, T.MUTED)) if self.current_id else Text("")
        bar = Text.assemble((" ◆ SECURIQ ", f"bold {T.TEXT}"), ("▌ IPSEC VPN ANALYTICS", T.DIM), (f"  v{__version__}", T.DIM), busy)
        right = Text.assemble((f"{len(self.rows)} captures  ", T.MUTED), model, current, ("   ", ""), (time.strftime("%H:%M:%S"), T.DIM), (" ", ""))
        width = max(40, self.size.width)
        pad = max(1, width - bar.cell_len - right.cell_len)
        try:
            self.query_one("#topbar", Static).update(Text.assemble(bar, " " * pad, right))
        except NoMatches:  # the timer can fire while the app is shutting down
            pass

    # ------------------------------------------------------------ navigation
    def action_view(self, vid: str) -> None:
        self.show_view(vid)

    def show_view(self, vid: str) -> None:
        self.query_one("#views", ContentSwitcher).current = vid
        nav = self.query_one("#nav-list", OptionList)
        for i in range(nav.option_count):
            if nav.get_option_at_index(i).id == vid:
                nav.highlighted = i
        view = self.query_one(f"#{vid}")
        if hasattr(view, "refresh_data"):
            view.refresh_data()
        self.call_after_refresh(self._focus_view, vid)

    def _focus_view(self, vid: str) -> None:
        targets = {"v-explorer": "#ex-table", "v-graph": "#g-canvas", "v-inbox": "#in-table", "v-policy": "#pol-table", "v-testbed": "#tb-actions"}
        if vid in targets:
            try:
                self.query_one(targets[vid]).focus()
            except Exception:
                pass

    @on(OptionList.OptionSelected, "#nav-list")
    def _nav(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.show_view(event.option.id)

    def action_toggle_nav(self) -> None:
        nav = self.query_one("#nav")
        nav.display = not nav.display

    def action_help(self) -> None:
        self.push_screen(Help())

    def action_refresh(self) -> None:
        self.refresh_fleet()

    # ------------------------------------------------------------ data
    def refresh_fleet(self, then: Callable[[], Any] | None = None) -> None:
        def work(progress):
            rows = core.fleet_rows()
            return rows, core.link_graph(rows)

        def done(result):
            self.rows, self.graph = result
            current = self.query_one("#views", ContentSwitcher).current
            if current and current != "v-workspace":
                view = self.query_one(f"#{current}")
                if hasattr(view, "refresh_data"):
                    view.refresh_data()
            if then:
                then()
        self.background("Loading fleet…", work, done, quiet=True)

    def background(self, label: str, fn: Callable[[Callable[[str], None]], Any], done: Callable[[Any], Any] | None = None, quiet: bool = False) -> None:
        """Run fn(progress) in a thread; call done(result) on the UI thread; failures become notifications."""
        self.jobs += 1
        if not quiet:
            self.busy = label

        def runner() -> None:
            try:
                result = fn(lambda m: self.call_from_thread(self._set_busy, m))
            except core.CoreError as exc:
                self.call_from_thread(self._failed, str(exc))
                return
            except Exception as exc:  # surfaced to the analyst rather than crashing the console
                self.call_from_thread(self._failed, f"{type(exc).__name__}: {exc}")
                return
            self.call_from_thread(self._finished, done, result)
        self.run_worker(runner, thread=True, exit_on_error=False)

    def _set_busy(self, message: str) -> None:
        if self.busy is not None:
            self.busy = message

    def _finished(self, done: Callable[[Any], Any] | None, result: Any) -> None:
        self.jobs -= 1
        if self.jobs <= 0:
            self.busy = None
            self.jobs = 0
        if done:
            done(result)

    def _failed(self, message: str) -> None:
        self.jobs = max(0, self.jobs - 1)
        if self.jobs == 0:
            self.busy = None
        self.notify(message, severity="error", title="Error", timeout=8)

    # ------------------------------------------------------------ opening captures
    def action_open(self) -> None:
        def chosen(result: tuple[str, str] | None) -> None:
            if not result:
                return
            kind, ident = result
            self.open_analysis(ident) if kind == "analysis" else self.open_target(ident)
        self.push_screen(OpenCapture(), chosen)

    def open_target(self, target: str | None) -> None:
        if not target:
            return
        try:  # already an analysis id / reference?
            self.open_analysis(core.resolve_analysis_id(target)) if target in {a["analysis_id"] for a in core.analyses()} else self._analyze(target)
        except core.CoreError:
            self._analyze(target)

    def _analyze(self, target: str) -> None:
        def done(rec: dict) -> None:
            self.notify(f"score {rec['security']['overall_score']} · {rec['security']['risk_level']}", title=f"Analysed {rec['analysis_id']}")
            self.refresh_fleet()
            self.open_analysis(rec["analysis_id"], rec)
        self.background(f"Analysing {target}…", lambda progress: core.analyze(target, progress), done)

    def open_analysis(self, analysis_id: str, rec: dict | None = None) -> None:
        try:
            rec = rec or core.record(analysis_id)
        except core.CoreError as exc:
            self.notify(str(exc), severity="error")
            return
        self.current_id = rec["analysis_id"]
        ws = self.query_one("#v-workspace", V.WorkspaceView)
        ws.load(rec)
        self.show_view("v-workspace")

    def workspace_tab(self, key: str) -> None:
        if not self.current_id:
            self.notify("Open a capture first (o)", severity="warning")
            return
        self.show_view("v-workspace")
        from textual.widgets import TabbedContent
        self.query_one("#ws-tabs", TabbedContent).active = f"tab-{key}"

    def explorer_query(self, query: str) -> None:
        from textual.widgets import Input
        self.show_view("v-explorer")
        self.query_one("#ex-query", Input).value = query

    def testbed_run(self, key: str) -> None:
        self.show_view("v-testbed")
        lst = self.query_one("#tb-actions", OptionList)
        for i in range(lst.option_count):
            if lst.get_option_at_index(i).id == key:
                lst.highlighted = i
                lst.action_select()
                break


def run(capture: str | None = None) -> None:
    SecurIQApp(capture).run()
