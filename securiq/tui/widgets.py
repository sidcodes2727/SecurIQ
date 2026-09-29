"""Reusable widgets: modal dialogs and the configuration knob form shared by the simulator and the lab."""
from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Input, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from securiq import core, theme as T


class TextPrompt(ModalScreen):
    """Single-line input dialog; dismisses with the text, or None when cancelled."""

    BINDINGS = [("escape", "dismiss(None)", "Cancel")]

    def __init__(self, title: str, value: str = "", placeholder: str = "") -> None:
        super().__init__()
        self._title, self._value, self._placeholder = title, value, placeholder

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self._title.upper(), classes="dialog-title")
            yield Input(value=self._value, placeholder=self._placeholder, id="prompt-input")
            yield Label("enter to confirm · esc to cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    @on(Input.Submitted)
    def _done(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


LOGO = r"""
   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗ ██████╗
   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║██╔═══██╗
   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║██║   ██║
   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║██║▄▄ ██║
   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║╚██████╔╝
   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚══▀▀═╝ """


class BootScreen(ModalScreen):
    """System-initialisation log shown while the engine, samples and classifier load. Any key skips."""

    SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[tuple[str, str, str]] = []  # (status, text, detail)
        self.frame = 0
        self.done_steps = 0
        self.total_steps = 6

    def compose(self) -> ComposeResult:
        with Vertical(id="boot"):
            yield Static(Text(LOGO, style=f"bold {T.BLUE}"), id="boot-logo")
            yield Static(Text("   PASSIVE KEYLESS IPSEC ANALYTICS  ·  SIH 26160  ·  NTRO", style=f"bold {T.DIM}"))
            yield Static(id="boot-log")
            yield Static(id="boot-bar")

    def on_mount(self) -> None:
        self.set_interval(0.08, self._spin)

    def log(self, text: str, detail: str = "", status: str = "run") -> None:
        if self.lines and self.lines[-1][0] == "run":
            s, t, d = self.lines[-1]
            self.lines[-1] = ("ok", t, d)
            self.done_steps += 1
        self.lines.append((status, text, detail))
        if status == "ok":
            self.done_steps += 1
        self._spin()

    def finish(self) -> None:
        if self.lines and self.lines[-1][0] == "run":
            self.lines[-1] = ("ok", *self.lines[-1][1:])
        self.done_steps = self.total_steps
        self._spin()

    def _spin(self) -> None:
        if not self.is_mounted:
            return
        self.frame += 1
        out = Text()
        for status, text, detail in self.lines[-12:]:
            if status == "run":
                out.append(f"   {self.SPINNER[self.frame % len(self.SPINNER)]} ", style=f"bold {T.GOLD}")
            elif status == "ok":
                out.append("   ✓ ", style=f"bold {T.GREEN}")
            else:
                out.append("   ! ", style=f"bold {T.ORANGE}")
            out.append(f"{text:<42}", style=T.TEXT)
            out.append(f"{detail}\n", style=T.DIM)
        self.query_one("#boot-log", Static).update(out)
        frac = min(1.0, self.done_steps / self.total_steps)
        from securiq import viz
        self.query_one("#boot-bar", Static).update(
            Text("\n   ") + viz.bar(frac, 1, 52, T.BLUE) + Text(f"  {frac * 100:3.0f}%   any key to skip", style=T.DIM))

    def on_key(self) -> None:
        self.dismiss(None)


class OpenCapture(ModalScreen):
    """Pick a stored analysis, or a sample / upload / lab build to analyse, or type a path.
    Dismisses with (kind, id) where kind is 'analysis' or 'target'."""

    BINDINGS = [("escape", "dismiss(None)", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label("OPEN CAPTURE", classes="dialog-title")
            yield Input(placeholder="type a .pcap/.pcapng path, or filter the list…", id="open-input")
            yield OptionList(id="open-list")
            yield Label("enter opens (stored analyses instantly, others are analysed first) · esc cancels", classes="hint")

    def on_mount(self) -> None:
        self._entries: list[tuple[str, str, str]] = []
        caps = core.list_captures()
        for a in core.analyses()[:40]:
            name = (a.get("filename") or "").split("__", 1)[-1]
            self._entries.append(("analysis", a["analysis_id"],
                                  f"● {name}  score {a.get('security_score')}  {a.get('risk_level')}  [{a['analysis_id']}]"))
        for s in caps["samples"]:
            self._entries.append(("target", s["id"], f"◇ sample  {s['id']}  ({s['ike']}, {s['esp']}, {s['mode']})"))
        for b in caps["lab"]:
            self._entries.append(("target", b["id"], f"◈ lab     {b['label']}  [{b['id']}]"))
        for u in caps["uploads"][:20]:
            self._entries.append(("target", u["id"], f"▪ upload  {u['file']}  [{u['id']}]"))
        self._fill("")
        self.query_one("#open-input", Input).focus()

    def _fill(self, needle: str) -> None:
        lst = self.query_one("#open-list", OptionList)
        lst.clear_options()
        for kind, ident, label in self._entries:
            if needle.lower() in label.lower():
                lst.add_option(Option(label, id=f"{kind}|{ident}"))

    @on(Input.Changed, "#open-input")
    def _filter(self, event: Input.Changed) -> None:
        self._fill(event.value)

    @on(Input.Submitted, "#open-input")
    def _path(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        lst = self.query_one("#open-list", OptionList)
        if value and (value.lower().endswith((".pcap", ".pcapng", ".cap")) or not lst.option_count):
            self.dismiss(("target", value))
        elif lst.option_count:
            lst.focus()
            lst.highlighted = 0

    @on(OptionList.OptionSelected, "#open-list")
    def _picked(self, event: OptionList.OptionSelected) -> None:
        kind, _, ident = (event.option.id or "").partition("|")
        self.dismiss((kind, ident))


class Help(ModalScreen):
    BINDINGS = [("escape", "dismiss(None)", "Close"), ("question_mark", "dismiss(None)", "Close")]

    TEXT = [
        ("GLOBAL", [("1 – 9", "switch view"), ("ctrl+p", "command palette: pages, captures, findings, actions"),
                    ("o", "open / analyse a capture"), ("ctrl+r", "refresh data"), ("ctrl+b", "collapse navigation"),
                    ("?", "this help"), ("q", "quit")]),
        ("EXPLORER", [("/", "focus the query box"), ("enter", "open capture in workspace"),
                      ("e", "export matching rows to CSV"), ("facet list", "enter adds the facet to the query")]),
        ("LINK GRAPH", [("← ↑ → ↓", "select the neighbouring node"), ("n / p", "next / previous node"),
                        ("enter", "isolate neighbourhood"), ("esc", "release isolation"),
                        ("i c y g h", "toggle findings · configs · traffic · gateways · fingerprints"),
                        ("click", "select the nearest node"), ("o", "open the selected capture")]),
        ("TRIAGE", [("j / k", "move"), ("i a r f", "investigating · accepted · resolved · false positive"),
                    ("w", "back to new"), ("n", "add a note"), ("x", "select / unselect (bulk actions use the selection)"),
                    ("s / v", "cycle status / severity filter"), ("enter", "open the capture")]),
        ("WORKSPACE", [("[ / ]", "previous / next tab"), ("x", "export the report as HTML"), ("j", "export as JSON")]),
        ("LIVE", [("s", "start replay"), ("c", "capture the chosen interface"), ("k", "stop"),
                  ("enter", "open the finished analysis")]),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog wide"):
            yield Label("KEYBOARD", classes="dialog-title")
            for group, rows in self.TEXT:
                body = Text()
                body.append(f"\n{group}\n", style=f"bold {T.DIM}")
                for key, desc in rows:
                    body.append(f"  {key:<14}", style=f"bold {T.BLUE}")
                    body.append(f"{desc}\n", style=T.MUTED)
                yield Static(body)
            yield Label("esc to close", classes="hint")


class KnobForm(VerticalScroll):
    """One Select per configuration knob, grouped; used by the what-if simulator and the digital-twin lab."""

    class Changed(Message):
        def __init__(self, form: "KnobForm") -> None:
            super().__init__()
            self.form = form

        @property
        def control(self) -> "KnobForm":
            return self.form

    def __init__(self, *, extras: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.extras = extras
        self._loading = False

    def compose(self) -> ComposeResult:
        from backend.intel import simulator
        group = None
        for k in simulator.KNOBS:
            if k["group"] != group:
                group = k["group"]
                yield Label(group.upper(), classes="knob-group")
            opts = []
            for o in k["options"]:
                value, label = (o["value"], o["label"]) if isinstance(o, dict) else (o, {True: "on", False: "off"}.get(o, str(o)))
                opts.append((str(label), value))
            yield Label(k["label"], classes="knob-label")
            yield Select(opts, id=f"knob-{k['key']}", allow_blank=True, prompt="unchanged", compact=True)
        if self.extras:
            yield Label("NETWORK", classes="knob-group")
            yield Label("IP version", classes="knob-label")
            yield Select([("IPv4", 4), ("IPv6", 6)], id="knob-ip_version", allow_blank=False, value=4, compact=True)
            yield Label("NAT traversal", classes="knob-label")
            yield Select([("off", False), ("on (UDP 4500)", True)], id="knob-nat_t", allow_blank=False, value=False, compact=True)

    def load(self, values: dict[str, Any]) -> None:
        """Set every Select from a dict; missing or unsupported values become blank."""
        from backend.intel import simulator
        self._loading = True
        for k in simulator.KNOBS:
            sel = self.query_one(f"#knob-{k['key']}", Select)
            valid = [(o["value"] if isinstance(o, dict) else o) for o in k["options"]]
            v = values.get(k["key"])
            if v in valid:
                sel.value = v
            else:
                sel.clear()
        self.set_timer(0.3, self._unlock)

    def _unlock(self) -> None:
        self._loading = False

    def values(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for sel in self.query(Select):
            if sel.id and sel.id.startswith("knob-") and sel.value is not Select.NULL and sel.value is not None:
                out[sel.id[5:]] = sel.value
        return out

    @on(Select.Changed)
    def _changed(self, event: Select.Changed) -> None:
        event.stop()
        if not self._loading:
            self.post_message(self.Changed(self))
