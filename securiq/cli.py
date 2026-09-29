"""`securiq` command line: every feature of the platform, from the shell."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

import click
from rich.console import Console, Group
from rich.text import Text

import securiq
from securiq import core, theme as T

console = Console(highlight=False)

BANNER = f"""[bold {T.BLUE}]SECURIQ[/] [{T.DIM}]▌ IPsec VPN analytics · SIH 26160 · NTRO · v{securiq.__version__}[/]"""


def _fail(message: str) -> None:
    console.print(f"[bold {T.RED}]✕[/] {message}")
    raise SystemExit(1)


def _work(message: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run fn with a spinner; the fn may call its `progress` argument to update the message."""
    try:
        with console.status(f"[{T.MUTED}]{message}[/]", spinner="dots", spinner_style=T.BLUE) as status:
            return fn(*args, progress=lambda m: status.update(f"[{T.MUTED}]{m}[/]"), **kwargs)
    except core.CoreError as exc:
        _fail(str(exc))


def _quiet(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except core.CoreError as exc:
        _fail(str(exc))


def _kv(pairs: tuple[str, ...]) -> dict[str, str]:
    out = {}
    for p in pairs:
        if "=" not in p:
            _fail(f"Expected key=value, got '{p}'")
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out


VIEW_CHOICES = click.Choice(["overview", "protocol", "findings", "threats", "compliance", "traffic", "timeline", "surface",
                             "privacy", "policy", "fingerprint", "esp", "packets", "executive", "technical", "all"],
                            case_sensitive=False)


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(securiq.__version__, prog_name="securiq")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """SecurIQ — AI-powered IPsec VPN protocol analyzer and security assessment.

    Run with no command to open the full-screen console (the operations centre).
    Every feature is also a command below; try `securiq init` then `securiq analyze weak_ikev1_main_3des_md5`.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(tui)


# ---------------------------------------------------------------- console UI

@cli.command()
@click.option("--capture", "-c", help="Open this capture (path, sample name, or analysis id) straight into the workspace")
def tui(capture: str | None) -> None:
    """Open the full-screen operations console (dashboard, explorer, graph, triage, workspace, live, lab, testbed)."""
    from securiq.tui.app import run
    run(capture)


# ---------------------------------------------------------------- setup

@cli.command()
@click.option("--force", is_flag=True, help="Regenerate samples and retrain even if they exist")
def init(force: bool) -> None:
    """Generate the testbed sample captures and train the traffic classifier (first-run setup)."""
    console.print(BANNER)
    if force:
        n = _work("Regenerating samples…", lambda progress: core.regenerate_samples(progress))
        console.print(f"[{T.GREEN}]✓[/] {n} testbed samples generated")
        _work("Training…", lambda progress: core.train(progress))
    else:
        _work("Preparing…", lambda progress: core.ensure_ready(progress))
    st = core.ready_state()
    console.print(f"[{T.GREEN}]✓[/] model trained: {st['model_trained']} · testbed samples: {st['samples']}")
    console.print(f"[{T.DIM}]next: securiq captures · securiq analyze <sample>[/]")


@cli.command()
def doctor() -> None:
    """Check the environment: model, samples, data directory, capture backends."""
    from backend.config import DATA_DIR
    console.print(BANNER)
    st = core.ready_state()
    caps = core.live_capabilities()

    def line(ok: bool | None, label: str, detail: str = "") -> None:
        mark = f"[{T.GREEN}]✓[/]" if ok else f"[{T.GOLD}]![/]" if ok is None else f"[{T.RED}]✕[/]"
        console.print(f" {mark} {label} [{T.DIM}]{detail}[/]")

    line(True, "Python", sys.version.split()[0])
    line(True, "Data directory", str(DATA_DIR))
    line(st["model_trained"], "Traffic classifier", "trained" if st["model_trained"] else "run `securiq init`")
    line(st["samples"] > 0, "Testbed samples", f"{st['samples']} available")
    line(True if caps["tools"] else None, "Capture tools", ", ".join(caps["tools"]) or "none (tcpdump / dumpcap not found)")
    line(True if caps["scapy"] else None, "Scapy live capture", "available" if caps["scapy"] else "not available (needs Npcap / libpcap + privileges)")
    line(True, "Interfaces", f"{len(caps['interfaces'])} found" if caps["interfaces"] else "replay only")
    line(True, "Analyses stored", str(len(core.analyses())))


# ---------------------------------------------------------------- analyse & inspect

@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--view", "-v", "views", multiple=True, type=VIEW_CHOICES, default=("overview",), show_default=True,
              help="What to display (repeatable; 'all' shows every view)")
@click.option("--json", "as_json", is_flag=True, help="Print the full analysis as JSON instead")
@click.option("--open", "open_tui", is_flag=True, help="Open the result in the console workspace")
def analyze(targets: tuple[str, ...], views: tuple[str, ...], as_json: bool, open_tui: bool) -> None:
    """Analyse captures: a .pcap/.pcapng path, a testbed sample name, a lab build id or an upload id."""
    from securiq import render
    last = None
    for target in targets:
        rec = _work(f"Analysing {target}…", core.analyze, target)
        last = rec
        if as_json:
            click.echo(json.dumps(rec, indent=2, default=str))
            continue
        console.print(f"[{T.GREEN}]✓[/] analysis [bold]{rec['analysis_id']}[/] saved — score "
                      f"[bold {T.score_color(rec['security']['overall_score'])}]{rec['security']['overall_score']}[/] · {rec['security']['risk_level']}")
        chosen = render.VIEWS if "all" in views else list(views)
        pk = core.packets(rec["analysis_id"]) if "packets" in chosen else None
        for v in chosen:
            console.print(render.view(rec, v, pk))
    if open_tui and last:
        from securiq.tui.app import run
        run(last["analysis_id"])


@cli.command()
@click.argument("ref", default="latest")
@click.argument("view", type=VIEW_CHOICES, default="overview")
def show(ref: str, view: str) -> None:
    """Show a stored analysis. REF: latest, @N, an id or a file-name fragment."""
    from securiq import render
    rec = _quiet(core.record, ref)
    chosen = render.VIEWS if view == "all" else [view]
    pk = core.packets(rec["analysis_id"]) if "packets" in chosen else None
    for v in chosen:
        console.print(render.view(rec, v, pk))


@cli.command()
@click.argument("ref", default="latest")
@click.argument("finding", required=False)
def explain(ref: str, finding: str | None) -> None:
    """Evidence chain for a finding: packets → parameter → rule → risk → fix (all critical/high when FINDING is omitted)."""
    from securiq import render
    rec = _quiet(core.record, ref)
    if finding and finding.upper() not in rec["intel"]["chains"]:
        _fail(f"No finding {finding} in this analysis. Available: {', '.join(rec['intel']['chains'])}")
    console.print(render.findings(rec, finding))


@cli.command()
@click.argument("ref", default="latest")
@click.option("--kind", type=click.Choice(["all", "esp", "ike", "ah", "other"]), default="all")
@click.option("--limit", default=80, show_default=True)
def packets(ref: str, kind: str, limit: int) -> None:
    """Packet table with ESP sequence-number traces."""
    from securiq import render
    rec = _quiet(core.record, ref)
    console.print(render.packets(core.packets(rec["analysis_id"]), limit, None if kind == "all" else kind))


@cli.command("analyses")
def analyses_cmd() -> None:
    """List stored analyses (use @N or the id as REF elsewhere)."""
    from securiq import render_fleet as F
    items = core.analyses()
    if not items:
        console.print(f"[{T.DIM}]No analyses yet — run `securiq analyze <capture>`[/]")
        return
    console.print(F.analyses_table(items))


@cli.command()
def captures() -> None:
    """List analysable captures: testbed samples, uploads and lab builds."""
    from securiq import render_fleet as F
    _quiet(core.ensure_ready)
    console.print(F.capture_lists(core.list_captures()))


# ---------------------------------------------------------------- fleet

@cli.command()
@click.argument("query", nargs=-1)
@click.option("--csv", "csv_path", type=click.Path(dir_okay=False), help="Write matching rows to a CSV file")
@click.option("--facets", is_flag=True, help="Show facet counts for the matching rows")
@click.option("--help-query", is_flag=True, help="Explain the query language")
def fleet(query: tuple[str, ...], csv_path: str | None, facets: bool, help_query: bool) -> None:
    """Object explorer. QUERY e.g.:  dh:2 dh:5 pfs:off risk:high score<70 -src:testbed finding:KE-001 traffic:voip"""
    from securiq import render_fleet as F
    from securiq.render import panel
    if help_query:
        console.print(core.query_help())
        return
    rows = core.filter_rows(core.fleet_rows(), " ".join(query))
    if csv_path:
        Path(csv_path).write_text(core.rows_to_csv(rows), encoding="utf-8")
        console.print(f"[{T.GREEN}]✓[/] {len(rows)} rows → {csv_path}")
        return
    console.print(panel(F.explorer_table(rows), "Object explorer", f"{len(rows)} match"))
    if facets:
        console.print(panel(F.facets(core.facet_counts(rows)), "Facets"))


@cli.command()
def dashboard() -> None:
    """Fleet operations dashboard: KPIs, distributions, recurring findings."""
    from securiq import render_fleet as F
    console.print(F.dashboard(core.fleet_rows()))


@cli.command()
@click.option("--width", type=int, help="Canvas width (default: terminal width)")
@click.option("--height", default=34, show_default=True)
@click.option("--type", "types", multiple=True, type=click.Choice(["capture", "gateway", "fingerprint", "finding", "traffic", "config"]),
              help="Only draw these node types")
@click.option("--focus", help="Isolate the neighbourhood of a node (e.g. gateway:10.99.0.1, finding:KE-001)")
def graph(width: int | None, height: int, types: tuple[str, ...], focus: str | None) -> None:
    """Link graph: captures, gateways, fingerprints, findings, traffic and configuration values."""
    from securiq import render_fleet as F
    from securiq.render import panel
    rows = core.fleet_rows()
    g = core.link_graph(rows)
    keep = None
    if focus:
        if not any(n["id"] == focus for n in g["nodes"]):
            _fail(f"No node '{focus}'. Try one of: " + ", ".join(n["id"] for n in g["nodes"][:6]))
        near = {focus} | {e["target"] for e in g["edges"] if e["source"] == focus} | {e["source"] for e in g["edges"] if e["target"] == focus}
        keep = near | {x for e in g["edges"] for x in (e["source"], e["target"]) if e["source"] in near or e["target"] in near}
    w = width or max(60, console.width - 4)
    text, _, _ = F.graph_canvas(g, w, height, focus, set(types) or None, keep)
    console.print(panel(text, "Link graph", "  ".join(f"{T.NODE_GLYPH[k]} {k}" for k in T.NODE_COLOR)))
    if focus:
        console.print(panel(F.node_detail(g, focus), "Selected"))
    else:
        console.print(panel(F.graph_insights(g, rows), "Insights"))


@cli.group(invoke_without_command=True)
@click.option("--status", type=click.Choice(["new", "investigating", "accepted", "resolved", "false_positive"]))
@click.option("--severity", type=click.Choice(["Critical", "High", "Medium", "Low", "Informational"]))
@click.pass_context
def triage(ctx: click.Context, status: str | None, severity: str | None) -> None:
    """Triage inbox: every finding occurrence with a persisted status and notes."""
    if ctx.invoked_subcommand:
        return
    from securiq import render_fleet as F
    from securiq.render import panel
    inbox = core.triage_inbox()
    items = [i for i in inbox["items"] if (not status or i["status"] == status) and (not severity or i["severity"] == severity)]
    console.print(panel(F.inbox_counts(inbox), "Triage status"))
    console.print(panel(F.inbox_table(items[:80]), "Inbox", f"{len(items)} finding(s)"))
    console.print(f"[{T.DIM}]keys look like  analysisId:FINDING-ID — set with  securiq triage set KEY… --status investigating[/]")


@triage.command("set")
@click.argument("keys", nargs=-1, required=True)
@click.option("--status", type=click.Choice(["new", "investigating", "accepted", "resolved", "false_positive"]))
@click.option("--note")
def triage_set(keys: tuple[str, ...], status: str | None, note: str | None) -> None:
    """Set status and/or note. KEYS are analysisId:FINDING-ID, or a bare FINDING-ID to hit every occurrence."""
    inbox = core.triage_inbox()
    resolved = []
    for k in keys:
        if ":" in k:
            resolved.append(k)
        else:
            resolved += [i["key"] for i in inbox["items"] if i["finding_id"] == k.upper()]
    if not resolved:
        _fail("No matching finding keys")
    n = _quiet(core.triage_update, resolved, status, note)
    console.print(f"[{T.GREEN}]✓[/] updated {n} finding(s)")


# ---------------------------------------------------------------- decision support

@cli.command()
@click.argument("ref", default="latest")
@click.option("--set", "sets", multiple=True, metavar="KEY=VALUE", help="Change a setting, e.g. --set dh_group=20 --set pfs=on")
@click.option("--recommended", is_flag=True, help="Apply the smallest set of changes that resolves every fixable weakness")
@click.option("--verify", is_flag=True, help="Render the proposed configuration in the digital twin and measure it")
@click.option("--options", is_flag=True, help="List every setting and its allowed values")
def whatif(ref: str, sets: tuple[str, ...], recommended: bool, verify: bool, options: bool) -> None:
    """What-if simulator: change settings, the unchanged rule engine re-scores the capture; --verify measures it."""
    from securiq import render
    from securiq.render import panel, kv_table
    rec = _quiet(core.record, ref)
    base = core.simulator_baseline(rec)
    if options:
        rows = []
        for k in base["knobs"]:
            opts = ", ".join(str(o["value"]) if isinstance(o, dict) else str(o) for o in k["options"])
            rows.append((Text(f"{k['key']}", style=T.BLUE), f"{opts}   (now: {base['current'].get(k['key'])})"))
        console.print(panel(kv_table(rows, 20), "Simulator settings"))
        return
    changes: dict[str, Any] = dict(base["recommended"]) if recommended else {}
    for k, v in _kv(sets).items():
        changes[k] = _quiet(core.coerce_knob, k, v)
    if not changes:
        console.print(f"[{T.DIM}]Recommended changes for this capture:[/] " + ", ".join(f"{k}={v}" for k, v in base["recommended"].items())
                      + f"\n[{T.DIM}]use --recommended or --set key=value[/]")
        return
    sim = _quiet(core.simulate, rec, changes)
    console.print(render.simulation(sim))
    if verify:
        v = _work("Verifying…", core.verify, rec, changes)
        console.print(render.verification(v))
        console.print(f"[{T.DIM}]verification analysis saved as {v['analysis_id']}[/]")


@cli.group(invoke_without_command=True)
@click.pass_context
def policy(ctx: click.Context) -> None:
    """Golden policy: the configuration the administrator requires."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(policy_show)


@policy.command("show")
def policy_show() -> None:
    """Show the active policy as YAML-like text."""
    from securiq.render import panel
    current, default = core.policy_get()
    lines = [Text.assemble((f"{k}: ", T.DIM), (str(v), T.TEXT if v == default.get(k) else f"bold {T.VIOLET}")) for k, v in current.items()]
    console.print(panel(Group(*lines), "Golden policy", "purple = changed from default"))


@policy.command("set")
@click.argument("pairs", nargs=-1, required=True, metavar="KEY=VALUE…")
def policy_set(pairs: tuple[str, ...]) -> None:
    """Change policy keys, e.g. `policy set require_pfs=true allowed_dh_groups=14,19,20 max_child_lifetime_s=7200`."""
    changes = {k: _quiet(core.parse_policy_value, k, v) for k, v in _kv(pairs).items()}
    _quiet(core.policy_set, changes)
    console.print(f"[{T.GREEN}]✓[/] policy updated ({', '.join(changes)})")


@policy.command("reset")
def policy_reset() -> None:
    """Restore the default golden policy."""
    core.policy_reset()
    console.print(f"[{T.GREEN}]✓[/] policy reset")


@policy.command("check")
@click.argument("ref", default="latest")
def policy_check(ref: str) -> None:
    """Check a capture (or `all`) against the active policy."""
    from securiq import render
    if ref == "all":
        for r in core.fleet_rows():
            colour = T.GREEN if r["policy_status"] == "Compliant" else T.RED
            console.print(f"[{colour}]{'✓' if colour == T.GREEN else '✕'}[/] {r['analysis_id']}  {r['filename'].split('__', 1)[-1][:40]:<40} {r['policy_status']} ({r['policy_fail']} fail)")
        return
    rec = _quiet(core.record, ref)
    console.print(render.policy(rec, core.policy_evaluate(rec)))


@cli.command()
@click.argument("target", default="latest")
@click.option("--baseline", "-b", help="Baseline analysis (default: the previous capture of the same gateways)")
def drift(target: str, baseline: str | None) -> None:
    """Configuration drift between two captures, each change judged strengthened / weakened / visibility-only."""
    from securiq import render
    console.print(render.drift(_quiet(core.drift, target, baseline)))


@cli.command()
def fingerprints() -> None:
    """Configuration fingerprints of every capture, grouped."""
    from rich.table import Table
    groups: dict[str, list[dict]] = {}
    for f in core.fleet_fingerprints():
        groups.setdefault(f["fingerprint"], []).append(f)
    t = Table(header_style=f"bold {T.DIM}", border_style=T.BORDER, expand=True)
    for c in ("FINGERPRINT", "CAPTURES", "CONFIGURATION", "SCORE"):
        t.add_column(c)
    for fp, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        t.add_row(Text(fp, style=T.VIOLET), str(len(items)), items[0]["label"], str(items[0]["score"]))
    console.print(t)


# ---------------------------------------------------------------- lab (digital twin)

@cli.group()
def lab() -> None:
    """Digital twin: generate a labelled VPN capture from a chosen configuration, then analyse it."""


@lab.command("options")
def lab_options() -> None:
    """List every configurable setting with its defaults."""
    from securiq.render import panel, kv_table
    from backend.intel import simulator
    defaults = core.lab_defaults()
    rows = []
    for k in simulator.KNOBS:
        opts = ", ".join(str(o["value"]) if isinstance(o, dict) else str(o) for o in k["options"])
        rows.append((Text(k["key"], style=T.BLUE), f"{opts}   (default {defaults.get(k['key'])})"))
    rows += [(Text("ip_version", style=T.BLUE), "4, 6   (default 4)"), (Text("nat_t", style=T.BLUE), "true, false   (default false)")]
    console.print(panel(kv_table(rows, 18), "Lab settings  →  --set key=value"))
    console.print(f"[{T.DIM}]traffic:  --traffic web:25 --traffic voip:20   (classes: web video voip file_transfer email chat icmp; 10-60 s each)[/]")


@lab.command("build")
@click.option("--set", "sets", multiple=True, metavar="KEY=VALUE")
@click.option("--traffic", "traffic", multiple=True, metavar="CLASS:SECONDS")
@click.option("--label", default="")
@click.option("--impairment", type=click.Choice(["none", "light", "moderate", "heavy"]), default="none")
@click.option("--strongswan", is_flag=True, help="Print the matching strongSwan profile for the Docker lab")
@click.option("--view", "-v", "views", multiple=True, type=VIEW_CHOICES, default=("overview",))
def lab_build(sets: tuple[str, ...], traffic: tuple[str, ...], label: str, impairment: str, strongswan: bool, views: tuple[str, ...]) -> None:
    """Build a capture from a configuration and analyse it end to end."""
    from securiq import render
    from securiq.render import panel
    from rich.syntax import Syntax
    config: dict[str, Any] = {}
    for k, v in _kv(sets).items():
        if k in ("ip_version",):
            config[k] = int(v)
        elif k == "nat_t":
            config[k] = v.lower() in ("1", "true", "yes", "on")
        else:
            config[k] = _quiet(core.coerce_knob, k, v)
    tr = []
    for item in traffic:
        cls, _, secs = item.partition(":")
        tr.append({"class": cls, "seconds": float(secs or 25)})
    out = _work("Building…", core.lab_build, config, tr, label, impairment)
    rec = out["record"]
    console.print(f"[{T.GREEN}]✓[/] built [bold]{out['file_id']}[/] · {out['packets']} packets · analysis [bold]{rec['analysis_id']}[/]")
    for v in ("all",) if "all" in views else views:
        for name in (render.VIEWS if v == "all" else [v]):
            console.print(render.view(rec, name, core.packets(rec["analysis_id"]) if name == "packets" else None))
    if strongswan:
        console.print(panel(Syntax(out["strongswan_profile"], "ini", theme="ansi_dark", background_color=T.PANEL), "strongSwan profile"))


@lab.command("list")
def lab_list() -> None:
    """Previously built lab captures."""
    from rich.table import Table
    t = Table(header_style=f"bold {T.DIM}", border_style=T.BORDER, expand=True)
    for c in ("ID", "LABEL", "PACKETS", "IKE", "ENCRYPTION", "DH", "PFS"):
        t.add_column(c)
    for b in core.lab_builds():
        c = b["config"]
        t.add_row(Text(b["id"], style=T.VIOLET), b["label"], str(b.get("packets") or ""), c["ike_version"], c["ike_encryption"], str(c["dh_group"]), str(c["pfs"]))
    console.print(t)


# ---------------------------------------------------------------- live and capture

@cli.group()
def live() -> None:
    """Real-time analysis of a paced replay or a live interface."""


@live.command("replay")
@click.argument("target")
@click.option("--speed", default=10.0, show_default=True, help="Replay speed multiplier (0 = as fast as possible)")
def live_replay(target: str, speed: float) -> None:
    """Stream a stored capture through the real-time engine."""
    session = _quiet(core.live_start_replay, target, speed)
    _follow(session)


@live.command("capture")
@click.argument("interface")
@click.option("--filter", "bpf", default=None, help="BPF filter (default: ESP, AH, UDP 500/4500)")
@click.option("--tool", type=click.Choice(["tcpdump", "dumpcap"]))
def live_capture(interface: str, bpf: str | None, tool: str | None) -> None:
    """Analyse a live interface until you press Ctrl-C (needs capture privileges)."""
    session = _quiet(core.live_start_interface, interface, bpf, tool)
    _follow(session)


@live.command("interfaces")
def live_interfaces() -> None:
    """Capture backends and interfaces on this machine."""
    from securiq.render import panel, kv_table
    caps = core.live_capabilities()
    console.print(panel(kv_table([("Capture tools", ", ".join(caps["tools"]) or "none"), ("Scapy", caps["scapy"]),
                                  ("Default filter", caps["default_filter"]),
                                  ("Interfaces", "\n".join(caps["interfaces"]) or "none — replay of stored captures always works")]), "Live capture"))


def _follow(session) -> None:
    from rich.live import Live
    from securiq import render_fleet as F
    alerts: list[dict] = []
    pps: list[float] = []
    seq = 0
    with Live(console=console, refresh_per_second=4, screen=False, vertical_overflow="crop") as lv:
        try:
            while True:
                for ev in session.events_since(seq):
                    seq = ev["seq"]
                    if ev["type"] == "alert":
                        alerts.append(ev["data"])
                pps.append(session.metrics.get("ingest_pps", 0.0))
                lv.update(F.live(session.summary(), session.snapshot, alerts, pps))
                if not session.running and session.status != "finalizing":
                    break
                time.sleep(0.4)
        except KeyboardInterrupt:
            session.stop()
            while session.status in ("running", "starting", "finalizing"):
                time.sleep(0.2)
            lv.update(F.live(session.summary(), session.snapshot, alerts, pps))
    if session.analysis_id:
        console.print(f"[{T.GREEN}]✓[/] full analysis saved: [bold]{session.analysis_id}[/]  →  securiq show {session.analysis_id}")


@cli.command()
@click.option("--interface", "-i")
@click.option("--duration", "-d", default=30, show_default=True, help="Seconds to sniff")
@click.option("--filter", "bpf", default="esp or ah or udp port 500 or udp port 4500", show_default=True)
@click.option("--analyze/--no-analyze", "run_analysis", default=True)
def capture(interface: str | None, duration: int, bpf: str, run_analysis: bool) -> None:
    """Bounded live capture with Scapy, saved to the upload store and analysed."""
    file_id, n = _work(f"Sniffing for {duration}s…", lambda progress: core.bounded_capture(interface, duration, bpf))
    console.print(f"[{T.GREEN}]✓[/] captured {n} packets → upload id [bold]{file_id}[/]")
    if run_analysis and n:
        rec = _work("Analysing…", core.analyze, file_id)
        from securiq import render
        console.print(render.overview(rec))


# ---------------------------------------------------------------- testbed, model, evaluation

@cli.group()
def testbed() -> None:
    """Testbed generation, labelled datasets, evaluation and the misconfiguration benchmark."""


@testbed.command("matrix")
def testbed_matrix() -> None:
    """The configuration matrix the generator can render."""
    from securiq import render_fleet as F
    console.print(F.matrix(core.testbed_matrix()))


@testbed.command("samples")
def testbed_samples() -> None:
    """List the curated testbed samples (regenerate with --regen)."""
    ctx = click.get_current_context()
    from securiq import render_fleet as F
    _quiet(core.ensure_ready)
    console.print(F.capture_lists({**core.list_captures(), "uploads": [], "lab": []}))


@testbed.command("regen")
def testbed_regen() -> None:
    """Regenerate the curated sample captures."""
    n = _work("Generating…", lambda progress: core.regenerate_samples(progress))
    console.print(f"[{T.GREEN}]✓[/] {n} samples generated")


@testbed.command("dataset")
@click.option("--count", default=30, show_default=True, type=click.IntRange(1, 200))
@click.option("--seed", default=1, show_default=True)
def testbed_dataset(count: int, seed: int) -> None:
    """Render random matrix scenarios to a labelled PCAP dataset with ground-truth manifest."""
    from securiq.render import panel, kv_table
    res = _work("Rendering…", lambda progress: core.build_dataset(count, seed, progress))
    console.print(panel(kv_table([(k, v) for k, v in res.items() if isinstance(v, (str, int, float))]), "Dataset written"))


@testbed.command("evaluate")
@click.option("--scenarios", default=24, show_default=True, type=click.IntRange(4, 60))
@click.option("--seed", default=2024, show_default=True)
@click.option("--latest", is_flag=True, help="Show the last stored result instead of running")
def testbed_evaluate(scenarios: int, seed: int, latest: bool) -> None:
    """End-to-end accuracy on unseen scenarios: every field, with abstentions counted separately."""
    from securiq import render_fleet as F
    res = core.evaluation_latest() if latest else _work("Evaluating…", lambda progress: core.evaluate(scenarios, seed, progress))
    if not res:
        _fail("No stored evaluation yet — run without --latest")
    console.print(F.evaluation(res))


@testbed.command("benchmark")
@click.option("--count", default=40, show_default=True, type=click.IntRange(8, 120))
@click.option("--seed", default=99, show_default=True)
@click.option("--latest", is_flag=True)
def testbed_benchmark(count: int, seed: int, latest: bool) -> None:
    """Inject known misconfigurations, then measure how many the analyser finds from the PCAP."""
    from securiq import render_fleet as F
    res = core.benchmark_latest() if latest else _work("Benchmarking…", lambda progress: core.benchmark(count, seed, progress))
    if not res:
        _fail("No stored benchmark yet — run without --latest")
    console.print(F.benchmark(res))


@testbed.command("model")
def testbed_model() -> None:
    """Traffic-classifier metrics, per-class report, calibration and feature importance."""
    from securiq import render_fleet as F
    _quiet(core.ensure_ready)
    console.print(F.model(core.model_info()))


@testbed.command("train")
def testbed_train() -> None:
    """Retrain the traffic classifier from freshly generated flows."""
    _work("Training…", lambda progress: core.train(progress))
    console.print(f"[{T.GREEN}]✓[/] classifier retrained")


# ---------------------------------------------------------------- reports & export

@cli.command()
@click.argument("ref", default="latest")
@click.option("--kind", type=click.Choice(["executive", "technical"]), default="executive", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["terminal", "html", "json"]), default="terminal", show_default=True)
@click.option("--output", "-o", type=click.Path(dir_okay=False), help="Write to a file (html is printable to PDF from a browser)")
def report(ref: str, kind: str, fmt: str, output: str | None) -> None:
    """Executive or technical report: in the terminal, or as printable HTML / JSON."""
    from securiq import render
    rec = _quiet(core.record, ref)
    if fmt == "terminal":
        console.print(render.view(rec, kind))
        return
    text = _quiet(core.render_report, rec, kind, fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[{T.GREEN}]✓[/] {kind} report ({fmt}) → {output}")
    else:
        click.echo(text)


@cli.command()
@click.argument("ref", default="latest")
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def export(ref: str, output: str | None) -> None:
    """Export the complete analysis as JSON."""
    rec = _quiet(core.record, ref)
    text = json.dumps(rec, indent=2, default=str)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[{T.GREEN}]✓[/] {output}")
    else:
        click.echo(text)


def main() -> None:
    cli(prog_name="securiq")


if __name__ == "__main__":
    main()
