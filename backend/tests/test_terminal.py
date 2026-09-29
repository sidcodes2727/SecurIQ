"""The terminal package: service layer, renderers, CLI commands and the full-screen console."""
import asyncio
import os
import json

import pytest
from click.testing import CliRunner
from rich.console import Console

from securiq import core, render, render_fleet
from securiq.cli import cli


@pytest.fixture(scope="module", autouse=True)
def _no_bootstrap(trained_classifier):
    """The session classifier is already trained; skip the first-run sample generation and training."""
    original = core.ensure_ready
    core.ensure_ready = lambda progress=None: None
    yield
    core.ensure_ready = original


@pytest.fixture(scope="module")
def weak_record(scenario_capture):
    path, _ = scenario_capture("weak_ikev1_main_3des_md5")
    return core.analyze(str(path))


@pytest.fixture(scope="module")
def strong_record(scenario_capture):
    path, _ = scenario_capture("strong_ikev2_gcm_ecp384_pfs")
    return core.analyze(str(path))


def _render(renderable) -> str:
    console = Console(width=160, record=True, file=open(os.devnull, "w"))
    console.print(renderable)
    return console.export_text()


# ---------------------------------------------------------------- service layer

def test_analyze_saves_and_resolves_references(weak_record, strong_record):
    assert weak_record["security"]["overall_score"] < 60 < strong_record["security"]["overall_score"]
    assert core.record("latest")["analysis_id"] == strong_record["analysis_id"]
    assert core.record("@2")["analysis_id"] == weak_record["analysis_id"]
    assert core.record(weak_record["analysis_id"][:5])["analysis_id"] == weak_record["analysis_id"]
    with pytest.raises(core.CoreError):
        core.record("does-not-exist")


def test_bad_target_is_a_readable_error():
    with pytest.raises(core.CoreError, match="not a file"):
        core.analyze("no-such-sample")


def test_query_language(weak_record, strong_record):
    rows = core.fleet_rows()
    assert {r["analysis_id"] for r in rows} >= {weak_record["analysis_id"], strong_record["analysis_id"]}
    weak = core.filter_rows(rows, "ike:ikev1 pfs:off")
    assert weak and all(r["ike_version"] == "IKEv1" and r["pfs"] == "off" for r in weak)
    assert all(r["score"] >= 70 for r in core.filter_rows(rows, "score>=70"))
    assert not any(r["ike_version"] == "IKEv1" for r in core.filter_rows(rows, "-ike:ikev1"))
    assert core.filter_rows(rows, "finding:KE-001")
    either = core.filter_rows(rows, "dh:2 dh:20")  # same field = OR
    assert {r["dh_group"] for r in either} == {2, 20}
    both = core.filter_rows(rows, "dh:20 ike:ikev1")  # different fields = AND
    assert all(r["dh_group"] == 20 and r["ike_version"] == "IKEv1" for r in both)
    assert len(both) < len(core.filter_rows(rows, "dh:20"))
    assert "ike" in core.facet_counts(rows)
    assert core.rows_to_csv(rows).splitlines()[0].startswith("analysis_id,filename")


def test_simulate_and_coerce(weak_record):
    base = core.simulator_baseline(weak_record)
    sim = core.simulate(weak_record, base["recommended"])
    assert sim["delta"] > 30 and not sim["introduced"]
    assert core.coerce_knob("dh_group", "20") == 20
    assert core.coerce_knob("pfs", "on") is True
    with pytest.raises(core.CoreError):
        core.coerce_knob("dh_group", "7")
    with pytest.raises(core.CoreError):
        core.simulate(weak_record, {"ike_version": "IKEv1", "ike_encryption": "AES-256-GCM-16"})


def test_policy_roundtrip():
    try:
        core.policy_set({"require_pfs": False, "allowed_dh_groups": core.parse_policy_value("allowed_dh_groups", "14,20")})
        assert core.policy_get()[0]["allowed_dh_groups"] == [14, 20]
        with pytest.raises(core.CoreError):
            core.policy_set({"no_such_key": 1})
    finally:
        core.policy_reset()


def test_triage_update(weak_record):
    key = f"{weak_record['analysis_id']}:KE-001"
    assert core.triage_update([key], status="investigating", note="checking") == 1
    item = next(i for i in core.triage_inbox()["items"] if i["key"] == key)
    assert item["status"] == "investigating" and item["note"] == "checking"
    with pytest.raises(core.CoreError):
        core.triage_update([key], status="nonsense")


def test_import_rejects_non_pcap(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"not a capture at all")
    with pytest.raises(core.CoreError, match="magic"):
        core.import_capture(bad)


# ---------------------------------------------------------------- renderers

@pytest.mark.parametrize("name", render.VIEWS)
def test_every_view_renders(weak_record, name):
    pk = core.packets(weak_record["analysis_id"])
    text = _render(render.view(weak_record, name, pk))
    assert text.strip()


def test_findings_show_evidence_chain(weak_record):
    text = _render(render.findings(weak_record, "KE-001"))
    for step in ("PACKETS", "PARAMETER", "RULE", "RISK", "FIX"):
        assert step in text
    assert "NIST SP 800-57" in text


def test_fleet_views_render(weak_record, strong_record):
    rows = core.fleet_rows()
    assert "FLEET OPERATIONS" in _render(render_fleet.dashboard(rows))
    graph = core.link_graph(rows)
    text, cells, order = render_fleet.graph_canvas(graph, 100, 30)
    assert cells and order and text.plain.strip()
    assert render_fleet.node_detail(graph, graph["nodes"][0]["id"])
    mid, _, _ = render_fleet.graph_canvas(graph, 100, 30, progress=0.3)
    assert mid.plain != text.plain  # a settling frame differs from the final layout
    tuns = render_fleet.tunnels(rows)
    assert tuns and all(t["pps"] > 0 for t in tuns)
    frame1, frame2 = (_render(render_fleet.topology(tuns, f, 140)) for f in (1, 2))
    assert "LIVE TUNNEL TOPOLOGY" in frame1 and frame1 != frame2
    assert render_fleet.ticker(rows, 3, 120).plain.startswith(" LIVE")
    assert _render(render_fleet.model(core.model_info())).strip()


# ---------------------------------------------------------------- CLI

def test_cli_analyze_and_show(scenario_capture):
    path, _ = scenario_capture("replay_anomaly")
    runner = CliRunner()
    out = runner.invoke(cli, ["analyze", str(path), "--view", "findings"])
    assert out.exit_code == 0, out.output
    assert "saved" in out.output and "FINDINGS" in out.output
    shown = runner.invoke(cli, ["show", "latest", "protocol"])
    assert shown.exit_code == 0 and "IDENTIFIED CONFIGURATION" in shown.output


def test_cli_json_output(scenario_capture):
    path, _ = scenario_capture("weak_ikev1_main_3des_md5")
    out = CliRunner().invoke(cli, ["analyze", str(path), "--json"])
    assert out.exit_code == 0
    assert json.loads(out.output[out.output.index("{"):])["security"]["risk_level"]


def test_cli_whatif_fleet_policy_graph(weak_record):
    runner = CliRunner()
    for args, expect in (
        (["whatif", weak_record["analysis_id"], "--recommended"], "WHAT-IF SIMULATION"),
        (["whatif", weak_record["analysis_id"], "--set", "dh_group=20"], "PROPOSED CHANGES"),
        (["fleet", "ike:ikev1", "--facets"], "OBJECT EXPLORER"),
        (["policy", "check", weak_record["analysis_id"]], "GOLDEN POLICY"),
        (["graph", "--focus", "finding:KE-001"], "LINK GRAPH"),
        (["triage"], "INBOX"),
        (["dashboard"], "FLEET OPERATIONS"),
        (["explain", weak_record["analysis_id"], "KE-001"], "EVIDENCE CHAIN"),
        (["report", weak_record["analysis_id"], "--kind", "technical"], "REMEDIATION PLAN"),
        (["testbed", "matrix"], "CONFIGURATION MATRIX"),
    ):
        out = runner.invoke(cli, args)
        assert out.exit_code == 0, (args, out.output)
        assert expect in out.output, (args, out.output[-400:])


def test_cli_errors_are_clean(weak_record):
    runner = CliRunner()
    out = runner.invoke(cli, ["whatif", weak_record["analysis_id"], "--set", "dh_group=7"])
    assert out.exit_code == 1 and "not valid" in out.output and "Traceback" not in out.output
    out = runner.invoke(cli, ["show", "zzzz"])
    assert out.exit_code == 1 and "No analysis matches" in out.output


def test_cli_report_export_files(weak_record, tmp_path):
    html = tmp_path / "r.html"
    out = CliRunner().invoke(cli, ["report", weak_record["analysis_id"], "--format", "html", "-o", str(html)])
    assert out.exit_code == 0 and "<html" in html.read_text(encoding="utf-8").lower()
    csv_path = tmp_path / "f.csv"
    assert CliRunner().invoke(cli, ["fleet", "--csv", str(csv_path)]).exit_code == 0
    assert csv_path.read_text(encoding="utf-8").startswith("analysis_id")


# ---------------------------------------------------------------- full-screen console

def test_console_walks_every_view(weak_record, strong_record):
    from securiq.tui.app import SecurIQApp
    from securiq.tui.views import TABS

    def screen(app):
        return "\n".join(s.text for s in app.screen._compositor.render_strips())

    async def scenario():
        app = SecurIQApp()
        async with app.run_test(size=(180, 50)) as pilot:
            for _ in range(40):
                await pilot.pause(0.25)
                if app.rows:
                    break
            assert len(app.rows) >= 2
            for key in "123456789":
                await pilot.press(key)
                await pilot.pause(0.4)
            await pilot.press("1")
            await pilot.pause(0.3)
            assert "FLEET OPERATIONS" in screen(app)
            app.open_analysis(weak_record["analysis_id"])
            await pilot.pause(0.5)
            for tab, _ in TABS:
                app.workspace_tab(tab)
                await pilot.pause(0.3)
            app.workspace_tab("simulator")
            await pilot.pause(0.5)
            await pilot.click("#sim-rec")
            for _ in range(20):
                await pilot.pause(0.3)
                if "MODELLED" in screen(app):
                    break
            assert "MODELLED" in screen(app)
            await pilot.press("3")
            await pilot.pause(0.4)
            await pilot.press("n", "enter")
            await pilot.pause(0.3)
            assert "ISOLATED" in screen(app)
            errors = [n for n in app._notifications if n.severity == "error"]
            assert not errors, [e.message for e in errors]

    asyncio.run(scenario())
