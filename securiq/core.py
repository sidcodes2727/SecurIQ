"""Service layer: everything the web API did, as plain function calls (no server, no HTTP)."""
from __future__ import annotations

import csv
import io
import re
import shutil
import time
from pathlib import Path
from typing import Any, Callable

Progress = Callable[[str], None]


class CoreError(Exception):
    """A problem the user can act on (bad id, missing file, not ready…)."""


def _noop(_: str) -> None:
    pass


# ---------------------------------------------------------------- readiness

def ready_state() -> dict[str, Any]:
    from backend.bootstrap import state
    from backend.config import SAMPLE_DIR
    from backend.ml.model import classifier
    from backend.storage import sample_manifest
    trained = classifier.is_trained or classifier.load()
    return {"model_trained": bool(trained), "model_training": state["model_training"],
            "samples": len(sample_manifest().get("samples", {})) if SAMPLE_DIR.exists() else 0}


def ensure_ready(progress: Progress = _noop) -> None:
    """Generate the testbed samples and train the classifier on first use."""
    from backend.bootstrap import ensure_samples, train_model
    from backend.ml.model import classifier
    from backend.storage import sample_manifest
    if not sample_manifest().get("samples"):
        progress("Generating testbed sample captures…")
        ensure_samples()
    if not (classifier.is_trained or classifier.load()):
        progress("Training the traffic classifier (about 30 s, first run only)…")
        train_model()
    progress("Ready")


def train(progress: Progress = _noop) -> dict[str, Any]:
    from backend.bootstrap import train_model
    progress("Training the traffic classifier…")
    return train_model()


def regenerate_samples(progress: Progress = _noop) -> int:
    from backend.bootstrap import ensure_samples
    progress("Regenerating testbed samples…")
    return len(ensure_samples(force=True)["samples"])


def model_info() -> dict[str, Any]:
    from backend.ml.model import classifier
    classifier.is_trained or classifier.load()
    return classifier.get_model_info()


# ---------------------------------------------------------------- captures and analyses

def list_captures() -> dict[str, list[dict[str, Any]]]:
    from backend.intel.lab import list_builds
    from backend.storage import list_uploads, sample_manifest
    samples = [{"id": k, "file": t["file"], "description": t.get("description"), "packets": t.get("packets"),
                "ike": f"{t['ike_version']} {t['exchange_mode'] if t['ike_version'] == 'IKEv1' else ''}".strip(),
                "esp": t.get("esp_suite") or "AH", "mode": t["mode"], "ip": t["ip_version"],
                "traffic": [s["class"] for s in t["traffic_segments"]]}
               for k, t in sample_manifest().get("samples", {}).items()]
    uploads = [{"id": u["id"], "file": u["original_name"], "size": u["size"]} for u in list_uploads()]
    lab = [{"id": b["id"], "label": b["label"], "packets": b.get("packets"), "created": b["created"]}
           for b in list_builds()[:30]]
    return {"samples": samples, "uploads": uploads, "lab": lab}


def import_capture(path: str | Path) -> str:
    """Copy a PCAP into the upload store; returns its file id."""
    from backend.analyzers.pcap_parser import is_capture_file
    from backend.storage import new_id, upload_path
    src = Path(path).expanduser()
    if not src.is_file():
        raise CoreError(f"File not found: {src}")
    with open(src, "rb") as fh:
        if not is_capture_file(fh.read(4)):
            raise CoreError(f"{src.name} is not a pcap / pcapng capture (unrecognised magic number)")
    file_id = new_id()
    shutil.copyfile(src, upload_path(file_id, src.name))
    return file_id


def resolve_target(target: str) -> tuple[str, Path, dict | None]:
    """A path, sample name, lab id or upload id → (file id, path, ground truth)."""
    from backend.storage import resolve_capture
    if Path(target).expanduser().is_file():
        file_id = import_capture(target)
        path, truth = resolve_capture(file_id)  # type: ignore[misc]
        return file_id, path, truth
    resolved = resolve_capture(target)
    if resolved is None:
        raise CoreError(f"'{target}' is not a file, a testbed sample, a lab build or an upload id "
                        "(try `securiq captures`)")
    return target, resolved[0], resolved[1]


def analyze(target: str, progress: Progress = _noop, source_extra: dict | None = None) -> dict[str, Any]:
    """Run the full pipeline on a target and persist the analysis; returns the stored record."""
    from backend.analyzers.pcap_parser import CaptureFormatError
    from backend.pipeline import run_pipeline
    from backend.storage import load_analysis, new_id, save_analysis
    ensure_ready(progress)
    file_id, path, truth = resolve_target(target)
    progress(f"Analysing {path.name.split('__', 1)[-1]}…")
    try:
        result = run_pipeline(str(path), truth)
    except (CaptureFormatError, ValueError) as exc:
        raise CoreError(str(exc)) from exc
    analysis_id = new_id()
    result["created"] = time.time()
    result["source"] = {"file_id": file_id, "is_sample": truth is not None, **(source_extra or {})}
    save_analysis(analysis_id, file_id, result)
    return record(analysis_id)


def analyses() -> list[dict[str, Any]]:
    from backend.storage import list_analyses
    return list_analyses()


def resolve_analysis_id(ref: str | None) -> str:
    """'latest', '@N' (Nth newest), an id, or a unique id / filename prefix."""
    items = analyses()
    if not items:
        raise CoreError("No analyses yet — run `securiq analyze <capture>` first")
    ref = (ref or "latest").strip()
    if ref == "latest":
        return items[0]["analysis_id"]
    if ref.startswith("@") and ref[1:].isdigit():
        n = int(ref[1:])
        if 1 <= n <= len(items):
            return items[n - 1]["analysis_id"]
        raise CoreError(f"Only {len(items)} analyses exist")
    exact = [a for a in items if a["analysis_id"] == ref]
    if exact:
        return exact[0]["analysis_id"]
    matches = [a for a in items if a["analysis_id"].startswith(ref) or ref.lower() in (a.get("filename") or "").lower()]
    if len(matches) == 1:
        return matches[0]["analysis_id"]
    if not matches:
        raise CoreError(f"No analysis matches '{ref}'")
    raise CoreError(f"'{ref}' is ambiguous: " + ", ".join(m["analysis_id"] for m in matches[:5]))


def record(ref: str | None) -> dict[str, Any]:
    from backend.intel import build_intel
    from backend.storage import load_analysis
    rec = load_analysis(resolve_analysis_id(ref))
    if rec is None:
        raise CoreError(f"Analysis not found: {ref}")
    if not rec.get("intel") or rec["intel"].get("version") != 1:
        rec["intel"] = build_intel(rec)
    return rec


def packets(ref: str | None) -> dict[str, Any]:
    from backend.storage import load_packets
    data = load_packets(resolve_analysis_id(ref))
    return data or {"total": 0, "packets": []}


# ---------------------------------------------------------------- what-if, verify, lab

def simulator_baseline(rec: dict[str, Any]) -> dict[str, Any]:
    from backend.intel import simulator
    a = rec["ipsec_analysis"]
    return {"current": simulator.current_config(a), "recommended": simulator.recommended_changes(a),
            "knobs": simulator.KNOBS}


def simulate(rec: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    from backend.intel import simulator
    problems = simulator.validate(changes, rec["ipsec_analysis"])
    if problems:
        raise CoreError("; ".join(problems))
    return simulator.simulate(rec, changes)


def coerce_knob(key: str, raw: str) -> Any:
    """CLI text → the typed value a simulator knob expects."""
    from backend.intel import simulator
    knob = next((k for k in simulator.KNOBS if k["key"] == key), None)
    if knob is None:
        raise CoreError(f"Unknown setting '{key}'. Known: {', '.join(sorted(simulator.KNOB_KEYS))}")
    for opt in knob["options"]:
        value, label = (opt["value"], opt["label"]) if isinstance(opt, dict) else (opt, str(opt))
        if raw.lower() in (str(value).lower(), label.lower()):
            return value
    if raw.lower() in ("true", "on", "yes"):
        return True
    if raw.lower() in ("false", "off", "no"):
        return False
    choices = [str(o["value"]) if isinstance(o, dict) else str(o) for o in knob["options"]]
    raise CoreError(f"'{raw}' is not valid for {key}. Choose one of: {', '.join(choices)}")


def _run_saved(file_id: str, path: Path, truth: dict | None, extra: dict) -> dict[str, Any]:
    from backend.pipeline import run_pipeline
    from backend.storage import new_id, save_analysis
    ensure_ready()
    result = run_pipeline(str(path), truth)
    analysis_id = new_id()
    result["created"] = time.time()
    result["source"] = {"file_id": file_id, "is_sample": True, **extra}
    save_analysis(analysis_id, file_id, result)
    return record(analysis_id)


def verify(rec: dict[str, Any], changes: dict[str, Any], progress: Progress = _noop) -> dict[str, Any]:
    """Render the proposed configuration with the testbed and measure it with the full pipeline."""
    from backend.intel import lab, simulator
    problems = simulator.validate(changes, rec["ipsec_analysis"])
    if problems:
        raise CoreError("; ".join(problems))
    progress("Rendering the proposed configuration in the digital twin…")
    config = lab.config_for_verify(rec, changes)
    traffic = lab.traffic_from_record(rec)
    file_id, path, truth = lab.build(config, traffic, f"Verification of {rec['parsed_metadata']['filename']}",
                                     derived_from=rec["analysis_id"])
    progress("Measuring it with the analysis pipeline…")
    after = _run_saved(file_id, path, truth, {"lab": True, "derived_from": rec["analysis_id"]})
    before, measured = rec["security"], after["security"]
    return {
        "analysis_id": after["analysis_id"], "config": config,
        "before": {"score": before["overall_score"], "risk_level": before["risk_level"]},
        "after": {"score": measured["overall_score"], "risk_level": measured["risk_level"],
                  "identification_accuracy": (after.get("ground_truth") or {}).get("accuracy")},
        "delta": None if before["overall_score"] is None or measured["overall_score"] is None
        else round(measured["overall_score"] - before["overall_score"], 1),
        "categories": [{"label": c["label"], "before": c["score"], "after": measured["categories"][k]["score"]}
                       for k, c in before["categories"].items()],
        "resolved": sorted({f["id"] for f in before["findings"] if f["severity"] != "Informational"}
                           - {f["id"] for f in measured["findings"]}),
        "remaining": [{"id": f["id"], "title": f["title"], "severity": f["severity"]}
                      for f in measured["findings"] if f["severity"] != "Informational"],
        "strongswan_profile": lab.strongswan_profile(config, traffic, file_id),
    }


def lab_defaults() -> dict[str, Any]:
    from backend.intel import lab
    return dict(lab.DEFAULT_CONFIG)


def lab_build(config: dict[str, Any], traffic: list[dict[str, Any]], label: str = "", impairment: str = "none",
              progress: Progress = _noop) -> dict[str, Any]:
    from backend.intel import lab, simulator
    config = {k: v for k, v in config.items() if k in lab.DEFAULT_CONFIG}
    probe = {"profile": {}, "ike_analysis": {}, "esp_analysis": {}}
    problems = simulator.validate({k: v for k, v in config.items() if k in simulator.KNOB_KEYS}, probe)
    merged = {**lab.DEFAULT_CONFIG, **config}
    if merged["ike_version"] == "IKEv1" and any(t in merged["ike_encryption"] for t in ("GCM", "ChaCha")):
        problems.append("IKEv1 Phase 1 has no AEAD ciphers: choose a CBC cipher or IKEv2")
    if merged["ike_integrity"] == "None (AEAD)" and not any(t in merged["ike_encryption"] for t in ("GCM", "ChaCha")):
        problems.append("A CBC IKE cipher needs an integrity algorithm")
    if problems:
        raise CoreError("; ".join(sorted(set(problems))))
    ensure_ready(progress)
    norm = lab.normalise_traffic(traffic)
    progress("Generating the negotiation and encrypted traffic…")
    file_id, path, truth = lab.build(config, norm, label or "Lab build", impairment=impairment)
    progress("Analysing the generated capture…")
    rec = _run_saved(file_id, path, truth, {"lab": True})
    return {"record": rec, "file_id": file_id, "packets": truth.get("packets"),
            "strongswan_profile": lab.strongswan_profile(config, norm, file_id)}


def lab_builds() -> list[dict[str, Any]]:
    from backend.intel import lab
    return lab.list_builds()


# ---------------------------------------------------------------- policy, drift, fleet, triage

def policy_get() -> tuple[dict, dict]:
    from backend.intel.policy import DEFAULT_POLICY, load_policy
    return load_policy(), DEFAULT_POLICY


def policy_set(changes: dict[str, Any]) -> dict[str, Any]:
    from backend.intel.policy import DEFAULT_POLICY, load_policy, save_policy
    for key, value in changes.items():
        if key not in DEFAULT_POLICY:
            raise CoreError(f"Unknown policy key '{key}'. Known: {', '.join(DEFAULT_POLICY)}")
        want = DEFAULT_POLICY[key]
        if isinstance(want, bool):
            if not isinstance(value, bool):
                raise CoreError(f"{key} must be true or false")
        elif isinstance(want, int):
            if not isinstance(value, int) or isinstance(value, bool):
                raise CoreError(f"{key} must be an integer")
        elif isinstance(want, list) and not isinstance(value, list):
            raise CoreError(f"{key} must be a list")
    return save_policy({**load_policy(), **changes})


def policy_reset() -> dict[str, Any]:
    from backend.intel.policy import reset_policy
    return reset_policy()


def parse_policy_value(key: str, raw: str) -> Any:
    from backend.intel.policy import DEFAULT_POLICY
    want = DEFAULT_POLICY.get(key)
    if isinstance(want, bool):
        return raw.lower() in ("1", "true", "yes", "on")
    if isinstance(want, int):
        try:
            return int(raw)
        except ValueError as exc:
            raise CoreError(f"{key} must be an integer") from exc
    if isinstance(want, list):
        items = [x.strip() for x in raw.split(",") if x.strip()]
        if want and isinstance(want[0], int):
            try:
                return [int(x) for x in items]
            except ValueError as exc:
                raise CoreError(f"{key} takes a comma-separated list of integers") from exc
        return items
    return raw


def policy_evaluate(rec: dict[str, Any]) -> dict[str, Any]:
    from backend.intel.policy import evaluate_policy, load_policy
    return evaluate_policy(load_policy(), rec["ipsec_analysis"])


def drift(target_ref: str, baseline_ref: str | None = None) -> dict[str, Any]:
    from backend.intel.fingerprint import drift as compute
    target = record(target_ref)
    if baseline_ref:
        return compute(record(baseline_ref), target)
    endpoints = set(target["intel"]["fingerprint"].get("endpoints") or [])
    for a in analyses():
        if a["analysis_id"] != target["analysis_id"] and (a.get("created") or 0) < (target.get("created") or 0) \
                and endpoints & set(a.get("endpoints") or []):
            return compute(record(a["analysis_id"]), target)
    return {"status": "no_baseline", "note": "No earlier capture of these endpoints to compare with"}


def fleet_rows() -> list[dict[str, Any]]:
    from backend.intel import fleet
    return fleet.object_rows()


def link_graph(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from backend.intel import fleet
    return fleet.link_graph(rows if rows is not None else fleet.object_rows())


def triage_inbox() -> dict[str, Any]:
    from backend.intel import fleet
    return fleet.inbox(fleet.object_rows())


def triage_update(keys: list[str], status: str | None = None, note: str | None = None) -> int:
    from backend.intel import fleet
    try:
        return fleet.update_triage(keys, status, note)["updated"]
    except ValueError as exc:
        raise CoreError(str(exc)) from exc


def fleet_fingerprints() -> list[dict[str, Any]]:
    return [{"analysis_id": r["analysis_id"], "filename": r["filename"], "fingerprint": r["fingerprint"],
             "label": r["fingerprint_label"], "score": r["score"], "risk_level": r["risk_level"]}
            for r in fleet_rows()]


# ---------------------------------------------------------------- explorer query language

_NUMERIC = re.compile(r"^(score|packets|policy_fail|tunnels)(<=|>=|<|>|=)(-?\d+(?:\.\d+)?)$")
_FIELDS = {
    "ike": lambda r: [r["ike_version"]], "mode": lambda r: [r["mode"]], "dh": lambda r: [r["dh_group"]],
    "pfs": lambda r: [r["pfs"]], "risk": lambda r: [(r["risk_level"] or "").split()[0]],
    "src": lambda r: [r["source"]], "auth": lambda r: [r["auth"]], "ip": lambda r: [r["ip_version"]],
    "nat": lambda r: ["on" if r["nat_t"] else "off"], "policy": lambda r: [(r["policy_status"] or "").split("-")[0]],
    "novelty": lambda r: [r["novelty"]], "enc": lambda r: [r["ike_encryption"], r["esp_encryption"]],
    "esp": lambda r: [r["esp_encryption"]], "fp": lambda r: [r["fingerprint"]],
    "gw": lambda r: r["gateways"], "finding": lambda r: [f["id"] for f in r["findings"]],
    "sev": lambda r: [f["severity"] for f in r["findings"]], "traffic": lambda r: r["traffic"],
}


def query_help() -> str:
    return ("fields: " + " ".join(sorted(_FIELDS)) + " · numeric: score packets policy_fail tunnels with < > <= >= = · "
            "same field = OR, different fields = AND, '-' negates, bare words match the file name")


def filter_rows(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    terms = query.split()
    groups: dict[tuple[str, bool], list[str]] = {}
    numeric: list[tuple[str, str, float]] = []
    words: list[str] = []
    for term in terms:
        neg = term.startswith("-") and len(term) > 1
        body = term[1:] if neg else term
        m = _NUMERIC.match(body)
        if m:
            numeric.append((m.group(1), m.group(2), float(m.group(3))))
        elif ":" in body and body.split(":", 1)[0].lower() in _FIELDS:
            field, value = body.split(":", 1)
            groups.setdefault((field.lower(), neg), []).append(value.lower())
        else:
            words.append(body.lower())
    out = []
    for r in rows:
        ok = True
        for (field, neg), values in groups.items():
            have = {str(x).lower() for x in _FIELDS[field](r) if x is not None}
            hit = any(v in have or any(v == h.split()[0] for h in have) for v in values)
            if hit == neg:
                ok = False
                break
        if ok:
            for field, op, num in numeric:
                have = r.get(field)
                if have is None or not {"<": have < num, ">": have > num, "<=": have <= num,
                                        ">=": have >= num, "=": have == num}[op]:
                    ok = False
                    break
        if ok and words:
            hay = f"{r['filename']} {r['fingerprint_label']}".lower()
            ok = all(w in hay for w in words)
        if ok:
            out.append(r)
    return out


def facet_counts(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    facets: dict[str, dict[str, int]] = {}
    for field in ("ike", "risk", "dh", "pfs", "src", "auth", "policy", "novelty"):
        counts: dict[str, int] = {}
        for r in rows:
            for v in _FIELDS[field](r):
                if v is not None:
                    counts[str(v)] = counts.get(str(v), 0) + 1
        facets[field] = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
    return facets


def rows_to_csv(rows: list[dict[str, Any]]) -> str:
    cols = ["analysis_id", "filename", "source", "score", "risk_level", "ike_version", "ike_encryption", "ike_integrity",
            "dh_group", "esp_encryption", "pfs", "mode", "auth", "policy_status", "novelty", "fingerprint"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([r.get(c) for c in cols])
    return buf.getvalue()


# ---------------------------------------------------------------- testbed, evaluation, benchmark

def testbed_matrix() -> dict[str, Any]:
    from backend.analyzers.ike_constants import DH_NAMES
    from backend.testbed.esp_model import ESP_SUITES, IKE_SUITES
    from backend.testbed.scenarios import AUTH_LABELS
    from backend.testbed.traffic_models import TRAFFIC_LABELS
    return {
        "ike_versions": ["IKEv2", "IKEv1 Main Mode", "IKEv1 Aggressive Mode"],
        "ike_suites": [{"key": s.key, "encryption": s.encryption_name, "integrity": s.integrity_name or "AEAD",
                        "prf": s.prf_name, "dh": f"{DH_NAMES[s.dh_group]} ({s.dh_group})"} for s in IKE_SUITES.values()],
        "esp_suites": [{"key": s.key, "label": s.label, "iv": s.iv, "block": s.block, "icv": s.icv,
                        "family": s.family} for s in ESP_SUITES.values()],
        "modes": ["Tunnel", "Transport"], "ip_versions": ["IPv4", "IPv6"], "pfs": ["enabled", "disabled"],
        "nat_traversal": ["off", "on (UDP 4500)"], "authentication": list(AUTH_LABELS.values()),
        "traffic": TRAFFIC_LABELS,
        "anomalies": ["duplicate sequence numbers", "counter reset", "ESP-NULL", "AH-only", "weak fallback proposals"],
    }


def build_dataset(count: int, seed: int, progress: Progress = _noop) -> dict[str, Any]:
    from backend.config import DATASET_DIR
    from backend.testbed.build_dataset import build_dataset as build
    progress(f"Rendering {count} labelled scenarios…")
    return build(DATASET_DIR / "testbed", count, seed)


def evaluate(scenarios: int, seed: int, progress: Progress = _noop) -> dict[str, Any]:
    from backend.ml import evaluation
    ensure_ready(progress)
    progress(f"Evaluating end-to-end on {scenarios} unseen scenarios…")
    return evaluation.evaluate_end_to_end(scenarios, seed)


def evaluation_latest() -> dict[str, Any] | None:
    from backend.ml import evaluation
    return evaluation.latest()


def benchmark(count: int, seed: int, progress: Progress = _noop) -> dict[str, Any]:
    from backend.ml import benchmark as bench
    ensure_ready(progress)
    progress(f"Running the misconfiguration benchmark ({count} scenarios)…")
    return bench.run_benchmark(count, seed)


def benchmark_latest() -> dict[str, Any] | None:
    from backend.ml import benchmark as bench
    return bench.latest()


# ---------------------------------------------------------------- live capture

def live_capabilities() -> dict[str, Any]:
    from backend.realtime.sources import DEFAULT_FILTER, capture_tools, list_interfaces, scapy_available
    tools = capture_tools()
    live = bool(tools) or scapy_available()
    return {"tools": sorted(tools), "scapy": scapy_available(), "live_capture": live,
            "interfaces": list_interfaces() if live else [], "default_filter": DEFAULT_FILTER}


def live_start_replay(target: str, speed: float):
    from backend.realtime.manager import manager
    ensure_ready()
    file_id, _, _ = resolve_target(target)
    return manager.start_replay(file_id, speed)


def live_start_interface(interface: str, bpf: str | None = None, tool: str | None = None):
    from backend.realtime.manager import manager
    ensure_ready()
    try:
        return manager.start_interface(interface, bpf, tool)
    except (ValueError, RuntimeError) as exc:
        raise CoreError(str(exc)) from exc


def bounded_capture(interface: str | None, duration: int, bpf: str, max_packets: int = 50_000) -> tuple[str, int]:
    """Sniff for a fixed time with Scapy, store as an upload; returns (file id, packet count)."""
    from backend.realtime.sources import BPF_ALLOWED, IFACE_ALLOWED
    from backend.storage import new_id, upload_path
    if not BPF_ALLOWED.match(bpf):
        raise CoreError("Capture filter contains unsupported characters")
    if interface and not IFACE_ALLOWED.match(interface):
        raise CoreError("Invalid interface name")
    try:
        from scapy.all import conf, sniff, wrpcap
        if not conf.use_pcap:
            raise PermissionError("libpcap/Npcap not available")
        pkts = sniff(iface=interface or None, filter=bpf, timeout=duration, count=max_packets, store=True)
    except (PermissionError, OSError, RuntimeError) as exc:
        raise CoreError(f"Live capture unavailable: {exc}. Install Npcap (Windows) or run as root (Linux), "
                        "or capture with tcpdump/Wireshark and pass the file to `securiq analyze`.") from exc
    file_id = new_id()
    wrpcap(str(upload_path(file_id, f"live-capture-{file_id}.pcap")), pkts)
    return file_id, len(pkts)


# ---------------------------------------------------------------- reports

def render_report(rec: dict[str, Any], kind: str, fmt: str) -> str:
    import json
    from backend.reports.html import render_executive, render_technical
    if fmt == "json":
        return json.dumps(rec if kind == "full" else rec[f"{kind}_report"], indent=2, default=str)
    if kind == "executive":
        return render_executive(rec["executive_report"], rec["threat_matrix"])
    if kind == "technical":
        return render_technical(rec["technical_report"])
    raise CoreError("HTML is available for executive and technical reports")
