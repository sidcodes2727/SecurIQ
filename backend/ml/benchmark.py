"""
Misconfiguration benchmark: does the analyzer catch weak configurations it has never seen?

Each test capture is a random configuration with 0–3 injected misconfigurations. Ground truth comes from
the configuration itself; detection comes from the findings the full pipeline raises on the rendered
PCAP. Reported per misconfiguration type: TP / FN / FP, precision, recall, F1; overall detection rate and
the false-alarm rate on clean captures.

    python -m backend.ml.benchmark --count 40
"""
from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from backend.config import EVALUATION_DIR, TRAFFIC_CLASSES
from backend.intel.lab import ike_suite_for
from backend.testbed.scenarios import Scenario, write_scenario

RESULT_PATH = EVALUATION_DIR / "misconfig_benchmark.json"

# type → (label, mutate scenario kwargs, expected-from-config predicate, detected-from-finding-ids predicate)
Mutator = Callable[[dict, random.Random], None]


def _set_ike(kw: dict, encryption: str | None = None, integrity: str | None = None, dh: int | None = None) -> None:
    enc, integ, group = kw["_ike"]
    kw["_ike"] = (encryption or enc, integrity if integrity is not None else integ, dh or group)


MISCONFIGS: dict[str, dict[str, Any]] = {
    "weak_dh": {"label": "Weak DH group (1024/1536-bit)",
                "mutate": lambda kw, r: _set_ike(kw, dh=r.choice([2, 5])),
                "expected": lambda c: c["_ike"][2] in (1, 2, 5, 22),
                "detected": lambda ids: bool(ids & {"KE-001", "KE-002"})},
    "legacy_cipher": {"label": "3DES cipher (64-bit block)",
                      "mutate": lambda kw, r: (_set_ike(kw, encryption="3DES-CBC", integrity=kw["_ike"][1]
                                                        if kw["_ike"][1] != "None (AEAD)" else "HMAC-SHA1-96"),
                                               kw.update(esp_suite=r.choice(["3des-sha1", kw["esp_suite"]]))),
                      "expected": lambda c: c["_ike"][0] == "3DES-CBC" or c["esp_suite"].startswith("3des"),
                      "detected": lambda ids: "CRYPTO-003" in ids},
    "no_encryption": {"label": "ESP-NULL (no encryption)",
                      "mutate": lambda kw, r: kw.update(esp_suite="null-sha256"),
                      "expected": lambda c: c["esp_suite"] == "null-sha256",
                      "detected": lambda ids: "CRYPTO-001" in ids},
    "md5_integrity": {"label": "MD5 integrity",
                      "mutate": lambda kw, r: (_set_ike(kw, encryption=kw["_ike"][0] if "GCM" not in kw["_ike"][0]
                                                        else "AES-128-CBC", integrity="HMAC-MD5-96")),
                      "expected": lambda c: c["_ike"][1] == "HMAC-MD5-96" or c["esp_suite"].endswith("md5"),
                      "detected": lambda ids: "AUTH-004" in ids},
    "no_pfs": {"label": "PFS disabled",
               "mutate": lambda kw, r: kw.update(pfs=False),
               "expected": lambda c: not c["pfs"],
               "detected": lambda ids: "PFS-001" in ids},
    "long_lifetime": {"label": "IKE SA lifetime > 24 h",
                      "mutate": lambda kw, r: (kw.update(ike_version=1, lifetime=r.choice([172800, 604800])),
                                               _set_ike(kw, encryption=kw["_ike"][0] if "GCM" not in kw["_ike"][0]
                                                        else "AES-256-CBC",
                                                        integrity=kw["_ike"][1] if kw["_ike"][1] != "None (AEAD)"
                                                        else "HMAC-SHA2-256-128")),
                      "expected": lambda c: c["ike_version"] == 1 and c["lifetime"] > 86400,
                      "detected": lambda ids: "LIFE-001" in ids},
    "aggressive_psk": {"label": "IKEv1 Aggressive Mode + PSK",
                       "mutate": lambda kw, r: (kw.update(ike_version=1, aggressive=True, auth="psk"),
                                                _set_ike(kw, encryption=kw["_ike"][0] if "GCM" not in kw["_ike"][0]
                                                         else "AES-128-CBC",
                                                         integrity=kw["_ike"][1] if kw["_ike"][1] != "None (AEAD)"
                                                         else "HMAC-SHA1-96")),
                       "expected": lambda c: c["ike_version"] == 1 and c["aggressive"] and c["auth"] == "psk",
                       "detected": lambda ids: "AUTH-001" in ids},
    "ikev1": {"label": "Deprecated IKEv1",
              "mutate": lambda kw, r: (kw.update(ike_version=1),
                                       _set_ike(kw, encryption=kw["_ike"][0] if "GCM" not in kw["_ike"][0]
                                                else "AES-256-CBC",
                                                integrity=kw["_ike"][1] if kw["_ike"][1] != "None (AEAD)"
                                                else "HMAC-SHA2-256-128")),
              "expected": lambda c: c["ike_version"] == 1,
              "detected": lambda ids: "CFG-001" in ids},
    "replay": {"label": "Replayed ESP packets",
               "mutate": lambda kw, r: kw.update(replay_duplicates=r.randint(6, 14)),
               "expected": lambda c: c["replay_duplicates"] > 0,
               "detected": lambda ids: "REPLAY-001" in ids},
    "counter_reset": {"label": "Sequence counter reset (anti-replay off)",
                      "mutate": lambda kw, r: kw.update(counter_reset=True),
                      "expected": lambda c: c["counter_reset"],
                      "detected": lambda ids: "REPLAY-002" in ids},
    "weak_proposals": {"label": "Weak fallback proposals offered",
                       "mutate": lambda kw, r: kw.update(offer_weak=True),
                       "expected": lambda c: c["offer_weak"],
                       "detected": lambda ids: "KE-006" in ids},
    "vendor_id": {"label": "Implementation disclosed (Vendor ID)",
                  "mutate": lambda kw, r: kw.update(vendor=r.choice(["cisco", "strongswan", "windows"])),
                  "expected": lambda c: c["vendor"] is not None,
                  "detected": lambda ids: "META-002" in ids},
}


def _clean(rng: random.Random, index: int) -> dict[str, Any]:
    return {
        "name": f"bench_{index:04d}", "description": "Misconfiguration benchmark", "ike_version": 2,
        "aggressive": False, "_ike": (rng.choice(["AES-256-GCM-16", "AES-128-GCM-16"]), "None (AEAD)",
                                     rng.choice([19, 20, 31])),
        "esp_suite": rng.choice(["aes256gcm16", "aes128gcm16", "chacha20poly1305"]), "pfs": True,
        "mode": "tunnel", "ip_version": rng.choice([4, 4, 6]), "nat_t": rng.random() < 0.2,
        "auth": rng.choice(["rsa", "ecdsa"]), "lifetime": 14400, "rekey_after": rng.uniform(10, 16),
        "traffic": [(c, rng.uniform(18, 26)) for c in rng.sample(TRAFFIC_CLASSES, k=2)], "vendor": None,
        "offer_weak": False, "identity": "gw-a.example.org", "replay_duplicates": 0, "counter_reset": False,
        "seed": rng.randint(1, 10**9),
    }


def _scenario(kw: dict[str, Any]) -> Scenario:
    enc, integ, dh = kw["_ike"]
    if kw["ike_version"] == 1 and "GCM" in enc:
        enc, integ = "AES-256-CBC", "HMAC-SHA2-256-128"
    suite = ike_suite_for(enc, integ, dh)
    args = {k: v for k, v in kw.items() if not k.startswith("_")}
    return Scenario(ike_suite=suite.key, **args)


def run_benchmark(count: int = 40, seed: int = 99, clean_share: float = 0.2) -> dict[str, Any]:
    from backend.pipeline import run_pipeline

    started = time.time()
    rng = random.Random(seed)
    types = list(MISCONFIGS)
    stats = {t: {"tp": 0, "fn": 0, "fp": 0} for t in types}
    cases, clean_alarms, clean_total = [], 0, 0
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(count):
            kw = _clean(rng, i)
            injected = [] if rng.random() < clean_share else rng.sample(types, k=rng.choice([1, 2, 3]))
            for t in injected:
                MISCONFIGS[t]["mutate"](kw, rng)
            scenario = _scenario(kw)
            path, truth = write_scenario(scenario, Path(tmp))
            result = run_pipeline(str(path), truth)
            ids = {f["id"] for f in result["security"]["findings"]}
            expected = {t for t in types if MISCONFIGS[t]["expected"](kw)}
            detected = {t for t in types if MISCONFIGS[t]["detected"](ids)}
            for t in types:
                if t in expected and t in detected:
                    stats[t]["tp"] += 1
                elif t in expected:
                    stats[t]["fn"] += 1
                elif t in detected:
                    stats[t]["fp"] += 1
            if not expected:
                clean_total += 1
                clean_alarms += bool(detected)
            cases.append({"name": scenario.name, "injected": injected, "expected": sorted(expected),
                          "detected": sorted(detected), "missed": sorted(expected - detected),
                          "false_alarms": sorted(detected - expected), "score": result["security"]["overall_score"],
                          "risk_level": result["security"]["risk_level"]})

    per_type = []
    for t in types:
        s = stats[t]
        precision = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else None
        recall = s["tp"] / (s["tp"] + s["fn"]) if s["tp"] + s["fn"] else None
        f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
        per_type.append({"type": t, "label": MISCONFIGS[t]["label"], **s,
                         "precision": None if precision is None else round(precision, 3),
                         "recall": None if recall is None else round(recall, 3),
                         "f1": None if f1 is None else round(f1, 3)})
    tp = sum(s["tp"] for s in stats.values())
    fn = sum(s["fn"] for s in stats.values())
    fp = sum(s["fp"] for s in stats.values())
    result = {
        "available": True,
        "captures": count,
        "seed": seed,
        "injected_total": tp + fn,
        "detected": tp,
        "missed": fn,
        "false_positives": fp,
        "detection_rate": round(tp / (tp + fn), 4) if tp + fn else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "clean_captures": clean_total,
        "clean_false_alarm_rate": round(clean_alarms / clean_total, 4) if clean_total else None,
        "per_type": per_type,
        "cases": cases,
        "seconds": round(time.time() - started, 1),
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": ("Ground truth is the configuration that produced each PCAP; detection is the set of findings the "
                 "full pipeline raised from the PCAP alone. Captures come from the synthetic testbed generator."),
    }
    RESULT_PATH.write_text(json.dumps(result), encoding="utf-8")
    return result


def latest() -> dict[str, Any] | None:
    try:
        return json.loads(RESULT_PATH.read_text(encoding="utf-8")) if RESULT_PATH.exists() else None
    except (OSError, ValueError):
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=99)
    args = parser.parse_args()
    out = run_benchmark(args.count, args.seed)
    print(json.dumps({k: v for k, v in out.items() if k not in ("cases",)}, indent=2))
