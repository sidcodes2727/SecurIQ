"""
Digital-twin VPN lab: turn a chosen configuration into a labelled capture (testbed generator) plus the
equivalent strongSwan profile for the Docker lab in backend/testbed/strongswan.

Builds are stored under <data>/lab with a manifest, so they resolve like uploads and carry ground truth.
"""
from __future__ import annotations

import json
import re
import threading
import time
import zlib
from pathlib import Path
from typing import Any

from backend.config import DATA_DIR, TRAFFIC_CLASSES
from backend.testbed.esp_model import ESP_SUITES, IKE_SUITES, IkeSuite
from backend.testbed.scenarios import Scenario, write_scenario

LAB_DIR = DATA_DIR / "lab"
LAB_DIR.mkdir(parents=True, exist_ok=True)
MANIFEST = LAB_DIR / "manifest.json"
_lock = threading.Lock()

ENCR_IDS = {"AES-CBC": 12, "AES-GCM-16": 20, "3DES-CBC": 3, "ChaCha20-Poly1305": 28}
INTEG_IDS = {"HMAC-MD5-96": 1, "HMAC-SHA1-96": 2, "HMAC-SHA2-256-128": 12, "HMAC-SHA2-384-192": 13,
             "HMAC-SHA2-512-256": 14}
PRF_IDS = {"MD5": 1, "SHA1": 2, "SHA2-256": 5, "SHA2-384": 6, "SHA2-512": 7}
V1_HASH = {"MD5": 1, "SHA1": 2, "SHA2-256": 4, "SHA2-384": 5, "SHA2-512": 6}
SWAN_ENC = {"AES-256-GCM-16": "aes256gcm16", "AES-128-GCM-16": "aes128gcm16", "ChaCha20-Poly1305": "chacha20poly1305",
            "AES-256-CBC": "aes256", "AES-128-CBC": "aes128", "3DES-CBC": "3des"}
SWAN_INTEG = {"HMAC-MD5-96": "md5", "HMAC-SHA1-96": "sha1", "HMAC-SHA2-256-128": "sha256",
              "HMAC-SHA2-384-192": "sha384", "HMAC-SHA2-512-256": "sha512"}
SWAN_DH = {2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 19: "ecp256",
           20: "ecp384", 21: "ecp521", 31: "curve25519"}
SWAN_ESP = {"aes128gcm16": "aes128gcm16", "aes256gcm16": "aes256gcm16", "chacha20poly1305": "chacha20poly1305",
            "aes128-sha1": "aes128-sha1", "aes128-sha256": "aes128-sha256", "aes256-sha256": "aes256-sha256",
            "aes256-sha384": "aes256-sha384", "aes256-sha512": "aes256-sha512", "3des-sha1": "3des-sha1",
            "3des-md5": "3des-md5", "null-sha256": "null-sha256"}

DEFAULT_CONFIG: dict[str, Any] = {
    "ike_version": "IKEv2", "exchange_mode": "Main Mode", "ike_encryption": "AES-256-GCM-16",
    "ike_integrity": "None (AEAD)", "dh_group": 20, "auth": "rsa", "ike_lifetime": 14400,
    "esp_suite": "aes256gcm16", "pfs": True, "mode": "Tunnel", "child_lifetime": 3600,
    "anti_replay": True, "weak_proposals": False, "vendor_id": False,
    "ip_version": 4, "nat_t": False,
}


def _hash_token(integrity: str | None, encryption: str) -> str:
    if integrity:
        for token in ("SHA2-512", "SHA2-384", "SHA2-256", "SHA1", "MD5"):
            if token in integrity:
                return token
    return "SHA2-384" if "256" in encryption or "ChaCha" in encryption else "SHA2-256"


def ike_suite_for(encryption: str, integrity: str | None, dh_group: int) -> IkeSuite:
    """Register (once) and return an IKE suite object for any encryption/integrity/DH combination."""
    integrity = None if integrity in (None, "None (AEAD)") else integrity
    base = re.sub(r"-(128|256)", "", encryption, count=1) if encryption.startswith("AES-") else encryption
    key_length = 256 if "256" in encryption else 128 if "128" in encryption else None
    hash_token = _hash_token(integrity, encryption)
    key = f"lab-{SWAN_ENC.get(encryption, encryption)}-{SWAN_INTEG.get(integrity, 'aead') if integrity else 'aead'}-g{dh_group}"
    if key not in IKE_SUITES:
        IKE_SUITES[key] = IkeSuite(
            key, ENCR_IDS[base], key_length, INTEG_IDS.get(integrity, 0) if integrity else 0,
            PRF_IDS[hash_token], int(dh_group), 5 if base == "3DES-CBC" else 7, V1_HASH[hash_token])
    return IKE_SUITES[key]


def scenario_from_config(config: dict[str, Any], traffic: list[tuple[str, float]], name: str, seed: int,
                         description: str = "", impairment: str = "none") -> Scenario:
    c = {**DEFAULT_CONFIG, **{k: v for k, v in config.items() if v is not None}}
    v1 = c["ike_version"] == "IKEv1"
    suite = ike_suite_for(c["ike_encryption"], c["ike_integrity"], int(c["dh_group"]))
    return Scenario(
        name=name,
        description=description or "Lab build",
        ike_version=1 if v1 else 2,
        aggressive=v1 and c["exchange_mode"] == "Aggressive Mode",
        ike_suite=suite.key,
        esp_suite=c["esp_suite"],
        pfs=bool(c["pfs"]),
        mode=str(c["mode"]).lower(),
        ip_version=int(c.get("ip_version") or 4),
        nat_t=bool(c.get("nat_t")),
        auth=c["auth"] if not (v1 and c["auth"] == "eap") else "rsa",
        lifetime=int(c["ike_lifetime"] or 28800),
        rekey_after=18.0,    # compressed lab time: a rekey every 18 s makes PFS observable
        traffic=traffic,
        vendor="strongswan" if c["vendor_id"] else None,
        offer_weak=bool(c["weak_proposals"]),
        identity="gw-a.example.org",
        replay_duplicates=0 if c["anti_replay"] else 10,
        counter_reset=not c["anti_replay"],
        impairment=impairment,
        seed=seed,
    )


def strongswan_profile(config: dict[str, Any], traffic: list[tuple[str, float]], name: str) -> str:
    c = {**DEFAULT_CONFIG, **{k: v for k, v in config.items() if v is not None}}
    dh = SWAN_DH.get(int(c["dh_group"]), f"modp{c['dh_group']}")
    enc = SWAN_ENC.get(c["ike_encryption"], "aes256")
    integ = SWAN_INTEG.get(c["ike_integrity"])
    prf = "prf" + _hash_token(integ and c["ike_integrity"], c["ike_encryption"]).lower().replace("2-", "").replace("-", "")
    ike = f"{enc}-{integ}-{dh}" if integ else f"{enc}-{prf}-{dh}"
    esp = SWAN_ESP.get(c["esp_suite"], "aes256gcm16") + (f"-{dh}" if c["pfs"] else "")
    traffic_spec = " ".join(f"{cls}:{int(seconds)}" for cls, seconds in traffic)
    lines = [
        f"PROFILE_NAME={name}",
        "DESCRIPTION=SecurIQ lab build",
        f"IKE_VERSION={1 if c['ike_version'] == 'IKEv1' else 2}",
        f"AGGRESSIVE={'yes' if c['ike_version'] == 'IKEv1' and c['exchange_mode'] == 'Aggressive Mode' else 'no'}",
        f"IKE_PROPOSALS={ike}",
        f"ESP_PROPOSALS={esp}",
        f"MODE={str(c['mode']).lower()}",
        f"IP_FAMILY={int(c.get('ip_version') or 4)}",
        f"FORCE_ENCAP={'yes' if c.get('nat_t') else 'no'}",
        "CHILD_REKEY_TIME=40s",
        f"CHILD_LIFE_TIME={int(c['child_lifetime'] or 3600)}s",
        f"IKE_REKEY_TIME={int(c['ike_lifetime'] or 14400)}s",
        "PSK=lab-only-change-me",
        f"TRAFFIC={traffic_spec}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- persistence

def _read() -> dict[str, Any]:
    try:
        return json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    except (OSError, ValueError):
        return {}


def list_builds() -> list[dict[str, Any]]:
    builds = list(_read().values())
    builds.sort(key=lambda b: b.get("created", 0), reverse=True)
    return [{k: v for k, v in b.items() if k != "truth"} for b in builds]


def resolve(file_id: str) -> tuple[Path, dict[str, Any]] | None:
    entry = _read().get(file_id)
    if not entry:
        return None
    path = LAB_DIR / entry["file"]
    return (path, entry["truth"]) if path.exists() else None


def normalise_traffic(traffic: list[dict[str, Any]] | None) -> list[tuple[str, float]]:
    out = []
    for item in traffic or []:
        cls, seconds = item.get("class"), float(item.get("seconds") or 0)
        if cls in TRAFFIC_CLASSES and seconds > 0:
            out.append((cls, max(10.0, min(60.0, seconds))))
    return out[:7] or [("web", 25.0), ("voip", 25.0)]


def build(config: dict[str, Any], traffic: list[tuple[str, float]], label: str = "",
          derived_from: str | None = None, impairment: str = "none") -> tuple[str, Path, dict[str, Any]]:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    file_id = f"lab_{stamp}_{zlib.crc32(json.dumps([config, traffic, label, time.time()], default=str).encode()) % 10**6:06d}"
    seed = zlib.crc32(file_id.encode()) % 10**8
    scenario = scenario_from_config(config, traffic, file_id, seed, label or "Lab build", impairment)
    path, truth = write_scenario(scenario, LAB_DIR)
    profile = strongswan_profile(config, traffic, file_id)
    entry = {"id": file_id, "file": path.name, "label": label or "Lab build", "created": time.time(),
             "config": {**DEFAULT_CONFIG, **{k: v for k, v in config.items() if v is not None}},
             "traffic": [{"class": c, "seconds": s} for c, s in traffic], "packets": truth.get("packets"),
             "derived_from": derived_from, "strongswan_profile": profile, "truth": truth}
    with _lock:
        manifest = _read()
        manifest[file_id] = entry
        MANIFEST.write_text(json.dumps(manifest, default=str), encoding="utf-8")
    return file_id, path, truth


def traffic_from_record(record: dict[str, Any]) -> list[tuple[str, float]]:
    """Reuse the capture's traffic: the ground-truth segments of a testbed capture, else the classified mix."""
    source = record.get("source") or {}
    if source.get("is_sample") or source.get("lab"):
        from backend.storage import resolve_capture
        resolved = resolve_capture(source.get("file_id", ""))
        if resolved and resolved[1] and resolved[1].get("config"):
            return [(c, min(60.0, float(s))) for c, s in resolved[1]["config"]["traffic"]]
    traffic = record.get("traffic") or {}
    mix = traffic.get("mix") or {}
    total = min(120.0, max(40.0, 10.0 * (traffic.get("windows") or 4)))
    out = [(cls, max(12.0, total * share)) for cls, share in mix.items() if share >= 0.08]
    return out[:5] or [("web", 25.0), ("voip", 25.0)]


def config_for_verify(record: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Current configuration (observed where possible, lab defaults where not) with the proposed changes."""
    from backend.intel.simulator import current_config
    analysis = record["ipsec_analysis"]
    cur = current_config(analysis)
    config = {k: v for k, v in cur.items() if k in DEFAULT_CONFIG and v is not None}
    if cur.get("esp_observed") and "esp_suite" not in changes:
        config["esp_suite"] = _esp_key_from_observed(cur["esp_observed"], cur.get("ike_encryption"))
    if config.get("ike_encryption") not in SWAN_ENC:
        config.pop("ike_encryption", None)
        config.pop("ike_integrity", None)
    if config.get("ike_integrity") not in list(SWAN_INTEG) + ["None (AEAD)"]:
        config.pop("ike_integrity", None)
    if config.get("dh_group") not in SWAN_DH:
        config.pop("dh_group", None)
    ip = ((analysis.get("profile") or {}).get("ip_version") or {}).get("value")
    config["ip_version"] = 6 if ip == "IPv6" else 4
    config["nat_t"] = bool(((analysis.get("profile") or {}).get("nat_traversal") or {}).get("value"))
    if config.get("ike_version") != "IKEv1":
        config.pop("exchange_mode", None)
    config.update({k: v for k, v in changes.items() if v is not None})
    if "ike_integrity" not in changes and config.get("ike_encryption") and "GCM" in config["ike_encryption"]:
        config["ike_integrity"] = "None (AEAD)"
    if config.get("ike_integrity") == "None (AEAD)" and not any(
            t in (config.get("ike_encryption") or "AES-256-GCM-16") for t in ("GCM", "ChaCha")):
        config["ike_integrity"] = "HMAC-SHA2-256-128"
    return config


def _esp_key_from_observed(observed: str, ike_encryption: str | None) -> str:
    """Pick the testbed ESP suite matching the inferred family; key length follows the IKE SA as a best guess."""
    wide = bool(ike_encryption) and "256" in ike_encryption
    if "NULL" in observed:
        return "null-sha256"
    if "AEAD" in observed or "GCM" in observed:
        return "aes256gcm16" if wide else "aes128gcm16"
    if "3DES" in observed:
        return "3des-md5" if "MD5" in observed else "3des-sha1"
    if "SHA2-512" in observed:
        return "aes256-sha512"
    if "SHA2-384" in observed:
        return "aes256-sha384"
    if "SHA2-256" in observed:
        return "aes256-sha256" if wide else "aes128-sha256"
    return "aes128-sha1"
