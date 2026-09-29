"""
Threat matrix (PS §e): findings mapped to IPsec-specific threats on a 5 × 5
likelihood × impact grid, with MITRE ATT&CK technique references where one applies.
"""
from __future__ import annotations

from typing import Any

THREATS: dict[str, dict[str, str]] = {
    "passive_decryption": {
        "name": "Decryption of recorded traffic",
        "description": "Weak ciphers or DH groups let an adversary who records the tunnel recover plaintext.",
        "attack": "T1040 Network Sniffing",
    },
    "quantum_hndl": {
        "name": "Harvest now, decrypt later (quantum)",
        "description": "Classical key exchange recorded today may be broken by a future quantum computer.",
        "attack": "T1040 Network Sniffing",
    },
    "downgrade": {
        "name": "Algorithm / protocol downgrade",
        "description": "Weaker proposals or legacy protocol versions an active attacker can steer toward.",
        "attack": "T1600.001 Weaken Encryption: Reduce Key Space",
    },
    "psk_cracking": {
        "name": "Offline pre-shared key cracking",
        "description": "Captured authentication hashes allow brute-forcing the PSK and impersonating a gateway.",
        "attack": "T1110.002 Password Cracking",
    },
    "reconnaissance": {
        "name": "Identity & topology reconnaissance",
        "description": "Cleartext identities, product fingerprints and endpoint addresses aid targeting.",
        "attack": "T1590 Gather Victim Network Information",
    },
    "traffic_analysis": {
        "name": "Traffic analysis of the tunnel",
        "description": "Packet sizes and timing reveal what applications run inside the encrypted tunnel.",
        "attack": "T1040 Network Sniffing",
    },
    "replay_injection": {
        "name": "Replay / packet injection",
        "description": "Weak integrity or disabled anti-replay lets captured packets be replayed or forged.",
        "attack": "T1557 Adversary-in-the-Middle",
    },
    "key_compromise": {
        "name": "Key compromise blast radius",
        "description": "Without PFS and with long lifetimes, one stolen key exposes large volumes of traffic.",
        "attack": "—",
    },
    "impersonation": {
        "name": "Gateway impersonation / MitM",
        "description": "Weak peer authentication allows an attacker to stand in for a VPN gateway.",
        "attack": "T1557 Adversary-in-the-Middle",
    },
}

# finding id -> [(threat, likelihood 1-5, impact 1-5)]
FINDING_THREATS: dict[str, list[tuple[str, int, int]]] = {
    "CRYPTO-001": [("passive_decryption", 5, 5), ("traffic_analysis", 5, 4)],
    "CRYPTO-002": [("passive_decryption", 4, 5)],
    "CRYPTO-003": [("passive_decryption", 3, 4)],
    "CRYPTO-004": [("passive_decryption", 1, 3)],
    "KE-001": [("passive_decryption", 4, 5), ("impersonation", 3, 5)],
    "KE-002": [("passive_decryption", 3, 4)],
    "KE-003": [("quantum_hndl", 2, 4)],
    "KE-005": [("quantum_hndl", 2, 4)],
    "KE-006": [("downgrade", 2, 4)],
    "PFS-001": [("key_compromise", 3, 4)],
    "AUTH-001": [("psk_cracking", 4, 5), ("impersonation", 3, 5), ("reconnaissance", 4, 2)],
    "AUTH-002": [("psk_cracking", 2, 4)],
    "AUTH-004": [("replay_injection", 2, 4), ("impersonation", 2, 4)],
    "AUTH-005": [("replay_injection", 1, 3)],
    "LIFE-001": [("key_compromise", 2, 3)],
    "LIFE-002": [("key_compromise", 2, 2)],
    "LIFE-004": [("replay_injection", 2, 3)],
    "REPLAY-001": [("replay_injection", 3, 4)],
    "REPLAY-002": [("replay_injection", 3, 4)],
    "REPLAY-003": [("replay_injection", 1, 2)],
    "CFG-001": [("downgrade", 2, 3)],
    "META-001": [("reconnaissance", 5, 3)],
    "META-002": [("reconnaissance", 4, 2)],
    "META-003": [("traffic_analysis", 4, 3)],
    "META-005": [("reconnaissance", 3, 2)],
}

LEVELS = [(20, "Critical"), (12, "High"), (6, "Medium"), (3, "Low"), (0, "Negligible")]


def _level(risk: int) -> str:
    return next(label for threshold, label in LEVELS if risk >= threshold)


def generate_threat_matrix(findings: list[dict[str, Any]]) -> dict[str, Any]:
    threats: dict[str, dict[str, Any]] = {}
    for f in findings:
        for key, likelihood, impact in FINDING_THREATS.get(f["id"], []):
            entry = threats.setdefault(key, {"id": key, **THREATS[key], "likelihood": 0, "impact": 0,
                                             "contributing_findings": []})
            # Inferred evidence with low confidence lowers likelihood by one step.
            if f.get("evidence_source") == "inferred" and f.get("confidence", 1) < 0.6:
                likelihood = max(1, likelihood - 1)
            entry["likelihood"] = max(entry["likelihood"], likelihood)
            entry["impact"] = max(entry["impact"], impact)
            if f["id"] not in entry["contributing_findings"]:
                entry["contributing_findings"].append(f["id"])

    for entry in threats.values():
        entry["risk_score"] = entry["likelihood"] * entry["impact"]
        entry["risk_level"] = _level(entry["risk_score"])
    ordered = sorted(threats.values(), key=lambda t: t["risk_score"], reverse=True)

    grid = [[[] for _ in range(5)] for _ in range(5)]  # grid[likelihood-1][impact-1]
    for t in ordered:
        grid[t["likelihood"] - 1][t["impact"] - 1].append(t["id"])

    return {
        "threats": ordered,
        "grid": grid,
        "scale": {"likelihood": "1 rare – 5 almost certain", "impact": "1 negligible – 5 severe",
                  "risk": "likelihood × impact (1–25)"},
        "max_risk_score": max((t["risk_score"] for t in ordered), default=0),
        "threat_count": len(ordered),
        "critical_count": sum(1 for t in ordered if t["risk_level"] == "Critical"),
        "high_count": sum(1 for t in ordered if t["risk_level"] == "High"),
        "categories_defined": len(THREATS),
    }
