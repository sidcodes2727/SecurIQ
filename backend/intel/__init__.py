"""
Decision-support layer on top of the analysis pipeline.

  chains       Packet → extracted parameter → security rule → risk → recommendation, per finding
  checks       per-field evidence checklists and configuration-novelty signals
  metadata     what an eavesdropper still learns from an encrypted tunnel
  fingerprint  a stable configuration fingerprint, and drift between two captures
  policy       "golden configuration" compliance against an administrator's policy
  simulator    what-if configuration changes, re-scored by the same rule engine
  surface      attack-surface graph: gateways → IKE SA → Child SAs → traffic, with risks overlaid
  lab          digital-twin builds: a chosen configuration rendered to a capture (and a strongSwan config)

Everything here is deterministic: rules and templates, no language model, so every sentence
can be traced back to a packet field or a measured statistic.
"""
from __future__ import annotations

from typing import Any


def build_intel(record: dict[str, Any]) -> dict[str, Any]:
    """Derive every decision-support view from a pipeline result or a stored analysis record."""
    from backend.intel.chains import build_chains, posture_explanation
    from backend.intel.checks import configuration_novelty, evidence_checks
    from backend.intel.fingerprint import config_fingerprint
    from backend.intel.metadata import metadata_leakage
    from backend.intel.policy import evaluate_policy, load_policy
    from backend.intel.surface import attack_surface

    analysis = record["ipsec_analysis"]
    security = record["security"]
    chains = build_chains(analysis, security, record.get("traffic") or {})
    return {
        "version": 1,
        "chains": chains,
        "posture": posture_explanation(security, chains),
        "checks": evidence_checks(analysis, record.get("traffic") or {}, record.get("classification") or []),
        "novelty": configuration_novelty(analysis, record.get("traffic") or {}),
        "metadata": metadata_leakage(analysis, record.get("traffic") or {}, security),
        "fingerprint": config_fingerprint(analysis),
        "surface": attack_surface(analysis, security, record.get("traffic") or {}),
        "policy": evaluate_policy(load_policy(), analysis),
    }
