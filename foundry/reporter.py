"""REPORTER role (Foundry Security Spec §5, finding pipeline).

Publishes the final artifact: only CONFIRMED findings, severity/priority sorted,
each carrying its full provenance chain (detected -> triaged -> validated ->
reported). Also emits the coverage/done verdict and a rule-gap list (exploratory
findings with no CodeGuard rule — candidates for the prevention flywheel).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from .coverage_guide import Coverage
from .finding import Finding, State
from .substrate import Substrate


def run(substrate: Substrate, findings: List[Finding], coverage: Coverage,
        meta: dict, model: str, offline: bool) -> dict:
    confirmed = [f for f in findings if f.state == State.CONFIRMED]
    for f in confirmed:
        f.state = State.REPORTED
        f.stamp("REPORTER", "published")
    confirmed.sort(key=lambda f: f.sort_key())

    rule_gaps = [f.to_dict() for f in confirmed if f.rule_id == "EXPLORE"]

    report = {
        "summary": {
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "engine": "foundry-sec-app (reference impl of Foundry Security Spec)",
            "target": f"{meta.get('owner','?')}/{meta.get('repo','?')}",
            "detector": "heuristic (offline)" if offline else f"llm:{model} + rule-sweep",
            "files_indexed": meta.get("source_files_indexed"),
            "files_total": meta.get("source_files_total"),
            "total_confirmed": len(confirmed),
            "by_severity": dict(Counter(f.severity.upper() for f in confirmed)),
            "by_rule": dict(Counter(f.rule_id for f in confirmed)),
            "rule_gaps": len(rule_gaps),
            "llm_calls_used": substrate.budget.used_llm_calls,
            "coverage_pct": coverage.coverage_pct,
            "coverage_floor_pct": coverage.floor_pct,
            "done": coverage.done,
        },
        "coverage": coverage.to_dict(),
        "findings": [f.to_dict() for f in confirmed],
        "rule_gaps": rule_gaps,
        "run_log": substrate.log,
    }
    substrate.emit("REPORTER", f"published {len(confirmed)} finding(s)")
    return report
