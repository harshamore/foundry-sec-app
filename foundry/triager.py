"""TRIAGER role (Foundry Security Spec §5, finding pipeline).

Takes raw detections and makes them a bounded, prioritised set: deduplicates by
fingerprint (the same line found by both the sweep and the hunt collapses to
one), normalises severity, and assigns a priority score the Reporter sorts on.
Priority blends severity, detector confidence, and whether the finding sits on a
mapped attack-surface hotspot.
"""

from __future__ import annotations

from typing import Dict, List

from .cartographer import SurfaceMap
from .finding import Finding, SEVERITY_ORDER, State
from .substrate import Substrate

_SEV_WEIGHT = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 20, "INFO": 5}


def run(substrate: Substrate, findings: List[Finding],
        smap: SurfaceMap) -> List[Finding]:
    hotspot_files = set(smap.hotspots)

    # dedupe, preferring the higher-confidence / rule-attributed copy
    by_fp: Dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint
        if fp not in by_fp:
            by_fp[fp] = f
        else:
            keep = by_fp[fp]
            # prefer a rule-attributed finding over an EXPLORE duplicate
            if keep.rule_id == "EXPLORE" and f.rule_id != "EXPLORE":
                by_fp[fp] = f
            else:
                keep.confidence = max(keep.confidence, f.confidence)

    deduped = list(by_fp.values())
    dropped = len(findings) - len(deduped)

    for f in deduped:
        sev = f.severity.upper()
        if sev not in _SEV_WEIGHT:
            sev = "MEDIUM"
            f.severity = "MEDIUM"
        score = _SEV_WEIGHT[sev]
        score += int(f.confidence * 20)
        if f.file in hotspot_files:
            score += 15            # on a mapped entry->sink path
        f.priority = score
        f.state = State.TRIAGED
        f.stamp("TRIAGER", "prioritised", f"score={score}")

    deduped.sort(key=lambda f: f.sort_key())
    substrate.metrics["triaged"] = len(deduped)
    substrate.metrics["deduped_out"] = dropped
    substrate.emit("TRIAGER",
                   f"{len(deduped)} finding(s) after dedup ({dropped} merged)")
    return deduped
