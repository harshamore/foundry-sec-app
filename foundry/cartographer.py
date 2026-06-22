"""CARTOGRAPHER role (Foundry Security Spec §5, knowledge layer).

Builds the map of the target the Detector hunts within: entry points (where
untrusted input arrives), dangerous sinks (where it can do harm), and a rough
sense of the trust boundaries. The spec's point is that detection without a map
is undirected; the Cartographer gives the Detector somewhere to look first.

Heuristic by default (regex over the corpus). With an LLM available it adds a
short architectural read of the highest-signal files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

from .indexer import Unit
from .llm import LLM
from .substrate import Substrate

ENTRY_PATTERNS = [
    (r"@app\.route|@router\.(get|post|put|delete)|@bp\.route", "HTTP route"),
    (r"def\s+(handler|lambda_handler)\b", "serverless handler"),
    (r"request\.(args|form|json|data|get_data|files|cookies)", "request input"),
    (r"input\s*\(", "stdin input"),
    (r"sys\.argv", "CLI args"),
    (r"os\.environ", "environment input"),
]
SINK_PATTERNS = [
    (r"subprocess\.|os\.system|os\.popen|shell=True", "command execution"),
    (r"\.execute\s*\(|cursor\.execute", "SQL execution"),
    (r"pickle\.loads?|yaml\.load\s*\((?!.*Safe)", "deserialization"),
    (r"open\s*\(|os\.remove|shutil\.", "filesystem"),
    (r"requests\.(get|post)|urllib|httpx\.", "outbound network"),
    (r"eval\s*\(|exec\s*\(", "dynamic eval"),
]


@dataclass
class SurfaceMap:
    entry_points: List[dict] = field(default_factory=list)
    sinks: List[dict] = field(default_factory=list)
    hotspots: List[str] = field(default_factory=list)   # files with both entry + sink
    notes: str = ""

    def to_dict(self) -> dict:
        return {"entry_points": self.entry_points, "sinks": self.sinks,
                "hotspots": self.hotspots, "notes": self.notes}


def _scan(units: List[Unit], patterns) -> List[dict]:
    hits = []
    for u in units:
        for i, ln in enumerate(u.code.splitlines(), start=1):
            s = ln.lstrip()
            if s.startswith("#") or s.startswith("//"):
                continue
            for pat, label in patterns:
                if re.search(pat, ln):
                    hits.append({"file": u.file, "line": i, "kind": label})
                    break
    return hits


def run(substrate: Substrate, units: List[Unit], llm: LLM) -> SurfaceMap:
    entries = _scan(units, ENTRY_PATTERNS)
    sinks = _scan(units, SINK_PATTERNS)
    entry_files = {e["file"] for e in entries}
    sink_files = {s["file"] for s in sinks}
    hotspots = sorted(entry_files & sink_files)

    smap = SurfaceMap(entry_points=entries, sinks=sinks, hotspots=hotspots)

    if llm.available and substrate.budget.can_spend() and units:
        digest = "\n\n".join(
            f"### {u.file}\n{u.code[:1500]}" for u in units[:6])
        sys = ("You are the Cartographer of a Foundry-spec security evaluation. "
               "In <=120 words, describe the target's attack surface: where "
               "untrusted input enters and which sinks it can reach. Be concrete, "
               "no preamble.")
        out = llm.complete(substrate, sys, digest, max_tokens=400)
        if out:
            smap.notes = out

    substrate.metrics["surface"] = {
        "entry_points": len(entries), "sinks": len(sinks), "hotspots": len(hotspots)}
    substrate.emit("CARTOGRAPHER",
                   f"{len(entries)} entry point(s), {len(sinks)} sink(s), "
                   f"{len(hotspots)} hotspot file(s)")
    return smap
