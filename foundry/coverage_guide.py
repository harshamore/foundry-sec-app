"""COVERAGE-GUIDE role (Foundry Security Spec §5, oversight).

Answers the question raw-LLM scanning can't: "are we done, and what did we
miss?" Produces a coverage signal and a done/not-done verdict against an
operator-set coverage floor — one of the spec's four required outcomes (a clear
"done" signal based on coverage floors and economic yield).

Coverage here = fraction of indexed units actually swept AND (if the LLM hunt
ran) examined, adjusted down when ingestion was truncated by the file cap. This
is a transparent proxy, not a guarantee — the spec is explicit that coverage is
operator-defined; we surface the number and let the operator judge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .finding import Finding, State
from .indexer import Unit
from .substrate import Substrate


@dataclass
class Coverage:
    units_total: int = 0
    units_swept: int = 0
    units_hunted: int = 0
    repo_truncated: bool = False
    repo_files_total: int = 0
    repo_files_indexed: int = 0
    sweep_pct: float = 0.0
    hunt_pct: float = 0.0
    ingest_pct: float = 100.0
    coverage_pct: float = 0.0
    floor_pct: float = 0.0
    done: bool = False
    gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__


def run(substrate: Substrate, units: List[Unit], findings: List[Finding],
        meta: dict, floor_pct: float, hunt_ran: bool) -> Coverage:
    total = len(units)
    swept = total                      # rule sweep always covers every unit
    files_with_findings = {f.file for f in findings}
    hunted = total if hunt_ran else 0

    repo_total = meta.get("source_files_total", total)
    repo_indexed = meta.get("source_files_indexed", total)
    truncated = bool(meta.get("truncated", False))

    sweep_pct = 100.0 if total else 0.0
    hunt_pct = (100.0 if hunt_ran else 0.0)
    ingest_pct = (repo_indexed / repo_total * 100.0) if repo_total else 100.0

    # Overall coverage: ingestion completeness gates everything; within what was
    # ingested, the sweep is full and the hunt is a bonus weighting.
    base = ingest_pct
    quality = 0.6 * sweep_pct + 0.4 * hunt_pct   # 60 with sweep only, 100 with both
    coverage = base * (quality / 100.0)

    cov = Coverage(
        units_total=total, units_swept=swept, units_hunted=hunted,
        repo_truncated=truncated, repo_files_total=repo_total,
        repo_files_indexed=repo_indexed,
        sweep_pct=round(sweep_pct, 1), hunt_pct=round(hunt_pct, 1),
        ingest_pct=round(ingest_pct, 1), coverage_pct=round(coverage, 1),
        floor_pct=floor_pct,
    )

    if truncated:
        cov.gaps.append(
            f"Ingestion truncated at {meta.get('cap')} files "
            f"({repo_indexed}/{repo_total} source files indexed). "
            "Remaining files were not assessed.")
    if not hunt_ran:
        cov.gaps.append(
            "Exploratory hunt did not run (offline or no API key) — only the "
            "CodeGuard rule sweep was applied. Logic/auth flaws may be missed.")
    if substrate.budget.remaining == 0 and hunt_ran:
        cov.gaps.append(
            "LLM budget was exhausted before all files were hunted; "
            "raise the budget for fuller exploratory coverage.")

    cov.done = cov.coverage_pct >= floor_pct
    substrate.metrics["coverage"] = cov.coverage_pct
    substrate.metrics["done"] = cov.done
    substrate.emit("COVERAGE-GUIDE",
                   f"coverage {cov.coverage_pct:.1f}% vs floor {floor_pct:.0f}% -> "
                   f"{'DONE' if cov.done else 'NOT DONE'}")
    return cov
