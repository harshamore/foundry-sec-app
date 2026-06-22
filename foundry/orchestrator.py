"""ORCHESTRATOR role (Foundry Security Spec §5, lifecycle).

Owns the run: sequences the eight core roles, enforces the finding lifecycle,
holds the budget, and produces the final report with its done signal. The order
mirrors the spec's data flow:

    INDEXER -> CARTOGRAPHER -> DETECTOR -> TRIAGER -> VALIDATOR
            -> COVERAGE-GUIDE -> REPORTER

`progress` is an optional callback(stage_name, fraction) so a UI can render the
lifecycle as it runs.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from . import (cartographer, constitution, coverage_guide, detector, indexer,
               reporter, triager, validator)
from .ingest import SourceFile
from .finding import State
from .llm import LLM, DEFAULT_MODEL
from .substrate import Budget, Substrate

STAGES = ["Indexer", "Cartographer", "Detector", "Triager",
          "Validator", "Coverage-Guide", "Reporter"]


def assess(files: List[SourceFile], meta: dict, *,
           api_key: Optional[str] = None,
           model: str = DEFAULT_MODEL,
           offline: bool = False,
           max_llm_calls: int = 40,
           coverage_floor: float = 80.0,
           rules_path: str = "rules",
           progress: Optional[Callable[[str, float], None]] = None) -> dict:

    def tick(stage: str):
        if progress:
            progress(stage, (STAGES.index(stage) + 1) / len(STAGES))

    substrate = Substrate(budget=Budget(max_llm_calls=max_llm_calls))
    llm = LLM(model=model, api_key=None if offline else api_key)
    if offline:
        substrate.emit("ORCHESTRATOR", "offline mode: rule sweep only, no LLM roles")
    elif not llm.available:
        substrate.emit("ORCHESTRATOR",
                       "no usable API key: degrading to offline rule sweep")
        offline = True
    substrate.emit("ORCHESTRATOR",
                   f"run start | model={model if not offline else 'none'} "
                   f"| budget={max_llm_calls} calls | floor={coverage_floor:.0f}%")
    substrate.emit("CONSTITUTION",
                   "Principle IX (Sandbox by infrastructure): engine reads source "
                   "only, never executes target code")

    units = indexer.run(substrate, files);                       tick("Indexer")
    smap = cartographer.run(substrate, units, llm);              tick("Cartographer")
    detected = detector.run(substrate, units, smap, llm, rules_path); tick("Detector")
    triaged = triager.run(substrate, detected, smap);            tick("Triager")
    validated = validator.run(substrate, triaged, units, llm)

    # Constitution Principle I — Evidence Over Assertion: demote any finding
    # whose citation does not mechanically resolve, regardless of confidence.
    p1 = constitution.enforce_evidence_over_assertion(validated, units)
    substrate.emit("CONSTITUTION",
                   f"Principle I: checked {p1['checked']}, demoted {p1['demoted']} "
                   f"(unresolved citations)")
    tick("Validator")

    hunt_ran = (not offline) and llm.available
    cov = coverage_guide.run(substrate, units, validated, meta,
                             coverage_floor, hunt_ran);           tick("Coverage-Guide")
    report = reporter.run(substrate, validated, cov, meta, model, offline)

    # Constitution Principle II — Surface Only What Survives: the report must
    # carry only gated survivors; everything else stays in the internal store.
    surfaced = [f for f in validated if f.state == State.REPORTED]
    p2 = constitution.enforce_surface_only_what_survives(validated, surfaced)
    substrate.emit("CONSTITUTION",
                   f"Principle II: {p2['surfaced']} surfaced, {p2['withheld']} "
                   f"withheld in internal store (ok={p2['ok']})")
    report["constitution"] = {
        "enforced": constitution.ENFORCED,
        "structural": constitution.STRUCTURAL,
        "principle_I": p1,
        "principle_II": p2,
    }
    tick("Reporter")

    substrate.emit("ORCHESTRATOR",
                   f"run complete | {report['summary']['total_confirmed']} confirmed "
                   f"| coverage {cov.coverage_pct:.1f}% | done={cov.done}")
    report["summary"]["stages"] = STAGES
    return report
