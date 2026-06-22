"""Foundry Constitution — runtime enforcement.

The full constitution (11 inviolable principles) ships verbatim as
`constitution.md` (CC-BY-4.0, © Cisco). This module turns two of those
principles from prose into mechanical gates the Orchestrator actually runs:

  Principle I  — Evidence Over Assertion:
      "A claim whose citations do not resolve is demoted, regardless of how
       confident the prose is." We verify every finding's cited line resolves
       to a real location in the indexed source; those that don't are demoted,
       no matter their confidence. This is what catches a hallucinated line
       number from the exploratory hunt.

  Principle II — Surface Only What Survives:
      "Humans see findings that have passed the gates. Everything else stays in
       the internal store." We assert the published report contains only gated
       survivors and record the internal-vs-surfaced split.

The remaining principles (III–XI) are documented in constitution.md but not
enforced by this demo (several govern multi-agent fleet behaviour that this
single-process build doesn't have). Principle IX — "Sandbox by infrastructure,
not by prompt" — is satisfied structurally: this engine never executes target
code, it only reads it.
"""

from __future__ import annotations

from typing import Dict, List

from .finding import Finding, State
from .indexer import Unit


def _norm(s: str) -> str:
    return "".join(s.split()).lower()


def enforce_evidence_over_assertion(findings: List[Finding],
                                    units: List[Unit]) -> Dict:
    """Principle I. Demote any finding whose citation does not mechanically
    resolve to the source. Returns an audit result."""
    by_file = {u.file: u.code.splitlines() for u in units}
    checked = 0
    demoted: List[Dict] = []

    for f in findings:
        if f.state in (State.REJECTED,):
            continue
        checked += 1
        lines = by_file.get(f.file)
        resolved = True
        reason = ""

        if lines is None:
            resolved, reason = False, "cited file not in index"
        elif not (1 <= f.line <= len(lines)):
            resolved, reason = False, f"line {f.line} outside file (1..{len(lines)})"
        elif f.snippet.strip():
            # snippet must appear within a small window of the cited line
            window = "".join(_norm(lines[i]) for i in
                             range(max(0, f.line - 3), min(len(lines), f.line + 2)))
            if _norm(f.snippet) not in window:
                resolved, reason = False, "snippet does not match cited location"

        if not resolved:
            f.state = State.REJECTED
            f.validation_note = f"Constitution I (Evidence Over Assertion): {reason}"
            f.stamp("CONSTITUTION", "demoted", f"Principle I: {reason}")
            demoted.append({"file": f.file, "line": f.line,
                            "title": f.title, "reason": reason})

    return {"principle": "I. Evidence Over Assertion",
            "checked": checked, "demoted": len(demoted), "violations": demoted}


def enforce_surface_only_what_survives(all_findings: List[Finding],
                                       surfaced: List[Finding]) -> Dict:
    """Principle II. The report must surface only gated survivors; everything
    else stays in the internal store. Returns the split and an ok flag."""
    internal = len(all_findings)
    surfaced_n = len(surfaced)
    leaked = [f for f in surfaced
              if f.state not in (State.CONFIRMED, State.REPORTED)]
    return {"principle": "II. Surface Only What Survives",
            "internal_store": internal, "surfaced": surfaced_n,
            "withheld": internal - surfaced_n,
            "ok": len(leaked) == 0,
            "leaked": [f"{f.file}:{f.line}" for f in leaked]}


ENFORCED = ["I. Evidence Over Assertion", "II. Surface Only What Survives"]
STRUCTURAL = ["IX. Sandbox By Infrastructure, Not By Prompt (read-only engine)"]
