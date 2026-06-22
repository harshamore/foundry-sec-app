"""VALIDATOR role (Foundry Security Spec §5, finding pipeline).

The quality gate that separates Foundry from "toss a repo at the model." Each
triaged finding is checked against the actual code: confirmed (real, with a
reason) or rejected (false positive, with a reason). This is where the spec's
"false positives at scale" failure mode is contained.

LLM path: re-reads the cited code window and rules on each finding.
Offline path: applies an evidence gate plus a confidence floor, and confirms
rule-sourced findings (which already matched a concrete pattern) while holding
low-confidence exploratory findings to a higher bar.
"""

from __future__ import annotations

from typing import List

from .finding import Finding, State
from .indexer import Unit
from .llm import LLM
from .substrate import Substrate

VALIDATE_SYSTEM = (
    "You are the Validator role of a Foundry-spec security evaluation. For each "
    "candidate finding you are given the cited code window. Decide if it is a "
    "true vulnerability in this context. Reject false positives (e.g. a pattern "
    "in a comment, a test fixture, a safe usage). "
    "Return ONLY a JSON array, one object per input finding in the same order: "
    '{"verdict":"CONFIRMED|REJECTED","note":str}. No prose, no fences.'
)

CONF_FLOOR = 0.45


def _window(units_by_file, file, line, ctx=4):
    code = units_by_file.get(file)
    if not code:
        return ""
    lines = code.splitlines()
    lo = max(0, line - 1 - ctx)
    hi = min(len(lines), line + ctx)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))


def _validate_llm(substrate, findings, units_by_file, llm) -> bool:
    """Validate in one bounded batch call. Returns True if it ran."""
    if not (llm.available and substrate.budget.can_spend()):
        return False
    blocks = []
    for idx, f in enumerate(findings):
        blocks.append(
            f"[{idx}] {f.severity} {f.title} ({f.cwe}) at {f.file}:{f.line}\n"
            f"rationale: {f.rationale}\ncode:\n{_window(units_by_file, f.file, f.line)}")
    user = "Findings to validate:\n\n" + "\n\n---\n\n".join(blocks)
    raw = LLM.parse_json(llm.complete(substrate, VALIDATE_SYSTEM, user, max_tokens=3000))
    if not isinstance(raw, list):
        return False
    for f, v in zip(findings, raw):
        verdict = str(v.get("verdict", "")).upper()
        note = str(v.get("note", ""))[:300]
        f.validation_note = note
        if verdict == "REJECTED":
            f.state = State.REJECTED
            f.stamp("VALIDATOR", "rejected", note)
        else:
            f.state = State.CONFIRMED
            f.stamp("VALIDATOR", "confirmed", note)
    # any findings beyond the returned list: leave for heuristic gate below
    for f in findings[len(raw):]:
        _gate_one(f)
    return True


def _gate_one(f: Finding) -> None:
    if not f.evidence_ok():
        f.state = State.REJECTED
        f.validation_note = "dropped: missing evidence (file/line/rationale)"
        f.stamp("VALIDATOR", "rejected", "no evidence")
        return
    if f.source == "rule":
        f.state = State.CONFIRMED
        f.validation_note = "rule match on concrete pattern"
        f.stamp("VALIDATOR", "confirmed", "rule pattern")
    elif f.confidence >= CONF_FLOOR:
        f.state = State.CONFIRMED
        f.validation_note = f"exploratory finding above confidence floor ({f.confidence:.2f})"
        f.stamp("VALIDATOR", "confirmed", "confidence floor")
    else:
        f.state = State.REJECTED
        f.validation_note = f"below confidence floor ({f.confidence:.2f})"
        f.stamp("VALIDATOR", "rejected", "low confidence")


def run(substrate: Substrate, findings: List[Finding],
        units: List[Unit], llm: LLM) -> List[Finding]:
    units_by_file = {u.file: u.code for u in units}
    for f in findings:
        f.state = State.VALIDATED
        f.stamp("VALIDATOR", "validating")

    ran_llm = _validate_llm(substrate, findings, units_by_file, llm)
    if not ran_llm:
        for f in findings:
            _gate_one(f)

    confirmed = [f for f in findings if f.state == State.CONFIRMED]
    rejected = [f for f in findings if f.state == State.REJECTED]
    substrate.metrics["confirmed"] = len(confirmed)
    substrate.metrics["rejected"] = len(rejected)
    substrate.emit("VALIDATOR",
                   f"{len(confirmed)} confirmed, {len(rejected)} rejected "
                   f"({'llm' if ran_llm else 'heuristic'} gate)")
    return findings
