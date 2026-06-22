"""Coordination substrate (Foundry Security Spec §coordination-substrate).

The spec's substrate is the shared layer every role reads and writes:
a work queue, a finding store, a sandbox, a budget, and a dashboard. This is a
lightweight, single-process version sized for a demo: an in-memory finding
store, a budget meter that bounds LLM spend, and a run log the UI renders as the
dashboard. Sandbox/isolation is out of scope here (we never execute target code
— we only read it), which is itself a safety guardrail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .finding import Finding


@dataclass
class Budget:
    """Bounds the run so a model can't spend without limit — the spec requires
    an economic stop condition, not just a coverage one."""
    max_llm_calls: int = 40
    used_llm_calls: int = 0

    def can_spend(self) -> bool:
        return self.used_llm_calls < self.max_llm_calls

    def spend(self, n: int = 1) -> None:
        self.used_llm_calls += n

    @property
    def remaining(self) -> int:
        return max(0, self.max_llm_calls - self.used_llm_calls)


@dataclass
class Substrate:
    budget: Budget = field(default_factory=Budget)
    findings: List[Finding] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    metrics: Dict[str, object] = field(default_factory=dict)

    def emit(self, role: str, msg: str) -> None:
        line = f"[{role}] {msg}"
        self.log.append(line)

    def add(self, f: Finding) -> None:
        self.findings.append(f)
