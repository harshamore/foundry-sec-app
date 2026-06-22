"""Finding model + lifecycle (Foundry Security Spec §finding-lifecycle).

A finding flows through the spec's pipeline:

    DETECTED -> TRIAGED -> VALIDATED -> (CONFIRMED | REJECTED) -> REPORTED

Each role stamps the provenance chain, so the final report carries an auditable
trail from detection through triage, validation, and publication — one of the
four outcomes the spec is designed to deliver.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
import hashlib


class State(str, Enum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    REPORTED = "REPORTED"


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class ProvenanceEvent:
    role: str
    action: str
    detail: str = ""
    ts: str = field(default_factory=lambda:
                    datetime.now(timezone.utc).isoformat(timespec="seconds"))


@dataclass
class Finding:
    title: str
    severity: str
    file: str
    line: int
    cwe: str
    rule_id: str            # CodeGuard rule id, or "EXPLORE" for agent-found
    rationale: str
    snippet: str = ""
    source: str = "rule"    # "rule" (sweep) | "explore" (agent hunt)
    detector: str = "heuristic"  # "heuristic" | "llm"
    confidence: float = 0.5
    priority: int = 0       # set by Triager
    validation_note: str = ""
    state: State = State.DETECTED
    provenance: List[ProvenanceEvent] = field(default_factory=list)

    # ---- lifecycle helpers -------------------------------------------------
    def stamp(self, role: str, action: str, detail: str = "") -> None:
        self.provenance.append(ProvenanceEvent(role, action, detail))

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup: file + line + rule + title."""
        h = hashlib.sha1(f"{self.file}:{self.line}:{self.rule_id}:{self.title}"
                         .encode()).hexdigest()[:12]
        return h

    def evidence_ok(self) -> bool:
        return bool(self.file) and isinstance(self.line, int) and self.line >= 1 \
            and bool(self.rationale.strip())

    def sort_key(self):
        return (-self.priority,
                SEVERITY_ORDER.get(self.severity.upper(), 99),
                self.file, self.line)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        d["fingerprint"] = self.fingerprint
        return d
