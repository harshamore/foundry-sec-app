"""INDEXER role (Foundry Security Spec §5, knowledge layer).

Enumerates the units the rest of the pipeline reasons over. One unit per source
file, with line numbers preserved so every downstream finding cites a real
location. Builds the inventory the Coverage-Guide later measures completion
against.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .ingest import SourceFile
from .substrate import Substrate


@dataclass
class Unit:
    file: str
    code: str
    lines: int


def run(substrate: Substrate, files: List[SourceFile]) -> List[Unit]:
    units = [Unit(file=f.path, code=f.code, lines=f.code.count("\n") + 1)
             for f in files]
    total_lines = sum(u.lines for u in units)
    substrate.metrics["units"] = len(units)
    substrate.metrics["lines"] = total_lines
    substrate.emit("INDEXER", f"{len(units)} unit(s), {total_lines} line(s) indexed")
    return units
