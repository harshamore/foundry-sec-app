"""DETECTOR role (Foundry Security Spec §5.4, finding pipeline).

Two complementary detection strategies, exactly as the spec describes:

  1. Rule sweep  — the CodeGuard corpus runs over every unit. Systematic,
     repeatable, finds the known classes. Always on.
  2. Exploratory hunt — an LLM agent reasons over the Cartographer's hotspots,
     looking for what no rule describes yet. Bounded by the budget.

When the hunt confirms something the rules missed, that is a *rule gap* — the
seed of the detection-to-prevention flywheel. We flag those so the Self-Improver
extension role (not built here) could later generalise them into new rules.
"""

from __future__ import annotations

import os
import re
from typing import List

from .cartographer import SurfaceMap
from .finding import Finding
from .indexer import Unit
from .llm import LLM
from .substrate import Substrate

MAX_PER_UNIT = 25

# Offline heuristic sweep — (regex, title, severity, cwe, rule_id, rationale).
# rule_id cites the REAL CodeGuard core rule file (rules/core/<id>.md) whose
# class this pattern belongs to, so offline attribution points at the genuine
# corpus rather than an invented id.
RULES = [
    (r"(api[_-]?key|secret|token|passwd|password)\s*=\s*['\"][A-Za-z0-9\-_/+]{8,}['\"]",
     "Hardcoded credential", "CRITICAL", "CWE-798", "codeguard-1-hardcoded-credentials",
     "A secret is embedded in source; move it to a secrets manager or env var."),
    (r"shell\s*=\s*True", "subprocess with shell=True", "HIGH", "CWE-78",
     "codeguard-0-input-validation-injection",
     "shell=True allows command injection if any argument is attacker-influenced."),
    (r"os\.system\s*\(|os\.popen\s*\(", "os.system / os.popen call", "HIGH", "CWE-78",
     "codeguard-0-input-validation-injection",
     "Passing a built string to a shell enables command injection."),
    (r"\.execute\s*\(\s*f['\"]|\.execute\s*\(\s*['\"].*%s.*['\"]\s*%|\.execute\([^)]*\+",
     "SQL built by string concatenation", "CRITICAL", "CWE-89",
     "codeguard-0-input-validation-injection",
     "SQL assembled from strings is injectable; use bound parameters."),
    (r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(", "Weak hash (MD5/SHA-1)", "MEDIUM",
     "CWE-327", "codeguard-1-crypto-algorithms",
     "MD5/SHA-1 are broken for security use; use SHA-256+ or a password KDF."),
    (r"pickle\.loads?\s*\(", "Insecure deserialization (pickle)", "HIGH", "CWE-502",
     "codeguard-0-xml-and-serialization",
     "pickle executes arbitrary code on load; never unpickle untrusted data."),
    (r"yaml\.load\s*\((?!.*Loader)", "Unsafe yaml.load", "HIGH", "CWE-502",
     "codeguard-0-xml-and-serialization",
     "yaml.load without SafeLoader can instantiate arbitrary objects."),
    (r"requests\.(get|post)\s*\(\s*[a-zA-Z_][\w\.]*\s*[,)]", "Possible SSRF",
     "HIGH", "CWE-918", "codeguard-0-input-validation-injection",
     "Outbound request to a variable URL with no allowlist; attacker can pivot internally."),
    (r"(logging|logger|log|print)\b.*\b(ssn|card|cvv|password|passwd|secret|token)\b",
     "Sensitive data in logs", "HIGH", "CWE-532", "codeguard-0-logging",
     "PII/secrets written to logs in plaintext; redact or omit before logging."),
    (r"eval\s*\(|exec\s*\(", "Dynamic eval/exec", "HIGH", "CWE-95",
     "codeguard-0-input-validation-injection",
     "eval/exec on any non-constant input is remote code execution."),
    (r"debug\s*=\s*True", "Debug mode enabled", "MEDIUM", "CWE-489",
     "codeguard-0-framework-and-languages",
     "debug=True exposes a console (RCE) and stack traces in production."),
    (r"verify\s*=\s*False", "TLS verification disabled", "HIGH", "CWE-295",
     "codeguard-1-digital-certificates",
     "Disabling certificate verification allows man-in-the-middle attacks."),
]

HUNT_SYSTEM = (
    "You are the Detector role of a Foundry-spec security evaluation, running the "
    "exploratory hunt that complements the rule sweep. Find vulnerabilities that "
    "simple pattern rules would miss: logic flaws, broken auth/access control, "
    "injection through indirect data flow, unsafe defaults.\n"
    "Rules of engagement: only report what you can tie to a specific line in the "
    "supplied code; do not invent line numbers; prefer precision over recall.\n"
    "Return ONLY a JSON array (no prose, no fences). Each element: "
    '{"title":str,"severity":"CRITICAL|HIGH|MEDIUM|LOW","line":int,'
    '"cwe":"CWE-###","rationale":str,"snippet":str,"confidence":0.0-1.0}. '
    "Empty array if nothing."
)


def _walk_rule_files(rules_path: str):
    """Yield every rule markdown file under rules_path (recursively), so the real
    CodeGuard corpus in rules/core/ is picked up."""
    if os.path.isfile(rules_path):
        yield rules_path
        return
    for root, _dirs, files in os.walk(rules_path):
        for f in sorted(files):
            if f.endswith((".md", ".txt", ".yaml", ".yml")) \
                    and not f.endswith("LICENSE.md"):
                yield os.path.join(root, f)


def load_rules_index(rules_path: str) -> str:
    """Compact index of the real corpus: one line per rule (id + description).
    Fed to the exploratory hunt so it knows what the sweep already covers and
    can focus on gaps — without injecting ~100 KB of rule text per call."""
    lines = []
    for path in _walk_rule_files(rules_path):
        rid = os.path.splitext(os.path.basename(path))[0]
        desc = ""
        try:
            for ln in open(path, encoding="utf-8", errors="replace"):
                if ln.startswith("description:"):
                    desc = ln.split("description:", 1)[1].strip().strip("'\"")
                    break
        except OSError:
            pass
        lines.append(f"- {rid}: {desc}" if desc else f"- {rid}")
    return "\n".join(lines)


def load_rules_text(rules_path: str) -> str:
    return "\n\n".join(open(p, encoding="utf-8", errors="replace").read()
                       for p in _walk_rule_files(rules_path))


def _sweep_unit(unit: Unit) -> List[Finding]:
    out: List[Finding] = []
    for i, ln in enumerate(unit.code.splitlines(), start=1):
        s = ln.lstrip()
        if s.startswith("#") or s.startswith("//"):
            continue
        for pat, title, sev, cwe, rid, why in RULES:
            if re.search(pat, ln, re.I):
                f = Finding(title=title, severity=sev, file=unit.file, line=i,
                            cwe=cwe, rule_id=rid, rationale=why,
                            snippet=ln.strip()[:200], source="rule",
                            detector="heuristic", confidence=0.7)
                f.stamp("DETECTOR", "rule-sweep", rid)
                out.append(f)
                if len(out) >= MAX_PER_UNIT:
                    return out
    return out


def _hunt_unit(substrate: Substrate, unit: Unit, llm: LLM,
               rule_index: str) -> List[Finding]:
    numbered = "\n".join(f"{i+1}: {l}" for i, l in enumerate(unit.code.splitlines()))
    user = (f"CodeGuard rule classes already swept (find what these MISS — logic, "
            f"auth, indirect data flow):\n{rule_index}\n\n"
            f"File: {unit.file}\n{numbered}\n\nReturn the JSON array.")
    raw = LLM.parse_json(llm.complete(substrate, HUNT_SYSTEM, user, max_tokens=2500))
    out: List[Finding] = []
    if not isinstance(raw, list):
        return out
    for r in raw[:MAX_PER_UNIT]:
        try:
            f = Finding(
                title=str(r["title"]), severity=str(r["severity"]).upper(),
                file=unit.file, line=int(r["line"]), cwe=str(r.get("cwe", "")),
                rule_id="EXPLORE", rationale=str(r.get("rationale", "")),
                snippet=str(r.get("snippet", ""))[:200], source="explore",
                detector="llm", confidence=float(r.get("confidence", 0.5)))
            f.stamp("DETECTOR", "explore-hunt", "agent")
            out.append(f)
        except (KeyError, ValueError, TypeError):
            continue
    return out


def run(substrate: Substrate, units: List[Unit], smap: SurfaceMap,
        llm: LLM, rules_path: str) -> List[Finding]:
    findings: List[Finding] = []

    # 1) rule sweep over everything
    for u in units:
        findings.extend(_sweep_unit(u))
    swept = len(findings)
    n_rules = sum(1 for _ in _walk_rule_files(rules_path))
    substrate.emit("DETECTOR",
                   f"rule sweep ({n_rules} CodeGuard rule files): {swept} candidate(s)")

    # 2) exploratory hunt over hotspots first, then remaining files, within budget
    if llm.available:
        rule_index = load_rules_index(rules_path)
        order = sorted(units, key=lambda u: (u.file not in smap.hotspots, u.file))
        hunted = 0
        for u in order:
            if not substrate.budget.can_spend():
                substrate.emit("DETECTOR", "explore-hunt stopped: budget exhausted")
                break
            findings.extend(_hunt_unit(substrate, u, llm, rule_index))
            hunted += 1
        substrate.emit("DETECTOR", f"explore hunt: {hunted} file(s) examined")
    else:
        substrate.emit("DETECTOR", "explore-hunt skipped (offline / no key)")

    for f in findings:
        substrate.add(f)
    substrate.metrics["detected"] = len(findings)
    return findings
