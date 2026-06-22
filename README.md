# Foundry Security Spec — Reference Implementation (Streamlit)

A deployable Streamlit app that implements the **eight core roles** of the
[Cisco Foundry Security Spec](https://github.com/CiscoDevNet/foundry-security-spec).
Paste a public GitHub repo URL; the app runs an agentic code assessment over it
and returns a **bounded, prioritised, auditable** set of findings with a
coverage/"done" signal.

> **Scope honesty — say this in the room.** Cisco published a *specification*,
> not a scanner, and was explicit that it is "a starting point, not a ready-made
> scanner." Their internal implementation is bound to Cisco infrastructure and
> was deliberately **not** open-sourced. This app is therefore a **demo-grade
> reference implementation** of the spec's role model — *not* an official Cisco
> product, and *not* the full ~130 functional requirements or the five extension
> roles. It reads source only (never executes target code) and is built for
> enablement and BFSI demos. CodeGuard is a separate CoSAI/OASIS open project
> that supplies the Detector's rules.

---

## The eight roles (all implemented)

```
INDEXER → CARTOGRAPHER → DETECTOR → TRIAGER → VALIDATOR → COVERAGE-GUIDE → REPORTER
                                 (ORCHESTRATOR drives all + owns budget & done signal)
```

| Role | What it does here | File |
|------|-------------------|------|
| **Orchestrator** | sequences roles, holds the budget, emits the done signal | `foundry/orchestrator.py` |
| **Indexer** | walks the repo into line-numbered units (knowledge layer) | `foundry/indexer.py` |
| **Cartographer** | maps attack surface: entry points, sinks, hotspots (+LLM read) | `foundry/cartographer.py` |
| **Detector** | CodeGuard rule sweep over everything **+** LLM exploratory hunt | `foundry/detector.py` |
| **Triager** | dedupes, normalises severity, assigns priority | `foundry/triager.py` |
| **Validator** | confirms/refutes each finding to kill false positives (quality gate) | `foundry/validator.py` |
| **Coverage-Guide** | coverage % + done verdict vs operator floor; lists gaps | `foundry/coverage_guide.py` |
| **Reporter** | publishes confirmed findings with full provenance + rule gaps | `foundry/reporter.py` |

Supporting: `foundry/finding.py` (lifecycle + provenance), `foundry/substrate.py`
(finding store + budget = the spec's coordination substrate, lightweight),
`foundry/ingest.py` (GitHub tarball fetch), `foundry/llm.py` (Anthropic wrapper).

The spec's four required outcomes are all visible in the UI: a **bounded,
prioritised** finding list; a **done signal** against a coverage floor; an
**auditable provenance chain** per finding (detected→triaged→validated→reported);
and **safety guardrails** (read-only, no code execution, budget cap).

### Two detection modes

- **Offline** (no API key): CodeGuard rule sweep + heuristic validation. Free,
  fast, deterministic. Coverage caps at ~60% by design — the app refuses to
  claim "done" on a rule sweep alone.
- **Live** (with an Anthropic API key): adds the Cartographer's architectural
  read, the Detector's **exploratory hunt** (finds logic/auth flaws no rule
  describes), and LLM **validation**. Exploratory findings with no matching rule
  are surfaced as **rule gaps** — the seed of the detection→prevention flywheel.

---

## Run locally (MacBook)

```bash
brew install python                 # if needed
cd foundry-sec-app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# offline (no key): tick "Use bundled sample" in the UI to see planted vulns
streamlit run streamlit_app.py
```

To enable the LLM roles locally, either paste the key in the sidebar, or:

```bash
mkdir -p .streamlit
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# edit secrets.toml and put your key in
```

> The Anthropic API key (console.anthropic.com) is **billed separately** from
> any Claude.ai Pro/Max subscription.

---

## Deploy to Streamlit Community Cloud

Streamlit Cloud runs your app straight from a GitHub repo.

**1. Push this folder to a GitHub repo**

```bash
cd foundry-sec-app
git init && git add . && git commit -m "Foundry Security Spec reference impl"
git branch -M main
git remote add origin https://github.com/<you>/foundry-sec-app.git
git push -u origin main
```

(`.gitignore` already excludes `.streamlit/secrets.toml`, so your key never gets
committed.)

**2. Create the app**

1. Go to <https://share.streamlit.io> and sign in with GitHub.
2. **New app → From existing repo.**
3. Repository: `<you>/foundry-sec-app` · Branch: `main` · Main file path:
   `streamlit_app.py`.

**3. Add your API key as a secret**

In **Advanced settings → Secrets** (or later, App → Settings → Secrets), paste:

```toml
ANTHROPIC_API_KEY = "sk-ant-..."
```

The app reads it via `st.secrets` and shows "API key loaded from secrets". If
you skip this, the app still deploys and runs in offline mode.

**4. Deploy.** First boot installs `requirements.txt` (~1–2 min). You get a
public `https://<app>.streamlit.app` URL.

### Notes for live use
- Public repos work with no GitHub token. For private repos or to avoid the
  unauthenticated 60-req/hr rate limit, paste a GitHub token in the sidebar.
- Ingestion is capped (60 files / 200 KB per file) so a monorepo can't stall a
  demo; the Coverage-Guide reports exactly what was and wasn't assessed.
- The LLM budget slider hard-caps spend per run.

---

## Bundled real artifacts (CC-BY-4.0)

This app ships two genuine upstream artifacts verbatim, not stand-ins:

- **`rules/core/`** — the **official Project CodeGuard core rules** (23 files)
  from [cosai-oasis/project-codeguard](https://github.com/cosai-oasis/project-codeguard).
  The Detector's rule sweep cites these real rule files (e.g.
  `codeguard-1-hardcoded-credentials`), and the exploratory hunt is given a
  compact index of them so it targets the gaps the sweep can't reach. License:
  `rules/CODEGUARD-LICENSE.md`.
- **`constitution.md`** — the **Foundry Constitution** (11 inviolable principles)
  from [CiscoDevNet/foundry-security-spec](https://github.com/CiscoDevNet/foundry-security-spec).
  License: `FOUNDRY-LICENSE`. Attribution for both: `NOTICE.md`.

### Constitution principles enforced at runtime (`foundry/constitution.py`)

Two principles are turned from prose into mechanical gates the Orchestrator runs:

- **Principle I — Evidence Over Assertion.** Every finding's cited line is
  mechanically verified against the indexed source; any whose citation doesn't
  resolve (line out of range, snippet mismatch, file not indexed) is **demoted,
  regardless of confidence**. This is the gate that catches a hallucinated
  citation from the LLM hunt — see the **Constitution** tab in the UI.
- **Principle II — Surface Only What Survives.** The report is asserted to carry
  only gated survivors; the internal-vs-surfaced split is recorded.

**Principle IX — Sandbox by infrastructure, not by prompt** is satisfied
structurally: the engine only reads source, never executes target code.
Principles III–VIII, X, XI are documented in `constitution.md` but not enforced
by this single-process demo (several govern multi-agent fleet behaviour).

## What this is **not**

- Not Cisco's internal system, and not a complete implementation of the spec.
- The five **extension roles** (Deep-Tester, Variant-Hunter, Attack-Mapper,
  Remediator, Self-Improver) are **not** built — they're "build after core
  works" in the spec. The Self-Improver is where rule-gap → new-rule would close.
- No sandboxed dynamic analysis; this is static, read-only review.

Use it to demonstrate the *shape* the spec defines — roles, finding lifecycle,
coverage discipline, auditable provenance — which is exactly what Cisco says
transfers.
