# ABHIMANYU X CORE

## An experimental vulnerability-scanning and auto-patching pipeline for Python and C

**Status: research prototype.** This finds real vulnerabilities, generates real patches via an LLM, and verifies them with genuine (not simulated) checks — but it is not validated for production or defence-classified environments, has no domain-specific hardening for any particular infrastructure, and every patch is meant to be human-reviewed before use, not auto-deployed.

---

## 🎯 Overview

ABHIMANYU X CORE discovers, patches, and verifies fixes for security vulnerabilities in Python and C source files, and remembers what it's seen so later scans can build on earlier ones. It combines:

- **REWIND Engine** — pattern/heuristic-based static analysis (Python + C)
- **Fuzz Engine** — randomized mutation-based dynamic testing
- **ANVIL Engine** — LLM-based patch generation, with a self-critique pass and retrieval from prior fixes
- **Verification Pipeline** — re-scan-based exploit checking, syntax/compile checks, and regression/behavior checks
- **Immune Memory** — a SQLite-backed record of vulnerabilities, patches, and their outcomes, used to recalibrate detection confidence over time
- **Watch Engine** — continuous file-change monitoring with regression detection

None of this involves a "reasoning" system in the DARPA Cyber-Grand-Challenge sense (no symbolic or concolic execution) — detection is regex/heuristic pattern matching, and the "reasoning" is confined to what the LLM does during patch generation.

## 🏗️ Architecture

```
ABHIMANYU X CORE
        │
        ▼
┌─────────────────────────────────────────┐
│         LLM Patch-Generation Layer      │
│   (local via Ollama, or a cloud API,    │
│    configurable — default: a small      │
│    local model, not a frontier model)   │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│      Vulnerability Discovery Layer      │
│  ┌─────────────┐    ┌───────────────┐  │
│  │   REWIND    │    │  FUZZ ENGINE  │  │
│  │  (Static)   │    │  (Dynamic)    │  │
│  └─────────────┘    └───────────────┘  │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           ANVIL Repair Cell             │
│      Root Cause Analysis                │
│      Patch Generation + Self-Critique   │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Verification Cell               │
│      Compile/Syntax Check               │
│      Differential Re-Scan (exploit)     │
│      Regression & Behavior Checks       │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│        Immune Memory Cell               │
│      Vulnerability + Capability Atoms   │
│      Fix Strategies                     │
│      Confidence Feedback Loop           │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│          Watch Engine (optional)        │
│      Polls for file changes             │
│      Flags new / resolved / regressed   │
└─────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd abhimanyux

# Install dependencies
pip install -r requirements.txt
```

### Usage

#### Command Line

```bash
# Scan a file
python -m abhimanyux.core.orchestrator <target-file>

# Scan a directory
python -m abhimanyux.core.orchestrator ./src/

# Continuously monitor a directory for new/regressed vulnerabilities
python -m abhimanyux.core.orchestrator ./src/ --watch

# Run API server
python -m abhimanyux.api.server
```

#### Python API

```python
from abhimanyux.core.orchestrator import AbhimanyuXCore
from abhimanyux.models.schemas import VulnType

# Initialize
sentinel = AbhimanyuXCore()

# Scan inline code
code = """
import os
def run(cmd):
    return os.popen(cmd).read()
"""
result = sentinel.scan_code(code, "test.py")

# Print report
sentinel.print_report(result)

# Search memory for similar vulnerabilities
similar = sentinel.search_similar(VulnType.COMMAND_INJECTION)
```

#### REST API

```bash
# Health check
curl http://localhost:8000/health

# Analyze code
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "import os; os.popen(input())", "filename": "test.py"}'

# Full scan
curl -X POST http://localhost:8000/api/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target_path": "./src/", "language": "python"}'

# Get memory stats
curl http://localhost:8000/api/memory/stats
```

### Docker

```bash
# Build image
docker build -t abhimanyux-core .

# Run container
docker run -p 8000:8000 -e DEEPSEEK_API_KEY=your_key abhimanyux-core
```

## 🔍 Components

### REWIND Engine (Static Analysis)

Pattern/heuristic detection — not a sound or complete analysis, and it will miss anything past straightforward pattern matching (obfuscated code, cross-file taint flows, indirection through variables). Two language paths:

- **Python**: regex patterns + AST-based checks (dangerous function calls)
- **C/C++**: regex patterns for one-line-detectable issues, plus function-body heuristics (a lightweight brace-matching splitter, not a real parser) for classes that need multi-line context

**Detected vulnerability types (Python):** SQL Injection, Command Injection, Path Traversal, Insecure Deserialization, SSRF, XSS, Hardcoded Credentials, Weak Crypto, Info Disclosure, Open Redirect

**Detected vulnerability types (C):** Buffer Overflow (strcpy/strcat/gets/sprintf), Format String, Command Injection, Use-After-Free, Memory Leak, Null Pointer Dereference, Integer Overflow, Path Traversal, Race Condition

A confidence-feedback loop (`evolve()`) recalibrates each rule's confidence score based on how often its findings actually led to a verified patch — a real signal, but a proxy: a low rate can mean the rule over-fires, or that the patch/verification stages struggled with that vuln class specifically, not necessarily that detection was wrong.

### Fuzz Engine (Dynamic Analysis)

Randomized mutation-based fuzzing — despite the name suggesting otherwise, mutation strategy selection is `random.choice` over a fixed set of generators (bit flipping, boundary values, format strings, SQL/command injection payloads, overflow strings), not model-driven. It does genuinely execute generated test scripts against the target and watch for crashes/hangs.

### ANVIL Engine (Patch Generation)

LLM-based patch generation:
- Root-cause analysis and patch generation via a configurable local or cloud LLM (default: a small local model via Ollama, not a frontier model — patch quality depends heavily on which model is actually configured)
- Retrieval-grounded generation: pulls the closest prior patch for the same vulnerability type from Immune Memory as an exemplar
- A bounded generator+judge self-critique pass before the patch goes to verification (improves output quality; does not eliminate the possibility of a bad patch)

### Verification Pipeline

Staged, evidence-based checks — an earlier failed stage skips the rest rather than letting them report on code that can't even compile:
- Compile/syntax check (AST for Python, a real compiler's `-fsyntax-only` for C, when one's available)
- Exploit verification via a **differential re-scan**: confirms REWIND's rule fires on the original code and no longer fires on the patch — not a real dynamic exploit attempt
- Regression check (Python: imports and runs the patched module; C: structural function-presence check only — does not compile-and-execute C as a smoke test, since running arbitrary AI-generated C would itself be a risk)
- Behavior-preservation check (AST diff for Python; function-set + size-delta heuristic for C)

### Immune Memory

A SQLite-backed record, not just a log:
- Stores every vulnerability, patch, and verification outcome
- Builds "capability atoms" per vulnerability type — an exploit precondition and a capability grant, plus links between atoms that share exploit context (e.g. two different vuln classes found in the same function)
- Feeds verified-outcome rates back into REWIND's confidence scores

### Watch Engine

Polls a directory for file changes (mtime + content hash) and re-scans what changed, distinguishing a brand-new finding from a **regression** — a vulnerability that previously had a verified fix and has now reappeared (e.g. via a revert). This is file/content-change monitoring, not OS-level runtime introspection — no process hooks, no live memory inspection of a running system.

## 📊 Metrics

| Metric | Description |
|--------|-------------|
| Vulnerabilities Found | Total vulnerabilities discovered |
| Patches Generated | LLM-generated candidate patches |
| Patches Verified | Patches that pass every verification stage |
| Memory Records | Stored vulnerability/patch/outcome records |
| Rule Confidence | Per-rule confidence, recalibrated from verified-patch history |

There is no measured detection-accuracy figure (precision/recall against a labeled corpus) — this has only been exercised against the bundled `vulnerable_targets/` fixtures and hand-written test cases, not a real-world codebase at scale.

## 🧪 Testing

```bash
# Run unit tests
pytest abhimanyux/tests/ -v

# Run with coverage
pytest abhimanyux/tests/ --cov=abhimanyux --cov-report=html
```

52 tests currently pass, covering REWIND's Python and C rules, the confidence feedback loop, ANVIL's retrieval-grounding, the Verifier's differential exploit-replay (including a regression test guarding against silently accepting a no-op patch), Immune Memory's capability-atom linking, and the Watch engine's event transitions.

## 📁 Project Structure

```
abhimanyux/
├── core/                  # Main orchestrator
│   └── orchestrator.py
├── rewind/                # Static analysis engine (Python + C)
│   └── engine.py
├── fuzzer/                # Dynamic analysis engine
│   └── engine.py
├── anvil/                 # Patch generation engine
│   └── engine.py
├── verifier/              # Verification pipeline
│   └── engine.py
├── memory/                # Immune memory store
│   └── store.py
├── watch/                 # Continuous file-change monitoring
│   └── engine.py
├── models/                # Data models
│   └── schemas.py
├── api/                   # FastAPI backend
│   └── server.py
├── vulnerable_targets/    # Test vulnerable code
│   ├── web_app.py
│   └── vulnerable.c
├── tests/                 # Unit tests
│   └── test_abhimanyux.py
├── Dockerfile
├── requirements.txt
└── README.md
```

## 🔧 Configuration

### LLM Configuration

```python
from abhimanyux.anvil.engine import ANVILEngine, LLMConfig

config = LLMConfig(
    provider="deepseek",      # local, deepseek, gemini, claude
    model="deepseek-chat",
    api_url="https://api.deepseek.com/v1/chat/completions",
    temperature=0.2,
    use_local=False
)

sentinel = AbhimanyuXCore(llm_config=config)
```

### Environment Variables

```bash
# For cloud LLM
DEEPSEEK_API_KEY=your_api_key

# Optional: Custom API URL
DEEPSEEK_API_URL=https://api.deepseek.com/v1/chat/completions
```

## 🎯 Demo Scenario

1. **Introduce Vulnerable Code**
```python
# vulnerable_app.py
import os
def run_command(cmd):
    return os.popen(cmd).read()
```

2. **Run ABHIMANYU X**
```bash
python -m abhimanyux.core.orchestrator vulnerable_app.py
```

3. **Output** (this exact flow — detect → patch → verify — has been run and confirmed end-to-end)
```
ABHIMANYU X CORE - SECURITY SCAN REPORT
========================================

VULNERABILITIES FOUND
---------------------
1. [CRITICAL] Command Injection - os.popen
   Type: command_injection
   Location: vulnerable_app.py:2

GENERATED PATCHES
-----------------
Patch: patch-0001
Status: generated
Explanation: Use subprocess.run() with list arguments...

VERIFICATION RESULTS
--------------------
Patch: patch-0001
  Compile: ✓
  Exploit Blocked: ✓
  Regression: ✓
  Behavior: ✓
  All Tests: ✓
```

4. **Query Memory**
```python
# Find similar vulnerabilities
similar = sentinel.search_similar(VulnType.COMMAND_INJECTION)

# Get fix strategies
strategies = sentinel.get_fix_strategies(VulnType.COMMAND_INJECTION)
```

## Known limitations

- **Detection is heuristic, not sound.** REWIND is regex/pattern-based; it will miss vulnerabilities that don't match its rules, and its C-language function splitter assumes conventional formatting rather than actually parsing C.
- **Patch quality depends on the configured LLM.** No patch is guaranteed correct; the self-critique pass improves but does not guarantee output quality.
- **No human-free deployment path.** Patches are generated and verified, not auto-applied to a live system.
- **C verification is weaker than Python's.** Regression/behavior checks for C are structural (function presence, size deltas) rather than actual compile-and-run smoke tests, since executing arbitrary AI-generated C automatically would itself be a risk.
- **Not validated at scale.** Testing so far is against small bundled fixtures and unit tests, not a real production codebase.
- **No defence/military-specific features.** No ICS/SCADA protocol awareness, classification handling, air-gap hardening, or compliance-framework alignment — it's a general-purpose Python/C scanner.

## 🚧 Future Expansion (unbuilt)

- **PULSEMESH** — runtime protection
- **ORACLE** — threat prediction
- **Multi-language** — JavaScript, Go, Rust support
- **Real C dynamic verification** — sandboxed compile-and-execute regression testing

## 📝 License

MIT License - See LICENSE file for details
