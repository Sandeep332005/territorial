# ABHIMANYU X CORE

## Autonomous Cyber Reasoning & Software Immunization System for Defence Infrastructure

**The First Cell of an Autonomous Cyber Immune System**

---

## 🎯 Overview

ABHIMANYU X CORE is a lightweight autonomous cyber-reasoning system that discovers, repairs, verifies, and remembers security vulnerabilities in software. Inspired by biological immunity, it combines:

- **REWIND Engine** - Static analysis & vulnerability detection
- **Fuzz Engine** - AI-guided dynamic analysis
- **ANVIL Engine** - LLM-based patch generation
- **Verification Pipeline** - Evidence-based proof of fixes
- **Immune Memory** - Vulnerability knowledge base & learning

## 🏗️ Architecture

```
ABHIMANYU X CORE
        │
        ▼
┌─────────────────────────────────────────┐
│           AI Reasoning Layer            │
│     (DeepSeek-Coder / Qwen-Coder)      │
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
│      Patch Generation                   │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Verification Cell               │
│      Build Verification                 │
│      Exploit Replay                     │
│      Regression Testing                 │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│        Immune Memory Cell               │
│      Vulnerability Patterns             │
│      Fix Strategies                     │
│      Regression Seeds                   │
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

Detects vulnerabilities through:
- Pattern matching (regex-based)
- AST analysis (Python)
- Known vulnerability signatures

**Supported vulnerability types:**
- SQL Injection
- Command Injection
- Path Traversal
- Insecure Deserialization
- SSRF
- XSS
- Hardcoded Credentials
- And more...

### Fuzz Engine (Dynamic Analysis)

AI-guided fuzzing with mutation strategies:
- Bit flipping
- Boundary values
- Format strings
- SQL injection payloads
- Command injection payloads
- Overflow strings

### ANVIL Engine (Patch Generation)

LLM-based patch generation that:
- Analyzes root cause
- Generates minimal patches
- Explains the fix
- Uses local or cloud LLM

### Verification Pipeline

Evidence-based patch verification:
- Syntax validation
- Exploit replay
- Regression testing
- Behavior preservation

### Immune Memory

Vulnerability knowledge base:
- Stores vulnerability patterns
- Creates DNA signatures
- Tracks fix strategies
- Learns from each incident

## 📊 Metrics

| Metric | Description |
|--------|-------------|
| Vulnerabilities Found | Total vulnerabilities discovered |
| Patches Generated | AI-generated security patches |
| Patches Verified | Patches that pass all verification |
| Memory Records | Stored vulnerability patterns |
| Detection Accuracy | True positives / total detections |

## 🧪 Testing

```bash
# Run unit tests
pytest abhimanyux/tests/ -v

# Run with coverage
pytest abhimanyux/tests/ --cov=abhimanyux --cov-report=html
```

## 📁 Project Structure

```
abhimanyux/
├── core/                  # Main orchestrator
│   └── orchestrator.py
├── rewind/                # Static analysis engine
│   └── engine.py
├── fuzzer/                # Dynamic analysis engine
│   └── engine.py
├── anvil/                 # Patch generation engine
│   └── engine.py
├── verifier/              # Verification pipeline
│   └── engine.py
├── memory/                # Immune memory store
│   └── store.py
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
    provider="deepseek",      # deepseek, ollama, vllm
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

3. **Output**
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

## 🚧 Future Expansion

- **PULSEMESH** - Runtime protection
- **ORACLE** - Threat prediction
- **Evolution Engine** - Adaptive improvement
- **C/C++ Support** - Enhanced fuzzing with AFL++/libFuzzer
- **Multi-language** - JavaScript, Go, Rust support

## 📝 License

MIT License - See LICENSE file for details

---

**"The first lightweight cyber immune cell that not only finds vulnerabilities but learns from every verified repair."**
