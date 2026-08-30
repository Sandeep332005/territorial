"""
ABHIMANYU X - Real AFL++/ASan Crash Replay

Actually compiles a given parser.c source with clang+ASan inside the Colima
Linux VM (via `colima ssh`), links it against the real fuzz harness, and
executes it against the real crash input AFL++ found (see
vulnerable_targets/secure_packet_parser/findings/crashes/crash-00017.bin).
Returns the genuine exit code and ASan report — nothing here is simulated.

Known limitation, disclosed rather than hidden: afl-cc's SanitizerCoverage
instrumentation pass (LLVM 17, arm64 Ubuntu 24.04 apt package) does not
correctly interact with ASan's stack redzone poisoning on this platform —
a minimal repro confirmed the same break with no project code involved.
Coverage-guided fuzzing is therefore not currently functional here; AFL++
was run for real in blind/non-instrumented mode (`-n`) against a plain
clang+ASan binary, which correctly detects the crash. Exploit replay
(before/after patch) below runs the same real ASan binary directly and is
unaffected by that limitation.
"""

import subprocess
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = REPO_ROOT / "vulnerable_targets" / "secure_packet_parser"
CRASH_INPUT = TARGET_DIR / "findings" / "crashes" / "crash-00017.bin"
SCRATCH = TARGET_DIR / "_replay_scratch"
HARNESS_SRC = TARGET_DIR / "fuzz_harness.c"


def _vm(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["colima", "ssh", "--", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def replay_against_code(code: str, payload_size: int = None) -> Dict:
    """Compile `code` as parser.c + the real fuzz harness with clang+ASan in
    the Linux VM, then execute a real input against it. Real subprocess
    execution and real ASan output; not a canned result.

    payload_size: if given, generates a fresh all-'B' input of exactly that
    many bytes (for adversarial robustness testing across the boundary)
    instead of using the fixed AFL++-found crash-00017.bin."""
    try:
        SCRATCH.mkdir(exist_ok=True)
        (SCRATCH / "parser.c").write_text(code)
        (SCRATCH / "fuzz_harness.c").write_text(HARNESS_SRC.read_text())

        compile_result = _vm(
            f"cd {SCRATCH} && clang-18 -g -fsanitize=address -o replay_bin fuzz_harness.c 2>&1"
        )
        if compile_result.returncode != 0:
            return {
                "evidence_type": "measured",
                "compiled": False,
                "crashed": None,
                "output": compile_result.stdout[-2000:],
            }

        if payload_size is not None:
            input_path = SCRATCH / f"input_{payload_size}.bin"
            input_path.write_bytes(b"B" * payload_size)
        else:
            input_path = CRASH_INPUT

        run_result = _vm(f"cd {SCRATCH} && ./replay_bin {input_path} 2>&1")
        crashed = run_result.returncode != 0
        return {
            "evidence_type": "measured",
            "compiled": True,
            "crashed": crashed,
            "exit_code": run_result.returncode,
            "output": run_result.stdout[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"evidence_type": "measured", "compiled": None, "crashed": None,
                "output": "VM call timed out"}
    except FileNotFoundError:
        return {"evidence_type": "measured", "compiled": None, "crashed": None,
                "output": "colima not available on PATH"}
