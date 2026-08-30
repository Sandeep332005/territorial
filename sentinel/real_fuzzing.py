"""
ABHIMANYU X - Real AFL++/ASan Crash Replay

Actually compiles a given C source with clang+ASan inside the Colima Linux
VM (via `colima ssh`), links it against the real fuzz harness for that
target, and executes it against a real AFL++-found crash input. Returns the
genuine exit code and ASan report — nothing here is simulated.

Known limitation, disclosed rather than hidden: afl-cc's SanitizerCoverage
instrumentation pass (LLVM 17, arm64 Ubuntu 24.04 apt package) does not
correctly interact with ASan's stack redzone poisoning on this platform —
a minimal repro confirmed the same break with no project code involved.
Coverage-guided fuzzing is therefore not currently functional here; AFL++
was run for real in blind/non-instrumented mode (`-n`) against a plain
clang+ASan binary, which correctly detects the crash. Exploit replay
(before/after patch) below runs the same real ASan binary directly and is
unaffected by that limitation.

Two real targets are registered: secure_packet_parser (parser.c) and
network_protocol_parser (frame.c) — each has its own real 2-commit git
history, fuzz harness, and AFL++-found crash input.
"""

import subprocess
from pathlib import Path
from typing import Dict, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS_ROOT = REPO_ROOT / "vulnerable_targets"

TARGETS = {
    "secure_packet_parser": {
        "dir": TARGETS_ROOT / "secure_packet_parser",
        "source_filename": "parser.c",
        "crash_input": TARGETS_ROOT / "secure_packet_parser" / "findings" / "crashes" / "crash-00017.bin",
    },
    "network_protocol_parser": {
        "dir": TARGETS_ROOT / "network_protocol_parser",
        "source_filename": "frame.c",
        "crash_input": TARGETS_ROOT / "network_protocol_parser" / "findings" / "crashes" / "crash-frame-01.bin",
    },
}

# Preserved for existing call sites that don't pass target=
TARGET_DIR = TARGETS["secure_packet_parser"]["dir"]
CRASH_INPUT = TARGETS["secure_packet_parser"]["crash_input"]


def _vm(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["colima", "ssh", "--", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def replay_against_code(code: str, payload_size: int = None,
                         target: str = "secure_packet_parser",
                         sanitizers: str = "address") -> Dict:
    """Compile `code` as the target's source file + its real fuzz harness
    with clang+sanitizers in the Linux VM, then execute a real input against
    it. Real subprocess execution and real sanitizer output; not a canned
    result.

    payload_size: if given, generates a fresh all-'B' input of exactly that
    many bytes (for adversarial robustness testing across the boundary)
    instead of using the target's fixed AFL++-found crash input.
    target: key into TARGETS — which registered vulnerable application to
    compile and replay against.
    sanitizers: clang -fsanitize= value, e.g. "address" (default, matches
    the AFL++ crash-finding binary) or "undefined" (a separate,
    independently-compiled UBSan-only check — trapping/aborting on
    undefined behavior exercised by the given input, orthogonal to whether
    that specific bug was originally an ASan-domain memory-safety issue)."""
    spec = TARGETS[target]
    target_dir = spec["dir"]
    scratch = target_dir / "_replay_scratch"
    harness_src = target_dir / "fuzz_harness.c"
    source_filename = spec["source_filename"]

    try:
        scratch.mkdir(exist_ok=True)
        (scratch / source_filename).write_text(code)
        (scratch / "fuzz_harness.c").write_text(harness_src.read_text())

        recover_flag = " -fno-sanitize-recover=undefined" if "undefined" in sanitizers else ""
        compile_result = _vm(
            f"cd {scratch} && clang-18 -g -fsanitize={sanitizers}{recover_flag} "
            f"-o replay_bin fuzz_harness.c 2>&1"
        )
        if compile_result.returncode != 0:
            return {
                "evidence_type": "measured",
                "compiled": False,
                "crashed": None,
                "output": compile_result.stdout[-2000:],
            }

        if payload_size is not None:
            input_path = scratch / f"input_{payload_size}.bin"
            input_path.write_bytes(b"B" * payload_size)
        else:
            input_path = spec["crash_input"]

        run_result = _vm(f"cd {scratch} && ./replay_bin {input_path} 2>&1")
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
