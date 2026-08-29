"""
SENTINEL-X CORE - Autonomous Demo Orchestrator

Drives one vulnerability through the full lifecycle for the Judge Mode
("START AUTONOMOUS DEMO") experience, emitting a WebSocket event per stage.

Real stages (execute against actual code, a real local LLM, and a real
compiler): INGEST, REWIND, STATIC_ANALYSIS, ANALYZE (ANVIL), PATCH, BUILD,
REGRESSION, BEHAVIOUR_CHECK, MEMORY_COMMIT.

EXPLOIT_REPLAY is also real: it compiles the before/after code with
clang+ASan inside the Colima Linux VM and executes each against the actual
crash input a real AFL++ run found, via sentinel/real_fuzzing.py.

Deterministic-demo stage (fixed, clearly-labeled placeholder evidence):
DYNAMIC_ANALYSIS's execution-count telemetry, and FUZZ's executions/sec and
coverage-% figures — a real AFL++ 4.09c is installed and was used to find
the crash EXPLOIT_REPLAY replays, but its LLVM17 SanitizerCoverage pass does
not correctly interact with ASan's redzones on this arm64/Ubuntu 24.04
package (reproduced with a minimal, project-independent repro case), so
coverage-guided instrumentation is not currently functional here and these
specific numbers are not measured. See sentinel/real_fuzzing.py docstring.
"""

import re
import threading
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Dict, Optional

from abhimanyux.core.orchestrator import AbhimanyuXCore
from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.sentinel.demo_evidence import (
    dynamic_analysis_evidence,
    fuzz_campaign_evidence,
    vulnerability_evidence_bundle,
)
from abhimanyux.sentinel.real_fuzzing import replay_against_code

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_REPO = REPO_ROOT / "vulnerable_targets" / "secure_packet_parser"
TARGET_FILE = TARGET_REPO / "parser.c"
TARGET_FILE_REL = "abhimanyux/vulnerable_targets/secure_packet_parser/parser.c"
V2_FILE = REPO_ROOT / "vulnerable_targets" / "network_parser_v2.c"
V2_FILE_REL = "abhimanyux/vulnerable_targets/network_parser_v2.c"


def _now_hms() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")


class DemoReset(Exception):
    """Internal control-flow signal: a reset was requested mid-run."""


class SentinelOrchestrator:
    """One instance per running demo. Not safe for concurrent overlapping
    runs (a single Judge Mode session is the intended usage)."""

    def __init__(self, core: AbhimanyuXCore, emit_fn: Callable[[str, Dict], None]):
        self.core = core
        self.emit = emit_fn
        self.state = "IDLE"
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._reset_flag = threading.Event()
        self.metrics = {
            "vulnerabilities_found": 0,
            "vulnerabilities_verified": 0,
            "patches_generated": 0,
            "patches_accepted": 0,
            "regression_tests_passed": 0,
            "regression_tests_total": 0,
            "fuzz_executions": 0,
            "immune_records": 0,
            "false_fixes": 0,
        }
        self._last_verified_vuln = None

    def pause(self):
        self._pause_event.clear()
        self.state = "PAUSED"
        self.emit("demo_state", {"state": self.state})

    def resume(self):
        self._pause_event.set()
        self.state = "RUNNING"
        self.emit("demo_state", {"state": self.state})

    def reset(self):
        self._reset_flag.set()
        self._pause_event.set()

    def _checkpoint(self):
        self._pause_event.wait()
        if self._reset_flag.is_set():
            raise DemoReset()

    def _stage(self, stage: str, message: str, progress: int, evidence_type: str = "measured", **extra):
        self._checkpoint()
        payload = {
            "stage": stage,
            "message": message,
            "progress": progress,
            "evidence_type": evidence_type,
            **extra,
        }
        self.emit("stage_update", payload)
        self.emit("timeline_event", {"time": _now_hms(), "message": message})

    def run_full_demo(self):
        """Executes the entire lifecycle once against secure_packet_parser."""
        self._reset_flag.clear()
        self.state = "RUNNING"
        self.emit("demo_state", {"state": self.state, "message": "INITIALIZING SENTINEL-X"})

        try:
            self._stage("INIT", "SENTINEL-X CORE initializing", 2)
            self._stage("INGEST", "Loading vulnerable target: secure_packet_parser", 6,
                         target={"name": "secure_packet_parser", "language": "C",
                                 "build": "CMake", "profile": "Memory Safety"})

            # --- REWIND: real git commit diff analysis ---
            self._stage("REWIND", "Running REWIND commit analysis", 12)
            rewind = REWINDEngine()
            commit_info = rewind.analyze_commit(str(TARGET_REPO), "HEAD")
            self.emit("rewind_result", commit_info)
            self._stage(
                "REWIND", f"Security-sensitive change detected in {commit_info['commit']}",
                18, commit=commit_info["commit"], risk=commit_info["risk"]
            )

            # --- STATIC_ANALYSIS: real REWIND scan ---
            self._stage("STATIC_ANALYSIS", "Running static analysis", 24)
            code = TARGET_FILE.read_text()
            findings = rewind.scan(code, TARGET_FILE_REL)
            self.emit("static_analysis_result", {
                "evidence_type": "measured",
                "files_scanned": 1,
                "functions_analyzed": len(rewind.split_c_functions(code)),
                "findings": [
                    {
                        "severity": f.severity.value, "title": f.title,
                        "location": f"{Path(f.location.file_path).name}:{f.location.line_start}",
                        "cwe_id": f.cwe_id, "confidence": f.confidence,
                        "code_snippet": f.location.code_snippet,
                    } for f in findings
                ],
            })
            if not findings:
                self._stage("COMPLETE", "No vulnerabilities found in current target state", 100,
                             evidence_type="measured")
                self.state = "COMPLETE"
                self.emit("demo_state", {"state": self.state})
                return
            vuln = findings[0]
            self.metrics["vulnerabilities_found"] += 1
            self._stage("STATIC_ANALYSIS",
                        f"{len(findings)} security finding(s) — {vuln.title}", 30)

            # --- DYNAMIC_ANALYSIS: deterministic demo ---
            self._stage("DYNAMIC_ANALYSIS", "Running dynamic analysis (instrumented execution)",
                         36, evidence_type="demo")
            dyn = dynamic_analysis_evidence(vuln)
            self.emit("dynamic_analysis_result", dyn)
            self._stage("DYNAMIC_ANALYSIS", "Memory error detected by sanitizer", 42,
                         evidence_type="demo")

            # --- FUZZ: deterministic demo ---
            self._stage("FUZZ", "Fuzz engine searching for memory-safety violations", 48,
                         evidence_type="demo")
            fuzz = fuzz_campaign_evidence(vuln)
            self.emit("fuzz_result", fuzz)
            self.metrics["fuzz_executions"] = fuzz["total_executions"]
            self._stage("FUZZ", f"Crash found: {fuzz['crash']['input_file']} ({fuzz['crash']['signal']})",
                         54, evidence_type="demo")

            # --- DISCOVERY: combine real static finding + demo dynamic/fuzz evidence ---
            evidence_bundle = vulnerability_evidence_bundle(vuln, dyn, fuzz)
            self.emit("vulnerability_confirmed", evidence_bundle)
            self._stage("DISCOVERY", f"Vulnerability confirmed: {vuln.cwe_id}", 58)

            # --- ANALYZE: real ANVIL reasoning via local LLM ---
            self._stage("ANALYZE", "ANVIL reasoning about root cause", 64,
                         evidence_type="ai_generated")
            patch = self.core.anvil.analyze_and_patch(code, vuln)
            self.metrics["patches_generated"] += 1
            self.emit("anvil_result", {
                "evidence_type": "ai_generated",
                "explanation": patch.explanation,
                "model": self.core.anvil.config.model,
                "provider": self.core.anvil.config.provider,
            })
            self._stage("ANALYZE", "Root cause identified", 68, evidence_type="ai_generated")

            # --- PATCH ---
            self._stage("PATCH", "Patch generated", 72, evidence_type="ai_generated")
            self.emit("patch_result", {
                "evidence_type": "ai_generated",
                "patch_id": patch.id,
                "original_code": code,
                "patched_code": patch.patched_code,
            })

            # --- BUILD: real compile check ---
            self._stage("BUILD", "Build verification (compiling patched code)", 78)
            verification = self.core.verifier.verify(code, patch.patched_code, vuln, patch)
            self.emit("build_result", {
                "evidence_type": "measured",
                "compile_success": verification.compile_success,
                "details": verification.details.get("syntax"),
            })
            if not verification.compile_success:
                self.metrics["false_fixes"] += 1
                self._stage("COMPLETE", "Patch rejected — does not compile. AI-generated patches "
                                         "are never auto-trusted.", 100, evidence_type="measured")
                self.emit("demo_final", {"verified": False, "reason": "compile_failed"})
                self.state = "COMPLETE"
                self.emit("demo_state", {"state": self.state})
                return
            self._stage("BUILD", "Build passed", 82)

            # --- EXPLOIT_REPLAY: real compile+execute in the Linux VM against
            # the real AFL++-found crash input ---
            self._stage("EXPLOIT_REPLAY",
                         "Replaying real crash input against original and patched code (Colima VM)",
                         86)
            before = replay_against_code(code)
            after = replay_against_code(patch.patched_code)
            exploit_blocked = bool(before.get("crashed")) and after.get("crashed") is False
            self.emit("replay_result", {"before": before, "after": after,
                                         "exploit_blocked": exploit_blocked})
            self._stage(
                "EXPLOIT_REPLAY",
                "Exploit replay: patched code rejects malicious input" if exploit_blocked
                else "Exploit replay: patch did not block the real crash input",
                89,
            )

            # --- REGRESSION: real regression/behavior checks ---
            self._stage("REGRESSION", "Running regression tests", 92)
            reg_passed = verification.regression_pass
            self.metrics["regression_tests_total"] = 12
            self.metrics["regression_tests_passed"] = 12 if reg_passed else 0
            self.emit("regression_result", {
                "evidence_type": "measured",
                "passed": reg_passed,
                "details": verification.details.get("regression"),
                "demo_test_count": "12/12 (demo count; PASS/FAIL gate itself is real)",
            })

            self._stage("BEHAVIOUR_CHECK", "Validating behavior preservation", 95)
            self.emit("behaviour_result", {
                "evidence_type": "measured",
                "preserved": verification.behavior_preserved,
                "details": verification.details.get("behavior"),
            })

            all_pass = verification.all_tests_pass
            if all_pass:
                self.metrics["vulnerabilities_verified"] += 1
                self.metrics["patches_accepted"] += 1
            else:
                self.metrics["false_fixes"] += 1

            # --- MEMORY_COMMIT: real Immune Memory ---
            if all_pass:
                self._stage("MEMORY_COMMIT", "Creating Immune Memory record", 98)
                self.core.memory.store_vulnerability(vuln)
                self.core.memory.store_patch(patch)
                dna = self.core.memory.create_dna(vuln, patch.explanation)
                self.core.memory.store_immune_record(vuln.id, patch.id, dna.id)
                self.metrics["immune_records"] += 1
                self._last_verified_vuln = vuln
                self.emit("immune_memory_created", {
                    "evidence_type": "measured",
                    "id": dna.id,
                    "vulnerability": vuln.title,
                    "cwe": vuln.cwe_id,
                    "pattern": "Untrusted length -> fixed-size buffer copy",
                })

            self._stage("COMPLETE", "SENTINEL-X HAS LEARNED" if all_pass else
                        "Verification failed — patch rejected", 100)
            self.emit("demo_final", {
                "verified": all_pass,
                "vulnerability": vuln.title,
                "cwe": vuln.cwe_id,
                "compile_success": verification.compile_success,
                "exploit_blocked": exploit_blocked,
                "regression_pass": verification.regression_pass,
                "behaviour_preserved": verification.behavior_preserved,
                "immune_memory_created": all_pass,
            })
            self.state = "COMPLETE"
            self.emit("demo_state", {"state": self.state})

        except DemoReset:
            self.state = "IDLE"
            self.emit("demo_state", {"state": self.state, "message": "Reset"})

    def run_future_learning_demo(self):
        """Scans the second vulnerable file and matches it against the
        vulnerability verified by run_full_demo(). Real REWIND scan; the
        similarity score is a live SequenceMatcher comparison between the two
        vulnerabilities' flagged code snippets (the memcpy call itself), not
        whole-file text — whole-file comparison is dominated by unrelated
        struct/include boilerplate and understates a real pattern match."""
        rewind = REWINDEngine()
        code = V2_FILE.read_text()
        findings = rewind.scan(code, V2_FILE_REL)
        if not findings:
            self.emit("future_learning_result", {"matched": False,
                       "message": "No findings in network_parser_v2.c"})
            return
        vuln = findings[0]

        prior = self._last_verified_vuln
        if prior and prior.vuln_type == vuln.vuln_type:
            similarity = SequenceMatcher(
                None,
                prior.location.code_snippet or "",
                vuln.location.code_snippet or "",
            ).ratio()
            prior_id = prior.id
        else:
            similar = self.core.memory.get_similar_patches(vuln.vuln_type, code, limit=1)
            similarity = similar[0]["similarity"] if similar else 0.0
            prior_id = None

        matched = similarity > 0
        result = {
            "evidence_type": "measured",
            "new_file": V2_FILE_REL,
            "finding": {
                "title": vuln.title, "cwe": vuln.cwe_id,
                "location": f"{vuln.location.function_name}() line {vuln.location.line_start}",
            },
            "matched": matched,
            "similarity_pct": round(similarity * 100),
            "similarity_basis": "flagged code snippet (memcpy call), same vulnerability type",
            "prior_vulnerability_id": prior_id,
            "recommendation": "Review input boundary before memory copy." if matched else None,
        }
        self.emit("future_learning_result", result)
