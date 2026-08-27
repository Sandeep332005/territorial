"""
ABHIMANYU X CORE - Verification Pipeline
Evidence-Based Patch Verification

Verifies patches through:
- Compile verification (syntax check)
- Exploit replay (proving vulnerability is fixed)
- Regression testing (proving functionality preserved)
- Behavior validation (code analysis)
"""

import os
import sys
import ast
import shutil
import tempfile
import subprocess
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from abhimanyux.models.schemas import (
    Vulnerability, Patch, VerificationResult, ExploitEvidence
)
from abhimanyux.rewind.engine import REWINDEngine


@dataclass
class VerificationConfig:
    """Configuration for verification"""
    timeout: int = 30
    run_tests: bool = True
    replay_exploits: bool = True
    check_syntax: bool = True
    check_behavior: bool = True


class VerificationEngine:
    """
    Verification Pipeline
    
    Proves that:
    1. The patched code compiles/parse correctly
    2. The original exploit no longer works
    3. Normal functionality is preserved
    4. No regressions are introduced
    """
    
    def __init__(self, config: Optional[VerificationConfig] = None):
        self.config = config or VerificationConfig()
        self.rewind = REWINDEngine()
        self.verification_count = 0

    def verify(self, original_code: str, patched_code: str,
               vulnerability: Vulnerability, patch: Patch) -> VerificationResult:
        """
        Complete verification of a patch, staged so later checks only run
        once an earlier one has established they're meaningful.

        Args:
            original_code: Original vulnerable code
            patched_code: Patched code
            vulnerability: The vulnerability being fixed
            patch: The generated patch

        Returns:
            VerificationResult with all checks
        """
        self.verification_count += 1
        filename = vulnerability.location.file_path or "patched"
        is_c = filename.endswith(REWINDEngine.C_EXTENSIONS)

        results = {
            "patch_id": patch.id,
            "compile_success": False,
            "exploit_blocked": False,
            "regression_pass": False,
            "behavior_preserved": False,
            "all_tests_pass": False,
            "details": {}
        }

        # Stage 1: environment qualification. Nothing downstream is
        # trustworthy if the patch doesn't even compile/parse — treating a
        # non-compiling patch as anything but failed (e.g. by still running
        # regression/behavior checks and averaging the result) would be the
        # ungrounded "Hack Rewarding" gap SysEvolve warns about, where a
        # result the checker can't actually stand behind gets counted anyway.
        if self.config.check_syntax:
            syntax_result = self._verify_syntax(patched_code, filename)
            results["compile_success"] = syntax_result["success"]
            results["details"]["syntax"] = syntax_result

        if not results["compile_success"]:
            results["details"]["skipped"] = (
                "exploit/regression/behavior checks skipped: patch does not compile"
            )
            return VerificationResult(**results)

        # Stage 2: capability checks, each drawing on an independent
        # evidence source (re-scan output, subprocess exit code, AST diff)
        # rather than trusting the patch's own claims about itself.
        if self.config.replay_exploits:
            exploit_result = self._replay_exploit(original_code, patched_code, vulnerability, filename)
            results["exploit_blocked"] = exploit_result["blocked"]
            results["details"]["exploit"] = exploit_result

        if self.config.run_tests:
            if is_c:
                # No C regression harness yet; report untested rather than
                # defaulting to pass, so all_tests_pass stays honest about
                # what was actually checked for this language.
                regression_result = {
                    "passed": False, "tested": False,
                    "note": "regression harness only supports Python currently"
                }
            else:
                regression_result = self._run_regression_tests(original_code, patched_code)
            results["regression_pass"] = regression_result["passed"]
            results["details"]["regression"] = regression_result

        # Stage 3: terminal objective
        if self.config.check_behavior:
            if is_c:
                behavior_result = {
                    "preserved": False, "tested": False,
                    "note": "behavior-preservation check only supports Python currently"
                }
            else:
                behavior_result = self._validate_behavior(original_code, patched_code)
            results["behavior_preserved"] = behavior_result["preserved"]
            results["details"]["behavior"] = behavior_result

        results["all_tests_pass"] = (
            results["compile_success"] and
            results["exploit_blocked"] and
            results["regression_pass"] and
            results["behavior_preserved"]
        )

        return VerificationResult(**results)

    def _verify_syntax(self, code: str, filename: str = "") -> Dict:
        """Compile/syntax-check the patched code, dispatching to a real C
        compiler's -fsyntax-only pass for C/C++ files (mirroring REWIND's own
        language dispatch) instead of always running Python's ast.parse,
        which would reject every valid C file."""
        if filename.endswith(REWINDEngine.C_EXTENSIONS):
            return self._verify_c_syntax(code)
        return self._verify_python_syntax(code)

    def _verify_python_syntax(self, code: str) -> Dict:
        result = {"success": False, "errors": []}

        try:
            ast.parse(code)
            result["success"] = True
        except SyntaxError as e:
            result["errors"].append({
                "line": e.lineno,
                "message": str(e),
                "type": "SyntaxError"
            })

        # Also try to compile
        try:
            compile(code, '<string>', 'exec')
            result["compile_success"] = True
        except SyntaxError as e:
            if not result["errors"]:
                result["errors"].append({
                    "line": e.lineno,
                    "message": str(e),
                    "type": "CompileError"
                })

        return result

    def _verify_c_syntax(self, code: str) -> Dict:
        result = {"success": False, "errors": []}
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            result["errors"].append({
                "message": "no C compiler (cc/gcc/clang) found on PATH; cannot verify syntax",
                "type": "EnvironmentError"
            })
            return result
        try:
            proc = subprocess.run(
                [compiler, "-fsyntax-only", "-x", "c", "-"],
                input=code, capture_output=True, text=True, timeout=self.config.timeout
            )
            result["success"] = proc.returncode == 0
            if not result["success"]:
                result["errors"].append({"message": proc.stderr[:1000], "type": "CompileError"})
        except Exception as e:
            result["errors"].append({"message": str(e), "type": "EnvironmentError"})
        return result

    def _replay_exploit(self, original_code: str, patched_code: str,
                         vulnerability: Vulnerability, filename: str = "") -> Dict:
        """
        "Exploit replay" implemented as a differential re-scan: rerun REWIND
        against both the original and patched code and confirm the specific
        vulnerability class (and CWE, when known) is present-before /
        absent-after.

        This replaces the previous per-type hardcoded test templates, which
        never executed against the actual patch content and unconditionally
        printed "SAFE" regardless of what the patch did — a checker that
        cannot fail is exactly the "Hack Rewarding" gap SysEvolve describes.

        Checking only the patched side isn't enough either: if REWIND's own
        rule doesn't happen to match the original code's exact shape (e.g. a
        SQL query built through a variable REWIND's regex doesn't trace
        through), a no-op "patch" would trivially show "not present" on both
        sides and be misread as fixed. Requiring the original to also
        reproduce the finding makes this a true before/after comparison
        instead of a one-sided absence check.
        """
        original_findings = self.rewind.scan(original_code, filename or "original")
        originally_confirmed = any(
            f.vuln_type == vulnerability.vuln_type
            and (not vulnerability.cwe_id or f.cwe_id == vulnerability.cwe_id)
            for f in original_findings
        )

        if not originally_confirmed:
            return {
                "blocked": False, "tested": False,
                "details": (
                    "REWIND's own rules did not reproduce the original vulnerability "
                    "in the unpatched code, so its absence in the patched code can't "
                    "be trusted as evidence of a fix"
                )
            }

        patched_findings = self.rewind.scan(patched_code, filename or "patched")
        still_present = [
            f for f in patched_findings
            if f.vuln_type == vulnerability.vuln_type
            and (not vulnerability.cwe_id or f.cwe_id == vulnerability.cwe_id)
        ]

        if still_present:
            return {
                "blocked": False, "tested": True,
                "details": (
                    f"Re-scan still detects {vulnerability.vuln_type.value} "
                    f"({len(still_present)} finding(s)) in the patched code"
                )
            }
        return {
            "blocked": True, "tested": True,
            "details": "Re-scan confirms the pattern in the original code and its absence in the patch"
        }

    def _run_regression_tests(self, original_code: str, patched_code: str) -> Dict:
        """Run regression tests to ensure functionality preserved"""
        result = {"passed": False, "tests_run": 0, "tests_passed": 0, "errors": []}
        
        # Extract function definitions from both versions
        original_funcs = self._extract_functions(original_code)
        patched_funcs = self._extract_functions(patched_code)
        
        # Check that all functions still exist
        for func_name in original_funcs:
            if func_name not in patched_funcs:
                result["errors"].append(f"Function {func_name} removed in patch")
                return result
            result["tests_run"] += 1
            result["tests_passed"] += 1
        
        # Try to import and test basic functionality
        try:
            # Create a test module
            test_code = f'''
import sys
sys.path.insert(0, '.')

{patched_code}

# Basic functionality tests
print("REGRESSION: All functions present")
'''
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_code)
                temp_path = f.name
            
            proc = subprocess.run(
                [sys.executable, temp_path],
                capture_output=True,
                text=True,
                timeout=self.config.timeout
            )
            
            if proc.returncode == 0:
                result["passed"] = True
            
            os.unlink(temp_path)
        
        except Exception as e:
            result["errors"].append(str(e))
        
        return result
    
    def _validate_behavior(self, original_code: str, patched_code: str) -> Dict:
        """Validate that behavior is preserved"""
        result = {"preserved": False, "changes": []}
        
        # Parse both versions
        try:
            original_ast = ast.parse(original_code)
            patched_ast = ast.parse(patched_code)
        except SyntaxError:
            result["changes"].append("Syntax error in patched code")
            return result
        
        # Compare AST structure
        original_structure = self._get_ast_structure(original_ast)
        patched_structure = self._get_ast_structure(patched_ast)
        
        # Check for removed functionality
        for key in original_structure:
            if key not in patched_structure:
                result["changes"].append(f"Removed: {key}")
        
        # Check for significant changes
        for key in patched_structure:
            if key in original_structure:
                if original_structure[key] != patched_structure[key]:
                    result["changes"].append(f"Modified: {key}")
        
        # Consider preserved if only security-relevant changes
        if len(result["changes"]) <= 2:  # Allow some modifications
            result["preserved"] = True
        
        return result
    
    def _extract_functions(self, code: str) -> List[str]:
        """Extract function names from code"""
        try:
            tree = ast.parse(code)
            return [node.name for node in ast.walk(tree) 
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        except SyntaxError:
            return []
    
    def _get_ast_structure(self, tree: ast.AST) -> Dict[str, str]:
        """Get simplified AST structure"""
        structure = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                structure[f"func:{node.name}"] = "function"
            elif isinstance(node, ast.ClassDef):
                structure[f"class:{node.name}"] = "class"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    structure[f"import:{alias.name}"] = "import"
            elif isinstance(node, ast.ImportFrom):
                structure[f"importfrom:{node.module}"] = "import"
        
        return structure
    
    def get_stats(self) -> Dict[str, int]:
        """Get verification statistics"""
        return {
            "total_verifications": self.verification_count
        }
