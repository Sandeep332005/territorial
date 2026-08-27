"""
ABHIMANYU X CORE - Test Suite
Comprehensive tests for all engines
"""

import os
import sys
import json
import shutil
import tempfile
import time
import pytest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.fuzzer.engine import FuzzEngine, FuzzConfig
from abhimanyux.anvil.engine import ANVILEngine
from abhimanyux.verifier.engine import VerificationEngine
from abhimanyux.memory.store import ImmuneMemoryStore
from abhimanyux.core.orchestrator import AbhimanyuXCore
from abhimanyux.watch.engine import WatchEngine
from abhimanyux.models.schemas import (
    Vulnerability, VulnType, Severity, Patch, AnalysisPhase, VerificationResult
)


class TestREWINDEngine:
    """Tests for REWIND Static Analysis Engine"""
    
    def setup_method(self):
        self.engine = REWINDEngine()
    
    def test_scan_python_sql_injection(self):
        """Test detection of SQL injection"""
        code = '''def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()
'''
        vulns = self.engine.scan(code, "test.py")
        
        assert len(vulns) > 0
        sql_injection = [v for v in vulns if v.vuln_type == VulnType.SQL_INJECTION]
        assert len(sql_injection) > 0
        assert sql_injection[0].severity == Severity.CRITICAL
    
    def test_scan_command_injection(self):
        """Test detection of command injection"""
        code = '''
import os
def run_command(cmd):
    return os.popen(cmd).read()
'''
        vulns = self.engine.scan(code, "test.py")
        
        assert len(vulns) > 0
        cmd_injection = [v for v in vulns if v.vuln_type == VulnType.COMMAND_INJECTION]
        assert len(cmd_injection) > 0
    
    def test_scan_path_traversal(self):
        """Test detection of path traversal"""
        code = '''def read_file(filename):
    with open("/data/" + filename, 'r') as f:
        return f.read()
'''
        vulns = self.engine.scan(code, "test.py")
        
        assert len(vulns) > 0
        path_traversal = [v for v in vulns if v.vuln_type == VulnType.PATH_TRAVERSAL]
        assert len(path_traversal) > 0
    
    def test_scan_pickle_deserialization(self):
        """Test detection of pickle deserialization"""
        code = '''
import pickle
def load_data(data):
    return pickle.loads(data)
'''
        vulns = self.engine.scan(code, "test.py")
        
        assert len(vulns) > 0
        deser = [v for v in vulns if v.vuln_type == VulnType.DESERIALIZATION]
        assert len(deser) > 0
    
    def test_scan_hardcoded_credentials(self):
        """Test detection of hardcoded credentials"""
        code = '''
API_KEY = "sk-1234567890abcdef12345678"
DATABASE_PASSWORD = "admin123"
'''
        vulns = self.engine.scan(code, "test.py")
        
        assert len(vulns) > 0
        hardcoded = [v for v in vulns if v.vuln_type == VulnType.HARDCODED_CREDENTIALS]
        assert len(hardcoded) > 0
    
    def test_scan_no_vulnerabilities(self):
        """Test scan of clean code"""
        code = '''
def safe_function(user_input):
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9]', '', user_input)
    return sanitized
'''
        vulns = self.engine.scan(code, "test.py")
        
        # Should find no critical vulnerabilities
        critical = [v for v in vulns if v.severity == Severity.CRITICAL]
        assert len(critical) == 0
    
    def test_deduplication(self):
        """Test that duplicate vulnerabilities are removed"""
        code = '''def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
'''
        vulns = self.engine.scan(code, "test.py")
        
        # Should find SQL injection but not duplicates on same line
        sql_vulns = [v for v in vulns if v.vuln_type == VulnType.SQL_INJECTION]
        assert len(sql_vulns) >= 1
    
    def test_stats(self):
        """Test statistics tracking"""
        code = "x = 1"
        self.engine.scan(code, "test.py")
        self.engine.scan(code, "test2.py")

        stats = self.engine.get_stats()
        assert stats["total_scans"] == 2

    def test_scan_c_buffer_overflow(self):
        """Test detection of C buffer overflow via strcpy"""
        code = '''void copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
'''
        vulns = self.engine.scan(code, "test.c")
        overflow = [v for v in vulns if v.vuln_type == VulnType.BUFFER_OVERFLOW]
        assert len(overflow) > 0
        assert overflow[0].severity == Severity.CRITICAL

    def test_scan_c_use_after_free(self):
        """Test detection of C use-after-free"""
        code = '''void bad() {
    char *ptr = malloc(64);
    free(ptr);
    printf("%s\\n", ptr);
}
'''
        vulns = self.engine.scan(code, "test.c")
        uaf = [v for v in vulns if v.vuln_type == VulnType.USE_AFTER_FREE]
        assert len(uaf) > 0

    def test_scan_c_null_deref_and_memory_leak_same_function(self):
        """Test that a conditionally-assigned NULL pointer and an unfreed
        allocation in the same function are both caught"""
        code = '''void vulnerable_null(char *input) {
    char *ptr = NULL;
    if (input[0] == 'a') {
        ptr = malloc(64);
    }
    strcpy(ptr, input);
}
'''
        vulns = self.engine.scan(code, "test.c")
        types = {v.vuln_type for v in vulns}
        assert VulnType.NULL_POINTER_DEREFERENCE in types
        assert VulnType.MEMORY_LEAK in types

    def test_scan_c_does_not_affect_python_dispatch(self):
        """Regression guard: adding C patterns must not change .py scanning"""
        code = "import os\nos.system(cmd)\n"
        vulns = self.engine.scan(code, "test.py")
        assert any(v.vuln_type == VulnType.COMMAND_INJECTION for v in vulns)

    def test_apply_feedback_blends_confidence(self):
        """Verified-patch outcomes should recalibrate a rule's confidence,
        blended toward (not replaced by) the empirical verified rate"""
        pattern = next(p for p in self.engine.patterns if p.name == "Hardcoded - Password")
        starting = pattern.confidence
        reliability = {"Hardcoded - Password": {"total_patches": 5, "verified_patches": 1, "verified_rate": 0.2}}

        adjusted = self.engine.apply_feedback(reliability)

        assert adjusted == 1
        assert pattern.confidence == pytest.approx(0.7 * starting + 0.3 * 0.2)

    def test_apply_feedback_ignores_low_sample_count(self):
        """A pattern with fewer than min_samples verified patches must be left untouched"""
        pattern = next(p for p in self.engine.patterns if p.name == "Hardcoded - Password")
        starting = pattern.confidence
        reliability = {"Hardcoded - Password": {"total_patches": 1, "verified_patches": 0, "verified_rate": 0.0}}

        adjusted = self.engine.apply_feedback(reliability, min_samples=3)

        assert adjusted == 0
        assert pattern.confidence == starting


class TestFuzzEngine:
    """Tests for Fuzz Engine"""
    
    def setup_method(self):
        self.engine = FuzzEngine()
    
    def test_mutation_strategies(self):
        """Test that all mutation strategies work"""
        for strategy_name, strategy in self.engine.mutation_strategies.items():
            result = strategy()
            assert "type" in result
            assert "value" in result
            assert isinstance(result["value"], str)
    
    def test_bit_flip(self):
        """Test bit flip mutation"""
        result = self.engine._bit_flip()
        assert result["type"] == "bit_flip"
        assert len(result["value"]) > 0
    
    def test_boundary_values(self):
        """Test boundary value generation"""
        result = self.engine._boundary_values()
        assert result["type"] == "boundary"
        assert result["value"] in [
            "0", "-1", "2147483647", "-2147483648",
            "99999999999999999999", "-99999999999999999999",
            "", " " * 10000, "\x00" * 100,
            "A" * 100000, "\n" * 10000
        ]
    
    def test_overflow_strings(self):
        """Test overflow string generation"""
        result = self.engine._overflow_strings()
        assert result["type"] == "overflow"
        assert len(result["value"]) >= 256
    
    def test_format_strings(self):
        """Test format string generation"""
        result = self.engine._format_strings()
        assert result["type"] == "format_string"
        assert "%" in result["value"] or "{" in result["value"]
    
    def test_sql_injection_payloads(self):
        """Test SQL injection payload generation. Checks against every
        marker actually present in the payload pool (was flaky: random.choice
        could pick the stacked-query payload, which has none of OR/UNION/');
        SELECT/; cover it without weakening the check for the others."""
        result = self.engine._sql_injection_payloads()
        assert result["type"] == "sql_injection"
        markers = ("OR", "UNION", "'", "SELECT", ";")
        assert any(marker in result["value"] for marker in markers)
    
    def test_fuzz_code(self):
        """Test fuzzing a simple code"""
        code = '''def process(input_data):
    return input_data.upper()
'''
        config = FuzzConfig(target_path="test.py", max_iterations=10, timeout_per_input=2)
        result = self.engine.fuzz(code, config)
        
        assert result.iterations == 10
        assert result.duration > 0
    
    def test_stats(self):
        """Test statistics tracking"""
        code = "x = 1"
        config = FuzzConfig(target_path="test.py", max_iterations=5)
        self.engine.fuzz(code, config)
        
        stats = self.engine.get_stats()
        assert stats["total_fuzzes"] == 1


class TestANVILEngine:
    """Tests for ANVIL Patch Generation Engine"""
    
    def setup_method(self):
        self.engine = ANVILEngine()
    
    def test_analyze_sql_injection(self):
        """Test patch generation for SQL injection"""
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
        vuln = Vulnerability(
            id="test-001",
            vuln_type=VulnType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="User input in SQL query",
            location={"file_path": "test.py", "line_start": 2},
            cwe_id="CWE-89",
            confidence=0.9,
            source="static"
        )
        
        patch = self.engine.analyze_and_patch(code, vuln)
        
        assert patch.id.startswith("patch-")
        assert patch.vuln_id == "test-001"
        assert patch.patched_code  # Should have a fix
        assert patch.explanation
    
    def test_fix_instructions(self):
        """Test fix instruction generation"""
        instructions = self.engine._get_fix_instructions(VulnType.SQL_INJECTION)
        assert "parameterized" in instructions.lower()
        
        instructions = self.engine._get_fix_instructions(VulnType.COMMAND_INJECTION)
        assert "subprocess" in instructions.lower()
    
    def test_extract_code(self):
        """Test code extraction from LLM response"""
        response = '''Here's the fixed code:

```python
def safe_query(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

This uses parameterized queries.'''
        
        code = self.engine._extract_code(response)
        assert "def safe_query" in code
        assert "?" in code
    
    def test_stats(self):
        """Test statistics tracking"""
        stats = self.engine.get_stats()
        assert stats["total_patches"] == 0

    def test_retrieve_similar_patch_none_without_memory(self):
        """Retrieval must degrade gracefully when no memory is wired in"""
        vuln = Vulnerability(
            id="anvil-nomem-001", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="Command Injection - os.system", description="test",
            location={"file_path": "test.py", "line_start": 1}, confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        assert self.engine._retrieve_similar_patch(vuln, "code") is None

    def test_retrieve_similar_patch_from_memory(self):
        """Retrieval-grounded generation should pull the closest prior patch
        for the same vuln type without calling the LLM"""
        temp_db = tempfile.mktemp(suffix='.db')
        memory = ImmuneMemoryStore(temp_db)
        try:
            code = "def f():\n    os.system(cmd)\n"
            vuln = Vulnerability(
                id="anvil-mem-001", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
                title="Command Injection - os.system", description="test",
                location={"file_path": "test.py", "line_start": 2}, confidence=0.9,
                source=AnalysisPhase.STATIC
            )
            patch = Patch(id="anvil-mem-patch", vuln_id=vuln.id, original_code=code,
                          patched_code="def f():\n    subprocess.run(cmd.split())\n",
                          explanation="fixed", status="verified")
            memory.store_vulnerability(vuln)
            memory.store_patch(patch)

            engine = ANVILEngine(memory=memory)
            similar = engine._retrieve_similar_patch(vuln, code)

            assert similar is not None
            assert similar["id"] == "anvil-mem-patch"
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)


class TestVerificationEngine:
    """Tests for Verification Pipeline"""
    
    def setup_method(self):
        self.engine = VerificationEngine()
    
    def test_verify_syntax_valid(self):
        """Test syntax verification for valid code"""
        code = '''
def safe_function(x):
    return x * 2
'''
        result = self.engine._verify_syntax(code)
        assert result["success"] is True
    
    def test_verify_syntax_invalid(self):
        """Test syntax verification for invalid code"""
        code = '''
def broken(
    return x
'''
        result = self.engine._verify_syntax(code)
        assert result["success"] is False
        assert len(result["errors"]) > 0
    
    def test_extract_functions(self):
        """Test function extraction"""
        code = '''
def func1():
    pass

def func2():
    pass

class MyClass:
    def method(self):
        pass
'''
        funcs = self.engine._extract_functions(code)
        assert "func1" in funcs
        assert "func2" in funcs
        assert "method" in funcs
    
    def test_full_verification(self):
        """Test complete verification pipeline"""
        original = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
'''
        patched = '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''
        vuln = Vulnerability(
            id="test-001",
            vuln_type=VulnType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="Test",
            location={"file_path": "test.py", "line_start": 2},
            confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        
        patch = Patch(
            id="patch-001",
            vuln_id="test-001",
            original_code=original,
            patched_code=patched,
            explanation="Fixed SQL injection",
            status="generated"
        )
        
        result = self.engine.verify(original, patched, vuln, patch)

        assert result.patch_id == "patch-001"
        assert result.compile_success is True
        assert result.behavior_preserved is True

    def test_replay_exploit_confirms_genuine_fix(self):
        """Differential re-scan should confirm a genuine fix as blocked"""
        original = "def run(cmd):\n    os.system(cmd)\n"
        patched = "def run(cmd):\n    subprocess.run(cmd.split())\n"
        vuln = Vulnerability(
            id="verify-genuine", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="Command Injection - os.system", description="test",
            location={"file_path": "test.py", "line_start": 2}, confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        result = self.engine._replay_exploit(original, patched, vuln, "test.py")
        assert result["blocked"] is True
        assert result["tested"] is True

    def test_replay_exploit_catches_fake_fix(self):
        """A no-op patch (comment only, vulnerability untouched) must not
        be reported as blocked — regression guard for the old hardcoded
        'always SAFE' exploit templates this replaced"""
        original = "def run(cmd):\n    os.system(cmd)\n"
        fake = "def run(cmd):\n    # patched\n    os.system(cmd)\n"
        vuln = Vulnerability(
            id="verify-fake", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="Command Injection - os.system", description="test",
            location={"file_path": "test.py", "line_start": 3}, confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        result = self.engine._replay_exploit(original, fake, vuln, "test.py")
        assert result["blocked"] is False

    def test_replay_exploit_untested_when_rule_never_matched_original(self):
        """If REWIND's own rule can't reproduce the original finding, its
        absence in the patch can't be trusted as proof of a fix"""
        vuln = Vulnerability(
            id="verify-untested", vuln_type=VulnType.SQL_INJECTION, severity=Severity.CRITICAL,
            title="SQL Injection", description="test",
            location={"file_path": "test.py", "line_start": 1}, confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        result = self.engine._replay_exploit("x = 1", "x = 2", vuln, "test.py")
        assert result["tested"] is False
        assert result["blocked"] is False

    def test_verify_short_circuits_on_compile_failure(self):
        """A patch that doesn't compile must skip exploit/regression/behavior
        rather than default any of them to a pass"""
        original = "def f():\n    os.system(cmd)\n"
        broken_patch = "def f(\n    pass\n"
        vuln = Vulnerability(
            id="verify-broken", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="Command Injection - os.system", description="test",
            location={"file_path": "test.py", "line_start": 2}, confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        patch = Patch(id="p-broken", vuln_id=vuln.id, original_code=original,
                      patched_code=broken_patch, explanation="x", status="generated")

        result = self.engine.verify(original, broken_patch, vuln, patch)

        assert result.compile_success is False
        assert result.all_tests_pass is False
        assert "skipped" in result.details

    @pytest.mark.skipif(
        not (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")),
        reason="no C compiler available"
    )
    def test_verify_c_patch_can_reach_full_pass(self):
        """A genuine C fix should be able to reach all_tests_pass, closing
        the gap where C patches could compile-check but never fully verify"""
        original = ('#include <string.h>\n'
                     'void f(char *input) {\n'
                     '    char buffer[64];\n'
                     '    strcpy(buffer, input);\n'
                     '}\n')
        patched = ('#include <string.h>\n'
                    'void f(char *input) {\n'
                    '    char buffer[64];\n'
                    '    strncpy(buffer, input, sizeof(buffer) - 1);\n'
                    '    buffer[sizeof(buffer) - 1] = 0;\n'
                    '}\n')
        vuln = Vulnerability(
            id="verify-c-001", vuln_type=VulnType.BUFFER_OVERFLOW, severity=Severity.CRITICAL,
            title="Buffer Overflow - strcpy", description="test",
            location={"file_path": "test.c", "line_start": 4}, confidence=0.85,
            source=AnalysisPhase.STATIC
        )
        patch = Patch(id="p-c-001", vuln_id=vuln.id, original_code=original,
                      patched_code=patched, explanation="x", status="generated")

        result = self.engine.verify(original, patched, vuln, patch)

        assert result.all_tests_pass is True


class TestImmuneMemory:
    """Tests for Immune Memory Store"""
    
    def setup_method(self):
        # Use temporary database
        self.temp_db = tempfile.mktemp(suffix='.db')
        self.memory = ImmuneMemoryStore(self.temp_db)
    
    def teardown_method(self):
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
    
    def test_store_vulnerability(self):
        """Test vulnerability storage"""
        vuln = Vulnerability(
            id="mem-001",
            vuln_type=VulnType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="Test Vuln",
            description="Test",
            location={"file_path": "test.py", "line_start": 1},
            confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        
        vuln_id = self.memory.store_vulnerability(vuln)
        assert vuln_id == "mem-001"
    
    def test_create_dna(self):
        """Test DNA pattern creation"""
        vuln = Vulnerability(
            id="dna-001",
            vuln_type=VulnType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            title="Test Vuln",
            description="Test",
            location={"file_path": "test.py", "line_start": 1},
            raw_analysis="Test analysis",
            confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        
        dna = self.memory.create_dna(vuln, "Use parameterized queries")
        assert dna.id.startswith("dna-")
        assert dna.vuln_type == VulnType.SQL_INJECTION
    
    def test_store_and_retrieve(self):
        """Test storing and retrieving data"""
        vuln = Vulnerability(
            id="ret-001",
            vuln_type=VulnType.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            location={"file_path": "test.py", "line_start": 1},
            confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        
        self.memory.store_vulnerability(vuln)
        
        results = self.memory.search_by_type(VulnType.COMMAND_INJECTION)
        assert len(results) == 1
        assert results[0]["id"] == "ret-001"
    
    def test_statistics(self):
        """Test statistics collection"""
        vuln = Vulnerability(
            id="stat-001",
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="Test",
            description="Test",
            location={"file_path": "test.py", "line_start": 1},
            confidence=0.9,
            source=AnalysisPhase.STATIC
        )
        
        self.memory.store_vulnerability(vuln)
        
        stats = self.memory.get_statistics()
        assert stats["total_vulnerabilities"] == 1
        assert "xss" in stats["by_type"]

    def test_get_similar_patches_compares_like_for_like(self):
        """Similarity must compare full-file text against full-file text
        (what's actually stored), not a snippet against a whole file —
        regression guard for a bug caught during development where every
        comparison scored near zero regardless of true relevance"""
        code = "def f():\n    os.system(cmd)\n"
        vuln = Vulnerability(
            id="sim-a", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="t", description="d", location={"file_path": "a.py", "line_start": 1},
            confidence=0.9, source=AnalysisPhase.STATIC
        )
        patch = Patch(id="patch-sim-a", vuln_id="sim-a", original_code=code,
                      patched_code="fixed", explanation="e", status="generated")
        self.memory.store_vulnerability(vuln)
        self.memory.store_patch(patch)

        same = self.memory.get_similar_patches(VulnType.COMMAND_INJECTION, code, limit=1)
        assert same[0]["similarity"] == pytest.approx(1.0)

        different = self.memory.get_similar_patches(
            VulnType.COMMAND_INJECTION, "totally unrelated content\n" * 5, limit=1
        )
        assert different[0]["similarity"] < 0.5

    def test_create_dna_populates_capability_profile(self):
        """A DNA atom should carry an exploit precondition and a capability
        grant, not just a bare detection/fix pair"""
        vuln = Vulnerability(
            id="cap-001", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="t", description="d", location={"file_path": "a.py", "line_start": 1},
            confidence=0.9, source=AnalysisPhase.STATIC
        )
        dna = self.memory.create_dna(vuln, "use subprocess")
        assert dna.preconditions
        assert dna.capability_grant

    def test_related_dna_links_across_types_in_same_function(self):
        """Two different vulnerability classes found in the same function
        should link as related atoms (composition, not per-CWE isolation)"""
        vuln1 = Vulnerability(
            id="rel-001", vuln_type=VulnType.MEMORY_LEAK, severity=Severity.HIGH,
            title="leak", description="d",
            location={"file_path": "a.c", "line_start": 5, "function_name": "f"},
            confidence=0.55, source=AnalysisPhase.STATIC
        )
        vuln2 = Vulnerability(
            id="rel-002", vuln_type=VulnType.NULL_POINTER_DEREFERENCE, severity=Severity.HIGH,
            title="nullderef", description="d",
            location={"file_path": "a.c", "line_start": 7, "function_name": "f"},
            confidence=0.55, source=AnalysisPhase.STATIC
        )

        self.memory.store_vulnerability(vuln1)
        dna1 = self.memory.create_dna(vuln1, "free the pointer")
        self.memory.store_immune_record(vuln1.id, patch_id=None, dna_id=dna1.id)

        self.memory.store_vulnerability(vuln2)
        dna2 = self.memory.create_dna(vuln2, "add a null check")

        assert dna1.id in dna2.related_dna_ids
        resolved = self.memory.get_dna(dna1.id)
        assert resolved["vuln_type"] == "memory_leak"

    def test_has_verified_patch(self):
        """The regression-detection primitive the Watch engine relies on"""
        vuln = Vulnerability(
            id="hvp-001", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
            title="t", description="d", location={"file_path": "a.py", "line_start": 1},
            confidence=0.9, source=AnalysisPhase.STATIC
        )
        patch = Patch(id="hvp-patch", vuln_id="hvp-001", original_code="x", patched_code="y",
                      explanation="e", status="generated")
        self.memory.store_vulnerability(vuln)
        self.memory.store_patch(patch)
        assert self.memory.has_verified_patch("hvp-001") is False

        self.memory.store_verification(patch.id, VerificationResult(
            patch_id=patch.id, compile_success=True, exploit_blocked=True,
            regression_pass=True, behavior_preserved=True
        ))
        assert self.memory.has_verified_patch("hvp-001") is True

    def test_get_rule_reliability_aggregates_verified_rate(self):
        """Reliability data should reflect what fraction of a rule's
        patches actually passed full verification"""
        for i in range(3):
            vuln = Vulnerability(
                id=f"rel-rule-{i}", vuln_type=VulnType.HARDCODED_CREDENTIALS,
                severity=Severity.MEDIUM, title="Hardcoded - Password", description="d",
                location={"file_path": "a.py", "line_start": i}, confidence=0.75,
                source=AnalysisPhase.STATIC
            )
            patch = Patch(id=f"rel-rule-patch-{i}", vuln_id=vuln.id, original_code="x",
                          patched_code="y", explanation="e", status="generated")
            self.memory.store_vulnerability(vuln)
            self.memory.store_patch(patch)
            self.memory.store_verification(patch.id, VerificationResult(
                patch_id=patch.id, compile_success=True, exploit_blocked=(i == 0),
                regression_pass=True, behavior_preserved=True
            ))

        reliability = self.memory.get_rule_reliability()

        assert reliability["Hardcoded - Password"]["total_patches"] == 3
        assert reliability["Hardcoded - Password"]["verified_patches"] == 1
        assert reliability["Hardcoded - Password"]["verified_rate"] == pytest.approx(1 / 3)


class TestAbhimanyuXCore:
    """Tests for the main orchestrator"""
    
    def setup_method(self):
        self.temp_db = tempfile.mktemp(suffix='.db')
        self.sentinel = AbhimanyuXCore(db_path=self.temp_db)
    
    def teardown_method(self):
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
    
    def test_scan_code(self):
        """Test scanning inline code"""
        code = '''
import os
def run(cmd):
    return os.popen(cmd).read()
'''
        result = self.sentinel.scan_code(code, "test.py")
        
        assert result.scan_id.startswith("scan-")
        assert len(result.vulnerabilities) > 0
        assert len(result.patches) > 0
    
    def test_full_pipeline(self):
        """Test the complete pipeline"""
        code = '''import sqlite3
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()
'''
        result = self.sentinel.scan_code(code, "pipeline_test.py")
        
        # Should find SQL injection
        sql_vulns = [v for v in result.vulnerabilities 
                    if v.vuln_type == VulnType.SQL_INJECTION]
        assert len(sql_vulns) > 0
        
        # Should generate patches
        assert len(result.patches) > 0
        
        # Should have verification results
        assert len(result.verifications) > 0
    
    def test_memory_integration(self):
        """Test that memory is populated after scan"""
        code = '''
API_KEY = "sk-1234567890abcdef"
'''
        self.sentinel.scan_code(code, "memory_test.py")
        
        stats = self.sentinel.get_memory_stats()
        assert stats["total_vulnerabilities"] > 0
        assert stats["total_dna_patterns"] > 0

    def test_evolve_is_safe_on_empty_memory(self):
        """The feedback-loop entry point must be a safe no-op with no history"""
        assert self.sentinel.evolve() == 0


class TestWatchEngine:
    """Tests for the continuous Watch engine"""

    def setup_method(self):
        self.temp_db = tempfile.mktemp(suffix='.db')
        self.sentinel = AbhimanyuXCore(db_path=self.temp_db)
        self.tmpdir = tempfile.mkdtemp()
        self.target = os.path.join(self.tmpdir, "app.py")

    def teardown_method(self):
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)

    def test_new_resolved_regression_transitions(self):
        """A full lifecycle: introduce a vuln, fix it, then revert it —
        should produce new -> resolved -> regression, distinguishing a
        reverted-and-previously-fixed vuln from one that was never patched"""
        watcher = WatchEngine(self.sentinel, poll_interval=0.01)
        vulnerable_line = "os.system(cmd)\n"
        safe_line = "subprocess.run(cmd.split())\n"

        with open(self.target, 'w') as f:
            f.write(vulnerable_line)
        events = watcher.check_once(self.tmpdir)
        assert len(events) == 1
        assert events[0].event_type == "new"
        vuln_id = events[0].vulnerability.id

        # Simulate that this exact vulnerability was previously verified-fixed
        self.sentinel.memory.store_vulnerability(events[0].vulnerability)
        patch = Patch(id="watch-patch", vuln_id=vuln_id, original_code=vulnerable_line,
                      patched_code=safe_line, explanation="fixed", status="verified")
        self.sentinel.memory.store_patch(patch)
        self.sentinel.memory.store_verification(patch.id, VerificationResult(
            patch_id=patch.id, compile_success=True, exploit_blocked=True,
            regression_pass=True, behavior_preserved=True
        ))

        time.sleep(0.02)
        with open(self.target, 'w') as f:
            f.write(safe_line)
        events = watcher.check_once(self.tmpdir)
        assert len(events) == 1
        assert events[0].event_type == "resolved"

        time.sleep(0.02)
        with open(self.target, 'w') as f:
            f.write(vulnerable_line)
        events = watcher.check_once(self.tmpdir)
        assert len(events) == 1
        assert events[0].event_type == "regression"

    def test_no_events_when_nothing_changes(self):
        """A poll cycle over an unchanged file should be silent"""
        watcher = WatchEngine(self.sentinel, poll_interval=0.01)
        with open(self.target, 'w') as f:
            f.write("x = 1\n")

        watcher.check_once(self.tmpdir)  # first sighting establishes baseline
        events = watcher.check_once(self.tmpdir)

        assert events == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
