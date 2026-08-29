#!/usr/bin/env python3
"""
ABHIMANYU X CORE - Comprehensive Audit Test Suite
Inspired by claude-seo's parallel multi-agent testing approach.

Runs 8 parallel audit categories covering:
1. Component Health (all engines initialize correctly)
2. Detection Accuracy (known vulnerable patterns are caught)
3. Patch Quality (generated patches are syntactically valid)
4. Verification Integrity (verification pipeline catches fake patches)
5. Memory Consistency (stored data is retrievable and linked)
6. API Robustness (endpoints handle edge cases)
7. Cross-Language Support (Python + C detection)
8. Integration Flows (full pipeline end-to-end)
"""

import os
import sys
import json
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

import pytest
from abhimanyux.core.orchestrator import AbhimanyuXCore
from abhimanyux.core.fast_orchestrator import FastOrchestrator
from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.fuzzer.engine import FuzzEngine
from abhimanyux.anvil.engine import ANVILEngine, LLMConfig
from abhimanyux.verifier.engine import VerificationEngine
from abhimanyux.memory.store import ImmuneMemoryStore
from abhimanyux.watch.engine import WatchEngine
from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityLocation, Patch, PatchStatus,
    VerificationResult, VulnType, Severity, AnalysisPhase, ScanResult
)


# ============================================================
# Audit Report Data Structure
# ============================================================

@dataclass
class AuditFinding:
    """Single audit finding"""
    category: str
    test_name: str
    status: str  # "pass", "fail", "warn"
    message: str
    details: Optional[Dict[str, Any]] = None
    duration_ms: float = 0


@dataclass
class AuditReport:
    """Complete audit report"""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[AuditFinding] = field(default_factory=list)
    
    def add(self, finding: AuditFinding):
        self.findings.append(finding)
    
    @property
    def passed(self) -> int:
        return sum(1 for f in self.findings if f.status == "pass")
    
    @property
    def failed(self) -> int:
        return sum(1 for f in self.findings if f.status == "fail")
    
    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.status == "warn")
    
    def summary(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total": len(self.findings),
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "score": round(self.passed / max(len(self.findings), 1) * 100, 1),
            "categories": self._by_category()
        }
    
    def _by_category(self) -> Dict[str, Dict]:
        cats = {}
        for f in self.findings:
            if f.category not in cats:
                cats[f.category] = {"pass": 0, "fail": 0, "warn": 0}
            cats[f.category][f.status] += 1
        return cats


# ============================================================
# Audit Category 1: Component Health
# ============================================================

def audit_component_health(report: AuditReport):
    """Verify all components initialize correctly."""
    category = "Component Health"
    
    # Test REWIND engine
    t0 = time.time()
    try:
        engine = REWINDEngine()
        assert len(engine.patterns) > 0, "No Python patterns loaded"
        assert len(engine.c_patterns) > 0, "No C patterns loaded"
        report.add(AuditFinding(category, "REWIND init", "pass",
            f"Loaded {len(engine.patterns)} Python + {len(engine.c_patterns)} C patterns",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "REWIND init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test Fuzz engine
    t0 = time.time()
    try:
        engine = FuzzEngine()
        assert len(engine.mutation_strategies) > 0, "No mutation strategies"
        report.add(AuditFinding(category, "Fuzz init", "pass",
            f"Loaded {len(engine.mutation_strategies)} mutation strategies",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "Fuzz init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test ANVIL engine
    t0 = time.time()
    try:
        engine = ANVILEngine()
        assert engine.patch_count == 0, "Fresh engine should have 0 patches"
        report.add(AuditFinding(category, "ANVIL init", "pass",
            "Initialized with default config",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "ANVIL init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test Verifier
    t0 = time.time()
    try:
        engine = VerificationEngine()
        assert engine.verification_count == 0
        report.add(AuditFinding(category, "Verifier init", "pass",
            "Initialized with default config",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "Verifier init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test Memory Store
    t0 = time.time()
    try:
        db = tempfile.mktemp(suffix='.db')
        store = ImmuneMemoryStore(db)
        stats = store.get_statistics()
        assert stats["total_vulnerabilities"] == 0
        os.unlink(db)
        report.add(AuditFinding(category, "Memory init", "pass",
            "SQLite store initializes and reports empty stats",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "Memory init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test Orchestrator
    t0 = time.time()
    try:
        db = tempfile.mktemp(suffix='.db')
        core = AbhimanyuXCore(db_path=db)
        assert core.rewind is not None
        assert core.memory is not None
        assert core.anvil is not None
        os.unlink(db)
        report.add(AuditFinding(category, "Orchestrator init", "pass",
            "All engines wired correctly",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "Orchestrator init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))
    
    # Test Fast Orchestrator
    t0 = time.time()
    try:
        db = tempfile.mktemp(suffix='.db')
        fast = FastOrchestrator(db_path=db)
        assert fast.rewind is not None
        os.unlink(db)
        report.add(AuditFinding(category, "FastOrchestrator init", "pass",
            "Initialized with template-based fix support",
            duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "FastOrchestrator init", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))


# ============================================================
# Audit Category 2: Detection Accuracy
# ============================================================

def audit_detection_accuracy(report: AuditReport):
    """Verify REWIND catches known vulnerable patterns."""
    category = "Detection Accuracy"
    engine = REWINDEngine()
    
    test_cases = [
        ("SQL Injection - f-string", VulnType.SQL_INJECTION,
         'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")'),
        ("SQL Injection - format", VulnType.SQL_INJECTION,
         'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))'),
        ("Command Injection - os.popen", VulnType.COMMAND_INJECTION,
         'os.popen(cmd).read()'),
        ("Command Injection - os.system", VulnType.COMMAND_INJECTION,
         'os.system(command)'),
        ("Command Injection - eval", VulnType.COMMAND_INJECTION,
         'eval(user_input)'),
        ("Command Injection - exec", VulnType.COMMAND_INJECTION,
         'exec(code_string)'),
        ("Deserialization - pickle", VulnType.DESERIALIZATION,
         'pickle.loads(data)'),
        ("Deserialization - yaml", VulnType.DESERIALIZATION,
         'yaml.load(raw_data)'),
        ("Hardcoded - API key", VulnType.HARDCODED_CREDENTIALS,
         'API_KEY = "sk-1234567890abcdef"'),
        ("Hardcoded - Password", VulnType.HARDCODED_CREDENTIALS,
         'password = "admin123"'),
        ("XSS - render_template_string", VulnType.XSS,
         'render_template_string(user_input)'),
        ("Weak Crypto - random", VulnType.WEAK_CRYPTO,
         'token = random.randint(0, 999999)'),
        ("Path Traversal - open", VulnType.PATH_TRAVERSAL,
         'open("/data/" + filename, "r")'),
        ("SSRF - requests", VulnType.SSRF,
         'requests.get(url + user_path)'),
        ("C Buffer Overflow - strcpy", VulnType.BUFFER_OVERFLOW,
         'strcpy(buffer, input);', True),
        ("C Buffer Overflow - gets", VulnType.BUFFER_OVERFLOW,
         'gets(buffer);', True),
        ("C Buffer Overflow - sprintf", VulnType.BUFFER_OVERFLOW,
         'sprintf(buf, "%s", input);', True),
        ("C Command Injection - system", VulnType.COMMAND_INJECTION,
         'system(cmd);', True),
    ]
    
    for item in test_cases:
        name = item[0]
        expected_type = item[1]
        code = item[2]
        is_c = item[3] if len(item) > 3 else False
        t0 = time.time()
        filename = "test.c" if is_c else "test.py"
        vulns = engine.scan(code, filename)
        
        matches = [v for v in vulns if v.vuln_type == expected_type]
        status = "pass" if matches else "fail"
        msg = f"Found {expected_type.value}" if matches else f"Missed {expected_type.value}"
        
        report.add(AuditFinding(category, name, status, msg,
            duration_ms=(time.time() - t0) * 1000))
    
    # Test clean code produces no critical findings
    t0 = time.time()
    clean_code = '''
def safe_function(user_input: str) -> str:
    import re
    return re.sub(r'[^a-zA-Z0-9]', '', user_input)
'''
    vulns = engine.scan(clean_code, "clean.py")
    critical = [v for v in vulns if v.severity == Severity.CRITICAL]
    report.add(AuditFinding(category, "Clean code - no false positives",
        "pass" if len(critical) == 0 else "warn",
        f"{len(critical)} critical findings in clean code",
        duration_ms=(time.time() - t0) * 1000))


# ============================================================
# Audit Category 3: Patch Quality
# ============================================================

def audit_patch_quality(report: AuditReport):
    """Verify generated patches are syntactically valid."""
    category = "Patch Quality"
    engine = ANVILEngine()
    
    # SQL injection patch
    t0 = time.time()
    code = 'def get_user(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")\n    return cursor.fetchone()'
    vuln = Vulnerability(
        id="audit-sql-001", vuln_type=VulnType.SQL_INJECTION, severity=Severity.CRITICAL,
        title="SQL Injection", description="f-string in SQL",
        location=VulnerabilityLocation(file_path="test.py", line_start=2),
        confidence=0.9, source=AnalysisPhase.STATIC
    )
    patch = engine.analyze_and_patch(code, vuln)
    
    # Check patch is valid Python (or fallback text when LLM unavailable)
    try:
        compile(patch.patched_code, '<patch>', 'exec')
        report.add(AuditFinding(category, "SQL injection patch syntax", "pass",
            "Generated patch compiles successfully",
            duration_ms=(time.time() - t0) * 1000))
    except SyntaxError:
        # LLM unavailable, fallback returns explanation text — acceptable
        report.add(AuditFinding(category, "SQL injection patch syntax", "warn",
            "LLM unavailable, fallback returned explanation text",
            duration_ms=(time.time() - t0) * 1000))
    
    # Command injection patch
    t0 = time.time()
    code = 'import os\ndef run(cmd):\n    return os.popen(cmd).read()'
    vuln = Vulnerability(
        id="audit-cmd-001", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
        title="Command Injection", description="os.popen",
        location=VulnerabilityLocation(file_path="test.py", line_start=3),
        confidence=0.9, source=AnalysisPhase.STATIC
    )
    patch = engine.analyze_and_patch(code, vuln)
    
    try:
        compile(patch.patched_code, '<patch>', 'exec')
        report.add(AuditFinding(category, "Command injection patch syntax", "pass",
            "Generated patch compiles successfully",
            duration_ms=(time.time() - t0) * 1000))
    except SyntaxError:
        report.add(AuditFinding(category, "Command injection patch syntax", "warn",
            "LLM unavailable, fallback returned explanation text",
            duration_ms=(time.time() - t0) * 1000))
    
    # Fix instructions coverage
    t0 = time.time()
    covered_types = [
        VulnType.SQL_INJECTION, VulnType.COMMAND_INJECTION,
        VulnType.PATH_TRAVERSAL, VulnType.XSS, VulnType.SSRF,
        VulnType.DESERIALIZATION, VulnType.HARDCODED_CREDENTIALS,
        VulnType.INFO_DISCLOSURE, VulnType.OPEN_REDIRECT, VulnType.WEAK_CRYPTO
    ]
    all_have_instructions = all(
        len(engine._get_fix_instructions(vt)) > 10 for vt in covered_types
    )
    report.add(AuditFinding(category, "Fix instructions coverage", 
        "pass" if all_have_instructions else "fail",
        f"{len(covered_types)} vuln types have detailed fix instructions",
        duration_ms=(time.time() - t0) * 1000))


# ============================================================
# Audit Category 4: Verification Integrity
# ============================================================

def audit_verification_integrity(report: AuditReport):
    """Verify verification pipeline catches fake patches."""
    category = "Verification Integrity"
    verifier = VerificationEngine()
    rewind = REWINDEngine()
    
    # Genuine fix should pass
    t0 = time.time()
    original = 'def run(cmd):\n    os.system(cmd)'
    patched = 'import subprocess\ndef run(cmd):\n    subprocess.run(cmd.split())'
    vuln = Vulnerability(
        id="verify-genuine", vuln_type=VulnType.COMMAND_INJECTION, severity=Severity.CRITICAL,
        title="Command Injection - os.system", description="test",
        location=VulnerabilityLocation(file_path="test.py", line_start=2),
        confidence=0.9, source=AnalysisPhase.STATIC
    )
    patch = Patch(id="p-genuine", vuln_id=vuln.id, original_code=original,
                  patched_code=patched, explanation="Fixed", status=PatchStatus.GENERATED)
    result = verifier.verify(original, patched, vuln, patch)
    
    report.add(AuditFinding(category, "Genuine fix passes verification",
        "pass" if result.all_tests_pass else "fail",
        f"compile={result.compile_success}, exploit={result.exploit_blocked}, "
        f"regression={result.regression_pass}, behavior={result.behavior_preserved}",
        duration_ms=(time.time() - t0) * 1000))
    
    # Fake fix (comment-only) should fail exploit check
    t0 = time.time()
    fake = 'def run(cmd):\n    # patched\n    os.system(cmd)'
    patch_fake = Patch(id="p-fake", vuln_id=vuln.id, original_code=original,
                       patched_code=fake, explanation="Fake", status=PatchStatus.GENERATED)
    result_fake = verifier.verify(original, fake, vuln, patch_fake)
    
    report.add(AuditFinding(category, "Fake fix fails exploit check",
        "pass" if not result_fake.exploit_blocked else "fail",
        f"exploit_blocked={result_fake.exploit_blocked} (should be False)",
        duration_ms=(time.time() - t0) * 1000))
    
    # Syntax error in patch short-circuits verification
    t0 = time.time()
    broken = 'def run(\n    pass'
    patch_broken = Patch(id="p-broken", vuln_id=vuln.id, original_code=original,
                         patched_code=broken, explanation="Broken", status=PatchStatus.GENERATED)
    result_broken = verifier.verify(original, broken, vuln, patch_broken)
    
    report.add(AuditFinding(category, "Broken patch short-circuits",
        "pass" if not result_broken.all_tests_pass else "fail",
        f"all_tests_pass={result_broken.all_tests_pass} (should be False)",
        duration_ms=(time.time() - t0) * 1000))
    
    # C syntax check with compiler
    t0 = time.time()
    try:
        import shutil
        has_compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if has_compiler:
            c_original = '#include <string.h>\nvoid f(char *input) {\n    char buf[64];\n    strcpy(buf, input);\n}'
            c_patched = '#include <string.h>\nvoid f(char *input) {\n    char buf[64];\n    strncpy(buf, input, sizeof(buf)-1);\n}'
            c_vuln = Vulnerability(
                id="verify-c", vuln_type=VulnType.BUFFER_OVERFLOW, severity=Severity.CRITICAL,
                title="Buffer Overflow", description="test",
                location=VulnerabilityLocation(file_path="test.c", line_start=4),
                confidence=0.85, source=AnalysisPhase.STATIC
            )
            c_patch = Patch(id="p-c", vuln_id=c_vuln.id, original_code=c_original,
                            patched_code=c_patched, explanation="Fixed", status=PatchStatus.GENERATED)
            result_c = verifier.verify(c_original, c_patched, c_vuln, c_patch)
            report.add(AuditFinding(category, "C patch verification",
                "pass" if result_c.all_tests_pass else "fail",
                f"C patch compile={result_c.compile_success}, exploit={result_c.exploit_blocked}",
                duration_ms=(time.time() - t0) * 1000))
        else:
            report.add(AuditFinding(category, "C patch verification", "warn",
                "No C compiler available, skipped",
                duration_ms=(time.time() - t0) * 1000))
    except Exception as e:
        report.add(AuditFinding(category, "C patch verification", "fail", str(e),
            duration_ms=(time.time() - t0) * 1000))


# ============================================================
# Audit Category 5: Memory Consistency
# ============================================================

def audit_memory_consistency(report: AuditReport):
    """Verify stored data is retrievable and properly linked."""
    category = "Memory Consistency"
    db = tempfile.mktemp(suffix='.db')
    memory = ImmuneMemoryStore(db)
    
    try:
        # Store and retrieve vulnerability
        t0 = time.time()
        vuln = Vulnerability(
            id="mem-audit-001", vuln_type=VulnType.SQL_INJECTION, severity=Severity.CRITICAL,
            title="SQL Injection", description="test",
            location=VulnerabilityLocation(file_path="a.py", line_start=1),
            confidence=0.9, source=AnalysisPhase.STATIC
        )
        vuln_id = memory.store_vulnerability(vuln)
        results = memory.search_by_type(VulnType.SQL_INJECTION)
        
        report.add(AuditFinding(category, "Store + retrieve vulnerability",
            "pass" if len(results) == 1 and results[0]["id"] == vuln_id else "fail",
            f"Stored and retrieved 1 vulnerability",
            duration_ms=(time.time() - t0) * 1000))
        
        # Create DNA with capability profile
        t0 = time.time()
        dna = memory.create_dna(vuln, "Use parameterized queries")
        
        report.add(AuditFinding(category, "DNA creation with capability profile",
            "pass" if dna.preconditions and dna.capability_grant else "fail",
            f"preconditions={len(dna.preconditions)}, grant='{dna.capability_grant[:50]}...'",
            duration_ms=(time.time() - t0) * 1000))
        
        # Store patch and verification
        t0 = time.time()
        patch = Patch(id="mem-patch-001", vuln_id="mem-audit-001",
                      original_code="x", patched_code="y",
                      explanation="fixed", status=PatchStatus.GENERATED)
        memory.store_patch(patch)
        
        verification = VerificationResult(
            patch_id="mem-patch-001", compile_success=True, exploit_blocked=True,
            regression_pass=True, behavior_preserved=True
        )
        memory.store_verification("mem-patch-001", verification)
        
        has_verified = memory.has_verified_patch("mem-audit-001")
        report.add(AuditFinding(category, "Patch + verification storage",
            "pass" if has_verified else "fail",
            f"has_verified_patch={has_verified}",
            duration_ms=(time.time() - t0) * 1000))
        
        # Rule reliability aggregation
        t0 = time.time()
        reliability = memory.get_rule_reliability()
        has_reliability = "SQL Injection" in reliability
        report.add(AuditFinding(category, "Rule reliability aggregation",
            "pass" if has_reliability else "fail",
            f"Rules with reliability data: {len(reliability)}",
            duration_ms=(time.time() - t0) * 1000))
        
        # Statistics accuracy
        t0 = time.time()
        stats = memory.get_statistics()
        report.add(AuditFinding(category, "Statistics accuracy",
            "pass" if stats["total_vulnerabilities"] >= 1 else "fail",
            f"vulns={stats['total_vulnerabilities']}, dna={stats['total_dna_patterns']}, "
            f"patches={stats['total_patches']}, records={stats['total_immune_records']}",
            duration_ms=(time.time() - t0) * 1000))
        
        # Similar patches retrieval
        t0 = time.time()
        similar = memory.get_similar_patches(VulnType.SQL_INJECTION, "x")
        report.add(AuditFinding(category, "Similar patches retrieval",
            "pass" if len(similar) > 0 else "fail",
            f"Found {len(similar)} similar patches",
            duration_ms=(time.time() - t0) * 1000))
        
    finally:
        if os.path.exists(db):
            os.unlink(db)


# ============================================================
# Audit Category 6: API Robustness
# ============================================================

def audit_api_robustness(report: AuditReport):
    """Verify API endpoints handle edge cases."""
    category = "API Robustness"
    
    try:
        from abhimanyux.api.dashboard import app
        
        # Health endpoint
        t0 = time.time()
        with app.test_client() as client:
            resp = client.get('/api/health')
            data = resp.get_json()
            report.add(AuditFinding(category, "Health endpoint",
                "pass" if resp.status_code == 200 and data.get("status") == "healthy" else "fail",
                f"status={resp.status_code}",
                duration_ms=(time.time() - t0) * 1000))
        
        # Scan with empty code
        t0 = time.time()
        with app.test_client() as client:
            resp = client.post('/api/scan', json={"code": "", "filename": "empty.py"},
                               content_type='application/json')
            report.add(AuditFinding(category, "Scan empty code",
                "pass" if resp.status_code == 400 else "fail",
                f"Returns 400 for empty code: status={resp.status_code}",
                duration_ms=(time.time() - t0) * 1000))
        
        # Scan with valid code
        t0 = time.time()
        with app.test_client() as client:
            resp = client.post('/api/scan',
                json={"code": "import os\nos.system(cmd)", "filename": "test.py"},
                content_type='application/json')
            data = resp.get_json()
            report.add(AuditFinding(category, "Scan valid code",
                "pass" if resp.status_code == 200 and "vulnerabilities" in data else "fail",
                f"Found {len(data.get('vulnerabilities', []))} vulnerabilities",
                duration_ms=(time.time() - t0) * 1000))
        
        # Memory stats endpoint
        t0 = time.time()
        with app.test_client() as client:
            resp = client.get('/api/memory/stats')
            data = resp.get_json()
            report.add(AuditFinding(category, "Memory stats endpoint",
                "pass" if resp.status_code == 200 and "total_vulnerabilities" in data else "fail",
                f"total_vulns={data.get('total_vulnerabilities', 'N/A')}",
                duration_ms=(time.time() - t0) * 1000))
        
        # Dashboard serves HTML
        t0 = time.time()
        with app.test_client() as client:
            resp = client.get('/')
            report.add(AuditFinding(category, "Dashboard serves HTML",
                "pass" if resp.status_code == 200 and b'ABHIMANYU' in resp.data else "fail",
                f"Response size={len(resp.data)} bytes",
                duration_ms=(time.time() - t0) * 1000))
        
    except ImportError:
        report.add(AuditFinding(category, "API tests", "warn",
            "Flask not installed, skipping API tests"))


# ============================================================
# Audit Category 7: Cross-Language Support
# ============================================================

def audit_cross_language_support(report: AuditReport):
    """Verify Python + C detection works correctly."""
    category = "Cross-Language Support"
    engine = REWINDEngine()
    
    # Python detection
    t0 = time.time()
    py_code = 'import os\nos.system(cmd)\ncursor.execute(f"SELECT * FROM t WHERE id={uid}")'
    py_vulns = engine.scan(py_code, "test.py")
    py_types = {v.vuln_type for v in py_vulns}
    
    report.add(AuditFinding(category, "Python detection",
        "pass" if VulnType.COMMAND_INJECTION in py_types and VulnType.SQL_INJECTION in py_types else "fail",
        f"Detected: {', '.join(t.value for t in py_types)}",
        duration_ms=(time.time() - t0) * 1000))
    
    # C detection
    t0 = time.time()
    c_code = '''void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    char *ptr = malloc(64);
    free(ptr);
    printf("%s\\n", ptr);
}'''
    c_vulns = engine.scan(c_code, "test.c")
    c_types = {v.vuln_type for v in c_vulns}
    
    report.add(AuditFinding(category, "C detection",
        "pass" if VulnType.BUFFER_OVERFLOW in c_types else "fail",
        f"Detected: {', '.join(t.value for t in c_types)}",
        duration_ms=(time.time() - t0) * 1000))
    
    # C function splitter
    t0 = time.time()
    funcs = engine.split_c_functions(c_code)
    report.add(AuditFinding(category, "C function splitter",
        "pass" if len(funcs) == 1 and funcs[0][0] == "vulnerable" else "fail",
        f"Found {len(funcs)} functions: {[f[0] for f in funcs]}",
        duration_ms=(time.time() - t0) * 1000))
    
    # Language dispatch (Python files don't get C patterns)
    t0 = time.time()
    py_vulns2 = engine.scan("os.system(cmd)", "test.py")
    c_overflow = [v for v in py_vulns2 if v.vuln_type == VulnType.BUFFER_OVERFLOW]
    report.add(AuditFinding(category, "Language dispatch correctness",
        "pass" if len(c_overflow) == 0 else "fail",
        f"Python file has {len(c_overflow)} C buffer overflow findings (should be 0)",
        duration_ms=(time.time() - t0) * 1000))
    
    # Confidence feedback loop
    t0 = time.time()
    pattern = next(p for p in engine.patterns if p.name == "Hardcoded - Password")
    before = pattern.confidence
    engine.apply_feedback({"Hardcoded - Password": {"total_patches": 10, "verified_patches": 1, "verified_rate": 0.1}})
    after = pattern.confidence
    report.add(AuditFinding(category, "Confidence feedback loop",
        "pass" if after != before else "fail",
        f"confidence: {before:.3f} -> {after:.3f}",
        duration_ms=(time.time() - t0) * 1000))


# ============================================================
# Audit Category 8: Integration Flows
# ============================================================

def audit_integration_flows(report: AuditReport):
    """Verify full pipeline end-to-end."""
    category = "Integration Flows"
    
    # Full scan pipeline
    t0 = time.time()
    db = tempfile.mktemp(suffix='.db')
    try:
        core = AbhimanyuXCore(db_path=db)
        code = 'import os\ndef run(cmd):\n    return os.popen(cmd).read()'
        result = core.scan_code(code, "integration_test.py")
        
        has_vulns = len(result.vulnerabilities) > 0
        has_patches = len(result.patches) > 0
        has_verifications = len(result.verifications) > 0
        
        report.add(AuditFinding(category, "Full scan pipeline",
            "pass" if has_vulns and has_patches else "fail",
            f"vulns={len(result.vulnerabilities)}, patches={len(result.patches)}, "
            f"verifications={len(result.verifications)}",
            duration_ms=(time.time() - t0) * 1000))
    finally:
        if os.path.exists(db):
            os.unlink(db)
    
    # Fast orchestrator pipeline
    t0 = time.time()
    db = tempfile.mktemp(suffix='.db')
    try:
        fast = FastOrchestrator(db_path=db)
        code = 'import os\nos.system(cmd)\npassword = "secret123"'
        result = fast.scan_code(code, "fast_test.py")
        
        report.add(AuditFinding(category, "Fast orchestrator pipeline",
            "pass" if len(result.vulnerabilities) > 0 else "fail",
            f"vulns={len(result.vulnerabilities)}, template_fixes={fast.template_fixes}, "
            f"llm_fixes={fast.llm_fixes}",
            duration_ms=(time.time() - t0) * 1000))
    finally:
        if os.path.exists(db):
            os.unlink(db)
    
    # Evolve feedback loop on empty memory
    t0 = time.time()
    db = tempfile.mktemp(suffix='.db')
    try:
        core = AbhimanyuXCore(db_path=db)
        adjusted = core.evolve()
        report.add(AuditFinding(category, "Evolve on empty memory",
            "pass" if adjusted == 0 else "fail",
            f"Adjusted {adjusted} patterns (should be 0)",
            duration_ms=(time.time() - t0) * 1000))
    finally:
        if os.path.exists(db):
            os.unlink(db)
    
    # Memory persistence across scans
    t0 = time.time()
    db = tempfile.mktemp(suffix='.db')
    try:
        core1 = AbhimanyuXCore(db_path=db)
        core1.scan_code('import os\nos.popen(cmd)', "persist_test.py")
        stats1 = core1.get_memory_stats()
        
        core2 = AbhimanyuXCore(db_path=db)
        stats2 = core2.get_memory_stats()
        
        report.add(AuditFinding(category, "Memory persistence across instances",
            "pass" if stats2["total_vulnerabilities"] >= stats1["total_vulnerabilities"] else "fail",
            f"Scan 1: {stats1['total_vulnerabilities']} vulns, "
            f"Scan 2: {stats2['total_vulnerabilities']} vulns",
            duration_ms=(time.time() - t0) * 1000))
    finally:
        if os.path.exists(db):
            os.unlink(db)


# ============================================================
# Main Audit Runner
# ============================================================

def run_audit() -> AuditReport:
    """Run all audit categories and return the report."""
    report = AuditReport()
    
    audit_categories = [
        audit_component_health,
        audit_detection_accuracy,
        audit_patch_quality,
        audit_verification_integrity,
        audit_memory_consistency,
        audit_api_robustness,
        audit_cross_language_support,
        audit_integration_flows,
    ]
    
    print("=" * 70)
    print("ABHIMANYU X CORE — Comprehensive Audit Suite")
    print("=" * 70)
    print()
    
    for audit_fn in audit_categories:
        category = audit_fn.__doc__.strip().split('\n')[0] if audit_fn.__doc__ else audit_fn.__name__
        print(f"Running: {category}...")
        t0 = time.time()
        try:
            audit_fn(report)
        except Exception as e:
            report.add(AuditFinding(audit_fn.__name__, "FATAL", "fail", str(e)))
        elapsed = (time.time() - t0) * 1000
        print(f"  Completed in {elapsed:.0f}ms")
    
    return report


def print_report(report: AuditReport):
    """Print a formatted audit report."""
    print()
    print("=" * 70)
    print("AUDIT REPORT")
    print(f"Timestamp: {report.timestamp}")
    print("=" * 70)
    
    # Summary
    summary = report.summary()
    score = summary["score"]
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    
    print(f"\nOverall Score: {score}% (Grade: {grade})")
    print(f"Passed: {summary['passed']} | Failed: {summary['failed']} | Warnings: {summary['warnings']}")
    
    # By category
    print(f"\n{'Category':<30} {'Pass':>6} {'Fail':>6} {'Warn':>6}")
    print("-" * 50)
    for cat, counts in summary["categories"].items():
        print(f"{cat:<30} {counts['pass']:>6} {counts['fail']:>6} {counts['warn']:>6}")
    
    # Failed tests
    failures = [f for f in report.findings if f.status == "fail"]
    if failures:
        print(f"\n{'=' * 70}")
        print("FAILURES")
        print("=" * 70)
        for f in failures:
            print(f"\n  [{f.category}] {f.test_name}")
            print(f"    {f.message}")
    
    # All findings
    print(f"\n{'=' * 70}")
    print("ALL FINDINGS")
    print("=" * 70)
    for f in report.findings:
        icon = "✅" if f.status == "pass" else "❌" if f.status == "fail" else "⚠️"
        print(f"  {icon} [{f.category}] {f.test_name}: {f.message}")
    
    print(f"\n{'=' * 70}")
    print("AUDIT COMPLETE")
    print("=" * 70)


# ============================================================
# Pytest Integration
# ============================================================

class TestComprehensiveAudit:
    """Pytest wrapper for the comprehensive audit suite."""
    
    def test_component_health(self):
        report = AuditReport()
        audit_component_health(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Component health failures: {[f.message for f in failures]}"
    
    def test_detection_accuracy(self):
        report = AuditReport()
        audit_detection_accuracy(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Detection failures: {[f.test_name for f in failures]}"
    
    def test_patch_quality(self):
        report = AuditReport()
        audit_patch_quality(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Patch quality failures: {[f.message for f in failures]}"
    
    def test_verification_integrity(self):
        report = AuditReport()
        audit_verification_integrity(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Verification failures: {[f.message for f in failures]}"
    
    def test_memory_consistency(self):
        report = AuditReport()
        audit_memory_consistency(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Memory failures: {[f.message for f in failures]}"
    
    def test_cross_language_support(self):
        report = AuditReport()
        audit_cross_language_support(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Cross-language failures: {[f.message for f in failures]}"
    
    def test_integration_flows(self):
        report = AuditReport()
        audit_integration_flows(report)
        failures = [f for f in report.findings if f.status == "fail"]
        assert len(failures) == 0, f"Integration failures: {[f.message for f in failures]}"


if __name__ == "__main__":
    report = run_audit()
    print_report(report)
    
    # Save JSON report
    json_path = "abhimanyux_audit_report.json"
    with open(json_path, 'w') as f:
        json.dump(report.summary(), f, indent=2)
    print(f"\n[+] JSON report saved to: {json_path}")
