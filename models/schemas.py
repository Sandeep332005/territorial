"""
ABHIMANYU X CORE - Data Models
Pydantic schemas for the autonomous cyber reasoning system
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    WEAK_CRYPTO = "weak_crypto"
    INFO_DISCLOSURE = "info_disclosure"
    OPEN_REDIRECT = "open_redirect"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    OTHER = "other"


class AnalysisPhase(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    FUZZING = "fuzzing"
    LLM_REASONING = "llm_reasoning"
    VERIFICATION = "verification"


class PatchStatus(str, Enum):
    GENERATED = "generated"
    VERIFIED = "verified"
    REJECTED = "rejected"
    APPLIED = "applied"


# ==================== Vulnerability Models ====================

class VulnerabilityLocation(BaseModel):
    """Location of a vulnerability in source code"""
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    column: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: Optional[str] = None


class Vulnerability(BaseModel):
    """Discovered vulnerability"""
    id: str
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    location: VulnerabilityLocation
    exploit_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    source: AnalysisPhase
    raw_analysis: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExploitEvidence(BaseModel):
    """Evidence of successful exploitation"""
    vuln_id: str
    exploit_code: str
    crash_output: Optional[str] = None
    stack_trace: Optional[str] = None
    sanitizer_output: Optional[str] = None
    reproduction_steps: List[str] = []
    success: bool


# ==================== Patch Models ====================

class Patch(BaseModel):
    """Generated security patch"""
    id: str
    vuln_id: str
    original_code: str
    patched_code: str
    explanation: str
    status: PatchStatus = PatchStatus.GENERATED
    verification_results: Optional[Dict[str, Any]] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==================== Verification Models ====================

class VerificationResult(BaseModel):
    """Result of patch verification"""
    patch_id: str
    compile_success: bool = False
    exploit_blocked: bool = False
    regression_pass: bool = False
    behavior_preserved: bool = False
    all_tests_pass: bool = False
    details: Dict[str, Any] = {}
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==================== Immune Memory Models ====================

class VulnerabilityDNA(BaseModel):
    """Immutable vulnerability pattern for immune memory (a "Weakness
    Capability Atom"): binds a vuln type to what must hold for it to be
    exploitable, what an attacker gains from it, and which other atoms
    share its exploit context — so memory can reason about which
    vulnerability classes compose rather than treating each CWE in
    isolation."""
    id: str
    vuln_type: VulnType
    pattern_signature: str  # AST/hash pattern
    description: str
    detection_rules: List[str] = []
    fix_strategies: List[str] = []
    regression_seeds: List[str] = []
    preconditions: List[str] = []
    capability_grant: str = ""
    related_dna_ids: List[str] = []
    occurrences: int = 0
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ImmuneRecord(BaseModel):
    """Complete immune memory record for a vulnerability"""
    vulnerability: Vulnerability
    exploit_evidence: Optional[ExploitEvidence] = None
    patch: Optional[Patch] = None
    verification: Optional[VerificationResult] = None
    dna: Optional[VulnerabilityDNA] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==================== Scan Models ====================

class ScanRequest(BaseModel):
    """Request to scan a codebase"""
    target_path: str
    language: str = "python"
    scan_depth: str = "full"  # quick, standard, full
    enable_fuzzing: bool = True
    enable_llm: bool = True


class ScanResult(BaseModel):
    """Complete scan result"""
    scan_id: str
    target_path: str
    vulnerabilities: List[Vulnerability] = []
    patches: List[Patch] = []
    verifications: List[VerificationResult] = []
    immune_records: List[ImmuneRecord] = []
    summary: Dict[str, Any] = {}
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


# ==================== API Models ====================

class HealthResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    version: str = "0.1.0"
    components: Dict[str, bool] = {}


class AnalyzeRequest(BaseModel):
    """Request body for code analysis"""
    code: str
    filename: str = "untitled.py"
    language: str = "python"
    analysis_type: str = "full"  # static, dynamic, full


class AnalyzeResponse(BaseModel):
    """Response from code analysis"""
    scan_id: str
    vulnerabilities: List[Vulnerability]
    summary: Dict[str, Any]


class PatchRequest(BaseModel):
    """Request to generate a patch"""
    vulnerability_id: str
    code: str
    vulnerability_info: str


class PatchResponse(BaseModel):
    """Response from patch generation"""
    patch_id: str
    patched_code: str
    explanation: str
    status: PatchStatus
