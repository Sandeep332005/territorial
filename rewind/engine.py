"""
ABHIMANYU X CORE - REWIND Engine
Static Analysis & Security Regression Detection

Detects vulnerabilities through:
- Pattern matching (regex-based)
- AST analysis
- Taint analysis (simplified)
- Known vulnerability signatures
"""

import re
import ast
import hashlib
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityLocation, Severity, VulnType, AnalysisPhase
)


@dataclass
class Pattern:
    """Vulnerability detection pattern"""
    name: str
    vuln_type: VulnType
    severity: Severity
    pattern: str
    description: str
    cwe_id: str
    confidence: float = 0.8


class REWINDEngine:
    """
    REWIND - Static Analysis Engine
    
    Detects security vulnerabilities through pattern matching,
    AST analysis, and known vulnerability signatures.
    """
    
    C_EXTENSIONS = ('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp')

    def __init__(self):
        self.patterns = self._load_patterns()
        self.c_patterns = self._load_c_patterns()
        self.scan_count = 0

    def _load_c_patterns(self) -> List[Pattern]:
        """Load vulnerability detection patterns for C/C++"""
        return [
            Pattern(
                name="Buffer Overflow - strcpy",
                vuln_type=VulnType.BUFFER_OVERFLOW,
                severity=Severity.CRITICAL,
                pattern=r'\bstrcpy\s*\(',
                description="strcpy() performs no bounds checking and can overflow the destination buffer",
                cwe_id="CWE-120",
                confidence=0.85
            ),
            Pattern(
                name="Buffer Overflow - strcat",
                vuln_type=VulnType.BUFFER_OVERFLOW,
                severity=Severity.HIGH,
                pattern=r'\bstrcat\s*\(',
                description="strcat() performs no bounds checking and can overflow the destination buffer",
                cwe_id="CWE-120",
                confidence=0.8
            ),
            Pattern(
                name="Buffer Overflow - gets",
                vuln_type=VulnType.BUFFER_OVERFLOW,
                severity=Severity.CRITICAL,
                pattern=r'\bgets\s*\(',
                description="gets() cannot limit input length and is inherently unsafe",
                cwe_id="CWE-242",
                confidence=0.95
            ),
            Pattern(
                name="Buffer Overflow - unbounded sprintf",
                vuln_type=VulnType.BUFFER_OVERFLOW,
                severity=Severity.CRITICAL,
                pattern=r'\bsprintf\s*\(',
                description="sprintf() writes into a fixed-size buffer with no bounds checking; use snprintf() instead",
                cwe_id="CWE-121",
                confidence=0.8
            ),
            Pattern(
                name="Format String - variable format argument",
                vuln_type=VulnType.FORMAT_STRING,
                severity=Severity.CRITICAL,
                pattern=r'\b(?:printf|fprintf)\s*\(\s*[a-zA-Z_]\w*\s*\)',
                description="printf()-family call whose format string is a variable rather than a literal, allowing format-string attacks",
                cwe_id="CWE-134",
                confidence=0.85
            ),
            Pattern(
                name="Command Injection - system",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'\bsystem\s*\(',
                description="system() executes a shell command that may be built from untrusted input",
                cwe_id="CWE-78",
                confidence=0.85
            ),
            Pattern(
                name="Command Injection - popen",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'\bpopen\s*\(',
                description="popen() executes a shell command that may be built from untrusted input",
                cwe_id="CWE-78",
                confidence=0.85
            ),
        ]

    def _load_patterns(self) -> List[Pattern]:
        """Load vulnerability detection patterns"""
        return [
            # SQL Injection patterns
            Pattern(
                name="SQL Injection - f-string",
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'(execute|cursor\.execute)\s*\(\s*[f"\'].*\{.*\}',
                description="SQL query constructed using f-string with user input",
                cwe_id="CWE-89",
                confidence=0.95
            ),
            Pattern(
                name="SQL Injection - format",
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'(execute|cursor\.execute)\s*\(\s*.*\.format\(',
                description="SQL query constructed using .format() with user input",
                cwe_id="CWE-89",
                confidence=0.9
            ),
            Pattern(
                name="SQL Injection - concatenation",
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'(execute|cursor\.execute)\s*\(\s*["\'].*\+\s*\w+',
                description="SQL query constructed using string concatenation",
                cwe_id="CWE-89",
                confidence=0.85
            ),
            Pattern(
                name="SQL Injection - % formatting",
                vuln_type=VulnType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'(execute|cursor\.execute)\s*\(\s*["\'].*%\s*\(',
                description="SQL query constructed using % formatting",
                cwe_id="CWE-89",
                confidence=0.85
            ),
            
            # Command Injection patterns
            Pattern(
                name="Command Injection - os.system",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'os\.system\s*\(',
                description="os.system() called with potential user input",
                cwe_id="CWE-78",
                confidence=0.9
            ),
            Pattern(
                name="Command Injection - os.popen",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'os\.popen\s*\(',
                description="os.popen() called with potential user input",
                cwe_id="CWE-78",
                confidence=0.9
            ),
            Pattern(
                name="Command Injection - subprocess shell=True",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
                description="subprocess called with shell=True",
                cwe_id="CWE-78",
                confidence=0.85
            ),
            Pattern(
                name="Command Injection - eval",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'\beval\s*\(',
                description="eval() can execute arbitrary code",
                cwe_id="CWE-95",
                confidence=0.9
            ),
            Pattern(
                name="Command Injection - exec",
                vuln_type=VulnType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                pattern=r'\bexec\s*\(',
                description="exec() can execute arbitrary code",
                cwe_id="CWE-95",
                confidence=0.9
            ),
            
            # Path Traversal patterns
            Pattern(
                name="Path Traversal - open with user input",
                vuln_type=VulnType.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                pattern=r'open\s*\(\s*["\']\/.*\{',
                description="File open with potential path traversal",
                cwe_id="CWE-22",
                confidence=0.85
            ),
            Pattern(
                name="Path Traversal - unsanitized path",
                vuln_type=VulnType.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                pattern=r'open\s*\([^)]*\+[^)]*\)',
                description="File open with concatenated path",
                cwe_id="CWE-22",
                confidence=0.8
            ),
            
            # Insecure Deserialization
            Pattern(
                name="Deserialization - pickle.loads",
                vuln_type=VulnType.DESERIALIZATION,
                severity=Severity.CRITICAL,
                pattern=r'pickle\.loads?\s*\(',
                description="Pickle deserialization can execute arbitrary code",
                cwe_id="CWE-502",
                confidence=0.95
            ),
            Pattern(
                name="Deserialization - yaml.load",
                vuln_type=VulnType.DESERIALIZATION,
                severity=Severity.HIGH,
                pattern=r'yaml\.load\s*\((?!.*Loader)',
                description="YAML load without safe Loader",
                cwe_id="CWE-502",
                confidence=0.9
            ),
            
            # SSRF patterns
            Pattern(
                name="SSRF - requests.get with user input",
                vuln_type=VulnType.SSRF,
                severity=Severity.HIGH,
                pattern=r'requests\.(get|post|put|delete)\s*\([^)]*\+',
                description="HTTP request with concatenated URL",
                cwe_id="CWE-918",
                confidence=0.85
            ),
            
            # Hardcoded Credentials
            Pattern(
                name="Hardcoded - API key",
                vuln_type=VulnType.HARDCODED_CREDENTIALS,
                severity=Severity.MEDIUM,
                pattern=r'(api_key|apikey|API_KEY)\s*=\s*["\'][^"\']{8,}["\']',
                description="Hardcoded API key in source code",
                cwe_id="CWE-798",
                confidence=0.8
            ),
            Pattern(
                name="Hardcoded - Password",
                vuln_type=VulnType.HARDCODED_CREDENTIALS,
                severity=Severity.MEDIUM,
                pattern=r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
                description="Hardcoded password in source code",
                cwe_id="CWE-798",
                confidence=0.75
            ),
            
            # Information Disclosure
            Pattern(
                name="Info Disclosure - debug mode",
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                pattern=r'debug\s*=\s*True',
                description="Debug mode enabled (potential info disclosure)",
                cwe_id="CWE-215",
                confidence=0.7
            ),
            Pattern(
                name="Info Disclosure - env vars",
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                pattern=r'os\.environ',
                description="Environment variables exposed",
                cwe_id="CWE-200",
                confidence=0.6
            ),
            
            # Open Redirect
            Pattern(
                name="Open Redirect - meta refresh",
                vuln_type=VulnType.OPEN_REDIRECT,
                severity=Severity.MEDIUM,
                pattern=r'meta.*http-equiv.*refresh.*url=',
                description="Open redirect via meta refresh",
                cwe_id="CWE-601",
                confidence=0.8
            ),
            Pattern(
                name="Open Redirect - redirect with user input",
                vuln_type=VulnType.OPEN_REDIRECT,
                severity=Severity.MEDIUM,
                pattern=r'redirect\([^)]*\+',
                description="Redirect with concatenated URL",
                cwe_id="CWE-601",
                confidence=0.85
            ),
            
            # Weak Crypto
            Pattern(
                name="Weak Crypto - random.randint",
                vuln_type=VulnType.WEAK_CRYPTO,
                severity=Severity.LOW,
                pattern=r'random\.randint\s*\(',
                description="Using random.randint for security-sensitive values",
                cwe_id="CWE-330",
                confidence=0.7
            ),
            
            # XSS patterns
            Pattern(
                name="XSS - render_template_string",
                vuln_type=VulnType.XSS,
                severity=Severity.HIGH,
                pattern=r'render_template_string\s*\(',
                description="Potential XSS via render_template_string",
                cwe_id="CWE-79",
                confidence=0.8
            ),
            Pattern(
                name="XSS - direct HTML response",
                vuln_type=VulnType.XSS,
                severity=Severity.HIGH,
                pattern=r'return\s*f["\']<',
                description="Direct HTML response with f-string (potential XSS)",
                cwe_id="CWE-79",
                confidence=0.75
            ),
        ]
    
    def scan(self, code: str, filename: str = "unknown") -> List[Vulnerability]:
        """
        Perform static analysis on source code
        
        Args:
            code: Source code to analyze
            filename: Name of the file being analyzed
            
        Returns:
            List of discovered vulnerabilities
        """
        self.scan_count += 1
        vulnerabilities = []
        is_c = filename.endswith(self.C_EXTENSIONS)

        # Pattern-based scanning
        patterns = self.c_patterns if is_c else self.patterns
        vulns = self._pattern_scan(code, filename, patterns)
        vulnerabilities.extend(vulns)

        # AST-based scanning (Python only)
        if filename.endswith('.py'):
            ast_vulns = self._ast_scan(code, filename)
            vulnerabilities.extend(ast_vulns)
        elif is_c:
            vulnerabilities.extend(self._c_function_scan(code, filename))

        # Deduplicate
        vulnerabilities = self._deduplicate(vulnerabilities)

        return vulnerabilities

    def _pattern_scan(self, code: str, filename: str, patterns: List[Pattern]) -> List[Vulnerability]:
        """Scan code using regex patterns"""
        vulnerabilities = []
        lines = code.split('\n')

        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern.pattern, line, re.IGNORECASE):
                    vuln = Vulnerability(
                        id=hashlib.sha256(
                            f"{filename}:{line_num}:{pattern.name}".encode()
                        ).hexdigest()[:16],
                        vuln_type=pattern.vuln_type,
                        severity=pattern.severity,
                        title=pattern.name,
                        description=pattern.description,
                        location=VulnerabilityLocation(
                            file_path=filename,
                            line_start=line_num,
                            code_snippet=line.strip()
                        ),
                        cwe_id=pattern.cwe_id,
                        confidence=pattern.confidence,
                        source=AnalysisPhase.STATIC,
                        raw_analysis=f"Pattern: {pattern.name}\nMatched: {line.strip()}"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _ast_scan(self, code: str, filename: str) -> List[Vulnerability]:
        """Scan Python code using AST analysis"""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                        if func_name in ('system', 'popen', 'execute'):
                            # Check if argument might be user-controlled
                            if node.args:
                                vuln = Vulnerability(
                                    id=hashlib.sha256(
                                        f"{filename}:ast:{node.lineno}:{func_name}".encode()
                                    ).hexdigest()[:16],
                                    vuln_type=VulnType.COMMAND_INJECTION,
                                    severity=Severity.HIGH,
                                    title=f"Dangerous function call: {func_name}",
                                    description=f"Function {func_name}() may execute arbitrary commands",
                                    location=VulnerabilityLocation(
                                        file_path=filename,
                                        line_start=node.lineno
                                    ),
                                    confidence=0.6,
                                    source=AnalysisPhase.STATIC
                                )
                                vulnerabilities.append(vuln)
                    
                    elif isinstance(node.func, ast.Name):
                        if node.func.id in ('eval', 'exec'):
                            vuln = Vulnerability(
                                id=hashlib.sha256(
                                    f"{filename}:ast:{node.lineno}:{node.func.id}".encode()
                                ).hexdigest()[:16],
                                vuln_type=VulnType.COMMAND_INJECTION,
                                severity=Severity.CRITICAL,
                                title=f"Dynamic code execution: {node.func.id}",
                                description=f"{node.func.id}() can execute arbitrary code",
                                location=VulnerabilityLocation(
                                    file_path=filename,
                                    line_start=node.lineno
                                ),
                                confidence=0.9,
                                source=AnalysisPhase.STATIC
                            )
                            vulnerabilities.append(vuln)
        
        except SyntaxError:
            # Not valid Python, skip AST analysis
            pass

        return vulnerabilities

    def split_c_functions(self, code: str) -> List[Tuple[str, int, int, str]]:
        """
        Approximate C/C++ function splitter using brace-depth tracking.

        Assumes a function signature occupies its own line ending in '{' (K&R)
        or immediately followed by a line containing only '{' (Allman). Does not
        parse the C grammar, so multi-line signatures or macro-generated
        functions are skipped rather than misattributed.

        Returns (function_name, signature_line, body_start_line, body_text),
        all line numbers 1-indexed.
        """
        lines = code.split('\n')
        n = len(lines)
        sig_re = re.compile(r'^[A-Za-z_][\w\s\*]*\b(\w+)\s*\([^;{}]*\)\s*\{?\s*$')
        control_keywords = {'if', 'for', 'while', 'switch', 'else', 'do', 'return'}
        functions = []
        i = 0
        while i < n:
            stripped = lines[i].strip()
            m = sig_re.match(stripped)
            if m and m.group(1) not in control_keywords:
                brace_line = i if '{' in lines[i] else None
                if brace_line is None:
                    j = i + 1
                    while j < n and '{' not in lines[j]:
                        j += 1
                    if j >= n:
                        i += 1
                        continue
                    brace_line = j
                depth = 0
                k = brace_line
                while k < n:
                    depth += lines[k].count('{') - lines[k].count('}')
                    if depth == 0:
                        break
                    k += 1
                body = '\n'.join(lines[brace_line:k + 1])
                functions.append((m.group(1), i + 1, brace_line + 1, body))
                i = k + 1
            else:
                i += 1
        return functions

    def _c_function_scan(self, code: str, filename: str) -> List[Vulnerability]:
        """Function-body heuristics for C/C++ vulnerability classes that a
        single-line regex can't see (use-after-free, leaks, null derefs,
        unchecked arithmetic, traversal via a built path)."""
        vulnerabilities = []
        try:
            for name, _sig_line, body_start, body in self.split_c_functions(code):
                vulnerabilities.extend(self._check_use_after_free(name, body_start, body, filename))
                vulnerabilities.extend(self._check_memory_leak(name, body_start, body, filename))
                vulnerabilities.extend(self._check_null_deref(name, body_start, body, filename))
                vulnerabilities.extend(self._check_integer_overflow(name, body_start, body, filename))
                vulnerabilities.extend(self._check_path_traversal_fopen(name, body_start, body, filename))
            vulnerabilities.extend(self._check_race_condition(code, filename))
        except Exception:
            # Heuristics are best-effort; malformed/unusual C source should not
            # abort the rest of the scan.
            pass
        return vulnerabilities

    def _check_use_after_free(self, name: str, body_start: int, body: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = body.split('\n')
        free_re = re.compile(r'\bfree\s*\(\s*(\w+)\s*\)')
        for idx, line in enumerate(lines):
            m = free_re.search(line)
            if not m:
                continue
            var = m.group(1)
            for j in range(idx + 1, len(lines)):
                later = lines[j]
                if re.search(rf'^\s*{re.escape(var)}\s*=\s*(?!=)', later):
                    break  # reassigned before reuse
                if re.search(rf'\b{re.escape(var)}\b', later):
                    vulnerabilities.append(Vulnerability(
                        id=hashlib.sha256(f"{filename}:{name}:uaf:{var}:{idx}".encode()).hexdigest()[:16],
                        vuln_type=VulnType.USE_AFTER_FREE,
                        severity=Severity.CRITICAL,
                        title=f"Use-After-Free - '{var}' used after free() in {name}()",
                        description=f"'{var}' is freed and then referenced again in {name}() without reassignment",
                        location=VulnerabilityLocation(
                            file_path=filename, line_start=body_start + j,
                            function_name=name, code_snippet=later.strip()
                        ),
                        cwe_id="CWE-416",
                        confidence=0.6,
                        source=AnalysisPhase.STATIC,
                    ))
                    break
        return vulnerabilities

    def _check_memory_leak(self, name: str, body_start: int, body: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = body.split('\n')
        alloc_re = re.compile(r'\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|strdup)\s*\(')
        for idx, line in enumerate(lines):
            m = alloc_re.search(line)
            if not m:
                continue
            var = m.group(1)
            freed = any(re.search(rf'\bfree\s*\(\s*{re.escape(var)}\s*\)', l) for l in lines)
            returned = any(re.search(rf'\breturn\s+{re.escape(var)}\b', l) for l in lines)
            if not freed and not returned:
                vulnerabilities.append(Vulnerability(
                    id=hashlib.sha256(f"{filename}:{name}:leak:{var}:{idx}".encode()).hexdigest()[:16],
                    vuln_type=VulnType.MEMORY_LEAK,
                    severity=Severity.HIGH,
                    title=f"Memory Leak - '{var}' allocated but never freed in {name}()",
                    description=f"'{var}' is allocated in {name}() but is never passed to free() or returned to the caller",
                    location=VulnerabilityLocation(
                        file_path=filename, line_start=body_start + idx,
                        function_name=name, code_snippet=line.strip()
                    ),
                    cwe_id="CWE-401",
                    confidence=0.55,
                    source=AnalysisPhase.STATIC,
                ))
        return vulnerabilities

    def _check_null_deref(self, name: str, body_start: int, body: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = body.split('\n')
        null_init_re = re.compile(r'\*\s*(\w+)\s*=\s*NULL\s*;')
        use_re = re.compile(r'(?:strcpy|strcat|sprintf|memcpy|memmove|strlen|\*)\s*\(?\s*(\w+)\b')
        for idx, line in enumerate(lines):
            m = null_init_re.search(line)
            if not m:
                continue
            var = m.group(1)
            conditionally_assigned = False
            guarded = False
            for j in range(idx + 1, len(lines)):
                l = lines[j]
                if re.search(rf'\bif\s*\([^)]*\b{re.escape(var)}\b', l):
                    guarded = True
                if re.search(rf'^\s*{re.escape(var)}\s*=\s*(?!NULL)', l):
                    conditionally_assigned = True
                use_m = use_re.search(l)
                if conditionally_assigned and use_m and use_m.group(1) == var and not guarded:
                    vulnerabilities.append(Vulnerability(
                        id=hashlib.sha256(f"{filename}:{name}:nullderef:{var}:{j}".encode()).hexdigest()[:16],
                        vuln_type=VulnType.NULL_POINTER_DEREFERENCE,
                        severity=Severity.HIGH,
                        title=f"Null Pointer Dereference - '{var}' may be NULL when used in {name}()",
                        description=f"'{var}' is initialized to NULL and only conditionally assigned a real value in {name}(); it is later dereferenced without a NULL check",
                        location=VulnerabilityLocation(
                            file_path=filename, line_start=body_start + j,
                            function_name=name, code_snippet=l.strip()
                        ),
                        cwe_id="CWE-476",
                        confidence=0.55,
                        source=AnalysisPhase.STATIC,
                    ))
                    break
        return vulnerabilities

    def _check_integer_overflow(self, name: str, body_start: int, body: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        if 'INT_MAX' in body or 'INT_MIN' in body or '__builtin_' in body:
            return vulnerabilities
        lines = body.split('\n')
        mul_re = re.compile(r'return\s+\w+\s*[\*\+]\s*\w+\s*;')
        for idx, line in enumerate(lines):
            m = mul_re.search(line)
            if not m:
                continue
            vulnerabilities.append(Vulnerability(
                id=hashlib.sha256(f"{filename}:{name}:intoverflow:{idx}".encode()).hexdigest()[:16],
                vuln_type=VulnType.INTEGER_OVERFLOW,
                severity=Severity.HIGH,
                title=f"Integer Overflow - unchecked arithmetic in {name}()",
                description=f"{name}() computes '{m.group(0).strip()}' without checking the operands against INT_MAX/INT_MIN",
                location=VulnerabilityLocation(
                    file_path=filename, line_start=body_start + idx,
                    function_name=name, code_snippet=line.strip()
                ),
                cwe_id="CWE-190",
                confidence=0.5,
                source=AnalysisPhase.STATIC,
            ))
        return vulnerabilities

    def _check_path_traversal_fopen(self, name: str, body_start: int, body: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        sanitized = '..' in body and ('strstr' in body or 'strchr' in body)
        lines = body.split('\n')
        build_re = re.compile(r'sprintf\s*\(\s*(\w+)\s*,')
        for idx, line in enumerate(lines):
            m = build_re.search(line)
            if not m:
                continue
            var = m.group(1)
            for j in range(idx + 1, len(lines)):
                if re.search(rf'\bfopen\s*\(\s*{re.escape(var)}\b', lines[j]):
                    if not sanitized:
                        vulnerabilities.append(Vulnerability(
                            id=hashlib.sha256(f"{filename}:{name}:pathtraversal:{var}:{j}".encode()).hexdigest()[:16],
                            vuln_type=VulnType.PATH_TRAVERSAL,
                            severity=Severity.HIGH,
                            title=f"Path Traversal - '{var}' built with sprintf() then passed to fopen() in {name}()",
                            description=f"'{var}' is built by concatenating input via sprintf() and opened with fopen() in {name}() with no '../' sanitization",
                            location=VulnerabilityLocation(
                                file_path=filename, line_start=body_start + j,
                                function_name=name, code_snippet=lines[j].strip()
                            ),
                            cwe_id="CWE-22",
                            confidence=0.6,
                            source=AnalysisPhase.STATIC,
                        ))
                    break
        return vulnerabilities

    def _check_race_condition(self, code: str, filename: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = code.split('\n')
        global_re = re.compile(r'^\s*(?:static\s+)?(?:int|long|unsigned|float|double|char)\s+(\w+)\s*=\s*[\w.]+\s*;\s*$')
        globals_found = {}
        depth = 0
        for idx, line in enumerate(lines):
            if depth == 0:
                m = global_re.match(line)
                if m:
                    globals_found[m.group(1)] = idx
            depth += line.count('{') - line.count('}')
        if not globals_found:
            return vulnerabilities
        has_lock_primitive = bool(re.search(r'pthread_mutex|atomic_|__sync_|std::mutex|lock_guard', code))
        if has_lock_primitive:
            return vulnerabilities
        for var, decl_idx in globals_found.items():
            mod_re = re.compile(rf'\b{re.escape(var)}\s*(\+\+|--|[+\-*/]=)')
            for idx, line in enumerate(lines):
                if idx == decl_idx:
                    continue
                if mod_re.search(line):
                    vulnerabilities.append(Vulnerability(
                        id=hashlib.sha256(f"{filename}:race:{var}:{idx}".encode()).hexdigest()[:16],
                        vuln_type=VulnType.RACE_CONDITION,
                        severity=Severity.MEDIUM,
                        title=f"Race Condition - unsynchronized access to shared variable '{var}'",
                        description=f"Global variable '{var}' is modified with no visible locking primitive (pthread_mutex/atomic), which is unsafe under concurrent access",
                        location=VulnerabilityLocation(file_path=filename, line_start=idx + 1, code_snippet=line.strip()),
                        cwe_id="CWE-362",
                        confidence=0.45,
                        source=AnalysisPhase.STATIC,
                    ))
        return vulnerabilities

    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            key = (vuln.vuln_type, vuln.location.line_start, vuln.location.file_path)
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def apply_feedback(self, reliability: Dict[str, Dict], min_samples: int = 3,
                        blend_weight: float = 0.3) -> int:
        """
        Recalibrate each pattern's static confidence toward its empirical
        verified-patch rate (from ImmuneMemoryStore.get_rule_reliability),
        closing detect -> patch -> verify -> learn into an actual loop
        instead of a one-way pipeline whose confidence scores never move
        from their initial hand-tuned values.

        Blends rather than replaces: `blend_weight` bounds how much a single
        call can move a pattern's confidence, so a handful of unlucky or
        lucky verifications can't swing its score outright, and a pattern
        with fewer than `min_samples` verified patches is left untouched.
        This only ever adjusts the *confidence* reported alongside a
        finding — it never disables a pattern or removes it from scanning,
        so recall is unaffected even if a rule's track record is poor.

        Returns the number of patterns actually adjusted.
        """
        adjusted = 0
        for pattern in self.patterns + self.c_patterns:
            stats = reliability.get(pattern.name)
            if not stats or stats["total_patches"] < min_samples:
                continue
            target = stats["verified_rate"]
            pattern.confidence = (1 - blend_weight) * pattern.confidence + blend_weight * target
            adjusted += 1
        return adjusted

    def get_stats(self) -> Dict[str, int]:
        """Get scan statistics"""
        return {
            "total_scans": self.scan_count,
            "patterns_loaded": len(self.patterns) + len(self.c_patterns)
        }
