"""
ABHIMANYU X CORE - ANVIL Engine
LLM-Based Patch Generation & Root Cause Analysis

Uses local LLM (Qwen-Coder / DeepSeek-Coder) to:
- Understand vulnerability root cause
- Generate minimal, targeted patches
- Explain the security fix
- Create regression test suggestions
"""

import os
import re
import json
import uuid
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from abhimanyux.models.schemas import (
    Vulnerability, Patch, PatchStatus, Severity, VulnType
)


@dataclass
class LLMConfig:
    """Configuration for LLM interaction"""
    provider: str = "local"  # local, gemini, deepseek, claude
    model: str = "dolphin-llama3:8b"
    api_url: str = "http://localhost:11434/api/generate"
    api_key: str = ""
    temperature: float = 0.2
    max_tokens: int = 4096
    use_local: bool = False
    local_model: str = "dolphin-llama3:8b"
    timeout: int = 60  # per-LLM-call wall-clock budget, in seconds
    enable_judge_loop: bool = True
    max_judge_iterations: int = 1
    judge_score_threshold: int = 8


class ANVILEngine:
    """
    ANVIL - LLM-Based Patch Generation Engine
    
    Responsibilities:
    - Root cause analysis of vulnerabilities
    - Minimal patch generation
    - Security fix explanation
    - Regression test suggestions
    """
    
    def __init__(self, config: Optional[LLMConfig] = None, memory=None):
        self.config = config or LLMConfig()
        self.memory = memory  # optional ImmuneMemoryStore, for retrieval-grounded generation
        self.patch_count = 0
        self.patches = {}

    def analyze_and_patch(self, code: str, vulnerability: Vulnerability) -> Patch:
        """
        Analyze vulnerability and generate a patch

        Args:
            code: Original source code
            vulnerability: Discovered vulnerability

        Returns:
            Generated Patch with fix and explanation
        """
        self.patch_count += 1

        # Single combined prompt for efficiency with local models
        fix_instructions = self._get_fix_instructions(vulnerability.vuln_type)
        similar_patch = self._retrieve_similar_patch(vulnerability, code)

        combined_prompt = f"""You are a security expert. Analyze and fix this vulnerability.

VULNERABILITY: {vulnerability.vuln_type.value}
SEVERITY: {vulnerability.severity.value}
DESCRIPTION: {vulnerability.description}
LINE: {vulnerability.location.line_start}
CODE SNIPPET:
```\n{vulnerability.location.code_snippet or 'Not available'}
```

Fix guidelines:
{fix_instructions}
{self._format_similar_patch(similar_patch)}
Respond in this EXACT format:

ROOT CAUSE:
<2-3 sentence root cause analysis>

PATCHED CODE:
```python
<complete patched code>
```

EXPLANATION:
<what changed and why>"""

        response = self._call_llm("You are a security expert.", combined_prompt)

        # Parse the combined response
        root_cause = self._extract_section(response, "ROOT CAUSE:", "PATCHED CODE:")
        patched_code = self._extract_code(response)
        explanation = self._extract_section(response, "EXPLANATION:", None)

        # Fallback if parsing fails
        if not root_cause:
            root_cause = self._analyze_root_cause(code, vulnerability)
        if not patched_code or patched_code == code:
            patched_code = self._generate_patch(code, vulnerability, root_cause)
        if not explanation:
            explanation = self._generate_explanation(vulnerability, root_cause, patched_code)

        if self.config.enable_judge_loop:
            patched_code, explanation = self._refine_with_judge(
                vulnerability, code, patched_code, explanation
            )

        patch = Patch(
            id=f"patch-{uuid.uuid4().hex[:12]}",
            vuln_id=vulnerability.id,
            original_code=code,
            patched_code=patched_code,
            explanation=explanation,
            status=PatchStatus.GENERATED
        )

        self.patches[patch.id] = patch
        return patch

    def _retrieve_similar_patch(self, vulnerability: Vulnerability, code: str) -> Optional[Dict]:
        """Look up the closest prior patch for this vulnerability type from
        Immune Memory, to use as a one-shot exemplar (retrieval-grounded
        generation, per AutoSigma's template-grounding approach).

        Similarity compares `code` (the full source of the file currently
        being patched) against each candidate's stored `original_code` —
        also a full file's source (see Patch.original_code in orchestrator.py)
        — so the two sides of the ratio are the same kind of text. Comparing
        a single-line snippet against a whole stored file would make the
        ratio meaningless regardless of true relevance.
        """
        if not self.memory:
            return None
        try:
            candidates = self.memory.get_similar_patches(
                vulnerability.vuln_type,
                code,
                limit=1
            )
        except Exception:
            return None
        # Require a minimum similarity so an unrelated past patch of the same
        # CWE class doesn't get force-fit as a template.
        if candidates and candidates[0].get("similarity", 0.0) >= 0.3:
            return candidates[0]
        return None

    def _format_similar_patch(self, similar_patch: Optional[Dict]) -> str:
        if not similar_patch:
            return ""
        return f"""
SIMILAR PAST FIX (from immune memory, adapt to this case rather than copying verbatim):
Original:
```
{(similar_patch.get('original_code') or '')[:800]}
```
Patched:
```
{(similar_patch.get('patched_code') or '')[:800]}
```
"""

    def _refine_with_judge(self, vulnerability: Vulnerability, original_code: str,
                            patched_code: str, explanation: str) -> Tuple[str, str]:
        """Bounded generator+judge refinement loop: a second LLM pass scores
        the draft patch and, below threshold, asks for a revision. Caps at
        max_judge_iterations so this can't compound the per-vulnerability
        LLM-call cost unboundedly on a slow local model."""
        for _ in range(self.config.max_judge_iterations):
            score, feedback = self._judge_patch(vulnerability, original_code, patched_code)
            if score >= self.config.judge_score_threshold:
                break

            revision_prompt = f"""The following patch for a {vulnerability.vuln_type.value} vulnerability was scored {score}/10 by a reviewer.

REVIEWER FEEDBACK:
{feedback}

ORIGINAL VULNERABLE CODE:
```
{original_code[:2000]}
```

CURRENT PATCHED CODE:
```
{patched_code[:2000]}
```

Revise the patch to address the feedback. Respond in this EXACT format:

PATCHED CODE:
```python
<complete revised code>
```

EXPLANATION:
<what changed and why>"""

            revised = self._call_llm(
                "You are a security expert revising a patch based on reviewer feedback.",
                revision_prompt
            )
            new_code = self._extract_code(revised)
            new_explanation = self._extract_section(revised, "EXPLANATION:", None)
            if new_code and new_code != patched_code:
                patched_code = new_code
            if new_explanation:
                explanation = new_explanation

        return patched_code, explanation

    def _judge_patch(self, vulnerability: Vulnerability, original_code: str,
                      patched_code: str) -> Tuple[int, str]:
        """Score a candidate patch 1-10 via a second LLM pass. Mirrors
        AutoSigma's Generator+Judge loop; per that paper, judging improves
        output validity/format but does not eliminate hallucination on its
        own, so this is a quality filter, not a correctness guarantee."""
        system_prompt = "You are a strict security code reviewer scoring a proposed patch."
        user_prompt = f"""Score this security patch from 1-10 on: (a) whether it actually fixes the {vulnerability.vuln_type.value} vulnerability, (b) whether it preserves existing functionality, (c) whether the code is syntactically well-formed.

VULNERABILITY: {vulnerability.description}

ORIGINAL CODE:
```
{original_code[:2000]}
```

PATCHED CODE:
```
{patched_code[:2000]}
```

Respond in this EXACT format:
SCORE: <integer 1-10>
FEEDBACK: <one or two sentences on what, if anything, is still wrong>"""

        response = self._call_llm(system_prompt, user_prompt)
        score_match = re.search(r'SCORE:\s*(\d+)', response)
        score = int(score_match.group(1)) if score_match else 5
        feedback = self._extract_section(response, "FEEDBACK:", None) or "No specific feedback provided."
        return score, feedback
    
    def _extract_section(self, response: str, start_marker: str, end_marker: Optional[str]) -> str:
        """Extract a section between markers from LLM response"""
        start_idx = response.find(start_marker)
        if start_idx == -1:
            return ""
        start_idx += len(start_marker)
        if end_marker:
            end_idx = response.find(end_marker, start_idx)
            if end_idx == -1:
                return response[start_idx:].strip()
            return response[start_idx:end_idx].strip()
        return response[start_idx:].strip()
    
    def _analyze_root_cause(self, code: str, vulnerability: Vulnerability) -> str:
        """Analyze the root cause of a vulnerability"""
        
        # Build analysis prompt
        system_prompt = """You are a security expert analyzing code vulnerabilities.
Provide a concise root cause analysis explaining WHY the vulnerability exists.
Focus on the security flaw, not general code quality."""

        user_prompt = f"""Analyze the root cause of this vulnerability:

VULNERABILITY TYPE: {vulnerability.vuln_type.value}
SEVERITY: {vulnerability.severity.value}
DESCRIPTION: {vulnerability.description}
LOCATION: Line {vulnerability.location.line_start}
CODE SNIPPET:
```
{vulnerability.location.code_snippet or 'Not available'}
```

Full context:
```python
{code[:2000]}
```

Provide root cause analysis (2-3 sentences):"""

        # Call LLM
        response = self._call_llm(system_prompt, user_prompt)
        return response
    
    def _generate_patch(self, code: str, vulnerability: Vulnerability, root_cause: str) -> str:
        """Generate a patched version of the code"""
        
        # Get specific fix instructions based on vulnerability type
        fix_instructions = self._get_fix_instructions(vulnerability.vuln_type)
        
        system_prompt = f"""You are an expert Python developer specializing in security patches.
Generate a COMPLETE patched version of the code that fixes the vulnerability.
Apply these fix guidelines:
{fix_instructions}

Rules:
1. Return ONLY the complete patched code
2. Preserve all functionality that is not vulnerable
3. Use minimal changes
4. Add security comments where appropriate"""

        user_prompt = f"""Fix this vulnerability in the code:

VULNERABILITY: {vulnerability.vuln_type.value}
ROOT CAUSE: {root_cause}

ORIGINAL CODE:
```python
{code}
```

Generate the complete patched code:"""

        response = self._call_llm(system_prompt, user_prompt)
        
        # Extract code from response
        patched_code = self._extract_code(response)
        return patched_code
    
    def _generate_explanation(self, vulnerability: Vulnerability, root_cause: str, patched_code: str) -> str:
        """Generate explanation for the patch"""
        
        system_prompt = """You are a security educator explaining code fixes.
Provide a clear, concise explanation of what was changed and why."""

        user_prompt = f"""Explain this security patch:

VULNERABILITY: {vulnerability.title}
TYPE: {vulnerability.vuln_type.value}
ROOT CAUSE: {root_cause}

Explain:
1. What the vulnerability allowed
2. How the fix addresses it
3. Why the fix is secure"""

        return self._call_llm(system_prompt, user_prompt)
    
    def _get_fix_instructions(self, vuln_type: VulnType) -> str:
        """Get specific fix instructions based on vulnerability type"""
        
        instructions = {
            VulnType.SQL_INJECTION: """
- Use parameterized queries instead of string formatting
- Use ? placeholders with tuple parameters
- Never concatenate user input into SQL strings
Example: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))""",
            
            VulnType.COMMAND_INJECTION: """
- Use subprocess.run() with list arguments instead of shell=True
- Never use os.system() or os.popen()
- Never use eval() or exec()
- Use shlex.quote() for shell arguments if absolutely necessary
Example: subprocess.run(["ls", "-la"], capture_output=True)""",
            
            VulnType.PATH_TRAVERSAL: """
- Validate and sanitize file paths
- Use os.path.realpath() and check prefix
- Use pathlib for safe path handling
- Never use user input directly in file paths
Example: safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))
if not safe_path.startswith(os.path.realpath(BASE_DIR)):
    raise ValueError("Invalid path")""",
            
            VulnType.DESERIALIZATION: """
- Never use pickle.loads() on untrusted data
- Use yaml.safe_load() instead of yaml.load()
- Use json for data exchange
- Consider signing serialized data""",
            
            VulnType.SSRF: """
- Validate and whitelist allowed URLs
- Use URL parsing to check scheme and host
- Block internal/private IP ranges
- Use a dedicated HTTP client with restrictions""",
            
            VulnType.XSS: """
- Use template autoescaping
- Sanitize user input before rendering
- Use Content-Security-Policy headers
- Never insert user data into HTML without escaping""",
            
            VulnType.HARDCODED_CREDENTIALS: """
- Move secrets to environment variables
- Use a secrets manager
- Never commit credentials to source control
- Use .env files (not committed) for development""",
            
            VulnType.INFO_DISCLOSURE: """
- Disable debug mode in production
- Don't expose environment variables
- Use proper error handling
- Log sensitive data securely""",
            
            VulnType.OPEN_REDIRECT: """
- Validate redirect URLs against whitelist
- Only allow relative redirects
- Never redirect to user-supplied URLs
- Use safe redirect patterns""",
            
            VulnType.WEAK_CRYPTO: """
- Use secrets module for cryptographic randomness
- Use os.urandom() for security-sensitive values
- Never use random module for security
Example: import secrets; token = secrets.token_hex(32)""",
        }
        
        return instructions.get(vuln_type, "Apply standard security best practices.")
    
    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the LLM for analysis"""
        
        if self.config.provider == "local":
            return self._call_local_model(system_prompt, user_prompt)
        elif self.config.use_local:
            return self._call_local_llm(system_prompt, user_prompt)
        elif self.config.provider == "gemini":
            return self._call_gemini(system_prompt, user_prompt)
        elif self.config.provider == "claude":
            return self._call_claude(system_prompt, user_prompt)
        else:
            return self._call_api(system_prompt, user_prompt)
    
    def _call_claude(self, system_prompt: str, user_prompt: str) -> str:
        """Call Anthropic Claude API"""
        try:
            import urllib.request
            
            api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                print("[ANVIL] No Anthropic API key found. Set ANTHROPIC_API_KEY or pass api_key.")
                return self._fallback_analysis(system_prompt, user_prompt)
            
            payload = json.dumps({
                "model": self.config.model or "claude-sonnet-4-20250514",
                "max_tokens": self.config.max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}]
            }).encode('utf-8')
            
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01"
                },
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data["content"][0]["text"]
        except Exception as e:
            print(f"[ANVIL] Claude API call failed: {e}")
            return self._fallback_analysis(system_prompt, user_prompt)
    
    def _call_local_model(self, system_prompt: str, user_prompt: str) -> str:
        """Call local model via Ollama API (dolphin-llama3, qwen3.5, etc.)"""
        try:
            import urllib.request
            import urllib.error
            
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            
            payload = json.dumps({
                "model": self.config.model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens
                }
            }).encode('utf-8')
            
            req = urllib.request.Request(
                self.config.api_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data["response"]
        except Exception as e:
            print(f"[ANVIL] Local model call failed: {e}")
            return self._fallback_analysis(system_prompt, user_prompt)
    
    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        """Call Google Gemini API"""
        try:
            from google import genai
            from google.genai import types
            
            api_key = self.config.api_key or os.getenv("GEMINI_API_KEY")
            if not api_key:
                return self._fallback_analysis(system_prompt, user_prompt)
            
            client = genai.Client(api_key=api_key)
            
            # Combine system and user prompts for Gemini
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            
            response = client.models.generate_content(
                model=self.config.model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=self.config.temperature,
                    max_output_tokens=self.config.max_tokens
                )
            )
            
            return response.text
        
        except Exception as e:
            print(f"[ANVIL] Gemini API call failed: {e}")
            return self._fallback_analysis(system_prompt, user_prompt)
    
    def _call_api(self, system_prompt: str, user_prompt: str) -> str:
        """Call external LLM API"""
        try:
            import requests
            
            api_key = self.config.api_key or os.getenv("DEEPSEEK_API_KEY")
            if not api_key:
                return self._fallback_analysis(system_prompt, user_prompt)
            
            response = requests.post(
                self.config.api_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.config.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                },
                timeout=60
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        
        except Exception as e:
            print(f"[ANVIL] API call failed: {e}")
            return self._fallback_analysis(system_prompt, user_prompt)
    
    def _call_local_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call local LLM (Ollama/vLLM) via urllib"""
        try:
            import urllib.request
            
            payload = json.dumps({
                "model": self.config.local_model,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False
            }).encode('utf-8')

            req = urllib.request.Request(
                self.config.api_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data["response"]
        
        except Exception as e:
            print(f"[ANVIL] Local LLM call failed: {e}")
            return self._fallback_analysis(system_prompt, user_prompt)
    
    def _fallback_analysis(self, system_prompt: str, user_prompt: str) -> str:
        """
        Fallback when LLM is unavailable
        Uses rule-based patch generation
        """
        # Extract vulnerability type from prompt
        vuln_type_match = re.search(r'VULNERABILITY TYPE: (\w+)', user_prompt)
        if vuln_type_match:
            vuln_type = vuln_type_match.group(1)
        else:
            vuln_type = "UNKNOWN"
        
        # Generate basic fix based on type
        if "SQL_INJECTION" in vuln_type:
            return "Use parameterized queries with ? placeholders instead of string formatting."
        elif "COMMAND_INJECTION" in vuln_type:
            return "Use subprocess.run() with list arguments instead of shell=True."
        elif "PATH_TRAVERSAL" in vuln_type:
            return "Validate and sanitize file paths before use."
        elif "DESERIALIZATION" in vuln_type:
            return "Use safe deserialization methods (yaml.safe_load, json)."
        elif "HARDCODED_CREDENTIALS" in vuln_type:
            return "Move credentials to environment variables."
        else:
            return "Apply security best practices for this vulnerability type."
    
    def _extract_code(self, response: str) -> str:
        """Extract code from LLM response"""
        # Try to extract code block
        code_match = re.search(r'```python\n(.*?)```', response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()
        
        code_match = re.search(r'```\n(.*?)```', response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()
        
        # Return full response if no code block found
        return response.strip()
    
    def get_stats(self) -> Dict[str, int]:
        """Get ANVIL statistics"""
        return {
            "total_patches": self.patch_count,
            "patches_generated": len(self.patches)
        }
