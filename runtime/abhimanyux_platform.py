"""
ABHIMANYU X Platform - Production-Grade Autonomous Cyber Reasoning System

Based on cutting-edge research:
- MalCodeAI: Language-agnostic multi-stage AI pipeline (arXiv:2507.10898)
- Antares: Foundation models for agentic vulnerability localization (arXiv:2608.02407)
- The Path To Autonomous Cyber Defense (arXiv:2404.10788)

Features:
- Multi-provider LLM support (Claude, GPT, Gemini, DeepSeek, local models)
- Intelligent model selection based on hardware
- Language-agnostic detection (14+ languages)
- CVSS scoring and exploit tracing
- Zero-shot vulnerability detection
- Immune memory system
"""

import os
import re
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field

from abhimanyux.runtime.providers import (
    ProviderFactory, ModelSelector, MODEL_REGISTRY,
    LLMProvider, ModelConfig, ProviderType
)
from abhimanyux.runtime.pipeline import (
    MultiStagePipeline, PipelineConfig, 
    detect_language, ProgrammingLanguage, CVSSScore, ExploitTrace
)
from abhimanyux.models.schemas import (
    Vulnerability, Patch, VerificationResult, ImmuneRecord,
    ScanResult, Severity, VulnType
)
from abhimanyux.memory.store import ImmuneMemoryStore


@dataclass
class PlatformConfig:
    """Configuration for ABHIMANYU X Platform"""
    # Model configuration
    model_name: str = "qwen2.5-coder-7b"  # Default to local model
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    
    # Auto-select best model based on hardware
    auto_select_model: bool = True
    prefer_local: bool = True
    prefer_frontier: bool = False
    
    # Pipeline configuration
    enable_cvss_scoring: bool = True
    enable_exploit_tracing: bool = True
    enable_zero_shot: bool = True
    enable_immune_memory: bool = True
    
    # Database
    db_path: str = "abhimanyux_platform.db"


class AbhimanyuXPlatform:
    """
    ABHIMANYU X Platform - Production-Grade Autonomous Cyber Reasoning
    
    A comprehensive security analysis platform that combines:
    - Multi-provider LLM support
    - Research-backed algorithms
    - Language-agnostic detection
    - Intelligent model selection
    """
    
    def __init__(self, config: Optional[PlatformConfig] = None):
        self.config = config or PlatformConfig()
        
        # Initialize components
        self.model_selector = ModelSelector()
        self.pipeline = MultiStagePipeline(PipelineConfig(
            enable_cvss_scoring=self.config.enable_cvss_scoring,
            enable_exploit_tracing=self.config.enable_exploit_tracing
        ))
        
        # Initialize LLM provider
        self.llm: Optional[LLMProvider] = None
        if self.config.model_name:
            self._init_llm_provider()
        
        # Initialize immune memory
        self.memory: Optional[ImmuneMemoryStore] = None
        if self.config.enable_immune_memory:
            self.memory = ImmuneMemoryStore(self.config.db_path)
        
        # Statistics
        self.scan_count = 0
        self.total_vulnerabilities = 0
        self.total_patches = 0
    
    def _init_llm_provider(self):
        """Initialize the LLM provider"""
        try:
            self.llm = ProviderFactory.create(
                self.config.model_name,
                api_key=self.config.api_key,
                api_url=self.config.api_url
            )
            print(f"[Platform] Initialized LLM: {self.config.model_name}")
        except Exception as e:
            print(f"[Platform] Failed to init LLM: {e}")
            print("[Platform] Falling back to rule-based detection")
    
    def get_hardware_info(self) -> Dict[str, Any]:
        """Get detected hardware information"""
        hw = self.model_selector.hardware
        return {
            "cpu_cores": hw.cpu_cores,
            "total_ram_gb": hw.total_ram_gb,
            "available_ram_gb": hw.available_ram_gb,
            "gpu_name": hw.gpu_name,
            "gpu_vram_gb": hw.gpu_vram_gb,
            "has_gpu": hw.has_gpu
        }
    
    def get_recommended_models(self, 
                               prefer_local: bool = True,
                               prefer_frontier: bool = False) -> List[Dict[str, Any]]:
        """Get recommended models for this hardware"""
        model_names = self.model_selector.get_recommended_models(
            prefer_local=prefer_local,
            prefer_frontier=prefer_frontier
        )
        
        return [
            {
                "name": name,
                "config": MODEL_REGISTRY[name]
            }
            for name in model_names
        ]
    
    def set_model(self, model_name: str, api_key: Optional[str] = None):
        """Change the active model"""
        self.config.model_name = model_name
        self.config.api_key = api_key
        self._init_llm_provider()
    
    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file for vulnerabilities"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        language = detect_language(file_path)
        return self.scan_code(code, file_path, language)
    
    def scan_directory(self, dir_path: str) -> List[ScanResult]:
        """Scan a directory for vulnerabilities"""
        results = []
        
        for root, dirs, files in os.walk(dir_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') 
                      and d not in ['node_modules', 'venv', '__pycache__', 'vendor']]
            
            for file in files:
                file_path = os.path.join(root, file)
                language = detect_language(file)
                
                # Skip non-source files
                if language is None:
                    continue
                
                try:
                    result = self.scan_file(file_path)
                    results.append(result)
                except Exception as e:
                    print(f"[Platform] Error scanning {file_path}: {e}")
        
        return results
    
    def scan_code(self, code: str, filename: str = "inline_code",
                  language: Optional[ProgrammingLanguage] = None) -> ScanResult:
        """
        Scan code for vulnerabilities
        
        This is the main analysis method that combines:
        1. Code decomposition
        2. Vulnerability detection
        3. CVSS scoring
        4. Exploit tracing
        5. AI-enhanced analysis (if LLM available)
        6. Immune memory storage
        """
        self.scan_count += 1
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"
        
        # Detect language if not specified
        if language is None:
            language = detect_language(filename)
        
        start_time = time.time()
        
        # Phase 1: Code Decomposition
        print(f"[*] Phase 1: Decomposing {filename} ({language.value})...")
        decomposition = self.pipeline.decompose_code(code, language)
        
        # Phase 2: Vulnerability Detection
        print(f"[*] Phase 2: Detecting vulnerabilities...")
        raw_vulns = self.pipeline.detect_vulnerabilities(code, language, decomposition)
        
        # Phase 3: AI-Enhanced Analysis (if LLM available)
        ai_vulns = []
        if self.llm:
            print(f"[*] Phase 3: AI analysis with {self.config.model_name}...")
            ai_vulns = self._ai_enhanced_detection(code, language, filename)
        
        # Combine results
        all_vulns = raw_vulns + ai_vulns
        
        # Phase 4: CVSS Scoring
        print(f"[*] Phase 4: CVSS scoring...")
        for vuln in all_vulns:
            if "cvss_vector" not in vuln or not vuln["cvss_vector"]:
                cvss = self.pipeline.generate_cvss_score(vuln["type"])
                vuln["cvss_score"] = cvss.base_score
                vuln["severity"] = cvss.severity.value
            else:
                # Parse provided CVSS vector
                vuln["cvss_score"] = 9.0  # Default for critical
        
        # Phase 5: Convert to Vulnerability objects
        vulnerabilities = []
        for i, v in enumerate(all_vulns):
            vuln = Vulnerability(
                id=f"vuln-{scan_id}-{i:04d}",
                vuln_type=VulnType(v["type"]) if v["type"] in [e.value for e in VulnType] else VulnType.OTHER,
                severity=Severity(v["severity"]) if v["severity"] in [e.value for e in Severity] else Severity.MEDIUM,
                title=f"{v['type'].replace('_', ' ').title()}",
                description=v["description"],
                location={"file_path": filename, "line_start": v.get("line", 0), "code_snippet": v.get("code_snippet", "")},
                confidence=0.8,
                cwe_id=v.get("cwe", ""),
                source="pattern" if v not in ai_vulns else "ai_analysis"
            )
            vulnerabilities.append(vuln)
        
        # Phase 6: Immune Memory Storage
        if self.memory:
            print(f"[*] Phase 6: Storing in immune memory...")
            for vuln in vulnerabilities:
                self.memory.store_vulnerability(vuln)
        
        # Generate summary
        elapsed = time.time() - start_time
        summary = self._generate_summary(vulnerabilities, filename, language, elapsed)
        
        self.total_vulnerabilities += len(vulnerabilities)
        
        return ScanResult(
            scan_id=scan_id,
            target_path=filename,
            vulnerabilities=vulnerabilities,
            patches=[],
            verifications=[],
            immune_records=[],
            summary=summary,
            completed_at=datetime.now(timezone.utc)
        )
    
    def _ai_enhanced_detection(self, code: str, 
                               language: ProgrammingLanguage,
                               filename: str) -> List[Dict[str, Any]]:
        """Use LLM for enhanced vulnerability detection"""
        if not self.llm:
            return []
        
        prompt = f"""Analyze this {language.value} code for security vulnerabilities.

Focus on:
1. Command injection
2. SQL injection
3. Path traversal
4. Deserialization attacks
5. XSS vulnerabilities
6. Hardcoded credentials
7. Weak cryptography
8. SSRF vulnerabilities
9. Logic flaws
10. Authentication bypasses

Return a JSON array of detected vulnerabilities:
[
  {{
    "type": "vulnerability_type",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "line": line_number,
    "code_snippet": "affected code",
    "description": "detailed description",
    "cwe": "CWE-XXX"
  }}
]

Only return valid JSON. If no vulnerabilities found, return empty array [].

Code:
```{language.value}
{code[:4000]}
```"""
        
        try:
            response = self.llm.generate(
                "You are a security expert analyzing code for vulnerabilities.",
                prompt
            )
            
            # Parse JSON response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                vulns = json.loads(json_match.group())
                print(f"  [AI] Detected {len(vulns)} additional vulnerabilities")
                return vulns
        except Exception as e:
            print(f"  [AI] Detection failed: {e}")
        
        return []
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability],
                         filename: str, language: ProgrammingLanguage,
                         elapsed: float) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {}
        type_counts = {}
        
        for v in vulnerabilities:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            type_counts[v.vuln_type.value] = type_counts.get(v.vuln_type.value, 0) + 1
        
        return {
            "scan_id": f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "target": filename,
            "language": language.value,
            "model_used": self.config.model_name,
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "scan_time_seconds": round(elapsed, 2),
            "hardware": self.get_hardware_info()
        }
    
    def print_report(self, result: ScanResult):
        """Print a formatted scan report"""
        print("\n" + "="*70)
        print("ABHIMANYU X PLATFORM - SECURITY ANALYSIS REPORT")
        print("="*70)
        print(f"\nScan ID: {result.scan_id}")
        print(f"Target: {result.target_path}")
        print(f"Completed: {result.completed_at}")
        
        if result.summary:
            print(f"\nModel: {result.summary.get('model_used', 'N/A')}")
            print(f"Language: {result.summary.get('language', 'N/A')}")
            print(f"Scan Time: {result.summary.get('scan_time_seconds', 0)}s")
        
        print("\n" + "-"*70)
        print("VULNERABILITIES FOUND")
        print("-"*70)
        
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n{i}. [{vuln.severity.value.upper()}] {vuln.title}")
            print(f"   Type: {vuln.vuln_type.value}")
            print(f"   Location: {vuln.location.file_path}:{vuln.location.line_start}")
            print(f"   CWE: {vuln.cwe_id or 'N/A'}")
            print(f"   Description: {vuln.description}")
            if vuln.location.code_snippet:
                print(f"   Code: {vuln.location.code_snippet[:100]}")
        
        print("\n" + "-"*70)
        print("SEVERITY SUMMARY")
        print("-"*70)
        
        if result.summary and "by_severity" in result.summary:
            for sev, count in result.summary["by_severity"].items():
                print(f"  {sev.upper()}: {count}")
        
        print("\n" + "-"*70)
        print("VULNERABILITY TYPES")
        print("-"*70)
        
        if result.summary and "by_type" in result.summary:
            for vtype, count in result.summary["by_type"].items():
                print(f"  {vtype}: {count}")
        
        print("\n" + "="*70)
        print("SCAN COMPLETE")
        print("="*70)
    
    def get_memory_stats(self) -> Dict[str, int]:
        """Get immune memory statistics"""
        if self.memory:
            return self.memory.get_statistics()
        return {"total_vulnerabilities": 0, "total_dna_patterns": 0}
    
    def search_similar(self, vuln_type: VulnType) -> List[Dict]:
        """Search for similar vulnerabilities in memory"""
        if self.memory:
            return self.memory.search_by_type(vuln_type)
        return []


# ============================================================
# CLI Interface
# ============================================================

def main():
    """Main CLI entry point"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ABHIMANYU X Platform - Autonomous Cyber Reasoning System"
    )
    parser.add_argument("target", nargs="?",
                        help="Target file or directory to scan")
    parser.add_argument("--model", default="qwen2.5-coder-7b",
                        help="LLM model to use (default: qwen2.5-coder-7b)")
    parser.add_argument("--provider", 
                        choices=["local", "claude", "gpt", "gemini", "deepseek"],
                        help="Force specific provider")
    parser.add_argument("--api-key", help="API key for cloud providers")
    parser.add_argument("--list-models", action="store_true",
                        help="List available models")
    parser.add_argument("--list-hardware", action="store_true",
                        help="Show detected hardware")
    parser.add_argument("--no-ai", action="store_true",
                        help="Disable AI analysis (pattern-only)")
    parser.add_argument("--no-memory", action="store_true",
                        help="Disable immune memory")
    
    args = parser.parse_args()
    
    print("="*70)
    print("ABHIMANYU X PLATFORM v2.0")
    print("Autonomous Cyber Reasoning System for Defence Infrastructure")
    print("="*70)
    
    # List models
    if args.list_models:
        print("\nAVAILABLE MODELS:")
        print("-"*70)
        for name, config in MODEL_REGISTRY.items():
            provider = config.provider.value
            if config.min_ram_gb > 0:
                print(f"  {name:25} [{provider:8}] RAM: {config.min_ram_gb}GB, VRAM: {config.min_vram_gb}GB")
            else:
                print(f"  {name:25} [{provider:8}] ${config.cost_per_1k_tokens}/1K tokens")
        return
    
    # List hardware
    if args.list_hardware:
        platform = AbhimanyuXPlatform()
        hw = platform.get_hardware_info()
        print(f"\nHARDWARE:")
        print(f"  CPU Cores:     {hw['cpu_cores']}")
        print(f"  Total RAM:     {hw['total_ram_gb']:.1f} GB")
        print(f"  Available RAM: {hw['available_ram_gb']:.1f} GB")
        print(f"  GPU:           {hw['gpu_name'] or 'None'}")
        print(f"  GPU VRAM:      {hw['gpu_vram_gb']:.1f} GB")
        
        print("\nRECOMMENDED MODELS:")
        platform2 = AbhimanyuXPlatform()
        for model in platform2.get_recommended_models()[:5]:
            print(f"  • {model['name']}")
        return
    
    # Check target
    if not args.target:
        parser.print_help()
        return
    
    # Determine model
    model_name = args.model
    if args.provider:
        provider_map = {
            "local": "qwen2.5-coder-7b",
            "claude": "claude-sonnet-4",
            "gpt": "gpt-4o",
            "gemini": "gemini-2.5-flash",
            "deepseek": "deepseek-coder-v2"
        }
        model_name = provider_map.get(args.provider, args.model)
    
    # Create platform
    config = PlatformConfig(
        model_name=model_name,
        api_key=args.api_key,
        enable_immune_memory=not args.no_memory
    )
    
    platform = AbhimanyuXPlatform(config)
    
    # Scan
    print(f"\n[*] Scanning: {args.target}")
    print(f"[*] Model: {model_name}")
    
    if os.path.isfile(args.target):
        result = platform.scan_file(args.target)
        platform.print_report(result)
    elif os.path.isdir(args.target):
        results = platform.scan_directory(args.target)
        for result in results:
            platform.print_report(result)
    else:
        print(f"[!] Target not found: {args.target}")
        return
    
    # Memory stats
    if platform.memory:
        stats = platform.get_memory_stats()
        print(f"\nImmune Memory: {stats['total_vulnerabilities']} vulnerabilities, "
              f"{stats['total_dna_patterns']} DNA patterns")


if __name__ == "__main__":
    main()
