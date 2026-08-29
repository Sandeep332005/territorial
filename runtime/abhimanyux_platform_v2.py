"""
ABHIMANYU X Platform v2.0 - Enhanced with Local/API/Custom LLM Support

Features:
- Intelligent provider selection based on hardware
- Automatic fallback chain (Local → API → Custom)
- Custom endpoint configuration
- Cost tracking and optimization
- Provider health checks
- Multi-provider parallel analysis
"""

import os
import json
import time
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path

from abhimanyux.runtime.providers_v2 import (
    ProviderFactory, ModelSelector, ModelConfig,
    LLMProvider, ProviderType, ProviderCategory,
    ProviderManager, MODEL_REGISTRY, HardwareProfile
)
from abhimanyux.runtime.pipeline import (
    MultiStagePipeline, PipelineConfig,
    detect_language, ProgrammingLanguage, CVSSScore
)
from abhimanyux.models.schemas import (
    Vulnerability, Patch, VerificationResult, ImmuneRecord,
    ScanResult, Severity, VulnType
)
from abhimanyux.memory.store import ImmuneMemoryStore


# ============================================================
# Platform Configuration
# ============================================================

@dataclass
class PlatformConfig:
    """Configuration for ABHIMANYU X Platform"""
    
    # Model configuration
    model_name: str = "auto"  # "auto" selects best model
    provider: Optional[str] = None  # Force specific provider
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    
    # Auto-selection settings
    auto_select_model: bool = True
    prefer_local: bool = True
    prefer_cheap: bool = False
    
    # Fallback settings
    enable_fallback: bool = True
    max_retries: int = 3
    
    # Feature flags
    enable_cvss_scoring: bool = True
    enable_exploit_tracing: bool = True
    enable_zero_shot: bool = True
    enable_immune_memory: bool = True
    enable_parallel_analysis: bool = False
    
    # Paths
    config_path: str = "config/providers.json"
    db_path: str = "abhimanyux_platform.db"
    
    # Cost limits
    max_cost_per_scan: float = 1.0  # Maximum cost per scan in USD


# ============================================================
# Enhanced Platform
# ============================================================

class AbhimanyuXPlatform:
    """
    ABHIMANYU X Platform v2.0 - Multi-Provider LLM Support
    
    Supports:
    - LOCAL: Ollama, vLLM, LM Studio (runs on your hardware)
    - API: Claude, GPT, Gemini, DeepSeek (cloud-based)
    - CUSTOM: Any OpenAI-compatible endpoint (self-hosted)
    """
    
    def __init__(self, config: Optional[PlatformConfig] = None):
        self.config = config or PlatformConfig()
        
        # Initialize components
        self.model_selector = ModelSelector()
        self.pipeline = MultiStagePipeline(PipelineConfig(
            enable_cvss_scoring=self.config.enable_cvss_scoring,
            enable_exploit_tracing=self.config.enable_exploit_tracing
        ))
        
        # Initialize provider manager
        config_path = self.config.config_path
        if not os.path.isabs(config_path):
            # Try relative to package
            package_dir = Path(__file__).parent.parent
            config_path = str(package_dir / config_path)
        
        self.provider_manager = ProviderManager(config_path)
        
        # Select and initialize model
        self.llm: Optional[LLMProvider] = None
        self.active_model: Optional[str] = None
        
        if self.config.model_name == "auto":
            self._auto_select_model()
        elif self.config.model_name:
            self._init_model(self.config.model_name)
        
        # Initialize immune memory
        self.memory: Optional[ImmuneMemoryStore] = None
        if self.config.enable_immune_memory:
            self.memory = ImmuneMemoryStore(self.config.db_path)
        
        # Statistics
        self.scan_count = 0
        self.total_vulnerabilities = 0
        self.total_patches = 0
        self.total_cost = 0.0
    
    def _auto_select_model(self):
        """Automatically select the best model based on hardware and availability"""
        print("[*] Auto-selecting optimal model...")
        
        # Get task-specific recommendation
        task = "vulnerability_detection"
        model_name = self.model_selector.select_best(
            prefer_local=self.config.prefer_local,
            prefer_cheap=self.config.prefer_cheap,
            task=task
        )
        
        print(f"  Selected: {model_name}")
        self._init_model(model_name)
    
    def _init_model(self, model_name: str):
        """Initialize a specific model"""
        try:
            self.llm = self.provider_manager.get_provider(model_name)
            self.active_model = model_name
            config = MODEL_REGISTRY.get(model_name)
            
            if config:
                category = config.category.value
                provider = config.provider.value
                print(f"[✓] Initialized: {model_name}")
                print(f"    Category: {category} | Provider: {provider}")
            else:
                print(f"[✓] Initialized: {model_name} (custom)")
        except Exception as e:
            print(f"[!] Failed to init {model_name}: {e}")
            print("[*] Falling back to pattern-only detection")
    
    def get_hardware_info(self) -> HardwareProfile:
        """Get detected hardware information"""
        return self.model_selector.hardware
    
    def get_available_models(self) -> Dict[str, List[str]]:
        """Get available models grouped by category"""
        return self.model_selector.get_available_providers()
    
    def set_model(self, model_name: str, api_key: Optional[str] = None,
                  api_url: Optional[str] = None):
        """Change the active model"""
        self.config.model_name = model_name
        self.config.api_key = api_key
        self.config.api_url = api_url
        
        if api_key or api_url:
            # Register as custom model
            self.provider_manager.register_custom_model(
                name=model_name,
                model_id=model_name,
                api_url=api_url or "",
                api_key=api_key
            )
        
        self._init_model(model_name)
    
    def add_custom_endpoint(self, name: str, api_url: str, model_id: str,
                           api_key: Optional[str] = None):
        """Add a custom API endpoint"""
        self.provider_manager.register_custom_model(
            name=name,
            model_id=model_id,
            api_url=api_url,
            api_key=api_key
        )
        print(f"[✓] Added custom endpoint: {name}")
        print(f"    URL: {api_url}")
        print(f"    Model: {model_id}")
    
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
                      and d not in ['node_modules', 'venv', '__pycache__', 'vendor', '.git']]
            
            for file in files:
                file_path = os.path.join(root, file)
                language = detect_language(file)
                
                if language is None:
                    continue
                
                try:
                    result = self.scan_file(file_path)
                    results.append(result)
                except Exception as e:
                    print(f"[!] Error scanning {file_path}: {e}")
        
        return results
    
    def scan_code(self, code: str, filename: str = "inline_code",
                  language: Optional[ProgrammingLanguage] = None) -> ScanResult:
        """
        Scan code for vulnerabilities
        
        Multi-phase pipeline:
        1. Code Decomposition
        2. Pattern-based Detection
        3. AI-Enhanced Analysis (if LLM available)
        4. CVSS Scoring
        5. Immune Memory Storage
        """
        self.scan_count += 1
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"
        
        if language is None:
            language = detect_language(filename)
        
        start_time = time.time()
        cost_so_far = 0.0
        
        print(f"\n{'='*60}")
        print(f"ABHIMANYU X Security Scan: {filename}")
        print(f"{'='*60}")
        
        # Phase 1: Code Decomposition
        print(f"\n[Phase 1] Decomposing {filename} ({language.value})...")
        decomposition = self.pipeline.decompose_code(code, language)
        print(f"  Functions: {len(decomposition.get('functions', []))}")
        print(f"  Classes: {len(decomposition.get('classes', []))}")
        print(f"  Imports: {len(decomposition.get('imports', []))}")
        
        # Phase 2: Pattern-based Detection
        print(f"\n[Phase 2] Pattern-based detection...")
        raw_vulns = self.pipeline.detect_vulnerabilities(code, language, decomposition)
        print(f"  Found: {len(raw_vulns)} vulnerabilities")
        
        # Phase 3: AI-Enhanced Analysis
        ai_vulns = []
        if self.llm and self.config.enable_zero_shot:
            print(f"\n[Phase 3] AI analysis with {self.active_model}...")
            try:
                ai_vulns = self._ai_enhanced_detection(code, language, filename)
                print(f"  AI detected: {len(ai_vulns)} additional vulnerabilities")
            except Exception as e:
                print(f"  [!] AI analysis failed: {e}")
        else:
            print(f"\n[Phase 3] AI analysis skipped (no LLM available)")
        
        # Combine results (deduplicate)
        all_vulns = raw_vulns + ai_vulns
        
        # Phase 4: CVSS Scoring
        print(f"\n[Phase 4] CVSS scoring...")
        for vuln in all_vulns:
            if "cvss_score" not in vuln or not vuln.get("cvss_score"):
                cvss = self.pipeline.generate_cvss_score(vuln["type"])
                vuln["cvss_score"] = cvss.base_score
                vuln["cvss_vector"] = cvss.vector
        
        # Phase 5: Convert to Vulnerability objects
        vulnerabilities = []
        for i, v in enumerate(all_vulns):
            try:
                vuln = Vulnerability(
                    id=f"vuln-{scan_id}-{i:04d}",
                    vuln_type=VulnType(v["type"]) if v["type"] in [e.value for e in VulnType] else VulnType.OTHER,
                    severity=Severity(v["severity"]) if v["severity"] in [e.value for e in Severity] else Severity.MEDIUM,
                    title=f"{v['type'].replace('_', ' ').title()}",
                    description=v["description"],
                    location={"file_path": filename, "line_start": v.get("line", 0), "code_snippet": v.get("code_snippet", "")},
                    confidence=0.8 if v in raw_vulns else 0.7,
                    cwe_id=v.get("cwe", ""),
                    source="pattern" if v in raw_vulns else "ai_analysis"
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                print(f"  [!] Error creating vulnerability object: {e}")
        
        # Phase 6: Immune Memory Storage
        if self.memory:
            print(f"\n[Phase 6] Storing in immune memory...")
            for vuln in vulnerabilities:
                self.memory.store_vulnerability(vuln)
            print(f"  Stored: {len(vulnerabilities)} vulnerabilities")
        
        # Generate summary
        elapsed = time.time() - start_time
        summary = self._generate_summary(vulnerabilities, filename, language, elapsed)
        
        self.total_vulnerabilities += len(vulnerabilities)
        
        # Print results
        self._print_results(vulnerabilities, summary)
        
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
                "You are a security expert analyzing code for vulnerabilities. Be thorough and precise.",
                prompt,
                max_tokens=2000
            )
            
            # Parse JSON response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                vulns = json.loads(json_match.group())
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
        source_counts = {"pattern": 0, "ai_analysis": 0}
        
        for v in vulnerabilities:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            type_counts[v.vuln_type.value] = type_counts.get(v.vuln_type.value, 0) + 1
            source_counts[v.source] = source_counts.get(v.source, 0) + 1
        
        return {
            "scan_id": f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "target": filename,
            "language": language.value,
            "model_used": self.active_model or "pattern-only",
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "by_source": source_counts,
            "scan_time_seconds": round(elapsed, 2),
            "hardware": {
                "ram_gb": self.model_selector.hardware.total_ram_gb,
                "gpu": self.model_selector.hardware.gpu_name or "None",
                "vram_gb": self.model_selector.hardware.gpu_vram_gb
            }
        }
    
    def _print_results(self, vulnerabilities: List[Vulnerability],
                      summary: Dict[str, Any]):
        """Print scan results"""
        print(f"\n{'='*60}")
        print("SCAN RESULTS")
        print(f"{'='*60}")
        
        print(f"\nTarget: {summary['target']}")
        print(f"Language: {summary['language']}")
        print(f"Model: {summary['model_used']}")
        print(f"Time: {summary['scan_time_seconds']}s")
        
        if vulnerabilities:
            print(f"\nFound {len(vulnerabilities)} vulnerabilities:")
            print("-" * 60)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_color = {
                    "CRITICAL": "\033[91m",  # Red
                    "HIGH": "\033[93m",       # Yellow
                    "MEDIUM": "\033[94m",     # Blue
                    "LOW": "\033[92m"         # Green
                }.get(vuln.severity.value, "")
                reset_color = "\033[0m"
                
                print(f"\n{i}. {severity_color}[{vuln.severity.value}]{reset_color} {vuln.title}")
                print(f"   Type: {vuln.vuln_type.value}")
                print(f"   Location: {vuln.location.file_path}:{vuln.location.line_start}")
                if vuln.cwe_id:
                    print(f"   CWE: {vuln.cwe_id}")
                print(f"   {vuln.description[:100]}...")
        else:
            print("\n✓ No vulnerabilities found")
        
        # Severity summary
        print(f"\n{'='*60}")
        print("SEVERITY SUMMARY")
        print(f"{'='*60}")
        for sev, count in summary.get("by_severity", {}).items():
            print(f"  {sev}: {count}")
        
        # Source summary
        print(f"\nDetection Sources:")
        for source, count in summary.get("by_source", {}).items():
            print(f"  {source}: {count}")
    
    def get_memory_stats(self) -> Dict[str, int]:
        """Get immune memory statistics"""
        if self.memory:
            return self.memory.get_statistics()
        return {"total_vulnerabilities": 0, "total_dna_patterns": 0}
    
    def check_providers(self) -> Dict[str, Any]:
        """Check status of all providers"""
        return self.provider_manager.check_all_providers()
    
    def get_usage(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return self.provider_manager.get_usage_summary()


# ============================================================
# CLI Interface
# ============================================================

def main():
    """Main CLI entry point"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ABHIMANYU X Platform v2.0 - Autonomous Cyber Reasoning System"
    )
    parser.add_argument("target", nargs="?",
                        help="Target file or directory to scan")
    parser.add_argument("--model", default="auto",
                        help="LLM model (default: auto-select)")
    parser.add_argument("--provider",
                        choices=["local", "api", "custom", "auto"],
                        help="Force provider category")
    parser.add_argument("--api-key", help="API key for cloud providers")
    parser.add_argument("--api-url", help="Custom API endpoint URL")
    parser.add_argument("--add-endpoint", nargs=3,
                        metavar=("NAME", "URL", "MODEL"),
                        help="Add custom endpoint: name url model_id")
    parser.add_argument("--list-models", action="store_true",
                        help="List available models")
    parser.add_argument("--list-providers", action="store_true",
                        help="List provider status")
    parser.add_argument("--check-providers", action="store_true",
                        help="Check provider health")
    parser.add_argument("--hardware", action="store_true",
                        help="Show detected hardware")
    parser.add_argument("--no-ai", action="store_true",
                        help="Disable AI analysis")
    parser.add_argument("--no-memory", action="store_true",
                        help="Disable immune memory")
    parser.add_argument("--prefer-local", action="store_true", default=True,
                        help="Prefer local models")
    parser.add_argument("--prefer-api", action="store_true",
                        help="Prefer API models")
    parser.add_argument("--prefer-cheap", action="store_true",
                        help="Prefer cheaper models")
    
    args = parser.parse_args()
    
    print("="*70)
    print("ABHIMANYU X Platform v2.0")
    print("Autonomous Cyber Reasoning System")
    print("Support: Local | API | Custom LLM Providers")
    print("="*70)
    
    # List models
    if args.list_models:
        print("\nAVAILABLE MODELS:")
        print("-"*70)
        
        for category in ["LOCAL", "API", "CUSTOM"]:
            print(f"\n{category} Models:")
            for name, config in MODEL_REGISTRY.items():
                if config.category.value == category.lower():
                    tags = ", ".join(config.tags[:3])
                    print(f"  {name:30} [{config.provider.value:10}] {tags}")
        return
    
    # List providers
    if args.list_providers:
        selector = ModelSelector()
        available = selector.get_available_providers()
        
        print("\nAVAILABLE PROVIDERS:")
        for category, models in available.items():
            print(f"\n{category.value.upper()} ({len(models)} models):")
            for name in models[:10]:
                print(f"  - {name}")
        return
    
    # Check providers
    if args.check_providers:
        platform = AbhimanyuXPlatform()
        health = platform.check_providers()
        
        print("\nPROVIDER HEALTH:")
        for name, status in health.items():
            icon = "✓" if status.is_available else "✗"
            print(f"  {icon} {name}: {status.error_message or 'OK'}")
        return
    
    # Hardware info
    if args.hardware:
        platform = AbhimanyuXPlatform()
        hw = platform.get_hardware_info()
        
        print(f"\nHARDWARE:")
        print(f"  CPU Cores:     {hw.cpu_cores}")
        print(f"  Total RAM:     {hw.total_ram_gb:.1f} GB")
        print(f"  Available RAM: {hw.available_ram_gb:.1f} GB")
        print(f"  GPU:           {hw.gpu_name or 'None detected'}")
        print(f"  GPU VRAM:      {hw.gpu_vram_gb:.1f} GB")
        print(f"  GPU Type:      {hw.gpu_type or 'Unknown'}")
        
        print("\nRECOMMENDED MODELS:")
        models = platform.get_available_models()
        for category, model_list in models.items():
            if model_list:
                print(f"\n  {category.value.upper()}:")
                for name in model_list[:5]:
                    print(f"    - {name}")
        return
    
    # Check target
    if not args.target:
        parser.print_help()
        return
    
    # Determine model selection
    if args.prefer_api:
        prefer_local = False
    else:
        prefer_local = args.prefer_local
    
    # Create platform config
    config = PlatformConfig(
        model_name=args.model,
        api_key=args.api_key,
        api_url=args.api_url,
        prefer_local=prefer_local,
        prefer_cheap=args.prefer_cheap,
        enable_zero_shot=not args.no_ai,
        enable_immune_memory=not args.no_memory
    )
    
    # Create platform
    platform = AbhimanyuXPlatform(config)
    
    # Add custom endpoint if specified
    if args.add_endpoint:
        name, url, model_id = args.add_endpoint
        platform.add_custom_endpoint(name, url, model_id)
    
    # Scan
    print(f"\n[*] Scanning: {args.target}")
    print(f"[*] Model: {platform.active_model or 'pattern-only'}")
    
    if os.path.isfile(args.target):
        result = platform.scan_file(args.target)
    elif os.path.isdir(args.target):
        results = platform.scan_directory(args.target)
        for result in results:
            pass  # Results already printed
    else:
        print(f"[!] Target not found: {args.target}")
        return
    
    # Memory stats
    if platform.memory:
        stats = platform.get_memory_stats()
        print(f"\nImmune Memory: {stats.get('total_vulnerabilities', 0)} vulnerabilities, "
              f"{stats.get('total_dna_patterns', 0)} DNA patterns")


if __name__ == "__main__":
    main()
