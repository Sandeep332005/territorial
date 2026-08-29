"""
ABHIMANYU X CORE - Main Orchestrator
Autonomous Cyber Reasoning & Software Immunization

Coordinates all engines:
- REWIND: Static analysis
- Fuzz Engine: Dynamic analysis
- ANVIL: Patch generation
- Verification: Proof generation
- Immune Memory: Knowledge storage
"""

import os
import json
from typing import List, Dict, Optional
from datetime import datetime, timezone
from pathlib import Path

from abhimanyux.models.schemas import (
    Vulnerability, Patch, VerificationResult, ImmuneRecord,
    ScanRequest, ScanResult, VulnerabilityDNA, VulnType, Severity
)
from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.fuzzer.engine import FuzzEngine
from abhimanyux.anvil.engine import ANVILEngine, LLMConfig
from abhimanyux.verifier.engine import VerificationEngine
from abhimanyux.memory.store import ImmuneMemoryStore


class AbhimanyuXCore:
    """
    ABHIMANYU X CORE - Autonomous Cyber Immune System
    
    The main orchestrator that coordinates all engines to:
    1. Discover vulnerabilities (REWIND + Fuzzer)
    2. Understand root cause (ANVIL)
    3. Generate patches (ANVIL)
    4. Verify fixes (Verification Pipeline)
    5. Remember and learn (Immune Memory)
    """
    
    def __init__(self, llm_config: Optional[LLMConfig] = None, 
                 db_path: str = "abhimanyux_memory.db"):
        """
        Initialize ABHIMANYU X CORE
        
        Args:
            llm_config: Configuration for LLM interaction
            db_path: Path to immune memory database
        """
        # Initialize engines
        self.rewind = REWINDEngine()
        self.memory = ImmuneMemoryStore(db_path)
        self.anvil = ANVILEngine(llm_config, memory=self.memory)
        self.fuzzer = FuzzEngine(anvil=self.anvil)
        self.verifier = VerificationEngine()
        
        # Statistics
        self.scan_count = 0
        self.vulns_found = 0
        self.patches_generated = 0
        self.patches_verified = 0
    
    def scan(self, target_path: str, language: str = "python", 
             full_scan: bool = True) -> ScanResult:
        """
        Perform a complete security scan on the target
        
        Args:
            target_path: Path to the target code/file/directory
            language: Programming language
            full_scan: Whether to include fuzzing and full verification
            
        Returns:
            Complete scan result with vulnerabilities, patches, and verifications
        """
        self.scan_count += 1
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"

        # Recalibrate REWIND's confidence scores from every verified outcome
        # seen so far, before scanning with them.
        self.evolve()

        # Read target
        if os.path.isfile(target_path):
            files = [target_path]
        elif os.path.isdir(target_path):
            files = self.discover_files(target_path, language)
        else:
            raise FileNotFoundError(f"Target not found: {target_path}")
        
        all_vulnerabilities = []
        all_patches = []
        all_verifications = []
        all_immune_records = []
        
        # Process each file
        for file_path in files:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Phase 1: Static Analysis (REWIND)
            print(f"[*] REWIND: Analyzing {file_path}...")
            vulns = self.rewind.scan(code, file_path)
            all_vulnerabilities.extend(vulns)
            
            # Phase 2: Dynamic Analysis (Fuzzer) - if enabled
            if full_scan:
                print(f"[*] FUZZER: Testing {file_path}...")
                fuzz_result = self.fuzzer.fuzz(code)
                # Convert fuzz crashes to vulnerabilities
                for crash in fuzz_result.crashes:
                    vuln = Vulnerability(
                        id=f"fuzz-{hash(str(crash))[:12]}",
                        vuln_type=VulnType.OTHER,
                        severity=Severity.HIGH,
                        title=f"Fuzzing crash: {crash.get('crash_type', 'unknown')}",
                        description=f"Crash discovered through fuzzing",
                        location={"file_path": file_path, "line_start": 0},
                        confidence=0.7,
                        source="fuzzing"
                    )
                    all_vulnerabilities.append(vuln)
            
            # Phase 3: Patch Generation (ANVIL)
            for vuln in vulns:
                print(f"[*] ANVIL: Generating patch for {vuln.title}...")
                patch = self.anvil.analyze_and_patch(code, vuln)
                all_patches.append(patch)
                self.patches_generated += 1
                
                # Phase 4: Verification
                print(f"[*] VERIFY: Checking patch {patch.id}...")
                verification = self.verifier.verify(
                    code, patch.patched_code, vuln, patch
                )
                all_verifications.append(verification)
                
                if verification.all_tests_pass:
                    self.patches_verified += 1
                    patch.status = "verified"
                
                # Phase 5: Store in Immune Memory
                self.memory.store_vulnerability(vuln)
                self.memory.store_patch(patch)
                
                # Create DNA pattern
                dna = self.memory.create_dna(vuln, patch.explanation)
                
                # Store immune record
                self.memory.store_immune_record(vuln.id, patch.id, dna.id)
        
        self.vulns_found += len(all_vulnerabilities)
        
        # Generate summary
        summary = self._generate_summary(
            all_vulnerabilities, all_patches, all_verifications
        )
        
        return ScanResult(
            scan_id=scan_id,
            target_path=target_path,
            vulnerabilities=all_vulnerabilities,
            patches=all_patches,
            verifications=all_verifications,
            immune_records=all_immune_records,
            summary=summary,
            completed_at=datetime.now(timezone.utc)
        )
    
    def scan_code(self, code: str, filename: str = "inline.py") -> ScanResult:
        """
        Scan inline code (not from file)
        
        Args:
            code: Source code to scan
            filename: Filename for reporting
            
        Returns:
            Scan result
        """
        self.scan_count += 1
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"

        self.evolve()

        # Static analysis
        vulns = self.rewind.scan(code, filename)
        
        # Generate patches
        patches = []
        verifications = []
        
        for vuln in vulns:
            patch = self.anvil.analyze_and_patch(code, vuln)
            patches.append(patch)
            
            verification = self.verifier.verify(
                code, patch.patched_code, vuln, patch
            )
            verifications.append(verification)
            
            # Store in memory
            self.memory.store_vulnerability(vuln)
            self.memory.store_patch(patch)
            dna = self.memory.create_dna(vuln, patch.explanation)
            self.memory.store_immune_record(vuln.id, patch.id, dna.id)
        
        self.vulns_found += len(vulns)
        self.patches_generated += len(patches)
        
        summary = self._generate_summary(vulns, patches, verifications)
        
        return ScanResult(
            scan_id=scan_id,
            target_path=filename,
            vulnerabilities=vulns,
            patches=patches,
            verifications=verifications,
            immune_records=[],
            summary=summary,
            completed_at=datetime.now(timezone.utc)
        )
    
    def evolve(self) -> int:
        """
        Close the feedback loop: recalibrate REWIND's pattern confidences
        using verified-patch outcomes accumulated in Immune Memory so far.
        Called automatically at the start of every scan so each one benefits
        from the system's own track record instead of confidence scores
        staying fixed at their initial hand-tuned values forever. Safe to
        call with an empty/sparse memory — patterns without enough samples
        are simply left untouched.

        Returns the number of patterns whose confidence was adjusted.
        """
        reliability = self.memory.get_rule_reliability()
        return self.rewind.apply_feedback(reliability)

    def get_memory_stats(self) -> Dict:
        """Get immune memory statistics"""
        return self.memory.get_statistics()
    
    def search_similar(self, vuln_type: VulnType) -> List[Dict]:
        """Search for similar vulnerabilities in memory"""
        return self.memory.search_by_type(vuln_type)
    
    def get_fix_strategies(self, vuln_type: VulnType) -> List[str]:
        """Get known fix strategies for a vulnerability type"""
        return self.memory.get_fix_strategies(vuln_type)
    
    def discover_files(self, directory: str, language: str) -> List[str]:
        """Discover files in directory"""
        extensions = {
            "python": [".py"],
            "c": [".c", ".h"],
            "cpp": [".cpp", ".cc", ".cxx", ".h", ".hpp"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"]
        }
        
        exts = extensions.get(language, [".py", ".c", ".cpp", ".js"])
        files = []
        
        for root, dirs, filenames in os.walk(directory):
            # Skip hidden dirs and common non-source dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') 
                       and d not in ['node_modules', 'venv', '__pycache__', 'vendor']]
            
            for filename in filenames:
                if any(filename.endswith(ext) for ext in exts):
                    files.append(os.path.join(root, filename))
        
        return files
    
    def _generate_summary(self, vulns: List[Vulnerability], 
                         patches: List[Patch],
                         verifications: List[VerificationResult]) -> Dict:
        """Generate scan summary"""
        severity_counts = {}
        type_counts = {}
        verified_count = 0
        
        for v in vulns:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            type_counts[v.vuln_type.value] = type_counts.get(v.vuln_type.value, 0) + 1
        
        for verification in verifications:
            if verification.all_tests_pass:
                verified_count += 1
        
        return {
            "total_vulnerabilities": len(vulns),
            "total_patches": len(patches),
            "verified_patches": verified_count,
            "by_severity": severity_counts,
            "by_type": type_counts,
            "scan_stats": {
                "rewind_scans": self.rewind.get_stats()["total_scans"],
                "fuzzes": self.fuzzer.get_stats()["total_fuzzes"],
                "patches_generated": self.anvil.get_stats()["total_patches"],
                "verifications": self.verifier.get_stats()["total_verifications"]
            }
        }
    
    def print_report(self, result: ScanResult):
        """Print a formatted scan report"""
        print("\n" + "="*70)
        print("ABHIMANYU X CORE - SECURITY SCAN REPORT")
        print("="*70)
        print(f"\nScan ID: {result.scan_id}")
        print(f"Target: {result.target_path}")
        print(f"Completed: {result.completed_at}")
        
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
        print("GENERATED PATCHES")
        print("-"*70)
        
        for patch in result.patches:
            print(f"\nPatch: {patch.id}")
            print(f"Status: {patch.status.value}")
            print(f"Explanation: {patch.explanation[:200]}...")
        
        print("\n" + "-"*70)
        print("VERIFICATION RESULTS")
        print("-"*70)
        
        for verification in result.verifications:
            print(f"\nPatch: {verification.patch_id}")
            print(f"  Compile: {'✓' if verification.compile_success else '✗'}")
            print(f"  Exploit Blocked: {'✓' if verification.exploit_blocked else '✗'}")
            print(f"  Regression: {'✓' if verification.regression_pass else '✗'}")
            print(f"  Behavior: {'✓' if verification.behavior_preserved else '✗'}")
            print(f"  All Tests: {'✓' if verification.all_tests_pass else '✗'}")
        
        print("\n" + "-"*70)
        print("IMMUNE MEMORY")
        print("-"*70)
        
        stats = self.memory.get_statistics()
        print(f"  Total Vulnerabilities in Memory: {stats['total_vulnerabilities']}")
        print(f"  DNA Patterns: {stats['total_dna_patterns']}")
        print(f"  Patches Stored: {stats['total_patches']}")
        print(f"  Immune Records: {stats['total_immune_records']}")
        
        print("\n" + "="*70)
        print("SCAN COMPLETE")
        print("="*70)


# CLI Interface
def main():
    """Main CLI entry point"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ABHIMANYU X CORE - Autonomous Cyber Reasoning System"
    )
    parser.add_argument("target", nargs="?", default="abhimanyux/vulnerable_targets/",
                        help="Target file or directory to scan")
    parser.add_argument("--provider", choices=["local", "gemini", "claude", "deepseek"],
                        default="local", help="LLM provider")
    parser.add_argument("--model", help="Model name")
    parser.add_argument("--api-key", help="API key for cloud providers")
    parser.add_argument("--api-url", help="API endpoint URL")
    parser.add_argument("--watch", action="store_true",
                        help="Continuously monitor target for changes instead of a one-shot scan")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                        help="Seconds between checks in --watch mode")

    args = parser.parse_args()
    
    print("="*70)
    print("ABHIMANYU X CORE")
    print("Autonomous Cyber Reasoning & Software Immunization System")
    print("="*70)
    
    # Configure LLM
    llm_config = LLMConfig(provider=args.provider)
    if args.model:
        llm_config.model = args.model
    if args.api_key:
        llm_config.api_key = args.api_key
    if args.api_url:
        llm_config.api_url = args.api_url
    
    # Initialize
    sentinel = AbhimanyuXCore(llm_config=llm_config)
    
    # Run scan
    print(f"\n[*] Scanning: {args.target}")
    print(f"[*] Provider: {args.provider}")
    print(f"[*] Model: {llm_config.model}")

    if args.watch:
        from abhimanyux.watch.engine import WatchEngine

        print(f"[*] Watching: {args.target} (every {args.poll_interval}s, Ctrl+C to stop)\n")
        watcher = WatchEngine(sentinel, poll_interval=args.poll_interval)

        def report(event):
            marker = {"new": "[NEW]", "regression": "[REGRESSION]", "resolved": "[RESOLVED]"}[event.event_type]
            print(f"{marker} {event.file_path}: {event.detail}")

        try:
            watcher.watch(args.target, on_event=report)
        except KeyboardInterrupt:
            print(f"\n[*] Stopped after {watcher.checks_run} checks")
        return

    result = sentinel.scan(args.target)

    # Print report
    sentinel.print_report(result)

    # Save results
    output_file = f"abhimanyux_report_{result.scan_id}.json"
    with open(output_file, 'w') as f:
        json.dump(result.model_dump(), f, indent=2, default=str)

    print(f"\n[+] Full report saved to: {output_file}")


if __name__ == "__main__":
    main()
