"""
ABHIMANYU X CORE - Fast Orchestrator
Minimal-LLM scanning: rule-based fixes for known vulns, LLM only for novel ones.

Usage:
    python -m abhimanyux.core.fast_orchestrator target.py
    python -m abhimanyux.core.fast_orchestrator target.py --framework flask
    python -m abhimanyux.core.fast_orchestrator target.py --docker --boss-os
"""

import os
import re
import json
import hashlib
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path

from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityLocation, Patch, PatchStatus,
    VerificationResult, ScanResult, Severity, VulnType, AnalysisPhase
)
from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.rewind.targeted_rules import scan_targeted, get_rules_for_file, TargetedRule
from abhimanyux.verifier.engine import VerificationEngine
from abhimanyux.memory.store import ImmuneMemoryStore


class FastOrchestrator:
    """
    Fast Orchestrator — minimal LLM usage.

    Strategy:
    1. Targeted rules (framework-specific) → template fix, no LLM
    2. REWIND heuristic patterns → template fix if available, else LLM
    3. Fuzzing (optional) → LLM only for novel crashes
    4. Verification always runs (no LLM needed)
    """

    def __init__(self, db_path: str = "abhimanyux_memory.db",
                 framework: Optional[str] = None,
                 llm_config=None):
        self.rewind = REWINDEngine()
        self.memory = ImmuneMemoryStore(db_path)
        self.verifier = VerificationEngine()
        self.framework = framework
        self.llm_config = llm_config
        self.scan_count = 0

        # Stats
        self.template_fixes = 0
        self.llm_fixes = 0
        self.llm_calls_saved = 0

    def scan(self, target_path: str, full_scan: bool = False) -> ScanResult:
        """Scan a file or directory with minimal LLM usage."""
        self.scan_count += 1
        scan_id = f"fast-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"

        # Discover files
        if os.path.isfile(target_path):
            files = [target_path]
        elif os.path.isdir(target_path):
            files = self._discover_files(target_path)
        else:
            raise FileNotFoundError(f"Target not found: {target_path}")

        all_vulns = []
        all_patches = []
        all_verifications = []

        for file_path in files:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            vulns, patches, verifications = self._scan_file(code, file_path)
            all_vulns.extend(vulns)
            all_patches.extend(patches)
            all_verifications.extend(verifications)

        # Generate summary
        summary = {
            "total_vulnerabilities": len(all_vulns),
            "total_patches": len(all_patches),
            "template_fixes": self.template_fixes,
            "llm_fixes": self.llm_fixes,
            "llm_calls_saved": self.llm_calls_saved,
            "by_severity": {},
            "by_type": {},
            "by_framework": {},
        }

        for v in all_vulns:
            summary["by_severity"][v.severity.value] = summary["by_severity"].get(v.severity.value, 0) + 1
            summary["by_type"][v.vuln_type.value] = summary["by_type"].get(v.vuln_type.value, 0) + 1

        return ScanResult(
            scan_id=scan_id,
            target_path=target_path,
            vulnerabilities=all_vulns,
            patches=all_patches,
            verifications=all_verifications,
            immune_records=[],
            summary=summary,
            completed_at=datetime.now(timezone.utc)
        )

    def scan_code(self, code: str, filename: str = "inline.py") -> ScanResult:
        """Scan inline code."""
        self.scan_count += 1
        scan_id = f"fast-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.scan_count:04d}"

        vulns, patches, verifications = self._scan_file(code, filename)

        summary = {
            "total_vulnerabilities": len(vulns),
            "total_patches": len(patches),
            "template_fixes": self.template_fixes,
            "llm_fixes": self.llm_fixes,
            "llm_calls_saved": self.llm_calls_saved,
        }

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

    def _scan_file(self, code: str, filename: str) -> Tuple[
        List[Vulnerability], List[Patch], List[VerificationResult]
    ]:
        """Scan a single file with minimal LLM usage."""
        vulns = []
        patches = []
        verifications = []

        # ── Phase 1: Targeted rules (no LLM) ──
        targeted_vulns = scan_targeted(code, filename, self.framework)
        print(f"  [REWIND] Targeted rules: {len(targeted_vulns)} findings")

        for vuln in targeted_vulns:
            # Extract template fix from raw_analysis
            template_fix = self._extract_template_fix(vuln)
            if template_fix and not self._needs_llm_for_fix(vuln):
                # Template-based fix — no LLM call
                patch = self._create_template_patch(vuln, code, template_fix)
                self.template_fixes += 1
                self.llm_calls_saved += 1
            else:
                # Needs LLM — but we'll batch later
                patch = self._create_placeholder_patch(vuln, code)
                self.llm_fixes += 1

            patches.append(patch)

            # Verify
            verification = self.verifier.verify(code, patch.patched_code, vuln, patch)
            verifications.append(verification)

            # Store in memory
            self.memory.store_vulnerability(vuln)
            self.memory.store_patch(patch)

        vulns.extend(targeted_vulns)

        # ── Phase 2: REWIND heuristic patterns (may need LLM for fixes) ──
        rewind_vulns = self.rewind.scan(code, filename)
        print(f"  [REWIND] Heuristic patterns: {len(rewind_vulns)} findings")

        # Deduplicate against targeted findings
        targeted_keys = {(v.vuln_type, v.location.line_start) for v in targeted_vulns}
        new_vulns = [v for v in rewind_vulns if (v.vuln_type, v.location.line_start) not in targeted_keys]

        for vuln in new_vulns:
            # Check if we have a template fix for this type
            template_fix = self._get_template_fix_for_type(vuln.vuln_type)
            if template_fix:
                patch = self._create_template_patch(vuln, code, template_fix)
                self.template_fixes += 1
                self.llm_calls_saved += 1
            else:
                # Novel vulnerability — needs LLM
                patch = self._create_placeholder_patch(vuln, code)
                self.llm_fixes += 1

            patches.append(patch)
            verification = self.verifier.verify(code, patch.patched_code, vuln, patch)
            verifications.append(verification)

            self.memory.store_vulnerability(vuln)
            self.memory.store_patch(patch)

        vulns.extend(new_vulns)

        return vulns, patches, verifications

    def _extract_template_fix(self, vuln: Vulnerability) -> Optional[str]:
        """Extract template fix from vulnerability's raw_analysis field."""
        if not vuln.raw_analysis:
            return None
        match = re.search(r'Template:\n(.*?)(?:\nNeeds LLM:|$)', vuln.raw_analysis, re.DOTALL)
        return match.group(1).strip() if match else None

    def _needs_llm_for_fix(self, vuln: Vulnerability) -> bool:
        """Check if the targeted rule requires LLM for its fix."""
        if not vuln.raw_analysis:
            return True
        return "Needs LLM: True" in vuln.raw_analysis

    def _get_template_fix_for_type(self, vuln_type: VulnType) -> Optional[str]:
        """Get a generic template fix for a vulnerability type."""
        fixes = {
            VulnType.SQL_INJECTION: "Use parameterized queries with ? or %s placeholders",
            VulnType.COMMAND_INJECTION: "Use subprocess.run() with list arguments, no shell=True",
            VulnType.PATH_TRAVERSAL: "Validate paths with os.path.realpath() and check prefix",
            VulnType.XSS: "Escape user input with html.escape() before rendering",
            VulnType.DESERIALIZATION: "Use json.loads() or yaml.safe_load() instead",
            VulnType.HARDCODED_CREDENTIALS: "Move secrets to os.environ.get()",
            VulnType.WEAK_CRYPTO: "Use secrets module for cryptographic randomness",
            VulnType.OPEN_REDIRECT: "Validate redirect URLs against a whitelist",
            VulnType.SSRF: "Validate and whitelist allowed URLs",
            VulnType.INFO_DISCLOSURE: "Disable debug mode in production",
        }
        return fixes.get(vuln_type)

    def _create_template_patch(self, vuln: Vulnerability, code: str, template: str) -> Patch:
        """Create a patch from a template fix (no LLM needed)."""
        # Apply the template as a comment-annotated fix
        patched_code = self._apply_template_fix(code, vuln, template)

        return Patch(
            id=f"tpl-{uuid.uuid4().hex[:12]}",
            vuln_id=vuln.id,
            original_code=code,
            patched_code=patched_code,
            explanation=f"[TEMPLATE FIX] {template}",
            status=PatchStatus.GENERATED
        )

    def _apply_template_fix(self, code: str, vuln: Vulnerability, template: str) -> str:
        """Apply a template fix to the code."""
        lines = code.split('\n')
        vuln_line = vuln.location.line_start - 1

        if vuln_line < 0 or vuln_line >= len(lines):
            return code

        original_line = lines[vuln_line]

        # Apply specific transformations based on vulnerability type
        if vuln.vuln_type == VulnType.COMMAND_INJECTION:
            if 'os.system(' in original_line:
                # Extract the argument
                match = re.search(r'os\.system\((.+?)\)', original_line)
                if match:
                    arg = match.group(1)
                    indent = len(original_line) - len(original_line.lstrip())
                    lines[vuln_line] = (
                        f"{' ' * indent}import subprocess\n"
                        f"{' ' * indent}subprocess.run({arg}, shell=False, check=True)"
                    )
            elif 'os.popen(' in original_line:
                match = re.search(r'os\.popen\((.+?)\)', original_line)
                if match:
                    arg = match.group(1)
                    indent = len(original_line) - len(original_line.lstrip())
                    lines[vuln_line] = (
                        f"{' ' * indent}import subprocess\n"
                        f"{' ' * indent}result = subprocess.run({arg}, capture_output=True, text=True)\n"
                        f"{' ' * indent}output = result.stdout"
                    )

        elif vuln.vuln_type == VulnType.SQL_INJECTION:
            if 'f"' in original_line or "f'" in original_line:
                # Convert f-string query to parameterized
                indent = len(original_line) - len(original_line.lstrip())
                lines[vuln_line] = (
                    f"{' ' * indent}# TODO: Convert to parameterized query\n"
                    f"{' ' * indent}{original_line.strip()}"
                )

        elif vuln.vuln_type == VulnType.DESERIALIZATION:
            if 'pickle.loads' in original_line:
                indent = len(original_line) - len(original_line.lstrip())
                lines[vuln_line] = original_line.replace('pickle.loads', 'json.loads')
            elif 'yaml.load(' in original_line:
                lines[vuln_line] = original_line.replace('yaml.load(', 'yaml.safe_load(')

        elif vuln.vuln_type == VulnType.HARDCODED_CREDENTIALS:
            match = re.search(r'(\w+)\s*=\s*["\'](.+?)["\']', original_line)
            if match:
                var_name = match.group(1)
                indent = len(original_line) - len(original_line.lstrip())
                lines[vuln_line] = (
                    f"{' ' * indent}{var_name} = os.environ.get(\"{var_name.upper()}\")\n"
                    f"{' ' * indent}if not {var_name}:\n"
                    f"{' ' * indent}    raise ValueError(\"{var_name.upper()} environment variable not set\")"
                )

        elif vuln.vuln_type == VulnType.WEAK_CRYPTO:
            if 'random.randint' in original_line:
                indent = len(original_line) - len(original_line.lstrip())
                lines[vuln_line] = (
                    f"{' ' * indent}import secrets\n"
                    f"{' ' * indent}{original_line.split('=')[0].strip()} = secrets.token_hex(32)"
                )

        elif vuln.vuln_type == VulnType.BUFFER_OVERFLOW:
            if 'strcpy(' in original_line:
                lines[vuln_line] = original_line.replace('strcpy(', 'strncpy(').rstrip(')') + ', sizeof(dest) - 1)'
            elif 'gets(' in original_line:
                lines[vuln_line] = original_line.replace('gets(', 'fgets(').rstrip(')') + ', sizeof(buffer), stdin)'

        elif vuln.vuln_type == VulnType.FORMAT_STRING:
            match = re.search(r'printf\s*\(\s*(\w+)\s*\)', original_line)
            if match:
                var = match.group(1)
                indent = len(original_line) - len(original_line.lstrip())
                lines[vuln_line] = f"{' ' * indent}printf(\"%s\", {var});"

        return '\n'.join(lines)

    def _create_placeholder_patch(self, vuln: Vulnerability, code: str) -> Patch:
        """Create a placeholder patch that marks the vuln as needing LLM attention."""
        return Patch(
            id=f"llm-{uuid.uuid4().hex[:12]}",
            vuln_id=vuln.id,
            original_code=code,
            patched_code=code,  # Unchanged — needs LLM
            explanation=f"[LLM NEEDED] {vuln.description}. Apply: {self._get_template_fix_for_type(vuln.vuln_type) or 'Manual review required'}",
            status=PatchStatus.GENERATED
        )

    def _discover_files(self, directory: str) -> List[str]:
        """Discover source files in directory."""
        extensions = {'.py', '.c', '.h', '.cpp', '.cc', '.js', '.ts'}
        skip_dirs = {'node_modules', 'venv', '__pycache__', '.git', 'vendor', 'dist', 'build'}
        files = []

        for root, dirs, filenames in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_dirs]
            for fn in filenames:
                if any(fn.endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, fn))

        return sorted(files)

    def print_report(self, result: ScanResult):
        """Print a fast scan report."""
        print("\n" + "=" * 70)
        print("ABHIMANYU X CORE — FAST SCAN REPORT")
        print("=" * 70)
        print(f"\nScan ID: {result.scan_id}")
        print(f"Target: {result.target_path}")
        print(f"Completed: {result.completed_at}")

        summary = result.summary

        print(f"\n{'─' * 70}")
        print("SUMMARY")
        print(f"{'─' * 70}")
        print(f"  Vulnerabilities Found:    {summary.get('total_vulnerabilities', 0)}")
        print(f"  Patches Generated:        {summary.get('total_patches', 0)}")
        print(f"  Template Fixes (no LLM):  {summary.get('template_fixes', 0)}")
        print(f"  LLM Fixes Needed:         {summary.get('llm_fixes', 0)}")
        print(f"  LLM Calls Saved:          {summary.get('llm_calls_saved', 0)}")

        if summary.get('by_severity'):
            print(f"\n  By Severity:")
            for sev, count in sorted(summary['by_severity'].items()):
                print(f"    {sev.upper():12s}: {count}")

        if summary.get('by_type'):
            print(f"\n  By Type:")
            for vtype, count in sorted(summary['by_type'].items()):
                print(f"    {vtype:24s}: {count}")

        print(f"\n{'─' * 70}")
        print("VULNERABILITIES")
        print(f"{'─' * 70}")

        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n  {i}. [{vuln.severity.value.upper()}] {vuln.title}")
            print(f"     Type: {vuln.vuln_type.value}")
            print(f"     Location: {vuln.location.file_path}:{vuln.location.line_start}")
            print(f"     CWE: {vuln.cwe_id or 'N/A'}")

        print(f"\n{'─' * 70}")
        print("PATCHES")
        print(f"{'─' * 70}")

        for patch in result.patches:
            fix_type = "📝 TEMPLATE" if patch.id.startswith("tpl-") else "🤖 LLM NEEDED"
            print(f"\n  {patch.id} [{fix_type}]")
            print(f"  {patch.explanation[:150]}")

        print(f"\n{'─' * 70}")
        print("VERIFICATION")
        print(f"{'─' * 70}")

        for v in result.verifications:
            status = "✓ PASS" if v.all_tests_pass else "✗ FAIL"
            print(f"\n  {v.patch_id}: {status}")
            print(f"    Compile: {'✓' if v.compile_success else '✗'}")
            print(f"    Exploit Blocked: {'✓' if v.exploit_blocked else '✗'}")
            print(f"    Regression: {'✓' if v.regression_pass else '✗'}")
            print(f"    Behavior: {'✓' if v.behavior_preserved else '✗'}")

        print(f"\n{'─' * 70}")
        print("IMMUNE MEMORY")
        print(f"{'─' * 70}")
        stats = self.memory.get_statistics()
        print(f"  Vulnerabilities in Memory: {stats['total_vulnerabilities']}")
        print(f"  DNA Patterns: {stats['total_dna_patterns']}")
        print(f"  Patches Stored: {stats['total_patches']}")

        print(f"\n{'=' * 70}")
        print("SCAN COMPLETE")
        print(f"{'=' * 70}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

import uuid

def main():
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="ABHIMANYU X CORE — Fast Scanner (minimal LLM)"
    )
    parser.add_argument("target", nargs="?", default="abhimanyux/vulnerable_targets/",
                        help="Target file or directory")
    parser.add_argument("--framework", choices=["flask", "django", "fastapi", "express", "python", "c"],
                        help="Target specific framework")
    parser.add_argument("--docker", action="store_true",
                        help="Build Docker artifact after scan")
    parser.add_argument("--boss-os", action="store_true",
                        help="Use BOSS OS base image for Docker")
    parser.add_argument("--output", "-o", help="Output report JSON path")

    args = parser.parse_args()

    print("=" * 70)
    print("ABHIMANYU X CORE — FAST SCANNER")
    print("Minimal LLM Usage | Template-Based Fixes")
    print("=" * 70)

    # Auto-detect framework if not specified
    framework = args.framework
    if not framework and args.target.endswith('.py'):
        framework = "python"
    elif not framework and args.target.endswith(('.c', '.h', '.cpp')):
        framework = "c"

    print(f"\n[*] Target: {args.target}")
    print(f"[*] Framework: {framework or 'auto-detect'}")

    orchestrator = FastOrchestrator(framework=framework)
    result = orchestrator.scan(args.target)

    orchestrator.print_report(result)

    # Save report
    output = args.output or f"fast_scan_{result.scan_id}.json"
    with open(output, 'w') as f:
        json.dump(result.model_dump(), f, indent=2, default=str)
    print(f"\n[+] Report saved to: {output}")

    # Build Docker if requested
    if args.docker:
        print("\n[*] Building Docker artifact...")
        build_docker_artifact(args.target, args.boss_os)


def build_docker_artifact(target: str, use_boss_os: bool = False):
    """Build a Docker artifact for the scanned project."""
    dockerfile = generate_dockerfile(use_boss_os)
    docker_path = os.path.join(os.path.dirname(target), "Dockerfile.abhimanyux")

    with open(docker_path, 'w') as f:
        f.write(dockerfile)

    print(f"[+] Dockerfile written to: {docker_path}")
    print(f"[*] Build with: docker build -f {docker_path} -t abhimanyux-app .")


def generate_dockerfile(use_boss_os: bool = False) -> str:
    """Generate a Dockerfile for the project."""
    if use_boss_os:
        base = "bosslinux/boss:latest"
        pkg_manager = "apt-get"
        install_cmd = "apt-get install -y"
    else:
        base = "python:3.12-slim"
        pkg_manager = "apt-get"
        install_cmd = "apt-get install -y"

    return f"""# ABHIMANYU X CORE — Docker Artifact
# {'BOSS OS (Indian Government Linux)' if use_boss_os else 'Python 3.12 Slim'} Base
FROM {base}

# Labels
LABEL maintainer="abhimanyux-core"
LABEL description="ABHIMANYU X CORE - Autonomous Cyber Reasoning System"
LABEL version="2.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN {pkg_manager} update && {install_cmd} \\
    gcc \\
    g++ \\
    make \\
    curl \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user for security
RUN useradd -m -s /bin/bash scanner
USER scanner

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Default command: run the API server
CMD ["python", "-m", "abhimanyux.api.server"]
"""


if __name__ == "__main__":
    main()
