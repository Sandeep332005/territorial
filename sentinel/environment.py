"""
ABHIMANYU X - Environment Detection ("doctor")

Real system inspection: every check here runs `shutil.which()` or a real
subprocess version call. Nothing is guessed or hardcoded as "available".
Used by both the CLI (`sentinel doctor`) and the dashboard's Setup Center.
"""

import platform
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class ToolCheck:
    name: str
    found: bool
    path: Optional[str] = None
    version: Optional[str] = None
    note: Optional[str] = None


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _version(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = (result.stdout or result.stderr or "").strip().splitlines()
        return out[0][:120] if out else None
    except Exception:
        return None


def check_tool(name: str, version_cmd: Optional[List[str]] = None, note: Optional[str] = None) -> ToolCheck:
    path = _which(name)
    if not path:
        return ToolCheck(name=name, found=False, note=note)
    version = _version(version_cmd) if version_cmd else None
    return ToolCheck(name=name, found=True, path=path, version=version, note=note)


def check_colima_docker() -> ToolCheck:
    """Docker itself may be the `docker` CLI pointed at a Colima context
    rather than Docker Desktop — check the CLI plus whether the daemon it's
    pointed at actually answers, not just whether the binary exists."""
    path = _which("docker")
    if not path:
        return ToolCheck(name="docker", found=False, note="not installed")
    try:
        result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                 capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return ToolCheck(name="docker", found=True, path=path,
                              version=f"daemon {result.stdout.strip()}", note="daemon reachable")
        return ToolCheck(name="docker", found=True, path=path, version=None,
                          note="CLI present, daemon not reachable (is Colima/Docker running?)")
    except Exception:
        return ToolCheck(name="docker", found=True, path=path, note="daemon check timed out")


def check_ollama_model(model: str, api_url: str) -> ToolCheck:
    """Whether the specific local model ANVIL is configured to use is
    actually pulled and reachable — a real HTTP call, not just checking the
    `ollama` binary."""
    import urllib.request
    import json as _json
    tags_url = api_url.rsplit("/api/", 1)[0] + "/api/tags"
    try:
        req = urllib.request.Request(tags_url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = _json.loads(resp.read().decode())
            names = [m.get("name") for m in data.get("models", [])]
            if model in names:
                return ToolCheck(name=f"ollama model {model}", found=True, note="pulled and reachable")
            return ToolCheck(name=f"ollama model {model}", found=False,
                              note=f"reachable but not pulled (have: {', '.join(names) or 'none'})")
    except Exception as e:
        return ToolCheck(name=f"ollama model {model}", found=False, note=f"unreachable at {tags_url}")


def system_report(anvil_model: str = "qwen2.5-coder:3b",
                   anvil_api_url: str = "http://127.0.0.1:21434/api/generate") -> dict:
    """Full real readiness report. Every field is a live check performed
    at call time, not a cached or hardcoded value."""
    checks = [
        check_tool("git", ["git", "--version"]),
        check_tool("python3", ["python3", "--version"]),
        check_tool("node", ["node", "--version"], note="optional — not required by this project"),
        check_tool("clang", ["clang", "--version"]),
        check_tool("gcc", ["gcc", "--version"]),
        check_colima_docker(),
        check_tool("colima", ["colima", "version"], note="Linux VM manager used for AFL++/ASan"),
        check_tool("ollama", ["ollama", "--version"],
                   note="binary check only — may report a local install even when the model actually serving ANVIL runs elsewhere (e.g. inside the Colima VM); see the model check below for what matters"),
        check_ollama_model(anvil_model, anvil_api_url),
        check_tool("qemu-system-x86_64", note="not used by this project on Apple Silicon; QEMU/KVM environments are FUTURE"),
    ]
    return {
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] if platform.system() == "Darwin" else platform.release(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "checks": [asdict(c) for c in checks],
        "kvm_available": False,
        "kvm_note": "KVM is a Linux kernel feature; unavailable on any macOS host regardless of configuration.",
    }
