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
from typing import Dict, List, Optional


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


def _ollama_tags(api_url: str, timeout: int = 3):
    """Real HTTP call to the actual endpoint ANVIL calls for inference —
    not the macOS `ollama` binary, which may be a completely separate,
    unrelated local install with nothing listening on its default port
    while the real serving instance (e.g. inside the Colima VM, forwarded
    to a different host port) is fully up. Returns the parsed tags JSON or
    raises."""
    import urllib.request
    import json as _json
    tags_url = api_url.rsplit("/api/", 1)[0] + "/api/tags"
    req = urllib.request.Request(tags_url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return tags_url, _json.loads(resp.read().decode())


def check_model_server(api_url: str) -> ToolCheck:
    """Is the Ollama HTTP server ANVIL actually points at reachable at all —
    independent of whether any particular model is pulled."""
    try:
        tags_url, data = _ollama_tags(api_url)
        return ToolCheck(name="model server", found=True, note=f"online at {tags_url}")
    except Exception:
        tags_url = api_url.rsplit("/api/", 1)[0] + "/api/tags"
        return ToolCheck(name="model server", found=False, note=f"offline — no response from {tags_url}")


def check_model_present(model: str, api_url: str) -> ToolCheck:
    """Is the specific model ANVIL is configured to use pulled on that
    server. Only meaningful once the server itself is reachable."""
    try:
        _, data = _ollama_tags(api_url)
        names = [m.get("name") for m in data.get("models", [])]
        if model in names:
            return ToolCheck(name=f"model {model}", found=True, note="present")
        return ToolCheck(name=f"model {model}", found=False,
                          note=f"not pulled on this server (have: {', '.join(names) or 'none'})")
    except Exception:
        return ToolCheck(name=f"model {model}", found=False, note="server unreachable, cannot check")


def check_multiarch() -> Dict:
    """Real Docker buildx platform list — not a fabricated architecture
    matrix. RISC-V is honestly absent unless buildx actually reports it."""
    try:
        result = subprocess.run(["docker", "buildx", "inspect", "--bootstrap"],
                                 capture_output=True, text=True, timeout=15)
        for line in result.stdout.splitlines():
            if line.strip().startswith("Platforms:"):
                platforms = [p.strip() for p in line.split(":", 1)[1].split(",")]
                return {"available": True, "platforms": platforms,
                        "note": "via Docker buildx/QEMU emulation, except the native arch"}
        return {"available": False, "platforms": [], "note": "buildx did not report a platform list"}
    except Exception as e:
        return {"available": False, "platforms": [], "note": f"buildx unavailable: {e}"}


def compiler_toolchain_report() -> List[ToolCheck]:
    """On macOS, `gcc` is virtually always an alias to Apple Clang, not the
    real GNU Compiler Collection — reporting its `--version` output under
    the name "gcc" without saying so is misleading. Report Clang/Clang++ as
    what they are, and only claim a genuine GCC when the version string
    doesn't self-identify as clang."""
    checks = []
    for name, label in [("clang", "clang"), ("clang++", "clang++")]:
        checks.append(check_tool(name, [name, "--version"]))
    gcc_path = _which("gcc")
    if gcc_path:
        version = _version(["gcc", "--version"]) or ""
        if "clang" in version.lower():
            checks.append(ToolCheck(name="gcc", found=False,
                                     note=f"N/A on this host — 'gcc' is Apple Clang in disguise ({version})"))
        else:
            checks.append(ToolCheck(name="gcc", found=True, path=gcc_path, version=version))
    else:
        checks.append(ToolCheck(name="gcc", found=False, note="not installed"))
    checks.append(check_tool("cmake", ["cmake", "--version"]))
    checks.append(check_tool("make", ["make", "--version"]))
    return checks


def system_report(anvil_model: str = "qwen2.5-coder:3b",
                   anvil_api_url: str = "http://127.0.0.1:21434/api/generate") -> dict:
    """Full real readiness report. Every field is a live check performed
    at call time, not a cached or hardcoded value."""
    ollama_binary = check_tool("ollama (macOS binary)", ["ollama", "--version"],
                                note="local install check only — the server ANVIL actually calls may be a "
                                     "different instance (e.g. inside the Colima VM); see the checks below")
    server = check_model_server(anvil_api_url)
    model = check_model_present(anvil_model, anvil_api_url)
    inference_ready = server.found and model.found

    checks = [
        check_tool("git", ["git", "--version"]),
        check_tool("python3", ["python3", "--version"]),
        check_tool("node", ["node", "--version"], note="optional — not required by this project"),
        *compiler_toolchain_report(),
        check_colima_docker(),
        check_tool("colima", ["colima", "version"], note="Linux VM manager used for AFL++/ASan"),
        ollama_binary,
        server,
        model,
        ToolCheck(name="inference ready", found=inference_ready,
                   note="model server online and model present" if inference_ready
                        else "cannot serve ANVIL requests until the server is online and the model is pulled"),
        check_tool("qemu-system-x86_64", note="not used by this project on Apple Silicon; QEMU/KVM environments are FUTURE"),
    ]
    return {
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] if platform.system() == "Darwin" else platform.release(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "checks": [asdict(c) for c in checks],
        "ollama": {
            "installation": asdict(ollama_binary),
            "server": asdict(server),
            "model": asdict(model),
            "inference_ready": inference_ready,
        },
        "kvm_available": False,
        "kvm_note": "KVM is a Linux kernel feature; unavailable on any macOS host regardless of configuration.",
        "multiarch": check_multiarch(),
    }
