#!/usr/bin/env python3
"""
ABHIMANYU X - Command Line Interface

    python -m abhimanyux.sentinel.cli doctor
    python -m abhimanyux.sentinel.cli scan <file-or-dir>
    python -m abhimanyux.sentinel.cli targets
    python -m abhimanyux.sentinel.cli environments
    python -m abhimanyux.sentinel.cli mission

Every subcommand calls the real engine directly (REWINDEngine, ANVILEngine,
VerificationEngine, ImmuneMemoryStore, SentinelOrchestrator) — this is not a
separate reimplementation, it is a thin argparse wrapper over the same code
the web dashboard drives.
"""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))


# Checks the live mission actually depends on: real commit analysis (git),
# the Colima VM sandbox (compile/exploit-replay/sanitizer runs happen
# there), and a reachable local LLM (ANVIL). Everything else in the report
# (node, cmake, host gcc/clang, the macOS ollama binary, qemu) is either
# optional or checked purely for information — see system_report().
_ESSENTIAL_CHECKS = {"git", "docker", "colima", "inference ready"}


def cmd_doctor(args):
    from abhimanyux.sentinel.environment import system_report
    report = system_report()
    print(f"OS: {report['os']} {report['os_version']} ({report['arch']})")
    print(f"Python: {report['python_version']}")
    print()
    ok, missing, missing_essential = 0, [], []
    for c in report["checks"]:
        mark = "✓" if c["found"] else "○"
        line = f"  {mark} {c['name']}"
        if c.get("version"):
            line += f"  — {c['version']}"
        elif c.get("note"):
            line += f"  — {c['note']}"
        print(line)
        if c["found"]:
            ok += 1
        else:
            missing.append(c["name"])
            if c["name"] in _ESSENTIAL_CHECKS:
                missing_essential.append(c["name"])
    print()
    print(f"{ok}/{len(report['checks'])} checks passed.")
    if missing:
        print(f"Missing: {', '.join(missing)}")
    print(f"KVM: unavailable — {report['kvm_note']}")
    print()
    if not missing_essential:
        print("SYSTEM READY")
    else:
        print(f"SYSTEM NOT READY — missing required: {', '.join(missing_essential)}")
    return 0


def cmd_scan(args):
    from abhimanyux.rewind.engine import REWINDEngine
    path = Path(args.target)
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1
    engine = REWINDEngine()
    files = [path] if path.is_file() else list(path.rglob("*.py")) + list(path.rglob("*.c"))
    total = 0
    for f in files:
        try:
            code = f.read_text()
        except Exception:
            continue
        findings = engine.scan(code, str(f))
        for v in findings:
            print(f"{v.severity.value.upper():9s} {v.cwe_id or '-':10s} {f}:{v.location.line_start}  {v.title}")
            total += 1
    print(f"\n{total} finding(s) across {len(files)} file(s).")
    return 0


def cmd_targets(args):
    print("REAL / MEASURED:")
    print("  secure_packet_parser      C     Memory safety (CWE-120 memcpy overflow) — Target A")
    print("  network_protocol_parser   C     Memory safety (CWE-120 memcpy overflow) — Target B, Immune Transfer")
    print()
    print("FUTURE (catalog entries, no real pipeline built yet):")
    for name, lang, cls in [
        ("authentication-service", "C++", "Input validation"),
        ("image-metadata-parser", "C/C++", "Memory safety"),
        ("archive-parser", "C++", "Malformed input handling"),
        ("web-api-service", "Python", "Input validation"),
    ]:
        print(f"  {name:26s} {lang:6s} {cls}")
    return 0


def cmd_environments(args):
    from abhimanyux.sentinel.environment import check_colima_docker
    docker = check_colima_docker()
    print(f"REAL: local process           {'●' if True else '○'} available")
    print(f"REAL: docker container        {'●' if docker.found and docker.note == 'daemon reachable' else '○'} "
          f"{docker.note}")
    print("FUTURE: linux VM (QEMU/KVM)   ○ not implemented — KVM unavailable on macOS")
    print("FUTURE: windows VM             ○ not implemented")
    return 0


DASHBOARD_URL = "http://127.0.0.1:5050"


def _dashboard_reachable(url: str = DASHBOARD_URL, timeout: float = 1.5) -> bool:
    """Real HTTP probe — no assumption the dashboard is running."""
    import urllib.request
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except Exception:
        return False


def _trigger_live_dashboard_mission(url: str = DASHBOARD_URL) -> bool:
    """POST to the actually-running dashboard's own API so the live mission
    it drives (and its WebSocket-connected browser view) is the SAME
    mission this command reports on — not a separate, disconnected
    standalone run that happens to share code. Returns True if the mission
    was really started this way."""
    import json
    import urllib.request
    try:
        # Best-effort: clear any stale prior run first.
        urllib.request.urlopen(
            urllib.request.Request(f"{url}/api/sentinel/reset", method="POST"), timeout=3)
    except Exception:
        pass
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(f"{url}/api/sentinel/start", method="POST"), timeout=3)
        body = json.loads(resp.read().decode())
        return body.get("status") == "started"
    except Exception:
        return False


def _run_mission():
    from abhimanyux.core.orchestrator import AbhimanyuXCore
    from abhimanyux.anvil.engine import LLMConfig
    from abhimanyux.sentinel.orchestrator import SentinelOrchestrator

    def emit(name, payload):
        if name == "stage_update":
            print(f"[{payload['stage']:18s}] {payload['message']}")

    core = AbhimanyuXCore(
        llm_config=LLMConfig(provider="local", model="qwen2.5-coder:3b",
                              api_url="http://127.0.0.1:21434/api/generate", timeout=280),
        db_path="abhimanyux_dashboard.db",
    )
    orch = SentinelOrchestrator(core, emit)
    orch.run_full_demo()
    return orch, core


def cmd_mission(args):
    if not getattr(args, "standalone", False) and _dashboard_reachable():
        if _trigger_live_dashboard_mission():
            print(f"Live dashboard mission started — watch {DASHBOARD_URL}")
            return 0
        print(f"Dashboard is running at {DASHBOARD_URL} but refused to start "
              f"(a mission may already be in progress). Not falling back to a "
              f"standalone run to avoid two missions racing on the same DB.")
        return 1
    print("Dashboard not reachable — running a standalone (terminal-only) mission.")
    _run_mission()
    return 0


def cmd_transfer(args):
    import json as _json
    orch, core = _run_mission()
    print()
    print("=== IMMUNE TRANSFER EXPERIMENT (target B: network_protocol_parser) ===")

    def emit(name, payload):
        if name in ("transfer_progress", "transfer_result"):
            print(payload.get("message") or _json.dumps(payload, indent=2))

    orch.emit = emit
    orch.run_transfer_experiment()
    return 0


def main():
    parser = argparse.ArgumentParser(prog="sentinel", description="ABHIMANYU X CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Check real tool/environment readiness").set_defaults(func=cmd_doctor)

    p_scan = sub.add_parser("scan", help="Run REWIND static analysis on a file or directory")
    p_scan.add_argument("target")
    p_scan.set_defaults(func=cmd_scan)

    sub.add_parser("targets", help="List vulnerable-application catalog").set_defaults(func=cmd_targets)
    sub.add_parser("environments", help="List execution environments").set_defaults(func=cmd_environments)
    p_mission = sub.add_parser("mission", help="Run the full autonomous mission against secure_packet_parser "
                                                "(controls the live web dashboard if one is running at "
                                                f"{DASHBOARD_URL}, otherwise runs standalone in this terminal)")
    p_mission.add_argument("--standalone", action="store_true",
                            help="Always run standalone in this terminal, even if the dashboard is reachable")
    p_mission.set_defaults(func=cmd_mission)
    sub.add_parser("transfer", help="Run the mission, then the real Immune Transfer experiment on target B").set_defaults(func=cmd_transfer)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
