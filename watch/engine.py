"""
ABHIMANYU X CORE - Watch Engine
Continuous Monitoring Over a Codebase

Turns one-shot scanning into a persistent watch loop: polls a directory for
file changes, re-scans whatever changed, and diffs the resulting
vulnerability set against what was last seen for that file — so a
regression (a previously-fixed vulnerability reappearing, e.g. via a
revert) or a newly introduced vulnerability is noticed as it happens,
not only when someone remembers to run a scan.

Deliberately file/content-change monitoring, not OS-level runtime
introspection: no process hooks, no eBPF, no live memory or behavior
inspection of a running program. That would require integration with a
real deployment target, which is a different kind of system than a
codebase scanner can responsibly claim to provide.
"""

import os
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from abhimanyux.models.schemas import Vulnerability


@dataclass
class WatchEvent:
    """A single state transition observed by the Watch engine for one file."""
    event_type: str  # "new", "regression", "resolved"
    file_path: str
    vulnerability: Optional[Vulnerability] = None
    detail: str = ""
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WatchEngine:
    """
    Continuous monitoring over a directory (or single file): polls for
    changes, re-scans what changed via the same REWIND engine a one-shot
    scan uses, and diffs against the last known vulnerability set per file.

    Requires a AbhimanyuXCore instance to reuse its REWIND engine, its
    file-discovery logic, and Immune Memory for regression detection,
    rather than duplicating that wiring here.
    """

    def __init__(self, orchestrator, poll_interval: float = 2.0):
        self.orchestrator = orchestrator
        self.poll_interval = poll_interval
        self._file_state: Dict[str, Tuple[float, str]] = {}
        self._last_vulns: Dict[str, Dict[str, Vulnerability]] = {}
        self.checks_run = 0

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except OSError:
            return None

    def _changed_files(self, target_path: str, language: str) -> List[str]:
        """Files whose mtime+content-hash differ from what was last seen, or
        that are being seen for the first time. Checking mtime before
        hashing avoids re-reading every file on every poll when nothing
        changed."""
        if os.path.isfile(target_path):
            files = [target_path]
        else:
            files = self.orchestrator.discover_files(target_path, language)

        changed = []
        for path in files:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            last = self._file_state.get(path)
            if last and last[0] == mtime:
                continue
            digest = self._hash_file(path)
            if digest is None:
                continue
            if last and last[1] == digest:
                self._file_state[path] = (mtime, digest)  # mtime touched, content unchanged
                continue
            self._file_state[path] = (mtime, digest)
            changed.append(path)
        return changed

    def check_once(self, target_path: str, language: str = "python") -> List[WatchEvent]:
        """
        Run a single poll cycle: re-scan whatever changed, diff against the
        last known vulnerability set per file, and return the resulting
        events.

        A finding is a "regression" rather than merely "new" when its exact
        id (REWIND derives this deterministically from file+line+rule, so
        the same vulnerability at the same location reproduces the same id)
        previously had a fully verified patch — i.e. it was fixed and has
        now come back, most likely via a revert, not a vuln nobody had
        gotten to yet.
        """
        self.checks_run += 1
        events: List[WatchEvent] = []

        for path in self._changed_files(target_path, language):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            current_vulns = {v.id: v for v in self.orchestrator.rewind.scan(code, path)}
            previous_vulns = self._last_vulns.get(path, {})

            for vuln_id, vuln in current_vulns.items():
                if vuln_id in previous_vulns:
                    continue  # already known and still present
                if self.orchestrator.memory.has_verified_patch(vuln_id):
                    events.append(WatchEvent(
                        event_type="regression", file_path=path, vulnerability=vuln,
                        detail=f"{vuln.title} reappeared after a previously verified fix"
                    ))
                else:
                    events.append(WatchEvent(
                        event_type="new", file_path=path, vulnerability=vuln,
                        detail=f"New {vuln.vuln_type.value} finding: {vuln.title}"
                    ))

            for vuln_id, vuln in previous_vulns.items():
                if vuln_id not in current_vulns:
                    events.append(WatchEvent(
                        event_type="resolved", file_path=path, vulnerability=vuln,
                        detail=f"{vuln.title} no longer detected"
                    ))

            self._last_vulns[path] = current_vulns

        return events

    def watch(self, target_path: str, language: str = "python",
              max_iterations: Optional[int] = None,
              on_event: Optional[Callable[[WatchEvent], None]] = None) -> int:
        """
        Poll loop: calls check_once repeatedly, sleeping poll_interval
        seconds between cycles.

        `max_iterations=None` runs forever (CLI/daemon use); pass a finite
        value for testability. Returns the total number of events observed
        across all iterations.
        """
        total_events = 0
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            for event in self.check_once(target_path, language):
                total_events += 1
                if on_event:
                    on_event(event)
            iterations += 1
            if max_iterations is None or iterations < max_iterations:
                time.sleep(self.poll_interval)
        return total_events
