# Agent Handoff — read this before touching anything

This file is for an AI agent (or person) picking up this project cold. It's
not product documentation — see `README.md` for that. This is the "what
happened and what to trust" file.

## What this is

**Abhimanyu X** (renamed from **SENTINEL-X**) is an entry for **AI Kavach**
(Army Terrier Fiesta 2026 — "Kavach means shield: defensive by design").
The actual competition problem statement, verbatim:

> Build a cyber-reasoning system - an LLM laced with fuzzers, static and
> dynamic analysis, and a regression test harness - that autonomously
> finds a vulnerability, patches it, and proves the fix holds. The
> solutions worked out in the finale by the teams shall be pitched to run
> autonomously against specific customised infrastructure of the Indian
> Armed Forces.

Everything in `core/`, `rewind/`, `anvil/`, `verifier/`, `memory/`,
`watch/`, `fuzzer/`, `models/`, `api/`, `tests/` is a direct, tested attempt
at that statement. Nothing here integrates with actual Armed Forces
infrastructure — that's explicitly a finale-stage requirement, not
buildable without knowing the target.

## Repo

Private GitHub repo: `https://github.com/Sandeep332005/territorial` (an
originally unrelated empty repo, repurposed — hence the mismatched name).
Real git history exists (`git log`), 8 commits at last count, all with
detailed messages explaining *why*, not just *what*. Read them; they're
more reliable than any summary including this one.

## Two very different parts of this codebase — do not confuse them

**Trusted, tested core engine**: `core/`, `rewind/`, `anvil/`, `verifier/`,
`memory/`, `watch/`, `fuzzer/`, `models/`, `api/`, `tests/`,
`vulnerable_targets/`. 57 tests, all passing, and — importantly — verified
by actually running things (real scans, real patch generation, real
before/after checks), not just written and assumed correct. Several real
bugs were found and fixed along the way (see "Bugs found and fixed"
below); treat that as evidence this code has been exercised, not as a
reason to distrust it.

**Disconnected, unverified scaffolding**: `platform/`, `cli/`, `deploy/`,
`iso/` (except `iso/build_data_iso.sh`, `iso/install.sh`, `iso/install.bat`,
`iso/output/abhimanyux-installer.iso` — those ARE verified, see below),
`usb/`, `config/`. This was built by a **different AI agent** ("Freebuff")
in an earlier/concurrent session, with its own LLM provider registry and
scanning pipeline that never integrates with the tested engine above. Its
own build log (visible in this repo's conversation history, not committed
here) shows: it couldn't read the actual research PDFs (sandboxed away
from it) and guessed wrong arXiv IDs instead; it invented a model name,
`antares-3b`, that doesn't exist; its own first test run failed
(`Unknown model: dolphin-llama3:8b` → silent fallback) and was never
actually fixed. It was deleted once (commit `ac8efac`), then restored on
request (commit `d90d0f6`, a `git revert`, not a manual redo — the delete
is still in history if you want it again). **Don't build on it or trust
its claims without independent verification.**

## What's been verified, and how (not just "trust me")

- **REWIND**: C-language rule set added this session. 0 → 16 findings on
  the bundled `vulnerable_targets/vulnerable.c` fixture, covering all 10
  intentionally-planted vulnerability classes in it.
- **ANVIL**: retrieval-grounding from Immune Memory + a bounded
  generator-judge self-critique loop, both confirmed with real Ollama LLM
  calls (not mocked), plus a timeout fix (180s → 60s per call — the
  original hung indefinitely with no fallback).
- **Verifier**: found and fixed a real correctness bug — the old exploit
  check unconditionally printed `"SAFE"` regardless of what the patch
  actually did (a no-op "patch" would always pass). Rebuilt as a
  differential re-scan (confirms the vuln pattern present-before,
  absent-after); a regression test proves a fake patch now correctly
  fails.
- **Immune Memory**: capability-atom schema (preconditions + capability
  grant + cross-vulnerability links) — verified two different vuln types
  in the same function actually link to each other.
- **Feedback loop**: `evolve()` recalibrates rule confidence from
  verified-patch history — exact math verified (`0.7×0.75 + 0.3×0.2 =
  0.585`), not just "should work."
- **Watch engine**: full new → resolved → regression lifecycle tested with
  real temp files.
- **Fuzz Engine**: found and fixed **three real bugs** while making it
  model-driven — `hashlib` used but never imported (crash recording would
  have raised `NameError` and killed every run that found anything);
  generated test scripts never actually called the target function (a
  function-definition-only snippet, which is the common case here, could
  never crash regardless of iterations); payload embedding via
  `json.loads('{...}')` broke on any payload containing a quote, i.e.
  every SQL/command-injection payload the fuzzer itself generates. All
  three fixed and covered by new tests. Strategy selection is now
  genuinely LLM-weighted when an `ANVILEngine` is wired in (it is, by
  default, from the orchestrator), with a hard fallback to uniform random
  if the LLM call fails.
- **Platform compatibility**: ran the real install + full test suite + a
  live scan inside a clean **Debian 12** Docker container from scratch.
  BOSS Linux (the likely real deployment target, being India's official
  government Linux) has **not** been tested directly — no public image
  exists — but it's a Debian derivative, and this has no OS-specific
  dependencies beyond Python 3.10+ and (for C verification) a C compiler.
- **Data ISO installer** (`iso/output/abhimanyux-installer.iso`): built
  with macOS's own `hdiutil` (a real ISO 9660 data disc, NOT a bootable
  live-OS image — see next section). Verified by mounting it, copying the
  install script from a genuinely read-only mount, and running the full
  test suite from the result — inside the Debian 12 container above.
  **Gotcha**: nothing auto-rebuilds this when source changes. If you
  change anything under `core/`/`rewind/`/etc., re-run
  `iso/build_data_iso.sh` before shipping the ISO again, or it'll be
  silently stale (this already happened once this session).

## Known limitations (stated honestly, not hidden)

See `README.md`'s "Known limitations" section — it's current and accurate
as of the last commit. Short version: detection is heuristic/regex-based,
not sound; patch quality depends entirely on whichever LLM is actually
configured; nothing auto-deploys a patch to a live system; C-language
regression/behavior verification is structural only (no actual
compile-and-run smoke test, since executing arbitrary AI-generated C
automatically would itself be a risk); not tested at real-world scale;
`platform/cli/deploy/iso/usb` (except the data-ISO pieces above) is
unverified scaffolding, not part of the tested claim.

## Other known-incomplete pieces, not yet touched

- `fuzzer/engine.py`'s `PythonAppFuzzer._test_web_payload` is a stub that
  always returns `{"crash": False, "vulnerable": False}` — it never
  actually tests anything. Not fixed this session (out of scope of what
  was asked); don't cite web-fuzzing capability without fixing this first.
- `install.bat` (Windows installer) is written but **untested** — no
  Windows environment was available in any session so far.
- The air-gapped Ollama transfer instructions in `README.md` describe
  Ollama's own documented offline mechanism (copying its content-addressed
  `~/.ollama` store between machines) but have not been verified
  end-to-end here — no two networked machines were available to test the
  actual transfer.
- `deploy/config_ai15dt.json` is present in the current working tree (it
  was restored along with the rest of `platform/cli/deploy/iso/usb`) with
  a real named lab machine's hardware profile (`AI15-DT.RRU.EDU`,
  i9-13900/64GB/RTX 4060). Low risk since the repo is private, but be
  aware it's there if this repo is ever made public.

## How to verify any of the above yourself

```bash
cd abhimanyux
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd ..
PYTHONPATH=. abhimanyux/venv/bin/python -m pytest abhimanyux/tests/ -q
# Expect: 57 passed
```

To rebuild and re-verify the data ISO after any source change:
```bash
cd abhimanyux/iso && bash build_data_iso.sh
# then mount iso/output/abhimanyux-installer.iso and run install.sh from it
```

## If you're an agent about to make changes

- Don't assume `platform/`'s claims are true without checking; it has a
  documented history of overclaiming.
- Don't add a feature and call it done without actually running it — every
  fix listed above was caught by actually executing the code, not by
  reading it. That pattern is the reason this codebase can currently be
  trusted more than the disconnected scaffolding next to it.
- If you touch REWIND/ANVIL/Verifier/Memory/Watch/Fuzzer, rerun the test
  suite (57 tests, ~80s) before claiming anything works.
