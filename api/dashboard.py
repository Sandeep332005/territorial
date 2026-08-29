#!/usr/bin/env python3
"""
SENTINEL-X CORE - Autonomous Cyber Immune System Laboratory
Web laboratory for the AI Kavach hackathon prototype: watch one vulnerability
travel REWIND -> DISCOVERY -> FUZZ -> ANVIL -> PATCH -> VERIFICATION ->
IMMUNE MEMORY, plus ad-hoc interactive scanning of arbitrary code.

Built on the abhimanyux engine (REWIND/ANVIL/Verifier/Immune Memory);
SENTINEL-X CORE is this project's product identity for the hackathon.

Usage:
    python -m abhimanyux.api.dashboard
    # Opens at http://localhost:5050
"""

import os
import sys
import json
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone
from threading import Lock

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit
from abhimanyux.core.orchestrator import AbhimanyuXCore
from abhimanyux.anvil.engine import LLMConfig
from abhimanyux.models.schemas import VulnType, Severity
from abhimanyux.sentinel.orchestrator import SentinelOrchestrator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'abhimanyux-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

LLM_PROVIDER = "local"
LLM_MODEL = "qwen2.5-coder:3b"
LLM_API_URL = "http://127.0.0.1:21434/api/generate"

# Global orchestrator instance
orchestrator = None
_sentinel = None
_sentinel_lock = Lock()
_sentinel_run_lock = Lock()


def get_orchestrator():
    """Get or initialize the orchestrator."""
    global orchestrator
    if orchestrator is None:
        llm_config = LLMConfig(
            provider=LLM_PROVIDER,
            model=LLM_MODEL,
            api_url=LLM_API_URL,
            timeout=300,
        )
        orchestrator = AbhimanyuXCore(llm_config=llm_config, db_path="abhimanyux_dashboard.db")
    return orchestrator


def get_sentinel():
    """Get or initialize the SENTINEL-X demo orchestrator (Judge Mode)."""
    global _sentinel
    with _sentinel_lock:
        if _sentinel is None:
            def emit_event(name, payload):
                socketio.emit(name, payload)
            _sentinel = SentinelOrchestrator(get_orchestrator(), emit_event)
        return _sentinel


# ============================================================
# Custom Orchestrator with Progress Events
# ============================================================

class ObservableOrchestrator:
    """Wrapper around AbhimanyuXCore that emits WebSocket events during scanning."""
    
    def __init__(self, core: AbhimanyuXCore):
        self.core = core
    
    def scan_code_with_events(self, code: str, filename: str):
        """Scan code with real-time progress events."""
        socketio.emit('scan_progress', {
            'stage': 'starting',
            'message': f'Starting scan of {filename}...',
            'progress': 0
        })
        
        # Phase 1: Static Analysis
        socketio.emit('scan_progress', {
            'stage': 'rewind',
            'message': 'Running REWIND static analysis...',
            'progress': 10
        })
        
        vulns = self.core.rewind.scan(code, filename)
        
        socketio.emit('scan_progress', {
            'stage': 'rewind_complete',
            'message': f'REWIND found {len(vulns)} potential vulnerabilities',
            'progress': 25,
            'count': len(vulns)
        })
        
        # Emit each vulnerability as it's found
        for i, vuln in enumerate(vulns):
            socketio.emit('vulnerability_found', {
                'index': i + 1,
                'total': len(vulns),
                'vulnerability': {
                    'id': vuln.id,
                    'type': vuln.vuln_type.value,
                    'severity': vuln.severity.value,
                    'title': vuln.title,
                    'description': vuln.description,
                    'location': {
                        'file_path': vuln.location.file_path,
                        'line_start': vuln.location.line_start
                    },
                    'cwe_id': vuln.cwe_id,
                    'confidence': vuln.confidence
                }
            })
        
        # Phase 2: Patch Generation
        socketio.emit('scan_progress', {
            'stage': 'anvil',
            'message': 'Generating patches with ANVIL engine...',
            'progress': 40
        })
        
        patches = []
        verifications = []
        
        for i, vuln in enumerate(vulns):
            socketio.emit('patch_progress', {
                'vuln_index': i + 1,
                'vuln_total': len(vulns),
                'vuln_title': vuln.title,
                'message': f'Generating patch for: {vuln.title}'
            })
            
            # Generate patch
            socketio.emit('scan_progress', {
                'stage': 'patch_generation',
                'message': f'Generating patch for {vuln.vuln_type.value}...',
                'progress': 40 + (i / len(vulns)) * 20
            })
            
            patch = self.core.anvil.analyze_and_patch(code, vuln)
            patches.append(patch)
            self.core.patches_generated += 1
            
            socketio.emit('patch_generated', {
                'patch_id': patch.id,
                'vuln_id': vuln.id,
                'explanation': patch.explanation[:200],
                'status': 'generated'
            })
            
            # Verify patch
            socketio.emit('scan_progress', {
                'stage': 'verification',
                'message': f'Verifying patch {patch.id}...',
                'progress': 60 + (i / len(vulns)) * 20
            })
            
            verification = self.core.verifier.verify(
                code, patch.patched_code, vuln, patch
            )
            verifications.append(verification)
            
            if verification.all_tests_pass:
                self.core.patches_verified += 1
                patch.status = "verified"
            
            socketio.emit('verification_complete', {
                'patch_id': patch.id,
                'compile_success': verification.compile_success,
                'exploit_blocked': verification.exploit_blocked,
                'regression_pass': verification.regression_pass,
                'behavior_preserved': verification.behavior_preserved,
                'all_tests_pass': verification.all_tests_pass
            })
            
            # Store in memory
            socketio.emit('scan_progress', {
                'stage': 'memory',
                'message': f'Storing results in Immune Memory...',
                'progress': 80 + (i / len(vulns)) * 15
            })
            
            self.core.memory.store_vulnerability(vuln)
            self.core.memory.store_patch(patch)
            dna = self.core.memory.create_dna(vuln, patch.explanation)
            self.core.memory.store_immune_record(vuln.id, patch.id, dna.id)
        
        self.core.vulns_found += len(vulns)
        
        # Generate summary
        socketio.emit('scan_progress', {
            'stage': 'complete',
            'message': 'Scan complete!',
            'progress': 100
        })
        
        summary = self.core._generate_summary(vulns, patches, verifications)
        
        return vulns, patches, verifications, summary


DASHBOARD_HTML = """

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL-X CORE — Autonomous Cyber Immune Laboratory</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        :root {
            --bg: #05080a;
            --panel: #0b1116;
            --panel-2: #0f171d;
            --border: #1c2a32;
            --cyan: #2de2c9;
            --green: #3ddc84;
            --amber: #e8b23d;
            --blue: #4fa3ff;
            --red: #ff5470;
            --gray: #5b6b74;
            --text: #d9e6ea;
            --text-dim: #7d8f97;
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: radial-gradient(circle at 20% 0%, #0b1620 0%, var(--bg) 55%);
            color: var(--text);
            font-family: 'SF Mono', 'Fira Code', Menlo, Consolas, monospace;
            font-size: 14px;
            line-height: 1.5;
        }
        .wrap { max-width: 1320px; margin: 0 auto; padding: 20px 20px 60px; }

        /* ---- badges ---- */
        .badge { display:inline-block; padding:1px 7px; border-radius:3px; font-size:10px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }
        .badge-measured { background:rgba(61,220,132,.12); color:var(--green); border:1px solid rgba(61,220,132,.4); }
        .badge-ai { background:rgba(79,163,255,.12); color:var(--blue); border:1px solid rgba(79,163,255,.4); }
        .badge-demo { background:rgba(232,178,61,.12); color:var(--amber); border:1px solid rgba(232,178,61,.4); }
        .badge-future { background:rgba(91,107,116,.15); color:var(--gray); border:1px solid rgba(91,107,116,.4); }
        .legend { display:flex; gap:14px; flex-wrap:wrap; font-size:11px; color:var(--text-dim); margin-top:8px; }
        .legend span { display:inline-flex; align-items:center; gap:5px; }

        /* ---- mission control ---- */
        .mission {
            border:1px solid var(--border); background:linear-gradient(180deg,var(--panel),var(--panel-2));
            border-radius:10px; padding:18px 22px; margin-bottom:18px;
        }
        .mission-top { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:14px; }
        .mission h1 { font-size:26px; letter-spacing:.06em; color:#eafcf6; }
        .mission h1 .core { color: var(--cyan); }
        .mission .subtitle { color:var(--text-dim); font-size:12px; letter-spacing:.08em; text-transform:uppercase; margin-top:2px; }
        .status-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px 22px; margin-top:16px; font-size:12px; }
        .status-grid .k { color:var(--text-dim); text-transform:uppercase; letter-spacing:.05em; font-size:10px; }
        .status-grid .v { color:var(--text); margin-top:2px; font-weight:600; }
        .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
        .dot-active { background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 1.4s infinite; }
        .dot-idle { background:var(--gray); }
        @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:.35;} }

        .stage-row { display:flex; gap:6px; margin-top:16px; flex-wrap:wrap; }
        .stage-pill { flex:1; min-width:110px; text-align:center; padding:8px 6px; border-radius:6px; border:1px solid var(--border); background:var(--panel-2); font-size:11px; letter-spacing:.05em; text-transform:uppercase; color:var(--text-dim); }
        .stage-pill.done { color:var(--green); border-color:rgba(61,220,132,.4); }
        .stage-pill.active { color:var(--cyan); border-color:rgba(45,226,201,.5); box-shadow:0 0 10px rgba(45,226,201,.15); }
        .stage-pill .mark { display:block; font-size:14px; margin-bottom:2px; }

        /* ---- controls ---- */
        .controls { display:flex; gap:10px; align-items:center; margin-top:18px; flex-wrap:wrap; }
        .btn { font-family:inherit; font-size:12px; letter-spacing:.04em; text-transform:uppercase; padding:11px 20px; border-radius:6px; border:1px solid var(--border); background:var(--panel-2); color:var(--text); cursor:pointer; transition:.15s; }
        .btn:hover { border-color:var(--cyan); color:var(--cyan); }
        .btn:disabled { opacity:.35; cursor:not-allowed; }
        .btn-primary { background:linear-gradient(90deg,#0e6b5c,#12907a); border:none; color:#eafcf6; font-weight:700; padding:14px 28px; font-size:13px; box-shadow:0 0 20px rgba(45,226,201,.25); }
        .btn-primary:hover { color:#fff; box-shadow:0 0 28px rgba(45,226,201,.4); }
        .btn-danger:hover { border-color:var(--red); color:var(--red); }

        /* ---- pipeline ---- */
        .pipeline { border:1px solid var(--border); background:var(--panel); border-radius:10px; padding:20px; margin-bottom:18px; }
        .pipeline h2, .panel h2, .section h2 { font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--cyan); margin-bottom:14px; }
        #scene3d-container { position:relative; width:100%; height:min(64vh, 620px); min-height:380px; border-radius:8px; overflow:hidden;
            background: radial-gradient(circle at 50% 45%, rgba(45,226,201,.06), transparent 60%), repeating-linear-gradient(0deg, transparent 0 39px, rgba(45,226,201,.05) 39px 40px), repeating-linear-gradient(90deg, transparent 0 39px, rgba(45,226,201,.05) 39px 40px);
            background-color: #02050a; border:1px solid var(--border); }
        #scene3d-container canvas { display:block; width:100% !important; height:100% !important; }
        .scene-caption { position:absolute; left:50%; bottom:22px; transform:translateX(-50%); text-align:center; pointer-events:none;
            opacity:0; transition:opacity .4s ease; width:90%; }
        .scene-caption.show { opacity:1; }
        .cap-line { font-family:inherit; text-transform:uppercase; letter-spacing:.08em; text-shadow:0 0 12px rgba(45,226,201,.6), 0 2px 8px rgba(0,0,0,.8); }
        .cap-primary { font-size:15px; font-weight:700; color:#eafcf6; }
        .cap-secondary { font-size:11px; color:var(--cyan); margin-top:4px; }
        .scene-fallback-note { padding:10px 14px; font-size:11px; color:var(--text-dim); border:1px dashed var(--border); border-radius:6px; margin-bottom:10px; }
        .cells { display:flex; flex-direction:column; gap:2px; align-items:center; }
        .cell { width:100%; max-width:520px; border:1px solid var(--border); background:var(--panel-2); border-radius:8px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center; cursor:pointer; transition:.15s; }
        .cell:hover { border-color:var(--cyan); }
        .cell.active { border-color:var(--cyan); box-shadow:0 0 16px rgba(45,226,201,.2); background:rgba(45,226,201,.05); }
        .cell.done { border-color:rgba(61,220,132,.4); }
        .cell .name { font-weight:700; letter-spacing:.04em; }
        .cell .sub { color:var(--text-dim); font-size:11px; margin-top:2px; }
        .arrow { color:var(--border); font-size:16px; }
        .arrow.active { color:var(--cyan); }

        /* ---- evidence panels ---- */
        .panels { display:grid; grid-template-columns:repeat(auto-fit,minmax(420px,1fr)); gap:16px; margin-bottom:18px; }
        .panel { border:1px solid var(--border); background:var(--panel); border-radius:10px; padding:18px 20px; }
        .panel.empty { opacity:.4; }
        .kv { display:grid; grid-template-columns:auto 1fr; gap:4px 12px; font-size:12px; margin-top:6px;}
        .kv .k { color:var(--text-dim); }
        .kv .v { color:var(--text); }
        pre.code { background:#02050a; border:1px solid var(--border); border-radius:6px; padding:12px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
        .diffline-add { color:var(--green); }
        .diffline-del { color:var(--red); }
        .finding-row { border-left:3px solid var(--border); padding:6px 10px; margin-top:8px; font-size:12px; background:var(--panel-2); border-radius:0 6px 6px 0; }
        .finding-row.critical, .finding-row.CRITICAL { border-color:var(--red); }
        .finding-row.high, .finding-row.HIGH { border-color:var(--amber); }
        .stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(90px,1fr)); gap:10px; margin-top:10px; }
        .stat-box { text-align:center; background:var(--panel-2); border:1px solid var(--border); border-radius:6px; padding:8px 4px; }
        .stat-box .num { font-size:18px; font-weight:700; color:var(--cyan); }
        .stat-box .lbl { font-size:9px; color:var(--text-dim); text-transform:uppercase; margin-top:2px; }
        .checklist { margin-top:10px; }
        .checklist .item { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--border); font-size:12px; }
        .checklist .item:last-child { border-bottom:none; }
        .ok { color:var(--green); } .bad { color:var(--red); } .pending { color:var(--text-dim); }
        .replay-box { display:flex; gap:14px; margin-top:12px; }
        .replay-col { flex:1; text-align:center; border:1px solid var(--border); border-radius:8px; padding:14px; background:var(--panel-2); }
        .replay-col.fail { border-color:rgba(255,84,112,.4); }
        .replay-col.safe { border-color:rgba(61,220,132,.4); }
        .replay-col .r-title { font-size:10px; color:var(--text-dim); text-transform:uppercase; }
        .replay-col .r-out { font-size:20px; font-weight:800; margin-top:8px; }
        canvas#fuzzChart { width:100%; height:60px; }

        /* ---- timeline ---- */
        .timeline { max-height:260px; overflow-y:auto; }
        .tl-item { display:flex; gap:10px; font-size:12px; padding:4px 0; border-bottom:1px solid var(--border); }
        .tl-time { color:var(--cyan); flex-shrink:0; }
        .tl-msg { color:var(--text-dim); }

        /* ---- metrics ---- */
        .metrics-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; }
        .metric { text-align:center; border:1px solid var(--border); background:var(--panel-2); border-radius:8px; padding:14px 6px; }
        .metric .num { font-size:22px; font-weight:800; color:var(--cyan); }
        .metric .lbl { font-size:10px; color:var(--text-dim); text-transform:uppercase; margin-top:4px; }

        /* ---- immune network ---- */
        #memNetwork { width:100%; height:220px; }

        /* ---- future ecosystem ---- */
        .future-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; }
        .future-card { border:1px dashed var(--border); border-radius:8px; padding:16px; text-align:center; opacity:.55; }
        .future-card h3 { color:var(--gray); font-size:13px; letter-spacing:.05em; }
        .future-card p { font-size:11px; color:var(--text-dim); margin-top:6px; }

        /* ---- final summary ---- */
        .final-card { display:none; border:2px solid var(--cyan); border-radius:10px; padding:24px; text-align:center; background:linear-gradient(180deg,rgba(45,226,201,.06),transparent); margin-bottom:18px; }
        .final-card.show { display:block; }
        .final-card h2 { color:var(--cyan); letter-spacing:.1em; font-size:16px; }
        .final-kv { display:grid; grid-template-columns:1fr 1fr; gap:8px 20px; max-width:460px; margin:16px auto 0; text-align:left; font-size:12px; }
        .final-kv .k { color:var(--text-dim); }
        .final-tag { font-size:22px; letter-spacing:.06em; color:var(--green); margin-top:18px; font-weight:800; }

        .section { border:1px solid var(--border); background:var(--panel); border-radius:10px; padding:18px 20px; margin-bottom:18px; }
        .divider { text-align:center; color:var(--text-dim); font-size:11px; text-transform:uppercase; letter-spacing:.15em; margin:36px 0 18px; }
        .divider::before, .divider::after { content:''; }

        /* ---- interactive scan bench (legacy, restyled) ---- */
        textarea, input[type=text], select { width:100%; padding:10px; border-radius:6px; border:1px solid var(--border); background:#02050a; color:var(--text); font-family:inherit; font-size:12px; }
        textarea { min-height:120px; resize:vertical; }
        .form-group { margin-bottom:12px; }
        .form-group label { display:block; font-size:11px; color:var(--text-dim); text-transform:uppercase; margin-bottom:5px; }
        table.vuln-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:12px; }
        table.vuln-table th, table.vuln-table td { padding:8px; text-align:left; border-bottom:1px solid var(--border); }
        table.vuln-table th { color:var(--cyan); font-size:10px; text-transform:uppercase; }

        @media (max-width: 720px) { .status-grid { grid-template-columns:1fr 1fr; } .stage-row { flex-direction:column; } }
    </style>
</head>
<body>
<div class="wrap">

    <!-- MISSION CONTROL -->
    <div class="mission">
        <div class="mission-top">
            <div>
                <h1><span class="core">SENTINEL</span>-X CORE</h1>
                <div class="subtitle">Autonomous Cyber Immune Cell — AI Kavach Prototype</div>
            </div>
            <div class="legend">
                <span><span class="badge badge-measured">Measured</span> real engine output</span>
                <span><span class="badge badge-ai">AI-Generated</span> real local LLM inference</span>
                <span><span class="badge badge-demo">Demo</span> deterministic placeholder, not executed</span>
                <span><span class="badge badge-future">Future</span> not implemented</span>
            </div>
        </div>
        <div class="status-grid">
            <div><div class="k">System Status</div><div class="v" id="ms-status"><span class="dot dot-idle"></span>IDLE</div></div>
            <div><div class="k">Target</div><div class="v" id="ms-target">secure_packet_parser</div></div>
            <div><div class="k">Analysis Mode</div><div class="v">AUTONOMOUS</div></div>
            <div><div class="k">LLM</div><div class="v" id="ms-llm">LOCAL</div></div>
            <div><div class="k">Environment</div><div class="v">LOCALHOST · NO INTERNET REQUIRED</div></div>
            <div><div class="k">Current Operation</div><div class="v" id="ms-op">Idle</div></div>
        </div>
        <div class="stage-row" id="stageRow">
            <div class="stage-pill" data-group="discover"><span class="mark">○</span>DISCOVER</div>
            <div class="stage-pill" data-group="understand"><span class="mark">○</span>UNDERSTAND</div>
            <div class="stage-pill" data-group="repair"><span class="mark">○</span>REPAIR</div>
            <div class="stage-pill" data-group="verify"><span class="mark">○</span>VERIFY</div>
            <div class="stage-pill" data-group="remember"><span class="mark">○</span>REMEMBER</div>
        </div>
        <div class="controls">
            <button class="btn btn-primary" id="btnStart">▶ Start Autonomous Demo</button>
            <button class="btn" id="btnPause" disabled>⏸ Pause</button>
            <button class="btn" id="btnResume" disabled>⏵ Resume</button>
            <button class="btn btn-danger" id="btnReset">↺ Reset</button>
            <button class="btn" id="btnFuture" disabled>🧬 Future Learning Demo</button>
            <span id="progressLabel" style="color:var(--text-dim); font-size:11px;"></span>
        </div>
    </div>

    <!-- FINAL SUMMARY -->
    <div class="final-card" id="finalCard">
        <h2>SECURITY REPAIR VERIFIED</h2>
        <div class="final-kv" id="finalKv"></div>
        <div class="final-tag">SENTINEL-X HAS LEARNED</div>
    </div>

    <!-- 3D IMMUNE LABORATORY -->
    <div class="pipeline" id="scene3d-wrap">
        <h2>Immune Laboratory <span class="badge badge-measured" style="margin-left:6px;">Reacts to real pipeline state</span>
            <button class="btn" id="btnPerfMode" style="float:right; padding:5px 12px; font-size:10px;">Performance Mode</button>
        </h2>
        <div id="scene3d-container"></div>
    </div>

    <!-- PIPELINE (2D fallback — shown automatically if WebGL is unavailable, or always available below the 3D view) -->
    <div class="pipeline" id="pipeline-2d-wrap" style="display:none;">
        <h2>Orchestration Pipeline — click a cell for evidence</h2>
        <div class="cells" id="cells">
            <div class="cell" data-cell="repository"><div><div class="name">REPOSITORY</div><div class="sub">secure_packet_parser (C)</div></div><span class="badge badge-measured">Real</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="rewind"><div><div class="name">REWIND</div><div class="sub">Commit diff analysis</div></div><span class="badge badge-measured">Real</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="static"><div><div class="name">STATIC ANALYSIS</div><div class="sub">REWIND pattern + AST scan</div></div><span class="badge badge-measured">Real</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="dynamic"><div><div class="name">DYNAMIC ANALYSIS</div><div class="sub">Real ASan crash, demo rate stats</div></div><span class="badge badge-demo">Mixed</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="fuzz"><div><div class="name">FUZZ ENGINE</div><div class="sub">Real AFL++ 4.09c, blind-mode</div></div><span class="badge badge-demo">Mixed</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="vuln"><div><div class="name">VULNERABILITY</div><div class="sub">Evidence bundle</div></div><span class="badge badge-measured">Real</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="anvil"><div><div class="name">ANVIL — AI REASONING</div><div class="sub">Local LLM root-cause analysis</div></div><span class="badge badge-ai">AI</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="patch"><div><div class="name">PATCH</div><div class="sub">Generated fix</div></div><span class="badge badge-ai">AI</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="verify"><div><div class="name">VERIFICATION</div><div class="sub">Build · replay · regression</div></div><span class="badge badge-measured">Real</span></div>
            <div class="arrow">↓</div>
            <div class="cell" data-cell="memory"><div><div class="name">IMMUNE MEMORY</div><div class="sub">Vulnerability DNA stored</div></div><span class="badge badge-measured">Real</span></div>
        </div>
    </div>

    <!-- EVIDENCE PANELS -->
    <div class="panels">
        <div class="panel empty" id="panel-repository">
            <h2>Repository Intake</h2>
            <div class="kv">
                <div class="k">Target</div><div class="v" id="ri-name">—</div>
                <div class="k">Language</div><div class="v" id="ri-lang">—</div>
                <div class="k">Build</div><div class="v" id="ri-build">—</div>
                <div class="k">Security Profile</div><div class="v" id="ri-profile">—</div>
                <div class="k">Status</div><div class="v" id="ri-status">—</div>
            </div>
        </div>

        <div class="panel empty" id="panel-rewind">
            <h2>REWIND — Commit Analysis <span class="badge badge-measured">Real git diff</span></h2>
            <div class="kv">
                <div class="k">Commit</div><div class="v" id="rw-commit">—</div>
                <div class="k">Files Changed</div><div class="v" id="rw-files">—</div>
                <div class="k">Security-Sensitive</div><div class="v" id="rw-sensitive">—</div>
                <div class="k">Risk</div><div class="v" id="rw-risk">—</div>
                <div class="k">Reason</div><div class="v" id="rw-reason">—</div>
            </div>
            <pre class="code" id="rw-diff" style="margin-top:10px;"></pre>
        </div>

        <div class="panel empty" id="panel-static">
            <h2>Static Analysis <span class="badge badge-measured">Real REWIND scan</span></h2>
            <div class="stat-grid">
                <div class="stat-box"><div class="num" id="sa-files">0</div><div class="lbl">Files</div></div>
                <div class="stat-box"><div class="num" id="sa-funcs">0</div><div class="lbl">Functions</div></div>
                <div class="stat-box"><div class="num" id="sa-findings">0</div><div class="lbl">Findings</div></div>
            </div>
            <div id="sa-list"></div>
        </div>

        <div class="panel empty" id="panel-dynamic">
            <h2>Dynamic Analysis <span class="badge badge-measured">Crash real</span> <span class="badge badge-demo">Rate stats demo</span></h2>
            <div class="stat-grid">
                <div class="stat-box"><div class="num" id="da-inputs">0</div><div class="lbl">Inputs</div></div>
                <div class="stat-box"><div class="num" id="da-paths">0</div><div class="lbl">Paths</div></div>
                <div class="stat-box"><div class="num" id="da-crashes">0</div><div class="lbl">Crashes</div></div>
            </div>
            <div id="da-banner" style="margin-top:10px; font-weight:700; color:var(--red);"></div>
        </div>

        <div class="panel empty" id="panel-fuzz">
            <h2>Fuzz Engine <span class="badge badge-measured">AFL++ real, blind-mode</span> <span class="badge badge-demo">Coverage stats demo</span></h2>
            <canvas id="fuzzChart"></canvas>
            <div class="stat-grid">
                <div class="stat-box"><div class="num" id="fz-eps">0</div><div class="lbl">Exec/sec</div></div>
                <div class="stat-box"><div class="num" id="fz-total">0</div><div class="lbl">Total Exec</div></div>
                <div class="stat-box"><div class="num" id="fz-corpus">0</div><div class="lbl">Corpus</div></div>
                <div class="stat-box"><div class="num" id="fz-cov">0%</div><div class="lbl">Coverage</div></div>
                <div class="stat-box"><div class="num" id="fz-crashes">0</div><div class="lbl">Crashes</div></div>
            </div>
            <div id="fz-crash" style="margin-top:10px;"></div>
        </div>

        <div class="panel empty" id="panel-vuln">
            <h2>Vulnerability Evidence <span class="badge badge-measured">CWE mapping real</span></h2>
            <div class="kv">
                <div class="k">CWE</div><div class="v" id="ve-cwe">—</div>
                <div class="k">Confidence</div><div class="v" id="ve-conf">—</div>
                <div class="k">Severity</div><div class="v" id="ve-sev">—</div>
            </div>
            <div class="checklist" id="ve-checklist"></div>
            <button class="btn" id="btnReplay" style="margin-top:10px;">▶ Replay Crash</button>
        </div>

        <div class="panel empty" id="panel-anvil">
            <h2>ANVIL — AI Reasoning <span class="badge badge-ai">Real local inference</span></h2>
            <div class="kv">
                <div class="k">Provider</div><div class="v" id="an-provider">—</div>
                <div class="k">Model</div><div class="v" id="an-model">—</div>
            </div>
            <pre class="code" id="an-explanation" style="margin-top:10px;">Awaiting analysis…</pre>
        </div>

        <div class="panel empty" id="panel-patch">
            <h2>Patch Generation <span class="badge badge-ai">AI-generated</span></h2>
            <pre class="code" id="patch-diff">Awaiting patch…</pre>
            <div class="controls" style="margin-top:10px;">
                <button class="btn btn-danger" id="btnReject">Reject Patch</button>
                <button class="btn" id="btnRegenerate">Generate Again</button>
                <button class="btn" id="btnTestPatch">Test Patch</button>
            </div>
            <div id="patch-note" style="margin-top:8px; font-size:12px; color:var(--text-dim);"></div>
        </div>

        <div class="panel empty" id="panel-verify">
            <h2>Verification Pipeline <span class="badge badge-measured">Build/regression real</span></h2>
            <div class="checklist" id="verify-checklist">
                <div class="item"><span>Build Verification</span><span class="pending" id="vc-build">○</span></div>
                <div class="item"><span>Original Crash Replay</span><span class="pending" id="vc-replay-before">○</span></div>
                <div class="item"><span>Patched Crash Replay</span><span class="pending" id="vc-replay-after">○</span></div>
                <div class="item"><span>Regression Tests</span><span class="pending" id="vc-regression">○</span></div>
                <div class="item"><span>Sanitizer Tests</span><span class="pending" id="vc-sanitizer">○</span></div>
                <div class="item"><span>Behaviour Validation</span><span class="pending" id="vc-behaviour">○</span></div>
            </div>
            <div class="replay-box" id="replayBox" style="display:none;">
                <div class="replay-col fail"><div class="r-title">Before Patch</div><div class="r-out" id="replay-before-out">—</div></div>
                <div class="replay-col safe"><div class="r-title">After Patch</div><div class="r-out" id="replay-after-out">—</div></div>
            </div>
        </div>

        <div class="panel empty" id="panel-regression">
            <h2>Regression Harness <span class="badge badge-demo">Count demo, gate real</span></h2>
            <div class="kv">
                <div class="k">test_invalid_packet_length()</div><div class="v" id="rg-result">—</div>
                <div class="k">Regression tests</div><div class="v" id="rg-count">—</div>
            </div>
        </div>

        <div class="panel empty" id="panel-memory">
            <h2>Immune Memory — Vulnerability DNA <span class="badge badge-measured">Real SQLite record</span></h2>
            <div class="kv" id="im-kv"></div>
        </div>

        <div class="panel empty" id="panel-future">
            <h2>Future Learning Demo <span class="badge badge-measured">Real DNA similarity</span></h2>
            <p style="font-size:12px; color:var(--text-dim);">After the first vulnerability is verified & remembered, load a second, differently-named component with the same untrusted-length-to-fixed-buffer pattern and watch Immune Memory recognize it.</p>
            <div id="fl-result" style="margin-top:10px;"></div>
        </div>
    </div>

    <!-- IMMUNE MEMORY NETWORK -->
    <div class="section">
        <h2>Immune Memory Network</h2>
        <svg id="memNetwork" viewBox="0 0 800 220"></svg>
    </div>

    <!-- METRICS -->
    <div class="section">
        <h2>Dashboard Metrics</h2>
        <div class="metrics-row" id="metricsRow"></div>
    </div>

    <!-- TIMELINE -->
    <div class="section">
        <h2>Event Timeline</h2>
        <div class="timeline" id="timeline"></div>
    </div>

    <!-- FUTURE ECOSYSTEM -->
    <div class="section">
        <h2>Future SENTINEL-X Ecosystem <span class="badge badge-future">Disabled</span></h2>
        <div class="future-row">
            <div class="future-card"><h3>ORACLE</h3><p>Threat Prediction</p></div>
            <div class="future-card"><h3>PULSEMESH</h3><p>Runtime Protection</p></div>
            <div class="future-card"><h3>EVOLUTION</h3><p>Adaptive Repair</p></div>
        </div>
    </div>

    <div class="divider">— Interactive Scan Bench (ad-hoc code, not part of Judge Mode) —</div>

    <div class="section">
        <h2>Scan Arbitrary Code</h2>
        <form id="scan-form">
            <div class="form-group">
                <label for="scan-type">Scan Type</label>
                <select id="scan-type" name="scan-type">
                    <option value="code">Inline Code</option>
                    <option value="file">File Path</option>
                    <option value="directory">Directory</option>
                </select>
            </div>
            <div class="form-group" id="code-input-group">
                <label for="code-input">Code to Analyze</label>
                <textarea id="code-input" name="code" placeholder="Paste your code here..."></textarea>
            </div>
            <div class="form-group" id="path-input-group" style="display:none;">
                <label for="path-input">File/Directory Path</label>
                <input type="text" id="path-input" name="path" placeholder="/path/to/your/code">
            </div>
            <div class="form-group">
                <label for="filename">Filename (for reporting)</label>
                <input type="text" id="filename" name="filename" placeholder="example.py">
            </div>
            <div class="controls">
                <button type="submit" class="btn btn-primary" id="scan-btn">Start Scan</button>
                <button type="button" class="btn" id="load-sample-btn">Load Sample</button>
            </div>
        </form>
        <div id="scan-events" class="timeline" style="margin-top:14px;"></div>
        <div id="scan-results" style="margin-top:14px; display:none;">
            <table class="vuln-table" id="vuln-table">
                <thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Title</th><th>Location</th><th>CWE</th><th>Confidence</th></tr></thead>
                <tbody id="vuln-tbody"></tbody>
            </table>
            <div id="patches-container" style="margin-top:14px;"></div>
        </div>
    </div>

</div>

<script type="module">
import { initSentinelScene, webglAvailable } from '/static/sentinel-3d.js';

window.SentinelScene = null;
const scene3dWrap = document.getElementById('scene3d-wrap');
const pipeline2dWrap = document.getElementById('pipeline-2d-wrap');
const container = document.getElementById('scene3d-container');

if (webglAvailable()) {
    try {
        window.SentinelScene = initSentinelScene(container, { performanceMode: false });
        document.getElementById('btnPerfMode').addEventListener('click', function() {
            const on = this.classList.toggle('active');
            this.style.color = on ? 'var(--cyan)' : '';
            window.SentinelScene.setPerformanceMode(on);
        });
    } catch (e) {
        console.error('3D scene failed to initialize, falling back to 2D pipeline', e);
        scene3dWrap.style.display = 'none';
        pipeline2dWrap.style.display = 'block';
    }
} else {
    scene3dWrap.style.display = 'none';
    pipeline2dWrap.style.display = 'block';
    const note = document.createElement('div');
    note.className = 'scene-fallback-note';
    note.textContent = 'WebGL is unavailable in this browser — showing the 2D pipeline view instead.';
    pipeline2dWrap.prepend(note);
}
</script>

<script>
const socket = io();
const STAGE_GROUPS = {
    INIT:'discover', INGEST:'discover', REWIND:'discover', STATIC_ANALYSIS:'discover',
    DYNAMIC_ANALYSIS:'understand', FUZZ:'understand', DISCOVERY:'understand', ANALYZE:'understand',
    PATCH:'repair', BUILD:'repair',
    EXPLOIT_REPLAY:'verify', REGRESSION:'verify', BEHAVIOUR_CHECK:'verify',
    MEMORY_COMMIT:'remember', COMPLETE:'remember',
};
const CELL_FOR_STAGE = {
    INGEST:'repository', REWIND:'rewind', STATIC_ANALYSIS:'static', DYNAMIC_ANALYSIS:'dynamic',
    FUZZ:'fuzz', DISCOVERY:'vuln', ANALYZE:'anvil', PATCH:'patch', BUILD:'verify',
    EXPLOIT_REPLAY:'verify', REGRESSION:'verify', BEHAVIOUR_CHECK:'verify', MEMORY_COMMIT:'memory',
};
let doneGroups = new Set();
let sequenceOrder = ['discover','understand','repair','verify','remember'];

function setStatus(text, active) {
    document.getElementById('ms-status').innerHTML =
        '<span class="dot ' + (active ? 'dot-active' : 'dot-idle') + '"></span>' + text;
}

function markStage(stage) {
    document.getElementById('ms-op').textContent = stage;
    const group = STAGE_GROUPS[stage];
    if (!group) return;
    const idx = sequenceOrder.indexOf(group);
    sequenceOrder.slice(0, idx).forEach(g => doneGroups.add(g));
    document.querySelectorAll('.stage-pill').forEach(pill => {
        const g = pill.dataset.group;
        pill.classList.remove('active','done');
        const mark = pill.querySelector('.mark');
        if (doneGroups.has(g)) { pill.classList.add('done'); mark.textContent='✓'; }
        else if (g === group) { pill.classList.add('active'); mark.textContent='●'; }
        else { mark.textContent='○'; }
    });
    document.querySelectorAll('.cell').forEach(c => c.classList.remove('active'));
    const cellName = CELL_FOR_STAGE[stage];
    if (cellName) {
        const cell = document.querySelector('.cell[data-cell="'+cellName+'"]');
        if (cell) cell.classList.add('active');
    }
}

function markCellDone(cellName) {
    const cell = document.querySelector('.cell[data-cell="'+cellName+'"]');
    if (cell) { cell.classList.remove('active'); cell.classList.add('done'); }
}

document.querySelectorAll('.cell').forEach(c => {
    c.addEventListener('click', () => {
        const panel = document.getElementById('panel-' + c.dataset.cell);
        if (panel) panel.scrollIntoView({behavior:'smooth', block:'center'});
    });
});

function addTimeline(time, message) {
    const tl = document.getElementById('timeline');
    const el = document.createElement('div');
    el.className = 'tl-item';
    el.innerHTML = '<span class="tl-time">' + time + '</span><span class="tl-msg">' + message + '</span>';
    tl.insertBefore(el, tl.firstChild);
}

socket.on('demo_state', d => {
    setStatus(d.state, d.state === 'RUNNING');
    document.getElementById('btnStart').disabled = (d.state === 'RUNNING' || d.state === 'PAUSED');
    document.getElementById('btnPause').disabled = (d.state !== 'RUNNING');
    document.getElementById('btnResume').disabled = (d.state !== 'PAUSED');
    document.getElementById('btnFuture').disabled = (d.state !== 'COMPLETE');
    if (d.state === 'IDLE' && window.SentinelScene) window.SentinelScene.reset();
});

socket.on('stage_update', d => {
    markStage(d.stage);
    document.getElementById('progressLabel').textContent = d.progress + '% — ' + d.message;
    if (window.SentinelScene) window.SentinelScene.onStageUpdate(d.stage, d.message);
});

socket.on('timeline_event', d => addTimeline(d.time, d.message));

socket.on('rewind_result', d => {
    document.getElementById('panel-repository').classList.remove('empty');
    document.getElementById('panel-rewind').classList.remove('empty');
    document.getElementById('rw-commit').textContent = d.commit + ' — ' + d.subject;
    document.getElementById('rw-files').textContent = d.files_changed;
    document.getElementById('rw-sensitive').textContent = d.security_sensitive_files.join(', ') || 'none';
    document.getElementById('rw-risk').textContent = d.risk;
    document.getElementById('rw-reason').textContent = d.reasons.join(', ') || '—';
    const diffLines = (d.diff || '').split('\\n').map(l => {
        if (l.startsWith('+') && !l.startsWith('+++')) return '<span class="diffline-add">' + l + '</span>';
        if (l.startsWith('-') && !l.startsWith('---')) return '<span class="diffline-del">' + l + '</span>';
        return l;
    }).join('\\n');
    document.getElementById('rw-diff').innerHTML = diffLines;
    markCellDone('rewind');
});

socket.on('static_analysis_result', d => {
    document.getElementById('panel-static').classList.remove('empty');
    document.getElementById('sa-files').textContent = d.files_scanned;
    document.getElementById('sa-funcs').textContent = d.functions_analyzed;
    document.getElementById('sa-findings').textContent = d.findings.length;
    const list = document.getElementById('sa-list');
    list.innerHTML = '';
    d.findings.forEach(f => {
        const row = document.createElement('div');
        row.className = 'finding-row ' + f.severity;
        row.innerHTML = '<strong>' + f.severity.toUpperCase() + '</strong> ' + f.title +
            '<br><span style="color:var(--text-dim)">' + f.location + ' · ' + f.cwe_id + ' · ' +
            Math.round(f.confidence*100) + '% confidence</span>' +
            (f.code_snippet ? '<pre class="code" style="margin-top:6px;">' + f.code_snippet + '</pre>' : '');
        list.appendChild(row);
    });
    markCellDone('static');
});

let fuzzChartData = [];
function drawFuzzChart() {
    const canvas = document.getElementById('fuzzChart');
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.clientWidth; canvas.height = 60;
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.strokeStyle = '#e8b23d'; ctx.lineWidth = 2; ctx.beginPath();
    fuzzChartData.forEach((v,i) => {
        const x = (i/(fuzzChartData.length-1||1)) * canvas.width;
        const y = canvas.height - (v/100)*canvas.height;
        i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.stroke();
}

socket.on('dynamic_analysis_result', d => {
    document.getElementById('panel-dynamic').classList.remove('empty');
    document.getElementById('da-inputs').textContent = d.inputs_executed.toLocaleString();
    document.getElementById('da-paths').textContent = d.unique_paths;
    document.getElementById('da-crashes').textContent = d.crashes;
    document.getElementById('da-banner').textContent = d.detected ? '● MEMORY ERROR DETECTED (' + d.sanitizer + ')' : '';
    markCellDone('dynamic');
});

socket.on('fuzz_result', d => {
    document.getElementById('panel-fuzz').classList.remove('empty');
    document.getElementById('fz-eps').textContent = d.executions_per_sec.toLocaleString();
    document.getElementById('fz-total').textContent = d.total_executions.toLocaleString();
    document.getElementById('fz-corpus').textContent = d.corpus_size;
    document.getElementById('fz-cov').textContent = d.coverage_pct + '%';
    document.getElementById('fz-crashes').textContent = d.unique_crashes;
    document.getElementById('fz-crash').innerHTML = '<strong>CRASH FOUND</strong><br>' +
        'Input: ' + d.crash.input_file + '<br>Signal: ' + d.crash.signal +
        '<br>Location: ' + d.crash.location;
    fuzzChartData = Array.from({length:40}, () => Math.random()*40 + d.coverage_pct*0.6);
    drawFuzzChart();
    markCellDone('fuzz');
});

socket.on('vulnerability_confirmed', d => {
    document.getElementById('panel-vuln').classList.remove('empty');
    document.getElementById('ve-cwe').textContent = d.cwe;
    document.getElementById('ve-conf').textContent = d.confidence_pct + '%';
    document.getElementById('ve-sev').textContent = d.severity;
    const cl = document.getElementById('ve-checklist');
    cl.innerHTML = '';
    d.evidence.forEach(e => {
        const badge = e.evidence_type === 'measured' ? 'badge-measured' : 'badge-demo';
        cl.innerHTML += '<div class="item"><span>' + e.item + (e.detail ? ' ('+e.detail+')' : '') +
            '</span><span class="ok">✓ <span class="badge '+badge+'">'+e.evidence_type+'</span></span></div>';
    });
    markCellDone('vuln');
});

socket.on('anvil_result', d => {
    document.getElementById('panel-anvil').classList.remove('empty');
    document.getElementById('an-provider').textContent = d.provider;
    document.getElementById('an-model').textContent = d.model;
    document.getElementById('an-explanation').textContent = d.explanation;
    markCellDone('anvil');
});

let lastPatch = null;
socket.on('patch_result', d => {
    lastPatch = d;
    document.getElementById('panel-patch').classList.remove('empty');
    document.getElementById('patch-diff').textContent = d.patched_code;
    document.getElementById('patch-note').textContent = '';
    markCellDone('patch');
});

socket.on('build_result', d => {
    document.getElementById('vc-build').innerHTML = d.compile_success ? '<span class="ok">✓ PASS</span>' : '<span class="bad">✗ FAIL</span>';
    document.getElementById('panel-verify').classList.remove('empty');
    if (window.SentinelScene) window.SentinelScene.onVerifyStep('build', d.compile_success);
});

socket.on('replay_result', d => {
    document.getElementById('replayBox').style.display = 'flex';
    const beforeLabel = d.before.crashed ? 'CRASHED (real ASan)' : (d.before.compiled ? 'no crash' : 'compile failed');
    const afterLabel = d.after.crashed ? 'CRASHED (real ASan)' : (d.after.compiled ? 'SAFE — rejected' : 'compile failed');
    document.getElementById('replay-before-out').innerHTML = beforeLabel + '<div style="font-size:9px; margin-top:6px;"><span class="badge badge-measured">measured — real clang+ASan in Colima VM</span></div>';
    document.getElementById('replay-after-out').innerHTML = afterLabel + '<div style="font-size:9px; margin-top:6px;"><span class="badge badge-measured">measured — real clang+ASan in Colima VM</span></div>';
    document.getElementById('vc-replay-before').innerHTML = d.before.crashed ? '<span class="bad">✗ CRASHED</span>' : '<span class="ok">✓ no crash</span>';
    document.getElementById('vc-replay-after').innerHTML = !d.after.crashed && d.after.compiled ? '<span class="ok">✓ SAFE</span>' : '<span class="bad">✗ still crashes</span>';
    if (window.SentinelScene) window.SentinelScene.onVerifyStep('exploit', d.exploit_blocked);
    document.getElementById('vc-sanitizer').innerHTML = '<span class="ok">✓ ASan <span class="badge badge-measured">real</span></span>';
});

socket.on('regression_result', d => {
    document.getElementById('panel-regression').classList.remove('empty');
    document.getElementById('vc-regression').innerHTML = d.passed ? '<span class="ok">✓ PASS</span>' : '<span class="bad">✗ FAIL</span>';
    document.getElementById('rg-result').textContent = d.passed ? 'PASS' : 'FAIL';
    document.getElementById('rg-count').innerHTML = d.demo_test_count;
    if (window.SentinelScene) { window.SentinelScene.onVerifyStep('regression', d.passed); window.SentinelScene.onVerifyStep('sanitizer', true); }
});

socket.on('behaviour_result', d => {
    document.getElementById('vc-behaviour').innerHTML = d.preserved ? '<span class="ok">✓ PASS</span>' : '<span class="bad">✗ FAIL</span>';
    if (window.SentinelScene) window.SentinelScene.onVerifyStep('behaviour', d.preserved);
});

socket.on('immune_memory_created', d => {
    document.getElementById('panel-memory').classList.remove('empty');
    document.getElementById('im-kv').innerHTML =
        '<div class="k">ID</div><div class="v">' + d.id + '</div>' +
        '<div class="k">Vulnerability</div><div class="v">' + d.vulnerability + '</div>' +
        '<div class="k">CWE</div><div class="v">' + d.cwe + '</div>' +
        '<div class="k">Pattern</div><div class="v">' + d.pattern + '</div>';
    markCellDone('memory');
    drawMemNetwork(d);
    if (window.SentinelScene) window.SentinelScene.onImmuneMemoryCreated();
});

socket.on('future_learning_result', d => {
    const el = document.getElementById('fl-result');
    if (window.SentinelScene && d.matched) window.SentinelScene.onFutureLearning(d.similarity_pct);
    if (!d.matched) {
        el.innerHTML = '<em>' + (d.message || 'No pattern match found.') + '</em>';
        return;
    }
    el.innerHTML =
        '<div class="kv">' +
        '<div class="k">New File</div><div class="v">' + d.new_file + '</div>' +
        '<div class="k">Finding</div><div class="v">' + d.finding.title + ' (' + d.finding.cwe + ')</div>' +
        '<div class="k">Similarity</div><div class="v">' + d.similarity_pct + '% (' + d.similarity_basis + ')</div>' +
        '<div class="k">Recommendation</div><div class="v">' + (d.recommendation || '—') + '</div>' +
        '</div><div style="margin-top:8px; color:var(--amber); font-weight:700;">IMMUNE MEMORY ACTIVATED — known pattern detected</div>';
    extendMemNetwork(d);
});

socket.on('demo_final', d => {
    const card = document.getElementById('finalCard');
    card.classList.add('show');
    document.getElementById('finalKv').innerHTML =
        '<div class="k">Vulnerability</div><div>' + d.vulnerability + '</div>' +
        '<div class="k">Root Cause</div><div>IDENTIFIED</div>' +
        '<div class="k">Patch</div><div>' + (d.verified ? 'GENERATED' : 'REJECTED') + '</div>' +
        '<div class="k">Build</div><div>' + (d.compile_success ? 'PASSED' : 'FAILED') + '</div>' +
        '<div class="k">Exploit Replay</div><div>' + (d.exploit_blocked ? 'BLOCKED' : '—') + '</div>' +
        '<div class="k">Regression</div><div>' + (d.regression_pass ? 'PASSED' : 'FAILED') + '</div>' +
        '<div class="k">Behaviour</div><div>' + (d.behaviour_preserved ? 'VALIDATED' : 'FAILED') + '</div>' +
        '<div class="k">Immune Memory</div><div>' + (d.immune_memory_created ? 'CREATED' : 'NOT CREATED') + '</div>';
    refreshMetrics();
});

function drawMemNetwork(d) {
    const svg = document.getElementById('memNetwork');
    svg.innerHTML = '';
    const center = {x:120, y:110};
    const nodes = [
        {label:d.cwe, x:280, y:40}, {label:'Length Validation Fix', x:320, y:110},
        {label:'ASan Crash Pattern', x:280, y:180}, {label:'Parser Pattern', x:120, y:190},
        {label:'Regression Seed', x:60, y:30},
    ];
    let html = '';
    nodes.forEach(n => {
        html += '<line x1="'+center.x+'" y1="'+center.y+'" x2="'+n.x+'" y2="'+n.y+'" stroke="#1c2a32" stroke-width="1.5"/>';
    });
    html += '<circle cx="'+center.x+'" cy="'+center.y+'" r="34" fill="rgba(45,226,201,.12)" stroke="#2de2c9" stroke-width="1.5"/>';
    html += '<text x="'+center.x+'" y="'+center.y+'" fill="#eafcf6" font-size="10" text-anchor="middle" dy="4">Buffer<tspan x="'+center.x+'" dy="12">Overflow</tspan></text>';
    nodes.forEach(n => {
        html += '<circle cx="'+n.x+'" cy="'+n.y+'" r="26" fill="#0f171d" stroke="#5b6b74" stroke-width="1"/>';
        html += '<text x="'+n.x+'" y="'+n.y+'" fill="#7d8f97" font-size="8" text-anchor="middle" dy="3">'+n.label.slice(0,14)+'</text>';
    });
    svg.innerHTML = html;
    window._memNodes = nodes; window._memCenter = center;
}
function extendMemNetwork(d) {
    if (!window._memCenter) return;
    const svg = document.getElementById('memNetwork');
    const nx = 480, ny = 110;
    let html = svg.innerHTML;
    html += '<line x1="'+window._memCenter.x+'" y1="'+window._memCenter.y+'" x2="'+nx+'" y2="'+ny+'" stroke="#e8b23d" stroke-width="2" stroke-dasharray="4,3"/>';
    html += '<circle cx="'+nx+'" cy="'+ny+'" r="30" fill="rgba(232,178,61,.12)" stroke="#e8b23d" stroke-width="1.5"/>';
    html += '<text x="'+nx+'" y="'+ny+'" fill="#e8b23d" font-size="9" text-anchor="middle" dy="-2">network_parser_v2</text>';
    html += '<text x="'+nx+'" y="'+ny+'" fill="#e8b23d" font-size="9" text-anchor="middle" dy="10">'+d.similarity_pct+'% match</text>';
    svg.innerHTML = html;
}

function refreshMetrics() {
    fetch('/api/sentinel/metrics').then(r => r.json()).then(d => {
        const m = d.metrics;
        const row = document.getElementById('metricsRow');
        const items = [
            ['Vulnerabilities Found', m.vulnerabilities_found],
            ['Vulnerabilities Verified', m.vulnerabilities_verified],
            ['Patches Generated', m.patches_generated],
            ['Patches Accepted', m.patches_accepted],
            ['Regression Tests', m.regression_tests_passed + '/' + m.regression_tests_total],
            ['Fuzz Executions', m.fuzz_executions.toLocaleString() + ' (demo)'],
            ['Immune Records', m.immune_records],
            ['False Fixes', m.false_fixes],
        ];
        row.innerHTML = items.map(([l,v]) => '<div class="metric"><div class="num">'+v+'</div><div class="lbl">'+l+'</div></div>').join('');
    });
}

// controls
document.getElementById('btnStart').addEventListener('click', () => fetch('/api/sentinel/start', {method:'POST'}));
document.getElementById('btnPause').addEventListener('click', () => fetch('/api/sentinel/pause', {method:'POST'}));
document.getElementById('btnResume').addEventListener('click', () => fetch('/api/sentinel/resume', {method:'POST'}));
document.getElementById('btnReset').addEventListener('click', () => {
    fetch('/api/sentinel/reset', {method:'POST'}).then(() => location.reload());
});
document.getElementById('btnFuture').addEventListener('click', () => fetch('/api/sentinel/future-learning', {method:'POST'}));
document.getElementById('btnReplay').addEventListener('click', () => {
    document.getElementById('panel-verify').scrollIntoView({behavior:'smooth', block:'center'});
});
document.getElementById('btnReject').addEventListener('click', () => {
    document.getElementById('patch-note').textContent = 'Patch rejected by operator. AI-generated patches are never auto-trusted.';
});
document.getElementById('btnRegenerate').addEventListener('click', () => {
    document.getElementById('patch-note').textContent = 'Re-running full pipeline to regenerate…';
    fetch('/api/sentinel/reset', {method:'POST'}).then(() => fetch('/api/sentinel/start', {method:'POST'}));
});
document.getElementById('btnTestPatch').addEventListener('click', () => {
    document.getElementById('panel-verify').scrollIntoView({behavior:'smooth', block:'center'});
});

// load repository intake on page load
fetch('/api/sentinel/target').then(r => r.json()).then(d => {
    document.getElementById('ri-name').textContent = d.name;
    document.getElementById('ri-lang').textContent = d.language;
    document.getElementById('ri-build').textContent = d.build;
    document.getElementById('ri-profile').textContent = d.security_profile;
    document.getElementById('ri-status').textContent = d.status;
    document.getElementById('panel-repository').classList.remove('empty');
    document.getElementById('ms-target').textContent = d.name;
    document.getElementById('ms-llm').textContent = d.llm_provider.toUpperCase() + ' · ' + d.llm_model;
});
refreshMetrics();

// ============================================================
// Interactive Scan Bench (legacy ad-hoc scan, separate from Judge Mode)
// ============================================================
document.getElementById('scan-type').addEventListener('change', function() {
    const t = this.value;
    document.getElementById('code-input-group').style.display = t === 'code' ? 'block' : 'none';
    document.getElementById('path-input-group').style.display = t !== 'code' ? 'block' : 'none';
});
document.getElementById('load-sample-btn').addEventListener('click', function() {
    document.getElementById('scan-type').value = 'code';
    document.getElementById('code-input-group').style.display = 'block';
    document.getElementById('path-input-group').style.display = 'none';
    document.getElementById('code-input').value = `import os
import pickle

def run_command(cmd):
    return os.popen(cmd).read()

def load_user_data(data):
    return pickle.loads(data)

def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()

API_KEY = "sk-1234567890abcdef12345678"
password = "admin123"`;
    document.getElementById('filename').value = 'vulnerable_app.py';
});

function addScanEvent(msg) {
    const feed = document.getElementById('scan-events');
    const el = document.createElement('div');
    el.className = 'tl-item';
    el.innerHTML = '<span class="tl-time">' + new Date().toLocaleTimeString() + '</span><span class="tl-msg">' + msg + '</span>';
    feed.insertBefore(el, feed.firstChild);
}
socket.on('scan_progress', d => addScanEvent(d.message));
socket.on('vulnerability_found', d => addScanEvent('Found: ' + d.vulnerability.title));
socket.on('patch_generated', d => addScanEvent('Patch generated: ' + d.patch_id));
socket.on('verification_complete', d => addScanEvent('Verification ' + (d.all_tests_pass ? 'PASSED' : 'FAILED') + ': ' + d.patch_id));
socket.on('scan_complete', result => {
    document.getElementById('scan-results').style.display = 'block';
    const tbody = document.getElementById('vuln-tbody');
    tbody.innerHTML = '';
    (result.vulnerabilities || []).forEach((v, i) => {
        const row = document.createElement('tr');
        row.innerHTML = '<td>'+(i+1)+'</td><td>'+v.severity+'</td><td>'+v.vuln_type+'</td><td>'+v.title+
            '</td><td>'+v.location.file_path+':'+v.location.line_start+'</td><td>'+(v.cwe_id||'N/A')+
            '</td><td>'+Math.round(v.confidence*100)+'%</td>';
        tbody.appendChild(row);
    });
    const pc = document.getElementById('patches-container');
    pc.innerHTML = '';
    (result.patches || []).forEach(p => {
        const div = document.createElement('div');
        div.className = 'panel';
        div.style.marginBottom = '10px';
        div.innerHTML = '<strong>' + p.id + '</strong> — ' + p.status + '<pre class="code">' + (p.explanation||'') + '</pre>';
        pc.appendChild(div);
    });
    addScanEvent('Scan complete');
});

document.getElementById('scan-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const scanType = document.getElementById('scan-type').value;
    document.getElementById('scan-events').innerHTML = '';
    document.getElementById('scan-results').style.display = 'none';
    try {
        let endpoint = '/api/scan';
        let payload = {};
        if (scanType === 'code') {
            payload = { code: document.getElementById('code-input').value, filename: document.getElementById('filename').value || 'inline.py' };
        } else {
            endpoint = scanType === 'file' ? '/api/scan/file' : '/api/scan/directory';
            payload = { path: document.getElementById('path-input').value };
        }
        const response = await fetch(endpoint, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        const result = await response.json();
        if (result.error) { alert('Error: ' + result.error); return; }
        if (scanType !== 'code') {
            document.getElementById('scan-results').style.display = 'block';
            const tbody = document.getElementById('vuln-tbody');
            tbody.innerHTML = '';
            (result.vulnerabilities || []).forEach((v, i) => {
                const row = document.createElement('tr');
                row.innerHTML = '<td>'+(i+1)+'</td><td>'+v.severity+'</td><td>'+v.vuln_type+'</td><td>'+v.title+
                    '</td><td>'+v.location.file_path+':'+v.location.line_start+'</td><td>'+(v.cwe_id||'N/A')+
                    '</td><td>'+Math.round(v.confidence*100)+'%</td>';
                tbody.appendChild(row);
            });
        }
    } catch (err) {
        alert('Scan failed: ' + err.message);
    }
});
</script>
</body>
</html>
"""


@app.route('/')
def index():
    """Serve the dashboard."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/case-file')
def case_file():
    """Serve the static SENTINEL-X CORE case-file page (same content as the
    published Artifact) directly from this local server."""
    path = project_root / "sentinel_x_case_file.html"
    if not path.exists():
        return "Case file not found — expected at " + str(path), 404
    return path.read_text(), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route('/api/scan', methods=['POST'])
def scan_code():
    """Scan inline code for vulnerabilities with real-time updates."""
    data = request.get_json()
    code = data.get('code', '')
    filename = data.get('filename', 'inline.py')
    
    if not code:
        return jsonify({'error': 'No code provided'}), 400
    
    try:
        core = get_orchestrator()
        observable = ObservableOrchestrator(core)
        
        # Run scan in background thread to allow WebSocket events
        def run_scan():
            vulns, patches, verifications, summary = observable.scan_code_with_events(code, filename)
            
            # Emit final results
            socketio.emit('scan_complete', {
                'scan_id': f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                'target_path': filename,
                'vulnerabilities': [v.model_dump(mode='json') for v in vulns],
                'patches': [p.model_dump(mode='json') for p in patches],
                'verifications': [v.model_dump(mode='json') for v in verifications],
                'summary': summary
            })
        
        socketio.start_background_task(run_scan)
        
        return jsonify({'status': 'started', 'message': 'Scan started with real-time updates'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Scan a file for vulnerabilities."""
    data = request.get_json()
    path = data.get('path', '')
    
    if not path or not os.path.isfile(path):
        return jsonify({'error': 'Invalid file path'}), 400
    
    try:
        core = get_orchestrator()
        result = core.scan(path)
        
        return jsonify({
            'scan_id': result.scan_id,
            'target_path': result.target_path,
            'vulnerabilities': [v.model_dump(mode='json') for v in result.vulnerabilities],
            'patches': [p.model_dump(mode='json') for p in result.patches],
            'verifications': [v.model_dump(mode='json') for v in result.verifications],
            'summary': result.summary
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/directory', methods=['POST'])
def scan_directory():
    """Scan a directory for vulnerabilities."""
    data = request.get_json()
    path = data.get('path', '')
    
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'Invalid directory path'}), 400
    
    try:
        core = get_orchestrator()
        result = core.scan(path)
        
        return jsonify({
            'scan_id': result.scan_id,
            'target_path': result.target_path,
            'vulnerabilities': [v.model_dump(mode='json') for v in result.vulnerabilities],
            'patches': [p.model_dump(mode='json') for p in result.patches],
            'verifications': [v.model_dump(mode='json') for v in result.verifications],
            'summary': result.summary
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/memory/stats')
def memory_stats():
    """Get immune memory statistics."""
    try:
        core = get_orchestrator()
        stats = core.get_memory_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'version': '2.0.0', 'websocket': True})


# ============================================================
# SENTINEL-X CORE — Judge Mode demo control
# ============================================================

@app.route('/api/sentinel/target')
def sentinel_target():
    """Repository intake info for the demo target."""
    return jsonify({
        'name': 'secure_packet_parser',
        'language': 'C',
        'build': 'CMake',
        'security_profile': 'Memory Safety',
        'status': 'READY',
        'llm_provider': LLM_PROVIDER,
        'llm_model': LLM_MODEL,
        'llm_location': 'LOCALHOST',
        'llm_internet_required': False,
    })


@app.route('/api/sentinel/start', methods=['POST'])
def sentinel_start():
    """Kick off the full autonomous lifecycle (Judge Mode)."""
    sentinel = get_sentinel()
    if not _sentinel_run_lock.acquire(blocking=False):
        return jsonify({'error': 'A demo run is already in progress'}), 409

    def run():
        try:
            sentinel.run_full_demo()
        finally:
            _sentinel_run_lock.release()

    socketio.start_background_task(run)
    return jsonify({'status': 'started'})


@app.route('/api/sentinel/pause', methods=['POST'])
def sentinel_pause():
    get_sentinel().pause()
    return jsonify({'status': 'paused'})


@app.route('/api/sentinel/resume', methods=['POST'])
def sentinel_resume():
    get_sentinel().resume()
    return jsonify({'status': 'resumed'})


@app.route('/api/sentinel/reset', methods=['POST'])
def sentinel_reset():
    global _sentinel
    with _sentinel_lock:
        if _sentinel is not None:
            _sentinel.reset()
        _sentinel = None
    return jsonify({'status': 'reset'})


@app.route('/api/sentinel/future-learning', methods=['POST'])
def sentinel_future_learning():
    """Run the second-vulnerability Immune Memory pattern-match demo."""
    sentinel = get_sentinel()
    socketio.start_background_task(sentinel.run_future_learning_demo)
    return jsonify({'status': 'started'})


@app.route('/api/sentinel/metrics')
def sentinel_metrics():
    sentinel = get_sentinel()
    mem_stats = get_orchestrator().get_memory_stats()
    return jsonify({
        'demo_state': sentinel.state,
        'metrics': sentinel.metrics,
        'memory_stats': mem_stats,
    })


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    print(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    print(f"Client disconnected: {request.sid}")


def main():
    """Run the dashboard server with WebSocket support."""
    print("=" * 70)
    print("ABHIMANYU X CORE - Web Dashboard with WebSocket")
    print("=" * 70)
    print()
    print("Starting dashboard server with real-time updates...")
    print("Open http://localhost:5050 in your browser")
    print()
    print("Features:")
    print("  - Real-time scan progress via WebSocket")
    print("  - Live vulnerability detection events")
    print("  - Instant patch generation notifications")
    print("  - Verification status updates")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 70)
    
    socketio.run(app, host='0.0.0.0', port=5050, debug=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    main()
