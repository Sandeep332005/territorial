"""
ABHIMANYU X CORE - FastAPI Backend
REST API for the autonomous cyber reasoning system
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

from abhimanyux.models.schemas import (
    HealthResponse, AnalyzeRequest, AnalyzeResponse,
    PatchRequest, PatchResponse, ScanRequest, ScanResult,
    Vulnerability, Patch, PatchStatus, Severity, VulnType
)

# Initialize engines
from abhimanyux.rewind.engine import REWINDEngine
from abhimanyux.anvil.engine import ANVILEngine
from abhimanyux.memory.store import ImmuneMemoryStore

app = FastAPI(
    title="ABHIMANYU X CORE",
    description="Autonomous Cyber Reasoning & Software Immunization System",
    version="0.1.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
rewind = REWINDEngine()
anvil = ANVILEngine()
memory = ImmuneMemoryStore()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        components={
            "rewind": True,
            "anvil": True,
            "memory": True
        }
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_code(request: AnalyzeRequest):
    """
    Analyze code for vulnerabilities
    
    Uses REWIND engine for static analysis
    """
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    
    # Run static analysis
    vulnerabilities = rewind.scan(request.code, request.filename)
    
    # Store in memory
    for vuln in vulnerabilities:
        memory.store_vulnerability(vuln)
    
    return AnalyzeResponse(
        scan_id=scan_id,
        vulnerabilities=vulnerabilities,
        summary={
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": _count_by_severity(vulnerabilities),
            "by_type": _count_by_type(vulnerabilities)
        }
    )


@app.post("/api/patch")
async def generate_patch(request: PatchRequest):
    """
    Generate a security patch for a vulnerability
    
    Uses ANVIL engine for LLM-based patch generation
    """
    # Get vulnerability from memory or create from request
    vuln = Vulnerability(
        id=request.vulnerability_id,
        vuln_type=VulnType.SQL_INJECTION,  # Default, should be provided
        severity=Severity.HIGH,
        title="Vulnerability",
        description=request.vulnerability_info,
        location={"file_path": "unknown", "line_start": 0}
    )
    
    # Generate patch
    patch = anvil.analyze_and_patch(request.code, vuln)
    
    # Store in memory
    memory.store_patch(patch)
    
    return {
        "patch_id": patch.id,
        "patched_code": patch.patched_code,
        "explanation": patch.explanation,
        "status": patch.status.value
    }


@app.post("/api/scan/full")
async def full_scan(request: ScanRequest):
    """
    Full security scan with all engines
    
    Performs:
    1. Static analysis (REWIND)
    2. Patch generation (ANVIL)
    3. Verification
    4. Memory storage
    """
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    
    # Read target file
    try:
        with open(request.target_path, 'r') as f:
            code = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Target file not found")
    
    # Step 1: Static analysis
    vulnerabilities = rewind.scan(code, request.target_path)
    
    # Step 2: Generate patches for each vulnerability
    patches = []
    for vuln in vulnerabilities:
        patch = anvil.analyze_and_patch(code, vuln)
        patches.append(patch)
        
        # Store in memory
        memory.store_vulnerability(vuln)
        memory.store_patch(patch)
    
    # Step 3: Create immune records
    immune_records = []
    for vuln, patch in zip(vulnerabilities, patches):
        dna = memory.create_dna(vuln, patch.explanation)
        memory.store_immune_record(vuln.id, patch.id, dna.id)
    
    return {
        "scan_id": scan_id,
        "target": request.target_path,
        "vulnerabilities": [v.model_dump() for v in vulnerabilities],
        "patches": [p.model_dump() for p in patches],
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "total_patches": len(patches),
            "by_severity": _count_by_severity(vulnerabilities),
            "by_type": _count_by_type(vulnerabilities)
        }
    }


@app.get("/api/memory/stats")
async def memory_stats():
    """Get immune memory statistics"""
    return memory.get_statistics()


@app.get("/api/memory/vulnerabilities")
async def list_vulnerabilities(vuln_type: Optional[str] = None):
    """List stored vulnerabilities"""
    if vuln_type:
        return memory.search_by_type(VulnType(vuln_type))
    else:
        # Return all
        conn = memory.db_path
        import sqlite3
        conn = sqlite3.connect(conn)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnerabilities ORDER BY last_seen DESC")
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results


@app.get("/api/memory/dna")
async def list_dna_patterns():
    """List vulnerability DNA patterns"""
    import sqlite3
    conn = sqlite3.connect(memory.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerability_dna ORDER BY created_at DESC")
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


@app.get("/api/memory/fixes")
async def list_fix_strategies():
    """List known fix strategies by vulnerability type"""
    strategies = {}
    for vuln_type in VulnType:
        type_strategies = memory.get_fix_strategies(vuln_type)
        if type_strategies:
            strategies[vuln_type.value] = type_strategies
    return strategies


@app.post("/api/verify")
async def verify_patch(patch_id: str, original_code: str, patched_code: str):
    """Verify a patch"""
    from abhimanyux.verifier.engine import VerificationEngine
    
    verifier = VerificationEngine()
    
    # Get patch from memory
    import sqlite3
    conn = sqlite3.connect(memory.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM patches WHERE id = ?", (patch_id,))
    patch_data = dict(cursor.fetchone() or {})
    conn.close()
    
    if not patch_data:
        raise HTTPException(status_code=404, detail="Patch not found")
    
    # Create patch object
    patch = Patch(
        id=patch_id,
        vuln_id=patch_data["vuln_id"],
        original_code=original_code,
        patched_code=patched_code,
        explanation=patch_data["explanation"],
        status=PatchStatus(patch_data["status"])
    )
    
    # Create vulnerability object (simplified)
    vuln = Vulnerability(
        id=patch_data["vuln_id"],
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.HIGH,
        title="Vulnerability",
        description="",
        location={"file_path": "unknown", "line_start": 0}
    )
    
    # Run verification
    result = verifier.verify(original_code, patched_code, vuln, patch)
    
    # Store verification result
    memory.store_verification(patch_id, result)
    
    return result.model_dump()


def _count_by_severity(vulnverabilities: List[Vulnerability]) -> Dict[str, int]:
    """Count vulnerabilities by severity"""
    counts = {}
    for v in vulnverabilities:
        counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
    return counts


def _count_by_type(vulnverabilities: List[Vulnerability]) -> Dict[str, int]:
    """Count vulnerabilities by type"""
    counts = {}
    for v in vulnverabilities:
        counts[v.vuln_type.value] = counts.get(v.vuln_type.value, 0) + 1
    return counts


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
