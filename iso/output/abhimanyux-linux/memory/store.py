"""
ABHIMANYU X CORE - Immune Memory Store
Vulnerability Knowledge Base & Pattern Learning

Stores and retrieves:
- Vulnerability DNA (immutable patterns)
- Fix strategies
- Regression seeds
- Attack pattern evolution
"""

import json
import hashlib
import sqlite3
from difflib import SequenceMatcher
from typing import List, Dict, Optional
from datetime import datetime, timezone
from pathlib import Path

from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityDNA, ImmuneRecord, 
    Patch, ExploitEvidence, VerificationResult, VulnType
)


class ImmuneMemoryStore:
    """
    Immune Memory Store
    
    Like biological immunity, this system:
    1. Remembers every vulnerability encountered
    2. Creates "DNA" patterns for each vulnerability type
    3. Uses memory to detect similar future vulnerabilities
    4. Improves defense over time
    """
    
    def __init__(self, db_path: str = "abhimanyux_memory.db"):
        self.db_path = db_path
        self._init_db()
        self.memory_count = 0
    
    def _init_db(self):
        """Initialize the memory database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                vuln_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                file_path TEXT,
                line_start INTEGER,
                cwe_id TEXT,
                confidence REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1
            )
        ''')
        
        # DNA patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_dna (
                id TEXT PRIMARY KEY,
                vuln_type TEXT,
                pattern_signature TEXT,
                description TEXT,
                detection_rules TEXT,
                fix_strategies TEXT,
                regression_seeds TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        # Patches table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patches (
                id TEXT PRIMARY KEY,
                vuln_id TEXT,
                original_code TEXT,
                patched_code TEXT,
                explanation TEXT,
                status TEXT,
                generated_at TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
            )
        ''')
        
        # Exploit evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploit_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id TEXT,
                exploit_code TEXT,
                crash_output TEXT,
                sanitizer_output TEXT,
                success BOOLEAN,
                recorded_at TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
            )
        ''')
        
        # Verification results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patch_id TEXT,
                compile_success BOOLEAN,
                exploit_blocked BOOLEAN,
                regression_pass BOOLEAN,
                behavior_preserved BOOLEAN,
                verified_at TIMESTAMP,
                FOREIGN KEY (patch_id) REFERENCES patches(id)
            )
        ''')
        
        # Immune records (complete lifecycle)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS immune_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id TEXT,
                patch_id TEXT,
                dna_id TEXT,
                created_at TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id),
                FOREIGN KEY (patch_id) REFERENCES patches(id),
                FOREIGN KEY (dna_id) REFERENCES vulnerability_dna(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_vulnerability(self, vulnerability: Vulnerability) -> str:
        """
        Store a discovered vulnerability
        
        Returns:
            Vulnerability ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if similar vulnerability exists
        existing = self._find_similar(vulnerability)
        
        if existing:
            # Update occurrence count
            cursor.execute('''
                UPDATE vulnerabilities 
                SET last_seen = ?, occurrence_count = occurrence_count + 1
                WHERE id = ?
            ''', (datetime.now(timezone.utc).isoformat(), existing))
            vuln_id = existing
        else:
            # Insert new vulnerability
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (id, vuln_type, severity, title, description, file_path, 
                 line_start, cwe_id, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vulnerability.id,
                vulnerability.vuln_type.value,
                vulnerability.severity.value,
                vulnerability.title,
                vulnerability.description,
                vulnerability.location.file_path,
                vulnerability.location.line_start,
                vulnerability.cwe_id,
                vulnerability.confidence,
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat()
            ))
            vuln_id = vulnerability.id
        
        conn.commit()
        conn.close()
        
        self.memory_count += 1
        return vuln_id
    
    def create_dna(self, vulnerability: Vulnerability, 
                   fix_strategy: str) -> VulnerabilityDNA:
        """
        Create vulnerability DNA - immutable pattern for future detection
        """
        # Generate pattern signature
        signature = self._generate_signature(vulnerability)
        
        # Create DNA
        dna = VulnerabilityDNA(
            id=f"dna-{hashlib.sha256(signature.encode()).hexdigest()[:12]}",
            vuln_type=vulnerability.vuln_type,
            pattern_signature=signature,
            description=f"Pattern for {vulnerability.vuln_type.value} vulnerabilities",
            detection_rules=[vulnerability.raw_analysis or ""],
            fix_strategies=[fix_strategy],
            regression_seeds=[]
        )
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerability_dna 
            (id, vuln_type, pattern_signature, description, 
             detection_rules, fix_strategies, regression_seeds, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            dna.id,
            dna.vuln_type.value,
            dna.pattern_signature,
            dna.description,
            json.dumps(dna.detection_rules),
            json.dumps(dna.fix_strategies),
            json.dumps(dna.regression_seeds),
            datetime.now(timezone.utc).isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return dna
    
    def store_patch(self, patch: Patch) -> str:
        """Store a generated patch"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO patches 
            (id, vuln_id, original_code, patched_code, explanation, 
             status, generated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            patch.id,
            patch.vuln_id,
            patch.original_code,
            patch.patched_code,
            patch.explanation,
            patch.status.value,
            datetime.now(timezone.utc).isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return patch.id
    
    def store_exploit_evidence(self, vuln_id: str, evidence: ExploitEvidence) -> int:
        """Store exploit evidence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO exploit_evidence 
            (vuln_id, exploit_code, crash_output, sanitizer_output, 
             success, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            vuln_id,
            evidence.exploit_code,
            evidence.crash_output,
            evidence.sanitizer_output,
            evidence.success,
            datetime.now(timezone.utc).isoformat()
        ))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return record_id
    
    def store_verification(self, patch_id: str, result: VerificationResult) -> int:
        """Store verification result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO verifications 
            (patch_id, compile_success, exploit_blocked, regression_pass, 
             behavior_preserved, verified_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            patch_id,
            result.compile_success,
            result.exploit_blocked,
            result.regression_pass,
            result.behavior_preserved,
            datetime.now(timezone.utc).isoformat()
        ))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return record_id
    
    def store_immune_record(self, vuln_id: str, patch_id: Optional[str] = None,
                           dna_id: Optional[str] = None) -> int:
        """Store complete immune record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO immune_records 
            (vuln_id, patch_id, dna_id, created_at)
            VALUES (?, ?, ?, ?)
        ''', (
            vuln_id,
            patch_id,
            dna_id,
            datetime.now(timezone.utc).isoformat()
        ))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return record_id
    
    def search_by_type(self, vuln_type: VulnType) -> List[Dict]:
        """Search memory for vulnerabilities of a specific type"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM vulnerabilities 
            WHERE vuln_type = ?
            ORDER BY last_seen DESC
        ''', (vuln_type.value,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def search_by_cwe(self, cwe_id: str) -> List[Dict]:
        """Search memory for vulnerabilities by CWE ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM vulnerabilities 
            WHERE cwe_id = ?
            ORDER BY last_seen DESC
        ''', (cwe_id,))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_similar_patches(self, vuln_type: VulnType, code: str = "",
                             limit: int = 3) -> List[Dict]:
        """
        Retrieve prior patches for the same vulnerability type, ranked by
        similarity of their stored `original_code` to `code` (tie-broken
        toward previously-verified patches). `code` should be full source
        text, the same granularity `original_code` is stored at (see
        Patch.original_code) — comparing a single-line snippet against a
        stored full file would make the ratio meaningless. Lets ANVIL ground
        new patch generation in past fixes instead of generating from scratch
        every time.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.original_code, p.patched_code, p.explanation, p.status
            FROM patches p
            JOIN vulnerabilities v ON p.vuln_id = v.id
            WHERE v.vuln_type = ?
            ORDER BY p.generated_at DESC
            LIMIT 50
        ''', (vuln_type.value,))
        candidates = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not candidates:
            return []

        for c in candidates:
            c["similarity"] = (
                SequenceMatcher(None, code, c["original_code"] or "").ratio()
                if code else 0.0
            )

        candidates.sort(key=lambda c: (c["status"] == "verified", c["similarity"]), reverse=True)
        return candidates[:limit]

    def get_fix_strategies(self, vuln_type: VulnType) -> List[str]:
        """Get known fix strategies for a vulnerability type"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT fix_strategies FROM vulnerability_dna 
            WHERE vuln_type = ?
        ''', (vuln_type.value,))
        
        strategies = []
        for row in cursor.fetchall():
            strategies.extend(json.loads(row[0]))
        
        conn.close()
        return list(set(strategies))  # Deduplicate
    
    def get_statistics(self) -> Dict:
        """Get immune memory statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats["total_vulnerabilities"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerability_dna")
        stats["total_dna_patterns"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM patches")
        stats["total_patches"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM verifications")
        stats["total_verifications"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM immune_records")
        stats["total_immune_records"] = cursor.fetchone()[0]
        
        # Vulnerability type distribution
        cursor.execute('''
            SELECT vuln_type, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY vuln_type
        ''')
        stats["by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Severity distribution
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY severity
        ''')
        stats["by_severity"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        return stats
    
    def _find_similar(self, vulnerability: Vulnerability) -> Optional[str]:
        """Find similar vulnerability in memory"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for same type at same location
        cursor.execute('''
            SELECT id FROM vulnerabilities 
            WHERE vuln_type = ? 
            AND file_path = ? 
            AND line_start = ?
            LIMIT 1
        ''', (
            vulnerability.vuln_type.value,
            vulnerability.location.file_path,
            vulnerability.location.line_start
        ))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    
    def _generate_signature(self, vulnerability: Vulnerability) -> str:
        """Generate a pattern signature for a vulnerability"""
        # Create a hash based on vulnerability characteristics
        components = [
            vulnerability.vuln_type.value,
            vulnerability.location.file_path,
            vulnerability.location.code_snippet or "",
            vulnerability.cwe_id or ""
        ]
        
        signature = hashlib.sha256(
            "|".join(components).encode()
        ).hexdigest()
        
        return signature
