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
from typing import List, Dict, Optional, Tuple
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
                function_name TEXT,
                cwe_id TEXT,
                confidence REAL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1
            )
        ''')

        # DNA patterns table ("Weakness Capability Atoms": vuln type +
        # exploit preconditions + capability grant + links to atoms sharing
        # exploit context, not just an isolated detection/fix pair)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_dna (
                id TEXT PRIMARY KEY,
                vuln_type TEXT,
                pattern_signature TEXT,
                description TEXT,
                detection_rules TEXT,
                fix_strategies TEXT,
                regression_seeds TEXT,
                preconditions TEXT,
                capability_grant TEXT,
                related_dna_ids TEXT,
                created_at TIMESTAMP
            )
        ''')

        # Forward-compatible migration for databases created before the
        # columns above existed; SQLite has no "ADD COLUMN IF NOT EXISTS".
        for table, column, coltype in (
            ("vulnerabilities", "function_name", "TEXT"),
            ("vulnerability_dna", "preconditions", "TEXT"),
            ("vulnerability_dna", "capability_grant", "TEXT"),
            ("vulnerability_dna", "related_dna_ids", "TEXT"),
        ):
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            except sqlite3.OperationalError:
                pass  # column already present
        
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
                 line_start, function_name, cwe_id, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vulnerability.id,
                vulnerability.vuln_type.value,
                vulnerability.severity.value,
                vulnerability.title,
                vulnerability.description,
                vulnerability.location.file_path,
                vulnerability.location.line_start,
                vulnerability.location.function_name,
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
    
    # Exploit precondition(s) and post-compromise capability grant per vuln
    # type — the two halves of a "Weakness Capability Atom" beyond the bare
    # detection/fix pair the DNA record already carried.
    _CAPABILITY_PROFILES: Dict[VulnType, Tuple[List[str], str]] = {
        VulnType.SQL_INJECTION: (
            ["attacker-controlled input reaches a SQL execute() call without parameterization"],
            "arbitrary SQL query execution against the application's database"),
        VulnType.COMMAND_INJECTION: (
            ["attacker-controlled input reaches a shell-executing sink (system/popen/eval/exec) without sanitization"],
            "arbitrary command execution as the process's user"),
        VulnType.PATH_TRAVERSAL: (
            ["attacker-controlled input reaches a file-path-constructing sink without normalization or a base-directory check"],
            "read/write access to files outside the intended directory"),
        VulnType.XSS: (
            ["attacker-controlled input reaches an HTML-rendering sink without escaping"],
            "arbitrary script execution in a victim's browser session"),
        VulnType.SSRF: (
            ["attacker-controlled input reaches an outbound HTTP request's URL without an allowlist"],
            "the server can be made to issue requests to attacker-chosen (including internal) hosts"),
        VulnType.DESERIALIZATION: (
            ["attacker-controlled bytes reach an unsafe deserializer (pickle.loads/yaml.load)"],
            "arbitrary object construction, typically leading to code execution"),
        VulnType.BUFFER_OVERFLOW: (
            ["attacker-controlled input length exceeds a fixed-size buffer with no bounds check"],
            "memory corruption, potentially leading to code execution or a crash"),
        VulnType.USE_AFTER_FREE: (
            ["a pointer is dereferenced after the memory it points to has been freed, with no reassignment in between"],
            "memory corruption via a dangling pointer, potentially leading to code execution"),
        VulnType.INTEGER_OVERFLOW: (
            ["an arithmetic result exceeds the target integer type's range with no overflow check"],
            "an unexpected wrapped/truncated value used downstream, often as a size or index"),
        VulnType.FORMAT_STRING: (
            ["attacker-controlled input is used directly as a printf-family format string"],
            "information disclosure (stack reads) or memory corruption (stack writes via %n)"),
        VulnType.HARDCODED_CREDENTIALS: (
            ["a credential is embedded directly in source code rather than externalized"],
            "credential exposure to anyone with source access, including via version control history"),
        VulnType.WEAK_CRYPTO: (
            ["a non-cryptographic RNG or weak algorithm is used for a security-sensitive value"],
            "predictable tokens/keys, enabling forgery or brute-force"),
        VulnType.INFO_DISCLOSURE: (
            ["internal state (env vars, debug output) is exposed to an untrusted party"],
            "disclosure of internal configuration or secrets useful for further attack"),
        VulnType.OPEN_REDIRECT: (
            ["attacker-controlled input reaches a redirect target without an allowlist"],
            "victims can be redirected to an attacker-controlled site, aiding phishing"),
        VulnType.MEMORY_LEAK: (
            ["allocated memory has no reachable free() on at least one code path"],
            "resource exhaustion under repeated or attacker-triggerable execution"),
        VulnType.RACE_CONDITION: (
            ["a shared variable is read-modified-written without synchronization across concurrent execution"],
            "inconsistent or corrupted shared state under concurrent access"),
        VulnType.NULL_POINTER_DEREFERENCE: (
            ["a pointer that may remain NULL on some path is dereferenced without a NULL check"],
            "a crash (denial of service) at the dereference point"),
    }

    def _find_related_dna(self, vulnerability: Vulnerability) -> List[str]:
        """Find DNA atoms for other vulnerabilities sharing this one's
        exploit context (same function, or same file when no function is
        known) — the composition step that lets memory recognize when
        different vulnerability classes co-occur (e.g. a memory leak and a
        null-pointer deref in the same function) instead of only ever
        looking things up by their own CWE."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if vulnerability.location.function_name:
            cursor.execute('''
                SELECT DISTINCT ir.dna_id
                FROM immune_records ir
                JOIN vulnerabilities v ON ir.vuln_id = v.id
                WHERE v.file_path = ? AND v.function_name = ? AND v.id != ?
                      AND ir.dna_id IS NOT NULL
            ''', (vulnerability.location.file_path, vulnerability.location.function_name, vulnerability.id))
        else:
            cursor.execute('''
                SELECT DISTINCT ir.dna_id
                FROM immune_records ir
                JOIN vulnerabilities v ON ir.vuln_id = v.id
                WHERE v.file_path = ? AND v.function_name IS NULL AND v.id != ?
                      AND ir.dna_id IS NOT NULL
            ''', (vulnerability.location.file_path, vulnerability.id))

        related = [row["dna_id"] for row in cursor.fetchall()]
        conn.close()
        return related

    def create_dna(self, vulnerability: Vulnerability,
                   fix_strategy: str) -> VulnerabilityDNA:
        """
        Create vulnerability DNA - a Weakness Capability Atom binding this
        vuln type's exploit precondition(s), what an attacker gains from it,
        and which other atoms share its exploit context.
        """
        signature = self._generate_signature(vulnerability)
        preconditions, capability_grant = self._CAPABILITY_PROFILES.get(
            vulnerability.vuln_type, (["unspecified"], "unspecified")
        )
        related_dna_ids = self._find_related_dna(vulnerability)

        dna = VulnerabilityDNA(
            id=f"dna-{hashlib.sha256(signature.encode()).hexdigest()[:12]}",
            vuln_type=vulnerability.vuln_type,
            pattern_signature=signature,
            description=f"Pattern for {vulnerability.vuln_type.value} vulnerabilities",
            detection_rules=[vulnerability.raw_analysis or ""],
            fix_strategies=[fix_strategy],
            regression_seeds=[],
            preconditions=preconditions,
            capability_grant=capability_grant,
            related_dna_ids=related_dna_ids
        )

        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO vulnerability_dna
            (id, vuln_type, pattern_signature, description,
             detection_rules, fix_strategies, regression_seeds,
             preconditions, capability_grant, related_dna_ids, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            dna.id,
            dna.vuln_type.value,
            dna.pattern_signature,
            dna.description,
            json.dumps(dna.detection_rules),
            json.dumps(dna.fix_strategies),
            json.dumps(dna.regression_seeds),
            json.dumps(dna.preconditions),
            dna.capability_grant,
            json.dumps(dna.related_dna_ids),
            datetime.now(timezone.utc).isoformat()
        ))

        conn.commit()
        conn.close()

        return dna

    def get_dna(self, dna_id: str) -> Optional[Dict]:
        """Fetch a single DNA atom by id with its JSON fields parsed, so
        `related_dna_ids` on one atom can be resolved into the actual related
        atoms (vuln type, capability grant, etc.) rather than staying opaque ids."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vulnerability_dna WHERE id = ?', (dna_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None
        record = dict(row)
        for field in ("detection_rules", "fix_strategies", "regression_seeds",
                      "preconditions", "related_dna_ids"):
            record[field] = json.loads(record[field]) if record.get(field) else []
        return record
    
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

    def has_verified_patch(self, vuln_id: str) -> bool:
        """Whether any patch generated for this exact vulnerability id has
        ever passed full verification. Used by the Watch engine to tell a
        genuine regression (a previously-fixed vulnerability reappearing,
        e.g. via a revert) apart from one that was simply never patched."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 1 FROM patches p
            JOIN verifications v ON v.patch_id = p.id
            WHERE p.vuln_id = ? AND v.compile_success AND v.exploit_blocked
                  AND v.regression_pass AND v.behavior_preserved
            LIMIT 1
        ''', (vuln_id,))
        found = cursor.fetchone() is not None
        conn.close()
        return found

    def get_rule_reliability(self, min_samples: int = 1) -> Dict[str, Dict]:
        """
        Aggregate verified-patch outcomes per detection rule (vulnerabilities
        .title, the closest stored identifier to a REWIND Pattern.name),
        giving each rule an empirical verified rate: of everything it
        flagged, what fraction led to a patch that passed the full
        verification pipeline.

        This is the feedback half of a closed detect -> patch -> verify ->
        learn loop: a rule's static confidence is a guess made before any
        patch exists; this reflects what actually held up afterward. It's a
        proxy, not a ground-truth precision measurement — a low rate can
        mean the rule over-fires, or that ANVIL/the Verifier struggle with
        that vuln class, not necessarily that the rule itself is wrong.
        Callers should blend it with the rule's static confidence rather
        than replace it outright.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT v.title AS title,
                   COUNT(DISTINCT p.id) AS total_patches,
                   SUM(CASE WHEN ver.compile_success AND ver.exploit_blocked
                            AND ver.regression_pass AND ver.behavior_preserved
                       THEN 1 ELSE 0 END) AS verified_patches
            FROM vulnerabilities v
            JOIN patches p ON p.vuln_id = v.id
            JOIN verifications ver ON ver.patch_id = p.id
            GROUP BY v.title
        ''')

        reliability = {}
        for row in cursor.fetchall():
            total = row["total_patches"]
            if total < min_samples:
                continue
            verified = row["verified_patches"] or 0
            reliability[row["title"]] = {
                "total_patches": total,
                "verified_patches": verified,
                "verified_rate": verified / total,
            }

        conn.close()
        return reliability

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
