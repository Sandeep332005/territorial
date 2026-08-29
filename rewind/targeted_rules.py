"""
ABHIMANYU X CORE - Targeted Framework Rules
Pre-built vulnerability patterns for specific frameworks/libraries.

Each rule includes:
- Pattern to detect the vulnerability
- Template-based fix (no LLM needed for common cases)
- Confidence threshold (skip LLM if above threshold)
"""

from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field

from abhimanyux.models.schemas import (
    Vulnerability, VulnerabilityLocation, Severity, VulnType, AnalysisPhase
)


@dataclass
class TargetedRule:
    """A framework-specific vulnerability rule with a template fix."""
    name: str
    vuln_type: VulnType
    severity: Severity
    pattern: str
    description: str
    cwe_id: str
    framework: str  # 'python', 'flask', 'django', 'fastapi', 'express', 'node', 'c', 'general'
    fix_template: str  # Template-based fix (no LLM needed)
    fix_description: str  # Human-readable fix description
    confidence: float = 0.9
    needs_llm: bool = False  # If True, LLM is needed for the fix


# ─── Flask / FastAPI Rules ───────────────────────────────────────────────────

FLASK_RULES = [
    TargetedRule(
        name="Flask: SQL Injection in query",
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(execute|cursor\.execute)\s*\(\s*[f"\'].*\{.*\}',
        description="SQL query built with f-string in Flask route handler",
        cwe_id="CWE-89",
        framework="flask",
        fix_template="""# BEFORE (vulnerable):
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# AFTER (fixed):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))""",
        fix_description="Use parameterized queries with %s placeholders",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Flask: XSS via render_template_string",
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        pattern=r'render_template_string\s*\(',
        description="Potential XSS via render_template_string with user input",
        cwe_id="CWE-79",
        framework="flask",
        fix_template="""# BEFORE (vulnerable):
return render_template_string(f"<h1>Hello {username}</h1>")

# AFTER (fixed):
from markupsafe import escape
return render_template_string("<h1>Hello {{ username }}</h1>", username=escape(username))""",
        fix_description="Use Jinja2 autoescaping and markupsafe.escape for user input",
        confidence=0.85,
        needs_llm=False,
    ),
    TargetedRule(
        name="Flask: Open redirect",
        vuln_type=VulnType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        pattern=r'redirect\s*\(\s*request\.(args|form)\.get',
        description="Open redirect using user-controlled URL",
        cwe_id="CWE-601",
        framework="flask",
        fix_template="""# BEFORE (vulnerable):
return redirect(request.args.get('next'))

# AFTER (fixed):
from urllib.parse import urlparse
next_url = request.args.get('next', '/')
parsed = urlparse(next_url)
if parsed.netloc and parsed.netloc != request.host:
    next_url = '/'
return redirect(next_url)""",
        fix_description="Validate redirect URL against whitelist; block external redirects",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="Flask: Debug mode enabled",
        vuln_type=VulnType.INFO_DISCLOSURE,
        severity=Severity.MEDIUM,
        pattern=r'app\.run\s*\(.*debug\s*=\s*True',
        description="Flask debug mode exposes stack traces and debugger",
        cwe_id="CWE-215",
        framework="flask",
        fix_template="""# BEFORE (vulnerable):
app.run(debug=True)

# AFTER (fixed):
app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')""",
        fix_description="Read debug flag from environment variable, not hardcoded",
        confidence=0.8,
        needs_llm=False,
    ),
    TargetedRule(
        name="Flask: Insecure session config",
        vuln_type=VulnType.HARDCODED_CREDENTIALS,
        severity=Severity.MEDIUM,
        pattern=r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
        description="Hardcoded Flask SECRET_KEY",
        cwe_id="CWE-798",
        framework="flask",
        fix_template="""# BEFORE (vulnerable):
app.config['SECRET_KEY'] = 'mysecretkey123'

# AFTER (fixed):
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex()""",
        fix_description="Load SECRET_KEY from environment variable or generate random key",
        confidence=0.85,
        needs_llm=False,
    ),
]

# ─── Django Rules ────────────────────────────────────────────────────────────

DJANGO_RULES = [
    TargetedRule(
        name="Django: Raw SQL query",
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(raw|extra)\s*\(\s*[f"\'].*\{',
        description="Django raw() or extra() with f-string interpolation",
        cwe_id="CWE-89",
        framework="django",
        fix_template="""# BEFORE (vulnerable):
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# AFTER (fixed):
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])""",
        fix_description="Use parameterized queries with Django ORM or raw() params",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Django: mark_safe with user input",
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        pattern=r'mark_safe\s*\(.*\+',
        description="Django mark_safe() with concatenated user input",
        cwe_id="CWE-79",
        framework="django",
        fix_template="""# BEFORE (vulnerable):
from django.utils.safestring import mark_safe
return mark_safe(f"<p>{user_input}</p>")

# AFTER (fixed):
from django.utils.html import escape
return mark_safe(f"<p>{escape(user_input)}</p>")""",
        fix_description="Escape user input before mark_safe(), or use template autoescaping",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="Django: Shell command execution",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
        description="Django view calling subprocess with shell=True",
        cwe_id="CWE-78",
        framework="django",
        fix_template="""# BEFORE (vulnerable):
subprocess.Popen(cmd, shell=True)

# AFTER (fixed):
subprocess.Popen(cmd, shell=False)""",
        fix_description="Use shell=False with list arguments",
        confidence=0.9,
        needs_llm=False,
    ),
]

# ─── FastAPI Rules ───────────────────────────────────────────────────────────

FASTAPI_RULES = [
    TargetedRule(
        name="FastAPI: SQL Injection in query",
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(execute|execute_query)\s*\(\s*[f"\'].*\{.*\}',
        description="SQL query built with f-string in FastAPI endpoint",
        cwe_id="CWE-89",
        framework="fastapi",
        fix_template="""# BEFORE (vulnerable):
await database.execute(f"SELECT * FROM users WHERE id = {user_id}")

# AFTER (fixed):
await database.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})""",
        fix_description="Use parameterized queries with named placeholders",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="FastAPI: CORS wildcard",
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        pattern=r'allow_origins\s*=\s*\["?\*"?]',
        description="FastAPI CORS allows all origins",
        cwe_id="CWE-942",
        framework="fastapi",
        fix_template="""# BEFORE (vulnerable):
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# AFTER (fixed):
app.add_middleware(CORSMiddleware, allow_origins=["https://yourdomain.com"])""",
        fix_description="Restrict CORS to specific trusted origins",
        confidence=0.85,
        needs_llm=False,
    ),
    TargetedRule(
        name="FastAPI: Dependency injection leak",
        vuln_type=VulnType.INFO_DISCLOSURE,
        severity=Severity.MEDIUM,
        pattern=r'@app\.(get|post)\s*\(.*\)\s*\nasync\s+def\s+\w+\s*\([^)]*password',
        description="FastAPI endpoint receives password as query parameter (logged in URL)",
        cwe_id="CWE-200",
        framework="fastapi",
        fix_template="""# BEFORE (vulnerable):
@app.post("/login")
async def login(username: str, password: str): ...

# AFTER (fixed):
from pydantic import BaseModel
class LoginRequest(BaseModel):
    username: str
    password: str  # In request body, not query params

@app.post("/login")
async def login(req: LoginRequest): ...""",
        fix_description="Use Pydantic models in request body instead of query parameters for secrets",
        confidence=0.8,
        needs_llm=True,  # Complex refactor
    ),
]

# ─── Node.js / Express Rules ────────────────────────────────────────────────

EXPRESS_RULES = [
    TargetedRule(
        name="Express: SQL Injection in query",
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'query\s*\(\s*`[^`]*\$\{',
        description="SQL query built with template literal in Express",
        cwe_id="CWE-89",
        framework="express",
        fix_template="""// BEFORE (vulnerable):
db.query(`SELECT * FROM users WHERE id = ${userId}`)

// AFTER (fixed):
db.query("SELECT * FROM users WHERE id = ?", [userId])""",
        fix_description="Use parameterized queries with ? placeholders",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Express: Command injection via exec",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'(exec|execSync|spawn)\s*\([^)]*\+',
        description="Shell command built with string concatenation in Express",
        cwe_id="CWE-78",
        framework="express",
        fix_template="""// BEFORE (vulnerable):
exec('ls ' + userInput)

// AFTER (fixed):
const { execFile } = require('child_process');
execFile('ls', [userInput], (err, stdout) => { ... });""",
        fix_description="Use execFile with array arguments instead of exec with concatenation",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="Express: XSS via res.send",
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        pattern=r'res\.send\s*\(\s*`[^`]*\$\{',
        description="Direct HTML response with template literal (potential XSS)",
        cwe_id="CWE-79",
        framework="express",
        fix_template="""// BEFORE (vulnerable):
res.send(`<h1>Hello ${username}</h1>`)

// AFTER (fixed):
const escapeHtml = require('escape-html');
res.send(`<h1>Hello ${escapeHtml(username)}</h1>`)""",
        fix_description="Escape user input before inserting into HTML response",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="Express: Path traversal in file serving",
        vuln_type=VulnType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        pattern=r'sendFile\s*\([^)]*\+',
        description="Path traversal via sendFile with concatenated path",
        cwe_id="CWE-22",
        framework="express",
        fix_template="""// BEFORE (vulnerable):
res.sendFile(__dirname + '/files/' + req.params.filename)

// AFTER (fixed):
const path = require('path');
const safePath = path.join(__dirname, 'files', path.basename(req.params.filename));
res.sendFile(safePath);""",
        fix_description="Use path.basename() to strip directory traversal sequences",
        confidence=0.9,
        needs_llm=False,
    ),
]

# ─── General Python Rules ────────────────────────────────────────────────────

GENERAL_PYTHON_RULES = [
    TargetedRule(
        name="Python: os.system() command injection",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'os\.system\s*\(',
        description="os.system() executes shell commands with potential injection",
        cwe_id="CWE-78",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
os.system(f"ping {host}")

# AFTER (fixed):
import subprocess
subprocess.run(["ping", host], capture_output=True, check=True)""",
        fix_description="Use subprocess.run() with list arguments (no shell=True)",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: os.popen() command injection",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'os\.popen\s*\(',
        description="os.popen() executes shell commands with potential injection",
        cwe_id="CWE-78",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
output = os.popen(f"cat {filename}").read()

# AFTER (fixed):
import subprocess
result = subprocess.run(["cat", filename], capture_output=True, text=True)
output = result.stdout""",
        fix_description="Use subprocess.run() with list arguments",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: eval() code injection",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'\beval\s*\(',
        description="eval() can execute arbitrary Python code",
        cwe_id="CWE-95",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
result = eval(user_input)

# AFTER (fixed):
import ast
result = ast.literal_eval(user_input)  # Only evaluates literals""",
        fix_description="Use ast.literal_eval() for safe evaluation of literals",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: Pickle deserialization",
        vuln_type=VulnType.DESERIALIZATION,
        severity=Severity.CRITICAL,
        pattern=r'pickle\.loads?\s*\(',
        description="Pickle deserialization can execute arbitrary code on load",
        cwe_id="CWE-502",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
data = pickle.loads(untrusted_bytes)

# AFTER (fixed):
import json
data = json.loads(untrusted_bytes.decode('utf-8'))""",
        fix_description="Use json.loads() instead of pickle for data exchange",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: YAML unsafe load",
        vuln_type=VulnType.DESERIALIZATION,
        severity=Severity.HIGH,
        pattern=r'yaml\.load\s*\((?!.*Loader)',
        description="yaml.load() without safe Loader can execute arbitrary code",
        cwe_id="CWE-502",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
config = yaml.load(data)

# AFTER (fixed):
config = yaml.safe_load(data)""",
        fix_description="Use yaml.safe_load() to prevent code execution",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: Hardcoded API key",
        vuln_type=VulnType.HARDCODED_CREDENTIALS,
        severity=Severity.MEDIUM,
        pattern=r'(api_key|apikey|API_KEY|secret_key|SECRET_KEY)\s*=\s*["\'][^"\']{8,}["\']',
        description="Hardcoded secret in source code",
        cwe_id="CWE-798",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
API_KEY = "sk-abc123def456"

# AFTER (fixed):
import os
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")""",
        fix_description="Load secrets from environment variables",
        confidence=0.85,
        needs_llm=False,
    ),
    TargetedRule(
        name="Python: Weak random for security",
        vuln_type=VulnType.WEAK_CRYPTO,
        severity=Severity.MEDIUM,
        pattern=r'random\.(randint|choice|random|randrange)\s*\(',
        description="Using non-cryptographic random for security-sensitive values",
        cwe_id="CWE-330",
        framework="python",
        fix_template="""# BEFORE (vulnerable):
token = random.randint(0, 999999)

# AFTER (fixed):
import secrets
token = secrets.token_hex(32)""",
        fix_description="Use secrets module for cryptographic randomness",
        confidence=0.7,
        needs_llm=False,
    ),
]

# ─── General C Rules ─────────────────────────────────────────────────────────

GENERAL_C_RULES = [
    TargetedRule(
        name="C: Buffer overflow - strcpy",
        vuln_type=VulnType.BUFFER_OVERFLOW,
        severity=Severity.CRITICAL,
        pattern=r'\bstrcpy\s*\(',
        description="strcpy() has no bounds checking",
        cwe_id="CWE-120",
        framework="c",
        fix_template="""// BEFORE (vulnerable):
strcpy(dest, src);

// AFTER (fixed):
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';""",
        fix_description="Use strncpy() with explicit size limit",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="C: Buffer overflow - gets",
        vuln_type=VulnType.BUFFER_OVERFLOW,
        severity=Severity.CRITICAL,
        pattern=r'\bgets\s*\(',
        description="gets() cannot limit input length — inherently unsafe",
        cwe_id="CWE-242",
        framework="c",
        fix_template="""// BEFORE (vulnerable):
gets(buffer);

// AFTER (fixed):
fgets(buffer, sizeof(buffer), stdin);""",
        fix_description="Use fgets() with explicit buffer size",
        confidence=0.95,
        needs_llm=False,
    ),
    TargetedRule(
        name="C: Format string vulnerability",
        vuln_type=VulnType.FORMAT_STRING,
        severity=Severity.CRITICAL,
        pattern=r'\b(?:printf|fprintf)\s*\(\s*[a-zA-Z_]\w*\s*\)',
        description="printf() called with variable format string",
        cwe_id="CWE-134",
        framework="c",
        fix_template="""// BEFORE (vulnerable):
printf(user_input);

// AFTER (fixed):
printf("%s", user_input);""",
        fix_description="Always use a literal format string with %s for user input",
        confidence=0.9,
        needs_llm=False,
    ),
    TargetedRule(
        name="C: Command injection via system()",
        vuln_type=VulnType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        pattern=r'\bsystem\s*\(',
        description="system() executes shell commands",
        cwe_id="CWE-78",
        framework="c",
        fix_template="""// BEFORE (vulnerable):
system(cmd);

// AFTER (fixed):
// Use execve() or posix_spawn() with explicit argument array
const char *argv[] = {"sh", "-c", cmd, NULL};
execve("/bin/sh", (char *const *)argv, NULL);""",
        fix_description="Use execve() with explicit argument array instead of system()",
        confidence=0.9,
        needs_llm=True,  # Complex refactor
    ),
]


# ─── Registry ────────────────────────────────────────────────────────────────

FRAMEWORK_RULES: Dict[str, List[TargetedRule]] = {
    "flask": FLASK_RULES,
    "django": DJANGO_RULES,
    "fastapi": FASTAPI_RULES,
    "express": EXPRESS_RULES,
    "python": GENERAL_PYTHON_RULES,
    "c": GENERAL_C_RULES,
}


def get_rules_for_framework(framework: str) -> List[TargetedRule]:
    """Get all rules for a specific framework."""
    return FRAMEWORK_RULES.get(framework, [])


def get_rules_for_file(filename: str) -> List[TargetedRule]:
    """Auto-detect framework from filename and return applicable rules."""
    rules = []

    # Always include general rules
    if filename.endswith('.py'):
        rules.extend(GENERAL_PYTHON_RULES)
    elif filename.endswith(('.c', '.h', '.cpp', '.cc')):
        rules.extend(GENERAL_C_RULES)

    # Detect framework from filename/path
    filename_lower = filename.lower()
    if 'flask' in filename_lower or 'app.py' in filename_lower:
        rules.extend(FLASK_RULES)
    if 'django' in filename_lower or 'views.py' in filename_lower:
        rules.extend(DJANGO_RULES)
    if 'fastapi' in filename_lower:
        rules.extend(FASTAPI_RULES)
    if 'express' in filename_lower or 'app.js' in filename_lower or 'server.js' in filename_lower:
        rules.extend(EXPRESS_RULES)

    return rules


def scan_targeted(code: str, filename: str, framework: Optional[str] = None) -> List[Vulnerability]:
    """
    Scan code using targeted framework rules.
    Returns vulnerabilities with template-based fixes (no LLM needed).

    Args:
        code: Source code to scan
        filename: File name for context
        framework: Specific framework to target (or None for auto-detect)

    Returns:
        List of vulnerabilities with attached fix templates
    """
    import re
    import hashlib

    if framework:
        rules = get_rules_for_framework(framework)
    else:
        rules = get_rules_for_file(filename)

    vulns = []
    lines = code.split('\n')

    for rule in rules:
        for line_num, line in enumerate(lines, 1):
            if re.search(rule.pattern, line, re.IGNORECASE):
                vuln = Vulnerability(
                    id=hashlib.sha256(
                        f"targeted:{filename}:{line_num}:{rule.name}".encode()
                    ).hexdigest()[:16],
                    vuln_type=rule.vuln_type,
                    severity=rule.severity,
                    title=rule.name,
                    description=rule.description,
                    location=VulnerabilityLocation(
                        file_path=filename,
                        line_start=line_num,
                        code_snippet=line.strip()
                    ),
                    cwe_id=rule.cwe_id,
                    confidence=rule.confidence,
                    source=AnalysisPhase.STATIC,
                    raw_analysis=(
                        f"Framework: {rule.framework}\n"
                        f"Fix: {rule.fix_description}\n"
                        f"Template:\n{rule.fix_template}\n"
                        f"Needs LLM: {rule.needs_llm}"
                    )
                )
                vulns.append(vuln)

    # Deduplicate
    seen = set()
    unique = []
    for v in vulns:
        key = (v.vuln_type, v.location.line_start, v.location.file_path)
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return unique
