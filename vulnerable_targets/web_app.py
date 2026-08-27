"""
Vulnerable Web Application - Test Target for ABHIMANYU X
Contains multiple intentional security vulnerabilities
"""

import os
import sqlite3
import pickle
import subprocess
import yaml
import random
import sys
from flask import Flask, request, jsonify

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user')")
    conn.commit()
    conn.close()

init_db()

# VULNERABILITY 1: SQL Injection (Critical)
@app.route('/api/login', methods=['POST'])
def login():
    """SQL Injection vulnerable login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL Injection via string formatting
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"status": "success", "user_id": user[0]})
    return jsonify({"status": "failed"}), 401


# VULNERABILITY 2: Command Injection (Critical)
@app.route('/api/ping', methods=['GET'])
def ping():
    """Command Injection vulnerable ping"""
    host = request.args.get('host', '127.0.0.1')
    
    # CRITICAL: Command Injection via os.popen
    result = os.popen(f"ping -c 1 {host}").read()
    
    return jsonify({"output": result})


# VULNERABILITY 3: Insecure Deserialization (Critical)
@app.route('/api/import', methods=['POST'])
def import_data():
    """Insecure Deserialization via pickle"""
    data = request.get_data()
    
    # CRITICAL: Pickle deserialization
    obj = pickle.loads(data)
    
    return jsonify({"imported": str(obj)})


# VULNERABILITY 4: Path Traversal (High)
@app.route('/api/read', methods=['GET'])
def read_file():
    """Path Traversal vulnerable file reader"""
    filename = request.args.get('file', 'readme.txt')
    directory = request.args.get('dir', '/data')
    
    # HIGH: Path Traversal
    filepath = f"{directory}/{filename}"
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# VULNERABILITY 5: Unsafe YAML Loading (High)
@app.route('/api/config', methods=['POST'])
def load_config():
    """Unsafe YAML deserialization"""
    config_data = request.get_data().decode()
    
    # HIGH: Unsafe yaml.load
    config = yaml.load(config_data)
    
    return jsonify({"config": config})


# VULNERABILITY 6: Command Injection via subprocess (Critical)
@app.route('/api/execute', methods=['POST'])
def execute_command():
    """Command Injection via subprocess with shell=True"""
    command = request.form.get('command', 'echo hello')
    
    # CRITICAL: subprocess with shell=True
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })


# VULNERABILITY 7: Hardcoded Credentials (Medium)
API_SECRET_KEY = "sk-proj-1234567890abcdef"
DATABASE_URL = "postgresql://admin:password123@localhost:5432/mydb"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# VULNERABILITY 8: Weak Random Number Generation (Low)
@app.route('/api/token', methods=['GET'])
def generate_token():
    """Weak token generation"""
    # LOW: Using random instead of secrets
    token = str(random.randint(1000000000, 9999999999))
    session_id = ''.join([chr(random.randint(65, 90)) for _ in range(32)])
    
    return jsonify({
        "token": token,
        "session_id": session_id
    })


# VULNERABILITY 9: Information Disclosure (Medium)
@app.route('/api/debug', methods=['GET'])
def debug_endpoint():
    """Information Disclosure"""
    # MEDIUM: Exposing environment and system info
    return jsonify({
        "python_version": sys.version,
        "environment": dict(os.environ),
        "path": sys.path,
        "platform": sys.platform
    })


# VULNERABILITY 10: SSRF (High)
@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    """Server-Side Request Forgery"""
    import requests
    
    url = request.args.get('url')
    
    # HIGH: SSRF - no URL validation
    resp = requests.get(url)
    
    return jsonify({"content": resp.text[:1000]})


# VULNERABILITY 11: Open Redirect (Medium)
@app.route('/api/redirect', methods=['GET'])
def redirect_user():
    """Open Redirect vulnerability"""
    url = request.args.get('url', '/')
    
    # MEDIUM: Unvalidated redirect
    return f'''<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url={url}">
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>'''


# VULNERABILITY 12: SQL Injection via concatenation (Critical)
@app.route('/api/search', methods=['GET'])
def search_users():
    """SQL Injection via concatenation"""
    search_term = request.args.get('q', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL Injection via concatenation
    query = "SELECT * FROM users WHERE username LIKE '%" + search_term + "%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    
    return jsonify({"results": results})


# VULNERABILITY 13: Eval injection (Critical)
@app.route('/api/calculate', methods=['POST'])
def calculate():
    """Eval injection vulnerability"""
    expression = request.form.get('expr', '1+1')
    
    # CRITICAL: eval() injection
    result = eval(expression)
    
    return jsonify({"result": result})


# VULNERABILITY 14: XSS via render_template_string (High)
@app.route('/api/greet', methods=['GET'])
def greet():
    """XSS vulnerability"""
    from flask import render_template_string
    
    name = request.args.get('name', 'World')
    
    # HIGH: XSS via render_template_string
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# VULNERABILITY 15: Insecure temp file (Medium)
@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Insecure temp file handling"""
    import tempfile
    
    data = request.get_data()
    
    # MEDIUM: Predictable temp filename
    temp_path = f"/tmp/upload_{os.getpid()}.dat"
    
    with open(temp_path, 'wb') as f:
        f.write(data)
    
    return jsonify({"saved": temp_path})


if __name__ == '__main__':
    # VULNERABILITY 16: Debug mode enabled (Low)
    app.run(debug=True, host='0.0.0.0', port=5000)
