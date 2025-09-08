# vuln_app.py
# Intentionally vulnerable Python code for CodeQL testing

import os
import subprocess
import pickle
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

# 1. Command Injection (CWE-77)
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    # ⚠️ Vulnerable: unsanitized user input in os.system
    os.system("ping -c 1  " + ip)
    return "Pinging " + ip

# 2. SQL Injection (CWE-89)
import sqlite3
@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    # ⚠️ Vulnerable: string concatenation in SQL query
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cur.fetchall())

# 3. Path Traversal (CWE-22)
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    # ⚠️ Vulnerable: allows ../../etc/passwd
    with open("uploads/" + filename, "r") as f:
        return f.read()

# 4. Insecure Deserialization (CWE-502)
@app.route("/load")
def load_pickle():
    data = request.args.get("data")
    # ⚠️ Vulnerable: pickle.loads on untrusted input
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)

# 5. Hardcoded Credentials (CWE-798)
API_KEY = "12345-SECRET-HARDCODED"  # ⚠️ Vulnerable: secret in source code

# 6. Weak Hashing (CWE-327)
def hash_password(pwd):
    # ⚠️ Vulnerable: MD5 is weak
    return hashlib.md5(pwd.encode()).hexdigest()

# 7. Insecure Randomness (CWE-338)
import random
def generate_token():
    # ⚠️ Vulnerable: predictable random
    return str(random.randint(1000, 9999))

# 8. SSRF - Server-Side Request Forgery (CWE-918)
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ⚠️ Vulnerable: user controls target URL
    r = requests.get(url)
    return r.text

# 9. XSS - Cross Site Scripting (CWE-79)
@app.route("/greet")
def greet():
    name = request.args.get("name")
    # ⚠️ Vulnerable: directly rendered user input
    return f"<h1>Hello {name}</h1>"

# 10. Open Redirect (CWE-601)
from flask import redirect
@app.route("/redirect")
def redir():
    target = request.args.get("url")
    # ⚠️ Vulnerable: open redirect
    return redirect(target)

# 11. Use of eval (CWE-94)
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # ⚠️ Vulnerable: remote code execution
    return str(eval(expr))

# 12. Missing Authentication (CWE-306)
@app.route("/admin")
def admin():
    # ⚠️ Vulnerable: no authentication check
    return "Welcome admin! Dangerous function exposed."
