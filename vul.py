import os
import sqlite3
import subprocess
from flask import Flask, request, make_response

app = Flask(__name__)


# 1. Hardcoded credentials (CWE-798)
DB_USER = "admin"
DB_PASS = "password123"

# 1. Command Injection (CWE-77)
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    # ⚠️ Vulnerable: unsanitized user input in os.system
    os.system("ping -c 1  " + ip)
    return "Pinging " + ip


# 2. Weak cryptography (CWE-327)
import hashlib
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# 3. SQL Injection (CWE-89)
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # vulnerable
    cursor.execute(query)
    return cursor.fetchall()

# 4. Command Injection (CWE-78)
def run_ping(ip):
    return os.system("ping -c 1 " + ip)  # no sanitization

# 5. Path Traversal (CWE-22)
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:  # attacker can read /etc/passwd
        return f.read()

# 6. XSS (CWE-79)
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"  # unsanitized HTML output

# 7. Insecure Deserialization (CWE-502)
import pickle
@app.route("/load")
def load_data():
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))  # unsafe
    return str(obj)

# 8. Insecure Randomness (CWE-330)
import random
def reset_token():
    return str(random.randint(1000, 9999))  # predictable token

# 9. Information Exposure (CWE-200)
@app.route("/debug")
def debug():
    return str(request.__dict__)  # leaks internal server info

# 10. Lack of Authentication (CWE-306)
@app.route("/admin")
def admin_panel():
    return "Sensitive admin data!"  # no authentication check

# 11. Unrestricted File Upload (CWE-434)
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file.save(f"./uploads/{file.filename}")  # attacker can upload .py and execute
    return "Uploaded!"

# 12. Use of eval() on user input (CWE-94)
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))  # attacker can run system commands
