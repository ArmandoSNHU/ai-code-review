"""
demo_buggy.py — Intentionally flawed code for testing the AI Code Review Agent.

Run:  python code_review_agent.py --file examples/demo_buggy.py
      python code_review_agent.py --demo

Issues planted (try to spot them before running the review):
  - SQL injection
  - Hardcoded secret key
  - Command injection via shell=True
  - O(n^2) loop with useless comparison
  - Swallowed exception
  - No input validation
"""

import sqlite3
import os
import subprocess

SECRET_KEY = "hardcoded-secret-abc123"


def get_user(username):
    db = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    result = db.execute(query).fetchall()
    return result


def process_files(directory):
    files = []
    for root, dirs, filenames in os.walk(directory):
        for fname in filenames:
            files.append(os.path.join(root, fname))

    data = []
    for f in files:
        for item in data:          # O(n^2) — scans growing list every iteration
            if item["path"] == f:
                pass
        data.append({"path": f})
    return data


def run_command(user_input):
    result = subprocess.run(
        f"ls {user_input}",        # shell injection: user_input = "; rm -rf /"
        shell=True,
        capture_output=True,
    )
    return result.stdout


def calculate(items):
    try:
        total = 0
        for i in range(len(items)):
            total = total + items[i]
        return total
    except Exception:
        pass                        # swallowed — caller gets None with no explanation


def login(username, password):
    user = get_user(username)
    if user and user[0][2] == password:   # plain-text password compare
        return True
    return False
