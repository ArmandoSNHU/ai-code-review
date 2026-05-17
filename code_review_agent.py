#!/usr/bin/env python3
"""
Code Review Agent — Multi-specialist AI code review pipeline.

Runs 4 specialized reviewers in parallel, aggregates into a severity-graded
Markdown report. Each reviewer focuses on one domain:

  SecurityReviewer    — OWASP Top 10, injection, secrets, auth flaws
  BugReviewer         — Logic errors, null refs, edge cases, race conditions
  PerformanceReviewer — Complexity, N+1 queries, memory leaks, blocking I/O
  QualityReviewer     — Naming, dead code, complexity, documentation gaps

Aggregator (The Weaver / qwen3:8b) synthesizes findings into final report.

Usage:
  python code_review_agent.py --file app.py
  python code_review_agent.py --file app.py --lang python
  git diff HEAD~1 | python code_review_agent.py --stdin
  python code_review_agent.py --demo

Bridge API:
  POST /code-review/new    {"code": "...", "lang": "python", "source": "filename.py"}
  GET  /code-review/status/<id>
  GET  /code-review/list

Output: /app/content/code-reviews/<id>/report.md
"""

import argparse
import datetime
import json
import os
import sys
import threading
import time
import uuid
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

OLLAMA_HOST  = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OUTPUT_DIR   = Path(os.environ.get("CODE_REVIEW_DIR", "/app/content/code-reviews"))
MAX_CODE_LEN = 8000   # chars — truncate to avoid blowing context

MODELS = {
    "security":    os.environ.get("SECURITY_MODEL",    "whiterabbitneo"),
    "bugs":        os.environ.get("WEAVER_MODEL",      "qwen3:8b"),
    "performance": os.environ.get("REASONING_MODEL",   "mistral:latest"),
    "quality":     os.environ.get("FAST_MODEL",        "llama3.2:1b"),
    "aggregator":  os.environ.get("WEAVER_MODEL",      "qwen3:8b"),
}

# ── Review session store ───────────────────────────────────────────────────────

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()

# ── Reviewer system prompts ────────────────────────────────────────────────────

REVIEWER_PROMPTS = {
    "security": """\
You are an expert security code reviewer specializing in OWASP Top 10 vulnerabilities.
Analyze the provided code for:
- Injection vulnerabilities (SQL, command, LDAP, XPath)
- Broken authentication / session management
- Sensitive data exposure (hardcoded secrets, keys, PII in logs)
- Insecure direct object references
- Cross-site scripting (XSS) / CSRF
- Security misconfiguration
- Insecure deserialization
- Missing input validation / sanitization
- Privilege escalation risks
- Dependency vulnerabilities

For each finding output EXACTLY this JSON format (array):
[{"severity":"critical|high|medium|low","title":"Short title","line":"line number or 'N/A'","description":"What the issue is and why it's dangerous","fix":"Specific code fix or mitigation"}]

If no issues found, output: []
Output ONLY the JSON array, nothing else.""",

    "bugs": """\
You are an expert software engineer specializing in finding logic bugs and correctness issues.
Analyze the provided code for:
- Logic errors and incorrect conditions
- Off-by-one errors
- Null / None / undefined reference errors
- Integer overflow / underflow
- Race conditions and thread safety issues
- Resource leaks (file handles, connections, memory)
- Incorrect error handling (swallowed exceptions, wrong error types)
- Edge cases not handled (empty input, zero, negative values)
- Incorrect assumptions about data types
- API misuse

For each finding output EXACTLY this JSON format (array):
[{"severity":"critical|high|medium|low","title":"Short title","line":"line number or 'N/A'","description":"What the bug is and when it would occur","fix":"Specific fix"}]

If no issues found, output: []
Output ONLY the JSON array, nothing else.""",

    "performance": """\
You are an expert performance engineer specializing in code efficiency.
Analyze the provided code for:
- Algorithmic complexity issues (O(n²) where O(n) is possible)
- N+1 query problems
- Missing caching for repeated expensive operations
- Blocking I/O in async contexts
- Memory leaks or unnecessary memory allocation
- Inefficient string concatenation in loops
- Missing database indexes (inferred from query patterns)
- Repeated computation that could be memoized
- Large data structures loaded entirely into memory
- Missing pagination for large result sets

For each finding output EXACTLY this JSON format (array):
[{"severity":"critical|high|medium|low","title":"Short title","line":"line number or 'N/A'","description":"Performance impact and when it manifests","fix":"Specific optimization"}]

If no issues found, output: []
Output ONLY the JSON array, nothing else.""",

    "quality": """\
You are a senior software engineer specializing in code quality and maintainability.
Analyze the provided code for:
- Poor naming (vague variable/function names like x, tmp, data)
- Functions that do too much (violates single responsibility)
- Deep nesting (>3 levels) that hurts readability
- Magic numbers/strings without named constants
- Missing or inadequate docstrings for public functions
- Dead code / unreachable code paths
- Code duplication that should be extracted
- Overly complex conditionals that could be simplified
- Missing type hints (Python) or type annotations
- Inconsistent style or naming conventions

For each finding output EXACTLY this JSON format (array):
[{"severity":"medium|low","title":"Short title","line":"line number or 'N/A'","description":"Why this hurts maintainability","fix":"Specific refactoring suggestion"}]

If no issues found, output: []
Output ONLY the JSON array, nothing else.""",
}

AGGREGATOR_PROMPT = """\
You are a senior engineering lead writing a code review summary report.
You have received findings from 4 specialized reviewers. Synthesize them into a
professional Markdown report.

Structure your report EXACTLY like this:

## Code Review Report

**Source:** {source}
**Language:** {lang}
**Reviewed:** {timestamp}

---

### Executive Summary
2-3 sentences on overall code health and top concern.

### Findings by Severity

#### 🔴 Critical ({n_critical})
(list each critical finding as: **[Category] Title** — description + fix)

#### 🟠 High ({n_high})
(same format)

#### 🟡 Medium ({n_medium})
(same format)

#### 🟢 Low ({n_low})
(same format)

### Recommendations
Top 3 actionable next steps, ordered by impact.

---
*Generated by Jarvis Code Review Agent*

Output ONLY the Markdown report."""

# ── Ollama call ────────────────────────────────────────────────────────────────

def _llm(model: str, system: str, user: str, timeout: int = 240) -> str:
    try:
        from ollama_sem import ollama_sem
    except ImportError:
        ollama_sem = threading.Semaphore(1)

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1500},
    }).encode()

    with ollama_sem:
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())["message"]["content"].strip()


def _parse_findings(raw: str) -> list[dict]:
    """Parse reviewer JSON output, return list of finding dicts."""
    raw = raw.strip()
    # Strip markdown fences
    if "```" in raw:
        import re
        raw = re.sub(r"```[a-z]*\n?", "", raw).strip().rstrip("`").strip()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict) and "title" in f]
    except Exception:
        pass
    return []

# ── Core pipeline ──────────────────────────────────────────────────────────────

def _run_reviewer(name: str, model: str, code: str, lang: str) -> tuple[str, list[dict]]:
    """Run a single reviewer. Returns (name, findings)."""
    system = REVIEWER_PROMPTS[name]
    user   = f"Language: {lang}\n\n```{lang}\n{code[:MAX_CODE_LEN]}\n```"
    try:
        raw      = _llm(model, system, user, timeout=180)
        findings = _parse_findings(raw)
        return name, findings
    except Exception as e:
        return name, [{"severity": "low", "title": f"Reviewer error ({name})",
                       "line": "N/A", "description": str(e), "fix": "Check Ollama connectivity"}]


def _build_report(source: str, lang: str, all_findings: dict[str, list]) -> str:
    """Aggregate findings from all reviewers into Markdown via LLM."""
    flat = []
    for reviewer, findings in all_findings.items():
        for f in findings:
            f["category"] = reviewer.capitalize()
            flat.append(f)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    flat.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 3))

    counts = {s: sum(1 for f in flat if f.get("severity") == s)
              for s in ("critical", "high", "medium", "low")}

    # Format findings for aggregator
    findings_text = json.dumps(flat, indent=2)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    system = AGGREGATOR_PROMPT.format(
        source=source, lang=lang, timestamp=ts,
        n_critical=counts["critical"], n_high=counts["high"],
        n_medium=counts["medium"], n_low=counts["low"],
    )
    user = f"All reviewer findings:\n{findings_text}"

    try:
        return _llm(MODELS["aggregator"], system, user, timeout=240)
    except Exception as e:
        # Fallback: build report from raw findings without LLM
        lines = [f"## Code Review Report\n\n**Source:** {source}  **Reviewed:** {ts}\n"]
        for sev in ("critical", "high", "medium", "low"):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
            matches = [f for f in flat if f.get("severity") == sev]
            if matches:
                lines.append(f"\n### {icon} {sev.capitalize()} ({len(matches)})\n")
                for f in matches:
                    lines.append(f"**[{f.get('category','')}] {f['title']}** (line {f.get('line','N/A')})")
                    lines.append(f"> {f.get('description','')}")
                    lines.append(f"> Fix: {f.get('fix','')}\n")
        return "\n".join(lines)


def run_review(code: str, lang: str = "python", source: str = "input") -> dict:
    """
    Run full code review pipeline. Returns session dict with report.

    Args:
        code:   Source code to review
        lang:   Programming language (python, javascript, go, etc.)
        source: Filename or description for the report header
    """
    session_id = str(uuid.uuid4())[:8]
    ts = datetime.datetime.now().isoformat()

    session = {
        "id":       session_id,
        "source":   source,
        "lang":     lang,
        "status":   "running",
        "started":  ts,
        "finished": None,
        "findings": {},
        "counts":   {},
        "report":   None,
        "report_path": None,
        "error":    None,
    }

    with _sessions_lock:
        _sessions[session_id] = session

    print(f"[code-review] Starting review {session_id} — {source} ({lang})", flush=True)

    try:
        # Run 4 reviewers in parallel
        results: dict[str, list] = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_run_reviewer, name, model, code, lang): name
                for name, model in [
                    ("security",    MODELS["security"]),
                    ("bugs",        MODELS["bugs"]),
                    ("performance", MODELS["performance"]),
                    ("quality",     MODELS["quality"]),
                ]
            }
            for future in as_completed(futures):
                name, findings = future.result()
                results[name] = findings
                total = sum(len(v) for v in results.values())
                print(f"[code-review] {name}: {len(findings)} findings ({total} total so far)", flush=True)

        session["findings"] = results

        # Count by severity
        all_flat = [f for findings in results.values() for f in findings]
        session["counts"] = {
            s: sum(1 for f in all_flat if f.get("severity") == s)
            for s in ("critical", "high", "medium", "low")
        }

        # Build final report
        print(f"[code-review] Aggregating {len(all_flat)} findings...", flush=True)
        report_md = _build_report(source, lang, results)
        session["report"] = report_md

        # Save to disk
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        slug   = source.replace("/", "_").replace(".", "_")[:30]
        out_dir = OUTPUT_DIR / f"{session_id}_{slug}"
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "report.md"
        report_path.write_text(report_md, encoding="utf-8")

        # Also save raw findings JSON
        (out_dir / "findings.json").write_text(
            json.dumps({"session": session_id, "source": source,
                        "findings": results, "counts": session["counts"]}, indent=2),
            encoding="utf-8",
        )

        session["report_path"] = str(report_path)
        session["status"]      = "done"
        session["finished"]    = datetime.datetime.now().isoformat()

        c = session["counts"]
        print(
            f"[code-review] Done {session_id} — "
            f"critical:{c['critical']} high:{c['high']} medium:{c['medium']} low:{c['low']}",
            flush=True,
        )

    except Exception as e:
        import traceback
        session["status"] = "error"
        session["error"]  = f"{e}\n{traceback.format_exc()[-500:]}"
        print(f"[code-review] Error {session_id}: {e}", flush=True)

    return session


def run_review_async(code: str, lang: str = "python", source: str = "input") -> str:
    """Start review in background. Returns session_id immediately."""
    session_id = str(uuid.uuid4())[:8]
    session = {
        "id": session_id, "source": source, "lang": lang,
        "status": "queued", "started": datetime.datetime.now().isoformat(),
        "finished": None, "findings": {}, "counts": {}, "report": None,
        "report_path": None, "error": None,
    }
    with _sessions_lock:
        _sessions[session_id] = session

    def _run():
        with _sessions_lock:
            _sessions[session_id]["status"] = "running"
        result = run_review(code, lang, source)
        with _sessions_lock:
            _sessions[session_id].update(result)

    threading.Thread(target=_run, daemon=True, name=f"review-{session_id}").start()
    return session_id


def get_status(session_id: str) -> dict | None:
    with _sessions_lock:
        return dict(_sessions.get(session_id, {}))


def list_reviews() -> list[dict]:
    with _sessions_lock:
        return [
            {k: v for k, v in s.items() if k != "report"}  # omit full report from list
            for s in sorted(_sessions.values(), key=lambda x: x["started"], reverse=True)
        ]

# ── CLI ────────────────────────────────────────────────────────────────────────

DEMO_CODE = '''\
import sqlite3, os, subprocess

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
        for item in data:
            if item["path"] == f:
                data.append({"path": f})
    return data

def run_command(user_input):
    result = subprocess.run(f"ls {user_input}", shell=True, capture_output=True)
    return result.stdout

def calculate(items):
    total = 0
    for i in range(len(items)):
        total = total + items[i]
    return total
'''


def main():
    parser = argparse.ArgumentParser(
        description="Code Review Agent — AI-powered multi-specialist code review",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file app.py
  %(prog)s --file server.js --lang javascript
  git diff HEAD~1 | %(prog)s --stdin --lang python
  %(prog)s --demo
        """
    )
    parser.add_argument("--file",   help="Source file to review")
    parser.add_argument("--stdin",  action="store_true", help="Read code from stdin")
    parser.add_argument("--code",   help="Code string to review (inline)")
    parser.add_argument("--demo",   action="store_true", help="Run demo with intentionally buggy code")
    parser.add_argument("--lang",   default="python", help="Programming language (default: python)")
    parser.add_argument("--output", help="Save report to this path (default: stdout)")
    parser.add_argument("--json",   action="store_true", help="Output raw findings JSON instead of Markdown")
    parser.add_argument("--ollama", default=None, help="Ollama host URL (overrides OLLAMA_HOST env)")

    args = parser.parse_args()

    if args.ollama:
        global OLLAMA_HOST
        OLLAMA_HOST = args.ollama

    # Determine source code + language
    if args.demo:
        code   = DEMO_CODE
        lang   = "python"
        source = "demo_buggy.py"
        print("Running demo review on intentionally buggy code...\n", file=sys.stderr)
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        code   = path.read_text(encoding="utf-8", errors="replace")
        lang   = args.lang or path.suffix.lstrip(".") or "python"
        source = path.name
    elif args.stdin:
        code   = sys.stdin.read()
        lang   = args.lang
        source = "stdin"
    elif args.code:
        code   = args.code
        lang   = args.lang
        source = "inline"
    else:
        parser.print_help()
        sys.exit(1)

    if not code.strip():
        print("Error: no code provided", file=sys.stderr)
        sys.exit(1)

    print(f"Reviewing {source} ({lang}) — 4 specialists running in parallel...", file=sys.stderr)
    t0      = time.time()
    session = run_review(code, lang, source)
    elapsed = time.time() - t0

    c = session["counts"]
    print(
        f"\nDone in {elapsed:.1f}s — "
        f"critical:{c.get('critical',0)} high:{c.get('high',0)} "
        f"medium:{c.get('medium',0)} low:{c.get('low',0)}",
        file=sys.stderr,
    )

    if session.get("error"):
        print(f"Error: {session['error']}", file=sys.stderr)
        sys.exit(1)

    output = json.dumps(session["findings"], indent=2) if args.json else session["report"]

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
