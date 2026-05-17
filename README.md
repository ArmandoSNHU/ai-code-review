# AI Code Review Agent

> Multi-specialist AI code review — no API keys required.

Runs **4 specialized reviewers in parallel**, each focused on a different domain, then synthesizes findings into a professional severity-graded Markdown report — all powered by local LLMs via [Ollama](https://ollama.ai).

---

## How It Works

```
Your Code
    │
    ├─▶ SecurityReviewer   (whiterabbitneo) — OWASP Top 10, injection, secrets
    ├─▶ BugReviewer        (qwen3:8b)       — Logic errors, null refs, race conditions
    ├─▶ PerformanceReviewer (mistral)        — Complexity, N+1 queries, memory leaks
    └─▶ QualityReviewer    (llama3.2:1b)    — Naming, dead code, documentation gaps
            │
            ▼
    Aggregator (qwen3:8b) — synthesizes all findings
            │
            ▼
    Severity-graded Markdown Report
    🔴 Critical  🟠 High  🟡 Medium  🟢 Low
```

All 4 reviewers run **concurrently** via `ThreadPoolExecutor` — typical review completes in 60–120 seconds.

---

## Features

- **Parallel execution** — 4 specialists run at the same time
- **Severity grading** — Critical / High / Medium / Low
- **Multiple input modes** — file path, stdin (pipe a git diff), or inline string
- **JSON + Markdown output** — machine-readable findings and human-readable report
- **Language agnostic** — Python, JavaScript, Go, Rust, Java, and more
- **100% local** — no cloud API, no data leaves your machine
- **REST API** — integrates with CI pipelines via HTTP

---

## Requirements

- Python 3.11+
- [Ollama](https://ollama.ai) running locally

Pull the required models:

```bash
ollama pull whiterabbitneo
ollama pull qwen3:8b
ollama pull mistral
ollama pull llama3.2:1b
```

---

## Installation

```bash
git clone https://github.com/ArmandoSNHU/ai-code-review.git
cd ai-code-review
pip install -r requirements.txt
```

---

## Usage

### Review a file

```bash
python code_review_agent.py --file app.py
python code_review_agent.py --file server.js --lang javascript
python code_review_agent.py --file main.go --lang go
```

### Pipe a git diff

```bash
git diff HEAD~1 | python code_review_agent.py --stdin --lang python
```

### Inline code string

```bash
python code_review_agent.py --code "def login(user, pw): exec(pw)" --lang python
```

### Run the built-in demo (intentionally buggy code)

```bash
python code_review_agent.py --demo
```

### Save report to file

```bash
python code_review_agent.py --file app.py --output review_report.md
```

### Get raw JSON findings

```bash
python code_review_agent.py --file app.py --json
```

### Use a remote Ollama instance

```bash
python code_review_agent.py --file app.py --ollama http://192.168.1.100:11434
```

---

## Example Output

```
Reviewing demo_buggy.py (python) — 4 specialists running in parallel...
Done in 87.3s — critical:2 high:1 medium:3 low:4
```

```markdown
## Code Review Report

**Source:** demo_buggy.py  
**Language:** python  
**Reviewed:** 2026-05-16 06:30 UTC

---

### Executive Summary
The code contains a critical SQL injection vulnerability and hardcoded credentials
that must be addressed before deployment. Performance and quality issues are secondary.

### Findings by Severity

#### 🔴 Critical (2)
**[Security] SQL Injection** — line 8  
Direct string interpolation in SQL query allows arbitrary SQL execution via username.  
Fix: Use parameterized queries — `cursor.execute("SELECT * FROM users WHERE name = ?", (username,))`

**[Security] Hardcoded Secret** — line 4  
`SECRET_KEY = "hardcoded-secret-abc123"` is committed to source control.  
Fix: `SECRET_KEY = os.environ["SECRET_KEY"]`

#### 🟠 High (1)
**[Security] Command Injection** — line 18  
`subprocess.run(f"ls {user_input}", shell=True)` allows shell injection.  
Fix: Use `subprocess.run(["ls", user_input], shell=False)`
```

---

## REST API

Wire to any HTTP server or run standalone:

```bash
# Submit code for async review
curl -X POST http://localhost:5000/code-review/new \
  -H "Content-Type: application/json" \
  -d '{"code": "...", "lang": "python", "source": "app.py"}'
# Returns: {"ok": true, "session_id": "a3f8b1c2", "status": "queued"}

# Poll for results
curl http://localhost:5000/code-review/status/a3f8b1c2

# List all sessions
curl http://localhost:5000/code-review/list
```

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `WEAVER_MODEL` | `qwen3:8b` | Bug detection + aggregator model |
| `SECURITY_MODEL` | `whiterabbitneo` | Security reviewer model |
| `REASONING_MODEL` | `mistral:latest` | Performance reviewer model |
| `FAST_MODEL` | `llama3.2:1b` | Quality reviewer model |
| `CODE_REVIEW_DIR` | `./code-reviews` | Report output directory |

---

## Project Structure

```
ai-code-review/
├── code_review_agent.py   # Core agent — reviewers, aggregator, CLI, API
├── requirements.txt
├── examples/
│   ├── demo_buggy.py      # Intentionally flawed code for demo
│   └── example_report.md  # Sample output report
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**Armando Gomez** — [@ArmandoSNHU](https://github.com/ArmandoSNHU)
