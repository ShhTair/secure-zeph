# SecureZef Engine 🛡️ (Go Implementation)

SecureZef is an ultra-lightweight, blazing-fast Go wrapper that intercepts output streams of any AI agent (Python, Node, Bash). It scans streams in real-time against strict DLP (Data Loss Prevention) and Prompt Injection policies before the output hits the terminal or the user.

Forget bloated API proxies. This is 100% Go. It's invisible, highly configurable, and blocks leaks instantly.

## 🚀 Quick Start

### 1. Build the Engine
```bash
go build -o securezef main.go
```

### 2. Run your agent securely
Wrap your existing AI script (`agent.py` or any other process):
```bash
./securezef -rules rules/master_rules_v1.json -script agent.py
```

## 📜 How Rules Work

Rules are defined in a simple, highly-configurable JSON file: `rules/master_rules_v1.json`. 
You don't need to recompile the Go binary to add new rules—just update the JSON and restart the wrapper.

### Example Rule Configuration
```json
{
  "rules": [
    {
      "id": "KEY_LEAK_OPENAI",
      "name": "Blocks OpenAI token leaks",
      "pattern": "sk-proj-[a-zA-Z0-9_-]+",
      "severity": "critical"
    }
  ]
}
```

### What You Can Block:
- **API Keys & Secrets:** Match specific token formats.
- **Destructive Commands:** Intercept dangerous system commands.
- **Prompt Overrides:** Flag known jailbreak terminology.

## 🛠 Project Structure
- `main.go`: The CLI entry point and process wrapper (intercepts IO pipes).
- `engine/engine.go`: The core regex scanning engine. Compiles rules on startup for zero-latency streaming.
- `rules/master_rules_v1.json`: The active ruleset repository.
- `agent.py`: A dummy python script for testing the wrapper.
