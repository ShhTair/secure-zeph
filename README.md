# SecureZef v2.0 🛡️

SecureZef is a lightweight, zero-trust security middleware for AI Agents. It acts as an API gateway proxy, intercepting LLM requests and responses, running heuristic analysis, tool firewalls, and alignment checks to prevent prompt injections, data exfiltration, and malicious tool executions.

![SecureZef Dashboard (Placeholder)](https://via.placeholder.com/800x400?text=SecureZef+Dashboard+Here)

## ✨ What's New in 2.0
- **Cleaned and optimized core architecture** (removed legacy planning files)
- **Advanced Heuristics Engine** with real-time payload sanitization
- **Strict Tool Firewall** preventing implicit data exfiltration via tool calls
- **Multi-Model Evaluator** support out-of-the-box (OpenAI, Anthropic, Gemini)

## 🚀 Quick Start

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/yourusername/secure-zeph.git
cd secure-zeph
pip install -r requirements.txt
```

### 2. Configuration
Copy the environment template and adjust it:
```bash
cp .env.example .env
# Edit .env to add your OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.
```

### 3. Running the Gateway
Start the SecureZef proxy server:
```bash
bash startup.sh
```
The gateway runs locally on `http://localhost:8000`.

## 📜 Core Rules & Policies

SecureZef enforces the following strict policies via `policies/`:
1. **No direct credential output**: The agent cannot dump `api_key`, `password`, or `secret`.
2. **Exfiltration block**: Blocks tool calls attempting to append sensitive data to URLs (`?q=secret`).
3. **Approval Gates**: Sensitive tools (e.g., `execute_command`, `delete_database`) require explicit human-in-the-loop approval.

![Policy Engine Flow (Placeholder)](https://via.placeholder.com/800x300?text=Policy+Flow+Diagram+Here)

## 🧪 Running Evaluations
To test the middleware against known prompt injection scenarios (like InjecAgent datasets):
```bash
python scripts/run_multi_model.py
```

## 🤝 Contributing
Open an issue or submit a PR. Please ensure all tests pass and no secrets are committed.

## 📄 License
MIT License

## 🛠️ Configuring Security Policies

SecureZef uses declarative YAML files in the `policies/` directory to configure rules, constraints, and tool firewalls. You don't need to write code to block attacks—just update the config.

### 1. Tool Firewall (`policies/default_tools.yaml`)
Control exactly which tools the LLM can use, how many times in a row (`max_chain_depth`), and what arguments are forbidden (Regex blocklists).

```yaml
allowed_tools:
  - name: "read_file"
    description: "Read a local file"
    max_chain_depth: 2
    arg_constraints:
      path:
        type: string
        blocked_patterns:
          - ".*\\.env$"      # Blocks reading .env
          - ".*\\.key$"      # Blocks reading .key files
          - ".*password.*"

blocked_tools:
  - name: "execute_shell"
    reason: "Direct shell execution is forbidden"

default_action: "deny" # Denies any tool not in the allowed list
```

### 2. Exfiltration Controls (`policies/exfil_controls.yaml`)
Prevent the agent from leaking data in URLs or bodies. This configuration intercepts outputs before they leave the gateway.

```yaml
rules:
  - name: "Block Secret Append to URL"
    pattern: "https?://[^\\s]+\\?[^\\s]*(?:base64|b64|data|q|query|secret|key|token|api_key|password)\\s*="
    action: "block"
    confidence: 0.9
```

### 3. Approval Gates (`policies/approval_gates.yaml`)
Some actions shouldn't be blocked entirely but require a Human-in-the-Loop (HITL). Define which actions trigger an approval workflow.

```yaml
gates:
  - trigger: "tool_name == 'drop_table'"
    action: "require_approval"
    timeout_seconds: 300
```
