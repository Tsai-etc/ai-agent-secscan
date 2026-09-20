# 🛡️ AI Agent Security & Vulnerability Scanner (`ai-agent-secscan`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Bug Bounty Ready](https://img.shields.io/badge/Bug_Bounty-Huntr_%7C_Immunefi-red.svg)](https://huntr.com)

**ai-agent-secscan** is an automated static and dynamic vulnerability analysis suite designed specifically for LLM frameworks, autonomous AI agents, and AI copilot backends (LangChain, Dify, vLLM, Ollama, CrewAI, AutoGPT).

Developed by [@Tsai-etc](https://github.com/Tsai-etc) (CashFlow Studio) to audit open-source AI repositories and hunt for high-severity CVEs on **Huntr.com**, **HackerOne**, and **Bugcrowd**.

---

## 🎯 Target Vulnerability Spectrum (OWASP Top 10 for LLM)

1. **LLM02: Insecure Output Handling & Remote Code Execution (RCE)**:
   - Identifies dynamic code evaluation (`eval`, `exec`).
   - Detects unsanitized command execution via `subprocess` with `shell=True`.
2. **LLM08: Excessive Agency & Server-Side Request Forgery (SSRF)**:
   - Analyzes tool-calling webhooks for unauthenticated access to internal networks (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) and cloud metadata endpoints (`169.254.169.254`).
3. **Insecure Deserialization**:
   - Detects unsafe deserialization of model weights, memories, or state snapshots via `pickle.loads` or unverified PyTorch `torch.load`.
4. **Cryptographic State Verification**:
   - Built-in `AgentExecutionAuditor` creates SHA-256 tamper-evident proof chains for agent tool calls and state transitions.

---

## 🚀 Quick Start & CLI Usage

### 1. Installation
```bash
git clone https://github.com/Tsai-etc/ai-agent-secscan.git
cd ai-agent-secscan
pip install -e .
```

### 2. Scanning a Repository for AI Vulnerabilities
```bash
# Scan a directory recursively
python cli.py /path/to/target/ai-repo

# Output in JSON format for automated bug bounty pipelines
python cli.py /path/to/target/ai-repo --json
```

### 3. Check Webhook URL for SSRF Vulnerabilities
```bash
python cli.py dummy --ssrf-check "http://169.254.169.254/latest/meta-data/"
```

---

## 🧪 Automated Test Suite
```bash
python -m unittest test_sec_scanner.py
python -m unittest test_auditor.py
```

---

## 💳 Settlement & Contact
- **Author**: [@Tsai-etc](https://github.com/Tsai-etc)
- **Settlement Wallet (BSC BEP20 / EVM)**: `0x322f38636bf6fa64d07af5f481bcb63bc3828731`
