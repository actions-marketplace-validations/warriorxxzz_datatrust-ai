# DataTrust AI

A local-first DevSecOps CLI for detecting and auto-remediating Secrets, PII, SAST vulnerabilities, and IaC misconfigurations. 

[![PyPI version](https://img.shields.io/pypi/v/datatrust-privacy-guard.svg)](https://pypi.org/project/datatrust-privacy-guard/)
[![Python Tests](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml/badge.svg)](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents
- [Core Features](#core-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Advanced Usage](#advanced-usage)
- [CI/CD Integration](#cicd-integration)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Core Features

DataTrust AI is designed to run instantly in your local environment without sending your code to the cloud.

- **Secret & PII Detection**: Detects AWS, OpenAI, and GitHub tokens using Shannon Entropy. Supports regional PII (Nepal/India) and handles Devanagari digits.
- **SAST (Static Analysis)**: Parses Python AST to detect SQL Injection risks, weak cryptography (e.g., MD5), and dangerous function calls (`eval`, `exec`).
- **Infrastructure as Code (IaC)**: Scans `Dockerfile` for root users/hardcoded secrets and Kubernetes YAMLs for `privileged: true`.
- **Dependency Scanning (SCA)**: Checks `requirements.txt` against the OSV database for known CVEs.
- **Auto-Remediation**: Automatically moves exposed secrets to `.env`, changes Docker `USER root` to `USER nonroot`, and fixes K8s YAML misconfigurations.
- **Blazing Fast**: Uses multi-processing and MD5 SQLite caching to only scan modified files.
- **Extensible**: Write custom detection rules using the local plugin system.

---

## Installation

```bash
pip install datatrust-privacy-guard
```

Quick Start

1. Scan a text prompt (e.g., before pasting into ChatGPT):

```bash
datatrust "My Aadhaar is 2345 6789 0123 and my OpenAI key is sk-abc123..."
```

2. Scan your entire repository:

```bash
datatrust -d .
```

3. Scan and Auto-Fix vulnerabilities:

```bash
datatrust -d . --fix
```

(This moves secrets to .env and patches Docker/K8s files automatically).

---

Advanced Usage

1. Setup FAANG-Level Automation

Create local Git pre-commit hooks and GitHub Actions workflows in one command. DataTrust will automatically block commits if secrets are detected.

```bash
datatrust --automate
```

2. Dependency & License Scans

```bash
datatrust --sca            # Scan for CVEs
datatrust --license-check  # Check for restrictive licenses (GPL, AGPL)
```

3. Local Web Dashboard

Generate a beautiful HTML report and serve it locally.

```bash
datatrust -d . --serve
```

4. Writing Custom Plugins

Create a folder named datatrust_plugins in your project root. Add a Python file (e.g., my_rule.py):

```python
def scan_line(line):
    if "company_secret_token_" in line:
        return [{"type": "Company Internal Token", "severity": "HIGH", "value": line}]
    return []
```

DataTrust will automatically load this rule on the next run.

---

CI/CD Integration

DataTrust AI is designed for pipelines. It exits with code 1 if high-severity issues are found.

GitHub Actions Format:

```bash
datatrust -d . --gh-actions
```

SARIF Output (For GitHub Advanced Security):

```bash
datatrust -d . --sarif
```

---

Configuration

Generate a default config file:

```bash
datatrust --init
```

Edit datatrust.yml to ignore specific paths or rules:

```yaml
ignore_paths:
  - tests/
  - docs/
ignore_types:
  - EMAIL
  - IPV4
```

You can also add # datatrust:ignore to the end of any line to skip scanning that specific line.

---

Architecture

DataTrust AI is built with zero heavy dependencies (no PyTorch, no Transformers). It relies on:

· Python ast module: For structural code analysis (SAST).
· Shannon Entropy: For mathematical detection of random strings/secrets.
· SQLite: For local caching and historical scan tracking.
· Multiprocessing: For parallel file scanning.

---

Contributing

Contributions are highly encouraged. Whether it's adding new PII regex patterns, improving SAST rules, or fixing bugs.

1. Fork the repository.
2. Create your feature branch (git checkout -b feature/AmazingFeature).
3. Run tests (python -m unittest discover tests).
4. Commit your changes.
5. Open a Pull Request.

