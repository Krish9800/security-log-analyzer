# Security Log Analyzer

[![CI Pipeline](https://github.com/Krish9800/security-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Krish9800/security-log-analyzer/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://github.com/python/mypy)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance, modular, SIEM-grade forensic analysis engine for security operations and threat hunting. Ingests heterogeneous system, web, network, and cloud logs, applies stateful sliding-window correlation, detects adversarial techniques mapped to **MITRE ATT&CK Enterprise Matrix**, and exports standardized alerts to ArcSight CEF, Markdown, and NDJSON.

---

## Key Features

- **Multi-Format Log Parsing**:
  - Linux `auth.log` / `secure` (SSH authentication failures/successes, sudo elevation).
  - Nginx / Apache W3C Combined Log Format (HTTP requests, status codes, query strings, user agents).
  - Netfilter / UFW firewall logs (packet drops, TCP/UDP port mapping).
  - Cloud SIEM NDJSON (structured event streams, AWS CloudTrail, container telemetry).
- **Hardened Ingestion Sanitizer**:
  - Active neutralization of CRLF log injection (`\r\n`), null-byte poisoning (`\0`), and ANSI terminal escape codes.
- **Stateful Threat Correlation**:
  - Sliding-window temporal ring buffer indexed by attacker IP to track burst-based attacks without memory exhaustion.
  - Detectors:
    - **T1110 (Brute Force)**: SSH and web authentication credential stuffing.
    - **T1190 (Exploit Public-Facing Application)**: SQL Injection, Path Traversal, Cross-Site Scripting (XSS).
    - **T1046 (Network Service Discovery)**: Horizontal and vertical port scanning.
    - **T1078 (Valid Accounts / Privilege Escalation)**: Unauthorized `sudo` abuse and suspicious privilege elevation.
- **Forensic Analytics & MITRE Mapping**:
  - Attacker profiling, source IP aggregation, tactic timeline generation, and MITRE coverage matrices.
- **Universal SIEM Exporters**:
  - Micro Focus ArcSight Common Event Format (CEF:0) syslog lines.
  - Detailed executive markdown forensic reports.
  - Normalized NDJSON SIEM log streams.
- **Interactive CLI & REST Microservice**:
  - Rich-powered terminal dashboard (`loganalyzer`).
  - Production-ready FastAPI service with OpenAPI documentation and rate limiting.

---

## Architecture Overview

```
Raw Logs ──> Core Sanitizer ──> Parser Registry ──> Normalized LogEvents
                                                           │
                                                           ▼
                                               Sliding-Window State Machine
                                                           │
                                                           ▼
                                                Detection Rules Engine
                                            (T1110, T1190, T1046, T1078)
                                                           │
                                                           ▼
                                                Forensic Correlator
                                                           │
                      ┌────────────────────────────────────┼───────────────────────────────────┐
                      ▼                                    ▼                                   ▼
             ArcSight CEF Exporter               Markdown Forensic Report             FastAPI & Rich CLI
```

---

## Installation

### Prerequisites
- Python 3.11 or 3.12
- `uv` (recommended) or standard `pip`

```bash
git clone https://github.com/Krish9800/security-log-analyzer.git
cd security-log-analyzer

# Create virtual environment and install in editable mode with development tools
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Quickstart & Usage

### 1. Command Line Interface (CLI)

#### Analyze Log Files
```bash
# Analyze an auth.log and output to terminal
loganalyzer analyze /var/log/auth.log

# Export detected incidents to ArcSight CEF
loganalyzer analyze /var/log/auth.log --format cef --output incidents.cef

# Export forensic summary report to Markdown
loganalyzer analyze /var/log/nginx/access.log --format markdown --output report.md

# Output raw JSON incidents
loganalyzer analyze /var/log/syslog --format json
```

#### Inspect Parsed Events (Without Detection)
```bash
# Inspect first 20 parsed events with schema validation
loganalyzer inspect /var/log/auth.log --limit 20
```

#### List Available Threat Detection Rules
```bash
loganalyzer rules list
```

---

### 2. REST API Service

#### Launch Server
```bash
uvicorn loganalyzer.api.app:app --host 127.0.0.1 --port 8000 --reload
```

#### Endpoints
- `GET /health`: Health probe and service status.
- `GET /metrics`: Service runtime metrics.
- `GET /rules`: List all registered detection rules.
- `POST /analyze`: Ingest raw log text or structured events and execute forensic detection.
- `POST /inspect`: Parse log lines into normalized `LogEvent` records.

#### Example API Request
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs": "Oct 06 14:00:01 server sshd[100]: Failed password for invalid user admin from 198.51.100.1 port 52123 ssh2\nOct 06 14:00:02 server sshd[101]: Failed password for invalid user admin from 198.51.100.1 port 52124 ssh2\nOct 06 14:00:03 server sshd[102]: Failed password for invalid user admin from 198.51.100.1 port 52125 ssh2\nOct 06 14:00:04 server sshd[103]: Failed password for invalid user admin from 198.51.100.1 port 52126 ssh2\nOct 06 14:00:05 server sshd[104]: Failed password for invalid user admin from 198.51.100.1 port 52127 ssh2",
    "parser_format": "auth_log"
  }'
```

---

## Docker Deployment

The application includes a hardened, multi-stage rootless container setup.

```bash
# Build and run container
docker compose up -d

# Verify container health
docker compose ps
curl http://127.0.0.1:8000/health
```

---

## Quality Gates & DevSecOps

This project adheres to strict automated code quality and security verification:

```bash
# Code formatting check
ruff format --check .

# Linting and style analysis
ruff check .

# Static type verification
mypy src

# Static application security testing (SAST)
bandit -c pyproject.toml -r src

# Full test suite with coverage gate (>=90%)
pytest --cov=src/loganalyzer --cov-fail-under=90
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
