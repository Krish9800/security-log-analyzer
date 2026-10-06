# Changelog

All notable changes to the **Security Log Analyzer** project are documented here in accordance with [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standards.

## [1.0.0] - 2026-10-06

### Added
- **Phase 1: Architecture & Foundation**
  - Modern Hatchling build system, PEP 621 metadata, pinned dependencies in `pyproject.toml`.
  - Core settings engine via Pydantic BaseSettings with zero-trust local defaults.
  - Sanitization module (`CoreSanitizer`) neutralizing CRLF, null-byte, and ANSI escape injection.
- **Phase 2: Canonical Event Schemas & MITRE Taxonomy**
  - Canonical `LogEvent` schema with strict IP address parsing and RFC 5424 timestamping.
  - Standardized `Incident` schema and MITRE ATT&CK taxonomy models (`T1110`, `T1190`, `T1046`, `T1078`).
- **Phase 3: Modular Parser Pipeline & Registry**
  - Abstract base parser with auto-registration and format sniffing capabilities.
  - Linux `auth.log` parser for SSH authentication events and sudo privilege abuse.
  - Web server access parser for Nginx and Apache Combined log formats.
  - Netfilter / UFW firewall log parser with TCP/UDP packet drop telemetry.
  - Cloud / SIEM NDJSON parser supporting AWS CloudTrail and generic event JSON.
- **Phase 4: Sliding-Window State Engine**
  - Memory-bounded temporal ring buffer (`SlidingWindowState`) indexed by attacker IP.
  - Configurable temporal window pruning and burst threshold tracking.
- **Phase 5: Threat Detection Engine**
  - Brute Force Detector (`T1110`) with credential guessing heuristics.
  - Web Exploit Detector (`T1190`) with SQLi, Path Traversal, and XSS signature matching.
  - Port Scan Detector (`T1046`) tracking multi-port probe thresholds.
  - Privilege Escalation Detector (`T1078`) monitoring unauthorized sudo invocation.
  - Orchestrating `DetectionEngine` handling multi-detector batch execution.
- **Phase 6: MITRE ATT&CK & Forensic Analytics**
  - Forensic statistics calculator for event distribution and failure rates.
  - Attacker profiling engine aggregating cross-phase behavioral tactics.
  - MITRE ATT&CK coverage matrix evaluator.
- **Phase 7: Telemetry & Exporters**
  - Micro Focus ArcSight Common Event Format (CEF:0) syslog exporter.
  - Executive forensic incident report exporter in Markdown format.
  - High-density normalized NDJSON SIEM exporter.
- **Phase 8: Typer & Rich CLI Dashboard**
  - Interactive terminal CLI with Rich tables, panels, and progress bars.
  - Commands: `analyze`, `inspect`, `rules list`, and `version`.
- **Phase 9: FastAPI Microservice & Adversarial Suite**
  - High-performance asynchronous REST API (`/analyze`, `/inspect`, `/health`, `/metrics`).
  - Security middleware: Request ID injection, security response headers, rate limiting.
  - Comprehensive adversarial test suite with 53/53 tests passing at 95% coverage.
- **Phase 10: CI/CD, Containerization & Documentation**
  - Multi-stage rootless Dockerfile (`UID 10001:10001`) and hardened `docker-compose.yml`.
  - Comprehensive GitHub Actions CI workflow (Python 3.11/3.12, Ruff, Mypy, Bandit, Pytest).
  - Deep architectural documentation and STRIDE threat model.
