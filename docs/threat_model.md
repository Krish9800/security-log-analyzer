# Threat Model & Defensive Security Controls

This document specifies the defensive architecture and security controls implemented in **Security Log Analyzer** in accordance with the STRIDE threat methodology.

---

## 1. STRIDE Threat Matrix

| Threat Category | Potential Attack Vector | Applied Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Forged syslog sender headers or fabricated source IP | Validation via Python `ipaddress` models; raw headers isolated in metadata; clear separation of observed network state vs claimed payloads. |
| **Tampering** | CRLF log injection (`\r\n`), Null-byte poisoning (`\0`), ANSI escape sequences injected to mislead SIEM analysts | Strict sanitization layer strips control characters and ANSI terminal codes before regex or parsing occurs. |
| **Repudiation** | Malicious actor claims events were dropped or fabricated | Cryptographic deterministic incident tracking; immutable log records; exact line and byte offset auditing. |
| **Information Disclosure** | Sensitive secrets, credentials, or session tokens exposed in exported reports or API responses | Redaction in regex parsers, token masking in URL parameters, non-root isolated container permissions. |
| **Denial of Service (DoS)** | ReDoS (Regular Expression Denial of Service), memory exhaustion via million-event log flooding | Anchored linear regex patterns with strict length limits; bounded deques in `SlidingWindowState`; max payload enforcement on FastAPI endpoints. |
| **Elevation of Privilege** | Code execution via malicious log files or unauthenticated microservice abuse | Unprivileged container execution (`UID 10001`); no shell execution (`subprocess` banned); Bandit SAST zero-finding policy. |

---

## 2. Ingestion Defense & Sanitization

### 2.1 Log Injection (CRLF / Terminal Injection)
Adversaries often inject `\r\n` characters into HTTP User-Agents, SSH usernames, or query parameters to forge new log entries or corrupt terminal displays (ANSI escape bomb).

**Defense Strategy:**
- The `CoreSanitizer` scans every string, converting all non-printable ASCII/Unicode control characters (`\x00-\x1f` except intentional delimiters) into safe representations.
- ANSI terminal sequences matching `\x1b\[[0-9;]*[a-zA-Z]` are stripped prior to terminal rendering.

### 2.2 ReDoS Vulnerability Defense
Vulnerable regular expressions with catastrophic backtracking can halt CPU execution when provided with adversarial payloads.

**Defense Strategy:**
- Regex patterns are thoroughly pre-compiled with atomic groupings and strict character classes.
- Log lengths are bounded (e.g. truncated at 8,192 characters) before pattern evaluation.

---

## 3. Container & Deployment Hardening
- **Rootless execution**: Runs under user `loganalyzer` (`UID:GID 10001:10001`).
- **Read-only Filesystem**: Container root filesystem is mounted `read_only: true` with ephemeral `/tmp` tmpfs.
- **Linux Capabilities Dropped**: `cap_drop: ALL`, `no-new-privileges: true`.
- **Healthcheck Probe**: Internal health check queries unprivileged `/health` endpoint.
