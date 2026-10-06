# System Architecture & Forensic Design

The **Security Log Analyzer** is designed as a modular, high-throughput, SIEM-grade forensic analysis system. It transforms heterogeneous raw system, web, network, and firewall logs into structured telemetry mapped against the **MITRE ATT&CK Enterprise Matrix**.

---

## 1. High-Level Subsystem Architecture

```mermaid
flowchart TD
    subgraph Ingestion ["1. Forensic Ingestion & Sanitization"]
        RawLogs["Raw Log Stream / Files / API Payload"]
        Sanitizer["Core Sanitizer (CRLF, Null-Byte, ANSI Stripping)"]
        RawLogs --> Sanitizer
    end

    subgraph Parsing ["2. Pluggable Parser Pipeline"]
        Registry["Parser Registry"]
        AuthParser["SSH / Auth Parser (RFC 5424)"]
        WebParser["Nginx / Apache W3C Parser"]
        FWParser["Iptables / UFW Netfilter Parser"]
        JSONParser["NDJSON Cloud Security Parser"]
        Sanitizer --> Registry
        Registry --> AuthParser
        Registry --> WebParser
        Registry --> FWParser
        Registry --> JSONParser
    end

    subgraph StateEngine ["3. Sliding-Window State Engine"]
        CanonEvents["Normalized LogEvent Stream"]
        AuthParser --> CanonEvents
        WebParser --> CanonEvents
        FWParser --> CanonEvents
        JSONParser --> CanonEvents
        WindowState["Sliding Window State Machine (Bounded Deques)"]
        CanonEvents --> WindowState
    end

    subgraph ThreatDetection ["4. Behavioral Threat Engine"]
        RulesEngine["Detection Engine"]
        BF["Brute Force (T1110)"]
        WebExploit["Web Attacks (T1190: SQLi, Path Traversal, XSS)"]
        PortScan["Reconnaissance (T1046)"]
        PrivEsc["Privilege Escalation (T1078)"]
        WindowState --> RulesEngine
        RulesEngine --> BF
        RulesEngine --> WebExploit
        RulesEngine --> PortScan
        RulesEngine --> PrivEsc
    end

    subgraph ForensicAnalytics ["5. MITRE Mapping & Correlation"]
        Correlator["Forensic Correlator & Attacker Profiler"]
        MitreTaxonomy["MITRE ATT&CK Taxonomy Coverage"]
        StatsEngine["Statistical Baseline Calculator"]
        BF --> Correlator
        WebExploit --> Correlator
        PortScan --> Correlator
        PrivEsc --> Correlator
        Correlator --> MitreTaxonomy
        Correlator --> StatsEngine
    end

    subgraph TelemetryReporting ["6. Reporting & Interfaces"]
        CLI["Typer & Rich Interactive Terminal"]
        API["FastAPI High-Performance REST Service"]
        CEF["ArcSight Common Event Format (CEF:0)"]
        MD["Forensic Incident Markdown Report"]
        JSONRep["Normalized NDJSON SIEM Export"]
        MitreTaxonomy --> CLI
        MitreTaxonomy --> API
        MitreTaxonomy --> CEF
        MitreTaxonomy --> MD
        MitreTaxonomy --> JSONRep
    end
```

---

## 2. Canonical Data Models

### 2.1 `LogEvent`
Every incoming log record is normalized into an immutable, strictly-typed Pydantic model:
- `timestamp`: UTC ISO-8601 standardized datetime.
- `source_type`: Log format identifier (`auth_log`, `web_w3c`, `firewall_netfilter`, `cloud_json`).
- `raw_message`: Sanitized original message.
- `source_ip` / `destination_ip`: Standardized `IPvAnyAddress` objects.
- `source_port` / `destination_port`: Integer ports with validation.
- `event_type`: Categorical taxonomy (`auth_failure`, `auth_success`, `http_request`, `packet_drop`, `sudo_command`).
- `status`: Result outcome (`success`, `failure`, `blocked`, `info`).
- `user`: Account identity extracted from log context.
- `process_name` / `pid`: Originating system process and identifier.
- `metadata`: Flexible contextual dictionary (e.g., HTTP method, user agent, TCP flags).

### 2.2 `Incident`
Represents an aggregated, validated security alert:
- `incident_id`: Deterministic or UUID forensic identifier.
- `title`: Standardized alert description.
- `severity`: Standardized CVSS-aligned ranking (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `attacker_ip`: Attribution candidate IP.
- `mitre_technique`: Mapped MITRE ATT&CK identifier (e.g. `T1110`, `T1190`, `T1046`, `T1078`).
- `event_count`: Number of correlated raw events.
- `evidence`: Sample raw event strings demonstrating the attack.
- `recommendation`: Contextual incident response guidance.

---

## 3. Sliding-Window State Engine
To prevent memory exhaustion attacks and unbounded state growth when processing gigabyte-scale logs:
1. **Source IP Indexing**: Events are partitioned into temporal ring buffers keyed by attacker IP.
2. **Deterministic Pruning**: Events falling outside the configurable temporal threshold (`window_seconds`) are evicted.
3. **Capacity Caps**: The deque enforces a hard limit of `max_events_per_ip` to guarantee $O(1)$ amortized memory operations.
