"""Integration tests for FastAPI REST endpoints and security headers."""

from fastapi.testclient import TestClient

from loganalyzer.api.app import app

client = TestClient(app)


def test_api_health_and_security_headers() -> None:
    """Test /health endpoint and defensive HTTP response headers."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["active_rules_count"] >= 4

    # Check security headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_api_rules_list() -> None:
    """Test /api/v1/rules endpoint returns registered detection rules."""
    resp = client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 4
    rule_ids = [r["rule_id"] for r in rules]
    assert "RULE-BRUTE-01" in rule_ids
    assert "RULE-WEB-02" in rule_ids


def test_api_analyze_logs() -> None:
    """Test /api/v1/analyze endpoint ingesting raw logs and returning incidents."""
    lines = [
        # Normal
        '10.0.0.1 - - [06/Oct/2026:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "-"',
        # Web attack (SQLi)
        '203.0.113.88 - - [06/Oct/2026:14:31:00 +0000] "GET /api?id=1%20UNION%20SELECT%20user HTTP/1.1" 200 500 "-" "-"',
    ]

    resp = client.post("/api/v1/analyze", json={"lines": lines})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 2
    assert data["incident_count"] == 1
    assert len(data["incidents"]) == 1
    assert "SQL Injection" in data["incidents"][0]["title"]
    assert len(data["report_sha256"]) == 64


def test_api_analyze_export_formats() -> None:
    """Test /api/v1/analyze/export endpoint in json, markdown, and cef formats."""
    lines = [
        '203.0.113.88 - - [06/Oct/2026:14:31:00 +0000] "GET /api?id=1%20UNION%20SELECT%20user HTTP/1.1" 200 500 "-" "-"',
    ]

    for fmt in ("json", "markdown", "cef"):
        resp = client.post(
            f"/api/v1/analyze/export?format={fmt}",
            json={"lines": lines},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == fmt
        assert len(data["content"]) > 0

    # Invalid format fails validation
    bad_resp = client.post(
        "/api/v1/analyze/export?format=unknown",
        json={"lines": lines},
    )
    assert bad_resp.status_code == 422
