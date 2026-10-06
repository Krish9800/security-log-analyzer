"""Integration tests for Typer and Rich CLI."""

from pathlib import Path

from typer.testing import CliRunner

from loganalyzer.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Test 'log-analyzer version' command."""
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "Security Log Analyzer" in res.stdout
    assert "Brute Force Threshold" in res.stdout


def test_cli_rules_list() -> None:
    """Test 'log-analyzer rules list' command."""
    res = runner.invoke(app, ["rules", "list"])
    assert res.exit_code == 0
    assert "RULE-BRUTE-01" in res.stdout
    assert "RULE-WEB-02" in res.stdout
    assert "T1110" in res.stdout


def test_cli_inspect_and_file_not_found(tmp_path: Path) -> None:
    """Test 'log-analyzer inspect' on sample log file and error handling."""
    sample_file = tmp_path / "test.log"
    sample_file.write_text(
        "Oct  6 14:30:00 srv sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2\n"
        '10.0.0.1 - - [06/Oct/2026:14:31:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "-"\n',
        encoding="utf-8",
    )

    # Valid inspect
    res = runner.invoke(app, ["inspect", str(sample_file), "--limit", "2"])
    assert res.exit_code == 0
    assert "Forensic Log Inspection" in res.stdout
    assert "auth_log" in res.stdout
    assert "root" in res.stdout

    # Missing file
    res_err = runner.invoke(app, ["inspect", "non_existent_file.log"])
    assert res_err.exit_code == 1
    assert "does not exist" in res_err.stdout


def test_cli_analyze_formats_and_export(tmp_path: Path) -> None:
    """Test 'log-analyzer analyze' with rich, json, markdown, and cef outputs."""
    sample_file = tmp_path / "attacks.log"
    lines = [
        # 3 failed logins for brute force
        "Oct  6 14:30:00 host sshd[1]: Failed password for root from 198.51.100.1 port 22 ssh2",
        "Oct  6 14:30:05 host sshd[2]: Failed password for root from 198.51.100.1 port 22 ssh2",
        "Oct  6 14:30:10 host sshd[3]: Failed password for root from 198.51.100.1 port 22 ssh2",
        "Oct  6 14:30:15 host sshd[4]: Failed password for root from 198.51.100.1 port 22 ssh2",
        "Oct  6 14:30:20 host sshd[5]: Failed password for root from 198.51.100.1 port 22 ssh2",
        # 1 web attack
        '203.0.113.88 - - [06/Oct/2026:14:32:00 +0000] "GET /api?id=1%20UNION%20SELECT%20user HTTP/1.1" 200 500 "-" "-"',
    ]
    sample_file.write_text("\n".join(lines), encoding="utf-8")

    # Terminal output
    res_term = runner.invoke(app, ["analyze", str(sample_file)])
    assert res_term.exit_code == 0
    assert "Forensic Analysis Summary" in res_term.stdout

    # JSON format
    res_json = runner.invoke(app, ["analyze", str(sample_file), "--format", "json"])
    assert res_json.exit_code == 0
    assert '"total_events": 6' in res_json.stdout
    assert '"report_sha256":' in res_json.stdout

    # Markdown format
    res_md = runner.invoke(app, ["analyze", str(sample_file), "--format", "markdown"])
    assert res_md.exit_code == 0
    assert "# Security Log Forensic Investigation Report" in res_md.stdout

    # CEF format
    res_cef = runner.invoke(app, ["analyze", str(sample_file), "--format", "cef"])
    assert res_cef.exit_code == 0
    assert "CEF:0|SecurityLogAnalyzer|" in res_cef.stdout

    # Output to file
    out_file = tmp_path / "out_report.md"
    res_out = runner.invoke(
        app,
        ["analyze", str(sample_file), "--format", "markdown", "--output", str(out_file)],
    )
    assert res_out.exit_code == 0
    assert out_file.is_file()
    assert "Forensic Investigation Report" in out_file.read_text(encoding="utf-8")
