import json
from pathlib import Path


def test_security_report_exists():
    report_path = Path("reports/iam_security_report.json")

    assert report_path.exists()


def test_security_report_is_valid_json():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert isinstance(report, dict)


def test_security_report_contains_summary():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert "summary" in report


def test_security_report_contains_findings():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert "findings" in report
    assert isinstance(report["findings"], list)


def test_security_report_summary():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    summary = report["summary"]

    assert "total_users" in summary
    assert "mfa_issues" in summary
    assert "old_access_keys" in summary
    assert "admin_users" in summary
    assert "wildcard_users" in summary
    assert "total_findings" in summary


def test_security_findings_have_required_fields():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    for finding in report["findings"]:

        assert "user" in finding
        assert "issue" in finding
        assert "severity" in finding
        assert "details" in finding


def test_findings_have_valid_severity():
    report_path = Path("reports/iam_security_report.json")

    with open(report_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    valid_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    for finding in report["findings"]:

        assert finding["severity"] in valid_severities