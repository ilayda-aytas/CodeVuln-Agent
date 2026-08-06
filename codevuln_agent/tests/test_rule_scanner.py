import pytest
from scanner.rule_scanner import run_rule_scanner, deduplicate_findings, sort_findings


def test_run_rule_scanner_detects_simple_pattern():
    code = "print('hello')\nuser_input = input()\nos.system(user_input)"
    findings = run_rule_scanner(code, "python")

    assert isinstance(findings, list)
    assert any(f["vulnerability_name"] == "Shell injection" for f in findings)


def test_deduplicate_findings_removes_duplicates():
    findings = [
        {"vulnerability_name": "Test", "affected_line": 1},
        {"vulnerability_name": "Test", "affected_line": 1},
        {"vulnerability_name": "Other", "affected_line": 2},
    ]
    unique = deduplicate_findings(findings)
    assert len(unique) == 2


def test_sort_findings_orders_by_severity():
    findings = [
        {"severity": "Low"},
        {"severity": "Critical"},
        {"severity": "Medium"},
    ]
    sorted_findings = sort_findings(findings)
    assert [f["severity"] for f in sorted_findings] == ["Critical", "Medium", "Low"]
