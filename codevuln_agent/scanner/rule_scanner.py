import re
from typing import List, Dict, Any

from scanner.rules.generic_rules import GENERIC_RULES
from scanner.rules.python_rules import PYTHON_RULES
from scanner.rules.javascript_rules import JAVASCRIPT_RULES
from scanner.rules.php_rules import PHP_RULES
from scanner.rules.java_rules import JAVA_RULES
from scanner.rules.html_rules import HTML_RULES

LANGUAGE_RULE_MAP = {
    "python": PYTHON_RULES,
    "javascript": JAVASCRIPT_RULES,
    "php": PHP_RULES,
    "java": JAVA_RULES,
    "html": HTML_RULES,
    "generic": [],
}


def run_rule_scanner(
    code: str,
    language: str,
    custom_rules: List[Dict[str, Any]] | None = None,
    source_name: str = "pasted code",
) -> List[Dict[str, Any]]:
    """
    Run rule-based scanner on code. Returns list of findings.
    """
    lines = code.splitlines()
    findings = []

    lang_rules = LANGUAGE_RULE_MAP.get(language, [])
    all_rules = GENERIC_RULES + lang_rules
    if custom_rules:
        all_rules += custom_rules

    seen = set()  # deduplicate (rule_id, line_no, source_name)

    for rule in all_rules:
        pattern = rule["pattern"]
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue

        for i, line in enumerate(lines, start=1):
            match = compiled.search(line)
            if match:
                key = (rule["id"], i, source_name)
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "vulnerability_name": rule["name"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "cwe": rule["cwe"],
                    "owasp_category": rule["owasp"],
                    "affected_line": i,
                    "evidence": line.strip()[:200],
                    "explanation": rule["explanation"],
                    "secure_recommendation": rule["recommendation"],
                    "detection_source": rule.get("detection_source", "custom_rule"),
                    "rule_id": rule["id"],
                    "source_file": source_name,
                })

    return findings


# feedback-memory scanner removed during cleanup


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings based on vulnerability name, line number, and source file."""
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("vulnerability_name"),
            f.get("affected_line"),
            f.get("source_file", "pasted code"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def sort_findings(findings: List[Dict]) -> List[Dict]:
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
