import subprocess
import sys
import json
import tempfile
import os
from typing import List, Dict, Any

BANDIT_AVAILABLE = None


def is_bandit_available() -> bool:
    global BANDIT_AVAILABLE
    if BANDIT_AVAILABLE is not None:
        return BANDIT_AVAILABLE
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "--version"],
            capture_output=True, text=True, timeout=10
        )
        BANDIT_AVAILABLE = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        BANDIT_AVAILABLE = False
    return BANDIT_AVAILABLE


BANDIT_SEVERITY_MAP = {
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

BANDIT_CWE_MAP = {
    "B101": "CWE-617",
    "B102": "CWE-78",
    "B103": "CWE-732",
    "B104": "CWE-605",
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-377",
    "B110": "CWE-391",
    "B112": "CWE-391",
    "B201": "CWE-94",
    "B202": "CWE-94",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-95",
    "B308": "CWE-330",
    "B310": "CWE-918",
    "B311": "CWE-330",
    "B312": "CWE-1188",
    "B313": "CWE-611",
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-319",
    "B322": "CWE-676",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B325": "CWE-338",
    "B401": "CWE-319",
    "B402": "CWE-319",
    "B403": "CWE-502",
    "B404": "CWE-78",
    "B405": "CWE-611",
    "B411": "CWE-1188",
    "B501": "CWE-295",
    "B502": "CWE-326",
    "B503": "CWE-326",
    "B504": "CWE-326",
    "B505": "CWE-326",
    "B506": "CWE-502",
    "B507": "CWE-295",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-155",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B701": "CWE-94",
    "B702": "CWE-79",
    "B703": "CWE-79",
}


def run_bandit(code: str) -> List[Dict[str, Any]]:
    """
    Run Bandit on Python code. Returns empty list if Bandit is not installed.
    """
    if not is_bandit_available():
        return []

    findings = []
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", tmp_path],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout)
        for issue in data.get("results", []):
            test_id = issue.get("test_id", "")
            cwe = BANDIT_CWE_MAP.get(test_id, "N/A")
            findings.append({
                "vulnerability_name": issue.get("test_name", "Bandit Finding").replace("_", " ").title(),
                "severity": BANDIT_SEVERITY_MAP.get(issue.get("issue_severity", "MEDIUM"), "Medium"),
                "confidence": BANDIT_SEVERITY_MAP.get(issue.get("issue_confidence", "MEDIUM"), "Medium"),
                "cwe": cwe,
                "owasp_category": "N/A (see Bandit docs)",
                "affected_line": issue.get("line_number", 0),
                "evidence": issue.get("code", "").strip()[:200],
                "explanation": issue.get("issue_text", ""),
                "secure_recommendation": f"See Bandit rule {test_id} documentation for remediation guidance.",
                "detection_source": "bandit",
                "rule_id": test_id,
            })
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return findings
