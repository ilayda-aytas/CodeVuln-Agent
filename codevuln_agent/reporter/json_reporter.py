import json
from datetime import datetime
from typing import List, Dict, Any


def generate_json_report(
    findings: List[Dict[str, Any]],
    language: str,
    summary: str = "",
) -> str:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1

    report = {
        "report_metadata": {
            "tool": "CodeVuln Agent",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "language_analyzed": language,
            "disclaimer": (
                "This report is produced by an automated security assistant. "
                "It may contain false positives or false negatives. "
                "Manual review by a qualified security engineer is recommended."
            ),
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": counts,
            "executive_summary": summary,
        },
        "findings": findings,
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
