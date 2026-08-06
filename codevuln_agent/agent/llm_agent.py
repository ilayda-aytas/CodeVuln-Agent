import json
import os
import re
from typing import List, Dict, Any, Optional

try:
    from groq import Groq
    GROQ_SDK_AVAILABLE = True
except ImportError:
    GROQ_SDK_AVAILABLE = False


def is_llm_available(api_key: Optional[str] = None) -> bool:
    key = api_key or os.environ.get("GROQ_API_KEY", "")
    return GROQ_SDK_AVAILABLE and bool(key.strip())


def enhance_findings_with_llm(
    code: str,
    findings: List[Dict[str, Any]],
    language: str,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Use Groq LLM to enrich finding explanations and recommendations.
    The LLM does NOT discover new vulnerabilities — it only improves existing findings.
    Returns enriched findings list.
    """
    if not findings:
        return findings
    if not is_llm_available(api_key):
        return findings

    key = api_key or os.environ.get("GROQ_API_KEY", "")
    client = Groq(api_key=key)

    findings_summary = []
    for i, f in enumerate(findings[:10]):  # limit to 10 to stay within context
        findings_summary.append(
            f"{i+1}. [{f['severity']}] {f['vulnerability_name']} "
            f"at line {f['affected_line']} — Evidence: {f['evidence'][:100]}"
        )

    prompt = f"""You are a senior security engineer reviewing static analysis findings.

Language: {language}
Code snippet (first 2000 chars):
```
{code[:2000]}
```

Detected findings from rule-based scanner:
{chr(10).join(findings_summary)}

For each finding, provide:
1. A clearer, context-aware explanation (2-3 sentences)
2. A specific, actionable fix recommendation for this code

Respond ONLY as a JSON array with this structure:
[
  {{
    "index": 1,
    "explanation": "...",
    "secure_recommendation": "..."
  }},
  ...
]

Important: Do NOT add new findings. Only enrich the existing ones listed above.
"""

    try:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content.strip()

        # Extract JSON array
        match = re.search(r'\[[\s\S]*\]', raw)
        if not match:
            import sys
            print("[LLM] Warning: No JSON array found in LLM response. Using original findings.", file=sys.stderr)
            return findings

        enriched = json.loads(match.group())
        for item in enriched:
            idx = item.get("index", 0) - 1
            if 0 <= idx < len(findings):
                if item.get("explanation"):
                    findings[idx]["explanation"] = item["explanation"]
                    findings[idx]["detection_source"] = "llm_assisted_explanation"
                if item.get("secure_recommendation"):
                    findings[idx]["secure_recommendation"] = item["secure_recommendation"]
    except json.JSONDecodeError as e:
        import sys
        print(f"[LLM] JSON parse error: {e}. Using original findings.", file=sys.stderr)
    except (KeyError, IndexError, TypeError) as e:
        import sys
        print(f"[LLM] Data structure error: {e}. Using original findings.", file=sys.stderr)
    except Exception as e:
        import sys
        print(f"[LLM] Unexpected error enriching findings: {type(e).__name__}: {e}", file=sys.stderr)

    return findings


def generate_executive_summary(
    findings: List[Dict[str, Any]],
    language: str,
    api_key: Optional[str] = None,
) -> str:
    """Generate a human-readable executive summary of findings."""
    if not findings:
        return "No vulnerabilities were detected by the rule-based scanner."
    if not is_llm_available(api_key):
        return _basic_summary(findings, language)

    key = api_key or os.environ.get("GROQ_API_KEY", "")
    client = Groq(api_key=key)

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    vuln_names = list(set(f["vulnerability_name"] for f in findings))

    prompt = f"""You are a security analyst writing an executive summary for a code review report.

Language analyzed: {language}
Total findings: {len(findings)}
Severity breakdown: {counts}
Vulnerability types: {', '.join(vuln_names[:10])}

Write a concise (3-5 sentence) executive summary for a non-technical stakeholder.
Mention the risk level, most critical issues, and whether immediate action is needed.
Do not use markdown headers — plain paragraph only.
"""

    try:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=300,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        import sys
        print(f"[LLM] Error generating executive summary: {type(e).__name__}: {e}. Using fallback.", file=sys.stderr)
        return _basic_summary(findings, language)


def _basic_summary(findings: List[Dict], language: str) -> str:
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = [f"{v}: {k}" for k, v in counts.items()]
    return (
        f"Analyzed {language} code. Found {len(findings)} potential issue(s): "
        + ", ".join(parts) + ". "
        + "Review findings carefully. False positives may be present."
    )
