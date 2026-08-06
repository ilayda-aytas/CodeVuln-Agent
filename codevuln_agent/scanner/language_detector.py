import re

LANGUAGE_SIGNATURES = {
    "python": [
        r"\bdef\s+\w+\s*\(",
        r"\bimport\s+\w+",
        r"\bfrom\s+\w+\s+import",
        r"print\s*\(",
        r"if\s+__name__\s*==\s*['\"]__main__['\"]",
        r"\bclass\s+\w+\s*[:\(]",
        r"\.py\b",
        r"#.*coding",
        r"\bpip\s+install",
    ],
    "javascript": [
        r"\bconst\s+\w+\s*=",
        r"\blet\s+\w+\s*=",
        r"\bvar\s+\w+\s*=",
        r"\bfunction\s+\w+\s*\(",
        r"=>\s*\{",
        r"\brequire\s*\(['\"]",
        r"\bimport\s+.*from\s+['\"]",
        r"document\.",
        r"console\.log\s*\(",
        r"\bmodule\.exports",
        r"addEventListener\s*\(",
    ],
    "php": [
        r"<\?php",
        r"\$\w+\s*=",
        r"\becho\s+",
        r"\$_(GET|POST|REQUEST|SESSION|COOKIE)",
        r"->",
        r"\barray\s*\(",
        r"\bfunction\s+\w+\s*\(",
    ],
    "java": [
        r"\bpublic\s+(class|interface|enum)\s+",
        r"\bprivate\s+(static\s+)?\w+\s+\w+",
        r"\bSystem\.out\.print",
        r"\bimport\s+java\.",
        r"@Override",
        r"\bpublic\s+static\s+void\s+main",
        r"\bString\[\]\s+args",
        r"new\s+\w+\s*\(",
    ],
    "html": [
        r"<!DOCTYPE\s+html",
        r"<html",
        r"<body",
        r"<head",
        r"<div",
        r"<form",
        r"<script",
        r"<style",
        r"<input",
    ],
}


def detect_language(code: str) -> str:
    """
    Detect programming language from code content.
    Returns: 'python', 'javascript', 'php', 'java', 'html', or 'generic'
    """
    code_lower = code.lower()
    scores = {lang: 0 for lang in LANGUAGE_SIGNATURES}

    for lang, patterns in LANGUAGE_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                scores[lang] += 1

    best_lang = max(scores, key=scores.get)
    if scores[best_lang] == 0:
        return "generic"
    return best_lang
