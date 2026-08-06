import subprocess
import sys
import shutil
import importlib.util
import json
import tempfile
import os
import re
from typing import List, Dict, Any

SEMGREP_AVAILABLE = None


def get_semgrep_command() -> List[str]:
    # Prefer the `semgrep` CLI on PATH
    exe = shutil.which("semgrep")
    if exe:
        return [exe]

    # Try to locate the semgrep package installation and the sibling Scripts folder
    try:
        spec = importlib.util.find_spec("semgrep")
        if spec and spec.origin:
            package_dir = os.path.dirname(spec.origin)
            site_packages = os.path.dirname(package_dir)
            python_root = os.path.dirname(site_packages)
            scripts_dir = os.path.join(python_root, "Scripts")
            # Common executable names on Windows and Unix
            candidates = [
                os.path.join(scripts_dir, "pysemgrep.exe"),
                os.path.join(scripts_dir, "pysemgrep"),
                os.path.join(scripts_dir, "semgrep.exe"),
                os.path.join(scripts_dir, "semgrep"),
            ]
            for c in candidates:
                if os.path.isfile(c):
                    return [c]
    except Exception:
        pass

    # Fallback to running as a module with the current Python
    return [sys.executable, "-m", "semgrep"]


def is_semgrep_available() -> bool:
    global SEMGREP_AVAILABLE
    if SEMGREP_AVAILABLE is not None:
        return SEMGREP_AVAILABLE

    candidates = []
    try:
        cmd = get_semgrep_command()
        if cmd:
            candidates.append(cmd)
    except Exception:
        pass

    candidates.extend([
        ["semgrep"],
        ["pysemgrep"],
        [sys.executable, "-m", "semgrep"],
    ])

    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            output = f"{result.stdout}\n{result.stderr}".lower()
            if result.returncode == 0 and "no module named semgrep" not in output:
                SEMGREP_AVAILABLE = True
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    SEMGREP_AVAILABLE = False
    return False


LANGUAGE_RULESETS = {
    # Optional online Semgrep registry packs. The default scanner path uses
    # local rules below so Semgrep still works without registry/network access.
    "python": "p/python",
    "javascript": "p/javascript",
    "php": "p/php",
    "java": "p/java",
    "generic": "p/secrets",
}

LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "php": ".php",
    "java": ".java",
    "html": ".html",
    "generic": ".txt",
}

SEMGREP_SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}

LOCAL_SEMGREP_CONFIG = r"""
rules:
  - id: codevuln.python.os-system
    languages: [python]
    severity: ERROR
    message: os.system executes shell commands and can lead to command injection.
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
    pattern: os.system(...)

  - id: codevuln.python.subprocess-shell-true
    languages: [python]
    severity: ERROR
    message: subprocess with shell=True can expose command injection risk.
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
    pattern-either:
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
      - pattern: subprocess.run(..., shell=True, ...)

  - id: codevuln.python.pickle-load
    languages: [python]
    severity: ERROR
    message: Loading pickle data from untrusted input can cause code execution.
    metadata:
      cwe: ["CWE-502"]
      owasp: ["A08:2021 - Software and Data Integrity Failures"]
    pattern-either:
      - pattern: pickle.load(...)
      - pattern: pickle.loads(...)

  - id: codevuln.python.yaml-unsafe-load
    languages: [python]
    severity: WARNING
    message: yaml.load without SafeLoader can deserialize unsafe objects.
    metadata:
      cwe: ["CWE-502"]
      owasp: ["A08:2021 - Software and Data Integrity Failures"]
    pattern: yaml.load(...)

  - id: codevuln.python.flask-debug
    languages: [python]
    severity: WARNING
    message: Flask debug mode should not be enabled in production.
    metadata:
      cwe: ["CWE-489"]
      owasp: ["A05:2021 - Security Misconfiguration"]
    pattern: app.run(..., debug=True, ...)

  - id: codevuln.javascript.eval
    languages: [javascript, typescript]
    severity: ERROR
    message: eval executes dynamic code and can lead to injection vulnerabilities.
    metadata:
      cwe: ["CWE-95"]
      owasp: ["A03:2021 - Injection"]
    pattern: eval(...)

  - id: codevuln.javascript.inner-html
    languages: [javascript, typescript]
    severity: WARNING
    message: Assigning to innerHTML can introduce cross-site scripting.
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
    pattern: $EL.innerHTML = $VALUE

  - id: codevuln.javascript.child-process-exec
    languages: [javascript, typescript]
    severity: ERROR
    message: child_process.exec executes shell commands and can lead to command injection.
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
    pattern-either:
      - pattern: child_process.exec(...)
      - pattern: exec(...)

  - id: codevuln.php.shell-exec
    languages: [php]
    severity: ERROR
    message: Shell execution functions can lead to command injection.
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
    pattern-either:
      - pattern: shell_exec(...)
      - pattern: system(...)
      - pattern: exec(...)
      - pattern: passthru(...)

  - id: codevuln.php.eval
    languages: [php]
    severity: ERROR
    message: eval executes dynamic code and can lead to code injection.
    metadata:
      cwe: ["CWE-95"]
      owasp: ["A03:2021 - Injection"]
    pattern: eval(...)

  - id: codevuln.java.runtime-exec
    languages: [java]
    severity: ERROR
    message: Runtime command execution can lead to command injection.
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
    pattern: Runtime.getRuntime().exec(...)
"""


def _write_local_semgrep_config() -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False, encoding="utf-8"
    ) as f:
        f.write(LOCAL_SEMGREP_CONFIG)
        return f.name


def run_semgrep(code: str, language: str, config: str | None = None) -> List[Dict[str, Any]]:
    """
    Run Semgrep on the provided code. Returns empty list if Semgrep is not installed.
    """
    if not is_semgrep_available():
        return []

    ext = LANGUAGE_EXTENSIONS.get(language, ".txt")
    config_path = None
    ruleset = config
    if not ruleset:
        config_path = _write_local_semgrep_config()
        ruleset = config_path
    if config == "p/python" and language != "python":
        # If the user selected the Python rule pack but the code is not Python,
        # fall back to the language-specific Semgrep pack so Semgrep still runs.
        ruleset = LANGUAGE_RULESETS.get(language, "p/default")

    findings = []
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        tmp_path = f.name

    try:
        result = subprocess.run(
            get_semgrep_command() + ["--quiet", "--config", ruleset, "--json", tmp_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )
        # Semgrep may return code 2 when run as a module with deprecation warnings.
        if result.returncode not in (0, 1, 2):
            if config:
                return run_semgrep(code, language)
            return []

        stdout = result.stdout.strip()
        if not stdout:
            # If no JSON output came through stdout, try stderr fallback.
            stdout = result.stderr.strip()

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # Attempt to extract a JSON object from noisy output.
            match = re.search(r"\{.*\}", stdout, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    data = None
            else:
                data = None

            if data is None:
                if config:
                    return run_semgrep(code, language)
                return []

        if not isinstance(data, dict):
            if config:
                return run_semgrep(code, language)
            return []

        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            cwe_list = meta.get("cwe", [])
            cwe = cwe_list[0] if cwe_list else "N/A"
            owasp_list = meta.get("owasp", [])
            owasp = owasp_list[0] if owasp_list else "N/A"

            findings.append({
                "vulnerability_name": r.get("check_id", "Semgrep Finding").split(".")[-1].replace("-", " ").title(),
                "severity": SEMGREP_SEVERITY_MAP.get(extra.get("severity", ""), "Medium"),
                "confidence": "Medium",
                "cwe": cwe,
                "owasp_category": owasp,
                "affected_line": r.get("start", {}).get("line", 0),
                "evidence": extra.get("lines", "").strip()[:200],
                "explanation": extra.get("message", "Semgrep detected a potential vulnerability."),
                "secure_recommendation": meta.get("fix", "Review and remediate this finding per Semgrep guidance."),
                "detection_source": "semgrep",
                "rule_id": r.get("check_id", ""),
            })
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass

    return findings
