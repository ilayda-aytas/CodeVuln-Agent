import json
from types import SimpleNamespace

import scanner.semgrep_scanner as semgrep_scanner


def test_semgrep_unavailable_when_module_missing(monkeypatch):
    semgrep_scanner.SEMGREP_AVAILABLE = None

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="No module named semgrep",
        )

    monkeypatch.setattr(semgrep_scanner.subprocess, "run", fake_run)

    assert semgrep_scanner.is_semgrep_available() is False


def test_run_semgrep_uses_local_rules_by_default(monkeypatch):
    monkeypatch.setattr(semgrep_scanner, "is_semgrep_available", lambda: True)
    monkeypatch.setattr(semgrep_scanner, "get_semgrep_command", lambda: ["semgrep"])

    def fake_run(cmd, *args, **kwargs):
        assert "--config" in cmd
        config_value = cmd[cmd.index("--config") + 1]
        assert config_value.endswith(".yml")

        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps({
                "results": [{
                    "check_id": "codevuln.python.os-system",
                    "start": {"line": 2},
                    "extra": {
                        "severity": "ERROR",
                        "lines": "os.system(user_input)",
                        "message": "os.system executes shell commands.",
                        "metadata": {
                            "cwe": ["CWE-78"],
                            "owasp": ["A03:2021 - Injection"],
                        },
                    },
                }]
            }),
            stderr="",
        )

    monkeypatch.setattr(semgrep_scanner.subprocess, "run", fake_run)

    findings = semgrep_scanner.run_semgrep("import os\nos.system(user_input)\n", "python")

    assert findings[0]["detection_source"] == "semgrep"
    assert findings[0]["cwe"] == "CWE-78"
