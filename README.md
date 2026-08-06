# CodeVuln Agent

CodeVuln Agent is a Streamlit-based SAST-style security analysis assistant. It helps developers scan pasted code or uploaded source files, identify suspicious vulnerability patterns, review findings in a web UI, and export structured reports.

The project combines local regex-based security rules with optional Semgrep and Bandit integrations. It can also use Groq for optional LLM-assisted explanations and executive summaries.

## Features

- Scan pasted source code or upload one or more files.
- Auto-detect common languages: Python, JavaScript, PHP, Java, HTML, and generic text.
- Run built-in local security rules from `scanner/rules/`.
- Optionally run Semgrep for pattern-based static analysis.
- Optionally run Bandit for Python-specific security checks.
- Add a custom regex rule from the UI without editing code.
- Filter findings by severity and detection source.
- View severity metrics and detailed finding cards.
- Export reports as JSON, Markdown, and HTML.
- Optionally enhance explanations with Groq LLM support.

## Technology Stack

| Technology | Purpose |
| --- | --- |
| Python 3.11 | Main application and scanner runtime |
| Streamlit | Interactive web interface |
| Pandas | Results table rendering and data formatting |
| Semgrep | Optional multi-language static analysis engine |
| Bandit | Optional Python security scanner |
| Groq SDK | Optional LLM enrichment for summaries and explanations |
| Pytest | Automated tests |
| Docker | Reproducible containerized deployment |

## Project Structure

```text
codevuln_agent/
+-- app.py                         # Streamlit UI and scan orchestration
+-- requirements.txt               # Python dependencies
+-- Dockerfile                     # Container runtime
+-- scanner/
|   +-- language_detector.py       # Language detection helper
|   +-- rule_scanner.py            # Local rule-based scanner
|   +-- semgrep_scanner.py         # Semgrep integration
|   +-- bandit_scanner.py          # Bandit integration
|   +-- rules/                     # Built-in local vulnerability rules
+-- reporter/
|   +-- json_reporter.py           # JSON report generation
|   +-- markdown_reporter.py       # Markdown report generation
|   +-- html_reporter.py           # HTML report generation
+-- agent/
|   +-- llm_agent.py               # Optional Groq-powered enrichment
+-- tests/                         # Pytest tests
```

## Installation

Clone or open the project folder, then install dependencies:

```bash
cd codevuln_agent
python -m pip install -r requirements.txt
```

The `requirements.txt` file includes Streamlit, Pandas, Groq, Bandit, Semgrep, and Pytest.

If Semgrep or Bandit is missing in your active Python environment, install them explicitly:

```bash
python -m pip install semgrep bandit
```

## Running Locally

```bash
python -m streamlit run app.py
```

Open the app in your browser:

```text
http://localhost:8501
```

## Docker Usage

Build the Docker image:

```bash
docker build -t codevuln-agent:latest .
```

Run the container:

```bash
docker run --rm -p 8501:8501 codevuln-agent:latest
```

Then open:

```text
http://localhost:8501
```

## How Scanning Works

1. The app receives pasted code or uploaded files.
2. `language_detector.py` detects the source language when Auto mode is selected.
3. `rule_scanner.py` runs local vulnerability rules.
4. If enabled and available, `semgrep_scanner.py` runs Semgrep.
5. If the language is Python and Bandit is enabled, `bandit_scanner.py` runs Bandit.
6. Findings are deduplicated, sorted by severity, and shown in the Results tab.
7. Reports can be downloaded as JSON, Markdown, or HTML.

## Semgrep Notes

Semgrep is optional. If it is installed, CodeVuln Agent can use it as an additional detection source.

The Semgrep integration includes local fallback rules so basic Semgrep scanning can still work without downloading registry rules from the internet. If Semgrep is not installed in the Python environment running Streamlit, the UI will show it as unavailable.

Check Semgrep manually:

```bash
python -m semgrep --version
```

## Bandit Notes

Bandit is optional and runs only for Python code. It adds Python-specific security findings such as unsafe subprocess usage, hardcoded secrets, insecure deserialization, weak crypto usage, and other common issues.

Check Bandit manually:

```bash
python -m bandit --version
```

## Optional Groq LLM Enrichment

The Groq API key field in the sidebar is optional. When enabled, the app can enrich findings with clearer explanations and generate an executive summary.

Do not commit real API keys or secrets to the repository.

## Testing

Run the test suite:

```bash
python -m pytest
```

The tests cover core rule scanning behavior and Semgrep integration safeguards.

## Limitations

- This is a pre-analysis assistant, not a replacement for a professional security audit.
- Findings can include false positives or false negatives.
- Semgrep and Bandit results depend on whether those tools are installed in the same Python environment used to run Streamlit.
- LLM output should be reviewed manually before being used in a security report.

