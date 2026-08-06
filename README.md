# CodeVuln Agent

CodeVuln Agent is a Python and Streamlit based SAST-style security analysis assistant for detecting potential vulnerabilities in source code.

The application combines local security rules, Semgrep, Bandit, and optional Groq LLM support. Users can paste code, upload source files, define custom regex rules, filter findings, inspect detailed vulnerability results, and export reports as JSON, Markdown, or HTML.

## Features

- Analyze Python, JavaScript, PHP, Java, HTML, and generic source code
- Streamlit-based web interface
- Local rule-based vulnerability scanning
- Optional Semgrep static analysis integration
- Optional Bandit security scanning for Python code
- Custom regex rule support from the UI
- Filtering by severity and detection source
- Detailed vulnerability finding view
- JSON, Markdown, and HTML report exports
- Optional Groq LLM-powered explanations and executive summaries

## Technology Stack

| Technology | Purpose |
| --- | --- |
| Python | Main backend and analysis logic |
| Streamlit | Web user interface |
| Semgrep | Static analysis and pattern-based security scanning |
| Bandit | Python-specific security analysis |
| Pandas | Rendering findings in table format |
| Groq SDK | Optional LLM-powered explanations |
| Pytest | Test framework |
| Docker | Containerized execution |


### 1. Code Analysis Screen

Users can paste source code or upload files for analysis. Semgrep, Bandit, and optional LLM enhancement can be controlled from the sidebar.

<img width="1911" height="812" alt="1" src="https://github.com/user-attachments/assets/0519757b-2c75-4ad2-8bfb-3b28735d903c" />

### 2. Results Summary

After the scan is completed, the application shows the detected language, total number of findings, severity distribution, and executive summary.

![Results Summary](docs/images/results-summary.png)

### 3. Findings Table

Detected vulnerabilities are displayed in a structured table with severity, vulnerability name, affected line, CWE, OWASP category, detection source, and confidence.

![Findings Table](docs/images/findings-table.png)

### 4. Detailed Finding View

Each finding can be expanded to inspect the affected line, evidence, explanation, recommendation, confidence, CWE, OWASP category, and detection source.

![Detailed Finding](docs/images/detailed-finding.png)

### 5. Report Export

Analysis results can be exported as JSON, Markdown, or HTML reports.

![Export Report](docs/images/export-report.png)

### 6. Custom Regex Rule

Users can define a custom regex-based security rule directly from the UI. This is useful for project-specific patterns or quick checks.

![Custom Rule](docs/images/custom-rule.png)

## Project Structure

```text
codevuln_agent/
+-- app.py
+-- requirements.txt
+-- Dockerfile
+-- scanner/
|   +-- language_detector.py
|   +-- rule_scanner.py
|   +-- semgrep_scanner.py
|   +-- bandit_scanner.py
|   +-- rules/
+-- reporter/
|   +-- json_reporter.py
|   +-- markdown_reporter.py
|   +-- html_reporter.py
+-- agent/
|   +-- llm_agent.py
+-- tests/
```

## Installation

```bash
git clone https://github.com/ilayda-aytas/codevuln-agent.git
cd codevuln-agent
python -m pip install -r requirements.txt
```

## Running the Application

```bash
python -m streamlit run app.py
```

Open the application in your browser:

```text
http://localhost:8501
```

## Semgrep Usage

If Semgrep is installed, the application uses it as an additional detection source.

Check Semgrep:

```bash
python -m semgrep --version
```

Install Semgrep if missing:

```bash
python -m pip install semgrep
```

## Bandit Usage

Bandit runs only for Python code and helps detect Python-specific security issues.

Check Bandit:

```bash
python -m bandit --version
```

Install Bandit if missing:

```bash
python -m pip install bandit
```

## Running with Docker

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

## Running Tests

```bash
python -m pytest
```


