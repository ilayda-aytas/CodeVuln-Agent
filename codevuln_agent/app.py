import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
import pandas as pd
import base64

from scanner.language_detector import detect_language
from scanner.rule_scanner import (
    run_rule_scanner,
    deduplicate_findings,
    sort_findings,
)
from scanner.semgrep_scanner import run_semgrep, is_semgrep_available
from scanner.bandit_scanner import run_bandit, is_bandit_available
from agent.llm_agent import (
    is_llm_available,
    enhance_findings_with_llm,
    generate_executive_summary,
)

from reporter.json_reporter import generate_json_report
from reporter.markdown_reporter import generate_markdown_report
from reporter.html_reporter import generate_html_report

# ─── Page config ────────────────────────────────────────────────────────────
logo_path = "logo.jpg"
page_icon = logo_path if os.path.exists(logo_path) else "🛡️"
st.set_page_config(
    page_title="CodeVuln Agent",
    page_icon=page_icon,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── UI text labels ───────────────────────────────────────────────────────────
LABELS = {
    "subtitle": "Automated code security analysis assistant — SAST-style vulnerability detection",
    "executive_summary": "Executive Summary",
    "tabs": ["Analyze Code", "Results", "Custom Rule"],
    "paste_code": "Paste your code",
    "upload_prompt": "Upload one or more source files for multi-file scanning",
    "analyze_button": "🚀 Analyze Code",
    "tool_status": "Tool Status",
    "semgrep_available": "available",
    "semgrep_not": "not installed",
    "bandit_available": "available",
    "bandit_not": "not installed (Python only)",
    "semgrep_config": "Semgrep config",
    "llm_heading": "LLM Enhancement (Optional)",
    "groq_key": "Groq API Key",
    "enable_llm": "Enable LLM enhancement",
    "scan_options": "Scan Options",
    "use_semgrep": "Use Semgrep",
    "use_bandit": "Use Bandit (Python only)",
    "custom_rule_heading": "Custom regex rule (optional)",
    "rule_name": "Rule name",
    "regex_pattern": "Regex pattern",
    "severity": "Severity",
    "cwe": "CWE",
    "owasp": "OWASP category",
    "explanation": "Explanation",
    "recommendation": "Recommendation",
    "run_first": "ℹ️ Run an analysis first in the Analyze Code tab.",
    "no_findings": "🎉 No vulnerabilities detected. The code appears clean per current rule set.",
    "findings": "Findings",
    "filter_severity": "Filter by severity",
    "filter_source": "Filter by detection source",
    "export_report": "Export Report",
    "download_json": "📥 Download JSON Report",
    "download_md": "📥 Download Markdown Report",
    "download_html": "📥 Download HTML Report",
    "disclaimer": "This report is produced by an automated security assistant and may contain false positives or false negatives.",
    "groq_help": "Provide a Groq API key to get AI-enhanced explanations. Leave empty for rule-only mode.",
    "custom_default_explanation": "This custom regex detected a potential issue.",
    "custom_default_recommendation": "Review and update the code to fix this issue.",
    "switch_to_results": "👉 Switch to the **Results** tab to view detailed findings.",
    "notice": "Notice:",
    "no_filters_match": "No findings match the selected filters.",
    "detailed_findings": "Detailed Findings",
    "settings": "Settings",
    "pre_analysis_assistance": "This tool provides pre-analysis assistance. False positives and negatives may occur. Not a substitute for manual review.",
    "or_upload": "Or upload source files",
    "label_language": "Language",
    "llm_ready": "LLM ready",
    "llm_not_available": "LLM not available (missing key or groq SDK)",
    "custom_rule_description": "Define a single custom regex rule that will be applied during code analysis. This is useful for project-specific patterns or quick checks.",
    "please_paste_or_upload": "⚠️ Please paste some code or upload files before analyzing.",
    "disclaimer_label": "Disclaimer:",
    "summary_no_findings": "No vulnerabilities detected.",
    "semgrep_help_long": "Select a Semgrep built-in rule pack. `p/owasp` is more security-focused but may require internet to download.",
    "upload_instructions": "If multiple files are uploaded, the scan runs on all files together. Otherwise the pasted code will be analyzed.",
    "label_severity": "Severity",
    "label_cwe": "CWE",
    "label_confidence": "Confidence",
    "label_owasp": "OWASP Category",
    "label_affected_line": "Affected Line",
    "label_detection_source": "Detection Source",
    "label_evidence": "Evidence (flagged line):",
    "label_explanation": "Explanation:",
    "label_secure_recommendation": "Secure Recommendation:",
    "analysis_complete_none": "🎉 Analysis complete: No vulnerabilities detected by rule-based scanner.",
    "analysis_complete_some": "🚨 Analysis complete: {count} potential issue(s) detected. Check the Results tab below.",
    "language_detected": "Language detected:",
    "total": "TOTAL",
    "label_vulnerability": "Vulnerability",
    "label_line": "Line",
    "label_source": "Source",
    "label_severity_column": "Severity",
    "label_confidence": "Confidence",
    "label_severity_critical": "Critical",
    "label_severity_high": "High",
    "label_severity_medium": "Medium",
    "label_severity_low": "Low",
}

# Severity translation helper
SEVERITY_KEYS = ["Critical", "High", "Medium", "Low"]

def translate_severity(severity: str) -> str:
    return severity

def t(key: str) -> str:
    return LABELS.get(key, key)


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    # Embed logo as base64 data URI to avoid external path issues
    sidebar_logo_html = ""
    if os.path.exists(logo_path):
        try:
            with open(logo_path, "rb") as _f:
                _b = _f.read()
            _b64 = base64.b64encode(_b).decode("utf-8")
            _ext = os.path.splitext(logo_path)[1].lower().lstrip('.')
            _mime = f"image/{'jpeg' if _ext in ('jpg','jpeg') else _ext}"
            # increase embedded logo size to 48px for better visibility in sidebar
            sidebar_logo_html = f'<img src="data:{_mime};base64,{_b64}" style="width:48px;height:48px;vertical-align:middle;margin-right:12px;">'
        except Exception:
            sidebar_logo_html = ""

    st.markdown(f'<h2 class="neon-sidebar">{sidebar_logo_html}CodeVuln Agent</h2>', unsafe_allow_html=True)
    st.markdown("---")

    # Tool status
    st.markdown("### " + t("tool_status"))
    semgrep_ok = is_semgrep_available()
    bandit_ok = is_bandit_available()

    st.markdown(f"**Semgrep:** {'✅ ' + t('semgrep_available') if semgrep_ok else '❌ ' + t('semgrep_not')}")
    st.markdown(f"**Bandit:** {'✅ ' + t('bandit_available') if bandit_ok else '❌ ' + t('bandit_not')}")
    st.markdown("---")

    semgrep_config = None

    # Groq API
    st.markdown("### " + t("llm_heading"))
    groq_key = st.text_input(
        t("groq_key"),
        type="password",
        placeholder="gsk_...",
        help=t("groq_help"),
    )
    use_llm = st.checkbox(t("enable_llm"), value=bool(groq_key))
    llm_ready = use_llm and is_llm_available(groq_key)
    if use_llm:
        if llm_ready:
            st.success(t("llm_ready"))
        else:
            st.warning(t("llm_not_available"))

    # Options
    st.markdown("### " + t("scan_options"))
    use_semgrep = st.checkbox(t("use_semgrep"), value=semgrep_ok, disabled=not semgrep_ok, key="use_semgrep")
    use_bandit = st.checkbox(t("use_bandit"), value=bandit_ok, disabled=not bandit_ok, key="use_bandit")

    st.markdown("---")

# ─── Main content ─────────────────────────────────────────────────────────────
st.markdown('<h1 class="neon-title">CodeVuln Agent</h1>', unsafe_allow_html=True)
st.markdown(f'<p class="neon-subtitle">{t("subtitle")}</p>', unsafe_allow_html=True)

tab_labels = t("tabs")
tab_scan, tab_results, tab_custom = st.tabs(tab_labels)

# ── Session state init ──
if "findings" not in st.session_state:
    st.session_state.findings = []
if "language" not in st.session_state:
    st.session_state.language = "generic"
if "summary" not in st.session_state:
    st.session_state.summary = ""
if "scanned" not in st.session_state:
    st.session_state.scanned = False

# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — Analyze Code
# ════════════════════════════════════════════════════════════════════════════
with tab_scan:
    col_code, col_opts = st.columns([3, 1])

    with col_opts:
        st.markdown("### " + t("settings"))
        language_choice = st.selectbox(
            t("label_language"),
            ["Auto", "Python", "JavaScript", "PHP", "HTML", "Java", "Generic"],
        )
        st.markdown("")
        st.markdown(
            f'<div class="disclaimer-box"><b>{t("notice")}</b> {t("pre_analysis_assistance")}</div>',
            unsafe_allow_html=True,
        )

    with col_code:
        st.markdown("### " + t("paste_code"))
        code_input = st.text_area(
            label="code_input_hidden",
            label_visibility="collapsed",
            placeholder="# Paste your code here...\n\nimport os\nos.system('ls ' + user_input)",
            height=240,
            key="code_input",
        )

        st.markdown("### " + t("or_upload"))
        uploaded_files = st.file_uploader(
            t("upload_prompt"),
            type=["py", "js", "php", "java", "html", "txt"],
            accept_multiple_files=True,
        )

        st.markdown(t("upload_instructions"))

    st.markdown("")
    analyze_btn = st.button(t("analyze_button"), type="primary", use_container_width=False, key="analyze_btn")

# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — Custom Rule Definition
# ════════════════════════════════════════════════════════════════════════════
with tab_custom:
    st.markdown("### " + t("custom_rule_heading"))
    st.markdown(t("custom_rule_description"))
    custom_rule_name = st.text_input(t("rule_name"), key="custom_rule_name")
    custom_rule_pattern = st.text_input(t("regex_pattern"), key="custom_rule_pattern")
    custom_rule_severity = st.selectbox(
        t("severity"),
        ["Critical", "High", "Medium", "Low"],
        index=1,
        key="custom_rule_severity",
    )
    custom_rule_cwe = st.text_input(t("cwe"), key="custom_rule_cwe")
    custom_rule_owasp = st.text_input(t("owasp"), key="custom_rule_owasp")
    custom_rule_explanation = st.text_area(t("explanation"), height=80, key="custom_rule_explanation")
    custom_rule_recommendation = st.text_area(t("recommendation"), height=80, key="custom_rule_recommendation")

# ════════════════════════════════════════════════════════════════════════════
# SCAN EXECUTION LOGIC WITH SPINNER (Dönme İşareti)
# ════════════════════════════════════════════════════════════════════════════
if analyze_btn:
    # Dönüş / Yükleniyor spinner efekti
    with st.spinner("🔍 Code Analysis in Progress... Please wait while vulnerabilities are detected..."):
        scan_source_text = ""
        findings = []

        if uploaded_files:
            for uploaded_file in uploaded_files:
                try:
                    file_bytes = uploaded_file.read()
                    file_text = file_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                scan_source_text = file_text
                if language_choice == "Auto":
                    file_lang = detect_language(file_text)
                else:
                    file_lang = language_choice.lower()

                if custom_rule_name and custom_rule_pattern:
                    custom_rules = [{
                        "id": f"custom_{custom_rule_name.lower().replace(' ', '_')}",
                        "name": custom_rule_name,
                        "pattern": custom_rule_pattern,
                        "severity": custom_rule_severity,
                        "confidence": "Medium",
                        "cwe": custom_rule_cwe or "N/A",
                        "owasp": custom_rule_owasp or "N/A",
                        "explanation": custom_rule_explanation or t("custom_default_explanation"),
                        "recommendation": custom_rule_recommendation or t("custom_default_recommendation"),
                        "detection_source": "custom_rule",
                    }]
                else:
                    custom_rules = []

                findings += run_rule_scanner(
                    file_text,
                    file_lang,
                    custom_rules=custom_rules,
                    source_name=uploaded_file.name,
                )

                # Optional Semgrep
                if use_semgrep and semgrep_ok:
                    findings.extend(run_semgrep(file_text, file_lang, semgrep_config))

                # Optional Bandit
                if use_bandit and bandit_ok and file_lang == "python":
                    findings.extend(run_bandit(file_text))

            lang = language_choice.lower() if language_choice != "Auto" else "mixed"
        else:
            code = code_input.strip()
            scan_source_text = code
            if not code:
                st.warning(t("please_paste_or_upload"))
                st.stop()

            # Language detection
            if language_choice == "Auto":
                lang = detect_language(code)
            else:
                lang = language_choice.lower()

            if custom_rule_name and custom_rule_pattern:
                custom_rules = [{
                    "id": f"custom_{custom_rule_name.lower().replace(' ', '_')}",
                    "name": custom_rule_name,
                    "pattern": custom_rule_pattern,
                    "severity": custom_rule_severity,
                    "confidence": "Medium",
                    "cwe": custom_rule_cwe or "N/A",
                    "owasp": custom_rule_owasp or "N/A",
                    "explanation": custom_rule_explanation or t("custom_default_explanation"),
                    "recommendation": custom_rule_recommendation or t("custom_default_recommendation"),
                    "detection_source": "custom_rule",
                }]
            else:
                custom_rules = []

            # Rule-based scan
            findings = run_rule_scanner(
                code,
                lang,
                custom_rules=custom_rules,
                source_name="pasted code",
            )

            # Optional Semgrep
            if use_semgrep and semgrep_ok:
                findings.extend(run_semgrep(code, lang, semgrep_config))

            # Optional Bandit (Python only)
            if use_bandit and bandit_ok and lang == "python":
                findings.extend(run_bandit(code))

        # Deduplicate + sort
        findings = deduplicate_findings(findings)
        findings = sort_findings(findings)

        # Optional LLM enrichment
        if llm_ready and findings:
            findings = enhance_findings_with_llm(scan_source_text, findings, lang, groq_key)
            summary = generate_executive_summary(findings, lang, groq_key)
        else:
            from agent.llm_agent import _basic_summary
            summary = _basic_summary(findings, lang) if findings else t("summary_no_findings")

        st.session_state.findings = findings
        st.session_state.language = lang
        st.session_state.summary = summary
        st.session_state.scanned = True
        st.session_state.results_filter_sev = SEVERITY_KEYS
        st.session_state.results_filter_src = sorted(set(f.get("detection_source", "") for f in findings))

    # Scan completion feedback
    count = len(findings)
    if count == 0:
        st.success(t("analysis_complete_none"))
    else:
        st.error(t("analysis_complete_some").format(count=count))
    st.info(t("switch_to_results"))


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — Results
# ════════════════════════════════════════════════════════════════════════════
with tab_results:
    findings = st.session_state.findings
    language = st.session_state.language
    summary = st.session_state.summary

    if not st.session_state.scanned:
        st.info(t("run_first"))
    else:
        # ── Metric cards ──
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            counts[sev] = counts.get(sev, 0) + 1

        st.markdown(f"### {t('language_detected')} `{language.upper()}`")
        st.markdown("")

        m0, m1, m2, m3, m4 = st.columns(5)
        with m0:
            st.markdown(
                f'<div class="metric-card"><div class="metric-number metric-total">{len(findings)}</div><div class="metric-label">{t("total")}</div></div>',
                unsafe_allow_html=True,
            )
        for col, sev, cls in zip(
            [m1, m2, m3, m4],
            ["Critical", "High", "Medium", "Low"],
            ["critical", "high", "medium", "low"],
        ):
            with col:
                st.markdown(
                    f'<div class="metric-card"><div class="metric-number metric-{cls}">{counts[sev]}</div>'
                    f'<div class="metric-label">{sev.upper()}</div></div>',
                    unsafe_allow_html=True,
                )

        st.markdown("")

        # ── Executive summary ──
        if summary:
            st.markdown("### " + t("executive_summary"))
            st.info(summary)

        # ── Severity filter ──
        st.markdown("### " + t("findings"))
        if findings:
            filter_sev = st.multiselect(
                t("filter_severity"),
                SEVERITY_KEYS,
                default=SEVERITY_KEYS,
                format_func=translate_severity,
            )
            filter_src_options = sorted(set(f.get("detection_source", "") for f in findings))
            filter_src = st.multiselect(
                t("filter_source"),
                filter_src_options,
                default=filter_src_options,
            )

            filtered = [
                f for f in findings
                if f.get("severity") in filter_sev
                and f.get("detection_source") in filter_src
            ]
            
            if not filtered:
                st.warning(t("no_filters_match"))
            else:
                df_data = []
                for i, f in enumerate(filtered, 1):
                    sev = f.get("severity", "Low")
                    df_data.append({
                        "#": i,
                        t("label_severity_column"): translate_severity(sev),
                        t("label_vulnerability"): f.get("vulnerability_name", ""),
                        t("label_line"): f.get("affected_line", ""),
                        t("label_cwe"): f.get("cwe", ""),
                        t("label_owasp"): f.get("owasp_category", ""),
                        t("label_source"): f.get("detection_source", ""),
                        t("label_confidence"): f.get("confidence", ""),
                    })

                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True, hide_index=True)

                st.markdown("### " + t("detailed_findings"))
                for i, f in enumerate(filtered, 1):
                    sev = f.get("severity", "Low")
                    vuln_name = f.get("vulnerability_name", "Unknown")
                    line = f.get("affected_line", "?")

                    with st.expander(f"#{i}  [{translate_severity(sev)}]  {vuln_name}  —  {t('label_line')} {line}", expanded=False):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(
                                f'<span class="field-label">{t("label_severity_column")}</span><br>'
                                f'<span class="badge badge-{sev.lower()}">{translate_severity(sev)}</span>',
                                unsafe_allow_html=True,
                            )
                            st.markdown("")
                            st.markdown(
                                f'<span class="field-label">{t("label_cwe")}</span><br>'
                                f'<span class="field-value">{f.get("cwe", "N/A")}</span>',
                                unsafe_allow_html=True,
                            )
                            st.markdown("")
                            st.markdown(
                                f'<span class="field-label">{t("label_confidence")}</span><br>'
                                f'<span class="field-value">{f.get("confidence", "N/A")}</span>',
                                unsafe_allow_html=True,
                            )
                        with col2:
                            st.markdown(
                                f'<span class="field-label">{t("label_owasp")}</span><br>'
                                f'<span class="field-value">{f.get("owasp_category", "N/A")}</span>',
                                unsafe_allow_html=True,
                            )
                            st.markdown("")
                            st.markdown(
                                f'<span class="field-label">{t("label_affected_line")}</span><br>'
                                f'<span class="field-value">{t("label_line")} {f.get("affected_line", "N/A")}</span>',
                                unsafe_allow_html=True,
                            )
                            st.markdown("")
                            st.markdown(
                                f'<span class="field-label">{t("label_detection_source")}</span><br>'
                                f'<span class="field-value">{f.get("detection_source", "N/A")}</span>',
                                unsafe_allow_html=True,
                            )

                        st.markdown("**" + t("label_evidence") + "**")
                        st.code(f.get("evidence", ""), language="text")

                        st.markdown("**" + t("label_explanation") + "**")
                        st.markdown(f.get("explanation", ""))

                        st.markdown("**" + t("label_secure_recommendation") + "**")
                        st.success(f.get("secure_recommendation", ""))
        else:
            st.success(t("no_findings"))

        st.markdown("---")
        st.markdown("### " + t("export_report"))
        json_report = generate_json_report(findings, language, summary)
        md_report = generate_markdown_report(findings, language, summary)

        dl_col1, dl_col2, dl_col3 = st.columns(3)
        with dl_col1:
            st.download_button(
                label=t("download_json"),
                data=json_report,
                file_name="codevuln_report.json",
                mime="application/json",
                use_container_width=True,
            )
        with dl_col2:
            st.download_button(
                label=t("download_md"),
                data=md_report,
                file_name="codevuln_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with dl_col3:
            st.download_button(
                label=t("download_html"),
                data=generate_html_report(findings, language, summary),
                file_name="codevuln_report.html",
                mime="text/html",
                use_container_width=True,
            )
        st.markdown(f'<div class="disclaimer-box"><b>{t("disclaimer_label")}</b> {t("disclaimer")}</div>', unsafe_allow_html=True)