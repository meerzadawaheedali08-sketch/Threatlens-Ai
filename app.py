

import streamlit as st

from config import APP_NAME
from input_validator import (
    validate_target,
    get_hostname_from_url
)
from vt_scanner import scan_target
from whois_scanner import lookup_whois
from risk_engine import calculate_risk
from gemini_analyzer import analyze_with_gemini
from report_generator import (
    build_report,
    report_to_json,
    report_to_txt
)
from styles import load_css, risk_class, risk_icon


st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide"
)

load_css()


if "history" not in st.session_state:
    st.session_state.history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None


def show_dashboard():

    st.markdown(
        '<div class="threat-title">🛡️ ThreatLens AI</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="threat-subtitle">'
        'AI-assisted Domain, URL and IP Security Analyzer'
        '</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Security Sources",
            "VirusTotal"
        )

    with col2:
        st.metric(
            "Domain Intelligence",
            "WHOIS"
        )

    with col3:
        st.metric(
            "AI Explanation",
            "Gemini"
        )

    st.info(
        "Enter a domain, URL, IPv4 or IPv6 address from the Scanner page."
    )


def show_scanner():

    st.title("🔎 Security Scanner")

    target = st.text_input(
        "Enter target",
        placeholder="example.com or https://example.com or 8.8.8.8"
    )

    mode = st.selectbox(
        "Explanation Level",
        [
            "Beginner",
            "Intermediate",
            "Expert"
        ]
    )

    scan_button = st.button(
        "🚀 Scan Target",
        type="primary"
    )

    if scan_button:

        if not target:

            st.warning("Please enter a target.")

            return

        validation = validate_target(target)

        if not validation["valid"]:

            st.error(validation["message"])

            return

        normalized_target = validation["target"]
        target_type = validation["type"]

        st.success(
            f"Detected target type: {target_type}"
        )

        with st.spinner("Collecting security intelligence..."):

            vt_result = scan_target(
                normalized_target,
                target_type
            )

            whois_result = {
                "available": False,
                "error": "WHOIS not applicable."
            }

            if target_type == "Domain":

                whois_result = lookup_whois(
                    normalized_target
                )

            elif target_type == "URL":

                hostname = get_hostname_from_url(
                    normalized_target
                )

                if hostname:

                    whois_result = lookup_whois(
                        hostname
                    )

            risk_result = calculate_risk(
                vt_result,
                whois_result
            )

        with st.spinner("Generating AI explanation..."):

            gemini_result = analyze_with_gemini(
                normalized_target,
                target_type,
                vt_result,
                whois_result,
                risk_result,
                mode
            )

        report = build_report(
            normalized_target,
            target_type,
            vt_result,
            whois_result,
            risk_result,
            gemini_result
        )

        result = {
            "report": report,
            "mode": mode
        }

        st.session_state.last_result = result

        st.session_state.history.insert(
            0,
            result
        )

        show_result(result)


def show_result(result):

    report = result["report"]

    risk = report["risk"]

    level = risk["level"]
    score = risk["score"]

    st.divider()

    st.subheader("Security Result")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.markdown(
            f"""
            <div class="risk-box">
                <div>Risk Level</div>
                <div class="{risk_class(level)} risk-score">
                    {risk_icon(level)} {level}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:

        st.metric(
            "Risk Score",
            f"{score}/100"
        )

    with col3:

        st.metric(
            "Target Type",
            report["target_type"]
        )

    st.write("### 🧠 Why this result?")

    if risk["reasons"]:

        for reason in risk["reasons"]:
            st.write(f"• {reason}")

    else:

        st.write("No additional risk reasons available.")

    st.write("### 🦠 VirusTotal")

    vt = report["virustotal"]

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Malicious",
        vt.get("malicious", 0)
    )

    c2.metric(
        "Suspicious",
        vt.get("suspicious", 0)
    )

    c3.metric(
        "Harmless",
        vt.get("harmless", 0)
    )

    c4.metric(
        "Undetected",
        vt.get("undetected", 0)
    )

    if vt.get("vendor_results"):

        st.write("#### Vendor Findings")

        for finding in vt["vendor_results"]:

            st.write(
                f"**{finding['vendor']}** — "
                f"{finding['category']} — "
                f"{finding['result']}"
            )

    st.write("### 🌐 WHOIS")

    whois_data = report["whois"]

    if whois_data.get("available"):

        st.write(
            f"**Registrar:** "
            f"{whois_data.get('registrar')}"
        )

        st.write(
            f"**Created:** "
            f"{whois_data.get('creation_date')}"
        )

        st.write(
            f"**Expires:** "
            f"{whois_data.get('expiration_date')}"
        )

        st.write(
            f"**Country:** "
            f"{whois_data.get('country')}"
        )

    else:

        st.info(
            whois_data.get(
                "error",
                "WHOIS information unavailable."
            )
        )

    st.write("### 🤖 Gemini Security Explanation")

    st.markdown(
        report["gemini_analysis"]
    )

    st.write("### 📥 Download Report")

    json_report = report_to_json(report)
    txt_report = report_to_txt(report)

    c1, c2 = st.columns(2)

    with c1:

        st.download_button(
            "Download JSON",
            json_report,
            file_name="threatlens_report.json",
            mime="application/json"
        )

    with c2:

        st.download_button(
            "Download TXT",
            txt_report,
            file_name="threatlens_report.txt",
            mime="text/plain"
        )

    # Friendly Educational Banner
    st.markdown(
        """
        <div style="background-color: #FEF9C3; border-left: 5px solid #EAB308; padding: 15px; border-radius: 8px; color: #854D0E; font-size: 0.95rem; margin-top: 25px;">
            🎓 <strong>Educational & Friendly Security Tool:</strong><br>
            ThreatLens AI is an open educational platform created to help users understand domain and IP security metrics easily.<br>
            <em>Note:</em> Results rely on security databases. While highly informative, always practice safe browsing habits!
        </div>
        """,
        unsafe_allow_html=True
    )


def show_history():

    st.title("📜 Scan History")

    if not st.session_state.history:

        st.info(
            "No scans yet. Your session history will appear here."
        )

        return

    for index, item in enumerate(
        st.session_state.history
    ):

        report = item["report"]

        risk = report["risk"]

        with st.expander(
            f"{risk_icon(risk['level'])} "
            f"{report['target']} — "
            f"{risk['level']} "
            f"({risk['score']}/100)"
        ):

            st.write(
                f"**Type:** {report['target_type']}"
            )

            for reason in risk["reasons"]:

                st.write(f"• {reason}")

    if st.button("Clear History"):

        st.session_state.history = []

        st.rerun()


def show_security_guide():

    st.title("📚 Security Guide")

    st.markdown(
        """
### What is an IP address?

An IP address identifies a device or network location.

### What is a domain?

A domain is a human-readable name such as:

`example.com`

### What is a URL?

A URL is a complete web address such as:

`https://example.com/login`

### What is phishing?

Phishing is a technique used to trick users into providing
information such as passwords or financial details.

### What is VirusTotal?

VirusTotal aggregates security analysis from many security vendors.

### What is WHOIS?

WHOIS can provide domain registration information such as
registrar, creation date and expiration date.

### What does the risk score mean?

ThreatLens uses a deterministic scoring engine based on
available evidence.

### Important

A score of zero or no known malicious detections does NOT
guarantee that a target is safe.
"""
    )


def show_about():

    st.title("ℹ️ About ThreatLens AI")

    st.write(
        "✨ Designed by Waheed Ali Hamouzai."
    )

    st.write("### Technology Stack")

    st.write(
        """
- Python
- Streamlit
- VirusTotal API
- WHOIS
- Google Gemini
- Requests
"""
    )

    st.markdown(
        """
        <div style="background-color: #FEF9C3; border-left: 5px solid #EAB308; padding: 15px; border-radius: 8px; color: #854D0E; font-size: 0.95rem; margin-top: 25px;">
            🎓 <strong>Educational Purpose & Friendly Tool:</strong><br>
            ThreatLens AI is designed to make cybersecurity analysis accessible and easy to understand for everyone.<br><br>
            <em>Note:</em> Results are compiled from threat intelligence services. No security tool guarantees 100% safety, so stay vigilant online!
        </div>
        """,
        unsafe_allow_html=True
    )


with st.sidebar:

    st.title("🛡️ ThreatLens AI")

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Scanner",
            "Scan History",
            "Security Guide",
            "About"
        ]
    )


if page == "Dashboard":

    show_dashboard()

elif page == "Scanner":

    show_scanner()

elif page == "Scan History":

    show_history()

elif page == "Security Guide":

    show_security_guide()

elif page == "About":

    show_about()
