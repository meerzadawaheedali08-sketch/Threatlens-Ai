

import streamlit as st


def load_css():

    st.markdown(
        """
        <style>

        .main {
            background-color: #0b1020;
        }

        .block-container {
            max-width: 1200px;
            padding-top: 2rem;
        }

        .threat-title {
            font-size: 42px;
            font-weight: 800;
            margin-bottom: 5px;
        }

        .threat-subtitle {
            color: #9ca3af;
            font-size: 17px;
            margin-bottom: 30px;
        }

        .risk-box {
            padding: 25px;
            border-radius: 15px;
            background: #111827;
            border: 1px solid #374151;
            text-align: center;
        }

        .risk-score {
            font-size: 50px;
            font-weight: 800;
        }

        .risk-low {
            color: #22c55e;
        }

        .risk-medium {
            color: #eab308;
        }

        .risk-high {
            color: #f97316;
        }

        .risk-critical {
            color: #ef4444;
        }

        .risk-unknown {
            color: #9ca3af;
        }

        </style>
        """,
        unsafe_allow_html=True
    )


def risk_class(level):

    return {
        "LOW": "risk-low",
        "MEDIUM": "risk-medium",
        "HIGH": "risk-high",
        "CRITICAL": "risk-critical",
        "UNKNOWN": "risk-unknown"
    }.get(level, "risk-unknown")


def risk_icon(level):

    return {
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🟠",
        "CRITICAL": "🔴",
        "UNKNOWN": "⚪"
    }.get(level, "⚪")
