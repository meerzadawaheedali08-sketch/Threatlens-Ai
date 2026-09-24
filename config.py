import os
import streamlit as st


def get_secret(name: str, default=None):
    value = os.getenv(name)

    if value:
        return value

    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass

    return default


VT_API_KEY = get_secret("VT_API_KEY")
GEMINI_API_KEY = get_secret("GEMINI_API_KEY")
GEMINI_MODEL = get_secret("GEMINI_MODEL", "gemini-2.5-flash")

REQUEST_TIMEOUT = 100

APP_NAME = "ThreatLens AI"

DISCLAIMER = (
    "ThreatLens AI is an educational tool using WHOIS, VirusTotal, and "
    "Gemini AI. Results do not guarantee absolute security."
)
