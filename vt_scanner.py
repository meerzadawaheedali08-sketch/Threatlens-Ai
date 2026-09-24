
import base64
import time

import requests
import streamlit as st

from config import VT_API_KEY, REQUEST_TIMEOUT


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def error_message(status_code):
    messages = {
        400: "VirusTotal rejected the request.",
        401: "VirusTotal API key is invalid.",
        403: "VirusTotal API access is forbidden.",
        404: "VirusTotal does not have this resource.",
        429: "VirusTotal rate limit exceeded.",
        500: "VirusTotal server error.",
        502: "VirusTotal gateway error.",
        503: "VirusTotal service temporarily unavailable.",
    }

    return messages.get(
        status_code,
        f"VirusTotal request failed with HTTP {status_code}."
    )


def vt_get(endpoint):
    if not VT_API_KEY:
        return None, "VirusTotal API key is missing."

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            f"{VT_BASE_URL}{endpoint}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            return None, error_message(response.status_code)

        return response.json(), None

    except requests.RequestException as e:
        return None, f"VirusTotal connection error: {e}"


def extract_result(data):
    if not data:
        return {
            "available": False,
            "message": "No VirusTotal data available.",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation": 0,
            "last_analysis_date": None,
            "categories": {},
            "vendor_results": [],
            "error": "No data",
            "raw_attributes": {}
        }

    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    results = attributes.get("last_analysis_results", {})

    vendor_results = []

    for vendor, result in results.items():
        category = result.get("category", "")
        result_text = result.get("result")

        if category in ["malicious", "suspicious"]:
            vendor_results.append({
                "vendor": vendor,
                "category": category,
                "result": result_text
            })

    return {
        "available": True,
        "message": "VirusTotal analysis available.",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "reputation": attributes.get("reputation", 0),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "categories": attributes.get("categories", {}),
        "vendor_results": vendor_results,
        "error": None,
        "raw_attributes": attributes
    }


def scan_domain(domain):
    data, error = vt_get(f"/domains/{domain}")

    if error:
        return extract_result(None) | {
            "error": error,
            "message": error
        }

    return extract_result(data)


def scan_ip(ip):
    data, error = vt_get(f"/ip_addresses/{ip}")

    if error:
        return extract_result(None) | {
            "error": error,
            "message": error
        }

    return extract_result(data)


def scan_url(url):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    data, error = vt_get(f"/urls/{url_id}")

    if not error:
        return extract_result(data)

    if "does not have this resource" not in error.lower():
        return extract_result(None) | {
            "error": error,
            "message": error
        }

    if not VT_API_KEY:
        return extract_result(None) | {
            "error": "VirusTotal API key is missing."
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": url},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code not in [200, 201]:
            return extract_result(None) | {
                "error": error_message(response.status_code),
                "message": error_message(response.status_code)
            }

        analysis_id = response.json()["data"]["id"]

        time.sleep(2)

        analysis_data, analysis_error = vt_get(
            f"/analyses/{analysis_id}"
        )

        if analysis_error:
            return extract_result(None) | {
                "error": analysis_error,
                "message": analysis_error
            }

        status = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
            .get("status")
        )

        if status != "completed":
            return extract_result(None) | {
                "available": True,
                "message": f"VirusTotal URL analysis status: {status}",
                "error": None
            }

        final_data, final_error = vt_get(f"/urls/{url_id}")

        if final_error:
            return extract_result(None) | {
                "error": final_error,
                "message": final_error
            }

        return extract_result(final_data)

    except requests.RequestException as e:
        return extract_result(None) | {
            "error": str(e),
            "message": str(e)
        }


@st.cache_data(ttl=300)
def scan_target(target, target_type):

    if target_type == "Domain":
        return scan_domain(target)

    if target_type in ["IPv4", "IPv6"]:
        return scan_ip(target)

    if target_type == "URL":
        return scan_url(target)

    return extract_result(None)
