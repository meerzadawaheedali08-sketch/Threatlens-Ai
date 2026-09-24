

from google import genai
from config import GEMINI_API_KEY, GEMINI_MODEL


def analyze_with_gemini(
    target,
    target_type,
    vt_result,
    whois_result,
    risk_result,
    mode="Beginner"
):

    if not GEMINI_API_KEY:
        return (
            "Gemini analysis is unavailable because "
            "GEMINI_API_KEY is not configured."
        )

    prompt = f"""
You are the AI explanation layer of a cybersecurity educational tool
called ThreatLens AI.

Target:
{target}

Target type:
{target_type}

Risk level:
{risk_result.get("level")}

Risk score:
{risk_result.get("score")}/100

Risk reasons:
{risk_result.get("reasons")}

VirusTotal evidence:
{vt_result}

WHOIS evidence:
{whois_result}

Explanation mode:
{mode}

IMPORTANT RULES:

1. Use ONLY the supplied evidence.
2. Never invent facts.
3. If information is unavailable, say "Not available".
4. Do not claim certainty.
5. Do not create a different numeric risk score.
6. Do not override the deterministic risk engine.
7. Zero detections does NOT mean guaranteed safe.
8. Explain technical terms according to the selected mode.

Write these sections:

### Summary

### Why this result?

### What should the user do?

### Technical explanation

### Confidence and limitations

For Beginner mode, use simple language.

For Intermediate mode, use moderate technical detail.

For Expert mode, use deeper cybersecurity terminology.
"""

    try:
        client = genai.Client(
            api_key=GEMINI_API_KEY
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )

        return response.text

    except Exception as e:
        error_text = str(e)

        if (
            "429" in error_text
            or "RESOURCE_EXHAUSTED" in error_text
            or "quota" in error_text.lower()
        ):
            return (
                "⚠️ **Gemini AI Rate Limit Reached**\n\n"
                "The daily AI quota has been reached. However, the risk assessment above "
                "remains 100% accurate based on live VirusTotal and WHOIS scan data."
            )

        if (
            "503" in error_text
            or "UNAVAILABLE" in error_text
            or "high demand" in error_text.lower()
        ):
            return (
                "⚠️ **AI Service Temporarily Busy**\n\n"
                "Google Gemini servers are currently experiencing high demand. "
                "Your technical VirusTotal and WHOIS scan results remain accurate and fully accessible above."
            )

        return (
            "⚠️ **AI Explanation Unavailable**\n\n"
            "An error occurred while generating the AI summary. "
            "Please refer to the technical scan results provided above."
        )
