
import json
from datetime import datetime


def build_report(
    target,
    target_type,
    vt_result,
    whois_result,
    risk_result,
    gemini_result
):

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "target_type": target_type,
        "risk": risk_result,
        "virustotal": vt_result,
        "whois": whois_result,
        "gemini_analysis": gemini_result
    }


def report_to_json(report):

    return json.dumps(
        report,
        indent=2,
        default=str
    )


def report_to_txt(report):

    lines = []

    lines.append("THREATLENS AI SECURITY REPORT")
    lines.append("=" * 50)

    lines.append(
        f"Target: {report['target']}"
    )

    lines.append(
        f"Type: {report['target_type']}"
    )

    lines.append(
        f"Risk Level: {report['risk']['level']}"
    )

    lines.append(
        f"Risk Score: {report['risk']['score']}/100"
    )

    lines.append("")
    lines.append("Risk Reasons")
    lines.append("-" * 30)

    for reason in report["risk"]["reasons"]:
        lines.append(f"- {reason}")

    lines.append("")
    lines.append("Gemini Analysis")
    lines.append("-" * 30)

    lines.append(
        report["gemini_analysis"]
    )

    lines.append("")
    lines.append("VirusTotal")
    lines.append("-" * 30)

    vt = report["virustotal"]

    lines.append(
        f"Malicious: {vt.get('malicious', 0)}"
    )

    lines.append(
        f"Suspicious: {vt.get('suspicious', 0)}"
    )

    lines.append(
        f"Harmless: {vt.get('harmless', 0)}"
    )

    lines.append(
        f"Undetected: {vt.get('undetected', 0)}"
    )

    return "\n".join(lines)
