 from datetime import datetime, timezone


def calculate_domain_age_days(creation_date):

    if not creation_date:
        return None

    try:

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(creation_date, str):
            creation_date = datetime.fromisoformat(
                creation_date.replace("Z", "+00:00")
            )

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        return max(
            0,
            (now - creation_date).days
        )

    except Exception:
        return None


def calculate_risk(vt_result, whois_result=None):

    score = 0
    reasons = []

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    reputation = vt_result.get("reputation", 0)

    score += min(60, malicious * 10)

    if malicious:
        reasons.append(
            f"{malicious} security vendor(s) flagged the target as malicious."
        )

    score += min(25, suspicious * 5)

    if suspicious:
        reasons.append(
            f"{suspicious} security vendor(s) marked the target suspicious."
        )

    if reputation < -20:

        score += 15

        reasons.append(
            "VirusTotal reputation is strongly negative."
        )

    elif reputation < 0:

        score += 8

        reasons.append(
            "VirusTotal reputation is negative."
        )

    if whois_result and whois_result.get("available"):

        age_days = calculate_domain_age_days(
            whois_result.get("creation_date")
        )

        if age_days is not None:

            if age_days < 30:

                score += 10

                reasons.append(
                    "The domain appears to be less than 30 days old."
                )

            elif age_days < 180:

                score += 5

                reasons.append(
                    "The domain appears to be less than 180 days old."
                )

    score = min(100, max(0, score))

    vt_available = vt_result.get("available", False)

    if not vt_available and score == 0:

        level = "UNKNOWN"

    elif score >= 60:

        level = "CRITICAL"

    elif score >= 30:

        level = "HIGH"

    elif score >= 1:

        level = "MEDIUM"

    else:

        level = "LOW"

    if score == 0 and vt_available:

        reasons.append(
            "No known malicious indicators were detected by the available sources. "
            "This does not guarantee that the target is safe."
        )

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }
