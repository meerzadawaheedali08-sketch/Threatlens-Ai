import re
import ipaddress
from urllib.parse import urlparse


def validate_target(target: str) -> dict:
    target = target.strip()

    if not target:
        return {"valid": False, "message": "Input target cannot be empty.", "type": None, "target": target}

    # IPv4 / IPv6 Check
    try:
        ip = ipaddress.ip_address(target)
        target_type = "IPv6" if ip.version == 6 else "IPv4"
        return {"valid": True, "message": "Valid IP Address", "type": target_type, "target": target}
    except ValueError:
        pass

    # URL Check
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        if parsed.netloc:
            return {"valid": True, "message": "Valid URL", "type": "URL", "target": target}

    # Domain Check
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_regex, target):
        return {"valid": True, "message": "Valid Domain", "type": "Domain", "target": target}

    return {"valid": False, "message": "Invalid target format. Enter a valid Domain, URL, or IP address.", "type": None, "target": target}


def get_hostname_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""
