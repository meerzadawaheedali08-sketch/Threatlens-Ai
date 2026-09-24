import ipaddress
import re
from urllib.parse import urlparse

import validators


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_input(value: str) -> str:
    return value.strip()


def detect_target_type(target: str) -> str:
    target = normalize_input(target)

    if not target:
        return "Invalid"

    try:
        ip = ipaddress.ip_address(target)

        if isinstance(ip, ipaddress.IPv4Address):
            return "IPv4"

        return "IPv6"

    except ValueError:
        pass

    if validators.url(target):
        parsed = urlparse(target)

        if parsed.scheme.lower() in ["http", "https"]:
            return "URL"

    if DOMAIN_PATTERN.match(target.lower()):
        return "Domain"

    return "Invalid"


def validate_target(target: str):
    target = normalize_input(target)
    target_type = detect_target_type(target)

    if target_type == "Invalid":
        return {
            "valid": False,
            "target": target,
            "type": target_type,
            "message": "Please enter a valid domain, URL, IPv4 or IPv6 address."
        }

    return {
        "valid": True,
        "target": target,
        "type": target_type,
        "message": "Valid target."
    }


def get_hostname_from_url(url: str):
    try:
        return urlparse(url).hostname
    except Exception:
        return None
