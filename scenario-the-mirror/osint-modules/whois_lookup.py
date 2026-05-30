"""WHOIS registry lookup — identify who owns the attacker's IP range."""

import subprocess
import re


def whois_lookup(ip):
    """
    Query WHOIS for IP ownership information.

    In production, use a library like ipwhois for structured parsing.
    This sketch shells out to the whois CLI for simplicity.
    """
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"error": "whois lookup failed"}

    def extract(pattern, text, default="unknown"):
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else default

    return {
        "org": extract(r"org-?name:\s*(.+)", output),
        "asn": extract(r"origin(?:as)?:\s*(AS\d+)", output),
        "net_range": extract(r"(?:inetnum|netrange):\s*(.+)", output),
        "country": extract(r"country:\s*(\w+)", output),
        "abuse_contact": extract(r"abuse-?(?:mailbox|contact).*?:\s*(\S+@\S+)", output),
        "registration_date": extract(r"(?:created|regdate):\s*(.+)", output),
    }
