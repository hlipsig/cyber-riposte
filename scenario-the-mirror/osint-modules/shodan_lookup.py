"""Shodan API lookup — discover what the attacker's machine is running."""

import json
import os
import urllib.request
import urllib.error


SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


def shodan_lookup(ip):
    """
    Query Shodan for information about the attacker's IP.

    Returns open ports, service banners, OS detection, and known vulnerabilities.
    Shodan indexes publicly-facing services — this is passive reconnaissance
    using data Shodan has already collected.
    """
    if not SHODAN_API_KEY:
        return _placeholder_response(ip)

    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError):
        return {"error": "Shodan lookup failed"}

    banners = []
    for service in data.get("data", []):
        banners.append({
            "port": service.get("port"),
            "service": service.get("product", service.get("_shodan", {}).get("module", "unknown")),
            "banner_snippet": service.get("data", "")[:200],
        })

    return {
        "open_ports": data.get("ports", []),
        "os": data.get("os", "unknown"),
        "banners": banners,
        "vulns": data.get("vulns", []),
        "last_update": data.get("last_update", "unknown"),
        "hostnames": data.get("hostnames", []),
    }


def _placeholder_response(ip):
    """Placeholder when no API key is configured."""
    return {
        "open_ports": [22, 80, 443, 8080],
        "os": "Linux",
        "banners": [
            {"port": 22, "service": "OpenSSH 8.9"},
            {"port": 80, "service": "nginx/1.24.0"},
            {"port": 443, "service": "nginx/1.24.0"},
            {"port": 8080, "service": "Cobalt Strike Beacon (!)"},
        ],
        "vulns": ["CVE-2023-XXXXX"],
        "last_update": "placeholder — set SHODAN_API_KEY for real data",
        "hostnames": [f"vps-{ip.replace('.', '-')}.example-hosting.com"],
        "_note": "This is placeholder data. Set SHODAN_API_KEY env var for real lookups.",
    }
