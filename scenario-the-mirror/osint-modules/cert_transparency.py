"""Certificate Transparency log search — find domains hosted on the attacker's IP."""

import json
import socket
import urllib.request
import urllib.error


def ct_lookup(ip):
    """
    Search Certificate Transparency logs for certificates associated with
    the attacker's IP.

    Uses crt.sh (a free CT log search engine). First resolves any hostnames
    on the IP via reverse DNS, then searches CT logs for certificates issued
    to those domains. This reveals the attacker's other infrastructure.
    """
    hostnames = _get_hostnames(ip)
    if not hostnames:
        return {"certificates": [], "note": "No hostnames resolved for this IP"}

    all_certs = []
    for hostname in hostnames:
        domain = _extract_registerable_domain(hostname)
        if domain:
            certs = _search_crtsh(domain)
            all_certs.extend(certs)

    unique_certs = sorted(set(all_certs))

    return {
        "searched_hostnames": hostnames,
        "certificates": unique_certs,
        "count": len(unique_certs),
    }


def _get_hostnames(ip):
    """Resolve hostnames for the IP (reverse DNS + any Shodan hostnames)."""
    hostnames = []
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        hostnames.append(hostname)
    except (socket.herror, socket.gaierror):
        pass
    return hostnames


def _extract_registerable_domain(hostname):
    """Extract the registerable domain from a hostname (naive implementation)."""
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _search_crtsh(domain):
    """Query crt.sh for certificates issued to a domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "cyber-riposte-osint/1.0")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError):
        return []

    return [
        entry.get("name_value", "").strip()
        for entry in data[:50]
        if entry.get("name_value")
    ]
