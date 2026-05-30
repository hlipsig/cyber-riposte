"""Reverse DNS lookup — check if the attacker's IP has a PTR record."""

import socket


def reverse_dns(ip):
    """
    Perform reverse DNS lookup on the attacker's IP.

    PTR records often reveal the hosting provider or machine role
    (e.g., 'vps-12345.hostingprovider.com').
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return {"ptr": None, "provider_guess": "unknown"}

    provider_guess = guess_provider(hostname)

    return {
        "ptr": hostname,
        "provider_guess": provider_guess,
    }


def guess_provider(hostname):
    """Guess the hosting provider from the PTR hostname."""
    hostname = hostname.lower()

    providers = {
        "digitalocean": "DigitalOcean",
        "linode": "Linode/Akamai",
        "vultr": "Vultr",
        "hetzner": "Hetzner",
        "ovh": "OVH",
        "amazonaws": "AWS EC2",
        "compute.google": "Google Cloud",
        "azure": "Microsoft Azure",
        "contabo": "Contabo",
        "hostwinds": "Hostwinds",
    }

    for pattern, name in providers.items():
        if pattern in hostname:
            return name

    return "unknown"
