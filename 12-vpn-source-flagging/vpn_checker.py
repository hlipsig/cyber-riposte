#!/usr/bin/env python3
"""
Sketch: check source IPs against known VPN/proxy/Tor databases and
propose graduated responses based on endpoint sensitivity.

Data sources for VPN/proxy detection (in practice):
- ip2location.com IP2Proxy database
- ipinfo.io privacy detection API
- Dan Pollock's Tor exit list
- Custom lists from threat intel
"""

import ipaddress
import subprocess
import yaml
from collections import defaultdict
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent


def load_vpn_ranges(path="vpn-providers.yaml"):
    with open(TEMPLATE_DIR / path) as f:
        return yaml.safe_load(f)


def load_endpoint_config(path="endpoint-sensitivity.yaml"):
    with open(TEMPLATE_DIR / path) as f:
        return yaml.safe_load(f)


def check_ip(ip_str, vpn_data):
    """Check if an IP belongs to a known VPN/proxy provider."""
    ip = ipaddress.ip_address(ip_str)
    for provider in vpn_data.get("providers", []):
        for cidr in provider.get("ranges", []):
            if ip in ipaddress.ip_network(cidr):
                return provider["name"]
    return None


def classify_traffic(access_logs, vpn_data, endpoint_config):
    """
    Analyze access logs for VPN-sourced traffic hitting sensitive endpoints.

    Returns flagged requests grouped by response level.
    """
    flagged = defaultdict(lambda: defaultdict(list))

    sensitivity_map = {}
    for level in endpoint_config.get("levels", []):
        for pattern in level.get("endpoints", []):
            sensitivity_map[pattern] = level["response"]

    for log_entry in access_logs:
        src_ip = log_entry.get("source_ip", "")
        endpoint = log_entry.get("path", "")

        provider = check_ip(src_ip, vpn_data)
        if not provider:
            continue

        response_level = "log"
        for pattern, level in sensitivity_map.items():
            if endpoint.startswith(pattern):
                response_level = level
                break

        flagged[response_level][provider].append({
            "ip": src_ip,
            "endpoint": endpoint,
            "method": log_entry.get("method", "GET"),
        })

    return dict(flagged)


def open_pr(flagged_traffic, response_level):
    """PR the appropriate response for the most sensitive level detected."""
    branch = "riposte/vpn-source-block"
    all_providers = []
    total_requests = 0

    for provider, requests in flagged_traffic.get(response_level, {}).items():
        unique_ips = len(set(r["ip"] for r in requests))
        endpoints = list(set(r["endpoint"] for r in requests))
        all_providers.append({
            "provider": provider,
            "ips": unique_ips,
            "requests": len(requests),
            "endpoints": endpoints,
        })
        total_requests += len(requests)

    table_rows = "\n".join(
        f"| {p['provider']} | {p['ips']} | {p['requests']} | {', '.join(p['endpoints'][:3])} |"
        for p in all_providers
    )

    subprocess.run(["git", "checkout", "-b", branch], check=True)

    rule_file = TEMPLATE_DIR / "block-vpn-admin.nft"
    rule_file.write_text(
        f"# Block VPN-sourced traffic to sensitive endpoints\n"
        f"# Providers detected: {', '.join(p['provider'] for p in all_providers)}\n"
        f"# Total requests: {total_requests}\n"
        f"# Response level: {response_level}\n\n"
        f"# IP set populated from VPN provider CIDR ranges\n"
        f"table inet filter {{\n"
        f"    set vpn_sources {{\n"
        f"        type ipv4_addr\n"
        f"        flags interval\n"
        f"        # elements populated by GitOps pipeline from vpn-providers.yaml\n"
        f"    }}\n\n"
        f"    chain input {{\n"
        f'        ip saddr @vpn_sources tcp dport {{ 80, 443 }} counter drop '
        f'comment "cyber-riposte: block VPN sources to sensitive endpoints"\n'
        f"    }}\n"
        f"}}\n"
    )

    subprocess.run(["git", "add", str(rule_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m",
         f"predict: {response_level} VPN-sourced traffic — "
         f"{total_requests} requests from {len(all_providers)} providers"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title",
            f"predict: {response_level} VPN-sourced traffic to sensitive endpoints",
            "--body", (
                f"Over the last 2 hours, {total_requests} requests to sensitive endpoints "
                f"originated from known VPN/proxy providers:\n\n"
                f"| Provider | IPs | Requests | Endpoints |\n|---|---|---|---|\n"
                f"{table_rows}\n\n"
                f"Response level: **{response_level}**\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)
