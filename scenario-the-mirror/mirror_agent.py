#!/usr/bin/env python3
"""
The Mirror — main agent orchestrator.

Detects attacker reconnaissance, redirects to honeypot, runs passive OSINT
on the attacker's IP, compiles a dossier, and opens a PR.

This is a sketch for presentation purposes — not production code.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from osint_modules.whois_lookup import whois_lookup
from osint_modules.reverse_dns import reverse_dns
from osint_modules.shodan_lookup import shodan_lookup
from osint_modules.cert_transparency import ct_lookup

TEMPLATE_DIR = Path(__file__).parent / "templates"
HONEYPOT_IP = "10.0.0.99"


def detect_recon(eve_event):
    """Determine if a Suricata EVE event indicates reconnaissance."""
    if eve_event.get("event_type") != "alert":
        return None

    alert = eve_event.get("alert", {})
    category = alert.get("category", "").lower()
    recon_categories = [
        "attempted-recon",
        "network-scan",
        "web-application-attack",
    ]

    if any(cat in category for cat in recon_categories):
        return {
            "src_ip": eve_event.get("src_ip"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
            "timestamp": eve_event.get("timestamp"),
        }
    return None


def redirect_to_honeypot(attacker_ip):
    """Generate and apply nftables DNAT rule to reroute attacker to honeypot."""
    rule_content = (
        f"# The Mirror — redirect attacker to honeypot\n"
        f"# Attacker: {attacker_ip}\n"
        f"# Honeypot: {HONEYPOT_IP}\n"
        f"table ip nat {{\n"
        f"    chain prerouting {{\n"
        f"        type nat hook prerouting priority -100; policy accept;\n"
        f'        ip saddr {attacker_ip} dnat to {HONEYPOT_IP} '
        f'comment "mirror: redirect to honeypot"\n'
        f"    }}\n"
        f"}}\n"
    )
    rule_file = TEMPLATE_DIR.parent / f"redirect-{attacker_ip.replace('.', '-')}.nft"
    rule_file.write_text(rule_content)
    return rule_file


def run_osint(attacker_ip):
    """Run all passive OSINT modules against the attacker's IP."""
    dossier = {
        "target_ip": attacker_ip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "modules": {},
    }

    dossier["modules"]["whois"] = whois_lookup(attacker_ip)
    dossier["modules"]["reverse_dns"] = reverse_dns(attacker_ip)
    dossier["modules"]["shodan"] = shodan_lookup(attacker_ip)
    dossier["modules"]["cert_transparency"] = ct_lookup(attacker_ip)

    return dossier


def compile_dossier(attacker_ip, detection, osint_data, honeypot_logs=None):
    """Render the intelligence dossier from OSINT and honeypot data."""
    whois = osint_data["modules"].get("whois", {})
    rdns = osint_data["modules"].get("reverse_dns", {})
    shodan = osint_data["modules"].get("shodan", {})
    ct = osint_data["modules"].get("cert_transparency", {})

    open_ports = shodan.get("open_ports", [])
    ports_str = ", ".join(str(p) for p in open_ports) if open_ports else "none found"

    certs = ct.get("certificates", [])
    certs_str = "\n".join(f"  - `{c}`" for c in certs) if certs else "  - none found"

    dossier = (
        f"# Intelligence Dossier: {attacker_ip}\n\n"
        f"**Generated:** {osint_data['collected_at']}\n"
        f"**Trigger:** {detection.get('signature', 'unknown')}\n\n"
        f"---\n\n"
        f"## WHOIS\n\n"
        f"- **Owner:** {whois.get('org', 'unknown')}\n"
        f"- **ASN:** {whois.get('asn', 'unknown')}\n"
        f"- **Net range:** {whois.get('net_range', 'unknown')}\n"
        f"- **Country:** {whois.get('country', 'unknown')}\n"
        f"- **Abuse contact:** {whois.get('abuse_contact', 'unknown')}\n\n"
        f"## Reverse DNS\n\n"
        f"- **PTR record:** {rdns.get('ptr', 'none')}\n"
        f"- **Hosting provider:** {rdns.get('provider_guess', 'unknown')}\n\n"
        f"## Shodan\n\n"
        f"- **Open ports:** {ports_str}\n"
        f"- **OS:** {shodan.get('os', 'unknown')}\n"
        f"- **Banners:**\n"
    )

    for banner in shodan.get("banners", []):
        dossier += f"  - Port {banner['port']}: `{banner['service']}`\n"

    dossier += (
        f"\n## Certificate Transparency\n\n"
        f"Domains associated with this IP:\n{certs_str}\n\n"
        f"## IOCs for Threat Intel Ingestion\n\n"
        f"```json\n"
        f"{json.dumps({'ip': attacker_ip, 'asn': whois.get('asn'), 'domains': ct.get('certificates', []), 'open_ports': open_ports}, indent=2)}\n"
        f"```\n"
    )

    return dossier


def open_pr(attacker_ip, detection, dossier_content, rule_file):
    """Commit the dossier and block rule, open a PR."""
    branch = f"riposte/mirror-{attacker_ip.replace('.', '-')}"

    dossier_file = TEMPLATE_DIR.parent / f"dossier-{attacker_ip.replace('.', '-')}.md"
    dossier_file.write_text(dossier_content)

    subprocess.run(["git", "checkout", "-b", branch], check=True)
    subprocess.run(["git", "add", str(dossier_file), str(rule_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m",
         f"mirror: counter-recon on {attacker_ip} — dossier + redirect rule"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"mirror: counter-recon dossier for {attacker_ip}",
            "--body", (
                f"## The Mirror — Counter-Reconnaissance Report\n\n"
                f"Attacker `{attacker_ip}` detected performing reconnaissance "
                f"({detection.get('signature', 'unknown')}).\n\n"
                f"**Actions taken:**\n"
                f"1. Traffic redirected to honeypot at `{HONEYPOT_IP}`\n"
                f"2. Passive OSINT collected (WHOIS, rDNS, Shodan, CT logs)\n"
                f"3. Full dossier attached\n\n"
                f"**They scanned us. We scanned them back.**\n\n"
                f"See `dossier-{attacker_ip.replace('.', '-')}.md` for the full "
                f"intelligence report.\n\n"
                f"---\n*Opened by cyber-riposte agent (The Mirror)*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)


def run(eve_stream):
    """Main loop: read EVE events, detect recon, mirror the attacker."""
    mirrored = set()

    for line in eve_stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        detection = detect_recon(event)
        if not detection:
            continue

        attacker_ip = detection["src_ip"]
        if not attacker_ip or attacker_ip in mirrored:
            continue

        print(f"[mirror] Recon detected from {attacker_ip}: {detection['signature']}")

        print(f"[mirror] Redirecting {attacker_ip} to honeypot {HONEYPOT_IP}")
        rule_file = redirect_to_honeypot(attacker_ip)

        print(f"[mirror] Running OSINT on {attacker_ip}...")
        osint_data = run_osint(attacker_ip)

        print(f"[mirror] Compiling dossier...")
        dossier_content = compile_dossier(attacker_ip, detection, osint_data)

        print(f"[mirror] Opening PR with dossier + redirect rule")
        open_pr(attacker_ip, detection, dossier_content, rule_file)

        mirrored.add(attacker_ip)
        print(f"[mirror] Complete — {attacker_ip} mirrored")


if __name__ == "__main__":
    run(sys.stdin)
