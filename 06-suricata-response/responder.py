#!/usr/bin/env python3
"""
Sketch: agent reads Suricata EVE JSON log, identifies high-severity alerts
or novel patterns, and opens PRs with block rules or new detection rules.

Simplified for presentation — not production code.
"""

import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

RULES_DIR = Path(__file__).parent / "custom-rules"
SEVERITY_THRESHOLD = 2


def read_eve_stream(stream):
    """Yield parsed alert events from a Suricata EVE JSON stream."""
    for line in stream:
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("event_type") == "alert":
            yield evt


def should_block(alert):
    """High-severity alerts trigger an immediate block PR."""
    return alert["alert"]["severity"] <= SEVERITY_THRESHOLD


def generate_block_pr(src_ip, alerts):
    """PR an nftables drop rule for a high-severity alert source."""
    branch = f"riposte/ids-block-{src_ip.replace('.', '-')}"
    alert_summary = alerts[0]["alert"]

    subprocess.run(["git", "checkout", "-b", branch], check=True)

    rule_file = RULES_DIR / f"block-{src_ip.replace('.', '-')}.nft"
    rule_file.parent.mkdir(exist_ok=True)
    rule_file.write_text(
        f"# Triggered by Suricata alert: {alert_summary['signature']}\n"
        f"# Severity: {alert_summary['severity']}\n"
        f"table inet filter {{\n"
        f"    chain input {{\n"
        f'        ip saddr {src_ip} counter drop comment "cyber-riposte: IDS response"\n'
        f"    }}\n"
        f"}}\n"
    )

    subprocess.run(["git", "add", str(rule_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"block: IDS response — drop {src_ip} (severity {alert_summary['severity']})"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"block: IDS response — drop {src_ip}",
            "--body", (
                f"Suricata alert: **{alert_summary['signature']}** (severity {alert_summary['severity']})\n\n"
                f"Source: `{src_ip}`\n"
                f"Total alerts from this source: {len(alerts)}\n\n"
                f"Proposing immediate drop rule.\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)


def main():
    """Read EVE events from stdin (pipe from: tail -F /var/log/suricata/eve.json)."""
    RULES_DIR.mkdir(exist_ok=True)
    blocked = set()
    alert_buffer = defaultdict(list)

    for alert in read_eve_stream(sys.stdin):
        src_ip = alert.get("src_ip", "")
        if not src_ip or src_ip in blocked:
            continue

        alert_buffer[src_ip].append(alert)

        if should_block(alert):
            generate_block_pr(src_ip, alert_buffer[src_ip])
            blocked.add(src_ip)
            del alert_buffer[src_ip]


if __name__ == "__main__":
    main()
