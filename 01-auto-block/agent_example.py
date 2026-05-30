#!/usr/bin/env python3
"""
Sketch of an AI agent that watches auth logs and opens PRs to block offending IPs.

This is a simplified example for presentation purposes — not production code.
"""

import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FAILED_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
THRESHOLD = 5
WINDOW = 60
ALLOWLIST = {"127.0.0.1"}
TEMPLATE = Path(__file__).parent / "template.nft"
RULES_DIR = Path(__file__).parent / "block-rules"


def render_rule(ip, failure_count, target_host):
    now = datetime.now(timezone.utc)
    template = TEMPLATE.read_text()
    return (
        template
        .replace("{{ src_ip }}", ip)
        .replace("{{ failure_count }}", str(failure_count))
        .replace("{{ window }}", str(WINDOW))
        .replace("{{ target_host }}", target_host)
        .replace("{{ timestamp }}", now.strftime("%Y%m%d-%H%M%SZ"))
        .replace("{{ expiry_utc }}", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    )


def open_pr(ip, failure_count, rule_file):
    """Create a branch, commit the rule, and open a PR via gh CLI."""
    branch = f"riposte/block-{ip.replace('.', '-')}"
    subprocess.run(["git", "checkout", "-b", branch], check=True)
    subprocess.run(["git", "add", str(rule_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"block: drop traffic from {ip} ({failure_count} auth failures in {WINDOW}s)"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"block: drop traffic from {ip} ({failure_count} auth failures in {WINDOW}s)",
            "--body", (
                f"Telemetry shows {failure_count} failed SSH password attempts from `{ip}` "
                f"within a {WINDOW}s window.\n\n"
                f"Proposing an nftables drop rule. Auto-expires in 1 hour.\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)


def watch_and_respond(log_file="/var/log/auth.log"):
    failures = defaultdict(list)
    blocked = set()

    with open(log_file) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            match = FAILED_RE.search(line)
            if not match:
                continue

            ip = match.group(1)
            if ip in ALLOWLIST or ip in blocked:
                continue

            now = time.time()
            failures[ip] = [t for t in failures[ip] if now - t < WINDOW] + [now]

            if len(failures[ip]) >= THRESHOLD:
                count = len(failures[ip])
                rule_content = render_rule(ip, count, "prod-bastion-01")

                RULES_DIR.mkdir(exist_ok=True)
                rule_file = RULES_DIR / f"block-{ip.replace('.', '-')}.nft"
                rule_file.write_text(rule_content)

                open_pr(ip, count, rule_file)
                blocked.add(ip)
                del failures[ip]


if __name__ == "__main__":
    watch_and_respond()
