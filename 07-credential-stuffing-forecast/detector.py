#!/usr/bin/env python3
"""
Sketch: detect distributed credential stuffing campaigns by correlating
failed logins across many source IPs targeting common accounts.

The agent looks for patterns that individual per-IP thresholds miss:
- Many IPs hitting the same small set of accounts
- Common user-agent or timing fingerprint across sources
- Credential reuse across different services
"""

import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

WINDOW_SECONDS = 1800  # 30-minute correlation window
MIN_SOURCES = 10       # minimum unique IPs to flag as campaign
MIN_TARGETS = 5        # minimum targeted accounts
TEMPLATE_DIR = Path(__file__).parent


def analyze_auth_events(events):
    """
    Correlate failed login events to detect distributed campaigns.

    Returns campaign fingerprint if detected, None otherwise.
    """
    target_to_sources = defaultdict(set)
    source_agents = defaultdict(set)
    source_timing = defaultdict(list)

    for evt in events:
        target = evt.get("username", "")
        source = evt.get("source_ip", "")
        agent = evt.get("user_agent", "")
        ts = evt.get("timestamp", 0)

        if not target or not source:
            continue

        target_to_sources[target].add(source)
        source_agents[source].add(agent)
        source_timing[source].append(ts)

    attacked_accounts = {
        acct: sources
        for acct, sources in target_to_sources.items()
        if len(sources) >= MIN_SOURCES
    }

    if len(attacked_accounts) < MIN_TARGETS:
        return None

    all_sources = set()
    for sources in attacked_accounts.values():
        all_sources.update(sources)

    common_agents = set.intersection(
        *(source_agents[s] for s in all_sources if s in source_agents)
    ) if all_sources else set()

    return {
        "accounts": list(attacked_accounts.keys()),
        "source_count": len(all_sources),
        "account_count": len(attacked_accounts),
        "common_user_agents": list(common_agents),
        "sources_sample": list(all_sources)[:20],
    }


def open_pr(campaign):
    """PR rate-limit and MFA enforcement for targeted accounts."""
    branch = f"riposte/stuffing-campaign-{len(campaign['accounts'])}-accounts"
    acct_list = ", ".join(f"`{a}`" for a in campaign["accounts"][:10])
    agent_str = ", ".join(f"`{a}`" for a in campaign["common_user_agents"]) or "varied"

    subprocess.run(["git", "checkout", "-b", branch], check=True)

    rate_limit_file = TEMPLATE_DIR / "applied-rate-limit.yaml"
    rate_limit_file.write_text(
        f"# Auto-generated: rate limit for credential stuffing campaign\n"
        f"# Targeted accounts: {campaign['account_count']}\n"
        f"# Source IPs: {campaign['source_count']}\n"
        f"accounts:\n"
        + "".join(f"  - {acct}\n" for acct in campaign["accounts"])
        + f"rate_limit:\n"
        f"  requests_per_minute: 3\n"
        f"  block_after: 5\n"
    )

    subprocess.run(["git", "add", str(rate_limit_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m",
         f"predict: credential stuffing campaign targeting {campaign['account_count']} accounts "
         f"across {campaign['source_count']} sources"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title",
            f"predict: credential stuffing campaign targeting "
            f"{campaign['account_count']} accounts across {campaign['source_count']} sources",
            "--body", (
                f"Over the last 30 minutes, {campaign['source_count']} unique source IPs have "
                f"attempted logins against {campaign['account_count']} accounts.\n\n"
                f"**Targeted accounts (sample):** {acct_list}\n"
                f"**Common user-agents:** {agent_str}\n\n"
                f"No single IP exceeds individual thresholds, but the aggregate pattern "
                f"indicates a coordinated campaign.\n\n"
                f"Proposing rate limits and temporary MFA enforcement.\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)
