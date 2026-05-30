#!/usr/bin/env python3
"""
Sketch: learn per-workload egress baselines and detect deviations
that could indicate exfiltration or C2 activity.

The agent builds a profile of normal egress behavior and flags anomalies
before data leaves the network.
"""

import subprocess
import yaml
from datetime import datetime, timezone
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent


def load_baseline(workload, path="baselines"):
    baseline_file = TEMPLATE_DIR / path / f"{workload}.yaml"
    if not baseline_file.exists():
        return None
    with open(baseline_file) as f:
        return yaml.safe_load(f)


def score_deviation(baseline, current):
    """
    Score how far current egress deviates from the baseline.
    Returns a 0-10 severity score and a list of deviations.
    """
    deviations = []
    score = 0.0

    known_dests = set(baseline.get("destinations", []))
    current_dests = set(current.get("destinations", []))
    new_dests = current_dests - known_dests
    if new_dests:
        deviations.append({
            "metric": "Destinations",
            "baseline": f"{len(known_dests)} known IPs",
            "observed": f"+{len(new_dests)} unknown ({', '.join(list(new_dests)[:3])})",
            "detail": "New destination",
        })
        score += 3.0

    baseline_hours = baseline.get("active_hours", {"start": 8, "end": 22})
    current_hour = current.get("hour", 12)
    if current_hour < baseline_hours["start"] or current_hour > baseline_hours["end"]:
        deviations.append({
            "metric": "Time of day",
            "baseline": f"{baseline_hours['start']:02d}:00-{baseline_hours['end']:02d}:00 UTC",
            "observed": f"{current_hour:02d}:{current.get('minute', 0):02d} UTC",
            "detail": "Off-hours",
        })
        score += 2.0

    baseline_vol = baseline.get("hourly_volume_mb", 50)
    current_vol = current.get("hourly_volume_mb", 0)
    if baseline_vol > 0 and current_vol > baseline_vol * 3:
        ratio = current_vol / baseline_vol
        deviations.append({
            "metric": "Volume (1h)",
            "baseline": f"~{baseline_vol} MB",
            "observed": f"{current_vol} MB",
            "detail": f"{ratio:.1f}x baseline",
        })
        score += min(3.0, ratio / 2)

    baseline_protos = set(baseline.get("protocols", []))
    current_protos = set(current.get("protocols", []))
    new_protos = current_protos - baseline_protos
    if new_protos:
        deviations.append({
            "metric": "Protocol",
            "baseline": ", ".join(baseline_protos),
            "observed": ", ".join(current_protos),
            "detail": "New protocol",
        })
        score += 2.0

    return min(10.0, score), deviations


def open_pr(workload, ip, score, deviations):
    branch = f"riposte/egress-{workload}"
    table_rows = "\n".join(
        f"| {d['metric']} | {d['baseline']} | {d['observed']} | {d['detail']} |"
        for d in deviations
    )

    subprocess.run(["git", "checkout", "-b", branch], check=True)

    rule_file = TEMPLATE_DIR / f"restrict-{workload}.nft"
    rule_file.write_text(
        f"# Anomalous egress detected — restricting pending investigation\n"
        f"# Workload: {workload} ({ip})\n"
        f"# Severity: {score}/10\n"
        f"table inet filter {{\n"
        f"    chain output {{\n"
        f'        ip saddr {ip} ct state new counter drop '
        f'comment "cyber-riposte: egress restriction for {workload}"\n'
        f"    }}\n"
        f"}}\n"
    )

    subprocess.run(["git", "add", str(rule_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m",
         f"predict: anomalous egress from {workload} (severity {score}/10)"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"predict: anomalous egress from {workload} (severity {score:.1f}/10)",
            "--body", (
                f"Workload `{workload}` deviated from its egress baseline:\n\n"
                f"| Metric | Baseline | Observed | Deviation |\n|---|---|---|---|\n"
                f"{table_rows}\n\n"
                f"**Severity score: {score:.1f}/10**\n\n"
                f"Recommending egress restriction pending investigation.\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)
