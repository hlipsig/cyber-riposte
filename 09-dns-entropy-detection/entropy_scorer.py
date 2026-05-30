#!/usr/bin/env python3
"""
Sketch: score DNS queries by entropy and statistical anomalies to detect
tunneling/exfiltration through domains not on any threat intel list.

The agent runs this analysis continuously against DNS query logs and
opens PRs when it finds domains with tunneling-like characteristics.
"""

import math
import re
import subprocess
import yaml
from collections import Counter, defaultdict
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent


def load_thresholds(path="thresholds.yaml"):
    with open(TEMPLATE_DIR / path) as f:
        return yaml.safe_load(f)


def shannon_entropy(s):
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def looks_encoded(label):
    """Check if a subdomain label looks like base32/base64/hex encoding."""
    if len(label) < 10:
        return False
    alnum_ratio = sum(c.isalnum() for c in label) / len(label)
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    return alnum_ratio > 0.95 and digit_ratio > 0.15


def analyze_domain(queries):
    """
    Analyze a set of queries to a single parent domain.

    Returns anomaly scores and evidence.
    """
    subdomains = []
    for q in queries:
        parts = q["query"].split(".")
        if len(parts) > 2:
            subdomains.append(".".join(parts[:-2]))

    if not subdomains:
        return None

    entropies = [shannon_entropy(s) for s in subdomains]
    avg_entropy = sum(entropies) / len(entropies)
    avg_length = sum(len(s) for s in subdomains) / len(subdomains)
    encoded_ratio = sum(looks_encoded(s) for s in subdomains) / len(subdomains)
    query_rate = len(queries)  # per analysis window

    querying_hosts = list({q.get("source_ip", "") for q in queries})

    return {
        "avg_entropy": round(avg_entropy, 2),
        "avg_label_length": round(avg_length, 1),
        "encoded_ratio": round(encoded_ratio, 2),
        "query_count": len(queries),
        "sample_queries": [q["query"] for q in queries[:5]],
        "querying_hosts": querying_hosts,
    }


def is_anomalous(analysis, thresholds):
    """Check if domain analysis exceeds tunneling thresholds."""
    return (
        analysis["avg_entropy"] > thresholds.get("entropy_threshold", 3.5)
        and analysis["avg_label_length"] > thresholds.get("label_length_threshold", 20)
        and analysis["query_count"] > thresholds.get("min_query_count", 10)
    )


def open_pr(domain, analysis):
    branch = f"riposte/entropy-{domain.replace('.', '-')}"
    hosts = ", ".join(f"`{h}`" for h in analysis["querying_hosts"])

    subprocess.run(["git", "checkout", "-b", branch], check=True)

    sinkhole_file = TEMPLATE_DIR / f"sinkhole-{domain.replace('.', '-')}.conf"
    sinkhole_file.write_text(
        f"# Anomalous entropy detected — probable DNS tunnel\n"
        f"# Avg entropy: {analysis['avg_entropy']} bits/char\n"
        f"# Avg label length: {analysis['avg_label_length']} chars\n"
        f"# Query count: {analysis['query_count']}\n"
        f'server:\n'
        f'    local-zone: "{domain}" redirect\n'
        f'    local-data: "{domain} A 127.0.0.1"\n'
    )

    subprocess.run(["git", "add", str(sinkhole_file)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"predict: probable DNS tunnel — {domain} (entropy {analysis['avg_entropy']})"],
        check=True,
    )
    subprocess.run(["git", "push", "-u", "origin", branch], check=True)
    subprocess.run(
        [
            "gh", "pr", "create",
            "--title", f"predict: probable DNS tunnel — {domain} (entropy {analysis['avg_entropy']})",
            "--body", (
                f"DNS query analysis detected anomalous patterns for `*.{domain}`:\n\n"
                f"| Metric | Value | Normal Range |\n|---|---|---|\n"
                f"| Subdomain entropy | {analysis['avg_entropy']} bits/char | < 3.0 |\n"
                f"| Avg label length | {analysis['avg_label_length']} chars | < 15 |\n"
                f"| Encoded-looking ratio | {analysis['encoded_ratio']:.0%} | < 10% |\n"
                f"| Query count | {analysis['query_count']} | baseline |\n\n"
                f"**Querying hosts:** {hosts}\n\n"
                f"This domain is not on any current threat intel list but matches the "
                f"statistical fingerprint of DNS tunneling. Proposing sinkhole.\n\n"
                f"---\n*Opened by cyber-riposte agent*"
            ),
            "--reviewer", "security-team",
        ],
        check=True,
    )
    subprocess.run(["git", "checkout", "main"], check=True)
