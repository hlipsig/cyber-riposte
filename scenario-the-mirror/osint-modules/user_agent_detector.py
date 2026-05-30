"""
User-Agent detection — identify known offensive tools, scanners, and
suspicious automation from HTTP request user-agent strings.

The agent uses this alongside IP-based detection. A spoofed IP is hard
to detect, but a default tool user-agent is a free signal — a surprising
number of attackers never bother changing it.
"""

import re
import yaml
from pathlib import Path

CONFIG_DIR = Path(__file__).parent.parent


def load_signatures(path="suspicious-user-agents.yaml"):
    with open(CONFIG_DIR / path) as f:
        return yaml.safe_load(f)


def classify_user_agent(ua_string, signatures=None):
    """
    Classify a user-agent string against known suspicious signatures.

    Returns:
        dict with keys:
            matched: bool
            tool_name: str or None
            category: str or None (recon, vuln_scan, exploit, brute_force, etc.)
            threat_level: str or None (high, medium, low)
            confidence: float (0.0-1.0)
            reason: str
        or None if no match
    """
    if not ua_string:
        return {
            "matched": True,
            "tool_name": "empty-user-agent",
            "category": "suspicious",
            "threat_level": "medium",
            "confidence": 0.6,
            "reason": "Empty user-agent string — common in custom exploit scripts",
        }

    if signatures is None:
        signatures = load_signatures()

    for category in signatures.get("categories", []):
        for sig in category.get("signatures", []):
            pattern = sig.get("pattern", "")
            if not pattern:
                continue

            match_type = sig.get("match", "contains")
            matched = False

            if match_type == "contains":
                matched = pattern.lower() in ua_string.lower()
            elif match_type == "startswith":
                matched = ua_string.lower().startswith(pattern.lower())
            elif match_type == "regex":
                matched = bool(re.search(pattern, ua_string, re.IGNORECASE))
            elif match_type == "exact":
                matched = ua_string.lower() == pattern.lower()

            if matched:
                return {
                    "matched": True,
                    "tool_name": sig.get("name", "unknown"),
                    "category": category.get("name", "unknown"),
                    "threat_level": sig.get("threat_level", "medium"),
                    "confidence": sig.get("confidence", 0.8),
                    "reason": sig.get("description", f"Matched signature: {pattern}"),
                }

    if _looks_suspicious(ua_string):
        return {
            "matched": True,
            "tool_name": "unknown-suspicious",
            "category": "heuristic",
            "threat_level": "low",
            "confidence": 0.5,
            "reason": _suspicious_reason(ua_string),
        }

    return {"matched": False}


def _looks_suspicious(ua_string):
    """Heuristic checks for user-agents that don't match a known signature."""
    ua_lower = ua_string.lower()

    if len(ua_string) < 10 and ua_string.isalpha():
        return True

    ancient_browsers = ["msie 6.0", "msie 7.0", "msie 8.0"]
    if any(old in ua_lower for old in ancient_browsers):
        if "compatible" in ua_lower:
            return True

    if ua_string == ua_string.lower() and " " not in ua_string:
        return True

    return False


def _suspicious_reason(ua_string):
    ua_lower = ua_string.lower()

    if len(ua_string) < 10:
        return f"Unusually short user-agent ({len(ua_string)} chars) — likely a custom script"

    if any(old in ua_lower for old in ["msie 6.0", "msie 7.0", "msie 8.0"]):
        return "Ancient Internet Explorer version — common default in exploit frameworks (Metasploit)"

    if ua_string == ua_string.lower() and " " not in ua_string:
        return "Single lowercase token — likely a tool identifier, not a real browser"

    return "Heuristic match — user-agent pattern is unusual for legitimate traffic"


def analyze_ua_batch(user_agents):
    """
    Analyze a batch of user-agent strings and return summary stats.

    Useful for the post-mortem report: "12 requests used Nuclei,
    47 used python-requests, 3 used sqlmap."
    """
    signatures = load_signatures()
    results = {}

    for ua in user_agents:
        classification = classify_user_agent(ua, signatures)
        if classification and classification.get("matched"):
            tool = classification["tool_name"]
            if tool not in results:
                results[tool] = {
                    "count": 0,
                    "category": classification["category"],
                    "threat_level": classification["threat_level"],
                    "example_ua": ua,
                }
            results[tool]["count"] += 1

    return results
