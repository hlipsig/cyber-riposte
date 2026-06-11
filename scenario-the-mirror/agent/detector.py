"""
Detection logic for The Mirror agent.
Detects reconnaissance from IDS alerts and/or user-agent analysis.
"""
import importlib.util
import logging
import sys
from pathlib import Path


# Import user_agent_detector from osint-modules directory (note: hyphenated name)
def _import_osint_module(module_name):
    """Import module from osint-modules directory (handles hyphenated dir name)."""
    parent_dir = Path(__file__).parent.parent
    osint_dir = parent_dir / "osint-modules"
    module_path = osint_dir / f"{module_name}.py"

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


user_agent_detector = _import_osint_module("user_agent_detector")
classify_user_agent = user_agent_detector.classify_user_agent


logger = logging.getLogger(__name__)


def detect_recon(eve_event):
    """
    Detect reconnaissance from IDS alerts and/or user-agent analysis.

    Phase 1: Enhanced with Suricata IDS integration.

    Detection sources:
    1. Suricata IDS alerts (port scans, web attacks, CVE exploits)
    2. Suspicious user-agent strings (Nuclei, sqlmap, gobuster, Nmap, etc.)
    3. Behavioral patterns (rapid requests, 404 patterns, SSH brute force)

    Either signal alone is sufficient to trigger, but multiple signals
    increase detection confidence. Confidence scores:
    - IDS high-severity alert: 0.95
    - IDS medium-severity alert: 0.85
    - Custom Mirror rules (SID 9000000+): 0.90+
    - Suspicious user-agent: 0.70-0.90 (based on threat level)

    Args:
        eve_event: Suricata EVE event (dict)

    Returns:
        Detection dict with signals and confidence, or None if no recon detected
    """
    detection = {
        "src_ip": eve_event.get("src_ip"),
        "timestamp": eve_event.get("timestamp"),
        "signals": [],
        "confidence": 0.0,
    }

    # Signal 1: IDS alerts (Phase 1)
    if eve_event.get("event_type") == "alert":
        alert = eve_event.get("alert", {})
        category = alert.get("category", "").lower()
        signature_id = alert.get("signature_id", 0)
        severity = alert.get("severity", 3)

        # Reconnaissance categories
        recon_categories = [
            "attempted-recon",
            "network-scan",
            "web-application-attack",
            "attempted-user",  # Brute force
            "attempted-admin",  # Exploit attempts
            "attempted-dos",    # DoS/DDoS
            "trojan-activity",  # Malware/crypto mining
        ]

        if any(cat in category for cat in recon_categories):
            detection["signals"].append({
                "type": "ids_alert",
                "signature": alert.get("signature"),
                "signature_id": signature_id,
                "category": category,
                "severity": severity,
            })

            # Confidence based on severity and rule origin
            if signature_id >= 9000000:  # Custom Mirror rules
                conf = 0.95
            elif severity == 1:  # High severity
                conf = 0.95
            elif severity == 2:  # Medium severity
                conf = 0.85
            else:  # Low severity
                conf = 0.75

            detection["confidence"] = max(detection["confidence"], conf)

    # Signal 2: User-agent analysis
    ua_string = eve_event.get("http", {}).get("http_user_agent", "")
    if ua_string:
        ua_result = classify_user_agent(ua_string)
        if ua_result and ua_result.get("matched"):
            detection["signals"].append({
                "type": "user_agent",
                "tool_name": ua_result["tool_name"],
                "category": ua_result["category"],
                "threat_level": ua_result["threat_level"],
                "ua_string": ua_string,
            })
            ua_conf = ua_result.get("confidence", 0.5)
            # Combine confidences if both signals present
            if detection["confidence"] > 0:
                detection["confidence"] = min(1.0, detection["confidence"] + ua_conf * 0.5)
            else:
                detection["confidence"] = ua_conf

    # Return None if no signals detected
    if not detection["signals"]:
        return None

    detection["signature"] = _summarize_signals(detection["signals"])
    detection["severity"] = _derive_severity(detection["signals"])

    return detection


def _summarize_signals(signals):
    """Create a human-readable summary of detection signals."""
    parts = []
    for s in signals:
        if s["type"] == "ids_alert":
            parts.append(s["signature"])
        elif s["type"] == "user_agent":
            parts.append(f"suspicious UA: {s['tool_name']}")
    return " + ".join(parts)


def _derive_severity(signals):
    """
    Derive severity from signals.
    Returns 1 (high), 2 (medium), or 3 (low).
    """
    for s in signals:
        if s["type"] == "user_agent" and s.get("threat_level") == "high":
            return 1
        if s["type"] == "ids_alert" and s.get("severity", 99) <= 2:
            return 1
    return 2
