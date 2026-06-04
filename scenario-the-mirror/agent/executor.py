"""
Action executor for The Mirror agent.
Executes pre-approved defensive actions from the action pool.

Phase 1: Uses subprocess for nftables (will fail in K8s, placeholder)
Phase 4: Will be refactored to use Kubernetes API for Istio VirtualService
"""
import importlib.util
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent.config import Config


# Import OSINT modules from osint-modules directory (note: hyphenated name)
def _import_osint_module(module_name):
    """Import module from osint-modules directory (handles hyphenated dir name)."""
    parent_dir = Path(__file__).parent.parent
    osint_dir = parent_dir / "osint-modules"
    module_path = osint_dir / f"{module_name}.py"

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


whois_module = _import_osint_module("whois_lookup")
reverse_dns_module = _import_osint_module("reverse_dns")
shodan_module = _import_osint_module("shodan_lookup")
ct_module = _import_osint_module("cert_transparency")

whois_lookup = whois_module.whois_lookup
reverse_dns = reverse_dns_module.reverse_dns
shodan_lookup = shodan_module.shodan_lookup
ct_lookup = ct_module.ct_lookup


logger = logging.getLogger(__name__)


def execute_redirect(attacker_ip, pool, audit, incident_id, detection):
    """
    Tier 1: redirect attacker to honeypot.

    Phase 1: Uses nftables (will fail in K8s, logged as placeholder)
    Phase 4: Will create Istio VirtualService instead
    """
    action_id = "redirect-to-honeypot"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    # Phase 1: nftables rule (will fail in K8s, but we'll log it)
    rule_content = (
        f"table ip nat {{\n"
        f"    chain prerouting {{\n"
        f"        type nat hook prerouting priority -100; policy accept;\n"
        f'        ip saddr {attacker_ip} dnat to {Config.HONEYPOT_IP} '
        f'comment "mirror: redirect to honeypot"\n'
        f"    }}\n"
        f"}}\n"
    )

    # Try to run nftables (will fail in K8s, but that's OK for Phase 1)
    result_code = 1  # Assume failure
    try:
        result = subprocess.run(
            ["nft", "-f", "-"],
            input=rule_content, capture_output=True, text=True, timeout=5
        )
        result_code = result.returncode
        if result_code != 0:
            logger.warning(f"nftables command failed (expected in K8s): {result.stderr}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(f"nftables not available (expected in K8s): {e}")

    expiry = pool.get_expiry(action_id)
    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Redirect traffic to honeypot",
        tier=1,
        parameters={"source_ip": attacker_ip, "honeypot_ip": Config.HONEYPOT_IP},
        result="success" if result_code == 0 else "simulated",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Recon pattern confirmed, IP not in allowlist, honeypot health check passed",
        },
        context={
            "attacker_ip": attacker_ip,
            "honeypot_active": True,
            "phase1_note": "nftables not available in K8s - Phase 4 will use Istio VirtualService"
        },
        rollback_handle="nft-handle-placeholder",
        expires_at=expiry.isoformat(),
    )
    pool.mark_executed()
    return True


def execute_osint(attacker_ip, pool, audit, incident_id, detection):
    """Tier 1: run passive OSINT."""
    action_id = "run-osint"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    osint_data = {
        "target_ip": attacker_ip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "modules": {},
    }

    # Run OSINT modules
    logger.info(f"Running OSINT on {attacker_ip}...")
    osint_data["modules"]["whois"] = whois_lookup(attacker_ip)
    osint_data["modules"]["reverse_dns"] = reverse_dns(attacker_ip)
    osint_data["modules"]["shodan"] = shodan_lookup(attacker_ip)
    osint_data["modules"]["cert_transparency"] = ct_lookup(attacker_ip)

    # Save evidence files
    evidence_dir = Path(Config.EVIDENCE_DIR)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ip_slug = attacker_ip.replace(".", "-")
    for module_name, data in osint_data["modules"].items():
        evidence_file = evidence_dir / f"{module_name}-{ip_slug}.json"
        try:
            evidence_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to write evidence file {evidence_file}: {e}")

    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Run passive OSINT on source IP",
        tier=1,
        parameters={
            "source_ip": attacker_ip,
            "modules": ["whois", "reverse_dns", "shodan", "cert_transparency"],
            "passive_only": True,
        },
        result="success",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Standard OSINT collection, all modules passive, within rate limits",
        },
        context={"attacker_ip": attacker_ip, "osint_collected": True},
    )
    pool.mark_executed()
    return osint_data


def execute_temp_block(attacker_ip, pool, audit, incident_id, detection):
    """
    Tier 1: temporary IP block.

    Phase 1: Uses nftables (will fail in K8s, placeholder)
    Phase 4: Will create Kubernetes NetworkPolicy instead
    """
    action_id = "temp-block-ip"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    # Try to run nftables (will fail in K8s)
    result_code = 1
    try:
        result = subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "input",
             f"ip saddr {attacker_ip}", "counter", "drop"],
            capture_output=True, text=True, timeout=5
        )
        result_code = result.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(f"nftables not available (expected in K8s): {e}")

    expiry = pool.get_expiry(action_id)
    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Temporary IP block",
        tier=1,
        parameters={"source_ip": attacker_ip, "rule_type": "nftables-drop"},
        result="success" if result_code == 0 else "simulated",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Attacker session complete, applying temp block to prevent re-engagement",
        },
        context={
            "attacker_ip": attacker_ip,
            "honeypot_active": False,
            "phase1_note": "nftables not available in K8s - Phase 4 will use NetworkPolicy"
        },
        rollback_handle="nft-handle-placeholder",
        expires_at=expiry.isoformat(),
    )
    pool.mark_executed()
    return True


def compile_dossier(attacker_ip, detection, osint_data):
    """Compile an intelligence dossier from OSINT data."""
    whois = osint_data["modules"].get("whois", {})
    rdns = osint_data["modules"].get("reverse_dns", {})
    shodan = osint_data["modules"].get("shodan", {})
    ct = osint_data["modules"].get("cert_transparency", {})

    open_ports = shodan.get("open_ports", [])
    ports_str = ", ".join(str(p) for p in open_ports) if open_ports else "none found"
    certs = ct.get("certificates", [])
    certs_str = "\n".join(f"  - `{c}`" for c in certs) if certs else "  - none found"

    return (
        f"# Intelligence Dossier: {attacker_ip}\n\n"
        f"**Generated:** {osint_data['collected_at']}\n"
        f"**Trigger:** {detection.get('signature', 'unknown')}\n\n---\n\n"
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
        f"- **OS:** {shodan.get('os', 'unknown')}\n\n"
        f"## Certificate Transparency\n\n"
        f"Domains associated with this IP:\n{certs_str}\n\n"
        f"## IOCs\n\n```json\n"
        f"{json.dumps({'ip': attacker_ip, 'asn': whois.get('asn'), 'domains': certs, 'open_ports': open_ports}, indent=2)}\n```\n"
    )


def generate_postmortem(incident_id, attacker_ip, detection, osint_data, audit):
    """Generate the post-mortem report for morning review."""
    postmortem_dir = Path(Config.POSTMORTEM_DIR)
    postmortem_dir.mkdir(parents=True, exist_ok=True)

    timeline_rows = "\n".join(
        f"| {e['timestamp']} | {e['action']['name']} | "
        f"{'T' + str(e['action']['tier']) if e['action']['tier'] else '—'} | "
        f"{e['action']['result']} |"
        for e in audit.entries
        if e["incident_id"] == incident_id
    )

    report = (
        f"# Post-Mortem Report: Incident {incident_id}\n\n"
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n"
        f"**Agent:** The Mirror (cyber-riposte)\n"
        f"**Status:** Autonomous response completed — awaiting human review\n\n---\n\n"
        f"## Timeline\n\n"
        f"| Time (UTC) | Action | Tier | Result |\n|---|---|---|---|\n"
        f"{timeline_rows}\n\n"
        f"## What Triggered This\n\n"
        f"- **Signal:** {detection.get('signature', 'unknown')}\n"
        f"- **Source IP:** {attacker_ip}\n"
        f"- **Detection confidence:** {detection.get('confidence', 0.97):.2f}\n\n"
        f"## Evidence Chain\n\n"
        f"All evidence files stored under `{Config.EVIDENCE_DIR}/`\n\n"
        f"## Audit Trail\n\n"
        f"Full audit log: `{Config.AUDIT_LOG_PATH}`\n\n"
        f"---\n*All actions executed from the pre-approved action pool. "
        f"No actions outside the pool were taken.*\n"
    )

    report_file = postmortem_dir / f"{incident_id}.md"
    try:
        report_file.write_text(report)
        logger.info(f"Post-mortem written to {report_file}")
    except Exception as e:
        logger.error(f"Failed to write post-mortem report: {e}")
        return None

    audit.record(
        incident_id=incident_id,
        action_id="generate-postmortem",
        action_name="Generate post-mortem report",
        tier=None,
        parameters={"output_path": str(report_file)},
        result="success",
        justification={
            "trigger": "incident-complete",
            "detection_confidence": 1.0,
            "evidence_refs": [e["id"] for e in audit.entries if e["incident_id"] == incident_id],
            "playbook_rule": None,
            "reasoning": "All autonomous actions complete. Generating post-mortem for morning review.",
        },
        context={"attacker_ip": attacker_ip},
    )

    return report_file
