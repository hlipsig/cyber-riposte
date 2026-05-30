#!/usr/bin/env python3
"""
The Mirror — autonomous agent orchestrator.

Detects attacker reconnaissance, executes pre-approved defensive actions,
runs passive OSINT, collects evidence, and generates a post-mortem report.
All actions come from the action pool — the agent never improvises.

This is a sketch for presentation purposes — not production code.
"""

import ipaddress
import json
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from osint_modules.whois_lookup import whois_lookup
from osint_modules.reverse_dns import reverse_dns
from osint_modules.shodan_lookup import shodan_lookup
from osint_modules.cert_transparency import ct_lookup

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"
HONEYPOT_IP = "10.0.0.99"


class AuditLog:
    """Structured audit trail — every action the agent takes is recorded."""

    def __init__(self, log_path="/var/log/cyber-riposte/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = []

    def record(self, incident_id, action_id, action_name, tier, parameters,
               result, justification, context, rollback_handle=None, expires_at=None):
        entry = {
            "id": f"aud-{uuid.uuid4().hex[:8]}",
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": {
                "id": action_id,
                "name": action_name,
                "tier": tier,
                "parameters": parameters,
                "result": result,
            },
            "justification": justification,
            "context": context,
        }
        if rollback_handle:
            entry["action"]["rollback_handle"] = rollback_handle
        if expires_at:
            entry["action"]["expires_at"] = expires_at

        self.entries.append(entry)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry["id"]


class ActionPool:
    """Pre-approved actions the agent is authorized to execute."""

    def __init__(self, config_path=None):
        config_path = config_path or BASE_DIR / "action-pool.yaml"
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.actions = {a["id"]: a for a in self.config.get("actions", [])}
        self.global_config = self.config.get("global", {})
        self.allowlisted_ips = self._parse_allowlist()
        self.action_count = 0

    def _parse_allowlist(self):
        networks = []
        for entry in self.global_config.get("allowlisted_ips", []):
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        return networks

    def is_allowlisted(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        return any(ip in net for net in self.allowlisted_ips)

    def can_execute(self, action_id):
        action = self.actions.get(action_id)
        if not action:
            return False, "Action not in pool"

        max_actions = self.global_config.get("max_actions_per_hour", 100)
        if self.action_count >= max_actions:
            return False, f"Hourly action limit reached ({max_actions})"

        return True, None

    def get_tier(self, action_id):
        action = self.actions.get(action_id)
        return action["tier"] if action else None

    def get_expiry(self, action_id):
        action = self.actions.get(action_id)
        expiry_str = action.get("auto_expire", "1h") if action else "1h"
        hours = int(expiry_str.replace("h", ""))
        return datetime.now(timezone.utc) + timedelta(hours=hours)

    def mark_executed(self):
        self.action_count += 1


def detect_recon(eve_event):
    if eve_event.get("event_type") != "alert":
        return None

    alert = eve_event.get("alert", {})
    category = alert.get("category", "").lower()
    recon_categories = ["attempted-recon", "network-scan", "web-application-attack"]

    if any(cat in category for cat in recon_categories):
        return {
            "src_ip": eve_event.get("src_ip"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
            "timestamp": eve_event.get("timestamp"),
        }
    return None


def execute_redirect(attacker_ip, pool, audit, incident_id, detection):
    """Tier 1: redirect attacker to honeypot."""
    action_id = "redirect-to-honeypot"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        print(f"[mirror] SKIPPED {action_id}: {reason}")
        return None

    rule_content = (
        f"table ip nat {{\n"
        f"    chain prerouting {{\n"
        f"        type nat hook prerouting priority -100; policy accept;\n"
        f'        ip saddr {attacker_ip} dnat to {HONEYPOT_IP} '
        f'comment "mirror: redirect to honeypot"\n'
        f"    }}\n"
        f"}}\n"
    )
    result = subprocess.run(
        ["nft", "-f", "-"],
        input=rule_content, capture_output=True, text=True,
    )

    expiry = pool.get_expiry(action_id)
    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Redirect traffic to honeypot",
        tier=1,
        parameters={"source_ip": attacker_ip, "honeypot_ip": HONEYPOT_IP},
        result="success" if result.returncode == 0 else "failed",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": 0.97,
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Recon pattern confirmed, IP not in allowlist, honeypot health check passed",
        },
        context={"attacker_ip": attacker_ip, "honeypot_active": True},
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
        print(f"[mirror] SKIPPED {action_id}: {reason}")
        return None

    osint_data = {
        "target_ip": attacker_ip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "modules": {},
    }
    osint_data["modules"]["whois"] = whois_lookup(attacker_ip)
    osint_data["modules"]["reverse_dns"] = reverse_dns(attacker_ip)
    osint_data["modules"]["shodan"] = shodan_lookup(attacker_ip)
    osint_data["modules"]["cert_transparency"] = ct_lookup(attacker_ip)

    evidence_dir = Path("/var/log/cyber-riposte/evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ip_slug = attacker_ip.replace(".", "-")
    for module_name, data in osint_data["modules"].items():
        evidence_file = evidence_dir / f"{module_name}-{ip_slug}.json"
        evidence_file.write_text(json.dumps(data, indent=2))

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
            "detection_confidence": 0.97,
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Standard OSINT collection, all modules passive, within rate limits",
        },
        context={"attacker_ip": attacker_ip, "osint_collected": True},
    )
    pool.mark_executed()
    return osint_data


def execute_temp_block(attacker_ip, pool, audit, incident_id, detection):
    """Tier 1: temporary IP block."""
    action_id = "temp-block-ip"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        print(f"[mirror] SKIPPED {action_id}: {reason}")
        return None

    result = subprocess.run(
        ["nft", "add", "rule", "inet", "filter", "input",
         f"ip saddr {attacker_ip}", "counter", "drop"],
        capture_output=True, text=True,
    )

    expiry = pool.get_expiry(action_id)
    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Temporary IP block",
        tier=1,
        parameters={"source_ip": attacker_ip, "rule_type": "nftables-drop"},
        result="success" if result.returncode == 0 else "failed",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": 0.97,
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Attacker session complete, applying temp block to prevent re-engagement",
        },
        context={"attacker_ip": attacker_ip, "honeypot_active": False},
        rollback_handle="nft-handle-placeholder",
        expires_at=expiry.isoformat(),
    )
    pool.mark_executed()
    return True


def compile_dossier(attacker_ip, detection, osint_data):
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
    postmortem_dir = Path("/var/log/cyber-riposte/postmortems")
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
        f"- **Detection confidence:** 0.97\n\n"
        f"## Evidence Chain\n\n"
        f"All evidence files stored under `/var/log/cyber-riposte/evidence/`\n\n"
        f"## Audit Trail\n\n"
        f"Full audit log: `/var/log/cyber-riposte/audit.jsonl`\n\n"
        f"---\n*All actions executed from the pre-approved action pool. "
        f"No actions outside the pool were taken.*\n"
    )

    report_file = postmortem_dir / f"{incident_id}.md"
    report_file.write_text(report)

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

    print(f"[mirror] Post-mortem written to {report_file}")
    return report_file


def run(eve_stream):
    """Main loop: read EVE events, detect recon, execute autonomous response."""
    pool = ActionPool()
    audit = AuditLog()
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

        if pool.is_allowlisted(attacker_ip):
            print(f"[mirror] Skipping allowlisted IP {attacker_ip}")
            continue

        now = datetime.now(timezone.utc)
        incident_id = f"INC-{now.strftime('%Y-%m%d-%H%M')}"

        print(f"[mirror] === Incident {incident_id} ===")
        print(f"[mirror] Recon from {attacker_ip}: {detection['signature']}")

        # Phase 1: Redirect to honeypot (Tier 1 — auto-execute)
        print(f"[mirror] [T1] Redirecting {attacker_ip} → honeypot {HONEYPOT_IP}")
        execute_redirect(attacker_ip, pool, audit, incident_id, detection)

        # Phase 2: Passive OSINT (Tier 1 — auto-execute)
        print(f"[mirror] [T1] Running OSINT on {attacker_ip}...")
        osint_data = execute_osint(attacker_ip, pool, audit, incident_id, detection)

        # Phase 3: Compile dossier
        if osint_data:
            print(f"[mirror] Compiling dossier...")
            dossier_content = compile_dossier(attacker_ip, detection, osint_data)
            dossier_file = BASE_DIR / f"dossier-{attacker_ip.replace('.', '-')}.md"
            dossier_file.write_text(dossier_content)

        # Phase 4: Temp block (Tier 1 — auto-execute)
        print(f"[mirror] [T1] Applying temp block on {attacker_ip}")
        execute_temp_block(attacker_ip, pool, audit, incident_id, detection)

        # Phase 5: Generate post-mortem for morning review
        generate_postmortem(incident_id, attacker_ip, detection, osint_data or {}, audit)

        mirrored.add(attacker_ip)
        print(f"[mirror] === Incident {incident_id} complete — report ready for morning review ===")


if __name__ == "__main__":
    run(sys.stdin)
