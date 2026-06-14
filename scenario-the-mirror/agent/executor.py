"""
Action executor for The Mirror agent.
Executes pre-approved defensive actions from the action pool.

Phase 1-3: Uses subprocess for nftables (will fail in K8s, placeholder)
Phase 4: Uses Kubernetes API for Istio VirtualService (dynamic traffic redirection)
"""
import importlib.util
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Tuple, Optional

from agent.config import Config
from psycopg2.extras import Json

# Kubernetes API client (Phase 4)
try:
    from kubernetes import client, config as k8s_config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    logging.warning("Kubernetes client not available. Install with: pip install kubernetes")


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


def _create_virtualservice(attacker_ip: str, incident_id: str, duration_hours: int = 24) -> Tuple[str, bool]:
    """
    Phase 2: Create Istio VirtualService to redirect attacker traffic to honeypot.

    Uses IstioManager for dynamic VirtualService manipulation.

    Returns (vs_name, success).
    """
    try:
        from agent.istio_manager import get_istio_manager

        istio = get_istio_manager()

        # Create redirect with configured honeypot
        success = istio.create_redirect(
            incident_id=incident_id,
            attacker_ip=attacker_ip,
            honeypot_host=Config.HONEYPOT_IP,
            honeypot_port=80,
            ttl_hours=duration_hours
        )

        vs_name = f"mirror-redirect-{incident_id.lower()}"
        return vs_name, success

    except ImportError as e:
        logger.error(f"IstioManager not available: {e}")
        return "", False
    except Exception as e:
        logger.error(f"Failed to create VirtualService via IstioManager: {e}")
        return "", False


def _create_virtualservice_legacy(attacker_ip: str, incident_id: str, duration_hours: int = 24) -> Tuple[str, bool]:
    """
    Legacy VirtualService creation (Phase 1 fallback).
    Kept for reference, use _create_virtualservice instead.
    """
    if not K8S_AVAILABLE:
        logger.error("Kubernetes client not available. Cannot create VirtualService.")
        return "", False

    try:
        # Load in-cluster Kubernetes config
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        try:
            # Fallback to kubeconfig (for local development)
            k8s_config.load_kube_config()
        except k8s_config.ConfigException:
            logger.error("Could not load Kubernetes config")
            return "", False

    # VirtualService name (sanitize IP for DNS)
    vs_name = f"redirect-attacker-{attacker_ip.replace('.', '-')}"
    namespace = "the-mirror"

    # VirtualService spec
    vs_spec = {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {
            "name": vs_name,
            "namespace": namespace,
            "labels": {
                "app": "mirror-agent",
                "route-type": "attacker",
                "incident": incident_id,
                "attacker_ip": attacker_ip.replace(".", "-"),  # Labels can't have dots
            },
            "annotations": {
                "mirror.cyber-riposte.io/created-at": datetime.now(timezone.utc).isoformat(),
                "mirror.cyber-riposte.io/expires-at": (
                    datetime.now(timezone.utc) + timedelta(hours=duration_hours)
                ).isoformat(),
                "mirror.cyber-riposte.io/incident-id": incident_id,
            },
        },
        "spec": {
            "hosts": ["*"],
            "gateways": ["mirror-gateway"],
            "http": [
                {
                    "match": [
                        {
                            "headers": {
                                "x-forwarded-for": {
                                    "exact": attacker_ip
                                }
                            }
                        }
                    ],
                    "route": [
                        {
                            "destination": {
                                "host": Config.HONEYPOT_IP,  # honeypot-service
                                "port": {"number": 80}
                            }
                        }
                    ],
                }
            ],
        },
    }

    try:
        # Create VirtualService via Kubernetes API
        api = client.CustomObjectsApi()
        api.create_namespaced_custom_object(
            group="networking.istio.io",
            version="v1beta1",
            namespace=namespace,
            plural="virtualservices",
            body=vs_spec,
        )

        logger.info(f"Created VirtualService: {vs_name} (redirects {attacker_ip} → honeypot)")

        # Phase 3: Store VirtualService in database
        try:
            from agent.db import get_db_manager
            db = get_db_manager()
            db.create_virtualservice(
                incident_id=incident_id,
                vs_name=vs_name,
                vs_namespace=namespace,
                attacker_ip=attacker_ip,
                honeypot_destination=Config.HONEYPOT_IP,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=duration_hours),
            )
        except Exception as e:
            logger.warning(f"Failed to record VirtualService in database: {e}")

        return vs_name, True

    except client.rest.ApiException as e:
        if e.status == 409:  # Already exists
            logger.warning(f"VirtualService {vs_name} already exists")
            return vs_name, True
        else:
            logger.error(f"Failed to create VirtualService: {e}")
            return "", False
    except Exception as e:
        logger.error(f"Unexpected error creating VirtualService: {e}")
        return "", False


def execute_redirect(attacker_ip, pool, audit, incident_id, detection):
    """
    Tier 1: redirect attacker to honeypot.

    Phase 4: Creates Istio VirtualService for dynamic traffic redirection.
    Fallback to nftables if Kubernetes API unavailable (Phase 1 behavior).
    """
    action_id = "redirect-to-honeypot"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    # Phase 2: Create Istio VirtualService redirect
    vs_name, vs_success = _create_virtualservice(attacker_ip, incident_id, duration_hours=24)

    if vs_success:
        # VirtualService created successfully
        expiry = pool.get_expiry(action_id)
        audit.record(
            incident_id=incident_id,
            action_id=action_id,
            action_name="Redirect traffic to honeypot via Istio VirtualService",
            tier=1,
            parameters={
                "source_ip": attacker_ip,
                "honeypot_ip": Config.HONEYPOT_IP,
                "virtualservice_name": vs_name,
                "method": "istio"
            },
            result="success",
            justification={
                "trigger": "recon-detected",
                "detection_confidence": detection.get("confidence", 0.97),
                "evidence_refs": [detection.get("timestamp", "")],
                "playbook_rule": action_id,
                "reasoning": "Recon pattern confirmed, IP not in allowlist, VirtualService created successfully via IstioManager",
            },
            context={
                "attacker_ip": attacker_ip,
                "honeypot_active": True,
                "virtualservice_name": vs_name,
                "namespace": "the-mirror",
                "method": "istio",
            },
            rollback_handle=vs_name,  # VirtualService name for cleanup
            expires_at=expiry,
        )
        pool.mark_executed()
        logger.info(f"✅ Istio redirect created: {attacker_ip} → {Config.HONEYPOT_IP}")
        return True

    # Fallback: Log error (no nftables fallback in Phase 2)
    logger.error("VirtualService creation failed - Istio redirection unavailable")

    rule_content = (
        f"table ip nat {{\n"
        f"    chain prerouting {{\n"
        f"        type nat hook prerouting priority -100; policy accept;\n"
        f'        ip saddr {attacker_ip} dnat to {Config.HONEYPOT_IP} '
        f'comment "mirror: redirect to honeypot"\n'
        f"    }}\n"
        f"}}\n"
    )

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
        action_name="Redirect traffic to honeypot (fallback mode)",
        tier=1,
        parameters={"source_ip": attacker_ip, "honeypot_ip": Config.HONEYPOT_IP, "method": "nftables"},
        result="success" if result_code == 0 else "simulated",
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": "Recon pattern confirmed, VirtualService unavailable, fell back to nftables",
        },
        context={
            "attacker_ip": attacker_ip,
            "honeypot_active": True,
            "method": "nftables-fallback",
            "note": "VirtualService creation failed - nftables not available in K8s"
        },
        rollback_handle="nft-handle-placeholder",
        expires_at=expiry,
    )
    pool.mark_executed()
    return True


def execute_osint(attacker_ip, pool, audit, incident_id, detection):
    """
    Tier 1: run passive OSINT.

    Phase 3: Uses OSINT orchestrator with parallel execution and caching.
    """
    action_id = "run-osint"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    # Phase 3: Use OSINT orchestrator for parallel execution and caching
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from osint_modules.osint_orchestrator import gather_intelligence

        logger.info(f"Running OSINT orchestrator on {attacker_ip}...")
        osint_data = gather_intelligence(attacker_ip)

    except Exception as e:
        logger.error(f"OSINT orchestrator failed, falling back to basic modules: {e}")
        # Fallback to individual modules
        from osint_modules.whois_lookup import whois_lookup
        from osint_modules.reverse_dns import reverse_dns
        from osint_modules.shodan_lookup import shodan_lookup

        osint_data = {
            "target_ip": attacker_ip,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "modules": {
                "whois": whois_lookup(attacker_ip),
                "reverse_dns": reverse_dns(attacker_ip),
                "shodan": shodan_lookup(attacker_ip),
            },
            "fallback_mode": True,
        }

    # Phase 3: Save evidence to database and update incident with attacker_info
    try:
        from agent.db import get_db_manager
        db = get_db_manager()

        # Save individual module results as evidence
        if "raw_modules" in osint_data:
            for module_name, data in osint_data["raw_modules"].items():
                if data and "error" not in data:
                    db.add_evidence(
                        incident_id=incident_id,
                        evidence_type=f"osint_{module_name}",
                        data=data,
                    )
        elif "modules" in osint_data:
            # Fallback mode structure
            for module_name, data in osint_data["modules"].items():
                if data and "error" not in data:
                    db.add_evidence(
                        incident_id=incident_id,
                        evidence_type=f"osint_{module_name}",
                        data=data,
                    )

        # Update incident with aggregated attacker_info
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE incidents
                    SET attacker_info = %s,
                        last_updated = NOW()
                    WHERE incident_id = %s
                """, (Json(osint_data), incident_id))
                conn.commit()
                logger.info(f"Updated incident {incident_id} with OSINT data")

    except Exception as e:
        logger.warning(f"Failed to save OSINT data to database: {e}")

    # Phase 1-2: Save evidence files (backward compatibility)
    evidence_dir = Path(Config.EVIDENCE_DIR)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ip_slug = attacker_ip.replace(".", "-")

    # Save aggregated OSINT data
    evidence_file = evidence_dir / f"osint-{ip_slug}.json"
    try:
        evidence_file.write_text(json.dumps(osint_data, indent=2))
        logger.debug(f"Saved OSINT evidence file: {evidence_file}")
    except Exception as e:
        logger.error(f"Failed to write evidence file {evidence_file}: {e}")

    # Determine result from orchestrator
    modules_succeeded = osint_data.get("modules_succeeded", [])
    modules_failed = osint_data.get("modules_failed", [])
    modules_run = osint_data.get("modules_run", [])

    result_status = "success" if len(modules_succeeded) > 0 else "partial"
    if len(modules_failed) > len(modules_succeeded):
        result_status = "partial"

    # Extract key intelligence for summary
    intelligence_summary = []
    if osint_data.get("organization"):
        intelligence_summary.append(f"Org: {osint_data['organization']}")
    if osint_data.get("asn"):
        intelligence_summary.append(f"ASN: {osint_data['asn']}")
    if osint_data.get("open_ports"):
        intelligence_summary.append(f"Ports: {len(osint_data['open_ports'])}")
    if osint_data.get("hosting_provider"):
        intelligence_summary.append(f"Host: {osint_data['hosting_provider']}")

    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Run passive OSINT on source IP (orchestrated)",
        tier=1,
        parameters={
            "source_ip": attacker_ip,
            "modules": modules_run,
            "passive_only": True,
            "orchestrator": "osint_orchestrator",
            "cache_enabled": True,
        },
        result=result_status,
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": f"OSINT orchestrator: {len(modules_succeeded)}/{len(modules_run)} modules succeeded. {', '.join(intelligence_summary)}",
        },
        context={
            "attacker_ip": attacker_ip,
            "osint_collected": True,
            "modules_succeeded": modules_succeeded,
            "modules_failed": modules_failed,
            "intelligence_summary": intelligence_summary,
        },
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


def generate_postmortem(incident_id, attacker_ip, detection, osint_data, audit, evidence_files=None):
    """
    Generate the post-mortem report for morning review.

    Phase 4: Also creates GitHub issue with incident report.
    Phase 5: Includes evidence file links.
    """
    if evidence_files is None:
        evidence_files = {}
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

    # Phase 4: Create GitHub issue with incident report
    github_issue_url = None
    try:
        from agent.github_reporter import create_incident_issue

        # Build timeline for GitHub
        timeline = [
            {
                'timestamp': e['timestamp'],
                'description': f"{e['action']['name']} - {e['action']['result']}"
            }
            for e in audit.entries
            if e["incident_id"] == incident_id
        ]

        # Build actions taken list
        actions_taken = [
            {
                'name': e['action']['name'],
                'result': e['action']['result'],
                'tier': e['action'].get('tier')
            }
            for e in audit.entries
            if e["incident_id"] == incident_id
        ]

        github_issue_url = create_incident_issue(
            incident_id=incident_id,
            incident_data={
                'attacker_ip': attacker_ip,
                'detection_signature': detection.get('signature', 'Unknown'),
                'detection_confidence': detection.get('confidence', 0.0),
                'osint_data': osint_data if osint_data else {},
                'actions_taken': actions_taken,
                'timeline': timeline,
            }
        )

        if github_issue_url:
            logger.info(f"✅ GitHub issue created: {github_issue_url}")

            # Update database with GitHub URL
            try:
                from agent.db import get_db_manager
                db = get_db_manager()
                with db.get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE incidents
                            SET github_issue_url = %s,
                                last_updated = NOW()
                            WHERE incident_id = %s
                        """, (github_issue_url, incident_id))
                        conn.commit()
                        logger.info(f"Updated incident {incident_id} with GitHub URL")
            except Exception as e:
                logger.warning(f"Failed to update incident with GitHub URL: {e}")

            # Post evidence as comment (Phase 5)
            try:
                from agent.github_reporter import get_github_reporter

                reporter = get_github_reporter()
                reporter.post_evidence_comment(
                    osint_data=osint_data,
                    evidence_files=list(evidence_files.values()) if evidence_files else None
                )
            except Exception as e:
                logger.warning(f"Failed to post evidence comment: {e}")

    except Exception as e:
        logger.warning(f"Failed to create GitHub issue: {e}")

    audit.record(
        incident_id=incident_id,
        action_id="generate-postmortem",
        action_name="Generate post-mortem report",
        tier=None,
        parameters={
            "output_path": str(report_file),
            "github_issue_url": github_issue_url
        },
        result="success",
        justification={
            "trigger": "incident-complete",
            "detection_confidence": 1.0,
            "evidence_refs": [e["id"] for e in audit.entries if e["incident_id"] == incident_id],
            "playbook_rule": None,
            "reasoning": "All autonomous actions complete. Generating post-mortem for morning review.",
        },
        context={
            "attacker_ip": attacker_ip,
            "github_issue_url": github_issue_url
        },
    )

    # Return GitHub URL for Slack notification
    return github_issue_url

    # Phase 8: Generate incident report templates
    try:
        from agent.template_generator import IncidentReportGenerator

        generator = IncidentReportGenerator()

        # Prepare incident data for templates
        incident_data = {
            "incident_id": incident_id,
            "attacker_ip": attacker_ip,
            "attacker_ip_slug": attacker_ip.replace(".", "-"),
            "detection_signature": detection.get("signature", "Unknown"),
            "first_seen": detection.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "confidence": detection.get("confidence", 0.97),
            "summary": f"Reconnaissance activity detected from {attacker_ip}. " +
                       f"Signature: {detection.get('signature', 'Unknown')}. " +
                       f"Confidence: {detection.get('confidence', 0.97):.2f}",
            "osint": {
                "whois": osint_data["modules"].get("whois", {}),
                "rdns": osint_data["modules"].get("reverse_dns", {}),
                "shodan": osint_data["modules"].get("shodan", {}),
                "ct": osint_data["modules"].get("cert_transparency", {}),
            },
            "detection_signals": [
                {
                    "type": detection.get("signature", "Unknown"),
                    "description": f"Detection confidence: {detection.get('confidence', 0.97):.2f}",
                    "confidence": detection.get("confidence", 0.97),
                }
            ],
            "actions": [
                {
                    "name": e["action"]["name"],
                    "timestamp": e["timestamp"],
                    "result": e["action"]["result"],
                    "success": e["action"]["result"] == "success",
                    "parameters": e["action"].get("parameters", {}),
                }
                for e in audit.entries
                if e["incident_id"] == incident_id
            ],
            "timeline": [
                {
                    "timestamp": e["timestamp"],
                    "description": f"{e['action']['name']} - {e['action']['result']}",
                }
                for e in audit.entries
                if e["incident_id"] == incident_id
            ],
            "recommendations": [
                "Review OSINT data for additional IOCs",
                "Check if this IP is part of a larger campaign",
                "Update threat intelligence feeds with IOCs",
                "Consider adjusting detection thresholds if false positive",
            ],
        }

        # Generate incident report
        incident_report_path = generator.generate_incident_report(incident_data)
        logger.info(f"Incident report generated: {incident_report_path}")

        # Generate Slack notification
        slack_msg = generator.generate_slack_notification(incident_data)
        logger.info(f"Slack notification ready (saved to incidents/slack/{incident_id}.txt)")

        # Generate enhanced dossier
        dossier_data = {
            "incident_id": incident_id,
            "attacker_ip": attacker_ip,
            "whois": osint_data["modules"].get("whois", {}),
            "rdns": osint_data["modules"].get("reverse_dns", {}),
            "shodan": osint_data["modules"].get("shodan", {}),
            "ct": osint_data["modules"].get("cert_transparency", {}),
            "detection_signals": incident_data["detection_signals"],
            "detected_tools": [],
            "timeline": incident_data["timeline"],
            "risk_score": min(10, int(detection.get("confidence", 0.97) * 10)),
            "risk_factors": [
                {
                    "name": "Detection Confidence",
                    "score": min(10, int(detection.get("confidence", 0.97) * 10)),
                    "reasoning": f"High confidence detection ({detection.get('confidence', 0.97):.2f})",
                }
            ],
            "attribution_confidence": "Medium",
            "behavioral_iocs": [
                f"Reconnaissance activity from {attacker_ip}",
                f"Signature: {detection.get('signature', 'Unknown')}",
            ],
            "immediate_actions": [
                "Monitor for continued activity from this IP",
                "Review honeypot logs for additional TTPs",
            ],
            "shortterm_actions": [
                "Correlate with other incidents from same ASN",
                "Update detection signatures if new patterns found",
            ],
            "longterm_actions": [
                "Review overall detection coverage",
                "Consider proactive threat hunting for similar patterns",
            ],
            "related_incidents": [],
            "associated_domains": [],
            "agent_version": "1.0.0",
            "database_entries": len(audit.entries),
            "cache_hit_rate": 0,
        }

        dossier_path = generator.generate_dossier(dossier_data)
        logger.info(f"Threat actor dossier generated: {dossier_path}")

        audit.record(
            incident_id=incident_id,
            action_id="generate-incident-templates",
            action_name="Generate incident report templates",
            tier=None,
            parameters={
                "incident_report": incident_report_path,
                "dossier": dossier_path,
                "slack_notification": f"incidents/slack/{incident_id}.txt",
            },
            result="success",
            justification={
                "trigger": "incident-complete",
                "detection_confidence": 1.0,
                "evidence_refs": [],
                "playbook_rule": None,
                "reasoning": "Templates generated for manual GitHub issue creation or Slack posting",
            },
            context={"attacker_ip": attacker_ip},
        )

    except Exception as e:
        logger.error(f"Failed to generate incident report templates: {e}")

    return report_file
