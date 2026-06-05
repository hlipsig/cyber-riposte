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
    Phase 4: Create Istio VirtualService to redirect attacker traffic to honeypot.

    Returns (vs_name, success).
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
    namespace = "cyber-riposte"

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
            "gateways": ["redteam-gateway"],
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
                                "port": {"number": 8080}
                            }
                        }
                    ],
                }
            ],
            "priority": 10,  # Higher precedence than default (lower number = higher priority)
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

    # Phase 4: Try to create VirtualService
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
                "reasoning": "Recon pattern confirmed, IP not in allowlist, VirtualService created successfully",
            },
            context={
                "attacker_ip": attacker_ip,
                "honeypot_active": True,
                "virtualservice_name": vs_name,
                "namespace": "cyber-riposte",
                "method": "istio",
            },
            rollback_handle=vs_name,  # VirtualService name for cleanup
            expires_at=expiry,
        )
        pool.mark_executed()
        return True

    # Fallback: Phase 1 behavior (nftables - will fail but logged)
    logger.warning("VirtualService creation failed. Falling back to nftables (Phase 1 mode)")

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

    Phase 6: Uses Redis caching and rate limiting to prevent API quota exhaustion.
    """
    action_id = "run-osint"
    can_exec, reason = pool.can_execute(action_id)
    if not can_exec:
        logger.warning(f"SKIPPED {action_id}: {reason}")
        return None

    # Phase 6: Import caching and rate limiting
    try:
        from agent.osint_cache import get_osint_cache
        from agent.rate_limiter import get_osint_rate_limiter

        cache = get_osint_cache()
        rate_limiter = get_osint_rate_limiter()
        use_resilience = True
    except ImportError as e:
        logger.warning(f"OSINT resilience modules not available: {e}")
        cache = None
        rate_limiter = None
        use_resilience = False

    osint_data = {
        "target_ip": attacker_ip,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "modules": {},
        "cache_stats": {},
        "rate_limited": [],
    }

    # Run OSINT modules with caching and rate limiting
    logger.info(f"Running OSINT on {attacker_ip}...")

    # Helper function to run module with resilience
    def run_module(name: str, func: Callable, *args, **kwargs):
        # Check cache first
        if cache:
            cached = cache.get(name, attacker_ip)
            if cached:
                logger.info(f"OSINT cache HIT: {name}")
                osint_data["cache_stats"][name] = "hit"
                return cached
            osint_data["cache_stats"][name] = "miss"

        # Check rate limit
        if rate_limiter and not rate_limiter.allow(name):
            wait = rate_limiter.wait_time(name)
            logger.warning(f"OSINT rate limited: {name} (wait: {wait:.1f}s)")
            osint_data["rate_limited"].append(name)
            return {"error": "rate_limited", "wait_time": wait}

        # Execute lookup
        try:
            result = func(*args, **kwargs)

            # Store in cache
            if cache and result:
                cache.set(name, attacker_ip, result)

            return result
        except Exception as e:
            logger.error(f"OSINT module {name} failed: {e}")
            return {"error": str(e)}

    osint_data["modules"]["whois"] = run_module("whois", whois_lookup, attacker_ip)
    osint_data["modules"]["reverse_dns"] = run_module("rdns", reverse_dns, attacker_ip)
    osint_data["modules"]["shodan"] = run_module("shodan", shodan_lookup, attacker_ip)
    osint_data["modules"]["cert_transparency"] = run_module("ct", ct_lookup, attacker_ip)

    # Phase 3: Save evidence to database
    try:
        from agent.db import get_db_manager
        db = get_db_manager()

        for module_name, data in osint_data["modules"].items():
            if data and "error" not in data:
                db.add_evidence(
                    incident_id=incident_id,
                    evidence_type=module_name,
                    data=data,
                )
    except Exception as e:
        logger.warning(f"Failed to save OSINT evidence to database: {e}")

    # Phase 1-2: Save evidence files (backward compatibility)
    evidence_dir = Path(Config.EVIDENCE_DIR)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ip_slug = attacker_ip.replace(".", "-")
    for module_name, data in osint_data["modules"].items():
        evidence_file = evidence_dir / f"{module_name}-{ip_slug}.json"
        try:
            evidence_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to write evidence file {evidence_file}: {e}")

    # Determine result based on rate limiting
    modules_run = len([m for m in osint_data["modules"].values() if "error" not in m])
    modules_cached = sum(1 for v in osint_data.get("cache_stats", {}).values() if v == "hit")
    modules_rate_limited = len(osint_data.get("rate_limited", []))

    result_status = "success" if modules_run > 0 else "partial"
    if modules_rate_limited > 0:
        result_status = "partial"

    audit.record(
        incident_id=incident_id,
        action_id=action_id,
        action_name="Run passive OSINT on source IP",
        tier=1,
        parameters={
            "source_ip": attacker_ip,
            "modules": ["whois", "reverse_dns", "shodan", "cert_transparency"],
            "passive_only": True,
            "cached_modules": modules_cached,
            "rate_limited_modules": modules_rate_limited,
            "resilience_enabled": use_resilience,
        },
        result=result_status,
        justification={
            "trigger": "recon-detected",
            "detection_confidence": detection.get("confidence", 0.97),
            "evidence_refs": [detection.get("timestamp", "")],
            "playbook_rule": action_id,
            "reasoning": f"OSINT collection: {modules_run} modules run, {modules_cached} cached, {modules_rate_limited} rate limited",
        },
        context={
            "attacker_ip": attacker_ip,
            "osint_collected": True,
            "cache_stats": osint_data.get("cache_stats", {}),
            "rate_limited": osint_data.get("rate_limited", []),
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
