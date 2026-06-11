#!/usr/bin/env python3
"""
The Mirror — autonomous agent orchestrator (refactored for OpenShift).

Phase 1: Reads from stdin, logs to stdout, exposes health endpoint
Phase 2: Will read from Kafka instead of stdin
Phase 3: Will write audit logs to PostgreSQL instead of file
Phase 4: Will create Istio VirtualService instead of nftables rules
"""
import ipaddress
import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import yaml
from flask import Flask, jsonify

from agent.config import Config
from agent.audit import AuditLog
from agent.detector import detect_recon
from agent.executor import (
    execute_redirect,
    execute_osint,
    execute_temp_block,
    compile_dossier,
    generate_postmortem,
)


# Configure structured JSON logging to stdout
def setup_logging():
    """Configure structured logging to stdout for OpenShift log aggregation."""
    if Config.LOG_FORMAT == "json":
        # JSON formatter for structured logs
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_obj = {
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                if record.exc_info:
                    log_obj["exception"] = self.formatException(record.exc_info)
                return json.dumps(log_obj)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
    else:
        # Plain text formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
    root_logger.addHandler(handler)


logger = logging.getLogger(__name__)


class ActionPool:
    """Pre-approved actions the agent is authorized to execute."""

    def __init__(self, config_path=None):
        config_path = config_path or Config.ACTION_POOL_PATH
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
        from datetime import timedelta
        action = self.actions.get(action_id)
        expiry_str = action.get("auto_expire", "1h") if action else "1h"
        hours = int(expiry_str.replace("h", ""))
        return datetime.now(timezone.utc) + timedelta(hours=hours)

    def mark_executed(self):
        self.action_count += 1


# Health check Flask app
app = Flask(__name__)
health_status = {"ready": False, "alive": True, "incidents_processed": 0}


@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness probe - is the agent running?"""
    if health_status["alive"]:
        return jsonify({"status": "healthy"}), 200
    else:
        return jsonify({"status": "unhealthy"}), 503


@app.route("/readyz", methods=["GET"])
def readyz():
    """Readiness probe - is the agent ready to process events?"""
    if health_status["ready"]:
        return jsonify({"status": "ready", "incidents_processed": health_status["incidents_processed"]}), 200
    else:
        return jsonify({"status": "not ready"}), 503


@app.route("/metrics", methods=["GET"])
def metrics_endpoint():
    """
    Prometheus metrics endpoint (Phase 7).
    Returns metrics in Prometheus text format.
    """
    try:
        from agent.metrics import get_metrics
        metrics_obj = get_metrics()

        if not metrics_obj.enabled:
            # Fallback to JSON if Prometheus not available
            return jsonify({
                "incidents_processed": health_status["incidents_processed"],
            }), 200

        # Return Prometheus metrics
        from flask import Response
        metrics_data = metrics_obj.generate_metrics()
        return Response(metrics_data, mimetype=metrics_obj.get_content_type())

    except ImportError:
        # Prometheus client not available
        return jsonify({
            "incidents_processed": health_status["incidents_processed"],
            "note": "Prometheus metrics not available",
        }), 200


def run_health_server():
    """Run Flask health check server in background thread."""
    app.run(host="0.0.0.0", port=Config.HEALTH_PORT, debug=False, use_reloader=False)


def run_dossier_web_server():
    """
    Run web dossier server in background thread (CTF).
    Serves password-protected dossier pages on port 8081.
    """
    try:
        from agent.web_dossier import create_dossier_app
        from agent.db import get_db_manager

        dossier_app = create_dossier_app(db_manager=get_db_manager())
        dossier_port = int(os.getenv("DOSSIER_PORT", "8081"))

        logger.info(f"Starting web dossier server on port {dossier_port}")
        dossier_app.run(host="0.0.0.0", port=dossier_port, debug=False, use_reloader=False)

    except ImportError as e:
        logger.warning(f"Web dossier server not available: {e}")
    except Exception as e:
        logger.error(f"Failed to start web dossier server: {e}")


def process_event(event, pool, audit, mirrored):
    """Process a single EVE event."""
    detection = detect_recon(event)
    if not detection:
        return False

    attacker_ip = detection["src_ip"]
    if not attacker_ip or attacker_ip in mirrored:
        return False

    if pool.is_allowlisted(attacker_ip):
        logger.info(f"Skipping allowlisted IP {attacker_ip}")
        return False

    now = datetime.now(timezone.utc)
    incident_id = f"INC-{now.strftime('%Y-%m%d-%H%M')}"

    logger.info(f"=== Incident {incident_id} ===")
    signal_types = [s["type"] for s in detection.get("signals", [])]
    logger.info(f"Recon from {attacker_ip}: {detection['signature']}")
    logger.info(f"Detection signals: {', '.join(signal_types)} "
                f"(confidence: {detection.get('confidence', 0):.2f})")

    # Phase 1: Redirect to honeypot (Tier 1 — auto-execute)
    logger.info(f"[T1] Redirecting {attacker_ip} → honeypot {Config.HONEYPOT_IP}")
    execute_redirect(attacker_ip, pool, audit, incident_id, detection)

    # Phase 2: Passive OSINT (Tier 1 — auto-execute)
    logger.info(f"[T1] Running OSINT on {attacker_ip}...")
    osint_data = execute_osint(attacker_ip, pool, audit, incident_id, detection)

    # Phase 3: Compile dossier
    if osint_data:
        logger.info("Compiling dossier...")
        dossier_content = compile_dossier(attacker_ip, detection, osint_data)
        dossier_file = Config.BASE_DIR / f"dossier-{attacker_ip.replace('.', '-')}.md"
        try:
            dossier_file.write_text(dossier_content)
        except Exception as e:
            logger.error(f"Failed to write dossier: {e}")

    # Phase 4: Temp block (Tier 1 — auto-execute)
    logger.info(f"[T1] Applying temp block on {attacker_ip}")
    execute_temp_block(attacker_ip, pool, audit, incident_id, detection)

    # Phase 5: Generate post-mortem for morning review
    generate_postmortem(incident_id, attacker_ip, detection, osint_data or {}, audit)

    mirrored.add(attacker_ip)
    logger.info(f"=== Incident {incident_id} complete — report ready for morning review ===")

    return True


def run_stdin_mode():
    """
    Phase 1: Read events from stdin (for testing and compatibility).
    """
    logger.info("Starting Mirror agent in stdin mode...")
    logger.info(f"Action pool: {Config.ACTION_POOL_PATH}")
    logger.info(f"Audit log: {Config.AUDIT_LOG_PATH}")

    # Validate configuration
    warnings = Config.validate()
    for warning in warnings:
        logger.warning(warning)

    pool = ActionPool()
    audit = AuditLog(Config.AUDIT_LOG_PATH)
    mirrored = set()

    # Phase 9: Setup hot-reload for action pool
    try:
        from agent.config_watcher import get_config_watcher
        watcher = get_config_watcher()

        def reload_action_pool():
            """Reload action pool from disk."""
            nonlocal pool
            try:
                pool = ActionPool()
                logger.info("Action pool reloaded successfully")
            except Exception as e:
                logger.error(f"Failed to reload action pool: {e}")

        watcher.watch(Config.ACTION_POOL_PATH, reload_action_pool)
    except ImportError:
        logger.debug("Config watcher not available")

    # Mark as ready
    health_status["ready"] = True
    logger.info("Agent ready to process events")

    # Keep process alive even if stdin closes (for Kubernetes deployment)
    import select
    try:
        for line in sys.stdin:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse EVE event: {e}")
                continue

            if process_event(event, pool, audit, mirrored):
                health_status["incidents_processed"] += 1
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down gracefully...")
        raise

    # If stdin closes, keep the process alive for health checks
    logger.info("stdin closed, entering keep-alive mode for health endpoint")
    try:
        import time
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down gracefully...")


def run_kafka_mode():
    """
    Phase 2: Read events from Kafka (distributed message queue).
    """
    logger.info("Starting Mirror agent in Kafka mode...")
    logger.info(f"Kafka brokers: {Config.KAFKA_BOOTSTRAP_SERVERS}")
    logger.info(f"Topic: {Config.KAFKA_TOPIC}")
    logger.info(f"Consumer group: {Config.KAFKA_CONSUMER_GROUP}")
    logger.info(f"Action pool: {Config.ACTION_POOL_PATH}")

    # Validate configuration
    warnings = Config.validate()
    for warning in warnings:
        logger.warning(warning)

    # Import Kafka consumer (only when needed)
    try:
        from agent.kafka_consumer import MirrorKafkaConsumer
    except ImportError:
        logger.error("kafka-python not installed. Install with: pip install kafka-python")
        sys.exit(1)

    pool = ActionPool()
    audit = AuditLog(Config.AUDIT_LOG_PATH)
    mirrored = set()

    # Phase 9: Setup hot-reload for action pool
    try:
        from agent.config_watcher import get_config_watcher
        watcher = get_config_watcher()

        def reload_action_pool():
            """Reload action pool from disk."""
            nonlocal pool
            try:
                new_pool = ActionPool()
                # Validate new pool before replacing
                if new_pool.actions:
                    pool = new_pool
                    logger.info(f"Action pool reloaded: {len(pool.actions)} actions")
                else:
                    logger.error("New action pool is empty, keeping current pool")
            except Exception as e:
                logger.error(f"Failed to reload action pool: {e}")

        watcher.watch(Config.ACTION_POOL_PATH, reload_action_pool)
    except ImportError:
        logger.debug("Config watcher not available")

    # Create Kafka consumer
    consumer = MirrorKafkaConsumer()

    if not consumer.connect():
        logger.error("Failed to connect to Kafka")
        sys.exit(1)

    # Mark as ready
    health_status["ready"] = True
    logger.info("Agent ready to consume events from Kafka")

    # Define event handler
    def handle_kafka_event(event: Dict[str, Any]):
        """Handle event from Kafka."""
        if process_event(event, pool, audit, mirrored):
            health_status["incidents_processed"] += 1

    # Start consuming
    try:
        consumer.consume(handle_kafka_event)
    finally:
        stats = consumer.get_stats()
        logger.info(f"Kafka consumer stats: {stats}")


def run_suricata_mode():
    """
    Phase 1: Read events from Suricata EVE JSON log.
    """
    logger.info("Starting Mirror agent in Suricata mode...")
    logger.info(f"Suricata EVE log: {Config.SURICATA_EVE_LOG}")
    logger.info(f"Suricata mode: {Config.SURICATA_MODE}")
    logger.info(f"Action pool: {Config.ACTION_POOL_PATH}")

    # Validate configuration
    warnings = Config.validate()
    for warning in warnings:
        logger.warning(warning)

    # Import Suricata consumer
    try:
        from agent.suricata_consumer import SuricataConsumer
    except ImportError:
        logger.error("suricata_consumer not found")
        sys.exit(1)

    pool = ActionPool()
    audit = AuditLog(Config.AUDIT_LOG_PATH)
    mirrored = set()

    # Phase 9: Setup hot-reload for action pool
    try:
        from agent.config_watcher import get_config_watcher
        watcher = get_config_watcher()

        def reload_action_pool():
            """Reload action pool from disk."""
            nonlocal pool
            try:
                new_pool = ActionPool()
                if new_pool.actions:
                    pool = new_pool
                    logger.info(f"Action pool reloaded: {len(pool.actions)} actions")
                else:
                    logger.error("New action pool is empty, keeping current pool")
            except Exception as e:
                logger.error(f"Failed to reload action pool: {e}")

        watcher.watch(Config.ACTION_POOL_PATH, reload_action_pool)
    except ImportError:
        logger.debug("Config watcher not available")

    # Create Suricata consumer
    consumer = SuricataConsumer(
        mode=Config.SURICATA_MODE,
        eve_log_path=Config.SURICATA_EVE_LOG
    )

    if not consumer.connect():
        logger.warning("Suricata not available, waiting for startup...")
        # Continue anyway - consumer will retry connection

    # Mark as ready
    health_status["ready"] = True
    logger.info("Agent ready to consume Suricata alerts")

    # Define event handler
    def handle_suricata_event(event: dict):
        """Handle event from Suricata."""
        if process_event(event, pool, audit, mirrored):
            health_status["incidents_processed"] += 1

    # Start consuming
    try:
        consumer.consume(handle_suricata_event)
    finally:
        stats = consumer.get_stats()
        logger.info(f"Suricata consumer stats: {stats}")


def main():
    """Main entry point."""
    setup_logging()

    logger.info("The Mirror agent starting...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Event source: {Config.EVENT_SOURCE}")
    logger.info(f"Health check port: {Config.HEALTH_PORT}")

    # Start health check server in background thread
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()
    logger.info(f"Health check server started on port {Config.HEALTH_PORT}")

    # CTF: Start web dossier server in background thread
    dossier_thread = threading.Thread(target=run_dossier_web_server, daemon=True)
    dossier_thread.start()

    # CTF: Start honeypot log watcher (automatic incident detection)
    # DISABLED: AI model download causes crashes - using manual incident creation
    # try:
    #     from agent.honeypot_log_watcher import watch_honeypot_logs
    #     log_watcher_thread = threading.Thread(target=watch_honeypot_logs, daemon=True)
    #     log_watcher_thread.start()
    #     logger.info("Honeypot log watcher thread started")
    # except Exception as e:
    #     logger.warning(f"Failed to start log watcher: {e}")

    # Phase 9: Start configuration watcher (hot-reload)
    try:
        from agent.config_watcher import get_config_watcher
        watcher = get_config_watcher()

        # Note: Can't reload action pool here as it's per-mode
        # Each mode creates its own ActionPool and sets up watcher

        if watcher.enabled:
            watcher.start()
            logger.info("Configuration hot-reload enabled")
    except ImportError as e:
        logger.warning(f"Configuration watcher not available: {e}")

    # Run event processing loop (Phase 1: Added Suricata mode)
    if Config.EVENT_SOURCE == "stdin":
        run_stdin_mode()
    elif Config.EVENT_SOURCE == "suricata":
        run_suricata_mode()
    elif Config.EVENT_SOURCE == "kafka":
        run_kafka_mode()
    else:
        logger.error(f"Unknown event source: {Config.EVENT_SOURCE}")
        sys.exit(1)


if __name__ == "__main__":
    main()
