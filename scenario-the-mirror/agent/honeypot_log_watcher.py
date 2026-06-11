"""
Honeypot log watcher that follows pod logs and creates incidents.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def watch_honeypot_logs():
    """
    Watch honeypot pod logs via Kubernetes API and create incidents for detections.

    This runs in a background thread and continuously follows the honeypot logs.
    """
    logger.info("Starting honeypot log watcher...")

    # Import here to avoid circular dependencies
    from agent.log_detector import LogDetector
    from agent.db import get_db_manager
    from kubernetes import client, config, watch

    detector = LogDetector()
    db = get_db_manager()

    # Track IPs we've already created incidents for
    detected_ips = set()

    # Load in-cluster config
    try:
        config.load_incluster_config()
        v1 = client.CoreV1Api()
        logger.info("Kubernetes API client initialized")
    except Exception as e:
        logger.error(f"Failed to initialize Kubernetes client: {e}")
        return

    # Get honeypot pod name
    try:
        pods = v1.list_namespaced_pod(
            namespace="cyber-riposte",
            label_selector="app=simple-honeypot"
        )

        if not pods.items:
            logger.error("No honeypot pod found")
            return

        pod_name = pods.items[0].metadata.name
        logger.info(f"Watching logs from pod: {pod_name}")

    except Exception as e:
        logger.error(f"Failed to get honeypot pod: {e}")
        return

    # Follow logs using direct API call
    try:
        logger.info("✅ Honeypot log watcher started")

        # Stream logs
        log_stream = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace="cyber-riposte",
            follow=True,
            _preload_content=False
        )

        for line in log_stream.stream():
            if not line:
                time.sleep(0.1)
                continue

            # Decode bytes to string
            if isinstance(line, bytes):
                line = line.decode('utf-8')

            line = line.strip()
            if not line:
                continue

            # Skip kubernetes probes
            if 'kube-probe' in line:
                continue

            # Analyze the log line
            try:
                result = detector.analyze_log_line(line)
                if not result:
                    continue

                ip = result['src_ip']
                detection = result['detection']

                # Skip if we already detected this IP
                if ip in detected_ips:
                    continue

                detected_ips.add(ip)

                # Create incident
                incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{ip.replace('.', '')[:8]}"

                logger.info(f"🚨 DETECTION: {ip} - {detection['signature']} (confidence: {detection['confidence']})")

                # Generate AI narrative
                ai_narrative = None
                try:
                    from agent.ai_narrator import generate_narrative
                    ai_narrative = generate_narrative({
                        'attacker_ip': ip,
                        'detection_signature': detection['signature'],
                        'detection_confidence': detection['confidence'],
                        'incident_id': incident_id
                    }, style='technical')
                    logger.info(f"🤖 AI narrative generated")
                except Exception as e:
                    logger.warning(f"AI narrative generation failed: {e}")

                # Store in database
                try:
                    with db.get_conn() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO incidents (
                                    incident_id, attacker_ip, first_seen, last_updated,
                                    status, detection_signature, detection_confidence,
                                    actions_count, ai_narrative
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (incident_id) DO NOTHING
                            """, (
                                incident_id,
                                ip,
                                datetime.now(timezone.utc),
                                datetime.now(timezone.utc),
                                'active',
                                detection['signature'],
                                detection['confidence'],
                                0,
                                ai_narrative
                            ))
                            conn.commit()

                    logger.info(f"✅ Incident created: {incident_id}")
                    if ai_narrative:
                        logger.info(f"   AI: {ai_narrative[:100]}...")

                except Exception as e:
                    logger.error(f"Failed to create incident for {ip}: {e}")

            except Exception as e:
                logger.error(f"Error analyzing log line: {e}")
                continue

    except Exception as e:
        logger.error(f"Log watcher error: {e}")
