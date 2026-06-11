"""
Simple HTTP log-based detection for The Mirror CTF.

Watches nginx/honeypot access logs and creates incidents when
scan patterns are detected (Nmap, gobuster, etc.).
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import time

logger = logging.getLogger(__name__)


# Scan detection patterns
SCAN_PATTERNS = [
    # Nmap signatures
    (r'Nmap\s+Scripting\s+Engine', 'ET SCAN Nmap Scripting Engine User-Agent Detected', 0.98),
    (r'nmap', 'ET SCAN Nmap User-Agent', 0.90),

    # Directory brute force tools
    (r'gobuster', 'ET SCAN Directory Brute Force (gobuster)', 0.95),
    (r'dirbuster', 'ET SCAN Directory Brute Force (dirbuster)', 0.95),
    (r'ffuf', 'ET SCAN Directory Brute Force (ffuf)', 0.95),
    (r'wfuzz', 'ET SCAN Directory Brute Force (wfuzz)', 0.95),

    # Web scanners
    (r'nikto', 'ET SCAN Nikto Web Scanner', 0.98),
    (r'sqlmap', 'ET SCAN SQLMap Detected', 0.98),
    (r'burpsuite', 'ET SCAN Burp Suite User-Agent', 0.85),
    (r'OWASP\s+ZAP', 'ET SCAN OWASP ZAP Scanner', 0.95),

    # Reconnaissance
    (r'whatweb', 'ET SCAN WhatWeb Reconnaissance', 0.90),
    (r'masscan', 'ET SCAN Masscan Port Scanner', 0.98),
    (r'nuclei', 'ET SCAN Nuclei Scanner', 0.95),

    # Unusual patterns
    (r'python-requests/[\d\.]+\s*$', 'ET SCAN Python Requests Library (possible automation)', 0.70),
    (r'curl/[\d\.]+\s*$', 'ET SCAN cURL Command Line Tool', 0.65),
]

# High request rate thresholds
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_THRESHOLD = 20  # requests per window


class LogDetector:
    """Detects reconnaissance patterns in HTTP access logs."""

    def __init__(self):
        self.ip_request_counts: Dict[str, list] = {}

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse nginx/apache access log line.

        Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
        """
        # Nginx combined log format
        pattern = r'([^\s]+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
        match = re.match(pattern, line)

        if not match:
            return None

        ip, timestamp_str, request, status, size, referer, user_agent = match.groups()

        # Parse request (e.g., "GET /path HTTP/1.1")
        request_parts = request.split()
        if len(request_parts) >= 2:
            method = request_parts[0]
            path = request_parts[1]
        else:
            method = "UNKNOWN"
            path = request

        return {
            'ip': ip,
            'timestamp': timestamp_str,
            'method': method,
            'path': path,
            'status': int(status),
            'user_agent': user_agent,
            'referer': referer,
        }

    def detect_scan_pattern(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect if log entry matches scan patterns.

        Returns detection details if pattern matched, None otherwise.
        """
        user_agent = log_entry.get('user_agent', '')

        # Check user-agent patterns
        for pattern, signature, confidence in SCAN_PATTERNS:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return {
                    'signature': signature,
                    'confidence': confidence,
                    'matched_pattern': pattern,
                    'user_agent': user_agent,
                    'method': log_entry.get('method'),
                    'path': log_entry.get('path'),
                }

        return None

    def detect_high_rate(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Detect high request rate (potential brute force/scanning).

        Returns detection details if rate exceeded, None otherwise.
        """
        now = time.time()

        # Initialize or get request history for this IP
        if ip not in self.ip_request_counts:
            self.ip_request_counts[ip] = []

        # Add current request
        self.ip_request_counts[ip].append(now)

        # Remove requests outside the window
        cutoff = now - RATE_LIMIT_WINDOW
        self.ip_request_counts[ip] = [
            ts for ts in self.ip_request_counts[ip] if ts > cutoff
        ]

        # Check if rate exceeded
        request_count = len(self.ip_request_counts[ip])
        if request_count > RATE_LIMIT_THRESHOLD:
            return {
                'signature': f'High Request Rate Detected ({request_count} requests in {RATE_LIMIT_WINDOW}s)',
                'confidence': 0.85,
                'request_count': request_count,
                'window_seconds': RATE_LIMIT_WINDOW,
            }

        return None

    def analyze_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Full analysis of a log line.

        Returns detection dict if reconnaissance detected, None otherwise.
        """
        parsed = self.parse_log_line(line)
        if not parsed:
            return None

        ip = parsed['ip']

        # Check for scan patterns
        pattern_detection = self.detect_scan_pattern(parsed)
        if pattern_detection:
            return {
                'src_ip': ip,
                'detection': pattern_detection,
                'log_entry': parsed,
            }

        # Check for high request rate
        rate_detection = self.detect_high_rate(ip)
        if rate_detection:
            return {
                'src_ip': ip,
                'detection': rate_detection,
                'log_entry': parsed,
            }

        return None


def watch_logs_and_create_incidents(log_file: str, db_manager, osint_func=None):
    """
    Watch log file and create incidents on detection.

    Args:
        log_file: Path to nginx/apache access log
        db_manager: DatabaseManager instance
        osint_func: Optional function to run OSINT on detected IP
    """
    detector = LogDetector()
    detected_ips = set()  # Track already-detected IPs to avoid duplicates

    logger.info(f"Starting log watcher on {log_file}")

    try:
        with open(log_file, 'r') as f:
            # Seek to end of file (only watch new entries)
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                # Analyze the log line
                result = detector.analyze_log_line(line.strip())
                if not result:
                    continue

                ip = result['src_ip']
                detection = result['detection']

                # Skip if we already detected this IP recently
                if ip in detected_ips:
                    continue

                detected_ips.add(ip)

                # Create incident
                incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')}-{ip.replace('.', '')[:8]}"

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
                except Exception as e:
                    logger.warning(f"AI narrative generation failed: {e}")

                # Store in database
                try:
                    from agent.db import get_db_manager
                    db = get_db_manager()

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
                        logger.info(f"🤖 AI narrative: {ai_narrative[:100]}...")

                    # Run OSINT if function provided
                    if osint_func:
                        try:
                            logger.info(f"Running OSINT on {ip}...")
                            osint_func(ip, incident_id)
                        except Exception as e:
                            logger.error(f"OSINT failed for {ip}: {e}")

                except Exception as e:
                    logger.error(f"Failed to create incident for {ip}: {e}")

    except FileNotFoundError:
        logger.warning(f"Log file not found: {log_file}")
    except Exception as e:
        logger.error(f"Log watcher error: {e}")
