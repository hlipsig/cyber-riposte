"""
Suricata EVE JSON Consumer

Reads Suricata alerts from EVE JSON log file and provides them to the detection system.
Supports both file tailing and Redis stream modes.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)


class SuricataConsumer:
    """
    Consumes Suricata EVE JSON alerts.

    Modes:
    - file: Tail /var/log/suricata/eve.json
    - redis: Read from Redis stream (for distributed deployment)
    """

    def __init__(self, mode="file", eve_log_path=None, redis_url=None, redis_stream=None):
        self.mode = mode
        self.eve_log_path = eve_log_path or os.getenv(
            'SURICATA_EVE_LOG',
            '/var/log/suricata/eve.json'
        )
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379')
        self.redis_stream = redis_stream or os.getenv('SURICATA_STREAM', 'suricata:alerts')

        self.running = False
        self.events_processed = 0
        self.alerts_detected = 0

        # Redis client (lazy init)
        self._redis_client = None

    def connect(self) -> bool:
        """
        Verify connection to alert source.

        Returns True if ready to consume.
        """
        if self.mode == "file":
            path = Path(self.eve_log_path)
            if not path.exists():
                logger.warning(f"EVE log not found: {self.eve_log_path}")
                logger.info("Suricata may not be running yet, will retry...")
                return False
            logger.info(f"Connected to EVE log: {self.eve_log_path}")
            return True

        elif self.mode == "redis":
            try:
                import redis
                self._redis_client = redis.from_url(self.redis_url, decode_responses=True)
                self._redis_client.ping()
                logger.info(f"Connected to Redis: {self.redis_url}")
                logger.info(f"Listening to stream: {self.redis_stream}")
                return True
            except ImportError:
                logger.error("redis-py not installed. Install with: pip install redis")
                return False
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                return False

        else:
            logger.error(f"Unknown mode: {self.mode}")
            return False

    def consume(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Start consuming Suricata alerts.

        Args:
            handler: Callback function that receives each alert event
        """
        if not self.connect():
            logger.error("Failed to connect to alert source")
            return

        self.running = True
        logger.info(f"Starting Suricata consumer in {self.mode} mode...")

        try:
            if self.mode == "file":
                self._consume_file(handler)
            elif self.mode == "redis":
                self._consume_redis(handler)
        except KeyboardInterrupt:
            logger.info("Shutting down gracefully...")
        finally:
            self.running = False

    def _consume_file(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Tail EVE JSON file and process alerts.
        """
        logger.info(f"Tailing {self.eve_log_path}...")

        # Wait for file to exist (Suricata may be starting)
        max_wait = 30
        waited = 0
        while not Path(self.eve_log_path).exists() and waited < max_wait:
            logger.info(f"Waiting for Suricata EVE log... ({waited}s)")
            time.sleep(5)
            waited += 5

        if not Path(self.eve_log_path).exists():
            logger.error(f"EVE log not found after {max_wait}s: {self.eve_log_path}")
            return

        # Open file and seek to end (only process new alerts)
        with open(self.eve_log_path, 'r') as f:
            # Seek to end
            f.seek(0, 2)
            logger.info("Started tailing EVE log (processing new alerts only)")

            while self.running:
                line = f.readline()

                if not line:
                    # No new data, sleep briefly
                    time.sleep(0.1)
                    continue

                try:
                    event = json.loads(line.strip())
                    self.events_processed += 1

                    # Only process alert events
                    if event.get('event_type') == 'alert':
                        self.alerts_detected += 1
                        logger.debug(f"Alert detected: {event.get('alert', {}).get('signature')}")
                        handler(event)

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse EVE JSON: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing alert: {e}", exc_info=True)

    def _consume_redis(self, handler: Callable[[Dict[str, Any]], None]):
        """
        Read from Redis stream (for distributed deployment).
        """
        logger.info(f"Reading from Redis stream: {self.redis_stream}")

        # Create consumer group if needed
        try:
            self._redis_client.xgroup_create(
                self.redis_stream,
                'mirror-agents',
                id='0',
                mkstream=True
            )
            logger.info("Created consumer group 'mirror-agents'")
        except Exception as e:
            # Group already exists
            logger.debug(f"Consumer group exists: {e}")

        # Generate consumer ID
        consumer_id = f"agent-{os.getpid()}"
        logger.info(f"Consumer ID: {consumer_id}")

        # Read from stream
        last_id = '>'
        while self.running:
            try:
                # Read new messages
                messages = self._redis_client.xreadgroup(
                    groupname='mirror-agents',
                    consumername=consumer_id,
                    streams={self.redis_stream: last_id},
                    count=10,
                    block=1000  # 1 second timeout
                )

                if not messages:
                    continue

                for stream, entries in messages:
                    for msg_id, data in entries:
                        try:
                            # Parse alert
                            event_json = data.get('event', '{}')
                            event = json.loads(event_json)

                            self.events_processed += 1

                            if event.get('event_type') == 'alert':
                                self.alerts_detected += 1
                                logger.debug(f"Alert from Redis: {event.get('alert', {}).get('signature')}")
                                handler(event)

                            # Acknowledge message
                            self._redis_client.xack(self.redis_stream, 'mirror-agents', msg_id)

                        except Exception as e:
                            logger.error(f"Error processing Redis message: {e}")

            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"Redis read error: {e}")
                time.sleep(5)

    def get_stats(self) -> Dict[str, int]:
        """Get consumer statistics."""
        return {
            'events_processed': self.events_processed,
            'alerts_detected': self.alerts_detected,
        }


def parse_suricata_alert(event: Dict) -> Optional[Dict]:
    """
    Parse Suricata EVE alert into standardized format.

    Returns dict with:
    - src_ip, src_port
    - dest_ip, dest_port
    - signature, category, severity
    - payload, http data if available
    - confidence (based on alert metadata)
    """
    if event.get('event_type') != 'alert':
        return None

    alert = event.get('alert', {})

    # Extract basic alert info
    result = {
        'timestamp': event.get('timestamp'),
        'src_ip': event.get('src_ip'),
        'src_port': event.get('src_port'),
        'dest_ip': event.get('dest_ip'),
        'dest_port': event.get('dest_port'),
        'proto': event.get('proto'),

        # Alert metadata
        'signature': alert.get('signature', 'Unknown'),
        'signature_id': alert.get('signature_id'),
        'category': alert.get('category', 'Unknown'),
        'severity': alert.get('severity', 3),
        'rev': alert.get('rev'),

        # Source
        'source': 'suricata',
        'event_type': 'ids_alert',
    }

    # Add HTTP data if available
    if 'http' in event:
        http = event['http']
        result['http'] = {
            'hostname': http.get('hostname'),
            'url': http.get('url'),
            'http_method': http.get('http_method'),
            'http_user_agent': http.get('http_user_agent'),
            'status': http.get('status'),
            'http_refer': http.get('http_refer'),
        }

    # Add payload if available
    if 'payload' in event:
        result['payload'] = event['payload']
    if 'payload_printable' in event:
        result['payload_printable'] = event['payload_printable']

    # Add packet info
    if 'packet' in event:
        result['packet'] = event['packet']

    # Calculate confidence based on metadata
    confidence = 0.7  # Base confidence for IDS alert

    # Increase confidence for high-severity alerts
    severity = alert.get('severity', 3)
    if severity == 1:  # High severity
        confidence = 0.95
    elif severity == 2:  # Medium severity
        confidence = 0.85
    elif severity == 3:  # Low severity
        confidence = 0.75

    # Custom rules (SID 9000000+) get higher confidence
    sig_id = alert.get('signature_id', 0)
    if sig_id >= 9000000:
        confidence = max(confidence, 0.90)

    # Certain categories get boosted confidence
    category = alert.get('category', '').lower()
    if 'attempted-recon' in category or 'web-application-attack' in category:
        confidence = max(confidence, 0.85)

    result['confidence'] = confidence

    return result


# Example usage / test
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    def test_handler(event):
        """Test handler that prints alerts."""
        parsed = parse_suricata_alert(event)
        if parsed:
            print(f"\n🚨 ALERT: {parsed['signature']}")
            print(f"   From: {parsed['src_ip']}:{parsed['src_port']}")
            print(f"   To: {parsed['dest_ip']}:{parsed['dest_port']}")
            print(f"   Confidence: {parsed['confidence']:.2f}")
            if 'http' in parsed and parsed['http'].get('http_user_agent'):
                print(f"   User-Agent: {parsed['http']['http_user_agent']}")

    # Test with file mode
    consumer = SuricataConsumer(mode="file")
    print("Starting test consumer (Ctrl+C to stop)...")
    consumer.consume(test_handler)
