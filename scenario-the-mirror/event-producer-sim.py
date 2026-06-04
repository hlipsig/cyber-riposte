#!/usr/bin/env python3
"""
Fake Suricata EVE event generator for testing The Mirror.

Generates realistic reconnaissance events and publishes them to Kafka.
Simulates various attack patterns without needing real Suricata.
"""
import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

from kafka import KafkaProducer
from kafka.errors import KafkaError


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# Attack tool user-agents (from suspicious-user-agents.yaml)
ATTACK_TOOLS = {
    "high": [
        "Nmap Scripting Engine",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "sqlmap/1.8#stable (http://sqlmap.org)",
        "Gobuster/3.6",
        "WPScan v3.8.25",
        "Nikto/2.5.0",
        "Metasploit RSPEC HTTP",
    ],
    "medium": [
        "httpx - Open-source project (github.com/projectdiscovery/httpx)",
        "masscan/1.3",
        "ZGrab/0.x",
        "ffuf/2.1.0",
    ],
    "low": [
        "python-requests/2.31.0",
        "curl/7.88.1",
        "Go-http-client/1.1",
        "axios/1.6.0",
    ]
}

# IDS alert categories
IDS_CATEGORIES = [
    "Attempted Recon",
    "Network Scan",
    "Web Application Attack",
    "Potential Corporate Privacy Violation",
    "Attempted Information Leak",
]

# IDS signatures
IDS_SIGNATURES = [
    "ET SCAN Nmap Scripting Engine User-Agent Detected",
    "ET SCAN Nuclei Vulnerability Scanner Detected",
    "ET WEB_SPECIFIC_APPS SQLMap SQL Injection Scanner Detected",
    "ET SCAN Gobuster Directory Brute Force Detected",
    "ET POLICY External IP Lookup api.ipify.org",
    "ET SCAN Masscan User-Agent Detected",
]

# HTTP URIs for different attack types
HTTP_URIS = {
    "reconnaissance": [
        "/robots.txt",
        "/.well-known/security.txt",
        "/.git/config",
        "/.env",
        "/admin",
        "/wp-admin",
        "/api",
        "/swagger/v1/swagger.json",
    ],
    "enumeration": [
        "/api/v1/users",
        "/api/v1/users?limit=1000",
        "/admin/api/users",
        "/api/internal/config",
        "/.git/HEAD",
        "/backup.zip",
        "/database.sql",
    ],
    "exploitation": [
        "/api/v1/users?id=1' OR '1'='1",
        "/search?q=<script>alert(1)</script>",
        "/upload?path=../../etc/passwd",
        "/api/v1/exec?cmd=whoami",
    ],
}

# Attacker IP pools
ATTACKER_IPS = {
    "vpn": [
        "198.51.100.42",
        "203.0.113.23",
        "192.0.2.100",
    ],
    "vps": [
        "45.142.212.100",
        "185.220.101.50",
        "167.99.142.88",
    ],
    "compromised": [
        "203.0.113.200",
        "198.51.100.150",
    ]
}


class EventGenerator:
    """Generate fake Suricata EVE events."""

    def __init__(self):
        self.event_count = 0

    def generate_recon_event(
        self,
        src_ip: str,
        tool_tier: str = "high",
        include_ids_alert: bool = True
    ) -> Dict[str, Any]:
        """
        Generate a reconnaissance detection event.

        Args:
            src_ip: Source IP address
            tool_tier: Tool threat level (high, medium, low)
            include_ids_alert: Include IDS alert or just user-agent

        Returns:
            Suricata EVE event dict
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "src_port": random.randint(40000, 65000),
            "dest_ip": "10.0.1.100",
            "dest_port": random.choice([80, 443, 8080, 8443]),
            "proto": "TCP",
        }

        # Add IDS alert
        if include_ids_alert:
            event["event_type"] = "alert"
            event["alert"] = {
                "signature": random.choice(IDS_SIGNATURES),
                "category": random.choice(IDS_CATEGORIES),
                "severity": random.randint(1, 3),
            }
        else:
            event["event_type"] = "http"

        # Add HTTP details with suspicious user-agent
        user_agent = random.choice(ATTACK_TOOLS.get(tool_tier, ATTACK_TOOLS["medium"]))
        uri = random.choice(HTTP_URIS["reconnaissance"])

        event["http"] = {
            "http_user_agent": user_agent,
            "http_method": "GET",
            "http_uri": uri,
            "protocol": "HTTP/1.1",
            "status": random.choice([200, 404, 403, 401]),
            "length": random.randint(100, 5000),
        }

        self.event_count += 1
        return event

    def generate_attack_sequence(
        self,
        src_ip: str,
        num_events: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate a realistic attack sequence (progression).

        Args:
            src_ip: Source IP
            num_events: Number of events in sequence

        Returns:
            List of events showing attack progression
        """
        events = []

        # Phase 1: Initial reconnaissance
        event = self.generate_recon_event(src_ip, tool_tier="high", include_ids_alert=True)
        event["http"]["http_uri"] = "/robots.txt"
        events.append(event)

        time.sleep(0.1)  # Simulate time delay

        # Phase 2: More scanning
        event = self.generate_recon_event(src_ip, tool_tier="high", include_ids_alert=False)
        event["http"]["http_uri"] = "/.git/config"
        event["http"]["status"] = 404
        events.append(event)

        time.sleep(0.1)

        # Phase 3: Enumeration
        event = self.generate_recon_event(src_ip, tool_tier="medium", include_ids_alert=False)
        event["http"]["http_uri"] = "/api/v1/users"
        event["http"]["status"] = 200
        events.append(event)

        time.sleep(0.1)

        # Phase 4: Exploitation attempt
        if num_events > 3:
            event = self.generate_recon_event(src_ip, tool_tier="high", include_ids_alert=True)
            event["http"]["http_uri"] = random.choice(HTTP_URIS["exploitation"])
            event["alert"]["category"] = "Web Application Attack"
            events.append(event)

        return events[:num_events]

    def generate_benign_event(self, src_ip: str = "10.0.0.50") -> Dict[str, Any]:
        """Generate a benign (non-attack) event for testing false positives."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "http",
            "src_ip": src_ip,
            "src_port": random.randint(40000, 65000),
            "dest_ip": "10.0.1.100",
            "dest_port": 443,
            "proto": "TCP",
            "http": {
                "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "http_method": "GET",
                "http_uri": "/",
                "protocol": "HTTP/1.1",
                "status": 200,
                "length": 1024,
            }
        }
        self.event_count += 1
        return event


def publish_to_kafka(
    events: List[Dict[str, Any]],
    bootstrap_servers: str = "localhost:9092",
    topic: str = "suricata-eve-events"
):
    """
    Publish events to Kafka.

    Args:
        events: List of events to publish
        bootstrap_servers: Kafka broker addresses
        topic: Kafka topic
    """
    try:
        producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all',  # Wait for all replicas
            retries=3,
        )

        logger.info(f"Publishing {len(events)} events to Kafka topic '{topic}'...")

        for i, event in enumerate(events, 1):
            future = producer.send(topic, value=event)

            # Wait for send to complete
            record_metadata = future.get(timeout=10)

            logger.info(
                f"[{i}/{len(events)}] Published event to partition {record_metadata.partition} "
                f"at offset {record_metadata.offset}"
            )

            # Add small delay between events
            time.sleep(0.1)

        producer.flush()
        producer.close()

        logger.info(f"Successfully published {len(events)} events")

    except KafkaError as e:
        logger.error(f"Kafka error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error publishing to Kafka: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Generate fake Suricata EVE events for testing The Mirror"
    )
    parser.add_argument(
        "--kafka",
        default="localhost:9092",
        help="Kafka bootstrap servers (default: localhost:9092)"
    )
    parser.add_argument(
        "--topic",
        default="suricata-eve-events",
        help="Kafka topic (default: suricata-eve-events)"
    )
    parser.add_argument(
        "--scenario",
        choices=["single", "sequence", "mixed", "continuous"],
        default="single",
        help="Event generation scenario"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of events/sequences to generate"
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Events per second for continuous mode"
    )

    args = parser.parse_args()

    generator = EventGenerator()
    events = []

    if args.scenario == "single":
        # Generate single reconnaissance events
        logger.info(f"Generating {args.count} single reconnaissance events...")
        for i in range(args.count):
            ip = random.choice(ATTACKER_IPS["vpn"])
            event = generator.generate_recon_event(ip, tool_tier="high")
            events.append(event)

    elif args.scenario == "sequence":
        # Generate attack sequences (realistic progression)
        logger.info(f"Generating {args.count} attack sequences...")
        for i in range(args.count):
            ip = random.choice(ATTACKER_IPS["vps"])
            sequence = generator.generate_attack_sequence(ip, num_events=5)
            events.extend(sequence)

    elif args.scenario == "mixed":
        # Generate mix of attacks and benign traffic
        logger.info(f"Generating mixed traffic ({args.count} events)...")
        for i in range(args.count):
            if random.random() < 0.2:  # 20% benign
                event = generator.generate_benign_event()
            else:
                ip = random.choice(ATTACKER_IPS["vpn"] + ATTACKER_IPS["vps"])
                event = generator.generate_recon_event(
                    ip,
                    tool_tier=random.choice(["high", "medium", "low"])
                )
            events.append(event)

    elif args.scenario == "continuous":
        # Continuous generation
        logger.info(f"Continuous generation at {args.rate} events/sec (Ctrl+C to stop)...")
        logger.info(f"Publishing to Kafka: {args.kafka} topic: {args.topic}")

        try:
            producer = KafkaProducer(
                bootstrap_servers=args.kafka.split(','),
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                acks='all',
            )

            count = 0
            while True:
                # Generate event
                if random.random() < 0.15:  # 15% benign
                    event = generator.generate_benign_event()
                else:
                    ip = random.choice(ATTACKER_IPS["vpn"] + ATTACKER_IPS["vps"])
                    event = generator.generate_recon_event(ip)

                # Publish
                producer.send(args.topic, value=event)
                count += 1

                logger.info(f"[{count}] Published event from {event['src_ip']}")

                # Rate limiting
                time.sleep(1.0 / args.rate)

        except KeyboardInterrupt:
            logger.info("\nStopping continuous generation...")
            producer.close()
            return

    # Publish batch events
    if events:
        publish_to_kafka(events, args.kafka, args.topic)
        logger.info(f"Total events generated: {generator.event_count}")


if __name__ == "__main__":
    main()
