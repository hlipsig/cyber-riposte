"""
Kafka consumer for The Mirror agent.
Replaces stdin with distributed message queue for event ingestion.
"""
import json
import logging
import signal
import sys
from typing import Callable, Dict, Any, Optional

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from agent.config import Config


logger = logging.getLogger(__name__)


class MirrorKafkaConsumer:
    """Kafka consumer for Suricata EVE events."""

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: Optional[str] = None,
        group_id: Optional[str] = None,
        auto_offset_reset: str = "latest"
    ):
        """
        Initialize Kafka consumer.

        Args:
            bootstrap_servers: Kafka broker addresses (default from config)
            topic: Topic to consume from (default from config)
            group_id: Consumer group ID (default from config)
            auto_offset_reset: Where to start if no offset ("earliest" or "latest")
        """
        self.bootstrap_servers = bootstrap_servers or Config.KAFKA_BOOTSTRAP_SERVERS
        self.topic = topic or Config.KAFKA_TOPIC
        self.group_id = group_id or Config.KAFKA_CONSUMER_GROUP
        self.auto_offset_reset = auto_offset_reset

        self.consumer = None
        self.running = False
        self.events_processed = 0
        self.errors = 0

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False

    def connect(self) -> bool:
        """
        Connect to Kafka broker.

        Returns:
            True if connected successfully, False otherwise
        """
        try:
            logger.info(f"Connecting to Kafka: {self.bootstrap_servers}")
            logger.info(f"Topic: {self.topic}, Group: {self.group_id}")

            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers.split(','),
                group_id=self.group_id,
                auto_offset_reset=self.auto_offset_reset,
                enable_auto_commit=False,  # Manual commit for at-least-once delivery
                value_deserializer=lambda m: m.decode('utf-8'),
                consumer_timeout_ms=1000,  # Timeout for polling
                max_poll_records=10,  # Process in small batches
                session_timeout_ms=30000,  # 30 seconds
                heartbeat_interval_ms=10000,  # 10 seconds
            )

            # Check if topic exists by listing topics
            topics = self.consumer.topics()
            if self.topic not in topics:
                logger.warning(f"Topic '{self.topic}' not found in Kafka. Available topics: {topics}")
                logger.warning("Consumer will wait for topic to be created...")

            logger.info("Kafka consumer connected successfully")
            return True

        except KafkaError as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to Kafka: {e}")
            return False

    def consume(self, event_handler: Callable[[Dict[str, Any]], None]) -> None:
        """
        Start consuming events from Kafka.

        Args:
            event_handler: Function to call for each event (receives parsed JSON dict)
        """
        if not self.consumer:
            if not self.connect():
                logger.error("Failed to connect to Kafka, exiting")
                sys.exit(1)

        logger.info("Starting event consumption loop...")
        self.running = True

        try:
            while self.running:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)

                if not message_batch:
                    continue

                # Process messages
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            # Parse JSON event
                            event = json.loads(message.value)

                            # Call event handler
                            event_handler(event)

                            self.events_processed += 1

                            # Commit offset after successful processing (at-least-once)
                            self.consumer.commit()

                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse event JSON: {e}")
                            logger.debug(f"Invalid JSON: {message.value[:200]}")
                            self.errors += 1

                            # Send to dead-letter queue (future enhancement)
                            # For now, just commit to skip it
                            self.consumer.commit()

                        except Exception as e:
                            logger.error(f"Error processing event: {e}")
                            self.errors += 1

                            # Don't commit - this will be retried
                            # But if we've retried too many times, we should commit to avoid infinite loop
                            # This is a simplification - production should use DLQ
                            logger.warning("Committing failed event to avoid blocking (DLQ needed)")
                            self.consumer.commit()

        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Fatal error in consumption loop: {e}")
        finally:
            self.close()

    def close(self):
        """Close Kafka consumer gracefully."""
        if self.consumer:
            logger.info(f"Closing Kafka consumer (processed {self.events_processed} events, {self.errors} errors)")
            try:
                self.consumer.close()
            except Exception as e:
                logger.error(f"Error closing consumer: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics."""
        return {
            "events_processed": self.events_processed,
            "errors": self.errors,
            "running": self.running,
            "topic": self.topic,
            "group_id": self.group_id,
        }
