"""
Prometheus metrics for The Mirror agent (Phase 7).
Exports metrics for monitoring via /metrics endpoint.
"""

import logging
from typing import Optional

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logging.warning("Prometheus client not available. Install with: pip install prometheus-client")


logger = logging.getLogger(__name__)


class MirrorMetrics:
    """
    Prometheus metrics for The Mirror agent.

    Metrics categories:
    - Events: Kafka events processed, detection rate
    - Actions: Actions executed, success/failure rate
    - OSINT: Cache hit rate, rate limit events, API latency
    - VirtualServices: Created, active, expired
    - LLM: Consultations, model usage, confidence
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """
        Initialize metrics.

        Args:
            registry: Prometheus registry (default: global registry)
        """
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus metrics disabled (client not installed)")
            self.enabled = False
            return

        self.enabled = True
        self.registry = registry

        # Event metrics
        self.events_total = Counter(
            "mirror_events_total",
            "Total events processed from Kafka",
            ["event_type", "source"],
            registry=registry,
        )

        self.detections_total = Counter(
            "mirror_detections_total",
            "Total detections (reconnaissance, enumeration, etc.)",
            ["detection_type", "confidence_level"],
            registry=registry,
        )

        self.detection_latency = Histogram(
            "mirror_detection_latency_seconds",
            "Time to detect threat in event",
            ["detection_method"],
            registry=registry,
        )

        # Action metrics
        self.actions_total = Counter(
            "mirror_actions_total",
            "Total actions executed",
            ["action_id", "result"],
            registry=registry,
        )

        self.action_latency = Histogram(
            "mirror_action_latency_seconds",
            "Time to execute action",
            ["action_id"],
            registry=registry,
        )

        # OSINT metrics
        self.osint_cache_hits = Counter(
            "mirror_osint_cache_hits_total",
            "OSINT cache hits",
            ["module"],
            registry=registry,
        )

        self.osint_cache_misses = Counter(
            "mirror_osint_cache_misses_total",
            "OSINT cache misses",
            ["module"],
            registry=registry,
        )

        self.osint_rate_limited = Counter(
            "mirror_osint_rate_limited_total",
            "OSINT API calls rate limited",
            ["module"],
            registry=registry,
        )

        self.osint_api_latency = Histogram(
            "mirror_osint_api_latency_seconds",
            "OSINT API call latency",
            ["module"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
            registry=registry,
        )

        # VirtualService metrics
        self.virtualservices_created = Counter(
            "mirror_virtualservices_created_total",
            "VirtualServices created for traffic redirection",
            registry=registry,
        )

        self.virtualservices_active = Gauge(
            "mirror_virtualservices_active",
            "Currently active VirtualServices",
            registry=registry,
        )

        self.virtualservices_expired = Counter(
            "mirror_virtualservices_expired_total",
            "VirtualServices expired and deleted",
            registry=registry,
        )

        # LLM metrics (if LLM backend enabled)
        self.llm_consultations = Counter(
            "mirror_llm_consultations_total",
            "LLM consultations for threat evaluation",
            ["model", "backend"],
            registry=registry,
        )

        self.llm_latency = Histogram(
            "mirror_llm_latency_seconds",
            "LLM API call latency",
            ["model"],
            buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            registry=registry,
        )

        self.llm_confidence = Histogram(
            "mirror_llm_confidence",
            "LLM confidence scores",
            ["model"],
            buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            registry=registry,
        )

        # Database metrics
        self.db_operations = Counter(
            "mirror_db_operations_total",
            "Database operations",
            ["operation", "result"],
            registry=registry,
        )

        self.db_latency = Histogram(
            "mirror_db_latency_seconds",
            "Database query latency",
            ["operation"],
            registry=registry,
        )

        # Incident metrics
        self.incidents_created = Counter(
            "mirror_incidents_created_total",
            "Incidents created",
            ["severity"],
            registry=registry,
        )

        self.incidents_active = Gauge(
            "mirror_incidents_active",
            "Currently active incidents",
            registry=registry,
        )

        # Health metrics
        self.agent_info = Info(
            "mirror_agent",
            "Agent version and configuration",
            registry=registry,
        )

        self.kafka_consumer_lag = Gauge(
            "mirror_kafka_consumer_lag",
            "Kafka consumer lag",
            ["partition"],
            registry=registry,
        )

        logger.info("Prometheus metrics initialized")

    def record_event(self, event_type: str, source: str = "kafka"):
        """Record event processed."""
        if self.enabled:
            self.events_total.labels(event_type=event_type, source=source).inc()

    def record_detection(self, detection_type: str, confidence: float):
        """Record detection."""
        if not self.enabled:
            return

        # Bin confidence
        if confidence >= 0.9:
            level = "high"
        elif confidence >= 0.7:
            level = "medium"
        else:
            level = "low"

        self.detections_total.labels(
            detection_type=detection_type,
            confidence_level=level
        ).inc()

    def record_action(self, action_id: str, result: str, duration: float):
        """Record action execution."""
        if not self.enabled:
            return

        self.actions_total.labels(action_id=action_id, result=result).inc()
        self.action_latency.labels(action_id=action_id).observe(duration)

    def record_osint_cache_hit(self, module: str):
        """Record OSINT cache hit."""
        if self.enabled:
            self.osint_cache_hits.labels(module=module).inc()

    def record_osint_cache_miss(self, module: str):
        """Record OSINT cache miss."""
        if self.enabled:
            self.osint_cache_misses.labels(module=module).inc()

    def record_osint_rate_limited(self, module: str):
        """Record OSINT rate limit hit."""
        if self.enabled:
            self.osint_rate_limited.labels(module=module).inc()

    def record_osint_api_call(self, module: str, duration: float):
        """Record OSINT API call."""
        if self.enabled:
            self.osint_api_latency.labels(module=module).observe(duration)

    def record_virtualservice_created(self):
        """Record VirtualService created."""
        if self.enabled:
            self.virtualservices_created.inc()

    def set_virtualservices_active(self, count: int):
        """Set active VirtualServices count."""
        if self.enabled:
            self.virtualservices_active.set(count)

    def record_virtualservice_expired(self):
        """Record VirtualService expired."""
        if self.enabled:
            self.virtualservices_expired.inc()

    def record_llm_consultation(self, model: str, backend: str, duration: float, confidence: float):
        """Record LLM consultation."""
        if not self.enabled:
            return

        self.llm_consultations.labels(model=model, backend=backend).inc()
        self.llm_latency.labels(model=model).observe(duration)
        self.llm_confidence.labels(model=model).observe(confidence)

    def record_db_operation(self, operation: str, result: str, duration: float):
        """Record database operation."""
        if not self.enabled:
            return

        self.db_operations.labels(operation=operation, result=result).inc()
        self.db_latency.labels(operation=operation).observe(duration)

    def record_incident_created(self, severity: int):
        """Record incident created."""
        if not self.enabled:
            return

        severity_label = {1: "high", 2: "medium", 3: "low"}.get(severity, "unknown")
        self.incidents_created.labels(severity=severity_label).inc()

    def set_incidents_active(self, count: int):
        """Set active incidents count."""
        if self.enabled:
            self.incidents_active.set(count)

    def set_agent_info(self, version: str, llm_backend: str, event_source: str):
        """Set agent info."""
        if self.enabled:
            self.agent_info.info({
                "version": version,
                "llm_backend": llm_backend,
                "event_source": event_source,
            })

    def set_kafka_consumer_lag(self, partition: int, lag: int):
        """Set Kafka consumer lag."""
        if self.enabled:
            self.kafka_consumer_lag.labels(partition=str(partition)).set(lag)

    def generate_metrics(self) -> bytes:
        """
        Generate Prometheus metrics in text format.

        Returns:
            Metrics in Prometheus text format
        """
        if not self.enabled:
            return b"# Prometheus metrics disabled\n"

        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """
        Get Prometheus metrics content type.

        Returns:
            Content-Type header value
        """
        return CONTENT_TYPE_LATEST


# Global metrics instance
_metrics: Optional[MirrorMetrics] = None


def get_metrics() -> MirrorMetrics:
    """
    Get singleton metrics instance.

    Returns:
        MirrorMetrics instance
    """
    global _metrics
    if _metrics is None:
        _metrics = MirrorMetrics()
    return _metrics
