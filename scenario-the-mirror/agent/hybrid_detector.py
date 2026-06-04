"""
Hybrid detector that combines rule-based detection with LLM intelligence.

Strategy:
1. Try rule-based detection first (fast path)
2. If rules have high confidence (>0.85), use that
3. If rules have medium confidence (0.5-0.85) or no detection, consult LLM
4. If LLM unavailable, fall back to rules
"""
import logging
from typing import Dict, Any, Optional, List

from agent.detector import detect_recon as rule_based_detect
from agent.llm import create_llm_provider
from agent.llm.base import LLMProvider


logger = logging.getLogger(__name__)


class HybridDetector:
    """Combines rule-based and LLM-based detection."""

    def __init__(self, llm_backend: Optional[str] = None):
        """
        Initialize hybrid detector.

        Args:
            llm_backend: LLM backend to use ("claude", "huggingface", "auto", or None)
        """
        self.llm_provider: Optional[LLMProvider] = create_llm_provider(llm_backend)

        if self.llm_provider:
            logger.info(f"Hybrid detector initialized with LLM: {self.llm_provider.get_model_info()}")
        else:
            logger.info("Hybrid detector initialized in rules-only mode (no LLM)")

        # Confidence thresholds
        self.HIGH_CONFIDENCE_THRESHOLD = 0.85
        self.LOW_CONFIDENCE_THRESHOLD = 0.50

        # Track statistics
        self.stats = {
            "total_events": 0,
            "rule_detections": 0,
            "llm_detections": 0,
            "llm_consultations": 0,
            "llm_failures": 0,
        }

    def detect(
        self,
        event: Dict[str, Any],
        action_pool: Optional[List[Dict[str, Any]]] = None,
        recent_context: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Detect reconnaissance using hybrid approach.

        Args:
            event: Suricata EVE event
            action_pool: Available actions (for LLM context)
            recent_context: Recent events from same IP (for LLM context)

        Returns:
            Detection dict with signals, confidence, reasoning, and recommended action
            Or None if no detection
        """
        self.stats["total_events"] += 1

        # Step 1: Try rule-based detection (fast path)
        rule_detection = rule_based_detect(event)

        # If no rule detection, check if we should consult LLM anyway
        if not rule_detection:
            if self.llm_provider and self._should_consult_llm_for_unknown(event):
                return self._consult_llm(event, action_pool, recent_context, rule_detection)
            else:
                return None

        # Step 2: Evaluate rule confidence
        rule_confidence = rule_detection.get("confidence", 0.0)

        # High confidence rules - trust them
        if rule_confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            logger.debug(f"Rule-based detection with high confidence: {rule_confidence:.2f}")
            self.stats["rule_detections"] += 1
            rule_detection["detection_method"] = "rule_based"
            rule_detection["llm_consulted"] = False
            return rule_detection

        # Medium/low confidence rules - consult LLM if available
        if self.llm_provider:
            logger.debug(
                f"Rule-based detection with medium confidence ({rule_confidence:.2f}), "
                f"consulting LLM"
            )
            return self._consult_llm(event, action_pool, recent_context, rule_detection)

        # No LLM available - use rules even with medium confidence
        logger.debug(
            f"Rule-based detection with medium confidence ({rule_confidence:.2f}), "
            f"no LLM available"
        )
        self.stats["rule_detections"] += 1
        rule_detection["detection_method"] = "rule_based_fallback"
        rule_detection["llm_consulted"] = False
        return rule_detection

    def _should_consult_llm_for_unknown(self, event: Dict[str, Any]) -> bool:
        """
        Decide if we should consult LLM even when rules didn't detect anything.

        This allows LLM to catch novel attacks that rules miss.

        Args:
            event: Suricata EVE event

        Returns:
            True if LLM should be consulted
        """
        # Heuristics for when to consult LLM on unknown events:

        # 1. IDS alert present (even if category not in known list)
        if event.get("event_type") == "alert":
            return True

        # 2. HTTP request with unusual user-agent (not empty, contains certain keywords)
        user_agent = event.get("http", {}).get("http_user_agent", "")
        suspicious_keywords = [
            "bot", "scan", "exploit", "hack", "security", "test",
            "audit", "probe", "crawler", "spider"
        ]
        if user_agent and any(kw in user_agent.lower() for kw in suspicious_keywords):
            return True

        # 3. Accessing sensitive endpoints
        uri = event.get("http", {}).get("http_uri", "")
        sensitive_paths = [
            "admin", "api", "config", ".git", ".env", "backup",
            "database", "sql", "user", "login", "auth"
        ]
        if uri and any(path in uri.lower() for path in sensitive_paths):
            return True

        # Otherwise, don't waste LLM calls on benign traffic
        return False

    def _consult_llm(
        self,
        event: Dict[str, Any],
        action_pool: Optional[List[Dict[str, Any]]],
        recent_context: Optional[List[Dict[str, Any]]],
        rule_detection: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Consult LLM for detection decision.

        Args:
            event: Suricata EVE event
            action_pool: Available actions
            recent_context: Recent events from same IP
            rule_detection: Detection from rules (if any)

        Returns:
            Enhanced detection dict with LLM reasoning
        """
        self.stats["llm_consultations"] += 1

        try:
            # Prepare action pool (use default if not provided)
            if not action_pool:
                action_pool = self._get_default_action_pool()

            # Get LLM evaluation
            llm_response = self.llm_provider.evaluate_event(
                event=event,
                action_pool=action_pool,
                recent_context=recent_context or []
            )

            if not llm_response:
                logger.warning("LLM evaluation failed, falling back to rules")
                self.stats["llm_failures"] += 1
                if rule_detection:
                    rule_detection["detection_method"] = "rule_based_fallback"
                    rule_detection["llm_consulted"] = True
                    rule_detection["llm_failed"] = True
                    return rule_detection
                return None

            # LLM recommends no action
            if llm_response.action == "no_action":
                logger.debug("LLM recommends no action")
                return None

            # LLM detected something - create detection dict
            self.stats["llm_detections"] += 1

            detection = {
                "src_ip": event.get("src_ip"),
                "timestamp": event.get("timestamp"),
                "signals": [],
                "confidence": llm_response.confidence,
                "reasoning": llm_response.reasoning,
                "recommended_action": llm_response.action,
                "detection_method": "llm",
                "llm_consulted": True,
                "llm_model": llm_response.model_info,
            }

            # If we had rule detection, merge signals
            if rule_detection:
                detection["signals"] = rule_detection.get("signals", [])
                detection["signature"] = rule_detection.get("signature", "")
                detection["severity"] = rule_detection.get("severity", 2)
                detection["rule_confidence"] = rule_detection.get("confidence", 0.0)
                detection["detection_method"] = "hybrid"  # Both rules and LLM
            else:
                # LLM-only detection
                detection["signals"] = [{
                    "type": "llm_analysis",
                    "reasoning": llm_response.reasoning,
                    "confidence": llm_response.confidence,
                }]
                detection["signature"] = f"LLM detected: {llm_response.action}"
                detection["severity"] = 1 if llm_response.confidence > 0.8 else 2

            return detection

        except Exception as e:
            logger.error(f"Error consulting LLM: {e}")
            self.stats["llm_failures"] += 1

            # Fall back to rules if available
            if rule_detection:
                rule_detection["detection_method"] = "rule_based_fallback"
                rule_detection["llm_consulted"] = True
                rule_detection["llm_error"] = str(e)
                return rule_detection

            return None

    def _get_default_action_pool(self) -> List[Dict[str, Any]]:
        """Get default action pool for LLM context."""
        return [
            {
                "id": "redirect-to-honeypot",
                "tier": 1,
                "name": "Redirect traffic to honeypot",
                "description": "Apply traffic redirection to honeypot for TTP collection"
            },
            {
                "id": "run-osint",
                "tier": 1,
                "name": "Run passive OSINT on source IP",
                "description": "WHOIS, reverse DNS, Shodan lookup, CT search"
            },
            {
                "id": "temp-block-ip",
                "tier": 1,
                "name": "Temporary IP block",
                "description": "Block single IP for 1 hour"
            },
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        stats = self.stats.copy()

        if stats["total_events"] > 0:
            stats["rule_detection_rate"] = stats["rule_detections"] / stats["total_events"]
            stats["llm_detection_rate"] = stats["llm_detections"] / stats["total_events"]

        if stats["llm_consultations"] > 0:
            stats["llm_success_rate"] = 1.0 - (stats["llm_failures"] / stats["llm_consultations"])

        return stats
