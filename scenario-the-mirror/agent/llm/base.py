"""
Base interface for LLM providers.
All LLM backends must implement this interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def evaluate_event(
        self,
        event: Dict[str, Any],
        action_pool: List[Dict[str, Any]],
        recent_context: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate a security event and recommend an action.

        Args:
            event: Suricata EVE event or similar telemetry
            action_pool: List of available actions the agent can take
            recent_context: Recent events from the same source IP (optional)

        Returns:
            Dict with:
                - action: Action ID from the pool (or "no_action")
                - reasoning: Natural language explanation
                - confidence: Float between 0.0 and 1.0
            Or None if LLM is unavailable/failed
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this LLM provider is available and configured.

        Returns:
            True if provider can be used, False otherwise
        """
        pass

    @abstractmethod
    def get_model_info(self) -> Dict[str, str]:
        """
        Get information about the LLM being used.

        Returns:
            Dict with model name, version, backend type, etc.
        """
        pass


class LLMResponse:
    """Structured response from LLM evaluation."""

    def __init__(
        self,
        action: str,
        reasoning: str,
        confidence: float,
        model_info: Optional[Dict[str, str]] = None,
        raw_response: Optional[str] = None
    ):
        self.action = action
        self.reasoning = reasoning
        self.confidence = max(0.0, min(1.0, confidence))  # Clamp to [0, 1]
        self.model_info = model_info or {}
        self.raw_response = raw_response

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return {
            "action": self.action,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "model_info": self.model_info,
        }

    def is_actionable(self) -> bool:
        """Check if this response recommends taking an action."""
        return self.action != "no_action" and self.confidence > 0.0
