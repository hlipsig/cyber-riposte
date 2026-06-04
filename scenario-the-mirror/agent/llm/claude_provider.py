"""
Claude API provider for LLM-based detection.
Uses Anthropic's Claude models for security event analysis.
"""
import json
import logging
import os
from typing import Dict, Any, Optional, List

from agent.llm.base import LLMProvider, LLMResponse
from agent.llm.prompts import build_evaluation_prompt


logger = logging.getLogger(__name__)


class ClaudeProvider(LLMProvider):
    """Claude API LLM provider."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize Claude provider.

        Args:
            api_key: Anthropic API key (or use ANTHROPIC_API_KEY env var)
            model: Claude model to use (default: claude-sonnet-4-6)
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.model = model or os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
        self.client = None

        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                logger.info(f"Claude provider initialized with model: {self.model}")
            except ImportError:
                logger.warning("anthropic package not installed. Install with: pip install anthropic")
            except Exception as e:
                logger.error(f"Failed to initialize Claude client: {e}")

    def is_available(self) -> bool:
        """Check if Claude API is available."""
        return self.client is not None and bool(self.api_key)

    def get_model_info(self) -> Dict[str, str]:
        """Get Claude model information."""
        return {
            "backend": "claude",
            "model": self.model,
            "provider": "anthropic",
        }

    def evaluate_event(
        self,
        event: Dict[str, Any],
        action_pool: List[Dict[str, Any]],
        recent_context: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[LLMResponse]:
        """
        Use Claude to evaluate a security event.

        Args:
            event: Suricata EVE event
            action_pool: Available actions
            recent_context: Recent events from same IP

        Returns:
            LLMResponse or None if failed
        """
        if not self.is_available():
            logger.warning("Claude provider not available")
            return None

        try:
            # Build structured prompt
            prompt = build_evaluation_prompt(event, action_pool, recent_context)

            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.3,  # Lower temperature for more consistent security decisions
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Extract response text
            response_text = response.content[0].text

            # Parse JSON response
            decision = self._parse_response(response_text)

            if not decision:
                logger.error("Failed to parse Claude response")
                return None

            return LLMResponse(
                action=decision.get("action", "no_action"),
                reasoning=decision.get("reasoning", ""),
                confidence=decision.get("confidence", 0.0),
                model_info=self.get_model_info(),
                raw_response=response_text
            )

        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return None

    def _parse_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parse Claude's JSON response.

        Args:
            response_text: Raw response from Claude

        Returns:
            Parsed decision dict or None if invalid
        """
        try:
            # Claude might wrap JSON in markdown code blocks
            if "```json" in response_text:
                # Extract JSON from code block
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                # Generic code block
                start = response_text.find("```") + 3
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()

            decision = json.loads(response_text)

            # Validate required fields
            if "action" not in decision:
                logger.error("Claude response missing 'action' field")
                return None

            # Ensure reasoning exists
            if "reasoning" not in decision:
                decision["reasoning"] = "No reasoning provided"

            # Ensure confidence is valid
            if "confidence" not in decision:
                decision["confidence"] = 0.5  # Default medium confidence
            else:
                decision["confidence"] = float(decision["confidence"])

            return decision

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Claude JSON response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return None
        except Exception as e:
            logger.error(f"Error parsing Claude response: {e}")
            return None
