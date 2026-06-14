"""
Local LLM Server Provider

Uses the lightweight LLM server (TinyLlama) running in the cluster.
Avoids crashes from downloading large models at runtime.
"""

import json
import logging
import os
from typing import Dict, Any, Optional, List

import requests

from agent.llm.base import LLMProvider, LLMResponse
from agent.llm.prompts import build_evaluation_prompt


logger = logging.getLogger(__name__)


class LocalServerProvider(LLMProvider):
    """
    Local LLM Server provider.

    Connects to in-cluster LLM server instead of loading model locally.
    Prevents crashes from runtime model downloads.
    """

    def __init__(self, server_url: Optional[str] = None, timeout: int = 30):
        """
        Initialize local server provider.

        Args:
            server_url: URL of LLM server (default: http://llm-server:8000)
            timeout: Request timeout in seconds
        """
        self.server_url = server_url or os.getenv(
            'LLM_SERVER_URL',
            'http://llm-server:8000'
        )
        self.timeout = timeout

        self._check_server()

    def _check_server(self):
        """Check if LLM server is reachable."""
        try:
            response = requests.get(
                f"{self.server_url}/health",
                timeout=5
            )

            if response.status_code == 200:
                info = response.json()
                logger.info(
                    f"LLM server available: {info.get('model')} on {info.get('device')}"
                )
            else:
                logger.warning(
                    f"LLM server returned non-200 status: {response.status_code}"
                )

        except requests.exceptions.RequestException as e:
            logger.warning(f"LLM server not reachable: {e}")

    def is_available(self) -> bool:
        """Check if local server is available."""
        try:
            response = requests.get(
                f"{self.server_url}/health",
                timeout=5
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def get_model_info(self) -> Dict[str, str]:
        """Get model information from server."""
        try:
            response = requests.get(
                f"{self.server_url}/info",
                timeout=5
            )

            if response.status_code == 200:
                info = response.json()
                return {
                    "backend": "local-server",
                    "model": info.get("model", "unknown"),
                    "device": info.get("device", "unknown"),
                    "server_url": self.server_url,
                }

        except requests.exceptions.RequestException as e:
            logger.debug(f"Failed to get model info: {e}")

        return {
            "backend": "local-server",
            "model": "unknown",
            "server_url": self.server_url,
        }

    def evaluate_event(
        self,
        event: Dict[str, Any],
        action_pool: List[Dict[str, Any]],
        recent_context: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[LLMResponse]:
        """
        Evaluate security event using local LLM server.

        Args:
            event: Suricata EVE event
            action_pool: Available actions
            recent_context: Recent events from same IP

        Returns:
            LLMResponse or None if failed
        """
        if not self.is_available():
            logger.warning("Local LLM server not available")
            return None

        try:
            # Build structured prompt
            prompt = build_evaluation_prompt(event, action_pool, recent_context)

            # Format as chat messages
            messages = [
                {
                    "role": "system",
                    "content": "You are a cybersecurity defense agent analyzing network traffic. "
                               "Respond only with valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]

            # Call chat endpoint
            response = requests.post(
                f"{self.server_url}/chat",
                json={
                    "messages": messages,
                    "max_tokens": 512,
                    "temperature": 0.3
                },
                timeout=self.timeout
            )

            if response.status_code != 200:
                logger.error(
                    f"LLM server returned error: {response.status_code} - {response.text}"
                )
                return None

            result = response.json()
            response_text = result.get("text", "")

            if not response_text:
                logger.error("Empty response from LLM server")
                return None

            # Parse JSON decision
            decision = self._parse_response(response_text)

            if not decision:
                logger.error("Failed to parse LLM server response")
                return None

            return LLMResponse(
                action=decision.get("action", "no_action"),
                reasoning=decision.get("reasoning", ""),
                confidence=decision.get("confidence", 0.0),
                model_info=self.get_model_info(),
                raw_response=response_text
            )

        except requests.exceptions.Timeout:
            logger.error(f"LLM server request timed out after {self.timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"LLM server request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Evaluation error: {e}", exc_info=True)
            return None

    def _parse_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parse model's JSON response.

        Args:
            response_text: Raw response from model

        Returns:
            Parsed decision dict or None if invalid
        """
        try:
            # Models might wrap JSON in markdown or add extra text
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.find("```") + 3
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "{" in response_text and "}" in response_text:
                # Extract just the JSON object
                start = response_text.find("{")
                end = response_text.rfind("}") + 1
                response_text = response_text[start:end]

            decision = json.loads(response_text)

            # Validate required fields
            if "action" not in decision:
                logger.error("Model response missing 'action' field")
                return None

            # Ensure reasoning exists
            if "reasoning" not in decision:
                decision["reasoning"] = "No reasoning provided"

            # Ensure confidence is valid
            if "confidence" not in decision:
                decision["confidence"] = 0.5
            else:
                decision["confidence"] = float(decision["confidence"])

            return decision

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse model JSON response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return None
        except Exception as e:
            logger.error(f"Error parsing model response: {e}")
            return None
