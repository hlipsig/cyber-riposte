"""
Hugging Face model provider for LLM-based detection.
Supports local or API-based inference with open-source models.
"""
import json
import logging
import os
from typing import Dict, Any, Optional, List

from agent.llm.base import LLMProvider, LLMResponse
from agent.llm.prompts import build_evaluation_prompt


logger = logging.getLogger(__name__)


class HuggingFaceProvider(LLMProvider):
    """Hugging Face LLM provider - supports local and API inference."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        device: Optional[str] = None,
        use_api: bool = False,
        api_token: Optional[str] = None
    ):
        """
        Initialize Hugging Face provider.

        Args:
            model_name: Hugging Face model ID (e.g., "meta-llama/Llama-3.1-8B-Instruct")
            device: Device for inference ("cuda", "cpu", "mps")
            use_api: If True, use Hugging Face Inference API instead of local
            api_token: Hugging Face API token (for API mode or gated models)
        """
        self.model_name = model_name or os.getenv(
            "HF_MODEL",
            "meta-llama/Llama-3.1-8B-Instruct"
        )
        self.device = device or os.getenv("HF_DEVICE", "cpu")
        self.use_api = use_api or os.getenv("HF_USE_API", "false").lower() == "true"
        self.api_token = api_token or os.getenv("HF_API_TOKEN", "")

        self.pipeline = None
        self.client = None

        if self.use_api:
            self._init_api_client()
        else:
            self._init_local_model()

    def _init_api_client(self):
        """Initialize Hugging Face Inference API client."""
        try:
            from huggingface_hub import InferenceClient

            self.client = InferenceClient(
                model=self.model_name,
                token=self.api_token if self.api_token else None
            )
            logger.info(f"HuggingFace API client initialized for model: {self.model_name}")

        except ImportError:
            logger.warning("huggingface_hub not installed. Install with: pip install huggingface_hub")
        except Exception as e:
            logger.error(f"Failed to initialize HuggingFace API client: {e}")

    def _init_local_model(self):
        """Initialize local Hugging Face model with transformers."""
        try:
            from transformers import pipeline
            import torch

            # Determine actual device
            if self.device == "cuda" and not torch.cuda.is_available():
                logger.warning("CUDA not available, falling back to CPU")
                self.device = "cpu"
            elif self.device == "mps" and not torch.backends.mps.is_available():
                logger.warning("MPS not available, falling back to CPU")
                self.device = "cpu"

            logger.info(f"Loading HuggingFace model {self.model_name} on {self.device}...")

            # Create text generation pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model_name,
                device=self.device,
                token=self.api_token if self.api_token else None,
                torch_dtype="auto"
            )

            logger.info(f"HuggingFace model loaded successfully on {self.device}")

        except ImportError:
            logger.warning(
                "transformers or torch not installed. "
                "Install with: pip install transformers torch"
            )
        except Exception as e:
            logger.error(f"Failed to load HuggingFace model: {e}")

    def is_available(self) -> bool:
        """Check if Hugging Face provider is available."""
        if self.use_api:
            return self.client is not None
        else:
            return self.pipeline is not None

    def get_model_info(self) -> Dict[str, str]:
        """Get Hugging Face model information."""
        return {
            "backend": "huggingface",
            "model": self.model_name,
            "device": self.device if not self.use_api else "api",
            "mode": "api" if self.use_api else "local",
        }

    def evaluate_event(
        self,
        event: Dict[str, Any],
        action_pool: List[Dict[str, Any]],
        recent_context: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[LLMResponse]:
        """
        Use Hugging Face model to evaluate a security event.

        Args:
            event: Suricata EVE event
            action_pool: Available actions
            recent_context: Recent events from same IP

        Returns:
            LLMResponse or None if failed
        """
        if not self.is_available():
            logger.warning("HuggingFace provider not available")
            return None

        try:
            # Build structured prompt
            prompt = build_evaluation_prompt(event, action_pool, recent_context)

            # Format for instruct models (using chat template)
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

            # Generate response
            if self.use_api:
                response_text = self._generate_api(messages)
            else:
                response_text = self._generate_local(messages)

            if not response_text:
                logger.error("Failed to generate response from HuggingFace model")
                return None

            # Parse JSON response
            decision = self._parse_response(response_text)

            if not decision:
                logger.error("Failed to parse HuggingFace response")
                return None

            return LLMResponse(
                action=decision.get("action", "no_action"),
                reasoning=decision.get("reasoning", ""),
                confidence=decision.get("confidence", 0.0),
                model_info=self.get_model_info(),
                raw_response=response_text
            )

        except Exception as e:
            logger.error(f"HuggingFace inference error: {e}")
            return None

    def _generate_api(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """Generate response using Hugging Face Inference API."""
        try:
            response = self.client.chat_completion(
                messages=messages,
                max_tokens=1024,
                temperature=0.3
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"HuggingFace API generation error: {e}")
            return None

    def _generate_local(self, messages: List[Dict[str, str]]) -> Optional[str]:
        """Generate response using local Hugging Face model."""
        try:
            # Apply chat template if available
            if hasattr(self.pipeline.tokenizer, 'apply_chat_template'):
                prompt = self.pipeline.tokenizer.apply_chat_template(
                    messages,
                    tokenize=False,
                    add_generation_prompt=True
                )
            else:
                # Fallback: simple concatenation
                prompt = "\n\n".join([
                    f"{msg['role']}: {msg['content']}"
                    for msg in messages
                ])

            # Generate
            outputs = self.pipeline(
                prompt,
                max_new_tokens=1024,
                temperature=0.3,
                do_sample=True,
                top_p=0.9,
                return_full_text=False
            )

            return outputs[0]['generated_text']

        except Exception as e:
            logger.error(f"HuggingFace local generation error: {e}")
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
            # Try to find JSON in response
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
