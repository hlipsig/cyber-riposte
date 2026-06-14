"""
Factory for creating LLM providers based on configuration.
"""
import logging
import os
from typing import Optional

from agent.llm.base import LLMProvider


logger = logging.getLogger(__name__)


def create_llm_provider(backend: Optional[str] = None) -> Optional[LLMProvider]:
    """
    Create an LLM provider based on configuration.

    Args:
        backend: LLM backend to use ("claude", "huggingface", "local-server", or None for auto-detect)

    Returns:
        LLMProvider instance or None if no provider available
    """
    backend = backend or os.getenv("LLM_BACKEND", "").lower()

    if not backend or backend == "rules":
        logger.info("LLM backend set to 'rules' - using rule-based detection only")
        return None

    if backend == "claude":
        return _create_claude_provider()
    elif backend == "huggingface" or backend == "hf":
        return _create_huggingface_provider()
    elif backend == "local-server" or backend == "local_server":
        return _create_local_server_provider()
    elif backend == "auto":
        # Try local server first (fastest, no crashes), then Claude, then HF
        provider = _create_local_server_provider()
        if provider and provider.is_available():
            return provider

        provider = _create_claude_provider()
        if provider and provider.is_available():
            return provider

        provider = _create_huggingface_provider()
        if provider and provider.is_available():
            return provider

        logger.warning("No LLM providers available, falling back to rules-only")
        return None
    else:
        logger.error(f"Unknown LLM backend: {backend}")
        return None


def _create_claude_provider() -> Optional[LLMProvider]:
    """Create Claude API provider."""
    try:
        from agent.llm.claude_provider import ClaudeProvider

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set - Claude provider unavailable")
            return None

        provider = ClaudeProvider(api_key=api_key)

        if provider.is_available():
            logger.info(f"Claude provider created: {provider.get_model_info()}")
            return provider
        else:
            logger.warning("Claude provider created but not available")
            return None

    except ImportError as e:
        logger.warning(f"Could not import Claude provider: {e}")
        return None
    except Exception as e:
        logger.error(f"Error creating Claude provider: {e}")
        return None


def _create_huggingface_provider() -> Optional[LLMProvider]:
    """Create Hugging Face provider."""
    try:
        from agent.llm.huggingface_provider import HuggingFaceProvider

        # Check if using API or local
        use_api = os.getenv("HF_USE_API", "false").lower() == "true"
        model_name = os.getenv("HF_MODEL", "meta-llama/Llama-3.1-8B-Instruct")

        if use_api:
            logger.info(f"Creating HuggingFace API provider for model: {model_name}")
        else:
            device = os.getenv("HF_DEVICE", "cpu")
            logger.info(f"Creating HuggingFace local provider for model: {model_name} on {device}")

        provider = HuggingFaceProvider(use_api=use_api)

        if provider.is_available():
            logger.info(f"HuggingFace provider created: {provider.get_model_info()}")
            return provider
        else:
            logger.warning("HuggingFace provider created but not available")
            return None

    except ImportError as e:
        logger.warning(f"Could not import HuggingFace provider: {e}")
        return None
    except Exception as e:
        logger.error(f"Error creating HuggingFace provider: {e}")
        return None


def _create_local_server_provider() -> Optional[LLMProvider]:
    """Create local LLM server provider (crash-free alternative to local HF)."""
    try:
        from agent.llm.local_server_provider import LocalServerProvider

        server_url = os.getenv("LLM_SERVER_URL", "http://llm-server:8000")
        logger.info(f"Creating local LLM server provider: {server_url}")

        provider = LocalServerProvider(server_url=server_url)

        if provider.is_available():
            logger.info(f"Local server provider created: {provider.get_model_info()}")
            return provider
        else:
            logger.warning("Local server provider created but not available")
            return None

    except ImportError as e:
        logger.warning(f"Could not import local server provider: {e}")
        return None
    except Exception as e:
        logger.error(f"Error creating local server provider: {e}")
        return None
