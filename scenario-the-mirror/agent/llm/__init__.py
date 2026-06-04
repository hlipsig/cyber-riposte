"""
LLM module for The Mirror agent.
Supports multiple backends: Claude API, Hugging Face, or rules-only.
"""
from agent.llm.factory import create_llm_provider

__all__ = ['create_llm_provider']
