"""LLM layer: provider-agnostic chat backends and role router.

Design goals:
* works with cloud vendors (OpenAI-compatible, Anthropic) AND local model
  servers (Ollama /v1, llama.cpp, vLLM, LM Studio) with zero dependencies;
* role-based routing (strategist / executor / reflector can each point to a
  different provider+model, e.g. cheap fast local model as executor and a
  strong cloud model as reflector);
* fallback chains + a tiny circuit breaker so a dying provider does not
  burn the clock during a live competition.
"""

from .base import ChatBackend, LLMError, Message, UsageReport
from .router import Router

__all__ = ["ChatBackend", "LLMError", "Message", "Router", "UsageReport"]
