"""
LLM client for Policy Intelligence demo.

Uses Azure OpenAI with DefaultAzureCredential (same pattern as
azure-policy-icm-copilot/agent/llm.py).
"""

from __future__ import annotations

import logging
import os
from typing import AsyncIterator

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AsyncAzureOpenAI

logger = logging.getLogger(__name__)

_MS_TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
_DEFAULT_ENDPOINT = "https://governanceopenai.openai.azure.com/"
_DEFAULT_MODEL = "GPT-4o"
_DEFAULT_API_VERSION = "2024-12-01-preview"

# Lazily initialised singleton so we reuse the same credential / HTTP pool.
_client: AsyncAzureOpenAI | None = None


def _get_client() -> AsyncAzureOpenAI:
    global _client
    if _client is None:
        token_provider = get_bearer_token_provider(
            DefaultAzureCredential(
                visual_studio_code_tenant_id=_MS_TENANT_ID,
            ),
            "https://cognitiveservices.azure.com/.default",
        )
        _client = AsyncAzureOpenAI(
            azure_endpoint=os.environ.get(
                "AZURE_OPENAI_ENDPOINT", _DEFAULT_ENDPOINT
            ),
            azure_ad_token_provider=token_provider,
            api_version=os.environ.get(
                "OPENAI_API_VERSION", _DEFAULT_API_VERSION
            ),
        )
    return _client


def _get_model() -> str:
    return os.environ.get("OPENAI_API_DEFAULT_MODEL", _DEFAULT_MODEL)


async def chat(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.3,
) -> str:
    """Send messages to the LLM and return the full reply as a string."""
    client = _get_client()
    response = await client.chat.completions.create(
        model=_get_model(),
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


async def chat_stream(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.3,
) -> AsyncIterator[str]:
    """Stream the LLM reply, yielding content-delta strings."""
    client = _get_client()
    stream = await client.chat.completions.create(
        model=_get_model(),
        messages=messages,
        temperature=temperature,
        stream=True,
    )
    async for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content
