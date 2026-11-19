"""OpenAI-compatible HTTP provider for Aegis AI Security Analyst.

Uses standard Python library (urllib.request) to avoid third-party dependencies,
ensuring strict compatibility across any deployment environment.
"""

import json
import logging
import os
from typing import Any, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class AIProviderError(Exception):
    """User-displayable provider error (network, authentication, quota)."""


def call_chat_messages(
    messages: list,
    model: str = None,
    timeout: int = 30,
    json_mode: bool = True
) -> tuple[Any, str]:
    """Sends a chat messages list to an OpenAI-compatible endpoint.

    Args:
        messages: List of dicts with 'role' and 'content'.
        model: Optional model override.
        timeout: Network timeout in seconds.
        json_mode: If True, sets response_format to json_object and parses output.

    Returns:
        tuple (response_content_or_parsed_json, model_name_used)
    Raises:
        AIProviderError on network failure, auth error, or unparseable output.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AIProviderError("OPENAI_API_KEY is not configured in the server environment.")

    is_gemini = bool(os.environ.get("GEMINI_API_KEY", "").strip()) or api_key.startswith("AIzaSy")
    if is_gemini:
        default_base_url = "https://generativelanguage.googleapis.com/v1beta/openai"
        default_model = "gemini-1.5-flash"
    else:
        default_base_url = "https://api.openai.com/v1"
        default_model = "gpt-4o-mini"

    base_url = os.environ.get("GEMINI_BASE_URL", "").strip() or os.environ.get("OPENAI_BASE_URL", "").strip() or default_base_url
    base_url = base_url.rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("https", "http"):
        raise AIProviderError("Invalid OPENAI_BASE_URL scheme; only http and https are permitted.")
    hostname = (parsed.hostname or "").lower()
    if hostname in ("169.254.169.254", "metadata.google.internal", "instance-data"):
        raise AIProviderError("Access to cloud metadata endpoints via OPENAI_BASE_URL is forbidden.")
    endpoint = f"{base_url}/chat/completions"

    resolved_model = model or os.environ.get("GEMINI_MODEL", "").strip() or os.environ.get("OPENAI_MODEL", "").strip() or default_model

    payload = {
        "model": resolved_model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1400,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    req = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Security-Scanner/2.4",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=timeout) as response:  # nosec B310
            raw_body = response.read().decode("utf-8")
            data = json.loads(raw_body)
    except HTTPError as error:
        logger.warning("OpenAI API returned HTTP status %s", error.code)
        if error.code == 401:
            raise AIProviderError("OpenAI rejected the API key. Please check your OPENAI_API_KEY.") from None
        if error.code == 429:
            raise AIProviderError("OpenAI rate limit or quota exceeded. Please check your account quota.") from None
        if error.code == 404:
            raise AIProviderError(f"Model '{resolved_model}' not found on endpoint.") from None
        raise AIProviderError(f"OpenAI service returned HTTP error {error.code}.") from None
    except (URLError, TimeoutError, OSError) as net_err:
        logger.warning("Network failure connecting to AI provider: %s", net_err)
        raise AIProviderError("Could not reach the AI service. Verify network connectivity.") from None
    except json.JSONDecodeError:
        logger.exception("Failed to decode response from AI provider")
        raise AIProviderError("Invalid response received from AI provider.") from None

    try:
        choices = data.get("choices", [])
        if not choices:
            raise AIProviderError("No response choices returned by the AI provider.")

        message_content = choices[0]["message"]["content"]
        if json_mode:
            parsed = json.loads(message_content)
            return parsed, resolved_model
        return message_content, resolved_model
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as parse_err:
        logger.exception("Error parsing message content from AI provider")
        raise AIProviderError("The AI provider did not return valid JSON output.") from parse_err


def call_chat_completion(
    system_prompt: str,
    user_prompt: str,
    model: str = None,
    timeout: int = 30
) -> tuple[dict, str]:
    """Sends a chat completion request to an OpenAI-compatible endpoint.

    Returns:
        tuple (parsed_json_dict, model_name_used)
    Raises:
        AIProviderError on network failure, auth error, or unparseable output.
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    return call_chat_messages(messages, model=model, timeout=timeout, json_mode=True)
