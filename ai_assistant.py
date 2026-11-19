"""OpenAI-backed scan-profile recommendations with a strict local allowlist."""

import json
import logging
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scanner import SCAN_PROFILES

logger = logging.getLogger(__name__)


class AssistantError(Exception):
    """A safe, user-displayable assistant configuration or service error."""


def recommend_scan_profile(need):
    """Ask OpenAI to select one reviewed profile; never accept model-supplied flags."""
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AssistantError(
            "AI assistant is not configured. Set OPENAI_API_KEY in the server environment."
        )

    profile_descriptions = "\n".join(
        f"{profile_id}: {profile['name']} — {profile['description']}"
        for profile_id, profile in SCAN_PROFILES.items()
    )
    payload = {
        "model": os.environ.get("OPENAI_MODEL", "gpt-6-astra"),
        "store": False,
        "max_output_tokens": 300,
        "input": [
            {
                "role": "system",
                "content": (
                    "You help an authorized local network administrator choose a proportionate "
                    "TCP port scan. Select exactly one profile from the supplied list. Never "
                    "invent or return command-line flags. Do not recommend stealth, evasion, "
                    "script-based vulnerability checks, exploitation, credential attacks, or "
                    "scanning beyond the user's stated authorized scope. Explain the tradeoff "
                    "briefly. If the request is unclear, choose quick and say what detail would help.\n\n"
                    f"Allowed profiles:\n{profile_descriptions}"  # nosec B608: False positive - LLM system prompt, not SQL query
                ),
            },
            {"role": "user", "content": need},
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "scan_profile_recommendation",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "profile_id": {
                            "type": "string",
                            "enum": list(SCAN_PROFILES.keys()),
                        },
                        "explanation": {"type": "string"},
                    },
                    "required": ["profile_id", "explanation"],
                    "additionalProperties": False,
                },
            }
        },
    }
    request = Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=25) as response:  # nosec B310: Hardcoded HTTPS endpoint to api.openai.com
            api_response = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        logger.warning("OpenAI recommendation request failed with HTTP status %s", error.code)
        if error.code in (401, 403):
            raise AssistantError("OpenAI rejected the API key. Check OPENAI_API_KEY.") from None
        raise AssistantError("OpenAI could not create a recommendation right now.") from None
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        logger.exception("OpenAI recommendation request failed")
        raise AssistantError("Could not reach OpenAI. Check the server connection and try again.") from None

    output_text = None
    refusal = False
    for item in api_response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "refusal":
                refusal = True
            elif content.get("type") == "output_text":
                output_text = content.get("text")

    if refusal or not output_text:
        raise AssistantError("The assistant could not make a recommendation for that request.")

    try:
        recommendation = json.loads(output_text)
        profile_id = recommendation["profile_id"]
        explanation = recommendation["explanation"].strip()
    except (json.JSONDecodeError, KeyError, AttributeError, TypeError):
        raise AssistantError("The assistant returned an invalid recommendation. Please try again.") from None

    if profile_id not in SCAN_PROFILES:
        raise AssistantError("The assistant selected an unsupported scan profile.")

    profile = SCAN_PROFILES[profile_id]
    return {
        "profile_id": profile_id,
        "name": profile["name"],
        "flags": profile["flags"],
        "description": profile["description"],
        "caution": profile["caution"],
        "explanation": explanation[:700],
    }
