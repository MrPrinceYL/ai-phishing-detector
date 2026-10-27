"""Optional second opinion from Claude.

The heuristics only know fixed rules. Claude can read the whole message like a
human would (tone, context, odd requests) and returns a structured verdict.
This module is only used when an Anthropic API key is configured.
"""

import os
from typing import Literal

import anthropic
from pydantic import BaseModel, ConfigDict

MODEL = "claude-opus-5-5"

SYSTEM_PROMPT = """You help everyday users decide whether a URL or an e-mail is a phishing attempt.
Judge only the content you are given. Explain your reasoning in plain language a non-technical
person understands, and give one concrete tip what the user should do next."""


class AiVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # -> "additionalProperties": false in the schema

    verdict: Literal["phishing", "suspicious", "legitimate"]
    confidence: int  # 0-100
    reasons: list[str]
    advice: str


def is_configured() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def ai_check(content: str) -> AiVerdict:
    """Ask Claude for a verdict."""
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Check this for phishing:\n\n{content}"}],
        output_config={"format": {"type": "json_schema", "schema": AiVerdict.model_json_schema()}},
    )
    text = next(block.text for block in response.content if block.type == "text")
    return AiVerdict.model_validate_json(text)
