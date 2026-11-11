"""Additional heuristic prompt-injection detection controls.

Provides limited encoded-payload, indirect-instruction,
and authority-spoofing detection.

This is defense in depth, not a comprehensive security guarantee.
"""

import base64
import binascii
import re


def detect_advanced_injection(prompt: str) -> dict:
    """Detect selected advanced injection patterns."""

    if not isinstance(prompt, str):
        return {"detected": False, "category": None}

    normalized = " ".join(prompt.lower().split())

    # Detect suspicious instructions embedded in quoted documents.
    indirect_pattern = (
        r"(document|webpage|email|file)\s+says:.*"
        r"(ignore|disregard|override).*"
        r"(instructions|secrets|rules)"
    )

    if re.search(indirect_pattern, normalized):
        return {
            "detected": True,
            "category": "indirect_injection",
        }

    # Detect selected attempts to impersonate trusted developers.
    authority_pattern = (
        r"(official\s+developer\s+update|"
        r"system\s+policy\s+update).*"
        r"(disable|bypass|override).*"
        r"(security|safety|guardrails)"
    )

    if re.search(authority_pattern, normalized):
        return {
            "detected": True,
            "category": "authority_spoofing",
        }

    # Inspect Base64 tokens for known instruction overrides.
    tokens = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])",
        prompt,
    )

    for token in tokens:
        try:
            decoded = base64.b64decode(token, validate=True)
            text = decoded.decode("utf-8", errors="strict").lower()

            if re.search(
                r"(ignore|disregard|forget)\s+"
                r"(all\s+)?(previous|prior)\s+instructions",
                text,
            ):
                return {
                    "detected": True,
                    "category": "encoded_injection",
                }

        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

    return {
        "detected": False,
        "category": None,
    }
